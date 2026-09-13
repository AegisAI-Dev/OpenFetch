"""Directory-based (one-folder) Windows update installation with rollback.

The compliance-friendly one-folder distribution keeps Qt/PySide shared
libraries externally replaceable.  This module implements the directory-wide
update transaction that the legacy one-file installer deliberately refuses:

- every file is listed in a strict directory manifest and verified by SHA-256;
- the installation directory is backed up byte-for-byte before any change;
- replacement is staged beside the target and applied with two directory
  renames so an interruption always leaves a recoverable layout;
- recipient-replaced Qt/PySide libraries are never overwritten silently: the
  caller must select an explicit :class:`QtReplacementPolicy`;
- startup confirmation, rollback, stale-state recovery, and concurrent-update
  rejection reuse the same ownership and process-lifetime controls as the
  legacy one-file transaction.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from openfetch.config import APP_NAME, EXECUTABLE_STEM, VERSION
from openfetch.core.process_control import process_creation_identity
from openfetch.core.update_installer import (
    ALLOWED_STATE_TRANSITIONS,
    HELPER_HANDOFF_TIMEOUT_SECONDS,
    PARENT_EXIT_TIMEOUT_SECONDS,
    PROCESS_POLL_INTERVAL_SECONDS,
    REPLACEMENT_RETRY_COUNT,
    REPLACEMENT_RETRY_DELAY_SECONDS,
    RESULT_FILENAME,
    STARTUP_CONFIRMATION_TIMEOUT_SECONDS,
    STARTUP_MARKER_FILENAME,
    TOKEN_PATTERN,
    ChildProcess,
    IdentityProvider,
    InstallationCapability,
    MessageCallback,
    Monotonic,
    PreparedUpdate,
    ProcessExists,
    ProcessLauncher,
    RecordedProcessStopper,
    Sleep,
    StaleRecoverySummary,
    _append_update_log,
    _atomic_write_json,
    _default_detached_launcher,
    _default_process_launcher,
    _directory_writable,
    _is_within,
    _show_native_message,
    _stop_child_process,
    _stop_recorded_process,
    _strict_json_object,
    update_root,
)
from openfetch.core.update_manifest import (
    SHA256_PATTERN,
    is_newer_version,
    parse_numeric_version,
    sha256_file,
)
from openfetch.core.update_ownership import (
    OwnershipRole,
    TransactionState,
    UpdateOwnershipManager,
    new_transaction_id,
    normalized_target_identity,
)
from openfetch.core.updater import CancelCallback, ProgressCallback, UpdateError

DIRECTORY_TRANSACTION_SCHEMA_VERSION = 1
DIRECTORY_TRANSACTION_FILENAME = "directory-transaction.json"
DIRECTORY_MANIFEST_FILENAME = "directory-manifest.json"
BACKUP_INVENTORY_FILENAME = "backup-inventory.json"
MAX_DIRECTORY_TRANSACTION_BYTES = 256 * 1024

DIRECTORY_MANIFEST_SCHEMA_VERSION = 1
DIRECTORY_MANIFEST_MAX_BYTES = 8 * 1024 * 1024
MAX_DIRECTORY_FILE_COUNT = 20_000
MAX_DIRECTORY_PATH_LENGTH = 240
MIN_DIRECTORY_TOTAL_BYTES = 1 * 1024 * 1024
MAX_DIRECTORY_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_REPLACEABLE_PATHS = 512
DIRECTORY_DISK_SPACE_MARGIN_BYTES = 64 * 1024 * 1024

ONEFOLDER_EXECUTABLE_NAME = f"{EXECUTABLE_STEM}.exe"
QT_COMPONENT_BASELINE_FILENAME = "QT-PYSIDE-COMPONENTS.json"
REPLACEABLE_FAMILY_ROOTS = ("PySide6", "shiboken6")

EXPECTED_APPLICATION_NAME = APP_NAME

_LEGACY_ONEFILE_PATTERN = re.compile(
    r"^(?:OpenFetch|NeuralExtractorV3)-\d+\.\d+\.\d+-windows-x64\.exe$",
    re.IGNORECASE,
)
_PROHIBITED_PATH_SUBSTRINGS = (
    "pyqt",
    "yt_dlp_plugins",
    "bgutil",
    "getpot",
    "node_modules/canvas",
)
_PROHIBITED_FILENAMES = {"sip.pyd"}
_WINDOWS_RESERVED_SEGMENTS = (
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_SEGMENT_FORBIDDEN_CHARS = set('<>:"|?*/\\') | {chr(code) for code in range(32)}

RenamePath = Callable[[Path, Path], None]


class QtReplacementPolicy(str, Enum):
    """Explicit recipient decision for locally replaced Qt/PySide libraries."""

    ABORT = "abort"
    PRESERVE = "preserve"
    REPLACE = "replace"


def expected_directory_root_name(version: str) -> str:
    parse_numeric_version(version)
    return f"{EXECUTABLE_STEM}-{version}-windows-x64"


def expected_directory_manifest_filename(version: str) -> str:
    return f"{expected_directory_root_name(version)}-directory-manifest.json"


def _long_path(path: Path | str) -> str:
    """Return an extended-length path so deep or Unicode installs keep working."""
    value = os.path.abspath(os.fspath(path))
    if sys.platform != "win32" or value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _rename_path(source: Path, destination: Path) -> None:
    os.rename(_long_path(source), _long_path(destination))


def _remove_tree(root: Path) -> None:
    shutil.rmtree(_long_path(root))


def _path_exists(path: Path | str) -> bool:
    return os.path.lexists(_long_path(path))


def _is_reparse_point(path: Path | str) -> bool:
    try:
        result = os.lstat(_long_path(path))
    except OSError:
        return True
    if stat.S_ISLNK(result.st_mode):
        return True
    attributes = getattr(result, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _hash_file(path: Path | str, chunk_size: int = 1024 * 1024) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(_long_path(path), "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _file_size(path: Path | str) -> int:
    return os.stat(_long_path(path)).st_size


def _copy_file_verified(source: Path | str, destination: Path | str) -> str:
    """Copy one regular file, fsync it, and return the verified SHA-256."""
    source_hash = _hash_file(source)
    destination_text = _long_path(destination)
    os.makedirs(os.path.dirname(destination_text), exist_ok=True)
    with open(_long_path(source), "rb") as input_handle, open(
        destination_text, "xb"
    ) as output_handle:
        while chunk := input_handle.read(1024 * 1024):
            output_handle.write(chunk)
        output_handle.flush()
        os.fsync(output_handle.fileno())
    if not hmac.compare_digest(_hash_file(destination), source_hash):
        raise UpdateError(
            "staging_failure",
            "A copied update file failed SHA-256 verification.",
        )
    return source_hash


def _walk_regular_files(root: Path) -> Iterator[tuple[str, str]]:
    """Yield (posix-relative, absolute) file paths, rejecting reparse points."""
    root_text = _long_path(root)
    if _is_reparse_point(root_text):
        raise UpdateError(
            "unsafe_path",
            "The update directory tree contains a symlink or reparse point.",
        )
    stack = [root_text]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError as exc:
            raise UpdateError(
                "unsafe_path",
                "An update directory tree could not be read safely.",
                technical=str(exc),
            ) from exc
        for entry in entries:
            if _is_reparse_point(entry.path):
                raise UpdateError(
                    "unsafe_path",
                    "The update directory tree contains a symlink or reparse point.",
                )
            if entry.is_dir(follow_symlinks=False):
                stack.append(entry.path)
            elif entry.is_file(follow_symlinks=False):
                relative = os.path.relpath(entry.path, root_text).replace(os.sep, "/")
                yield relative, entry.path
            else:
                raise UpdateError(
                    "unsafe_path",
                    "The update directory tree contains an unsupported special file.",
                )


def _read_json_limited(path: Path, max_bytes: int) -> dict[str, Any]:
    try:
        candidate = Path(path)
        if _file_size(candidate) > max_bytes:
            raise UpdateError(
                "invalid_transaction",
                "An update metadata file is too large.",
            )
        with open(_long_path(candidate), "rb") as handle:
            payload = json.loads(
                handle.read().decode("utf-8"),
                object_pairs_hook=_strict_json_object,
            )
    except UpdateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UpdateError(
            "invalid_transaction", "An update metadata file is invalid."
        ) from exc
    if not isinstance(payload, dict):
        raise UpdateError("invalid_transaction", "An update metadata file is invalid.")
    return payload


def validate_directory_relative_path(value: object) -> str:
    """Validate one manifest-relative path and return it unchanged."""
    if not isinstance(value, str) or not value or len(value) > MAX_DIRECTORY_PATH_LENGTH:
        raise UpdateError(
            "invalid_directory_manifest",
            "A directory manifest path has an invalid length.",
        )
    pure = PurePosixPath(value)
    if pure.is_absolute() or value != pure.as_posix() or "\\" in value:
        raise UpdateError(
            "invalid_directory_manifest",
            f"A directory manifest path is unsafe: {value!r}",
        )
    for segment in pure.parts:
        base = segment.split(".", 1)[0].casefold()
        if (
            segment in {"", ".", ".."}
            or segment != segment.strip(" ")
            or segment.endswith(".")
            or base in _WINDOWS_RESERVED_SEGMENTS
            or any(char in _SEGMENT_FORBIDDEN_CHARS for char in segment)
        ):
            raise UpdateError(
                "invalid_directory_manifest",
                f"A directory manifest path segment is unsafe: {segment!r}",
            )
    return value


def _reject_prohibited_artifact(relative: str, *, executable: str) -> None:
    casefolded = relative.casefold()
    name = PurePosixPath(relative).name
    if name.casefold() in _PROHIBITED_FILENAMES or any(
        marker in casefolded for marker in _PROHIBITED_PATH_SUBSTRINGS
    ):
        raise UpdateError(
            "prohibited_artifact",
            f"The update package lists a prohibited component: {relative}",
        )
    if _LEGACY_ONEFILE_PATTERN.fullmatch(name):
        raise UpdateError(
            "prohibited_artifact",
            f"The update package lists a legacy one-file artifact: {relative}",
        )
    if name.casefold().endswith(".exe") and relative != executable:
        allowed_runtime = relative.startswith("bin/")
        if not allowed_runtime:
            raise UpdateError(
                "prohibited_artifact",
                f"The update package lists an unexpected executable: {relative}",
            )


@dataclass(frozen=True, slots=True)
class DirectoryFileRecord:
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class DirectoryUpdateManifest:
    """Strict per-file manifest for a one-folder Windows release."""

    schema_version: int
    application_name: str
    release_version: str
    platform: str
    architecture: str
    channel: str
    root_name: str
    executable: str
    total_size: int
    files: dict[str, DirectoryFileRecord]
    replaceable_paths: tuple[str, ...]

    @classmethod
    def from_json(
        cls,
        document: str | bytes,
        *,
        release_version: str,
        current_version: str | None = None,
    ) -> DirectoryUpdateManifest:
        if isinstance(document, str):
            document = document.encode("utf-8")
        if len(document) > DIRECTORY_MANIFEST_MAX_BYTES:
            raise UpdateError(
                "invalid_directory_manifest", "The directory manifest is too large."
            )
        try:
            payload = json.loads(
                document.decode("utf-8"), object_pairs_hook=_strict_json_object
            )
        except UpdateError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise UpdateError(
                "invalid_directory_manifest", "The directory manifest is not valid JSON."
            ) from exc
        if not isinstance(payload, dict):
            raise UpdateError(
                "invalid_directory_manifest", "The directory manifest must be an object."
            )
        expected_fields = {
            "schema_version",
            "application_name",
            "release_version",
            "platform",
            "architecture",
            "channel",
            "root_name",
            "executable",
            "total_size",
            "files",
            "replaceable_paths",
        }
        if set(payload) != expected_fields:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest fields are invalid.",
            )
        if payload["schema_version"] != DIRECTORY_MANIFEST_SCHEMA_VERSION:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest schema version is unsupported.",
            )
        if payload["application_name"] != EXPECTED_APPLICATION_NAME:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest application name is invalid.",
            )
        if payload["platform"] != "windows" or payload["architecture"] != "x64":
            raise UpdateError(
                "wrong_platform",
                "The directory manifest is not for Windows x64.",
            )
        if payload["channel"] != "stable":
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest is not from the stable channel.",
            )
        manifest_version = str(payload["release_version"])
        try:
            parse_numeric_version(manifest_version)
            parse_numeric_version(release_version)
        except ValueError as exc:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest version is invalid.",
            ) from exc
        if manifest_version != release_version:
            raise UpdateError(
                "release_manifest_version_mismatch",
                "The release and directory manifest versions do not match.",
            )
        if current_version is not None and not is_newer_version(
            manifest_version, current_version
        ):
            raise UpdateError(
                "not_newer",
                "The directory manifest version is not newer than the installed version.",
            )
        if payload["root_name"] != expected_directory_root_name(manifest_version):
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest root name is invalid.",
            )
        executable = payload["executable"]
        if executable != ONEFOLDER_EXECUTABLE_NAME:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest executable name is invalid.",
            )

        raw_files = payload["files"]
        if not isinstance(raw_files, dict) or not raw_files:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest file list is invalid.",
            )
        if len(raw_files) > MAX_DIRECTORY_FILE_COUNT:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest lists too many files.",
            )
        files: dict[str, DirectoryFileRecord] = {}
        seen_casefolded: set[str] = set()
        computed_total = 0
        for raw_path, record in raw_files.items():
            relative = validate_directory_relative_path(raw_path)
            _reject_prohibited_artifact(relative, executable=executable)
            casefolded = relative.casefold()
            if casefolded in seen_casefolded:
                raise UpdateError(
                    "invalid_directory_manifest",
                    f"The directory manifest lists a duplicate path: {relative}",
                )
            seen_casefolded.add(casefolded)
            if not isinstance(record, dict) or set(record) != {"sha256", "size"}:
                raise UpdateError(
                    "invalid_directory_manifest",
                    f"The directory manifest record for {relative} is invalid.",
                )
            sha256_value = record["sha256"]
            size_value = record["size"]
            if not isinstance(sha256_value, str) or not SHA256_PATTERN.fullmatch(
                sha256_value
            ):
                raise UpdateError(
                    "invalid_directory_manifest",
                    f"The directory manifest checksum for {relative} is invalid.",
                )
            if (
                isinstance(size_value, bool)
                or not isinstance(size_value, int)
                or size_value < 0
                or size_value > MAX_DIRECTORY_TOTAL_BYTES
            ):
                raise UpdateError(
                    "invalid_directory_manifest",
                    f"The directory manifest size for {relative} is invalid.",
                )
            computed_total += size_value
            files[relative] = DirectoryFileRecord(sha256_value.lower(), size_value)

        if executable not in files:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest does not list the application executable.",
            )
        total_size = payload["total_size"]
        if (
            isinstance(total_size, bool)
            or not isinstance(total_size, int)
            or total_size != computed_total
            or not MIN_DIRECTORY_TOTAL_BYTES <= total_size <= MAX_DIRECTORY_TOTAL_BYTES
        ):
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest total size is invalid.",
            )

        raw_replaceable = payload["replaceable_paths"]
        if not isinstance(raw_replaceable, list) or len(raw_replaceable) > MAX_REPLACEABLE_PATHS:
            raise UpdateError(
                "invalid_directory_manifest",
                "The directory manifest replaceable path list is invalid.",
            )
        replaceable: list[str] = []
        for raw_path in raw_replaceable:
            relative = validate_directory_relative_path(raw_path)
            if relative not in files or relative in replaceable:
                raise UpdateError(
                    "invalid_directory_manifest",
                    f"The directory manifest replaceable path is invalid: {relative}",
                )
            first = PurePosixPath(relative).parts[0]
            if first not in REPLACEABLE_FAMILY_ROOTS:
                raise UpdateError(
                    "invalid_directory_manifest",
                    f"The directory manifest replaceable path is outside the Qt/PySide family: {relative}",
                )
            replaceable.append(relative)

        return cls(
            schema_version=DIRECTORY_MANIFEST_SCHEMA_VERSION,
            application_name=EXPECTED_APPLICATION_NAME,
            release_version=manifest_version,
            platform="windows",
            architecture="x64",
            channel="stable",
            root_name=str(payload["root_name"]),
            executable=executable,
            total_size=total_size,
            files=files,
            replaceable_paths=tuple(replaceable),
        )

    @classmethod
    def for_distribution_root(
        cls,
        *,
        version: str,
        root: Path,
        replaceable_paths: tuple[str, ...] | None = None,
    ) -> DirectoryUpdateManifest:
        parse_numeric_version(version)
        root = Path(root)
        files: dict[str, dict[str, object]] = {}
        replaceable: list[str] = []
        for relative, absolute in _walk_regular_files(root):
            validate_directory_relative_path(relative)
            files[relative] = {"sha256": _hash_file(absolute), "size": _file_size(absolute)}
            if (
                replaceable_paths is None
                and PurePosixPath(relative).parts[0] in REPLACEABLE_FAMILY_ROOTS
            ):
                replaceable.append(relative)
        payload = {
            "schema_version": DIRECTORY_MANIFEST_SCHEMA_VERSION,
            "application_name": EXPECTED_APPLICATION_NAME,
            "release_version": version,
            "platform": "windows",
            "architecture": "x64",
            "channel": "stable",
            "root_name": expected_directory_root_name(version),
            "executable": ONEFOLDER_EXECUTABLE_NAME,
            "total_size": sum(int(record["size"]) for record in files.values()),
            "files": files,
            "replaceable_paths": sorted(
                replaceable if replaceable_paths is None else replaceable_paths
            ),
        }
        return cls.from_json(json.dumps(payload), release_version=version)

    def to_json(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "application_name": self.application_name,
            "release_version": self.release_version,
            "platform": self.platform,
            "architecture": self.architecture,
            "channel": self.channel,
            "root_name": self.root_name,
            "executable": self.executable,
            "total_size": self.total_size,
            "files": {
                relative: {"sha256": record.sha256, "size": record.size}
                for relative, record in sorted(self.files.items())
            },
            "replaceable_paths": sorted(self.replaceable_paths),
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@dataclass(frozen=True, slots=True)
class DirectoryUpdateTransaction:
    schema_version: int
    transaction_id: str
    confirmation_token: str
    state: str
    expected_version: str
    manifest_sha256: str
    backup_inventory_sha256: str
    qt_policy: str
    preserved_files: dict[str, str]
    parent_pid: int
    parent_process_created: str
    target_identity: str
    target_root: str
    target_executable: str
    staged_root: str
    backup_root: str
    old_root: str
    new_root: str
    startup_marker: str
    created_at: str
    updated_at: str
    launched_pid: int | None
    launched_process_created: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DIRECTORY_TRANSACTION_FIELDS = {
    "schema_version",
    "transaction_id",
    "confirmation_token",
    "state",
    "expected_version",
    "manifest_sha256",
    "backup_inventory_sha256",
    "qt_policy",
    "preserved_files",
    "parent_pid",
    "parent_process_created",
    "target_identity",
    "target_root",
    "target_executable",
    "staged_root",
    "backup_root",
    "old_root",
    "new_root",
    "startup_marker",
    "created_at",
    "updated_at",
    "launched_pid",
    "launched_process_created",
}


def _sibling_path(target_root: Path, transaction_id: str, suffix: str) -> Path:
    return target_root.parent / f".{target_root.name}.{transaction_id}.{suffix}"


def _transition_directory_transaction(
    transaction_path: Path,
    transaction: DirectoryUpdateTransaction,
    state: TransactionState,
    *,
    launched_pid: int | None = None,
    launched_process_created: str | None = None,
) -> DirectoryUpdateTransaction:
    current_state = transaction.state
    if state.value != current_state and state.value not in ALLOWED_STATE_TRANSITIONS.get(
        current_state, set()
    ):
        raise UpdateError(
            "invalid_transaction_state",
            f"The directory update transaction cannot move from {current_state} to {state.value}.",
        )
    updated = replace(
        transaction,
        state=state.value,
        updated_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
        launched_pid=(transaction.launched_pid if launched_pid is None else launched_pid),
        launched_process_created=(
            transaction.launched_process_created
            if launched_process_created is None
            else launched_process_created
        ),
    )
    _atomic_write_json(transaction_path, updated.to_dict())
    return updated


def load_directory_update_transaction(
    transaction_path: Path,
    *,
    updates_root: Path | None = None,
    temporary_root: Path | None = None,
) -> DirectoryUpdateTransaction:
    root = Path(updates_root or update_root()).resolve()
    path = Path(transaction_path).resolve()
    if not _is_within(path, root) or path.name != DIRECTORY_TRANSACTION_FILENAME:
        raise UpdateError(
            "invalid_transaction", "The directory update transaction path is unsafe."
        )
    payload = _read_json_limited(path, MAX_DIRECTORY_TRANSACTION_BYTES)
    if set(payload) != DIRECTORY_TRANSACTION_FIELDS:
        raise UpdateError(
            "invalid_transaction", "The directory update transaction fields are invalid."
        )
    if payload.get("schema_version") != DIRECTORY_TRANSACTION_SCHEMA_VERSION:
        raise UpdateError(
            "invalid_transaction", "The directory update transaction schema is unsupported."
        )

    transaction_id = str(payload.get("transaction_id") or "")
    confirmation_token = str(payload.get("confirmation_token") or "")
    if not TOKEN_PATTERN.fullmatch(transaction_id):
        raise UpdateError(
            "invalid_transaction", "The directory update transaction ID is invalid."
        )
    if not TOKEN_PATTERN.fullmatch(confirmation_token):
        raise UpdateError(
            "invalid_transaction", "The startup confirmation token is invalid."
        )
    state = str(payload.get("state") or "")
    if state not in {item.value for item in TransactionState}:
        raise UpdateError(
            "invalid_transaction", "The directory update transaction state is invalid."
        )
    version = str(payload.get("expected_version") or "")
    try:
        parse_numeric_version(version)
    except ValueError as exc:
        raise UpdateError(
            "invalid_transaction", "The directory update transaction version is invalid."
        ) from exc

    manifest_hash = str(payload.get("manifest_sha256") or "")
    inventory_hash = str(payload.get("backup_inventory_sha256") or "")
    if not SHA256_PATTERN.fullmatch(manifest_hash) or not SHA256_PATTERN.fullmatch(
        inventory_hash
    ):
        raise UpdateError(
            "invalid_transaction", "The directory update transaction checksum is invalid."
        )
    qt_policy = str(payload.get("qt_policy") or "")
    if qt_policy not in {item.value for item in QtReplacementPolicy}:
        raise UpdateError(
            "invalid_transaction", "The directory update Qt policy is invalid."
        )
    raw_preserved = payload.get("preserved_files")
    if not isinstance(raw_preserved, dict) or len(raw_preserved) > MAX_REPLACEABLE_PATHS:
        raise UpdateError(
            "invalid_transaction", "The directory update preserved file map is invalid."
        )
    preserved: dict[str, str] = {}
    for raw_path, raw_hash in raw_preserved.items():
        relative = validate_directory_relative_path(raw_path)
        if not isinstance(raw_hash, str) or not SHA256_PATTERN.fullmatch(raw_hash):
            raise UpdateError(
                "invalid_transaction",
                "The directory update preserved file map is invalid.",
            )
        preserved[relative] = raw_hash.lower()
    if preserved and qt_policy != QtReplacementPolicy.PRESERVE.value:
        raise UpdateError(
            "invalid_transaction",
            "Preserved files require the preserve replacement policy.",
        )

    parent_pid = payload.get("parent_pid")
    parent_process_created = str(payload.get("parent_process_created") or "")
    target_identity = str(payload.get("target_identity") or "")
    if isinstance(parent_pid, bool) or not isinstance(parent_pid, int) or parent_pid <= 0:
        raise UpdateError(
            "invalid_transaction", "The directory update parent process ID is invalid."
        )
    if not SHA256_PATTERN.fullmatch(parent_process_created):
        raise UpdateError(
            "invalid_transaction",
            "The directory update parent process creation identity is invalid.",
        )
    if not SHA256_PATTERN.fullmatch(target_identity):
        raise UpdateError(
            "invalid_transaction", "The directory update target identity is invalid."
        )

    launched_pid = payload.get("launched_pid")
    launched_created = payload.get("launched_process_created")
    if launched_pid is None:
        if launched_created is not None:
            raise UpdateError(
                "invalid_transaction", "The launched process identity is invalid."
            )
    elif (
        isinstance(launched_pid, bool)
        or not isinstance(launched_pid, int)
        or launched_pid <= 0
        or not isinstance(launched_created, str)
        or not SHA256_PATTERN.fullmatch(launched_created)
    ):
        raise UpdateError(
            "invalid_transaction", "The launched process identity is invalid."
        )
    for timestamp_field in ("created_at", "updated_at"):
        timestamp = payload.get(timestamp_field)
        if not isinstance(timestamp, str) or len(timestamp) > 64:
            raise UpdateError(
                "invalid_transaction",
                "The directory update transaction timestamp is invalid.",
            )
        try:
            parsed_timestamp = datetime.fromisoformat(timestamp)
        except ValueError as exc:
            raise UpdateError(
                "invalid_transaction",
                "The directory update transaction timestamp is invalid.",
            ) from exc
        if parsed_timestamp.tzinfo is None:
            raise UpdateError(
                "invalid_transaction",
                "The directory update transaction timestamp is invalid.",
            )

    transaction_dir = path.parent.resolve()
    expected_transaction_dir = (root / version / transaction_id).resolve()
    if transaction_dir != expected_transaction_dir:
        raise UpdateError(
            "invalid_transaction",
            "The directory update transaction directory is invalid.",
        )

    target_root_path = Path(str(payload.get("target_root") or ""))
    target = Path(str(payload.get("target_executable") or ""))
    staged = Path(str(payload.get("staged_root") or "")).resolve()
    backup = Path(str(payload.get("backup_root") or ""))
    old_dir = Path(str(payload.get("old_root") or ""))
    new_dir = Path(str(payload.get("new_root") or ""))
    marker = Path(str(payload.get("startup_marker") or "")).resolve()

    temp_root = Path(temporary_root or tempfile.gettempdir()).resolve()
    if (
        not target_root_path.is_absolute()
        or target_root_path.name in {"", ".", ".."}
        or _is_within(target_root_path, root)
        or _is_within(target_root_path, temp_root)
    ):
        raise UpdateError(
            "invalid_transaction", "The directory update target root is invalid."
        )
    if target != target_root_path / ONEFOLDER_EXECUTABLE_NAME:
        raise UpdateError(
            "invalid_transaction", "The directory update target executable is invalid."
        )
    if normalized_target_identity(target) != target_identity:
        raise UpdateError(
            "target_mismatch",
            "The directory update target executable identity does not match.",
        )
    expected_staged = {
        (transaction_dir / "package" / expected_directory_root_name(version)).resolve(),
        (root / version / "package" / expected_directory_root_name(version)).resolve(),
    }
    if staged not in expected_staged:
        raise UpdateError(
            "invalid_transaction", "The staged update directory is invalid."
        )
    if backup != _sibling_path(target_root_path, transaction_id, "backup"):
        raise UpdateError(
            "invalid_transaction", "The directory update backup path is invalid."
        )
    if old_dir != _sibling_path(target_root_path, transaction_id, "old"):
        raise UpdateError(
            "invalid_transaction", "The directory update old-tree path is invalid."
        )
    if new_dir != _sibling_path(target_root_path, transaction_id, "new"):
        raise UpdateError(
            "invalid_transaction", "The directory update new-tree path is invalid."
        )
    if marker != transaction_dir / STARTUP_MARKER_FILENAME:
        raise UpdateError("invalid_transaction", "The startup marker path is invalid.")

    return DirectoryUpdateTransaction(
        schema_version=DIRECTORY_TRANSACTION_SCHEMA_VERSION,
        transaction_id=transaction_id,
        confirmation_token=confirmation_token,
        state=state,
        expected_version=version,
        manifest_sha256=manifest_hash.lower(),
        backup_inventory_sha256=inventory_hash.lower(),
        qt_policy=qt_policy,
        preserved_files=preserved,
        parent_pid=parent_pid,
        parent_process_created=parent_process_created,
        target_identity=target_identity,
        target_root=str(target_root_path),
        target_executable=str(target),
        staged_root=str(staged),
        backup_root=str(backup),
        old_root=str(old_dir),
        new_root=str(new_dir),
        startup_marker=str(marker),
        created_at=str(payload.get("created_at") or ""),
        updated_at=str(payload.get("updated_at") or ""),
        launched_pid=launched_pid,
        launched_process_created=launched_created,
    )


def load_transaction_manifest(
    transaction: DirectoryUpdateTransaction,
    transaction_path: Path,
) -> DirectoryUpdateManifest:
    """Load the transaction-scoped manifest copy and verify its recorded hash."""
    manifest_path = Path(transaction_path).resolve().parent / DIRECTORY_MANIFEST_FILENAME
    try:
        document = manifest_path.read_bytes()
    except OSError as exc:
        raise UpdateError(
            "invalid_directory_manifest",
            "The directory update manifest copy is missing.",
            technical=str(exc),
        ) from exc
    import hashlib

    if not hmac.compare_digest(
        hashlib.sha256(document).hexdigest(), transaction.manifest_sha256
    ):
        raise UpdateError(
            "invalid_directory_manifest",
            "The directory update manifest copy failed verification.",
        )
    return DirectoryUpdateManifest.from_json(
        document, release_version=transaction.expected_version
    )


def _load_backup_inventory(
    transaction: DirectoryUpdateTransaction,
    transaction_path: Path,
) -> dict[str, str]:
    inventory_path = Path(transaction_path).resolve().parent / BACKUP_INVENTORY_FILENAME
    try:
        document = inventory_path.read_bytes()
    except OSError as exc:
        raise UpdateError(
            "backup_failure",
            "The directory update backup inventory is missing.",
            technical=str(exc),
        ) from exc
    import hashlib

    if not hmac.compare_digest(
        hashlib.sha256(document).hexdigest(), transaction.backup_inventory_sha256
    ):
        raise UpdateError(
            "backup_failure",
            "The directory update backup inventory failed verification.",
        )
    payload = json.loads(document.decode("utf-8"), object_pairs_hook=_strict_json_object)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "transaction_id", "files"}
        or payload.get("schema_version") != 1
        or payload.get("transaction_id") != transaction.transaction_id
        or not isinstance(payload.get("files"), dict)
    ):
        raise UpdateError(
            "backup_failure", "The directory update backup inventory is invalid."
        )
    inventory: dict[str, str] = {}
    for raw_path, raw_hash in payload["files"].items():
        relative = validate_directory_relative_path(raw_path)
        if not isinstance(raw_hash, str) or not SHA256_PATTERN.fullmatch(raw_hash):
            raise UpdateError(
                "backup_failure", "The directory update backup inventory is invalid."
            )
        inventory[relative] = raw_hash.lower()
    if not inventory:
        raise UpdateError(
            "backup_failure", "The directory update backup inventory is empty."
        )
    return inventory


def _verify_tree(
    root: Path,
    expected: dict[str, str],
    *,
    missing_code: str,
    extra_code: str,
    mismatch_code: str,
    sizes: dict[str, int] | None = None,
    cancel_callback: CancelCallback | None = None,
) -> None:
    """Verify that ``root`` holds exactly the expected relative-path hash map."""
    expected_by_casefold = {relative.casefold(): relative for relative in expected}
    seen: set[str] = set()
    for relative, absolute in _walk_regular_files(root):
        if cancel_callback is not None and cancel_callback():
            raise UpdateError("cancelled", "The directory update was cancelled.")
        casefolded = relative.casefold()
        canonical = expected_by_casefold.get(casefolded)
        if canonical is None:
            raise UpdateError(
                extra_code,
                f"The directory tree contains an unexpected file: {relative}",
            )
        seen.add(casefolded)
        if sizes is not None and canonical in sizes and _file_size(absolute) != sizes[canonical]:
            raise UpdateError(
                mismatch_code,
                f"The directory tree file size does not match the manifest: {relative}",
            )
        if not hmac.compare_digest(_hash_file(absolute), expected[canonical]):
            raise UpdateError(
                mismatch_code,
                f"The directory tree file failed SHA-256 verification: {relative}",
            )
    missing = sorted(set(expected_by_casefold) - seen)
    if missing:
        raise UpdateError(
            missing_code,
            "The directory tree is missing required files: "
            + ", ".join(expected_by_casefold[item] for item in missing[:5]),
        )


def _tree_matches(root: Path, expected: dict[str, str]) -> bool:
    try:
        _verify_tree(
            root,
            expected,
            missing_code="tree_mismatch",
            extra_code="tree_mismatch",
            mismatch_code="tree_mismatch",
        )
    except UpdateError:
        return False
    return True


def _expected_target_map(
    manifest: DirectoryUpdateManifest,
    transaction: DirectoryUpdateTransaction,
) -> dict[str, str]:
    expected = {relative: record.sha256 for relative, record in manifest.files.items()}
    expected.update(transaction.preserved_files)
    return expected


def read_qt_component_baseline(target_root: Path) -> dict[str, str] | None:
    """Read the installed Qt/PySide component baseline, or None when unusable."""
    baseline_path = Path(target_root) / QT_COMPONENT_BASELINE_FILENAME
    try:
        payload = _read_json_limited(baseline_path, DIRECTORY_MANIFEST_MAX_BYTES)
    except UpdateError:
        return None
    records = payload.get("files")
    if not isinstance(records, list):
        return None
    baseline: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict):
            return None
        relative = record.get("path")
        sha256_value = record.get("sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(sha256_value, str)
            or not SHA256_PATTERN.fullmatch(sha256_value)
        ):
            return None
        baseline[relative] = sha256_value.lower()
    return baseline or None


def detect_modified_replaceable_files(
    target_root: Path,
    manifest: DirectoryUpdateManifest,
    *,
    baseline: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return replaceable paths whose installed bytes differ from the baseline.

    A missing or unreadable baseline treats every present replaceable file as
    potentially recipient-modified, which keeps overwrite decisions explicit.
    """
    if baseline is None:
        baseline = read_qt_component_baseline(target_root)
    modified: dict[str, str] = {}
    for relative in manifest.replaceable_paths:
        absolute = Path(target_root) / Path(PurePosixPath(relative))
        if not _path_exists(absolute):
            continue
        if _is_reparse_point(absolute):
            raise UpdateError(
                "unsafe_path",
                f"A replaceable library path is a symlink or reparse point: {relative}",
            )
        try:
            current_hash = _hash_file(absolute)
        except OSError:
            continue
        recorded = None if baseline is None else baseline.get(relative)
        if recorded is None or not hmac.compare_digest(current_hash, recorded):
            modified[relative] = current_hash
    return modified


def assess_directory_installation_capability(
    manifest: DirectoryUpdateManifest,
    *,
    target_executable: Path | None = None,
    frozen: bool | None = None,
    updates_root: Path | None = None,
    temporary_root: Path | None = None,
) -> InstallationCapability:
    """Check whether this one-folder installation can be replaced safely."""
    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    if not is_frozen:
        return InstallationCapability(
            False,
            "Automatic installation is available only in the packaged Windows application.",
            code="manual_install_required",
        )
    if sys.platform != "win32":
        return InstallationCapability(
            False,
            "Automatic installation is supported only on Windows.",
            code="wrong_platform",
        )
    target = Path(target_executable or sys.executable).resolve()
    if not target.exists() or not target.is_file():
        return InstallationCapability(
            False,
            "The running application executable could not be found.",
            code="invalid_install_location",
        )
    if target.name != ONEFOLDER_EXECUTABLE_NAME:
        return InstallationCapability(
            False,
            "The running executable does not have the official one-folder filename.",
            code="invalid_install_location",
        )
    target_root = target.parent
    root = Path(updates_root or update_root()).resolve()
    temp_root = Path(temporary_root or tempfile.gettempdir()).resolve()
    if (
        _is_within(target, root)
        or _is_within(target, temp_root)
        or target_root.parent == target_root
    ):
        return InstallationCapability(
            False,
            "The application is running from a temporary or update-staging location.",
            code="invalid_install_location",
        )
    if not _directory_writable(target_root) or not _directory_writable(target_root.parent):
        return InstallationCapability(
            False,
            "The application folder is not writable without elevated permissions.",
            code="insufficient_permissions",
        )
    try:
        current_size = sum(
            _file_size(absolute) for _relative, absolute in _walk_regular_files(target_root)
        )
    except UpdateError as exc:
        return InstallationCapability(False, exc.user_message, code=exc.code)
    except OSError:
        return InstallationCapability(
            False,
            "The installed application folder could not be inventoried.",
            code="invalid_install_location",
        )
    try:
        required = (
            current_size * 2
            + manifest.total_size
            + DIRECTORY_DISK_SPACE_MARGIN_BYTES
        )
        if shutil.disk_usage(target_root.parent).free < required:
            return InstallationCapability(
                False,
                "There is insufficient disk space for staging, backup, and replacement.",
                code="insufficient_disk_space",
            )
    except OSError:
        return InstallationCapability(
            False,
            "Available disk space could not be verified.",
            code="insufficient_disk_space",
        )
    return InstallationCapability(
        True,
        "Automatic one-folder installation is available.",
        target,
        code="available",
    )


def _copy_tree_verified(
    source_root: Path,
    destination_root: Path,
    *,
    cancel_callback: CancelCallback | None = None,
    progress_callback: ProgressCallback | None = None,
    progress_range: tuple[int, int] = (0, 0),
    progress_label: str = "",
) -> dict[str, str]:
    """Copy a directory tree with per-file verification; return the hash map."""
    hashes: dict[str, str] = {}
    entries = list(_walk_regular_files(source_root))
    start_percent, end_percent = progress_range
    for index, (relative, absolute) in enumerate(entries):
        if cancel_callback is not None and cancel_callback():
            raise UpdateError("cancelled", "The directory update was cancelled.")
        destination = Path(destination_root) / Path(PurePosixPath(relative))
        hashes[relative] = _copy_file_verified(absolute, destination)
        if progress_callback is not None and end_percent > start_percent and entries:
            percent = start_percent + int(
                (index + 1) / len(entries) * (end_percent - start_percent)
            )
            progress_callback(percent, progress_label)
    if not hashes:
        raise UpdateError(
            "staging_failure", "The directory update source tree is empty."
        )
    return hashes


def prepare_and_launch_directory_update(
    manifest: DirectoryUpdateManifest,
    staged_package_root: Path,
    *,
    parent_pid: int,
    current_version: str = VERSION,
    qt_policy: QtReplacementPolicy = QtReplacementPolicy.ABORT,
    transaction_id: str | None = None,
    progress_callback: ProgressCallback | None = None,
    cancel_callback: CancelCallback | None = None,
    target_executable: Path | None = None,
    frozen: bool | None = None,
    updates_root: Path | None = None,
    temporary_root: Path | None = None,
    detached_launcher: ProcessLauncher = _default_detached_launcher,
    identity_provider: IdentityProvider = process_creation_identity,
    ownership_manager: UpdateOwnershipManager | None = None,
    handoff_timeout: float = HELPER_HANDOFF_TIMEOUT_SECONDS,
) -> PreparedUpdate:
    """Verify, back up, and hand a one-folder update to the detached helper."""
    if not is_newer_version(manifest.release_version, current_version):
        raise UpdateError(
            "not_newer",
            "The directory update is not newer than the installed version.",
        )
    root = Path(updates_root or update_root()).resolve()
    capability = assess_directory_installation_capability(
        manifest,
        target_executable=target_executable,
        frozen=frozen,
        updates_root=root,
        temporary_root=temporary_root,
    )
    if not capability.available or capability.target_executable is None:
        raise UpdateError(capability.code or "installation_failure", capability.reason)

    transaction_id = transaction_id or new_transaction_id()
    if not TOKEN_PATTERN.fullmatch(transaction_id):
        raise UpdateError("invalid_transaction", "The update transaction ID is invalid.")

    target = capability.target_executable
    target_root = target.parent
    version = manifest.release_version
    staged = Path(staged_package_root).resolve()
    transaction_dir = (root / version / transaction_id).resolve()
    allowed_staged = {
        (transaction_dir / "package" / expected_directory_root_name(version)).resolve(),
        (root / version / "package" / expected_directory_root_name(version)).resolve(),
    }
    if not _is_within(transaction_dir, root) or staged not in allowed_staged:
        raise UpdateError("unsafe_path", "The staged update directory path is invalid.")

    if progress_callback:
        progress_callback(90, "Verifying the staged one-folder update")
    _verify_tree(
        staged,
        {relative: record.sha256 for relative, record in manifest.files.items()},
        sizes={relative: record.size for relative, record in manifest.files.items()},
        missing_code="update_package_incomplete",
        extra_code="update_package_unexpected_file",
        mismatch_code="checksum_mismatch",
        cancel_callback=cancel_callback,
    )

    modified = detect_modified_replaceable_files(target_root, manifest)
    if modified and qt_policy == QtReplacementPolicy.ABORT:
        raise UpdateError(
            "qt_replacement_consent_required",
            "Locally replaced Qt/PySide libraries were found. Choose whether to "
            "keep or replace them before updating: "
            + ", ".join(sorted(modified)[:5]),
        )
    preserved = dict(sorted(modified.items())) if (
        qt_policy == QtReplacementPolicy.PRESERVE
    ) else {}

    parent_process_created = identity_provider(parent_pid)
    if parent_process_created is None:
        raise UpdateError(
            "process_identity_unavailable",
            "The OpenFetch process identity could not be verified.",
        )

    transaction_dir.mkdir(parents=True, exist_ok=True)
    transaction_path = transaction_dir / DIRECTORY_TRANSACTION_FILENAME
    if transaction_path.exists():
        raise UpdateError(
            "invalid_transaction",
            "The directory update transaction already exists and cannot be overwritten.",
        )

    manifest_path = transaction_dir / DIRECTORY_MANIFEST_FILENAME
    manifest_bytes = manifest.to_json().encode("utf-8")
    import hashlib

    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    backup_root = _sibling_path(target_root, transaction_id, "backup")
    marker_path = transaction_dir / STARTUP_MARKER_FILENAME
    manager = ownership_manager or UpdateOwnershipManager(
        root,
        identity_provider=identity_provider,
        log_callback=_append_update_log,
    )
    process: ChildProcess | None = None
    helper_wrapper_identity: str | None = None
    transaction: DirectoryUpdateTransaction | None = None
    backup_created = False

    if progress_callback:
        progress_callback(92, "Backing up the current installation")

    # Reserve ownership before the expensive whole-directory backup so a
    # concurrent updater is rejected without copying anything.
    manager.reserve_handoff(
        transaction_id,
        target,
        parent_pid=parent_pid,
        parent_process_created=parent_process_created,
    )
    try:
        if _path_exists(backup_root):
            raise UpdateError(
                "backup_failure",
                "A previous update backup already exists beside the installation.",
            )
        inventory = _copy_tree_verified(
            target_root,
            backup_root,
            cancel_callback=cancel_callback,
            progress_callback=progress_callback,
            progress_range=(92, 96),
            progress_label="Backing up the current installation",
        )
        backup_created = True
        inventory_payload = {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "files": inventory,
        }
        inventory_bytes = (
            json.dumps(inventory_payload, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        inventory_hash = hashlib.sha256(inventory_bytes).hexdigest()
        _atomic_write_json(transaction_dir / BACKUP_INVENTORY_FILENAME, inventory_payload)
        _atomic_write_json(
            manifest_path,
            json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=_strict_json_object),
        )
        if not hmac.compare_digest(sha256_file(manifest_path), manifest_hash):
            raise UpdateError(
                "staging_failure",
                "The directory update manifest copy could not be verified.",
            )
        if not hmac.compare_digest(
            sha256_file(transaction_dir / BACKUP_INVENTORY_FILENAME), inventory_hash
        ):
            raise UpdateError(
                "backup_failure",
                "The directory update backup inventory could not be verified.",
            )

        import secrets

        timestamp = datetime.now(UTC).isoformat(timespec="milliseconds")
        transaction = DirectoryUpdateTransaction(
            schema_version=DIRECTORY_TRANSACTION_SCHEMA_VERSION,
            transaction_id=transaction_id,
            confirmation_token=secrets.token_urlsafe(48),
            state=TransactionState.VERIFIED.value,
            expected_version=version,
            manifest_sha256=manifest_hash,
            backup_inventory_sha256=inventory_hash,
            qt_policy=qt_policy.value,
            preserved_files=preserved,
            parent_pid=parent_pid,
            parent_process_created=parent_process_created,
            target_identity=normalized_target_identity(target),
            target_root=str(target_root),
            target_executable=str(target),
            staged_root=str(staged),
            backup_root=str(backup_root),
            old_root=str(_sibling_path(target_root, transaction_id, "old")),
            new_root=str(_sibling_path(target_root, transaction_id, "new")),
            startup_marker=str(marker_path),
            created_at=timestamp,
            updated_at=timestamp,
            launched_pid=None,
            launched_process_created=None,
        )
        _atomic_write_json(transaction_path, transaction.to_dict())
        transaction = _transition_directory_transaction(
            transaction_path, transaction, TransactionState.HELPER_PREPARED
        )
        transaction = _transition_directory_transaction(
            transaction_path, transaction, TransactionState.HANDOFF_PENDING
        )
        manager.reserve_handoff(
            transaction_id,
            target,
            parent_pid=parent_pid,
            parent_process_created=parent_process_created,
        )
        transaction = _transition_directory_transaction(
            transaction_path, transaction, TransactionState.HANDED_OFF
        )

        helper = backup_root / ONEFOLDER_EXECUTABLE_NAME
        process = detached_launcher(
            [str(helper), "--apply-directory-update", str(transaction_path)]
        )
        helper_wrapper_identity = identity_provider(process.pid)
        claimed = manager.wait_for_helper_claim(
            transaction_id,
            target,
            timeout=handoff_timeout,
            helper_exited=lambda: process.poll() is not None,
        )
        if progress_callback:
            progress_callback(100, "Updater ready; OpenFetch will restart")
        return PreparedUpdate(claimed.owner_pid, transaction_path, transaction_id)
    except Exception:
        record = manager.read(target)
        helper_claimed = bool(
            record is not None
            and record.transaction_id == transaction_id
            and record.role == OwnershipRole.INSTALLATION.value
            and identity_provider(record.owner_pid) == record.owner_process_created
        )
        if transaction is not None and not helper_claimed:
            with contextlib.suppress(Exception):
                transaction = load_directory_update_transaction(
                    transaction_path,
                    updates_root=root,
                    temporary_root=temporary_root,
                )
                _transition_directory_transaction(
                    transaction_path, transaction, TransactionState.FAILED
                )
        if not helper_claimed and (
            record is None
            or (
                record.transaction_id == transaction_id
                and record.role == OwnershipRole.HANDOFF.value
            )
        ):
            manager.release(transaction_id, target)
            if process is not None:
                _stop_child_process(
                    process,
                    expected_identity=helper_wrapper_identity,
                    identity_provider=identity_provider,
                )
        if not helper_claimed and backup_created:
            with contextlib.suppress(OSError):
                _remove_tree(backup_root)
        raise


class DirectoryUpdateApplier:
    """Apply one validated directory update transaction from the helper copy."""

    def __init__(
        self,
        transaction_path: Path,
        *,
        updates_root: Path | None = None,
        process_exists: ProcessExists | None = None,
        identity_provider: IdentityProvider = process_creation_identity,
        ownership_manager: UpdateOwnershipManager | None = None,
        process_launcher: ProcessLauncher = _default_process_launcher,
        sleep: Sleep = time.sleep,
        monotonic: Monotonic = time.monotonic,
        rename_path: RenamePath = _rename_path,
        message_callback: MessageCallback = _show_native_message,
        parent_exit_timeout: float = PARENT_EXIT_TIMEOUT_SECONDS,
        startup_timeout: float = STARTUP_CONFIRMATION_TIMEOUT_SECONDS,
        temporary_root: Path | None = None,
        fault_hook: Callable[[str], None] | None = None,
        recorded_process_stopper: RecordedProcessStopper | None = None,
    ) -> None:
        self.root = Path(updates_root or update_root()).resolve()
        self.transaction_path = Path(transaction_path).resolve()
        self.transaction = load_directory_update_transaction(
            self.transaction_path,
            updates_root=self.root,
            temporary_root=temporary_root,
        )
        self.manifest = load_transaction_manifest(self.transaction, self.transaction_path)
        self.backup_inventory = _load_backup_inventory(
            self.transaction, self.transaction_path
        )
        self.process_exists = process_exists
        self.identity_provider = identity_provider
        self.ownership = ownership_manager or UpdateOwnershipManager(
            self.root,
            identity_provider=identity_provider,
            sleep=sleep,
            monotonic=monotonic,
            log_callback=_append_update_log,
        )
        self.process_launcher = process_launcher
        self.sleep = sleep
        self.monotonic = monotonic
        self.rename_path = rename_path
        self.message_callback = message_callback
        self.parent_exit_timeout = parent_exit_timeout
        self.startup_timeout = startup_timeout
        self.fault_hook = fault_hook
        self.recorded_process_stopper = recorded_process_stopper or (
            lambda pid, created: _stop_recorded_process(
                pid,
                created,
                identity_provider=self.identity_provider,
            )
        )

    def apply(self) -> int:
        transaction = self.transaction
        target_root = Path(transaction.target_root)
        target = Path(transaction.target_executable)
        staged = Path(transaction.staged_root)
        new_root = Path(transaction.new_root)
        old_root = Path(transaction.old_root)
        marker = Path(transaction.startup_marker)
        target_replaced = False
        new_process: ChildProcess | None = None
        launched_wrapper_identity: str | None = None

        allowed_entry_states = {
            TransactionState.HANDED_OFF,
            TransactionState.WAITING_FOR_PARENT_EXIT,
            TransactionState.BACKING_UP,
            TransactionState.REPLACING,
            TransactionState.LAUNCHING,
            TransactionState.AWAITING_CONFIRMATION,
            TransactionState.CONFIRMED,
            TransactionState.ROLLING_BACK,
            TransactionState.ROLLED_BACK,
            TransactionState.FAILED,
        }
        current_state = TransactionState(transaction.state)
        if current_state not in allowed_entry_states:
            raise UpdateError(
                "invalid_transaction_state",
                "The directory update transaction is not ready for installation handoff.",
            )

        ownership_acquired = False
        try:
            self.ownership.assume_installation(
                transaction.transaction_id,
                target,
                parent_pid=transaction.parent_pid,
                parent_process_created=transaction.parent_process_created,
            )
            ownership_acquired = True
            if current_state == TransactionState.HANDED_OFF:
                self._set_state(TransactionState.WAITING_FOR_PARENT_EXIT)
            else:
                self.ownership.update(
                    transaction.transaction_id,
                    target,
                    current_state,
                )
        except Exception:
            if ownership_acquired:
                with contextlib.suppress(Exception):
                    self.ownership.release(transaction.transaction_id, target)
            raise
        _append_update_log(
            f"Applying directory update {transaction.expected_version}; "
            f"target={target_root.name}; state={transaction.state}"
        )

        try:
            if self.transaction.state == TransactionState.CONFIRMED.value:
                self._release_ownership_safely(target, "confirmed update")
                return 0
            if self.transaction.state == TransactionState.ROLLED_BACK.value:
                self._release_ownership_safely(target, "completed rollback")
                return 3
            if self.transaction.state == TransactionState.FAILED.value:
                raise UpdateError(
                    "invalid_transaction_state",
                    "This directory update transaction already ended in a handled failure.",
                )
            expected_new = _expected_target_map(self.manifest, self.transaction)
            if self.transaction.state in {
                TransactionState.LAUNCHING.value,
                TransactionState.AWAITING_CONFIRMATION.value,
            }:
                confirmation = self._valid_startup_marker(marker)
                if confirmation is not None and _tree_matches(target_root, expected_new):
                    confirmed_pid, confirmed_identity = confirmation
                    if self.transaction.state == TransactionState.LAUNCHING.value:
                        self._set_state(
                            TransactionState.AWAITING_CONFIRMATION,
                            role=OwnershipRole.STARTUP_CONFIRMATION,
                            launched_pid=confirmed_pid,
                            launched_process_created=confirmed_identity,
                        )
                    self._set_state(
                        TransactionState.CONFIRMED,
                        role=OwnershipRole.STARTUP_CONFIRMATION,
                        launched_pid=confirmed_pid,
                        launched_process_created=confirmed_identity,
                    )
                    return self._complete_success(staged, old_root, marker)
                return self._rollback(
                    UpdateError(
                        "startup_confirmation_timeout",
                        "A recovered directory update never confirmed startup; "
                        "the previous version will be restored.",
                    ),
                    None,
                )
            if self.transaction.state == TransactionState.ROLLING_BACK.value:
                return self._rollback(
                    UpdateError(
                        "installation_failure",
                        "A recovered updater rollback will restore the previous version.",
                    ),
                    None,
                )
            if self.transaction.state == TransactionState.REPLACING.value:
                target_replaced = True
                return self._rollback(
                    UpdateError(
                        "installation_failure",
                        "An interrupted directory replacement will be rolled back.",
                    ),
                    None,
                )

            self._verify_staged(staged)
            if self.transaction.state == TransactionState.WAITING_FOR_PARENT_EXIT.value:
                self._wait_for_parent_exit()
                self._set_state(TransactionState.BACKING_UP)
            if marker.exists():
                try:
                    marker.unlink()
                except OSError as exc:
                    raise UpdateError(
                        "stale_confirmation_marker",
                        "A stale startup confirmation marker could not be removed safely.",
                        technical=str(exc),
                    ) from exc

            # The backup copy was created and verified before handoff.  Verify
            # that neither the installation nor the backup drifted afterwards:
            # rollback fidelity depends on both trees still matching the
            # recorded inventory.
            _verify_tree(
                Path(self.transaction.backup_root),
                self.backup_inventory,
                missing_code="backup_failure",
                extra_code="backup_failure",
                mismatch_code="backup_failure",
            )
            _verify_tree(
                target_root,
                self.backup_inventory,
                missing_code="target_drift",
                extra_code="target_drift",
                mismatch_code="target_drift",
            )
            for relative, expected_hash in self.transaction.preserved_files.items():
                preserved_path = target_root / Path(PurePosixPath(relative))
                if not hmac.compare_digest(_hash_file(preserved_path), expected_hash):
                    raise UpdateError(
                        "target_drift",
                        f"A preserved Qt/PySide library changed during the update: {relative}",
                    )

            if _path_exists(new_root):
                with contextlib.suppress(OSError):
                    _remove_tree(new_root)
            _copy_tree_verified(staged, new_root)
            _verify_tree(
                new_root,
                {relative: record.sha256 for relative, record in self.manifest.files.items()},
                missing_code="staging_failure",
                extra_code="staging_failure",
                mismatch_code="staging_failure",
            )
            for relative, expected_hash in self.transaction.preserved_files.items():
                source = target_root / Path(PurePosixPath(relative))
                destination = new_root / Path(PurePosixPath(relative))
                with contextlib.suppress(OSError):
                    os.unlink(_long_path(destination))
                copied_hash = _copy_file_verified(source, destination)
                if not hmac.compare_digest(copied_hash, expected_hash):
                    raise UpdateError(
                        "staging_failure",
                        f"A preserved Qt/PySide library could not be carried forward: {relative}",
                    )

            if self.transaction.state == TransactionState.BACKING_UP.value:
                self._set_state(TransactionState.REPLACING)
            target_replaced = True
            self._rename_with_retry(target_root, old_root)
            try:
                self._rename_with_retry(new_root, target_root)
            except UpdateError:
                # Put the original tree back immediately when the second
                # rename cannot complete; rollback then only cleans up.
                with contextlib.suppress(UpdateError, OSError):
                    self._rename_with_retry(old_root, target_root)
                    target_replaced = False
                raise

            if self.transaction.state == TransactionState.REPLACING.value:
                self._set_state(TransactionState.LAUNCHING)
            try:
                new_process = self.process_launcher(
                    [
                        str(target),
                        "--post-update-transaction",
                        str(self.transaction_path),
                    ]
                )
            except Exception as exc:
                raise UpdateError(
                    "new_version_launch_failure",
                    "The updated application could not be started.",
                    technical=str(exc),
                ) from exc
            launched_wrapper_identity = self.identity_provider(new_process.pid)
            if launched_wrapper_identity is None:
                raise UpdateError(
                    "new_version_launch_failure",
                    "The updated application process identity could not be verified.",
                )
            self._set_state(
                TransactionState.AWAITING_CONFIRMATION,
                role=OwnershipRole.STARTUP_CONFIRMATION,
                launched_pid=new_process.pid,
                launched_process_created=launched_wrapper_identity,
            )
            confirmed_pid, confirmed_identity = self._wait_for_startup_confirmation(
                new_process, marker
            )
            self._set_state(
                TransactionState.CONFIRMED,
                role=OwnershipRole.STARTUP_CONFIRMATION,
                launched_pid=confirmed_pid,
                launched_process_created=confirmed_identity,
            )
            return self._complete_success(staged, old_root, marker)
        except Exception as exc:
            update_error = (
                exc
                if isinstance(exc, UpdateError)
                else UpdateError(
                    "installation_failure",
                    "The directory update installation failed.",
                    str(exc),
                )
            )
            _append_update_log(
                f"Directory update {self.transaction.expected_version} failed: "
                f"{update_error.code}"
            )
            if target_replaced:
                return self._rollback(
                    update_error,
                    new_process,
                    launched_identity=launched_wrapper_identity,
                )
            return self._recover_original_without_replacement(update_error)

    def _set_state(
        self,
        state: TransactionState,
        *,
        role: OwnershipRole = OwnershipRole.INSTALLATION,
        launched_pid: int | None = None,
        launched_process_created: str | None = None,
    ) -> None:
        self.transaction = _transition_directory_transaction(
            self.transaction_path,
            self.transaction,
            state,
            launched_pid=launched_pid,
            launched_process_created=launched_process_created,
        )
        self.ownership.update(
            self.transaction.transaction_id,
            Path(self.transaction.target_executable),
            state,
            role=role,
        )
        _append_update_log(
            f"Directory transaction {self.transaction.transaction_id[:12]} "
            f"state={state.value} owner_pid={os.getpid()}"
        )
        if self.fault_hook is not None:
            self.fault_hook(state.value)

    def _verify_staged(self, staged: Path) -> None:
        _verify_tree(
            staged,
            {relative: record.sha256 for relative, record in self.manifest.files.items()},
            sizes={relative: record.size for relative, record in self.manifest.files.items()},
            missing_code="update_package_incomplete",
            extra_code="update_package_unexpected_file",
            mismatch_code="checksum_mismatch",
        )

    def _wait_for_parent_exit(self) -> None:
        deadline = self.monotonic() + self.parent_exit_timeout
        next_heartbeat = self.monotonic() + 2.0
        identity_query_unavailable_logged = False
        while True:
            if self.process_exists is not None:
                parent_running = self.process_exists(self.transaction.parent_pid)
            else:
                try:
                    current_identity = self.identity_provider(self.transaction.parent_pid)
                except (OSError, PermissionError):
                    current_identity = self.transaction.parent_process_created
                    if not identity_query_unavailable_logged:
                        _append_update_log(
                            "Parent process identity query was unavailable; waiting conservatively"
                        )
                        identity_query_unavailable_logged = True
                parent_running = current_identity == self.transaction.parent_process_created
            if not parent_running:
                return
            if self.monotonic() >= deadline:
                raise UpdateError(
                    "parent_exit_timeout",
                    "OpenFetch did not close in time. The update was not installed.",
                )
            if self.monotonic() >= next_heartbeat:
                self.ownership.update(
                    self.transaction.transaction_id,
                    Path(self.transaction.target_executable),
                    TransactionState.WAITING_FOR_PARENT_EXIT,
                )
                next_heartbeat = self.monotonic() + 2.0
            self.sleep(PROCESS_POLL_INTERVAL_SECONDS)

    def _rename_with_retry(self, source: Path, destination: Path) -> None:
        last_error: OSError | None = None
        for attempt in range(REPLACEMENT_RETRY_COUNT):
            try:
                self.rename_path(source, destination)
                return
            except OSError as exc:
                last_error = exc
                if attempt + 1 < REPLACEMENT_RETRY_COUNT:
                    self.sleep(REPLACEMENT_RETRY_DELAY_SECONDS)
        raise UpdateError(
            "permission_failure"
            if isinstance(last_error, PermissionError)
            else "replacement_failure",
            "Windows could not swap the application folder. Antivirus or a file lock may be blocking it.",
            technical=str(last_error or "rename failed"),
        )

    def _wait_for_startup_confirmation(
        self, process: ChildProcess, marker: Path
    ) -> tuple[int, str]:
        deadline = self.monotonic() + self.startup_timeout
        next_heartbeat = self.monotonic() + 2.0
        while self.monotonic() < deadline:
            confirmation = self._valid_startup_marker(marker) if marker.exists() else None
            if confirmation is not None:
                return confirmation
            if process.poll() is not None:
                raise UpdateError(
                    "new_version_launch_failure",
                    "The updated application exited before startup completed.",
                )
            if self.monotonic() >= next_heartbeat:
                self.ownership.update(
                    self.transaction.transaction_id,
                    Path(self.transaction.target_executable),
                    TransactionState.AWAITING_CONFIRMATION,
                    role=OwnershipRole.STARTUP_CONFIRMATION,
                )
                next_heartbeat = self.monotonic() + 2.0
            self.sleep(PROCESS_POLL_INTERVAL_SECONDS)
        raise UpdateError(
            "startup_confirmation_timeout",
            "The updated application did not confirm startup in time.",
        )

    def _valid_startup_marker(self, marker: Path) -> tuple[int, str] | None:
        try:
            payload = _read_json_limited(marker, MAX_DIRECTORY_TRANSACTION_BYTES)
        except UpdateError:
            return None
        if set(payload) != {
            "transaction_id",
            "confirmation_token",
            "version",
            "status",
            "pid",
            "process_created",
        }:
            return None
        pid = payload.get("pid")
        created = payload.get("process_created")
        if (
            payload.get("transaction_id") != self.transaction.transaction_id
            or payload.get("confirmation_token") != self.transaction.confirmation_token
            or payload.get("version") != self.transaction.expected_version
            or payload.get("status") != "initialized"
            or isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or not isinstance(created, str)
            or not SHA256_PATTERN.fullmatch(created)
            or self.identity_provider(pid) != created
        ):
            return None
        return pid, created

    def _complete_success(self, staged: Path, old_root: Path, marker: Path) -> int:
        result_recorded = True
        try:
            self._write_result("success", "Update installed and startup confirmed.")
        except OSError:
            result_recorded = False
            _append_update_log(
                "Startup succeeded, but the success record could not be written"
            )
        if result_recorded:
            with contextlib.suppress(OSError):
                _remove_tree(old_root)
        with contextlib.suppress(OSError):
            _remove_tree(staged)
        with contextlib.suppress(OSError):
            marker.unlink()
        # The backup tree cannot be removed here: this helper process is
        # running from it.  Startup recovery removes it after confirmation.
        self._release_ownership_safely(
            Path(self.transaction.target_executable),
            "confirmed update",
        )
        _append_update_log(
            f"Directory update {self.transaction.expected_version} confirmed successfully"
        )
        return 0

    def _release_ownership_safely(self, target: Path, outcome: str) -> bool:
        try:
            released = self.ownership.release(self.transaction.transaction_id, target)
        except Exception as exc:
            _append_update_log(
                f"Ownership cleanup after {outcome} was deferred: {type(exc).__name__}"
            )
            return False
        if not released:
            _append_update_log(f"Ownership cleanup after {outcome} was deferred")
        return released

    def _restore_original_tree(self) -> None:
        """Bring the original installation back under the target root."""
        transaction = self.transaction
        target_root = Path(transaction.target_root)
        old_root = Path(transaction.old_root)
        new_root = Path(transaction.new_root)
        backup_root = Path(transaction.backup_root)
        failed_root = _sibling_path(target_root, transaction.transaction_id, "failed")
        restore_root = _sibling_path(target_root, transaction.transaction_id, "restore")

        def remove_redundant_trees() -> None:
            # Every sibling temporary tree is redundant once the target
            # verified against the backup inventory.  This includes ``old``
            # when the swapped-in release is byte-identical to the original,
            # in which case the target already matches without any rename.
            for leftover in (failed_root, new_root, old_root, restore_root):
                if _path_exists(leftover):
                    with contextlib.suppress(OSError):
                        _remove_tree(leftover)

        if _path_exists(target_root) and _tree_matches(target_root, self.backup_inventory):
            remove_redundant_trees()
            return
        if _path_exists(target_root):
            if _path_exists(failed_root):
                with contextlib.suppress(OSError):
                    _remove_tree(failed_root)
            self._rename_with_retry(target_root, failed_root)
        if _path_exists(old_root) and _tree_matches(old_root, self.backup_inventory):
            self._rename_with_retry(old_root, target_root)
        else:
            if not _path_exists(backup_root):
                raise UpdateError(
                    "rollback_failure",
                    "The last known-good backup is missing or invalid.",
                )
            _verify_tree(
                backup_root,
                self.backup_inventory,
                missing_code="rollback_failure",
                extra_code="rollback_failure",
                mismatch_code="rollback_failure",
            )
            if _path_exists(restore_root):
                with contextlib.suppress(OSError):
                    _remove_tree(restore_root)
            _copy_tree_verified(backup_root, restore_root)
            self._rename_with_retry(restore_root, target_root)
        if not _tree_matches(target_root, self.backup_inventory):
            raise UpdateError(
                "rollback_failure", "The restored application failed verification."
            )
        remove_redundant_trees()

    def _rollback(
        self,
        original_error: UpdateError,
        process: ChildProcess | None,
        *,
        launched_identity: str | None = None,
    ) -> int:
        target = Path(self.transaction.target_executable)
        backup_root = Path(self.transaction.backup_root)
        try:
            if self.transaction.state != TransactionState.ROLLING_BACK.value:
                self._set_state(TransactionState.ROLLING_BACK)
            if process is not None:
                _stop_child_process(
                    process,
                    expected_identity=launched_identity,
                    identity_provider=self.identity_provider,
                )
            elif (
                self.transaction.launched_pid is not None
                and self.transaction.launched_process_created is not None
            ):
                self.recorded_process_stopper(
                    self.transaction.launched_pid,
                    self.transaction.launched_process_created,
                )
            self._restore_original_tree()
            with contextlib.suppress(OSError):
                self._write_result(
                    "rollback_succeeded",
                    f"Update failed ({original_error.code}); the previous version was restored.",
                )
            self._set_state(TransactionState.ROLLED_BACK)
            with contextlib.suppress(OSError):
                Path(self.transaction.startup_marker).unlink()
            try:
                try:
                    self.process_launcher(
                        [str(target), "--update-rollback-status", str(self.transaction_path)]
                    )
                except Exception as launch_error:
                    self.message_callback(
                        "OpenFetch Update Recovery",
                        "The previous version was restored but could not be restarted "
                        "automatically. Open OpenFetch again manually.",
                    )
                    _append_update_log(
                        f"Rollback restored the previous version but restart failed: "
                        f"{type(launch_error).__name__}"
                    )
                    return 3
                _append_update_log(
                    "Directory rollback succeeded and the previous version was restarted"
                )
                return 3
            finally:
                self._release_ownership_safely(target, "completed rollback")
        except Exception as rollback_error:
            with contextlib.suppress(OSError):
                self._write_result(
                    "rollback_failed",
                    f"Update failed ({original_error.code}) and rollback failed.",
                )
            with contextlib.suppress(Exception):
                self._set_state(TransactionState.FAILED)
            self._release_ownership_safely(target, "failed rollback")
            self.message_callback(
                "OpenFetch Update Recovery",
                "The update and automatic rollback both failed.\n\n"
                f"Backup retained at:\n{backup_root}\n\n"
                f"Target application:\n{self.transaction.target_root}\n\n"
                "Close OpenFetch, copy the backup folder over the application "
                "folder, and retry later.",
            )
            _append_update_log(f"Directory rollback failed: {type(rollback_error).__name__}")
            return 4

    def _recover_original_without_replacement(self, error: UpdateError) -> int:
        target = Path(self.transaction.target_executable)
        new_root = Path(self.transaction.new_root)
        if _path_exists(new_root):
            with contextlib.suppress(OSError):
                _remove_tree(new_root)
        with contextlib.suppress(Exception):
            self._set_state(TransactionState.FAILED)
        with contextlib.suppress(OSError):
            self._write_result(
                "original_preserved",
                f"Update failed ({error.code}); the original installation was not replaced.",
            )
        if self.process_exists is not None:
            parent_running = self.process_exists(self.transaction.parent_pid)
        else:
            try:
                parent_running = (
                    self.identity_provider(self.transaction.parent_pid)
                    == self.transaction.parent_process_created
                )
            except (OSError, PermissionError):
                parent_running = True
        if not parent_running:
            with contextlib.suppress(Exception):
                self.process_launcher(
                    [str(target), "--update-rollback-status", str(self.transaction_path)]
                )
        self._release_ownership_safely(target, "handled installation failure")
        return 2

    def _write_result(self, status: str, message: str) -> None:
        _atomic_write_json(
            self.transaction_path.parent / RESULT_FILENAME,
            {
                "status": status,
                "message": message,
                "version": self.transaction.expected_version,
                "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            },
        )


def run_directory_update_helper(transaction_path: Path) -> int:
    """Entry point used by the backup helper copy in detached mode."""
    try:
        return DirectoryUpdateApplier(transaction_path).apply()
    except UpdateError as exc:
        _append_update_log(f"Directory updater helper rejected transaction: {exc.code}")
        _show_native_message(
            "OpenFetch Update",
            f"The update could not be applied safely.\n\n{exc.user_message}",
        )
        return 5
    except Exception as exc:
        _append_update_log(f"Directory updater helper failed: {type(exc).__name__}")
        _show_native_message(
            "OpenFetch Update",
            "The update helper encountered an unexpected error. The current "
            "application was not intentionally removed.",
        )
        return 6


def write_directory_startup_confirmation(
    transaction_path: Path,
    *,
    version: str = VERSION,
    updates_root: Path | None = None,
    identity_provider: IdentityProvider = process_creation_identity,
) -> None:
    """Confirm startup of an updated one-folder installation."""
    transaction = load_directory_update_transaction(
        transaction_path,
        updates_root=updates_root,
    )
    if transaction.state not in {
        TransactionState.LAUNCHING.value,
        TransactionState.AWAITING_CONFIRMATION.value,
    }:
        raise UpdateError(
            "invalid_transaction_state",
            "The directory update transaction is not awaiting startup confirmation.",
        )
    if version != transaction.expected_version:
        raise UpdateError(
            "transaction_mismatch",
            "The started application version does not match the update transaction.",
        )
    pid = os.getpid()
    created = identity_provider(pid)
    if created is None or not SHA256_PATTERN.fullmatch(created):
        raise UpdateError(
            "process_identity_unavailable",
            "The started application process identity could not be verified.",
        )
    _atomic_write_json(
        Path(transaction.startup_marker),
        {
            "transaction_id": transaction.transaction_id,
            "confirmation_token": transaction.confirmation_token,
            "version": version,
            "status": "initialized",
            "pid": pid,
            "process_created": created,
        },
    )


def read_directory_update_recovery_message(
    transaction_path: Path,
    *,
    updates_root: Path | None = None,
) -> str:
    root = Path(updates_root or update_root()).resolve()
    path = Path(transaction_path).resolve()
    if not _is_within(path, root) or path.name != DIRECTORY_TRANSACTION_FILENAME:
        return "The previous update failed, but its recovery details could not be validated."
    try:
        payload = _read_json_limited(path.parent / RESULT_FILENAME, MAX_DIRECTORY_TRANSACTION_BYTES)
    except UpdateError:
        return "The previous update failed. The original application remains available."
    status = payload.get("status")
    if status == "rollback_succeeded":
        return (
            "The update failed to start correctly. OpenFetch restored and "
            "restarted the previous version."
        )
    if status == "original_preserved":
        return (
            "The update could not be installed. The original OpenFetch "
            "installation was preserved."
        )
    if status == "rollback_failed":
        return (
            "The update and automatic rollback failed. Use the retained backup "
            "folder described in the updater log."
        )
    return (
        "The previous update did not complete. The current installation was "
        "preserved where possible."
    )


def _ownership_live(
    manager: UpdateOwnershipManager,
    target: Path,
    identity_provider: IdentityProvider,
) -> bool:
    record = manager.read(target)
    if record is None:
        return False
    try:
        return identity_provider(record.owner_pid) == record.owner_process_created
    except (OSError, PermissionError):
        return True


def recover_stale_directory_updates(
    log_callback: Callable[[str], None] | None = None,
    *,
    updates_root: Path | None = None,
    identity_provider: IdentityProvider = process_creation_identity,
    recorded_process_stopper: RecordedProcessStopper | None = None,
    current_executable: Path | None = None,
) -> StaleRecoverySummary:
    """Reconcile directory transactions whose helper process is no longer alive."""
    root = Path(updates_root or update_root()).resolve()

    def log(message: str) -> None:
        _append_update_log(message)
        if log_callback is not None:
            with contextlib.suppress(Exception):
                log_callback(message)

    manager = UpdateOwnershipManager(
        root,
        identity_provider=identity_provider,
        log_callback=log,
    )
    stopper = recorded_process_stopper or (
        lambda pid, created: _stop_recorded_process(
            pid,
            created,
            identity_provider=identity_provider,
        )
    )
    running_from = Path(current_executable or sys.executable).resolve()
    recovered = 0
    for transaction_path in sorted(root.glob(f"*/*/{DIRECTORY_TRANSACTION_FILENAME}")):
        try:
            transaction = load_directory_update_transaction(
                transaction_path, updates_root=root
            )
        except UpdateError:
            continue
        target = Path(transaction.target_executable)
        target_root = Path(transaction.target_root)
        if _ownership_live(manager, target, identity_provider):
            continue
        if _is_within(running_from, target_root):
            log(
                "Directory update recovery was deferred because this process runs "
                "from the affected installation."
            )
            continue
        try:
            if _reconcile_stale_directory_transaction(
                transaction_path,
                transaction,
                updates_root=root,
                identity_provider=identity_provider,
                log_callback=log,
                recorded_process_stopper=stopper,
            ):
                recovered += 1
                manager.release(transaction.transaction_id, target)
        except (UpdateError, OSError) as exc:
            log(
                "Stale directory update recovery retained recovery files after "
                f"{type(exc).__name__}."
            )
    return StaleRecoverySummary(recovered)


def _record_result(transaction_path: Path, status: str, message: str, version: str) -> None:
    _atomic_write_json(
        transaction_path.parent / RESULT_FILENAME,
        {
            "status": status,
            "message": message,
            "version": version,
            "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        },
    )


def _reconcile_stale_directory_transaction(
    transaction_path: Path,
    transaction: DirectoryUpdateTransaction,
    *,
    updates_root: Path,
    identity_provider: IdentityProvider,
    log_callback: Callable[[str], None],
    recorded_process_stopper: RecordedProcessStopper,
) -> bool:
    """Reconcile one dead-helper transaction; return True when ownership may clear."""
    manifest = load_transaction_manifest(transaction, transaction_path)
    inventory = _load_backup_inventory(transaction, transaction_path)
    state = TransactionState(transaction.state)
    target_root = Path(transaction.target_root)
    backup_root = Path(transaction.backup_root)
    old_root = Path(transaction.old_root)
    new_root = Path(transaction.new_root)
    staged = Path(transaction.staged_root)
    marker = Path(transaction.startup_marker)
    failed_root = _sibling_path(target_root, transaction.transaction_id, "failed")
    restore_root = _sibling_path(target_root, transaction.transaction_id, "restore")
    expected_new = _expected_target_map(manifest, transaction)

    target_is_new = _path_exists(target_root) and _tree_matches(target_root, expected_new)
    target_is_original = _path_exists(target_root) and _tree_matches(target_root, inventory)

    def cleanup_temps(*, include_backup: bool) -> None:
        for leftover in (new_root, restore_root, failed_root, staged):
            if _path_exists(leftover):
                with contextlib.suppress(OSError):
                    _remove_tree(leftover)
        with contextlib.suppress(OSError):
            marker.unlink()
        if include_backup and _path_exists(backup_root):
            with contextlib.suppress(OSError):
                _remove_tree(backup_root)

    if state == TransactionState.CONFIRMED:
        if not target_is_new:
            log_callback(
                "Confirmed directory update recovery retained cleanup files because "
                "the installation does not match the confirmed version."
            )
            return False
        with contextlib.suppress(OSError):
            _record_result(
                transaction_path,
                "success",
                "Recovered terminal confirmed-update cleanup.",
                transaction.expected_version,
            )
        cleanup_temps(include_backup=True)
        if _path_exists(old_root):
            with contextlib.suppress(OSError):
                _remove_tree(old_root)
        log_callback("Recovered terminal confirmed directory-update cleanup.")
        return True

    if state in {TransactionState.ROLLED_BACK, TransactionState.FAILED}:
        if not target_is_original:
            log_callback(
                "Terminal directory update recovery retained the backup because the "
                "installation does not match the original version."
            )
            return False
        cleanup_temps(include_backup=True)
        if _path_exists(old_root):
            with contextlib.suppress(OSError):
                _remove_tree(old_root)
        log_callback("Recovered terminal directory-update cleanup.")
        return True

    if state in {TransactionState.LAUNCHING, TransactionState.AWAITING_CONFIRMATION}:
        payload_valid = _valid_directory_startup_marker(
            transaction, identity_provider=identity_provider
        )
        if target_is_new and payload_valid:
            updated = _transition_directory_transaction(
                transaction_path,
                transaction,
                TransactionState.AWAITING_CONFIRMATION
                if state == TransactionState.LAUNCHING
                else TransactionState.CONFIRMED,
            )
            if updated.state != TransactionState.CONFIRMED.value:
                _transition_directory_transaction(
                    transaction_path, updated, TransactionState.CONFIRMED
                )
            _record_result(
                transaction_path,
                "success",
                "Recovered a confirmed directory update after the helper exited.",
                transaction.expected_version,
            )
            cleanup_temps(include_backup=True)
            if _path_exists(old_root):
                with contextlib.suppress(OSError):
                    _remove_tree(old_root)
            log_callback("Recovered confirmed startup after a directory helper exit.")
            return True

    if state in {
        TransactionState.REPLACING,
        TransactionState.LAUNCHING,
        TransactionState.AWAITING_CONFIRMATION,
        TransactionState.ROLLING_BACK,
    }:
        if (
            transaction.launched_pid is not None
            and transaction.launched_process_created is not None
        ):
            recorded_process_stopper(
                transaction.launched_pid, transaction.launched_process_created
            )
        restored = False
        if target_is_original:
            restored = True
        else:
            if _path_exists(target_root):
                if target_is_new or not _tree_matches(target_root, inventory):
                    if _path_exists(failed_root):
                        with contextlib.suppress(OSError):
                            _remove_tree(failed_root)
                    _rename_path(target_root, failed_root)
            if not _path_exists(target_root):
                if _path_exists(old_root) and _tree_matches(old_root, inventory):
                    _rename_path(old_root, target_root)
                    restored = True
                elif _path_exists(backup_root) and _tree_matches(backup_root, inventory):
                    if _path_exists(restore_root):
                        with contextlib.suppress(OSError):
                            _remove_tree(restore_root)
                    _copy_tree_verified(backup_root, restore_root)
                    _rename_path(restore_root, target_root)
                    restored = True
        if not restored:
            log_callback(
                "Stale directory update recovery retained the backup because the "
                "original installation could not be restored safely."
            )
            return False
        if state != TransactionState.ROLLING_BACK:
            transaction = _transition_directory_transaction(
                transaction_path, transaction, TransactionState.ROLLING_BACK
            )
        _transition_directory_transaction(
            transaction_path, transaction, TransactionState.ROLLED_BACK
        )
        _record_result(
            transaction_path,
            "rollback_succeeded",
            "Recovered an interrupted directory replacement after the helper exited.",
            transaction.expected_version,
        )
        cleanup_temps(include_backup=True)
        if _path_exists(old_root):
            with contextlib.suppress(OSError):
                _remove_tree(old_root)
        log_callback("Recovered an interrupted directory replacement.")
        return True

    if target_is_original:
        _transition_directory_transaction(
            transaction_path, transaction, TransactionState.FAILED
        )
        _record_result(
            transaction_path,
            "original_preserved",
            "Recovered stale directory update staging; nothing was replaced.",
            transaction.expected_version,
        )
        cleanup_temps(include_backup=True)
        log_callback("Recovered stale directory update staging.")
        return True

    log_callback(
        "Stale directory update recovery retained all files because the "
        "installation state is unknown."
    )
    return False


def _valid_directory_startup_marker(
    transaction: DirectoryUpdateTransaction,
    *,
    identity_provider: IdentityProvider,
) -> bool:
    try:
        payload = _read_json_limited(
            Path(transaction.startup_marker), MAX_DIRECTORY_TRANSACTION_BYTES
        )
    except UpdateError:
        return False
    pid = payload.get("pid")
    created = payload.get("process_created")
    return bool(
        set(payload)
        == {
            "transaction_id",
            "confirmation_token",
            "version",
            "status",
            "pid",
            "process_created",
        }
        and payload.get("transaction_id") == transaction.transaction_id
        and payload.get("confirmation_token") == transaction.confirmation_token
        and payload.get("version") == transaction.expected_version
        and payload.get("status") == "initialized"
        and isinstance(pid, int)
        and not isinstance(pid, bool)
        and pid > 0
        and isinstance(created, str)
        and SHA256_PATTERN.fullmatch(created)
        and identity_provider(pid) == created
    )


def cleanup_stale_directory_update_state(
    *,
    updates_root: Path | None = None,
    successful_retention_days: int = 7,
) -> None:
    """Remove only terminal, result-recorded directory transaction metadata."""
    root = Path(updates_root or update_root()).resolve()
    if not root.exists():
        return
    cutoff = time.time() - successful_retention_days * 24 * 60 * 60
    ownership_dir = root / "ownership"
    for transaction_path in root.glob(f"*/*/{DIRECTORY_TRANSACTION_FILENAME}"):
        try:
            transaction = load_directory_update_transaction(
                transaction_path, updates_root=root
            )
        except UpdateError:
            continue
        if transaction.state not in {
            TransactionState.CONFIRMED.value,
            TransactionState.ROLLED_BACK.value,
            TransactionState.FAILED.value,
        }:
            continue
        if (ownership_dir / f"{transaction.target_identity}.json").exists():
            continue
        result_path = transaction_path.parent / RESULT_FILENAME
        try:
            if not result_path.is_file() or result_path.stat().st_mtime >= cutoff:
                continue
        except OSError:
            continue
        leftovers = [
            Path(transaction.backup_root),
            Path(transaction.old_root),
            Path(transaction.new_root),
            _sibling_path(
                Path(transaction.target_root), transaction.transaction_id, "failed"
            ),
            _sibling_path(
                Path(transaction.target_root), transaction.transaction_id, "restore"
            ),
        ]
        if any(_path_exists(path) for path in leftovers):
            continue
        transaction_dir = transaction_path.parent.resolve()
        if _is_within(transaction_dir, root):
            with contextlib.suppress(OSError):
                shutil.rmtree(transaction_dir)
