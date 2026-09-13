"""Detached Windows update installation, startup confirmation, and rollback."""

from __future__ import annotations

import contextlib
import ctypes
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from openfetch.config import VERSION, app_data_dir, environment_value, legacy_app_data_dir
from openfetch.core.process_control import process_creation_identity
from openfetch.core.update_manifest import (
    LEGACY_RELEASE,
    MAX_UPDATE_SIZE_BYTES,
    MIN_UPDATE_SIZE_BYTES,
    SHA256_PATTERN,
    UpdateManifest,
    expected_exe_filename,
    parse_numeric_version,
    sha256_file,
)
from openfetch.core.update_ownership import (
    LEGACY_INSTALL_LOCK_FILENAME,
    OwnershipRole,
    TransactionState,
    UpdateOwnershipManager,
    new_transaction_id,
    normalized_target_identity,
)
from openfetch.core.updater import ProgressCallback, UpdateError, UpdateInfo

TRANSACTION_SCHEMA_VERSION = 2
MAX_TRANSACTION_BYTES = 64 * 1024
UPDATE_HELPER_FILENAME = "OpenFetch-Updater.exe"
TRANSACTION_FILENAME = "transaction.json"
RESULT_FILENAME = "result.json"
STARTUP_MARKER_FILENAME = "startup-confirmation.json"
INSTALL_LOCK_FILENAME = LEGACY_INSTALL_LOCK_FILENAME


def _bounded_environment_seconds(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(environment_value(name) or str(default))
    except ValueError:
        return default
    return min(maximum, max(minimum, value))


PARENT_EXIT_TIMEOUT_SECONDS = 90
STARTUP_CONFIRMATION_TIMEOUT_SECONDS = _bounded_environment_seconds(
    "UPDATER_STARTUP_TIMEOUT_SECONDS",
    60,
    3,
    300,
)
PROCESS_POLL_INTERVAL_SECONDS = 0.25
REPLACEMENT_RETRY_COUNT = 20
REPLACEMENT_RETRY_DELAY_SECONDS = 0.5
ORIGINAL_RECOVERY_GRACE_SECONDS = 5
DISK_SPACE_MARGIN_BYTES = 64 * 1024 * 1024
HELPER_HANDOFF_TIMEOUT_SECONDS = 45

TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
# An installation upgraded in place from Neural Extractor V3 keeps its original
# executable filename (shortcuts point at it), so both names are official.
OFFICIAL_EXECUTABLE_PATTERN = re.compile(
    r"^(?:OpenFetch|NeuralExtractorV3)(?:-\d+\.\d+\.\d+-windows-x64)?\.exe$",
    re.IGNORECASE,
)

ProcessExists = Callable[[int], bool]
IdentityProvider = Callable[[int], str | None]
Sleep = Callable[[float], None]
Monotonic = Callable[[], float]
ReplaceFile = Callable[[str | Path, str | Path], None]
MessageCallback = Callable[[str, str], None]
RecordedProcessStopper = Callable[[int, str], None]


class ChildProcess(Protocol):
    pid: int

    def poll(self) -> int | None:
        ...

    def terminate(self) -> None:
        ...

    def kill(self) -> None:
        ...

    def wait(self, timeout: float | None = None) -> int:
        ...


ProcessLauncher = Callable[[list[str]], ChildProcess]


@dataclass(frozen=True, slots=True)
class InstallationCapability:
    available: bool
    reason: str
    target_executable: Path | None = None
    code: str = ""


@dataclass(frozen=True, slots=True)
class PreparedUpdate:
    helper_pid: int
    transaction_path: Path
    transaction_id: str


@dataclass(frozen=True, slots=True)
class StaleRecoverySummary:
    recovered_count: int
    shutdown_required: bool = False


@dataclass(frozen=True, slots=True)
class _ReconcileOutcome:
    release_ownership: bool
    shutdown_required: bool = False


@dataclass(frozen=True, slots=True)
class UpdateTransaction:
    schema_version: int
    transaction_id: str
    confirmation_token: str
    state: str
    expected_version: str
    expected_sha256: str
    expected_size: int
    original_sha256: str
    parent_pid: int
    parent_process_created: str
    target_identity: str
    target_executable: str
    staged_executable: str
    backup_executable: str
    startup_marker: str
    created_at: str
    updated_at: str
    launched_pid: int | None
    launched_process_created: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def token(self) -> str:
        """Compatibility alias for the transaction ID used by older call sites."""

        return self.transaction_id


TRANSACTION_FIELDS = {
    "schema_version",
    "transaction_id",
    "confirmation_token",
    "state",
    "expected_version",
    "expected_sha256",
    "expected_size",
    "original_sha256",
    "parent_pid",
    "parent_process_created",
    "target_identity",
    "target_executable",
    "staged_executable",
    "backup_executable",
    "startup_marker",
    "created_at",
    "updated_at",
    "launched_pid",
    "launched_process_created",
}

ALLOWED_STATE_TRANSITIONS: dict[str, set[str]] = {
    TransactionState.VERIFIED.value: {TransactionState.HELPER_PREPARED.value},
    TransactionState.HELPER_PREPARED.value: {TransactionState.HANDOFF_PENDING.value},
    TransactionState.HANDOFF_PENDING.value: {TransactionState.HANDED_OFF.value},
    TransactionState.HANDED_OFF.value: {TransactionState.WAITING_FOR_PARENT_EXIT.value},
    TransactionState.WAITING_FOR_PARENT_EXIT.value: {TransactionState.BACKING_UP.value},
    TransactionState.BACKING_UP.value: {
        TransactionState.REPLACING.value,
        TransactionState.ROLLING_BACK.value,
    },
    TransactionState.REPLACING.value: {
        TransactionState.LAUNCHING.value,
        TransactionState.ROLLING_BACK.value,
    },
    TransactionState.LAUNCHING.value: {
        TransactionState.AWAITING_CONFIRMATION.value,
        TransactionState.ROLLING_BACK.value,
    },
    TransactionState.AWAITING_CONFIRMATION.value: {
        TransactionState.CONFIRMED.value,
        TransactionState.ROLLING_BACK.value,
    },
    TransactionState.ROLLING_BACK.value: {TransactionState.ROLLED_BACK.value},
}
for _state in TransactionState:
    if _state not in {TransactionState.CONFIRMED, TransactionState.ROLLED_BACK}:
        ALLOWED_STATE_TRANSITIONS.setdefault(_state.value, set()).add(TransactionState.FAILED.value)


def update_root() -> Path:
    root = (app_data_dir() / "updates").resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def legacy_update_root() -> Path:
    """Return the Neural Extractor V3 updates root without creating it."""
    return (legacy_app_data_dir() / "updates").resolve()


def _transaction_updates_root(transaction_path: Path) -> Path:
    """Return the updates root that owns a transaction reference.

    An installed Neural Extractor V3 updater keeps its transaction below the
    legacy data directory and then starts OpenFetch to confirm startup. That
    confirmation must be accepted, otherwise the legacy helper rolls back.
    """
    if _is_within(Path(transaction_path), legacy_update_root()):
        return legacy_update_root()
    return update_root()


def _is_within(path: Path, root: Path) -> bool:
    path = path.resolve()
    root = root.resolve()
    return path == root or root in path.parents


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UpdateError(
                "invalid_transaction",
                f"Duplicate update transaction field: {key}",
            )
        result[key] = value
    return result


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _copy_file_sync(source: Path, destination: Path) -> None:
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_handle, destination.open("xb") as output_handle:
        while chunk := input_handle.read(1024 * 1024):
            output_handle.write(chunk)
        output_handle.flush()
        os.fsync(output_handle.fileno())
    shutil.copystat(source, destination, follow_symlinks=True)


def _directory_writable(directory: Path) -> bool:
    probe = Path(directory) / f".openfetch-write-{secrets.token_hex(8)}.tmp"
    try:
        with probe.open("xb") as handle:
            handle.write(b"ok")
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            probe.unlink()


def _official_target_name(name: str) -> bool:
    return bool(OFFICIAL_EXECUTABLE_PATTERN.fullmatch(name))


def assess_installation_capability(
    manifest: UpdateManifest,
    *,
    target_executable: Path | None = None,
    frozen: bool | None = None,
    updates_root: Path | None = None,
    temporary_root: Path | None = None,
) -> InstallationCapability:
    """Check whether this process can safely self-replace without elevation."""
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
    if not _official_target_name(target.name):
        return InstallationCapability(
            False,
            "The running executable does not have an official OpenFetch filename.",
            code="invalid_install_location",
        )

    root = Path(updates_root or update_root()).resolve()
    temp_root = Path(temporary_root or tempfile.gettempdir()).resolve()
    meipass = (
        Path(str(getattr(sys, "_MEIPASS", ""))).resolve()
        if getattr(sys, "_MEIPASS", None)
        else None
    )
    onefolder_runtime = meipass is not None and meipass == target.parent
    if (
        _is_within(target, root)
        or _is_within(target, temp_root)
        or (
            meipass is not None
            and not onefolder_runtime
            and _is_within(target, meipass)
        )
    ):
        return InstallationCapability(
            False,
            "The application is running from a temporary or update-staging location.",
            code="invalid_install_location",
        )

    # The established updater transaction replaces one file.  Treating an
    # externally replaceable one-folder installation as that legacy layout
    # would leave old Python/Qt files behind and could silently overwrite a
    # recipient's LGPL replacement later.  Keep automatic installation
    # fail-closed until the separately reviewed directory transaction is wired
    # in; downloading and manual, consent-based replacement remain available.
    if onefolder_runtime:
        return InstallationCapability(
            False,
            "This compliance-friendly one-folder installation requires a "
            "manual directory update so locally replaced Qt/PySide libraries "
            "are not overwritten without explicit consent.",
            target,
            code="onefolder_manual_install_required",
        )

    if not _directory_writable(target.parent):
        return InstallationCapability(
            False,
            "The application folder is not writable without elevated permissions.",
            code="insufficient_permissions",
        )

    try:
        current_size = target.stat().st_size
        staged_candidate = root / manifest.release_version / "package" / manifest.asset_filename
        staged_size = (
            manifest.asset_size
            if staged_candidate.exists()
            and staged_candidate.is_file()
            and staged_candidate.stat().st_size == manifest.asset_size
            else 0
        )
        missing_staging_space = manifest.asset_size - staged_size
        required_target_space = current_size + manifest.asset_size + DISK_SPACE_MARGIN_BYTES
        required_staging_space = missing_staging_space + current_size + DISK_SPACE_MARGIN_BYTES

        root.mkdir(parents=True, exist_ok=True)
        target_usage = shutil.disk_usage(target.parent)
        root_usage = shutil.disk_usage(root)
        same_volume = target.parent.stat().st_dev == root.stat().st_dev
        if same_volume:
            combined_required = (
                missing_staging_space
                + current_size * 2
                + manifest.asset_size
                + DISK_SPACE_MARGIN_BYTES
            )
            if target_usage.free < combined_required:
                return InstallationCapability(
                    False,
                    "There is insufficient disk space for staging, backup, and replacement.",
                    code="insufficient_disk_space",
                )
        elif target_usage.free < required_target_space:
            return InstallationCapability(
                False,
                "There is insufficient disk space in the application folder.",
                code="insufficient_disk_space",
            )
        if not same_volume and root_usage.free < required_staging_space:
            return InstallationCapability(
                False,
                "There is insufficient disk space for update staging.",
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
        "Automatic installation is available.",
        target,
        code="available",
    )


def _default_detached_launcher(arguments: list[str]) -> ChildProcess:
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    return subprocess.Popen(  # noqa: S603 - arguments are internally constructed and validated
        arguments,
        shell=False,
        close_fds=True,
        creationflags=creation_flags,
    )


def _default_process_launcher(arguments: list[str]) -> ChildProcess:
    return subprocess.Popen(  # noqa: S603 - arguments are internally constructed and validated
        arguments,
        shell=False,
        close_fds=True,
    )


def _stop_child_process(
    process: ChildProcess,
    *,
    expected_identity: str | None = None,
    identity_provider: IdentityProvider = process_creation_identity,
) -> None:
    if process.poll() is not None:
        return
    if expected_identity is not None and identity_provider(process.pid) != expected_identity:
        return
    if sys.platform == "win32":
        taskkill = str(
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
        )
        subprocess.run(  # noqa: S603 - exact validated PID, no shell
            [taskkill, "/PID", str(process.pid), "/T", "/F"],
            shell=False,
            check=False,
            capture_output=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)
    else:
        with contextlib.suppress(Exception):
            process.terminate()
            process.wait(timeout=10)
    if process.poll() is None:
        if expected_identity is not None and identity_provider(process.pid) != expected_identity:
            return
        process.kill()
        process.wait(timeout=5)
    if expected_identity is not None and identity_provider(process.pid) == expected_identity:
        raise UpdateError(
            "rollback_failure",
            "The updated application process tree could not be stopped safely.",
        )


def _stop_recorded_process(
    pid: int,
    expected_identity: str,
    *,
    identity_provider: IdentityProvider = process_creation_identity,
) -> None:
    """Stop only the exact previously recorded process lifetime."""

    if pid <= 0 or identity_provider(pid) != expected_identity:
        return
    if sys.platform == "win32":
        taskkill = str(
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
        )
        subprocess.run(  # noqa: S603 - exact PID plus creation identity, no shell
            [taskkill, "/PID", str(pid), "/T", "/F"],
            shell=False,
            check=False,
            capture_output=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.monotonic() + 10
        while identity_provider(pid) == expected_identity and time.monotonic() < deadline:
            time.sleep(PROCESS_POLL_INTERVAL_SECONDS)
        if identity_provider(pid) == expected_identity:
            raise UpdateError(
                "rollback_failure",
                "The recorded updated application process tree could not be stopped safely.",
            )
        return
    with contextlib.suppress(OSError):
        os.kill(pid, 15)
    deadline = time.monotonic() + 10
    while identity_provider(pid) == expected_identity and time.monotonic() < deadline:
        time.sleep(PROCESS_POLL_INTERVAL_SECONDS)
    if identity_provider(pid) == expected_identity:
        with contextlib.suppress(OSError):
            os.kill(pid, 9)


def _process_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        process_query_limited_information = 0x1000
        still_active = 259
        handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
            process_query_limited_information,
            False,
            pid,
        )
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(  # type: ignore[attr-defined]
                handle,
                ctypes.byref(exit_code),
            ):
                return False
            return exit_code.value == still_active
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _show_native_message(title: str, message: str) -> None:
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                None,
                message,
                title,
                0x00000010,
            )


def _append_update_log(message: str) -> None:
    log_path = app_data_dir() / "updates" / "updater.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    with contextlib.suppress(OSError):
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        candidate = Path(path)
        if candidate.stat().st_size > MAX_TRANSACTION_BYTES:
            raise UpdateError(
                "invalid_transaction",
                "The update transaction file is too large.",
            )
        payload = json.loads(
            candidate.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except UpdateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UpdateError("invalid_transaction", "The update transaction file is invalid.") from exc
    if not isinstance(payload, dict):
        raise UpdateError("invalid_transaction", "The update transaction file is invalid.")
    return payload


def _transition_transaction(
    transaction_path: Path,
    transaction: UpdateTransaction,
    state: TransactionState,
    *,
    launched_pid: int | None = None,
    launched_process_created: str | None = None,
) -> UpdateTransaction:
    current_state = transaction.state
    if state.value != current_state and state.value not in ALLOWED_STATE_TRANSITIONS.get(
        current_state, set()
    ):
        raise UpdateError(
            "invalid_transaction_state",
            f"The update transaction cannot move from {current_state} to {state.value}.",
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


def _rebind_transaction_parent(
    transaction_path: Path,
    transaction: UpdateTransaction,
    *,
    parent_pid: int,
    parent_process_created: str,
) -> UpdateTransaction:
    updated = replace(
        transaction,
        parent_pid=parent_pid,
        parent_process_created=parent_process_created,
        updated_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
    )
    _atomic_write_json(transaction_path, updated.to_dict())
    return updated


def prepare_and_launch_update(
    info: UpdateInfo,
    staged_executable: Path,
    *,
    parent_pid: int,
    transaction_id: str | None = None,
    progress_callback: ProgressCallback | None = None,
    target_executable: Path | None = None,
    frozen: bool | None = None,
    updates_root: Path | None = None,
    temporary_root: Path | None = None,
    helper_root: Path | None = None,
    detached_launcher: ProcessLauncher = _default_detached_launcher,
    identity_provider: IdentityProvider = process_creation_identity,
    ownership_manager: UpdateOwnershipManager | None = None,
    handoff_timeout: float = HELPER_HANDOFF_TIMEOUT_SECONDS,
) -> PreparedUpdate:
    root = Path(updates_root or update_root()).resolve()
    capability = assess_installation_capability(
        info.manifest,
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
    staged = Path(staged_executable).resolve()
    transaction_dir = (root / info.version / transaction_id).resolve()
    expected_name = expected_exe_filename(info.version)
    scoped_staged = (transaction_dir / "package" / expected_name).resolve()
    legacy_staged = (root / info.version / "package" / expected_name).resolve()
    if (
        not _is_within(transaction_dir, root)
        or staged not in {scoped_staged, legacy_staged}
    ):
        raise UpdateError("unsafe_path", "The staged update path is invalid.")
    if not staged.exists() or staged.stat().st_size != info.manifest.asset_size:
        raise UpdateError("file_size_mismatch", "The staged update package size is invalid.")
    if not hmac.compare_digest(sha256_file(staged), info.manifest.asset_sha256):
        raise UpdateError("checksum_mismatch", "The staged update checksum is invalid.")

    parent_process_created = identity_provider(parent_pid)
    if parent_process_created is None:
        raise UpdateError(
            "process_identity_unavailable",
            "The OpenFetch process identity could not be verified.",
    )

    transaction_dir.mkdir(parents=True, exist_ok=True)
    transaction_path = transaction_dir / TRANSACTION_FILENAME
    if transaction_path.exists():
        raise UpdateError(
            "invalid_transaction",
            "The update transaction already exists and cannot be overwritten.",
        )

    target_identity = normalized_target_identity(target)
    helper_base = Path(helper_root or (app_data_dir() / "updater-helper")).resolve()
    helper_dir = (helper_base / target_identity / transaction_id).resolve()
    helper_dir.mkdir(parents=True, exist_ok=True)
    helper = helper_dir / UPDATE_HELPER_FILENAME
    helper_temp = helper_dir / f".{UPDATE_HELPER_FILENAME}.{secrets.token_hex(8)}.tmp"
    marker_path = transaction_dir / STARTUP_MARKER_FILENAME
    backup_path = target.parent / f".{target.name}.{transaction_id}.backup"
    manager = ownership_manager or UpdateOwnershipManager(
        root,
        identity_provider=identity_provider,
        log_callback=_append_update_log,
    )
    process: ChildProcess | None = None
    helper_wrapper_identity: str | None = None
    transaction: UpdateTransaction | None = None

    if progress_callback:
        progress_callback(92, "Preparing detached updater")

    try:
        _copy_file_sync(target, helper_temp)
        if not hmac.compare_digest(sha256_file(helper_temp), sha256_file(target)):
            raise UpdateError("staging_failure", "The detached updater copy could not be verified.")
        os.replace(helper_temp, helper)

        timestamp = datetime.now(UTC).isoformat(timespec="milliseconds")
        transaction = UpdateTransaction(
            schema_version=TRANSACTION_SCHEMA_VERSION,
            transaction_id=transaction_id,
            confirmation_token=secrets.token_urlsafe(48),
            state=TransactionState.VERIFIED.value,
            expected_version=info.version,
            expected_sha256=info.manifest.asset_sha256,
            expected_size=info.manifest.asset_size,
            original_sha256=sha256_file(target),
            parent_pid=parent_pid,
            parent_process_created=parent_process_created,
            target_identity=target_identity,
            target_executable=str(target),
            staged_executable=str(staged),
            backup_executable=str(backup_path),
            startup_marker=str(marker_path),
            created_at=timestamp,
            updated_at=timestamp,
            launched_pid=None,
            launched_process_created=None,
        )
        _atomic_write_json(transaction_path, transaction.to_dict())
        transaction = _transition_transaction(
            transaction_path, transaction, TransactionState.HELPER_PREPARED
        )
        transaction = _transition_transaction(
            transaction_path, transaction, TransactionState.HANDOFF_PENDING
        )
        manager.reserve_handoff(
            transaction_id,
            target,
            parent_pid=parent_pid,
            parent_process_created=parent_process_created,
        )
        transaction = _transition_transaction(
            transaction_path, transaction, TransactionState.HANDED_OFF
        )

        process = detached_launcher([str(helper), "--apply-update", str(transaction_path)])
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
                transaction = load_update_transaction(
                    transaction_path,
                    updates_root=root,
                    temporary_root=temporary_root,
                )
                transaction = _transition_transaction(
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
        with contextlib.suppress(OSError):
            helper_temp.unlink()
        if not helper_claimed:
            with contextlib.suppress(OSError):
                shutil.rmtree(helper_dir)
        raise


def load_update_transaction(
    transaction_path: Path,
    *,
    updates_root: Path | None = None,
    temporary_root: Path | None = None,
) -> UpdateTransaction:
    root = Path(updates_root or update_root()).resolve()
    path = Path(transaction_path).resolve()
    if not _is_within(path, root) or path.name != TRANSACTION_FILENAME:
        raise UpdateError("invalid_transaction", "The update transaction path is unsafe.")
    payload = _read_json(path)
    if set(payload) != TRANSACTION_FIELDS:
        raise UpdateError("invalid_transaction", "The update transaction fields are invalid.")
    if payload.get("schema_version") != TRANSACTION_SCHEMA_VERSION:
        raise UpdateError("invalid_transaction", "The update transaction schema is unsupported.")

    transaction_id = str(payload.get("transaction_id") or "")
    confirmation_token = str(payload.get("confirmation_token") or "")
    if not TOKEN_PATTERN.fullmatch(transaction_id):
        raise UpdateError("invalid_transaction", "The update transaction ID is invalid.")
    if not TOKEN_PATTERN.fullmatch(confirmation_token):
        raise UpdateError("invalid_transaction", "The startup confirmation token is invalid.")
    state = str(payload.get("state") or "")
    if state not in {item.value for item in TransactionState}:
        raise UpdateError("invalid_transaction", "The update transaction state is invalid.")
    version = str(payload.get("expected_version") or "")
    try:
        parse_numeric_version(version)
    except ValueError as exc:
        raise UpdateError(
            "invalid_transaction", "The update transaction version is invalid."
        ) from exc

    expected_hash = str(payload.get("expected_sha256") or "")
    original_hash = str(payload.get("original_sha256") or "")
    if not SHA256_PATTERN.fullmatch(expected_hash) or not SHA256_PATTERN.fullmatch(original_hash):
        raise UpdateError("invalid_transaction", "The update transaction checksum is invalid.")
    size = payload.get("expected_size")
    parent_pid = payload.get("parent_pid")
    parent_process_created = str(payload.get("parent_process_created") or "")
    target_identity = str(payload.get("target_identity") or "")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not MIN_UPDATE_SIZE_BYTES <= size <= MAX_UPDATE_SIZE_BYTES
    ):
        raise UpdateError("invalid_transaction", "The update transaction size is invalid.")
    if isinstance(parent_pid, bool) or not isinstance(parent_pid, int) or parent_pid <= 0:
        raise UpdateError("invalid_transaction", "The update parent process ID is invalid.")
    if not SHA256_PATTERN.fullmatch(parent_process_created):
        raise UpdateError(
            "invalid_transaction", "The update parent process creation identity is invalid."
        )
    if not SHA256_PATTERN.fullmatch(target_identity):
        raise UpdateError("invalid_transaction", "The update target identity is invalid.")

    launched_pid = payload.get("launched_pid")
    launched_created = payload.get("launched_process_created")
    if launched_pid is None:
        if launched_created is not None:
            raise UpdateError("invalid_transaction", "The launched process identity is invalid.")
    elif (
        isinstance(launched_pid, bool)
        or not isinstance(launched_pid, int)
        or launched_pid <= 0
        or not isinstance(launched_created, str)
        or not SHA256_PATTERN.fullmatch(launched_created)
    ):
        raise UpdateError("invalid_transaction", "The launched process identity is invalid.")
    for timestamp_field in ("created_at", "updated_at"):
        timestamp = payload.get(timestamp_field)
        if not isinstance(timestamp, str) or len(timestamp) > 64:
            raise UpdateError("invalid_transaction", "The update transaction timestamp is invalid.")
        try:
            parsed_timestamp = datetime.fromisoformat(timestamp)
        except ValueError as exc:
            raise UpdateError(
                "invalid_transaction", "The update transaction timestamp is invalid."
            ) from exc
        if parsed_timestamp.tzinfo is None:
            raise UpdateError("invalid_transaction", "The update transaction timestamp is invalid.")

    transaction_dir = path.parent.resolve()
    expected_transaction_dir = (root / version / transaction_id).resolve()
    if transaction_dir != expected_transaction_dir:
        raise UpdateError("invalid_transaction", "The update transaction directory is invalid.")

    target = Path(str(payload.get("target_executable") or "")).resolve()
    staged = Path(str(payload.get("staged_executable") or "")).resolve()
    backup = Path(str(payload.get("backup_executable") or "")).resolve()
    marker = Path(str(payload.get("startup_marker") or "")).resolve()

    temp_root = Path(temporary_root or tempfile.gettempdir()).resolve()
    if (
        not target.exists()
        or not target.is_file()
        or not _official_target_name(target.name)
        or _is_within(target, root)
        or _is_within(target, temp_root)
    ):
        raise UpdateError("invalid_transaction", "The update target executable is invalid.")
    if normalized_target_identity(target) != target_identity:
        raise UpdateError(
            "target_mismatch", "The update target executable identity does not match."
        )
    if not _directory_writable(target.parent):
        raise UpdateError("invalid_transaction", "The update target directory is not writable.")
    try:
        required_space = target.stat().st_size + size + DISK_SPACE_MARGIN_BYTES
        if shutil.disk_usage(target.parent).free < required_space:
            raise UpdateError(
                "insufficient_disk_space",
                "There is insufficient disk space to apply the staged update safely.",
            )
    except OSError as exc:
        raise UpdateError(
            "insufficient_disk_space",
            "Available disk space could not be verified before installation.",
        ) from exc
    # Transactions written by an installed Neural Extractor V3 stage the
    # legacy-named copy of the same release executable.
    allowed_names = {
        expected_exe_filename(version),
        expected_exe_filename(version, LEGACY_RELEASE),
    }
    allowed_staged = {
        (package_root / name).resolve()
        for package_root in (transaction_dir / "package", root / version / "package")
        for name in allowed_names
    }
    if staged not in allowed_staged:
        raise UpdateError("invalid_transaction", "The staged update executable is invalid.")
    if backup != target.parent / f".{target.name}.{transaction_id}.backup":
        raise UpdateError("invalid_transaction", "The update backup path is invalid.")
    if marker != transaction_dir / STARTUP_MARKER_FILENAME:
        raise UpdateError("invalid_transaction", "The startup marker path is invalid.")

    return UpdateTransaction(
        schema_version=TRANSACTION_SCHEMA_VERSION,
        transaction_id=transaction_id,
        confirmation_token=confirmation_token,
        state=state,
        expected_version=version,
        expected_sha256=expected_hash.lower(),
        expected_size=size,
        original_sha256=original_hash.lower(),
        parent_pid=parent_pid,
        parent_process_created=parent_process_created,
        target_identity=target_identity,
        target_executable=str(target),
        staged_executable=str(staged),
        backup_executable=str(backup),
        startup_marker=str(marker),
        created_at=str(payload.get("created_at") or ""),
        updated_at=str(payload.get("updated_at") or ""),
        launched_pid=launched_pid,
        launched_process_created=launched_created,
    )


class UpdateApplier:
    """Apply one validated update transaction from the detached helper process."""

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
        replace_file: ReplaceFile = os.replace,
        message_callback: MessageCallback = _show_native_message,
        parent_exit_timeout: float = PARENT_EXIT_TIMEOUT_SECONDS,
        startup_timeout: float = STARTUP_CONFIRMATION_TIMEOUT_SECONDS,
        temporary_root: Path | None = None,
        fault_hook: Callable[[str], None] | None = None,
        recorded_process_stopper: RecordedProcessStopper | None = None,
    ) -> None:
        self.root = Path(updates_root or update_root()).resolve()
        self.transaction_path = Path(transaction_path).resolve()
        self.transaction = load_update_transaction(
            self.transaction_path,
            updates_root=self.root,
            temporary_root=temporary_root,
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
        self.replace_file = replace_file
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
        target = Path(self.transaction.target_executable)
        staged = Path(self.transaction.staged_executable)
        backup = Path(self.transaction.backup_executable)
        marker = Path(self.transaction.startup_marker)
        replacement_temp = target.parent / f".{target.name}.{self.transaction.token}.new"
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
        current_state = TransactionState(self.transaction.state)
        if current_state not in allowed_entry_states:
            raise UpdateError(
                "invalid_transaction_state",
                "The detached updater transaction is not ready for installation handoff.",
            )

        ownership_acquired = False
        try:
            prior_ownership = self.ownership.read(target)
            self.ownership.assume_installation(
                self.transaction.transaction_id,
                target,
                parent_pid=self.transaction.parent_pid,
                parent_process_created=self.transaction.parent_process_created,
            )
            ownership_acquired = True
            if current_state == TransactionState.HANDED_OFF:
                self._set_state(TransactionState.WAITING_FOR_PARENT_EXIT)
            else:
                self.ownership.update(
                    self.transaction.transaction_id,
                    target,
                    current_state,
                )
            recovery_handoff = bool(
                prior_ownership is not None
                and prior_ownership.transaction_id == self.transaction.transaction_id
                and prior_ownership.role == OwnershipRole.HANDOFF.value
                and current_state != TransactionState.HANDED_OFF
            )
        except Exception:
            if ownership_acquired:
                with contextlib.suppress(Exception):
                    self.ownership.release(self.transaction.transaction_id, target)
            raise
        _append_update_log(
            f"Applying update {self.transaction.expected_version}; target={target.name}; "
            f"state={self.transaction.state}"
        )

        try:
            if recovery_handoff:
                self._wait_for_parent_exit()
            if self.transaction.state == TransactionState.CONFIRMED.value:
                self._release_ownership_safely(target, "confirmed update")
                return 0
            if self.transaction.state == TransactionState.ROLLED_BACK.value:
                self._release_ownership_safely(target, "completed rollback")
                return 3
            if self.transaction.state == TransactionState.FAILED.value:
                raise UpdateError(
                    "invalid_transaction_state",
                    "This update transaction already ended in a handled failure.",
                )
            if self.transaction.state in {
                TransactionState.LAUNCHING.value,
                TransactionState.AWAITING_CONFIRMATION.value,
            }:
                confirmation = self._valid_startup_marker(marker)
                if confirmation is not None and self._target_matches(
                    target, self.transaction.expected_sha256
                ):
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
                    return self._complete_success(staged, backup, marker)
                return self._rollback(
                    UpdateError(
                        "startup_confirmation_timeout",
                        "A recovered update never confirmed startup; the previous version will be restored.",
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

            if backup.exists():
                if not hmac.compare_digest(sha256_file(backup), self.transaction.original_sha256):
                    raise UpdateError(
                        "backup_failure",
                        "An existing update backup is invalid. Installation stopped.",
                    )
            else:
                try:
                    _copy_file_sync(target, backup)
                except OSError as exc:
                    raise UpdateError(
                        "backup_failure",
                        "The application backup could not be created.",
                        technical=str(exc),
                    ) from exc
            if not hmac.compare_digest(sha256_file(backup), self.transaction.original_sha256):
                raise UpdateError("backup_failure", "The application backup could not be verified.")

            if self.transaction.state == TransactionState.BACKING_UP.value:
                self._set_state(TransactionState.REPLACING)

            if self._target_matches(target, self.transaction.expected_sha256):
                target_replaced = True
            elif self._target_matches(target, self.transaction.original_sha256):
                with contextlib.suppress(OSError):
                    replacement_temp.unlink()
                _copy_file_sync(staged, replacement_temp)
                if (
                    replacement_temp.stat().st_size != self.transaction.expected_size
                    or not hmac.compare_digest(
                        sha256_file(replacement_temp), self.transaction.expected_sha256
                    )
                ):
                    raise UpdateError(
                        "checksum_mismatch", "The replacement copy failed verification."
                    )

                self._replace_with_retry(replacement_temp, target)
                target_replaced = True
            else:
                raise UpdateError(
                    "replacement_failure",
                    "The installed executable no longer matches the verified original.",
                )
            if not self._target_matches(target, self.transaction.expected_sha256):
                raise UpdateError("checksum_mismatch", "The installed update failed verification.")

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
            return self._complete_success(staged, backup, marker)
        except Exception as exc:
            update_error = (
                exc
                if isinstance(exc, UpdateError)
                else UpdateError(
                    "installation_failure", "The update installation failed.", str(exc)
                )
            )
            _append_update_log(
                f"Update {self.transaction.expected_version} failed: {update_error.code}"
            )
            with contextlib.suppress(OSError):
                replacement_temp.unlink()
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
        self.transaction = _transition_transaction(
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
            f"Transaction {self.transaction.transaction_id[:12]} state={state.value} "
            f"owner_pid={os.getpid()}"
        )
        if self.fault_hook is not None:
            self.fault_hook(state.value)

    @staticmethod
    def _target_matches(target: Path, expected_sha256: str) -> bool:
        try:
            return target.is_file() and hmac.compare_digest(sha256_file(target), expected_sha256)
        except OSError:
            return False

    def _complete_success(self, staged: Path, backup: Path, marker: Path) -> int:
        result_recorded = True
        try:
            self._write_result("success", "Update installed and startup confirmed.")
        except OSError:
            result_recorded = False
            _append_update_log("Startup succeeded, but the success record could not be written")
        if result_recorded:
            with contextlib.suppress(OSError):
                backup.unlink()
        with contextlib.suppress(OSError):
            staged.unlink()
        with contextlib.suppress(OSError):
            marker.unlink()
        self._release_ownership_safely(
            Path(self.transaction.target_executable),
            "confirmed update",
        )
        _append_update_log(f"Update {self.transaction.expected_version} confirmed successfully")
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

    def _verify_staged(self, staged: Path) -> None:
        transaction = self.transaction
        if not staged.exists() or staged.stat().st_size != transaction.expected_size:
            raise UpdateError(
                "file_size_mismatch", "The staged update package is missing or incomplete."
            )
        if not hmac.compare_digest(sha256_file(staged), transaction.expected_sha256):
            raise UpdateError("checksum_mismatch", "The staged update checksum is invalid.")

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
                if current_identity is not None and not parent_running:
                    _append_update_log(
                        "Parent PID creation identity changed; treating the original GUI as exited"
                    )
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

    def _replace_with_retry(self, source: Path, target: Path) -> None:
        last_error: OSError | None = None
        for attempt in range(REPLACEMENT_RETRY_COUNT):
            try:
                self.replace_file(source, target)
                return
            except OSError as exc:
                last_error = exc
                if attempt + 1 < REPLACEMENT_RETRY_COUNT:
                    self.sleep(REPLACEMENT_RETRY_DELAY_SECONDS)
        raise UpdateError(
            "permission_failure" if isinstance(last_error, PermissionError) else "replacement_failure",
            "Windows could not replace the application file. Antivirus or a file lock may be blocking it.",
            technical=str(last_error or "replace failed"),
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
            payload = _read_json(marker)
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

    def _rollback(
        self,
        original_error: UpdateError,
        process: ChildProcess | None,
        *,
        launched_identity: str | None = None,
    ) -> int:
        target = Path(self.transaction.target_executable)
        backup = Path(self.transaction.backup_executable)
        rollback_temp = target.parent / f".{target.name}.{self.transaction.token}.rollback"
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
            if not backup.exists() or not hmac.compare_digest(
                sha256_file(backup), self.transaction.original_sha256
            ):
                raise UpdateError(
                    "rollback_failure", "The last known-good backup is missing or invalid."
                )
            with contextlib.suppress(OSError):
                rollback_temp.unlink()
            _copy_file_sync(backup, rollback_temp)
            self._replace_with_retry(rollback_temp, target)
            if not hmac.compare_digest(sha256_file(target), self.transaction.original_sha256):
                raise UpdateError(
                    "rollback_failure", "The restored application failed verification."
                )
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
                        "The previous version was restored but could not be restarted automatically. "
                        "Open OpenFetch again manually.",
                    )
                    _append_update_log(
                        f"Rollback restored the previous version but restart failed: "
                        f"{type(launch_error).__name__}"
                    )
                    return 3
                with contextlib.suppress(OSError):
                    backup.unlink()
                _append_update_log("Rollback succeeded and the previous version was restarted")
                return 3
            finally:
                self._release_ownership_safely(target, "completed rollback")
        except Exception as rollback_error:
            with contextlib.suppress(OSError):
                rollback_temp.unlink()
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
                f"Backup retained at:\n{backup}\n\n"
                f"Target application:\n{target}\n\n"
                "Close OpenFetch, copy the backup over the target file, and retry later.",
            )
            _append_update_log(f"Rollback failed: {type(rollback_error).__name__}")
            return 4

    def _recover_original_without_replacement(self, error: UpdateError) -> int:
        target = Path(self.transaction.target_executable)
        backup = Path(self.transaction.backup_executable)
        if backup.exists():
            with contextlib.suppress(OSError):
                if not hmac.compare_digest(sha256_file(backup), self.transaction.original_sha256):
                    backup.unlink()
        with contextlib.suppress(Exception):
            self._set_state(TransactionState.FAILED)
        with contextlib.suppress(OSError):
            self._write_result(
                "original_preserved",
                f"Update failed ({error.code}); the original executable was not replaced.",
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
        deadline = self.monotonic() + ORIGINAL_RECOVERY_GRACE_SECONDS
        while parent_running and self.monotonic() < deadline:
            self.sleep(PROCESS_POLL_INTERVAL_SECONDS)
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


def run_update_helper(transaction_path: Path) -> int:
    """Entry point used by the copied packaged EXE in detached helper mode."""
    try:
        return UpdateApplier(transaction_path).apply()
    except UpdateError as exc:
        _append_update_log(f"Updater helper rejected transaction: {exc.code}")
        _show_native_message(
            "OpenFetch Update",
            f"The update could not be applied safely.\n\n{exc.user_message}",
        )
        return 5
    except Exception as exc:
        _append_update_log(f"Updater helper failed: {type(exc).__name__}")
        _show_native_message(
            "OpenFetch Update",
            "The update helper encountered an unexpected error. The current application was not intentionally removed.",
        )
        return 6


def write_startup_confirmation(
    token: str,
    marker_path: Path,
    *,
    version: str = VERSION,
    updates_root: Path | None = None,
) -> None:
    root = Path(updates_root or update_root()).resolve()
    marker = Path(marker_path).resolve()
    if not TOKEN_PATTERN.fullmatch(str(token or "")):
        raise UpdateError("invalid_transaction", "The startup confirmation token is invalid.")
    if not _is_within(marker, root) or marker.name != STARTUP_MARKER_FILENAME:
        raise UpdateError("unsafe_path", "The startup confirmation path is invalid.")
    if marker.parent.name != token:
        raise UpdateError(
            "invalid_transaction", "The startup confirmation token does not match its path."
        )
    parse_numeric_version(version)
    if marker.parent.parent.name != version:
        raise UpdateError(
            "invalid_transaction",
            "The startup confirmation version does not match its path.",
        )
    _atomic_write_json(
        marker,
        {
            "token": token,
            "version": version,
            "status": "initialized",
            "pid": os.getpid(),
        },
    )


def write_transaction_startup_confirmation(
    transaction_path: Path,
    *,
    version: str = VERSION,
    updates_root: Path | None = None,
    identity_provider: IdentityProvider = process_creation_identity,
) -> None:
    """Confirm startup using only a controlled transaction-file reference.

    The confirmation nonce remains in the private transaction file instead of
    appearing in the process command line.  The marker is additionally bound
    to the exact confirming process lifetime.
    """

    transaction = load_update_transaction(
        transaction_path,
        updates_root=updates_root or _transaction_updates_root(transaction_path),
    )
    if transaction.state not in {
        TransactionState.LAUNCHING.value,
        TransactionState.AWAITING_CONFIRMATION.value,
    }:
        raise UpdateError(
            "invalid_transaction_state",
            "The update transaction is not awaiting startup confirmation.",
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
    marker = Path(transaction.startup_marker)
    _atomic_write_json(
        marker,
        {
            "transaction_id": transaction.transaction_id,
            "confirmation_token": transaction.confirmation_token,
            "version": version,
            "status": "initialized",
            "pid": pid,
            "process_created": created,
        },
    )


def read_update_recovery_message(
    transaction_path: Path,
    *,
    updates_root: Path | None = None,
) -> str:
    root = Path(updates_root or _transaction_updates_root(transaction_path)).resolve()
    path = Path(transaction_path).resolve()
    if not _is_within(path, root) or path.name != TRANSACTION_FILENAME:
        return "The previous update failed, but its recovery details could not be validated."
    result_path = path.parent / RESULT_FILENAME
    try:
        payload = _read_json(result_path)
    except UpdateError:
        return "The previous update failed. The original application remains available."
    status = payload.get("status")
    if status == "rollback_succeeded":
        return "The update failed to start correctly. OpenFetch restored and restarted the previous version."
    if status == "original_preserved":
        return "The update could not be installed. The original OpenFetch executable was preserved."
    if status == "rollback_failed":
        return "The update and automatic rollback failed. Use the retained backup described in the updater log."
    return (
        "The previous update did not complete. The current executable was preserved where possible."
    )


def _launch_stale_recovery_helper(
    transaction_path: Path,
    transaction: UpdateTransaction,
    *,
    manager: UpdateOwnershipManager,
    identity_provider: IdentityProvider,
    detached_launcher: ProcessLauncher,
    helper_root: Path | None,
    handoff_timeout: float,
) -> PreparedUpdate:
    target = Path(transaction.target_executable)
    helper_base = Path(helper_root or (app_data_dir() / "updater-helper")).resolve()
    helper = (
        helper_base
        / transaction.target_identity
        / transaction.transaction_id
        / UPDATE_HELPER_FILENAME
    ).resolve()
    if not _is_within(helper, helper_base) or not helper.is_file():
        raise UpdateError(
            "recovery_helper_missing",
            "The detached updater recovery helper is missing.",
        )
    if not hmac.compare_digest(sha256_file(helper), transaction.original_sha256):
        raise UpdateError(
            "recovery_helper_invalid",
            "The detached updater recovery helper failed verification.",
        )

    parent_pid = os.getpid()
    parent_created = identity_provider(parent_pid)
    if parent_created is None or not SHA256_PATTERN.fullmatch(parent_created):
        raise UpdateError(
            "process_identity_unavailable",
            "The updater recovery process identity could not be verified.",
        )
    transaction = _rebind_transaction_parent(
        transaction_path,
        transaction,
        parent_pid=parent_pid,
        parent_process_created=parent_created,
    )
    manager.update(
        transaction.transaction_id,
        target,
        TransactionState(transaction.state),
        role=OwnershipRole.HANDOFF,
    )

    process: ChildProcess | None = None
    wrapper_created: str | None = None
    try:
        process = detached_launcher([str(helper), "--apply-update", str(transaction_path)])
        wrapper_created = identity_provider(process.pid)
        claimed = manager.wait_for_helper_claim(
            transaction.transaction_id,
            target,
            timeout=handoff_timeout,
            helper_exited=lambda: process.poll() is not None,
        )
        return PreparedUpdate(claimed.owner_pid, transaction_path, transaction.transaction_id)
    except Exception:
        record = manager.read(target)
        helper_claimed = bool(
            record is not None
            and record.transaction_id == transaction.transaction_id
            and record.role == OwnershipRole.INSTALLATION.value
            and identity_provider(record.owner_pid) == record.owner_process_created
        )
        if helper_claimed and record is not None:
            return PreparedUpdate(record.owner_pid, transaction_path, transaction.transaction_id)
        if process is not None:
            _stop_child_process(
                process,
                expected_identity=wrapper_created,
                identity_provider=identity_provider,
            )
        raise


def recover_stale_update_ownership(
    log_callback: Callable[[str], None] | None = None,
    *,
    updates_root: Path | None = None,
    identity_provider: IdentityProvider = process_creation_identity,
    recorded_process_stopper: RecordedProcessStopper | None = None,
    detached_launcher: ProcessLauncher = _default_detached_launcher,
    helper_root: Path | None = None,
    handoff_timeout: float = HELPER_HANDOFF_TIMEOUT_SECONDS,
) -> StaleRecoverySummary:
    """Recover only ownership that cannot match a live process lifetime."""

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
    events = manager.recover_stale(claim_for_recovery=True)
    recovered = len(events)
    shutdown_required = False
    for event in events:
        transaction_id = event.transaction_id
        if event.transaction_id == "unknown":
            matched: list[tuple[Path, UpdateTransaction]] = []
            for candidate in root.glob(f"*/*/{TRANSACTION_FILENAME}"):
                try:
                    transaction = load_update_transaction(candidate, updates_root=root)
                except UpdateError:
                    continue
                if (
                    transaction.target_identity == event.target_identity
                    and transaction.state
                    not in {
                        TransactionState.CONFIRMED.value,
                        TransactionState.ROLLED_BACK.value,
                        TransactionState.FAILED.value,
                    }
                ):
                    matched.append((candidate, transaction))
            if len(matched) != 1:
                log("Invalid updater ownership could not be bound to one safe transaction.")
                continue
            candidate, transaction = matched[0]
            try:
                manager.claim_recovery(
                    transaction.transaction_id,
                    Path(transaction.target_executable),
                    TransactionState(transaction.state),
                )
            except UpdateError as exc:
                log(f"Invalid updater ownership recovery was deferred after {exc.code}.")
                continue
            transaction_id = transaction.transaction_id
            candidates = [candidate]
        else:
            candidates = list(root.glob(f"*/{transaction_id}/{TRANSACTION_FILENAME}"))
        outcome = _ReconcileOutcome(release_ownership=False)
        try:
            if len(candidates) == 1:
                outcome = _reconcile_stale_transaction(
                    candidates[0],
                    updates_root=root,
                    identity_provider=identity_provider,
                    log_callback=log,
                    recorded_process_stopper=stopper,
                    ownership_manager=manager,
                    detached_launcher=detached_launcher,
                    helper_root=helper_root,
                    handoff_timeout=handoff_timeout,
                )
                shutdown_required = shutdown_required or outcome.shutdown_required
            else:
                log("Stale updater recovery could not identify one matching transaction.")
                outcome = _ReconcileOutcome(release_ownership=False)
        except (UpdateError, OSError) as exc:
            log(f"Stale updater recovery retained recovery files after {type(exc).__name__}.")
            outcome = _ReconcileOutcome(release_ownership=False)
        finally:
            if outcome.release_ownership:
                manager.release_identity(transaction_id, event.target_identity)
    if manager.recover_legacy_global_lock():
        recovered += 1
    return StaleRecoverySummary(recovered, shutdown_required)


def _valid_transaction_startup_marker(
    transaction: UpdateTransaction,
    *,
    identity_provider: IdentityProvider,
) -> bool:
    marker = Path(transaction.startup_marker)
    try:
        payload = _read_json(marker)
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


def _reconcile_stale_transaction(
    transaction_path: Path,
    *,
    updates_root: Path,
    identity_provider: IdentityProvider,
    log_callback: Callable[[str], None],
    recorded_process_stopper: RecordedProcessStopper,
    ownership_manager: UpdateOwnershipManager,
    detached_launcher: ProcessLauncher,
    helper_root: Path | None,
    handoff_timeout: float,
) -> _ReconcileOutcome:
    """Reconcile a crashed helper without discarding an unconfirmed backup."""

    transaction = load_update_transaction(transaction_path, updates_root=updates_root)
    state = TransactionState(transaction.state)
    target = Path(transaction.target_executable)
    backup = Path(transaction.backup_executable)
    marker = Path(transaction.startup_marker)
    staged = Path(transaction.staged_executable)

    target_is_new = UpdateApplier._target_matches(target, transaction.expected_sha256)
    target_is_original = UpdateApplier._target_matches(target, transaction.original_sha256)
    backup_is_valid = UpdateApplier._target_matches(backup, transaction.original_sha256)

    if state == TransactionState.CONFIRMED:
        if not target_is_new:
            log_callback(
                "Confirmed updater recovery retained cleanup files because the target hash "
                "does not match the confirmed version."
            )
            return _ReconcileOutcome(release_ownership=False)
        try:
            _atomic_write_json(
                transaction_path.parent / RESULT_FILENAME,
                {
                    "status": "success",
                    "message": "Recovered terminal confirmed-update cleanup.",
                    "version": transaction.expected_version,
                    "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                },
            )
        except OSError:
            log_callback(
                "Confirmed updater recovery retained cleanup files because the result record "
                "could not be written."
            )
            return _ReconcileOutcome(release_ownership=False)
        for cleanup_path in (backup, staged, marker):
            with contextlib.suppress(OSError):
                cleanup_path.unlink()
        log_callback("Recovered terminal confirmed-update cleanup after the helper exited.")
        return _ReconcileOutcome(release_ownership=True)

    if state == TransactionState.ROLLED_BACK:
        if not target_is_original:
            log_callback(
                "Rolled-back updater recovery retained cleanup files because the target hash "
                "does not match the original version."
            )
            return _ReconcileOutcome(release_ownership=False)
        try:
            _atomic_write_json(
                transaction_path.parent / RESULT_FILENAME,
                {
                    "status": "rollback_succeeded",
                    "message": "Recovered terminal rollback cleanup.",
                    "version": transaction.expected_version,
                    "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                },
            )
        except OSError:
            log_callback(
                "Rolled-back updater recovery retained cleanup files because the result record "
                "could not be written."
            )
            return _ReconcileOutcome(release_ownership=False)
        staged_is_valid = bool(
            staged.is_file()
            and staged.stat().st_size == transaction.expected_size
            and UpdateApplier._target_matches(staged, transaction.expected_sha256)
        )
        for cleanup_path in (backup, marker):
            with contextlib.suppress(OSError):
                cleanup_path.unlink()
        if not staged_is_valid:
            with contextlib.suppress(OSError):
                staged.unlink()
        log_callback("Recovered terminal rollback cleanup after the helper exited.")
        return _ReconcileOutcome(release_ownership=True)

    if state == TransactionState.ROLLING_BACK and target_is_original and backup_is_valid:
        transaction = _transition_transaction(
            transaction_path,
            transaction,
            TransactionState.ROLLED_BACK,
        )
        _atomic_write_json(
            transaction_path.parent / RESULT_FILENAME,
            {
                "status": "rollback_succeeded",
                "message": "Recovered a completed rollback after the updater helper exited.",
                "version": transaction.expected_version,
                "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            },
        )
        with contextlib.suppress(OSError):
            backup.unlink()
        with contextlib.suppress(OSError):
            marker.unlink()
        log_callback("Recovered a completed updater rollback after the helper exited.")
        return _ReconcileOutcome(release_ownership=True)

    if state in {TransactionState.LAUNCHING, TransactionState.AWAITING_CONFIRMATION}:
        if target_is_new and _valid_transaction_startup_marker(
            transaction, identity_provider=identity_provider
        ):
            if state == TransactionState.LAUNCHING:
                transaction = _transition_transaction(
                    transaction_path,
                    transaction,
                    TransactionState.AWAITING_CONFIRMATION,
                )
            transaction = _transition_transaction(
                transaction_path,
                transaction,
                TransactionState.CONFIRMED,
            )
            _atomic_write_json(
                transaction_path.parent / RESULT_FILENAME,
                {
                    "status": "success",
                    "message": "Recovered a confirmed update after the helper exited.",
                    "version": transaction.expected_version,
                    "updated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                },
            )
            with contextlib.suppress(OSError):
                backup.unlink()
            with contextlib.suppress(OSError):
                staged.unlink()
            with contextlib.suppress(OSError):
                marker.unlink()
            log_callback("Recovered confirmed startup after an updater helper exit.")
            return _ReconcileOutcome(release_ownership=True)

    needs_rollback = state in {
        TransactionState.REPLACING,
        TransactionState.LAUNCHING,
        TransactionState.AWAITING_CONFIRMATION,
        TransactionState.ROLLING_BACK,
    } and target_is_new
    if needs_rollback and backup_is_valid:
        prepared = _launch_stale_recovery_helper(
            transaction_path,
            transaction,
            manager=ownership_manager,
            identity_provider=identity_provider,
            detached_launcher=detached_launcher,
            helper_root=helper_root,
            handoff_timeout=handoff_timeout,
        )
        log_callback(
            f"Detached recovery helper {prepared.helper_pid} accepted transaction "
            f"{prepared.transaction_id[:12]}; OpenFetch must close."
        )
        return _ReconcileOutcome(release_ownership=False, shutdown_required=True)

    if not target_is_original and not target_is_new:
        log_callback("Stale updater recovery retained the backup because the target hash is unknown.")
        return _ReconcileOutcome(release_ownership=False)
    if state not in {
        TransactionState.CONFIRMED,
        TransactionState.ROLLED_BACK,
        TransactionState.FAILED,
    }:
        _transition_transaction(transaction_path, transaction, TransactionState.FAILED)
    log_callback("Recovered stale updater ownership; verified staged files and backups were preserved.")
    return _ReconcileOutcome(release_ownership=True)


def cleanup_legacy_update_state() -> None:
    """Reclaim finished Neural Extractor V3 update state after the OpenFetch migration.

    An installed Neural Extractor updater keeps its transaction, staged package
    and detached helper copy below its own data directory. Once it has handed
    off to OpenFetch, nothing else ever visits that directory, so the finished
    state - including a package the size of the release - would remain forever.

    Only a transaction in a terminal state whose target no longer has an
    ownership record is reclaimed, so a legacy helper that is still working is
    never disturbed. The version directory, which may hold a staged package
    shared by several transactions, is removed only once no transaction remains
    under it.
    """
    legacy_root = legacy_update_root()
    if not legacy_root.exists():
        return
    helper_base = (legacy_app_data_dir() / "updater-helper").resolve()
    ownership_dir = legacy_root / "ownership"
    for transaction_path in sorted(legacy_root.glob(f"*/*/{TRANSACTION_FILENAME}")):
        try:
            payload = _read_json(transaction_path)
        except (OSError, UpdateError):
            continue
        transaction_id = str(payload.get("transaction_id") or "")
        target_identity = str(payload.get("target_identity") or "")
        state = str(payload.get("state") or "")
        if (
            not TOKEN_PATTERN.fullmatch(transaction_id)
            or not SHA256_PATTERN.fullmatch(target_identity)
            or state
            not in {
                TransactionState.CONFIRMED.value,
                TransactionState.ROLLED_BACK.value,
                TransactionState.FAILED.value,
            }
            or (ownership_dir / f"{target_identity}.json").exists()
        ):
            continue
        helper_dir = (helper_base / target_identity / transaction_id).resolve()
        if _is_within(helper_dir, helper_base) and helper_dir.exists():
            with contextlib.suppress(OSError):
                shutil.rmtree(helper_dir)
            with contextlib.suppress(OSError):
                helper_dir.parent.rmdir()
        transaction_dir = transaction_path.parent.resolve()
        version_dir = transaction_dir.parent
        if not _is_within(transaction_dir, legacy_root) or version_dir == legacy_root:
            continue
        with contextlib.suppress(OSError):
            shutil.rmtree(transaction_dir)
        if not any(version_dir.glob(f"*/{TRANSACTION_FILENAME}")):
            # The staged package may be shared by the whole version directory.
            with contextlib.suppress(OSError):
                shutil.rmtree(version_dir)


def cleanup_stale_update_state(
    *,
    updates_root: Path | None = None,
    helper_root: Path | None = None,
    successful_retention_days: int = 7,
) -> None:
    """Remove only old, confirmed-success transaction metadata and stale partial files."""
    root = Path(updates_root or update_root()).resolve()
    if not root.exists():
        return
    cutoff = time.time() - successful_retention_days * 24 * 60 * 60
    helper_base = Path(helper_root or (app_data_dir() / "updater-helper")).resolve()
    ownership_dir = root / "ownership"
    for transaction_path in root.glob(f"*/*/{TRANSACTION_FILENAME}"):
        try:
            payload = _read_json(transaction_path)
            transaction_id = str(payload.get("transaction_id") or "")
            target_identity = str(payload.get("target_identity") or "")
            state = str(payload.get("state") or "")
            if (
                not TOKEN_PATTERN.fullmatch(transaction_id)
                or not SHA256_PATTERN.fullmatch(target_identity)
                or state
                not in {
                    TransactionState.CONFIRMED.value,
                    TransactionState.ROLLED_BACK.value,
                    TransactionState.FAILED.value,
                }
                or (ownership_dir / f"{target_identity}.json").exists()
            ):
                continue
            helper_dir = (helper_base / target_identity / transaction_id).resolve()
            if _is_within(helper_dir, helper_base):
                with contextlib.suppress(OSError):
                    shutil.rmtree(helper_dir)
                with contextlib.suppress(OSError):
                    helper_dir.parent.rmdir()
        except (OSError, UpdateError):
            continue
    for partial in root.rglob("*.part"):
        with contextlib.suppress(OSError):
            if partial.stat().st_mtime < cutoff:
                partial.unlink()
    for result_path in root.rglob(RESULT_FILENAME):
        try:
            if result_path.stat().st_mtime >= cutoff:
                continue
            payload = _read_json(result_path)
            if payload.get("status") != "success":
                continue
            transaction_dir = result_path.parent.resolve()
            if _is_within(transaction_dir, root):
                shutil.rmtree(transaction_dir)
        except (OSError, UpdateError):
            continue
