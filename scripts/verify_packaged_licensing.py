"""Fail closed when a Windows EXE crosses the audited distribution boundary."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from PyInstaller.archive.readers import CArchiveReader

try:
    from scripts.project_identity import (
        APP_NAME,
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
    )
except ModuleNotFoundError:  # executed directly as scripts/verify_packaged_licensing.py
    from project_identity import (  # type: ignore[no-redef]
        APP_NAME,
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
    )

CPYTHON_LIBFFI_SHA256 = (
    "d1682615247e165ba8aa0cff59e090a0b1b6b90793e48733f441dff8d8e6328e"
)
CPYTHON_CTYPES_SHA256 = (
    "6968228b18fc86b0b02f3dbf2c879c2c6f689a66130a72f35a3f0b2755d99e41"
)
ROOT_LIBFFI_PATH = "libffi-8.dll"
ROOT_CTYPES_PATH = "_ctypes.pyd"
LICENSE_MANIFEST_PATH = "licenses/RELEASE-LICENSE-MANIFEST.sha256"

ALLOWED_PYSIDE_ROOT_NATIVE = frozenset(
    {
        "pyside6/msvcp140.dll",
        "pyside6/msvcp140_1.dll",
        "pyside6/msvcp140_2.dll",
        "pyside6/opengl32sw.dll",
        "pyside6/pyside6.abi3.dll",
        "pyside6/qt6core.dll",
        "pyside6/qt6gui.dll",
        "pyside6/qt6widgets.dll",
        "pyside6/qtcore.pyd",
        "pyside6/qtgui.pyd",
        "pyside6/qtwidgets.pyd",
        "pyside6/vcruntime140.dll",
        "pyside6/vcruntime140_1.dll",
    }
)
ALLOWED_QT_PLUGINS = frozenset(
    {
        "pyside6/plugins/imageformats/qico.dll",
        "pyside6/plugins/platforms/qoffscreen.dll",
        "pyside6/plugins/platforms/qwindows.dll",
        "pyside6/plugins/styles/qmodernwindowsstyle.dll",
    }
)
REQUIRED_PYSIDE_PATHS = ALLOWED_PYSIDE_ROOT_NATIVE | ALLOWED_QT_PLUGINS | {
    "shiboken6/shiboken.pyd",
    "shiboken6/shiboken6.abi3.dll",
}

REQUIRED_COMPLIANCE_PATHS: tuple[str, ...] = (
    "LICENSE",
    "PROJECT-METADATA.json",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "docs/COPYRIGHT-OWNERSHIP-QUESTIONS.md",
    "docs/PROJECT-OWNERSHIP-DECLARATION.md",
    "docs/DEPENDENCY-SOURCE.md",
    "docs/BUILD-REPRODUCIBILITY.md",
    "docs/LGPL-COMPLIANCE.md",
    "docs/QT-REPLACEMENT-GUIDE.md",
    "docs/QT-BUILD-PROVENANCE.md",
    "docs/OPTIONAL-PO-PROVIDER.md",
    "requirements.lock",
    "SOURCE-HASHES.sha256",
    LICENSE_MANIFEST_PATH,
)

_MANIFEST_LINE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?(.+?)\s*$")
_SOURCE_HASH_LINE = re.compile(r"^([0-9a-f]{64})  ([^\\]+)$")
_INVENTORY_FINGERPRINT = re.compile(
    r"(?m)^Audited non-compliance payload fingerprint SHA-256: ([0-9a-f]{64})\s*$"
)
_PYQT_TOKEN = re.compile(r"(?:^|[./_\\-])pyqt(?:5|6)?(?:$|[./_\\-])", re.I)
_PROVIDER_TOKEN = re.compile(
    r"(?:^|[./_\\-])(?:bgutil|getpot)(?:$|[./_\\-])"
    r"|(?:^|[./\\])(?:yt_dlp_plugins|yt-dlp-plugins)(?:$|[./\\])",
    re.I,
)
_RAW_JAVASCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".js.map", ".ts.map")

PROHIBITED_LEGACY_SHA256S = frozenset(
    {
        # Legacy bundled-provider V3.0.8 one-file EXE (PyQt6 + in-process
        # GPL PO-provider payload, missing notices/source).
        "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac",
        # Legacy V3.0.4 one-file EXE (PyQt6, no embedded notices/source).
        "02fbde8845bcb7b8946a44f320aa1f88a63a70ceac9765f800276ce11bfa6ed7",
    }
)
PROHIBITED_LEGACY_SIZES = frozenset({234709652, 193141493})

ONEFOLDER_ROOT_NAME = ONEFOLDER_DIST_NAME
ONEFOLDER_LAUNCHER_PATH = EXECUTABLE_NAME
ONEFOLDER_DIRECTORY_MANIFEST_NAME = f"{ONEFOLDER_ROOT_NAME}-directory-manifest.json"
# The three external runtime tools are pinned to the audited byte-exact builds
# (same hashes as OpenFetch.spec require_sha256 pins).
ONEFOLDER_PINNED_EXECUTABLE_SHA256 = {
    "bin/node.exe": "39d45b5933f339d3ebdebd76474893dab5d7da1038920f65cf5bbcf0f20f3636",
    "bin/ffmpeg.exe": "6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e",
    "bin/ffprobe.exe": "55a3d20229c2373dade4362215c9bd5a04b59d4e734d0bbb882afd9cea4fb046",
}
ONEFOLDER_REQUIRED_PATHS: tuple[str, ...] = (
    ONEFOLDER_LAUNCHER_PATH,
    "LICENSE",
    "PROJECT-METADATA.json",
    "README.md",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "QT-PYSIDE-COMPONENTS.json",
    "SOURCE-HASHES.sha256",
    "requirements.lock",
    LICENSE_MANIFEST_PATH,
    "compliance/BINARY-TO-SOURCE-MAP.json",
    "compliance/BUILD-LABEL.txt",
    "compliance/PROJECT-METADATA.json",
    "compliance/QT-PYSIDE-COMPONENTS.json",
    "docs/BUILD-REPRODUCIBILITY.md",
    "docs/DEPENDENCY-SOURCE.md",
    "docs/LGPL-COMPLIANCE.md",
    "docs/OPTIONAL-PO-PROVIDER.md",
    "docs/QT-BUILD-PROVENANCE.md",
    "docs/QT-REPLACEMENT-GUIDE.md",
)
# One-folder trees must never ship runtime state: profiles, cookies, tokens,
# or logs are recipient-machine artifacts, not release material.
_RUNTIME_STATE_SUFFIXES = (".log",)
_RUNTIME_STATE_NAME_TOKENS = ("cookie", "browser-profile", "browser_profile")
_RUNTIME_STATE_EXACT_NAMES = frozenset({"tokens.json", "token.json", ".token"})
_LAUNCHER_FORBIDDEN_NATIVE_SUFFIXES = (".dll", ".dylib", ".pyd", ".so")
_ONEFOLDER_REPLACEABLE_ROOTS = ("PySide6", "shiboken6")

DIRECTORY_MANIFEST_MAX_BYTES = 8 * 1024 * 1024
DIRECTORY_MANIFEST_MAX_FILES = 20_000
DIRECTORY_MANIFEST_MAX_PATH_LENGTH = 240
DIRECTORY_MANIFEST_MAX_REPLACEABLE = 512
DIRECTORY_MANIFEST_MIN_TOTAL = 1 * 1024 * 1024
DIRECTORY_MANIFEST_MAX_TOTAL = 4 * 1024 * 1024 * 1024
_CODE_OR_BINARY_SUFFIXES = (
    ".dll",
    ".dylib",
    ".exe",
    ".pyd",
    ".py",
    ".pyc",
    ".so",
)


class _EmbeddedArchive(Protocol):
    toc: dict[str, object]

    def extract(self, name: str, raw: bool = False) -> bytes | None: ...


class _CArchive(Protocol):
    toc: dict[str, tuple[object, ...]]

    def extract(self, name: str) -> bytes: ...

    def open_embedded_archive(self, name: str) -> _EmbeddedArchive: ...


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fingerprint_payload_identity(path: str, payload: bytes) -> tuple[bytes, int, bytes]:
    if path.casefold() != "base_library.zip":
        return b"RAW", len(payload), hashlib.sha256(payload).digest()

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zip_archive:
            members = zip_archive.infolist()
            names = [member.filename.replace("\\", "/") for member in members]
            folded = [name.casefold() for name in names]
            if len(folded) != len(set(folded)):
                raise ValueError("base_library.zip contains duplicate member paths")
            records = []
            for member, name in zip(members, names, strict=True):
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts:
                    raise ValueError(
                        f"base_library.zip contains unsafe member path: {name}"
                    )
                records.append((name, zip_archive.read(member)))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"cannot inspect base_library.zip: {exc}") from exc

    digest = hashlib.sha256()
    total_size = 0
    for name, data in sorted(records, key=lambda item: (item[0].casefold(), item[0])):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
        total_size += len(data)
    return b"CANONICAL-ZIP-CONTENT-V1", total_size, digest.digest()


def _normalize_archive_path(value: str) -> str:
    return value.replace("\\", "/").removeprefix("./")


def _safe_manifest_path(value: str) -> PurePosixPath:
    normalized = value.replace("\\", "/").removeprefix("./")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe manifest path: {value!r}")
    return path


def _parse_manifest(payload: str) -> dict[PurePosixPath, str]:
    records: dict[PurePosixPath, str] = {}
    for line_number, raw_line in enumerate(payload.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid manifest line {line_number}: {raw_line!r}")
        path = _safe_manifest_path(match.group(2))
        if path in records:
            raise ValueError(f"duplicate manifest path: {path.as_posix()}")
        records[path] = match.group(1).lower()
    if not records:
        raise ValueError("manifest has no file records")
    return records


def _entry_type(entry: tuple[object, ...]) -> str:
    return str(entry[-1]) if entry else ""


def _is_code_or_binary(path: str, typecode: str) -> bool:
    lowered = path.casefold()
    return typecode in {"m", "s"} or lowered.endswith(_CODE_OR_BINARY_SUFFIXES)


def _is_documentation_path(path: str) -> bool:
    lowered = path.casefold()
    return lowered.startswith(("docs/", "licenses/")) or lowered in {
        "license",
        "third_party_licenses.txt",
        "third_party_notices.md",
    }


def _scan_carchive_names(
    archive: _CArchive,
    normalized: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    for archive_name in archive.toc:
        path = _normalize_archive_path(archive_name)
        lowered = path.casefold()
        if lowered.endswith(_RAW_JAVASCRIPT_SUFFIXES):
            errors.append(f"raw JavaScript/TypeScript payload is forbidden: {path}")
        if "node_modules/canvas/" in lowered or lowered.endswith("/canvas.node") or lowered == "canvas.node":
            errors.append(f"canvas native/provider payload is forbidden: {path}")
        if _PYQT_TOKEN.search(lowered) and not _is_documentation_path(path):
            errors.append(f"PyQt code or binary is forbidden: {path}")
        if _PROVIDER_TOKEN.search(lowered) and not _is_documentation_path(path):
            errors.append(f"in-process provider code is forbidden: {path}")

    folded: dict[str, list[str]] = {}
    for original, path in normalized.items():
        folded.setdefault(path.casefold(), []).append(original)
    collisions = [values for values in folded.values() if len(values) > 1]
    for values in collisions:
        errors.append("case-insensitive archive path collision: " + ", ".join(sorted(values)))
    return errors


def _verify_pyz(archive: _CArchive) -> list[str]:
    errors: list[str] = []
    pyz_names = [name for name, entry in archive.toc.items() if _entry_type(entry) == "z"]
    if len(pyz_names) != 1:
        return [f"expected exactly one embedded PYZ archive, found {len(pyz_names)}"]
    try:
        pyz = archive.open_embedded_archive(pyz_names[0])
    except Exception as exc:  # PyInstaller exposes several archive-specific exceptions.
        return [f"cannot inspect embedded PYZ archive: {exc}"]

    module_names = [str(name) for name in pyz.toc]
    for module_name in module_names:
        lowered = module_name.casefold()
        if _PYQT_TOKEN.search(lowered):
            errors.append(f"PyQt module is forbidden in embedded PYZ: {module_name}")
        if _PROVIDER_TOKEN.search(lowered):
            errors.append(f"provider module is forbidden in embedded PYZ: {module_name}")

    if not any(name.casefold() == "pyside6" for name in module_names):
        errors.append("embedded PYZ does not contain the required PySide6 package")
    return errors


def _verify_pyside_payload(archive: _CArchive, normalized: dict[str, str]) -> list[str]:
    errors: list[str] = []
    folded = {path.casefold() for path in normalized.values()}
    if not any(path.startswith("pyside6/") for path in folded):
        errors.append("archive does not contain a PySide6 binary payload")

    missing = sorted(REQUIRED_PYSIDE_PATHS - folded)
    if missing:
        errors.append("archive is missing audited PySide6/Qt paths: " + ", ".join(missing))

    audited_paths = {
        path
        for path in folded
        if path.startswith(("pyside6/plugins/", "pyside6/translations/"))
        or (
            len(PurePosixPath(path).parts) == 2
            and path.startswith("pyside6/")
            and path.endswith((".dll", ".pyd"))
        )
    }
    unexpected = sorted(audited_paths - ALLOWED_PYSIDE_ROOT_NATIVE - ALLOWED_QT_PLUGINS)
    if unexpected:
        errors.append("archive contains unaudited PySide6/Qt paths: " + ", ".join(unexpected))
    return errors


def _verify_libffi(archive: _CArchive, normalized: dict[str, str]) -> list[str]:
    errors: list[str] = []
    libffi_names = [
        name
        for name, path in normalized.items()
        if PurePosixPath(path.casefold()).name.startswith("libffi")
        and PurePosixPath(path.casefold()).suffix == ".dll"
    ]
    root_names = [
        name for name in libffi_names if normalized[name].casefold() == ROOT_LIBFFI_PATH
    ]
    if len(libffi_names) != 1:
        rendered = [normalized[name] for name in libffi_names]
        errors.append(
            "archive must contain exactly one libffi DLL at root "
            f"({ROOT_LIBFFI_PATH}); found {rendered}"
        )
    if len(root_names) != 1:
        errors.append(
            f"archive must contain exactly one root {ROOT_LIBFFI_PATH}; "
            f"found {[normalized[name] for name in root_names]}"
        )
        return errors
    archive_name = root_names[0]
    actual_hash = _sha256(archive.extract(archive_name))
    if actual_hash != CPYTHON_LIBFFI_SHA256:
        errors.append(
            f"archive hash mismatch for {ROOT_LIBFFI_PATH}: "
            f"expected {CPYTHON_LIBFFI_SHA256}, got {actual_hash}"
        )

    ctypes_names = [
        name for name, path in normalized.items() if path.casefold() == ROOT_CTYPES_PATH
    ]
    if len(ctypes_names) != 1:
        errors.append(
            f"archive must contain exactly one root {ROOT_CTYPES_PATH}; "
            f"found {[normalized[name] for name in ctypes_names]}"
        )
    else:
        ctypes_hash = _sha256(archive.extract(ctypes_names[0]))
        if ctypes_hash != CPYTHON_CTYPES_SHA256:
            errors.append(
                f"archive hash mismatch for {ROOT_CTYPES_PATH}: "
                f"expected {CPYTHON_CTYPES_SHA256}, got {ctypes_hash}"
            )
    return errors


def _verify_license_manifest(archive: _CArchive, normalized: dict[str, str]) -> list[str]:
    errors: list[str] = []
    by_folded_path = {path.casefold(): name for name, path in normalized.items()}
    manifest_name = by_folded_path.get(LICENSE_MANIFEST_PATH.casefold())
    if manifest_name is None:
        return [f"missing required compliance path: {LICENSE_MANIFEST_PATH}"]
    try:
        manifest = _parse_manifest(archive.extract(manifest_name).decode("utf-8-sig"))
    except (UnicodeError, ValueError) as exc:
        return [f"invalid packaged license manifest: {exc}"]

    actual_license_paths = {
        PurePosixPath(path[len("licenses/") :])
        for path in normalized.values()
        if path.casefold().startswith("licenses/")
        and path.casefold() != LICENSE_MANIFEST_PATH.casefold()
    }
    if set(manifest) != actual_license_paths:
        unlisted = sorted(actual_license_paths - set(manifest), key=str)
        absent = sorted(set(manifest) - actual_license_paths, key=str)
        errors.append(
            "packaged license manifest coverage mismatch: "
            f"unlisted={[path.as_posix() for path in unlisted]}, "
            f"absent={[path.as_posix() for path in absent]}"
        )

    for relative_path, expected_hash in manifest.items():
        packaged_path = f"licenses/{relative_path.as_posix()}"
        archive_name = by_folded_path.get(packaged_path.casefold())
        if archive_name is None:
            continue
        payload = archive.extract(archive_name)
        if not payload:
            errors.append(f"packaged license file is empty: {packaged_path}")
        elif _sha256(payload) != expected_hash:
            errors.append(f"packaged license hash mismatch: {packaged_path}")
    return errors


def _verify_source_hash_manifest(archive: _CArchive, normalized: dict[str, str]) -> list[str]:
    by_folded_path = {path.casefold(): name for name, path in normalized.items()}
    manifest_name = by_folded_path.get("source-hashes.sha256")
    if manifest_name is None:
        return []  # The common compliance-path check reports this once.
    try:
        lines = archive.extract(manifest_name).decode("utf-8-sig").splitlines()
    except UnicodeError as exc:
        return [f"invalid packaged SOURCE-HASHES.sha256: {exc}"]

    errors: list[str] = []
    records: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        match = _SOURCE_HASH_LINE.fullmatch(line)
        if match is None:
            errors.append(
                "invalid packaged SOURCE-HASHES.sha256 line "
                f"{line_number}; expected lowercase '<sha256>  <relative/posix-path>'"
            )
            continue
        try:
            path = _safe_manifest_path(match.group(2)).as_posix()
        except ValueError as exc:
            errors.append(f"invalid packaged source-hash path: {exc}")
            continue
        if path != match.group(2):
            errors.append(f"non-canonical source-hash path: {match.group(2)}")
        elif path in records:
            errors.append(f"duplicate packaged source-hash path: {path}")
        else:
            records[path] = match.group(1)
    if not records:
        errors.append("packaged SOURCE-HASHES.sha256 has no valid file records")

    # Build/source manifests may cover files intentionally supplied only in the
    # corresponding-source companion. If a listed file is also in the EXE,
    # however, its packaged bytes must match the declared source hash.
    for path, expected_hash in records.items():
        archive_name = by_folded_path.get(path.casefold())
        if archive_name is not None and _sha256(archive.extract(archive_name)) != expected_hash:
            errors.append(f"packaged source-hash mismatch: {path}")
    return errors


def _calculate_payload_fingerprint(
    archive: _CArchive, normalized: dict[str, str]
) -> str:
    compliance_folded = {path.casefold() for path in REQUIRED_COMPLIANCE_PATHS}
    digest = hashlib.sha256()
    for archive_name, path in sorted(
        normalized.items(), key=lambda item: (item[1].casefold(), item[1])
    ):
        if (
            _entry_type(archive.toc[archive_name]) == "z"
            or path.casefold() in compliance_folded
            or _is_documentation_path(path)
        ):
            continue
        payload = archive.extract(archive_name)
        identity_kind, identity_size, identity_digest = _fingerprint_payload_identity(
            path, payload
        )
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_entry_type(archive.toc[archive_name]).encode("ascii", "replace"))
        digest.update(b"\0")
        digest.update(identity_kind)
        digest.update(b"\0")
        digest.update(str(identity_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(identity_digest)

    pyz_names = [name for name, entry in archive.toc.items() if _entry_type(entry) == "z"]
    if len(pyz_names) != 1:
        raise ValueError(f"expected exactly one embedded PYZ archive, found {len(pyz_names)}")
    pyz = archive.open_embedded_archive(pyz_names[0])
    for module_name in sorted(
        (str(name) for name in pyz.toc),
        key=lambda item: (item.casefold(), item),
    ):
        raw_module = pyz.extract(module_name, raw=True)
        if raw_module is None:
            raw_module = b""
        if not isinstance(raw_module, bytes):
            raise ValueError(
                f"embedded PYZ extraction did not return bytes: {module_name}"
            )
        entry = pyz.toc[module_name]
        entry_type = entry[0] if isinstance(entry, (tuple, list)) and entry else "UNKNOWN"
        digest.update(b"PYZ\0")
        digest.update(module_name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry_type).encode("ascii", "replace"))
        digest.update(b"\0")
        digest.update(str(len(raw_module)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(raw_module).digest())
    return digest.hexdigest()


def _verify_distribution_inventory(
    archive: _CArchive, normalized: dict[str, str]
) -> list[str]:
    errors: list[str] = []
    inventory_name = next(
        (
            name
            for name, path in normalized.items()
            if path.casefold() == "third_party_licenses.txt"
        ),
        None,
    )
    if inventory_name is None:
        return []  # The common compliance-path check reports this once.
    try:
        text = archive.extract(inventory_name).decode("utf-8-sig")
    except UnicodeError as exc:
        return [f"invalid packaged THIRD_PARTY_LICENSES.txt: {exc}"]

    status_patterns = {
        "public verdict": r"(?m)^Public-distribution verdict: (HOLD|PASS)\s*$",
        "release gate": r"(?m)^Release-gate-status: (HOLD|PASS)\s*$",
        "qualified review": r"(?m)^Qualified-review-status: (HOLD|PASS)\s*$",
    }
    statuses: dict[str, str] = {}
    for label, pattern in status_patterns.items():
        matches = re.findall(pattern, text)
        if len(matches) != 1:
            errors.append(f"packaged inventory has no unique {label} status")
        else:
            statuses[label] = matches[0]
    blocker_matches = re.findall(r"(?m)^Audit-blocker-count: ([0-9]+)\s*$", text)
    blocker_count: int | None = None
    if len(blocker_matches) != 1:
        errors.append("packaged inventory has no unique audit blocker count")
    else:
        blocker_count = int(blocker_matches[0])

    status_values = set(statuses.values())
    if len(statuses) == len(status_patterns) and len(status_values) != 1:
        errors.append("packaged inventory has inconsistent audit status fields")
    elif status_values == {"HOLD"} and blocker_count == 0:
        errors.append("packaged HOLD inventory must declare at least one audit blocker")
    elif status_values == {"PASS"} and blocker_count != 0:
        errors.append("packaged PASS inventory must declare zero audit blockers")

    match = _INVENTORY_FINGERPRINT.search(text)
    if match is None:
        errors.append("packaged inventory has no audited payload fingerprint")
    else:
        try:
            actual = _calculate_payload_fingerprint(archive, normalized)
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"cannot calculate packaged payload fingerprint: {exc}")
        else:
            if match.group(1) != actual:
                errors.append(
                    "packaged inventory payload fingerprint mismatch: "
                    f"expected {match.group(1)}, got {actual}"
                )

    for zero_row in (
        "| PyQt code/binary/module | 0 | 0 | 0 |",
        "| bgutil/getpot/yt_dlp_plugins provider code/module | 0 | 0 | 0 |",
        "| Raw JavaScript/TypeScript payload | 0 | 0 | 0 |",
        "| canvas native/module payload | 0 | 0 | 0 |",
    ):
        if zero_row not in text:
            errors.append(f"packaged inventory lacks verified zero-count row: {zero_row}")

    inventoried_paths = {
        path
        for path in normalized.values()
        if path.casefold().endswith((".dll", ".pyd", ".exe"))
        or path.casefold().startswith(
            ("pyside6/plugins/", "pyside6/translations/")
        )
    }
    missing_paths = sorted(path for path in inventoried_paths if f"| {path} |" not in text)
    if missing_paths:
        errors.append(
            "packaged inventory omits native/Qt paths: " + ", ".join(missing_paths)
        )
    return errors


def verify_archive(archive: _CArchive) -> list[str]:
    """Return release-blocking errors for an already-open CArchive."""
    normalized = {name: _normalize_archive_path(name) for name in archive.toc}
    folded_paths = {path.casefold() for path in normalized.values()}
    errors = _scan_carchive_names(archive, normalized)

    missing = [
        path for path in REQUIRED_COMPLIANCE_PATHS if path.casefold() not in folded_paths
    ]
    if missing:
        errors.append("missing required compliance paths: " + ", ".join(missing))

    errors.extend(_verify_pyz(archive))
    errors.extend(_verify_pyside_payload(archive, normalized))
    errors.extend(_verify_libffi(archive, normalized))
    errors.extend(_verify_source_hash_manifest(archive, normalized))
    errors.extend(_verify_distribution_inventory(archive, normalized))
    if LICENSE_MANIFEST_PATH.casefold() in folded_paths:
        errors.extend(_verify_license_manifest(archive, normalized))
    return errors


def verify(executable: Path) -> list[str]:
    """Return release-blocking archive errors for *executable*."""
    try:
        archive = CArchiveReader(str(executable))
    except Exception as exc:  # Keep malformed/not-PyInstaller artifacts fail closed.
        return [f"cannot read PyInstaller CArchive: {exc}"]
    return verify_archive(archive)


BRIDGE_REQUIRED_RUNTIME_PATHS: tuple[str, ...] = (
    "bin/node.exe",
    "bin/ffmpeg.exe",
    "bin/ffprobe.exe",
)


def verify_bridge_boundary(archive: _CArchive) -> list[str]:
    """Return distribution-boundary errors for an owner-authorized bridge EXE.

    This runs the same audited payload-boundary checks as ``verify_archive`` —
    PyQt/provider/JavaScript/canvas rejection across the CArchive and embedded
    PYZ, the exact audited PySide6/Qt path set, the pinned CPython
    libffi/_ctypes bytes, presence of the required compliance material, and the
    license/source hash manifests — but deliberately omits
    ``_verify_distribution_inventory``.

    That inventory check binds ``THIRD_PARTY_LICENSES.txt`` to one specific
    historical artifact's payload fingerprint, so it can only pass for the exact
    EXE the inventory was generated from. A freshly built bridge EXE has a
    different fingerprint by definition. Omitting it here does NOT assert
    distribution compliance and does not alter any audit status: the general
    public-distribution verdict remains HOLD, and the compliance-gated release
    path continues to use ``verify_archive``.
    """
    normalized = {name: _normalize_archive_path(name) for name in archive.toc}
    folded_paths = {path.casefold() for path in normalized.values()}
    errors = _scan_carchive_names(archive, normalized)

    missing = [
        path for path in REQUIRED_COMPLIANCE_PATHS if path.casefold() not in folded_paths
    ]
    if missing:
        errors.append("missing required compliance paths: " + ", ".join(missing))

    missing_runtimes = [
        path for path in BRIDGE_REQUIRED_RUNTIME_PATHS if path.casefold() not in folded_paths
    ]
    if missing_runtimes:
        errors.append("missing bundled runtime payloads: " + ", ".join(missing_runtimes))

    errors.extend(_verify_pyz(archive))
    errors.extend(_verify_pyside_payload(archive, normalized))
    errors.extend(_verify_libffi(archive, normalized))
    errors.extend(_verify_source_hash_manifest(archive, normalized))
    if LICENSE_MANIFEST_PATH.casefold() in folded_paths:
        errors.extend(_verify_license_manifest(archive, normalized))
    return errors


def verify_bridge(executable: Path) -> list[str]:
    """Return bridge-boundary errors for a one-file bridge *executable*."""
    digest = hashlib.sha256()
    with executable.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() in PROHIBITED_LEGACY_SHA256S:
        return ["artifact is a prohibited legacy one-file EXE"]
    try:
        archive = CArchiveReader(str(executable))
    except Exception as exc:  # Keep malformed/not-PyInstaller artifacts fail closed.
        return [f"cannot read PyInstaller CArchive: {exc}"]
    return verify_bridge_boundary(archive)


@dataclass(frozen=True)
class _TreeMember:
    """Lazy view of one file inside a one-folder distribution tree or ZIP."""

    size: int
    read: Callable[[], bytes]


def _is_reparse_point(path: Path) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return True
    attributes = getattr(status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag) or stat.S_ISLNK(status.st_mode)


def _is_onefolder_documentation_path(path: str) -> bool:
    lowered = path.casefold()
    return lowered.startswith(("docs/", "licenses/", "compliance/")) or lowered in {
        "license",
        "readme.md",
        "third_party_licenses.txt",
        "third_party_notices.md",
    }


def _load_onefolder_directory(root: Path) -> tuple[dict[str, _TreeMember], list[str]]:
    errors: list[str] = []
    members: dict[str, _TreeMember] = {}
    if root.name != ONEFOLDER_ROOT_NAME:
        errors.append(f"unexpected one-folder distribution root name: {root.name}")
    seen_folded: set[str] = set()
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        for name in list(dirnames):
            if _is_reparse_point(current_path / name):
                relative = (current_path / name).relative_to(root).as_posix()
                errors.append(f"one-folder tree contains a reparse point: {relative}")
                dirnames.remove(name)
        for name in filenames:
            absolute = current_path / name
            relative = absolute.relative_to(root).as_posix()
            if _is_reparse_point(absolute):
                errors.append(f"one-folder tree contains a reparse point: {relative}")
                continue
            folded = relative.casefold()
            if folded in seen_folded:
                errors.append(f"case-colliding one-folder tree path: {relative}")
                continue
            seen_folded.add(folded)
            members[relative] = _TreeMember(
                size=absolute.stat().st_size, read=absolute.read_bytes
            )
    if not members:
        errors.append("one-folder tree contains no files")
    return members, errors


def _load_onefolder_zip(handle: zipfile.ZipFile) -> tuple[dict[str, _TreeMember], list[str]]:
    errors: list[str] = []
    raw_members: dict[str, _TreeMember] = {}
    seen_folded: set[str] = set()
    top_levels: set[str] = set()
    for info in handle.infolist():
        name = info.filename.replace("\\", "/")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or (pure.parts and ":" in pure.parts[0]):
            errors.append(f"unsafe one-folder ZIP path: {name}")
            continue
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            errors.append(f"one-folder ZIP symlink is forbidden: {name}")
            continue
        if not pure.parts:
            continue
        top_levels.add(pure.parts[0])
        if info.is_dir():
            continue
        folded = name.casefold()
        if folded in seen_folded:
            errors.append(f"case-colliding one-folder ZIP path: {name}")
            continue
        seen_folded.add(folded)

        def _read(member_name: str = info.filename) -> bytes:
            return handle.read(member_name)

        raw_members[name] = _TreeMember(size=info.file_size, read=_read)
    if len(top_levels) != 1:
        errors.append(
            "one-folder ZIP must contain exactly one top-level directory, "
            f"found {sorted(top_levels)}"
        )
        return {}, errors
    top_level = next(iter(top_levels))
    if top_level != ONEFOLDER_ROOT_NAME:
        errors.append(f"unexpected one-folder ZIP root: {top_level}")
        return {}, errors
    members = {
        name[len(top_level) + 1 :]: member
        for name, member in raw_members.items()
        if name.startswith(f"{top_level}/") and name != f"{top_level}/"
    }
    if not members:
        errors.append("one-folder ZIP contains no files")
    return members, errors


def _scan_onefolder_launcher(payload: bytes) -> list[str]:
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="openfetch-onefolder-verify-") as temporary:
        executable = Path(temporary) / ONEFOLDER_LAUNCHER_PATH
        executable.write_bytes(payload)
        try:
            archive = CArchiveReader(str(executable))
        except Exception as exc:  # Keep malformed launchers fail closed.
            return [f"cannot read one-folder launcher CArchive: {exc}"]
        for archive_name in archive.toc:
            path = _normalize_archive_path(str(archive_name))
            lowered = path.casefold()
            if lowered.endswith(_LAUNCHER_FORBIDDEN_NATIVE_SUFFIXES):
                errors.append(f"one-folder launcher embeds a native library: {path}")
            if lowered.endswith(_RAW_JAVASCRIPT_SUFFIXES):
                errors.append(f"raw JavaScript/TypeScript in one-folder launcher: {path}")
            if _PYQT_TOKEN.search(lowered) and not _is_documentation_path(path):
                errors.append(f"PyQt payload is forbidden in one-folder launcher: {path}")
            if _PROVIDER_TOKEN.search(lowered) and not _is_documentation_path(path):
                errors.append(f"provider payload is forbidden in one-folder launcher: {path}")
        pyz_names = [
            name for name, entry in archive.toc.items() if _entry_type(entry) == "z"
        ]
        if len(pyz_names) != 1:
            errors.append(
                f"one-folder launcher must embed exactly one PYZ, found {len(pyz_names)}"
            )
            return errors
        try:
            pyz = archive.open_embedded_archive(pyz_names[0])
            module_names = [str(name) for name in pyz.toc]
        except Exception as exc:  # PyInstaller raises archive-specific exceptions.
            errors.append(f"cannot inspect one-folder launcher PYZ: {exc}")
            return errors
        if not any(name.casefold() == "pyside6" for name in module_names):
            errors.append("one-folder launcher PYZ does not contain PySide6")
        for module_name in module_names:
            lowered = module_name.casefold()
            if _PYQT_TOKEN.search(lowered):
                errors.append(f"PyQt module is forbidden in one-folder launcher PYZ: {module_name}")
            if _PROVIDER_TOKEN.search(lowered):
                errors.append(
                    f"provider module is forbidden in one-folder launcher PYZ: {module_name}"
                )
    return errors


def _verify_onefolder_executables(
    members: dict[str, _TreeMember],
    launcher_scan: Callable[[bytes], list[str]],
) -> list[str]:
    errors: list[str] = []
    pinned_folded = {path.casefold(): (path, digest) for path, digest in
                     ONEFOLDER_PINNED_EXECUTABLE_SHA256.items()}
    for relative, member in sorted(members.items()):
        folded = relative.casefold()
        if not folded.endswith(".exe"):
            continue
        if folded == ONEFOLDER_LAUNCHER_PATH.casefold():
            errors.extend(launcher_scan(member.read()))
            continue
        pinned = pinned_folded.get(folded)
        if pinned is None:
            errors.append(f"unknown executable in one-folder tree: {relative}")
            continue
        actual = _sha256(member.read())
        if actual != pinned[1]:
            errors.append(
                f"pinned executable hash mismatch for {pinned[0]}: "
                f"expected {pinned[1]}, got {actual}"
            )
    return errors


def _verify_onefolder_prohibited_hashes(members: dict[str, _TreeMember]) -> list[str]:
    errors: list[str] = []
    for relative, member in sorted(members.items()):
        folded = relative.casefold()
        if not (
            folded.endswith((".exe", ".zip")) or member.size in PROHIBITED_LEGACY_SIZES
        ):
            continue
        if _sha256(member.read()) in PROHIBITED_LEGACY_SHA256S:
            errors.append(f"prohibited legacy artifact hash in one-folder tree: {relative}")
    return errors


def _onefolder_member(
    members: dict[str, _TreeMember], path: str
) -> _TreeMember | None:
    folded = path.casefold()
    for relative, member in members.items():
        if relative.casefold() == folded:
            return member
    return None


def _verify_onefolder_qt_inventory(members: dict[str, _TreeMember]) -> list[str]:
    root_member = _onefolder_member(members, "QT-PYSIDE-COMPONENTS.json")
    if root_member is None:
        return []  # The required-path check reports this once.
    errors: list[str] = []
    compliance_member = _onefolder_member(members, "compliance/QT-PYSIDE-COMPONENTS.json")
    root_bytes = root_member.read()
    if compliance_member is not None and compliance_member.read() != root_bytes:
        errors.append(
            "QT-PYSIDE-COMPONENTS.json differs between tree root and compliance copy"
        )
    try:
        payload = json.loads(root_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        return errors + [f"invalid QT-PYSIDE-COMPONENTS.json: {exc}"]
    rows = payload.get("files")
    if not isinstance(rows, list) or not rows:
        return errors + ["QT-PYSIDE-COMPONENTS.json has no file records"]
    manifest_paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            errors.append("QT-PYSIDE-COMPONENTS.json has an invalid file row")
            continue
        relative = row["path"].replace("\\", "/")
        if relative.casefold() in {path.casefold() for path in manifest_paths}:
            errors.append(f"duplicate Qt/PySide inventory path: {relative}")
            continue
        manifest_paths.add(relative)
        member = _onefolder_member(members, relative)
        if member is None:
            errors.append(f"Qt/PySide inventory file is missing from the tree: {relative}")
            continue
        content = member.read()
        if row.get("size") != len(content):
            errors.append(f"Qt/PySide inventory size mismatch: {relative}")
        if row.get("sha256") != _sha256(content):
            errors.append(f"Qt/PySide inventory hash mismatch: {relative}")
    replaceable_prefixes = tuple(
        f"{root.casefold()}/" for root in _ONEFOLDER_REPLACEABLE_ROOTS
    )
    on_disk = {
        relative
        for relative in members
        if relative.casefold().startswith(replaceable_prefixes)
    }
    manifest_folded = {path.casefold() for path in manifest_paths}
    on_disk_folded = {path.casefold() for path in on_disk}
    if manifest_folded != on_disk_folded:
        unlisted = sorted(on_disk_folded - manifest_folded)
        absent = sorted(manifest_folded - on_disk_folded)
        errors.append(
            "Qt/PySide inventory does not exactly cover the PySide6/shiboken6 tree: "
            f"unlisted={unlisted}, absent={absent}"
        )
    return errors


def _verify_onefolder_binary_map(members: dict[str, _TreeMember]) -> list[str]:
    map_member = _onefolder_member(members, "compliance/BINARY-TO-SOURCE-MAP.json")
    if map_member is None:
        return []  # The required-path check reports this once.
    try:
        payload = json.loads(map_member.read().decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        return [f"invalid embedded binary-to-source map: {exc}"]
    errors: list[str] = []
    rows = payload.get("files")
    if not isinstance(rows, list) or not rows:
        return ["embedded binary-to-source map has no file records"]
    by_path: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            errors.append("embedded binary-to-source map has an invalid row")
            continue
        relative = row["path"]
        if relative in by_path:
            errors.append(f"duplicate binary-map path: {relative}")
            continue
        by_path[relative] = row
    if set(by_path) != set(members):
        unlisted = sorted(set(members) - set(by_path))[:5]
        absent = sorted(set(by_path) - set(members))[:5]
        errors.append(
            "binary-map coverage differs from the one-folder tree "
            f"(unexpected files or missing rows): unlisted={unlisted}, absent={absent}"
        )
        return errors
    tree = hashlib.sha256()
    for relative in sorted(members, key=str.casefold):
        row = by_path[relative]
        content = members[relative].read()
        self_map = relative.casefold() == "compliance/binary-to-source-map.json"
        expected_size: int | str = "SELF-REFERENTIAL" if self_map else len(content)
        expected_hash = (
            "SELF-REFERENTIAL" if self_map else hashlib.sha256(content).hexdigest()
        )
        if row.get("size") != expected_size or row.get("sha256") != expected_hash:
            errors.append(f"binary-map size/hash mismatch: {relative}")
        if row.get("mapping_status") != "PASS" or not row.get("components"):
            errors.append(f"unresolved native/source mapping in binary map: {relative}")
        tree.update(relative.encode("utf-8"))
        tree.update(b"\0")
        tree.update(b"SELF-REFERENTIAL" if self_map else bytes.fromhex(expected_hash))
        tree.update(b"\0")
    if payload.get("tree_sha256") != tree.hexdigest():
        errors.append("binary-map canonical tree hash differs from the one-folder tree")
    if payload.get("file_count") != len(rows):
        errors.append("binary-map file_count differs from its file records")
    return errors


def _verify_onefolder_license_manifest(members: dict[str, _TreeMember]) -> list[str]:
    manifest_member = _onefolder_member(members, LICENSE_MANIFEST_PATH)
    if manifest_member is None:
        return []  # The required-path check reports this once.
    try:
        manifest = _parse_manifest(manifest_member.read().decode("utf-8-sig"))
    except (UnicodeError, ValueError) as exc:
        return [f"invalid one-folder license manifest: {exc}"]
    errors: list[str] = []
    actual_license_paths = {
        PurePosixPath(relative[len("licenses/") :])
        for relative in members
        if relative.casefold().startswith("licenses/")
        and relative.casefold() != LICENSE_MANIFEST_PATH.casefold()
    }
    if set(manifest) != actual_license_paths:
        unlisted = sorted(actual_license_paths - set(manifest), key=str)
        absent = sorted(set(manifest) - actual_license_paths, key=str)
        errors.append(
            "one-folder license manifest coverage mismatch: "
            f"unlisted={[path.as_posix() for path in unlisted]}, "
            f"absent={[path.as_posix() for path in absent]}"
        )
    for relative_path, expected_hash in manifest.items():
        member = _onefolder_member(members, f"licenses/{relative_path.as_posix()}")
        if member is None:
            continue
        payload = member.read()
        if not payload:
            errors.append(f"one-folder license file is empty: licenses/{relative_path}")
        elif _sha256(payload) != expected_hash:
            errors.append(f"one-folder license hash mismatch: licenses/{relative_path}")
    return errors


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _verify_onefolder_directory_manifest(
    members: dict[str, _TreeMember], manifest_path: Path | None
) -> list[str]:
    if manifest_path is None:
        return [
            "directory update manifest is required for the one-folder artifact "
            f"(--directory-manifest {ONEFOLDER_DIRECTORY_MANIFEST_NAME})"
        ]
    if not manifest_path.is_file():
        return [f"directory update manifest is missing: {manifest_path}"]
    errors: list[str] = []
    if manifest_path.name != ONEFOLDER_DIRECTORY_MANIFEST_NAME:
        errors.append(
            "directory update manifest must be named "
            f"{ONEFOLDER_DIRECTORY_MANIFEST_NAME}, found {manifest_path.name}"
        )
    document = manifest_path.read_bytes()
    if len(document) > DIRECTORY_MANIFEST_MAX_BYTES:
        return errors + ["directory update manifest is too large"]
    try:
        payload = json.loads(document.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeError, ValueError) as exc:
        return errors + [f"invalid directory update manifest: {exc}"]
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
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        return errors + ["directory update manifest fields are invalid"]
    expected_values = {
        "schema_version": 1,
        "application_name": APP_NAME,
        "release_version": APPLICATION_VERSION,
        "platform": "windows",
        "architecture": "x64",
        "channel": "stable",
        "root_name": ONEFOLDER_ROOT_NAME,
        "executable": ONEFOLDER_LAUNCHER_PATH,
    }
    for key, expected in expected_values.items():
        if payload.get(key) != expected:
            errors.append(
                f"directory update manifest {key} must be {expected!r}, "
                f"found {payload.get(key)!r}"
            )
    files = payload.get("files")
    if not isinstance(files, dict) or not files:
        return errors + ["directory update manifest has no file records"]
    if len(files) > DIRECTORY_MANIFEST_MAX_FILES:
        return errors + ["directory update manifest lists too many files"]
    total = 0
    for relative, record in files.items():
        if (
            not isinstance(relative, str)
            or not relative
            or len(relative) > DIRECTORY_MANIFEST_MAX_PATH_LENGTH
            or "\\" in relative
        ):
            errors.append(f"invalid directory-manifest path: {relative!r}")
            continue
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            errors.append(f"unsafe directory-manifest path: {relative}")
            continue
        if (
            not isinstance(record, dict)
            or set(record) != {"sha256", "size"}
            or not isinstance(record.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
            or not isinstance(record.get("size"), int)
            or record["size"] < 0
        ):
            errors.append(f"invalid directory-manifest record: {relative}")
            continue
        total += record["size"]
    if payload.get("total_size") != total:
        errors.append("directory-manifest total_size does not match its file records")
    if not (DIRECTORY_MANIFEST_MIN_TOTAL <= total <= DIRECTORY_MANIFEST_MAX_TOTAL):
        errors.append("directory-manifest total size is outside the accepted window")
    if set(files) != set(members):
        unlisted = sorted(set(members) - set(files))[:5]
        absent = sorted(set(files) - set(members))[:5]
        errors.append(
            "directory-manifest coverage differs from the one-folder tree: "
            f"unlisted={unlisted}, absent={absent}"
        )
    else:
        for relative, record in files.items():
            member = members[relative]
            if not isinstance(record, dict):
                continue
            if record.get("size") != member.size:
                errors.append(f"directory-manifest size mismatch: {relative}")
            elif record.get("sha256") != _sha256(member.read()):
                errors.append(f"directory-manifest hash mismatch: {relative}")
    replaceable = payload.get("replaceable_paths")
    if not isinstance(replaceable, list):
        errors.append("directory-manifest replaceable_paths must be a list")
        return errors
    if len(replaceable) > DIRECTORY_MANIFEST_MAX_REPLACEABLE:
        errors.append("directory-manifest lists too many replaceable paths")
    for relative in replaceable:
        if not isinstance(relative, str) or relative not in files:
            errors.append(f"replaceable path is not a manifest file: {relative!r}")
            continue
        if PurePosixPath(relative).parts[0] not in _ONEFOLDER_REPLACEABLE_ROOTS:
            errors.append(f"replaceable path outside Qt/PySide families: {relative}")
    expected_replaceable = sorted(
        relative
        for relative in files
        if isinstance(relative, str)
        and PurePosixPath(relative).parts
        and PurePosixPath(relative).parts[0] in _ONEFOLDER_REPLACEABLE_ROOTS
    )
    if sorted(str(item) for item in replaceable) != expected_replaceable:
        errors.append(
            "directory-manifest replaceable_paths must exactly cover the "
            "PySide6/shiboken6 files"
        )
    return errors


def verify_onefolder_members(
    members: dict[str, _TreeMember],
    directory_manifest: Path | None,
    *,
    launcher_scan: Callable[[bytes], list[str]] | None = None,
) -> list[str]:
    """Return release-blocking errors for a loaded one-folder tree."""
    scan = _scan_onefolder_launcher if launcher_scan is None else launcher_scan
    errors: list[str] = []
    folded_paths = {relative.casefold() for relative in members}

    missing = [
        path for path in ONEFOLDER_REQUIRED_PATHS if path.casefold() not in folded_paths
    ]
    if missing:
        errors.append("missing required one-folder paths: " + ", ".join(missing))

    for relative in sorted(members):
        lowered = relative.casefold()
        name = PurePosixPath(lowered).name
        if lowered.endswith(_RAW_JAVASCRIPT_SUFFIXES):
            errors.append(f"raw JavaScript/TypeScript payload is forbidden: {relative}")
        if "node_modules/canvas/" in lowered or name == "canvas.node":
            errors.append(f"canvas native/provider payload is forbidden: {relative}")
        if _PYQT_TOKEN.search(lowered) and not _is_onefolder_documentation_path(relative):
            errors.append(f"PyQt code or binary is forbidden: {relative}")
        if _PROVIDER_TOKEN.search(lowered) and not _is_onefolder_documentation_path(relative):
            errors.append(f"in-process provider code is forbidden: {relative}")
        if (
            name.endswith(_RUNTIME_STATE_SUFFIXES)
            or any(token in name for token in _RUNTIME_STATE_NAME_TOKENS)
            or name in _RUNTIME_STATE_EXACT_NAMES
        ):
            errors.append(f"runtime state must not ship in the release tree: {relative}")

    errors.extend(_verify_onefolder_executables(members, scan))
    errors.extend(_verify_onefolder_prohibited_hashes(members))
    errors.extend(_verify_onefolder_qt_inventory(members))
    errors.extend(_verify_onefolder_binary_map(members))
    errors.extend(_verify_onefolder_license_manifest(members))
    errors.extend(_verify_onefolder_directory_manifest(members, directory_manifest))

    root_metadata = _onefolder_member(members, "PROJECT-METADATA.json")
    compliance_metadata = _onefolder_member(members, "compliance/PROJECT-METADATA.json")
    if (
        root_metadata is not None
        and compliance_metadata is not None
        and root_metadata.read() != compliance_metadata.read()
    ):
        errors.append("PROJECT-METADATA.json differs between tree root and compliance copy")
    return errors


def verify_onefolder(
    artifact: Path,
    directory_manifest: Path | None,
    *,
    launcher_scan: Callable[[bytes], list[str]] | None = None,
) -> list[str]:
    """Return release-blocking errors for a one-folder directory or ZIP."""
    if artifact.is_dir():
        members, errors = _load_onefolder_directory(artifact)
        if not members:
            return errors
        return errors + verify_onefolder_members(
            members, directory_manifest, launcher_scan=launcher_scan
        )
    try:
        with zipfile.ZipFile(artifact) as handle:
            members, errors = _load_onefolder_zip(handle)
            if not members:
                return errors
            return errors + verify_onefolder_members(
                members, directory_manifest, launcher_scan=launcher_scan
            )
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"cannot read one-folder ZIP: {exc}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "artifact",
        type=Path,
        help="packaged one-file EXE, one-folder distribution directory, or one-folder ZIP",
    )
    parser.add_argument(
        "--directory-manifest",
        type=Path,
        help="sibling directory-update manifest asset for a one-folder artifact",
    )
    parser.add_argument(
        "--bridge-boundary",
        action="store_true",
        help=(
            "one-file EXEs only: verify the payload boundary (no PyQt, no provider, "
            "audited Qt paths, pinned CPython natives, required notices) without the "
            "artifact-specific distribution-inventory fingerprint. Does not assert "
            "distribution compliance; the public verdict remains HOLD."
        ),
    )
    args = parser.parse_args()
    artifact = args.artifact.resolve()
    if not artifact.exists():
        parser.error(f"artifact does not exist: {artifact}")

    if args.bridge_boundary:
        if artifact.is_dir() or artifact.suffix.casefold() == ".zip":
            parser.error("--bridge-boundary applies only to a one-file EXE")
        if args.directory_manifest is not None:
            parser.error("--bridge-boundary and --directory-manifest are mutually exclusive")
        errors = verify_bridge(artifact)
        if errors:
            for error in errors:
                print(f"HOLD: {error}")
            return 1
        print(
            "PASS: bridge payload boundary verified (no PyQt, no provider payload, "
            "audited PySide6/Qt paths, pinned CPython natives, required notices). "
            "General compliance status remains HOLD."
        )
        return 0

    if artifact.is_dir() or artifact.suffix.casefold() == ".zip":
        manifest = args.directory_manifest.resolve() if args.directory_manifest else None
        errors = verify_onefolder(artifact, manifest)
        success = (
            "PASS: one-folder layout, distribution boundary, notices, inventories, "
            "and directory-update manifest verified."
        )
    else:
        if args.directory_manifest is not None:
            parser.error("--directory-manifest applies only to one-folder artifacts")
        if not artifact.is_file():
            parser.error(f"executable does not exist: {artifact}")
        errors = verify(artifact)
        success = (
            "PASS: packaged PySide6 boundary, notices, manifests, and CPython libffi "
            "verified."
        )
    if errors:
        for error in errors:
            print(f"HOLD: {error}")
        return 1
    print(success)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
