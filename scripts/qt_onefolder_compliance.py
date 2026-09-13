"""Build, verify, and exercise the replaceable Qt/PySide one-folder candidate."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

try:
    from scripts.project_identity import (
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
        ONEFOLDER_SPEC_NAME,
    )
except ModuleNotFoundError:  # executed directly as scripts/qt_onefolder_compliance.py
    from project_identity import (  # type: ignore[no-redef]
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
        ONEFOLDER_SPEC_NAME,
    )

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = PROJECT_ROOT / ONEFOLDER_SPEC_NAME
VERSION = APPLICATION_VERSION
DIST_NAME = ONEFOLDER_DIST_NAME
COMPONENT_MANIFEST_NAME = "QT-PYSIDE-COMPONENTS.json"
REPLACEMENT_MARKER = b"\nOPENFETCH_QT_REPLACEMENT_SMOKE_V1\n"

PYSIDE_VERSION = "6.11.1"
SHIBOKEN_VERSION = "6.11.1"
QT_VERSION = "6.11.1"
PYSIDE_SOURCE_URL = (
    "https://download.qt.io/official_releases/QtForPython/pyside6/"
    "PySide6-6.11.1-src/pyside-setup-everywhere-src-6.11.1.tar.xz"
)
PYSIDE_SOURCE_SHA256 = (
    "6ffd9835bb0dd2c56f061d62f1616bb1707cfc0202b80e3165d6be087f3965e2"
)
QTBASE_SOURCE_URL = (
    "https://download.qt.io/official_releases/qt/6.11/6.11.1/submodules/"
    "qtbase-everywhere-src-6.11.1.tar.xz"
)
QTBASE_SOURCE_SHA256 = (
    "d9594a31228aa23ad6b531719a29b45f0f3989fe6c136d45767ea179f233c1ac"
)
SOURCE_ARCHIVES = {
    "pyside-setup-everywhere-src-6.11.1.tar.xz": PYSIDE_SOURCE_SHA256,
    "qtbase-everywhere-src-6.11.1.tar.xz": QTBASE_SOURCE_SHA256,
}

WINDOWS_WHEELS = {
    "PySide6": {
        "url": "https://files.pythonhosted.org/packages/57/f2/d9d8ce1373dabb37e5919f63cd18446556079631d3f2eea3ada03c29f6b8/pyside6-6.11.1-cp310-abi3-win_amd64.whl",
        "sha256": "0968877ab1fb4ef3587a284da6fe05e8647ada56a6a3750b6395188e01f4aba6",
    },
    "PySide6-Essentials": {
        "url": "https://files.pythonhosted.org/packages/64/0e/b663ecc96ca57b5c91b83b6615d6b174380b0faf30338125c26e053d6aa7/pyside6_essentials-6.11.1-cp310-abi3-win_amd64.whl",
        "sha256": "63311bd48e32c584599ab04b9ef7c324082374cd2c9fa533f978fb893bb47e40",
    },
    "PySide6-Addons": {
        "url": "https://files.pythonhosted.org/packages/9a/bd/8adc4d350b3b363f3dfc8fccdcf5bfed25f7e36c2fff30c64e106f4f1572/pyside6_addons-6.11.1-cp310-abi3-win_amd64.whl",
        "sha256": "0d13c4dfd671b050a48e4f8d8ddc724b7248f9c0437e7fc47fdf316278572923",
    },
    "shiboken6": {
        "url": "https://files.pythonhosted.org/packages/52/b5/3f6fb2ee65b534193fb4ef713dd619dc31dadff5d12c16979a7699ad58be/shiboken6-6.11.1-cp310-abi3-win_amd64.whl",
        "sha256": "c2c6863aa80ec18c0f82cea3417837b279cdc60024ac17123461dc9042577df7",
    },
}

# This is intentionally the complete retained family, including colocated
# Microsoft runtimes.  The latter are not asserted to be LGPL-covered.
EXPECTED_QT_PATHS = (
    "PySide6/MSVCP140.dll",
    "PySide6/MSVCP140_1.dll",
    "PySide6/MSVCP140_2.dll",
    "PySide6/opengl32sw.dll",
    "PySide6/plugins/imageformats/qico.dll",
    "PySide6/plugins/platforms/qoffscreen.dll",
    "PySide6/plugins/platforms/qwindows.dll",
    "PySide6/plugins/styles/qmodernwindowsstyle.dll",
    "PySide6/pyside6.abi3.dll",
    "PySide6/Qt6Core.dll",
    "PySide6/Qt6Gui.dll",
    "PySide6/Qt6Widgets.dll",
    "PySide6/QtCore.pyd",
    "PySide6/QtGui.pyd",
    "PySide6/QtWidgets.pyd",
    "PySide6/VCRUNTIME140.dll",
    "PySide6/VCRUNTIME140_1.dll",
    "shiboken6/MSVCP140.dll",
    "shiboken6/Shiboken.pyd",
    "shiboken6/shiboken6.abi3.dll",
    "shiboken6/VCRUNTIME140.dll",
    "shiboken6/VCRUNTIME140_1.dll",
)

EXPECTED_QT_SHA256 = {
    "PySide6/MSVCP140.dll": "708dd7bbc7bd23bce9e93f7837a70c2dd7ad55cff43801e92c0f7fcd7dda47cd",
    "PySide6/MSVCP140_1.dll": "b2113956aa3fcb9decfe65be1ee7829f8e3ae0899633ae89fe04888ada201594",
    "PySide6/MSVCP140_2.dll": "1b806b427ffb573deff8478cf6fe336465fe2c67e0919bb95f452b6f31d25736",
    "PySide6/opengl32sw.dll": "4a7d90f91fdecb5df7b426bc2d05974b8d7ffa450af2d1f93f3eca05800718da",
    "PySide6/plugins/imageformats/qico.dll": "f81378dd51392ff0d3ae094d5e59dfc4fa664a0ef4d756d6ed40584f90af2758",
    "PySide6/plugins/platforms/qoffscreen.dll": "426266e8ba0ea07c416616ad9973702fe126d4559cb2ee11e1c9bdbae85ba755",
    "PySide6/plugins/platforms/qwindows.dll": "54d736de022f707e9f7f555e4c9f9e993253cd5b0ee2364e6a9458c180828c42",
    "PySide6/plugins/styles/qmodernwindowsstyle.dll": "9af96b09ebaf7ff13e22c70bf69b9c3f226f069375d1a9f9efd63e944e43f5fb",
    "PySide6/pyside6.abi3.dll": "d4072be872b31f3748de5e6c28cb2976dafbf063d3ccfa38e5dabda29babcdaf",
    "PySide6/Qt6Core.dll": "65fe6224b6c47a15b058738031d31dce9928c4d7a58e1b8db6434f6f5cddd702",
    "PySide6/Qt6Gui.dll": "cd071161ad325ff2de92b0e33d71334ef20712544796949623ce92dfb3957e90",
    "PySide6/Qt6Widgets.dll": "5a9f37dedd3dc5bcc1a4bb8ea919c49fc62df751a1450accc34379eb6710eab6",
    "PySide6/QtCore.pyd": "be52341a5df1f76ecca2fb1e94eb429dfa46f0b659ed6536f25119b565b21ea8",
    "PySide6/QtGui.pyd": "f0549716b10a8b4fbd5c6c041f36af215223809f919f4c4722d44cc199d5c593",
    "PySide6/QtWidgets.pyd": "85cb6c2181b4b09887a7d8507dd950844d1b8f74a9c4002c7b71169f75bf6fda",
    "PySide6/VCRUNTIME140.dll": "c6e841078cd352299a58925991e2552f7251b046253ba895b3ad50cd5cd32ec6",
    "PySide6/VCRUNTIME140_1.dll": "b322e382ea249b50009f14a9a71ad16729eb6e4b58a8d3b3be6ac66ea6342a22",
    "shiboken6/MSVCP140.dll": "005f2324c7ff79bbe9a44992b0708abb4c871bd24bcc7a34aca5eab4439c1f4a",
    "shiboken6/Shiboken.pyd": "0e2c5318c5ac60a016a12230bbb1f6a9d990c45cbf4a7c4af24aefb5ab7dc40a",
    "shiboken6/shiboken6.abi3.dll": "47f4f9b44c95037565dd14f4be04f350f20c53c05483b750e0be867c39a7441e",
    "shiboken6/VCRUNTIME140.dll": "8d9c679c825c5fff298d66c41af30f35c289fc101868dfc9635547bada0daba6",
    "shiboken6/VCRUNTIME140_1.dll": "e4d7ea5f4f4ff6d0c208e693853617cdef0ad71cfe5dd5c3ae16c8a6b64c18ea",
}

REQUIRED_RECIPIENT_PATHS = (
    "LICENSE",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "SOURCE-HASHES.sha256",
    "licenses/RELEASE-LICENSE-MANIFEST.sha256",
    "docs/LGPL-COMPLIANCE.md",
    "docs/QT-REPLACEMENT-GUIDE.md",
    "docs/QT-BUILD-PROVENANCE.md",
)


class ComplianceError(RuntimeError):
    """Raised when a one-folder compliance invariant is not met."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_build_environment(python: Path) -> None:
    if Path(python).resolve() != Path(sys.executable).resolve():
        raise ComplianceError(
            "the build must run under the same explicitly pinned interpreter "
            "that executes this verifier"
        )
    if sys.version_info[:3] != (3, 12, 9):
        raise ComplianceError(
            f"build interpreter is {sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}; expected CPython 3.12.9"
        )
    expected_distributions = {
        "PyInstaller": "6.21.0",
        "PySide6": PYSIDE_VERSION,
        "PySide6-Essentials": PYSIDE_VERSION,
        "PySide6-Addons": PYSIDE_VERSION,
        "shiboken6": SHIBOKEN_VERSION,
    }
    for distribution, expected in expected_distributions.items():
        actual = importlib.metadata.version(distribution)
        if actual != expected:
            raise ComplianceError(
                f"build environment has {distribution} {actual}; expected {expected}"
            )
    verify_locked_wheels()
    _verify_installed_wheel_records()


def _run_prebuild_gate(python: Path, script: str, *arguments: str) -> None:
    completed = subprocess.run(
        [
            str(Path(python).resolve()),
            str(PROJECT_ROOT / "scripts" / script),
            *arguments,
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        detail = (completed.stdout + completed.stderr).strip()
        raise ComplianceError(f"prebuild gate {script} failed: {detail[:4000]}")


def _has_reparse_attribute(path: Path) -> bool:
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _reject_reparse_tree(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        if _has_reparse_attribute(path):
            raise ComplianceError(f"distribution contains a reparse point: {path}")


def verify_source_archives() -> None:
    source_root = PROJECT_ROOT / "third_party_sources" / "qt-pyside"
    sums_path = source_root / "SHA256SUMS"
    if not sums_path.is_file():
        raise ComplianceError("Qt/PySide source SHA256SUMS is missing")
    expected_sums = "".join(
        f"{digest}  {name}\n" for name, digest in SOURCE_ARCHIVES.items()
    )
    if sums_path.read_text(encoding="utf-8") != expected_sums:
        raise ComplianceError("Qt/PySide source SHA256SUMS does not match the pinned set")
    for name, expected in SOURCE_ARCHIVES.items():
        archive = source_root / name
        if not archive.is_file() or sha256_file(archive) != expected:
            raise ComplianceError(f"Qt/PySide source archive hash mismatch: {name}")
        try:
            with tarfile.open(archive, "r:xz") as source_tar:
                members = source_tar.getmembers()
        except (OSError, tarfile.TarError) as exc:
            raise ComplianceError(f"Qt/PySide source archive is unreadable: {name}") from exc
        if not members:
            raise ComplianceError(f"Qt/PySide source archive is empty: {name}")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ComplianceError(f"unsafe source archive member in {name}: {member.name}")


def verify_locked_wheels() -> None:
    try:
        with (PROJECT_ROOT / "uv.lock").open("rb") as stream:
            lock = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ComplianceError("uv.lock is missing or invalid TOML") from exc
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ComplianceError("uv.lock has no package table")
    for package, record in WINDOWS_WHEELS.items():
        matches = [
            item
            for item in packages
            if isinstance(item, dict)
            and str(item.get("name", "")).casefold() == package.casefold()
        ]
        if len(matches) != 1 or matches[0].get("version") != PYSIDE_VERSION:
            raise ComplianceError(
                f"uv.lock does not contain exactly one {package} {PYSIDE_VERSION} record"
            )
        wheels = matches[0].get("wheels")
        if not isinstance(wheels, list):
            raise ComplianceError(f"uv.lock {package} record has no wheel table")
        wheel_matches = [
            wheel
            for wheel in wheels
            if isinstance(wheel, dict)
            and wheel.get("url") == record["url"]
            and wheel.get("hash") == f"sha256:{record['sha256']}"
        ]
        if len(wheel_matches) != 1:
            raise ComplianceError(
                f"uv.lock does not bind {package} {PYSIDE_VERSION} to the audited "
                "Windows wheel URL and SHA-256"
            )


def _wheel_record_digest(record: importlib.metadata.PackagePath) -> str:
    if record.hash is None or record.hash.mode != "sha256":
        raise ComplianceError(f"wheel RECORD has no SHA-256 for {record}")
    encoded = record.hash.value
    encoded += "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded).hex()


def _verify_installed_wheel_records() -> None:
    expected_by_distribution = {
        "PySide6-Essentials": [
            relative for relative in EXPECTED_QT_PATHS if relative.startswith("PySide6/")
        ],
        "shiboken6": [
            relative for relative in EXPECTED_QT_PATHS if relative.startswith("shiboken6/")
        ],
    }
    for distribution_name, expected_paths in expected_by_distribution.items():
        distribution = importlib.metadata.distribution(distribution_name)
        records = {
            PurePosixPath(str(record).replace("\\", "/")).as_posix().casefold(): record
            for record in distribution.files or ()
        }
        for relative in expected_paths:
            record = records.get(relative.casefold())
            if record is None:
                raise ComplianceError(
                    f"{distribution_name} wheel RECORD omits {relative}"
                )
            installed = Path(record.locate()).resolve()
            if not installed.is_file():
                raise ComplianceError(f"installed wheel file is missing: {relative}")
            if record.size != installed.stat().st_size:
                raise ComplianceError(f"wheel RECORD size mismatch: {relative}")
            if _wheel_record_digest(record) != sha256_file(installed):
                raise ComplianceError(f"wheel RECORD hash mismatch: {relative}")


def _forbidden_archive_name(value: str) -> bool:
    normalized = value.casefold().replace("\\", "/").replace("-", "_")
    return (
        "pyqt" in normalized
        or "bgutil" in normalized
        or "getpot" in normalized
        or normalized == "yt_dlp_plugins"
        or normalized.startswith("yt_dlp_plugins.")
        or "/yt_dlp_plugins/" in normalized
        or "node_modules/canvas" in normalized
    )


def verify_executable_boundary(executable: Path) -> None:
    try:
        from PyInstaller.archive.readers import CArchiveReader

        archive = CArchiveReader(str(executable))
    except Exception as exc:
        raise ComplianceError("one-folder executable is not a readable PyInstaller archive") from exc
    archive_names = [str(name).replace("\\", "/") for name in archive.toc]
    forbidden = sorted(name for name in archive_names if _forbidden_archive_name(name))
    native = sorted(
        name
        for name in archive_names
        if name.casefold().endswith((".dll", ".pyd", ".so", ".dylib"))
    )
    if forbidden:
        raise ComplianceError(f"forbidden payload is embedded in the EXE: {forbidden}")
    if native:
        raise ComplianceError(
            f"shared/native libraries are embedded instead of externally replaceable: {native}"
        )
    if "PYZ.pyz" not in archive.toc:
        raise ComplianceError("one-folder executable has no auditable PYZ")
    try:
        pyz = archive.open_embedded_archive("PYZ.pyz")
    except Exception as exc:
        raise ComplianceError("one-folder executable PYZ is unreadable") from exc
    forbidden_modules = sorted(
        str(name) for name in pyz.toc if _forbidden_archive_name(str(name))
    )
    if forbidden_modules:
        raise ComplianceError(
            f"forbidden module is embedded in the EXE PYZ: {forbidden_modules}"
        )


def _safe_distribution_root(path: Path) -> Path:
    unresolved = Path(path).absolute()
    if unresolved.exists() and _has_reparse_attribute(unresolved):
        raise ComplianceError(f"distribution root is a reparse point: {unresolved}")
    root = unresolved.resolve()
    if not root.is_dir():
        raise ComplianceError(f"one-folder distribution is missing: {root}")
    if root.name != DIST_NAME:
        raise ComplianceError(
            f"distribution directory must be named {DIST_NAME}, got {root.name}"
        )
    _reject_reparse_tree(root)
    return root


def _path_record(root: Path, relative: str) -> dict[str, object]:
    path = root / Path(PurePosixPath(relative))
    if not path.is_file():
        raise ComplianceError(f"required Qt/PySide path is missing: {relative}")
    if path.is_symlink():
        raise ComplianceError(f"Qt/PySide path must not be a symlink: {relative}")
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ComplianceError(f"Qt/PySide path is not a PE image: {relative}")
    actual_hash = sha256_file(path)
    if actual_hash != EXPECTED_QT_SHA256[relative]:
        raise ComplianceError(
            f"Qt/PySide path differs from the audited wheel baseline: {relative}"
        )
    return {
        "path": relative,
        "size": path.stat().st_size,
        "sha256": actual_hash,
    }


def build_component_manifest(root: Path) -> dict[str, object]:
    root = _safe_distribution_root(root)
    if set(EXPECTED_QT_PATHS) != set(EXPECTED_QT_SHA256):
        raise ComplianceError("internal Qt/PySide baseline path/hash set is inconsistent")
    files = [_path_record(root, relative) for relative in EXPECTED_QT_PATHS]
    return {
        "schema_version": 1,
        "release_gate_status": "HOLD",
        "application_version": VERSION,
        "distribution_layout": "pyinstaller-one-folder-external-shared-libraries",
        "pyside6_version": PYSIDE_VERSION,
        "pyside6_essentials_version": PYSIDE_VERSION,
        "shiboken6_version": SHIBOKEN_VERSION,
        "qt_version": QT_VERSION,
        "modifications_to_upstream_qt_pyside_binaries": "none",
        "runtime_integrity_policy": (
            "application startup does not authenticate or restore external Qt/PySide files"
        ),
        "source_archives": [
            {
                "filename": "pyside-setup-everywhere-src-6.11.1.tar.xz",
                "url": PYSIDE_SOURCE_URL,
                "sha256": PYSIDE_SOURCE_SHA256,
            },
            {
                "filename": "qtbase-everywhere-src-6.11.1.tar.xz",
                "url": QTBASE_SOURCE_URL,
                "sha256": QTBASE_SOURCE_SHA256,
            },
        ],
        "files": files,
    }


def write_component_manifest(root: Path) -> Path:
    root = _safe_distribution_root(root)
    destination = root / COMPONENT_MANIFEST_NAME
    payload = build_component_manifest(root)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return destination


def verify_layout(root: Path, *, require_manifest: bool = True) -> dict[str, object]:
    root = _safe_distribution_root(root)
    verify_source_archives()
    verify_locked_wheels()
    executable = root / EXECUTABLE_NAME
    if not executable.is_file():
        raise ComplianceError(f"packaged executable is missing: {executable}")
    if executable.is_symlink():
        raise ComplianceError("packaged executable must not be a symlink")
    verify_executable_boundary(executable)

    for relative in REQUIRED_RECIPIENT_PATHS:
        path = root / Path(PurePosixPath(relative))
        if not path.is_file() or path.stat().st_size == 0:
            raise ComplianceError(f"recipient compliance file is missing or empty: {relative}")

    actual = build_component_manifest(root)
    actual_family_paths = {
        path.relative_to(root).as_posix()
        for family in (root / "PySide6", root / "shiboken6")
        for path in family.rglob("*")
        if path.is_file()
    }
    if actual_family_paths != set(EXPECTED_QT_PATHS):
        unexpected = sorted(actual_family_paths - set(EXPECTED_QT_PATHS))
        missing = sorted(set(EXPECTED_QT_PATHS) - actual_family_paths)
        raise ComplianceError(
            f"Qt/PySide family inventory is not exact; unexpected={unexpected}, missing={missing}"
        )
    manifest_path = root / COMPONENT_MANIFEST_NAME
    if require_manifest:
        if not manifest_path.is_file():
            raise ComplianceError(f"component manifest is missing: {manifest_path}")
        try:
            stored = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ComplianceError("component manifest is unreadable") from exc
        if stored != actual:
            raise ComplianceError("Qt/PySide component manifest does not match the distribution")

    forbidden: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().casefold()
        if (
            "pyqt" in relative
            or "yt_dlp_plugins" in relative
            or "bgutil" in relative
            or "getpot" in relative
            or "node_modules/canvas" in relative
        ):
            forbidden.append(relative)
    if forbidden:
        raise ComplianceError(
            "forbidden provider/PyQt payload in one-folder distribution: "
            + ", ".join(sorted(forbidden))
        )
    return actual


def _atomic_copy(source: Path, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.replace-{os.getpid()}")
    if temporary.exists():
        raise ComplianceError(f"stale replacement temporary file exists: {temporary}")
    try:
        shutil.copy2(source, temporary)
        with temporary.open("ab") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_overlay_replacement(source: Path, destination: Path, relative: str) -> None:
    temporary = destination.with_name(f".{destination.name}.overlay-{os.getpid()}")
    if temporary.exists():
        raise ComplianceError(f"stale overlay temporary file exists: {temporary}")
    try:
        with source.open("rb") as input_stream, temporary.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            output_stream.write(REPLACEMENT_MARKER)
            output_stream.write(relative.encode("ascii"))
            output_stream.flush()
            os.fsync(output_stream.fileno())
        shutil.copystat(source, temporary)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _installed_wheel_root() -> Path:
    versions = {
        "PySide6": PYSIDE_VERSION,
        "PySide6-Addons": PYSIDE_VERSION,
        "PySide6-Essentials": PYSIDE_VERSION,
        "shiboken6": SHIBOKEN_VERSION,
    }
    for distribution, expected in versions.items():
        actual = importlib.metadata.version(distribution)
        if actual != expected:
            raise ComplianceError(
                f"replacement set has {distribution} {actual}; expected {expected}"
            )
    _verify_installed_wheel_records()
    spec = importlib.util.find_spec("PySide6")
    if spec is None or spec.origin is None:
        raise ComplianceError("the approved PySide6 replacement set is unavailable")
    return Path(spec.origin).resolve().parent.parent


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if sys.platform == "win32":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
        taskkill = system_root / "System32" / "taskkill.exe"
        if taskkill.is_file():
            subprocess.run(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise ComplianceError("GUI smoke process tree did not terminate") from exc


def _relative_candidate_path(root: Path, value: object, label: str) -> str:
    path = Path(str(value)).resolve()
    try:
        relative = path.relative_to(root.resolve())
    except ValueError as exc:
        raise ComplianceError(f"{label} escaped the one-folder distribution: {path}") from exc
    return relative.as_posix() or "."


def _run_gui_smoke(
    root: Path, label: str, *, platform_name: str = "offscreen"
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix=f"openfetch-qt-{label}-") as temporary:
        result_path = Path(temporary) / "gui-result.json"
        environment = os.environ.copy()
        environment["QT_QPA_PLATFORM"] = platform_name
        smoke_argument = (
            "--internal-windows-gui-smoke"
            if platform_name == "windows"
            else "--internal-gui-startup-smoke"
        )
        process_options: dict[str, object] = {}
        if sys.platform == "win32":
            process_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            process_options["start_new_session"] = True
        process = subprocess.Popen(
            [
                str(root / EXECUTABLE_NAME),
                smoke_argument,
                str(result_path),
            ],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **process_options,  # type: ignore[arg-type]
        )
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired as exc:
            _terminate_process_tree(process)
            raise ComplianceError(f"{label} GUI smoke timed out") from exc
        if process.returncode != 0:
            raise ComplianceError(
                f"{label} GUI smoke exited {process.returncode}: "
                f"{stderr.decode('utf-8', errors='replace')[:2000]}"
            )
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ComplianceError(f"{label} GUI smoke produced no valid result") from exc
        if (
            not payload.get("passed")
            or str(payload.get("platform", "")).casefold() != platform_name
        ):
            raise ComplianceError(f"{label} GUI smoke failed: {payload}")
        plugins_path = Path(str(payload.get("qt_plugins_path", ""))).resolve()
        expected_plugins = (root / "PySide6" / "plugins").resolve()
        if plugins_path != expected_plugins:
            raise ComplianceError(
                f"{label} GUI loaded plugins from {plugins_path}, expected {expected_plugins}"
            )
        expected_binding_paths = {
            "QtCore.pyd": root / "PySide6" / "QtCore.pyd",
            "QtGui.pyd": root / "PySide6" / "QtGui.pyd",
            "QtWidgets.pyd": root / "PySide6" / "QtWidgets.pyd",
            "Shiboken.pyd": root / "shiboken6" / "Shiboken.pyd",
        }
        binding_paths = payload.get("qt_binding_module_paths")
        if not isinstance(binding_paths, dict):
            raise ComplianceError(f"{label} GUI did not report binding module paths")
        for name, expected in expected_binding_paths.items():
            actual = Path(str(binding_paths.get(name, ""))).resolve()
            if actual != expected.resolve():
                raise ComplianceError(
                    f"{label} GUI loaded {name} from {actual}, expected {expected.resolve()}"
                )
        expected_libraries = {
            "Qt6Core.dll": root / "PySide6" / "Qt6Core.dll",
            "Qt6Gui.dll": root / "PySide6" / "Qt6Gui.dll",
            "Qt6Widgets.dll": root / "PySide6" / "Qt6Widgets.dll",
            "pyside6.abi3.dll": root / "PySide6" / "pyside6.abi3.dll",
            "shiboken6.abi3.dll": root / "shiboken6" / "shiboken6.abi3.dll",
            f"q{platform_name}.dll": (
                root / "PySide6" / "plugins" / "platforms" / f"q{platform_name}.dll"
            ),
        }
        library_paths = payload.get("qt_loaded_library_paths")
        if not isinstance(library_paths, dict):
            raise ComplianceError(f"{label} GUI did not report loaded library paths")
        for name, expected in expected_libraries.items():
            actual = Path(str(library_paths.get(name, ""))).resolve()
            if actual != expected.resolve():
                raise ComplianceError(
                    f"{label} GUI loaded {name} from {actual}, expected {expected.resolve()}"
                )
        payload["qt_plugins_path"] = _relative_candidate_path(
            root, payload["qt_plugins_path"], f"{label} Qt plugin path"
        )
        raw_library_paths = payload.get("qt_library_paths")
        if not isinstance(raw_library_paths, list):
            raise ComplianceError(f"{label} GUI did not report Qt library paths")
        payload["qt_library_paths"] = [
            _relative_candidate_path(root, value, f"{label} Qt library path")
            for value in raw_library_paths
        ]
        payload["qt_binding_module_paths"] = {
            name: _relative_candidate_path(root, value, f"{label} {name}")
            for name, value in binding_paths.items()
        }
        payload["qt_loaded_library_paths"] = {
            name: _relative_candidate_path(root, value, f"{label} {name}")
            for name, value in library_paths.items()
        }
        if stdout:
            raise ComplianceError(f"{label} GUI smoke emitted unexpected stdout")
        return payload


def replacement_smoke(root: Path, output: Path | None = None) -> dict[str, object]:
    root = _safe_distribution_root(root)
    baseline = verify_layout(root)
    replacement_root = _installed_wheel_root()
    source_paths = {
        relative: replacement_root / Path(PurePosixPath(relative))
        for relative in EXPECTED_QT_PATHS
    }
    missing = [relative for relative, path in source_paths.items() if not path.is_file()]
    if missing:
        raise ComplianceError("approved replacement set is incomplete: " + ", ".join(missing))

    original_hashes = {
        str(record["path"]): str(record["sha256"])
        for record in baseline["files"]  # type: ignore[index]
    }
    overlay_relatives = {
        "PySide6/plugins/platforms/qoffscreen.dll",
        "PySide6/plugins/platforms/qwindows.dll",
    }
    result: dict[str, object] = {
        "status": "FAIL",
        "release_gate_status": "HOLD",
        "test_classification": (
            "external-library-integrity-policy-smoke; not a source-built LGPL relink proof"
        ),
        "lgpl_relink_proven": False,
        "replacement_set": "PyPI win_amd64 PySide6-Essentials/Shiboken6 6.11.1",
        "overlay_targets": sorted(overlay_relatives),
    }

    with tempfile.TemporaryDirectory(prefix="openfetch-qt-replacement-backup-") as temporary:
        backup_root = Path(temporary)
        for relative in EXPECTED_QT_PATHS:
            backup = backup_root / Path(PurePosixPath(relative))
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / Path(PurePosixPath(relative)), backup)

        replacement_error: BaseException | None = None
        try:
            for relative, source in source_paths.items():
                destination = root / Path(PurePosixPath(relative))
                if relative in overlay_relatives:
                    _write_overlay_replacement(source, destination, relative)
                else:
                    _atomic_copy(source, destination)

            replacement_hashes = {
                relative: sha256_file(root / Path(PurePosixPath(relative)))
                for relative in EXPECTED_QT_PATHS
            }
            for relative in overlay_relatives:
                if replacement_hashes[relative] == original_hashes[relative]:
                    raise ComplianceError(f"replacement smoke did not change {relative}")
            replacement_payload = _run_gui_smoke(root, "replacement")
            replacement_windows_payload = _run_gui_smoke(
                root, "replacement-windows", platform_name="windows"
            )
            for relative, expected in replacement_hashes.items():
                actual = sha256_file(root / Path(PurePosixPath(relative)))
                if actual != expected:
                    raise ComplianceError(
                        f"application startup rewrote replacement file {relative}"
                    )
            result.update(
                {
                    "replacement_gui": replacement_payload,
                    "replacement_windows_gui": replacement_windows_payload,
                    "replacement_sha256": replacement_hashes,
                    "integrity_block_absent": True,
                }
            )
        except BaseException as exc:
            replacement_error = exc
        finally:
            for relative in EXPECTED_QT_PATHS:
                _atomic_copy(
                    backup_root / Path(PurePosixPath(relative)),
                    root / Path(PurePosixPath(relative)),
                )

        for relative, expected in original_hashes.items():
            actual = sha256_file(root / Path(PurePosixPath(relative)))
            if actual != expected:
                raise ComplianceError(f"rollback hash mismatch for {relative}")
        rollback_payload = _run_gui_smoke(root, "rollback")
        windows_payload = _run_gui_smoke(
            root, "rollback-windows", platform_name="windows"
        )
        verify_layout(root)
        result["rollback_gui"] = rollback_payload
        result["windows_gui"] = windows_payload
        result["rollback_byte_exact"] = True
        if replacement_error is not None:
            raise replacement_error

    result["status"] = "PASS"
    if output is not None:
        Path(output).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return result


def _deterministic_zip(root: Path, destination: Path) -> Path:
    _reject_reparse_tree(root)
    timestamp = (1980, 1, 1, 0, 0, 0)
    if destination.exists():
        raise ComplianceError(f"refusing to overwrite existing archive: {destination}")
    with zipfile.ZipFile(
        destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            if not path.is_file():
                continue
            arcname = f"{root.name}/{path.relative_to(root).as_posix()}"
            info = zipfile.ZipInfo(arcname, date_time=timestamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with path.open("rb") as source, archive.open(info, "w") as destination_stream:
                shutil.copyfileobj(source, destination_stream, length=1024 * 1024)
    return destination


def build_candidate(
    *, python: Path, dist_root: Path, work_root: Path, create_zip: bool
) -> tuple[Path, Path | None]:
    dist_root = Path(dist_root).resolve()
    work_root = Path(work_root).resolve()
    candidate = dist_root / DIST_NAME
    if candidate.exists():
        raise ComplianceError(f"refusing to overwrite existing candidate: {candidate}")
    verify_build_environment(python)
    verify_source_archives()
    _run_prebuild_gate(python, "generate_compliance_manifests.py", "--check")
    _run_prebuild_gate(python, "verify_distribution_boundary.py")
    dist_root.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = "0"
    # 1980-01-01: the earliest timestamp ZIP containers accept.
    environment["SOURCE_DATE_EPOCH"] = "315532800"
    completed = subprocess.run(
        [
            str(Path(python).resolve()),
            "-m",
            "PyInstaller",
            str(SPEC_PATH),
            "--clean",
            "--noconfirm",
            "--workpath",
            str(work_root),
            "--distpath",
            str(dist_root),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        raise ComplianceError(f"PyInstaller failed with exit code {completed.returncode}")
    _run_prebuild_gate(python, "generate_compliance_manifests.py", "--check")
    write_component_manifest(candidate)
    verify_layout(candidate)
    archive = _deterministic_zip(candidate, dist_root / f"{DIST_NAME}.zip") if create_zip else None
    return candidate, archive


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--python", type=Path, default=Path(sys.executable))
    build.add_argument("--dist-root", type=Path, required=True)
    build.add_argument("--work-root", type=Path, required=True)
    build.add_argument("--no-zip", action="store_true")

    verify = subparsers.add_parser("verify")
    verify.add_argument("distribution", type=Path)

    replacement = subparsers.add_parser("replacement-smoke")
    replacement.add_argument("distribution", type=Path)
    replacement.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "build":
            candidate, archive = build_candidate(
                python=args.python,
                dist_root=args.dist_root,
                work_root=args.work_root,
                create_zip=not args.no_zip,
            )
            print(f"PASS: one-folder candidate built at {candidate}")
            if archive is not None:
                print(f"PASS: deterministic ZIP written to {archive}")
        elif args.command == "verify":
            verify_layout(args.distribution)
            print("PASS: external Qt/PySide one-folder layout verified.")
        elif args.command == "replacement-smoke":
            result = replacement_smoke(args.distribution, args.output)
            print(json.dumps(result, indent=2, sort_keys=True))
    except (ComplianceError, OSError, subprocess.SubprocessError) as exc:
        print(f"HOLD: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
