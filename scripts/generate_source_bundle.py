"""Generate the local corresponding-source candidate and exact hash manifests."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

try:
    from scripts.project_identity import (
        APPLICATION_VERSION,
        EXECUTABLE_STEM,
        ONEFOLDER_SPEC_NAME,
    )
except ModuleNotFoundError:  # executed directly as scripts/generate_source_bundle.py
    from project_identity import (  # type: ignore[no-redef]
        APPLICATION_VERSION,
        EXECUTABLE_STEM,
        ONEFOLDER_SPEC_NAME,
    )

VERSION = APPLICATION_VERSION
SOURCE_BUNDLE_NAME = f"{EXECUTABLE_STEM}-{VERSION}-corresponding-source.zip"
FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)
INCLUDE_ROOTS = (
    ".github/workflows",
    "assets",
    "docs",
    "licenses",
    "scripts",
    "src",
    "tests",
    "third_party_sources",
)
INCLUDE_FILES = (
    ".gitattributes",
    ".gitignore",
    "build.bat",
    "BUILD-INPUTS.lock",
    "BINARY-TO-SOURCE-MAP.json",
    "NATIVE-COMPONENTS.json",
    "QT-PYSIDE-COMPONENTS.json",
    "LICENSE",
    "main.py",
    "OpenFetch-onefile.spec",
    "OpenFetch.spec",
    "PROJECT-METADATA.json",
    "pyproject.toml",
    "README.md",
    "requirements.lock",
    "requirements.txt",
    "SOURCE-HASHES.sha256",
    "SOURCE-HASHES.json",
    "start.bat",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "uv.lock",
    "version_info.txt",
)
FORBIDDEN_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "browser profiles",
    "browser-profile",
}
FORBIDDEN_NAMES = {
    ".env",
    "cookies.txt",
    "credentials.json",
    "id_dsa",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx"}
# A PEM header alone is not key material: TLS libraries embed the marker as a
# parser string constant (for example inside FFmpeg binaries).  Actual leaked
# keys carry a base64 body between the BEGIN and END markers.
SECRET_PEM_PATTERN = re.compile(
    rb"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?" + rb"PRIVATE KEY-----"
    rb"[\r\n]+[A-Za-z0-9+/=\r\n]{40,}-----END"
)
TOKEN_PATTERN = re.compile(rb"(?:gh" + rb"p_|github_" + rb"pat_)[A-Za-z0-9_]{20,}")
ARCHIVE_SUFFIXES = (".tar", ".tar.bz2", ".tar.gz", ".tar.xz", ".tgz", ".whl", ".zip")
SCAN_CARRY_BYTES = 8192
PINNED_PYTHON = (3, 12, 9)
PINNED_ZLIB = "1.3.1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_deterministic_driver() -> None:
    if sys.version_info[:3] != PINNED_PYTHON:
        raise RuntimeError(
            f"Source-bundle driver must be CPython {PINNED_PYTHON}, got "
            f"{sys.version_info[:3]}"
        )
    if zlib.ZLIB_VERSION != PINNED_ZLIB or zlib.ZLIB_RUNTIME_VERSION != PINNED_ZLIB:
        raise RuntimeError(
            f"Source-bundle driver requires zlib {PINNED_ZLIB}, got "
            f"compile={zlib.ZLIB_VERSION}, runtime={zlib.ZLIB_RUNTIME_VERSION}"
        )


def is_forbidden_path(relative: Path) -> bool:
    parts = {part.casefold() for part in relative.parts}
    name = relative.name.casefold()
    return bool(
        parts & FORBIDDEN_PARTS
        or any(part.endswith(".egg-info") for part in parts)
        or name in FORBIDDEN_NAMES
        or relative.suffix.casefold() in FORBIDDEN_SUFFIXES
    )


def is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def walk_files_no_reparse(root: Path) -> Iterator[Path]:
    pending = [root]
    while pending:
        directory = pending.pop()
        if is_reparse_point(directory):
            raise RuntimeError(f"Reparse directory rejected from source bundle: {directory}")
        with os.scandir(directory) as entries:
            ordered = sorted(entries, key=lambda entry: entry.name.casefold(), reverse=True)
        for entry in ordered:
            path = Path(entry.path)
            if is_reparse_point(path):
                raise RuntimeError(f"Reparse path rejected from source bundle: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                yield path
            else:
                raise RuntimeError(f"Special filesystem entry rejected: {path}")


def scan_stream_for_secrets(handle: BinaryIO, label: str) -> None:
    carry = b""
    while chunk := handle.read(1024 * 1024):
        content = carry + chunk
        if SECRET_PEM_PATTERN.search(content):
            raise RuntimeError(f"Private-key material rejected from source bundle: {label}")
        if TOKEN_PATTERN.search(content):
            raise RuntimeError(f"GitHub credential-like value rejected from source bundle: {label}")
        carry = content[-SCAN_CARRY_BYTES:]


def safe_archive_name(name: str, label: str, seen: set[str]) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or ":" in pure.parts[0]:
        raise RuntimeError(f"Unsafe member in {label}: {name}")
    folded = normalized.casefold()
    if folded in seen:
        raise RuntimeError(f"Duplicate/case-colliding member in {label}: {name}")
    seen.add(folded)
    return pure


def scan_zip_members(path: Path, relative: Path, *, scan_contents: bool = True) -> None:
    seen: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            safe_archive_name(info.filename, relative.as_posix(), seen)
            if info.flag_bits & 0x1:
                raise RuntimeError(f"Encrypted archive member rejected: {relative}!{info.filename}")
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type == 0o120000:
                raise RuntimeError(f"Archive symlink rejected: {relative}!{info.filename}")
            if scan_contents and not info.is_dir():
                with archive.open(info) as member:
                    scan_stream_for_secrets(member, f"{relative}!{info.filename}")


def scan_tar_members(path: Path, relative: Path, *, scan_contents: bool = True) -> None:
    seen: set[str] = set()
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            safe_archive_name(member.name, relative.as_posix(), seen)
            if member.issym() or member.islnk():
                target = PurePosixPath(member.linkname.replace("\\", "/"))
                # Relative links are fine while they resolve inside the
                # archive root; absolute targets and escapes are rejected.
                unsafe = target.is_absolute()
                if not unsafe:
                    combined = (
                        PurePosixPath(member.name.replace("\\", "/")).parent / target
                    )
                    depth = 0
                    for part in combined.parts:
                        if part == "..":
                            depth -= 1
                            if depth < 0:
                                unsafe = True
                                break
                        elif part != ".":
                            depth += 1
                if unsafe:
                    raise RuntimeError(
                        f"Unsafe archive link rejected: {relative}!{member.name} -> "
                        f"{member.linkname}"
                    )
                continue
            if member.isdir():
                continue
            if not member.isfile():
                raise RuntimeError(f"Special archive member rejected: {relative}!{member.name}")
            if not scan_contents:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"Cannot inspect archive member: {relative}!{member.name}")
            with extracted:
                scan_stream_for_secrets(extracted, f"{relative}!{member.name}")


def _collect_sha256_values(value: Any, hashes: set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if (
                key == "sha256"
                and isinstance(item, str)
                and re.fullmatch(r"[0-9a-fA-F]{64}", item)
            ):
                hashes.add(item.casefold())
            else:
                _collect_sha256_values(item, hashes)
    elif isinstance(value, list):
        for item in value:
            _collect_sha256_values(item, hashes)


def upstream_pinned_hashes(project_root: Path) -> set[str]:
    """Collect the SHA-256 pins that identify byte-verified upstream archives."""
    hashes: set[str] = set()
    for json_relative in (
        "build_inputs/PREPARATION-MANIFEST.json",
        "third_party_sources/python-runtime/SOURCE-MANIFEST.json",
        "third_party_sources/ffmpeg/SOURCE-MANIFEST.json",
    ):
        manifest = project_root / Path(json_relative)
        with contextlib.suppress(OSError, UnicodeError, json.JSONDecodeError):
            _collect_sha256_values(
                json.loads(manifest.read_text(encoding="utf-8")), hashes
            )
    for sums_relative in (
        "third_party_sources/qt-pyside/SHA256SUMS",
        "third_party_sources/node/SHASUMS256.txt",
    ):
        sums_path = project_root / Path(sums_relative)
        with contextlib.suppress(OSError, UnicodeError):
            for line in sums_path.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if parts and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
                    hashes.add(parts[0].casefold())
    for lock_relative in ("requirements.lock", "uv.lock"):
        lock_path = project_root / lock_relative
        with contextlib.suppress(OSError, UnicodeError):
            for match in re.finditer(
                r"sha256[:\"'\s=]+([0-9a-fA-F]{64})",
                lock_path.read_text(encoding="utf-8"),
            ):
                hashes.add(match.group(1).casefold())
    return hashes


def assert_no_secret_material(
    path: Path, relative: Path, *, verified_upstream: bool = False
) -> None:
    """Reject secret material; structural archive checks always run.

    ``verified_upstream`` marks archives whose SHA-256 matches a recorded
    upstream pin: their bytes are exactly the public upstream release, so
    content scanning is skipped (public test keys inside OpenSSL or similar
    upstream test suites are not credential leakage).
    """
    if not verified_upstream:
        with path.open("rb") as handle:
            scan_stream_for_secrets(handle, relative.as_posix())
    lowered = path.name.casefold()
    if lowered.endswith((".whl", ".zip")):
        scan_zip_members(path, relative, scan_contents=not verified_upstream)
    elif lowered.endswith(ARCHIVE_SUFFIXES[:-2]):
        scan_tar_members(path, relative, scan_contents=not verified_upstream)


def prepared_build_inputs(project_root: Path) -> list[tuple[Path, Path]]:
    manifest = project_root / "build_inputs" / "PREPARATION-MANIFEST.json"
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read prepared-input manifest: {exc}") from exc
    result = [(manifest, manifest.relative_to(project_root))]
    seen = {result[0][1].as_posix().casefold()}
    rows = payload.get("files")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("Prepared-input manifest has no file records")
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise RuntimeError("Prepared-input manifest contains an invalid record")
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError(f"Unsafe prepared-input path: {relative}")
        path = (project_root / relative).resolve()
        if not path.is_relative_to(project_root.resolve()) or not path.is_file():
            raise RuntimeError(f"Prepared input is missing or outside the project: {relative}")
        if path.stat().st_size != row.get("size") or sha256_file(path) != row.get("sha256"):
            raise RuntimeError(f"Prepared input differs from authoritative manifest: {relative}")
        if relative.parts[0].casefold() != "build_inputs":
            continue
        folded = relative.as_posix().casefold()
        if folded in seen:
            raise RuntimeError(f"Duplicate prepared-input path: {relative}")
        seen.add(folded)
        result.append((path, relative))
    return result


def source_candidates(project_root: Path) -> list[tuple[Path, Path]]:
    candidates: dict[str, tuple[Path, Path]] = {}

    def add(path: Path, relative: Path) -> None:
        key = relative.as_posix().casefold()
        existing = candidates.get(key)
        if existing is not None and existing[1].as_posix() != relative.as_posix():
            raise RuntimeError(
                f"Case-colliding source paths: {existing[1].as_posix()} and "
                f"{relative.as_posix()}"
            )
        candidates[key] = (path, relative)

    for root_name in INCLUDE_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            raise RuntimeError(f"Required source-bundle directory is missing: {root_name}")
        for path in walk_files_no_reparse(root):
            relative = path.relative_to(project_root)
            if is_forbidden_path(relative):
                continue
            add(path, relative)
    for path, relative in prepared_build_inputs(project_root):
        add(path, relative)
    for name in INCLUDE_FILES:
        path = project_root / name
        if name in {"BINARY-TO-SOURCE-MAP.json", "SOURCE-HASHES.json"} and not path.exists():
            continue
        if not path.is_file():
            raise RuntimeError(f"Required source-bundle file is missing: {name}")
        relative = path.relative_to(project_root)
        if is_reparse_point(path):
            raise RuntimeError(f"Reparse path rejected from source bundle: {relative}")
        add(path, relative)
    result = [candidates[key] for key in sorted(candidates)]
    pinned_hashes = upstream_pinned_hashes(project_root)
    for path, relative in result:
        verified_upstream = bool(
            path.name.casefold().endswith(ARCHIVE_SUFFIXES)
            and sha256_file(path).casefold() in pinned_hashes
        )
        assert_no_secret_material(path, relative, verified_upstream=verified_upstream)
    return result


def generate_build_inputs_lock(project_root: Path) -> dict[str, Any]:
    inputs: list[dict[str, Any]] = []
    preparation_path = project_root / "build_inputs" / "PREPARATION-MANIFEST.json"
    preparation = json.loads(preparation_path.read_text(encoding="utf-8"))
    preparation_rows = {
        str(row["path"]): row
        for row in preparation.get("files", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    for path, relative_path in prepared_build_inputs(project_root):
        relative = relative_path.as_posix()
        row: dict[str, Any] = {
            "path": relative,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
            "kind": "offline-build-input",
            "pin_provenance": "build_inputs/PREPARATION-MANIFEST.json",
        }
        prepared = preparation_rows.get(relative)
        if prepared is not None:
            row["source_url"] = prepared.get("url")
            row["component"] = prepared.get("component")
            row["version"] = prepared.get("version")
        inputs.append(row)

    third_party_root = project_root / "third_party_sources"
    if not third_party_root.is_dir():
        raise RuntimeError("Required input root is missing: third_party_sources")
    for path in sorted(
        walk_files_no_reparse(third_party_root),
        key=lambda candidate: candidate.relative_to(project_root).as_posix().casefold(),
    ):
        relative = path.relative_to(project_root).as_posix()
        prepared = preparation_rows.get(relative)
        inputs.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "kind": "third-party-source-or-build-provenance",
                "pin_provenance": (
                    "build_inputs/PREPARATION-MANIFEST.json"
                    if prepared is not None
                    else "component-local source manifest; release remains HOLD unless "
                    "component closure is independently PASS"
                ),
                **(
                    {
                        "source_url": prepared.get("url"),
                        "component": prepared.get("component"),
                        "version": prepared.get("version"),
                    }
                    if prepared is not None
                    else {}
                ),
            }
        )
    binary_references = []
    for name in ("ffmpeg.exe", "ffprobe.exe", "node.exe"):
        path = project_root / "bin" / name
        if not path.is_file():
            raise RuntimeError(f"Distributed runtime reference is missing: bin/{name}")
        binary_references.append(
            {
                "path": f"bin/{name}",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {
        "schema_version": 1,
        "application_version": VERSION,
        "build_label": "pyside-provider-free-compliance-candidate",
        "public_distribution_verdict": "HOLD",
        "offline_after_preparation": True,
        "preparation_manifest_sha256": sha256_file(preparation_path),
        "prohibited_artifact_sha256": (
            "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac"
        ),
        "inputs": inputs,
        "distributed_binary_references": binary_references,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    # newline="\n" keeps the generated manifests byte-identical on Windows and
    # POSIX; the repository's canonical representation is LF (see .gitattributes).
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def source_hash_manifest(candidates: list[tuple[Path, Path]]) -> dict[str, Any]:
    dynamic_sidecars = {
        "BINARY-TO-SOURCE-MAP.json",
        "SOURCE-BUNDLE-MANIFEST.json",
        "SOURCE-HASHES.json",
    }
    rows = [
        {
            "path": relative.as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path, relative in candidates
        if relative.as_posix() not in dynamic_sidecars
    ]
    return {
        "schema_version": 1,
        "application_version": VERSION,
        "public_distribution_verdict": "HOLD",
        "self_reference": (
            "Dynamic post-build sidecars and SOURCE-HASHES.json are intentionally excluded "
            "to avoid circular artifact/source identities"
        ),
        "file_count": len(rows),
        "files": rows,
    }


def deterministic_zip(
    candidates: list[tuple[Path, Path]],
    output: Path,
    *,
    pinned_hashes: set[str] | None = None,
) -> None:
    pinned = pinned_hashes or set()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, relative in candidates:
            expected = sha256_file(path)
            verified_upstream = bool(
                path.name.casefold().endswith(ARCHIVE_SUFFIXES)
                and expected.casefold() in pinned
            )
            assert_no_secret_material(path, relative, verified_upstream=verified_upstream)
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != expected:
                raise RuntimeError(f"Source changed while bundling: {relative}")
            info = zipfile.ZipInfo(relative.as_posix(), FIXED_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(
                info,
                content,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def archive_manifest(archive: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    selected_content: dict[str, bytes] = {}
    with zipfile.ZipFile(archive) as handle:
        names = handle.namelist()
        if names != sorted(names, key=str.casefold) or len(names) != len(
            {name.casefold() for name in names}
        ):
            raise RuntimeError("Source bundle ordering or uniqueness check failed")
        for info in handle.infolist():
            content = handle.read(info)
            if info.filename in {
                "BUILD-INPUTS.lock",
                "NATIVE-COMPONENTS.json",
                "SOURCE-HASHES.json",
                "build_inputs/PREPARATION-MANIFEST.json",
                "third_party_sources/ffmpeg/SOURCE-MANIFEST.json",
                "third_party_sources/node/SHASUMS256.txt",
                "third_party_sources/python-runtime/SOURCE-MANIFEST.json",
                "third_party_sources/qt-pyside/SHA256SUMS",
            }:
                selected_content[info.filename] = content
            rows.append(
                {
                    "path": info.filename,
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
    required_prefixes = (
        "src/",
        "scripts/",
        "licenses/",
        "third_party_sources/ffmpeg/",
        "third_party_sources/python-runtime/",
        "third_party_sources/python-packages/",
        "third_party_sources/node/",
        "third_party_sources/qt-pyside/",
        "build_inputs/",
    )
    missing_prefixes = [
        prefix for prefix in required_prefixes if not any(row["path"].startswith(prefix) for row in rows)
    ]
    required_files = {
        ".github/workflows/build-release.yml",
        ONEFOLDER_SPEC_NAME,
        "requirements.lock",
        "uv.lock",
        "BUILD-INPUTS.lock",
        "NATIVE-COMPONENTS.json",
        "QT-PYSIDE-COMPONENTS.json",
        "SOURCE-HASHES.json",
        "LICENSE",
        "THIRD_PARTY_LICENSES.txt",
        "THIRD_PARTY_NOTICES.md",
        "build_inputs/PREPARATION-MANIFEST.json",
        "docs/BUILD-REPRODUCIBILITY.md",
        "docs/FFMPEG-SOURCE-AND-BUILD.md",
        "docs/LGPL-COMPLIANCE.md",
        "docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md",
        "docs/PYTHON-RUNTIME-REPRODUCIBILITY.md",
        "docs/PYTHON-RUNTIME-SOURCE.md",
        "docs/QT-BUILD-PROVENANCE.md",
        "docs/QT-REPLACEMENT-GUIDE.md",
        "scripts/build_offline_distribution.py",
        "scripts/prepare_offline_inputs.py",
        "scripts/qt_onefolder_compliance.py",
        "scripts/release_compliance_gate.py",
        "scripts/verify_distribution_closure.py",
        "third_party_sources/ffmpeg/BINARY-INVENTORY.json",
        "third_party_sources/ffmpeg/BUILD-DEPENDENCIES.json",
        "third_party_sources/ffmpeg/SOURCE-MANIFEST.json",
        "third_party_sources/node/SHASUMS256.txt",
        "third_party_sources/node/archives/node-v22.17.0.tar.gz",
        "third_party_sources/python-runtime/RUNTIME-ASSET-COMPARISON.json",
        "third_party_sources/python-runtime/SOURCE-MANIFEST.json",
        "third_party_sources/qt-pyside/SHA256SUMS",
        "third_party_sources/qt-pyside/pyside-setup-everywhere-src-6.11.1.tar.xz",
        "third_party_sources/qt-pyside/qtbase-everywhere-src-6.11.1.tar.xz",
    }
    names = {row["path"] for row in rows}
    archive_rows = {row["path"]: row for row in rows}
    missing_files = sorted(required_files - names)

    def json_status(relative: str, key: str, expected: object) -> bool:
        try:
            payload = json.loads(selected_content[relative])
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError):
            return False
        return payload.get(key) == expected

    qt_hashes_pass = False
    try:
        qt_sums = selected_content[
            "third_party_sources/qt-pyside/SHA256SUMS"
        ].decode("utf-8")
        expected_qt = {}
        for line in qt_sums.splitlines():
            digest, filename = line.split(maxsplit=1)
            expected_qt[filename.strip()] = digest
        qt_hashes_pass = all(
            next(
                row["sha256"]
                for row in rows
                if row["path"] == f"third_party_sources/qt-pyside/{filename}"
            )
            == digest
            for filename, digest in expected_qt.items()
        ) and set(expected_qt) == {
            "pyside-setup-everywhere-src-6.11.1.tar.xz",
            "qtbase-everywhere-src-6.11.1.tar.xz",
        }
    except (KeyError, StopIteration, ValueError, UnicodeDecodeError):
        qt_hashes_pass = False

    node_source_pass = False
    try:
        node_sums = selected_content[
            "third_party_sources/node/SHASUMS256.txt"
        ].decode("utf-8")
        expected_node = next(
            line.split()[0]
            for line in node_sums.splitlines()
            if line.split()[-1] == "node-v22.17.0.tar.gz"
        )
        actual_node = next(
            row["sha256"]
            for row in rows
            if row["path"]
            == "third_party_sources/node/archives/node-v22.17.0.tar.gz"
        )
        node_source_pass = actual_node == expected_node
    except (KeyError, StopIteration, UnicodeDecodeError):
        node_source_pass = False

    def embedded_rows_match(
        relative: str,
        key: str,
        expected_names: set[str],
    ) -> bool:
        try:
            payload = json.loads(selected_content[relative])
            embedded_rows = payload[key]
        except (KeyError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
            return False
        if not isinstance(embedded_rows, list):
            return False
        indexed: dict[str, dict[str, Any]] = {}
        for row in embedded_rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                return False
            if row["path"] in indexed:
                return False
            indexed[row["path"]] = row
        if set(indexed) != expected_names:
            return False
        return all(
            archive_rows[name]["size"] == indexed[name].get("size")
            and archive_rows[name]["sha256"] == indexed[name].get("sha256")
            for name in expected_names
        )

    exact_input_names = {
        name
        for name in names
        if name.startswith(("build_inputs/", "third_party_sources/"))
    }
    source_hash_exclusions = {
        "BINARY-TO-SOURCE-MAP.json",
        "SOURCE-BUNDLE-MANIFEST.json",
        "SOURCE-HASHES.json",
    }
    exact_source_hash_names = names - source_hash_exclusions
    build_input_lock_pass = embedded_rows_match(
        "BUILD-INPUTS.lock", "inputs", exact_input_names
    )
    source_hash_manifest_pass = embedded_rows_match(
        "SOURCE-HASHES.json", "files", exact_source_hash_names
    )

    component_closure = {
        "build-input-lock-exact": build_input_lock_pass,
        "ffmpeg": json_status(
            "third_party_sources/ffmpeg/SOURCE-MANIFEST.json", "status", "PASS"
        ),
        "native": json_status("NATIVE-COMPONENTS.json", "closure_status", "PASS"),
        "node-source-hash": node_source_pass,
        "python-runtime": json_status(
            "third_party_sources/python-runtime/SOURCE-MANIFEST.json", "status", "PASS"
        ),
        "qt-pyside-source-hashes": qt_hashes_pass,
        "source-hash-manifest-exact": source_hash_manifest_pass,
    }
    closure_pass = (
        not missing_prefixes
        and not missing_files
        and all(component_closure.values())
    )
    return {
        "schema_version": 1,
        "application_version": VERSION,
        "public_distribution_verdict": "HOLD",
        "closure_status": "PASS" if closure_pass else "HOLD",
        "qualified_review_status": "HOLD",
        "archive": {
            "path": archive.name,
            "size": archive.stat().st_size,
            "sha256": sha256_file(archive),
        },
        "file_count": len(rows),
        "missing_required_prefixes": missing_prefixes,
        "missing_required_files": missing_files,
        "component_closure": component_closure,
        "files": rows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-directory", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    assert_deterministic_driver()
    project_root = args.project_root.resolve()
    output_directory = (
        args.output_directory.resolve()
        if args.output_directory
        else project_root / "dist" / "compliance-candidate"
    )
    for included in INCLUDE_ROOTS:
        included_root = (project_root / included).resolve()
        if output_directory == included_root or output_directory.is_relative_to(included_root):
            raise RuntimeError(
                f"Output directory may not be inside source input root: {included_root}"
            )
    if output_directory == project_root:
        raise RuntimeError("Output directory may not be the project root")
    output_directory.mkdir(parents=True, exist_ok=True)

    build_lock = generate_build_inputs_lock(project_root)
    write_json(project_root / "BUILD-INPUTS.lock", build_lock)
    initial_candidates = source_candidates(project_root)
    hashes = source_hash_manifest(initial_candidates)
    write_json(project_root / "SOURCE-HASHES.json", hashes)
    final_candidates = source_candidates(project_root)
    archive = output_directory / SOURCE_BUNDLE_NAME
    deterministic_zip(
        final_candidates, archive, pinned_hashes=upstream_pinned_hashes(project_root)
    )
    manifest = archive_manifest(archive)
    write_json(project_root / "SOURCE-BUNDLE-MANIFEST.json", manifest)
    write_json(output_directory / "SOURCE-BUNDLE-MANIFEST.json", manifest)
    print(
        f"Generated source bundle with {manifest['file_count']} files: {archive} "
        f"({manifest['archive']['sha256']})"
    )
    return 0 if manifest["closure_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
