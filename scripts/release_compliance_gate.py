"""Fail-closed public-release gate for the compliance-friendly distribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from scripts.project_identity import (
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
    )
except ModuleNotFoundError:  # executed directly as scripts/release_compliance_gate.py
    from project_identity import (  # type: ignore[no-redef]
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
    )

# Legacy bundled-provider V3.0.8 one-file EXE (PyQt6 + in-process GPL
# PO-provider payload) and legacy V3.0.4 one-file EXE (PyQt6, no embedded
# notices/source). Neither may appear anywhere in the release workspace.
PROHIBITED_LEGACY_SHA256S = frozenset(
    {
        "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac",
        "02fbde8845bcb7b8946a44f320aa1f88a63a70ceac9765f800276ce11bfa6ed7",
    }
)
# Backward-compatible alias for the original single-hash constant.
PROHIBITED_OLD_SHA256 = "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac"
PROHIBITED_NAMES = re.compile(
    r"(?:^|/)(?:pyqt5|pyqt6|bgutil-ytdlp-pot-provider|yt_dlp_plugins|node_modules)(?:/|$)",
    re.IGNORECASE,
)
TEXT_GATES = {
    "third-party-notices": ("THIRD_PARTY_NOTICES.md", "Release-gate-status", "PASS"),
    "third-party-inventory": ("THIRD_PARTY_LICENSES.txt", "Release-gate-status", "PASS"),
    "zero-audit-blockers": ("THIRD_PARTY_LICENSES.txt", "Audit-blocker-count", "0"),
    "dependency-source": ("docs/DEPENDENCY-SOURCE.md", "Release-gate-status", "PASS"),
    "qualified-review-notices": (
        "THIRD_PARTY_NOTICES.md",
        "Qualified-review-status",
        "PASS",
    ),
    "qualified-review-inventory": (
        "THIRD_PARTY_LICENSES.txt",
        "Qualified-review-status",
        "PASS",
    ),
    "qualified-review-source": (
        "docs/DEPENDENCY-SOURCE.md",
        "Qualified-review-status",
        "PASS",
    ),
    "lgpl-replacement": ("docs/LGPL-COMPLIANCE.md", "Replacement-test-status", "PASS"),
    "one-folder-updater": (
        "docs/BUILD-REPRODUCIBILITY.md",
        "One-folder-updater-status",
        "PASS",
    ),
    "ffmpeg-source": ("docs/FFMPEG-SOURCE-AND-BUILD.md", "Closure-status", "PASS"),
    "python-runtime": ("docs/PYTHON-RUNTIME-SOURCE.md", "Closure-status", "PASS"),
    "microsoft-runtime": (
        "docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md",
        "Redistribution-evidence-status",
        "PASS",
    ),
}
OWNERSHIP_GATES: dict[str, dict[str, Any]] = {
    "project-copyright-owner-supplied": {
        "public_author_and_copyright_holder": "0xRootNull",
    },
    "copyright-start-year-supplied": {"development_started": 2025},
    "copyright-year-range-supplied": {"copyright_period": "2025-2026"},
    "public-attribution-supplied": {"public_attribution": "0xRootNull"},
    "mit-licensing-intent-explicitly-confirmed": {
        "project_license": "MIT for project-owned portions",
        "mit_licensing_intent": "explicitly confirmed",
    },
    "no-company-employer-client-ownership-claim": {
        "registered_company_or_legal_entity": None,
        "employer_client_or_commissioning_party": None,
    },
    "no-known-additional-human-contributor-claim": {
        "known_other_human_contributors": [],
    },
}
JSON_GATES = {
    "binary-to-source-map": (
        "BINARY-TO-SOURCE-MAP.json",
        {"closure_status": "PASS", "public_distribution_verdict": "PASS"},
    ),
    "source-bundle": (
        "SOURCE-BUNDLE-MANIFEST.json",
        {
            "closure_status": "PASS",
            "public_distribution_verdict": "PASS",
            "qualified_review_status": "PASS",
        },
    ),
    "native-components": ("NATIVE-COMPONENTS.json", {"closure_status": "PASS"}),
    "qt-replacement-smoke": (
        "QT-REPLACEMENT-SMOKE.json",
        {
            "status": "PASS",
            "release_gate_status": "PASS",
            "lgpl_relink_proven": True,
        },
    ),
    "reproducibility": (
        "REPRODUCIBILITY-COMPARISON.json",
        {"comparison_status": "PASS"},
    ),
}
REQUIRED_FILES = (
    "BUILD-INPUTS.lock",
    "PROJECT-METADATA.json",
    "SOURCE-HASHES.json",
    "SOURCE-BUNDLE-MANIFEST.json",
    "BINARY-TO-SOURCE-MAP.json",
    "NATIVE-COMPONENTS.json",
    "QT-REPLACEMENT-SMOKE.json",
    "REPRODUCIBILITY-COMPARISON.json",
    "uv.lock",
    "requirements.lock",
    "licenses/RELEASE-LICENSE-MANIFEST.sha256",
    "docs/COPYRIGHT-OWNERSHIP-QUESTIONS.md",
    "docs/PROJECT-OWNERSHIP-DECLARATION.md",
    "docs/QT-REPLACEMENT-GUIDE.md",
    "docs/QT-BUILD-PROVENANCE.md",
    "docs/PYTHON-RUNTIME-REPRODUCIBILITY.md",
)
ARTIFACT_BINDINGS = (
    "LICENSE",
    "PROJECT-METADATA.json",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "BUILD-INPUTS.lock",
    "NATIVE-COMPONENTS.json",
    "QT-PYSIDE-COMPONENTS.json",
    "SOURCE-BUNDLE-MANIFEST.json",
    "SOURCE-HASHES.json",
    "SOURCE-HASHES.sha256",
    "docs/BUILD-REPRODUCIBILITY.md",
    "docs/COPYRIGHT-OWNERSHIP-QUESTIONS.md",
    "docs/DEPENDENCY-SOURCE.md",
    "docs/FFMPEG-SOURCE-AND-BUILD.md",
    "docs/LGPL-COMPLIANCE.md",
    "docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md",
    "docs/PROJECT-OWNERSHIP-DECLARATION.md",
    "docs/PYTHON-RUNTIME-SOURCE.md",
    "docs/QT-BUILD-PROVENANCE.md",
    "docs/QT-REPLACEMENT-GUIDE.md",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_status_value(text: str, key: str) -> str | None:
    pattern = re.compile(rf"^{re.escape(key)}:\s*(\S+)\s*$")
    values = [match.group(1) for line in text.splitlines() if (match := pattern.match(line))]
    return values[0] if len(values) == 1 else None


def ownership_checks(root: Path) -> tuple[list[dict[str, str]], list[str]]:
    path = root / "PROJECT-METADATA.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    checks: list[dict[str, str]] = []
    failures: list[str] = []
    for identifier, expectations in OWNERSHIP_GATES.items():
        passed = all(payload.get(key) == expected for key, expected in expectations.items())
        checks.append({"id": identifier, "status": "PASS" if passed else "HOLD"})
        if not passed:
            required = ", ".join(
                f"{key}={expected!r}" for key, expected in expectations.items()
            )
            failures.append(
                f"PROJECT-METADATA.json does not resolve {identifier}: {required}"
            )
    return checks, failures


def safe_manifest_path(root: Path, value: str) -> Path | None:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        return None
    resolved = (root / relative).resolve()
    return resolved if resolved.is_relative_to(root.resolve()) else None


def verify_hash_rows(root: Path, manifest: Path, rows_key: str) -> list[str]:
    failures: list[str] = []
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot read {manifest.relative_to(root)}: {exc}"]
    rows = payload.get(rows_key)
    if not isinstance(rows, list) or not rows:
        return [f"{manifest.relative_to(root)} has no {rows_key} records"]
    declared_count = payload.get("file_count")
    if declared_count is not None and declared_count != len(rows):
        failures.append(
            f"{manifest.relative_to(root)} count differs: {declared_count} != {len(rows)}"
        )
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            failures.append(f"Invalid non-object hash row in {manifest.relative_to(root)}")
            continue
        relative = str(row.get("path", ""))
        if relative in seen:
            failures.append(f"Duplicate hashed input: {relative}")
            continue
        seen.add(relative)
        path = safe_manifest_path(root, relative)
        if path is None:
            failures.append(f"Unsafe hashed input path: {relative}")
            continue
        if not path.is_file():
            failures.append(f"Hashed input is missing: {relative}")
            continue
        expected = row.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            failures.append(f"Invalid SHA-256 for hashed input: {relative}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            failures.append(f"Hashed input differs: {relative}")
    return failures


def verify_source_bundle(root: Path) -> list[str]:
    manifest_path = root / "SOURCE-BUNDLE-MANIFEST.json"
    if not manifest_path.is_file():
        return ["SOURCE-BUNDLE-MANIFEST.json is missing"]
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot read SOURCE-BUNDLE-MANIFEST.json: {exc}"]
    archive_data = payload.get("archive", {})
    if not isinstance(archive_data, dict):
        return ["SOURCE-BUNDLE-MANIFEST.json has no valid archive record"]
    name = str(archive_data.get("path", ""))
    if not name or Path(name).name != name:
        return [f"Source bundle archive path is unsafe: {name}"]
    candidates = (
        root / "dist" / "compliance-candidate" / name,
        root / "release-assets" / name,
        root / name,
    )
    archive = next((candidate for candidate in candidates if candidate.is_file()), None)
    if archive is None:
        return [f"Source bundle is missing: {name}"]
    failures: list[str] = []
    if sha256_file(archive) != archive_data.get("sha256"):
        failures.append(f"Source bundle hash differs: {archive}")
    try:
        with zipfile.ZipFile(archive) as handle:
            names_list, zip_failures = safe_zip_names(handle)
            failures.extend(
                failure.replace("application ZIP", "source-bundle ZIP")
                for failure in zip_failures
            )
            names = set(names_list)
            rows = payload.get("files")
            if not isinstance(rows, list) or not rows:
                failures.append("SOURCE-BUNDLE-MANIFEST.json has no file records")
            else:
                by_path = {
                    row.get("path"): row
                    for row in rows
                    if isinstance(row, dict) and isinstance(row.get("path"), str)
                }
                if len(by_path) != len(rows):
                    failures.append("Source-bundle manifest has invalid or duplicate paths")
                if set(by_path) != names:
                    failures.append("Source-bundle manifest coverage differs from archive")
                else:
                    for relative, row in by_path.items():
                        content = handle.read(relative)
                        if row.get("size") != len(content):
                            failures.append(f"Source-bundle size differs: {relative}")
                        if row.get("sha256") != hashlib.sha256(content).hexdigest():
                            failures.append(f"Source-bundle hash differs: {relative}")
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        return [f"Cannot verify source bundle {archive}: {exc}"]
    for required in (
        "src/",
        "scripts/",
        "third_party_sources/ffmpeg/",
        "third_party_sources/python-runtime/",
        "third_party_sources/qt-pyside/",
    ):
        if not any(name.startswith(required) for name in names):
            failures.append(f"Source bundle prefix is missing: {required}")
    return failures


def scan_prohibited_artifacts(root: Path) -> list[str]:
    failures: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.casefold() not in {".exe", ".zip"}:
            continue
        if sha256_file(path) in PROHIBITED_LEGACY_SHA256S:
            failures.append(f"Prohibited legacy one-file artifact detected: {path}")
    return failures


def safe_zip_names(handle: zipfile.ZipFile) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    names: list[str] = []
    seen: set[str] = set()
    for info in handle.infolist():
        name = info.filename.replace("\\", "/")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or (pure.parts and ":" in pure.parts[0]):
            failures.append(f"Unsafe application ZIP path: {name}")
            continue
        folded = name.casefold()
        if folded in seen:
            failures.append(f"Duplicate/case-colliding application ZIP path: {name}")
            continue
        seen.add(folded)
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            failures.append(f"Application ZIP symlink is forbidden: {name}")
        if not info.is_dir():
            names.append(name)
    return names, failures


def scan_pyinstaller_modules(executable: Path) -> list[str]:
    failures: list[str] = []
    try:
        from PyInstaller.archive.readers import CArchiveReader

        archive = CArchiveReader(str(executable))
    except Exception as exc:
        return [f"Cannot inspect packaged PyInstaller executable: {exc}"]
    for name in archive.toc:
        normalized = str(name).replace("\\", "/")
        if PROHIBITED_NAMES.search(normalized):
            failures.append(f"Prohibited PyInstaller CArchive path: {normalized}")
        if normalized.casefold().endswith((".js", ".ts", ".js.map", ".ts.map")):
            failures.append(f"Raw JavaScript/TypeScript in main executable: {normalized}")
    pyz_names = [name for name, row in archive.toc.items() if row and str(row[-1]) == "z"]
    if len(pyz_names) != 1:
        failures.append(f"Expected one embedded PYZ, found {len(pyz_names)}")
        return failures
    try:
        pyz = archive.open_embedded_archive(pyz_names[0])
        module_names = [str(name) for name in pyz.toc]
    except Exception as exc:
        failures.append(f"Cannot inspect embedded PYZ: {exc}")
        return failures
    if not any(name.casefold() == "pyside6" for name in module_names):
        failures.append("Packaged PYZ does not contain PySide6")
    for name in module_names:
        normalized = name.replace(".", "/")
        if PROHIBITED_NAMES.search(normalized):
            failures.append(f"Prohibited embedded Python module: {name}")
    return failures


def verify_embedded_binary_map(
    root: Path,
    handle: zipfile.ZipFile,
    names: list[str],
    top_level: str,
) -> list[str]:
    failures: list[str] = []
    embedded_name = f"{top_level}/compliance/BINARY-TO-SOURCE-MAP.json"
    if embedded_name not in names:
        return [f"Application ZIP is missing {embedded_name}"]
    root_map = root / "BINARY-TO-SOURCE-MAP.json"
    if not root_map.is_file():
        return ["Root BINARY-TO-SOURCE-MAP.json is missing"]
    embedded_bytes = handle.read(embedded_name)
    if embedded_bytes != root_map.read_bytes():
        failures.append("Embedded and root BINARY-TO-SOURCE-MAP.json differ")
        return failures
    try:
        payload = json.loads(embedded_bytes)
    except json.JSONDecodeError as exc:
        return [f"Embedded binary-to-source map is invalid JSON: {exc}"]
    rows = payload.get("files")
    if not isinstance(rows, list) or not rows:
        return ["Embedded binary-to-source map has no file records"]
    by_path: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            failures.append("Embedded binary-to-source map has an invalid row")
            continue
        relative = row["path"]
        if relative in by_path:
            failures.append(f"Duplicate binary-map path: {relative}")
        by_path[relative] = row
    artifact_relatives = {
        name[len(top_level) + 1 :]
        for name in names
        if name.startswith(f"{top_level}/")
    }
    if set(by_path) != artifact_relatives:
        failures.append("Binary-map file coverage differs from application ZIP contents")
        return failures
    tree = hashlib.sha256()
    for relative in sorted(artifact_relatives, key=str.casefold):
        row = by_path[relative]
        member = f"{top_level}/{relative}"
        content = handle.read(member)
        self_map = relative.casefold() == "compliance/binary-to-source-map.json"
        expected_size: int | str = "SELF-REFERENTIAL" if self_map else len(content)
        expected_hash = (
            "SELF-REFERENTIAL" if self_map else hashlib.sha256(content).hexdigest()
        )
        if row.get("size") != expected_size or row.get("sha256") != expected_hash:
            failures.append(f"Binary-map size/hash mismatch: {relative}")
        if row.get("mapping_status") != "PASS" or not row.get("components"):
            failures.append(f"Binary-map source assignment is not PASS: {relative}")
        tree.update(relative.encode("utf-8"))
        tree.update(b"\0")
        tree.update(b"SELF-REFERENTIAL" if self_map else bytes.fromhex(expected_hash))
        tree.update(b"\0")
    if payload.get("tree_sha256") != tree.hexdigest():
        failures.append("Binary-map canonical tree hash differs")
    if payload.get("file_count") != len(rows):
        failures.append("Binary-map file_count differs")
    return failures


def verify_embedded_compliance_bindings(
    root: Path,
    handle: zipfile.ZipFile,
    names: list[str],
    top_level: str,
) -> list[str]:
    failures: list[str] = []
    for relative in ARTIFACT_BINDINGS:
        source = root / relative
        member = f"{top_level}/compliance/{relative}"
        if not source.is_file():
            failures.append(f"Root compliance binding is missing: {relative}")
        elif member not in names:
            failures.append(f"Application ZIP compliance binding is missing: {member}")
        elif handle.read(member) != source.read_bytes():
            failures.append(f"Application ZIP compliance binding differs: {relative}")

    label_name = f"{top_level}/compliance/BUILD-LABEL.txt"
    if label_name not in names:
        failures.append("Application ZIP is missing compliance/BUILD-LABEL.txt")
    else:
        label = handle.read(label_name).decode("utf-8", errors="replace")
        if exact_status_value(label, "Public-distribution verdict") != "PASS":
            failures.append("Embedded BUILD-LABEL.txt does not declare public PASS")

    qt_name = f"{top_level}/compliance/QT-PYSIDE-COMPONENTS.json"
    if qt_name in names:
        try:
            qt_payload = json.loads(handle.read(qt_name))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            failures.append(f"Embedded Qt/PySide component manifest is invalid: {exc}")
        else:
            if qt_payload.get("release_gate_status") != "PASS":
                failures.append("Embedded Qt/PySide component manifest remains HOLD")
    return failures


def verify_artifact(root: Path, artifact: Path) -> list[str]:
    failures: list[str] = []
    if not artifact.is_file():
        return [f"Application artifact is missing: {artifact}"]
    if sha256_file(artifact) in PROHIBITED_LEGACY_SHA256S:
        failures.append("Application artifact is a prohibited legacy one-file EXE")
    if artifact.suffix.casefold() != ".zip":
        failures.append("Primary public candidate must be a one-folder ZIP")
        return failures
    try:
        with zipfile.ZipFile(artifact) as handle:
            names, zip_failures = safe_zip_names(handle)
            failures.extend(zip_failures)
            top_levels = {
                PurePosixPath(name).parts[0]
                for name in names
                if PurePosixPath(name).parts
            }
            if len(top_levels) != 1:
                failures.append("Application ZIP must contain exactly one top-level directory")
                return failures
            top_level = next(iter(top_levels))
            if top_level != ONEFOLDER_DIST_NAME:
                failures.append(f"Unexpected application ZIP root: {top_level}")
            failures.extend(verify_embedded_binary_map(root, handle, names, top_level))
            failures.extend(
                verify_embedded_compliance_bindings(root, handle, names, top_level)
            )
            executable_name = f"{top_level}/{EXECUTABLE_NAME}"
            if executable_name in names:
                with tempfile.TemporaryDirectory(prefix="openfetch-release-gate-") as temporary:
                    executable = Path(temporary) / EXECUTABLE_NAME
                    executable.write_bytes(handle.read(executable_name))
                    failures.extend(scan_pyinstaller_modules(executable))
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        return [f"Cannot inspect application ZIP: {exc}"]
    prohibited = [name for name in names if PROHIBITED_NAMES.search(name)]
    if prohibited:
        failures.extend(f"Prohibited main-artifact path: {name}" for name in prohibited)
    required_suffixes = (
        f"/{EXECUTABLE_NAME}",
        "/compliance/LICENSE",
        "/compliance/BINARY-TO-SOURCE-MAP.json",
    )
    for suffix in required_suffixes:
        if not any(name.endswith(suffix) for name in names):
            failures.append(f"Application ZIP is missing required path suffix: {suffix}")
    return failures


def audit(
    root: Path,
    artifact: Path | None = None,
    *,
    preflight: bool = False,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: list[dict[str, str]] = []
    ownership_rows, ownership_failures = ownership_checks(root)
    checks.extend(ownership_rows)
    failures.extend(ownership_failures)
    for identifier, (relative, key, expected) in TEXT_GATES.items():
        path = root / relative
        text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        actual = exact_status_value(text, key)
        passed = actual == expected
        checks.append({"id": identifier, "status": "PASS" if passed else "HOLD"})
        if not passed:
            failures.append(
                f"{relative} does not declare exactly one {key}: {expected} "
                f"(found {actual!r})"
            )
    for identifier, (relative, expectations) in JSON_GATES.items():
        path = root / relative
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            passed = all(payload.get(key) == expected for key, expected in expectations.items())
        except (OSError, json.JSONDecodeError):
            passed = False
        checks.append({"id": identifier, "status": "PASS" if passed else "HOLD"})
        if not passed:
            required = ", ".join(f"{key}={value}" for key, value in expectations.items())
            failures.append(f"{relative} does not declare all required values: {required}")
    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            failures.append(f"Required release input is missing: {relative}")
    if (root / "BUILD-INPUTS.lock").is_file():
        failures.extend(verify_hash_rows(root, root / "BUILD-INPUTS.lock", "inputs"))
    if (root / "SOURCE-HASHES.json").is_file():
        failures.extend(verify_hash_rows(root, root / "SOURCE-HASHES.json", "files"))
    failures.extend(verify_source_bundle(root))
    failures.extend(scan_prohibited_artifacts(root))
    if artifact is not None:
        failures.extend(verify_artifact(root, artifact))
    elif not preflight:
        failures.append("Public release gate requires --artifact with the one-folder ZIP")
    unique_failures = sorted(set(failures))
    preflight_status = "PASS" if not unique_failures else "HOLD"
    return {
        "schema_version": 1,
        "application_version": APPLICATION_VERSION,
        "mode": "preflight" if preflight else "release",
        "preflight_status": preflight_status if preflight else "NOT-APPLICABLE",
        "public_distribution_verdict": (
            "HOLD" if preflight else ("PASS" if not unique_failures else "HOLD")
        ),
        "checks": checks,
        "failure_count": len(unique_failures),
        "failures": unique_failures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifact", type=Path)
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Validate inputs without an artifact; never returns public-distribution PASS.",
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.project_root.resolve()
    artifact = args.artifact.resolve() if args.artifact else None
    if args.preflight and artifact is not None:
        print("ERROR: --preflight and --artifact are mutually exclusive", file=sys.stderr)
        return 2
    report = audit(root, artifact, preflight=args.preflight)
    output = args.output or root / "RELEASE-GATE-REPORT.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report["failures"]:
        for failure in report["failures"]:
            print(f"HOLD: {failure}", file=sys.stderr)
        print(f"Release gate HOLD ({report['failure_count']} failures).", file=sys.stderr)
        return 1
    print("Release gate PASS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
