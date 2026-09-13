"""Map every one-folder distribution file to source/provenance and fail closed.

The default mode emits a reviewable HOLD report when legal/source evidence is
incomplete.  ``--require-pass`` is intended for the publication workflow and refuses
to succeed until every technical and review gate is explicitly PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from scripts.project_identity import (
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_SPEC_NAME,
    )
except ModuleNotFoundError:  # executed directly as scripts/verify_distribution_closure.py
    from project_identity import (  # type: ignore[no-redef]
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_SPEC_NAME,
    )

# Legacy bundled-provider V3.0.8 and legacy V3.0.4 one-file EXE hashes.
PROHIBITED_LEGACY_SHA256S = frozenset(
    {
        "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac",
        "02fbde8845bcb7b8946a44f320aa1f88a63a70ceac9765f800276ce11bfa6ed7",
    }
)
# Backward-compatible alias for the original single-hash constant.
PROHIBITED_OLD_SHA256 = "0d4d4bdf1eabf5af88c1094732ae28cf55f12a0dc36377d90088eb54537b82ac"
NATIVE_SUFFIXES = {".dll", ".exe", ".pyd", ".node"}
PROHIBITED_PATH_PATTERNS = (
    re.compile(r"(?:^|/)(?:pyqt5|pyqt6)(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:bgutil-ytdlp-pot-provider|yt_dlp_plugins)(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:node_modules)(?:/|$)", re.IGNORECASE),
)


@dataclass(frozen=True)
class Component:
    identifier: str
    version: str
    license_expression: str
    source_locations: tuple[str, ...]


COMPONENTS: dict[str, Component] = {
    "project": Component(
        "project",
        APPLICATION_VERSION,
        "MIT for project-owned portions; Copyright (c) 2025-2026 0xRootNull",
        (
            "src",
            "main.py",
            ONEFOLDER_SPEC_NAME,
            "PROJECT-METADATA.json",
            "docs/PROJECT-OWNERSHIP-DECLARATION.md",
        ),
    ),
    "pyinstaller": Component(
        "pyinstaller",
        "6.21.0",
        "GPL-2.0-or-later WITH Bootloader-exception",
        ("third_party_sources/python-packages/sdists/pyinstaller-6.21.0.tar.gz",),
    ),
    "cpython-runtime": Component(
        "cpython-runtime",
        "CPython 3.12.9 / python-build-standalone 20250317",
        "Python-2.0 and historical terms; PBS recipes MPL-2.0",
        ("third_party_sources/python-runtime",),
    ),
    "libffi": Component(
        "libffi",
        "3.4.2",
        "MIT",
        ("third_party_sources/python-runtime",),
    ),
    "openssl": Component(
        "openssl",
        "3.0.16",
        "Apache-2.0",
        ("third_party_sources/python-runtime",),
    ),
    "sqlite": Component(
        "sqlite",
        "3.47.1",
        "Public-domain dedication",
        ("third_party_sources/python-runtime",),
    ),
    "pyside": Component(
        "pyside",
        "PySide6/PySide6-Essentials/Shiboken6 6.11.1",
        "LGPL-3.0-only OR upstream GPL alternatives",
        ("third_party_sources/qt-pyside", "licenses/pyside"),
    ),
    "qt": Component(
        "qt",
        "Qt 6.11.1",
        "LGPL-3.0-only selected route plus third-party terms",
        ("third_party_sources/qt-pyside", "licenses/qt"),
    ),
    "node": Component(
        "node",
        "22.17.0",
        "MIT plus bundled third-party terms",
        ("third_party_sources/node", "licenses/Node.js-22.17.0-LICENSE.txt"),
    ),
    "ffmpeg": Component(
        "ffmpeg",
        "N-125365-g9a01c1cb6a / 2026-06-30",
        "GPL-3.0-or-later distribution route",
        ("third_party_sources/ffmpeg", "licenses/ffmpeg"),
    ),
    "microsoft-runtime": Component(
        "microsoft-runtime",
        "Exact versions per native inventory",
        "Microsoft redistributable/proprietary terms",
        ("licenses/microsoft", "docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md"),
    ),
    "python-package": Component(
        "python-package",
        "Exact versions in uv.lock/requirements.lock",
        "Per-package terms in THIRD_PARTY_LICENSES.txt",
        ("third_party_sources/python-packages/sdists", "licenses/python"),
    ),
    "compliance-material": Component(
        "compliance-material",
        f"{APPLICATION_VERSION} compliance candidate",
        "Documentation and unchanged third-party license terms",
        ("docs", "licenses", "THIRD_PARTY_LICENSES.txt", "THIRD_PARTY_NOTICES.md"),
    ),
}

PYTHON_PACKAGE_ROOTS = {
    "certifi",
    "charset_normalizer",
    "defusedxml",
    "idna",
    "packaging",
    "pillow",
    "pil",
    "requests",
    "setuptools",
    "typing_extensions",
    "urllib3",
    "youtube_transcript_api",
    "yt_dlp",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_parts(relative: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in relative.replace("\\", "/").split("/"))


def is_microsoft_runtime_name(name: str) -> bool:
    lowered = name.casefold()
    return (
        lowered.startswith("api-ms-win-")
        or lowered.startswith("vcruntime")
        or lowered.startswith("msvcp")
        or lowered in {"ucrtbase.dll", "concrt140.dll"}
    )


def classify(relative: str) -> tuple[str, ...]:
    parts = relative_parts(relative)
    name = parts[-1]
    suffix = Path(name).suffix.casefold()

    if not parts:
        return ()
    if parts[0] in {"compliance", "licenses", "docs"} or name in {
        "license",
        "third_party_licenses.txt",
        "third_party_notices.md",
        "component-inventory.json",
        "binary-to-source-map.json",
        "build-inputs.lock",
        "project-metadata.json",
        "qt-pyside-components.json",
        "readme.md",
        "requirements.lock",
        "source-bundle-manifest.json",
        "source-hashes.json",
        "source-hashes.sha256",
    }:
        return ("compliance-material",)
    if name == EXECUTABLE_NAME.casefold():
        return ("project", "pyinstaller", "cpython-runtime", "python-package")
    if "bin" in parts and name == "node.exe":
        return ("node",)
    if "bin" in parts and name in {"ffmpeg.exe", "ffprobe.exe"}:
        return ("ffmpeg",)
    if "pyside6" in parts:
        components = ["pyside"]
        if name.startswith("qt6") or "plugins" in parts or name == "opengl32sw.dll":
            components.append("qt")
        if is_microsoft_runtime_name(name):
            components.append("microsoft-runtime")
        return tuple(components)
    if "shiboken6" in parts:
        components = ["pyside"]
        if is_microsoft_runtime_name(name):
            components.append("microsoft-runtime")
        return tuple(components)
    if is_microsoft_runtime_name(name):
        return ("microsoft-runtime",)
    if name == "libffi-8.dll":
        return ("libffi", "cpython-runtime")
    if name.startswith("libcrypto-") or name.startswith("libssl-"):
        return ("openssl", "cpython-runtime")
    if name == "sqlite3.dll":
        return ("sqlite", "cpython-runtime")
    if name.startswith("python") and suffix == ".dll":
        return ("cpython-runtime",)
    if name == "base_library.zip" or suffix == ".pyd":
        if parts[0] in PYTHON_PACKAGE_ROOTS or any(
            package in parts for package in PYTHON_PACKAGE_ROOTS
        ):
            return ("python-package",)
        return ("cpython-runtime",)
    if parts[0] in PYTHON_PACKAGE_ROOTS or any(
        package in parts for package in PYTHON_PACKAGE_ROOTS
    ):
        return ("python-package",)
    if parts[0] in {"assets", "translations"}:
        return ("project",)
    if suffix in {".pyc", ".py", ".json", ".pem", ".txt", ".zip"}:
        return ("python-package",)
    return ()


def source_evidence(project_root: Path, component: Component) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    missing: list[str] = []
    for relative in component.source_locations:
        path = project_root / relative
        exists = path.is_file() or path.is_dir()
        evidence.append({"path": relative, "exists": exists})
        if not exists:
            missing.append(relative)
    return {"locations": evidence, "complete": not missing, "missing": missing}


def required_review_gates(project_root: Path) -> list[dict[str, Any]]:
    requirements = {
        "project-copyright-owner-supplied": (
            "PROJECT-METADATA.json",
            '"public_author_and_copyright_holder": "0xRootNull"',
        ),
        "copyright-start-year-supplied": (
            "PROJECT-METADATA.json",
            '"development_started": 2025',
        ),
        "copyright-year-range-supplied": (
            "PROJECT-METADATA.json",
            '"copyright_period": "2025-2026"',
        ),
        "public-attribution-supplied": (
            "PROJECT-METADATA.json",
            '"public_attribution": "0xRootNull"',
        ),
        "mit-licensing-intent-explicitly-confirmed": (
            "PROJECT-METADATA.json",
            '"mit_licensing_intent": "explicitly confirmed"',
        ),
        "no-company-employer-client-ownership-claim": (
            "PROJECT-METADATA.json",
            '"employer_client_or_commissioning_party": null',
        ),
        "no-known-additional-human-contributor-claim": (
            "PROJECT-METADATA.json",
            '"known_other_human_contributors": []',
        ),
        "qualified-review": ("THIRD_PARTY_NOTICES.md", "Qualified-review-status: PASS"),
        "lgpl-replacement": ("docs/LGPL-COMPLIANCE.md", "Replacement-test-status: PASS"),
        "ffmpeg-source": ("docs/FFMPEG-SOURCE-AND-BUILD.md", "Closure-status: PASS"),
        "python-runtime-source": ("docs/PYTHON-RUNTIME-SOURCE.md", "Closure-status: PASS"),
        "microsoft-redistribution": (
            "docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md",
            "Redistribution-evidence-status: PASS",
        ),
        "native-closure": ("NATIVE-COMPONENTS.json", '"closure_status": "PASS"'),
        "source-bundle": ("SOURCE-BUNDLE-MANIFEST.json", '"closure_status": "PASS"'),
    }
    rows: list[dict[str, Any]] = []
    for identifier, (relative, marker) in requirements.items():
        path = project_root / relative
        present = path.is_file()
        text = path.read_text(encoding="utf-8", errors="replace") if present else ""
        passed = present and marker in text
        rows.append(
            {
                "id": identifier,
                "path": relative,
                "required_marker": marker,
                "status": "PASS" if passed else "HOLD",
            }
        )
    return rows


def audit_distribution(distribution: Path, project_root: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    prohibited: list[dict[str, str]] = []
    unmapped: list[str] = []
    unknown_native: list[str] = []
    tree_digest = hashlib.sha256()

    for path in sorted(
        (item for item in distribution.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(distribution).as_posix().casefold(),
    ):
        relative = path.relative_to(distribution).as_posix()
        actual_digest = sha256_file(path)
        self_referential_map = relative.casefold() in {
            "binary-to-source-map.json",
            "compliance/binary-to-source-map.json",
        }
        recorded_digest = "SELF-REFERENTIAL" if self_referential_map else actual_digest
        recorded_size: int | str = (
            "SELF-REFERENTIAL" if self_referential_map else path.stat().st_size
        )
        components = classify(relative)
        normalized = relative.casefold()
        reasons = [pattern.pattern for pattern in PROHIBITED_PATH_PATTERNS if pattern.search(normalized)]
        if actual_digest in PROHIBITED_LEGACY_SHA256S:
            reasons.append("prohibited-legacy-one-file-sha256")
        if reasons:
            prohibited.append({"path": relative, "reason": "; ".join(reasons)})
        if not components:
            unmapped.append(relative)
            if path.suffix.casefold() in NATIVE_SUFFIXES:
                unknown_native.append(relative)
        tree_digest.update(relative.encode("utf-8"))
        tree_digest.update(b"\0")
        tree_digest.update(
            b"SELF-REFERENTIAL" if self_referential_map else bytes.fromhex(actual_digest)
        )
        tree_digest.update(b"\0")
        files.append(
            {
                "path": relative,
                "size": recorded_size,
                "sha256": recorded_digest,
                "components": list(components),
                "mapping_status": "PASS" if components else "HOLD",
            }
        )

    evidence = {
        identifier: source_evidence(project_root, component)
        for identifier, component in COMPONENTS.items()
    }
    gates = required_review_gates(project_root)
    technical_pass = bool(files) and not prohibited and not unmapped and not unknown_native
    evidence_pass = all(row["complete"] for row in evidence.values())
    review_pass = all(row["status"] == "PASS" for row in gates)
    closure_pass = technical_pass and evidence_pass and review_pass
    return {
        "schema_version": 1,
        "application_version": APPLICATION_VERSION,
        "distribution_format": "windows-one-folder",
        "public_distribution_verdict": "PASS" if closure_pass else "HOLD",
        "closure_status": "PASS" if closure_pass else "HOLD",
        "technical_mapping_status": "PASS" if technical_pass else "HOLD",
        "distribution_root": distribution.name,
        "tree_sha256": tree_digest.hexdigest(),
        "file_count": len(files),
        "prohibited_entries": prohibited,
        "unmapped_files": unmapped,
        "unknown_native_files": unknown_native,
        "component_catalog": {
            identifier: {
                "version": component.version,
                "license": component.license_expression,
                "source_locations": list(component.source_locations),
            }
            for identifier, component in COMPONENTS.items()
        },
        "source_evidence": evidence,
        "review_gates": gates,
        "files": files,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("distribution", type=Path)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-pass", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    distribution = args.distribution.resolve()
    project_root = args.project_root.resolve()
    if not distribution.is_dir():
        raise SystemExit(f"Distribution directory does not exist: {distribution}")
    report = audit_distribution(distribution, project_root)
    output = args.output or (project_root / "BINARY-TO-SOURCE-MAP.json")
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"{report['technical_mapping_status']}: mapped {report['file_count']} files; "
        f"public distribution {report['public_distribution_verdict']}"
    )
    if report["prohibited_entries"]:
        print(f"Prohibited entries: {len(report['prohibited_entries'])}", file=sys.stderr)
    if report["unmapped_files"]:
        print(f"Unmapped files: {len(report['unmapped_files'])}", file=sys.stderr)
    if report["unknown_native_files"]:
        print(f"Unknown native files: {len(report['unknown_native_files'])}", file=sys.stderr)
    if args.require_pass and report["closure_status"] != "PASS":
        print("Release closure is HOLD; publication is blocked.", file=sys.stderr)
        return 1
    return 0 if report["technical_mapping_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
