"""Assemble the final non-public one-folder release asset from a verified build.

Takes an audited, reproducibility-verified one-folder distribution tree (the
rc build output), refreshes the embedded compliance material from the current
project root, adds the required public materials (root PROJECT-METADATA.json
and README.md), regenerates the canonical binary-to-source map over the final
tree, produces the sibling directory-update manifest release asset, and writes
the deterministic ZIP twice to prove assembly reproducibility.

The directory-update manifest is deliberately a SIBLING asset, not a ZIP
member: the directory updater verifies the staged tree exactly against the
manifest (update_directory_installer._verify_staged fails closed with
``update_package_unexpected_file`` on any unlisted file), so a manifest
embedded in the tree could never cover itself.

This script never changes the public-distribution verdict: the embedded
BUILD-LABEL.txt continues to declare ``Public-distribution verdict: HOLD``.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from build_offline_distribution import (
    APPLICATION_VERSION,
    DIST_NAME,
    EXECUTABLE_NAME,
    ZIP_NAME,
    copy_compliance_material,
    deterministic_zip,
    sha256_file,
    tree_manifest,
)

DISTRIBUTION_README_SOURCE = "docs/ONE-FOLDER-DISTRIBUTION-README.md"
# Files at the distribution root that must byte-match the current project
# root when the asset is finalized (they are also embedded under compliance/).
ROOT_REFRESH_FILES = (
    "LICENSE",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "SOURCE-HASHES.sha256",
    "requirements.lock",
)
# Top-level docs shipped inside the distribution (kept in sync with the spec
# datas list); refreshed from the current project docs.
TREE_DOCS = (
    "docs/BUILD-REPRODUCIBILITY.md",
    "docs/DEPENDENCY-SOURCE.md",
    "docs/LGPL-COMPLIANCE.md",
    "docs/OPTIONAL-PO-PROVIDER.md",
    "docs/QT-BUILD-PROVENANCE.md",
    "docs/QT-REPLACEMENT-GUIDE.md",
)


def ensure_empty_destination(path: Path) -> None:
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise RuntimeError(f"Destination must be a new or empty directory: {path}")
    else:
        path.mkdir(parents=True)


def run(command: list[str], *, cwd: Path) -> None:
    printable = " ".join(command)
    print(f"RUN {printable}", flush=True)
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode:
        raise RuntimeError(f"Command failed with exit code {completed.returncode}: {printable}")


def copy_distribution_tree(source: Path, destination: Path) -> None:
    def reject_reparse(path: Path) -> None:
        status = os.lstat(path)
        attributes = getattr(status, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if attributes & reparse_flag or stat.S_ISLNK(status.st_mode):
            raise RuntimeError(f"Source distribution contains a reparse point: {path}")

    destination.mkdir(parents=True)
    for current, dirnames, filenames in os.walk(source):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        for name in dirnames:
            reject_reparse(current_path / name)
            (destination / relative / name).mkdir(exist_ok=True)
        for name in filenames:
            reject_reparse(current_path / name)
            shutil.copy2(current_path / name, destination / relative / name)


def refresh_public_materials(project_root: Path, distribution: Path) -> None:
    for relative in ROOT_REFRESH_FILES:
        source = project_root / relative
        if not source.is_file():
            raise RuntimeError(f"Required project file is missing: {relative}")
        shutil.copy2(source, distribution / Path(relative).name)
    for relative in TREE_DOCS:
        source = project_root / relative
        if not source.is_file():
            raise RuntimeError(f"Required distribution doc is missing: {relative}")
        destination = distribution / relative
        destination.parent.mkdir(exist_ok=True)
        shutil.copy2(source, destination)
    readme_source = project_root / DISTRIBUTION_README_SOURCE
    if not readme_source.is_file():
        raise RuntimeError(f"Distribution README source is missing: {DISTRIBUTION_README_SOURCE}")
    shutil.copy2(readme_source, distribution / "README.md")
    metadata_source = project_root / "PROJECT-METADATA.json"
    if not metadata_source.is_file():
        raise RuntimeError("PROJECT-METADATA.json is missing from the project root")
    shutil.copy2(metadata_source, distribution / "PROJECT-METADATA.json")
    # The tree-root Qt/PySide inventory is build-generated; it must already
    # byte-match the audited project-root copy. Never overwrite it silently.
    tree_inventory = distribution / "QT-PYSIDE-COMPONENTS.json"
    root_inventory = project_root / "QT-PYSIDE-COMPONENTS.json"
    if not tree_inventory.is_file():
        raise RuntimeError("Distribution is missing QT-PYSIDE-COMPONENTS.json")
    if tree_inventory.read_bytes() != root_inventory.read_bytes():
        raise RuntimeError(
            "Distribution QT-PYSIDE-COMPONENTS.json differs from the project root copy"
        )
    # Refresh the shipped license directory from the audited project licenses.
    licenses_destination = distribution / "licenses"
    if licenses_destination.exists():
        shutil.rmtree(licenses_destination)
    shutil.copytree(project_root / "licenses", licenses_destination)


def rebuild_compliance_directory(project_root: Path, distribution: Path) -> None:
    compliance = distribution / "compliance"
    if compliance.exists():
        shutil.rmtree(compliance)
    copy_compliance_material(project_root, distribution)


def regenerate_binary_map(project_root: Path, distribution: Path, output_root: Path) -> None:
    verifier = project_root / "scripts" / "verify_distribution_closure.py"
    embedded_map = distribution / "compliance" / "BINARY-TO-SOURCE-MAP.json"
    embedded_map.write_text("{}\n", encoding="utf-8")
    run(
        [sys.executable, str(verifier), str(distribution), "--project-root",
         str(project_root), "--output", str(embedded_map)],
        cwd=project_root,
    )
    external_map = output_root / "BINARY-TO-SOURCE-MAP.json"
    run(
        [sys.executable, str(verifier), str(distribution), "--project-root",
         str(project_root), "--output", str(external_map)],
        cwd=project_root,
    )
    if embedded_map.read_bytes() != external_map.read_bytes():
        raise RuntimeError("Embedded and external canonical binary-to-source maps differ")
    payload = json.loads(external_map.read_text(encoding="utf-8"))
    if payload.get("technical_mapping_status") != "PASS":
        raise RuntimeError(
            "Binary-to-source technical mapping is not PASS: "
            f"prohibited={payload.get('prohibited_entries')}, "
            f"unmapped={payload.get('unmapped_files')}, "
            f"unknown_native={payload.get('unknown_native_files')}"
        )


def generate_directory_manifest(project_root: Path, distribution: Path, output_root: Path) -> Path:
    sys.path.insert(0, str(project_root / "src"))
    try:
        from openfetch.core.update_directory_installer import (
            DirectoryUpdateManifest,
            expected_directory_manifest_filename,
        )
    finally:
        sys.path.pop(0)
    manifest = DirectoryUpdateManifest.for_distribution_root(
        version=APPLICATION_VERSION, root=distribution
    )
    manifest_path = output_root / expected_directory_manifest_filename(APPLICATION_VERSION)
    manifest_path.write_text(manifest.to_json(), encoding="utf-8")
    return manifest_path


def build_release_zip(distribution: Path, output_root: Path) -> Path:
    archive = output_root / ZIP_NAME
    rebuild = output_root / f"{ZIP_NAME}.rebuild"
    deterministic_zip(distribution, archive)
    shutil.copy2(archive, rebuild)
    archive.unlink()
    deterministic_zip(distribution, archive)
    if archive.read_bytes() != rebuild.read_bytes():
        rebuild.unlink()
        raise RuntimeError("Deterministic ZIP rebuild produced differing bytes")
    rebuild.unlink()
    return archive


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--source-dist", type=Path, required=True,
                        help="Verified one-folder distribution tree (rc build output)")
    parser.add_argument("--output-root", type=Path, required=True,
                        help="New or empty release-staging directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = args.project_root.resolve()
    source = args.source_dist.resolve()
    output_root = args.output_root.resolve()
    if not (source / EXECUTABLE_NAME).is_file():
        raise RuntimeError(f"Source distribution has no launcher: {source}")
    if source.name != DIST_NAME:
        raise RuntimeError(f"Source distribution must be named {DIST_NAME}: {source.name}")
    ensure_empty_destination(output_root)
    distribution = output_root / DIST_NAME
    copy_distribution_tree(source, distribution)
    refresh_public_materials(project_root, distribution)
    rebuild_compliance_directory(project_root, distribution)
    regenerate_binary_map(project_root, distribution, output_root)
    manifest_path = generate_directory_manifest(project_root, distribution, output_root)
    archive = build_release_zip(distribution, output_root)
    (output_root / f"{ZIP_NAME}.sha256").write_text(
        f"{sha256_file(archive)}  {ZIP_NAME}\n", encoding="utf-8"
    )
    files, tree_hash = tree_manifest(distribution)
    report = {
        "schema_version": 1,
        "application_version": APPLICATION_VERSION,
        "public_distribution_verdict": "HOLD",
        "source_distribution": str(source),
        "distribution_file_count": len(files),
        "distribution_tree_sha256": tree_hash,
        "zip": {
            "path": archive.name,
            "size": archive.stat().st_size,
            "sha256": sha256_file(archive),
        },
        "directory_manifest": {
            "path": manifest_path.name,
            "size": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
        },
        "executable": {
            "path": f"{DIST_NAME}/{EXECUTABLE_NAME}",
            "size": (distribution / EXECUTABLE_NAME).stat().st_size,
            "sha256": sha256_file(distribution / EXECUTABLE_NAME),
        },
    }
    (output_root / "RELEASE-ASSET-REPORT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Finalized one-folder release asset: {archive}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
