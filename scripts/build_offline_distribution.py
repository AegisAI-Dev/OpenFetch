"""Build the primary Windows one-folder compliance candidate without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path
from typing import Any

try:
    from scripts.project_identity import (
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
        ONEFOLDER_SPEC_NAME,
    )
except ModuleNotFoundError:  # executed directly as scripts/build_offline_distribution.py
    from project_identity import (  # type: ignore[no-redef]
        APPLICATION_VERSION,
        EXECUTABLE_NAME,
        ONEFOLDER_DIST_NAME,
        ONEFOLDER_SPEC_NAME,
    )

BUILD_LABEL = "pyside-provider-free-compliance-candidate"
ZIP_NAME = f"{ONEFOLDER_DIST_NAME}.zip"
DIST_NAME = ONEFOLDER_DIST_NAME
FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)
TARGET_WHEELHOUSE = Path("build_inputs/wheels/cp312-win_amd64")
PINNED_PYTHON = (3, 12, 9)
PINNED_ZLIB = "1.3.1"
# The staged copy must be a complete audited mirror: the prebuild gates
# re-verify SOURCE-HASHES.sha256 against every listed file inside staging.
# ``bin`` is intentionally absent; it is recreated from the pinned runtime
# archives, whose members are byte-identical to the audited ``bin`` entries.
PROJECT_FILES = (
    ".github",
    ".gitignore",
    "assets",
    "build_inputs",
    "docs",
    "licenses",
    "scripts",
    "src",
    "tests",
    "third_party_sources",
    "build.bat",
    "LICENSE",
    "main.py",
    ONEFOLDER_SPEC_NAME,
    "PROJECT-METADATA.json",
    "pyproject.toml",
    "README.md",
    "requirements.lock",
    "requirements.txt",
    "SOURCE-HASHES.sha256",
    "start.bat",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "uv.lock",
    "version_info.txt",
)
COMPLIANCE_FILES = (
    "LICENSE",
    "PROJECT-METADATA.json",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "SOURCE-HASHES.sha256",
    "SOURCE-HASHES.json",
    "BUILD-INPUTS.lock",
    "NATIVE-COMPONENTS.json",
    "QT-PYSIDE-COMPONENTS.json",
    "SOURCE-BUNDLE-MANIFEST.json",
    "docs/DEPENDENCY-SOURCE.md",
    "docs/BUILD-REPRODUCIBILITY.md",
    "docs/LGPL-COMPLIANCE.md",
    "docs/QT-REPLACEMENT-GUIDE.md",
    "docs/QT-BUILD-PROVENANCE.md",
    "docs/FFMPEG-SOURCE-AND-BUILD.md",
    "docs/PYTHON-RUNTIME-SOURCE.md",
    "docs/PYTHON-RUNTIME-REPRODUCIBILITY.md",
    "docs/MICROSOFT-RUNTIME-REDISTRIBUTION.md",
    "docs/COPYRIGHT-OWNERSHIP-QUESTIONS.md",
    "docs/PROJECT-OWNERSHIP-DECLARATION.md",
    "docs/EXISTING-RELEASE-COMPLIANCE-REVIEW.md",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_deterministic_driver() -> None:
    if sys.version_info[:3] != PINNED_PYTHON:
        raise RuntimeError(
            f"Offline build driver must be CPython {PINNED_PYTHON}, got "
            f"{sys.version_info[:3]}"
        )
    if zlib.ZLIB_VERSION != PINNED_ZLIB or zlib.ZLIB_RUNTIME_VERSION != PINNED_ZLIB:
        raise RuntimeError(
            f"Offline build driver requires zlib {PINNED_ZLIB}, got "
            f"compile={zlib.ZLIB_VERSION}, runtime={zlib.ZLIB_RUNTIME_VERSION}"
        )


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    printable = " ".join(command)
    print(f"RUN {printable}", flush=True)
    completed = subprocess.run(command, cwd=cwd, env=env, check=False)
    if completed.returncode:
        raise RuntimeError(f"Command failed with exit code {completed.returncode}: {printable}")


def load_prepared_inputs(project_root: Path) -> dict[str, dict[str, Any]]:
    manifest_path = project_root / "build_inputs" / "PREPARATION-MANIFEST.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_target = {
        "python": "3.12",
        "interpreter": "cp312",
        "abi": "cp312",
        "platform": "win_amd64",
        "directory": TARGET_WHEELHOUSE.as_posix(),
    }
    if payload.get("wheel_target") != expected_target:
        raise RuntimeError(
            "Prepared wheel target differs from the pinned runtime: "
            f"{payload.get('wheel_target')!r} != {expected_target!r}"
        )
    rows: dict[str, dict[str, Any]] = {}
    declared_wheels: set[Path] = set()
    for row in payload["files"]:
        path = Path(str(row["path"]))
        if not path.is_absolute():
            path = project_root / path
        path = path.resolve()
        if not path.is_relative_to(project_root.resolve()):
            raise RuntimeError(f"Prepared input escapes project root: {path}")
        if not path.is_file():
            raise RuntimeError(f"Prepared input is missing: {path}")
        actual = sha256_file(path)
        if actual != row["sha256"]:
            raise RuntimeError(f"Prepared input hash mismatch: {path}")
        row = dict(row)
        row["resolved_path"] = str(path)
        rows[str(row["component"])] = row
        if row.get("kind") == "python-build-wheel":
            declared_wheels.add(path)
    wheelhouse = (project_root / TARGET_WHEELHOUSE).resolve()
    if not wheelhouse.is_dir():
        raise RuntimeError(f"Pinned target wheelhouse is missing: {wheelhouse}")
    actual_wheels = {path.resolve() for path in wheelhouse.glob("*.whl") if path.is_file()}
    if any(not path.is_relative_to(wheelhouse) for path in declared_wheels):
        raise RuntimeError("A declared Python build wheel is outside the pinned wheelhouse")
    missing = sorted(str(path) for path in declared_wheels - actual_wheels)
    extra = sorted(str(path) for path in actual_wheels - declared_wheels)
    if missing or extra:
        raise RuntimeError(
            "Pinned wheelhouse differs from preparation manifest; "
            f"missing={missing}, extra={extra}"
        )
    return rows


def ensure_empty_destination(path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise RuntimeError(f"Build destination is not a directory: {path}")
        if any(path.iterdir()):
            raise RuntimeError(f"Build destination must be new or empty: {path}")
    else:
        path.mkdir(parents=True)


def safe_extract_tar(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:gz") as handle:
        for member in handle.getmembers():
            target = (destination / member.name).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise RuntimeError(f"Unsafe tar member: {member.name}")
        handle.extractall(destination, filter="data")


def safe_extract_zip(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(archive) as handle:
        for member in handle.infolist():
            target = (destination / member.filename).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise RuntimeError(f"Unsafe ZIP member: {member.filename}")
        handle.extractall(destination)


def copy_project(project_root: Path, staged: Path) -> None:
    staged.mkdir(parents=True)
    for relative in PROJECT_FILES:
        source = project_root / relative
        if not source.exists():
            raise RuntimeError(f"Required project build input is missing: {relative}")
        destination = staged / relative
        if source.is_dir():
            shutil.copytree(
                source,
                destination,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".ruff_cache"),
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def find_exact(root: Path, name: str) -> Path:
    matches = [path for path in root.rglob(name) if path.is_file()]
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one {name} below {root}, found {len(matches)}")
    return matches[0]


def stage_runtimes(inputs: dict[str, dict[str, Any]], workspace: Path, staged: Path) -> Path:
    runtime_root = workspace / "runtime"
    runtime_root.mkdir()
    pbs_archive = Path(inputs["python-build-standalone-runtime"]["resolved_path"])
    safe_extract_tar(pbs_archive, runtime_root)
    # The stripped PBS archive holds the interpreter at python/python.exe plus
    # the Lib/venv/scripts/nt stub, so an exact-name search would find two.
    python = runtime_root / "python" / "python.exe"
    if not python.is_file():
        raise RuntimeError(f"Unexpected PBS archive layout: {python}")

    extracted = workspace / "runtime-archives"
    extracted.mkdir()
    safe_extract_zip(Path(inputs["node-binary-archive"]["resolved_path"]), extracted / "node")
    safe_extract_zip(
        Path(inputs["ffmpeg-btbn-binary-archive"]["resolved_path"]), extracted / "ffmpeg"
    )
    bin_directory = staged / "bin"
    bin_directory.mkdir()
    for name, root in (
        ("node.exe", extracted / "node"),
        ("ffmpeg.exe", extracted / "ffmpeg"),
        ("ffprobe.exe", extracted / "ffmpeg"),
    ):
        shutil.copy2(find_exact(root, name), bin_directory / name)
    return python


def install_environment(
    base_python: Path, workspace: Path, staged: Path, project_root: Path
) -> Path:
    environment = workspace / "build-env"
    run([str(base_python), "-m", "venv", str(environment)], cwd=workspace)
    python = environment / "Scripts" / "python.exe"
    wheelhouse = project_root / TARGET_WHEELHOUSE
    env = offline_environment()
    run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--require-hashes",
            "-r",
            str(staged / "requirements.lock"),
        ],
        cwd=staged,
        env=env,
    )
    run([str(python), "-m", "pip", "check"], cwd=staged, env=env)
    return python


def offline_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONHASHSEED": "0",
            # 1980-01-01: the earliest timestamp ZIP containers accept.
            "SOURCE_DATE_EPOCH": "315532800",
            "QT_HASH_SEED": "0",
            "TZ": "UTC",
        }
    )
    env.pop("PIP_INDEX_URL", None)
    env.pop("PIP_EXTRA_INDEX_URL", None)
    return env


def copy_compliance_material(project_root: Path, distribution: Path) -> None:
    compliance = distribution / "compliance"
    compliance.mkdir()
    for relative in COMPLIANCE_FILES:
        source = project_root / relative
        if not source.is_file():
            raise RuntimeError(f"Required candidate compliance file is missing: {relative}")
        destination = compliance / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    shutil.copytree(project_root / "licenses", compliance / "licenses")
    (compliance / "BUILD-LABEL.txt").write_text(
        f"{BUILD_LABEL}\nVersion: {APPLICATION_VERSION}\nPublic-distribution verdict: HOLD\n",
        encoding="utf-8",
    )


def deterministic_zip(source: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(
            (candidate for candidate in source.rglob("*") if candidate.is_file()),
            key=lambda candidate: candidate.relative_to(source).as_posix().casefold(),
        ):
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(f"{source.name}/{relative}", FIXED_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def tree_manifest(root: Path) -> tuple[list[dict[str, Any]], str]:
    rows: list[dict[str, Any]] = []
    tree = hashlib.sha256()
    for path in sorted(
        (candidate for candidate in root.rglob("*") if candidate.is_file()),
        key=lambda candidate: candidate.relative_to(root).as_posix().casefold(),
    ):
        relative = path.relative_to(root).as_posix()
        digest = sha256_file(path)
        rows.append({"path": relative, "size": path.stat().st_size, "sha256": digest})
        tree.update(relative.encode("utf-8"))
        tree.update(b"\0")
        tree.update(bytes.fromhex(digest))
        tree.update(b"\0")
    return rows, tree.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    assert_deterministic_driver()
    project_root = args.project_root.resolve()
    workspace = args.workspace.resolve()
    output_root = args.output_root.resolve()
    ensure_empty_destination(workspace)
    ensure_empty_destination(output_root)
    inputs = load_prepared_inputs(project_root)
    staged = workspace / "project"
    copy_project(project_root, staged)
    base_python = stage_runtimes(inputs, workspace, staged)
    python = install_environment(base_python, workspace, staged, project_root)

    env = offline_environment()
    work_path = workspace / "pyinstaller-work"
    dist_path = workspace / "pyinstaller-dist"
    onefolder_tool = staged / "scripts" / "qt_onefolder_compliance.py"
    run(
        [
            str(python),
            str(onefolder_tool),
            "build",
            "--python",
            str(python),
            "--dist-root",
            str(dist_path),
            "--work-root",
            str(work_path),
            "--no-zip",
        ],
        cwd=staged,
        env=env,
    )
    distribution = dist_path / DIST_NAME
    executable = distribution / EXECUTABLE_NAME
    if not executable.is_file():
        raise RuntimeError(
            "The primary spec did not produce the required one-folder distribution"
        )
    copy_compliance_material(project_root, distribution)

    replacement_result = output_root / "QT-REPLACEMENT-SMOKE.json"
    run(
        [
            str(python),
            str(onefolder_tool),
            "replacement-smoke",
            str(distribution),
            "--output",
            str(replacement_result),
        ],
        cwd=staged,
        env=env,
    )

    verifier = project_root / "scripts" / "verify_distribution_closure.py"
    embedded_map = distribution / "compliance" / "BINARY-TO-SOURCE-MAP.json"
    embedded_map.write_text("{}\n", encoding="utf-8")
    run(
        [str(python), str(verifier), str(distribution), "--output", str(embedded_map)],
        cwd=project_root,
        env=env,
    )
    final_map = output_root / "BINARY-TO-SOURCE-MAP.json"
    run(
        [str(python), str(verifier), str(distribution), "--output", str(final_map)],
        cwd=project_root,
        env=env,
    )
    if embedded_map.read_bytes() != final_map.read_bytes():
        raise RuntimeError("Embedded and external canonical binary-to-source maps differ")

    output_distribution = output_root / DIST_NAME
    shutil.copytree(distribution, output_distribution)
    archive = output_root / ZIP_NAME
    deterministic_zip(output_distribution, archive)
    files, tree_hash = tree_manifest(output_distribution)
    report = {
        "schema_version": 1,
        "application_version": APPLICATION_VERSION,
        "build_label": BUILD_LABEL,
        "public_distribution_verdict": "HOLD",
        "network_used_during_build": False,
        "base_python": str(base_python),
        "build_python_version": subprocess.check_output(
            [str(python), "--version"], text=True, stderr=subprocess.STDOUT
        ).strip(),
        "distribution_file_count": len(files),
        "distribution_tree_sha256": tree_hash,
        "zip": {
            "path": archive.name,
            "size": archive.stat().st_size,
            "sha256": sha256_file(archive),
        },
        "executable": {
            "path": f"{DIST_NAME}/{EXECUTABLE_NAME}",
            "size": (output_distribution / EXECUTABLE_NAME).stat().st_size,
            "sha256": sha256_file(output_distribution / EXECUTABLE_NAME),
        },
        "files": files,
    }
    (output_root / "BUILD-REPORT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Built offline one-folder candidate: {archive}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
