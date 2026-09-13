"""Generate deterministic source-input and license-text SHA-256 manifests."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_OUTPUT = PROJECT_ROOT / "SOURCE-HASHES.sha256"
LICENSE_ROOT = PROJECT_ROOT / "licenses"
LICENSE_OUTPUT = LICENSE_ROOT / "RELEASE-LICENSE-MANIFEST.sha256"

SOURCE_FILES = (
    ".gitattributes",
    ".github/workflows/build-onefile-release.yml",
    ".github/workflows/build-release.yml",
    ".gitignore",
    "LICENSE",
    "OpenFetch-onefile.spec",
    "OpenFetch.spec",
    "PROJECT-METADATA.json",
    "README.md",
    "THIRD_PARTY_LICENSES.txt",
    "THIRD_PARTY_NOTICES.md",
    "build.bat",
    "main.py",
    "pyproject.toml",
    "requirements.lock",
    "requirements.txt",
    "start.bat",
    "uv.lock",
    "version_info.txt",
)
SOURCE_DIRECTORIES = (
    "assets",
    "bin",
    "build_inputs",
    "docs",
    "scripts",
    "src",
    "tests",
    "third_party_sources",
)
IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "vendor",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _source_paths(root: Path) -> list[Path]:
    paths: set[Path] = set()
    for relative in SOURCE_FILES:
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(f"required source/build input is missing: {relative}")
        paths.add(path)
    for relative in SOURCE_DIRECTORIES:
        directory = root / relative
        if not directory.is_dir():
            raise FileNotFoundError(f"required source directory is missing: {relative}")
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            relative_parts = path.relative_to(root).parts
            if any(
                part in IGNORED_PARTS or part.endswith(".egg-info")
                for part in relative_parts
            ):
                continue
            paths.add(path)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def _license_paths(license_root: Path) -> list[Path]:
    paths = [
        path
        for path in license_root.rglob("*")
        if path.is_file() and path.resolve() != LICENSE_OUTPUT.resolve()
    ]
    if not paths:
        raise FileNotFoundError("the license payload is empty")
    return sorted(paths, key=lambda path: path.relative_to(license_root).as_posix())


def _render(paths: list[Path], base: Path) -> str:
    return "".join(
        f"{sha256(path)}  {path.relative_to(base).as_posix()}\n" for path in paths
    )


def generate() -> tuple[int, int]:
    """Regenerate both manifests and return their entry counts."""
    license_paths = _license_paths(LICENSE_ROOT)
    # newline="\n" keeps the generated manifests byte-identical on Windows and
    # POSIX; the repository's canonical representation is LF (see .gitattributes).
    LICENSE_OUTPUT.write_text(
        _render(license_paths, LICENSE_ROOT), encoding="utf-8", newline="\n"
    )

    source_paths = _source_paths(PROJECT_ROOT)
    SOURCE_OUTPUT.write_text(
        _render(source_paths, PROJECT_ROOT), encoding="utf-8", newline="\n"
    )
    return len(source_paths), len(license_paths)


def verify_manifest(
    manifest: Path,
    base: Path,
    *,
    expected_paths: list[Path] | None = None,
) -> list[str]:
    """Return errors for incomplete, malformed, missing, or mismatched entries."""
    errors: list[str] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        try:
            expected, relative = raw_line.split("  ", 1)
        except ValueError:
            errors.append(f"line {line_number}: expected '<sha256>  <path>'")
            continue
        if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
            errors.append(f"line {line_number}: invalid lowercase SHA-256")
            continue
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            errors.append(f"line {line_number}: unsafe path {relative!r}")
            continue
        normalized = relative_path.as_posix()
        if normalized in seen:
            errors.append(f"line {line_number}: duplicate path {normalized}")
            continue
        seen.add(normalized)
        path = base / relative_path
        if not path.is_file():
            errors.append(f"missing file: {normalized}")
        elif sha256(path) != expected:
            errors.append(f"hash mismatch: {normalized}")

    if expected_paths is not None:
        expected_records = {
            path.relative_to(base).as_posix() for path in expected_paths
        }
        for missing in sorted(expected_records - seen):
            errors.append(f"manifest omits file: {missing}")
        for unexpected in sorted(seen - expected_records):
            errors.append(f"manifest contains unexpected file: {unexpected}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        errors = []
        errors.extend(
            verify_manifest(
                SOURCE_OUTPUT,
                PROJECT_ROOT,
                expected_paths=_source_paths(PROJECT_ROOT),
            )
        )
        errors.extend(
            verify_manifest(
                LICENSE_OUTPUT,
                LICENSE_ROOT,
                expected_paths=_license_paths(LICENSE_ROOT),
            )
        )
        if errors:
            for error in errors:
                print(f"HOLD: {error}")
            return 1
        print("Source and license SHA-256 manifests verified.")
        return 0

    source_count, license_count = generate()
    print(f"Wrote {source_count} source hashes and {license_count} license hashes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
