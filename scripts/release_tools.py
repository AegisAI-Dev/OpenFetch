"""Validate release versions, render version metadata, and generate update manifests."""

from __future__ import annotations

import argparse
import ast
import sys
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from openfetch.core.update_manifest import (  # noqa: E402
    LEGACY_RELEASE,
    OPENFETCH_RELEASE,
    UpdateManifest,
    UpdateValidationError,
    parse_numeric_version,
)

# Installed Neural Extractor V3 updaters before 3.0.4 cannot hand off safely.
BOOTSTRAP_UPDATER_VERSION = "3.0.4"
# OpenFetch manifests are read only by OpenFetch updaters.
OPENFETCH_MINIMUM_UPDATER_VERSION = "3.1.0"
RELEASE_NAMINGS = {"openfetch": OPENFETCH_RELEASE, "legacy": LEGACY_RELEASE}
DEFAULT_MINIMUM_UPDATER_VERSIONS = {
    "openfetch": OPENFETCH_MINIMUM_UPDATER_VERSION,
    "legacy": BOOTSTRAP_UPDATER_VERSION,
}
VERSION_ATTRIBUTE = "openfetch.config.VERSION"
LEGAL_COPYRIGHT = "Copyright (c) 2025-2026 0xRootNull"

VERSION_INFO_TEMPLATE = """VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, 0),
    prodvers=({major}, {minor}, {patch}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          "040904B0",
          [
            StringStruct("CompanyName", "{publisher}"),
            StringStruct("FileDescription", "{product}"),
            StringStruct("FileVersion", "{version}"),
            StringStruct("InternalName", "{stem}"),
            StringStruct(
              "LegalCopyright",
              "{copyright}"
            ),
            StringStruct("OriginalFilename", "{stem}.exe"),
            StringStruct("ProductName", "{product}"),
            StringStruct("ProductVersion", "{version}")
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct("Translation", [1033, 1200])])
  ]
)
"""


def config_constant(project_root: Path, name: str) -> str:
    config_path = project_root / "src" / "openfetch" / "config.py"
    tree = ast.parse(config_path.read_text(encoding="utf-8"), filename=str(config_path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise ValueError(f"{name} was not found as a string constant in config.py")


def config_version(project_root: Path) -> str:
    return config_constant(project_root, "VERSION")


def project_version(project_root: Path) -> str:
    """Return the packaging version, which must be derived from config.py."""
    payload = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = payload.get("project", {})
    if "version" in project:
        raise ValueError(
            "pyproject.toml must not declare a static project.version; "
            f"derive it from {VERSION_ATTRIBUTE}"
        )
    dynamic = payload.get("tool", {}).get("setuptools", {}).get("dynamic", {})
    if "version" not in project.get("dynamic", []) or dynamic.get("version") != {
        "attr": VERSION_ATTRIBUTE
    }:
        raise ValueError(f"pyproject.toml must derive the version from {VERSION_ATTRIBUTE}")
    return config_version(project_root)


def render_version_info(project_root: Path) -> str:
    version = config_version(project_root)
    major, minor, patch = parse_numeric_version(version)
    return VERSION_INFO_TEMPLATE.format(
        major=major,
        minor=minor,
        patch=patch,
        version=version,
        product=config_constant(project_root, "APP_NAME"),
        publisher=config_constant(project_root, "APP_PUBLISHER"),
        stem=config_constant(project_root, "EXECUTABLE_STEM"),
        copyright=LEGAL_COPYRIGHT,
    )


def version_info_is_current(project_root: Path) -> bool:
    path = project_root / "version_info.txt"
    return path.is_file() and path.read_text(encoding="utf-8") == render_version_info(project_root)


def release_version(release_ref: str) -> str:
    value = str(release_ref or "")
    version = value[1:] if value.startswith("v") else value
    parse_numeric_version(version)
    return version


def validate_release_versions(project_root: Path, release_ref: str) -> str:
    release = release_version(release_ref)
    config = config_version(project_root)
    project = project_version(project_root)
    parse_numeric_version(config)
    if config != project:
        raise ValueError(f"Version mismatch: config.py={config}, pyproject.toml={project}")
    if not version_info_is_current(project_root):
        raise ValueError(
            "version_info.txt does not match config.py; run scripts/release_tools.py version-info"
        )
    if release != config:
        raise ValueError(f"Release version mismatch: release={release}, source={config}")
    return release


def generate_manifest(
    *,
    version: str,
    executable: Path,
    output: Path,
    minimum_updater_version: str | None = None,
    naming: str = "openfetch",
) -> UpdateManifest:
    if naming not in RELEASE_NAMINGS:
        raise ValueError(f"Unknown release naming: {naming}")
    release_naming = RELEASE_NAMINGS[naming]
    minimum = minimum_updater_version or DEFAULT_MINIMUM_UPDATER_VERSIONS[naming]
    parse_numeric_version(version)
    parse_numeric_version(minimum)
    expected_output = release_naming.manifest_filename(version)
    if output.name != expected_output:
        raise ValueError(f"Manifest output must be named {expected_output}")
    manifest = UpdateManifest.for_executable(
        version=version,
        executable=executable,
        minimum_updater_version=minimum,
        naming=release_naming,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(manifest.to_json(), encoding="utf-8", newline="\n")
    return manifest


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate release/source versions")
    validate.add_argument("--release-ref", required=True)
    validate.add_argument("--project-root", type=Path, default=PROJECT_ROOT)

    version_info = subparsers.add_parser(
        "version-info", help="Write version_info.txt from config.py"
    )
    version_info.add_argument("--check", action="store_true")
    version_info.add_argument("--project-root", type=Path, default=PROJECT_ROOT)

    manifest = subparsers.add_parser("manifest", help="Generate strict release manifest")
    manifest.add_argument("--version", required=True)
    manifest.add_argument("--exe", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    manifest.add_argument("--naming", choices=sorted(RELEASE_NAMINGS), default="openfetch")
    manifest.add_argument("--minimum-updater-version", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            version = validate_release_versions(args.project_root.resolve(), args.release_ref)
            print(f"Release version validated: {version}")
        elif args.command == "version-info":
            project_root = args.project_root.resolve()
            if args.check:
                if not version_info_is_current(project_root):
                    print("version_info.txt is stale", file=sys.stderr)
                    return 1
                print("version_info.txt matches config.py")
            else:
                (project_root / "version_info.txt").write_text(
                    render_version_info(project_root), encoding="utf-8", newline="\n"
                )
                print("version_info.txt written")
        else:
            manifest = generate_manifest(
                version=args.version,
                executable=args.exe.resolve(),
                output=args.output.resolve(),
                minimum_updater_version=args.minimum_updater_version,
                naming=args.naming,
            )
            print(
                f"Manifest generated: {args.output.name} "
                f"({manifest.asset_size} bytes, sha256={manifest.asset_sha256})"
            )
    except (OSError, ValueError, UpdateValidationError) as exc:
        print(f"Release validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
