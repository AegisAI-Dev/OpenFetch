"""Prepare hash-pinned local source and wheel inputs without using Git.

This command is deliberately separate from the build.  Network access is allowed only
during this preparation phase.  The offline build consumes the resulting files with
``--no-index`` and verifies every recorded SHA-256 before use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tomllib
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.tags import Tag, compatible_tags, cpython_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

try:
    from scripts.project_identity import (
        APPLICATION_VERSION,
    )
except ModuleNotFoundError:  # executed directly as scripts/prepare_offline_inputs.py
    from project_identity import (  # type: ignore[no-redef]
        APPLICATION_VERSION,
    )


@dataclass(frozen=True)
class Download:
    component: str
    version: str
    url: str
    sha256: str
    destination: Path
    kind: str


STATIC_DOWNLOADS = (
    {
        "component": "python-build-standalone-runtime",
        "version": "CPython 3.12.9 / PBS 20250317",
        "url": (
            "https://github.com/astral-sh/python-build-standalone/releases/download/"
            "20250317/cpython-3.12.9%2B20250317-x86_64-pc-windows-msvc-"
            "install_only_stripped.tar.gz"
        ),
        "sha256": "ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661",
        "destination": (
            "build_inputs/runtime-archives/"
            "cpython-3.12.9+20250317-x86_64-pc-windows-msvc-"
            "install_only_stripped.tar.gz"
        ),
        "kind": "build-runtime",
    },
    {
        "component": "ffmpeg-btbn-binary-archive",
        "version": "N-125365-g9a01c1cb6a / 2026-06-30",
        "url": (
            "https://github.com/BtbN/FFmpeg-Builds/releases/download/"
            "autobuild-2026-06-30-13-34/ffmpeg-N-125365-g9a01c1cb6a-win64-gpl.zip"
        ),
        "sha256": "52c0383c460f0ec1039088f1591921fb82e3b870b32aab8faf2ff1e5ae14bf9d",
        "destination": (
            "build_inputs/runtime-archives/ffmpeg-N-125365-g9a01c1cb6a-win64-gpl.zip"
        ),
        "kind": "build-runtime",
    },
    {
        "component": "node-source",
        "version": "22.17.0",
        "url": "https://nodejs.org/download/release/v22.17.0/node-v22.17.0.tar.gz",
        "sha256": "f8bf095ff559033edf04108fb1f14f72e2be337c609d4f83e8af1e299af7f4b4",
        "destination": "third_party_sources/node/archives/node-v22.17.0.tar.gz",
        "kind": "corresponding-source",
    },
)

NODE_SHASUMS_URL = "https://nodejs.org/download/release/v22.17.0/SHASUMS256.txt"
NODE_BINARY_NAME = "node-v22.17.0-win-x64.zip"
NODE_BINARY_URL = f"https://nodejs.org/download/release/v22.17.0/{NODE_BINARY_NAME}"
TARGET_PYTHON = (3, 12)
TARGET_INTERPRETER = "cp312"
TARGET_ABI = "cp312"
TARGET_PLATFORM = "win_amd64"
TARGET_WHEELHOUSE = Path("build_inputs/wheels/cp312-win_amd64")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_verified(item: Download) -> dict[str, Any]:
    item.destination.parent.mkdir(parents=True, exist_ok=True)
    if item.destination.is_file():
        actual = sha256_file(item.destination)
        if actual == item.sha256:
            return manifest_row(item, actual, "reused")
        raise RuntimeError(
            f"Existing input hash mismatch for {item.destination}: {actual} != {item.sha256}"
        )

    temporary = item.destination.with_name(f".{item.destination.name}.download")
    if temporary.exists():
        temporary.unlink()
    request = urllib.request.Request(item.url, headers={"User-Agent": f"OpenFetch-build-inputs/{APPLICATION_VERSION}"})
    with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    actual = sha256_file(temporary)
    if actual != item.sha256:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(
            f"Downloaded input hash mismatch for {item.component}: {actual} != {item.sha256}"
        )
    os.replace(temporary, item.destination)
    return manifest_row(item, actual, "downloaded")


def manifest_row(item: Download, actual: str, disposition: str) -> dict[str, Any]:
    return {
        "component": item.component,
        "version": item.version,
        "kind": item.kind,
        "path": item.destination.as_posix(),
        "url": item.url,
        "sha256": actual,
        "size": item.destination.stat().st_size,
        "disposition": disposition,
    }


def expected_hash(value: str) -> str:
    algorithm, separator, digest = value.partition(":")
    if separator != ":" or algorithm.lower() != "sha256" or len(digest) != 64:
        raise ValueError(f"Unsupported locked hash: {value!r}")
    return digest.lower()


def target_wheel_tags() -> list[Tag]:
    """Return deterministic tags for the pinned PBS CPython, never the host Python."""

    ordered = list(
        cpython_tags(
            python_version=TARGET_PYTHON,
            abis=[TARGET_ABI],
            platforms=[TARGET_PLATFORM],
        )
    )
    seen = set(ordered)
    for tag in compatible_tags(
        python_version=TARGET_PYTHON,
        interpreter=TARGET_INTERPRETER,
        platforms=[TARGET_PLATFORM],
    ):
        if tag not in seen:
            seen.add(tag)
            ordered.append(tag)
    return ordered


def locked_python_downloads(project_root: Path) -> list[Download]:
    lock = tomllib.loads((project_root / "uv.lock").read_text(encoding="utf-8"))
    source_root = project_root / "third_party_sources" / "python-packages" / "sdists"
    wheel_root = project_root / TARGET_WHEELHOUSE
    supported = {tag: index for index, tag in enumerate(target_wheel_tags())}
    downloads: list[Download] = []

    for package in lock["package"]:
        name = str(package["name"])
        package_source = package.get("source", {})
        if isinstance(package_source, dict) and "editable" in package_source:
            # The project's own entry has a dynamic version and no locked artifact.
            continue
        version = str(package["version"])
        canonical = canonicalize_name(name)
        source = package.get("sdist")
        if source:
            url = str(source["url"])
            downloads.append(
                Download(
                    component=canonical,
                    version=version,
                    url=url,
                    sha256=expected_hash(str(source["hash"])),
                    destination=source_root / url.rsplit("/", 1)[-1],
                    kind="python-source-distribution",
                )
            )

        candidates: list[tuple[int, dict[str, Any]]] = []
        for wheel in package.get("wheels", []):
            filename = str(wheel["url"]).rsplit("/", 1)[-1]
            try:
                parsed_name, parsed_version, _build, tags = parse_wheel_filename(filename)
            except ValueError:
                continue
            if canonicalize_name(parsed_name) != canonical or str(parsed_version) != version:
                continue
            ranks = [supported[tag] for tag in tags if tag in supported]
            if ranks:
                candidates.append((min(ranks), wheel))
        if candidates:
            wheel = min(candidates, key=lambda candidate: candidate[0])[1]
            url = str(wheel["url"])
            downloads.append(
                Download(
                    component=canonical,
                    version=version,
                    url=url,
                    sha256=expected_hash(str(wheel["hash"])),
                    destination=wheel_root / url.rsplit("/", 1)[-1],
                    kind="python-build-wheel",
                )
            )
    return downloads


def node_downloads(project_root: Path) -> tuple[list[Download], dict[str, Any]]:
    request = urllib.request.Request(
        NODE_SHASUMS_URL, headers={"User-Agent": f"OpenFetch-build-inputs/{APPLICATION_VERSION}"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        shasums_bytes = response.read()
    shasums_text = shasums_bytes.decode("utf-8")
    expected = ""
    for line in shasums_text.splitlines():
        digest, separator, filename = line.partition("  ")
        if separator and filename.strip() == NODE_BINARY_NAME:
            expected = digest.lower()
            break
    if len(expected) != 64:
        raise RuntimeError(f"{NODE_BINARY_NAME} is absent from official Node SHASUMS256.txt")

    sums_path = project_root / "third_party_sources" / "node" / "SHASUMS256.txt"
    sums_path.parent.mkdir(parents=True, exist_ok=True)
    if sums_path.exists() and sums_path.read_bytes() != shasums_bytes:
        raise RuntimeError("Stored Node SHASUMS256.txt differs from the current official response")
    if not sums_path.exists():
        sums_path.write_bytes(shasums_bytes)
    return (
        [
            Download(
                component="node-binary-archive",
                version="22.17.0",
                url=NODE_BINARY_URL,
                sha256=expected,
                destination=(
                    project_root / "build_inputs" / "runtime-archives" / NODE_BINARY_NAME
                ),
                kind="build-runtime",
            )
        ],
        {
            "url": NODE_SHASUMS_URL,
            "path": sums_path.relative_to(project_root).as_posix(),
            "sha256": sha256_file(sums_path),
            "size": sums_path.stat().st_size,
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-python", action="store_true")
    parser.add_argument("--skip-static", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = args.project_root.resolve()
    downloads: list[Download] = []
    if not args.skip_python:
        downloads.extend(locked_python_downloads(project_root))
    if not args.skip_static:
        downloads.extend(
            Download(
                component=item["component"],
                version=item["version"],
                url=item["url"],
                sha256=item["sha256"],
                destination=project_root / item["destination"],
                kind=item["kind"],
            )
            for item in STATIC_DOWNLOADS
        )
        node_items, shasums = node_downloads(project_root)
        downloads.extend(node_items)
    else:
        shasums = None

    rows = [download_verified(item) for item in downloads]
    for row in rows:
        absolute = Path(str(row["path"])).resolve()
        if not absolute.is_relative_to(project_root):
            raise RuntimeError(f"Prepared input escaped project root: {absolute}")
        row["path"] = absolute.relative_to(project_root).as_posix()
    manifest = {
        "schema_version": 1,
        "application_version": APPLICATION_VERSION,
        "network_phase": "preparation-only",
        "public_distribution_verdict": "HOLD",
        "wheel_target": {
            "python": ".".join(str(part) for part in TARGET_PYTHON),
            "interpreter": TARGET_INTERPRETER,
            "abi": TARGET_ABI,
            "platform": TARGET_PLATFORM,
            "directory": TARGET_WHEELHOUSE.as_posix(),
        },
        "node_shasums": shasums,
        "files": sorted(rows, key=lambda row: row["path"].casefold()),
    }
    manifest_path = project_root / "build_inputs" / "PREPARATION-MANIFEST.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Prepared {len(rows)} verified local inputs: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
