"""Reconstruct the ignored, hash-pinned offline build inputs in a clean checkout.

``build_inputs/`` payloads (the pinned CPython/FFmpeg/Node archives and the
locked wheelhouse) are intentionally not committed, but ``SOURCE-HASHES.sha256``
covers them, so a clean CI checkout cannot satisfy the packaging-contract tests
until they are materialized again.

Why this is a separate command from ``scripts/prepare_offline_inputs.py``:
that script is the maintainer's *preparation* tool and rewrites
``build_inputs/PREPARATION-MANIFEST.json`` on every run, recording a per-file
``disposition`` ("reused" or "downloaded") that depends on what already existed
on the machine. The manifest is itself committed and hash-covered, so
regenerating it in CI would change tracked bytes and newly break the very
source-hash check we are trying to satisfy. This command therefore treats the
committed manifest as an immutable pin list: it only ever reads it.

Every file is verified against the SHA-256 recorded in the manifest, cross-checked
against ``BUILD-INPUTS.lock`` where that lock also pins the path, and finally
re-verified against every ``build_inputs/`` record in ``SOURCE-HASHES.sha256``.

Nothing here is ever committed, uploaded, or published; the inputs exist only so
the offline build and the full test suite can run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

BUILD_INPUTS_ROOT = "build_inputs"
PREPARATION_MANIFEST = "build_inputs/PREPARATION-MANIFEST.json"
SOURCE_HASH_MANIFEST = "SOURCE-HASHES.sha256"
BUILD_INPUTS_LOCK = "BUILD-INPUTS.lock"
WHEELHOUSE = "build_inputs/wheels/cp312-win_amd64"
WHEEL_MIRROR = "build_inputs/wheels"
USER_AGENT = "OpenFetch-build-inputs/1"
_SOURCE_HASH_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
ALLOWED_SUFFIXES = frozenset({".whl", ".zip", ".gz", ".json"})
# Runtime state that must never appear beside pinned build inputs.
FORBIDDEN_NAME_TOKENS = (
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "browser-profile",
    "browser_profile",
    "login",
    ".pem",
    ".key",
    "id_rsa",
)


class RestoreError(RuntimeError):
    """Raised when a pinned build input cannot be restored or verified."""


@dataclass(frozen=True)
class PinnedInput:
    path: str
    url: str
    sha256: str
    size: int
    component: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value: str) -> PurePosixPath:
    normalized = value.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise RestoreError(f"unsafe manifest path: {value!r}")
    return candidate


def read_pinned_inputs(project_root: Path) -> list[PinnedInput]:
    manifest_path = project_root / PREPARATION_MANIFEST
    if not manifest_path.is_file():
        raise RestoreError(f"pinned preparation manifest is missing: {manifest_path}")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = payload.get("files")
    if not isinstance(rows, list) or not rows:
        raise RestoreError("preparation manifest has no file records")
    pinned: list[PinnedInput] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RestoreError("preparation manifest has an invalid file record")
        relative = str(row.get("path", ""))
        if not relative.startswith(f"{BUILD_INPUTS_ROOT}/"):
            continue  # Corresponding-source payloads are tracked, not restored here.
        candidate = safe_relative(relative)
        digest = str(row.get("sha256", ""))
        url = str(row.get("url", ""))
        size = row.get("size")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RestoreError(f"invalid pinned sha256 for {relative}")
        if not url.startswith("https://"):
            raise RestoreError(f"pinned input has a non-HTTPS source URL: {relative}")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise RestoreError(f"invalid pinned size for {relative}")
        if candidate.as_posix() in seen:
            raise RestoreError(f"duplicate pinned input: {relative}")
        seen.add(candidate.as_posix())
        pinned.append(
            PinnedInput(
                path=candidate.as_posix(),
                url=url,
                sha256=digest,
                size=size,
                component=str(row.get("component", "")),
            )
        )
    if not pinned:
        raise RestoreError("preparation manifest pins no build_inputs payloads")
    return pinned


def read_lock_hashes(project_root: Path) -> dict[str, str]:
    lock_path = project_root / BUILD_INPUTS_LOCK
    if not lock_path.is_file():
        return {}
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    hashes: dict[str, str] = {}
    for row in payload.get("inputs", []):
        if not isinstance(row, dict):
            continue
        relative = str(row.get("path", "")).replace("\\", "/")
        digest = str(row.get("sha256", ""))
        if relative.startswith(f"{BUILD_INPUTS_ROOT}/") and re.fullmatch(
            r"[0-9a-f]{64}", digest
        ):
            hashes[relative] = digest
    return hashes


def read_source_hash_targets(project_root: Path) -> dict[str, str]:
    manifest_path = project_root / SOURCE_HASH_MANIFEST
    if not manifest_path.is_file():
        raise RestoreError(f"source hash manifest is missing: {manifest_path}")
    targets: dict[str, str] = {}
    for number, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        match = _SOURCE_HASH_LINE.fullmatch(line)
        if match is None:
            raise RestoreError(f"invalid source-hash line {number}: {line!r}")
        relative = match.group(2)
        if relative.startswith(f"{BUILD_INPUTS_ROOT}/"):
            targets[safe_relative(relative).as_posix()] = match.group(1)
    if not targets:
        raise RestoreError("source hash manifest covers no build_inputs payloads")
    return targets


def locate_reusable(name: str, reuse_dirs: list[Path], expected: str) -> Path | None:
    """Return an already-downloaded, hash-matching copy of *name*, if any."""
    for directory in reuse_dirs:
        if not directory.is_dir():
            continue
        candidate = directory / name
        if candidate.is_file() and sha256_file(candidate) == expected:
            return candidate
    return None


def download_verified(item: PinnedInput, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.download")
    temporary.unlink(missing_ok=True)
    request = urllib.request.Request(item.url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=180) as response:  # noqa: S310 - pinned HTTPS URL
        with temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
    actual = sha256_file(temporary)
    if actual != item.sha256:
        temporary.unlink(missing_ok=True)
        raise RestoreError(
            f"downloaded hash mismatch for {item.path}: {actual} != {item.sha256}"
        )
    temporary.replace(destination)


def restore_input(
    item: PinnedInput,
    project_root: Path,
    reuse_dirs: list[Path],
    *,
    verify_only: bool,
) -> str:
    destination = project_root / Path(item.path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        actual = sha256_file(destination)
        if actual == item.sha256:
            return "present"
        if verify_only:
            raise RestoreError(
                f"existing input hash mismatch for {item.path}: {actual} != {item.sha256}"
            )
        destination.unlink()
    if verify_only:
        raise RestoreError(f"pinned input is missing: {item.path}")

    reusable = locate_reusable(destination.name, reuse_dirs, item.sha256)
    if reusable is not None:
        shutil.copy2(reusable, destination)
        if sha256_file(destination) != item.sha256:
            raise RestoreError(f"reused copy failed verification: {item.path}")
        return "reused"

    download_verified(item, destination)
    return "downloaded"


def mirror_wheelhouse(
    project_root: Path, targets: dict[str, str], *, verify_only: bool
) -> list[str]:
    """Materialize the flat wheel mirror that the source manifest also covers."""
    mirrored: list[str] = []
    for relative, expected in sorted(targets.items()):
        parent = PurePosixPath(relative).parent.as_posix()
        if parent != WHEEL_MIRROR or not relative.endswith(".whl"):
            continue
        destination = project_root / Path(relative)
        if destination.is_file() and sha256_file(destination) == expected:
            continue
        if verify_only:
            raise RestoreError(f"mirrored wheel is missing or differs: {relative}")
        source = project_root / WHEELHOUSE / destination.name
        if not source.is_file():
            raise RestoreError(f"cannot mirror {relative}: {source} is absent")
        if sha256_file(source) != expected:
            raise RestoreError(
                f"wheelhouse copy does not match the pinned mirror hash: {relative}"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if sha256_file(destination) != expected:
            raise RestoreError(f"mirrored wheel failed verification: {relative}")
        mirrored.append(relative)
    return mirrored


def assert_no_runtime_state(project_root: Path) -> None:
    root = project_root / BUILD_INPUTS_ROOT
    offenders: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(project_root).as_posix()
        lowered = path.name.casefold()
        if any(token in lowered for token in FORBIDDEN_NAME_TOKENS):
            offenders.append(f"{relative} (runtime state or credential material)")
            continue
        if path.suffix.casefold() not in ALLOWED_SUFFIXES:
            offenders.append(f"{relative} (unexpected payload type)")
    if offenders:
        raise RestoreError(
            "build_inputs must contain only pinned archives, wheels and the "
            "preparation manifest; found: " + ", ".join(offenders)
        )


def verify_targets(project_root: Path, targets: dict[str, str]) -> None:
    missing: list[str] = []
    mismatched: list[str] = []
    for relative, expected in sorted(targets.items()):
        path = project_root / Path(relative)
        if not path.is_file():
            missing.append(relative)
        elif sha256_file(path) != expected:
            mismatched.append(relative)
    if missing or mismatched:
        detail = []
        if missing:
            detail.append(f"missing={missing[:5]} (total {len(missing)})")
        if mismatched:
            detail.append(f"mismatched={mismatched[:5]} (total {len(mismatched)})")
        raise RestoreError("source-hash targets unsatisfied: " + "; ".join(detail))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--reuse-dir",
        type=Path,
        action="append",
        default=[],
        help=(
            "directory holding an already downloaded and verified archive; a copy "
            "is used only when its SHA-256 matches the pinned value"
        ),
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify existing inputs without downloading or copying anything",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = args.project_root.resolve()
    reuse_dirs = [directory.resolve() for directory in args.reuse_dir]
    try:
        pinned = read_pinned_inputs(project_root)
        lock_hashes = read_lock_hashes(project_root)
        for item in pinned:
            locked = lock_hashes.get(item.path)
            if locked is not None and locked != item.sha256:
                raise RestoreError(
                    f"BUILD-INPUTS.lock and the preparation manifest disagree on "
                    f"{item.path}: {locked} != {item.sha256}"
                )
        targets = read_source_hash_targets(project_root)

        counts = {"present": 0, "reused": 0, "downloaded": 0}
        for item in pinned:
            outcome = restore_input(
                item, project_root, reuse_dirs, verify_only=args.verify_only
            )
            counts[outcome] += 1
            if outcome != "present":
                print(f"{outcome}: {item.path}")
        mirrored = mirror_wheelhouse(project_root, targets, verify_only=args.verify_only)

        assert_no_runtime_state(project_root)
        verify_targets(project_root, targets)
    except (RestoreError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 1

    print(
        f"Pinned build inputs verified: {len(pinned)} manifest payloads "
        f"({counts['present']} already present, {counts['reused']} reused, "
        f"{counts['downloaded']} downloaded), {len(mirrored)} wheels mirrored, "
        f"{len(targets)} source-hash targets satisfied."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
