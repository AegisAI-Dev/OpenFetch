"""Run offline guided-auth and GUI startup smokes against the packaged EXE."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from openfetch.config import EXECUTABLE_STEM, VERSION


def _run(executable: Path, argument: str, result: Path, timeout: int = 30) -> dict:
    completed = subprocess.run(
        [str(executable), argument, str(result)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        check=False,
        close_fds=True,
        timeout=timeout,
        text=True,
    )
    if completed.returncode:
        raise RuntimeError(
            f"Packaged smoke {argument} exited {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    payload = json.loads(result.read_text(encoding="utf-8"))
    if not payload.get("passed"):
        raise RuntimeError(f"Packaged smoke {argument} failed: {payload}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "executable",
        nargs="?",
        type=Path,
        default=Path("dist/OpenFetch.exe"),
    )
    args = parser.parse_args()
    executable = args.executable.resolve()
    if not executable.is_file():
        raise SystemExit(f"Packaged executable not found: {executable}")

    with tempfile.TemporaryDirectory(prefix="openfetch-packaged-smoke-") as temporary:
        root = Path(temporary)
        connection = _run(
            executable,
            "--internal-youtube-connection-smoke",
            root / "connection.json",
        )
        provider_media = _run(
            executable,
            "--internal-provider-media-smoke",
            root / "provider-media.json",
            timeout=60,
        )
        gui = _run(
            executable,
            "--internal-gui-startup-smoke",
            root / "gui.json",
        )
    version = subprocess.run(
        [str(executable), "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        check=False,
        close_fds=True,
        timeout=30,
        text=True,
    )
    expected_version = f"{EXECUTABLE_STEM} {VERSION}"
    if version.returncode or version.stdout.strip() != expected_version:
        raise RuntimeError(
            f"Packaged version smoke failed: exit={version.returncode}; "
            f"stdout={version.stdout!r}; stderr={version.stderr!r}"
        )
    print(
        json.dumps(
            {
                "connection": connection,
                "provider_media": provider_media,
                "gui": gui,
                "version": expected_version,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
