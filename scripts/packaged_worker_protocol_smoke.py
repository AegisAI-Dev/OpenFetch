"""Exercise the packaged worker protocol offline under a CP1252 environment."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from openfetch.core.ytdlp_worker import PROTOCOL_PREFIX, PROTOCOL_SMOKE_TITLE


def _parse_frames(output: bytes) -> list[dict[str, object]]:
    text = output.decode("utf-8")
    lines = text.splitlines()
    if not lines:
        raise RuntimeError("Packaged worker emitted no protocol frames")
    if any(not line.startswith(PROTOCOL_PREFIX) for line in lines):
        raise RuntimeError(f"Packaged worker emitted unframed stdout: {text!r}")
    return [json.loads(line.removeprefix(PROTOCOL_PREFIX)) for line in lines]


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

    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "0"
    environment["PYTHONIOENCODING"] = "cp1252"
    completed = subprocess.run(
        [str(executable), "--internal-ytdlp-worker"],
        input=json.dumps({"mode": "protocol_smoke"}).encode("utf-8"),
        capture_output=True,
        env=environment,
        shell=False,
        check=False,
        close_fds=True,
        timeout=60,
    )
    if completed.returncode:
        stderr = completed.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Packaged worker exited {completed.returncode} under CP1252: {stderr}"
        )
    if b"UnicodeEncodeError" in completed.stderr:
        raise RuntimeError("Packaged worker reproduced the UnicodeEncodeError")
    if completed.stderr:
        raise RuntimeError(
            "Packaged worker emitted unexpected stderr: "
            + completed.stderr.decode("utf-8", errors="replace")
        )

    frames = _parse_frames(completed.stdout)
    if len(frames) != 2 or [frame.get("sequence") for frame in frames] != [0, 1]:
        raise RuntimeError(f"Packaged worker framing failed: {frames!r}")
    for frame in frames:
        checks = {
            "u_ff5c": "｜" in str(frame.get("title") or ""),
            "exact_title": frame.get("title") == PROTOCOL_SMOKE_TITLE,
            "subtitle": str(frame.get("subtitle_destination") or "").endswith("夜の名曲.srt"),
            "emoji": "❤️" in str(frame.get("emoji") or ""),
            "cjk": frame.get("cjk") == "日本語 中文 한국어",
            "cyrillic": frame.get("cyrillic") == "Русская музыка",
            "arabic": frame.get("arabic") == "الموسيقى العربية",
            "combining": frame.get("combining") == "Cafe\u0301",
            "long_windows_path": len(str(frame.get("long_windows_path") or "")) > 260,
        }
        if not all(checks.values()):
            raise RuntimeError(f"Packaged worker Unicode checks failed: {checks}")

    malformed = subprocess.run(
        [str(executable), "--internal-ytdlp-worker"],
        input=b"{not-json",
        capture_output=True,
        env=environment,
        shell=False,
        check=False,
        close_fds=True,
        timeout=60,
    )
    if malformed.returncode != 2 or malformed.stderr:
        raise RuntimeError(
            "Packaged malformed-request handling failed: "
            f"exit={malformed.returncode}, stderr={malformed.stderr!r}"
        )
    malformed_frames = _parse_frames(malformed.stdout)
    if len(malformed_frames) != 1 or malformed_frames[0].get("kind") != "error":
        raise RuntimeError(f"Packaged malformed-request frame failed: {malformed_frames!r}")

    print(
        json.dumps(
            {
                "passed": True,
                "parent_encoding": "cp1252",
                "frames": len(frames),
                "u_ff5c": "pass",
                "emoji_cjk": "pass",
                "unicode_output_path": "pass",
                "malformed_request": "pass",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
