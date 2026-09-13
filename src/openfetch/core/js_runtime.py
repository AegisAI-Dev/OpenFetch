"""JavaScript runtime discovery for YouTube challenge solving."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from openfetch.config import bin_dir, environment_value

MISSING_JS_RUNTIME_MESSAGE = (
    "YouTube challenge solver unavailable. Install Node.js or use the bundled runtime."
)
MISSING_CHALLENGE_SOLVER_COMPONENT_MESSAGE = (
    "YouTube challenge solver component unavailable. Check internet/firewall or retry later."
)


@dataclass(frozen=True, slots=True)
class JavaScriptRuntimeStatus:
    found: bool
    name: str = ""
    path: Path | None = None
    version: str = ""

    @property
    def diagnostic(self) -> str:
        state = "found" if self.found else "not found"
        if self.found and self.name and self.path:
            return (
                f"JavaScript runtime for YouTube challenge: "
                f"{state} ({self.name} {self.version} at {self.path})"
            )
        return f"JavaScript runtime for YouTube challenge: {state}"

    def ytdlp_options(self) -> dict[str, dict[str, str]]:
        if not self.found or not self.path:
            return {}
        return {self.name: {"path": str(self.path)}}


def ensure_youtube_js_runtime() -> JavaScriptRuntimeStatus:
    """Resolve a runtime and prepend its folder to PATH for yt-dlp subprocesses."""
    status = resolve_youtube_js_runtime()
    if status.found and status.path:
        _prepend_to_path(status.path.parent)
    return status


def resolve_youtube_js_runtime() -> JavaScriptRuntimeStatus:
    """Find a Node.js runtime usable by yt-dlp for YouTube n-challenge solving."""
    for candidate in _node_candidates():
        path = _resolve_executable(candidate)
        if not path:
            continue
        version = _node_version(path)
        if version:
            return JavaScriptRuntimeStatus(True, "node", path, version)
    return JavaScriptRuntimeStatus(False)


def is_youtube_challenge_runtime_error(error_text: str) -> bool:
    """Return True only when yt-dlp explicitly attributes failure to no JS runtime."""
    lowered = error_text.lower()
    patterns = (
        "no supported javascript runtime could be found",
        "no javascript runtime could be found",
        "javascript runtime is unavailable",
        "youtube extraction without a js runtime",
    )
    return any(pattern in lowered for pattern in patterns)


def clean_youtube_challenge_runtime_error() -> str:
    return MISSING_JS_RUNTIME_MESSAGE


def is_youtube_challenge_component_error(error_text: str) -> bool:
    """Return True when the EJS solver component cannot be loaded or fetched."""
    lowered = error_text.lower()
    patterns = (
        "no usable challenge solver",
        "remote component challenge solver script was skipped",
        "remote components challenge solver script",
        "failed to download challenge solver",
        "failed to read builtin challenge solver",
        "failed to load challenge solver",
        "challenge solver lib script",
        "challenge solver core script",
        "challenge solver script distribution installed",
    )
    return any(pattern in lowered for pattern in patterns)


def clean_youtube_challenge_component_error() -> str:
    return MISSING_CHALLENGE_SOLVER_COMPONENT_MESSAGE


def _node_candidates() -> list[Path | str]:
    candidates: list[Path | str] = []
    env_node = environment_value("NODE")
    if env_node:
        candidates.append(Path(env_node).expanduser())

    executable = "node.exe" if sys.platform == "win32" else "node"
    candidates.append(bin_dir() / executable)

    path_node = shutil.which("node")
    if path_node:
        candidates.append(Path(path_node))

    if sys.platform == "win32":
        for env_name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            root = os.environ.get(env_name)
            if root:
                candidates.append(Path(root) / "nodejs" / "node.exe")
        candidates.append(Path.home() / "AppData" / "Local" / "Programs" / "nodejs" / "node.exe")
    else:
        candidates.extend(
            [
                "/usr/local/bin/node",
                "/usr/bin/node",
                Path.home() / ".local" / "bin" / "node",
            ]
        )

    return candidates


def _resolve_executable(candidate: Path | str) -> Path | None:
    path = Path(candidate).expanduser()
    if path.exists() and path.is_file():
        return path.resolve()

    found = shutil.which(str(candidate))
    if found:
        return Path(found).resolve()
    return None


def _node_version(path: Path) -> str:
    try:
        completed = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    if completed.returncode:
        return ""
    output = (completed.stdout or completed.stderr).strip()
    return output if output.startswith("v") else output


def _prepend_to_path(directory: Path) -> None:
    current_paths = os.environ.get("PATH", "").split(os.pathsep)
    resolved = str(directory.resolve())
    if any(Path(entry).expanduser().resolve() == directory.resolve() for entry in current_paths if entry):
        return
    os.environ["PATH"] = os.pathsep.join([resolved, *current_paths])
