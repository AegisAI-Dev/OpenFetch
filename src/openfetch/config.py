"""Configuration constants for OpenFetch."""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "OpenFetch"
APP_PUBLISHER = "Brainbyte"
APP_DESCRIPTION = "Open-source media downloader & toolkit"
APP_USER_MODEL_ID = "Brainbyte.OpenFetch"
EXECUTABLE_STEM = "OpenFetch"
VERSION = "3.1.0"
BUILD_LABEL = "openfetch-brainbyte-migration"
WINDOW_TITLE = f"{APP_NAME} {VERSION}"

SETTINGS_ORGANIZATION = APP_PUBLISHER
SETTINGS_APPLICATION = APP_NAME
APP_DATA_DIRECTORY = APP_NAME

# OpenFetch 3.1.0 is the renamed Neural Extractor V3. The legacy identifiers are
# used only to migrate an upgraded installation's data and settings and to
# accept the update handoff performed by an installed Neural Extractor updater.
LEGACY_APP_NAME = "Neural Extractor V3"
LEGACY_EXECUTABLE_STEM = "NeuralExtractorV3"
LEGACY_APP_DATA_DIRECTORY = "NeuralExtractorV3"
LEGACY_SETTINGS_ORGANIZATION = "Neuralshield"
LEGACY_SETTINGS_APPLICATION = "NeuralExtractorV3"

ENVIRONMENT_PREFIX = "OPENFETCH_"
LEGACY_ENVIRONMENT_PREFIX = "NEURAL_EXTRACTOR_"


def environment_value(name: str) -> str | None:
    """Read ``OPENFETCH_<name>``, falling back to ``NEURAL_EXTRACTOR_<name>``."""
    value = os.environ.get(ENVIRONMENT_PREFIX + name)
    if value is None:
        value = os.environ.get(LEGACY_ENVIRONMENT_PREFIX + name)
    return value


def _env_seconds(name: str, default: int, minimum: int) -> int:
    try:
        value = int(environment_value(name) or str(default))
    except ValueError:
        return default
    return max(minimum, value)

# Canonical OpenFetch release feed. Installed OpenFetch builds trust exactly
# this repository, refuse redirects, and require exact release-asset URLs from
# it, so it must never name a namespace the project does not own.
GITHUB_REPO = "AegisAI-Dev/OpenFetch"
# Migration bridge for installed Neural Extractor V3 updaters (3.0.4-3.0.8).
# Those builds are pinned to the pre-rename slug and cannot follow GitHub's
# rename redirect, so a repository keeping that exact name carries one
# legacy-named release that delivers OpenFetch. OpenFetch itself never reads
# this repository; the constant exists for release tooling, tests and
# documentation. Both repositories are owned by AegisAI-Dev.
# See docs/OPENFETCH-MIGRATION.md.
LEGACY_BRIDGE_REPO = "AegisAI-Dev/NeuralExtractor"
LEGACY_BRIDGE_RELEASES_URL = f"https://github.com/{LEGACY_BRIDGE_REPO}/releases"
GITHUB_RELEASES_URL = f"https://github.com/{GITHUB_REPO}/releases"
GITHUB_LATEST_RELEASE_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
UPDATE_CHECK_TIMEOUT_SECONDS = 8

QUALITY_PRESETS: dict[str, int | None] = {
    "Best available": None,
    "2160p 4K": 2160,
    "1440p QHD": 1440,
    "1080p Full HD": 1080,
    "720p HD": 720,
    "480p": 480,
    "360p": 360,
}

YTDLP_SOCKET_TIMEOUT_SECONDS = 30
YTDLP_INACTIVITY_TIMEOUT_SECONDS = _env_seconds("YTDLP_INACTIVITY_TIMEOUT_SECONDS", 300, 30)
YTDLP_ATTEMPT_TOTAL_TIMEOUT_SECONDS = _env_seconds(
    "YTDLP_ATTEMPT_TOTAL_TIMEOUT_SECONDS", 21_600, 300
)
YTDLP_STATUS_HEARTBEAT_SECONDS = _env_seconds("YTDLP_STATUS_HEARTBEAT_SECONDS", 15, 5)
YTDLP_TERMINATION_GRACE_SECONDS = _env_seconds("YTDLP_TERMINATION_GRACE_SECONDS", 3, 1)

YOUTUBE_EJS_REMOTE_COMPONENT = "ejs:github"
YOUTUBE_REMOTE_COMPONENTS = [YOUTUBE_EJS_REMOTE_COMPONENT]

AUDIO_BITRATES = ["320", "256", "192", "128"]

SUBTITLE_LANGUAGES: dict[str, str] = {
    "nl": "Dutch",
    "en": "English",
    "de": "German",
    "fr": "French",
    "es": "Spanish",
    "it": "Italian",
    "pt": "Portuguese",
    "tr": "Turkish",
    "ar": "Arabic",
    "ja": "Japanese",
    "ko": "Korean",
    "zh-Hans": "Chinese Simplified",
}

YOUTUBE_HOSTS = {
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "youtu.be",
}

THROTTLE_SAFE_OPTIONS = {
    "socket_timeout": YTDLP_SOCKET_TIMEOUT_SECONDS,
    "sleep_interval": 1,
    "max_sleep_interval": 5,
    "sleep_interval_requests": 1,
    "sleep_interval_subtitles": 2,
    "retries": 5,
    "fragment_retries": 10,
    "extractor_retries": 5,
    "throttled_rate": 100_000,
}


def base_dir() -> Path:
    """Return project root in development or the bundle temp dir in PyInstaller."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[2]


def assets_dir() -> Path:
    return base_dir() / "assets"


def bin_dir() -> Path:
    return base_dir() / "bin"


def _local_data_root() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return Path.home() / ".local" / "share"


def app_data_dir() -> Path:
    data_dir = _local_data_root() / APP_DATA_DIRECTORY
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def legacy_app_data_dir() -> Path:
    """Return the OpenFetch data directory without creating it."""
    return _local_data_root() / LEGACY_APP_DATA_DIRECTORY
