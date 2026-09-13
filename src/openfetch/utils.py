"""Utility helpers for URLs, filenames, and progress formatting."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

from openfetch.config import YOUTUBE_HOSTS

INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(value: str, max_length: int = 180) -> str:
    cleaned = INVALID_FILENAME_CHARS.sub("_", value or "")
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .")
    if not cleaned:
        cleaned = "download"
    return cleaned[:max_length].rstrip(" .")


def normalize_user_url(url: str) -> str:
    stripped = (url or "").strip()
    if stripped and not re.match(r"^https?://", stripped, flags=re.IGNORECASE):
        if stripped.startswith(("youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be")):
            return f"https://{stripped}"
    return stripped


def split_urls(text: str) -> list[str]:
    if not text:
        return []
    candidates = re.split(r"[\r\n\t,]+", text)
    urls: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        url = normalize_user_url(candidate)
        if not url or url in seen:
            continue
        urls.append(url)
        seen.add(url)
    return urls


def is_youtube_url(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(normalize_user_url(url))
    except ValueError:
        return False
    host = parsed.netloc.lower()
    if not host and parsed.path.startswith("www.youtube.com"):
        return True
    return host in YOUTUBE_HOSTS and bool(parsed.scheme in {"http", "https"})


def extract_video_id(url: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(normalize_user_url(url))
    host = parsed.netloc.lower()
    if host == "youtu.be":
        video_id = parsed.path.strip("/").split("/")[0]
        return video_id or None
    if parsed.path.startswith("/shorts/"):
        parts = parsed.path.strip("/").split("/")
        return parts[1] if len(parts) > 1 else None
    return parse_qs(parsed.query).get("v", [None])[0]


def has_playlist_marker(url: str) -> bool:
    parsed = urlparse(normalize_user_url(url))
    query = parse_qs(parsed.query)
    list_id = query.get("list", [None])[0]
    return bool(list_id or parsed.path.startswith("/playlist"))


def is_youtube_mix_url(url: str) -> bool:
    parsed = urlparse(normalize_user_url(url))
    query = parse_qs(parsed.query)
    list_id = query.get("list", [""])[0] or ""
    return list_id.upper().startswith("RD") or query.get("start_radio", [""])[0] == "1"


def should_download_playlist(url: str, playlist_mode: str) -> bool:
    if playlist_mode == "single":
        return False
    if is_youtube_mix_url(url):
        return False
    if playlist_mode == "full":
        return has_playlist_marker(url)
    return has_playlist_marker(url)


def normalize_single_video_url(url: str) -> str:
    video_id = extract_video_id(url)
    if not video_id:
        return url.strip()
    return f"https://www.youtube.com/watch?v={video_id}"


def strip_playlist_params(url: str) -> str:
    parsed = urlparse(normalize_user_url(url))
    query = parse_qs(parsed.query)
    video_id = query.get("v", [None])[0]
    if video_id:
        return normalize_single_video_url(url)
    return urlunparse(parsed._replace(query=""))


def format_bytes_per_second(value: float | int | None) -> str:
    if not value:
        return ""
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return ""


def format_eta(seconds: float | int | None) -> str:
    if seconds is None:
        return ""
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return ""
    if seconds < 0:
        return ""
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def coerce_path(path_text: str | None) -> Path | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    return path if path.exists() else None
