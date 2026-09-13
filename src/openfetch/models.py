"""Shared data models for OpenFetch."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from uuid import uuid4


class MediaMode(Enum):
    VIDEO = "video"
    AUDIO_MP3 = "audio_mp3"
    AUDIO_M4A = "audio_m4a"
    THUMBNAIL_ONLY = "thumbnail_only"
    SUBTITLES_ONLY = "subtitles_only"

    @property
    def label(self) -> str:
        return {
            MediaMode.VIDEO: "Video MP4",
            MediaMode.AUDIO_MP3: "Audio MP3",
            MediaMode.AUDIO_M4A: "Audio M4A",
            MediaMode.THUMBNAIL_ONLY: "Thumbnail only",
            MediaMode.SUBTITLES_ONLY: "Subtitles only",
        }[self]


class PlaylistMode(Enum):
    AUTO = "auto"
    SINGLE = "single"
    FULL = "full"

    @property
    def label(self) -> str:
        return {
            PlaylistMode.AUTO: "Auto detect",
            PlaylistMode.SINGLE: "Current video only",
            PlaylistMode.FULL: "Full playlist / mix",
        }[self]


@dataclass(slots=True)
class DownloadOptions:
    output_dir: Path
    media_mode: MediaMode = MediaMode.VIDEO
    playlist_mode: PlaylistMode = PlaylistMode.AUTO
    quality: str = "Best available"
    audio_quality: str = "320"
    subtitles: bool = True
    auto_subtitles: bool = True
    subtitle_language: str = "nl"
    thumbnail: bool = True
    embed_thumbnail: bool = True
    metadata_json: bool = False
    cookie_file: Path | None = None
    dedicated_browser: str | None = None
    dedicated_browser_profile: Path | None = None
    dedicated_browser_last_verified: str | None = None
    dedicated_firefox_profile: Path | None = None
    guided_youtube_auth: bool = False
    legacy_browser_fallback: bool = False
    overwrite: bool = False
    restrict_filenames: bool = False


@dataclass(slots=True)
class DownloadJob:
    url: str
    job_id: str = field(default_factory=lambda: uuid4().hex[:10])


@dataclass(slots=True)
class ProgressEvent:
    job_id: str
    status: str
    percent: int = 0
    title: str = ""
    filename: str = ""
    speed: str = ""
    eta: str = ""
    playlist_index: int | None = None
    playlist_total: int | None = None

    def compact_status(self) -> str:
        pieces = [self.status]
        if self.percent:
            pieces.append(f"{self.percent}%")
        if self.playlist_index and self.playlist_total:
            pieces.append(f"{self.playlist_index}/{self.playlist_total}")
        if self.speed:
            pieces.append(self.speed)
        if self.eta:
            pieces.append(f"ETA {self.eta}")
        if self.title:
            pieces.append(self.title)
        return " | ".join(pieces)


@dataclass(slots=True)
class DownloadResult:
    job_id: str
    success: bool
    message: str
    files: list[Path] = field(default_factory=list)
    failure_category: str = ""
