"""Subtitle option helpers."""

from __future__ import annotations


def subtitle_ydl_options(language: str, include_automatic: bool = True) -> dict:
    """Return yt-dlp options that prefer SRT output for the requested language."""
    return {
        "writesubtitles": True,
        "writeautomaticsub": include_automatic,
        "subtitleslangs": [language],
        "subtitlesformat": "srt/vtt/best",
    }


def subtitle_postprocessor() -> dict:
    """Return the FFmpeg subtitle converter postprocessor for SRT output."""
    return {"key": "FFmpegSubtitlesConvertor", "format": "srt"}
