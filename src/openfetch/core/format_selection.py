"""Select only format IDs that yt-dlp actually reported as available."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from openfetch.models import MediaMode


@dataclass(frozen=True, slots=True)
class DiscoveredFormatSelection:
    selector: str | None
    media_format_count: int
    image_only: bool


def select_discovered_format(
    formats: list[dict[str, Any]],
    media_mode: MediaMode,
    *,
    max_height: int | None = None,
) -> DiscoveredFormatSelection:
    """Return a selector composed only from concrete discovered format IDs."""

    media = [
        item
        for item in formats
        if not _is_sabr_or_image_transport(item)
        and (_has_video(item) or _has_audio(item))
    ]
    if not media:
        return DiscoveredFormatSelection(None, 0, bool(formats))

    if media_mode in {MediaMode.THUMBNAIL_ONLY, MediaMode.SUBTITLES_ONLY}:
        return DiscoveredFormatSelection(None, len(media), False)

    if media_mode in {MediaMode.AUDIO_MP3, MediaMode.AUDIO_M4A}:
        audio = [item for item in media if _has_audio(item)]
        if media_mode == MediaMode.AUDIO_M4A:
            preferred = [item for item in audio if str(item.get("ext") or "").lower() == "m4a"]
            audio = preferred or audio
        selected = _best(audio, key=_audio_rank)
        return DiscoveredFormatSelection(_format_id(selected), len(media), False)

    progressive = [item for item in media if _has_video(item) and _has_audio(item)]
    progressive = _within_height(progressive, max_height)
    progressive_mp4 = [
        item for item in progressive if str(item.get("ext") or "").lower() == "mp4"
    ]
    selected_progressive = _best(progressive_mp4 or progressive, key=_video_rank)
    if selected_progressive:
        return DiscoveredFormatSelection(
            _format_id(selected_progressive), len(media), False
        )

    video = _within_height([item for item in media if _has_video(item)], max_height)
    video_mp4 = [item for item in video if str(item.get("ext") or "").lower() == "mp4"]
    selected_video = _best(video_mp4 or video, key=_video_rank)

    audio = [item for item in media if _has_audio(item)]
    audio_m4a = [item for item in audio if str(item.get("ext") or "").lower() == "m4a"]
    selected_audio = _best(audio_m4a or audio, key=_audio_rank)

    if selected_video and selected_audio:
        return DiscoveredFormatSelection(
            f"{_format_id(selected_video)}+{_format_id(selected_audio)}",
            len(media),
            False,
        )
    if selected_video:
        return DiscoveredFormatSelection(_format_id(selected_video), len(media), False)
    return DiscoveredFormatSelection(None, len(media), False)


def _format_id(item: dict[str, Any] | None) -> str | None:
    if not item:
        return None
    value = str(item.get("format_id") or "").strip()
    return value or None


def _codec_present(value: Any) -> bool:
    return str(value or "none").lower() not in {"", "none", "null"}


def _has_video(item: dict[str, Any]) -> bool:
    return _codec_present(item.get("vcodec"))


def _has_audio(item: dict[str, Any]) -> bool:
    return _codec_present(item.get("acodec"))


def _is_sabr_or_image_transport(item: dict[str, Any]) -> bool:
    protocol = str(item.get("protocol") or "").casefold()
    extension = str(item.get("ext") or "").casefold()
    format_note = str(item.get("format_note") or "").casefold()
    return (
        "sabr" in protocol
        or "sabr" in format_note
        or protocol in {"mhtml", "images"}
        or extension in {"mhtml", "html"}
        or "storyboard" in format_note
    )


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _video_rank(item: dict[str, Any]) -> tuple[float, float]:
    return (_number(item.get("height")), _number(item.get("tbr")))


def _audio_rank(item: dict[str, Any]) -> tuple[float, float]:
    return (_number(item.get("abr")), _number(item.get("tbr")))


def _within_height(
    formats: list[dict[str, Any]], max_height: int | None
) -> list[dict[str, Any]]:
    if not max_height:
        return formats
    within = [
        item
        for item in formats
        if not item.get("height") or _number(item.get("height")) <= max_height
    ]
    return within or formats


def _best(
    formats: list[dict[str, Any]],
    *,
    key,
) -> dict[str, Any] | None:
    candidates = [item for item in formats if _format_id(item)]
    return max(candidates, key=key) if candidates else None
