from openfetch.core.format_selection import select_discovered_format
from openfetch.models import MediaMode


def fmt(
    format_id,
    *,
    ext="mp4",
    vcodec="none",
    acodec="none",
    height=None,
    tbr=0,
    abr=0,
    protocol="",
    format_note="",
):
    return {
        "format_id": format_id,
        "ext": ext,
        "vcodec": vcodec,
        "acodec": acodec,
        "height": height,
        "tbr": tbr,
        "abr": abr,
        "protocol": protocol,
        "format_note": format_note,
    }


def test_video_selection_uses_only_discovered_mp4_and_m4a_ids():
    formats = [
        fmt("v720", vcodec="avc1", height=720, tbr=1000),
        fmt("v1080", vcodec="avc1", height=1080, tbr=2000),
        fmt("a1", ext="m4a", acodec="mp4a", abr=128),
    ]

    selection = select_discovered_format(formats, MediaMode.VIDEO, max_height=1080)

    assert selection.selector == "v1080+a1"
    assert all(part in {"v720", "v1080", "a1"} for part in selection.selector.split("+"))


def test_progressive_mp4_is_selected_when_reported_available():
    formats = [
        fmt("18", vcodec="avc1", acodec="mp4a", height=360, tbr=500),
        fmt("22", vcodec="avc1", acodec="mp4a", height=720, tbr=1200),
    ]

    selection = select_discovered_format(formats, MediaMode.VIDEO)

    assert selection.selector == "22"


def test_unavailable_progressive_selector_is_never_invented():
    formats = [
        fmt("137", vcodec="avc1", height=1080),
        fmt("140", ext="m4a", acodec="mp4a"),
    ]

    selection = select_discovered_format(formats, MediaMode.VIDEO)

    assert selection.selector == "137+140"
    assert "best" not in selection.selector


def test_image_only_formats_do_not_trigger_media_download():
    formats = [fmt("storyboard", ext="mhtml"), fmt("thumb", ext="jpg")]

    selection = select_discovered_format(formats, MediaMode.VIDEO)

    assert selection.selector is None
    assert selection.image_only


def test_sabr_only_records_are_not_treated_as_direct_media():
    formats = [
        fmt("sabr-v", vcodec="avc1", height=1080, protocol="sabr"),
        fmt("sabr-a", ext="m4a", acodec="mp4a", protocol="sabr"),
    ]

    selection = select_discovered_format(formats, MediaMode.VIDEO)

    assert selection.selector is None
    assert selection.image_only


def test_concrete_hls_media_remains_selectable_without_enabling_a_safari_retry():
    formats = [
        fmt(
            "hls-720",
            vcodec="avc1",
            acodec="mp4a",
            height=720,
            protocol="m3u8_native",
        )
    ]

    selection = select_discovered_format(formats, MediaMode.VIDEO)

    assert selection.selector == "hls-720"


def test_m4a_mode_selects_actual_m4a_audio_id():
    formats = [
        fmt("opus", ext="webm", acodec="opus", abr=160),
        fmt("m4a", ext="m4a", acodec="mp4a", abr=128),
    ]

    selection = select_discovered_format(formats, MediaMode.AUDIO_M4A)

    assert selection.selector == "m4a"
