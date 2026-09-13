from openfetch.models import PlaylistMode
from openfetch.utils import (
    extract_video_id,
    is_youtube_mix_url,
    is_youtube_url,
    normalize_single_video_url,
    sanitize_filename,
    should_download_playlist,
    split_urls,
)


def test_split_urls_deduplicates_lines_and_commas():
    text = "https://youtu.be/abc\nhttps://youtu.be/abc, https://youtu.be/def"
    assert split_urls(text) == ["https://youtu.be/abc", "https://youtu.be/def"]


def test_youtube_url_detection_and_video_id_extraction():
    url = "https://www.youtube.com/watch?v=abc123&list=PL42"
    assert is_youtube_url(url)
    assert extract_video_id(url) == "abc123"
    assert normalize_single_video_url(url) == "https://www.youtube.com/watch?v=abc123"


def test_playlist_decision_modes():
    url = "https://www.youtube.com/watch?v=abc123&list=PL42"
    assert should_download_playlist(url, PlaylistMode.AUTO.value)
    assert should_download_playlist(url, PlaylistMode.FULL.value)
    assert not should_download_playlist(url, PlaylistMode.SINGLE.value)


def test_mix_url_is_not_treated_as_playlist():
    url = "https://www.youtube.com/watch?v=abc123&list=RDabc123&start_radio=1"
    assert is_youtube_mix_url(url)
    assert normalize_single_video_url(url) == "https://www.youtube.com/watch?v=abc123"
    assert not should_download_playlist(url, PlaylistMode.AUTO.value)
    assert not should_download_playlist(url, PlaylistMode.FULL.value)


def test_sanitize_filename_removes_windows_reserved_chars():
    assert sanitize_filename('bad:name/with*chars?') == "bad_name_with_chars_"
