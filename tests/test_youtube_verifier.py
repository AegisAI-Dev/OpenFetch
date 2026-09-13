from types import SimpleNamespace

from openfetch.core import youtube_verifier as verifier_module
from openfetch.core.downloader import (
    YtdlpCapturedOutput,
    YtdlpRunError,
    YtdlpRunResult,
)
from openfetch.core.youtube_connection import ManagedBrowser
from openfetch.core.youtube_errors import FailureCategory
from openfetch.core.youtube_verifier import verify_dedicated_youtube_profile


def test_mocked_verification_is_metadata_only_bounded_and_classifies_po_warning(
    tmp_path, monkeypatch
):
    captured = {}

    class FakeEngine:
        def __init__(self, options, *, process_record_label, process_limits):
            captured["options"] = options
            captured["label"] = process_record_label
            captured["limits"] = process_limits
            self.js_runtime_status = SimpleNamespace(found=True)

        def run_authentication_preflight(self, url, profile):
            captured["url"] = url
            captured["profile"] = profile
            return YtdlpRunResult(
                metadata={"id": "abc123", "title": "Offline test"},
                diagnostic="WARNING: This client may require a PO Token",
            )

    monkeypatch.setattr(verifier_module, "DownloadEngine", FakeEngine)
    result = verify_dedicated_youtube_profile(
        tmp_path / "profile",
        "https://www.youtube.com/watch?v=abc123",
    )

    assert result.success
    assert result.code == "connected"
    assert "PO Token" in result.warning
    assert captured["label"] == "youtube-verification"
    assert captured["limits"].total_timeout == 90
    assert captured["options"].subtitles is False
    assert captured["options"].thumbnail is False


def test_mocked_verification_classifies_rotated_session_separately(tmp_path, monkeypatch):
    class FakeEngine:
        def __init__(self, *_args, **_kwargs):
            self.js_runtime_status = SimpleNamespace(found=True)

        def run_authentication_preflight(self, url, profile):
            del url, profile
            raise YtdlpRunError(
                "yt-dlp <redacted>",
                YtdlpCapturedOutput(
                    stderr=["WARNING: cookies are no longer valid. Login required."]
                ),
                exit_code=1,
            )

    monkeypatch.setattr(verifier_module, "DownloadEngine", FakeEngine)
    result = verify_dedicated_youtube_profile(
        tmp_path / "profile",
        "https://www.youtube.com/watch?v=abc123",
    )
    assert not result.success
    assert result.code == "expired"
    assert "cookie" not in result.message.casefold()


def test_chrome_verification_uses_managed_provider_and_classifies_app_bound_failure(
    tmp_path,
    monkeypatch,
):
    captured = {}

    class FakeEngine:
        def __init__(self, options, **_kwargs):
            captured["options"] = options
            self.js_runtime_status = SimpleNamespace(found=True)

        def run_authentication_preflight(self, url, profile, browser):
            captured["call"] = (url, profile, browser)
            raise YtdlpRunError(
                "yt-dlp <redacted>",
                YtdlpCapturedOutput(stderr=["Failed to decrypt with DPAPI"]),
                exit_code=1,
            )

    monkeypatch.setattr(verifier_module, "DownloadEngine", FakeEngine)
    profile = tmp_path / "chrome-profile"
    result = verify_dedicated_youtube_profile(
        profile,
        "https://www.youtube.com/watch?v=abc123",
        browser=ManagedBrowser.CHROME,
    )
    assert not result.success
    assert result.code == "cookie_decryption_failed"
    assert "managed Firefox" in result.message
    assert captured["options"].dedicated_browser == "chrome"
    assert captured["options"].dedicated_browser_profile == profile
    assert captured["call"][2] is ManagedBrowser.CHROME


def test_chrome_extraction_failure_never_reports_connected(tmp_path, monkeypatch):
    class FakeEngine:
        def __init__(self, *_args, **_kwargs):
            self.js_runtime_status = SimpleNamespace(found=True)

        def run_authentication_preflight(self, *_args):
            raise YtdlpRunError(
                "yt-dlp <redacted>",
                YtdlpCapturedOutput(stderr=["Failed to load cookies from browser"]),
                exit_code=1,
            )

    monkeypatch.setattr(verifier_module, "DownloadEngine", FakeEngine)
    result = verify_dedicated_youtube_profile(
        tmp_path / "chrome-profile",
        "https://www.youtube.com/watch?v=abc123",
        browser="chrome",
    )
    assert not result.success
    assert result.code == "cookie_extraction_unsupported"


def test_malformed_worker_protocol_is_not_reported_as_session_rejection(tmp_path, monkeypatch):
    class FakeEngine:
        def __init__(self, *_args, **_kwargs):
            self.js_runtime_status = SimpleNamespace(found=True)

        def run_authentication_preflight(self, *_args):
            raise YtdlpRunError(
                "yt-dlp <redacted>",
                YtdlpCapturedOutput(stderr=["Malformed worker protocol frame"]),
                exit_code=1,
                category_hint=FailureCategory.WORKER_PROTOCOL_ERROR,
            )

    monkeypatch.setattr(verifier_module, "DownloadEngine", FakeEngine)
    result = verify_dedicated_youtube_profile(
        tmp_path / "profile",
        "https://www.youtube.com/watch?v=abc123",
    )

    assert not result.success
    assert result.code == "worker_protocol_error"
    assert "protocol" in result.message.lower()

