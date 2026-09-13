from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from openfetch.core import downloader as downloader_module
from openfetch.core.auth import (
    AuthResolution,
    AuthStrategy,
    BrowserCookieSource,
    CookieFileStatus,
)
from openfetch.core.downloader import (
    AUDIO_M4A_SELECTOR,
    AUDIO_MP3_SELECTOR,
    DEFAULT_YOUTUBE_CLIENTS,
    MAX_DOWNLOAD_ATTEMPTS,
    VIDEO_MP4_SELECTOR,
    DownloadEngine,
    YtdlpCapturedOutput,
    YtdlpRunError,
    YtdlpRunResult,
    recover_stale_download_processes,
)
from openfetch.core.js_runtime import JavaScriptRuntimeStatus
from openfetch.core.pot_provider import PROVIDER_EXTRACTOR_KEY
from openfetch.core.youtube_errors import FailureCategory
from openfetch.models import (
    DownloadJob,
    DownloadOptions,
    MediaMode,
    PlaylistMode,
)

PUBLIC_VIDEO_TEST_URL = "https://www.youtube.com/watch?v=jNQXAC9IVRw"


def _mock_runtime(monkeypatch, tmp_path, *, found=True):
    path = tmp_path / "node.exe" if found else None
    monkeypatch.setattr(
        downloader_module,
        "ensure_youtube_js_runtime",
        lambda: JavaScriptRuntimeStatus(
            found=found,
            name="node" if found else "",
            path=path,
            version="v22.17.0" if found else "",
        ),
    )
    helper = SimpleNamespace(
        status=SimpleNamespace(
            available=True,
            bundled=False,
            installed=True,
            integrity_verified=True,
            provider_id="neural-extractor:external-helper",
            version="1.3.1",
            helper_version="1.0.0",
            protocol_version=1,
            diagnostic="Optional external PO Token helper ready for test.",
        ),
        ytdlp_options=lambda: {
            "extractor_args": {
                PROVIDER_EXTRACTOR_KEY: {"protocol": ["1"]},
            }
        },
    )
    monkeypatch.setattr(downloader_module, "get_po_token_provider", lambda: helper)


def _resolution(tmp_path, *, cookie=True, browsers=("chrome", "edge", "brave", "firefox")):
    strategies = [AuthStrategy("none", "no authentication", {}, attempted_auth=False)]
    cookie_path = tmp_path / "cookies.txt" if cookie else None
    messages = []
    if cookie_path:
        cookie_path.write_text(
            "# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tFALSE\t0\tSID\tsecret\n",
            encoding="utf-8",
        )
        strategies.append(
            AuthStrategy(
                "cookies_file",
                "cookies.txt",
                {"cookiefile": str(cookie_path)},
                attempted_auth=True,
            )
        )
        messages.append("cookies.txt available: cookies.txt (held for authenticated fallback)")
    else:
        messages.append("cookies.txt not loaded")

    sources = []
    for browser in browsers:
        display = browser.title()
        source = BrowserCookieSource(browser, display, tmp_path / display)
        sources.append(source)
        strategies.append(
            AuthStrategy(
                "browser",
                display,
                {"cookiesfrombrowser": (browser,)},
                attempted_auth=True,
            )
        )
    if sources:
        messages.append(
            "browser cookie fallback available: "
            + ", ".join(source.display_name for source in sources)
        )
    status = CookieFileStatus(
        cookie_path,
        bool(cookie_path),
        "cookies.txt contains YouTube/Google cookies" if cookie_path else "cookies.txt not loaded",
    )
    return AuthResolution(
        strategies=strategies,
        messages=messages,
        cookie_file_status=status,
        browser_source=sources[0] if sources else None,
        browser_sources=sources,
    )


def _mock_resolution(monkeypatch, resolution):
    monkeypatch.setattr(
        downloader_module,
        "resolve_auth_strategies",
        lambda _cookie_file, **_kwargs: resolution,
    )


def _engine(tmp_path, **overrides):
    options = DownloadOptions(output_dir=tmp_path, **overrides)
    return DownloadEngine(options)


def _auth_id(options):
    if options.get("cookiefile"):
        return "cookies.txt"
    if options.get("cookiesfrombrowser"):
        return options["cookiesfrombrowser"][0]
    return "none"


def _clients(options):
    return tuple(options["extractor_args"]["youtube"]["player_client"])


def _media_formats():
    return [
        {
            "format_id": "137",
            "ext": "mp4",
            "vcodec": "avc1",
            "acodec": "none",
            "height": 1080,
            "protocol": "https",
        },
        {
            "format_id": "140",
            "ext": "m4a",
            "vcodec": "none",
            "acodec": "mp4a",
            "abr": 128,
            "protocol": "https",
        },
    ]


def _error(
    message,
    options,
    *,
    category_hint=None,
    phase="download",
    formats=None,
    metadata=None,
):
    return YtdlpRunError(
        "yt-dlp <redacted>",
        YtdlpCapturedOutput(stderr=[message]),
        exit_code=1,
        phase=phase,
        format_selector=str(options.get("format") or ""),
        player_clients=_clients(options),
        category_hint=category_hint,
        formats=formats,
        metadata=metadata,
    )


def test_worker_environment_forces_utf8_mode(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)

    environment = _engine(tmp_path)._worker_environment()

    assert environment["PYTHONUTF8"] == "1"
    assert environment["PYTHONIOENCODING"] == "utf-8"


def test_provider_worker_environment_isolates_cache_and_blocks_node_injection(
    tmp_path,
    monkeypatch,
):
    _mock_runtime(monkeypatch, tmp_path)
    monkeypatch.setenv("NODE_OPTIONS", "--require malicious.js")
    monkeypatch.setenv("NODE_PATH", str(tmp_path / "untrusted-modules"))
    attempt_temp = tmp_path / "attempt"
    attempt_temp.mkdir()

    environment = _engine(tmp_path)._worker_environment(attempt_temp)

    assert environment["XDG_CACHE_HOME"] == str(attempt_temp / "cache")
    assert environment["YTDLP_NO_PLUGINS"] == "1"
    assert environment["FORCE_COLOR"] == "false"
    assert "NODE_OPTIONS" not in environment
    assert "NODE_PATH" not in environment


def test_malformed_worker_frame_fails_with_typed_redacted_protocol_error(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    application_data = tmp_path / "app-data"
    monkeypatch.setattr(downloader_module, "app_data_dir", lambda: application_data)
    engine = _engine(tmp_path)
    malformed_frame = (
        f'{downloader_module.PROTOCOL_PREFIX}{{"kind":"log",'
        '"message":"authorization=worker-secret"\n'
    )

    class MalformedProtocolSupervisor:
        def run(self, _command, **kwargs):
            kwargs["stdout_callback"](malformed_frame)
            return SimpleNamespace(returncode=0, stdout=malformed_frame, stderr="")

    engine._supervisor = MalformedProtocolSupervisor()

    with pytest.raises(YtdlpRunError) as raised:
        engine._run_yt_dlp(
            PUBLIC_VIDEO_TEST_URL,
            engine.build_ydl_options(PUBLIC_VIDEO_TEST_URL),
        )

    error = raised.value
    assert error.category_hint == FailureCategory.WORKER_PROTOCOL_ERROR
    assert "worker-secret" not in error.diagnostic_text()
    profile = engine._profile(
        AuthStrategy("none", "none", {}, attempted_auth=False),
        reason="public_primary",
    )
    analysis = engine._analyse_error(error, profile)
    assert analysis.category == FailureCategory.WORKER_PROTOCOL_ERROR
    assert "protocol" in analysis.user_message.lower()


def test_public_video_first_attempt_uses_no_cookies_even_when_cookie_file_exists(
    tmp_path, monkeypatch
):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path)
    _mock_resolution(monkeypatch, resolution)
    calls = []
    logs = []

    def succeed(self, url, options, *, discover_only=False):
        calls.append((_auth_id(options), discover_only))
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", succeed)
    engine = DownloadEngine(
        DownloadOptions(output_dir=tmp_path, cookie_file=resolution.cookie_file_status.path),
        log_callback=logs.append,
    )

    result = engine.download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert result.success
    assert calls == [("none", False)]
    assert any("cookies.txt available" in log for log in logs)
    assert not any("Using cookies.txt" in log for log in logs)
    assert any("auth=none" in log for log in logs)


def test_authentication_specific_failure_enables_cookie_file_fallback(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, browsers=())
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def auth_then_success(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        if len(calls) == 1:
            raise _error("ERROR: Sign in to confirm your age. Use --cookies", options)
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", auth_then_success)

    result = _engine(tmp_path, cookie_file=resolution.cookie_file_status.path).download(
        DownloadJob(PUBLIC_VIDEO_TEST_URL)
    )

    assert result.success
    assert calls == ["none", "cookies.txt"]


def test_generic_http_403_never_triggers_cookie_or_browser_fallback(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path)
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def always_403(self, url, options, *, discover_only=False):
        calls.append((_auth_id(options), discover_only, _clients(options)))
        raise _error(
            "ERROR: unable to download video data: HTTP Error 403: Forbidden",
            options,
        )

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", always_403)

    result = _engine(tmp_path, cookie_file=resolution.cookie_file_status.path).download(
        DownloadJob(PUBLIC_VIDEO_TEST_URL)
    )

    assert not result.success
    assert result.failure_category == FailureCategory.HTTP_403_MEDIA_REJECTED.value
    assert all(call[0] == "none" for call in calls)
    assert calls[0][2] == DEFAULT_YOUTUBE_CLIENTS
    assert len(calls) == 2  # primary and one clean public retry; no blind discovery/auth


def test_media_403_owner_flow_uses_exact_firefox_then_one_mweb_provider(
    tmp_path,
    monkeypatch,
):
    _mock_runtime(monkeypatch, tmp_path)
    application_data = tmp_path / "OpenFetch"
    profile = application_data / "youtube" / "firefox-profile"
    profile.mkdir(parents=True)
    monkeypatch.setattr(downloader_module, "app_data_dir", lambda: application_data)
    resolution = AuthResolution(
        strategies=[
            AuthStrategy("none", "none", {}, attempted_auth=False),
            AuthStrategy(
                "dedicated_browser",
                "Dedicated OpenFetch Firefox profile",
                {"cookiesfrombrowser": ("firefox", str(profile.resolve()))},
                attempted_auth=True,
            ),
            AuthStrategy(
                "browser",
                "Chrome",
                {"cookiesfrombrowser": ("chrome",)},
                attempted_auth=True,
            ),
        ],
        messages=[],
        cookie_file_status=CookieFileStatus(None, False, "missing"),
        browser_source=None,
        browser_sources=[],
    )
    _mock_resolution(monkeypatch, resolution)
    calls = []
    logs = []

    def run(self, url, options, *, discover_only=False):
        youtube_args = options["extractor_args"]["youtube"]
        calls.append(
            (
                _auth_id(options),
                _clients(options),
                tuple(youtube_args["fetch_pot"]),
                tuple(youtube_args["pot_trace"]),
                str(options["format"]),
                PROVIDER_EXTRACTOR_KEY in options["extractor_args"],
            )
        )
        if len(calls) == 4:
            return YtdlpRunResult()
        message = "ERROR: unable to download video data: HTTP Error 403: Forbidden"
        if len(calls) == 3:
            message = "WARNING: This client requires a PO Token for GVS playback\n" + message
        raise _error(
            message,
            options,
            formats=_media_formats(),
            metadata={"id": "abc123"},
        )

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", run)
    engine = DownloadEngine(
        DownloadOptions(
            output_dir=tmp_path,
            dedicated_browser="firefox",
            dedicated_browser_profile=profile,
            dedicated_browser_last_verified=datetime.now(UTC).isoformat(timespec="seconds"),
            guided_youtube_auth=True,
            legacy_browser_fallback=True,
        ),
        log_callback=logs.append,
    )

    result = engine.download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert result.success
    assert calls == [
        ("none", ("default",), ("never",), ("false",), VIDEO_MP4_SELECTOR, False),
        ("none", ("default",), ("never",), ("false",), "137+140", False),
        ("firefox", ("default",), ("never",), ("false",), "137+140", False),
        ("firefox", ("mweb",), ("auto",), ("false",), "137+140", True),
    ]
    assert all(call[0] != "chrome" for call in calls)
    assert sum(call[1] == ("mweb",) for call in calls) == 1
    assert "Retrying media access using the verified dedicated Firefox session." in logs


def test_stale_verified_provider_fails_closed_before_auth_or_pot(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    application_data = tmp_path / "OpenFetch"
    profile = application_data / "youtube" / "firefox-profile"
    profile.mkdir(parents=True)
    monkeypatch.setattr(downloader_module, "app_data_dir", lambda: application_data)
    resolution = AuthResolution(
        strategies=[
            AuthStrategy("none", "none", {}, attempted_auth=False),
            AuthStrategy(
                "dedicated_browser",
                "Dedicated OpenFetch Firefox profile",
                {"cookiesfrombrowser": ("firefox", str(profile.resolve()))},
                attempted_auth=True,
            ),
        ],
        messages=[],
        cookie_file_status=CookieFileStatus(None, False, "missing"),
        browser_source=None,
        browser_sources=[],
    )
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def fail(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        raise _error(
            "WARNING: PO Token may be required\n"
            "ERROR: unable to download video data: HTTP Error 403: Forbidden",
            options,
            formats=_media_formats(),
        )

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", fail)
    result = _engine(
        tmp_path,
        dedicated_browser="firefox",
        dedicated_browser_profile=profile,
        dedicated_browser_last_verified=(datetime.now(UTC) - timedelta(days=2)).isoformat(),
        guided_youtube_auth=True,
    ).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.VERIFIED_PROVIDER_NOT_APPLIED.value
    assert calls == ["none", "none"]


def test_authenticated_media_403_stops_without_blind_browser_fallback(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, browsers=("chrome",))
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def run(self, url, options, *, discover_only=False):
        auth = _auth_id(options)
        calls.append(auth)
        if auth == "none":
            raise _error("ERROR: Login required. Use --cookies", options)
        if auth == "cookies.txt":
            raise _error(
                "ERROR: unable to download video data: HTTP Error 403: Forbidden",
                options,
            )
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", run)

    result = _engine(tmp_path, cookie_file=resolution.cookie_file_status.path).download(
        DownloadJob(PUBLIC_VIDEO_TEST_URL)
    )

    assert not result.success
    assert result.failure_category == (
        FailureCategory.MEDIA_ACCESS_REJECTED_AFTER_AUTHENTICATION.value
    )
    assert calls == ["none", "cookies.txt"]


def test_chrome_cookie_lock_disables_chrome_for_remainder_of_job(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, cookie=False, browsers=("chrome", "firefox"))
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def run(self, url, options, *, discover_only=False):
        auth = _auth_id(options)
        calls.append(auth)
        if auth == "none":
            raise _error("ERROR: Sign in to confirm you're not a bot. Use --cookies", options)
        if auth == "chrome":
            raise _error("ERROR: Could not copy Chrome cookie database", options)
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", run)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert result.success
    assert calls == ["none", "chrome", "firefox"]
    assert calls.count("chrome") == 1


def test_dpapi_failure_disables_provider_without_node_guidance(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, cookie=False, browsers=("edge", "brave"))
    _mock_resolution(monkeypatch, resolution)
    calls = []
    logs = []

    def run(self, url, options, *, discover_only=False):
        auth = _auth_id(options)
        calls.append(auth)
        if auth == "none":
            raise _error("ERROR: Login required. Use --cookies", options)
        if auth == "edge":
            raise _error("ERROR: Failed to decrypt cookies with Windows DPAPI", options)
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", run)
    engine = DownloadEngine(DownloadOptions(output_dir=tmp_path), log_callback=logs.append)

    result = engine.download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert result.success
    assert calls == ["none", "edge", "brave"]
    assert not any("install node" in log.lower() for log in logs)
    assert not any("solver unavailable" in log.lower() for log in logs)


def test_authenticated_browser_order_is_bounded_deterministic_and_unique(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path)
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def always_auth_failure(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        raise _error("ERROR: Login required. Use --cookies", options)

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", always_auth_failure)

    result = _engine(tmp_path, cookie_file=resolution.cookie_file_status.path).download(
        DownloadJob(PUBLIC_VIDEO_TEST_URL)
    )

    assert not result.success
    assert calls == ["none", "cookies.txt", "chrome", "edge", "brave", "firefox"]
    assert len(calls) == MAX_DOWNLOAD_ATTEMPTS
    assert len(calls) == len(set(calls))


def test_inactivity_timeout_starts_one_clean_no_cookie_retry(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, cookie=False, browsers=())
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def timeout_then_success(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        if len(calls) == 1:
            raise _error(
                "Network inactivity timeout",
                options,
                category_hint=FailureCategory.NETWORK_INACTIVITY_TIMEOUT,
            )
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", timeout_then_success)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert result.success
    assert calls == ["none", "none"]


def test_cancel_stops_new_attempts_and_returns_typed_result(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path)
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def cancel_on_first(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        self.cancel()
        raise _error(
            "ERROR: unable to download video data: HTTP Error 403: Forbidden",
            options,
        )

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", cancel_on_first)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.message == "Download cancelled"
    assert result.failure_category == FailureCategory.DOWNLOAD_CANCELLED.value
    assert calls == ["none"]


def test_format_discovery_selects_only_actual_available_ids(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, cookie=False, browsers=())
    _mock_resolution(monkeypatch, resolution)
    downloads = []
    discoveries = []

    def run(self, url, options, *, discover_only=False):
        if discover_only:
            discoveries.append(str(options["format"]))
            return YtdlpRunResult(
                formats=[
                    {
                        "format_id": "137",
                        "ext": "mp4",
                        "vcodec": "avc1",
                        "acodec": "none",
                        "height": 1080,
                    },
                    {
                        "format_id": "140",
                        "ext": "m4a",
                        "vcodec": "none",
                        "acodec": "mp4a",
                        "abr": 128,
                    },
                ]
            )
        downloads.append(str(options["format"]))
        if len(downloads) == 1:
            raise _error("ERROR: Requested format is not available", options, phase="preflight")
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", run)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert result.success
    assert downloads == [VIDEO_MP4_SELECTOR, "137+140"]
    assert discoveries == [VIDEO_MP4_SELECTOR]
    assert "best" not in downloads[1]


def test_image_only_discovery_does_not_start_media_fallback(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, cookie=False, browsers=())
    _mock_resolution(monkeypatch, resolution)
    downloads = []

    def run(self, url, options, *, discover_only=False):
        if discover_only:
            return YtdlpRunResult(
                formats=[
                    {"format_id": "storyboard", "ext": "mhtml", "vcodec": "none", "acodec": "none"}
                ]
            )
        downloads.append(str(options["format"]))
        raise _error("ERROR: Requested format is not available", options, phase="preflight")

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", run)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.ONLY_IMAGE_FORMATS_AVAILABLE.value
    assert downloads == [VIDEO_MP4_SELECTOR, VIDEO_MP4_SELECTOR]


def test_po_token_warning_uses_exactly_one_supported_provider_attempt(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path)
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def fail(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        raise _error("WARNING: This client requires a PO Token for video playback", options)

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", fail)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.PO_TOKEN_FETCH_FAILED.value
    assert calls == ["none", "none"]


@pytest.mark.parametrize(
    ("provider_error", "expected_category"),
    [
        (
            "ERROR: Error fetching PO Token: external_po_helper_helper_timeout",
            FailureCategory.PO_TOKEN_FETCH_FAILED,
        ),
        (
            "ERROR: unable to download video data: HTTP Error 403: Forbidden",
            FailureCategory.PO_TOKEN_MEDIA_403,
        ),
    ],
)
def test_provider_failures_are_precise_and_never_repeat(
    tmp_path,
    monkeypatch,
    provider_error,
    expected_category,
):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, cookie=False, browsers=())
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def fail(self, url, options, *, discover_only=False):
        calls.append((_clients(options), tuple(options["extractor_args"]["youtube"]["fetch_pot"])))
        if len(calls) == 1:
            raise _error("WARNING: This client requires a PO Token for GVS", options)
        raise _error(provider_error, options, formats=_media_formats())

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", fail)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == expected_category.value
    assert calls == [(("default",), ("never",)), (("mweb",), ("auto",))]


def test_matching_pot_enforcement_fails_closed_when_provider_unavailable(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path, cookie=False, browsers=())
    _mock_resolution(monkeypatch, resolution)
    unavailable = SimpleNamespace(
        status=SimpleNamespace(
            available=False,
            bundled=False,
            provider_id="neural-extractor:external-helper",
            version="1.3.1",
            diagnostic="PO Token provider unavailable for test",
        )
    )
    monkeypatch.setattr(downloader_module, "get_po_token_provider", lambda: unavailable)
    calls = []

    def fail(self, url, options, *, discover_only=False):
        calls.append(_clients(options))
        raise _error("WARNING: This client requires a PO Token for GVS", options)

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", fail)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.PO_TOKEN_PROVIDER_UNAVAILABLE.value
    assert calls == [("default",)]


def test_node_found_plus_n_challenge_never_reports_missing_node(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path, found=True)
    resolution = _resolution(tmp_path, cookie=False, browsers=())
    _mock_resolution(monkeypatch, resolution)

    def fail(self, url, options, *, discover_only=False):
        raise _error("WARNING: n challenge solving failed", options)

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", fail)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.UNKNOWN.value
    assert "unavailable" not in result.message.lower()


def test_genuine_missing_runtime_stops_before_attempt(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path, found=False)
    resolution = _resolution(tmp_path, cookie=False, browsers=())
    _mock_resolution(monkeypatch, resolution)

    def should_not_run(*args, **kwargs):
        raise AssertionError("yt-dlp must not start without the required runtime")

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", should_not_run)

    result = _engine(tmp_path).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.JAVASCRIPT_RUNTIME_UNAVAILABLE.value
    assert "Install Node.js" in result.message


def test_video_quality_generates_height_limited_selector(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    options = _engine(tmp_path, quality="1080p Full HD").build_ydl_options(PUBLIC_VIDEO_TEST_URL)

    assert "height<=1080" in options["format"]
    assert options["merge_output_format"] == "mp4"


def test_mp3_m4a_subtitles_and_thumbnail_options_are_preserved(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    mp3 = _engine(
        tmp_path,
        media_mode=MediaMode.AUDIO_MP3,
        thumbnail=True,
        embed_thumbnail=True,
    ).build_ydl_options(PUBLIC_VIDEO_TEST_URL)
    m4a = _engine(tmp_path, media_mode=MediaMode.AUDIO_M4A).build_ydl_options(PUBLIC_VIDEO_TEST_URL)
    subtitles = _engine(
        tmp_path,
        media_mode=MediaMode.SUBTITLES_ONLY,
        subtitle_language="nl",
        subtitles=True,
    ).build_ydl_options(PUBLIC_VIDEO_TEST_URL)

    assert mp3["format"] == AUDIO_MP3_SELECTOR
    assert {item["key"] for item in mp3["postprocessors"]} >= {
        "FFmpegExtractAudio",
        "EmbedThumbnail",
    }
    assert m4a["format"] == AUDIO_M4A_SELECTOR
    assert "merge_output_format" not in m4a
    assert subtitles["skip_download"] is True
    assert subtitles["subtitleslangs"] == ["nl"]


def test_mix_url_normalizes_to_current_video_only_and_command_has_no_playlist(
    tmp_path, monkeypatch
):
    _mock_runtime(monkeypatch, tmp_path)
    logs = []
    engine = DownloadEngine(
        DownloadOptions(output_dir=tmp_path, playlist_mode=PlaylistMode.FULL),
        log_callback=logs.append,
    )
    prepared = engine.prepare_url(
        "https://www.youtube.com/watch?v=abc123&list=RDabc123&start_radio=1"
    )
    options = engine.build_ydl_options(prepared)
    command = engine._yt_dlp_command(prepared, options)

    assert prepared == "https://www.youtube.com/watch?v=abc123"
    assert options["noplaylist"] is True
    assert "--no-playlist" in command
    assert "--yes-playlist" not in command
    assert "--playlist-end" not in command
    assert logs == ["YouTube Mix detected. Downloading current video only."]


def test_auth_options_merge_without_overwriting_selected_client(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    auth = AuthStrategy(
        "browser",
        "Firefox",
        {"cookiesfrombrowser": ("firefox",)},
        attempted_auth=True,
    )
    engine = _engine(tmp_path)
    profile = engine._profile(
        auth,
        player_clients=("web",),
        reason="authenticated_fallback",
    )

    options = engine._options_for_attempt_profile(PUBLIC_VIDEO_TEST_URL, profile)

    assert options["cookiesfrombrowser"] == ("firefox",)
    assert _clients(options) == ("web",)


def test_command_and_logs_redact_cookie_path_and_secret_values(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    cookie_path = tmp_path / "cookies.txt"
    engine = _engine(tmp_path, cookie_file=cookie_path)
    auth = AuthStrategy(
        "cookies_file",
        "cookies.txt",
        {"cookiefile": str(cookie_path)},
        attempted_auth=True,
    )
    options = engine.build_ydl_options(PUBLIC_VIDEO_TEST_URL, auth)

    command = engine._yt_dlp_command(PUBLIC_VIDEO_TEST_URL, options)
    cleaned = engine._redact_diagnostic_text(
        f"cookie=super-secret authorization=token path={cookie_path}"
    )

    assert "--cookies <cookies.txt>" in command
    assert str(cookie_path) not in command
    assert "super-secret" not in cleaned
    assert "authorization=token" not in cleaned


@pytest.mark.parametrize(
    "diagnostic",
    [
        "poToken=token-sentinel-123456",
        "po_token: token-sentinel-123456",
        "Generated POT: token-sentinel-123456",
        "PoTokenResponse(po_token='token-sentinel-123456')",
        "https://provider.invalid/pot/token-sentinel-123456/result",
        "https://youtube.invalid/media?pot=token-sentinel-123456&x=1",
        '{"integrityToken":"token-sentinel-123456"}',
        '{"visitorData":"token-sentinel-123456"}',
    ],
)
def test_po_token_material_is_redacted_from_diagnostics_and_full_errors(
    tmp_path,
    monkeypatch,
    diagnostic,
):
    _mock_runtime(monkeypatch, tmp_path)
    engine = _engine(tmp_path)

    cleaned = engine._redact_diagnostic_text(diagnostic)
    error = YtdlpRunError(
        f"yt-dlp {diagnostic}",
        YtdlpCapturedOutput(stderr=[diagnostic]),
        cause=RuntimeError(diagnostic),
    )

    assert "token-sentinel-123456" not in cleaned
    assert "token-sentinel-123456" not in error.diagnostic_text()
    assert "token-sentinel-123456" not in error.full_text()


def test_public_video_test_url_is_normal_video_url():
    assert PUBLIC_VIDEO_TEST_URL == "https://www.youtube.com/watch?v=jNQXAC9IVRw"


def test_guided_auth_stops_for_connection_assistant_before_cookie_or_browser_fallback(
    tmp_path, monkeypatch
):
    _mock_runtime(monkeypatch, tmp_path)
    resolution = _resolution(tmp_path)
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def auth_required(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        raise _error("ERROR: Sign in to confirm you're not a bot. Use --cookies", options)

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", auth_required)
    result = _engine(
        tmp_path,
        cookie_file=resolution.cookie_file_status.path,
        guided_youtube_auth=True,
    ).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.AUTHENTICATION_REQUIRED.value
    assert calls == ["none"]


def test_connected_profile_is_structured_first_fallback_and_suppresses_browser_cycle(
    tmp_path, monkeypatch
):
    _mock_runtime(monkeypatch, tmp_path)
    application_data = tmp_path / "OpenFetch"
    profile = application_data / "youtube" / "firefox-profile"
    profile.mkdir(parents=True)
    monkeypatch.setattr(downloader_module, "app_data_dir", lambda: application_data)
    cookie_file = tmp_path / "cookies.txt"
    cookie_file.write_text(
        ".youtube.com\tTRUE\t/\tFALSE\t0\tSID\tredacted\n",
        encoding="utf-8",
    )
    resolution = AuthResolution(
        strategies=[
            AuthStrategy("none", "none", {}, attempted_auth=False),
            AuthStrategy(
                "dedicated_firefox",
                "Dedicated OpenFetch Firefox profile",
                {"cookiesfrombrowser": ("firefox", str(profile.resolve()))},
                attempted_auth=True,
            ),
            AuthStrategy(
                "cookies_file",
                "cookies.txt",
                {"cookiefile": str(cookie_file)},
                attempted_auth=True,
            ),
            AuthStrategy(
                "browser",
                "Chrome",
                {"cookiesfrombrowser": ("chrome",)},
                attempted_auth=True,
            ),
        ],
        messages=[],
        cookie_file_status=CookieFileStatus(cookie_file, True, "valid"),
        browser_source=None,
        browser_sources=[],
    )
    _mock_resolution(monkeypatch, resolution)
    calls = []
    dedicated_options = {}

    def run(self, url, options, *, discover_only=False):
        calls.append(_auth_id(options))
        if len(calls) == 1:
            raise _error("ERROR: Sign in to confirm you're not a bot. Use --cookies", options)
        dedicated_options.update(options)
        return YtdlpRunResult()

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", run)
    result = _engine(
        tmp_path,
        cookie_file=cookie_file,
        dedicated_firefox_profile=profile,
        guided_youtube_auth=True,
    ).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert result.success
    assert calls == ["none", "firefox"]
    assert dedicated_options["cookiesfrombrowser"] == ("firefox", str(profile.resolve()))


def test_rotated_dedicated_cookies_mark_session_expired_without_blind_fallback(
    tmp_path, monkeypatch
):
    _mock_runtime(monkeypatch, tmp_path)
    application_data = tmp_path / "OpenFetch"
    profile = application_data / "youtube" / "firefox-profile"
    profile.mkdir(parents=True)
    monkeypatch.setattr(downloader_module, "app_data_dir", lambda: application_data)
    resolution = AuthResolution(
        strategies=[
            AuthStrategy("none", "none", {}, attempted_auth=False),
            AuthStrategy(
                "dedicated_firefox",
                "Dedicated OpenFetch Firefox profile",
                {"cookiesfrombrowser": ("firefox", str(profile.resolve()))},
                attempted_auth=True,
            ),
            AuthStrategy(
                "browser",
                "Chrome",
                {"cookiesfrombrowser": ("chrome",)},
                attempted_auth=True,
            ),
        ],
        messages=[],
        cookie_file_status=CookieFileStatus(None, False, "missing"),
        browser_source=None,
        browser_sources=[],
    )
    _mock_resolution(monkeypatch, resolution)
    calls = []

    def fail(self, url, options, *, discover_only=False):
        auth = _auth_id(options)
        calls.append(auth)
        if auth == "none":
            raise _error("ERROR: Sign in to confirm you're not a bot. Use --cookies", options)
        raise _error("WARNING: cookies are no longer valid. Login required.", options)

    monkeypatch.setattr(DownloadEngine, "_run_yt_dlp", fail)
    result = _engine(
        tmp_path,
        dedicated_firefox_profile=profile,
        guided_youtube_auth=True,
    ).download(DownloadJob(PUBLIC_VIDEO_TEST_URL))

    assert not result.success
    assert result.failure_category == FailureCategory.YOUTUBE_SESSION_EXPIRED.value
    assert calls == ["none", "firefox"]


def test_attempt_temp_is_isolated_and_stale_owner_state_is_cleaned(tmp_path, monkeypatch):
    _mock_runtime(monkeypatch, tmp_path)
    app_data = tmp_path / "app-data"
    monkeypatch.setattr(downloader_module, "app_data_dir", lambda: app_data)
    engine = _engine(tmp_path)

    active = engine._create_attempt_temp()
    (active / "worker.tmp").write_text("isolated", encoding="utf-8")
    engine._cleanup_attempt_temp(active)

    stale = app_data / "worker-temp" / "owner-99999999-controlled"
    stale.mkdir(parents=True)
    (stale / "leftover.tmp").write_text("stale", encoding="utf-8")
    monkeypatch.setattr(downloader_module, "is_process_running", lambda _pid: False)

    messages = recover_stale_download_processes()

    assert not active.exists()
    assert not stale.exists()
    assert any("Removed stale" in message for message in messages)


@pytest.mark.parametrize("mode", [MediaMode.VIDEO, MediaMode.AUDIO_MP3, MediaMode.AUDIO_M4A])
def test_media_modes_keep_remote_ejs_and_node_runtime(tmp_path, monkeypatch, mode):
    _mock_runtime(monkeypatch, tmp_path)

    options = _engine(tmp_path, media_mode=mode).build_ydl_options(PUBLIC_VIDEO_TEST_URL)

    assert options["remote_components"] == ["ejs:github"]
    assert options["js_runtimes"]["node"]["path"].endswith("node.exe")
