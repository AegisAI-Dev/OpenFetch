from pathlib import Path

from openfetch.core.auth import (
    BROWSER_FALLBACK_ORDER,
    AuthenticationState,
    BrowserCookieFailureKind,
    BrowserCookieSource,
    classify_browser_cookie_extraction_error,
    clean_authentication_error,
    clean_browser_cookie_extraction_error,
    clean_browser_cookie_failure,
    clean_live_event_ended_error,
    inspect_cookie_file,
    is_authentication_error,
    is_browser_cookie_decryption_error,
    is_browser_cookie_extraction_error,
    is_browser_cookie_locked_error,
    is_live_event_ended_error,
    resolve_auth_strategies,
)


def _write_cookie_file(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_public_video_strategy_is_no_cookie_first_even_when_cookie_file_is_valid(tmp_path):
    cookie_file = _write_cookie_file(
        tmp_path / "cookies.txt",
        "# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tFALSE\t0\tSID\tredacted\n",
    )
    browser = BrowserCookieSource("chrome", "Chrome", tmp_path / "Chrome")
    resolution = resolve_auth_strategies(cookie_file, browser_detector=lambda: [browser])

    assert [strategy.kind for strategy in resolution.strategies] == ["none", "cookies_file", "browser"]
    assert resolution.strategies[0].ydl_options == {}
    assert resolution.strategies[1].ydl_options == {"cookiefile": str(cookie_file)}
    assert resolution.strategies[2].ydl_options == {"cookiesfrombrowser": ("chrome",)}
    assert any("cookies.txt available" in message for message in resolution.messages)
    assert any("held for authenticated fallback" in message for message in resolution.messages)
    assert not any("using cookies.txt" in message.lower() for message in resolution.messages)


def test_browser_cookies_are_retained_as_fallback_when_cookie_file_missing(tmp_path):
    browser = BrowserCookieSource("edge", "Edge", tmp_path / "Edge")
    resolution = resolve_auth_strategies(None, browser_detector=lambda: [browser])

    assert [strategy.kind for strategy in resolution.strategies] == ["none", "browser"]
    assert resolution.strategies[0].ydl_options == {}
    assert resolution.strategies[1].ydl_options["cookiesfrombrowser"] == ("edge",)
    assert any("cookies.txt not loaded" in message for message in resolution.messages)


def test_invalid_cookie_file_falls_back_to_browser(tmp_path):
    cookie_file = _write_cookie_file(tmp_path / "cookies.txt", "# header only\n")
    browser = BrowserCookieSource("firefox", "Firefox", tmp_path / "Firefox")
    resolution = resolve_auth_strategies(cookie_file, browser_detector=lambda: [browser])

    assert [strategy.kind for strategy in resolution.strategies] == ["none", "browser"]
    assert "invalid" in resolution.messages[0]


def test_no_auth_strategy_when_no_cookie_or_browser():
    resolution = resolve_auth_strategies(None, browser_detector=lambda: [])

    assert [strategy.kind for strategy in resolution.strategies] == ["none"]
    assert not resolution.strategies[0].attempted_auth
    assert any("browser cookies unavailable" in message for message in resolution.messages)


def test_dedicated_firefox_precedes_cookie_file_and_legacy_browsers(tmp_path):
    application_data = tmp_path / "OpenFetch"
    profile = application_data / "youtube" / "firefox-profile"
    profile.mkdir(parents=True)
    cookie_file = _write_cookie_file(
        tmp_path / "cookies.txt",
        ".youtube.com\tTRUE\t/\tFALSE\t0\tSID\tredacted\n",
    )
    browser = BrowserCookieSource("chrome", "Chrome", tmp_path / "Chrome")

    resolution = resolve_auth_strategies(
        cookie_file,
        browser_detector=lambda: [browser],
        dedicated_firefox_profile=profile,
        dedicated_application_data=application_data,
        allow_legacy_browser_fallback=True,
    )

    assert [strategy.kind for strategy in resolution.strategies] == [
        "none",
        "dedicated_firefox",
        "cookies_file",
        "browser",
    ]
    assert resolution.strategies[1].ydl_options["cookiesfrombrowser"] == (
        "firefox",
        str(profile.resolve()),
    )


def test_legacy_browser_profiles_are_omitted_when_advanced_fallback_is_disabled(tmp_path):
    browser = BrowserCookieSource("chrome", "Chrome", tmp_path / "Chrome")
    resolution = resolve_auth_strategies(
        None,
        browser_detector=lambda: [browser],
        allow_legacy_browser_fallback=False,
    )
    assert [strategy.kind for strategy in resolution.strategies] == ["none"]
    assert any("legacy browser cookie fallback disabled" in item for item in resolution.messages)


def test_cookie_file_inspection_never_requires_secret_values(tmp_path):
    cookie_file = _write_cookie_file(
        tmp_path / "cookies.txt",
        ".google.com\tTRUE\t/\tTRUE\t0\tSAPISID\tredacted-secret-value\n",
    )

    status = inspect_cookie_file(cookie_file)

    assert status.valid
    assert "redacted-secret-value" not in status.reason


def test_authentication_error_detection_and_clean_messages():
    assert is_authentication_error("Sign in to confirm you're not a bot. Use --cookies")
    assert not is_authentication_error("Unable to download media: HTTP Error 403: Forbidden")
    assert clean_authentication_error(True) == (
        "Cookies appear expired or invalid. Please export fresh cookies from your browser."
    )
    assert "Authentication unavailable" in clean_authentication_error(False)


def test_browser_fallback_order_and_multiple_strategies(tmp_path):
    sources = [
        BrowserCookieSource("chrome", "Chrome", tmp_path / "Chrome"),
        BrowserCookieSource("edge", "Edge", tmp_path / "Edge"),
        BrowserCookieSource("brave", "Brave", tmp_path / "Brave"),
        BrowserCookieSource("firefox", "Firefox", tmp_path / "Firefox"),
    ]

    resolution = resolve_auth_strategies(None, browser_detector=lambda: sources)

    assert resolution.strategies[0].kind == "none"
    browser_strategies = [strategy for strategy in resolution.strategies if strategy.is_browser]

    assert tuple(strategy.ydl_options["cookiesfrombrowser"][0] for strategy in browser_strategies) == (
        "chrome",
        "edge",
        "brave",
        "firefox",
    )
    assert tuple(source.browser for source in resolution.browser_sources) == BROWSER_FALLBACK_ORDER


def test_authentication_state_requires_explicit_justification_before_cookie_fallback(tmp_path):
    cookie_file = _write_cookie_file(
        tmp_path / "cookies.txt",
        ".youtube.com\tTRUE\t/\tFALSE\t0\tSID\tredacted\n",
    )
    browser = BrowserCookieSource("chrome", "Chrome", tmp_path / "Chrome")
    resolution = resolve_auth_strategies(cookie_file, browser_detector=lambda: [browser])
    state = AuthenticationState(resolution)

    assert state.eligible_authenticated_strategies() == []
    assert state.next_authenticated_strategy() is None

    state.justify_authenticated_fallback()
    strategy = state.next_authenticated_strategy()

    assert strategy is not None
    assert strategy.is_cookie_file
    assert strategy.provider_id == "cookies_file"
    assert state.attempted_provider_ids == {"cookies_file"}


def test_authentication_state_yields_each_provider_once_in_deterministic_order(tmp_path):
    cookie_file = _write_cookie_file(
        tmp_path / "cookies.txt",
        ".youtube.com\tTRUE\t/\tFALSE\t0\tSID\tredacted\n",
    )
    sources = [
        BrowserCookieSource(browser, browser.title(), tmp_path / browser)
        for browser in BROWSER_FALLBACK_ORDER
    ]
    state = AuthenticationState(
        resolve_auth_strategies(cookie_file, browser_detector=lambda: sources)
    )
    state.justify_authenticated_fallback()

    provider_ids = []
    while strategy := state.next_authenticated_strategy():
        provider_ids.append(strategy.provider_id)

    assert provider_ids == [
        "cookies_file",
        "browser:chrome",
        "browser:edge",
        "browser:brave",
        "browser:firefox",
    ]
    assert len(provider_ids) == len(set(provider_ids))
    assert state.next_authenticated_strategy() is None


def test_rejected_cookie_file_is_recorded_and_never_selected_again(tmp_path):
    cookie_file = _write_cookie_file(
        tmp_path / "cookies.txt",
        ".youtube.com\tTRUE\t/\tFALSE\t0\tSID\tredacted\n",
    )
    browser = BrowserCookieSource("firefox", "Firefox", tmp_path / "Firefox")
    state = AuthenticationState(
        resolve_auth_strategies(cookie_file, browser_detector=lambda: [browser])
    )
    state.justify_authenticated_fallback()
    state.reject_cookie_file("HTTP 403; cookies may be stale or rejected")

    assert state.cookie_file_rejected
    assert state.cookie_file_rejection_reason == "HTTP 403; cookies may be stale or rejected"
    assert state.next_authenticated_strategy().provider_id == "browser:firefox"
    assert state.next_authenticated_strategy() is None


def test_locked_chrome_is_disabled_for_remainder_of_job_and_edge_is_next(tmp_path):
    sources = [
        BrowserCookieSource("chrome", "Chrome", tmp_path / "Chrome"),
        BrowserCookieSource("edge", "Edge", tmp_path / "Edge"),
    ]
    state = AuthenticationState(resolve_auth_strategies(None, browser_detector=lambda: sources))
    state.justify_authenticated_fallback()
    state.disable_browser("Chrome", "cookie database locked")

    assert state.is_browser_disabled("chrome")
    assert state.disabled_browser_reasons == {"chrome": "cookie database locked"}
    assert state.next_authenticated_strategy().provider_id == "browser:edge"
    assert state.next_authenticated_strategy() is None


def test_dpapi_failed_edge_and_brave_are_disabled_without_retries(tmp_path):
    sources = [
        BrowserCookieSource("edge", "Edge", tmp_path / "Edge"),
        BrowserCookieSource("brave", "Brave", tmp_path / "Brave"),
        BrowserCookieSource("firefox", "Firefox", tmp_path / "Firefox"),
    ]
    state = AuthenticationState(resolve_auth_strategies(None, browser_detector=lambda: sources))
    state.justify_authenticated_fallback()
    state.disable_browser("edge", "DPAPI decryption failed")
    state.disable_browser("brave", "DPAPI decryption failed")

    assert state.next_authenticated_strategy().provider_id == "browser:firefox"
    assert state.next_authenticated_strategy() is None


def test_browser_cookie_extraction_error_is_not_auth_error():
    error = "ERROR: Could not copy Chrome cookie database. See https://github.com/yt-dlp/yt-dlp/issues"

    assert classify_browser_cookie_extraction_error(error) == BrowserCookieFailureKind.LOCKED
    assert is_browser_cookie_locked_error(error)
    assert not is_browser_cookie_decryption_error(error)
    assert is_browser_cookie_extraction_error(error)
    assert not is_authentication_error(error)
    assert clean_browser_cookie_extraction_error(error, "Chrome") == (
        "Chrome cookie database is locked. Close Chrome and try again."
    )


def test_dpapi_failure_has_distinct_category_and_never_recommends_node_or_browser_close():
    error = "ERROR: Failed to decrypt cookies with Windows DPAPI"

    assert classify_browser_cookie_extraction_error(error) == (
        BrowserCookieFailureKind.DECRYPTION_FAILED
    )
    assert is_browser_cookie_decryption_error(error)
    assert not is_browser_cookie_locked_error(error)

    message = clean_browser_cookie_extraction_error(error, "Edge")
    assert message == (
        "Browser cookie decryption failed for Edge. "
        "Try cookies.txt or another signed-in browser."
    )
    assert "close" not in message.lower()
    assert "node" not in message.lower()


def test_generic_browser_cookie_failure_has_concise_non_lock_message():
    message = clean_browser_cookie_failure(
        BrowserCookieFailureKind.EXTRACTION_FAILED,
        "Firefox",
    )

    assert message == (
        "Browser cookie extraction failed for Firefox. "
        "Try cookies.txt or another supported browser."
    )
    assert "close" not in message.lower()


def test_failed_to_load_cookies_is_browser_cookie_extraction_error():
    error = "ERROR: failed to load cookies"

    assert is_browser_cookie_extraction_error(error)
    assert not is_authentication_error(error)


def test_live_event_ended_is_not_auth_error():
    error = "ERROR: [youtube] abc123: This live event has ended."

    assert is_live_event_ended_error(error)
    assert not is_authentication_error(error)
    assert clean_live_event_ended_error() == (
        "This live event has ended and is not currently downloadable."
    )


def test_youtube_n_challenge_failure_is_not_auth_error():
    error = "WARNING: [youtube] n challenge solving failed. Only images are available."

    assert not is_authentication_error(error)
