"""Offline packaged smoke for the guided YouTube connection components."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from openfetch.core.youtube_connection import (
    ACTIVE_PROVIDER_KEY,
    ChromeDiscovery,
    FirefoxDiscovery,
    ManagedBrowser,
    VerificationResult,
    YouTubeConnectionManager,
    dedicated_browser_profile_path,
    validate_managed_profile_path,
)


class _MemorySettings:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {}

    def value(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def setValue(self, key: str, value: Any) -> None:  # noqa: N802
        self.values[key] = value

    def remove(self, key: str) -> None:
        self.values.pop(key, None)

    def sync(self) -> None:
        return None


class _FakeProcess:
    pid = 4545

    def __init__(self) -> None:
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode


def _managed_profile_path_is_safe(
    profile: Path,
    application_data: Path,
    browser: ManagedBrowser,
) -> bool:
    """Confirm the manager returned the validator's canonical fixed profile."""
    try:
        validated = validate_managed_profile_path(
            profile,
            browser=browser,
            application_data=application_data,
        )
        expected = dedicated_browser_profile_path(browser, application_data).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return profile == validated == expected


def _run_offline_youtube_connection_smoke_at_root(root: Path) -> dict[str, bool]:
    """Run the offline contract below a caller-owned isolated test root."""
    from openfetch.core.auth import resolve_auth_strategies

    application_data = root / "LocalAppData" / "OpenFetch"
    chrome = root / "Google" / "Chrome" / "Application" / "chrome.exe"
    firefox = root / "Mozilla Firefox" / "firefox.exe"
    chrome.parent.mkdir(parents=True)
    chrome.write_bytes(b"MZ\x00\x00")
    firefox.parent.mkdir(parents=True)
    firefox.write_bytes(b"MZ\x00\x00")
    process = _FakeProcess()
    captured: dict[str, Any] = {}

    def popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return process

    settings = _MemorySettings()
    manager = YouTubeConnectionManager(
        settings,
        browser=ManagedBrowser.CHROME,
        application_data=application_data,
        discovery=ChromeDiscovery(
            registry_reader=lambda: [chrome],
            environ={},
            binary_validator=lambda _path: True,
        ),
        popen_factory=popen,
        identity_provider=lambda _pid: "packaged-smoke-identity",
    )
    profile = manager.create_profile()
    profile_path_safe = _managed_profile_path_is_safe(
        profile,
        application_data,
        ManagedBrowser.CHROME,
    )
    traversal_rejected = False
    try:
        validate_managed_profile_path(
            profile / ".." / "escape",
            browser=ManagedBrowser.CHROME,
            application_data=application_data,
            require_exists=False,
        )
    except ValueError:
        traversal_rejected = True

    manager.launch("https://www.youtube.com/watch?v=offline&token=must-not-appear")
    command = list(captured["command"])
    launch_safe = (
        captured["kwargs"].get("shell") is False
        and command[1] == f"--user-data-dir={profile}"
        and command[2:5] == [
            "--new-window",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        and not any("remote-debugging" in item for item in command)
        and "must-not-appear" not in " ".join(command)
    )
    process.returncode = 0
    manager.refresh_browser_state()

    stale_marker = profile / "SingletonLock"
    stale_marker.write_text("stale", encoding="utf-8")
    manager.refresh_browser_state()
    stale_recovered = (
        manager.recover_stale_state() or not stale_marker.exists()
    ) and not stale_marker.exists()
    stale_recovery_logged = "Recovered stale managed-browser profile state." in manager.events

    cookie_path = profile / "Default" / "Network" / "Cookies"
    cookie_path.parent.mkdir(parents=True)
    cookie_database = sqlite3.connect(cookie_path)
    try:
        connection = cookie_database
        connection.execute(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)"
        )
        connection.execute(
            "INSERT INTO cookies VALUES (?, ?, ?, ?)",
            (".youtube.com", "SAPISID", "never-log-this-cookie", b"v20-not-read"),
        )
        connection.commit()
    finally:
        cookie_database.close()
    verified = manager.verify(
        lambda checked_profile, _url: VerificationResult(
            checked_profile == profile,
            "connected",
            "YouTube session verified.",
        ),
        "https://www.youtube.com/watch?v=offline",
    )
    chrome_became_active = settings.value(ACTIVE_PROVIDER_KEY) == "chrome"
    manager.mark_expired("cookies are no longer valid")
    renewal_reused_profile = manager.create_profile() == profile
    chrome_resolution = resolve_auth_strategies(
        None,
        browser_detector=lambda: [],
        dedicated_browser="chrome",
        dedicated_browser_profile=profile,
        dedicated_application_data=application_data,
        allow_legacy_browser_fallback=False,
    )
    chrome_strategy = next(
        (item for item in chrome_resolution.strategies if item.is_dedicated_browser),
        None,
    )
    chrome_authenticated_options = chrome_strategy is not None and chrome_strategy.ydl_options.get(
        "cookiesfrombrowser"
    ) == ("chrome", str(profile / "Default"))
    firefox_manager = YouTubeConnectionManager(
        settings,
        browser=ManagedBrowser.FIREFOX,
        application_data=application_data,
        discovery=FirefoxDiscovery(
            registry_reader=lambda: [firefox],
            environ={},
            binary_validator=lambda _path: True,
        ),
        popen_factory=lambda _command, **_kwargs: _FakeProcess(),
        identity_provider=lambda _pid: None,
    )
    firefox_profile = firefox_manager.create_profile()
    firefox_database = sqlite3.connect(firefox_profile / "cookies.sqlite")
    try:
        firefox_database.execute(
            "CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT)"
        )
        firefox_database.execute(
            "INSERT INTO moz_cookies VALUES (?, ?, ?)",
            (".youtube.com", "SAPISID", "never-log-firefox-cookie"),
        )
        firefox_database.commit()
    finally:
        firefox_database.close()
    firefox_verified = firefox_manager.verify(
        lambda checked_profile, _url: VerificationResult(
            checked_profile == firefox_profile,
            "connected",
            "YouTube session verified.",
        ),
        "https://www.youtube.com/watch?v=offline",
    )
    firefox_became_active = settings.value(ACTIVE_PROVIDER_KEY) == "firefox"
    firefox_resolution = resolve_auth_strategies(
        None,
        browser_detector=lambda: [],
        dedicated_browser="firefox",
        dedicated_browser_profile=firefox_profile,
        dedicated_application_data=application_data,
        allow_legacy_browser_fallback=False,
    )
    firefox_strategy = next(
        (item for item in firefox_resolution.strategies if item.is_dedicated_browser),
        None,
    )
    firefox_authenticated_options = (
        firefox_strategy is not None
        and firefox_strategy.ydl_options.get("cookiesfrombrowser")
        == ("firefox", str(firefox_profile))
    )
    disconnected = manager.disconnect()
    nonactive_disconnect_preserved_firefox = (
        disconnected.success and settings.value(ACTIVE_PROVIDER_KEY) == "firefox"
    )
    firefox_preserved_separately = (
        firefox_profile.name == "firefox-profile"
        and firefox_profile != profile
        and firefox_manager.disconnect().success
    )
    settings_dump = repr(settings.values)
    settings_private = (
        "never-log-this-cookie" not in settings_dump
        and "never-log-firefox-cookie" not in settings_dump
    )
    return {
        "profile_path_safe": profile_path_safe,
        "path_traversal_rejected": traversal_rejected,
        "launch_arguments_safe": launch_safe,
        "stale_profile_state_recovered": stale_recovered,
        "stale_recovery_logged": stale_recovery_logged,
        "authentication_state_machine": verified.success,
        "chrome_became_active": chrome_became_active,
        "firefox_became_active": firefox_verified.success and firefox_became_active,
        "nonactive_disconnect_preserved_active_provider": nonactive_disconnect_preserved_firefox,
        "chrome_authenticated_options": chrome_authenticated_options,
        "firefox_authenticated_options": firefox_authenticated_options,
        "firefox_fallback_separate": firefox_preserved_separately,
        "renewal_reused_profile": renewal_reused_profile,
        "disconnect_safe": disconnected.success and not profile.exists(),
        "settings_private": settings_private,
    }


def run_offline_youtube_connection_smoke() -> dict[str, bool]:
    """Exercise safety, argv, state, renewal, and disconnect without network/browser use."""
    with tempfile.TemporaryDirectory(prefix="openfetch-youtube-smoke-") as temporary:
        return _run_offline_youtube_connection_smoke_at_root(Path(temporary))


__all__ = ["run_offline_youtube_connection_smoke"]
