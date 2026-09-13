from __future__ import annotations

import inspect
import sqlite3
from pathlib import Path

import pytest
import yt_dlp.cookies as ytdlp_cookies
from yt_dlp.version import __version__ as ytdlp_version

from openfetch.core import youtube_connection as connection_module
from openfetch.core.auth import (
    BrowserCookieFailureKind,
    classify_browser_cookie_extraction_error,
    resolve_auth_strategies,
)
from openfetch.core.youtube_connection import (
    ChromeDiscovery,
    ConnectionState,
    FirefoxDiscovery,
    ManagedBrowser,
    VerificationResult,
    YouTubeConnectionManager,
    dedicated_chrome_profile_path,
    validate_managed_profile_path,
)


class MemorySettings:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def value(self, key, default=None, **_kwargs):
        return self.values.get(key, default)

    def setValue(self, key, value):  # noqa: N802
        self.values[key] = value

    def remove(self, key):
        self.values.pop(key, None)

    def sync(self):
        return None


class FakeProcess:
    def __init__(self, pid=5001):
        self.pid = pid
        self.returncode = None

    def poll(self):
        return self.returncode


def executable(path: Path, name: str) -> Path:
    target = path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"MZ\x00\x00")
    return target


def chrome_manager(
    tmp_path: Path,
    *,
    settings=None,
    chrome=None,
    process=None,
    identities=None,
    process_tree=None,
):
    chrome = chrome or executable(tmp_path / "Chrome", "chrome.exe")
    process = process or FakeProcess()
    identities = identities if identities is not None else {process.pid: "chrome-root"}
    return YouTubeConnectionManager(
        settings or MemorySettings(),
        browser=ManagedBrowser.CHROME,
        application_data=tmp_path / "LocalAppData" / "OpenFetch",
        discovery=ChromeDiscovery(
            registry_reader=lambda: [chrome],
            environ={},
            binary_validator=lambda _path: True,
        ),
        popen_factory=lambda _argv, **_kwargs: process,
        identity_provider=lambda pid: identities.get(pid),
        process_tree_provider=process_tree or (lambda pid: [pid]),
    )


def write_chrome_cookie_database(profile: Path) -> None:
    database = profile / "Default" / "Network" / "Cookies"
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)"
        )
        connection.execute(
            "INSERT INTO cookies VALUES (?, ?, ?, ?)",
            (".youtube.com", "SAPISID", "secret-not-selected", b"v20-ciphertext"),
        )
        connection.commit()
    finally:
        connection.close()


def test_chrome_discovery_registry_user_program_files_stored_and_manual(tmp_path):
    registry = executable(tmp_path / "registry", "chrome.exe")
    user = executable(
        tmp_path / "Local" / "Google" / "Chrome" / "Application",
        "chrome.exe",
    )
    program_files = executable(
        tmp_path / "Program Files" / "Google" / "Chrome" / "Application",
        "chrome.exe",
    )

    discovery = ChromeDiscovery(
        registry_reader=lambda: [registry],
        environ={},
        binary_validator=lambda _path: True,
    )
    assert discovery.discover().source == "registry"
    assert discovery.discover(registry).source == "stored"
    assert discovery.validate_executable(registry) == registry.resolve()

    user_discovery = ChromeDiscovery(
        registry_reader=lambda: [],
        environ={"LOCALAPPDATA": str(tmp_path / "Local")},
        binary_validator=lambda _path: True,
    )
    assert user_discovery.discover().executable == user.resolve()
    assert user_discovery.discover().source == "user_install"

    program_discovery = ChromeDiscovery(
        registry_reader=lambda: [],
        environ={"ProgramFiles": str(tmp_path / "Program Files")},
        binary_validator=lambda _path: True,
    )
    assert program_discovery.discover().executable == program_files.resolve()
    assert program_discovery.discover().source == "standard_install"


def test_chrome_discovery_rejects_invalid_renamed_and_stale_stored_path(tmp_path):
    wrong_name = executable(tmp_path, "renamed.exe")
    renamed_non_chrome = executable(tmp_path / "fake", "chrome.exe")
    discovery = ChromeDiscovery(
        registry_reader=lambda: [wrong_name, renamed_non_chrome],
        environ={},
        binary_validator=lambda _path: False,
    )
    assert discovery.validate_executable(wrong_name) is None
    assert discovery.validate_executable(renamed_non_chrome) is None
    assert discovery.discover(tmp_path / "missing" / "chrome.exe").executable is None


def test_chrome_profile_is_exact_localappdata_child_and_normal_data_is_unchanged(tmp_path):
    normal_user_data = tmp_path / "Local" / "Google" / "Chrome" / "User Data"
    normal_user_data.mkdir(parents=True)
    normal_state = normal_user_data / "Local State"
    normal_state.write_text("normal-profile-unchanged", encoding="utf-8")
    before = normal_state.read_bytes()
    manager = chrome_manager(tmp_path)
    profile = manager.create_profile()

    assert profile == dedicated_chrome_profile_path(manager.application_data).resolve()
    assert profile.parent == (manager.application_data / "youtube").resolve()
    assert normal_state.read_bytes() == before
    assert not (profile / "Default").exists()


def test_chrome_profile_traversal_outside_root_and_reparse_are_rejected(tmp_path, monkeypatch):
    manager = chrome_manager(tmp_path)
    profile = manager.create_profile()
    for unsafe in (
        profile / ".." / "escape",
        manager.application_data / "youtube",
        manager.application_data,
        tmp_path.anchor,
    ):
        with pytest.raises(ValueError):
            validate_managed_profile_path(
                unsafe,
                browser=ManagedBrowser.CHROME,
                application_data=manager.application_data,
                require_exists=False,
            )
    outside = tmp_path / "outside" / "chrome-profile"
    outside.mkdir(parents=True)
    with pytest.raises(ValueError):
        validate_managed_profile_path(
            outside,
            browser=ManagedBrowser.CHROME,
            application_data=manager.application_data,
        )
    monkeypatch.setattr(connection_module, "_is_reparse_point", lambda path: path == profile)
    with pytest.raises(ValueError):
        validate_managed_profile_path(
            profile,
            browser=ManagedBrowser.CHROME,
            application_data=manager.application_data,
        )


def test_chrome_launch_is_argv_only_tracks_tree_and_never_uses_unsafe_flags(tmp_path):
    chrome = executable(tmp_path / "Chrome", "chrome.exe")
    process = FakeProcess()
    identities = {process.pid: "root", 5002: "child", 9000: "unrelated-normal-chrome"}
    captured = {}

    def popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return process

    manager = YouTubeConnectionManager(
        MemorySettings(),
        browser=ManagedBrowser.CHROME,
        application_data=tmp_path / "LocalAppData" / "OpenFetch",
        discovery=ChromeDiscovery(
            registry_reader=lambda: [chrome],
            environ={},
            binary_validator=lambda _path: True,
        ),
        popen_factory=popen,
        identity_provider=lambda pid: identities.get(pid),
        process_tree_provider=lambda _pid: [5001, 5002],
    )
    manager.launch("https://www.youtube.com/watch?v=abc&token=never-pass")

    argv = captured["argv"]
    assert captured["kwargs"]["shell"] is False
    assert argv[1] == f"--user-data-dir={manager.profile_path.resolve()}"
    assert "--new-window" in argv
    assert "--no-first-run" in argv
    assert "--no-default-browser-check" in argv
    assert not any("remote-debugging" in value for value in argv)
    assert "never-pass" not in " ".join(argv)
    assert set(manager._tracked_processes) == {5001, 5002}
    assert 9000 not in manager._tracked_processes

    process.returncode = 0
    identities.pop(5001)
    assert manager.browser_is_open()
    identities.pop(5002)
    assert not manager.browser_is_open()
    assert identities[9000] == "unrelated-normal-chrome"


def test_stale_lock_and_pid_reuse_recover_without_false_open(tmp_path):
    settings = MemorySettings()
    process = FakeProcess()
    identities = {process.pid: "original"}
    manager = chrome_manager(
        tmp_path,
        settings=settings,
        process=process,
        identities=identities,
    )
    manager.launch()
    marker = manager.profile_path / "SingletonLock"
    marker.write_text("leftover", encoding="utf-8")
    process.returncode = 0
    identities[process.pid] = "reused-pid"

    assert manager.refresh_browser_state() == ConnectionState.WAITING_FOR_LOGIN
    assert not marker.exists()
    assert "Recovered stale managed-browser profile state." in manager.events


def test_restart_recognizes_only_exact_persisted_process_identity(tmp_path):
    settings = MemorySettings()
    process = FakeProcess()
    identities = {process.pid: "original", 7777: "unrelated"}
    first = chrome_manager(tmp_path, settings=settings, process=process, identities=identities)
    first.launch()
    second = chrome_manager(tmp_path, settings=settings, identities=identities)
    assert second.browser_is_open()

    identities[process.pid] = "pid-reused"
    assert not second.browser_is_open()
    assert identities[7777] == "unrelated"


def test_inconclusive_process_probe_fails_safe_without_deleting_live_lock(tmp_path):
    chrome = executable(tmp_path / "Chrome", "chrome.exe")
    process = FakeProcess()
    denied = False

    def identity_provider(_pid):
        if denied:
            raise PermissionError("process query denied")
        return "managed-process"

    manager = YouTubeConnectionManager(
        MemorySettings(),
        browser=ManagedBrowser.CHROME,
        application_data=tmp_path / "LocalAppData" / "OpenFetch",
        discovery=ChromeDiscovery(
            registry_reader=lambda: [chrome],
            environ={},
            binary_validator=lambda _path: True,
        ),
        popen_factory=lambda _argv, **_kwargs: process,
        identity_provider=identity_provider,
        process_tree_provider=lambda pid: [pid],
    )
    manager.launch()
    marker = manager.profile_path / "SingletonLock"
    marker.write_text("possibly-live", encoding="utf-8")
    denied = True
    result = manager.disconnect()
    assert not result.success
    assert result.code == "process_state_unknown"
    assert marker.exists()
    assert manager.profile_path.exists()


def test_stale_marker_allows_verification_but_validated_live_process_blocks(tmp_path):
    process = FakeProcess()
    identities = {process.pid: "root"}
    manager = chrome_manager(tmp_path, process=process, identities=identities)
    profile = manager.create_profile()
    write_chrome_cookie_database(profile)
    marker = profile / "SingletonLock"
    marker.write_text("stale", encoding="utf-8")
    manager.refresh_browser_state()
    called = []
    result = manager.verify(
        lambda checked, _url: (
            called.append(checked)
            or VerificationResult(True, "connected", "verified")
        ),
        "https://www.youtube.com/watch?v=offline",
    )
    assert result.success
    assert called == [profile]

    manager.launch()
    blocked = manager.verify(
        lambda *_args: VerificationResult(True, "connected", "should not run"),
        "https://www.youtube.com/",
    )
    assert blocked.code == "browser_open"
    assert "Close the dedicated Google Chrome" in blocked.message
    assert not manager.disconnect().success


def test_chrome_structured_cookie_option_is_fixed_to_dedicated_default_profile(tmp_path):
    manager = chrome_manager(tmp_path)
    profile = manager.create_profile()
    resolution = resolve_auth_strategies(
        None,
        browser_detector=lambda: [],
        dedicated_browser="chrome",
        dedicated_browser_profile=profile,
        dedicated_application_data=manager.application_data,
        allow_legacy_browser_fallback=False,
    )
    dedicated = resolution.strategies[1]
    assert dedicated.kind == "dedicated_browser"
    assert dedicated.ydl_options["cookiesfrombrowser"] == (
        "chrome",
        str(profile / "Default"),
    )
    assert "Google\\Chrome\\User Data" not in repr(dedicated.ydl_options)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Could not copy Chrome cookie database", BrowserCookieFailureKind.LOCKED),
        ("Failed to decrypt with DPAPI", BrowserCookieFailureKind.DECRYPTION_FAILED),
        ("Chrome app-bound encryption v20 is unsupported", BrowserCookieFailureKind.UNSUPPORTED),
        ("Failed to load cookies from browser", BrowserCookieFailureKind.EXTRACTION_FAILED),
    ],
)
def test_chrome_cookie_failures_are_classified_separately(message, expected):
    assert classify_browser_cookie_extraction_error(message) == expected


def test_bundled_ytdlp_chrome_gate_is_explicit_about_missing_v20_support():
    decryptor_source = inspect.getsource(ytdlp_cookies.WindowsChromeCookieDecryptor.decrypt)
    assert ytdlp_version == "2026.07.04"
    assert "b'v10'" in decryptor_source
    assert "b'v20'" not in decryptor_source


def test_unsupported_chrome_verification_never_marks_connected_and_firefox_is_preserved(tmp_path):
    settings = MemorySettings()
    chrome = chrome_manager(tmp_path, settings=settings)
    chrome_profile = chrome.create_profile()
    write_chrome_cookie_database(chrome_profile)
    result = chrome.verify(
        lambda *_args: VerificationResult(
            False,
            "cookie_decryption_failed",
            "Chrome session could not be read securely. Try the managed Firefox connection.",
        ),
        "https://www.youtube.com/",
    )
    assert not result.success
    assert chrome.state == ConnectionState.ERROR
    assert chrome.connected_profile() is None

    firefox_exe = executable(tmp_path / "Firefox", "firefox.exe")
    firefox = YouTubeConnectionManager(
        settings,
        browser=ManagedBrowser.FIREFOX,
        application_data=chrome.application_data,
        discovery=FirefoxDiscovery(
            registry_reader=lambda: [firefox_exe],
            environ={},
            binary_validator=lambda _path: True,
        ),
    )
    firefox_profile = firefox.create_profile()
    assert firefox_profile.exists()
    assert chrome.disconnect().success
    assert firefox_profile.exists()


def test_v305_firefox_settings_migrate_by_preservation_while_chrome_defaults_new(tmp_path):
    application_data = tmp_path / "LocalAppData" / "OpenFetch"
    firefox_profile = application_data / "youtube" / "firefox-profile"
    firefox_profile.mkdir(parents=True)
    settings = MemorySettings(
        {
            "youtube_connection/state": "connected",
            "youtube_connection/profile_path": str(firefox_profile),
            "youtube_connection/last_verified": "2026-07-20T10:00:00+00:00",
        }
    )
    firefox = YouTubeConnectionManager(
        settings,
        browser=ManagedBrowser.FIREFOX,
        application_data=application_data,
    )
    chrome = chrome_manager(tmp_path, settings=settings)
    assert firefox.state == ConnectionState.CONNECTED
    assert firefox.connected_profile() == firefox_profile.resolve()
    assert chrome.state == ConnectionState.NOT_CONFIGURED
    assert chrome.profile_path.name == "chrome-profile"
    assert firefox_profile.exists()
