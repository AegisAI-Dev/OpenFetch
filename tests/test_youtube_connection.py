from __future__ import annotations

import ctypes
import os
import sqlite3
from pathlib import Path

import pytest

from openfetch.config import app_data_dir
from openfetch.core import youtube_connection as connection_module
from openfetch.core import youtube_connection_smoke as smoke_module
from openfetch.core.youtube_connection import (
    ACTIVE_PROVIDER_KEY,
    ConnectionState,
    FirefoxDiscovery,
    ManagedBrowser,
    VerificationResult,
    YouTubeConnectionManager,
    dedicated_firefox_profile_path,
    inspect_youtube_session_cookies,
    validate_dedicated_profile_path,
)
from openfetch.core.youtube_connection_smoke import (
    run_offline_youtube_connection_smoke,
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
    def __init__(self, pid=4321):
        self.pid = pid
        self.returncode = None

    def poll(self):
        return self.returncode


def firefox_executable(path: Path, *, valid=True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ\x00\x00" if valid else b"not-a-windows-binary")
    return path


def manager_for(
    tmp_path,
    *,
    settings=None,
    registry_paths=(),
    popen_factory=None,
    application_data=None,
):
    discovery = FirefoxDiscovery(
        registry_reader=lambda: list(registry_paths),
        environ={},
        binary_validator=lambda _path: True,
    )
    return YouTubeConnectionManager(
        settings or MemorySettings(),
        application_data=(
            application_data
            if application_data is not None
            else tmp_path / "LocalAppData" / "OpenFetch"
        ),
        discovery=discovery,
        popen_factory=popen_factory or (lambda *_args, **_kwargs: FakeProcess()),
        identity_provider=lambda _pid: "creation-identity",
    )


def windows_short_path(path: Path) -> Path:
    buffer = ctypes.create_unicode_buffer(32_768)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise OSError(ctypes.get_last_error(), "Windows short-path lookup failed")
    return Path(buffer.value)


def write_cookie_database(profile: Path, *, authenticated: bool) -> None:
    database = profile / "cookies.sqlite"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT)")
        if authenticated:
            connection.execute(
                "INSERT INTO moz_cookies VALUES (?, ?, ?)",
                (".youtube.com", "SAPISID", "super-secret-session-value"),
            )
        else:
            connection.execute(
                "INSERT INTO moz_cookies VALUES (?, ?, ?)",
                (".youtube.com", "PREF", "not-an-auth-cookie"),
            )
        connection.commit()
    finally:
        connection.close()


def test_firefox_discovery_accepts_registry_and_standard_install_paths(tmp_path):
    registry_firefox = firefox_executable(tmp_path / "registry" / "firefox.exe")
    result = FirefoxDiscovery(
        registry_reader=lambda: [registry_firefox],
        environ={},
        binary_validator=lambda _path: True,
    ).discover()
    assert result.executable == registry_firefox.resolve()
    assert result.source == "registry"

    standard = firefox_executable(tmp_path / "Program Files" / "Mozilla Firefox" / "firefox.exe")
    result = FirefoxDiscovery(
        registry_reader=lambda: [],
        environ={"ProgramFiles": str(tmp_path / "Program Files")},
        binary_validator=lambda _path: True,
    ).discover()
    assert result.executable == standard.resolve()
    assert result.source == "standard_install"


def test_firefox_discovery_rejects_arbitrary_or_stale_executables(tmp_path):
    arbitrary = firefox_executable(tmp_path / "malware.exe")
    fake_firefox = firefox_executable(tmp_path / "firefox.exe", valid=False)
    discovery = FirefoxDiscovery(
        registry_reader=lambda: [arbitrary, fake_firefox],
        environ={},
        binary_validator=lambda _path: True,
    )
    assert discovery.discover().executable is None
    assert discovery.validate_executable(arbitrary) is None
    assert discovery.validate_executable(fake_firefox) is None
    renamed_non_firefox = firefox_executable(tmp_path / "renamed" / "firefox.exe")
    strict = FirefoxDiscovery(
        registry_reader=lambda: [renamed_non_firefox],
        environ={},
        binary_validator=lambda _path: False,
    )
    assert strict.discover().executable is None


def test_user_selected_firefox_is_validated_and_revalidated(tmp_path):
    executable = firefox_executable(tmp_path / "selected" / "firefox.exe")
    settings = MemorySettings()
    manager = manager_for(tmp_path, settings=settings)
    assert manager.set_firefox_path(executable)
    assert settings.values["youtube_connection/firefox_path"] == str(executable.resolve())
    executable.unlink()
    assert manager.discover_firefox().executable is None
    assert manager.state == ConnectionState.FIREFOX_MISSING


def test_profile_creation_is_fixed_to_local_appdata_and_does_not_touch_normal_firefox(tmp_path):
    roaming = tmp_path / "AppData" / "Roaming" / "Mozilla" / "Firefox"
    roaming.mkdir(parents=True)
    profiles_ini = roaming / "profiles.ini"
    profiles_ini.write_text("[Profile0]\nPath=Profiles/default\n", encoding="utf-8")
    before = profiles_ini.read_bytes()

    manager = manager_for(tmp_path)
    profile = manager.create_profile()

    assert profile == dedicated_firefox_profile_path(manager.application_data).resolve()
    assert profile.parent == (manager.application_data / "youtube").resolve()
    assert profiles_ini.read_bytes() == before
    assert not (roaming / "Profiles" / "firefox-profile").exists()


def test_mocked_windows_localappdata_root_is_used_consistently(tmp_path, monkeypatch):
    local_app_data = tmp_path / "Users" / "runneradmin" / "AppData" / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    application_data = app_data_dir()
    manager = manager_for(tmp_path, application_data=application_data)

    profile = manager.create_profile()

    expected = (
        local_app_data
        / "OpenFetch"
        / "youtube"
        / "firefox-profile"
    ).resolve()
    assert application_data.resolve() == (local_app_data / "OpenFetch").resolve()
    assert profile == expected
    assert validate_dedicated_profile_path(
        profile,
        application_data=application_data,
    ) == expected


@pytest.mark.skipif(os.name != "nt", reason="Windows path casing semantics")
def test_windows_path_case_differences_do_not_reject_managed_profile(tmp_path):
    manager = manager_for(
        tmp_path,
        application_data=(
            tmp_path
            / "Users"
            / "RunnerAdmin"
            / "AppData"
            / "Local"
            / "OpenFetch"
        ),
    )
    profile = manager.create_profile()
    case_variant_profile = Path(str(profile).swapcase())
    case_variant_application_data = Path(str(manager.application_data).swapcase())

    assert validate_dedicated_profile_path(
        case_variant_profile,
        application_data=case_variant_application_data,
    ) == profile


@pytest.mark.skipif(os.name != "nt", reason="Windows 8.3 path alias reproduction")
def test_offline_smoke_accepts_canonicalized_windows_runner_temp_alias(tmp_path):
    canonical_root = tmp_path / "runneradmin"
    canonical_root.mkdir()
    runner_alias = windows_short_path(canonical_root)
    raw_expected_parent = (
        runner_alias / "LocalAppData" / "OpenFetch" / "youtube"
    )
    assert raw_expected_parent != raw_expected_parent.resolve()

    results = smoke_module._run_offline_youtube_connection_smoke_at_root(
        runner_alias
    )

    assert results["profile_path_safe"] is True
    assert all(results.values())


def test_profile_path_traversal_root_and_reparse_are_rejected(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    profile = manager.create_profile()
    with pytest.raises(ValueError):
        validate_dedicated_profile_path(
            profile / ".." / "outside",
            application_data=manager.application_data,
            require_exists=False,
        )
    with pytest.raises(ValueError):
        validate_dedicated_profile_path(
            manager.application_data / "youtube",
            application_data=manager.application_data,
            require_exists=False,
        )
    with pytest.raises(ValueError):
        validate_dedicated_profile_path(
            manager.application_data,
            application_data=manager.application_data,
            require_exists=False,
        )
    outside = tmp_path / "outside" / "firefox-profile"
    outside.mkdir(parents=True)
    with pytest.raises(ValueError):
        validate_dedicated_profile_path(
            outside,
            application_data=manager.application_data,
        )

    monkeypatch.setattr(connection_module, "_is_reparse_point", lambda path: path == profile)
    with pytest.raises(ValueError):
        validate_dedicated_profile_path(profile, application_data=manager.application_data)

    monkeypatch.setattr(
        connection_module,
        "_is_reparse_point",
        lambda path: path == manager.application_data,
    )
    with pytest.raises(ValueError):
        validate_dedicated_profile_path(profile, application_data=manager.application_data)


def test_launch_uses_argv_shell_false_tracks_identity_and_strips_sensitive_query(tmp_path):
    executable = firefox_executable(tmp_path / "Firefox" / "firefox.exe")
    captured = {}
    process = FakeProcess()

    def popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return process

    manager = manager_for(tmp_path, registry_paths=[executable], popen_factory=popen)
    identity = manager.launch(
        "https://www.youtube.com/watch?v=abc123&token=secret&authorization=hidden"
    )

    command = captured["command"]
    assert command[:4] == [
        str(executable.resolve()),
        "-no-remote",
        "-profile",
        str(manager.profile_path.resolve()),
    ]
    assert captured["kwargs"]["shell"] is False
    assert "secret" not in " ".join(command)
    assert "hidden" not in " ".join(command)
    assert identity.pid == process.pid
    assert identity.creation_identity == "creation-identity"
    assert manager.browser_is_open()

    process.returncode = 0
    assert manager.refresh_browser_state() == ConnectionState.WAITING_FOR_LOGIN


def test_browser_open_state_recovers_after_restart_from_profile_lock(tmp_path):
    settings = MemorySettings({"youtube_connection/state": "browser_open"})
    first = manager_for(tmp_path, settings=settings)
    profile = first.create_profile()
    (profile / "parent.lock").write_text("locked", encoding="utf-8")
    settings.setValue("youtube_connection/state", "browser_open")
    second = manager_for(tmp_path, settings=settings)
    assert second.state == ConnectionState.WAITING_FOR_LOGIN
    assert not (profile / "parent.lock").exists()
    assert "Recovered stale managed-browser profile state." in second.events


def test_cookies_database_alone_never_marks_connection_verified(tmp_path):
    manager = manager_for(tmp_path)
    profile = manager.create_profile()
    write_cookie_database(profile, authenticated=False)
    called = False

    def verifier(_profile, _url):
        nonlocal called
        called = True
        return VerificationResult(True, "connected", "verified")

    result = manager.verify(verifier, "https://www.youtube.com/watch?v=abc")
    assert not result.success
    assert result.code == "sign_in_incomplete"
    assert not called
    assert manager.state == ConnectionState.INVALID


def test_successful_preflight_marks_connected_and_expiry_reuses_same_profile(tmp_path):
    settings = MemorySettings({ACTIVE_PROVIDER_KEY: ManagedBrowser.CHROME.value})
    manager = manager_for(tmp_path, settings=settings)
    profile = manager.create_profile()
    write_cookie_database(profile, authenticated=True)
    seen = []

    def success(verified_profile, url):
        seen.append((verified_profile, url))
        return VerificationResult(True, "connected", "YouTube session verified.")

    result = manager.verify(success, "https://www.youtube.com/watch?v=abc")
    assert result.success
    assert manager.state == ConnectionState.CONNECTED
    assert manager.connected_profile() == profile
    assert manager.last_verified
    assert settings.values[ACTIVE_PROVIDER_KEY] == ManagedBrowser.FIREFOX.value

    manager.mark_expired("cookies are no longer valid: cookie=secret")
    assert manager.state == ConnectionState.EXPIRED
    assert "secret" not in manager.failure_reason
    assert manager.create_profile() == profile
    assert seen[0][0] == profile


def test_failed_preflight_never_replaces_the_last_verified_provider(tmp_path):
    settings = MemorySettings({ACTIVE_PROVIDER_KEY: ManagedBrowser.CHROME.value})
    manager = manager_for(tmp_path, settings=settings)
    profile = manager.create_profile()
    write_cookie_database(profile, authenticated=True)

    result = manager.verify(
        lambda _profile, _url: VerificationResult(
            False,
            "session_rejected",
            "session rejected",
        ),
        "https://www.youtube.com/watch?v=abc",
    )

    assert not result.success
    assert manager.state == ConnectionState.EXPIRED
    assert settings.values[ACTIVE_PROVIDER_KEY] == ManagedBrowser.CHROME.value


def test_cookie_values_are_never_returned_or_stored(tmp_path):
    settings = MemorySettings()
    manager = manager_for(tmp_path, settings=settings)
    profile = manager.create_profile()
    write_cookie_database(profile, authenticated=True)
    valid, reason = inspect_youtube_session_cookies(profile)
    assert valid
    assert "super-secret-session-value" not in reason
    assert "super-secret-session-value" not in repr(settings.values)


def test_disconnect_deletes_only_managed_profile_and_keeps_firefox_path_and_cookies_txt(tmp_path):
    executable = firefox_executable(tmp_path / "Firefox" / "firefox.exe")
    settings = MemorySettings()
    manager = manager_for(tmp_path, settings=settings, registry_paths=[executable])
    manager.set_firefox_path(executable)
    profile = manager.create_profile()
    settings.setValue(ACTIVE_PROVIDER_KEY, ManagedBrowser.FIREFOX.value)
    (profile / "owned.txt").write_text("owned", encoding="utf-8")
    cookie_file = tmp_path / "cookies.txt"
    cookie_file.write_text("advanced fallback", encoding="utf-8")
    normal_profile = tmp_path / "normal-firefox-profile"
    normal_profile.mkdir()

    result = manager.disconnect()
    assert result.success
    assert not profile.exists()
    assert normal_profile.exists()
    assert cookie_file.exists()
    assert settings.values["youtube_connection/firefox_path"] == str(executable.resolve())
    assert "youtube_connection/profile_path" not in settings.values
    assert ACTIVE_PROVIDER_KEY not in settings.values


def test_disconnect_does_not_clear_another_verified_provider(tmp_path):
    settings = MemorySettings({ACTIVE_PROVIDER_KEY: ManagedBrowser.CHROME.value})
    firefox = manager_for(tmp_path, settings=settings)
    firefox.create_profile()

    result = firefox.disconnect()

    assert result.success
    assert settings.values[ACTIVE_PROVIDER_KEY] == ManagedBrowser.CHROME.value


def test_locked_or_failed_disconnect_preserves_recoverable_profile(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    profile = manager.create_profile()
    lock = profile / "parent.lock"
    lock.write_text("locked", encoding="utf-8")
    result = manager.disconnect()
    assert result.success
    assert not profile.exists()

    profile = manager.create_profile()
    monkeypatch.setattr(connection_module.shutil, "rmtree", lambda _path: (_ for _ in ()).throw(PermissionError()))
    result = manager.disconnect()
    assert not result.success
    assert result.manual_cleanup_path == profile
    assert profile.exists()


def test_disconnect_rejects_reparse_content_without_deleting_profile(tmp_path, monkeypatch):
    manager = manager_for(tmp_path)
    profile = manager.create_profile()
    escape = profile / "escape"
    escape.mkdir()
    monkeypatch.setattr(connection_module, "_is_reparse_point", lambda path: path == escape)
    result = manager.disconnect()
    assert not result.success
    assert profile.exists()


def test_offline_packaged_connection_smoke_contract():
    results = run_offline_youtube_connection_smoke()
    assert results
    assert all(results.values())
