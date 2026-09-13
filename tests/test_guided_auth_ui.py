from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from openfetch.core import youtube_connection as connection_module
from openfetch.core.youtube_connection import (
    ACTIVE_PROVIDER_KEY,
    ConnectionState,
    ManagedBrowser,
)
from openfetch.gui import main_window as gui_module
from openfetch.models import DownloadJob


@pytest.fixture
def main_window(tmp_path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    application = QApplication.instance() or QApplication([])
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    monkeypatch.setattr(gui_module, "QSettings", lambda *_args: settings)
    monkeypatch.setattr(connection_module, "app_data_dir", lambda: tmp_path / "app-data")
    monkeypatch.setattr(
        gui_module,
        "ensure_youtube_js_runtime",
        lambda: SimpleNamespace(found=True, diagnostic="JavaScript runtime found for test"),
    )
    window = gui_module.MainWindow()
    yield application, window
    window.close()
    settings.clear()


def _mark_connected(window, browser, verified_at):
    manager = window.youtube_connections[browser]
    profile = manager.create_profile()
    manager.last_verified = verified_at
    manager.settings.setValue(manager._key("last_verified"), verified_at)
    manager._set_state(ConnectionState.CONNECTED)
    return manager, profile


def test_authentication_required_jobs_open_one_assistant_and_resume_originals(main_window):
    application, window = main_window
    first = DownloadJob("https://www.youtube.com/watch?v=first")
    second = DownloadJob("https://www.youtube.com/watch?v=second")
    window._append_job(first)
    window._append_job(second)
    prompts = []
    resumes = []
    window.connect_youtube = lambda **kwargs: prompts.append(kwargs) or True
    window._resume_authenticated_jobs = lambda: resumes.append(True)

    window.on_job_finished(first.job_id, False, "Authentication required", "authentication_required")
    window.on_job_finished(second.job_id, False, "Authentication required", "authentication_required")
    application.processEvents()
    application.processEvents()

    assert len(prompts) == 1
    assert window.table.item(window.row_by_job_id[first.job_id], 2).text() == "Queued"
    assert window.table.item(window.row_by_job_id[second.job_id], 2).text() == "Queued"
    assert window._auth_retry_counts[first.job_id] == 1
    assert window._auth_retry_counts[second.job_id] == 1
    assert resumes

    window.on_job_finished(first.job_id, False, "Authentication required", "authentication_required")
    application.processEvents()
    assert len(prompts) == 1


def test_cancelled_connection_does_not_resume_original_job(main_window):
    application, window = main_window
    job = DownloadJob("https://www.youtube.com/watch?v=cancelled")
    window._append_job(job)
    resumes = []
    window.connect_youtube = lambda **_kwargs: False
    window._resume_authenticated_jobs = lambda: resumes.append(True)

    window.on_job_finished(job.job_id, False, "Authentication required", "authentication_required")
    application.processEvents()
    application.processEvents()

    row = window.row_by_job_id[job.job_id]
    assert window.table.item(row, 2).text() == "Failed"
    assert "cancelled" in window.table.item(row, 4).text().casefold()
    assert not resumes


def test_explicit_active_provider_selects_exact_firefox_session_not_first_connected(
    main_window,
):
    _application, window = main_window
    now = datetime.now(UTC).isoformat(timespec="seconds")
    chrome, _chrome_profile = _mark_connected(window, ManagedBrowser.CHROME, now)
    firefox, firefox_profile = _mark_connected(window, ManagedBrowser.FIREFOX, now)
    window.settings.setValue(ACTIVE_PROVIDER_KEY, ManagedBrowser.FIREFOX.value)
    window.settings.sync()

    assert window._active_connection_manager() is firefox
    assert window._connected_connection_manager() is firefox
    assert window._connected_connection_manager() is not chrome
    options = window._collect_options()
    assert options.dedicated_browser == ManagedBrowser.FIREFOX.value
    assert options.dedicated_browser_profile == firefox_profile
    assert options.dedicated_browser_last_verified == now


def test_invalid_explicit_active_provider_fails_closed_without_browser_fallback(
    main_window,
):
    _application, window = main_window
    now = datetime.now(UTC).isoformat(timespec="seconds")
    _mark_connected(window, ManagedBrowser.CHROME, now)
    _mark_connected(window, ManagedBrowser.FIREFOX, now)
    window.settings.setValue(ACTIVE_PROVIDER_KEY, "unreviewed-browser")
    window.settings.sync()

    assert window._active_connection_manager() is None
    assert window._connected_connection_manager() is None
    options = window._collect_options()
    assert options.dedicated_browser is None
    assert options.dedicated_browser_profile is None
    assert options.dedicated_browser_last_verified is None
    assert window.settings.value(ACTIVE_PROVIDER_KEY) == "unreviewed-browser"


def test_legacy_state_migration_uses_only_a_strictly_newer_verified_provider(
    main_window,
):
    _application, window = main_window
    now = datetime.now(UTC)
    chrome, _chrome_profile = _mark_connected(
        window,
        ManagedBrowser.CHROME,
        (now - timedelta(minutes=5)).isoformat(timespec="seconds"),
    )
    firefox, _firefox_profile = _mark_connected(
        window,
        ManagedBrowser.FIREFOX,
        now.isoformat(timespec="seconds"),
    )
    window.settings.remove(ACTIVE_PROVIDER_KEY)
    window.settings.sync()

    assert window._active_connection_manager() is firefox
    assert window._active_connection_manager() is not chrome
    assert window.settings.value(ACTIVE_PROVIDER_KEY) == ManagedBrowser.FIREFOX.value


def test_legacy_state_migration_fails_closed_when_verified_timestamps_tie(main_window):
    _application, window = main_window
    verified_at = datetime.now(UTC).isoformat(timespec="seconds")
    _mark_connected(window, ManagedBrowser.CHROME, verified_at)
    _mark_connected(window, ManagedBrowser.FIREFOX, verified_at)
    window.settings.remove(ACTIVE_PROVIDER_KEY)
    window.settings.sync()

    assert window._active_connection_manager() is None
    assert window._connected_connection_manager() is None
    assert window.settings.value(ACTIVE_PROVIDER_KEY) is None


def test_verified_media_403_is_shown_verbatim_without_opening_login_assistant(
    main_window,
):
    application, window = main_window
    job = DownloadJob("https://www.youtube.com/watch?v=media403")
    window._append_job(job)
    prompts = []
    window.connect_youtube = lambda **kwargs: prompts.append(kwargs) or True
    message = (
        "The browser session is valid, but YouTube rejected the media request. "
        "A PO Token may be required."
    )

    window.on_job_finished(job.job_id, False, message, "verified_session_media_403")
    application.processEvents()

    row = window.row_by_job_id[job.job_id]
    assert window.table.item(row, 2).text() == "Failed"
    assert window.table.item(row, 4).text() == message
    assert not prompts
