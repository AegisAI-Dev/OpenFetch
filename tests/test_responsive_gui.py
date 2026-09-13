from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QRect, QSettings, QSize
from PySide6.QtWidgets import QApplication, QFileDialog

from openfetch.core import youtube_connection as connection_module
from openfetch.core.pot_provider import PoTokenProviderStatus
from openfetch.core.youtube_connection import (
    ChromeDiscovery,
    ManagedBrowser,
    YouTubeConnectionManager,
)
from openfetch.gui import main_window as gui_module
from openfetch.gui.managed_browser_dialog import YouTubeConnectionDialog
from openfetch.gui.responsive_layout import (
    clamp_splitter_sizes,
    clamp_window_rect,
    logical_viewport_size,
)


class MemorySettings:
    def __init__(self):
        self.values = {}

    def value(self, key, default=None, **_kwargs):
        return self.values.get(key, default)

    def setValue(self, key, value):  # noqa: N802
        self.values[key] = value

    def remove(self, key):
        self.values.pop(key, None)

    def sync(self):
        return None


@pytest.fixture
def main_window(tmp_path, monkeypatch):
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
    window.show()
    application.processEvents()
    yield application, window, settings
    window.close()
    settings.clear()


def test_restored_geometry_and_splitter_positions_are_clamped():
    available = QRect(100, 50, 1280, 720)
    restored = QRect(-5000, 9000, 2400, 1200)
    clamped = clamp_window_rect(restored, available, QSize(860, 620))
    assert clamped == available

    assert clamp_splitter_sizes(
        1200,
        [10, 1190],
        minimum_left=330,
        minimum_right=440,
    ) == (330, 870)
    assert clamp_splitter_sizes(
        1200,
        [1100, 100],
        minimum_left=330,
        minimum_right=440,
    ) == (760, 440)


@pytest.mark.parametrize(
    ("width", "height", "scale", "expected"),
    [
        (1280, 720, 1.0, QSize(1280, 720)),
        (1366, 768, 1.0, QSize(1366, 768)),
        (1920, 1080, 1.0, QSize(1920, 1080)),
        (1920, 1080, 1.25, QSize(1536, 864)),
        (1920, 1080, 1.5, QSize(1280, 720)),
    ],
)
def test_supported_dpi_scenarios_have_sufficient_logical_viewport(
    width,
    height,
    scale,
    expected,
):
    assert logical_viewport_size(width, height, scale) == expected
    assert expected.width() >= 860
    assert expected.height() >= 620


def test_main_window_responsive_contract(main_window):
    _application, window, _settings = main_window
    checks = window.responsive_layout_smoke_checks()
    assert checks
    assert all(checks.values()), checks
    assert window.side_panel.maximumWidth() > 10_000
    assert window.settings_scroll.widgetResizable()
    assert window.work_panel.minimumWidth() >= 440


def test_optional_helper_state_is_clear_and_does_not_disable_normal_ui(main_window):
    _application, window, _settings = main_window
    absent = PoTokenProviderStatus(
        available=False,
        bundled=False,
        installed=False,
        integrity_verified=False,
        provider_id="neural-extractor:external-helper",
        version="1.3.1",
        helper_version="",
        protocol_version=1,
        diagnostic="Optional helper is not installed.",
    )

    window._on_optional_po_helper_status(absent)

    text = window.optional_po_helper_status.text()
    assert "Not installed (optional)" in text
    assert "Normal downloads remain available" in text
    assert window.start_button.isEnabled()
    assert window.optional_po_helper_instructions_button.isEnabled()


def test_output_folder_browse_stays_visible_and_unicode_path_persists(
    main_window,
    tmp_path,
    monkeypatch,
):
    application, window, settings = main_window
    selected = tmp_path / "Downloads \U0001f680" / "\u65e5\u672c\u8a9e"
    selected.mkdir(parents=True)
    monkeypatch.setattr(
        QFileDialog,
        "getExistingDirectory",
        lambda *_args, **_kwargs: str(selected),
    )
    window.resize(window.minimumSize())
    application.processEvents()
    assert window._scroll_widget_reachable(window.browse_output_button)
    window.browse_output()
    assert window.output_dir == selected
    assert window.output_edit.text() == str(selected)
    assert window.output_edit.toolTip() == str(selected)
    assert settings.value("output_dir") == str(selected)


def test_connection_controls_stack_at_narrow_width_and_expand_at_wide_width(main_window):
    application, window, _settings = main_window
    window.connection_button_grid.set_available_width_for_test(320)
    application.processEvents()
    assert window.connection_button_grid.column_count == 1
    window.connection_button_grid.set_available_width_for_test(500)
    assert window.connection_button_grid.column_count == 2
    for button in window.connection_button_grid.buttons:
        assert button.minimumWidth() <= window.side_panel.width()


def test_managed_browser_wizard_is_resizable_scrollable_and_actions_remain_reachable(tmp_path):
    application = QApplication.instance() or QApplication([])
    settings = MemorySettings()
    manager = YouTubeConnectionManager(
        settings,
        browser=ManagedBrowser.CHROME,
        application_data=tmp_path / "LocalAppData" / "OpenFetch",
        discovery=ChromeDiscovery(
            registry_reader=lambda: [],
            environ={},
            binary_validator=lambda _path: True,
        ),
    )
    dialog = YouTubeConnectionDialog(manager, "https://www.youtube.com/")
    dialog.resize(dialog.minimumSize())
    dialog.show()
    application.processEvents()
    assert dialog.maximumWidth() > dialog.minimumWidth()
    assert dialog.body_scroll.widgetResizable()
    assert dialog.status_label.isVisibleTo(dialog)
    assert dialog.verify_button.isVisibleTo(dialog)
    assert dialog.cancel_button.isVisibleTo(dialog)
    assert dialog.browser_actions.column_count == 1
    assert dialog.fallback_button.isVisibleTo(dialog)
    dialog.close()
