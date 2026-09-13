"""Professional PySide6 interface for OpenFetch."""

from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from threading import Event, Lock

from PySide6.QtCore import QPoint, QRect, QSettings, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from openfetch.config import (
    APP_DESCRIPTION,
    APP_NAME,
    APP_PUBLISHER,
    APP_USER_MODEL_ID,
    AUDIO_BITRATES,
    BUILD_LABEL,
    QUALITY_PRESETS,
    SETTINGS_APPLICATION,
    SETTINGS_ORGANIZATION,
    SUBTITLE_LANGUAGES,
    VERSION,
    assets_dir,
    base_dir,
)
from openfetch.core.diagnostics import run_support_diagnostics
from openfetch.core.downloader import DownloadEngine
from openfetch.core.js_runtime import (
    MISSING_JS_RUNTIME_MESSAGE,
    ensure_youtube_js_runtime,
)
from openfetch.core.pot_provider import (
    PoTokenProviderStatus,
    get_po_token_provider,
)
from openfetch.core.update_installer import (
    PreparedUpdate,
    assess_installation_capability,
    prepare_and_launch_update,
)
from openfetch.core.update_ownership import TransactionState, new_transaction_id
from openfetch.core.updater import (
    UpdateChecker,
    UpdateDownloader,
    UpdateError,
    UpdateInfo,
)
from openfetch.core.youtube_connection import (
    ACTIVE_PROVIDER_KEY,
    ConnectionState,
    ManagedBrowser,
    YouTubeConnectionManager,
)
from openfetch.gui.managed_browser_dialog import YouTubeConnectionDialog
from openfetch.gui.responsive_layout import (
    ResponsiveButtonGrid,
    clamp_splitter_sizes,
    clamp_window_rect,
    logical_viewport_size,
)
from openfetch.models import (
    DownloadJob,
    DownloadOptions,
    MediaMode,
    PlaylistMode,
)
from openfetch.utils import coerce_path, is_youtube_url, split_urls

MODE_BUTTON_LABELS: dict[MediaMode, str] = {
    MediaMode.VIDEO: "Video",
    MediaMode.AUDIO_MP3: "MP3",
    MediaMode.AUDIO_M4A: "M4A",
    MediaMode.SUBTITLES_ONLY: "Subtitles only",
    MediaMode.THUMBNAIL_ONLY: "Thumbnail only",
}

MODE_DESCRIPTIONS: dict[MediaMode, str] = {
    MediaMode.VIDEO: "Full video with audio, saved as MP4 up to the selected quality.",
    MediaMode.AUDIO_MP3: "Audio only, converted to MP3 at the selected bitrate.",
    MediaMode.AUDIO_M4A: "Audio only, kept as M4A (AAC) at the selected bitrate.",
    MediaMode.SUBTITLES_ONLY: "No media — downloads only the subtitle file as SRT.",
    MediaMode.THUMBNAIL_ONLY: "No media — downloads only the video thumbnail as JPG.",
}

PLAYLIST_TOOLTIP = (
    "How playlist and mix URLs are handled:\n"
    "• Auto detect — plain video links download alone, playlist links download fully\n"
    "• Current video only — ignore the playlist and fetch just the linked video\n"
    "• Full playlist / mix — always expand and download every entry"
)

STATUS_COLORS: tuple[tuple[str, str], ...] = (
    ("Queued", "#8b98ad"),
    ("Starting", "#7cc7ff"),
    ("Preparing", "#7cc7ff"),
    ("Active download", "#2dd4bf"),
    ("Downloading", "#2dd4bf"),
    ("Waiting", "#e8b34b"),
    ("No response", "#e8b34b"),
    ("Processing", "#e8b34b"),
    ("Cancelling", "#9aa7bd"),
    ("Done", "#4ade80"),
    ("Failed", "#f16a7c"),
    ("Cancelled", "#9aa7bd"),
)


def _status_color(status: str) -> QColor:
    for prefix, color in STATUS_COLORS:
        if status.startswith(prefix):
            return QColor(color)
    return QColor("#e9eef7")


class DownloadWorker(QThread):
    """Run queued downloads without blocking the Qt event loop."""

    progress = Signal(str, int, str, str)
    job_started = Signal(str, str)
    job_finished = Signal(str, bool, str, str)
    log = Signal(str)
    batch_finished = Signal()

    def __init__(self, jobs: list[DownloadJob], options: DownloadOptions) -> None:
        super().__init__()
        self.jobs = jobs
        self.options = options
        self.engine: DownloadEngine | None = None
        self._stop_event = Event()
        self._state_lock = Lock()
        self._current_job_id: str | None = None
        self._last_progress_by_job_id: dict[str, tuple[int, str, str]] = {}

    @property
    def stop_requested(self) -> bool:
        return self._stop_event.is_set()

    def current_job_id(self) -> str | None:
        with self._state_lock:
            return self._current_job_id

    def request_stop(self) -> str | None:
        self._stop_event.set()
        with self._state_lock:
            engine = self.engine
            job_id = self._current_job_id
        if engine:
            engine.cancel()
        return job_id

    def run(self) -> None:
        try:
            for index, job in enumerate(self.jobs):
                if self.stop_requested:
                    self._emit_cancelled_jobs(self.jobs[index:])
                    break

                with self._state_lock:
                    self._current_job_id = job.job_id
                self.job_started.emit(job.job_id, job.url)

                try:
                    engine = DownloadEngine(
                        self.options,
                        progress_callback=self._on_progress,
                        log_callback=self.log.emit,
                    )
                    with self._state_lock:
                        self.engine = engine

                    if self.stop_requested:
                        engine.cancel()
                        self.job_finished.emit(job.job_id, False, "Cancelled", "cancelled")
                    else:
                        result = engine.download(job)
                        raw_category = getattr(result, "failure_category", "")
                        failure_category = str(
                            getattr(raw_category, "value", raw_category) or ""
                        )
                        if self.stop_requested and not result.success:
                            failure_category = "cancelled"
                        self.job_finished.emit(
                            job.job_id,
                            result.success,
                            result.message,
                            failure_category,
                        )
                except Exception:
                    self.log.emit("Download worker exception:\n" + traceback.format_exc())
                    if self.stop_requested:
                        self.job_finished.emit(job.job_id, False, "Cancelled", "cancelled")
                    else:
                        self.job_finished.emit(
                            job.job_id,
                            False,
                            "Download failed unexpectedly. See the Activity Log for details.",
                            "unknown_ytdlp_failure",
                        )
                finally:
                    with self._state_lock:
                        self.engine = None
                        self._current_job_id = None

                if self.stop_requested:
                    self._emit_cancelled_jobs(self.jobs[index + 1 :])
                    break
        finally:
            with self._state_lock:
                self.engine = None
                self._current_job_id = None
            self.batch_finished.emit()

    def _emit_cancelled_jobs(self, jobs: list[DownloadJob]) -> None:
        for job in jobs:
            self.job_finished.emit(job.job_id, False, "Cancelled", "cancelled")

    def _on_progress(self, event) -> None:
        if self.stop_requested:
            status = "Cancelling"
        elif event.status == "downloading":
            status = f"Downloading {event.percent}%"
        elif event.status == "finished":
            status = "Processing"
        else:
            raw_status = str(event.status or "Working")
            status = (
                raw_status.replace("_", " ").capitalize()
                if raw_status.islower()
                else raw_status
            )

        detail_parts = ["Cancelling download"] if self.stop_requested else []
        if event.playlist_index and event.playlist_total:
            detail_parts.append(f"{event.playlist_index}/{event.playlist_total}")
        if event.title:
            detail_parts.append(event.title)
        if event.speed:
            detail_parts.append(event.speed)
        if event.eta:
            detail_parts.append(f"ETA {event.eta}")

        detail = " | ".join(detail_parts)
        signature = (event.percent, status, detail)
        if self._last_progress_by_job_id.get(event.job_id) == signature:
            return
        self._last_progress_by_job_id[event.job_id] = signature
        self.progress.emit(event.job_id, event.percent, status, detail)


class UpdateCheckWorker(QThread):
    """Check GitHub releases without blocking the UI."""

    update_available = Signal(object)
    up_to_date = Signal()
    error = Signal(str, str)

    def __init__(self, current_version: str) -> None:
        super().__init__()
        self.current_version = current_version

    def run(self) -> None:
        try:
            info = UpdateChecker().check(self.current_version)
        except UpdateError as exc:
            self.error.emit(exc.code, exc.user_message)
            return
        except Exception:
            self.error.emit(
                "network_failure",
                "Could not check the official GitHub release. Check your connection and try again.",
            )
            return

        if info:
            self.update_available.emit(info)
        else:
            self.up_to_date.emit()


class UpdateInstallWorker(QThread):
    """Download, verify, and launch the detached updater without blocking Qt."""

    progress = Signal(int, str)
    prepared = Signal(object)
    error = Signal(str, str)
    cancelled = Signal()
    cancellation_locked = Signal()

    def __init__(self, info: UpdateInfo) -> None:
        super().__init__()
        self.info = info
        self.transaction_id = new_transaction_id()
        self.transaction_state = TransactionState.CHECKING
        self.cancel_requested = False
        self._cancel_lock = Lock()

    def request_cancel(self) -> bool:
        with self._cancel_lock:
            if self.transaction_state not in {
                TransactionState.CHECKING,
                TransactionState.DOWNLOADING,
                TransactionState.DOWNLOADED,
            }:
                return False
            self.cancel_requested = True
            self.requestInterruption()
            return True

    def can_cancel(self) -> bool:
        with self._cancel_lock:
            return self.transaction_state in {
                TransactionState.CHECKING,
                TransactionState.DOWNLOADING,
                TransactionState.DOWNLOADED,
            }

    def _cancelled(self) -> bool:
        with self._cancel_lock:
            return self.cancel_requested or self.isInterruptionRequested()

    def run(self) -> None:
        try:
            with self._cancel_lock:
                self.transaction_state = TransactionState.DOWNLOADING
            staged = UpdateDownloader().stage(
                self.info,
                transaction_id=self.transaction_id,
                progress_callback=self.progress.emit,
                cancel_callback=self._cancelled,
            )
            with self._cancel_lock:
                self.transaction_state = TransactionState.DOWNLOADED
                if self.cancel_requested or self.isInterruptionRequested():
                    raise UpdateError("cancelled", "Update download cancelled.")
                self.transaction_state = TransactionState.VERIFIED
            self.cancellation_locked.emit()
            prepared = prepare_and_launch_update(
                self.info,
                staged,
                parent_pid=os.getpid(),
                transaction_id=self.transaction_id,
                progress_callback=self.progress.emit,
            )
        except UpdateError as exc:
            with self._cancel_lock:
                self.transaction_state = TransactionState.FAILED
            if exc.code == "cancelled":
                self.cancelled.emit()
            else:
                self.error.emit(exc.code, exc.user_message)
            return
        except Exception:
            with self._cancel_lock:
                self.transaction_state = TransactionState.FAILED
            self.error.emit(
                "installation_failure",
                "The update could not be prepared safely. The current application was not changed.",
            )
            return
        self.prepared.emit(prepared)


class DiagnosticsWorker(QThread):
    """Run support diagnostics without blocking the Qt event loop."""

    line = Signal(str)
    error = Signal(str)

    def __init__(self, options: DownloadOptions, probe_url: str | None) -> None:
        super().__init__()
        self.options = options
        self.probe_url = probe_url

    def run(self) -> None:
        try:
            report = run_support_diagnostics(self.options, self.probe_url)
        except Exception as exc:
            self.error.emit(str(exc))
            return

        for line in report.lines():
            self.line.emit(line)


class OptionalPoHelperStatusWorker(QThread):
    """Check the separately installed helper without blocking the GUI thread."""

    status_ready = Signal(object)
    unavailable = Signal()

    def run(self) -> None:
        try:
            status = get_po_token_provider().refresh_status()
        except Exception:
            # The helper boundary may carry token material. Never forward an
            # external exception string into the UI or application log.
            self.unavailable.emit()
            return
        self.status_ready.emit(status)


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.settings = QSettings(SETTINGS_ORGANIZATION, SETTINGS_APPLICATION)
        self.youtube_connections = {
            ManagedBrowser.CHROME: YouTubeConnectionManager(
                self.settings,
                browser=ManagedBrowser.CHROME,
            ),
            ManagedBrowser.FIREFOX: YouTubeConnectionManager(
                self.settings,
                browser=ManagedBrowser.FIREFOX,
            ),
        }
        self.youtube_connection = self.youtube_connections[ManagedBrowser.CHROME]
        self.jobs: list[DownloadJob] = []
        self.row_by_job_id: dict[str, int] = {}
        self.progress_by_job_id: dict[str, QProgressBar] = {}
        self.worker: DownloadWorker | None = None
        self.active_job_id: str | None = None
        self._close_after_worker_stops = False
        self.update_worker: UpdateCheckWorker | None = None
        self.update_install_worker: UpdateInstallWorker | None = None
        self.update_progress_dialog: QProgressDialog | None = None
        self.update_install_outcome = ""
        self.diagnostics_worker: DiagnosticsWorker | None = None
        self.po_helper_status_worker: OptionalPoHelperStatusWorker | None = None
        self._auth_waiting_job_ids: set[str] = set()
        self._auth_resume_job_ids: set[str] = set()
        self._auth_retry_counts: dict[str, int] = {}
        self._auth_dialog_active = False
        self.update_check_silent = False
        self.js_runtime_status = ensure_youtube_js_runtime()

        self.output_dir = Path(
            str(self.settings.value("output_dir", str(Path.home() / "Downloads")))
        )
        self.cookie_file = coerce_path(str(self.settings.value("cookie_file", "")))

        self.setWindowTitle(f"{APP_NAME} {VERSION}")
        self.setMinimumSize(860, 620)
        self.resize(1380, 860)
        self._set_app_icon()
        self._apply_theme()
        self._build_ui()
        for manager in self.youtube_connections.values():
            manager.log_callback = self.log
            for event_message in manager.events:
                self.log(event_message)
        QTimer.singleShot(0, self._restore_window_layout)
        self._update_mode_controls()
        self._refresh_queue_summary()
        self.log(f"{APP_NAME} {VERSION} build {BUILD_LABEL} ready")
        self.log(self.js_runtime_status.diagnostic)
        if not self.js_runtime_status.found:
            QTimer.singleShot(500, self._show_js_runtime_warning)
        self.statusBar().showMessage("Ready")
        QTimer.singleShot(0, self.refresh_optional_po_helper_status)
        QTimer.singleShot(1800, lambda: self.check_for_updates(silent=True))

    def _set_app_icon(self) -> None:
        icon_path = assets_dir() / ("OpenFetch.ico" if sys.platform == "win32" else "OpenFetchIcon.png")
        if icon_path.exists():
            icon = QIcon(str(icon_path))
            self.setWindowIcon(icon)
            app = QApplication.instance()
            if app:
                app.setWindowIcon(icon)

        if sys.platform == "win32":
            try:
                import ctypes

                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    APP_USER_MODEL_ID
                )
            except Exception:
                pass

    def _apply_theme(self) -> None:
        arrow = (assets_dir() / "chevron-down.png").as_posix()
        arrow_disabled = (assets_dir() / "chevron-down-disabled.png").as_posix()
        style = """
            QWidget {
                color: #e9eef7;
                font-family: "Segoe UI Variable Text", "Segoe UI", "Inter", Arial, sans-serif;
                font-size: 13px;
            }
            QMainWindow, QDialog, QMessageBox {
                background: #0f131a;
            }
            QFrame#sidePanel {
                background: #141923;
                border-right: 1px solid #232b3a;
            }
            QFrame#workPanel {
                background: #0f131a;
            }
            QScrollArea#sideScroll {
                background: transparent;
                border: 0;
            }
            QScrollArea#sideScroll > QWidget > QWidget {
                background: transparent;
            }

            QLabel#brand {
                font-size: 19px;
                font-weight: 800;
                color: #ffffff;
                letter-spacing: 0.5px;
            }
            QLabel#brandSub {
                color: #8fa0b8;
                font-size: 11px;
            }
            QLabel#versionChip {
                background: rgba(45, 212, 191, 0.12);
                color: #2dd4bf;
                border: 1px solid rgba(45, 212, 191, 0.35);
                border-radius: 10px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
            }
            QLabel#panelTitle {
                font-size: 18px;
                font-weight: 800;
                color: #ffffff;
            }
            QLabel#panelSub {
                color: #8fa0b8;
                font-size: 12px;
            }
            QLabel#queueSummary {
                color: #8fa0b8;
                font-size: 12px;
                font-weight: 600;
            }
            QLabel#sectionLabel {
                color: #93a1b8;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.8px;
            }
            QLabel#hintLabel {
                color: #67748c;
                font-size: 11px;
            }
            QLabel#modeDescription {
                color: #8fa0b8;
                font-size: 11px;
            }
            QFrame#separator {
                background: #232b3a;
                border: 0;
            }

            QGroupBox {
                border: 1px solid #232b3a;
                border-radius: 10px;
                margin-top: 12px;
                padding: 16px 14px 12px 14px;
                background: #171d29;
                font-weight: 700;
                font-size: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px;
                color: #2dd4bf;
                letter-spacing: 1.2px;
            }

            QTextEdit, QLineEdit, QComboBox {
                background: #0c1016;
                border: 1px solid #2a3447;
                border-radius: 8px;
                color: #e9eef7;
                padding: 8px 10px;
                selection-background-color: #2dd4bf;
                selection-color: #06211d;
            }
            QTextEdit:focus, QLineEdit:focus, QComboBox:focus {
                border-color: #2dd4bf;
            }
            QLineEdit:read-only {
                color: #b9c4d6;
            }
            QTextEdit:disabled, QLineEdit:disabled, QComboBox:disabled {
                color: #5c6982;
                background: #10141c;
                border-color: #222a3a;
            }
            QComboBox::drop-down {
                border: 0;
                width: 26px;
            }
            QComboBox::down-arrow {
                image: url("%ARROW%");
                width: 12px;
                height: 12px;
                margin-right: 8px;
            }
            QComboBox::down-arrow:disabled {
                image: url("%ARROW_DISABLED%");
            }
            QComboBox QAbstractItemView {
                background: #151b27;
                border: 1px solid #2a3447;
                color: #e9eef7;
                selection-background-color: #22314a;
                selection-color: #ffffff;
                outline: 0;
                padding: 4px;
            }

            QCheckBox {
                spacing: 9px;
                color: #cbd5e5;
            }
            QCheckBox:disabled {
                color: #5c6982;
            }
            QCheckBox::indicator {
                width: 17px;
                height: 17px;
                border-radius: 5px;
                border: 1px solid #3a4763;
                background: #0c1016;
            }
            QCheckBox::indicator:hover {
                border-color: #2dd4bf;
            }
            QCheckBox::indicator:checked {
                background: #2dd4bf;
                border-color: #2dd4bf;
            }
            QCheckBox::indicator:checked:disabled {
                background: #1f4a44;
                border-color: #1f4a44;
            }
            QCheckBox::indicator:unchecked:disabled {
                border-color: #2a3447;
            }

            QPushButton {
                background: #212a3a;
                border: 1px solid #2f3a50;
                border-radius: 8px;
                color: #e9eef7;
                font-weight: 600;
                padding: 8px 14px;
            }
            QPushButton:hover {
                background: #283349;
                border-color: #3d4a66;
            }
            QPushButton:pressed {
                background: #1c2434;
            }
            QPushButton:disabled {
                color: #5c6982;
                background: #161c28;
                border-color: #222a3a;
            }
            QPushButton#primaryButton {
                background: #2dd4bf;
                border-color: #2dd4bf;
                color: #04211d;
                font-weight: 700;
                font-size: 14px;
            }
            QPushButton#primaryButton:hover {
                background: #47e0cd;
                border-color: #47e0cd;
            }
            QPushButton#primaryButton:pressed {
                background: #1fb8a5;
            }
            QPushButton#primaryButton:disabled {
                background: #1b3a37;
                border-color: #1b3a37;
                color: #4d6e66;
            }
            QPushButton#dangerButton {
                background: rgba(241, 106, 124, 0.10);
                border: 1px solid rgba(241, 106, 124, 0.45);
                color: #f28a9b;
                font-weight: 700;
            }
            QPushButton#dangerButton:hover {
                background: rgba(241, 106, 124, 0.22);
                border-color: #f16a7c;
                color: #ffb3bf;
            }
            QPushButton#dangerButton:disabled {
                background: #161c28;
                border-color: #222a3a;
                color: #5c6982;
            }
            QPushButton#warmButton {
                background: rgba(232, 179, 75, 0.10);
                border: 1px solid rgba(232, 179, 75, 0.40);
                color: #e8b34b;
                font-weight: 700;
            }
            QPushButton#warmButton:hover {
                background: rgba(232, 179, 75, 0.20);
                border-color: #e8b34b;
            }
            QPushButton#queueButton {
                background: rgba(45, 212, 191, 0.10);
                border: 1px solid rgba(45, 212, 191, 0.35);
                color: #2dd4bf;
                font-weight: 700;
            }
            QPushButton#queueButton:hover {
                background: rgba(45, 212, 191, 0.20);
                border-color: #2dd4bf;
            }
            QPushButton#queueButton:disabled {
                background: #161c28;
                border-color: #222a3a;
                color: #5c6982;
            }
            QPushButton#modeButton {
                background: #0c1016;
                border: 1px solid #2a3447;
                border-radius: 8px;
                color: #a9b6ca;
                font-weight: 600;
                padding: 8px 6px;
            }
            QPushButton#modeButton:hover {
                border-color: #3d4a66;
                color: #e9eef7;
                background: #10141c;
            }
            QPushButton#modeButton:checked {
                background: rgba(45, 212, 191, 0.14);
                border-color: #2dd4bf;
                color: #2dd4bf;
                font-weight: 700;
            }
            QPushButton#modeButton:disabled {
                color: #5c6982;
                border-color: #222a3a;
            }

            QTableWidget {
                background: #12161f;
                alternate-background-color: #151a25;
                border: 1px solid #232b3a;
                border-radius: 10px;
                gridline-color: transparent;
                selection-background-color: #1d2a40;
                selection-color: #ffffff;
            }
            QTableWidget::item {
                padding: 4px 10px;
                border: 0;
            }
            QHeaderView::section {
                background: #171d29;
                color: #93a1b8;
                border: 0;
                border-bottom: 1px solid #232b3a;
                padding: 9px 10px;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 0.6px;
            }
            QTableCornerButton::section {
                background: #171d29;
                border: 0;
            }

            QProgressBar {
                background: #0c1016;
                border: 1px solid #232b3a;
                border-radius: 6px;
                color: #e9eef7;
                text-align: center;
                font-size: 11px;
                font-weight: 600;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1fb8a5, stop:1 #2dd4bf);
                border-radius: 5px;
            }

            QTextEdit#logBox {
                background: #0b0e14;
                border: 1px solid #232b3a;
                border-radius: 10px;
                color: #9fe8de;
                font-family: "Cascadia Mono", "Consolas", monospace;
                font-size: 12px;
            }

            QSplitter::handle {
                background: #232b3a;
            }
            QSplitter::handle:horizontal {
                width: 2px;
            }
            QSplitter::handle:vertical {
                height: 2px;
            }

            QScrollBar:vertical {
                background: transparent;
                width: 10px;
                margin: 2px;
            }
            QScrollBar::handle:vertical {
                background: #2a3447;
                border-radius: 4px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #3d4a66;
            }
            QScrollBar:horizontal {
                background: transparent;
                height: 10px;
                margin: 2px;
            }
            QScrollBar::handle:horizontal {
                background: #2a3447;
                border-radius: 4px;
                min-width: 30px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #3d4a66;
            }
            QScrollBar::add-line, QScrollBar::sub-line {
                width: 0;
                height: 0;
            }
            QScrollBar::add-page, QScrollBar::sub-page {
                background: transparent;
            }

            QStatusBar {
                background: #12161f;
                color: #8fa0b8;
                border-top: 1px solid #232b3a;
                font-size: 12px;
            }
            QStatusBar::item {
                border: 0;
            }

            QToolTip {
                background: #1c2434;
                color: #e9eef7;
                border: 1px solid #2f3a50;
                padding: 6px 8px;
                font-size: 12px;
            }
            """
        self.setStyleSheet(
            style.replace("%ARROW%", arrow).replace("%ARROW_DISABLED%", arrow_disabled)
        )

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.setObjectName("mainSplitter")
        self.side_panel = self._build_side_panel()
        self.work_panel = self._build_work_panel()
        self.main_splitter.addWidget(self.side_panel)
        self.main_splitter.addWidget(self.work_panel)
        self.main_splitter.setSizes([440, 940])
        self.main_splitter.setStretchFactor(0, 0)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setHandleWidth(8)
        self.main_splitter.setCollapsible(0, False)
        self.main_splitter.setCollapsible(1, False)
        root_layout.addWidget(self.main_splitter)
        self.setCentralWidget(root)

    # ------------------------------------------------------------------ side panel

    def _build_side_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("sidePanel")
        panel.setMinimumWidth(330)
        panel.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(14)

        layout.addLayout(self._brand_header())

        self.settings_scroll = QScrollArea()
        self.settings_scroll.setObjectName("sideScroll")
        self.settings_scroll.setWidgetResizable(True)
        self.settings_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.settings_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        content = QWidget()
        content.setMinimumWidth(0)
        content.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 6, 0)
        content_layout.setSpacing(14)
        groups = [
            self._source_group(),
            self._format_group(),
            self._extras_group(),
            self._destination_group(),
        ]
        for group in groups:
            group.setMinimumWidth(0)
            group.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            content_layout.addWidget(group)
        content_layout.addStretch(1)
        self.settings_content = content
        self.settings_scroll.setWidget(content)
        layout.addWidget(self.settings_scroll, 1)

        layout.addLayout(self._action_buttons())
        return panel

    def _brand_header(self) -> QHBoxLayout:
        header = QHBoxLayout()
        header.setSpacing(12)

        logo_path = assets_dir() / "OpenFetchIcon.png"
        if logo_path.exists():
            logo = QLabel()
            pixmap = QPixmap(str(logo_path)).scaled(
                34,
                34,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo.setPixmap(pixmap)
            header.addWidget(logo)

        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        brand = QLabel(APP_NAME)
        brand.setObjectName("brand")
        brand_sub = QLabel(f"by {APP_PUBLISHER} · {APP_DESCRIPTION}")
        brand_sub.setObjectName("brandSub")
        title_box.addWidget(brand)
        title_box.addWidget(brand_sub)
        header.addLayout(title_box)
        header.addStretch(1)

        chip = QLabel(f"v{VERSION}")
        chip.setObjectName("versionChip")
        header.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)
        return header

    def _source_group(self) -> QGroupBox:
        group = QGroupBox("SOURCE")
        layout = QVBoxLayout(group)
        layout.setSpacing(10)

        self.url_edit = QTextEdit()
        self.url_edit.setPlaceholderText("Paste one or more YouTube URLs — one per line")
        self.url_edit.setToolTip("Videos, Shorts, playlists, and mixes are supported. One URL per line.")
        self.url_edit.setFixedHeight(96)
        layout.addWidget(self.url_edit)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.paste_button = QPushButton("Paste")
        self.paste_button.setToolTip("Append URLs from the clipboard")
        self.paste_button.clicked.connect(self.paste_from_clipboard)
        self.add_button = QPushButton("Add to Queue")
        self.add_button.setObjectName("queueButton")
        self.add_button.setToolTip("Validate the URLs above and add them to the download queue")
        self.add_button.clicked.connect(self.add_to_queue)
        row.addWidget(self.paste_button)
        row.addWidget(self.add_button, 1)
        layout.addLayout(row)

        self.playlist_combo = QComboBox()
        for mode in PlaylistMode:
            self.playlist_combo.addItem(mode.label, mode.value)
        self.playlist_combo.setToolTip(PLAYLIST_TOOLTIP)
        layout.addWidget(self._labeled("PLAYLIST HANDLING", self.playlist_combo))

        hint = QLabel("Applies when a URL points to a playlist or mix.")
        hint.setObjectName("hintLabel")
        layout.addWidget(hint)
        return group

    def _format_group(self) -> QGroupBox:
        group = QGroupBox("OUTPUT FORMAT")
        layout = QVBoxLayout(group)
        layout.setSpacing(10)

        mode_grid = QGridLayout()
        mode_grid.setHorizontalSpacing(8)
        mode_grid.setVerticalSpacing(8)

        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        self.mode_buttons: dict[MediaMode, QPushButton] = {}
        placements = {
            MediaMode.VIDEO: (0, 0, 1, 2),
            MediaMode.AUDIO_MP3: (0, 2, 1, 2),
            MediaMode.AUDIO_M4A: (0, 4, 1, 2),
            MediaMode.SUBTITLES_ONLY: (1, 0, 1, 3),
            MediaMode.THUMBNAIL_ONLY: (1, 3, 1, 3),
        }
        for mode in MediaMode:
            button = QPushButton(MODE_BUTTON_LABELS[mode])
            button.setObjectName("modeButton")
            button.setCheckable(True)
            button.setToolTip(f"{mode.label} — {MODE_DESCRIPTIONS[mode]}")
            button.setProperty("mode_value", mode.value)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            self.mode_group.addButton(button)
            self.mode_buttons[mode] = button
            mode_grid.addWidget(button, *placements[mode])
        self.mode_buttons[MediaMode.VIDEO].setChecked(True)
        self.mode_group.buttonToggled.connect(self._on_mode_toggled)
        layout.addLayout(mode_grid)

        self.mode_description = QLabel(MODE_DESCRIPTIONS[MediaMode.VIDEO])
        self.mode_description.setObjectName("modeDescription")
        self.mode_description.setWordWrap(True)
        layout.addWidget(self.mode_description)

        self.quality_combo = QComboBox()
        for label in QUALITY_PRESETS:
            self.quality_combo.addItem(label)
        self.quality_combo.setToolTip(
            "Upper limit for video resolution. 'Best available' picks the highest quality YouTube offers."
        )

        self.audio_quality_combo = QComboBox()
        for bitrate in AUDIO_BITRATES:
            self.audio_quality_combo.addItem(f"{bitrate} kbps", bitrate)
        self.audio_quality_combo.setToolTip(
            "Bitrate used for MP3/M4A output. Higher means better quality and larger files."
        )

        quality_row = QHBoxLayout()
        quality_row.setSpacing(10)
        quality_row.addWidget(self._labeled("VIDEO QUALITY", self.quality_combo), 1)
        quality_row.addWidget(self._labeled("AUDIO BITRATE", self.audio_quality_combo), 1)
        layout.addLayout(quality_row)
        return group

    def _extras_group(self) -> QGroupBox:
        group = QGroupBox("EXTRAS")
        layout = QVBoxLayout(group)
        layout.setSpacing(9)

        self.subtitle_check = QCheckBox("Download subtitles (SRT)")
        self.subtitle_check.setChecked(True)
        self.subtitle_check.setToolTip("Save subtitles next to the media file in SRT format.")

        self.auto_subtitle_check = QCheckBox("Allow auto-generated captions")
        self.auto_subtitle_check.setChecked(True)
        self.auto_subtitle_check.setToolTip(
            "If no human-made subtitles exist, fall back to YouTube's auto-generated captions."
        )

        self.subtitle_lang_combo = QComboBox()
        for code, name in SUBTITLE_LANGUAGES.items():
            self.subtitle_lang_combo.addItem(f"{name} ({code})", code)
        self.subtitle_lang_combo.setToolTip("Language of the subtitle track to download.")

        self.thumbnail_check = QCheckBox("Download thumbnail (JPG)")
        self.thumbnail_check.setChecked(True)
        self.thumbnail_check.setToolTip("Save the video thumbnail as a JPG next to the media file.")

        self.embed_thumb_check = QCheckBox("Embed thumbnail as cover art")
        self.embed_thumb_check.setChecked(True)
        self.embed_thumb_check.setToolTip(
            "Embed the thumbnail inside MP3/M4A files so players show album art."
        )

        self.metadata_check = QCheckBox("Write metadata JSON")
        self.metadata_check.setToolTip(
            "Save a .json file with full video metadata: title, uploader, dates, and statistics."
        )

        layout.addWidget(self.subtitle_check)
        layout.addWidget(self._indented(self.auto_subtitle_check))
        layout.addWidget(self._indented(self._labeled("SUBTITLE LANGUAGE", self.subtitle_lang_combo)))
        layout.addWidget(self._separator())
        layout.addWidget(self.thumbnail_check)
        layout.addWidget(self._indented(self.embed_thumb_check))
        layout.addWidget(self._separator())
        layout.addWidget(self.metadata_check)

        # State order matters: set defaults above before wiring the refresh.
        self.subtitle_check.stateChanged.connect(self._update_mode_controls)
        self.thumbnail_check.stateChanged.connect(self._update_mode_controls)
        return group

    def _destination_group(self) -> QGroupBox:
        group = QGroupBox("DESTINATION")
        layout = QVBoxLayout(group)
        layout.setSpacing(10)

        self.output_edit = QLineEdit(str(self.output_dir))
        self.output_edit.setReadOnly(True)
        self.output_edit.setMinimumWidth(0)
        self.output_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.output_edit.setToolTip(str(self.output_dir))
        self.browse_output_button = QPushButton("Browse…")
        self.browse_output_button.setToolTip("Choose the output folder")
        self.browse_output_button.setMinimumWidth(82)
        self.browse_output_button.clicked.connect(self.browse_output)
        output_row = QHBoxLayout()
        output_row.setSpacing(8)
        output_row.addWidget(self.output_edit, 1)
        output_row.addWidget(self.browse_output_button)
        layout.addWidget(self._labeled("OUTPUT FOLDER", self._row_widget(output_row)))

        layout.addWidget(self._separator())
        self.youtube_connection_status = QLabel()
        self.youtube_connection_status.setWordWrap(True)
        self.youtube_connection_status.setObjectName("hintLabel")
        self.youtube_profile_label = QLabel(
            "Browser: Google Chrome / Profile: Dedicated OpenFetch profile"
        )
        self.youtube_profile_label.setObjectName("hintLabel")
        self.youtube_profile_label.setWordWrap(True)
        self.youtube_connect_button = QPushButton("Google Chrome verbinden")
        self.youtube_connect_button.setToolTip(
            "Open the isolated OpenFetch Google Chrome profile"
        )
        self.youtube_connect_button.clicked.connect(self.connect_youtube)
        self.youtube_renew_button = QPushButton("Vernieuwen")
        self.youtube_renew_button.setToolTip("Renew the active managed YouTube connection")
        self.youtube_renew_button.clicked.connect(
            lambda _checked=False: self.connect_youtube(renewal=True)
        )
        self.youtube_test_button = QPushButton("Verbinding testen")
        self.youtube_test_button.clicked.connect(self.test_youtube_connection)
        self.youtube_disconnect_button = QPushButton("Chrome loskoppelen")
        self.youtube_disconnect_button.clicked.connect(
            lambda _checked=False: self.disconnect_youtube(browser=ManagedBrowser.CHROME)
        )
        self.youtube_firefox_button = QPushButton("Firefox fallback")
        self.youtube_firefox_button.setToolTip(
            "Use managed Firefox when Chrome cookies cannot be read securely"
        )
        self.youtube_firefox_button.clicked.connect(
            lambda _checked=False: self.connect_youtube(browser=ManagedBrowser.FIREFOX)
        )
        self.youtube_firefox_disconnect_button = QPushButton("Firefox loskoppelen")
        self.youtube_firefox_disconnect_button.clicked.connect(
            lambda _checked=False: self.disconnect_youtube(browser=ManagedBrowser.FIREFOX)
        )
        self.connection_button_grid = ResponsiveButtonGrid(
            [
                self.youtube_connect_button,
                self.youtube_renew_button,
                self.youtube_test_button,
                self.youtube_disconnect_button,
                self.youtube_firefox_button,
                self.youtube_firefox_disconnect_button,
            ],
            two_column_width=390,
            four_column_width=760,
        )
        layout.addWidget(self._labeled("YOUTUBE CONNECTION", self.youtube_connection_status))
        layout.addWidget(self.youtube_profile_label)
        layout.addWidget(self.connection_button_grid)

        self.optional_po_helper_status = QLabel(
            "Status: Checking separately installed optional helper..."
        )
        self.optional_po_helper_status.setWordWrap(True)
        self.optional_po_helper_status.setObjectName("hintLabel")
        self.optional_po_helper_refresh_button = QPushButton("Refresh helper status")
        self.optional_po_helper_refresh_button.clicked.connect(
            self.refresh_optional_po_helper_status
        )
        self.optional_po_helper_instructions_button = QPushButton(
            "Open installation instructions"
        )
        self.optional_po_helper_instructions_button.clicked.connect(
            self.open_optional_po_helper_instructions
        )
        po_helper_row = QHBoxLayout()
        po_helper_row.setSpacing(8)
        po_helper_row.addWidget(self.optional_po_helper_refresh_button)
        po_helper_row.addWidget(self.optional_po_helper_instructions_button)
        po_helper_row.addStretch(1)
        layout.addWidget(
            self._labeled("OPTIONAL PO TOKEN HELPER", self.optional_po_helper_status)
        )
        layout.addWidget(self._row_widget(po_helper_row))

        self.cookie_edit = QLineEdit(str(self.cookie_file) if self.cookie_file else "")
        self.cookie_edit.setPlaceholderText("No cookies file loaded")
        self.cookie_edit.setReadOnly(True)
        self.cookie_edit.setToolTip(
            "Advanced compatibility fallback. The guided YouTube connection is the normal workflow."
        )
        self.browse_cookie_button = QPushButton("Browse…")
        self.browse_cookie_button.setToolTip("Select an advanced compatibility cookies.txt file")
        self.browse_cookie_button.clicked.connect(self.browse_cookie_file)
        self.clear_cookie_button = QPushButton("Clear")
        self.clear_cookie_button.setToolTip("Stop using the cookies file")
        self.clear_cookie_button.clicked.connect(self.clear_cookie_file)
        cookie_row = QHBoxLayout()
        cookie_row.setSpacing(8)
        cookie_row.addWidget(self.cookie_edit, 1)
        cookie_row.addWidget(self.browse_cookie_button)
        cookie_row.addWidget(self.clear_cookie_button)
        layout.addWidget(self._labeled("COOKIES FILE (OPTIONAL)", self._row_widget(cookie_row)))

        hint = QLabel("cookies.txt is retained only as an optional advanced fallback.")
        hint.setObjectName("hintLabel")
        layout.addWidget(hint)
        self.legacy_browser_check = QCheckBox(
            "Enable detected browser-profile fallback (advanced)"
        )
        self.legacy_browser_check.setChecked(
            bool(
                self.settings.value(
                    "youtube_connection/legacy_browser_fallback",
                    False,
                    type=bool,
                )
            )
        )
        self.legacy_browser_check.setToolTip(
            "When enabled, Chrome, Edge, Brave, or normal Firefox profiles may be tried after "
            "the dedicated profile and cookies.txt."
        )
        self.legacy_browser_check.stateChanged.connect(self._save_legacy_browser_fallback)
        layout.addWidget(self.legacy_browser_check)
        return group

    def _action_buttons(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)
        self.start_button = QPushButton("Start Queue")
        self.start_button.setObjectName("primaryButton")
        self.start_button.setMinimumHeight(40)
        self.start_button.setToolTip("Start downloading everything in the queue")
        self.start_button.clicked.connect(self.start_queue)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("dangerButton")
        self.stop_button.setMinimumHeight(40)
        self.stop_button.setEnabled(False)
        self.stop_button.setToolTip("Cancel the active download and stop the queue")
        self.stop_button.clicked.connect(self.stop_queue)
        self.clear_button = QPushButton("Clear")
        self.clear_button.setMinimumHeight(40)
        self.clear_button.setToolTip("Remove all jobs from the queue and clear the log")
        self.clear_button.clicked.connect(self.clear_queue)
        row.addWidget(self.start_button, 2)
        row.addWidget(self.stop_button, 1)
        row.addWidget(self.clear_button, 1)
        return row

    # ------------------------------------------------------------------ work panel

    def _build_work_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("workPanel")
        panel.setMinimumWidth(440)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 20, 24, 18)
        layout.setSpacing(12)

        top = QHBoxLayout()
        top.setSpacing(12)
        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        title = QLabel("Download Queue")
        title.setObjectName("panelTitle")
        subtitle = QLabel("Jobs run in order from the top")
        subtitle.setObjectName("panelSub")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        top.addLayout(title_box)
        top.addStretch(1)

        self.queue_summary = QLabel("Queue is empty")
        self.queue_summary.setObjectName("queueSummary")
        top.addWidget(self.queue_summary)

        open_folder = QPushButton("Open Folder")
        open_folder.setObjectName("warmButton")
        open_folder.setToolTip("Open the output folder in the file explorer")
        open_folder.clicked.connect(self.open_output_folder)
        self.update_button = QPushButton("Check Updates")
        self.update_button.setToolTip("Check the latest GitHub Release for a newer OpenFetch build")
        self.update_button.clicked.connect(lambda: self.check_for_updates(silent=False))
        self.diagnostics_button = QPushButton("Diagnostics")
        self.diagnostics_button.setToolTip("Run a safe environment report for support")
        self.diagnostics_button.clicked.connect(self.run_diagnostics)
        top.addWidget(self.diagnostics_button)
        top.addWidget(self.update_button)
        top.addWidget(open_folder)
        layout.addLayout(top)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Source", "Mode", "Status", "Progress", "Details"])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setHighlightSections(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(3, 200)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        log_section = QWidget()
        log_layout = QVBoxLayout(log_section)
        log_layout.setContentsMargins(0, 6, 0, 0)
        log_layout.setSpacing(6)
        log_label = QLabel("ACTIVITY LOG")
        log_label.setObjectName("sectionLabel")
        log_layout.addWidget(log_label)
        self.log_box = QTextEdit()
        self.log_box.setObjectName("logBox")
        self.log_box.setReadOnly(True)
        self.log_box.setPlaceholderText("Download activity will appear here.")
        self.log_box.setMinimumHeight(120)
        self.log_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        log_layout.addWidget(self.log_box)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(log_section)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([540, 200])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        layout.addWidget(splitter, 1)
        return panel

    # ------------------------------------------------------------------ helpers

    def _labeled(self, label_text: str, widget: QWidget) -> QWidget:
        wrapper = QWidget()
        layout = QVBoxLayout(wrapper)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        label = QLabel(label_text)
        label.setObjectName("sectionLabel")
        layout.addWidget(label)
        layout.addWidget(widget)
        return wrapper

    def _indented(self, widget: QWidget) -> QWidget:
        wrapper = QWidget()
        layout = QHBoxLayout(wrapper)
        layout.setContentsMargins(26, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(widget)
        return wrapper

    def _row_widget(self, layout: QHBoxLayout) -> QWidget:
        wrapper = QWidget()
        wrapper.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)
        return wrapper

    def _separator(self) -> QFrame:
        line = QFrame()
        line.setObjectName("separator")
        line.setFixedHeight(1)
        return line

    def _current_mode(self) -> MediaMode:
        button = self.mode_group.checkedButton()
        if button is None:
            return MediaMode.VIDEO
        return MediaMode(button.property("mode_value"))

    def _run_locked_widgets(self) -> list[QWidget]:
        return [
            *self.mode_buttons.values(),
            self.playlist_combo,
            self.quality_combo,
            self.audio_quality_combo,
            self.subtitle_check,
            self.auto_subtitle_check,
            self.subtitle_lang_combo,
            self.thumbnail_check,
            self.embed_thumb_check,
            self.metadata_check,
            self.add_button,
            self.browse_output_button,
            self.youtube_connect_button,
            self.youtube_renew_button,
            self.youtube_test_button,
            self.youtube_disconnect_button,
            self.youtube_firefox_button,
            self.youtube_firefox_disconnect_button,
            self.optional_po_helper_refresh_button,
            self.legacy_browser_check,
            self.browse_cookie_button,
            self.clear_cookie_button,
        ]

    def _on_mode_toggled(self, button: QPushButton, checked: bool) -> None:
        if checked:
            self._update_mode_controls()

    def _update_mode_controls(self) -> None:
        mode = self._current_mode()
        is_video = mode == MediaMode.VIDEO
        is_audio = mode in {MediaMode.AUDIO_MP3, MediaMode.AUDIO_M4A}
        is_subtitles_only = mode == MediaMode.SUBTITLES_ONLY
        is_thumbnail_only = mode == MediaMode.THUMBNAIL_ONLY

        self.mode_description.setText(MODE_DESCRIPTIONS[mode])

        if is_subtitles_only:
            self.subtitle_check.setChecked(True)
        if is_thumbnail_only:
            self.thumbnail_check.setChecked(True)

        subtitles_active = self.subtitle_check.isChecked() or is_subtitles_only
        self.quality_combo.setEnabled(is_video)
        self.audio_quality_combo.setEnabled(is_audio)
        self.embed_thumb_check.setEnabled(is_audio and self.thumbnail_check.isChecked())
        self.subtitle_check.setEnabled(not is_thumbnail_only)
        self.auto_subtitle_check.setEnabled(not is_thumbnail_only and subtitles_active)
        self.subtitle_lang_combo.setEnabled(not is_thumbnail_only and subtitles_active)
        self.thumbnail_check.setEnabled(not is_subtitles_only)

    # ------------------------------------------------------------------ actions

    def paste_from_clipboard(self) -> None:
        text = QApplication.clipboard().text().strip()
        if not text:
            return
        existing = self.url_edit.toPlainText().strip()
        self.url_edit.setPlainText(f"{existing}\n{text}".strip())

    def add_to_queue(self) -> bool:
        urls = split_urls(self.url_edit.toPlainText())
        if not urls:
            QMessageBox.information(self, APP_NAME, "Paste at least one YouTube URL.")
            return False

        invalid = [url for url in urls if not is_youtube_url(url)]
        if invalid:
            QMessageBox.warning(self, APP_NAME, "Invalid URL:\n" + invalid[0])
            return False

        for url in urls:
            self._append_job(DownloadJob(url=url))
        self.url_edit.clear()
        self.log(f"Queued {len(urls)} job(s)")
        return True

    def _append_job(self, job: DownloadJob) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.jobs.append(job)
        self.row_by_job_id[job.job_id] = row

        source_item = QTableWidgetItem(job.url)
        source_item.setToolTip(job.url)
        self.table.setItem(row, 0, source_item)
        self.table.setItem(row, 1, QTableWidgetItem(self._current_mode().label))

        status_item = QTableWidgetItem("Queued")
        status_font = status_item.font()
        status_font.setBold(True)
        status_item.setFont(status_font)
        status_item.setForeground(_status_color("Queued"))
        self.table.setItem(row, 2, status_item)
        self.table.setItem(row, 4, QTableWidgetItem(""))

        progress = QProgressBar()
        progress.setRange(0, 100)
        progress.setValue(0)
        progress.setFixedHeight(18)
        self.progress_by_job_id[job.job_id] = progress
        cell = QWidget()
        cell_layout = QHBoxLayout(cell)
        cell_layout.setContentsMargins(8, 0, 8, 0)
        cell_layout.addWidget(progress)
        self.table.setCellWidget(row, 3, cell)
        self._refresh_queue_summary()

    def start_queue(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        if self.diagnostics_worker and self.diagnostics_worker.isRunning():
            QMessageBox.information(self, APP_NAME, "Wait for diagnostics to finish before starting downloads.")
            return
        runnable_jobs = self._runnable_jobs()
        if not runnable_jobs:
            if not self.add_to_queue():
                return
            runnable_jobs = self._runnable_jobs()

        self._start_download_worker(runnable_jobs, reset_auth_attempts=True)

    def _start_download_worker(
        self,
        runnable_jobs: list[DownloadJob],
        *,
        reset_auth_attempts: bool,
    ) -> None:
        if not runnable_jobs or (self.worker and self.worker.isRunning()):
            return
        for job in runnable_jobs:
            if reset_auth_attempts:
                self._auth_retry_counts.pop(job.job_id, None)
            row = self.row_by_job_id.get(job.job_id)
            if row is None:
                continue
            self._set_status(row, "Queued")
            self._set_detail(row, "")
            progress = self.progress_by_job_id.get(job.job_id)
            if progress:
                progress.setValue(0)

        options = self._collect_options()
        self._set_running_state(True)
        self.log("Starting queue" if reset_auth_attempts else "Resuming authenticated job(s)")

        worker = DownloadWorker(runnable_jobs, options)
        self.worker = worker
        worker.job_started.connect(self.on_job_started)
        worker.progress.connect(self.on_progress)
        worker.job_finished.connect(self.on_job_finished)
        worker.log.connect(self.log)
        worker.finished.connect(self.on_batch_finished)
        worker.start()

    def _resume_authenticated_jobs(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        job_ids = set(self._auth_resume_job_ids)
        if not job_ids:
            return
        self._auth_resume_job_ids.clear()
        jobs = [job for job in self.jobs if job.job_id in job_ids]
        self._start_download_worker(jobs, reset_auth_attempts=False)

    def stop_queue(self) -> None:
        if self.worker and self.worker.isRunning():
            self.log("Cancellation requested")
            worker_job_id = self.worker.request_stop()
            job_id = self.active_job_id or worker_job_id
            if job_id:
                row = self.row_by_job_id.get(job_id)
                if row is not None:
                    self._set_status(row, "Cancelling")
                    self._set_detail(row, "Cancelling download")
            self.statusBar().showMessage("Cancelling download")
            self.stop_button.setText("Cancelling...")
            self.stop_button.setEnabled(False)

    def _runnable_jobs(self) -> list[DownloadJob]:
        runnable_statuses = {"Queued", "Failed", "Cancelled"}
        jobs: list[DownloadJob] = []
        for job in self.jobs:
            row = self.row_by_job_id.get(job.job_id)
            item = self.table.item(row, 2) if row is not None else None
            if item is not None and item.text() in runnable_statuses:
                jobs.append(job)
        return jobs

    def clear_queue(self) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, APP_NAME, "Stop the queue before clearing it.")
            return
        self.jobs.clear()
        self.row_by_job_id.clear()
        self.progress_by_job_id.clear()
        self.table.setRowCount(0)
        self.log_box.clear()
        self._refresh_queue_summary()

    def run_diagnostics(self) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, APP_NAME, "Stop the queue before running diagnostics.")
            return
        if self.diagnostics_worker and self.diagnostics_worker.isRunning():
            self.statusBar().showMessage("Diagnostics already running")
            return

        self.log("Starting environment diagnostics")
        self.statusBar().showMessage("Running diagnostics")
        if hasattr(self, "diagnostics_button"):
            self.diagnostics_button.setEnabled(False)

        self.diagnostics_worker = DiagnosticsWorker(
            self._collect_options(),
            self._diagnostic_probe_url(),
        )
        self.diagnostics_worker.line.connect(self.log)
        self.diagnostics_worker.error.connect(self.on_diagnostics_error)
        self.diagnostics_worker.finished.connect(self.on_diagnostics_finished)
        self.diagnostics_worker.start()

    def _diagnostic_probe_url(self) -> str | None:
        for url in split_urls(self.url_edit.toPlainText()):
            if is_youtube_url(url):
                return url
        if self.jobs:
            return self.jobs[0].url
        return None
        self.statusBar().showMessage("Queue cleared")

    def _refresh_youtube_connection_ui(self) -> None:
        if not hasattr(self, "youtube_connection_status"):
            return
        for connection in self.youtube_connections.values():
            connection.refresh_browser_state()
        manager = self._active_connection_manager() or self.youtube_connection
        snapshot = manager.snapshot()
        browser_open = next(
            (
                connection
                for connection in self.youtube_connections.values()
                if connection.browser_is_open()
            ),
            None,
        )
        if snapshot.state == ConnectionState.CONNECTED:
            verified = snapshot.last_verified.replace("T", " ").replace("+00:00", " UTC")
            text = f"Status: Connected · Last verified: {verified or 'unknown'}"
        elif snapshot.state == ConnectionState.EXPIRED:
            text = "Status: Expired · Renew the connection in the same dedicated profile"
        elif snapshot.state in {
            ConnectionState.ERROR,
            ConnectionState.INVALID,
            ConnectionState.LOCKED,
            ConnectionState.FIREFOX_MISSING,
        }:
            text = "Status: Needs attention"
        else:
            text = "Status: Not connected"
        if browser_open is not None:
            text = f"Status: Browser open / {browser_open.display_name}"
        self.youtube_connection_status.setText(text)
        self.youtube_profile_label.setText(
            f"Browser: {manager.display_name} / Profile: Dedicated OpenFetch profile"
        )
        connected = snapshot.state == ConnectionState.CONNECTED
        renew = snapshot.state in {
            ConnectionState.CONNECTED,
            ConnectionState.EXPIRED,
            ConnectionState.INVALID,
            ConnectionState.LOCKED,
            ConnectionState.ERROR,
        }
        queue_running = bool(self.worker and self.worker.isRunning())
        chrome = self.youtube_connections[ManagedBrowser.CHROME]
        firefox = self.youtube_connections[ManagedBrowser.FIREFOX]
        self.youtube_connect_button.setVisible(
            chrome.state not in {ConnectionState.CONNECTED, ConnectionState.BROWSER_OPEN}
        )
        self.youtube_connect_button.setEnabled(not queue_running)
        self.youtube_renew_button.setVisible(renew)
        self.youtube_renew_button.setEnabled(not queue_running)
        self.youtube_test_button.setEnabled((connected or renew) and not queue_running)
        self.youtube_disconnect_button.setVisible(chrome.profile_path.exists())
        self.youtube_disconnect_button.setEnabled(chrome.profile_path.exists() and not queue_running)
        self.youtube_firefox_button.setVisible(firefox.state != ConnectionState.CONNECTED)
        self.youtube_firefox_button.setEnabled(not queue_running)
        self.youtube_firefox_disconnect_button.setVisible(firefox.profile_path.exists())
        self.youtube_firefox_disconnect_button.setEnabled(
            firefox.profile_path.exists() and not queue_running
        )

    def refresh_optional_po_helper_status(self) -> None:
        """Refresh helper state asynchronously; absence never disables downloads."""
        worker = self.po_helper_status_worker
        if worker is not None and worker.isRunning():
            return
        self.optional_po_helper_status.setText(
            "Status: Checking separately installed optional helper..."
        )
        self.optional_po_helper_refresh_button.setEnabled(False)
        worker = OptionalPoHelperStatusWorker()
        self.po_helper_status_worker = worker
        worker.status_ready.connect(self._on_optional_po_helper_status)
        worker.unavailable.connect(self._on_optional_po_helper_status_error)
        worker.finished.connect(self._on_optional_po_helper_status_finished)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    @Slot(object)
    def _on_optional_po_helper_status(self, status: object) -> None:
        if not isinstance(status, PoTokenProviderStatus):
            self._on_optional_po_helper_status_error()
            return
        if status.available and status.integrity_verified:
            text = (
                "Status: Installed separately and integrity verified - "
                f"helper {status.helper_version} / provider {status.version} / "
                f"protocol v{status.protocol_version}"
            )
        elif not status.installed:
            text = (
                "Status: Not installed (optional) - Normal downloads remain available. "
                "Installation is always manual."
            )
        else:
            text = f"Status: Unavailable - {status.diagnostic}"
        self.optional_po_helper_status.setText(text)

    @Slot()
    def _on_optional_po_helper_status_error(self) -> None:
        self.optional_po_helper_status.setText(
            "Status: Unavailable - Normal downloads remain available."
        )

    @Slot()
    def _on_optional_po_helper_status_finished(self) -> None:
        self.optional_po_helper_refresh_button.setEnabled(True)
        self.po_helper_status_worker = None

    def open_optional_po_helper_instructions(self) -> None:
        """Open only the packaged, first-party manual installation guide."""
        instructions = base_dir() / "docs" / "OPTIONAL-PO-PROVIDER.md"
        if not instructions.is_file():
            QMessageBox.information(
                self,
                APP_NAME,
                "The optional-helper installation guide is not available in this build.",
            )
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(instructions)))

    def _active_connection_manager(self) -> YouTubeConnectionManager | None:
        """Return the exact verified provider, with one fail-closed migration."""
        stored = str(self.settings.value(ACTIVE_PROVIDER_KEY, "") or "").strip().casefold()
        if stored:
            try:
                return self.youtube_connections[ManagedBrowser(stored)]
            except (KeyError, ValueError):
                return None

        connected = [
            manager
            for manager in self.youtube_connections.values()
            if manager.connected_profile() is not None
        ]
        selected: YouTubeConnectionManager | None = None
        if len(connected) == 1:
            selected = connected[0]
        elif len(connected) > 1:
            verified: list[tuple[float, YouTubeConnectionManager]] = []
            for manager in connected:
                try:
                    parsed = datetime.fromisoformat(
                        manager.last_verified.replace("Z", "+00:00")
                    )
                    if parsed.tzinfo is None:
                        raise ValueError("timestamp has no timezone")
                    verified.append((parsed.timestamp(), manager))
                except (OverflowError, OSError, ValueError):
                    verified = []
                    break
            verified.sort(key=lambda item: item[0], reverse=True)
            if len(verified) == len(connected) and verified[0][0] > verified[1][0]:
                selected = verified[0][1]

        if selected is not None:
            self.settings.setValue(ACTIVE_PROVIDER_KEY, selected.browser.value)
            self.settings.sync()
        return selected

    def _connected_connection_manager(self) -> YouTubeConnectionManager | None:
        manager = self._active_connection_manager()
        if manager is not None and manager.connected_profile() is not None:
            return manager
        return None

    def _connection_target_url(self) -> str:
        if self._auth_waiting_job_ids:
            for job in self.jobs:
                if job.job_id in self._auth_waiting_job_ids:
                    return job.url
        probe = self._diagnostic_probe_url()
        return probe or "https://www.youtube.com/"

    def connect_youtube(
        self,
        _checked: bool = False,
        *,
        renewal: bool = False,
        target_url: str | None = None,
        browser: ManagedBrowser | str = ManagedBrowser.CHROME,
    ) -> bool:
        del _checked
        selected_browser = ManagedBrowser(browser)
        manager = self.youtube_connections[selected_browser]
        dialog = YouTubeConnectionDialog(
            manager,
            target_url or self._connection_target_url(),
            renewal=renewal,
            parent=self,
        )
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        self._refresh_youtube_connection_ui()
        if (
            not accepted
            and dialog.fallback_requested
            and selected_browser is ManagedBrowser.CHROME
        ):
            return self.connect_youtube(
                renewal=self.youtube_connections[ManagedBrowser.FIREFOX].profile_path.exists(),
                target_url=target_url,
                browser=ManagedBrowser.FIREFOX,
            )
        if accepted:
            self.youtube_connection = manager
            self.log(
                f"YouTube connection verified using the dedicated OpenFetch "
                f"{manager.display_name} profile."
            )
            self.statusBar().showMessage("YouTube session verified")
        return accepted

    def test_youtube_connection(self) -> None:
        manager = self._active_connection_manager() or self.youtube_connection
        self.connect_youtube(
            renewal=manager.snapshot().state == ConnectionState.EXPIRED,
            target_url=self._connection_target_url(),
            browser=manager.browser,
        )

    def disconnect_youtube(
        self,
        _checked: bool = False,
        *,
        browser: ManagedBrowser | str = ManagedBrowser.CHROME,
    ) -> None:
        del _checked
        manager = self.youtube_connections[ManagedBrowser(browser)]
        reply = QMessageBox.question(
            self,
            "YouTube loskoppelen",
            f"Remove the dedicated {manager.display_name} YouTube session? Normal browser "
            "profiles and cookies.txt will not be changed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        result = manager.disconnect()
        self._refresh_youtube_connection_ui()
        if result.success:
            self.log(
                f"YouTube disconnected; the dedicated {manager.display_name} profile was removed."
            )
            QMessageBox.information(self, APP_NAME, result.message)
            return
        message = result.message
        if result.manual_cleanup_path:
            message += f"\n\nManual cleanup path:\n{result.manual_cleanup_path}"
        self.log(f"YouTube disconnect failed ({result.code}): {result.message}")
        QMessageBox.warning(self, APP_NAME, message)

    def browse_output(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose output folder", str(self.output_dir))
        if not folder:
            return
        self.output_dir = Path(folder)
        self.output_edit.setText(str(self.output_dir))
        self.output_edit.setToolTip(str(self.output_dir))
        self.settings.setValue("output_dir", str(self.output_dir))
        self.log(f"Output folder: {self.output_dir}")

    def browse_cookie_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select cookies.txt",
            str(Path.home()),
            "Cookies file (*.txt);;All files (*)",
        )
        if not path:
            return
        self.cookie_file = Path(path)
        self.cookie_edit.setText(path)
        self.settings.setValue("cookie_file", path)
        self.log(f"cookies.txt loaded: {self.cookie_file.name}")

    def clear_cookie_file(self) -> None:
        self.cookie_file = None
        self.cookie_edit.clear()
        self.settings.remove("cookie_file")
        self.log("cookies.txt cleared; the guided YouTube connection remains the normal workflow")

    def _save_legacy_browser_fallback(self) -> None:
        enabled = self.legacy_browser_check.isChecked()
        self.settings.setValue("youtube_connection/legacy_browser_fallback", enabled)
        self.log(
            "Legacy browser-profile fallback enabled"
            if enabled
            else "Legacy browser-profile fallback disabled"
        )

    def open_output_folder(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.output_dir)))

    def check_for_updates(self, silent: bool = False) -> None:
        if self.update_install_worker and self.update_install_worker.isRunning():
            if not silent:
                self.statusBar().showMessage("An update installation is already in progress")
            return
        if self.update_worker and self.update_worker.isRunning():
            if not silent:
                self.statusBar().showMessage("Update check already running")
            return

        self.update_check_silent = silent
        if hasattr(self, "update_button"):
            self.update_button.setEnabled(False)
        if not silent:
            self.statusBar().showMessage("Checking GitHub Releases...")
            self.log("Checking for updates")

        self.update_worker = UpdateCheckWorker(VERSION)
        self.update_worker.update_available.connect(self.on_update_available)
        self.update_worker.up_to_date.connect(self.on_update_up_to_date)
        self.update_worker.error.connect(self.on_update_error)
        self.update_worker.finished.connect(self.on_update_check_finished)
        self.update_worker.start()

    @Slot(object)
    def on_update_available(self, info: UpdateInfo) -> None:
        self.statusBar().showMessage(f"Update available: {info.tag_name}")
        self.log(f"Update available: {info.tag_name}")

        capability = assess_installation_capability(info.manifest)
        body = " ".join(info.body.split())
        if len(body) > 650:
            body = body[:650].rstrip() + "..."
        release_name = " ".join(info.name.split())[:160] or info.tag_name
        size_mb = info.download_size / (1024 * 1024)

        message = (
            f"{release_name} is available.\n\n"
            f"Current version: {VERSION}\n"
            f"Latest version: {info.version}\n"
            f"Download size: {size_mb:.1f} MB\n\n"
        )
        if body:
            message += f"Release notes:\n{body}\n\n"

        dialog = QMessageBox(self)
        dialog.setWindowTitle("Update Available")
        dialog.setIcon(QMessageBox.Icon.Information)
        if capability.available:
            message += (
                "The package will be downloaded and verified before installation. "
                "OpenFetch will restart after you confirm this action."
            )
            install_button = dialog.addButton(
                "Download and Install",
                QMessageBox.ButtonRole.AcceptRole,
            )
            manual_button = None
        else:
            message += (
                "Automatic installation is unavailable on this copy.\n\n"
                f"Reason: {capability.reason}\n\n"
                "You can open the verified release download page and install it manually."
            )
            install_button = None
            manual_button = dialog.addButton(
                "Open Download Page",
                QMessageBox.ButtonRole.ActionRole,
            )
        dialog.addButton("Later", QMessageBox.ButtonRole.RejectRole)
        dialog.setText(message)
        dialog.exec()

        clicked = dialog.clickedButton()
        if install_button is not None and clicked is install_button:
            self.start_update_install(info)
        elif manual_button is not None and clicked is manual_button:
            QDesktopServices.openUrl(QUrl(info.html_url))

    def start_update_install(self, info: UpdateInfo) -> None:
        if self.update_install_worker and self.update_install_worker.isRunning():
            return
        if self.worker and self.worker.isRunning():
            QMessageBox.information(
                self,
                APP_NAME,
                "Stop the download queue before installing an update.",
            )
            return
        if self.diagnostics_worker and self.diagnostics_worker.isRunning():
            QMessageBox.information(
                self,
                APP_NAME,
                "Wait for diagnostics to finish before installing an update.",
            )
            return
        self.log(f"Starting verified update download: {info.tag_name}")
        self.statusBar().showMessage("Downloading update")
        self._set_update_install_state(True)

        dialog = QProgressDialog("Downloading update", "Cancel", 0, 100, self)
        dialog.setWindowTitle("OpenFetch Update")
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.setMinimumDuration(0)
        dialog.setAutoClose(False)
        dialog.setAutoReset(False)
        dialog.setValue(0)
        self.update_progress_dialog = dialog

        worker = UpdateInstallWorker(info)
        self.update_install_worker = worker
        self.update_install_outcome = "running"
        worker.progress.connect(self.on_update_install_progress)
        worker.prepared.connect(self.on_update_install_prepared)
        worker.error.connect(self.on_update_install_error)
        worker.cancelled.connect(self.on_update_install_cancelled)
        worker.cancellation_locked.connect(self.on_update_cancellation_locked)
        worker.finished.connect(self.on_update_install_finished)
        dialog.canceled.connect(self.cancel_update_install)
        worker.start()
        dialog.show()

    def cancel_update_install(self) -> None:
        if not self.update_install_worker or not self.update_install_worker.isRunning():
            return
        if self.update_install_worker.request_cancel():
            if self.update_progress_dialog:
                self.update_progress_dialog.setLabelText("Cancelling update download...")
            return
        self.on_update_cancellation_locked()

    @Slot()
    def on_update_cancellation_locked(self) -> None:
        if self.update_progress_dialog:
            self.update_progress_dialog.setCancelButton(None)
            self.update_progress_dialog.setLabelText(
                "Preparing the secure updater handoff. This step cannot be cancelled."
            )
        self.statusBar().showMessage("Preparing secure updater handoff")

    @Slot(int, str)
    def on_update_install_progress(self, percent: int, message: str) -> None:
        if self.update_progress_dialog:
            self.update_progress_dialog.setValue(percent)
            self.update_progress_dialog.setLabelText(message)
        self.statusBar().showMessage(message)

    @Slot(object)
    def on_update_install_prepared(self, prepared: PreparedUpdate) -> None:
        self.update_install_outcome = "restart"
        self.log(
            f"Verified updater handoff accepted by helper process {prepared.helper_pid}; "
            f"transaction={prepared.transaction_id[:12]}"
        )
        self.statusBar().showMessage("Update verified. OpenFetch will restart now.")
        if self.update_progress_dialog:
            self.update_progress_dialog.setCancelButton(None)
            self.update_progress_dialog.setValue(100)
            self.update_progress_dialog.setLabelText(
                "Update verified. OpenFetch will restart now."
            )
        QTimer.singleShot(900, self._quit_for_update)

    @Slot(str, str)
    def on_update_install_error(self, code: str, message: str) -> None:
        self.update_install_outcome = "error"
        self.log(f"Update failed ({code}): {message}")
        self.statusBar().showMessage("Update failed; the current application was not replaced")
        if self.update_progress_dialog:
            self.update_progress_dialog.close()
            self.update_progress_dialog = None
        QMessageBox.warning(self, "Update Failed", message)

    @Slot()
    def on_update_install_cancelled(self) -> None:
        self.update_install_outcome = "cancelled"
        self.log("Update download cancelled; the current application was not changed")
        self.statusBar().showMessage("Update cancelled")
        if self.update_progress_dialog:
            self.update_progress_dialog.close()
            self.update_progress_dialog = None

    @Slot()
    def on_update_install_finished(self) -> None:
        self.update_install_worker = None
        if self.update_install_outcome != "restart":
            self._set_update_install_state(False)

    def _quit_for_update(self) -> None:
        application = QApplication.instance()
        if application:
            application.quit()

    def _set_update_install_state(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.clear_button.setEnabled(not running)
        self.update_button.setEnabled(not running)
        self.diagnostics_button.setEnabled(not running)

    @Slot()
    def on_update_up_to_date(self) -> None:
        if self.update_check_silent:
            return
        self.statusBar().showMessage("You are running the latest version")
        self.log("No update available")
        QMessageBox.information(self, APP_NAME, "You are running the latest version.")

    @Slot(str, str)
    def on_update_error(self, code: str, error: str) -> None:
        if self.update_check_silent:
            return
        self.statusBar().showMessage("Update check failed")
        self.log(f"Update check failed ({code}): {error}")
        QMessageBox.warning(self, APP_NAME, f"Could not check for updates:\n{error}")

    @Slot()
    def on_update_check_finished(self) -> None:
        if hasattr(self, "update_button") and not (
            self.update_install_worker and self.update_install_worker.isRunning()
        ):
            self.update_button.setEnabled(True)
        self.update_worker = None

    @Slot(str)
    def on_diagnostics_error(self, error: str) -> None:
        self.log(f"Diagnostics failed: {error}")
        self.statusBar().showMessage("Diagnostics failed")

    @Slot()
    def on_diagnostics_finished(self) -> None:
        self.log("Diagnostics finished")
        self.statusBar().showMessage("Diagnostics finished")
        if hasattr(self, "diagnostics_button"):
            self.diagnostics_button.setEnabled(True)
        self.diagnostics_worker = None

    def _show_js_runtime_warning(self) -> None:
        QMessageBox.warning(self, APP_NAME, MISSING_JS_RUNTIME_MESSAGE)

    def _collect_options(self) -> DownloadOptions:
        mode = self._current_mode()
        subtitle_enabled = self.subtitle_check.isChecked() or mode == MediaMode.SUBTITLES_ONLY
        thumbnail_enabled = self.thumbnail_check.isChecked() or mode == MediaMode.THUMBNAIL_ONLY
        connection = self._connected_connection_manager()
        return DownloadOptions(
            output_dir=self.output_dir,
            media_mode=mode,
            playlist_mode=PlaylistMode(self.playlist_combo.currentData()),
            quality=self.quality_combo.currentText(),
            audio_quality=str(self.audio_quality_combo.currentData()),
            subtitles=subtitle_enabled,
            auto_subtitles=self.auto_subtitle_check.isChecked(),
            subtitle_language=str(self.subtitle_lang_combo.currentData()),
            thumbnail=thumbnail_enabled,
            embed_thumbnail=self.embed_thumb_check.isChecked(),
            metadata_json=self.metadata_check.isChecked(),
            cookie_file=self.cookie_file,
            dedicated_browser=connection.browser.value if connection else None,
            dedicated_browser_profile=connection.connected_profile() if connection else None,
            dedicated_browser_last_verified=connection.last_verified if connection else None,
            guided_youtube_auth=True,
            legacy_browser_fallback=self.legacy_browser_check.isChecked(),
        )

    # ------------------------------------------------------------------ worker slots

    @Slot(str, str)
    def on_job_started(self, job_id: str, url: str) -> None:
        row = self.row_by_job_id.get(job_id)
        if row is None:
            return
        self.active_job_id = job_id
        self._set_status(row, "Starting")
        self._set_detail(row, url)
        self.statusBar().showMessage(f"Starting {url}")

    @Slot(str, int, str, str)
    def on_progress(self, job_id: str, percent: int, status: str, detail: str) -> None:
        row = self.row_by_job_id.get(job_id)
        if row is None:
            return
        current_item = self.table.item(row, 2)
        if (
            current_item is not None
            and current_item.text() == "Cancelling"
            and status != "Cancelling"
        ):
            return
        progress = self.progress_by_job_id.get(job_id)
        if progress:
            progress.setValue(percent)
        self._set_status(row, status)
        self._set_detail(row, detail)
        self.statusBar().showMessage(detail or status)

    @Slot(str, bool, str, str)
    def on_job_finished(
        self,
        job_id: str,
        success: bool,
        message: str,
        failure_category: str = "",
    ) -> None:
        row = self.row_by_job_id.get(job_id)
        if row is None:
            return
        normalized_category = failure_category.strip().lower().replace("-", "_").replace(" ", "_")
        guided_auth_failures = {
            "authentication_required",
            "youtube_session_expired",
            "dedicated_profile_invalid",
            "verified_provider_not_applied",
            "browser_cookie_database_locked",
            "browser_cookie_decryption_failed",
            "browser_cookie_extraction_failed",
        }
        if (
            not success
            and normalized_category in guided_auth_failures
            and self._auth_retry_counts.get(job_id, 0) < 1
        ):
            self._queue_youtube_connection_assistant(
                job_id,
                row,
                normalized_category,
                message,
            )
            return
        if not success and normalized_category == "youtube_session_expired":
            manager = self._active_connection_manager()
            if manager is not None:
                manager.mark_expired(message)
            self._refresh_youtube_connection_ui()
        if not success and normalized_category in {
            "po_token_provider_unavailable",
            "po_token_fetch_failed",
            "po_token_media_403",
            "po_token_required",
        }:
            self.optional_po_helper_status.setText(
                "Status: Optional helper unavailable or unsuccessful - "
                "ordinary downloads remain enabled; installation is always manual."
            )
        cancelled = normalized_category in {
            "cancelled",
            "download_cancelled",
            "user_cancelled",
            "user_cancellation",
        } or message.strip().lower() in {
            "cancelled",
            "download cancelled by user",
        }
        if success:
            status = "Done"
        elif cancelled:
            status = "Cancelled"
        else:
            status = "Failed"
        self._set_status(row, status)
        progress = self.progress_by_job_id.get(job_id)
        if progress:
            progress.setValue(100 if success else progress.value())
        self._set_detail(row, message)
        self.log(message)
        if self.active_job_id == job_id:
            self.active_job_id = None
        self._refresh_queue_summary()

    def _queue_youtube_connection_assistant(
        self,
        job_id: str,
        row: int,
        failure_category: str,
        message: str,
    ) -> None:
        self._auth_waiting_job_ids.add(job_id)
        self._set_status(row, "Waiting for YouTube")
        self._set_detail(row, "Authentication required · YouTube verbinden")
        self.log(f"Authentication required ({failure_category}): {message}")
        if self.active_job_id == job_id:
            self.active_job_id = None
        manager = self._active_connection_manager() or self.youtube_connection
        if manager.profile_path.exists():
            manager.mark_expired(message)
        self._refresh_youtube_connection_ui()
        self._refresh_queue_summary()
        if not self._auth_dialog_active:
            self._auth_dialog_active = True
            QTimer.singleShot(0, self._show_pending_connection_assistant)

    def _show_pending_connection_assistant(self) -> None:
        if not self._auth_waiting_job_ids:
            self._auth_dialog_active = False
            return
        target_url = self._connection_target_url()
        manager = self._active_connection_manager() or self.youtube_connection
        snapshot = manager.snapshot()
        renewal = bool(snapshot.last_verified or manager.profile_path.exists())
        accepted = self.connect_youtube(
            renewal=renewal,
            target_url=target_url,
            browser=manager.browser,
        )
        pending = set(self._auth_waiting_job_ids)
        self._auth_waiting_job_ids.clear()
        self._auth_dialog_active = False
        if accepted:
            for job_id in pending:
                self._auth_retry_counts[job_id] = self._auth_retry_counts.get(job_id, 0) + 1
                self._auth_resume_job_ids.add(job_id)
                row = self.row_by_job_id.get(job_id)
                if row is not None:
                    self._set_status(row, "Queued")
                    self._set_detail(row, "YouTube connection verified; waiting to resume")
            if not (self.worker and self.worker.isRunning()):
                QTimer.singleShot(0, self._resume_authenticated_jobs)
        else:
            for job_id in pending:
                row = self.row_by_job_id.get(job_id)
                if row is not None:
                    self._set_status(row, "Failed")
                    self._set_detail(row, "Authentication required · verification cancelled")
            self.log("YouTube connection verification cancelled; original job was not resumed.")
        self._refresh_queue_summary()
        self._refresh_youtube_connection_ui()

    @Slot()
    def on_batch_finished(self, worker: DownloadWorker | None = None) -> None:
        if worker is None:
            sender = self.sender()
            worker = sender if isinstance(sender, DownloadWorker) else self.worker
        if worker is not None and self.worker is not worker:
            return
        stopped = bool(worker and worker.stop_requested)
        self._set_running_state(False)
        self.active_job_id = None
        message = "Queue stopped" if stopped else "Queue finished"
        self.statusBar().showMessage(message)
        self.log(message)
        self.worker = None
        self._refresh_youtube_connection_ui()
        self._refresh_queue_summary()
        if self._close_after_worker_stops:
            self._close_after_worker_stops = False
            QTimer.singleShot(0, self.close)
        elif self._auth_resume_job_ids and not self._auth_dialog_active:
            QTimer.singleShot(0, self._resume_authenticated_jobs)

    # ------------------------------------------------------------------ state

    def _set_status(self, row: int, status: str) -> None:
        item = self.table.item(row, 2)
        if item is None:
            return
        item.setText(status)
        item.setForeground(_status_color(status))

    def _set_detail(self, row: int, detail: str) -> None:
        item = self.table.item(row, 4)
        if item is None:
            return
        item.setText(detail)
        item.setToolTip(detail)

    def _refresh_queue_summary(self) -> None:
        total = self.table.rowCount()
        if total == 0:
            self.queue_summary.setText("Queue is empty")
            return
        done = failed = 0
        for row in range(total):
            item = self.table.item(row, 2)
            text = item.text() if item else ""
            if text == "Done":
                done += 1
            elif text in {"Failed", "Cancelled"}:
                failed += 1
        self.queue_summary.setText(f"{total} job(s)  ·  {done} done  ·  {failed} failed")

    def _set_running_state(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.clear_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.stop_button.setText("Stop")
        if hasattr(self, "diagnostics_button"):
            self.diagnostics_button.setEnabled(not running)
        for widget in self._run_locked_widgets():
            widget.setEnabled(not running)
        if not running:
            # Restore the mode-dependent enabled states the blanket unlock overwrote.
            self._update_mode_controls()

    @Slot(str)
    def log(self, message: str) -> None:
        self.log_box.append(f"[{datetime.now():%H:%M:%S}] {message}")

    def _restore_window_layout(self) -> None:
        geometry = self.settings.value("ui/window_geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        screen = self.screen() or QApplication.primaryScreen()
        if screen is not None:
            self.setGeometry(
                clamp_window_rect(
                    self.geometry(),
                    screen.availableGeometry(),
                    self.minimumSize(),
                )
            )

        raw_sizes = self.settings.value("ui/main_splitter_sizes", [440, 940])
        if not isinstance(raw_sizes, list | tuple):
            raw_sizes = [440, 940]
        usable = max(
            0,
            self.main_splitter.width() - self.main_splitter.handleWidth(),
        )
        sizes = clamp_splitter_sizes(
            usable,
            raw_sizes,
            minimum_left=self.side_panel.minimumWidth(),
            minimum_right=max(440, self.work_panel.minimumWidth()),
        )
        self.main_splitter.setSizes(list(sizes))

    def _save_window_layout(self) -> None:
        self.settings.setValue("ui/window_geometry", self.saveGeometry())
        self.settings.setValue("ui/main_splitter_sizes", self.main_splitter.sizes())
        self.settings.sync()

    def _scroll_widget_reachable(self, widget: QWidget) -> bool:
        self.settings_scroll.ensureWidgetVisible(widget, 4, 4)
        QApplication.processEvents()
        origin = widget.mapTo(self.settings_scroll.viewport(), QPoint(0, 0))
        mapped = QRect(origin, widget.size())
        return widget.isVisibleTo(self) and mapped.intersects(self.settings_scroll.viewport().rect())

    def responsive_layout_smoke_checks(self) -> dict[str, bool]:
        """Exercise widget geometry offline for unit and packaged smokes."""
        original_size = self.size()
        original_splitter = self.main_splitter.sizes()
        self.resize(self.minimumSize())
        self.main_splitter.setSizes([330, max(440, self.width() - 338)])
        QApplication.processEvents()
        self.connection_button_grid.set_available_width_for_test(
            self.connection_button_grid.width()
        )
        browse_visible = self._scroll_widget_reachable(self.browse_output_button)
        buttons_visible = all(
            self._scroll_widget_reachable(button)
            for button in (
                self.youtube_connect_button,
                self.youtube_renew_button,
                self.youtube_test_button,
                self.youtube_disconnect_button,
                self.youtube_firefox_button,
                self.youtube_firefox_disconnect_button,
            )
            if not button.isHidden()
        )
        narrow_path_width = self.output_edit.width()
        narrow_columns = self.connection_button_grid.column_count

        self.resize(max(1280, self.minimumWidth()), max(720, self.minimumHeight()))
        self.main_splitter.setSizes([540, max(440, self.width() - 548)])
        QApplication.processEvents()
        self.connection_button_grid.set_available_width_for_test(
            self.connection_button_grid.width()
        )
        wide_path_width = self.output_edit.width()
        moved_splitter = self.main_splitter.sizes()[0] > 400
        scenarios = (
            (1280, 720, 1.0),
            (1366, 768, 1.0),
            (1920, 1080, 1.0),
            (1920, 1080, 1.25),
            (1920, 1080, 1.5),
        )
        dpi_supported = all(
            logical_viewport_size(width, height, scale).width() >= self.minimumWidth()
            and logical_viewport_size(width, height, scale).height() >= self.minimumHeight()
            for width, height, scale in scenarios
        )
        checks = {
            "window_resizable": self.maximumWidth() > self.minimumWidth(),
            "browse_visible_at_minimum": browse_visible,
            "output_path_expands": wide_path_width > narrow_path_width,
            "connection_buttons_accessible": buttons_visible,
            "narrow_buttons_stack": narrow_columns == 1,
            "settings_vertically_scrollable": (
                self.settings_scroll.verticalScrollBar().maximum() > 0
                or self.settings_content.sizeHint().height()
                <= self.settings_scroll.viewport().height()
            ),
            "no_horizontal_settings_scroll": (
                self.settings_scroll.horizontalScrollBar().maximum() == 0
            ),
            "splitter_adjustable": moved_splitter,
            "queue_and_log_usable": self.table.width() > 0 and self.log_box.height() > 0,
            "dpi_scenarios_supported": dpi_supported,
        }
        self.resize(original_size)
        self.main_splitter.setSizes(original_splitter)
        QApplication.processEvents()
        return checks

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.po_helper_status_worker and self.po_helper_status_worker.isRunning():
            get_po_token_provider().cancel()
            if not self.po_helper_status_worker.wait(5000):
                self.statusBar().showMessage("Waiting for the optional helper check to stop safely")
                event.ignore()
                return
        if self.update_install_worker and self.update_install_worker.isRunning():
            if not self.update_install_worker.can_cancel():
                self.statusBar().showMessage(
                    "Secure updater handoff is in progress; OpenFetch will close when safe"
                )
                event.ignore()
                return
            reply = QMessageBox.question(
                self,
                APP_NAME,
                "An update is being downloaded and verified. Cancel it and close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.update_install_worker.request_cancel()
            self.update_install_worker.wait(5000)
            if self.update_install_worker and self.update_install_worker.isRunning():
                self.statusBar().showMessage("Waiting for the update download to cancel safely")
                event.ignore()
                return
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self,
                APP_NAME,
                "A download is still running. Stop it and close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._close_after_worker_stops = True
            self.stop_queue()
            event.ignore()
            return
        self._save_window_layout()
        event.accept()
