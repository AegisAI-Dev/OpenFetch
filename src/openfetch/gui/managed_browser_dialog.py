"""Responsive guided YouTube connection assistant for managed browser profiles."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from openfetch.config import APP_NAME
from openfetch.core.youtube_connection import (
    ConnectionState,
    ManagedBrowser,
    VerificationResult,
    YouTubeConnectionManager,
)
from openfetch.core.youtube_verifier import verify_dedicated_youtube_profile
from openfetch.gui.responsive_layout import ResponsiveButtonGrid

Verifier = Callable[[Path, str], VerificationResult]


class ConnectionVerificationWorker(QThread):
    completed = Signal(object)

    def __init__(
        self,
        manager: YouTubeConnectionManager,
        target_url: str,
        verifier: Verifier,
    ) -> None:
        super().__init__()
        self.manager = manager
        self.target_url = target_url
        self.verifier = verifier

    def run(self) -> None:
        self.completed.emit(self.manager.verify(self.verifier, self.target_url))


class YouTubeConnectionDialog(QDialog):
    """Explain, launch, monitor, and verify either managed browser provider."""

    def __init__(
        self,
        manager: YouTubeConnectionManager,
        target_url: str,
        *,
        renewal: bool = False,
        verifier: Verifier | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.manager = manager
        self.target_url = target_url
        self.renewal = renewal
        self.verifier = verifier or (
            lambda profile, url: verify_dedicated_youtube_profile(
                profile,
                url,
                browser=self.manager.browser,
            )
        )
        self.verification_worker: ConnectionVerificationWorker | None = None
        self.fallback_requested = False
        self._discovery_checked = False

        action = "renew" if renewal else "connect"
        self.setWindowTitle(f"YouTube {action} - {self.manager.display_name}")
        self.setModal(True)
        self.setMinimumSize(520, 500)
        self.resize(720, 640)
        self._build_ui()
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(750)
        self._poll_timer.timeout.connect(self._refresh_state)
        self._poll_timer.start()
        self._refresh_state()

    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(18, 16, 18, 16)
        root_layout.setSpacing(12)

        self.body_scroll = QScrollArea()
        self.body_scroll.setObjectName("connectionScroll")
        self.body_scroll.setWidgetResizable(True)
        self.body_scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(6, 4, 10, 4)
        layout.setSpacing(13)

        title = QLabel("YouTube connection renewal" if self.renewal else "Connect YouTube")
        title.setObjectName("panelTitle")
        layout.addWidget(title)

        browser = self.manager.display_name
        explanation = QLabel(
            "YouTube requested human verification. OpenFetch will open a separate "
            f"{browser} profile. Your normal {browser} data will not be changed. Sign in if "
            "needed, complete any bot or CAPTCHA check, confirm the requested video plays, "
            f"and then close the dedicated {browser} window completely."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        warning = QLabel(
            "Account notice: authenticated automated downloading can carry account restrictions. "
            "Use this connection only when required; a secondary YouTube account may be preferable."
        )
        warning.setWordWrap(True)
        warning.setObjectName("hintLabel")
        layout.addWidget(warning)

        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(separator)

        steps = QLabel(
            "1. Sign into YouTube if required.\n"
            "2. Complete any verification.\n"
            "3. Confirm the requested video plays.\n"
            f"4. Close the dedicated {browser} window completely.\n"
            "5. Return here and choose Opnieuw controleren."
        )
        steps.setWordWrap(True)
        layout.addWidget(steps)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("queueSummary")
        layout.addWidget(self.status_label)

        self.open_button = QPushButton(f"{browser} openen")
        self.open_button.setObjectName("primaryButton")
        self.open_button.clicked.connect(self._open_browser)
        self.select_button = QPushButton(f"{self.manager.browser.executable_name} kiezen...")
        self.select_button.clicked.connect(self._select_browser)
        self.fallback_button = QPushButton("Managed Firefox fallback gebruiken")
        self.fallback_button.clicked.connect(self._request_fallback)
        self.fallback_button.setVisible(False)
        self.browser_actions = ResponsiveButtonGrid(
            [self.open_button, self.select_button, self.fallback_button],
            two_column_width=560,
            four_column_width=1000,
        )
        layout.addWidget(self.browser_actions)

        privacy = QLabel(
            f"Privacy: {browser} stores the session only in the dedicated LocalAppData profile. "
            "OpenFetch never receives your password, never logs cookie values, and never "
            "uploads or imports a normal browser profile."
        )
        privacy.setWordWrap(True)
        privacy.setObjectName("hintLabel")
        layout.addWidget(privacy)
        layout.addStretch(1)
        self.body_scroll.setWidget(body)
        root_layout.addWidget(self.body_scroll, 1)

        self.verify_button = QPushButton("Opnieuw controleren")
        self.verify_button.clicked.connect(self._verify)
        self.cancel_button = QPushButton("Annuleren")
        self.cancel_button.clicked.connect(self.reject)
        self.dialog_actions = ResponsiveButtonGrid(
            [self.verify_button, self.cancel_button],
            two_column_width=420,
            four_column_width=1000,
        )
        root_layout.addWidget(self.dialog_actions)

    def _refresh_state(self) -> None:
        if self.verification_worker and self.verification_worker.isRunning():
            return
        state = self.manager.refresh_browser_state()
        if not self._discovery_checked and state == ConnectionState.NOT_CONFIGURED:
            self._discovery_checked = True
            self.manager.discover_browser()
            state = self.manager.state
        browser = self.manager.display_name
        messages = {
            ConnectionState.NOT_CONFIGURED: f"Ready to create the dedicated {browser} profile.",
            ConnectionState.FIREFOX_MISSING: (
                f"{browser} is not installed or its executable is invalid."
            ),
            ConnectionState.PROFILE_READY: "Dedicated profile is ready.",
            ConnectionState.WAITING_FOR_LOGIN: f"{browser} closed. You can verify the session now.",
            ConnectionState.BROWSER_OPEN: (
                f"Dedicated {browser} is open. Close it before verification."
            ),
            ConnectionState.VERIFYING: "Verifying the YouTube session...",
            ConnectionState.CONNECTED: "YouTube session verified.",
            ConnectionState.EXPIRED: f"YouTube session expired. Reopen {browser} to renew it.",
            ConnectionState.LOCKED: "Managed profile data is locked by another process.",
            ConnectionState.INVALID: "YouTube sign-in was not completed.",
            ConnectionState.DISCONNECTED: "YouTube is not connected.",
            ConnectionState.ERROR: "The YouTube connection needs attention.",
        }
        self.status_label.setText(messages[state])
        missing = state == ConnectionState.FIREFOX_MISSING
        self.select_button.setVisible(missing)
        if missing and self.manager.browser is ManagedBrowser.CHROME:
            self.fallback_button.setVisible(True)

    def _select_browser(self) -> None:
        executable = self.manager.browser.executable_name
        path, _ = QFileDialog.getOpenFileName(
            self,
            f"Select {executable}",
            "",
            f"{self.manager.display_name} ({executable});;Applications (*.exe)",
        )
        if not path:
            return
        if not self.manager.set_browser_path(path):
            QMessageBox.warning(
                self,
                APP_NAME,
                f"{self.manager.display_name} executable is invalid.",
            )
        self._refresh_state()

    def _open_browser(self) -> None:
        try:
            self.manager.launch(self.target_url)
        except RuntimeError as exc:
            message = str(exc)
            if "not installed" in message.casefold():
                message = (
                    f"{self.manager.display_name} is not installed. Install it or select "
                    f"{self.manager.browser.executable_name} manually."
                )
                if self.manager.browser is ManagedBrowser.CHROME:
                    self.fallback_button.setVisible(True)
            QMessageBox.warning(self, APP_NAME, message)
        else:
            self.open_button.setText(f"{self.manager.display_name} opnieuw openen")
        self._refresh_state()

    def _verify(self) -> None:
        if self.verification_worker and self.verification_worker.isRunning():
            return
        if self.manager.browser_is_open():
            QMessageBox.information(
                self,
                APP_NAME,
                f"Close the dedicated {self.manager.display_name} window before checking again.",
            )
            self._refresh_state()
            return
        self._set_verifying(True)
        worker = ConnectionVerificationWorker(self.manager, self.target_url, self.verifier)
        self.verification_worker = worker
        worker.completed.connect(self._verification_finished)
        worker.finished.connect(self._verification_thread_finished)
        worker.start()

    def _set_verifying(self, verifying: bool) -> None:
        for button in (
            self.open_button,
            self.select_button,
            self.fallback_button,
            self.verify_button,
            self.cancel_button,
        ):
            button.setEnabled(not verifying)
        if verifying:
            self.status_label.setText("Verifying the YouTube session...")

    @Slot(object)
    def _verification_finished(self, result: VerificationResult) -> None:
        self._set_verifying(False)
        if result.success:
            message = result.message
            if result.warning:
                message += f"\n\n{result.warning}"
            QMessageBox.information(self, APP_NAME, message)
            self.accept()
            return
        self.status_label.setText(result.message)
        if self.manager.browser is ManagedBrowser.CHROME and result.code in {
            "cookie_decryption_failed",
            "cookie_extraction_unsupported",
        }:
            self.fallback_button.setVisible(True)
        QMessageBox.warning(self, APP_NAME, result.message)

    @Slot()
    def _verification_thread_finished(self) -> None:
        self.verification_worker = None
        self._set_verifying(False)
        self._refresh_state()

    def _request_fallback(self) -> None:
        self.fallback_requested = True
        self.reject()

    def closeEvent(self, event) -> None:  # noqa: N802
        self._poll_timer.stop()
        super().closeEvent(event)


__all__ = ["ConnectionVerificationWorker", "YouTubeConnectionDialog"]
