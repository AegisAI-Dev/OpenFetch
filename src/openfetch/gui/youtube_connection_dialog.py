"""Guided YouTube connection assistant using an isolated Firefox profile."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from openfetch.config import APP_NAME
from openfetch.core.youtube_connection import (
    ConnectionState,
    VerificationResult,
    YouTubeConnectionManager,
)
from openfetch.core.youtube_verifier import verify_dedicated_youtube_profile
from openfetch.gui.managed_browser_dialog import (
    ConnectionVerificationWorker as ManagedConnectionVerificationWorker,
)
from openfetch.gui.managed_browser_dialog import (
    YouTubeConnectionDialog as ManagedYouTubeConnectionDialog,
)

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
        result = self.manager.verify(self.verifier, self.target_url)
        self.completed.emit(result)


class YouTubeConnectionDialog(QDialog):
    """Explain, launch, and verify the managed browser session."""

    def __init__(
        self,
        manager: YouTubeConnectionManager,
        target_url: str,
        *,
        renewal: bool = False,
        verifier: Verifier = verify_dedicated_youtube_profile,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.manager = manager
        self.target_url = target_url
        self.renewal = renewal
        self.verifier = verifier
        self.verification_worker: ConnectionVerificationWorker | None = None

        self.setWindowTitle(
            "YouTube-verbinding vernieuwen" if renewal else "YouTube verbinden"
        )
        self.setModal(True)
        self.setMinimumWidth(660)
        self._build_ui()
        self._refresh_state()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        title = QLabel(
            "YouTube-verbinding vernieuwen" if self.renewal else "YouTube verbinden"
        )
        title.setObjectName("panelTitle")
        layout.addWidget(title)

        explanation = QLabel(
            "YouTube requested human verification. OpenFetch will open a separate "
            "Firefox profile. Your normal Firefox profile is not changed. Sign in if needed, "
            "complete any bot or CAPTCHA check, confirm the requested video plays, and then "
            "close the dedicated Firefox window."
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
            "1. Open Firefox.\n"
            "2. Sign in and complete YouTube verification.\n"
            "3. Play the requested video briefly.\n"
            "4. Close the dedicated Firefox window.\n"
            "5. Return here and choose Opnieuw controleren."
        )
        steps.setWordWrap(True)
        layout.addWidget(steps)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setObjectName("queueSummary")
        layout.addWidget(self.status_label)

        firefox_row = QHBoxLayout()
        self.open_button = QPushButton("Firefox openen")
        self.open_button.setObjectName("primaryButton")
        self.open_button.clicked.connect(self._open_firefox)
        self.select_button = QPushButton("firefox.exe kiezen…")
        self.select_button.clicked.connect(self._select_firefox)
        firefox_row.addWidget(self.open_button)
        firefox_row.addWidget(self.select_button)
        firefox_row.addStretch(1)
        layout.addLayout(firefox_row)

        action_row = QHBoxLayout()
        action_row.addStretch(1)
        self.verify_button = QPushButton("Opnieuw controleren")
        self.verify_button.clicked.connect(self._verify)
        self.cancel_button = QPushButton("Annuleren")
        self.cancel_button.clicked.connect(self.reject)
        action_row.addWidget(self.verify_button)
        action_row.addWidget(self.cancel_button)
        layout.addLayout(action_row)

        privacy = QLabel(
            "Privacy: Firefox stores the session only in the dedicated LocalAppData profile. "
            "OpenFetch never receives your password, never logs cookie values, and never "
            "uploads the profile."
        )
        privacy.setWordWrap(True)
        privacy.setObjectName("hintLabel")
        layout.addWidget(privacy)

    def _refresh_state(self) -> None:
        state = self.manager.refresh_browser_state()
        messages = {
            ConnectionState.NOT_CONFIGURED: "Ready to create the dedicated Firefox profile.",
            ConnectionState.FIREFOX_MISSING: "Firefox is not installed or firefox.exe is invalid.",
            ConnectionState.PROFILE_READY: "Dedicated profile is ready.",
            ConnectionState.WAITING_FOR_LOGIN: "Firefox closed. You can verify the session now.",
            ConnectionState.BROWSER_OPEN: "Dedicated Firefox is open. Close it before verification.",
            ConnectionState.VERIFYING: "Verifying the YouTube session…",
            ConnectionState.CONNECTED: "YouTube session verified.",
            ConnectionState.EXPIRED: "YouTube session expired. Reopen Firefox to renew it.",
            ConnectionState.LOCKED: "Profile is still locked. Close dedicated Firefox and retry.",
            ConnectionState.INVALID: "YouTube sign-in was not completed.",
            ConnectionState.DISCONNECTED: "YouTube is not connected.",
            ConnectionState.ERROR: "The YouTube connection needs attention.",
        }
        self.status_label.setText(messages[state])
        self.select_button.setVisible(state == ConnectionState.FIREFOX_MISSING)

    def _select_firefox(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select firefox.exe",
            "",
            "Firefox (firefox.exe);;Applications (*.exe)",
        )
        if not path:
            return
        if not self.manager.set_firefox_path(path):
            QMessageBox.warning(self, APP_NAME, "Firefox executable is invalid.")
        self._refresh_state()

    def _open_firefox(self) -> None:
        try:
            self.manager.launch(self.target_url)
        except RuntimeError as exc:
            message = str(exc)
            if "not installed" in message.casefold():
                message = "Firefox is not installed. Install Firefox or select firefox.exe manually."
            QMessageBox.warning(self, APP_NAME, message)
        self._refresh_state()

    def _verify(self) -> None:
        if self.verification_worker and self.verification_worker.isRunning():
            return
        if self.manager.browser_is_open():
            QMessageBox.information(
                self,
                APP_NAME,
                "Close the dedicated Firefox window before checking again.",
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
        self.open_button.setEnabled(not verifying)
        self.select_button.setEnabled(not verifying)
        self.verify_button.setEnabled(not verifying)
        self.cancel_button.setEnabled(not verifying)
        if verifying:
            self.status_label.setText("Verifying the YouTube session…")

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
        QMessageBox.warning(self, APP_NAME, result.message)

    @Slot()
    def _verification_thread_finished(self) -> None:
        self.verification_worker = None
        self._set_verifying(False)
        self._refresh_state()


ConnectionVerificationWorker = ManagedConnectionVerificationWorker  # noqa: F811
YouTubeConnectionDialog = ManagedYouTubeConnectionDialog  # noqa: F811

__all__ = ["ConnectionVerificationWorker", "YouTubeConnectionDialog"]
