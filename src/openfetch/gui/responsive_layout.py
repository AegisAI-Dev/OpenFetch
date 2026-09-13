"""Small responsive-layout helpers shared by the main window and auth wizard."""

from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import QRect, QSize
from PySide6.QtWidgets import QGridLayout, QPushButton, QSizePolicy, QWidget


def clamp_window_rect(rect: QRect, available: QRect, minimum: QSize) -> QRect:
    """Clamp a restored window to the current screen's available rectangle."""
    width = min(max(rect.width(), minimum.width()), available.width())
    height = min(max(rect.height(), minimum.height()), available.height())
    maximum_x = available.right() - width + 1
    maximum_y = available.bottom() - height + 1
    x = min(max(rect.x(), available.left()), maximum_x)
    y = min(max(rect.y(), available.top()), maximum_y)
    return QRect(x, y, width, height)


def clamp_splitter_sizes(
    total: int,
    requested: Iterable[int],
    *,
    minimum_left: int,
    minimum_right: int,
) -> tuple[int, int]:
    """Return two non-collapsible splitter sizes within a known usable width."""
    usable = max(0, int(total))
    if usable <= minimum_left + minimum_right:
        return minimum_left, minimum_right
    values = [max(0, int(value)) for value in requested]
    left = values[0] if values else minimum_left
    left = min(max(left, minimum_left), usable - minimum_right)
    return left, usable - left


def logical_viewport_size(width: int, height: int, scale: float) -> QSize:
    """Convert physical display pixels to logical Qt layout pixels for test scenarios."""
    safe_scale = max(1.0, float(scale))
    return QSize(round(width / safe_scale), round(height / safe_scale))


class ResponsiveButtonGrid(QWidget):
    """Relayout action buttons as one, two, or four columns as width changes."""

    def __init__(
        self,
        buttons: Iterable[QPushButton],
        *,
        two_column_width: int = 410,
        four_column_width: int = 760,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.buttons = list(buttons)
        self.two_column_width = two_column_width
        self.four_column_width = four_column_width
        self.column_count = 0
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(7)
        self.grid.setVerticalSpacing(7)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(0)
        for button in self.buttons:
            button.setMinimumWidth(0)
            button.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._relayout(max(1, self.width()))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._relayout(event.size().width())

    def set_available_width_for_test(self, width: int) -> None:
        self._relayout(width)

    def _relayout(self, width: int) -> None:
        columns = 1
        if width >= self.four_column_width and len(self.buttons) >= 4:
            columns = 4
        elif width >= self.two_column_width and len(self.buttons) >= 2:
            columns = 2
        if columns == self.column_count:
            return
        for button in self.buttons:
            self.grid.removeWidget(button)
        for index, button in enumerate(self.buttons):
            self.grid.addWidget(button, index // columns, index % columns)
        for column in range(4):
            self.grid.setColumnStretch(column, 1 if column < columns else 0)
        self.column_count = columns


__all__ = [
    "ResponsiveButtonGrid",
    "clamp_splitter_sizes",
    "clamp_window_rect",
    "logical_viewport_size",
]
