from PySide6.QtCore import Qt
from PySide6.QtCore import QRectF
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class StatCard(QFrame):
    def __init__(self, title: str, value: str):
        super().__init__()
        self.setObjectName("StatCard")

        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("CardValue")

        layout = QVBoxLayout(self)
        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        layout.addStretch()

    def set_value(self, value: str):
        self.value_label.setText(value)


class TopBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("TopBar")
        self.setFixedHeight(64)

        title = QLabel("FileAudit 文件体检分析器")
        title.setObjectName("AppTitle")

        self.status_label = QLabel("状态：未扫描")
        self.status_label.setObjectName("TopStatus")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(self.status_label)

    def set_status(self, text: str):
        self.status_label.setText(text)


class Sidebar(QFrame):
    def __init__(self, navigate):
        super().__init__()
        self.setObjectName("SideBar")
        self.setFixedWidth(220)
        self.buttons = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 16, 12, 16)
        layout.setSpacing(8)

        buttons = [
            ("扫描配置", 0),
            ("扫描概览", 1),
            ("文件明细", 2),
            ("重复文件", 3),
            ("可疑文件", 4),
            ("扫描错误", 5),
            ("文件导出", 6),
            ("设置", 7),
        ]

        for text, index in buttons:
            button = QPushButton(text)
            button.setObjectName("NavButton")
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(lambda checked=False, i=index: self.navigate_to(i, navigate))
            self.buttons[index] = button
            layout.addWidget(button)

        layout.addStretch()

        self.info = QLabel("当前项目：FileAudit\n扫描状态：未开始\n风险文件：0\n重复文件：0")
        self.info.setObjectName("SideInfo")
        self.info.setWordWrap(True)
        layout.addWidget(self.info)
        self.set_current_index(0)

    def navigate_to(self, index: int, navigate):
        navigate(index)
        self.set_current_index(index)

    def set_current_index(self, index: int):
        for button_index, button in self.buttons.items():
            button.setProperty("active", button_index == index)
            button.style().unpolish(button)
            button.style().polish(button)

    def set_info(self, status: str, risk_files: int = 0, duplicate_files: int = 0, scan_path: str = ""):
        path_text = scan_path if scan_path else "未选择"
        display_path = path_text if len(path_text) <= 42 else f"...{path_text[-39:]}"
        self.info.setText(
            "当前项目：FileAudit\n"
            f"扫描目录：{display_path}\n"
            f"扫描状态：{status}\n"
            f"风险文件：{risk_files}\n"
            f"重复文件：{duplicate_files}"
        )
        self.info.setToolTip(path_text)


class BarChart(QWidget):
    def __init__(self, title: str, value_formatter=None, accent_color: str = "#2F80ED"):
        super().__init__()
        self.title = title
        self.items = []
        self.total = 0
        self.value_formatter = value_formatter or (lambda value: f"{value:,}")
        self.accent_color = QColor(accent_color)
        self.setMinimumHeight(170)

    def set_items(self, items: list[tuple[str, int]], total: int | None = None):
        self.items = [(str(label), int(value)) for label, value in items if value]
        self.total = total if total is not None else sum(value for _, value in self.items)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        text_color = QColor("#E5E7EB")
        muted_color = QColor("#9CA3AF")
        bar_bg = QColor("#111827")
        border = QColor("#374151")
        panel_bg = QColor("#182230")

        painter.setPen(QPen(border))
        painter.setBrush(panel_bg)
        painter.drawRoundedRect(self.rect().adjusted(1, 1, -2, -2), 8, 8)

        painter.setPen(QPen(text_color))
        painter.drawText(12, 24, self.title)

        if not self.items:
            painter.setPen(QPen(muted_color))
            painter.drawText(12, 58, "暂无数据")
            return

        max_value = max(value for _, value in self.items) or 1
        y = 44
        row_height = 22
        label_width = min(170, max(86, self.width() // 4))
        value_width = 76
        bar_left = 12 + label_width
        bar_right = self.width() - value_width - 16
        bar_width = max(40, bar_right - bar_left)

        for label, value in self.items[:10]:
            if y + row_height > self.height() - 8:
                break

            painter.setPen(QPen(muted_color))
            label_text = label if len(label) <= 22 else f"...{label[-19:]}"
            painter.drawText(12, y + 15, label_text)

            painter.setPen(Qt.NoPen)
            painter.setBrush(bar_bg)
            painter.drawRoundedRect(bar_left, y + 4, bar_width, 10, 4, 4)

            fill_width = max(2, int(bar_width * value / max_value))
            painter.setBrush(self.accent_color)
            painter.drawRoundedRect(bar_left, y + 4, fill_width, 10, 4, 4)

            painter.setPen(QPen(text_color))
            percent = f" ({value / self.total:.0%})" if self.total else ""
            painter.drawText(bar_right + 8, y + 15, f"{self.value_formatter(value)}{percent}")
            y += row_height


class DonutChart(QWidget):
    COLORS = [
        QColor("#2F80ED"),
        QColor("#F97316"),
        QColor("#22C55E"),
        QColor("#A855F7"),
        QColor("#06B6D4"),
        QColor("#EF4444"),
        QColor("#F59E0B"),
        QColor("#94A3B8"),
    ]

    def __init__(self, title: str):
        super().__init__()
        self.title = title
        self.items = []
        self.total = 0
        self.setMinimumHeight(260)

    def set_items(self, items: list[tuple[str, int]], total: int | None = None):
        self.items = [(str(label), int(value)) for label, value in items if value]
        self.total = total if total is not None else sum(value for _, value in self.items)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        text_color = QColor("#E5E7EB")
        muted_color = QColor("#9CA3AF")
        border = QColor("#374151")
        panel_bg = QColor("#182230")
        hole_color = QColor("#111827")

        painter.setPen(QPen(border))
        painter.setBrush(panel_bg)
        painter.drawRoundedRect(self.rect().adjusted(1, 1, -2, -2), 8, 8)

        painter.setPen(QPen(text_color))
        painter.drawText(12, 24, self.title)

        if not self.items or not self.total:
            painter.setPen(QPen(muted_color))
            painter.drawText(12, 58, "暂无数据")
            return

        size = min(self.height() - 82, self.width() // 2 - 30, 150)
        size = max(96, size)
        center_y = 48 + size // 2
        chart_rect = QRectF(20, 46, size, size)
        start_angle = 90 * 16

        for index, (_, value) in enumerate(self.items[:8]):
            span_angle = int(-360 * 16 * value / self.total)
            painter.setPen(Qt.NoPen)
            painter.setBrush(self.COLORS[index % len(self.COLORS)])
            painter.drawPie(chart_rect, start_angle, span_angle)
            start_angle += span_angle

        hole_size = size * 0.58
        hole_rect = QRectF(
            chart_rect.center().x() - hole_size / 2,
            chart_rect.center().y() - hole_size / 2,
            hole_size,
            hole_size,
        )
        painter.setBrush(hole_color)
        painter.drawEllipse(hole_rect)

        painter.setPen(QPen(text_color))
        font = QFont(painter.font())
        font.setBold(True)
        font.setPointSize(12)
        painter.setFont(font)
        painter.drawText(chart_rect, Qt.AlignCenter, f"{self.total:,}")

        font.setBold(False)
        font.setPointSize(9)
        painter.setFont(font)

        legend_x = 36 + size
        legend_y = max(52, center_y - 70)
        for index, (label, value) in enumerate(self.items[:8]):
            y = legend_y + index * 22
            if y > self.height() - 16:
                break
            color = self.COLORS[index % len(self.COLORS)]
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(legend_x, y - 10, 10, 10, 3, 3)
            painter.setPen(QPen(text_color))
            label_text = label if len(label) <= 16 else f"{label[:15]}..."
            painter.drawText(legend_x + 16, y, label_text)
            painter.setPen(QPen(muted_color))
            percent = value / self.total
            painter.drawText(legend_x + 150, y, f"{value:,} ({percent:.0%})")


class BottomBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("BottomBar")
        self.setFixedHeight(34)

        self.message_label = QLabel("准备就绪")
        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setValue(0)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)
        layout.addWidget(self.message_label)
        layout.addStretch()
        layout.addWidget(self.progress)

    def set_message(self, text: str):
        self.message_label.setText(text)

    def set_progress(self, value: int):
        self.progress.setRange(0, 100)
        self.progress.setValue(value)

    def set_busy(self, busy: bool):
        if busy:
            self.progress.setRange(0, 0)
            return
        self.progress.setRange(0, 100)
