import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QStackedWidget, QFrame, QLineEdit,
    QFileDialog, QCheckBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QComboBox, QGridLayout
)
from PySide6.QtCore import Qt


class StatCard(QFrame):
    def __init__(self, title: str, value: str):
        super().__init__()
        self.setObjectName("StatCard")

        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")

        value_label = QLabel(value)
        value_label.setObjectName("CardValue")

        layout = QVBoxLayout(self)
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addStretch()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("FileAudit 文件体检分析器")
        self.resize(1280, 820)
        self.setMinimumSize(1100, 700)

        self.current_path = ""

        root = QWidget()
        self.setCentralWidget(root)

        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self.create_top_bar())

        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self.sidebar = self.create_sidebar()
        self.pages = QStackedWidget()

        self.pages.addWidget(self.page_scan_config())
        self.pages.addWidget(self.page_overview())
        self.pages.addWidget(self.page_file_detail())
        self.pages.addWidget(self.page_duplicate())
        self.pages.addWidget(self.page_risk())
        self.pages.addWidget(self.page_export())
        self.pages.addWidget(self.page_settings())

        body_layout.addWidget(self.sidebar)
        body_layout.addWidget(self.pages, 1)

        main_layout.addLayout(body_layout, 1)
        main_layout.addWidget(self.create_bottom_bar())

        self.apply_style()

    def create_top_bar(self):
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(64)

        title = QLabel("FileAudit 文件体检分析器")
        title.setObjectName("AppTitle")

        self.status_label = QLabel("状态：未扫描")
        self.status_label.setObjectName("TopStatus")

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(self.status_label)

        return bar

    def create_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("SideBar")
        sidebar.setFixedWidth(220)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 16, 12, 16)
        layout.setSpacing(8)

        buttons = [
            ("扫描配置", 0),
            ("扫描概览", 1),
            ("文件明细", 2),
            ("重复文件", 3),
            ("可疑文件", 4),
            ("报告导出", 5),
            ("设置", 6),
        ]

        for text, index in buttons:
            btn = QPushButton(text)
            btn.setObjectName("NavButton")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked=False, i=index: self.pages.setCurrentIndex(i))
            layout.addWidget(btn)

        layout.addStretch()

        mini = QLabel("当前项目：FileAudit\n扫描状态：未开始\n风险文件：0\n重复文件：0")
        mini.setObjectName("SideInfo")
        layout.addWidget(mini)

        return sidebar

    def create_bottom_bar(self):
        bar = QFrame()
        bar.setObjectName("BottomBar")
        bar.setFixedHeight(34)

        self.bottom_label = QLabel("准备就绪")
        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setValue(0)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 16, 0)
        layout.addWidget(self.bottom_label)
        layout.addStretch()
        layout.addWidget(self.progress)

        return bar

    def page_scan_config(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("扫描配置")
        title.setObjectName("PageTitle")

        desc = QLabel("选择要分析的文件夹，设置扫描规则，然后开始文件体检。")
        desc.setObjectName("PageDesc")

        path_row = QHBoxLayout()
        path_label = QLabel("扫描目录：")
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("请选择要扫描的目录，例如 D:\\Downloads")
        choose_btn = QPushButton("选择目录")
        choose_btn.clicked.connect(self.choose_folder)

        path_row.addWidget(path_label)
        path_row.addWidget(self.path_input, 1)
        path_row.addWidget(choose_btn)

        option_box = QFrame()
        option_box.setObjectName("Panel")
        option_layout = QGridLayout(option_box)

        options = [
            "递归扫描子目录",
            "计算 SHA256 用于重复检测",
            "检测可疑扩展名",
            "检测双扩展名伪装",
            "检测隐藏文件",
            "检测空文件",
            "检测大文件",
            "检测时间异常",
            "检测路径过长",
        ]

        for i, text in enumerate(options):
            cb = QCheckBox(text)
            cb.setChecked(True)
            option_layout.addWidget(cb, i // 3, i % 3)

        setting_row = QHBoxLayout()
        self.big_file_input = QLineEdit("100")
        self.big_file_input.setFixedWidth(90)

        self.hash_select = QComboBox()
        self.hash_select.addItems(["SHA256", "MD5", "SHA1"])

        setting_row.addWidget(QLabel("大文件阈值："))
        setting_row.addWidget(self.big_file_input)
        setting_row.addWidget(QLabel("MB"))
        setting_row.addSpacing(30)
        setting_row.addWidget(QLabel("Hash 算法："))
        setting_row.addWidget(self.hash_select)
        setting_row.addStretch()

        button_row = QHBoxLayout()
        start_btn = QPushButton("开始扫描")
        start_btn.setObjectName("PrimaryButton")
        start_btn.clicked.connect(self.fake_start_scan)

        cancel_btn = QPushButton("取消")
        clear_btn = QPushButton("清空结果")

        button_row.addWidget(start_btn)
        button_row.addWidget(cancel_btn)
        button_row.addWidget(clear_btn)
        button_row.addStretch()

        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addLayout(path_row)
        layout.addWidget(option_box)
        layout.addLayout(setting_row)
        layout.addLayout(button_row)
        layout.addStretch()

        return page

    def page_overview(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("扫描概览")
        title.setObjectName("PageTitle")

        card_layout = QHBoxLayout()
        card_layout.addWidget(StatCard("总文件数", "0"))
        card_layout.addWidget(StatCard("总大小", "0 MB"))
        card_layout.addWidget(StatCard("重复文件", "0"))
        card_layout.addWidget(StatCard("可疑文件", "0"))
        card_layout.addWidget(StatCard("扫描错误", "0"))

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.addWidget(QLabel("这里后面放：文件类型分布图、风险等级分布图、目录占用 Top 10。"))
        panel_layout.addStretch()

        layout.addWidget(title)
        layout.addLayout(card_layout)
        layout.addWidget(panel, 1)

        return page

    def page_file_detail(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("文件明细")
        title.setObjectName("PageTitle")

        filter_row = QHBoxLayout()
        search = QLineEdit()
        search.setPlaceholderText("搜索文件名 / 路径")
        risk_filter = QComboBox()
        risk_filter.addItems(["全部风险", "高风险", "中风险", "低风险", "正常"])
        type_filter = QComboBox()
        type_filter.addItems(["全部类型", "文档", "图片", "压缩包", "代码", "可执行"])

        filter_row.addWidget(search, 1)
        filter_row.addWidget(risk_filter)
        filter_row.addWidget(type_filter)

        table = QTableWidget(5, 8)
        table.setHorizontalHeaderLabels([
            "文件名", "路径", "扩展名", "大小", "创建时间", "修改时间", "风险", "原因"
        ])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        demo_rows = [
            ["report.xlsx", "D:\\Downloads", ".xlsx", "128 KB", "2026-06-10", "2026-06-10", "正常", ""],
            ["作业.pdf.exe", "D:\\Downloads", ".exe", "2.1 MB", "2026-06-10", "2026-06-10", "高", "双扩展名/可执行文件"],
            ["temp.tmp", "D:\\Temp", ".tmp", "0 KB", "2026-06-10", "2026-06-10", "低", "空文件/临时文件"],
            ["backup.zip", "D:\\Backup", ".zip", "560 MB", "2026-06-10", "2024-01-01", "中", "创建新但修改旧"],
            ["main.py", "D:\\Project", ".py", "12 KB", "2026-06-10", "2026-06-10", "正常", ""],
        ]

        for r, row in enumerate(demo_rows):
            for c, value in enumerate(row):
                table.setItem(r, c, QTableWidgetItem(value))

        layout.addWidget(title)
        layout.addLayout(filter_row)
        layout.addWidget(table, 1)

        return page

    def page_duplicate(self):
        return self.simple_page(
            "重复文件",
            "这里后面做重复文件分组：DUP001、DUP002，并显示每组文件路径和可节省空间。"
        )

    def page_risk(self):
        return self.simple_page(
            "可疑文件",
            "这里后面集中显示高风险、中风险、低风险文件，并说明可疑原因。"
        )

    def page_export(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("报告导出")
        title.setObjectName("PageTitle")

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)

        checks = [
            "导出 Excel 多 Sheet 报告",
            "包含扫描概览",
            "包含文件明细",
            "包含重复文件",
            "包含可疑文件",
            "包含目录统计",
            "包含扫描错误",
        ]

        for text in checks:
            cb = QCheckBox(text)
            cb.setChecked(True)
            panel_layout.addWidget(cb)

        export_btn = QPushButton("生成报告")
        export_btn.setObjectName("PrimaryButton")

        layout.addWidget(title)
        layout.addWidget(panel)
        layout.addWidget(export_btn)
        layout.addStretch()

        return page

    def page_settings(self):
        return self.simple_page(
            "设置",
            "这里后面放默认扫描目录、大文件阈值、风险扩展名、忽略目录、白名单规则。"
        )

    def simple_page(self, title_text, body_text):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel(title_text)
        title.setObjectName("PageTitle")

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.addWidget(QLabel(body_text))
        panel_layout.addStretch()

        layout.addWidget(title)
        layout.addWidget(panel, 1)

        return page

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择扫描目录")
        if folder:
            self.current_path = folder
            self.path_input.setText(folder)
            self.status_label.setText(f"状态：已选择目录")
            self.bottom_label.setText(f"当前目录：{folder}")

    def fake_start_scan(self):
        self.status_label.setText("状态：模拟扫描完成")
        self.bottom_label.setText("草图阶段：已模拟完成扫描，后面再接真实扫描逻辑")
        self.progress.setValue(100)
        self.pages.setCurrentIndex(1)

    def apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #111827;
                color: #E5E7EB;
            }

            QLabel {
                color: #E5E7EB;
                font-size: 14px;
            }

            #TopBar {
                background-color: #111827;
                border-bottom: 1px solid #374151;
            }

            #AppTitle {
                font-size: 20px;
                font-weight: bold;
            }

            #TopStatus {
                color: #9CA3AF;
            }

            #SideBar {
                background-color: #0F172A;
                border-right: 1px solid #374151;
            }

            #NavButton {
                background-color: transparent;
                color: #D1D5DB;
                border: none;
                text-align: left;
                padding: 12px 14px;
                border-radius: 8px;
                font-size: 15px;
            }

            #NavButton:hover {
                background-color: #1F2937;
            }

            #SideInfo {
                color: #9CA3AF;
                font-size: 12px;
                background-color: #111827;
                padding: 10px;
                border-radius: 8px;
            }

            #BottomBar {
                background-color: #111827;
                border-top: 1px solid #374151;
            }

            #PageTitle {
                font-size: 24px;
                font-weight: bold;
            }

            #PageDesc {
                color: #9CA3AF;
                font-size: 14px;
            }

            #Panel {
                background-color: #1F2937;
                border: 1px solid #374151;
                border-radius: 10px;
                padding: 12px;
            }

            #StatCard {
                background-color: #1F2937;
                border: 1px solid #374151;
                border-radius: 10px;
                min-height: 90px;
            }

            #CardTitle {
                color: #9CA3AF;
                font-size: 13px;
            }

            #CardValue {
                font-size: 24px;
                font-weight: bold;
                color: #F9FAFB;
            }

            QPushButton {
                background-color: #374151;
                color: #F9FAFB;
                border: none;
                padding: 9px 14px;
                border-radius: 8px;
                font-size: 14px;
            }

            QPushButton:hover {
                background-color: #4B5563;
            }

            #PrimaryButton {
                background-color: #2563EB;
                font-weight: bold;
            }

            #PrimaryButton:hover {
                background-color: #1D4ED8;
            }

            QLineEdit, QComboBox {
                background-color: #111827;
                color: #F9FAFB;
                border: 1px solid #4B5563;
                border-radius: 6px;
                padding: 8px;
                font-size: 14px;
            }

            QCheckBox {
                color: #E5E7EB;
                spacing: 8px;
                font-size: 14px;
            }

            QTableWidget {
                background-color: #111827;
                color: #E5E7EB;
                gridline-color: #374151;
                border: 1px solid #374151;
                border-radius: 8px;
            }

            QHeaderView::section {
                background-color: #1F2937;
                color: #F9FAFB;
                padding: 8px;
                border: none;
                border-right: 1px solid #374151;
            }

            QProgressBar {
                background-color: #1F2937;
                color: white;
                border: 1px solid #374151;
                border-radius: 5px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: #2563EB;
                border-radius: 5px;
            }
        """)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()