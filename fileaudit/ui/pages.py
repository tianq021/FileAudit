from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from fileaudit.config import AppSettings, default_settings
from fileaudit.ui.components import BarChart, StatCard
from fileaudit.models import ScanOptions


class ScanConfigPage(QWidget):
    folder_selected = Signal(str)
    scan_requested = Signal()
    cancel_requested = Signal()

    def __init__(self):
        super().__init__()
        self.path_input = QLineEdit()
        self.big_file_input = QLineEdit("100")
        self.path_length_input = QLineEdit("180")
        self.hash_select = QComboBox()
        self.ignored_dirs_edit = QTextEdit()
        self.suspicious_extensions_edit = QTextEdit()
        self.whitelisted_extensions_edit = QTextEdit()
        self.option_checks = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("扫描配置")
        title.setObjectName("PageTitle")

        folder_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        title_icon = QLabel()
        title_icon.setPixmap(folder_icon.pixmap(36, 36))

        title_row = QHBoxLayout()
        title_row.addWidget(title_icon)
        title_row.addWidget(title)
        title_row.addStretch()

        desc = QLabel("选择要分析的文件夹，设置扫描规则，然后开始文件体检。")
        desc.setObjectName("PageDesc")

        path_row = QHBoxLayout()
        self.path_input.setPlaceholderText("请选择要扫描的目录")

        choose_btn = QPushButton("选择目录")
        choose_btn.setIcon(folder_icon)
        choose_btn.setIconSize(QSize(18, 18))
        choose_btn.clicked.connect(self.choose_folder)
        self.choose_btn = choose_btn

        path_row.addWidget(QLabel("扫描目录："))
        path_row.addWidget(self.path_input, 1)
        path_row.addWidget(choose_btn)

        option_box = QFrame()
        option_box.setObjectName("Panel")
        option_layout = QGridLayout(option_box)

        options = [
            ("recursive", "递归扫描子目录"),
            ("calculate_hash", "计算 SHA256 用于重复检测"),
            ("detect_suspicious_extensions", "检测可疑扩展名"),
            ("detect_double_extensions", "检测双扩展名伪装"),
            ("detect_hidden_files", "检测隐藏文件"),
            ("detect_empty_files", "检测空文件"),
            ("detect_big_files", "检测大文件"),
            ("detect_time_anomalies", "检测时间异常"),
            ("detect_long_paths", "检测路径过长"),
        ]

        for index, (key, text) in enumerate(options):
            checkbox = QCheckBox(text)
            checkbox.setChecked(True)
            self.option_checks[key] = checkbox
            option_layout.addWidget(checkbox, index // 3, index % 3)

        setting_row = QHBoxLayout()
        self.big_file_input.setFixedWidth(90)
        self.path_length_input.setFixedWidth(90)
        self.hash_select.addItems(["SHA256", "MD5", "SHA1(不推荐)"])

        setting_row.addWidget(QLabel("大文件阈值："))
        setting_row.addWidget(self.big_file_input)
        setting_row.addWidget(QLabel("MB"))
        setting_row.addSpacing(30)
        setting_row.addWidget(QLabel("路径过长阈值："))
        setting_row.addWidget(self.path_length_input)
        setting_row.addWidget(QLabel("字符"))
        setting_row.addSpacing(30)
        setting_row.addWidget(QLabel("Hash 算法："))
        setting_row.addWidget(self.hash_select)
        setting_row.addStretch()

        rule_box = QFrame()
        rule_box.setObjectName("Panel")
        rule_layout = QGridLayout(rule_box)
        for edit in [self.ignored_dirs_edit, self.suspicious_extensions_edit, self.whitelisted_extensions_edit]:
            edit.setFixedHeight(88)
        rule_layout.addWidget(QLabel("忽略目录（每行一个）："), 0, 0)
        rule_layout.addWidget(QLabel("可疑扩展名（每行一个）："), 0, 1)
        rule_layout.addWidget(QLabel("白名单扩展名（每行一个）："), 0, 2)
        rule_layout.addWidget(self.ignored_dirs_edit, 1, 0)
        rule_layout.addWidget(self.suspicious_extensions_edit, 1, 1)
        rule_layout.addWidget(self.whitelisted_extensions_edit, 1, 2)

        button_row = QHBoxLayout()
        start_btn = QPushButton("开始扫描")
        start_btn.setObjectName("PrimaryButton")
        start_btn.clicked.connect(self.scan_requested.emit)

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.cancel_requested.emit)
        clear_btn = QPushButton("清空结果")

        button_row.addWidget(start_btn)
        button_row.addWidget(self.cancel_btn)
        button_row.addWidget(clear_btn)
        button_row.addStretch()

        layout.addLayout(title_row)
        layout.addWidget(desc)
        layout.addLayout(path_row)
        layout.addWidget(option_box)
        layout.addLayout(setting_row)
        layout.addWidget(rule_box)
        layout.addLayout(button_row)
        layout.addStretch()

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择扫描目录")
        if folder:
            self.path_input.setText(folder)
            self.path_input.setToolTip(folder)
            self.choose_btn.setToolTip(folder)
            self.folder_selected.emit(folder)

    def get_scan_options(self) -> ScanOptions:
        threshold_text = self.big_file_input.text().strip()
        threshold_mb = int(threshold_text) if threshold_text else 100
        path_length_text = self.path_length_input.text().strip()
        path_length_threshold = int(path_length_text) if path_length_text else 180
        return ScanOptions(
            root_path=Path(self.path_input.text().strip()),
            recursive=self.option_checks["recursive"].isChecked(),
            calculate_hash=self.option_checks["calculate_hash"].isChecked(),
            hash_algorithm=self.hash_select.currentText(),
            big_file_threshold_mb=threshold_mb,
            path_length_threshold=path_length_threshold,
            detect_suspicious_extensions=self.option_checks["detect_suspicious_extensions"].isChecked(),
            detect_double_extensions=self.option_checks["detect_double_extensions"].isChecked(),
            detect_hidden_files=self.option_checks["detect_hidden_files"].isChecked(),
            detect_empty_files=self.option_checks["detect_empty_files"].isChecked(),
            detect_big_files=self.option_checks["detect_big_files"].isChecked(),
            detect_time_anomalies=self.option_checks["detect_time_anomalies"].isChecked(),
            detect_long_paths=self.option_checks["detect_long_paths"].isChecked(),
            ignored_dirs=tuple(_lines(self.ignored_dirs_edit.toPlainText())),
            suspicious_extensions=tuple(_extension_lines(self.suspicious_extensions_edit.toPlainText())),
            whitelisted_extensions=tuple(_extension_lines(self.whitelisted_extensions_edit.toPlainText())),
        )

    def apply_settings(self, settings: AppSettings):
        self.path_input.setText(settings.default_scan_dir)
        self.path_input.setToolTip(settings.default_scan_dir)
        self.big_file_input.setText(str(settings.big_file_threshold_mb))
        self.path_length_input.setText(str(settings.path_length_threshold))
        self.hash_select.setCurrentText(settings.hash_algorithm)
        self.option_checks["recursive"].setChecked(settings.recursive)
        self.option_checks["calculate_hash"].setChecked(settings.calculate_hash)
        self.option_checks["detect_suspicious_extensions"].setChecked(settings.detect_suspicious_extensions)
        self.option_checks["detect_double_extensions"].setChecked(settings.detect_double_extensions)
        self.option_checks["detect_hidden_files"].setChecked(settings.detect_hidden_files)
        self.option_checks["detect_empty_files"].setChecked(settings.detect_empty_files)
        self.option_checks["detect_big_files"].setChecked(settings.detect_big_files)
        self.option_checks["detect_time_anomalies"].setChecked(settings.detect_time_anomalies)
        self.option_checks["detect_long_paths"].setChecked(settings.detect_long_paths)
        self.ignored_dirs_edit.setPlainText("\n".join(settings.ignored_dirs))
        self.suspicious_extensions_edit.setPlainText("\n".join(settings.suspicious_extensions))
        self.whitelisted_extensions_edit.setPlainText("\n".join(settings.whitelisted_extensions))


class OverviewPage(QWidget):
    def __init__(self):
        super().__init__()
        self.cards = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("扫描概览")
        title.setObjectName("PageTitle")

        card_layout = QHBoxLayout()
        for key, title_text, value in [
            ("total_files", "总文件数", "0"),
            ("total_size", "总大小", "0 MB"),
            ("duplicate_files", "重复文件", "0"),
            ("risk_files", "可疑文件", "0"),
            ("error_count", "扫描错误", "0"),
        ]:
            card = StatCard(title_text, value)
            self.cards[key] = card
            card_layout.addWidget(card)

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)

        chart_scroll = QScrollArea()
        chart_scroll.setWidgetResizable(True)
        chart_scroll.setFrameShape(QFrame.NoFrame)
        chart_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        chart_content = QWidget()
        chart_content.setMinimumHeight(520)
        chart_layout = QGridLayout(chart_content)
        chart_layout.setContentsMargins(12, 12, 12, 12)
        chart_layout.setSpacing(14)

        self.type_chart = BarChart("文件类型分布", accent_color="#2F80ED")
        self.risk_chart = BarChart("风险等级分布", accent_color="#F97316")
        self.directory_chart = BarChart("目录占用 Top 10", format_size, "#22C55E")
        chart_layout.addWidget(self.type_chart, 0, 0)
        chart_layout.addWidget(self.risk_chart, 0, 1)
        chart_layout.addWidget(self.directory_chart, 1, 0, 1, 2)

        chart_scroll.setWidget(chart_content)
        panel_layout.addWidget(chart_scroll)

        layout.addWidget(title)
        layout.addLayout(card_layout)
        layout.addWidget(panel, 1)

    def update_result(self, result):
        summary = result.summary
        self.cards["total_files"].set_value(f"{summary.total_files:,}")
        self.cards["total_size"].set_value(format_size(summary.total_size))
        self.cards["duplicate_files"].set_value(f"{summary.duplicate_files:,}")
        self.cards["risk_files"].set_value(f"{summary.risk_files:,}")
        self.cards["error_count"].set_value(f"{summary.error_count:,}")
        self.type_chart.set_items(build_file_type_distribution(result.records))
        self.risk_chart.set_items(build_risk_distribution(summary.risk_counts), summary.total_files)
        self.directory_chart.set_items(build_directory_size_distribution(result.records))


class FileDetailPage(QWidget):
    def __init__(self):
        super().__init__()
        self.records = []
        self.sort_column = 3
        self.sort_reverse = True
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("文件明细")
        title.setObjectName("PageTitle")

        filter_row = QHBoxLayout()
        self.summary_label = QLabel("显示文件：0 / 0")
        self.summary_label.setObjectName("PageDesc")

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索文件名 / 路径")
        self.search_input.textChanged.connect(self.apply_filters)

        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["全部风险", "高风险", "中风险", "低风险", "正常"])
        self.risk_filter.currentIndexChanged.connect(self.apply_filters)

        self.type_filter = QComboBox()
        self.type_filter.addItems(["全部类型", "文档", "图片", "音视频", "压缩包", "代码", "可执行", "其他"])
        self.type_filter.currentIndexChanged.connect(self.apply_filters)

        filter_row.addWidget(self.search_input, 1)
        filter_row.addWidget(self.risk_filter)
        filter_row.addWidget(self.type_filter)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "文件名",
            "路径",
            "扩展名",
            "大小",
            "创建时间",
            "修改时间",
            "风险",
            "原因",
            "Hash"
        ])
        configure_path_table(self.table, 1)
        self.table.setSortingEnabled(False)
        header = self.table.horizontalHeader()
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        header.setSortIndicator(self.sort_column, Qt.DescendingOrder)
        header.sectionClicked.connect(self.on_sort_requested)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addLayout(filter_row)
        layout.addWidget(self.table, 1)

    def update_result(self, result):
        self.records = result.records
        self.apply_filters()

    def apply_filters(self):
        records = self.filtered_records()
        self.populate_table(records)
        self.summary_label.setText(f"显示文件：{len(records):,} / {len(self.records):,}")

    def filtered_records(self):
        keyword = self.search_input.text().strip().lower()
        risk_level = risk_filter_value(self.risk_filter.currentText())
        file_type = self.type_filter.currentText()

        records = []
        for record in self.records:
            searchable = f"{record.name} {record.path}".lower()
            if keyword and keyword not in searchable:
                continue
            if risk_level and record.risk_level != risk_level:
                continue
            if file_type != "全部类型" and classify_file_type(record.extension) != file_type:
                continue
            records.append(record)
        records.sort(key=lambda record: file_detail_sort_key(record, self.sort_column), reverse=self.sort_reverse)
        return records

    def populate_table(self, records):
        self.table.setRowCount(len(records))

        for row_index, record in enumerate(records):
            row_values = [
                record.name,
                str(record.path),
                record.extension or "[无]",
                format_size(record.size),
                format_datetime(record.created_at),
                format_datetime(record.modified_at),
                format_risk_level(record.risk_level),
                format_risk_reasons(record.risk_reasons),
                record.hash_value,
            ]
            for column_index, value in enumerate(row_values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row_index, column_index, item)

    def on_sort_requested(self, column_index: int):
        if self.sort_column == column_index:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column_index
            self.sort_reverse = column_index in {3, 4, 5}
        order = Qt.DescendingOrder if self.sort_reverse else Qt.AscendingOrder
        self.table.horizontalHeader().setSortIndicator(self.sort_column, order)
        self.apply_filters()


class DuplicatePage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("重复文件")
        title.setObjectName("PageTitle")

        self.summary_label = QLabel("重复文件组：0，可节省空间：0 B")
        self.summary_label.setObjectName("PageDesc")

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "组号",
            "文件名",
            "路径",
            "大小",
            "组内文件数",
            "Hash",
        ])
        configure_path_table(self.table, 2)
        self.table.setSortingEnabled(False)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)

    def update_result(self, result):
        rows = []
        for group_index, group in enumerate(result.duplicate_groups, start=1):
            for record in group.files:
                rows.append((group_index, group, record))

        self.table.setRowCount(len(rows))
        for row_index, (group_index, group, record) in enumerate(rows):
            row_values = [
                str(group_index),
                record.name,
                str(record.path),
                format_size(record.size),
                str(len(group.files)),
                group.hash_value,
            ]
            for column_index, value in enumerate(row_values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row_index, column_index, item)

        self.summary_label.setText(
            f"重复文件组：{len(result.duplicate_groups):,}，"
            f"重复文件：{result.summary.duplicate_files:,}，"
            f"可节省空间：{format_size(result.summary.duplicate_wasted_size)}"
        )


class RiskPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("可疑文件")
        title.setObjectName("PageTitle")

        self.summary_label = QLabel("可疑文件：0")
        self.summary_label.setObjectName("PageDesc")

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "风险",
            "文件名",
            "路径",
            "扩展名",
            "大小",
            "修改时间",
            "原因",
        ])
        configure_path_table(self.table, 2)
        self.table.setSortingEnabled(False)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)

    def update_result(self, result):
        records = [record for record in result.records if record.risk_level != "normal"]
        records.sort(key=lambda record: risk_sort_key(record.risk_level))

        self.table.setRowCount(len(records))
        for row_index, record in enumerate(records):
            row_values = [
                format_risk_level(record.risk_level),
                record.name,
                str(record.path),
                record.extension or "[无]",
                format_size(record.size),
                format_datetime(record.modified_at),
                format_risk_reasons(record.risk_reasons),
            ]
            for column_index, value in enumerate(row_values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row_index, column_index, item)

        high_count = result.summary.risk_counts.get("high", 0)
        medium_count = result.summary.risk_counts.get("medium", 0)
        low_count = result.summary.risk_counts.get("low", 0)
        self.summary_label.setText(
            f"可疑文件：{len(records):,}，"
            f"高风险：{high_count:,}，中风险：{medium_count:,}，低风险：{low_count:,}"
        )


class ExportPage(QWidget):
    export_requested = Signal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("报告导出")
        title.setObjectName("PageTitle")

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)

        checks = [
            "导出 CSV 数据文件",
            "生成 HTML 图表报告",
            "包含扫描概览",
            "包含文件明细",
            "包含重复文件",
            "包含可疑文件",
            "包含目录统计",
            "包含扫描错误",
        ]

        for text in checks:
            checkbox = QCheckBox(text)
            checkbox.setChecked(True)
            panel_layout.addWidget(checkbox)

        export_btn = QPushButton("生成报告")
        export_btn.setObjectName("PrimaryButton")
        export_btn.clicked.connect(self.export_requested.emit)

        layout.addWidget(title)
        layout.addWidget(panel)
        layout.addWidget(export_btn)
        layout.addStretch()


class SettingsPage(QWidget):
    settings_saved = Signal(object)

    def __init__(self):
        super().__init__()
        self.scan_dir_input = QLineEdit()
        self.report_dir_input = QLineEdit()
        self.big_file_input = QLineEdit()
        self.path_length_input = QLineEdit()
        self.hash_select = QComboBox()
        self.option_checks = {}
        self.ignored_dirs_edit = QTextEdit()
        self.suspicious_extensions_edit = QTextEdit()
        self.whitelisted_extensions_edit = QTextEdit()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("设置")
        title.setObjectName("PageTitle")

        path_box = QFrame()
        path_box.setObjectName("Panel")
        path_layout = QGridLayout(path_box)
        scan_btn = QPushButton("选择")
        report_btn = QPushButton("选择")
        scan_btn.clicked.connect(lambda: self.choose_dir(self.scan_dir_input, "选择默认扫描目录"))
        report_btn.clicked.connect(lambda: self.choose_dir(self.report_dir_input, "选择默认报告目录"))
        path_layout.addWidget(QLabel("默认扫描目录："), 0, 0)
        path_layout.addWidget(self.scan_dir_input, 0, 1)
        path_layout.addWidget(scan_btn, 0, 2)
        path_layout.addWidget(QLabel("默认报告目录："), 1, 0)
        path_layout.addWidget(self.report_dir_input, 1, 1)
        path_layout.addWidget(report_btn, 1, 2)

        scan_box = QFrame()
        scan_box.setObjectName("Panel")
        scan_layout = QGridLayout(scan_box)
        self.hash_select.addItems(["SHA256", "MD5", "SHA1(不推荐)"])
        self.big_file_input.setFixedWidth(100)
        self.path_length_input.setFixedWidth(100)
        scan_layout.addWidget(QLabel("大文件阈值："), 0, 0)
        scan_layout.addWidget(self.big_file_input, 0, 1)
        scan_layout.addWidget(QLabel("MB"), 0, 2)
        scan_layout.addWidget(QLabel("路径过长阈值："), 0, 3)
        scan_layout.addWidget(self.path_length_input, 0, 4)
        scan_layout.addWidget(QLabel("字符"), 0, 5)
        scan_layout.addWidget(QLabel("Hash 算法："), 0, 6)
        scan_layout.addWidget(self.hash_select, 0, 7)

        options = [
            ("recursive", "递归扫描子目录"),
            ("calculate_hash", "计算 Hash 重复检测"),
            ("detect_suspicious_extensions", "检测可疑扩展名"),
            ("detect_double_extensions", "检测双扩展名伪装"),
            ("detect_hidden_files", "检测隐藏文件"),
            ("detect_empty_files", "检测空文件"),
            ("detect_big_files", "检测大文件"),
            ("detect_time_anomalies", "检测时间异常"),
            ("detect_long_paths", "检测路径过长"),
        ]
        for index, (key, text) in enumerate(options):
            checkbox = QCheckBox(text)
            self.option_checks[key] = checkbox
            scan_layout.addWidget(checkbox, 1 + index // 3, index % 3)

        rule_box = QFrame()
        rule_box.setObjectName("Panel")
        rule_layout = QGridLayout(rule_box)
        for edit in [self.ignored_dirs_edit, self.suspicious_extensions_edit, self.whitelisted_extensions_edit]:
            edit.setMinimumHeight(150)
        rule_layout.addWidget(QLabel("忽略目录（每行一个）："), 0, 0)
        rule_layout.addWidget(QLabel("可疑扩展名（每行一个）："), 0, 1)
        rule_layout.addWidget(QLabel("白名单扩展名（每行一个）："), 0, 2)
        rule_layout.addWidget(self.ignored_dirs_edit, 1, 0)
        rule_layout.addWidget(self.suspicious_extensions_edit, 1, 1)
        rule_layout.addWidget(self.whitelisted_extensions_edit, 1, 2)

        button_row = QHBoxLayout()
        save_btn = QPushButton("保存设置")
        save_btn.setObjectName("PrimaryButton")
        reset_btn = QPushButton("恢复默认")
        save_btn.clicked.connect(self.save_current_settings)
        reset_btn.clicked.connect(lambda: self.apply_settings(default_settings()))
        button_row.addWidget(save_btn)
        button_row.addWidget(reset_btn)
        button_row.addStretch()

        layout.addWidget(title)
        layout.addWidget(path_box)
        layout.addWidget(scan_box)
        layout.addWidget(rule_box, 1)
        layout.addLayout(button_row)

    def choose_dir(self, line_edit: QLineEdit, title: str):
        folder = QFileDialog.getExistingDirectory(self, title, line_edit.text())
        if folder:
            line_edit.setText(folder)
            line_edit.setToolTip(folder)

    def apply_settings(self, settings: AppSettings):
        self.scan_dir_input.setText(settings.default_scan_dir)
        self.scan_dir_input.setToolTip(settings.default_scan_dir)
        self.report_dir_input.setText(settings.default_report_dir)
        self.report_dir_input.setToolTip(settings.default_report_dir)
        self.big_file_input.setText(str(settings.big_file_threshold_mb))
        self.path_length_input.setText(str(settings.path_length_threshold))
        self.hash_select.setCurrentText(settings.hash_algorithm)
        for key in self.option_checks:
            self.option_checks[key].setChecked(getattr(settings, key))
        self.ignored_dirs_edit.setPlainText("\n".join(settings.ignored_dirs))
        self.suspicious_extensions_edit.setPlainText("\n".join(settings.suspicious_extensions))
        self.whitelisted_extensions_edit.setPlainText("\n".join(settings.whitelisted_extensions))

    def current_settings(self) -> AppSettings:
        return AppSettings(
            default_scan_dir=self.scan_dir_input.text().strip(),
            default_report_dir=self.report_dir_input.text().strip(),
            recursive=self.option_checks["recursive"].isChecked(),
            calculate_hash=self.option_checks["calculate_hash"].isChecked(),
            hash_algorithm=self.hash_select.currentText(),
            big_file_threshold_mb=int(self.big_file_input.text().strip() or "100"),
            path_length_threshold=int(self.path_length_input.text().strip() or "180"),
            detect_suspicious_extensions=self.option_checks["detect_suspicious_extensions"].isChecked(),
            detect_double_extensions=self.option_checks["detect_double_extensions"].isChecked(),
            detect_hidden_files=self.option_checks["detect_hidden_files"].isChecked(),
            detect_empty_files=self.option_checks["detect_empty_files"].isChecked(),
            detect_big_files=self.option_checks["detect_big_files"].isChecked(),
            detect_time_anomalies=self.option_checks["detect_time_anomalies"].isChecked(),
            detect_long_paths=self.option_checks["detect_long_paths"].isChecked(),
            ignored_dirs=_lines(self.ignored_dirs_edit.toPlainText()),
            suspicious_extensions=_extension_lines(self.suspicious_extensions_edit.toPlainText()),
            whitelisted_extensions=_extension_lines(self.whitelisted_extensions_edit.toPlainText()),
        )

    def save_current_settings(self):
        self.settings_saved.emit(self.current_settings())


def setup_simple_page(page: QWidget, title_text: str, body_text: str):
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


def configure_path_table(table: QTableWidget, path_column: int):
    table.setWordWrap(False)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    header = table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setSectionResizeMode(QHeaderView.Interactive)
    table.setColumnWidth(0, 180)
    table.setColumnWidth(path_column, 720)
    for column in range(table.columnCount()):
        if column not in {0, path_column}:
            table.setColumnWidth(column, 120)


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _extension_lines(text: str) -> list[str]:
    extensions = []
    for line in _lines(text):
        extension = line.lower()
        if not extension.startswith("."):
            extension = f".{extension}"
        extensions.append(extension)
    return extensions


def format_size(size: int) -> str:
    value = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024


def format_datetime(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def format_risk_level(level: str) -> str:
    names = {
        "high": "高风险",
        "medium": "中风险",
        "low": "低风险",
        "normal": "正常",
    }
    return names.get(level, level)


def format_risk_reasons(reasons: list[str]) -> str:
    names = {
        "suspicious extension": "可疑扩展名",
        "double extension": "双扩展名伪装",
        "hidden file": "隐藏文件",
        "empty file": "空文件",
        "big file": "大文件",
        "time anomaly": "时间异常",
        "long path": "路径过长",
    }
    return "，".join(names.get(reason, reason) for reason in reasons)


def risk_filter_value(text: str) -> str:
    values = {
        "高风险": "high",
        "中风险": "medium",
        "低风险": "low",
        "正常": "normal",
    }
    return values.get(text, "")


def file_detail_sort_key(record, column_index: int):
    keys = {
        0: lambda item: item.name.lower(),
        1: lambda item: str(item.path).lower(),
        2: lambda item: item.extension.lower(),
        3: lambda item: item.size,
        4: lambda item: item.created_at,
        5: lambda item: item.modified_at,
        6: lambda item: risk_sort_key(item.risk_level),
        7: lambda item: "，".join(item.risk_reasons),
        8: lambda item: item.hash_value,
    }
    return keys.get(column_index, keys[0])(record)


def risk_sort_key(level: str) -> int:
    order = {
        "high": 0,
        "medium": 1,
        "low": 2,
        "normal": 3,
    }
    return order.get(level, 9)


def classify_file_type(extension: str) -> str:
    extension = extension.lower()
    groups = {
        "文档": {
            ".csv",
            ".doc",
            ".docx",
            ".md",
            ".pdf",
            ".ppt",
            ".pptx",
            ".rtf",
            ".txt",
            ".xls",
            ".xlsx",
        },
        "图片": {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".svg", ".tif", ".tiff", ".webp"},
        "音视频": {".aac", ".avi", ".flac", ".m4a", ".mkv", ".mov", ".mp3", ".mp4", ".wav", ".webm", ".wmv"},
        "压缩包": {".7z", ".gz", ".rar", ".tar", ".tgz", ".zip"},
        "代码": {
            ".bat",
            ".cmd",
            ".css",
            ".go",
            ".html",
            ".java",
            ".js",
            ".json",
            ".py",
            ".rs",
            ".sh",
            ".ts",
            ".xml",
            ".yaml",
            ".yml",
        },
        "可执行": {".com", ".dll", ".exe", ".msi", ".scr"},
    }
    for name, extensions in groups.items():
        if extension in extensions:
            return name
    return "其他"


def build_file_type_distribution(records) -> list[tuple[str, int]]:
    counts = {}
    for record in records:
        file_type = classify_file_type(record.extension)
        counts[file_type] = counts.get(file_type, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)


def build_risk_distribution(risk_counts: dict[str, int]) -> list[tuple[str, int]]:
    order = ["high", "medium", "low", "normal"]
    return [
        (format_risk_level(level), risk_counts.get(level, 0))
        for level in order
        if risk_counts.get(level, 0)
    ]


def build_directory_size_distribution(records) -> list[tuple[str, int]]:
    sizes = {}
    for record in records:
        directory = str(record.parent)
        sizes[directory] = sizes.get(directory, 0) + record.size
    top_items = sorted(sizes.items(), key=lambda item: item[1], reverse=True)[:10]
    return [(path, size) for path, size in top_items]
