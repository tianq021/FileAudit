from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QIntValidator
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
    QRadioButton,
    QScrollArea,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from fileaudit.config import AppSettings, default_settings
from fileaudit.ui.components import BarChart, DonutChart, StatCard
from fileaudit.models import ScanOptions
from fileaudit.utils import (
    build_directory_size_distribution,
    build_duplicate_extension_distribution,
    build_duplicate_group_distribution,
    build_error_directory_distribution,
    build_extension_distribution,
    build_file_type_distribution,
    build_largest_files_distribution,
    build_modified_time_distribution,
    build_risk_distribution,
    build_risk_directory_distribution,
    build_risk_reason_distribution,
    build_size_distribution,
    build_skip_reason_distribution,
    classify_file_type,
    format_datetime,
    format_risk_level,
    format_risk_reasons,
    format_size,
    risk_sort_key,
)

INITIAL_TABLE_ROWS = 5000
LOAD_MORE_ROWS = 1000


class ScanConfigPage(QWidget):
    folder_selected = Signal(str)
    scan_requested = Signal()
    cancel_requested = Signal()
    clear_requested = Signal()

    def __init__(self):
        super().__init__()
        self.path_input = QLineEdit()
        self.big_file_input = QLineEdit("100")
        self.path_length_input = QLineEdit("180")
        self.file_timeout_input = QLineEdit("15")
        self.hash_select = QComboBox()
        self.ignored_dirs_edit = QTextEdit()
        self.suspicious_extensions_edit = QTextEdit()
        self.whitelisted_extensions_edit = QTextEdit()
        self.skip_hidden_files_check = QCheckBox("跳过隐藏文件")
        self.skip_large_files_input = QLineEdit("0")
        self.skip_dirs_edit = QTextEdit()
        self.skip_file_names_edit = QTextEdit()
        self.skip_extensions_edit = QTextEdit()
        self.skip_path_keywords_edit = QTextEdit()
        self.include_only_matched_check = QCheckBox("只扫描匹配规则的文件")
        self.include_conflict_select = QComboBox()
        self.include_extensions_edit = QTextEdit()
        self.include_name_keywords_edit = QTextEdit()
        self.include_path_keywords_edit = QTextEdit()
        self.include_file_types_edit = QTextEdit()
        self.scan_all_radio = QRadioButton("全部扫描")
        self.include_only_radio = QRadioButton("只扫描匹配规则")
        self.option_checks = {}
        self._setup_ui()

    def _setup_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
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

        desc = QLabel("选择要分析的文件夹，然后开始文件体检。高级规则可在“设置”页调整。")
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

        mode_box = QFrame()
        mode_box.setObjectName("Panel")
        mode_layout = QVBoxLayout(mode_box)
        mode_layout.setSpacing(10)
        mode_title = QLabel("扫描范围")
        mode_title.setObjectName("PageDesc")
        self.scan_all_radio.setChecked(True)
        mode_row = QHBoxLayout()
        mode_row.addWidget(self.scan_all_radio)
        mode_row.addWidget(self.include_only_radio)
        mode_row.addStretch()
        mode_hint = QLabel("默认全部扫描；选择“只扫描匹配规则”时，会使用设置页里的只扫描规则。")
        mode_hint.setObjectName("PageDesc")
        mode_hint.setWordWrap(True)
        mode_layout.addWidget(mode_title)
        mode_layout.addLayout(mode_row)
        mode_layout.addWidget(mode_hint)

        option_box = QFrame()
        option_box.setObjectName("Panel")
        option_layout = QGridLayout(option_box)

        options = [
            ("recursive", "递归扫描子目录"),
            ("calculate_hash", "查找重复文件"),
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
            if key in {"recursive", "calculate_hash"}:
                option_layout.addWidget(checkbox, 0, 0 if key == "recursive" else 1)

        setting_row = QHBoxLayout()
        self.big_file_input.setFixedWidth(90)
        self.path_length_input.setFixedWidth(90)
        self.file_timeout_input.setFixedWidth(90)
        self.skip_large_files_input.setFixedWidth(90)
        int_validator = QIntValidator(0, 2147483647, self)
        self.big_file_input.setValidator(int_validator)
        self.path_length_input.setValidator(int_validator)
        self.file_timeout_input.setValidator(int_validator)
        self.skip_large_files_input.setValidator(int_validator)
        self.hash_select.addItems(["SHA256", "MD5", "SHA1(不推荐)"])

        setting_row.addWidget(QLabel("大文件阈值："))
        setting_row.addWidget(self.big_file_input)
        setting_row.addWidget(QLabel("MB"))
        setting_row.addSpacing(30)
        setting_row.addWidget(QLabel("路径过长阈值："))
        setting_row.addWidget(self.path_length_input)
        setting_row.addWidget(QLabel("字符"))
        setting_row.addSpacing(30)
        setting_row.addWidget(QLabel("单文件超时："))
        setting_row.addWidget(self.file_timeout_input)
        setting_row.addWidget(QLabel("秒"))
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

        privacy_box = QFrame()
        privacy_box.setObjectName("Panel")
        privacy_layout = QVBoxLayout(privacy_box)
        privacy_layout.setSpacing(12)
        privacy_top_row = QHBoxLayout()
        privacy_grid = QGridLayout()
        privacy_grid.setHorizontalSpacing(16)
        privacy_grid.setVerticalSpacing(8)
        for edit in [self.skip_dirs_edit, self.skip_file_names_edit, self.skip_extensions_edit, self.skip_path_keywords_edit]:
            edit.setFixedHeight(82)
        privacy_top_row.addWidget(self.skip_hidden_files_check)
        privacy_top_row.addSpacing(24)
        privacy_top_row.addWidget(QLabel("跳过大于等于："))
        privacy_top_row.addWidget(self.skip_large_files_input)
        privacy_top_row.addWidget(QLabel("MB 的文件（0 表示不跳过）"))
        privacy_top_row.addStretch()
        privacy_grid.addWidget(QLabel("跳过目录名（每行一个）："), 0, 0)
        privacy_grid.addWidget(QLabel("跳过文件名（每行一个）："), 0, 1)
        privacy_grid.addWidget(self.skip_dirs_edit, 1, 0)
        privacy_grid.addWidget(self.skip_file_names_edit, 1, 1)
        privacy_grid.addWidget(QLabel("跳过扩展名（每行一个）："), 2, 0)
        privacy_grid.addWidget(QLabel("跳过路径关键词（每行一个）："), 2, 1)
        privacy_grid.addWidget(self.skip_extensions_edit, 3, 0)
        privacy_grid.addWidget(self.skip_path_keywords_edit, 3, 1)
        privacy_layout.addLayout(privacy_top_row)
        privacy_layout.addLayout(privacy_grid)

        include_box = QFrame()
        include_box.setObjectName("Panel")
        include_layout = QVBoxLayout(include_box)
        include_layout.setSpacing(12)
        include_top_row = QHBoxLayout()
        include_grid = QGridLayout()
        include_grid.setHorizontalSpacing(16)
        include_grid.setVerticalSpacing(8)
        self.include_conflict_select.addItems(["跳过规则优先", "只扫描规则优先"])
        for edit in [
            self.include_extensions_edit,
            self.include_name_keywords_edit,
            self.include_path_keywords_edit,
            self.include_file_types_edit,
        ]:
            edit.setFixedHeight(82)
        include_top_row.addWidget(self.include_only_matched_check)
        include_top_row.addSpacing(24)
        include_top_row.addWidget(QLabel("规则冲突时："))
        include_top_row.addWidget(self.include_conflict_select)
        include_top_row.addStretch()
        include_grid.addWidget(QLabel("只扫描扩展名（每行一个）："), 0, 0)
        include_grid.addWidget(QLabel("只扫描文件名关键词（每行一个）："), 0, 1)
        include_grid.addWidget(self.include_extensions_edit, 1, 0)
        include_grid.addWidget(self.include_name_keywords_edit, 1, 1)
        include_grid.addWidget(QLabel("只扫描路径关键词（每行一个）："), 2, 0)
        include_grid.addWidget(QLabel("只扫描文件类型（每行一个）："), 2, 1)
        include_grid.addWidget(self.include_path_keywords_edit, 3, 0)
        include_grid.addWidget(self.include_file_types_edit, 3, 1)
        include_layout.addLayout(include_top_row)
        include_layout.addLayout(include_grid)

        advanced_state_box = QFrame()
        advanced_state_box.setVisible(False)
        advanced_state_layout = QVBoxLayout(advanced_state_box)
        advanced_state_layout.addLayout(setting_row)
        advanced_state_layout.addWidget(rule_box)
        advanced_state_layout.addWidget(privacy_box)
        advanced_state_layout.addWidget(include_box)

        button_row = QHBoxLayout()
        start_btn = QPushButton("开始扫描")
        start_btn.setObjectName("PrimaryButton")
        start_btn.clicked.connect(self.scan_requested.emit)

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.cancel_requested.emit)
        clear_btn = QPushButton("清空结果")
        clear_btn.clicked.connect(self.clear_requested.emit)

        button_row.addWidget(start_btn)
        button_row.addWidget(self.cancel_btn)
        button_row.addWidget(clear_btn)
        button_row.addStretch()

        layout.addLayout(title_row)
        layout.addWidget(desc)
        layout.addLayout(path_row)
        layout.addWidget(mode_box)
        layout.addWidget(option_box)
        layout.addWidget(advanced_state_box)
        layout.addLayout(button_row)
        layout.addStretch()
        scroll.setWidget(content)
        root_layout.addWidget(scroll)

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择扫描目录")
        if folder:
            self.path_input.setText(folder)
            self.path_input.setToolTip(folder)
            self.choose_btn.setToolTip(folder)
            self.folder_selected.emit(folder)

    def get_scan_options(self) -> ScanOptions:
        threshold_mb = parse_positive_int(self.big_file_input.text(), 100, "大文件阈值")
        path_length_threshold = parse_positive_int(self.path_length_input.text(), 180, "路径过长阈值")
        file_timeout_seconds = parse_positive_int(self.file_timeout_input.text(), 15, "单文件超时")
        skip_large_files_mb = parse_positive_int(self.skip_large_files_input.text(), 0, "跳过大文件阈值")
        return ScanOptions(
            root_path=Path(self.path_input.text().strip()),
            recursive=self.option_checks["recursive"].isChecked(),
            calculate_hash=self.option_checks["calculate_hash"].isChecked(),
            hash_algorithm=self.hash_select.currentText(),
            big_file_threshold_mb=threshold_mb,
            path_length_threshold=path_length_threshold,
            file_timeout_seconds=file_timeout_seconds,
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
            skip_hidden_files=self.skip_hidden_files_check.isChecked(),
            skip_large_files_mb=skip_large_files_mb,
            skip_dirs=tuple(_lines(self.skip_dirs_edit.toPlainText())),
            skip_file_names=tuple(_lines(self.skip_file_names_edit.toPlainText())),
            skip_extensions=tuple(_extension_lines(self.skip_extensions_edit.toPlainText())),
            skip_path_keywords=tuple(_lines(self.skip_path_keywords_edit.toPlainText())),
            include_only_matched=self.include_only_radio.isChecked(),
            include_conflict_policy=include_conflict_policy_value(self.include_conflict_select.currentText()),
            include_extensions=tuple(_extension_lines(self.include_extensions_edit.toPlainText())),
            include_name_keywords=tuple(_lines(self.include_name_keywords_edit.toPlainText())),
            include_path_keywords=tuple(_lines(self.include_path_keywords_edit.toPlainText())),
            include_file_types=tuple(_lines(self.include_file_types_edit.toPlainText())),
        )

    def apply_settings(self, settings: AppSettings):
        self.path_input.setText(settings.default_scan_dir)
        self.path_input.setToolTip(settings.default_scan_dir)
        self.big_file_input.setText(str(settings.big_file_threshold_mb))
        self.path_length_input.setText(str(settings.path_length_threshold))
        self.file_timeout_input.setText(str(settings.file_timeout_seconds))
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
        self.skip_hidden_files_check.setChecked(settings.skip_hidden_files)
        self.skip_large_files_input.setText(str(settings.skip_large_files_mb))
        self.skip_dirs_edit.setPlainText("\n".join(settings.skip_dirs))
        self.skip_file_names_edit.setPlainText("\n".join(settings.skip_file_names))
        self.skip_extensions_edit.setPlainText("\n".join(settings.skip_extensions))
        self.skip_path_keywords_edit.setPlainText("\n".join(settings.skip_path_keywords))
        self.include_only_matched_check.setChecked(settings.include_only_matched)
        self.include_only_radio.setChecked(settings.include_only_matched)
        self.scan_all_radio.setChecked(not settings.include_only_matched)
        self.include_conflict_select.setCurrentText(include_conflict_policy_label(settings.include_conflict_policy))
        self.include_extensions_edit.setPlainText("\n".join(settings.include_extensions))
        self.include_name_keywords_edit.setPlainText("\n".join(settings.include_name_keywords))
        self.include_path_keywords_edit.setPlainText("\n".join(settings.include_path_keywords))
        self.include_file_types_edit.setPlainText("\n".join(settings.include_file_types))


class OverviewPage(QWidget):
    def __init__(self):
        super().__init__()
        self.cards = {}
        self.modified_time_months = 3
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        content = QWidget()
        content.setMinimumWidth(1040)
        layout = QVBoxLayout(content)
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
            ("skipped_items", "已跳过", "0"),
        ]:
            card = StatCard(title_text, value)
            self.cards[key] = card
            card_layout.addWidget(card)

        chart_tabs = QTabWidget()
        chart_tabs.setObjectName("ChartTabs")
        chart_tabs.setMinimumHeight(620)

        summary_tab = QWidget()
        summary_layout = QGridLayout(summary_tab)
        summary_layout.setContentsMargins(0, 0, 0, 0)
        summary_layout.setSpacing(16)

        risk_tab = QWidget()
        risk_layout = QGridLayout(risk_tab)
        risk_layout.setContentsMargins(0, 0, 0, 0)
        risk_layout.setSpacing(16)

        space_tab = QWidget()
        space_scroll = QScrollArea()
        space_scroll.setWidgetResizable(True)
        space_scroll.setFrameShape(QFrame.NoFrame)
        space_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        space_content = QWidget()
        space_layout = QGridLayout(space_content)
        space_layout.setContentsMargins(0, 0, 0, 0)
        space_layout.setSpacing(16)
        space_scroll.setWidget(space_content)
        space_tab_layout = QVBoxLayout(space_tab)
        space_tab_layout.setContentsMargins(0, 0, 0, 0)
        space_tab_layout.addWidget(space_scroll)

        time_tab = QWidget()
        time_layout = QGridLayout(time_tab)
        time_layout.setContentsMargins(0, 0, 0, 0)
        time_layout.setSpacing(16)

        self.type_chart = DonutChart("文件类型分布")
        self.risk_chart = DonutChart("风险等级分布")
        self.directory_chart = BarChart("目录占用 Top 10", format_size, "#22C55E")
        self.extension_chart = BarChart("扩展名 Top 10", accent_color="#A855F7")
        self.size_chart = DonutChart("文件大小分布")
        self.risk_reason_chart = BarChart("风险原因 Top 10", accent_color="#EF4444")
        self.risk_directory_chart = BarChart("风险目录 Top 10", accent_color="#F43F5E")
        self.skip_reason_chart = BarChart("跳过原因", accent_color="#F59E0B")
        self.error_directory_chart = BarChart("扫描错误目录 Top 10", accent_color="#F97316")
        self.largest_files_chart = BarChart("最大文件 Top 10", format_size, "#38BDF8")
        self.duplicate_group_chart = BarChart("重复文件组 Top 10", format_size, "#FB7185")
        self.duplicate_extension_chart = BarChart("重复扩展名 Top 10", accent_color="#C084FC")
        self.modified_time_chart = BarChart("修改时间分布", accent_color="#84CC16")

        for chart in [
            self.directory_chart,
            self.extension_chart,
            self.risk_reason_chart,
            self.risk_directory_chart,
            self.skip_reason_chart,
            self.error_directory_chart,
            self.largest_files_chart,
            self.duplicate_group_chart,
            self.duplicate_extension_chart,
            self.modified_time_chart,
        ]:
            chart.setMinimumHeight(240)

        summary_layout.addWidget(self.type_chart, 0, 0)
        summary_layout.addWidget(self.risk_chart, 0, 1)
        summary_layout.addWidget(self.size_chart, 1, 0)
        summary_layout.addWidget(self.extension_chart, 1, 1)

        risk_layout.addWidget(self.risk_reason_chart, 0, 0)
        risk_layout.addWidget(self.risk_directory_chart, 0, 1)
        risk_layout.addWidget(self.skip_reason_chart, 1, 0)
        risk_layout.addWidget(self.error_directory_chart, 1, 1)

        space_layout.addWidget(self.directory_chart, 0, 0, 1, 2)
        space_layout.addWidget(self.largest_files_chart, 1, 0)
        space_layout.addWidget(self.duplicate_group_chart, 1, 1)
        space_layout.addWidget(self.duplicate_extension_chart, 2, 0, 1, 2)

        time_layout.addWidget(self.modified_time_chart, 0, 0)

        chart_tabs.addTab(summary_tab, "总览")
        chart_tabs.addTab(risk_tab, "风险")
        chart_tabs.addTab(space_tab, "空间")
        chart_tabs.addTab(time_tab, "时间")

        layout.addWidget(title)
        layout.addLayout(card_layout)
        layout.addWidget(chart_tabs, 1)
        scroll.setWidget(content)
        root_layout.addWidget(scroll)

    def update_result(self, result):
        summary = result.summary
        self.cards["total_files"].set_value(f"{summary.total_files:,}")
        self.cards["total_size"].set_value(format_size(summary.total_size))
        self.cards["duplicate_files"].set_value(f"{summary.duplicate_files:,}")
        self.cards["risk_files"].set_value(f"{summary.risk_files:,}")
        self.cards["error_count"].set_value(f"{summary.error_count:,}")
        self.cards["skipped_items"].set_value(f"{summary.skipped_files + summary.skipped_dirs:,}")
        self.type_chart.set_items(build_file_type_distribution(result.records))
        self.risk_chart.set_items(build_risk_distribution(summary.risk_counts), summary.total_files)
        self.directory_chart.set_items(build_directory_size_distribution(result.records))
        self.extension_chart.set_items(build_extension_distribution(result.records))
        self.size_chart.set_items(build_size_distribution(result.records), summary.total_files)
        self.risk_reason_chart.set_items(build_risk_reason_distribution(result.records))
        self.risk_directory_chart.set_items(build_risk_directory_distribution(result.records))
        self.skip_reason_chart.set_items(build_skip_reason_distribution(summary.skip_reasons))
        self.error_directory_chart.set_items(build_error_directory_distribution(result.errors))
        self.largest_files_chart.set_items(build_largest_files_distribution(result.records))
        self.duplicate_group_chart.set_items(build_duplicate_group_distribution(result.duplicate_groups))
        self.duplicate_extension_chart.set_items(build_duplicate_extension_distribution(result.duplicate_groups))
        self.modified_time_chart.set_items(
            build_modified_time_distribution(result.records, self.modified_time_months),
            summary.total_files,
        )

    def clear_result(self):
        self.cards["total_files"].set_value("0")
        self.cards["total_size"].set_value("0 B")
        self.cards["duplicate_files"].set_value("0")
        self.cards["risk_files"].set_value("0")
        self.cards["error_count"].set_value("0")
        self.cards["skipped_items"].set_value("0")
        self.type_chart.set_items([])
        self.risk_chart.set_items([])
        self.directory_chart.set_items([])
        self.extension_chart.set_items([])
        self.size_chart.set_items([])
        self.risk_reason_chart.set_items([])
        self.risk_directory_chart.set_items([])
        self.skip_reason_chart.set_items([])
        self.error_directory_chart.set_items([])
        self.largest_files_chart.set_items([])
        self.duplicate_group_chart.set_items([])
        self.duplicate_extension_chart.set_items([])
        self.modified_time_chart.set_items([])

    def apply_settings(self, settings: AppSettings):
        self.modified_time_months = max(1, settings.modified_time_months)


class FileDetailPage(QWidget):
    def __init__(self):
        super().__init__()
        self.records = []
        self.sort_column = 3
        self.sort_reverse = True
        self.visible_limit = INITIAL_TABLE_ROWS
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
        self.search_input.textChanged.connect(self.reset_visible_limit_and_apply)

        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["全部风险", "高风险", "中风险", "低风险", "正常"])
        self.risk_filter.currentIndexChanged.connect(self.reset_visible_limit_and_apply)

        self.type_filter = QComboBox()
        self.type_filter.addItems(["全部类型", "文档", "图片", "音视频", "压缩包", "代码", "可执行", "其他"])
        self.type_filter.currentIndexChanged.connect(self.reset_visible_limit_and_apply)

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

        self.load_more_btn = QPushButton("查看更多 1000 行")
        self.load_more_btn.clicked.connect(self.load_more)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addLayout(filter_row)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.load_more_btn)

    def update_result(self, result):
        self.records = result.records
        self.visible_limit = INITIAL_TABLE_ROWS
        self.apply_filters()

    def clear_result(self):
        self.records = []
        self.visible_limit = INITIAL_TABLE_ROWS
        self.table.setRowCount(0)
        self.summary_label.setText("显示文件：0 / 0")
        self.load_more_btn.setVisible(False)

    def apply_filters(self):
        records = self.filtered_records()
        self.populate_table(records)
        shown = min(len(records), self.visible_limit)
        limited_text = f"，当前表格显示前 {shown:,} 行" if len(records) > self.visible_limit else ""
        self.summary_label.setText(f"显示文件：{len(records):,} / {len(self.records):,}{limited_text}")
        self.load_more_btn.setVisible(len(records) > self.visible_limit)

    def reset_visible_limit_and_apply(self):
        self.visible_limit = INITIAL_TABLE_ROWS
        self.apply_filters()

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
        visible_records = records[:self.visible_limit]
        self.table.setRowCount(len(visible_records))

        for row_index, record in enumerate(visible_records):
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

    def load_more(self):
        self.visible_limit += LOAD_MORE_ROWS
        self.apply_filters()


class DuplicatePage(QWidget):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.visible_limit = INITIAL_TABLE_ROWS
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

        self.load_more_btn = QPushButton("查看更多 1000 行")
        self.load_more_btn.clicked.connect(self.load_more)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.load_more_btn)

    def update_result(self, result):
        self.last_result = result
        self.visible_limit = INITIAL_TABLE_ROWS
        self.rows = []
        for group_index, group in enumerate(result.duplicate_groups, start=1):
            for record in group.files:
                self.rows.append((group_index, group, record))
        self.populate_table(result)

    def clear_result(self):
        self.rows = []
        self.visible_limit = INITIAL_TABLE_ROWS
        if hasattr(self, "last_result"):
            del self.last_result
        self.table.setRowCount(0)
        self.summary_label.setText("重复文件组：0，可节省空间：0 B")
        self.load_more_btn.setVisible(False)

    def populate_table(self, result):
        visible_rows = self.rows[:self.visible_limit]
        self.table.setRowCount(len(visible_rows))
        for row_index, (group_index, group, record) in enumerate(visible_rows):
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
            + (f"，当前表格显示前 {len(visible_rows):,} 行" if len(self.rows) > self.visible_limit else "")
        )
        self.load_more_btn.setVisible(len(self.rows) > self.visible_limit)

    def load_more(self):
        if not hasattr(self, "last_result"):
            return
        self.visible_limit += LOAD_MORE_ROWS
        self.populate_table(self.last_result)


class RiskPage(QWidget):
    def __init__(self):
        super().__init__()
        self.records = []
        self.visible_limit = INITIAL_TABLE_ROWS
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

        self.load_more_btn = QPushButton("查看更多 1000 行")
        self.load_more_btn.clicked.connect(self.load_more)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.load_more_btn)

    def update_result(self, result):
        self.last_result = result
        self.visible_limit = INITIAL_TABLE_ROWS
        self.records = [record for record in result.records if record.risk_level != "normal"]
        self.records.sort(key=lambda record: risk_sort_key(record.risk_level))
        self.populate_table(result)

    def clear_result(self):
        self.records = []
        self.visible_limit = INITIAL_TABLE_ROWS
        if hasattr(self, "last_result"):
            del self.last_result
        self.table.setRowCount(0)
        self.summary_label.setText("可疑文件：0")
        self.load_more_btn.setVisible(False)

    def populate_table(self, result):
        visible_records = self.records[:self.visible_limit]
        self.table.setRowCount(len(visible_records))
        for row_index, record in enumerate(visible_records):
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
            f"可疑文件：{len(self.records):,}，"
            f"高风险：{high_count:,}，中风险：{medium_count:,}，低风险：{low_count:,}"
            + (f"，当前表格显示前 {len(visible_records):,} 行" if len(self.records) > self.visible_limit else "")
        )
        self.load_more_btn.setVisible(len(self.records) > self.visible_limit)

    def load_more(self):
        if not hasattr(self, "last_result"):
            return
        self.visible_limit += LOAD_MORE_ROWS
        self.populate_table(self.last_result)


class ErrorPage(QWidget):
    def __init__(self):
        super().__init__()
        self.errors = []
        self.visible_limit = INITIAL_TABLE_ROWS
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("扫描错误")
        title.setObjectName("PageTitle")

        self.summary_label = QLabel("扫描错误：0")
        self.summary_label.setObjectName("PageDesc")

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["路径", "错误原因"])
        configure_path_table(self.table, 0)
        self.table.setColumnWidth(1, 520)
        self.table.setSortingEnabled(False)

        self.load_more_btn = QPushButton("查看更多 1000 行")
        self.load_more_btn.clicked.connect(self.load_more)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.load_more_btn)

    def update_result(self, result):
        self.errors = result.errors
        self.visible_limit = INITIAL_TABLE_ROWS
        self.populate_table()

    def clear_result(self):
        self.errors = []
        self.visible_limit = INITIAL_TABLE_ROWS
        self.table.setRowCount(0)
        self.summary_label.setText("扫描错误：0")
        self.load_more_btn.setVisible(False)

    def populate_table(self):
        visible_errors = self.errors[:self.visible_limit]
        self.table.setRowCount(len(visible_errors))
        for row_index, error in enumerate(visible_errors):
            row_values = [str(error.path), error.message]
            for column_index, value in enumerate(row_values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row_index, column_index, item)

        limited_text = f"，当前表格显示前 {len(visible_errors):,} 行" if len(self.errors) > self.visible_limit else ""
        self.summary_label.setText(f"扫描错误：{len(self.errors):,}{limited_text}")
        self.load_more_btn.setVisible(len(self.errors) > self.visible_limit)

    def load_more(self):
        self.visible_limit += LOAD_MORE_ROWS
        self.populate_table()


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
        desc = QLabel(
            "生成完整报告包：summary.csv、files.csv、duplicates.csv、risks.csv、errors.csv 和 report.html。"
        )
        desc.setObjectName("PageDesc")
        desc.setWordWrap(True)
        panel_layout.addWidget(desc)

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
        self.file_timeout_input = QLineEdit()
        self.modified_time_months_input = QLineEdit()
        self.hash_select = QComboBox()
        self.option_checks = {}
        self.ignored_dirs_edit = QTextEdit()
        self.suspicious_extensions_edit = QTextEdit()
        self.whitelisted_extensions_edit = QTextEdit()
        self.skip_hidden_files_check = QCheckBox("跳过隐藏文件")
        self.skip_large_files_input = QLineEdit()
        self.skip_dirs_edit = QTextEdit()
        self.skip_file_names_edit = QTextEdit()
        self.skip_extensions_edit = QTextEdit()
        self.skip_path_keywords_edit = QTextEdit()
        self.include_only_matched_check = QCheckBox("只扫描匹配规则的文件")
        self.include_conflict_select = QComboBox()
        self.include_extensions_edit = QTextEdit()
        self.include_name_keywords_edit = QTextEdit()
        self.include_path_keywords_edit = QTextEdit()
        self.include_file_types_edit = QTextEdit()
        self.export_full_paths_check = QCheckBox("报告导出完整路径")
        self._setup_ui()

    def _setup_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
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
        self.file_timeout_input.setFixedWidth(100)
        self.modified_time_months_input.setFixedWidth(100)
        self.skip_large_files_input.setFixedWidth(100)
        int_validator = QIntValidator(0, 2147483647, self)
        month_validator = QIntValidator(1, 120, self)
        self.big_file_input.setValidator(int_validator)
        self.path_length_input.setValidator(int_validator)
        self.file_timeout_input.setValidator(int_validator)
        self.modified_time_months_input.setValidator(month_validator)
        self.skip_large_files_input.setValidator(int_validator)
        scan_layout.addWidget(QLabel("大文件阈值："), 0, 0)
        scan_layout.addWidget(self.big_file_input, 0, 1)
        scan_layout.addWidget(QLabel("MB"), 0, 2)
        scan_layout.addWidget(QLabel("路径过长阈值："), 0, 3)
        scan_layout.addWidget(self.path_length_input, 0, 4)
        scan_layout.addWidget(QLabel("字符"), 0, 5)
        scan_layout.addWidget(QLabel("Hash 算法："), 0, 6)
        scan_layout.addWidget(self.hash_select, 0, 7)
        scan_layout.addWidget(QLabel("单文件超时："), 1, 0)
        scan_layout.addWidget(self.file_timeout_input, 1, 1)
        scan_layout.addWidget(QLabel("秒（0 表示关闭）"), 1, 2)
        scan_layout.addWidget(QLabel("修改时间分类："), 1, 3)
        scan_layout.addWidget(self.modified_time_months_input, 1, 4)
        scan_layout.addWidget(QLabel("个月内"), 1, 5)

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
            scan_layout.addWidget(checkbox, 2 + index // 3, index % 3)

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

        privacy_box = QFrame()
        privacy_box.setObjectName("Panel")
        privacy_layout = QVBoxLayout(privacy_box)
        privacy_layout.setSpacing(12)
        privacy_top_row = QHBoxLayout()
        privacy_grid = QGridLayout()
        privacy_grid.setHorizontalSpacing(16)
        privacy_grid.setVerticalSpacing(8)
        for edit in [self.skip_dirs_edit, self.skip_file_names_edit, self.skip_extensions_edit, self.skip_path_keywords_edit]:
            edit.setFixedHeight(96)
        privacy_top_row.addWidget(self.skip_hidden_files_check)
        privacy_top_row.addSpacing(24)
        privacy_top_row.addWidget(QLabel("跳过大于等于："))
        privacy_top_row.addWidget(self.skip_large_files_input)
        privacy_top_row.addWidget(QLabel("MB 的文件（0 表示不跳过）"))
        privacy_top_row.addSpacing(24)
        privacy_top_row.addWidget(self.export_full_paths_check)
        privacy_top_row.addStretch()
        privacy_grid.addWidget(QLabel("跳过目录名（每行一个）："), 0, 0)
        privacy_grid.addWidget(QLabel("跳过文件名（每行一个）："), 0, 1)
        privacy_grid.addWidget(self.skip_dirs_edit, 1, 0)
        privacy_grid.addWidget(self.skip_file_names_edit, 1, 1)
        privacy_grid.addWidget(QLabel("跳过扩展名（每行一个）："), 2, 0)
        privacy_grid.addWidget(QLabel("跳过路径关键词（每行一个）："), 2, 1)
        privacy_grid.addWidget(self.skip_extensions_edit, 3, 0)
        privacy_grid.addWidget(self.skip_path_keywords_edit, 3, 1)
        privacy_layout.addLayout(privacy_top_row)
        privacy_layout.addLayout(privacy_grid)

        include_box = QFrame()
        include_box.setObjectName("Panel")
        include_layout = QVBoxLayout(include_box)
        include_layout.setSpacing(12)
        include_top_row = QHBoxLayout()
        include_grid = QGridLayout()
        include_grid.setHorizontalSpacing(16)
        include_grid.setVerticalSpacing(8)
        self.include_conflict_select.addItems(["跳过规则优先", "只扫描规则优先"])
        for edit in [
            self.include_extensions_edit,
            self.include_name_keywords_edit,
            self.include_path_keywords_edit,
            self.include_file_types_edit,
        ]:
            edit.setFixedHeight(96)
        include_top_row.addWidget(self.include_only_matched_check)
        include_top_row.addSpacing(24)
        include_top_row.addWidget(QLabel("规则冲突时："))
        include_top_row.addWidget(self.include_conflict_select)
        include_top_row.addStretch()
        include_grid.addWidget(QLabel("只扫描扩展名（每行一个）："), 0, 0)
        include_grid.addWidget(QLabel("只扫描文件名关键词（每行一个）："), 0, 1)
        include_grid.addWidget(self.include_extensions_edit, 1, 0)
        include_grid.addWidget(self.include_name_keywords_edit, 1, 1)
        include_grid.addWidget(QLabel("只扫描路径关键词（每行一个）："), 2, 0)
        include_grid.addWidget(QLabel("只扫描文件类型（每行一个）："), 2, 1)
        include_grid.addWidget(self.include_path_keywords_edit, 3, 0)
        include_grid.addWidget(self.include_file_types_edit, 3, 1)
        include_layout.addLayout(include_top_row)
        include_layout.addLayout(include_grid)

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
        layout.addWidget(rule_box)
        layout.addWidget(privacy_box)
        layout.addWidget(include_box)
        layout.addLayout(button_row)
        layout.addStretch()
        scroll.setWidget(content)
        root_layout.addWidget(scroll)

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
        self.file_timeout_input.setText(str(settings.file_timeout_seconds))
        self.modified_time_months_input.setText(str(settings.modified_time_months))
        self.hash_select.setCurrentText(settings.hash_algorithm)
        for key in self.option_checks:
            self.option_checks[key].setChecked(getattr(settings, key))
        self.ignored_dirs_edit.setPlainText("\n".join(settings.ignored_dirs))
        self.suspicious_extensions_edit.setPlainText("\n".join(settings.suspicious_extensions))
        self.whitelisted_extensions_edit.setPlainText("\n".join(settings.whitelisted_extensions))
        self.skip_hidden_files_check.setChecked(settings.skip_hidden_files)
        self.skip_large_files_input.setText(str(settings.skip_large_files_mb))
        self.skip_dirs_edit.setPlainText("\n".join(settings.skip_dirs))
        self.skip_file_names_edit.setPlainText("\n".join(settings.skip_file_names))
        self.skip_extensions_edit.setPlainText("\n".join(settings.skip_extensions))
        self.skip_path_keywords_edit.setPlainText("\n".join(settings.skip_path_keywords))
        self.include_only_matched_check.setChecked(settings.include_only_matched)
        self.include_conflict_select.setCurrentText(include_conflict_policy_label(settings.include_conflict_policy))
        self.include_extensions_edit.setPlainText("\n".join(settings.include_extensions))
        self.include_name_keywords_edit.setPlainText("\n".join(settings.include_name_keywords))
        self.include_path_keywords_edit.setPlainText("\n".join(settings.include_path_keywords))
        self.include_file_types_edit.setPlainText("\n".join(settings.include_file_types))
        self.export_full_paths_check.setChecked(settings.export_full_paths)

    def current_settings(self) -> AppSettings:
        return AppSettings(
            default_scan_dir=self.scan_dir_input.text().strip(),
            default_report_dir=self.report_dir_input.text().strip(),
            recursive=self.option_checks["recursive"].isChecked(),
            calculate_hash=self.option_checks["calculate_hash"].isChecked(),
            hash_algorithm=self.hash_select.currentText(),
            big_file_threshold_mb=parse_positive_int(self.big_file_input.text(), 100, "大文件阈值"),
            path_length_threshold=parse_positive_int(self.path_length_input.text(), 180, "路径过长阈值"),
            file_timeout_seconds=parse_positive_int(self.file_timeout_input.text(), 15, "单文件超时"),
            modified_time_months=parse_min_int(self.modified_time_months_input.text(), 3, "修改时间分类月份", 1),
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
            skip_hidden_files=self.skip_hidden_files_check.isChecked(),
            skip_large_files_mb=parse_positive_int(self.skip_large_files_input.text(), 0, "跳过大文件阈值"),
            skip_dirs=_lines(self.skip_dirs_edit.toPlainText()),
            skip_file_names=_lines(self.skip_file_names_edit.toPlainText()),
            skip_extensions=_extension_lines(self.skip_extensions_edit.toPlainText()),
            skip_path_keywords=_lines(self.skip_path_keywords_edit.toPlainText()),
            include_only_matched=self.include_only_matched_check.isChecked(),
            include_conflict_policy=include_conflict_policy_value(self.include_conflict_select.currentText()),
            include_extensions=_extension_lines(self.include_extensions_edit.toPlainText()),
            include_name_keywords=_lines(self.include_name_keywords_edit.toPlainText()),
            include_path_keywords=_lines(self.include_path_keywords_edit.toPlainText()),
            include_file_types=_lines(self.include_file_types_edit.toPlainText()),
            export_full_paths=self.export_full_paths_check.isChecked(),
        )

    def save_current_settings(self):
        try:
            settings = self.current_settings()
        except ValueError as error:
            from PySide6.QtWidgets import QMessageBox

            QMessageBox.warning(self, "设置错误", str(error))
            return
        self.settings_saved.emit(settings)


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


def parse_positive_int(text: str, default: int, field_name: str) -> int:
    value_text = text.strip()
    if not value_text:
        return default
    try:
        value = int(value_text)
    except ValueError as error:
        raise ValueError(f"{field_name}必须填写数字。") from error
    if value < 0:
        raise ValueError(f"{field_name}不能小于 0。")
    return value


def parse_min_int(text: str, default: int, field_name: str, minimum: int) -> int:
    value = parse_positive_int(text, default, field_name)
    if value < minimum:
        raise ValueError(f"{field_name}不能小于 {minimum}。")
    return value


def include_conflict_policy_value(text: str) -> str:
    return "include_wins" if text == "只扫描规则优先" else "skip_wins"


def include_conflict_policy_label(value: str) -> str:
    return "只扫描规则优先" if value == "include_wins" else "跳过规则优先"


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
