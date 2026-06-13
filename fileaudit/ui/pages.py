from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSize, Qt, Signal
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
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from fileaudit.config import SETTINGS_PATH, AppSettings, default_settings
from fileaudit.config.validation import validate_detection_skip_conflicts
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
    format_risk_actions,
    format_risk_explanations,
    format_risk_level,
    format_risk_reasons,
    format_size,
    risk_sort_key,
)

class ListTableModel(QAbstractTableModel):
    def __init__(self, headers: list[str], row_builder):
        super().__init__()
        self.headers = headers
        self.row_builder = row_builder
        self.rows = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        if role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return None
        row_values = self.row_builder(self.rows[index.row()])
        if index.column() >= len(row_values):
            return None
        return row_values[index.column()]

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal and section < len(self.headers):
            return self.headers[section]
        if orientation == Qt.Vertical:
            return str(section + 1)
        return None

    def set_rows(self, rows) -> None:
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()

OPTION_TOOLTIPS = {
    "recursive": "扫描所选目录下的所有子目录。关闭后只扫描当前目录中的文件。",
    "calculate_hash": "读取文件内容并计算 Hash，用于发现内容完全相同的重复文件。文件很多或很大时会更慢。",
    "detect_suspicious_extensions": "根据可疑扩展名列表标记高风险文件，例如脚本、可执行文件或安装包。",
    "detect_double_extensions": "识别类似 report.pdf.exe 这类双扩展名伪装文件。",
    "detect_empty_files": "标记大小为 0 的空文件，便于发现占位文件或异常文件。",
    "detect_time_anomalies": "标记创建时间、修改时间明显异常的文件。",
    "detect_long_paths": "完整路径长度超过阈值时标记为路径过长风险。",
}

CONTROL_TOOLTIPS = {
    "path_input": "选择本次要扫描的根目录。",
    "scan_dir_input": "新建扫描任务时默认填入的目录。",
    "report_dir_input": "导出报告时默认使用的目录。",
    "scan_all_radio": "扫描目录下所有未被跳过规则排除的文件。",
    "include_only_radio": "只扫描命中“只扫描规则”的文件，跳过规则仍然优先。",
    "single_file_type_radio": "只扫描所选常用后缀名的文件，适合快速定位文档、图片、压缩包等某一类文件。",
    "hidden_file_mode_select": (
        "扫描并标记风险：隐藏文件会进入结果，并标记为隐藏文件风险。\n"
        "跳过不扫描：隐藏文件不进入扫描结果，也不会出现在报告中。\n"
        "扫描但不标记：隐藏文件照常进入结果，但不因为隐藏属性被标记风险。"
    ),
    "big_file_mode_select": (
        "扫描并标记风险：超过阈值的文件会进入结果，并标记为大文件风险。\n"
        "跳过不扫描：超过阈值的文件不进入扫描结果，可减少耗时。\n"
        "扫描但不标记：超过阈值的文件照常进入结果，但不因为大小被标记风险。"
    ),
    "big_file_input": "大文件判断阈值，单位 MB。会配合“大文件处理”模式使用。",
    "path_length_input": "完整文件路径超过该字符数时，会在开启路径过长检测后标记风险。",
    "file_timeout_input": "单个文件处理允许的最长秒数。填写 0 表示不限制。",
    "modified_time_months_input": "概览统计中用于区分最近文件和较早文件的月份范围。",
    "hash_select": "重复文件检测使用的 Hash 算法。SHA256 更稳妥，MD5/SHA1 更快但不推荐用于安全判断。",
    "ignored_dirs_edit": "目录名命中后会跳过整个目录，不扫描其中任何文件。每行一个名称，例如 node_modules。",
    "suspicious_extensions_edit": "会被标记为可疑的扩展名。每行一个，可写 exe 或 .exe。",
    "whitelisted_extensions_edit": "白名单扩展名不会按可疑扩展名标记。每行一个，可写 txt 或 .txt。",
    "skip_dirs_edit": "目录名命中后跳过整个目录。每行一个名称，不需要写完整路径。",
    "skip_file_names_edit": "文件名完全命中后跳过该文件。每行一个文件名。",
    "skip_extensions_edit": "扩展名命中后跳过该类文件。每行一个，可写 log 或 .log。",
    "skip_path_keywords_edit": "完整路径中包含关键词时跳过。每行一个关键词，适合排除缓存或隐私目录。",
    "include_only_matched_check": "启用后只扫描命中下方“只扫描规则”的文件；跳过规则仍然优先。",
    "include_extensions_edit": "只扫描这些扩展名的文件。开启只扫描模式后生效，每行一个。",
    "custom_suffix_input": "输入一个自定义后缀名，例如 log 或 .sqlite。查询会说明是否属于常用分类，也可以直接加入只扫描扩展名。",
    "include_name_keywords_edit": "文件名包含关键词时才扫描。开启只扫描模式后生效，每行一个。",
    "include_path_keywords_edit": "完整路径包含关键词时才扫描。开启只扫描模式后生效，每行一个。",
    "include_file_types_edit": "只扫描这些文件类型。开启只扫描模式后生效，每行一个。",
    "export_full_paths_check": "导出报告时包含完整文件路径。关闭后可减少敏感路径泄露。",
}

MODE_MARK_RISK = "扫描并标记风险"
MODE_SKIP_SCAN = "跳过不扫描"
MODE_SCAN_ONLY = "扫描但不标记"

COMMON_SCAN_SUFFIXES = (
    ("文档", (".doc", ".docx", ".pdf", ".rtf", ".txt"), "常见办公文档、PDF 和纯文本文件。"),
    ("表格", (".xls", ".xlsx", ".csv"), "电子表格和逗号分隔数据文件。"),
    ("图片", (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"), "常见图片格式，适合查找照片、截图和素材。"),
    ("压缩包", (".zip", ".rar", ".7z", ".tar", ".gz"), "压缩归档文件，常用于打包资料或备份。"),
    ("音视频", (".mp3", ".wav", ".mp4", ".mov", ".avi", ".mkv"), "常见音频和视频媒体文件。"),
    ("程序/脚本", (".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs"), "可执行文件、安装包和自动化脚本，安全审计时常重点查看。"),
)


class ScanConfigPage(QWidget):
    folder_selected = Signal(str)
    preview_requested = Signal()
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
        self.hidden_file_mode_select = QComboBox()
        self.big_file_mode_select = QComboBox()
        self.ignored_dirs_edit = QTextEdit()
        self.suspicious_extensions_edit = QTextEdit()
        self.whitelisted_extensions_edit = QTextEdit()
        self.skip_dirs_edit = QTextEdit()
        self.skip_file_names_edit = QTextEdit()
        self.skip_extensions_edit = QTextEdit()
        self.skip_path_keywords_edit = QTextEdit()
        self.include_only_matched_check = QCheckBox("只扫描匹配规则的文件")
        self.include_extensions_edit = QTextEdit()
        self.include_name_keywords_edit = QTextEdit()
        self.include_path_keywords_edit = QTextEdit()
        self.include_file_types_edit = QTextEdit()
        self.scan_all_radio = QRadioButton("全部扫描")
        self.include_only_radio = QRadioButton("只扫描匹配规则")
        self.single_file_type_radio = QRadioButton("只扫描某类文件")
        self.common_suffix_box = QFrame()
        self.common_suffix_checks = {}
        self.rule_status_label = QLabel()
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
        mode_row.addWidget(self.single_file_type_radio)
        mode_row.addStretch()
        mode_hint = QLabel("默认全部扫描；选择“只扫描匹配规则”时，会使用下方只扫描规则；选择“只扫描某类文件”时，可直接勾选常用后缀名。")
        mode_hint.setObjectName("PageDesc")
        mode_hint.setWordWrap(True)
        mode_layout.addWidget(mode_title)
        mode_layout.addLayout(mode_row)
        mode_layout.addWidget(mode_hint)

        self.common_suffix_box.setObjectName("Panel")
        common_suffix_layout = QVBoxLayout(self.common_suffix_box)
        common_suffix_layout.setSpacing(10)
        common_suffix_title = QLabel("常用后缀名")
        common_suffix_title.setObjectName("PageDesc")
        common_suffix_grid = QGridLayout()
        common_suffix_grid.setHorizontalSpacing(16)
        common_suffix_grid.setVerticalSpacing(8)
        for index, (label, extensions, explanation) in enumerate(COMMON_SCAN_SUFFIXES):
            checkbox = QCheckBox(f"{label}（{' '.join(extensions)}）")
            checkbox.setToolTip(explanation)
            checkbox.toggled.connect(self.on_common_suffix_changed)
            self.common_suffix_checks[label] = checkbox
            common_suffix_grid.addWidget(checkbox, index // 2, index % 2)
        common_suffix_layout.addWidget(common_suffix_title)
        common_suffix_layout.addLayout(common_suffix_grid)
        self.common_suffix_box.setVisible(False)

        option_box = QFrame()
        option_box.setObjectName("Panel")
        option_layout = QGridLayout(option_box)

        options = [
            ("recursive", "递归扫描子目录"),
            ("calculate_hash", "查找重复文件"),
            ("detect_suspicious_extensions", "检测可疑扩展名"),
            ("detect_double_extensions", "检测双扩展名伪装"),
            ("detect_empty_files", "检测空文件"),
            ("detect_time_anomalies", "检测时间异常"),
            ("detect_long_paths", "检测路径过长"),
        ]

        for index, (key, text) in enumerate(options):
            checkbox = QCheckBox(text)
            checkbox.setChecked(True)
            checkbox.setToolTip(OPTION_TOOLTIPS[key])
            self.option_checks[key] = checkbox
            if key in {"recursive", "calculate_hash"}:
                option_layout.addWidget(checkbox, 0, 0 if key == "recursive" else 1)

        setting_row = QHBoxLayout()
        self.big_file_input.setFixedWidth(90)
        self.path_length_input.setFixedWidth(90)
        self.file_timeout_input.setFixedWidth(90)
        int_validator = QIntValidator(0, 2147483647, self)
        self.big_file_input.setValidator(int_validator)
        self.path_length_input.setValidator(int_validator)
        self.file_timeout_input.setValidator(int_validator)
        self.hash_select.addItems(["SHA256", "MD5", "SHA1(不推荐)"])
        self.hidden_file_mode_select.addItems([MODE_MARK_RISK, MODE_SKIP_SCAN, MODE_SCAN_ONLY])
        self.big_file_mode_select.addItems([MODE_MARK_RISK, MODE_SKIP_SCAN, MODE_SCAN_ONLY])

        setting_row.addWidget(QLabel("隐藏文件处理："))
        setting_row.addWidget(self.hidden_file_mode_select)
        setting_row.addSpacing(30)
        setting_row.addWidget(QLabel("大文件处理："))
        setting_row.addWidget(self.big_file_mode_select)
        setting_row.addSpacing(12)
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
        rule_layout.addWidget(QLabel("不扫描目录名（每行一个）："), 0, 0)
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
        for edit in [
            self.include_extensions_edit,
            self.include_name_keywords_edit,
            self.include_path_keywords_edit,
            self.include_file_types_edit,
        ]:
            edit.setFixedHeight(82)
        include_top_row.addWidget(self.include_only_matched_check)
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
        preview_btn = QPushButton("预检查")
        preview_btn.clicked.connect(self.preview_requested.emit)
        self.preview_btn = preview_btn

        start_btn = QPushButton("开始扫描")
        start_btn.setObjectName("PrimaryButton")
        start_btn.clicked.connect(self.scan_requested.emit)

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.cancel_requested.emit)
        clear_btn = QPushButton("清空结果")
        clear_btn.clicked.connect(self.clear_requested.emit)

        button_row.addWidget(preview_btn)
        button_row.addWidget(start_btn)
        button_row.addWidget(self.cancel_btn)
        button_row.addWidget(clear_btn)
        button_row.addStretch()

        apply_control_tooltips(self)
        self.single_file_type_radio.toggled.connect(self.on_scan_scope_changed)
        self.include_only_radio.toggled.connect(self.on_scan_scope_changed)
        self.scan_all_radio.toggled.connect(self.on_scan_scope_changed)
        connect_rule_feedback(self)
        self.on_scan_scope_changed()
        update_rule_feedback(self)

        layout.addLayout(title_row)
        layout.addWidget(desc)
        layout.addLayout(path_row)
        layout.addWidget(mode_box)
        layout.addWidget(self.common_suffix_box)
        layout.addWidget(option_box)
        layout.addWidget(advanced_state_box)
        layout.addWidget(self.rule_status_label)
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

    def on_scan_scope_changed(self, *_args):
        self.common_suffix_box.setVisible(self.single_file_type_radio.isChecked())

    def on_common_suffix_changed(self, *_args):
        update_rule_feedback(self)

    def _selected_common_suffix_extensions(self) -> list[str]:
        selected = []
        for label, extensions, _explanation in COMMON_SCAN_SUFFIXES:
            checkbox = self.common_suffix_checks.get(label)
            if checkbox is not None and checkbox.isChecked():
                selected.extend(extensions)
        return selected

    def get_scan_options(self) -> ScanOptions:
        threshold_mb = parse_positive_int(self.big_file_input.text(), 100, "大文件阈值")
        path_length_threshold = parse_positive_int(self.path_length_input.text(), 180, "路径过长阈值")
        file_timeout_seconds = parse_positive_int(self.file_timeout_input.text(), 15, "单文件超时")
        hidden_mode = self.hidden_file_mode_select.currentText()
        big_file_mode = self.big_file_mode_select.currentText()
        detect_hidden_files = hidden_mode == MODE_MARK_RISK
        skip_hidden_files = hidden_mode == MODE_SKIP_SCAN
        detect_big_files = big_file_mode == MODE_MARK_RISK
        skip_large_files_mb = threshold_mb if big_file_mode == MODE_SKIP_SCAN else 0
        ignored_dirs = tuple(_lines(self.ignored_dirs_edit.toPlainText()))
        suspicious_extensions = tuple(_extension_lines(self.suspicious_extensions_edit.toPlainText()))
        whitelisted_extensions = tuple(_extension_lines(self.whitelisted_extensions_edit.toPlainText()))
        skip_dirs = tuple(_lines(self.skip_dirs_edit.toPlainText()))
        skip_file_names = tuple(_lines(self.skip_file_names_edit.toPlainText()))
        skip_extensions = tuple(_extension_lines(self.skip_extensions_edit.toPlainText()))
        skip_path_keywords = tuple(_lines(self.skip_path_keywords_edit.toPlainText()))
        include_extensions = tuple(
            dict.fromkeys(
                [
                    *_extension_lines(self.include_extensions_edit.toPlainText()),
                    *self._selected_common_suffix_extensions(),
                ]
            )
        )
        include_name_keywords = tuple(_lines(self.include_name_keywords_edit.toPlainText()))
        include_path_keywords = tuple(_lines(self.include_path_keywords_edit.toPlainText()))
        include_file_types = tuple(_lines(self.include_file_types_edit.toPlainText()))
        include_only_matched = self.include_only_radio.isChecked() or self.single_file_type_radio.isChecked()
        validate_detection_skip_conflicts(
            detect_suspicious_extensions=self.option_checks["detect_suspicious_extensions"].isChecked(),
            detect_double_extensions=self.option_checks["detect_double_extensions"].isChecked(),
            detect_hidden_files=detect_hidden_files,
            skip_hidden_files=skip_hidden_files,
            detect_big_files=detect_big_files,
            big_file_threshold_mb=threshold_mb,
            skip_large_files_mb=skip_large_files_mb,
            suspicious_extensions=suspicious_extensions,
            whitelisted_extensions=whitelisted_extensions,
            skip_extensions=skip_extensions,
            ignored_dirs=ignored_dirs,
            skip_dirs=skip_dirs,
            skip_path_keywords=skip_path_keywords,
            include_only_matched=include_only_matched,
            include_extensions=include_extensions,
            include_name_keywords=include_name_keywords,
            include_path_keywords=include_path_keywords,
            include_file_types=include_file_types,
        )
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
            detect_hidden_files=detect_hidden_files,
            detect_empty_files=self.option_checks["detect_empty_files"].isChecked(),
            detect_big_files=detect_big_files,
            detect_time_anomalies=self.option_checks["detect_time_anomalies"].isChecked(),
            detect_long_paths=self.option_checks["detect_long_paths"].isChecked(),
            ignored_dirs=ignored_dirs,
            suspicious_extensions=suspicious_extensions,
            whitelisted_extensions=whitelisted_extensions,
            skip_hidden_files=skip_hidden_files,
            skip_large_files_mb=skip_large_files_mb,
            skip_dirs=skip_dirs,
            skip_file_names=skip_file_names,
            skip_extensions=skip_extensions,
            skip_path_keywords=skip_path_keywords,
            include_only_matched=include_only_matched,
            include_conflict_policy="skip_wins",
            include_extensions=include_extensions,
            include_name_keywords=include_name_keywords,
            include_path_keywords=include_path_keywords,
            include_file_types=include_file_types,
        )

    def validate_rule_status(self) -> None:
        threshold_mb = parse_positive_int(self.big_file_input.text(), 100, "大文件阈值")
        hidden_mode = self.hidden_file_mode_select.currentText()
        big_file_mode = self.big_file_mode_select.currentText()
        detect_hidden_files = hidden_mode == MODE_MARK_RISK
        skip_hidden_files = hidden_mode == MODE_SKIP_SCAN
        detect_big_files = big_file_mode == MODE_MARK_RISK
        skip_large_files_mb = threshold_mb if big_file_mode == MODE_SKIP_SCAN else 0
        validate_detection_skip_conflicts(
            detect_suspicious_extensions=self.option_checks["detect_suspicious_extensions"].isChecked(),
            detect_double_extensions=self.option_checks["detect_double_extensions"].isChecked(),
            detect_hidden_files=detect_hidden_files,
            skip_hidden_files=skip_hidden_files,
            detect_big_files=detect_big_files,
            big_file_threshold_mb=threshold_mb,
            skip_large_files_mb=skip_large_files_mb,
            suspicious_extensions=tuple(_extension_lines(self.suspicious_extensions_edit.toPlainText())),
            whitelisted_extensions=tuple(_extension_lines(self.whitelisted_extensions_edit.toPlainText())),
            skip_extensions=tuple(_extension_lines(self.skip_extensions_edit.toPlainText())),
            ignored_dirs=tuple(_lines(self.ignored_dirs_edit.toPlainText())),
            skip_dirs=tuple(_lines(self.skip_dirs_edit.toPlainText())),
            skip_path_keywords=tuple(_lines(self.skip_path_keywords_edit.toPlainText())),
            include_only_matched=self.include_only_matched_check.isChecked(),
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
        self.hidden_file_mode_select.setCurrentText(hidden_file_mode_label(settings))
        self.big_file_mode_select.setCurrentText(big_file_mode_label(settings))
        self.big_file_input.setText(str(big_file_threshold_value(settings)))
        self.option_checks["recursive"].setChecked(settings.recursive)
        self.option_checks["calculate_hash"].setChecked(settings.calculate_hash)
        self.option_checks["detect_suspicious_extensions"].setChecked(settings.detect_suspicious_extensions)
        self.option_checks["detect_double_extensions"].setChecked(settings.detect_double_extensions)
        self.option_checks["detect_empty_files"].setChecked(settings.detect_empty_files)
        self.option_checks["detect_time_anomalies"].setChecked(settings.detect_time_anomalies)
        self.option_checks["detect_long_paths"].setChecked(settings.detect_long_paths)
        self.ignored_dirs_edit.setPlainText("\n".join(settings.ignored_dirs))
        self.suspicious_extensions_edit.setPlainText("\n".join(settings.suspicious_extensions))
        self.whitelisted_extensions_edit.setPlainText("\n".join(settings.whitelisted_extensions))
        self.skip_dirs_edit.setPlainText("\n".join(settings.skip_dirs))
        self.skip_file_names_edit.setPlainText("\n".join(settings.skip_file_names))
        self.skip_extensions_edit.setPlainText("\n".join(settings.skip_extensions))
        self.skip_path_keywords_edit.setPlainText("\n".join(settings.skip_path_keywords))
        self.include_only_matched_check.setChecked(settings.include_only_matched)
        self.include_only_radio.setChecked(settings.include_only_matched)
        self.scan_all_radio.setChecked(not settings.include_only_matched)
        self.single_file_type_radio.setChecked(False)
        self.include_extensions_edit.setPlainText("\n".join(settings.include_extensions))
        self.include_name_keywords_edit.setPlainText("\n".join(settings.include_name_keywords))
        self.include_path_keywords_edit.setPlainText("\n".join(settings.include_path_keywords))
        self.include_file_types_edit.setPlainText("\n".join(settings.include_file_types))
        self.on_scan_scope_changed()
        update_rule_feedback(self)


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

        self.table_model = ListTableModel([
            "文件名",
            "路径",
            "扩展名",
            "大小",
            "创建时间",
            "修改时间",
            "风险",
            "原因",
            "Hash"
        ], file_detail_row_values)
        self.table = QTableView()
        self.table.setModel(self.table_model)
        configure_path_table(self.table, 1)
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

    def clear_result(self):
        self.records = []
        self.table_model.set_rows([])
        self.summary_label.setText("显示文件：0 / 0")

    def apply_filters(self):
        records = self.filtered_records()
        self.table_model.set_rows(records)
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
        self.rows = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("重复文件")
        title.setObjectName("PageTitle")

        self.summary_label = QLabel("重复文件组：0，可节省空间：0 B")
        self.summary_label.setObjectName("PageDesc")

        self.table_model = ListTableModel([
            "组号",
            "文件名",
            "路径",
            "大小",
            "组内文件数",
            "Hash",
        ], duplicate_row_values)
        self.table = QTableView()
        self.table.setModel(self.table_model)
        configure_path_table(self.table, 2)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)

    def update_result(self, result):
        self.last_result = result
        self.rows = []
        for group_index, group in enumerate(result.duplicate_groups, start=1):
            for record in group.files:
                self.rows.append((group_index, group, record))
        self.populate_table(result)

    def clear_result(self):
        self.rows = []
        if hasattr(self, "last_result"):
            del self.last_result
        self.table_model.set_rows([])
        self.summary_label.setText("重复文件组：0，可节省空间：0 B")

    def populate_table(self, result):
        self.table_model.set_rows(self.rows)
        self.summary_label.setText(
            f"重复文件组：{len(result.duplicate_groups):,}，"
            f"重复文件：{result.summary.duplicate_files:,}，"
            f"可节省空间：{format_size(result.summary.duplicate_wasted_size)}"
        )


class RiskPage(QWidget):
    def __init__(self):
        super().__init__()
        self.records = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("可疑文件")
        title.setObjectName("PageTitle")

        self.summary_label = QLabel("可疑文件：0")
        self.summary_label.setObjectName("PageDesc")

        self.table_model = ListTableModel([
            "风险",
            "文件名",
            "路径",
            "扩展名",
            "大小",
            "修改时间",
            "原因",
            "说明",
            "建议",
        ], risk_row_values)
        self.table = QTableView()
        self.table.setModel(self.table_model)
        configure_path_table(self.table, 2)
        self.table.setColumnWidth(7, 360)
        self.table.setColumnWidth(8, 420)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)

    def update_result(self, result):
        self.last_result = result
        self.records = [record for record in result.records if record.risk_level != "normal"]
        self.records.sort(key=lambda record: risk_sort_key(record.risk_level))
        self.populate_table(result)

    def clear_result(self):
        self.records = []
        if hasattr(self, "last_result"):
            del self.last_result
        self.table_model.set_rows([])
        self.summary_label.setText("可疑文件：0")

    def populate_table(self, result):
        self.table_model.set_rows(self.records)
        high_count = result.summary.risk_counts.get("high", 0)
        medium_count = result.summary.risk_counts.get("medium", 0)
        low_count = result.summary.risk_counts.get("low", 0)
        self.summary_label.setText(
            f"可疑文件：{len(self.records):,}，"
            f"高风险：{high_count:,}，中风险：{medium_count:,}，低风险：{low_count:,}"
        )


class ErrorPage(QWidget):
    def __init__(self):
        super().__init__()
        self.errors = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel("扫描错误")
        title.setObjectName("PageTitle")

        self.summary_label = QLabel("扫描错误：0")
        self.summary_label.setObjectName("PageDesc")

        self.table_model = ListTableModel(["路径", "错误原因"], error_row_values)
        self.table = QTableView()
        self.table.setModel(self.table_model)
        configure_path_table(self.table, 0)
        self.table.setColumnWidth(1, 520)

        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.table, 1)

    def update_result(self, result):
        self.errors = result.errors
        self.populate_table()

    def clear_result(self):
        self.errors = []
        self.table_model.set_rows([])
        self.summary_label.setText("扫描错误：0")

    def populate_table(self):
        self.table_model.set_rows(self.errors)
        self.summary_label.setText(f"扫描错误：{len(self.errors):,}")


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
        self.hidden_file_mode_select = QComboBox()
        self.big_file_mode_select = QComboBox()
        self.option_checks = {}
        self.ignored_dirs_edit = QTextEdit()
        self.suspicious_extensions_edit = QTextEdit()
        self.whitelisted_extensions_edit = QTextEdit()
        self.skip_dirs_edit = QTextEdit()
        self.skip_file_names_edit = QTextEdit()
        self.skip_extensions_edit = QTextEdit()
        self.skip_path_keywords_edit = QTextEdit()
        self.include_only_matched_check = QCheckBox("只扫描匹配规则的文件")
        self.include_extensions_edit = QTextEdit()
        self.custom_suffix_input = QLineEdit()
        self.custom_suffix_result_label = QLabel()
        self.include_name_keywords_edit = QTextEdit()
        self.include_path_keywords_edit = QTextEdit()
        self.include_file_types_edit = QTextEdit()
        self.export_full_paths_check = QCheckBox("报告导出完整路径")
        self.rule_status_label = QLabel()
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
        settings_path_label = QLabel(f"设置文件位置：{SETTINGS_PATH}")
        settings_path_label.setObjectName("PageDesc")
        settings_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        settings_path_label.setToolTip(str(SETTINGS_PATH))
        path_layout.addWidget(settings_path_label, 2, 0, 1, 3)

        scan_box = QFrame()
        scan_box.setObjectName("Panel")
        scan_layout = QVBoxLayout(scan_box)
        scan_layout.setSpacing(12)
        self.hash_select.addItems(["SHA256", "MD5", "SHA1(不推荐)"])
        self.big_file_input.setFixedWidth(100)
        self.path_length_input.setFixedWidth(100)
        self.file_timeout_input.setFixedWidth(100)
        self.modified_time_months_input.setFixedWidth(100)
        self.hidden_file_mode_select.setFixedWidth(150)
        self.big_file_mode_select.setFixedWidth(150)
        self.hash_select.setFixedWidth(150)
        int_validator = QIntValidator(0, 2147483647, self)
        month_validator = QIntValidator(1, 120, self)
        self.big_file_input.setValidator(int_validator)
        self.path_length_input.setValidator(int_validator)
        self.file_timeout_input.setValidator(int_validator)
        self.modified_time_months_input.setValidator(month_validator)
        self.hidden_file_mode_select.addItems([MODE_MARK_RISK, MODE_SKIP_SCAN, MODE_SCAN_ONLY])
        self.big_file_mode_select.addItems([MODE_MARK_RISK, MODE_SKIP_SCAN, MODE_SCAN_ONLY])

        def add_setting(row: QHBoxLayout, label_text: str, widget: QWidget, suffix_text: str = ""):
            row.addWidget(QLabel(label_text))
            row.addWidget(widget)
            if suffix_text:
                row.addWidget(QLabel(suffix_text))

        setting_row_one = QHBoxLayout()
        setting_row_one.setSpacing(10)
        add_setting(setting_row_one, "隐藏文件处理：", self.hidden_file_mode_select)
        setting_row_one.addSpacing(20)
        add_setting(setting_row_one, "大文件处理：", self.big_file_mode_select)
        setting_row_one.addSpacing(20)
        add_setting(setting_row_one, "大文件阈值：", self.big_file_input, "MB")
        setting_row_one.addStretch()

        setting_row_two = QHBoxLayout()
        setting_row_two.setSpacing(10)
        add_setting(setting_row_two, "单文件超时：", self.file_timeout_input, "秒（0 表示关闭）")
        setting_row_two.addSpacing(20)
        add_setting(setting_row_two, "修改时间分类：", self.modified_time_months_input, "个月内")
        setting_row_two.addSpacing(20)
        add_setting(setting_row_two, "路径过长阈值：", self.path_length_input)
        setting_row_two.addSpacing(20)
        add_setting(setting_row_two, "Hash 算法：", self.hash_select)
        setting_row_two.addStretch()

        options_grid = QGridLayout()
        options_grid.setHorizontalSpacing(18)
        options_grid.setVerticalSpacing(10)

        options = [
            ("recursive", "递归扫描子目录"),
            ("calculate_hash", "计算 Hash 重复检测"),
            ("detect_suspicious_extensions", "检测可疑扩展名"),
            ("detect_double_extensions", "检测双扩展名伪装"),
            ("detect_empty_files", "检测空文件"),
            ("detect_time_anomalies", "检测时间异常"),
            ("detect_long_paths", "检测路径过长"),
        ]
        for index, (key, text) in enumerate(options):
            checkbox = QCheckBox(text)
            checkbox.setToolTip(OPTION_TOOLTIPS[key])
            self.option_checks[key] = checkbox
            options_grid.addWidget(checkbox, index // 3, index % 3)

        scan_layout.addLayout(setting_row_one)
        scan_layout.addLayout(setting_row_two)
        scan_layout.addLayout(options_grid)

        rule_box = QFrame()
        rule_box.setObjectName("Panel")
        rule_layout = QGridLayout(rule_box)
        for edit in [self.ignored_dirs_edit, self.suspicious_extensions_edit, self.whitelisted_extensions_edit]:
            edit.setMinimumHeight(150)
        rule_layout.addWidget(QLabel("不扫描目录名（每行一个）："), 0, 0)
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
        for edit in [
            self.include_extensions_edit,
            self.include_name_keywords_edit,
            self.include_path_keywords_edit,
            self.include_file_types_edit,
        ]:
            edit.setFixedHeight(96)
        include_top_row.addWidget(self.include_only_matched_check)
        include_top_row.addStretch()
        custom_suffix_row = QHBoxLayout()
        custom_suffix_row.setSpacing(10)
        self.custom_suffix_input.setPlaceholderText("输入后缀名，例如 log 或 .sqlite")
        self.custom_suffix_result_label.setObjectName("PageDesc")
        self.custom_suffix_result_label.setWordWrap(True)
        query_suffix_btn = QPushButton("查询后缀名")
        add_suffix_btn = QPushButton("加入只扫描")
        query_suffix_btn.clicked.connect(self.query_custom_suffix)
        add_suffix_btn.clicked.connect(self.add_custom_suffix)
        custom_suffix_row.addWidget(QLabel("自定义后缀名："))
        custom_suffix_row.addWidget(self.custom_suffix_input, 1)
        custom_suffix_row.addWidget(query_suffix_btn)
        custom_suffix_row.addWidget(add_suffix_btn)
        include_grid.addWidget(QLabel("只扫描扩展名（每行一个）："), 0, 0)
        include_grid.addWidget(QLabel("只扫描文件名关键词（每行一个）："), 0, 1)
        include_grid.addWidget(self.include_extensions_edit, 1, 0)
        include_grid.addWidget(self.include_name_keywords_edit, 1, 1)
        include_grid.addWidget(QLabel("只扫描路径关键词（每行一个）："), 2, 0)
        include_grid.addWidget(QLabel("只扫描文件类型（每行一个）："), 2, 1)
        include_grid.addWidget(self.include_path_keywords_edit, 3, 0)
        include_grid.addWidget(self.include_file_types_edit, 3, 1)
        include_layout.addLayout(include_top_row)
        include_layout.addLayout(custom_suffix_row)
        include_layout.addWidget(self.custom_suffix_result_label)
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

        apply_control_tooltips(self)
        connect_rule_feedback(self)
        update_rule_feedback(self)

        layout.addWidget(title)
        layout.addWidget(path_box)
        layout.addWidget(scan_box)
        layout.addWidget(rule_box)
        layout.addWidget(privacy_box)
        layout.addWidget(include_box)
        layout.addWidget(self.rule_status_label)
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
        self.hidden_file_mode_select.setCurrentText(hidden_file_mode_label(settings))
        self.big_file_mode_select.setCurrentText(big_file_mode_label(settings))
        self.big_file_input.setText(str(big_file_threshold_value(settings)))
        for key in self.option_checks:
            self.option_checks[key].setChecked(getattr(settings, key))
        self.ignored_dirs_edit.setPlainText("\n".join(settings.ignored_dirs))
        self.suspicious_extensions_edit.setPlainText("\n".join(settings.suspicious_extensions))
        self.whitelisted_extensions_edit.setPlainText("\n".join(settings.whitelisted_extensions))
        self.skip_dirs_edit.setPlainText("\n".join(settings.skip_dirs))
        self.skip_file_names_edit.setPlainText("\n".join(settings.skip_file_names))
        self.skip_extensions_edit.setPlainText("\n".join(settings.skip_extensions))
        self.skip_path_keywords_edit.setPlainText("\n".join(settings.skip_path_keywords))
        self.include_only_matched_check.setChecked(settings.include_only_matched)
        self.include_extensions_edit.setPlainText("\n".join(settings.include_extensions))
        self.include_name_keywords_edit.setPlainText("\n".join(settings.include_name_keywords))
        self.include_path_keywords_edit.setPlainText("\n".join(settings.include_path_keywords))
        self.include_file_types_edit.setPlainText("\n".join(settings.include_file_types))
        self.custom_suffix_input.clear()
        self.custom_suffix_result_label.clear()
        self.export_full_paths_check.setChecked(settings.export_full_paths)
        update_rule_feedback(self)

    def query_custom_suffix(self):
        try:
            extension = normalize_custom_extension(self.custom_suffix_input.text())
        except ValueError as error:
            self.custom_suffix_result_label.setText(str(error))
            self.custom_suffix_result_label.setToolTip(str(error))
            return

        description = describe_extension(extension)
        conflict_text = self._suffix_conflict_text(extension)
        result_text = f"{extension}：{description}"
        if conflict_text:
            result_text = f"{result_text}\n{conflict_text}"
        self.custom_suffix_result_label.setText(result_text)
        self.custom_suffix_result_label.setToolTip(result_text)

    def add_custom_suffix(self):
        try:
            extension = normalize_custom_extension(self.custom_suffix_input.text())
        except ValueError as error:
            self.custom_suffix_result_label.setText(str(error))
            self.custom_suffix_result_label.setToolTip(str(error))
            return

        existing_extensions = _extension_lines(self.include_extensions_edit.toPlainText())
        if extension not in existing_extensions:
            existing_extensions.append(extension)
            self.include_extensions_edit.setPlainText("\n".join(existing_extensions))
        self.include_only_matched_check.setChecked(True)
        self.query_custom_suffix()
        update_rule_feedback(self)

    def _suffix_conflict_text(self, extension: str) -> str:
        skip_extensions = set(_extension_lines(self.skip_extensions_edit.toPlainText()))
        suspicious_extensions = set(_extension_lines(self.suspicious_extensions_edit.toPlainText()))
        whitelisted_extensions = set(_extension_lines(self.whitelisted_extensions_edit.toPlainText()))
        messages = []
        if extension in skip_extensions:
            messages.append("冲突：该后缀也在跳过扩展名中，开启只扫描时会被跳过规则挡掉。")
        if extension in suspicious_extensions:
            messages.append("提示：该后缀也在可疑扩展名中，扫描后可能会被标记风险。")
        if extension in whitelisted_extensions:
            messages.append("提示：该后缀也在白名单扩展名中，不会按可疑扩展名触发风险。")
        return "\n".join(messages)

    def current_settings(self) -> AppSettings:
        big_file_threshold_mb = parse_positive_int(self.big_file_input.text(), 100, "大文件阈值")
        path_length_threshold = parse_positive_int(self.path_length_input.text(), 180, "路径过长阈值")
        file_timeout_seconds = parse_positive_int(self.file_timeout_input.text(), 15, "单文件超时")
        modified_time_months = parse_min_int(self.modified_time_months_input.text(), 3, "修改时间分类月份", 1)
        hidden_mode = self.hidden_file_mode_select.currentText()
        big_file_mode = self.big_file_mode_select.currentText()
        detect_hidden_files = hidden_mode == MODE_MARK_RISK
        skip_hidden_files = hidden_mode == MODE_SKIP_SCAN
        detect_big_files = big_file_mode == MODE_MARK_RISK
        skip_large_files_mb = big_file_threshold_mb if big_file_mode == MODE_SKIP_SCAN else 0
        ignored_dirs = _lines(self.ignored_dirs_edit.toPlainText())
        suspicious_extensions = _extension_lines(self.suspicious_extensions_edit.toPlainText())
        whitelisted_extensions = _extension_lines(self.whitelisted_extensions_edit.toPlainText())
        skip_dirs = _lines(self.skip_dirs_edit.toPlainText())
        skip_file_names = _lines(self.skip_file_names_edit.toPlainText())
        skip_extensions = _extension_lines(self.skip_extensions_edit.toPlainText())
        skip_path_keywords = _lines(self.skip_path_keywords_edit.toPlainText())
        include_extensions = _extension_lines(self.include_extensions_edit.toPlainText())
        include_name_keywords = _lines(self.include_name_keywords_edit.toPlainText())
        include_path_keywords = _lines(self.include_path_keywords_edit.toPlainText())
        include_file_types = _lines(self.include_file_types_edit.toPlainText())
        include_only_matched = self.include_only_matched_check.isChecked()
        validate_detection_skip_conflicts(
            detect_suspicious_extensions=self.option_checks["detect_suspicious_extensions"].isChecked(),
            detect_double_extensions=self.option_checks["detect_double_extensions"].isChecked(),
            detect_hidden_files=detect_hidden_files,
            skip_hidden_files=skip_hidden_files,
            detect_big_files=detect_big_files,
            big_file_threshold_mb=big_file_threshold_mb,
            skip_large_files_mb=skip_large_files_mb,
            suspicious_extensions=suspicious_extensions,
            whitelisted_extensions=whitelisted_extensions,
            skip_extensions=skip_extensions,
            ignored_dirs=ignored_dirs,
            skip_dirs=skip_dirs,
            skip_path_keywords=skip_path_keywords,
            include_only_matched=include_only_matched,
            include_extensions=include_extensions,
            include_name_keywords=include_name_keywords,
            include_path_keywords=include_path_keywords,
            include_file_types=include_file_types,
        )
        return AppSettings(
            default_scan_dir=self.scan_dir_input.text().strip(),
            default_report_dir=self.report_dir_input.text().strip(),
            recursive=self.option_checks["recursive"].isChecked(),
            calculate_hash=self.option_checks["calculate_hash"].isChecked(),
            hash_algorithm=self.hash_select.currentText(),
            big_file_threshold_mb=big_file_threshold_mb,
            path_length_threshold=path_length_threshold,
            file_timeout_seconds=file_timeout_seconds,
            modified_time_months=modified_time_months,
            detect_suspicious_extensions=self.option_checks["detect_suspicious_extensions"].isChecked(),
            detect_double_extensions=self.option_checks["detect_double_extensions"].isChecked(),
            detect_hidden_files=detect_hidden_files,
            detect_empty_files=self.option_checks["detect_empty_files"].isChecked(),
            detect_big_files=detect_big_files,
            detect_time_anomalies=self.option_checks["detect_time_anomalies"].isChecked(),
            detect_long_paths=self.option_checks["detect_long_paths"].isChecked(),
            ignored_dirs=ignored_dirs,
            suspicious_extensions=suspicious_extensions,
            whitelisted_extensions=whitelisted_extensions,
            skip_hidden_files=skip_hidden_files,
            skip_large_files_mb=skip_large_files_mb,
            skip_dirs=skip_dirs,
            skip_file_names=skip_file_names,
            skip_extensions=skip_extensions,
            skip_path_keywords=skip_path_keywords,
            include_only_matched=include_only_matched,
            include_conflict_policy="skip_wins",
            include_extensions=include_extensions,
            include_name_keywords=include_name_keywords,
            include_path_keywords=include_path_keywords,
            include_file_types=include_file_types,
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


def configure_path_table(table: QTableView, path_column: int):
    table.setWordWrap(False)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setAlternatingRowColors(False)
    header = table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setSectionResizeMode(QHeaderView.Interactive)
    table.setColumnWidth(0, 180)
    table.setColumnWidth(path_column, 720)
    model = table.model()
    column_count = model.columnCount() if model is not None else 0
    for column in range(column_count):
        if column not in {0, path_column}:
            table.setColumnWidth(column, 120)


def file_detail_row_values(record) -> list[str]:
    return [
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


def duplicate_row_values(row) -> list[str]:
    group_index, group, record = row
    return [
        str(group_index),
        record.name,
        str(record.path),
        format_size(record.size),
        str(len(group.files)),
        group.hash_value,
    ]


def risk_row_values(record) -> list[str]:
    return [
        format_risk_level(record.risk_level),
        record.name,
        str(record.path),
        record.extension or "[无]",
        format_size(record.size),
        format_datetime(record.modified_at),
        format_risk_reasons(record.risk_reasons),
        format_risk_explanations(record.risk_reasons),
        format_risk_actions(record.risk_reasons),
    ]


def error_row_values(error) -> list[str]:
    return [str(error.path), error.message]


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _extension_lines(text: str) -> list[str]:
    extensions = []
    for line in _lines(text):
        extensions.append(normalize_custom_extension(line))
    return extensions


def normalize_custom_extension(text: str) -> str:
    extension = text.strip().lower()
    if not extension:
        raise ValueError("请先输入后缀名，例如 log 或 .log。")
    if extension.startswith("*."):
        extension = extension[1:]
    if not extension.startswith("."):
        extension = f".{extension}"
    if len(extension) == 1:
        raise ValueError("后缀名不能只有点号，请输入类似 .log 的格式。")
    if any(char.isspace() for char in extension):
        raise ValueError("后缀名不能包含空格，请每次只查询一个后缀名。")
    if any(char in extension for char in "\\/:*?\"<>|"):
        raise ValueError("后缀名不能包含路径或通配符字符。")
    return extension


def describe_extension(extension: str) -> str:
    for label, extensions, explanation in COMMON_SCAN_SUFFIXES:
        if extension in extensions:
            return f"属于常用“{label}”后缀。{explanation}"
    return "未在常用后缀分类中；仍可加入只扫描扩展名，扫描时会按该后缀精确匹配。"


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


def hidden_file_mode_label(settings: AppSettings) -> str:
    if settings.skip_hidden_files:
        return MODE_SKIP_SCAN
    if settings.detect_hidden_files:
        return MODE_MARK_RISK
    return MODE_SCAN_ONLY


def big_file_mode_label(settings: AppSettings) -> str:
    if settings.skip_large_files_mb > 0:
        return MODE_SKIP_SCAN
    if settings.detect_big_files and settings.big_file_threshold_mb > 0:
        return MODE_MARK_RISK
    return MODE_SCAN_ONLY


def big_file_threshold_value(settings: AppSettings) -> int:
    if settings.skip_large_files_mb > 0:
        return settings.skip_large_files_mb
    return settings.big_file_threshold_mb


def apply_control_tooltips(page: QWidget):
    for name, tooltip in CONTROL_TOOLTIPS.items():
        widget = getattr(page, name, None)
        if widget is not None:
            widget.setToolTip(tooltip)


def connect_rule_feedback(page: QWidget):
    def refresh(*_args):
        update_rule_feedback(page)

    for checkbox in getattr(page, "option_checks", {}).values():
        checkbox.stateChanged.connect(refresh)

    for name in (
        "hidden_file_mode_select",
        "big_file_mode_select",
        "hash_select",
    ):
        widget = getattr(page, name, None)
        if widget is not None:
            widget.currentTextChanged.connect(refresh)

    for name in (
        "big_file_input",
        "path_length_input",
        "file_timeout_input",
        "modified_time_months_input",
    ):
        widget = getattr(page, name, None)
        if widget is not None:
            widget.textChanged.connect(refresh)

    for name in (
        "ignored_dirs_edit",
        "suspicious_extensions_edit",
        "whitelisted_extensions_edit",
        "skip_dirs_edit",
        "skip_file_names_edit",
        "skip_extensions_edit",
        "skip_path_keywords_edit",
        "include_extensions_edit",
        "include_name_keywords_edit",
        "include_path_keywords_edit",
        "include_file_types_edit",
    ):
        widget = getattr(page, name, None)
        if widget is not None:
            widget.textChanged.connect(refresh)

    for name in ("include_only_matched_check", "scan_all_radio", "include_only_radio", "single_file_type_radio"):
        widget = getattr(page, name, None)
        if widget is not None:
            widget.toggled.connect(refresh)

    for checkbox in getattr(page, "common_suffix_checks", {}).values():
        checkbox.toggled.connect(refresh)


def update_rule_feedback(page: QWidget):
    label = getattr(page, "rule_status_label", None)
    if label is None:
        return

    try:
        if hasattr(page, "validate_rule_status"):
            page.validate_rule_status()
        elif hasattr(page, "current_settings"):
            page.current_settings()
        else:
            page.get_scan_options()
    except ValueError as error:
        label.setText(f"规则状态：有冲突\n{error}")
        label.setStyleSheet("color: #FCA5A5; font-size: 13px;")
        label.setToolTip(str(error))
        return

    label.setText("规则状态：正常")
    label.setStyleSheet("color: #86EFAC; font-size: 13px;")
    label.setToolTip("当前规则没有发现明显冲突。")


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
