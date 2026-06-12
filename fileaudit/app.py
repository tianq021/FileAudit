from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QMessageBox, QHBoxLayout, QMainWindow, QStackedWidget, QVBoxLayout, QWidget

from fileaudit.config import load_settings, save_settings
from fileaudit.reports import export_report_bundle
from fileaudit.services import PreviewWorker, ScanWorker
from fileaudit.utils import format_size, format_skip_reasons
from fileaudit.ui.components import BottomBar, Sidebar, TopBar
from fileaudit.ui.pages import (
    DuplicatePage,
    ErrorPage,
    ExportPage,
    FileDetailPage,
    OverviewPage,
    RiskPage,
    ScanConfigPage,
    SettingsPage,
)
from fileaudit.ui.styles import APP_STYLE


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("文件分析器")
        self.resize(1280, 820)
        self.setMinimumSize(1100, 700)

        self.current_path = ""
        self.top_bar = TopBar()
        self.bottom_bar = BottomBar()
        self.pages = QStackedWidget()
        self.preview_worker = None
        self.scan_worker = None
        self.scan_result = None
        self.settings = load_settings()

        self.scan_config_page = ScanConfigPage()
        self.scan_config_page.folder_selected.connect(self.on_folder_selected)
        self.scan_config_page.preview_requested.connect(self.on_preview_requested)
        self.scan_config_page.scan_requested.connect(self.on_scan_requested)
        self.scan_config_page.cancel_requested.connect(self.on_cancel_requested)
        self.scan_config_page.clear_requested.connect(self.on_clear_requested)

        self._setup_pages()
        self.sidebar = Sidebar(self.pages.setCurrentIndex)
        self.pages.currentChanged.connect(self.sidebar.set_current_index)
        self._setup_layout()
        self.setStyleSheet(APP_STYLE)
        self.apply_settings_to_pages()

    def _setup_pages(self):
        self.pages.addWidget(self.scan_config_page)
        self.overview_page = OverviewPage()
        self.pages.addWidget(self.overview_page)
        self.file_detail_page = FileDetailPage()
        self.pages.addWidget(self.file_detail_page)
        self.duplicate_page = DuplicatePage()
        self.pages.addWidget(self.duplicate_page)
        self.risk_page = RiskPage()
        self.pages.addWidget(self.risk_page)
        self.error_page = ErrorPage()
        self.pages.addWidget(self.error_page)
        self.export_page = ExportPage()
        self.export_page.export_requested.connect(self.on_export_requested)
        self.pages.addWidget(self.export_page)
        self.settings_page = SettingsPage()
        self.settings_page.settings_saved.connect(self.on_settings_saved)
        self.pages.addWidget(self.settings_page)

    def _setup_layout(self):
        root = QWidget()
        self.setCentralWidget(root)

        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(self.top_bar)

        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)
        body_layout.addWidget(self.sidebar)
        body_layout.addWidget(self.pages, 1)

        main_layout.addLayout(body_layout, 1)
        main_layout.addWidget(self.bottom_bar)

    def on_folder_selected(self, folder: str):
        self.current_path = folder
        self.top_bar.set_status("状态：已选择目录")
        self.sidebar.set_info("已选择目录", scan_path=folder)
        self.bottom_bar.set_message(f"当前目录：{folder}")

    def on_scan_requested(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.bottom_bar.set_message("扫描正在进行中")
            return
        if self.preview_worker and self.preview_worker.isRunning():
            self.bottom_bar.set_message("预检查正在进行中，请稍后再开始扫描")
            return

        if not self.scan_config_page.path_input.text().strip():
            QMessageBox.warning(self, "扫描配置错误", "请先选择要扫描的目录。")
            return

        try:
            options = self.scan_config_page.get_scan_options()
        except ValueError as error:
            QMessageBox.warning(self, "扫描配置错误", str(error))
            return

        self.current_path = str(options.root_path)
        self.top_bar.set_status("状态：扫描中")
        self.sidebar.set_info("扫描中", scan_path=self.current_path)
        self.bottom_bar.set_busy(True)
        self.bottom_bar.set_message(f"开始扫描：{options.root_path}")

        self.scan_worker = ScanWorker(options)
        self.scan_worker.detail_progress_changed.connect(self.on_scan_detail_progress)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.scan_failed.connect(self.on_scan_failed)
        self.scan_worker.finished.connect(self.on_scan_worker_finished)
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_worker.start()

    def on_scan_progress(self, stage: str, count: int, total: int, file_path: str):
        if stage == "hash":
            total_text = f" / {total:,}" if total else ""
            self.bottom_bar.set_message(f"正在计算重复文件 Hash：{count:,}{total_text} - {file_path}")
            return

        self.bottom_bar.set_message(f"正在扫描文件：{count:,} - {file_path}")

    def on_scan_detail_progress(
        self,
        stage: str,
        count: int,
        total: int,
        total_dirs: int,
        skipped_files: int,
        error_count: int,
        file_path: str,
    ):
        display_path = shorten_path(file_path)
        if stage == "hash":
            total_text = f" / {total:,}" if total else ""
            self.bottom_bar.set_message(
                f"正在计算重复文件 Hash：{count:,}{total_text}，目录 {total_dirs:,}，跳过 {skipped_files:,}，错误 {error_count:,} - {display_path}"
            )
            return

        self.bottom_bar.set_message(
            f"正在扫描：文件 {count:,}，目录 {total_dirs:,}，跳过 {skipped_files:,}，错误 {error_count:,} - {display_path}"
        )

    def on_preview_requested(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.bottom_bar.set_message("扫描正在进行中，无法预检查")
            return
        if self.preview_worker and self.preview_worker.isRunning():
            self.bottom_bar.set_message("预检查正在进行中")
            return
        if not self.scan_config_page.path_input.text().strip():
            QMessageBox.warning(self, "扫描配置错误", "请先选择要扫描的目录。")
            return

        try:
            options = self.scan_config_page.get_scan_options()
        except ValueError as error:
            QMessageBox.warning(self, "扫描配置错误", str(error))
            return

        self.bottom_bar.set_busy(True)
        self.bottom_bar.set_message(f"正在预检查：{options.root_path}")
        self.preview_worker = PreviewWorker(options)
        self.preview_worker.preview_progress_changed.connect(self.on_preview_progress)
        self.preview_worker.preview_finished.connect(self.on_preview_finished)
        self.preview_worker.preview_failed.connect(self.on_preview_failed)
        self.preview_worker.finished.connect(self.on_preview_worker_finished)
        self.preview_worker.finished.connect(self.preview_worker.deleteLater)
        self.preview_worker.start()

    def on_preview_progress(
        self,
        stage: str,
        count: int,
        total: int,
        total_dirs: int,
        skipped_files: int,
        error_count: int,
        file_path: str,
    ):
        self.bottom_bar.set_message(
            f"正在预检查：预计文件 {count:,}，目录 {total_dirs:,}，跳过 {skipped_files:,}，错误 {error_count:,} - {shorten_path(file_path)}"
        )

    def on_preview_finished(self, preview):
        self.bottom_bar.set_busy(False)
        self.bottom_bar.set_progress(0)
        hash_text = f"，Hash 候选 {preview.hash_candidate_files:,}" if preview.hash_candidate_files else ""
        skip_text = format_skip_reasons(preview.skip_reasons)
        skip_suffix = f"，跳过原因：{skip_text}" if skip_text else ""
        canceled_text = "（已取消）" if preview.canceled else ""
        self.bottom_bar.set_message(
            f"预检查{canceled_text}：预计扫描 {preview.total_files:,} 个文件，目录 {preview.total_dirs:,}，"
            f"大小 {format_size(preview.total_size)}，跳过 {preview.skipped_files + preview.skipped_dirs:,}，"
            f"错误 {preview.error_count:,}{hash_text}{skip_suffix}"
        )

    def on_preview_failed(self, message: str):
        self.bottom_bar.set_busy(False)
        self.bottom_bar.set_progress(0)
        self.bottom_bar.set_message(f"预检查失败：{message}")
        QMessageBox.warning(self, "预检查失败", message)

    def on_preview_worker_finished(self):
        self.preview_worker = None

    def on_scan_finished(self, result):
        self.scan_result = result
        summary = result.summary
        self.overview_page.update_result(result)
        self.file_detail_page.update_result(result)
        self.duplicate_page.update_result(result)
        self.risk_page.update_result(result)
        self.error_page.update_result(result)
        status_text = "已取消" if summary.canceled else "完成"
        self.top_bar.set_status(f"状态：扫描{status_text}")
        self.sidebar.set_info(status_text, summary.risk_files, summary.duplicate_files, str(summary.root_path))
        self.bottom_bar.set_busy(False)
        self.bottom_bar.set_progress(0 if summary.canceled else 100)
        self.bottom_bar.set_message(
            f"扫描{status_text}：文件 {summary.total_files:,}，可疑 {summary.risk_files:,}，"
            f"重复 {summary.duplicate_files:,}，错误 {summary.error_count:,}"
        )
        self.pages.setCurrentIndex(1)

    def on_cancel_requested(self):
        if not self.scan_worker or not self.scan_worker.isRunning():
            self.bottom_bar.set_message("当前没有正在运行的扫描")
            return

        self.scan_worker.cancel()
        self.top_bar.set_status("状态：正在取消")
        self.sidebar.set_info("正在取消", scan_path=self.current_path)
        self.bottom_bar.set_message("正在取消扫描，将保留已经扫描到的文件信息")

    def on_clear_requested(self):
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "无法清空", "扫描正在进行中，请先取消或等待扫描完成。")
            return

        self.scan_result = None
        self.overview_page.clear_result()
        self.file_detail_page.clear_result()
        self.duplicate_page.clear_result()
        self.risk_page.clear_result()
        self.error_page.clear_result()
        self.top_bar.set_status("状态：未扫描")
        self.sidebar.set_info("未开始", scan_path=self.current_path)
        self.bottom_bar.set_busy(False)
        self.bottom_bar.set_progress(0)
        self.bottom_bar.set_message("扫描结果已清空")

    def on_scan_failed(self, message: str):
        self.top_bar.set_status("状态：扫描失败")
        self.sidebar.set_info("失败", scan_path=self.current_path)
        self.bottom_bar.set_busy(False)
        self.bottom_bar.set_progress(0)
        self.bottom_bar.set_message(f"扫描失败：{message}")
        QMessageBox.warning(self, "扫描失败", message)

    def on_scan_worker_finished(self):
        self.scan_worker = None

    def apply_settings_to_pages(self):
        self.scan_config_page.apply_settings(self.settings)
        self.overview_page.apply_settings(self.settings)
        self.settings_page.apply_settings(self.settings)
        if self.scan_result:
            self.overview_page.update_result(self.scan_result)
        if self.settings.default_scan_dir:
            self.current_path = self.settings.default_scan_dir
            self.sidebar.set_info("已加载设置", scan_path=self.current_path)

    def on_settings_saved(self, settings):
        self.settings = settings
        try:
            save_settings(settings)
        except OSError as error:
            QMessageBox.warning(self, "保存失败", str(error))
            return

        self.apply_settings_to_pages()
        self.bottom_bar.set_message("设置已保存")
        QMessageBox.information(self, "设置", "设置已保存，并已同步到扫描配置页。")

    def on_export_requested(self):
        if not self.scan_result:
            QMessageBox.warning(self, "无法导出", "请先完成一次扫描，再生成报告。")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = Path(self.settings.default_report_dir) if self.settings.default_report_dir else Path.cwd() / "reports"
        default_dir = base_dir / f"fileaudit_report_{timestamp}"
        folder = QFileDialog.getExistingDirectory(self, "选择报告输出目录", str(default_dir.parent))
        if not folder:
            return

        output_dir = Path(folder) / default_dir.name
        try:
            report_path = export_report_bundle(
                self.scan_result,
                output_dir,
                export_full_paths=self.settings.export_full_paths,
                modified_time_months=self.settings.modified_time_months,
            )
        except OSError as error:
            QMessageBox.warning(self, "导出失败", str(error))
            return

        self.bottom_bar.set_message(f"报告已生成：{report_path}")
        QMessageBox.information(self, "导出完成", f"报告已生成：\n{report_path}")


def shorten_path(path: str, max_length: int = 90) -> str:
    if len(path) <= max_length:
        return path
    keep = max_length - 3
    head = keep // 2
    tail = keep - head
    return f"{path[:head]}...{path[-tail:]}"
