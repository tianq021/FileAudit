from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from fileaudit.core import preview_scan, scan_directory
from fileaudit.models import ScanOptions


class ScanWorker(QThread):
    progress_changed = Signal(str, int, int, str)
    detail_progress_changed = Signal(str, int, int, int, int, int, str)
    scan_finished = Signal(object)
    scan_failed = Signal(str)

    def __init__(self, options: ScanOptions):
        super().__init__()
        self.options = options
        self._cancel_requested = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:
        try:
            result = scan_directory(
                self.options,
                stage_progress_callback=self._emit_progress,
                should_cancel=lambda: self._cancel_requested,
            )
        except Exception as error:
            self.scan_failed.emit(str(error))
            return

        self.scan_finished.emit(result)

    def _emit_progress(
        self,
        stage: str,
        count: int,
        total: int,
        file_path: Path,
        total_dirs: int,
        skipped_files: int,
        error_count: int,
    ) -> None:
        self.progress_changed.emit(stage, count, total, str(file_path))
        self.detail_progress_changed.emit(stage, count, total, total_dirs, skipped_files, error_count, str(file_path))


class PreviewWorker(QThread):
    preview_progress_changed = Signal(str, int, int, int, int, int, str)
    preview_finished = Signal(object)
    preview_failed = Signal(str)

    def __init__(self, options: ScanOptions):
        super().__init__()
        self.options = options
        self._cancel_requested = False

    def cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:
        try:
            result = preview_scan(
                self.options,
                progress_callback=self._emit_progress,
                should_cancel=lambda: self._cancel_requested,
            )
        except Exception as error:
            self.preview_failed.emit(str(error))
            return

        self.preview_finished.emit(result)

    def _emit_progress(
        self,
        stage: str,
        count: int,
        total: int,
        file_path: Path,
        total_dirs: int,
        skipped_files: int,
        error_count: int,
    ) -> None:
        self.preview_progress_changed.emit(stage, count, total, total_dirs, skipped_files, error_count, str(file_path))
