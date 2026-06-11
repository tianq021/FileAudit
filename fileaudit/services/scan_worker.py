from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from fileaudit.core import scan_directory
from fileaudit.models import ScanOptions


class ScanWorker(QThread):
    progress_changed = Signal(str, int, int, str)
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

    def _emit_progress(self, stage: str, count: int, total: int, file_path: Path) -> None:
        self.progress_changed.emit(stage, count, total, str(file_path))
