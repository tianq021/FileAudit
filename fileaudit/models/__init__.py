"""Data models for FileAudit core features."""

from fileaudit.models.scan import (
    DuplicateGroup,
    FileRecord,
    ScanError,
    ScanOptions,
    ScanResult,
    ScanSummary,
)

__all__ = [
    "DuplicateGroup",
    "FileRecord",
    "ScanError",
    "ScanOptions",
    "ScanResult",
    "ScanSummary",
]
