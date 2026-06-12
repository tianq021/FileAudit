"""Data models for FileAudit core features."""

from fileaudit.models.scan import (
    DEFAULT_IGNORED_DIRS,
    DEFAULT_SKIP_DIRS,
    DuplicateGroup,
    FileRecord,
    ScanError,
    ScanOptions,
    ScanPreview,
    ScanResult,
    ScanSummary,
)

__all__ = [
    "DEFAULT_IGNORED_DIRS",
    "DEFAULT_SKIP_DIRS",
    "DuplicateGroup",
    "FileRecord",
    "ScanError",
    "ScanOptions",
    "ScanPreview",
    "ScanResult",
    "ScanSummary",
]
