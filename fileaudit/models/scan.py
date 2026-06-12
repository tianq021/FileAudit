from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

DEFAULT_IGNORED_DIRS = (".git", "__pycache__", "node_modules", ".venv", "venv")
DEFAULT_SKIP_DIRS = (
    "System Volume Information",
    "$RECYCLE.BIN",
    "Recovery",
    "Config.Msi",
)


@dataclass
class ScanOptions:
    root_path: Path
    recursive: bool = True
    calculate_hash: bool = True
    hash_algorithm: str = "sha256"
    big_file_threshold_mb: int = 100
    path_length_threshold: int = 180
    detect_suspicious_extensions: bool = True
    detect_double_extensions: bool = True
    detect_hidden_files: bool = True
    detect_empty_files: bool = True
    detect_big_files: bool = True
    detect_time_anomalies: bool = True
    detect_long_paths: bool = True
    ignored_dirs: tuple[str, ...] = DEFAULT_IGNORED_DIRS
    whitelisted_extensions: tuple[str, ...] = ()
    skip_hidden_files: bool = False
    skip_large_files_mb: int = 0
    skip_dirs: tuple[str, ...] = DEFAULT_SKIP_DIRS
    skip_file_names: tuple[str, ...] = ()
    skip_extensions: tuple[str, ...] = ()
    skip_path_keywords: tuple[str, ...] = ()
    include_only_matched: bool = False
    include_conflict_policy: str = "skip_wins"
    include_extensions: tuple[str, ...] = ()
    include_name_keywords: tuple[str, ...] = ()
    include_path_keywords: tuple[str, ...] = ()
    include_file_types: tuple[str, ...] = ()
    suspicious_extensions: tuple[str, ...] = (
        ".bat",
        ".cmd",
        ".com",
        ".dll",
        ".exe",
        ".jse",
        ".lnk",
        ".msi",
        ".ps1",
        ".scr",
        ".vbe",
        ".vbs",
        ".wsf",
    )


@dataclass
class FileRecord:
    path: Path
    name: str
    parent: Path
    extension: str
    size: int
    created_at: datetime
    modified_at: datetime
    is_empty: bool = False
    is_hidden: bool = False
    hash_value: str = ""
    risk_level: str = "normal"
    risk_reasons: list[str] = field(default_factory=list)


@dataclass
class ScanError:
    path: Path
    message: str


@dataclass
class DuplicateGroup:
    hash_value: str
    size: int
    files: list[FileRecord]

    @property
    def wasted_size(self) -> int:
        if len(self.files) <= 1:
            return 0
        return self.size * (len(self.files) - 1)


@dataclass
class ScanSummary:
    root_path: Path
    started_at: datetime
    finished_at: datetime
    canceled: bool = False
    total_files: int = 0
    total_dirs: int = 0
    total_size: int = 0
    duplicate_files: int = 0
    duplicate_groups: int = 0
    duplicate_wasted_size: int = 0
    risk_files: int = 0
    error_count: int = 0
    skipped_files: int = 0
    skipped_dirs: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    extension_counts: dict[str, int] = field(default_factory=dict)
    risk_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    records: list[FileRecord]
    duplicate_groups: list[DuplicateGroup]
    errors: list[ScanError]
    summary: ScanSummary
