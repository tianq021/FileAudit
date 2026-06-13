from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from fileaudit.models import DEFAULT_IGNORED_DIRS, DEFAULT_SKIP_DIRS


def _project_settings_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "settings.json"
    return Path(__file__).resolve().parents[2] / "settings.json"


SETTINGS_PATH = _project_settings_path()


@dataclass
class AppSettings:
    default_scan_dir: str = ""
    default_report_dir: str = ""
    recursive: bool = True
    calculate_hash: bool = True
    hash_algorithm: str = "SHA256"
    big_file_threshold_mb: int = 100
    path_length_threshold: int = 180
    file_timeout_seconds: int = 15
    modified_time_months: int = 3
    detect_suspicious_extensions: bool = True
    detect_double_extensions: bool = True
    detect_hidden_files: bool = True
    detect_empty_files: bool = True
    detect_big_files: bool = True
    detect_time_anomalies: bool = True
    detect_long_paths: bool = True
    ignored_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORED_DIRS))
    skip_hidden_files: bool = False
    skip_large_files_mb: int = 0
    skip_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_SKIP_DIRS))
    skip_file_names: list[str] = field(default_factory=list)
    skip_extensions: list[str] = field(default_factory=lambda: [".key", ".pem", ".pfx", ".kdbx", ".wallet"])
    skip_path_keywords: list[str] = field(default_factory=list)
    include_only_matched: bool = False
    include_conflict_policy: str = "skip_wins"
    include_extensions: list[str] = field(default_factory=list)
    include_name_keywords: list[str] = field(default_factory=list)
    include_path_keywords: list[str] = field(default_factory=list)
    include_file_types: list[str] = field(default_factory=list)
    export_full_paths: bool = True
    suspicious_extensions: list[str] = field(
        default_factory=lambda: [
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
        ]
    )
    whitelisted_extensions: list[str] = field(default_factory=list)


def default_settings() -> AppSettings:
    return AppSettings()


def load_settings(path: Path = SETTINGS_PATH) -> AppSettings:
    if not path.exists():
        return default_settings()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_settings()

    defaults = asdict(default_settings())
    defaults.update({key: value for key, value in data.items() if key in defaults})
    return AppSettings(**defaults)


def save_settings(settings: AppSettings, path: Path = SETTINGS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(asdict(settings), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
