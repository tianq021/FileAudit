from __future__ import annotations

import hashlib
import os
import stat
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable

from fileaudit.models import DuplicateGroup, FileRecord, ScanError, ScanOptions, ScanResult, ScanSummary

ProgressCallback = Callable[[int, Path], None]
CancelCallback = Callable[[], bool]

HIGH_RISK_REASONS = {"suspicious extension", "double extension"}
MEDIUM_RISK_REASONS = {"hidden file", "time anomaly", "long path"}


def scan_directory(
    options: ScanOptions,
    progress_callback: ProgressCallback | None = None,
    should_cancel: CancelCallback | None = None,
) -> ScanResult:
    root_path = Path(options.root_path).expanduser().resolve()
    started_at = datetime.now()
    records: list[FileRecord] = []
    errors: list[ScanError] = []
    total_dirs = 0
    canceled = False

    if not root_path.exists():
        raise FileNotFoundError(f"Scan root does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Scan root is not a directory: {root_path}")

    for current_root, dir_names, file_names in os.walk(root_path, onerror=lambda error: _record_walk_error(error, errors)):
        if should_cancel and should_cancel():
            canceled = True
            break

        current_path = Path(current_root)
        dir_names[:] = _filter_dirs(dir_names, options.ignored_dirs)
        total_dirs += len(dir_names)

        if not options.recursive:
            dir_names[:] = []

        for file_name in file_names:
            if should_cancel and should_cancel():
                canceled = True
                break

            file_path = current_path / file_name
            try:
                record = _build_record(file_path, options)
            except OSError as error:
                errors.append(ScanError(file_path, str(error)))
                continue

            records.append(record)
            if progress_callback:
                progress_callback(len(records), file_path)

        if canceled:
            break

    duplicate_groups = (
        _find_duplicates(records, options, errors, should_cancel) if options.calculate_hash else []
    )
    if should_cancel and should_cancel():
        canceled = True
    summary = _build_summary(root_path, started_at, records, duplicate_groups, errors, total_dirs, canceled)
    return ScanResult(records, duplicate_groups, errors, summary)


def _filter_dirs(dir_names: list[str], ignored_dirs: tuple[str, ...]) -> list[str]:
    ignored = {name.lower() for name in ignored_dirs}
    return [name for name in dir_names if name.lower() not in ignored]


def _record_walk_error(error: OSError, errors: list[ScanError]) -> None:
    errors.append(ScanError(Path(getattr(error, "filename", "")), str(error)))


def _build_record(file_path: Path, options: ScanOptions) -> FileRecord:
    file_stat = file_path.stat()
    record = FileRecord(
        path=file_path,
        name=file_path.name,
        parent=file_path.parent,
        extension=file_path.suffix.lower(),
        size=file_stat.st_size,
        created_at=datetime.fromtimestamp(file_stat.st_ctime),
        modified_at=datetime.fromtimestamp(file_stat.st_mtime),
        is_empty=file_stat.st_size == 0,
        is_hidden=_is_hidden(file_path),
    )
    _apply_risk_rules(record, options)
    return record


def _apply_risk_rules(record: FileRecord, options: ScanOptions) -> None:
    suspicious_extensions = {extension.lower() for extension in options.suspicious_extensions}
    whitelisted_extensions = {extension.lower() for extension in options.whitelisted_extensions}
    threshold_bytes = max(options.big_file_threshold_mb, 0) * 1024 * 1024
    extension_is_whitelisted = record.extension in whitelisted_extensions

    if options.detect_suspicious_extensions and not extension_is_whitelisted and record.extension in suspicious_extensions:
        record.risk_reasons.append("suspicious extension")

    if options.detect_double_extensions and not extension_is_whitelisted and _has_double_extension(record.path, suspicious_extensions):
        record.risk_reasons.append("double extension")

    if options.detect_hidden_files and record.is_hidden:
        record.risk_reasons.append("hidden file")

    if options.detect_empty_files and record.is_empty:
        record.risk_reasons.append("empty file")

    if options.detect_big_files and threshold_bytes and record.size >= threshold_bytes:
        record.risk_reasons.append("big file")

    if options.detect_time_anomalies and record.modified_at.timestamp() > datetime.now().timestamp() + 300:
        record.risk_reasons.append("time anomaly")

    if options.detect_long_paths and len(str(record.path)) >= options.path_length_threshold:
        record.risk_reasons.append("long path")

    record.risk_level = _risk_level(record.risk_reasons)


def _has_double_extension(file_path: Path, suspicious_extensions: set[str]) -> bool:
    suffixes = [suffix.lower() for suffix in file_path.suffixes]
    if len(suffixes) < 2:
        return False
    return suffixes[-1] in suspicious_extensions


def _risk_level(reasons: list[str]) -> str:
    if any(reason in HIGH_RISK_REASONS for reason in reasons):
        return "high"
    if any(reason in MEDIUM_RISK_REASONS for reason in reasons):
        return "medium"
    if reasons:
        return "low"
    return "normal"


def _is_hidden(file_path: Path) -> bool:
    if file_path.name.startswith("."):
        return True
    if os.name != "nt":
        return False
    try:
        return bool(file_path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
    except (AttributeError, OSError):
        return False


def _find_duplicates(
    records: list[FileRecord],
    options: ScanOptions,
    errors: list[ScanError],
    should_cancel: CancelCallback | None = None,
) -> list[DuplicateGroup]:
    by_size: dict[int, list[FileRecord]] = defaultdict(list)
    for record in records:
        if record.size > 0:
            by_size[record.size].append(record)

    duplicate_groups: list[DuplicateGroup] = []
    for size, same_size_records in by_size.items():
        if should_cancel and should_cancel():
            break
        if len(same_size_records) < 2:
            continue

        by_hash: dict[str, list[FileRecord]] = defaultdict(list)
        for record in same_size_records:
            if should_cancel and should_cancel():
                break
            try:
                record.hash_value = _hash_file(record.path, options.hash_algorithm)
            except OSError as error:
                errors.append(ScanError(record.path, str(error)))
                continue
            by_hash[record.hash_value].append(record)

        for hash_value, same_hash_records in by_hash.items():
            if len(same_hash_records) > 1:
                duplicate_groups.append(DuplicateGroup(hash_value, size, same_hash_records))

    duplicate_groups.sort(key=lambda group: group.wasted_size, reverse=True)
    return duplicate_groups


def _hash_file(file_path: Path, algorithm: str) -> str:
    digest = hashlib.new(_normalize_hash_algorithm(algorithm))
    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_hash_algorithm(algorithm: str) -> str:
    normalized = algorithm.lower().strip()
    if normalized.startswith("sha1"):
        return "sha1"
    if normalized.startswith("sha256"):
        return "sha256"
    if normalized.startswith("md5"):
        return "md5"
    return normalized


def _build_summary(
    root_path: Path,
    started_at: datetime,
    records: list[FileRecord],
    duplicate_groups: list[DuplicateGroup],
    errors: list[ScanError],
    total_dirs: int,
    canceled: bool,
) -> ScanSummary:
    extension_counts = Counter(record.extension or "[none]" for record in records)
    risk_counts = Counter(record.risk_level for record in records)
    duplicate_files = sum(len(group.files) for group in duplicate_groups)

    return ScanSummary(
        root_path=root_path,
        started_at=started_at,
        finished_at=datetime.now(),
        canceled=canceled,
        total_files=len(records),
        total_dirs=total_dirs,
        total_size=sum(record.size for record in records),
        duplicate_files=duplicate_files,
        duplicate_groups=len(duplicate_groups),
        duplicate_wasted_size=sum(group.wasted_size for group in duplicate_groups),
        risk_files=sum(1 for record in records if record.risk_level != "normal"),
        error_count=len(errors),
        extension_counts=dict(extension_counts),
        risk_counts=dict(risk_counts),
    )
