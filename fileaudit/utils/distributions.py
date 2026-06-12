from datetime import datetime, timedelta

from fileaudit.utils.file_types import classify_file_type
from fileaudit.utils.formatters import format_risk_level, format_risk_reasons, format_skip_reason


def build_file_type_distribution(records) -> list[tuple[str, int]]:
    counts = {}
    for record in records:
        file_type = classify_file_type(record.extension)
        counts[file_type] = counts.get(file_type, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)


def build_risk_distribution(risk_counts: dict[str, int]) -> list[tuple[str, int]]:
    order = ["high", "medium", "low", "normal"]
    return [
        (format_risk_level(level), risk_counts.get(level, 0))
        for level in order
        if risk_counts.get(level, 0)
    ]


def build_extension_distribution(records) -> list[tuple[str, int]]:
    counts = {}
    for record in records:
        extension = record.extension or "[无扩展名]"
        counts[extension] = counts.get(extension, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]


def build_size_distribution(records) -> list[tuple[str, int]]:
    buckets = {
        "空文件": 0,
        "< 1 MB": 0,
        "1-10 MB": 0,
        "10-100 MB": 0,
        "100 MB-1 GB": 0,
        ">= 1 GB": 0,
    }
    for record in records:
        size = record.size
        if size == 0:
            buckets["空文件"] += 1
        elif size < 1024 * 1024:
            buckets["< 1 MB"] += 1
        elif size < 10 * 1024 * 1024:
            buckets["1-10 MB"] += 1
        elif size < 100 * 1024 * 1024:
            buckets["10-100 MB"] += 1
        elif size < 1024 * 1024 * 1024:
            buckets["100 MB-1 GB"] += 1
        else:
            buckets[">= 1 GB"] += 1
    return [(label, count) for label, count in buckets.items() if count]


def build_risk_reason_distribution(records) -> list[tuple[str, int]]:
    counts = {}
    for record in records:
        for reason in record.risk_reasons:
            label = format_risk_reasons([reason])
            counts[label] = counts.get(label, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]


def build_risk_directory_distribution(records, export_full_paths: bool = True) -> list[tuple[str, int]]:
    counts = {}
    for record in records:
        if record.risk_level == "normal":
            continue
        directory = str(record.parent) if export_full_paths else record.parent.name
        counts[directory] = counts.get(directory, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]


def build_skip_reason_distribution(skip_reasons: dict[str, int]) -> list[tuple[str, int]]:
    return [
        (format_skip_reason(reason), count)
        for reason, count in sorted(skip_reasons.items(), key=lambda item: item[1], reverse=True)
    ]


def build_largest_files_distribution(records) -> list[tuple[str, int]]:
    largest_records = sorted(records, key=lambda record: record.size, reverse=True)[:10]
    return [(record.name, record.size) for record in largest_records]


def build_duplicate_group_distribution(duplicate_groups) -> list[tuple[str, int]]:
    rows = []
    for index, group in enumerate(duplicate_groups[:10], start=1):
        label = f"第 {index} 组（{len(group.files)} 个）"
        rows.append((label, group.wasted_size))
    return rows


def build_duplicate_extension_distribution(duplicate_groups) -> list[tuple[str, int]]:
    counts = {}
    for group in duplicate_groups:
        for record in group.files:
            extension = record.extension or "[无扩展名]"
            counts[extension] = counts.get(extension, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]


def build_error_directory_distribution(errors, export_full_paths: bool = True) -> list[tuple[str, int]]:
    counts = {}
    for error in errors:
        parent = error.path.parent
        directory = str(parent) if export_full_paths else parent.name
        if not directory:
            directory = str(error.path)
        counts[directory] = counts.get(directory, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]


def build_modified_time_distribution(records, recent_months: int = 3) -> list[tuple[str, int]]:
    now = datetime.now()
    recent_months = max(1, int(recent_months or 3))
    buckets = {
        "今天": 0,
        "7 天内": 0,
        "30 天内": 0,
        f"{recent_months} 个月内": 0,
        "更早": 0,
        "未来时间": 0,
    }
    for record in records:
        modified_at = record.modified_at
        if modified_at > now:
            buckets["未来时间"] += 1
        elif modified_at.date() == now.date():
            buckets["今天"] += 1
        elif modified_at >= now - timedelta(days=7):
            buckets["7 天内"] += 1
        elif modified_at >= now - timedelta(days=30):
            buckets["30 天内"] += 1
        elif modified_at >= now - timedelta(days=recent_months * 30):
            buckets[f"{recent_months} 个月内"] += 1
        else:
            buckets["更早"] += 1
    return [(label, count) for label, count in buckets.items() if count]


def build_directory_size_distribution(records, export_full_paths: bool = True) -> list[tuple[str, int]]:
    sizes = {}
    for record in records:
        directory = str(record.parent) if export_full_paths else record.parent.name
        sizes[directory] = sizes.get(directory, 0) + record.size
    top_items = sorted(sizes.items(), key=lambda item: item[1], reverse=True)[:10]
    return [(path, size) for path, size in top_items]
