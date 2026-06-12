from __future__ import annotations

import csv
import html
from datetime import datetime
from pathlib import Path

from fileaudit.models import ScanResult


def export_report_bundle(result: ScanResult, output_dir: Path, export_full_paths: bool = True) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_summary_csv(result, output_dir / "summary.csv")
    _write_files_csv(result, output_dir / "files.csv", export_full_paths)
    _write_duplicates_csv(result, output_dir / "duplicates.csv", export_full_paths)
    _write_risks_csv(result, output_dir / "risks.csv", export_full_paths)
    _write_errors_csv(result, output_dir / "errors.csv", export_full_paths)

    report_path = output_dir / "report.html"
    report_path.write_text(_build_html_report(result, export_full_paths), encoding="utf-8")
    return report_path


def _write_summary_csv(result: ScanResult, path: Path) -> None:
    summary = result.summary
    rows = [
        ("扫描目录", str(summary.root_path)),
        ("开始时间", _format_datetime(summary.started_at)),
        ("结束时间", _format_datetime(summary.finished_at)),
        ("是否取消", "是" if summary.canceled else "否"),
        ("总文件数", summary.total_files),
        ("总目录数", summary.total_dirs),
        ("总大小字节", summary.total_size),
        ("总大小", _format_size(summary.total_size)),
        ("重复文件数", summary.duplicate_files),
        ("重复文件组", summary.duplicate_groups),
        ("可节省空间字节", summary.duplicate_wasted_size),
        ("可节省空间", _format_size(summary.duplicate_wasted_size)),
        ("可疑文件数", summary.risk_files),
        ("扫描错误数", summary.error_count),
        ("跳过文件数", summary.skipped_files),
        ("跳过目录数", summary.skipped_dirs),
        ("跳过原因", _format_skip_reasons(summary.skip_reasons)),
    ]
    _write_csv(path, ["项目", "值"], rows)


def _write_files_csv(result: ScanResult, path: Path, export_full_paths: bool) -> None:
    rows = []
    for record in result.records:
        rows.append([
            record.name,
            _format_record_path(record, export_full_paths),
            record.extension,
            record.size,
            _format_size(record.size),
            _format_datetime(record.created_at),
            _format_datetime(record.modified_at),
            "是" if record.is_hidden else "否",
            "是" if record.is_empty else "否",
            _format_risk_level(record.risk_level),
            _format_risk_reasons(record.risk_reasons),
            record.hash_value,
        ])
    _write_csv(
        path,
        ["文件名", _path_header(export_full_paths), "扩展名", "大小字节", "大小", "创建时间", "修改时间", "隐藏", "空文件", "风险", "原因", "Hash"],
        rows,
    )


def _write_duplicates_csv(result: ScanResult, path: Path, export_full_paths: bool) -> None:
    rows = []
    for group_index, group in enumerate(result.duplicate_groups, start=1):
        for record in group.files:
            rows.append([
                group_index,
                record.name,
                _format_record_path(record, export_full_paths),
                group.size,
                _format_size(group.size),
                len(group.files),
                group.hash_value,
                group.wasted_size,
                _format_size(group.wasted_size),
            ])
    _write_csv(path, ["组号", "文件名", _path_header(export_full_paths), "大小字节", "大小", "组内文件数", "Hash", "组可节省字节", "组可节省空间"], rows)


def _write_risks_csv(result: ScanResult, path: Path, export_full_paths: bool) -> None:
    records = [record for record in result.records if record.risk_level != "normal"]
    records.sort(key=lambda record: _risk_sort_key(record.risk_level))
    rows = [
        [
            _format_risk_level(record.risk_level),
            record.name,
            _format_record_path(record, export_full_paths),
            record.extension,
            record.size,
            _format_size(record.size),
            _format_datetime(record.modified_at),
            _format_risk_reasons(record.risk_reasons),
        ]
        for record in records
    ]
    _write_csv(path, ["风险", "文件名", _path_header(export_full_paths), "扩展名", "大小字节", "大小", "修改时间", "原因"], rows)


def _write_errors_csv(result: ScanResult, path: Path, export_full_paths: bool) -> None:
    rows = [[str(error.path) if export_full_paths else Path(error.path).name, error.message] for error in result.errors]
    _write_csv(path, [_path_header(export_full_paths), "错误"], rows)


def _write_csv(path: Path, headers: list[str], rows) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)


def _build_html_report(result: ScanResult, export_full_paths: bool) -> str:
    summary = result.summary
    type_items = _file_type_distribution(result)
    risk_items = _risk_distribution(result)
    directory_items = _directory_size_distribution(result, export_full_paths)
    extension_items = _extension_distribution(result)
    size_items = _size_distribution(result)
    risk_reason_items = _risk_reason_distribution(result)
    skip_reason_items = [(_format_skip_reason_name(reason), count) for reason, count in summary.skip_reasons.items()]
    generated_at = _format_datetime(datetime.now())
    status = "已取消" if summary.canceled else "完成"

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>FileAudit 扫描报告</title>
  <style>
    body {{ margin: 0; background: #111827; color: #e5e7eb; font-family: "Microsoft YaHei", Arial, sans-serif; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    h1 {{ margin: 0 0 6px; font-size: 28px; }}
    .muted {{ color: #9ca3af; }}
    .cards {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; margin: 24px 0; }}
    .card, .panel {{ background: #1f2937; border: 1px solid #374151; border-radius: 8px; }}
    .card {{ padding: 16px; }}
    .card b {{ display: block; margin-top: 8px; font-size: 28px; color: #fff; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    .panel {{ padding: 16px; margin-bottom: 16px; }}
    .panel.wide {{ grid-column: 1 / -1; }}
    .bar-row {{ display: grid; grid-template-columns: minmax(120px, 220px) 1fr 96px; gap: 12px; align-items: center; margin: 12px 0; }}
    .bar-bg {{ height: 12px; background: #111827; border-radius: 999px; overflow: hidden; }}
    .bar {{ height: 12px; border-radius: 999px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border-bottom: 1px solid #374151; padding: 8px; text-align: left; font-size: 13px; }}
    th {{ color: #fff; background: #182230; }}
    td.path {{ max-width: 560px; word-break: break-all; }}
  </style>
</head>
<body>
<main>
  <h1>FileAudit 扫描报告</h1>
  <div class="muted">扫描目录：{_escape(str(summary.root_path) if export_full_paths else summary.root_path.name)}</div>
  <div class="muted">状态：{status}　生成时间：{generated_at}</div>
  <section class="cards">
    {_card("总文件数", f"{summary.total_files:,}")}
    {_card("总大小", _format_size(summary.total_size))}
    {_card("重复文件", f"{summary.duplicate_files:,}")}
    {_card("可疑文件", f"{summary.risk_files:,}")}
    {_card("扫描错误", f"{summary.error_count:,}")}
    {_card("已跳过", f"{summary.skipped_files + summary.skipped_dirs:,}")}
  </section>
  <section class="grid">
    {_chart_panel("文件类型分布", type_items, "#2f80ed")}
    {_chart_panel("风险等级分布", risk_items, "#f97316")}
    {_chart_panel("目录占用 Top 10", directory_items, "#22c55e", _format_size, wide=True)}
    {_chart_panel("扩展名 Top 10", extension_items, "#a855f7")}
    {_chart_panel("文件大小分布", size_items, "#06b6d4")}
    {_chart_panel("风险原因 Top 10", risk_reason_items, "#ef4444")}
    {_chart_panel("跳过原因", skip_reason_items, "#f59e0b")}
  </section>
  <section class="panel">
    <h2>高风险/中风险文件预览</h2>
    {_risk_preview_table(result, export_full_paths)}
  </section>
  <section class="panel">
    <h2>扫描错误预览</h2>
    {_error_preview_table(result, export_full_paths)}
  </section>
</main>
</body>
</html>
"""


def _card(title: str, value: str) -> str:
    return f'<div class="card"><span class="muted">{_escape(title)}</span><b>{_escape(value)}</b></div>'


def _chart_panel(title: str, items: list[tuple[str, int]], color: str, formatter=None, wide: bool = False) -> str:
    formatter = formatter or (lambda value: f"{value:,}")
    total = sum(value for _, value in items) or 1
    max_value = max((value for _, value in items), default=1)
    rows = []
    for label, value in items[:10]:
        width = max(2, int(value / max_value * 100))
        percent = value / total
        rows.append(
            f'<div class="bar-row"><div>{_escape(label)}</div>'
            f'<div class="bar-bg"><div class="bar" style="width:{width}%;background:{color}"></div></div>'
            f'<div>{_escape(formatter(value))} ({percent:.0%})</div></div>'
        )
    body = "\n".join(rows) if rows else '<div class="muted">暂无数据</div>'
    class_name = "panel wide" if wide else "panel"
    return f'<section class="{class_name}"><h2>{_escape(title)}</h2>{body}</section>'


def _risk_preview_table(result: ScanResult, export_full_paths: bool) -> str:
    records = [record for record in result.records if record.risk_level in {"high", "medium"}]
    records.sort(key=lambda record: _risk_sort_key(record.risk_level))
    records = records[:30]
    if not records:
        return '<div class="muted">暂无高风险或中风险文件。</div>'
    rows = []
    for record in records:
        rows.append(
            "<tr>"
            f"<td>{_escape(_format_risk_level(record.risk_level))}</td>"
            f"<td>{_escape(record.name)}</td>"
            f'<td class="path">{_escape(_format_record_path(record, export_full_paths))}</td>'
            f"<td>{_escape(_format_size(record.size))}</td>"
            f"<td>{_escape(_format_risk_reasons(record.risk_reasons))}</td>"
            "</tr>"
        )
    return f"<table><thead><tr><th>风险</th><th>文件名</th><th>{_escape(_path_header(export_full_paths))}</th><th>大小</th><th>原因</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _error_preview_table(result: ScanResult, export_full_paths: bool) -> str:
    errors = result.errors[:30]
    if not errors:
        return '<div class="muted">暂无扫描错误。</div>'
    rows = []
    for error in errors:
        path = str(error.path) if export_full_paths else Path(error.path).name
        rows.append(
            "<tr>"
            f'<td class="path">{_escape(path)}</td>'
            f"<td>{_escape(error.message)}</td>"
            "</tr>"
        )
    return f"<table><thead><tr><th>{_escape(_path_header(export_full_paths))}</th><th>错误原因</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _file_type_distribution(result: ScanResult) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for record in result.records:
        name = _classify_file_type(record.extension)
        counts[name] = counts.get(name, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)


def _risk_distribution(result: ScanResult) -> list[tuple[str, int]]:
    order = ["high", "medium", "low", "normal"]
    return [
        (_format_risk_level(level), result.summary.risk_counts.get(level, 0))
        for level in order
        if result.summary.risk_counts.get(level, 0)
    ]


def _extension_distribution(result: ScanResult) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for record in result.records:
        extension = record.extension or "[无扩展名]"
        counts[extension] = counts.get(extension, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]


def _size_distribution(result: ScanResult) -> list[tuple[str, int]]:
    buckets = {
        "空文件": 0,
        "< 1 MB": 0,
        "1-10 MB": 0,
        "10-100 MB": 0,
        "100 MB-1 GB": 0,
        ">= 1 GB": 0,
    }
    for record in result.records:
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


def _risk_reason_distribution(result: ScanResult) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for record in result.records:
        for reason in record.risk_reasons:
            label = _format_risk_reasons([reason])
            counts[label] = counts.get(label, 0) + 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]


def _directory_size_distribution(result: ScanResult, export_full_paths: bool) -> list[tuple[str, int]]:
    sizes: dict[str, int] = {}
    for record in result.records:
        path = str(record.parent) if export_full_paths else record.parent.name
        sizes[path] = sizes.get(path, 0) + record.size
    return sorted(sizes.items(), key=lambda item: item[1], reverse=True)[:10]


def _format_record_path(record, export_full_paths: bool) -> str:
    return str(record.path) if export_full_paths else record.name


def _path_header(export_full_paths: bool) -> str:
    return "完整路径" if export_full_paths else "路径信息"


def _classify_file_type(extension: str) -> str:
    extension = extension.lower()
    groups = {
        "文档": {".csv", ".doc", ".docx", ".md", ".pdf", ".ppt", ".pptx", ".rtf", ".txt", ".xls", ".xlsx"},
        "图片": {".bmp", ".gif", ".jpeg", ".jpg", ".png", ".svg", ".tif", ".tiff", ".webp"},
        "音视频": {".aac", ".avi", ".flac", ".m4a", ".mkv", ".mov", ".mp3", ".mp4", ".wav", ".webm", ".wmv"},
        "压缩包": {".7z", ".gz", ".rar", ".tar", ".tgz", ".zip"},
        "代码": {".bat", ".cmd", ".css", ".go", ".html", ".java", ".js", ".json", ".py", ".rs", ".sh", ".ts", ".xml", ".yaml", ".yml"},
        "可执行": {".com", ".dll", ".exe", ".msi", ".scr"},
    }
    for name, extensions in groups.items():
        if extension in extensions:
            return name
    return "其他"


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def _format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _format_risk_level(level: str) -> str:
    return {"high": "高风险", "medium": "中风险", "low": "低风险", "normal": "正常"}.get(level, level)


def _format_risk_reasons(reasons: list[str]) -> str:
    names = {
        "suspicious extension": "可疑扩展名",
        "script file": "脚本文件",
        "double extension": "双扩展名伪装",
        "hidden file": "隐藏文件",
        "empty file": "空文件",
        "big file": "大文件",
        "large file without extension": "无扩展名大文件",
        "temporary file": "临时/备份文件",
        "time anomaly": "时间异常",
        "long path": "路径过长",
    }
    return "，".join(names.get(reason, reason) for reason in reasons)


def _format_skip_reasons(reasons: dict[str, int]) -> str:
    if not reasons:
        return "无"
    return "，".join(f"{_format_skip_reason_name(reason)} {count}" for reason, count in reasons.items())


def _format_skip_reason_name(reason: str) -> str:
    names = {
        "skip dir name": "目录名",
        "skip dir path keyword": "目录路径关键词",
        "skip file name": "文件名",
        "skip path keyword": "路径关键词",
        "skip extension": "扩展名",
        "skip hidden file": "隐藏文件",
        "skip large file": "大文件",
        "skip include unmatched": "未匹配只扫描规则",
    }
    return names.get(reason, reason)


def _risk_sort_key(level: str) -> int:
    return {"high": 0, "medium": 1, "low": 2, "normal": 3}.get(level, 9)


def _escape(value: str) -> str:
    return html.escape(str(value), quote=True)
