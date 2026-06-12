from __future__ import annotations

import csv
import html
from datetime import datetime
from pathlib import Path

from fileaudit.models import ScanResult
from fileaudit.utils import (
    build_directory_size_distribution,
    build_duplicate_extension_distribution,
    build_extension_distribution,
    build_error_directory_distribution,
    build_file_type_distribution,
    build_modified_time_distribution,
    build_risk_distribution,
    build_risk_directory_distribution,
    build_risk_reason_distribution,
    build_size_distribution,
    build_skip_reason_distribution,
    format_datetime,
    format_risk_level,
    format_risk_reasons,
    format_size,
    format_skip_reasons,
    risk_sort_key,
)


def export_report_bundle(
    result: ScanResult,
    output_dir: Path,
    export_full_paths: bool = True,
    modified_time_months: int = 3,
) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_summary_csv(result, output_dir / "summary.csv")
    _write_files_csv(result, output_dir / "files.csv", export_full_paths)
    _write_duplicates_csv(result, output_dir / "duplicates.csv", export_full_paths)
    _write_risks_csv(result, output_dir / "risks.csv", export_full_paths)
    _write_errors_csv(result, output_dir / "errors.csv", export_full_paths)

    report_path = output_dir / "report.html"
    report_path.write_text(_build_html_report(result, export_full_paths, modified_time_months), encoding="utf-8")
    return report_path


def _write_summary_csv(result: ScanResult, path: Path) -> None:
    summary = result.summary
    rows = [
        ("扫描目录", str(summary.root_path)),
        ("开始时间", format_datetime(summary.started_at)),
        ("结束时间", format_datetime(summary.finished_at)),
        ("是否取消", "是" if summary.canceled else "否"),
        ("总文件数", summary.total_files),
        ("总目录数", summary.total_dirs),
        ("总大小字节", summary.total_size),
        ("总大小", format_size(summary.total_size)),
        ("重复文件数", summary.duplicate_files),
        ("重复文件组", summary.duplicate_groups),
        ("可节省空间字节", summary.duplicate_wasted_size),
        ("可节省空间", format_size(summary.duplicate_wasted_size)),
        ("可疑文件数", summary.risk_files),
        ("扫描错误数", summary.error_count),
        ("跳过文件数", summary.skipped_files),
        ("跳过目录数", summary.skipped_dirs),
        ("跳过原因", format_skip_reasons(summary.skip_reasons)),
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
            format_size(record.size),
            format_datetime(record.created_at),
            format_datetime(record.modified_at),
            "是" if record.is_hidden else "否",
            "是" if record.is_empty else "否",
            format_risk_level(record.risk_level),
            format_risk_reasons(record.risk_reasons),
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
                format_size(group.size),
                len(group.files),
                group.hash_value,
                group.wasted_size,
                format_size(group.wasted_size),
            ])
    _write_csv(path, ["组号", "文件名", _path_header(export_full_paths), "大小字节", "大小", "组内文件数", "Hash", "组可节省字节", "组可节省空间"], rows)


def _write_risks_csv(result: ScanResult, path: Path, export_full_paths: bool) -> None:
    records = [record for record in result.records if record.risk_level != "normal"]
    records.sort(key=lambda record: risk_sort_key(record.risk_level))
    rows = [
        [
            format_risk_level(record.risk_level),
            record.name,
            _format_record_path(record, export_full_paths),
            record.extension,
            record.size,
            format_size(record.size),
            format_datetime(record.modified_at),
            format_risk_reasons(record.risk_reasons),
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


def _build_html_report(result: ScanResult, export_full_paths: bool, modified_time_months: int) -> str:
    summary = result.summary
    type_items = build_file_type_distribution(result.records)
    risk_items = build_risk_distribution(summary.risk_counts)
    directory_items = build_directory_size_distribution(result.records, export_full_paths)
    extension_items = build_extension_distribution(result.records)
    size_items = build_size_distribution(result.records)
    risk_reason_items = build_risk_reason_distribution(result.records)
    risk_directory_items = build_risk_directory_distribution(result.records, export_full_paths)
    skip_reason_items = build_skip_reason_distribution(summary.skip_reasons)
    error_directory_items = build_error_directory_distribution(result.errors, export_full_paths)
    duplicate_extension_items = build_duplicate_extension_distribution(result.duplicate_groups)
    modified_time_items = build_modified_time_distribution(result.records, modified_time_months)
    generated_at = format_datetime(datetime.now())
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
    {_card("总大小", format_size(summary.total_size))}
    {_card("重复文件", f"{summary.duplicate_files:,}")}
    {_card("可疑文件", f"{summary.risk_files:,}")}
    {_card("扫描错误", f"{summary.error_count:,}")}
    {_card("已跳过", f"{summary.skipped_files + summary.skipped_dirs:,}")}
  </section>
  <section class="grid">
    {_chart_panel("文件类型分布", type_items, "#2f80ed")}
    {_chart_panel("风险等级分布", risk_items, "#f97316")}
    {_chart_panel("目录占用 Top 10", directory_items, "#22c55e", format_size, wide=True)}
    {_chart_panel("扩展名 Top 10", extension_items, "#a855f7")}
    {_chart_panel("文件大小分布", size_items, "#06b6d4")}
    {_chart_panel("风险原因 Top 10", risk_reason_items, "#ef4444")}
    {_chart_panel("风险目录 Top 10", risk_directory_items, "#f43f5e")}
    {_chart_panel("跳过原因", skip_reason_items, "#f59e0b")}
    {_chart_panel("扫描错误目录 Top 10", error_directory_items, "#f97316")}
    {_chart_panel("重复扩展名 Top 10", duplicate_extension_items, "#c084fc")}
    {_chart_panel("修改时间分布", modified_time_items, "#84cc16")}
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
    records.sort(key=lambda record: risk_sort_key(record.risk_level))
    records = records[:30]
    if not records:
        return '<div class="muted">暂无高风险或中风险文件。</div>'
    rows = []
    for record in records:
        rows.append(
            "<tr>"
            f"<td>{_escape(format_risk_level(record.risk_level))}</td>"
            f"<td>{_escape(record.name)}</td>"
            f'<td class="path">{_escape(_format_record_path(record, export_full_paths))}</td>'
            f"<td>{_escape(format_size(record.size))}</td>"
            f"<td>{_escape(format_risk_reasons(record.risk_reasons))}</td>"
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


def _format_record_path(record, export_full_paths: bool) -> str:
    return str(record.path) if export_full_paths else record.name


def _path_header(export_full_paths: bool) -> str:
    return "完整路径" if export_full_paths else "路径信息"


def _escape(value: str) -> str:
    return html.escape(str(value), quote=True)
