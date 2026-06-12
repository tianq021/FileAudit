import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from fileaudit.models import DuplicateGroup, FileRecord, ScanError
from fileaudit.utils import (
    build_directory_size_distribution,
    build_duplicate_extension_distribution,
    build_duplicate_group_distribution,
    build_error_directory_distribution,
    build_file_type_distribution,
    build_modified_time_distribution,
    build_risk_distribution,
    build_risk_directory_distribution,
    classify_file_type,
    format_risk_actions,
    format_risk_explanations,
    format_risk_reasons,
    format_size,
    format_skip_reasons,
    risk_sort_key,
)


def make_record(path: str, size: int = 1, extension: str | None = None, risk_level: str = "normal", risk_reasons=None):
    file_path = Path(path)
    extension = file_path.suffix.lower() if extension is None else extension
    return FileRecord(
        path=file_path,
        name=file_path.name,
        parent=file_path.parent,
        extension=extension,
        size=size,
        created_at=datetime.now(),
        modified_at=datetime.now(),
        risk_level=risk_level,
        risk_reasons=list(risk_reasons or []),
    )


class UtilsTests(unittest.TestCase):
    def test_formats_common_display_values(self):
        self.assertEqual(format_size(1024), "1.0 KB")
        self.assertEqual(format_risk_reasons(["script file", "long path"]), "脚本文件，路径过长")
        self.assertIn("脚本文件可以批量执行命令", format_risk_explanations(["script file"]))
        self.assertIn("不要双击执行", format_risk_actions(["script file"]))
        self.assertEqual(format_skip_reasons({"skip extension": 2}), "扩展名 2")
        self.assertEqual(format_skip_reasons({"skip slow file": 1, "skip slow hash": 2}), "慢文件 1，慢 Hash 2")
        self.assertLess(risk_sort_key("high"), risk_sort_key("low"))

    def test_classifies_file_types_once_for_all_callers(self):
        self.assertEqual(classify_file_type(".pdf"), "文档")
        self.assertEqual(classify_file_type(".jpg"), "图片")
        self.assertEqual(classify_file_type(".py"), "代码")
        self.assertEqual(classify_file_type(".unknown"), "其他")

    def test_builds_shared_distributions(self):
        records = [
            make_record(r"C:\data\a.pdf", 10, risk_level="high", risk_reasons=["double extension"]),
            make_record(r"C:\data\b.jpg", 20, risk_level="low", risk_reasons=["big file"]),
            make_record(r"C:\private\c.bin", 30),
        ]
        duplicate_group = DuplicateGroup("hash", 10, [records[0], replace(records[0], name="copy.pdf")])

        self.assertEqual(build_file_type_distribution(records)[0], ("文档", 1))
        self.assertIn(("高风险", 1), build_risk_distribution({"high": 1, "low": 1}))
        self.assertIn((r"C:\data", 30), build_directory_size_distribution(records))
        self.assertIn(("data", 30), build_directory_size_distribution(records, export_full_paths=False))
        self.assertEqual(build_duplicate_group_distribution([duplicate_group]), [("第 1 组（2 个）", 10)])
        self.assertEqual(build_duplicate_extension_distribution([duplicate_group]), [(".pdf", 2)])
        self.assertIn((r"C:\data", 2), build_risk_directory_distribution(records))
        self.assertIn(("data", 2), build_risk_directory_distribution(records, export_full_paths=False))

    def test_builds_error_directory_distribution(self):
        errors = [
            ScanError(Path(r"C:\System Volume Information\a.dat"), "无权限访问"),
            ScanError(Path(r"C:\System Volume Information\b.dat"), "无权限访问"),
            ScanError(Path(r"C:\Other\c.dat"), "其他错误"),
        ]

        self.assertEqual(build_error_directory_distribution(errors)[0], (r"C:\System Volume Information", 2))
        self.assertEqual(build_error_directory_distribution(errors, export_full_paths=False)[0], ("System Volume Information", 2))

    def test_modified_time_distribution_marks_future_files(self):
        future = make_record("future.txt")
        future.modified_at = datetime.now() + timedelta(days=1)

        self.assertIn(("未来时间", 1), build_modified_time_distribution([future]))

    def test_modified_time_distribution_uses_configured_month_window(self):
        recent = make_record("recent.txt")
        older = make_record("older.txt")
        recent.modified_at = datetime.now() - timedelta(days=60)
        older.modified_at = datetime.now() - timedelta(days=150)

        items = build_modified_time_distribution([recent, older], recent_months=3)

        self.assertIn(("3 个月内", 1), items)
        self.assertIn(("更早", 1), items)


if __name__ == "__main__":
    unittest.main()
