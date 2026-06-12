import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from fileaudit.config import default_settings
from fileaudit.core.scanner import _format_scan_error, scan_directory
from fileaudit.models import DEFAULT_SKIP_DIRS, ScanError, ScanOptions, ScanResult
from fileaudit.reports.exporter import export_report_bundle


class ScannerTests(unittest.TestCase):
    def test_detects_empty_suspicious_double_extension_and_long_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            empty_file = root / "empty.txt"
            script_file = root / "run.ps1"
            double_extension_file = root / "invoice.pdf.exe"
            long_path_file = root / "very_long_file_name.txt"
            empty_file.write_text("", encoding="utf-8")
            script_file.write_text("Write-Host test", encoding="utf-8")
            double_extension_file.write_text("binary", encoding="utf-8")
            long_path_file.write_text("long", encoding="utf-8")

            result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    path_length_threshold=5,
                    suspicious_extensions=(".ps1", ".exe"),
                )
            )

            by_name = {record.name: record for record in result.records}
            self.assertIn("empty file", by_name["empty.txt"].risk_reasons)
            self.assertIn("suspicious extension", by_name["run.ps1"].risk_reasons)
            self.assertIn("script file", by_name["run.ps1"].risk_reasons)
            self.assertEqual(by_name["run.ps1"].risk_level, "medium")
            self.assertIn("double extension", by_name["invoice.pdf.exe"].risk_reasons)
            self.assertEqual(by_name["invoice.pdf.exe"].risk_level, "high")
            self.assertIn("long path", by_name["very_long_file_name.txt"].risk_reasons)

    def test_marks_no_extension_big_file_and_temporary_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            no_extension_big_file = root / "blob"
            temp_file = root / "cache.tmp"
            no_extension_big_file.write_bytes(b"x" * 1024 * 1024)
            temp_file.write_text("temp", encoding="utf-8")

            result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    big_file_threshold_mb=1,
                )
            )

            by_name = {record.name: record for record in result.records}
            self.assertIn("large file without extension", by_name["blob"].risk_reasons)
            self.assertEqual(by_name["blob"].risk_level, "medium")
            self.assertIn("temporary file", by_name["cache.tmp"].risk_reasons)
            self.assertEqual(by_name["cache.tmp"].risk_level, "low")

    def test_versioned_library_names_are_not_double_extension_spoofs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            library_file = root / "libglib-2.0-0.dll"
            namespaced_exe = root / "CNCMaps.Renderer.exe"
            library_file.write_text("library", encoding="utf-8")
            namespaced_exe.write_text("program", encoding="utf-8")

            result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    suspicious_extensions=(".dll", ".exe"),
                )
            )

            by_name = {record.name: record for record in result.records}
            self.assertNotIn("double extension", by_name["libglib-2.0-0.dll"].risk_reasons)
            self.assertNotIn("double extension", by_name["CNCMaps.Renderer.exe"].risk_reasons)
            self.assertEqual(by_name["libglib-2.0-0.dll"].risk_level, "low")
            self.assertEqual(by_name["CNCMaps.Renderer.exe"].risk_level, "low")

    def test_whitelisted_extension_is_not_flagged_by_extension(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            setup_file = root / "setup.exe"
            setup_file.write_text("installer", encoding="utf-8")

            result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    suspicious_extensions=(".exe",),
                    whitelisted_extensions=(".exe",),
                )
            )

            self.assertEqual(result.records[0].risk_level, "normal")
            self.assertNotIn("suspicious extension", result.records[0].risk_reasons)

    def test_finds_duplicate_files_by_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "a.txt").write_text("same content", encoding="utf-8")
            (root / "b.txt").write_text("same content", encoding="utf-8")
            (root / "c.txt").write_text("different", encoding="utf-8")

            result = scan_directory(ScanOptions(root_path=root))

            self.assertEqual(result.summary.duplicate_groups, 1)
            self.assertEqual(result.summary.duplicate_files, 2)

    def test_ignored_dirs_and_privacy_skip_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ignored_dir = root / "node_modules"
            keyword_dir = root / "Chrome" / "User Data"
            ignored_dir.mkdir()
            keyword_dir.mkdir(parents=True)
            (ignored_dir / "ignored.exe").write_text("ignored", encoding="utf-8")
            (keyword_dir / "secret.txt").write_text("secret", encoding="utf-8")
            (root / "secret.pem").write_text("key", encoding="utf-8")
            (root / "huge.bin").write_bytes(b"x" * 8)
            (root / "visible.txt").write_text("visible", encoding="utf-8")

            result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    ignored_dirs=("node_modules",),
                    skip_extensions=(".pem",),
                    skip_large_files_mb=1,
                    skip_path_keywords=("Chrome\\User Data",),
                )
            )

            scanned_names = {record.name for record in result.records}
            self.assertEqual(scanned_names, {"huge.bin", "visible.txt"})
            self.assertEqual(result.summary.skipped_files, 1)
            self.assertGreaterEqual(result.summary.skipped_dirs, 1)
            self.assertEqual(result.summary.skip_reasons["skip extension"], 1)
            self.assertEqual(result.summary.skip_reasons["skip dir name"], 1)

    def test_protected_windows_dirs_are_skipped_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            protected_dir = root / "System Volume Information"
            protected_dir.mkdir()
            (protected_dir / "metadata.dat").write_text("secret", encoding="utf-8")
            (root / "normal.txt").write_text("normal", encoding="utf-8")

            result = scan_directory(ScanOptions(root_path=root, calculate_hash=False))

            self.assertIn("System Volume Information", DEFAULT_SKIP_DIRS)
            self.assertIn("System Volume Information", default_settings().skip_dirs)
            self.assertEqual({record.name for record in result.records}, {"normal.txt"})
            self.assertEqual(result.summary.skip_reasons["skip dir name"], 1)

    def test_permission_errors_are_displayed_as_friendly_messages(self):
        message = _format_scan_error(PermissionError(13, "Access is denied"))

        self.assertIn("无权限访问", message)
        self.assertIn("跳过目录", message)

    def test_include_only_rules_filter_by_extension_keyword_and_type(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "setup.exe").write_text("exe", encoding="utf-8")
            (root / "notes.txt").write_text("notes", encoding="utf-8")
            (root / "photo.jpg").write_text("jpg", encoding="utf-8")
            (root / "backup.bin").write_text("backup", encoding="utf-8")
            nested = root / "Downloads"
            nested.mkdir()
            (nested / "archive.bin").write_text("archive", encoding="utf-8")

            result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    include_only_matched=True,
                    include_extensions=(".exe",),
                    include_name_keywords=("backup",),
                    include_path_keywords=("Downloads",),
                    include_file_types=("图片",),
                )
            )

            scanned_names = {record.name for record in result.records}
            self.assertEqual(scanned_names, {"setup.exe", "photo.jpg", "backup.bin", "archive.bin"})
            self.assertEqual(result.summary.skip_reasons["skip include unmatched"], 1)

    def test_include_conflict_policy_controls_file_level_skip_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            key_file = root / "secret.pem"
            key_file.write_text("secret", encoding="utf-8")

            skip_wins_result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    skip_extensions=(".pem",),
                    include_only_matched=True,
                    include_extensions=(".pem",),
                    include_conflict_policy="skip_wins",
                )
            )
            include_wins_result = scan_directory(
                ScanOptions(
                    root_path=root,
                    calculate_hash=False,
                    skip_extensions=(".pem",),
                    include_only_matched=True,
                    include_extensions=(".pem",),
                    include_conflict_policy="include_wins",
                )
            )

            self.assertEqual(len(skip_wins_result.records), 0)
            self.assertEqual(skip_wins_result.summary.skip_reasons["skip extension"], 1)
            self.assertEqual({record.name for record in include_wins_result.records}, {"secret.pem"})

    def test_detects_future_modified_time(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            future_file = root / "future.txt"
            future_file.write_text("future", encoding="utf-8")
            future_time = time.time() + 3600
            os.utime(future_file, (future_time, future_time))

            result = scan_directory(ScanOptions(root_path=root, calculate_hash=False))

            self.assertIn("time anomaly", result.records[0].risk_reasons)

    def test_export_can_omit_full_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "private.txt").write_text("private", encoding="utf-8")
            result = scan_directory(ScanOptions(root_path=root, calculate_hash=False))

            output_dir = root / "report"
            export_report_bundle(result, output_dir, export_full_paths=False)

            files_csv = (output_dir / "files.csv").read_text(encoding="utf-8-sig")
            report_html = (output_dir / "report.html").read_text(encoding="utf-8")
            self.assertIn("private.txt", files_csv)
            self.assertNotIn(str(root), files_csv)
            self.assertNotIn(str(root), report_html)
            self.assertIn("修改时间分布", report_html)

    def test_export_includes_scan_error_details(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "ok.txt").write_text("ok", encoding="utf-8")
            result = scan_directory(ScanOptions(root_path=root, calculate_hash=False))
            error_path = root / "locked.txt"
            result = ScanResult(
                records=result.records,
                duplicate_groups=result.duplicate_groups,
                errors=[ScanError(error_path, "Permission denied")],
                summary=replace(result.summary, error_count=1),
            )

            output_dir = root / "report"
            export_report_bundle(result, output_dir)

            errors_csv = (output_dir / "errors.csv").read_text(encoding="utf-8-sig")
            report_html = (output_dir / "report.html").read_text(encoding="utf-8")
            self.assertIn("locked.txt", errors_csv)
            self.assertIn("Permission denied", errors_csv)
            self.assertIn("扫描错误预览", report_html)
            self.assertIn("Permission denied", report_html)

    def test_default_modified_time_month_setting_is_three(self):
        self.assertEqual(default_settings().modified_time_months, 3)


if __name__ == "__main__":
    unittest.main()
