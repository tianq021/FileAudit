import unittest

from fileaudit.config.validation import validate_detection_skip_conflicts


class UiSettingsTests(unittest.TestCase):
    def test_rejects_hidden_detection_skip_conflict(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_hidden_files=True,
                skip_hidden_files=True,
                detect_big_files=False,
                big_file_threshold_mb=50,
                skip_large_files_mb=0,
            )

        self.assertIn("检测隐藏文件", str(context.exception))
        self.assertIn("跳过隐藏文件", str(context.exception))

    def test_rejects_big_file_detection_skip_threshold_conflict(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_hidden_files=False,
                skip_hidden_files=False,
                detect_big_files=True,
                big_file_threshold_mb=50,
                skip_large_files_mb=50,
            )

        self.assertIn("跳过大文件阈值", str(context.exception))
        self.assertIn("大文件阈值", str(context.exception))

    def test_allows_partial_big_file_detection_window(self):
        validate_detection_skip_conflicts(
            detect_hidden_files=False,
            skip_hidden_files=False,
            detect_big_files=True,
            big_file_threshold_mb=50,
            skip_large_files_mb=200,
        )

    def test_rejects_whitelisted_suspicious_extension_overlap(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_suspicious_extensions=True,
                detect_hidden_files=False,
                skip_hidden_files=False,
                detect_big_files=False,
                big_file_threshold_mb=50,
                skip_large_files_mb=0,
                suspicious_extensions=(".exe", ".ps1"),
                whitelisted_extensions=(".exe",),
            )

        self.assertIn("白名单扩展名", str(context.exception))
        self.assertIn(".exe", str(context.exception))

    def test_rejects_skipped_suspicious_extension_overlap(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_double_extensions=True,
                detect_hidden_files=False,
                skip_hidden_files=False,
                detect_big_files=False,
                big_file_threshold_mb=50,
                skip_large_files_mb=0,
                suspicious_extensions=(".scr",),
                skip_extensions=(".scr",),
            )

        self.assertIn("跳过扩展名", str(context.exception))
        self.assertIn(".scr", str(context.exception))

    def test_rejects_include_only_without_rules(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_hidden_files=False,
                skip_hidden_files=False,
                detect_big_files=False,
                big_file_threshold_mb=50,
                skip_large_files_mb=0,
                include_only_matched=True,
            )

        self.assertIn("只扫描匹配规则", str(context.exception))

    def test_rejects_include_extension_overlapped_with_skip_extension(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_hidden_files=False,
                skip_hidden_files=False,
                detect_big_files=False,
                big_file_threshold_mb=50,
                skip_large_files_mb=0,
                include_only_matched=True,
                include_extensions=(".log", ".pdf"),
                skip_extensions=(".log",),
            )

        self.assertIn(".log", str(context.exception))

    def test_rejects_include_path_inside_skipped_directory(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_hidden_files=False,
                skip_hidden_files=False,
                detect_big_files=False,
                big_file_threshold_mb=50,
                skip_large_files_mb=0,
                ignored_dirs=("node_modules",),
                include_only_matched=True,
                include_path_keywords=("node_modules",),
            )

        self.assertIn("目录跳过规则", str(context.exception))
        self.assertIn("node_modules", str(context.exception))

    def test_rejects_include_path_overlapped_with_skip_path_keyword(self):
        with self.assertRaises(ValueError) as context:
            validate_detection_skip_conflicts(
                detect_hidden_files=False,
                skip_hidden_files=False,
                detect_big_files=False,
                big_file_threshold_mb=50,
                skip_large_files_mb=0,
                skip_path_keywords=("Chrome\\User Data",),
                include_only_matched=True,
                include_path_keywords=("User Data",),
            )

        self.assertIn("跳过路径关键词", str(context.exception))
        self.assertIn("user data", str(context.exception))


if __name__ == "__main__":
    unittest.main()
