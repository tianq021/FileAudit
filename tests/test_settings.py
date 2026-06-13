import tempfile
import unittest
from pathlib import Path

from fileaudit.config.settings import SETTINGS_PATH, AppSettings, load_settings, save_settings, settings_path_label


class SettingsTests(unittest.TestCase):
    def test_default_settings_path_is_project_local(self):
        project_root = Path(__file__).resolve().parents[1]

        self.assertEqual(SETTINGS_PATH, project_root / "settings.json")

    def test_settings_path_label_uses_project_relative_path(self):
        self.assertEqual(settings_path_label(), "settings.json")

    def test_save_and_load_settings_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            settings_path = Path(temp_dir) / "settings.json"
            save_settings(AppSettings(include_only_matched=True, include_extensions=[".log"]), settings_path)

            settings = load_settings(settings_path)

            self.assertTrue(settings.include_only_matched)
            self.assertEqual(settings.include_extensions, [".log"])


if __name__ == "__main__":
    unittest.main()
