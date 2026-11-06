import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

from qq_dump_db.cli import main
from qq_dump_db.i18n import _MESSAGES, get_language, set_language, tr
from qq_dump_db.services.keymap_writer import resolve_output_paths, write_key_map


class CliTests(unittest.TestCase):
    def test_help_is_localized_chinese(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--lang", "zh-CN", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("目标 QQ 号", stdout.getvalue())

    def test_help_is_localized_english(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--lang", "en-US", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("Target QQ account number", stdout.getvalue())
        self.assertNotIn("日文", stdout.getvalue())

    def test_version_does_not_start_windows_workflow(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("2.0.1", stdout.getvalue())

    def test_invalid_qq_returns_usage_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--qq", "abc"])
        self.assertEqual(code, 2)
        self.assertIn("CLI_USAGE", stderr.getvalue())

    def test_invalid_pid_returns_usage_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--qq", "10001", "--pid", "0"])
        self.assertEqual(code, 2)
        self.assertIn("CLI_USAGE", stderr.getvalue())

    def test_invalid_pid_equals_form_returns_usage_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--qq", "10001", "--pid=0"])
        self.assertEqual(code, 2)
        self.assertIn("CLI_USAGE", stderr.getvalue())

    def test_only_chinese_and_english_are_allowed(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--qq", "10001", "--lang", "ja-JP"])
        self.assertEqual(code, 2)
        self.assertIn("CLI_USAGE", stderr.getvalue())

    def test_non_windows_runtime_returns_platform_code(self):
        if os.name == "nt":
            self.skipTest("Windows host does not exercise platform rejection")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--qq", "10001", "--lang", "en-US"])
        self.assertEqual(code, 10)
        self.assertIn("PLATFORM_UNSUPPORTED", stderr.getvalue())


class I18nTests(unittest.TestCase):
    def tearDown(self):
        set_language("zh-CN")

    def test_messages_switch_language(self):
        set_language("en-US")
        self.assertIn("Completed", tr("exit.ok"))
        set_language("zh-CN")
        self.assertIn("处理完成", tr("exit.ok"))

    def test_chinese_and_english_catalogs_have_same_keys(self):
        self.assertEqual(set(_MESSAGES["zh-CN"]), set(_MESSAGES["en-US"]))

    def test_environment_language(self):
        old = os.environ.get("QQ_DUMP_DB_LANG")
        try:
            os.environ["QQ_DUMP_DB_LANG"] = "en-US"
            self.assertEqual(get_language("auto"), "en-US")
            os.environ["QQ_DUMP_DB_LANG"] = "ja-JP"
            self.assertEqual(get_language("auto"), "zh-CN")
        finally:
            if old is None:
                os.environ.pop("QQ_DUMP_DB_LANG", None)
            else:
                os.environ["QQ_DUMP_DB_LANG"] = old


class OutputTests(unittest.TestCase):
    def test_default_output_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            previous = os.getcwd()
            os.chdir(temp)
            try:
                class Args:
                    qq = "10001"
                    output_dir = None
                    output = None
                root, key_path = resolve_output_paths(Args())
                self.assertEqual(root, Path(temp) / "output" / "10001")
                self.assertEqual(key_path, root / "key_map.json")
            finally:
                os.chdir(previous)

    def test_relative_key_map_is_under_output_root_and_schema_v1(self):
        with tempfile.TemporaryDirectory() as temp:
            previous = os.getcwd()
            os.chdir(temp)
            try:
                class Args:
                    qq = "10001"
                    output_dir = "exports"
                    output = "keys.json"
                root, key_path = resolve_output_paths(Args())
                self.assertEqual(key_path, root / "keys.json")
                write_key_map(key_path, {"00" * 16: "11" * 32})
                import json
                payload = json.loads(key_path.read_text(encoding="utf-8"))
                self.assertEqual(payload["schema_version"], 1)
                self.assertTrue(payload["_generated"].endswith("Z"))
                self.assertEqual(payload["key_map"], {"00" * 16: "11" * 32})
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
