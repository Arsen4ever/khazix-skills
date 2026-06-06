import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load_module(
    "storage_server",
    ROOT / "storage-analyzer" / "scripts" / "server.py",
)
build_report = load_module(
    "storage_build_report",
    ROOT / "storage-analyzer" / "scripts" / "build_report.py",
)


class InlineJsonTests(unittest.TestCase):
    def test_script_closing_sequence_is_escaped(self):
        payload = {"name": "</script><script>alert(1)</script>&"}
        for serializer in (
            server.safe_json_for_inline_script,
            build_report.safe_json_for_inline_script,
        ):
            encoded = serializer(payload)
            self.assertNotIn("</script>", encoded.lower())
            self.assertIn("\\u003c", encoded)
            self.assertIn("\\u0026", encoded)


class StorageAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.safe_cache = os.path.expanduser("~/Library/Caches/khazix-hardening-test")
        self.protected = os.path.expanduser("~/.ssh")
        self.analysis = {
            "system": {"os": "macOS"},
            "green": [
                {
                    "name": "safe cache",
                    "trash_paths": [self.safe_cache, self.protected],
                }
            ],
            "yellow": [],
            "red": [],
        }

    def write_analysis(self, directory):
        path = Path(directory) / "analysis.json"
        path.write_text(json.dumps(self.analysis), encoding="utf-8")
        return path

    def test_permanent_delete_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_analysis(directory)
            _, _, rm_allow, trash_allow, _ = server.load(path)
        self.assertEqual(rm_allow, set())
        self.assertIn(os.path.realpath(self.safe_cache), trash_allow)
        self.assertNotIn(os.path.realpath(self.protected), trash_allow)
        self.assertTrue(server.is_protected("~/.Trash"))
        self.assertTrue(server.is_protected("~/unexpected-top-level-file"))

    def test_permanent_delete_only_allows_known_cache_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_analysis(directory)
            _, _, rm_allow, _, _ = server.load(path, allow_permanent_delete=True)
        self.assertIn(os.path.realpath(self.safe_cache), rm_allow)
        self.assertNotIn(os.path.realpath(self.protected), rm_allow)
        self.assertFalse(server.can_permanently_delete("~/Documents/example"))
        self.assertFalse(server.can_permanently_delete("~/Library/Caches"))


if __name__ == "__main__":
    unittest.main()
