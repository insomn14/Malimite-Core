import unittest
from pathlib import Path
from unittest.mock import patch

from web.app import scanner


class CliCmdTests(unittest.TestCase):
    def test_full_scan_passes_llm_mode_without_llm(self):
        cmd = scanner._cli_cmd(
            Path("/tmp/upload.apk"),
            Path("/tmp/out"),
            {"llm_mode": "find_vulns", "llm_enabled": False, "llm_provider": "none"},
        )
        self.assertIn("--llm-mode", cmd)
        self.assertEqual(cmd[cmd.index("--llm-mode") + 1], "find_vulns")
        self.assertNotIn("--llm", cmd)

    def test_fast_scan_default_mode(self):
        cmd = scanner._cli_cmd(
            Path("/tmp/upload.apk"),
            Path("/tmp/out"),
            {"llm_enabled": False, "llm_provider": "none"},
        )
        self.assertEqual(cmd[cmd.index("--llm-mode") + 1], "summarize")

    def test_llm_enrichment_keeps_mode_and_provider(self):
        cmd = scanner._cli_cmd(
            Path("/tmp/upload.apk"),
            Path("/tmp/out"),
            {
                "llm_mode": "find_vulns",
                "llm_enabled": True,
                "llm_provider": "deepseek",
                "llm_model": "deepseek-v4-flash",
            },
        )
        self.assertIn("--llm", cmd)
        self.assertEqual(cmd[cmd.index("--llm-provider") + 1], "deepseek")
        self.assertEqual(cmd[cmd.index("--llm-mode") + 1], "find_vulns")
        self.assertEqual(cmd[cmd.index("--llm-model") + 1], "deepseek-v4-flash")

    @patch.object(scanner.settings, "cli_jar", "/opt/malimite-cli.jar")
    @patch.object(scanner.settings, "ghidra_home", "/opt/ghidra")
    def test_paths_come_from_settings(self):
        cmd = scanner._cli_cmd(
            Path("/tmp/upload.apk"),
            Path("/tmp/out"),
            {"llm_mode": "summarize"},
        )
        self.assertEqual(cmd[1], "-jar")
        self.assertEqual(cmd[2], "/opt/malimite-cli.jar")
        self.assertEqual(cmd[cmd.index("--ghidra") + 1], "/opt/ghidra")


class LlmEnvTests(unittest.TestCase):
    def test_provider_env_mapping(self):
        with patch.object(scanner.settings, "openai_api_key", "O"), \
             patch.object(scanner.settings, "deepseek_api_key", "D"), \
             patch.object(scanner.settings, "deepseek_base_url", "http://d"):
            self.assertEqual(scanner.llm_env("openai"), {"OPENAI_API_KEY": "O"})
            self.assertEqual(scanner.llm_env("openai", "per-req"), {"OPENAI_API_KEY": "per-req"})
            self.assertEqual(scanner.llm_env("deepseek"), {"DEEPSEEK_API_KEY": "D", "DEEPSEEK_BASE_URL": "http://d"})
            self.assertEqual(scanner.llm_env("none"), {})


class KeyHygieneTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._d = tempfile.TemporaryDirectory()
        self.root = Path(self._d.name)
        self._p = patch.object(scanner.settings, "scan_dir", self.root)
        self._p.start()

    def tearDown(self):
        self._p.stop()
        self._d.cleanup()

    def test_write_meta_never_persists_underscore_keys_but_keeps_them_in_memory(self):
        import json
        (self.root / "s1").mkdir()
        meta = {"scan_id": "s1", "state": "queued", "_llm_api_key": "sk-secret"}
        scanner._write_meta("s1", meta)
        on_disk = (self.root / "s1" / "meta.json").read_text()
        self.assertNotIn("sk-secret", on_disk)
        self.assertEqual(json.loads(on_disk), {"scan_id": "s1", "state": "queued"})
        self.assertEqual(meta["_llm_api_key"], "sk-secret")  # _run still needs it
        self.assertEqual(scanner.llm_env("openai", meta["_llm_api_key"]), {"OPENAI_API_KEY": "sk-secret"})

    def test_scrub_removes_legacy_keys_and_leaves_everything_else(self):
        import json
        for n, m in {"a": {"scan_id": "a", "_llm_api_key": "k1", "llm_model": "m"}, "b": {"scan_id": "b"}}.items():
            (self.root / n).mkdir()
            (self.root / n / "meta.json").write_text(json.dumps(m))
        (self.root / "c").mkdir()
        (self.root / "c" / "meta.json").write_text("{not json")
        (self.root / "stray.txt").write_text("x")
        self.assertEqual(scanner.scrub_stored_keys(), 1)
        self.assertEqual(json.loads((self.root / "a" / "meta.json").read_text()), {"scan_id": "a", "llm_model": "m"})
        self.assertEqual(scanner.scrub_stored_keys(), 0)  # idempotent
        self.assertEqual((self.root / "c" / "meta.json").read_text(), "{not json")  # untouched
