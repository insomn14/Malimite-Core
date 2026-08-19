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
