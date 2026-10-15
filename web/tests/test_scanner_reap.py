import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web.app import scanner


class ReapStaleRunningScansTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scan_root = Path(self.tmp.name) / "malimite-scans"
        self.scan_root.mkdir(parents=True)
        self._scan_dir_patch = patch.object(scanner.settings, "scan_dir", self.scan_root)
        self._scan_dir_patch.start()

    def tearDown(self):
        self._scan_dir_patch.stop()
        self.tmp.cleanup()

    def _make_scan(self, scan_id: str, state: str) -> Path:
        d = self.scan_root / scan_id
        d.mkdir()
        (d / "meta.json").write_text(json.dumps({
            "scan_id": scan_id, "filename": "a.ipa", "state": state,
            "created_at": "t", "started_at": "t" if state != "queued" else None,
            "finished_at": None, "exit_code": None,
        }))
        return d

    def test_running_and_queued_scans_are_marked_errored(self):
        self._make_scan("s-running", "running")
        self._make_scan("s-queued", "queued")
        self._make_scan("s-done", "done")

        reaped = scanner.reap_stale_running_scans()

        self.assertEqual(reaped, 2)
        self.assertEqual(scanner._read_meta("s-running")["state"], "error")
        self.assertEqual(scanner._read_meta("s-running")["exit_code"], -1)
        self.assertIsNotNone(scanner._read_meta("s-running")["finished_at"])
        self.assertEqual(scanner._read_meta("s-queued")["state"], "error")
        self.assertEqual(scanner._read_meta("s-done")["state"], "done")  # untouched

    def test_is_idempotent_on_repeated_startups(self):
        self._make_scan("s-running", "running")
        scanner.reap_stale_running_scans()
        second_pass = scanner.reap_stale_running_scans()
        self.assertEqual(second_pass, 0)

    def test_appends_a_note_to_analysis_log_when_present(self):
        d = self._make_scan("s-running", "running")
        (d / "analysis.log").write_text("[ghidra-output] still going\n")

        scanner.reap_stale_running_scans()

        self.assertIn("scan interrupted", (d / "analysis.log").read_text())


if __name__ == "__main__":
    unittest.main()
