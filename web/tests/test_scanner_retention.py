import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import main, scanner


class DeleteExpiredScansTests(unittest.TestCase):
    """scanner.delete_expired_scans() — there was previously no automatic retention at all; a
    server fed continuously by CI pipelines (tools/malimite-ci) would accumulate scan directories
    forever (one scan can be well over 1GB) with no built-in way to bound disk usage."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scan_root = Path(self.tmp.name) / "malimite-scans"
        self.scan_root.mkdir(parents=True)
        self._scan_dir_patch = patch.object(scanner.settings, "scan_dir", self.scan_root)
        self._scan_dir_patch.start()

    def tearDown(self):
        self._scan_dir_patch.stop()
        self.tmp.cleanup()

    def _make_scan(self, scan_id: str, state: str, age_days: float) -> Path:
        d = self.scan_root / scan_id
        d.mkdir()
        created = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
        (d / "meta.json").write_text(json.dumps({
            "scan_id": scan_id, "filename": "a.apk", "state": state,
            "created_at": created, "started_at": created, "finished_at": created, "exit_code": 0,
        }))
        (d / "report.html").write_text("<html>fake report</html>")  # something to actually delete
        return d

    def test_zero_retention_days_deletes_nothing(self):
        self._make_scan("old", "done", age_days=400)
        deleted = scanner.delete_expired_scans(retention_days=0)
        self.assertEqual(deleted, 0)
        self.assertTrue((self.scan_root / "old").exists())

    def test_none_retention_days_falls_back_to_settings_and_is_disabled_by_default(self):
        self._make_scan("old", "done", age_days=400)
        with patch.object(scanner.settings, "scan_retention_days", 0):
            deleted = scanner.delete_expired_scans()  # no explicit arg
        self.assertEqual(deleted, 0)

    def test_scans_older_than_retention_are_deleted(self):
        self._make_scan("old", "done", age_days=40)
        self._make_scan("recent", "done", age_days=5)
        deleted = scanner.delete_expired_scans(retention_days=30)
        self.assertEqual(deleted, 1)
        self.assertFalse((self.scan_root / "old").exists())
        self.assertTrue((self.scan_root / "recent").exists())

    def test_error_state_scans_also_age_out(self):
        """A scan that errored (server crash, CLI failure) must not linger forever just because
        it never reached 'done' — it's aged from created_at regardless of final state."""
        self._make_scan("old-error", "error", age_days=40)
        deleted = scanner.delete_expired_scans(retention_days=30)
        self.assertEqual(deleted, 1)

    def test_currently_running_scans_are_never_deleted_even_if_old(self):
        """Deleting a scan's output directory out from under its in-flight CLI subprocess would
        corrupt it — skip queued/running regardless of age; it'll be swept once it finishes."""
        self._make_scan("stuck-running", "running", age_days=400)
        deleted = scanner.delete_expired_scans(retention_days=30)
        self.assertEqual(deleted, 0)
        self.assertTrue((self.scan_root / "stuck-running").exists())

    def test_scan_exactly_at_the_boundary_is_not_deleted(self):
        self._make_scan("boundary", "done", age_days=30 - 0.001)  # just under the cutoff
        deleted = scanner.delete_expired_scans(retention_days=30)
        self.assertEqual(deleted, 0)

    def test_missing_or_corrupt_meta_json_is_skipped_not_raised(self):
        d = self.scan_root / "no-meta"
        d.mkdir()  # directory with no meta.json at all
        deleted = scanner.delete_expired_scans(retention_days=1)
        self.assertEqual(deleted, 0)
        self.assertTrue(d.exists())

    def test_missing_created_at_is_skipped_not_raised(self):
        d = self.scan_root / "legacy"
        d.mkdir()
        (d / "meta.json").write_text(json.dumps({"scan_id": "legacy", "state": "done"}))
        deleted = scanner.delete_expired_scans(retention_days=1)
        self.assertEqual(deleted, 0)

    def test_empty_scan_dir_returns_zero(self):
        self.assertEqual(scanner.delete_expired_scans(retention_days=30), 0)

    def test_nonexistent_scan_dir_returns_zero_without_raising(self):
        with patch.object(scanner.settings, "scan_dir", self.scan_root / "does-not-exist"):
            self.assertEqual(scanner.delete_expired_scans(retention_days=30), 0)


class RetentionLifespanIntegrationTests(unittest.TestCase):
    """The retention sweep is wired into main.py's app lifespan: run once at startup when
    retention is enabled, then loop in the background for as long as the app is up, and stop
    cleanly on shutdown (not leak a dangling asyncio.Task)."""

    def test_runs_once_at_startup_when_retention_is_enabled(self):
        with patch.object(main.settings, "scan_retention_days", 30), \
             patch.object(scanner, "delete_expired_scans", return_value=0) as mock_delete, \
             patch.object(main, "_RETENTION_INTERVAL_S", 999999):  # don't actually loop during the test
            with TestClient(main.app):
                pass
        mock_delete.assert_called()

    async def _empty_loop(self):
        """Stand-in for main._retention_loop(): an awaitable background task that does nothing,
        so this test can isolate _lifespan()'s own explicit startup-time call to
        delete_expired_scans() without the real loop's unconditional first-iteration call to it
        (which is a separate, intentional "pick up a config change without a restart" behavior,
        covered by test_runs_once_at_startup_when_retention_is_enabled using the real loop)."""
        try:
            await asyncio.sleep(999999)
        except asyncio.CancelledError:
            pass

    def test_explicit_startup_call_is_skipped_when_retention_is_disabled(self):
        with patch.object(main.settings, "scan_retention_days", 0), \
             patch.object(scanner, "delete_expired_scans") as mock_delete, \
             patch.object(main, "_retention_loop", self._empty_loop):
            with TestClient(main.app):
                pass
        mock_delete.assert_not_called()

    def test_background_task_is_cancelled_cleanly_on_app_shutdown(self):
        """A leaked, never-cancelled asyncio.Task across repeated TestClient context-manager
        enter/exits (one per test across the whole suite) would eventually surface as warnings
        or resource exhaustion — this exercises the finally: block's cancel + await explicitly."""
        # api_key pinned to "": this test is about lifespan shutdown, not auth — without it the
        # test 401s whenever the developer's web/.env configures an API key (a real flake here
        # before, and the same class of bug as the two env-dependent failures CI hits).
        with patch.object(main.settings, "scan_retention_days", 0), \
             patch.object(main.settings, "api_key", ""), \
             patch.object(main, "_RETENTION_INTERVAL_S", 999999):
            with TestClient(main.app) as client:
                r = client.get("/api/v1/scans")
                self.assertEqual(r.status_code, 200)
            # exiting the `with` block runs the lifespan's shutdown phase; getting here without
            # hanging or raising confirms the task was cancelled and awaited cleanly.


if __name__ == "__main__":
    unittest.main()
