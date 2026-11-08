"""Tests for the outbound Slack notification when a scan finishes.

Two properties are load-bearing and asserted throughout:
  * it fires for ANY finished scan (Web UI upload, watcher, API, CI all share _run()), gated only
    by the configured severity threshold — never by how the scan was started;
  * it can never break a scan. Every failure path (no webhook, bad status, connection error,
    missing database) must be swallowed.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from web.app import notify


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class ThresholdTests(unittest.TestCase):
    """slack_notify_min_severity uses the same ladder as --fail-on, so operators learn one
    vocabulary. HIGH == critical/high only; LOW == any finding at all."""

    def test_high_threshold_alerts_on_critical_and_high(self):
        self.assertTrue(notify.should_notify({"CRITICAL": 1}, "HIGH", "done"))
        self.assertTrue(notify.should_notify({"HIGH": 2}, "HIGH", "done"))

    def test_high_threshold_stays_quiet_on_medium_and_below(self):
        self.assertFalse(notify.should_notify({"MEDIUM": 30}, "HIGH", "done"))
        self.assertFalse(notify.should_notify({"LOW": 5, "INFO": 40}, "HIGH", "done"))

    def test_medium_threshold_alerts_on_medium(self):
        self.assertTrue(notify.should_notify({"MEDIUM": 1}, "MEDIUM", "done"))
        self.assertFalse(notify.should_notify({"LOW": 1}, "MEDIUM", "done"))

    def test_low_threshold_alerts_on_info_only(self):
        self.assertTrue(notify.should_notify({"INFO": 1}, "LOW", "done"))

    def test_none_threshold_never_alerts_on_findings(self):
        self.assertFalse(notify.should_notify({"CRITICAL": 99}, "NONE", "done"))

    def test_clean_scan_never_alerts(self):
        self.assertFalse(notify.should_notify({}, "HIGH", "done"))
        self.assertFalse(notify.should_notify({"total": 0}, "LOW", "done"))

    def test_failed_scan_always_alerts_even_at_threshold_none(self):
        """A scan that died is worse than a noisy channel: there are no counts to reason about."""
        self.assertTrue(notify.should_notify({}, "NONE", "error"))
        self.assertTrue(notify.should_notify({}, "HIGH", "error"))

    def test_unknown_threshold_falls_back_to_high_instead_of_crashing(self):
        self.assertTrue(notify.should_notify({"HIGH": 1}, "BOGUS", "done"))
        self.assertFalse(notify.should_notify({"MEDIUM": 1}, "BOGUS", "done"))

    def test_threshold_is_case_and_space_insensitive(self):
        self.assertTrue(notify.should_notify({"HIGH": 1}, " high ", "done"))


class PayloadTests(unittest.TestCase):
    def test_payload_reports_counts_and_no_file(self):
        payload = notify.build_payload(
            "abcd1234-0000", "app-release.apk", "done",
            {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 3},
            executable="com.example.app", base_url="https://malimite.internal")
        text = str(payload)
        self.assertIn("3 findings detected", text)
        self.assertIn("app-release.apk", text)
        self.assertIn("com.example.app", text)
        self.assertIn("https://malimite.internal/#/scan/abcd1234-0000", text)
        # text-only by design: nothing that would imply an uploaded artifact
        self.assertNotIn("files", payload)
        for block in payload["blocks"]:
            self.assertNotIn(block.get("type"), ("file", "image"))

    def test_clean_scan_payload_says_no_findings(self):
        payload = notify.build_payload("s1", "a.apk", "done", {"total": 0})
        self.assertIn("No active findings", str(payload))

    def test_failed_scan_payload_says_failed(self):
        payload = notify.build_payload("s1", "a.apk", "error", {})
        self.assertIn("Scan failed", str(payload))

    def test_link_omitted_when_base_url_blank(self):
        """The server cannot reliably infer its own public URL behind a proxy, so it must not
        guess one — a wrong link is worse than no link."""
        payload = notify.build_payload("s1", "a.apk", "done", {"total": 0}, base_url="")
        self.assertNotIn("View report", str(payload))

    def test_long_filename_is_truncated_to_slacks_150_char_header_limit(self):
        """Slack rejects the entire message (not just truncates) when a header exceeds 150 chars,
        which would silently drop the alert this module exists to deliver."""
        payload = notify.build_payload("s1", "x" * 160 + ".apk", "done", {"total": 0})
        header = payload["blocks"][0]["text"]["text"]
        self.assertLessEqual(len(header), 150)


class PostTests(unittest.IsolatedAsyncioTestCase):
    async def test_successful_post_returns_true(self):
        seen = {}

        def handler(req):
            seen["url"] = str(req.url)
            seen["body"] = req.read().decode()
            return httpx.Response(200, text="ok")

        ok = await notify.post("https://hooks.slack.test/x", {"blocks": []}, client=_client(handler))
        self.assertTrue(ok)
        self.assertEqual(seen["url"], "https://hooks.slack.test/x")
        self.assertIn("blocks", seen["body"])

    async def test_rejected_status_returns_false_not_raises(self):
        ok = await notify.post("https://hooks.slack.test/x", {"blocks": []},
                               client=_client(lambda req: httpx.Response(400, text="invalid_blocks")))
        self.assertFalse(ok)

    async def test_connection_error_returns_false_not_raises(self):
        def handler(req):
            raise httpx.ConnectError("boom")

        ok = await notify.post("https://hooks.slack.test/x", {"blocks": []}, client=_client(handler))
        self.assertFalse(ok)


class NotifyScanFinishedTests(unittest.IsolatedAsyncioTestCase):
    async def test_does_nothing_when_no_webhook_configured(self):
        with patch.object(notify.settings, "slack_webhook_url", ""), \
             patch.object(notify, "post", AsyncMock()) as post:
            ok = await notify.notify_scan_finished("s1", "a.apk", "done", {"HIGH": 5})
        self.assertFalse(ok)
        post.assert_not_awaited()

    async def test_skips_when_threshold_not_met(self):
        with patch.object(notify.settings, "slack_webhook_url", "https://hooks.slack.test/x"), \
             patch.object(notify.settings, "slack_notify_min_severity", "HIGH"), \
             patch.object(notify, "post", AsyncMock(return_value=True)) as post:
            ok = await notify.notify_scan_finished("s1", "a.apk", "done", {"MEDIUM": 10})
        self.assertFalse(ok)
        post.assert_not_awaited()

    async def test_posts_when_threshold_met(self):
        with patch.object(notify.settings, "slack_webhook_url", "https://hooks.slack.test/x"), \
             patch.object(notify.settings, "slack_notify_min_severity", "HIGH"), \
             patch.object(notify.settings, "public_base_url", ""), \
             patch.object(notify, "post", AsyncMock(return_value=True)) as post:
            ok = await notify.notify_scan_finished("s1", "a.apk", "done", {"HIGH": 1})
        self.assertTrue(ok)
        post.assert_awaited_once()

    async def test_webhook_with_only_whitespace_counts_as_unconfigured(self):
        with patch.object(notify.settings, "slack_webhook_url", "   "), \
             patch.object(notify, "post", AsyncMock()) as post:
            ok = await notify.notify_scan_finished("s1", "a.apk", "done", {"HIGH": 5})
        self.assertFalse(ok)
        post.assert_not_awaited()


class ScheduleTests(unittest.IsolatedAsyncioTestCase):
    async def test_schedules_nothing_without_a_webhook(self):
        with patch.object(notify.settings, "slack_webhook_url", ""):
            notify.schedule_scan_finished("s1", "a.apk", "done", {"HIGH": 1})
        self.assertEqual(notify._NOTIFY_TASKS, set())

    async def test_schedules_a_background_task_and_discards_it_when_done(self):
        done = asyncio.Event()

        async def fake_notify(*a, **k):
            done.set()
            return True

        with patch.object(notify.settings, "slack_webhook_url", "https://hooks.slack.test/x"), \
             patch.object(notify, "notify_scan_finished", fake_notify):
            notify.schedule_scan_finished("s1", "a.apk", "done", {"HIGH": 1})
            self.assertEqual(len(notify._NOTIFY_TASKS), 1)
            await asyncio.wait_for(done.wait(), timeout=2)
        for _ in range(50):  # done-callback runs on the loop; give it a turn
            if not notify._NOTIFY_TASKS:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(notify._NOTIFY_TASKS, set())


class ScannerHookTests(unittest.IsolatedAsyncioTestCase):
    """The alert must be scheduled by scanner._run() itself — that is the single code path every
    scan takes (Web UI upload, watcher daemon, direct API call, malimite-ci), so hooking there is
    what makes "every finished scan alerts" true rather than aspirational."""

    async def _run_scan(self, exit_code: int):
        import tempfile
        from pathlib import Path
        from unittest.mock import MagicMock

        from web.app import scanner

        scanner._scan_sems.clear()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        out_dir = root / "s1"
        out_dir.mkdir()

        proc = AsyncMock()
        proc.wait = AsyncMock(return_value=exit_code)

        with patch.object(scanner.settings, "scan_dir", root), \
             patch.object(scanner.settings, "max_concurrent_scans", 1), \
             patch.object(scanner, "_cli_cmd", return_value=["true"]), \
             patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)), \
             patch.object(scanner.notify, "schedule_scan_finished") as schedule:
            meta = {"filename": "a.apk", "state": "queued", "llm_provider": "none"}
            await scanner._run("s1", root / "upload.apk", out_dir, meta)
        return schedule

    async def test_successful_scan_schedules_notification(self):
        schedule = await self._run_scan(exit_code=0)
        schedule.assert_called_once()
        scan_id, filename, state, _counts = schedule.call_args.args[:4]
        self.assertEqual((scan_id, filename, state), ("s1", "a.apk", "done"))

    async def test_failed_scan_also_schedules_notification(self):
        """A silent failure is worse than a noisy channel, so state=error must not skip the hook."""
        schedule = await self._run_scan(exit_code=1)
        schedule.assert_called_once()
        self.assertEqual(schedule.call_args.args[2], "error")

    async def test_notification_trouble_never_breaks_the_scan(self):
        """Even if computing counts explodes, the scan must still be recorded as finished."""
        import tempfile
        from pathlib import Path

        from web.app import scanner

        scanner._scan_sems.clear()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        out_dir = root / "s1"
        out_dir.mkdir()

        proc = AsyncMock()
        proc.wait = AsyncMock(return_value=0)

        with patch.object(scanner.settings, "scan_dir", root), \
             patch.object(scanner.settings, "max_concurrent_scans", 1), \
             patch.object(scanner, "_cli_cmd", return_value=["true"]), \
             patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)), \
             patch.object(scanner, "_counts_for_notification", AsyncMock(side_effect=RuntimeError("db on fire"))), \
             patch.object(scanner.notify, "schedule_scan_finished") as schedule:
            meta = {"filename": "a.apk", "state": "queued", "llm_provider": "none"}
            await scanner._run("s1", root / "upload.apk", out_dir, meta)

        self.assertEqual(meta["state"], "done")     # scan still completed normally
        self.assertEqual(meta["exit_code"], 0)
        schedule.assert_called_once()                # and the alert was still attempted


if __name__ == "__main__":
    unittest.main()
