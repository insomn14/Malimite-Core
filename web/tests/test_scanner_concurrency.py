"""
Concurrency and rate-limiting guards for full scans (POST /scans).

Before this, scanner.create_scan()/_run() had NO limit at all: every upload spawned its own
Ghidra/JADX subprocess immediately, so a burst of parallel uploads (e.g. several teams' CI
pipelines firing at once) could spawn unbounded parallel subprocesses, each with its own JVM
heap — the single biggest way to OOM the host. This module tests the two guards added to close
that gap: a bounded semaphore around subprocess spawn (max_concurrent_scans) and a sliding-window
limiter on scan starts (scan_rate_per_min), independent of the existing chat_rate_per_min (which
only guards LLM spend, not raw scan volume).
"""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from web.app import scanner
from web.app.config import settings


class ConcurrencyLimitTests(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        scanner._scan_sems.clear()  # fresh semaphore per test (one per event loop, cleared on new loop)

    async def test_at_most_max_concurrent_scans_run_their_subprocess_simultaneously(self):
        """3 scans queued with max_concurrent_scans=2: at any instant, at most 2 are 'running'."""
        gate = asyncio.Event()
        concurrent_count = 0
        peak_concurrent = 0

        async def fake_create_subprocess_exec(*args, **kwargs):
            nonlocal concurrent_count, peak_concurrent
            concurrent_count += 1
            peak_concurrent = max(peak_concurrent, concurrent_count)
            await gate.wait()
            concurrent_count -= 1
            proc = AsyncMock()
            proc.wait = AsyncMock(return_value=0)
            return proc

        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner.settings, "max_concurrent_scans", 2), \
             patch.object(scanner.settings, "scan_rate_per_min", 0), \
             patch("asyncio.create_subprocess_exec", fake_create_subprocess_exec), \
             patch.object(scanner, "_cli_cmd", return_value=["true"]):
            metas = [await scanner.create_scan(b"PK\x03\x04", f"a{i}.apk", False, "none", "summarize", "")
                     for i in range(3)]
            # Give the 3 background _run() tasks a moment to reach their subprocess call.
            await asyncio.sleep(0.05)
            self.assertEqual(peak_concurrent, 2, "a 3rd scan must wait for a free slot, not run immediately")
            gate.set()
            # Let everything drain.
            await asyncio.sleep(0.05)

        for m in metas:
            self.assertEqual(m.state, "queued")  # the ScanMeta returned by create_scan is a snapshot

    async def test_queued_scan_state_is_queued_not_running_while_waiting_for_a_slot(self):
        """A scan blocked behind the concurrency limit must read back as 'queued', not 'running' —
        it hasn't actually started its Ghidra/JADX subprocess yet."""
        gate = asyncio.Event()

        async def fake_create_subprocess_exec(*args, **kwargs):
            await gate.wait()
            proc = AsyncMock()
            proc.wait = AsyncMock(return_value=0)
            return proc

        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner.settings, "max_concurrent_scans", 1), \
             patch.object(scanner.settings, "scan_rate_per_min", 0), \
             patch("asyncio.create_subprocess_exec", fake_create_subprocess_exec), \
             patch.object(scanner, "_cli_cmd", return_value=["true"]):
            first = await scanner.create_scan(b"PK\x03\x04", "a.apk", False, "none", "summarize", "")
            second = await scanner.create_scan(b"PK\x03\x04", "b.apk", False, "none", "summarize", "")
            await asyncio.sleep(0.05)

            first_detail = scanner.get_scan_detail(first.scan_id)
            second_detail = scanner.get_scan_detail(second.scan_id)
            self.assertEqual(first_detail.state, "running")
            self.assertEqual(second_detail.state, "queued", "blocked by the concurrency limit, not started")

            gate.set()
            await asyncio.sleep(0.1)

    async def test_default_concurrency_is_not_accidentally_unlimited(self):
        self.assertGreaterEqual(settings.max_concurrent_scans, 1)
        self.assertLess(settings.max_concurrent_scans, 50, "sanity bound — this is per-host, not per-cluster")


class ScanRateLimitTests(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        scanner._SCAN_START_HITS.clear()

    async def test_allows_scans_under_the_limit(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner.settings, "scan_rate_per_min", 5), \
             patch.object(scanner, "_run", AsyncMock()):
            for i in range(5):
                await scanner.create_scan(b"PK\x03\x04", f"a{i}.apk", False, "none", "summarize", "")
            # no exception raised

    async def test_raises_429_once_the_limit_is_exceeded(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner.settings, "scan_rate_per_min", 2), \
             patch.object(scanner, "_run", AsyncMock()):
            await scanner.create_scan(b"PK\x03\x04", "a.apk", False, "none", "summarize", "")
            await scanner.create_scan(b"PK\x03\x04", "b.apk", False, "none", "summarize", "")
            with self.assertRaises(HTTPException) as cm:
                await scanner.create_scan(b"PK\x03\x04", "c.apk", False, "none", "summarize", "")
        self.assertEqual(cm.exception.status_code, 429)
        self.assertIn("Retry-After", cm.exception.headers)

    async def test_zero_disables_the_rate_limit(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner.settings, "scan_rate_per_min", 0), \
             patch.object(scanner, "_run", AsyncMock()):
            for i in range(20):
                await scanner.create_scan(b"PK\x03\x04", f"a{i}.apk", False, "none", "summarize", "")
            # no exception raised even well past a typical limit

    async def test_old_hits_roll_off_the_sliding_window(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(scanner.settings, "scan_dir", Path(d)), \
             patch.object(scanner.settings, "scan_rate_per_min", 1), \
             patch.object(scanner, "_run", AsyncMock()):
            await scanner.create_scan(b"PK\x03\x04", "a.apk", False, "none", "summarize", "")
            with self.assertRaises(HTTPException):
                await scanner.create_scan(b"PK\x03\x04", "b.apk", False, "none", "summarize", "")
            # Simulate 61 real seconds passing by backdating the recorded hit directly —
            # sleeping 61s in a test would be wasteful.
            scanner._SCAN_START_HITS[0] -= 61
            await scanner.create_scan(b"PK\x03\x04", "c.apk", False, "none", "summarize", "")
            # no exception raised — the old hit rolled off


if __name__ == "__main__":
    unittest.main()
