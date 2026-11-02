"""Tests for Auto Enhance (bulk AI Fix as a background job): web/app/auto_enhance.py and the
/api/v1/scans/{id}/auto-enhance endpoints."""
import asyncio
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from web.app import auto_enhance, db, finding_fix, main, scanner
from web.app.agent.llm import LlmCfg, LlmError
from web.app.models import ScanDetail


def _make_db(path: str, n: int = 3) -> list[int]:
    with sqlite3.connect(path) as conn:
        conn.execute(
            """CREATE TABLE Vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                RuleId TEXT, Title TEXT, Category TEXT, Severity TEXT, CvssScore REAL, Cwe TEXT,
                Description TEXT, AffectedType TEXT, AffectedName TEXT, Evidence TEXT,
                EvidenceLocation TEXT, PocSteps TEXT, Remediation TEXT, ReferenceUrl TEXT,
                ExecutableName TEXT, CreatedAt INTEGER)"""
        )
        ids = []
        for i in range(n):
            cur = conn.execute(
                """INSERT INTO Vulnerabilities
                   (RuleId, Title, Category, Severity, CvssScore, Cwe, Description, AffectedType,
                    AffectedName, Evidence, EvidenceLocation, PocSteps, Remediation, ReferenceUrl,
                    ExecutableName, CreatedAt)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (f"RULE-{i}", f"Finding {i}", "STORAGE", "HIGH", 7.5, "CWE-1",
                 f"Original description {i}", "STRING", "0x1", "ev", "0x1",
                 "1. step", "fix", "https://x", "App", 0),
            )
            ids.append(cur.lastrowid)
        conn.commit()
        return ids


CFG = LlmCfg(provider="ollama", model="llama3.1", api_key="", base_url="http://x")


class AutoEnhanceJobTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scan_dir = Path(self.tmp.name)
        self.db_path = str(self.scan_dir / "scan.sqlite")
        self.ids = _make_db(self.db_path)
        auto_enhance._JOBS.clear()
        auto_enhance._ACTIVE_BY_SCAN.clear()

    async def asyncTearDown(self):
        self.tmp.cleanup()

    async def _rows(self):
        return await db.get_vulnerabilities(self.db_path, "App")

    async def test_job_applies_all_and_regenerates_once(self):
        rows = await self._rows()
        regen = AsyncMock(return_value=True)
        fake = AsyncMock(return_value={"description": "AI text"})
        job = auto_enhance.create_job("s1", CFG, ["description"], rows)
        with patch.object(finding_fix, "fix_finding", fake):
            await auto_enhance.run_job(job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows,
                                       scan_dir=self.scan_dir, regenerate=regen)
        self.assertEqual(job["state"], "done")
        self.assertEqual((job["succeeded"], job["failed"], job["completed"]), (3, 0, 3))
        self.assertTrue(all(it["state"] == "applied" for it in job["items"]))
        regen.assert_awaited_once_with("s1")
        self.assertTrue(job["report_regenerated"])
        for r in await self._rows():
            self.assertEqual(r["effective_description"], "AI text")
            self.assertEqual(r["ai_fix_status"], "applied")
        # fields restriction is forwarded to the per-finding fix
        self.assertEqual(fake.await_args.args[3], ["description"])

    async def test_one_failure_does_not_abort_the_run(self):
        rows = await self._rows()
        calls = {"n": 0}

        async def flaky(cfg, row, src, fields):
            calls["n"] += 1
            if row["id"] == self.ids[1]:
                raise LlmError("provider exploded")
            return {"remediation": "AI fix"}

        job = auto_enhance.create_job("s1", CFG, list(finding_fix.FIXABLE_FIELDS), rows)
        with patch.object(finding_fix, "fix_finding", flaky):
            await auto_enhance.run_job(job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows,
                                       scan_dir=self.scan_dir, regenerate=AsyncMock(return_value=True))
        self.assertEqual(job["state"], "done")
        self.assertEqual((job["succeeded"], job["failed"]), (2, 1))
        failed = [it for it in job["items"] if it["state"] == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("provider exploded", failed[0]["error"])
        # original text untouched on the failed finding
        bad = next(r for r in await self._rows() if r["id"] == self.ids[1])
        self.assertNotEqual(bad.get("ai_fix_status"), "applied")
        self.assertEqual(bad["effective_remediation"], "fix")

    async def test_no_regeneration_when_nothing_applied(self):
        rows = await self._rows()
        regen = AsyncMock(return_value=True)
        job = auto_enhance.create_job("s1", CFG, ["description"], rows)
        with patch.object(finding_fix, "fix_finding", AsyncMock(side_effect=LlmError("nope"))):
            await auto_enhance.run_job(job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows,
                                       scan_dir=self.scan_dir, regenerate=regen)
        self.assertEqual(job["failed"], 3)
        regen.assert_not_awaited()

    async def test_concurrency_is_bounded(self):
        rows = await self._rows()
        live = {"now": 0, "peak": 0}

        async def slow(cfg, row, src, fields):
            live["now"] += 1
            live["peak"] = max(live["peak"], live["now"])
            await asyncio.sleep(0.02)
            live["now"] -= 1
            return {"description": "x"}

        job = auto_enhance.create_job("s1", CFG, ["description"], rows)
        with patch.object(finding_fix, "fix_finding", slow):
            await auto_enhance.run_job(job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows,
                                       scan_dir=self.scan_dir, regenerate=AsyncMock(return_value=True),
                                       concurrency=2)
        self.assertLessEqual(live["peak"], 2)

    async def test_finished_job_is_persisted_and_releases_the_scan(self):
        rows = await self._rows()
        job = auto_enhance.create_job("s1", CFG, ["description"], rows)
        self.assertEqual(auto_enhance.active_job_id("s1"), job["job_id"])
        with patch.object(finding_fix, "fix_finding", AsyncMock(return_value={"description": "x"})):
            await auto_enhance.run_job(job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows,
                                       scan_dir=self.scan_dir, regenerate=AsyncMock(return_value=True))
        self.assertIsNone(auto_enhance.active_job_id("s1"))
        log = auto_enhance.read_activity_log(self.scan_dir)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["job_id"], job["job_id"])
        self.assertEqual(log[0]["succeeded"], 3)

    async def test_items_record_updated_fields_changes_and_duration(self):
        rows = await self._rows()
        fix = {"description": "New desc", "risk": {"severity": "HIGH", "cvss": 7.1},
               "remediation": "New fix"}
        job = auto_enhance.create_job("s1", CFG, list(finding_fix.FIXABLE_FIELDS), rows[:1])
        with patch.object(finding_fix, "fix_finding", AsyncMock(return_value=fix)):
            await auto_enhance.run_job(job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows[:1],
                                       scan_dir=self.scan_dir, regenerate=AsyncMock(return_value=True))
        it = job["items"][0]
        self.assertEqual(it["updated_fields"], ["description", "risk", "remediation"])
        self.assertEqual(it["changes"]["description"], "New desc")
        self.assertEqual(it["changes"]["risk"], "Severity: HIGH · CVSS: 7.1")
        self.assertEqual(it["category"], "STORAGE")
        self.assertIsInstance(it["duration_ms"], int)
        self.assertEqual(it["attempts"], 1)

    async def test_cancel_skips_findings_not_started_yet(self):
        rows = await self._rows()
        gate = asyncio.Event()

        async def slow(cfg, row, src, fields):
            await gate.wait()
            return {"description": "x"}

        job = auto_enhance.create_job("s1", CFG, ["description"], rows)
        with patch.object(finding_fix, "fix_finding", slow):
            task = asyncio.create_task(auto_enhance.run_job(
                job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows,
                scan_dir=self.scan_dir, regenerate=AsyncMock(return_value=True), concurrency=1))
            await asyncio.sleep(0.05)            # first finding is in flight
            auto_enhance.request_cancel(job)
            gate.set()
            await task
        self.assertEqual(job["state"], "cancelled")
        self.assertEqual((job["succeeded"], job["cancelled"], job["completed"]), (1, 2, 3))

    async def test_retry_reopens_a_finished_job_for_one_item(self):
        rows = await self._rows()
        regen = AsyncMock(return_value=True)
        job = auto_enhance.create_job("s1", CFG, ["description"], rows[:2])

        async def first(cfg, row, src, fields):
            if row["id"] == self.ids[1]:
                raise LlmError("Rate limit exceeded")
            return {"description": "ok"}

        with patch.object(finding_fix, "fix_finding", first):
            await auto_enhance.run_job(job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows[:2],
                                       scan_dir=self.scan_dir, regenerate=regen)
        self.assertEqual((job["succeeded"], job["failed"]), (1, 1))

        with patch.object(finding_fix, "fix_finding", AsyncMock(return_value={"remediation": "retry ok"})):
            auto_enhance.retry_item(job, rows[1], cfg=CFG, db_path=self.db_path, exe="App",
                                    scan_dir=self.scan_dir, regenerate=regen)
            self.assertEqual(auto_enhance.active_job_id("s1"), job["job_id"])
            await auto_enhance._TASKS[job["job_id"]]
        self.assertEqual(job["state"], "done")
        self.assertEqual((job["succeeded"], job["failed"]), (2, 0))
        retried = job["items"][1]
        self.assertEqual(retried["attempts"], 2)
        self.assertEqual(retried["updated_fields"], ["remediation"])
        self.assertEqual(regen.await_count, 2)
        log = auto_enhance.read_activity_log(self.scan_dir)
        self.assertEqual(len(log), 1, "retry updates the same Activity Log entry")
        self.assertEqual(log[0]["succeeded"], 2)

    async def test_retry_refused_while_batch_is_cancelling(self):
        rows = await self._rows()
        gate = asyncio.Event()

        async def slow(cfg, row, src, fields):
            await gate.wait()
            raise LlmError("boom")

        job = auto_enhance.create_job("s1", CFG, ["description"], rows[:1])
        with patch.object(finding_fix, "fix_finding", slow):
            task = asyncio.create_task(auto_enhance.run_job(
                job, cfg=CFG, db_path=self.db_path, exe="App", rows=rows[:1],
                scan_dir=self.scan_dir, regenerate=AsyncMock(return_value=True)))
            await asyncio.sleep(0.02)
            auto_enhance.request_cancel(job)
            job["items"][0]["state"] = "failed"   # simulate an already-failed item mid-run
            with self.assertRaises(ValueError):
                auto_enhance.retry_item(job, rows[0], cfg=CFG, db_path=self.db_path, exe="App",
                                        scan_dir=self.scan_dir, regenerate=AsyncMock())
            gate.set()
            await task

    def test_activity_log_tolerates_corrupt_file(self):
        (self.scan_dir / auto_enhance.LOG_FILENAME).write_text("{not json", encoding="utf-8")
        self.assertEqual(auto_enhance.read_activity_log(self.scan_dir), [])

    def test_source_location_only_for_function_findings(self):
        self.assertEqual(auto_enhance.source_location_for(
            {"affected_type": "FUNCTION", "evidence_location": "Cls.fn"}), ("Cls", "fn"))
        self.assertEqual(auto_enhance.source_location_for(
            {"affected_type": "FUNCTION", "evidence_location": "Cls"}), ("Cls", None))
        self.assertIsNone(auto_enhance.source_location_for(
            {"affected_type": "STRING", "evidence_location": "0x1"}))


class AutoEnhanceRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scan_root = Path(self.tmp.name)
        (self.scan_root / "s1").mkdir()
        self.db_path = str(self.scan_root / "s1" / "scan.sqlite")
        self.ids = _make_db(self.db_path)
        detail = ScanDetail(scan_id="s1", filename="a.ipa", state="done", created_at="t",
                            llm_provider="ollama", llm_model="llama3.1", platform="ios",
                            bundle_executable="App", db_path=self.db_path)
        self.regen = AsyncMock(return_value=True)
        self.patches = [
            patch.object(main, "_require_db", return_value=(self.db_path, "App")),
            patch.object(scanner, "get_scan_detail", return_value=detail),
            patch.object(scanner, "regenerate_report", self.regen),
            patch.object(main.settings, "api_key", ""),
            patch.object(main.settings, "scan_dir", self.scan_root),
        ]
        for p in self.patches:
            p.start()
        main._CHAT_HITS.clear()
        auto_enhance._JOBS.clear()
        auto_enhance._ACTIVE_BY_SCAN.clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _wait_done(self, client, job_id, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = client.get(f"/api/v1/scans/s1/auto-enhance/jobs/{job_id}")
            if r.status_code == 200 and r.json()["state"] in ("done", "error"):
                return r.json()
            time.sleep(0.02)
        self.fail("job did not finish in time")

    def test_start_poll_and_history(self):
        with patch.object(finding_fix, "fix_finding", AsyncMock(return_value={"description": "AI"})), \
             TestClient(main.app) as client:
            r = client.post("/api/v1/scans/s1/auto-enhance",
                            json={"vuln_ids": self.ids[:2], "fields": ["description"]})
            self.assertEqual(r.status_code, 202, r.text)
            job = r.json()
            self.assertEqual(job["total"], 2)
            self.assertEqual(job["fields"], ["description"])
            final = self._wait_done(client, job["job_id"])
            self.assertEqual(final["succeeded"], 2)
            ov = client.get("/api/v1/scans/s1/auto-enhance").json()
            self.assertIsNone(ov["active"])
            self.assertEqual(ov["history"][0]["job_id"], job["job_id"])
        self.regen.assert_awaited_once()

    def test_rejects_unknown_field(self):
        with TestClient(main.app) as client:
            r = client.post("/api/v1/scans/s1/auto-enhance",
                            json={"vuln_ids": self.ids, "fields": ["bogus"]})
        self.assertEqual(r.status_code, 422)

    def test_rejects_empty_selection(self):
        with TestClient(main.app) as client:
            r = client.post("/api/v1/scans/s1/auto-enhance", json={"vuln_ids": []})
        self.assertEqual(r.status_code, 422)

    def test_404_for_unknown_vuln_id(self):
        with TestClient(main.app) as client:
            r = client.post("/api/v1/scans/s1/auto-enhance", json={"vuln_ids": [999999]})
        self.assertEqual(r.status_code, 404)

    def test_409_while_a_job_is_running(self):
        auto_enhance._JOBS["busy"] = {"job_id": "busy", "scan_id": "s1", "state": "running"}
        auto_enhance._ACTIVE_BY_SCAN["s1"] = "busy"
        with TestClient(main.app) as client:
            r = client.post("/api/v1/scans/s1/auto-enhance", json={"vuln_ids": self.ids})
        self.assertEqual(r.status_code, 409)

    def test_400_when_no_provider_configured(self):
        with patch.object(main, "resolve_llm", side_effect=LlmError("no provider")), \
             TestClient(main.app) as client:
            r = client.post("/api/v1/scans/s1/auto-enhance", json={"vuln_ids": self.ids})
        self.assertEqual(r.status_code, 400)

    def test_counts_as_one_rate_limit_hit(self):
        with patch.object(main.settings, "chat_rate_per_min", 1), \
             patch.object(finding_fix, "fix_finding", AsyncMock(return_value={"description": "AI"})), \
             TestClient(main.app) as client:
            r1 = client.post("/api/v1/scans/s1/auto-enhance", json={"vuln_ids": self.ids})
            self.assertEqual(r1.status_code, 202)
            self._wait_done(client, r1.json()["job_id"])   # 3 LLM calls, still one hit
            r2 = client.post("/api/v1/scans/s1/auto-enhance", json={"vuln_ids": self.ids})
            self.assertEqual(r2.status_code, 429)

    def test_retry_route_reruns_failed_finding(self):
        async def flaky(cfg, row, src, fields):
            if row["id"] == self.ids[0] and not getattr(flaky, "healed", False):
                raise LlmError("Rate limit exceeded")
            return {"description": "AI"}

        with patch.object(finding_fix, "fix_finding", flaky), TestClient(main.app) as client:
            job = client.post("/api/v1/scans/s1/auto-enhance", json={"vuln_ids": self.ids[:2]}).json()
            final = self._wait_done(client, job["job_id"])
            self.assertEqual(final["failed"], 1)
            # only failed/cancelled items are retryable
            ok_id = self.ids[1]
            r = client.post(f"/api/v1/scans/s1/auto-enhance/jobs/{job['job_id']}/items/{ok_id}/retry")
            self.assertEqual(r.status_code, 409)
            flaky.healed = True
            r = client.post(f"/api/v1/scans/s1/auto-enhance/jobs/{job['job_id']}/items/{self.ids[0]}/retry")
            self.assertEqual(r.status_code, 202, r.text)
            final = self._wait_done(client, job["job_id"])
            self.assertEqual((final["succeeded"], final["failed"]), (2, 0))

    def test_cancel_route(self):
        with TestClient(main.app) as client:
            r = client.post("/api/v1/scans/s1/auto-enhance/jobs/nope/cancel")
            self.assertEqual(r.status_code, 404)
            auto_enhance._JOBS["j1"] = {"job_id": "j1", "scan_id": "s1", "state": "done"}
            r = client.post("/api/v1/scans/s1/auto-enhance/jobs/j1/cancel")
            self.assertEqual(r.status_code, 409)
            auto_enhance._JOBS["j1"]["state"] = "running"
            r = client.post("/api/v1/scans/s1/auto-enhance/jobs/j1/cancel")
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json()["cancel_requested"])

    def test_job_404_for_unknown_job(self):
        with TestClient(main.app) as client:
            r = client.get("/api/v1/scans/s1/auto-enhance/jobs/nope")
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
