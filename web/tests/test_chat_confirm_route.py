"""Tests for POST /scans/{id}/chat/{session_id}/confirm-tool — the route that settles a
propose_finding/apply_triage pause started by POST /chat (see agent/loop.py's
tool_confirm_needed/awaiting_confirmation events and resume_after_confirmation())."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from web.app import main, scanner
from web.app.agent import loop
from web.app.models import ScanDetail


def _events(text):
    return [json.loads(b[6:]) for b in text.split("\n\n") if b.startswith("data: ")]


def _make_db(path: str) -> int:
    with sqlite3.connect(path) as conn:
        conn.execute(
            """CREATE TABLE Vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                RuleId TEXT, Title TEXT, Category TEXT, Severity TEXT, CvssScore REAL, Cwe TEXT,
                Description TEXT, AffectedType TEXT, AffectedName TEXT, Evidence TEXT,
                EvidenceLocation TEXT, PocSteps TEXT, Remediation TEXT, ReferenceUrl TEXT,
                ExecutableName TEXT, CreatedAt INTEGER)"""
        )
        cur = conn.execute(
            """INSERT INTO Vulnerabilities
               (RuleId, Title, Category, Severity, CvssScore, Cwe, Description, AffectedType,
                AffectedName, Evidence, EvidenceLocation, PocSteps, Remediation, ReferenceUrl,
                ExecutableName, CreatedAt)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("MSTG-STORAGE-1", "Hardcoded API key", "STORAGE", "CRITICAL", 9.1, "CWE-798",
             "Original description", "STRING", "0x1234", "api_key=abc", "0x1234",
             "1. find it", "Use Keychain", "https://x", "App", 0),
        )
        conn.commit()
        return cur.lastrowid


def _step_with(*blocks):
    async def step(cfg, system, messages, tools, **kw):
        for b in blocks:
            yield b
    return step


class ConfirmToolRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "scan.sqlite")
        self.vuln_id = _make_db(self.db_path)
        detail = ScanDetail(scan_id="s1", filename="a.ipa", state="done", created_at="t",
                            llm_provider="ollama", llm_model="llama3.1", platform="ios",
                            bundle_executable="App", db_path=self.db_path)
        self.regen = AsyncMock(return_value=True)
        self.patches = [
            patch.object(main, "_require_db", return_value=(self.db_path, "App")),
            patch.object(scanner, "get_scan_detail", return_value=detail),
            patch.object(scanner, "_scan_dir", return_value=Path(self.tmp.name)),
            patch.object(scanner, "regenerate_report", self.regen),
            patch.object(main.settings, "api_key", ""),
        ]
        for p in self.patches:
            p.start()
        main._CHAT_HITS.clear()
        self.client = TestClient(main.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _start_propose_finding(self):
        """POST /chat with a mocked step() that immediately calls propose_finding — returns the
        session id and the paused round's pending tool_use_id."""
        tool_use = {"type": "tool_use", "id": "tu1", "name": "propose_finding",
                    "input": {"title": "Found in chat", "severity": "HIGH",
                              "description": "Discussed and confirmed with the user."}}
        step = _step_with({"type": "text", "text": "I found something."}, tool_use,
                          {"type": "stop", "reason": "tool_use"})
        with patch.object(loop, "chat_step", step):
            r = self.client.post("/api/v1/scans/s1/chat", json={"message": "investigate this"})
        evs = _events(r.text)
        self.assertEqual([e["type"] for e in evs][-2:], ["tool_confirm_needed", "awaiting_confirmation"])
        sid = evs[0]["session_id"]
        return sid, evs[-1]["pending_ids"][0]

    def test_approve_writes_the_finding_and_regenerates_the_report(self):
        sid, tool_use_id = self._start_propose_finding()
        step2 = _step_with({"type": "text", "text": "Added it to Vulnerabilities."},
                           {"type": "stop", "reason": "end_turn"})
        with patch.object(loop, "chat_step", step2):
            r = self.client.post(f"/api/v1/scans/s1/chat/{sid}/confirm-tool",
                                 json={"decisions": {tool_use_id: True}})
        self.assertEqual(r.status_code, 200)
        evs = _events(r.text)
        self.assertEqual(evs[0]["type"], "tool_result")
        self.assertTrue(evs[0]["ok"])
        self.assertEqual(evs[-1]["type"], "done")
        self.regen.assert_awaited_once_with("s1")

        rows = sqlite3.connect(self.db_path).execute("SELECT Title, Source FROM Vulnerabilities").fetchall()
        self.assertIn(("Found in chat", "ai_assistant"), rows)

    def test_decline_does_not_write_or_regenerate(self):
        sid, tool_use_id = self._start_propose_finding()
        step2 = _step_with({"type": "text", "text": "Okay, skipping that."}, {"type": "stop", "reason": "end_turn"})
        with patch.object(loop, "chat_step", step2):
            r = self.client.post(f"/api/v1/scans/s1/chat/{sid}/confirm-tool",
                                 json={"decisions": {tool_use_id: False}})
        self.assertEqual(r.status_code, 200)
        evs = _events(r.text)
        self.assertFalse(evs[0]["ok"])
        self.regen.assert_not_awaited()
        rows = sqlite3.connect(self.db_path).execute("SELECT Title FROM Vulnerabilities").fetchall()
        self.assertEqual(len(rows), 1)   # only the original seeded row

    def test_apply_triage_approval_writes_and_regenerates(self):
        tool_use = {"type": "tool_use", "id": "tu2", "name": "apply_triage",
                    "input": {"vuln_id": self.vuln_id, "status": "accepted_risk", "note": "Reviewed in chat."}}
        step = _step_with({"type": "text", "text": "Updating triage."}, tool_use, {"type": "stop", "reason": "tool_use"})
        with patch.object(loop, "chat_step", step):
            r = self.client.post("/api/v1/scans/s1/chat", json={"message": "mark this accepted risk"})
        sid = _events(r.text)[0]["session_id"]

        step2 = _step_with({"type": "text", "text": "Done."}, {"type": "stop", "reason": "end_turn"})
        with patch.object(loop, "chat_step", step2):
            r2 = self.client.post(f"/api/v1/scans/s1/chat/{sid}/confirm-tool", json={"decisions": {"tu2": True}})
        self.assertEqual(r2.status_code, 200)
        self.regen.assert_awaited_once_with("s1")
        row = sqlite3.connect(self.db_path).execute(
            "SELECT Status, OverrideNote FROM Vulnerabilities WHERE id=?", (self.vuln_id,)).fetchone()
        self.assertEqual(row, ("accepted_risk", "Reviewed in chat."))

    def test_unknown_session_404(self):
        r = self.client.post("/api/v1/scans/s1/chat/does-not-exist/confirm-tool", json={"decisions": {"x": True}})
        self.assertEqual(r.status_code, 404)

    def test_empty_decisions_rejected(self):
        sid, _ = self._start_propose_finding()
        r = self.client.post(f"/api/v1/scans/s1/chat/{sid}/confirm-tool", json={"decisions": {}})
        self.assertEqual(r.status_code, 422)

    def test_wrong_tool_use_id_surfaces_as_a_stream_error_not_a_crash(self):
        sid, _real_id = self._start_propose_finding()
        r = self.client.post(f"/api/v1/scans/s1/chat/{sid}/confirm-tool", json={"decisions": {"not-the-real-id": True}})
        self.assertEqual(r.status_code, 200)   # the SSE stream itself always 200s; the error is inside it
        evs = _events(r.text)
        self.assertEqual(evs[-1]["type"], "error")
        self.regen.assert_not_awaited()

    def test_confirming_twice_the_second_time_errors_inside_the_stream(self):
        sid, tool_use_id = self._start_propose_finding()
        step2 = _step_with({"type": "text", "text": "ok"}, {"type": "stop", "reason": "end_turn"})
        with patch.object(loop, "chat_step", step2):
            self.client.post(f"/api/v1/scans/s1/chat/{sid}/confirm-tool", json={"decisions": {tool_use_id: True}})
            r2 = self.client.post(f"/api/v1/scans/s1/chat/{sid}/confirm-tool", json={"decisions": {tool_use_id: True}})
        self.assertEqual(_events(r2.text)[-1]["type"], "error")

    def test_auth_enforced(self):
        with patch.object(main.settings, "api_key", "secret"):
            r = self.client.post("/api/v1/scans/s1/chat/anything/confirm-tool", json={"decisions": {"x": True}})
            self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
