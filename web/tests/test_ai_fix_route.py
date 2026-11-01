"""Tests for the AI Fix endpoints: POST .../ai-fix and POST .../ai-fix/revert."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from web.app import db, finding_fix, main, scanner
from web.app.agent.llm import LlmCfg, LlmError
from web.app.models import ScanDetail


def _make_db(path: str) -> int:
    """Creates a minimal Vulnerabilities table with one row and returns its id."""
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


class AiFixRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "scan.sqlite")
        self.vuln_id = _make_db(self.db_path)

        detail = ScanDetail(scan_id="s1", filename="a.ipa", state="done", created_at="t",
                            llm_provider="ollama", llm_model="llama3.1", platform="ios",
                            bundle_executable="App", db_path=self.db_path)
        self.patches = [
            patch.object(main, "_require_db", return_value=(self.db_path, "App")),
            patch.object(scanner, "get_scan_detail", return_value=detail),
            patch.object(scanner, "regenerate_report", AsyncMock(return_value=True)),
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

    def test_ai_fix_applies_overrides_and_response_reflects_them(self):
        fake_fix = {"description": "AI description", "evidence": "AI evidence",
                    "risk": {"severity": "HIGH", "cvss": 7.2},
                    "poc_steps": "1. AI step", "remediation": "AI remediation"}
        with patch.object(finding_fix, "fix_finding", AsyncMock(return_value=fake_fix)):
            r = self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix", json={})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["updated"])
        v = body["vulnerability"]
        self.assertEqual(v["effective_description"], "AI description")
        self.assertEqual(v["effective_evidence"], "AI evidence")
        self.assertEqual(v["effective_severity"], "HIGH")
        self.assertEqual(v["effective_cvss_score"], 7.2)
        self.assertEqual(v["effective_poc_steps"], "1. AI step")
        self.assertEqual(v["effective_remediation"], "AI remediation")
        self.assertEqual(v["ai_fix_status"], "applied")
        self.assertEqual(v["ai_fix_provider"], "ollama")
        # original fields untouched
        self.assertEqual(v["description"], "Original description")
        self.assertEqual(v["severity"], "CRITICAL")

    def test_ai_fix_accepts_provider_and_model_override(self):
        fake_fix = {"description": "x"}
        mock_fix = AsyncMock(return_value=fake_fix)
        with patch.object(finding_fix, "fix_finding", mock_fix):
            r = self.client.post(
                f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix",
                json={"provider": "deepseek", "model": "deepseek-v4-pro", "fields": ["description"]},
            )
        self.assertEqual(r.status_code, 200, r.text)
        cfg_arg = mock_fix.call_args.args[0]
        self.assertIsInstance(cfg_arg, LlmCfg)
        self.assertEqual(cfg_arg.provider, "deepseek")
        self.assertEqual(cfg_arg.model, "deepseek-v4-pro")
        self.assertEqual(r.json()["vulnerability"]["ai_fix_provider"], "deepseek")

    def test_ai_fix_rejects_unknown_field_name(self):
        r = self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix",
                             json={"fields": ["not_a_real_field"]})
        self.assertEqual(r.status_code, 422)

    def test_ai_fix_404_for_unknown_vuln_id(self):
        fake_fix = {"description": "x"}
        with patch.object(finding_fix, "fix_finding", AsyncMock(return_value=fake_fix)):
            r = self.client.post("/api/v1/scans/s1/vulnerabilities/999999/ai-fix", json={})
        self.assertEqual(r.status_code, 404)

    def test_ai_fix_502_when_llm_fails(self):
        with patch.object(finding_fix, "fix_finding", AsyncMock(side_effect=LlmError("provider exploded"))):
            r = self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix", json={})
        self.assertEqual(r.status_code, 502)
        self.assertIn("provider exploded", r.text)

    def test_ai_fix_400_when_no_provider_configured(self):
        detail = ScanDetail(scan_id="s1", filename="a.ipa", state="done", created_at="t",
                            llm_provider="none", platform="ios",
                            bundle_executable="App", db_path=self.db_path)
        # Isolate from the developer's local web/.env (which may set a real server-wide
        # llm_provider fallback) so this asserts the "truly nothing configured" path.
        with patch.object(scanner, "get_scan_detail", return_value=detail), \
             patch.object(main.settings, "llm_provider", "none"):
            r = self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix", json={})
        self.assertEqual(r.status_code, 400)

    def test_revert_restores_original_and_marks_reverted(self):
        fake_fix = {"description": "AI description", "risk": {"severity": "LOW", "cvss": 2.0}}
        with patch.object(finding_fix, "fix_finding", AsyncMock(return_value=fake_fix)):
            self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix", json={})

        r = self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix/revert")
        self.assertEqual(r.status_code, 200, r.text)
        v = r.json()["vulnerability"]
        self.assertEqual(v["effective_description"], "Original description")
        self.assertEqual(v["effective_severity"], "CRITICAL")
        self.assertEqual(v["ai_fix_status"], "reverted")

    def test_revert_404_for_unknown_vuln_id(self):
        r = self.client.post("/api/v1/scans/s1/vulnerabilities/999999/ai-fix/revert")
        self.assertEqual(r.status_code, 404)

    def test_ai_fix_shares_chat_rate_limit(self):
        with patch.object(main.settings, "chat_rate_per_min", 1):
            fake_fix = {"description": "x"}
            with patch.object(finding_fix, "fix_finding", AsyncMock(return_value=fake_fix)):
                r1 = self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix", json={})
                self.assertEqual(r1.status_code, 200)
                r2 = self.client.post(f"/api/v1/scans/s1/vulnerabilities/{self.vuln_id}/ai-fix", json={})
                self.assertEqual(r2.status_code, 429)


class FindingFixUnitTests(unittest.IsolatedAsyncioTestCase):
    """Unit tests for finding_fix.py helpers that don't need the HTTP layer."""

    def test_extract_fix_json_clean(self):
        obj = finding_fix.extract_fix_json('{"description": "x", "risk": {"severity": "HIGH"}}')
        self.assertEqual(obj["description"], "x")

    def test_extract_fix_json_code_fence(self):
        obj = finding_fix.extract_fix_json('Here:\n```json\n{"evidence": "e"}\n```\nDone')
        self.assertEqual(obj["evidence"], "e")

    def test_extract_fix_json_prose_prefix(self):
        obj = finding_fix.extract_fix_json('Sure, I analyzed it. {"remediation": "fix"}')
        self.assertEqual(obj["remediation"], "fix")

    def test_extract_fix_json_none_for_garbage(self):
        self.assertIsNone(finding_fix.extract_fix_json("not json at all"))

    def test_extract_fix_json_none_for_empty(self):
        self.assertIsNone(finding_fix.extract_fix_json(""))
        self.assertIsNone(finding_fix.extract_fix_json(None))

    def test_sanitize_fix_drops_placeholders_and_clamps_cvss(self):
        san = finding_fix.sanitize_fix({
            "description": "...",
            "evidence": "real",
            "risk": {"severity": "bogus", "cvss": 99},
            "poc_steps": "N/A",
            "remediation": "Do the thing",
        })
        self.assertNotIn("description", san)
        self.assertEqual(san["evidence"], "real")
        self.assertNotIn("severity", san["risk"])
        self.assertEqual(san["risk"]["cvss"], 10.0)
        self.assertNotIn("poc_steps", san)
        self.assertEqual(san["remediation"], "Do the thing")

    def test_sanitize_fix_empty_dict_when_nothing_usable(self):
        self.assertEqual(finding_fix.sanitize_fix({"description": "..."}), {})

    async def test_fix_finding_raises_when_no_json_returned(self):
        async def fake_chat_step(cfg, system, messages, tools, **kw):
            yield {"type": "text", "text": "no json here"}
            yield {"type": "stop", "reason": "end_turn"}

        cfg = LlmCfg("ollama", "llama3.1", "", "http://localhost:11434")
        with patch.object(finding_fix, "chat_step", fake_chat_step):
            with self.assertRaises(LlmError):
                await finding_fix.fix_finding(cfg, {"rule_id": "X"}, None)

    async def test_fix_finding_returns_sanitized_dict(self):
        async def fake_chat_step(cfg, system, messages, tools, **kw):
            yield {"type": "text", "text": '{"description": "improved", "evidence": "..."}'}
            yield {"type": "stop", "reason": "end_turn"}

        cfg = LlmCfg("ollama", "llama3.1", "", "http://localhost:11434")
        with patch.object(finding_fix, "chat_step", fake_chat_step):
            fix = await finding_fix.fix_finding(cfg, {"rule_id": "X"}, None)
        self.assertEqual(fix, {"description": "improved"})  # placeholder evidence dropped


if __name__ == "__main__":
    unittest.main()
