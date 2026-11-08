"""Tests for bot/python/api_client.py — the Slack bot's bridge to the Malimite web API.

No Slack workspace and no running Malimite server are needed: httpx.MockTransport stands in for
the API, so these run anywhere (and in CI) with just httpx installed.
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api_client  # noqa: E402


def _api(handler, api_key: str = "") -> api_client.MalimiteApi:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return api_client.MalimiteApi("http://malimite.test", api_key, client=client)


def _run(coro):
    return asyncio.run(coro)


class MappingTests(unittest.TestCase):
    def test_effective_values_win_over_original(self):
        """The bot must show what a reviewer sees in the web UI, i.e. triage/AI-Fix overrides."""
        mapped = api_client.to_slack_finding({
            "rule_id": "MASTG-TEST-0001",
            "title": "Insecure storage",
            "severity": "LOW", "effective_severity": "CRITICAL",
            "cvss_score": 2.0, "effective_cvss_score": 9.8,
            "status": "accepted_risk",
            "description": "orig", "effective_description": "rewritten",
            "remediation": "orig fix", "effective_remediation": "new fix",
            "affected_name": "com.example.Store",
            "reference_url": "https://example.test/ref",
        })
        self.assertEqual(mapped["effective_severity"], "CRITICAL")
        self.assertEqual(mapped["effective_cvss"], 9.8)
        self.assertEqual(mapped["Description"], "rewritten")
        self.assertEqual(mapped["Remediation"], "new fix")
        self.assertEqual(mapped["Title"], "Insecure storage")
        self.assertEqual(mapped["RuleId"], "MASTG-TEST-0001")

    def test_suppression_matches_server_semantics(self):
        for status, suppressed in [("false_positive", True), ("fixed", True),
                                   ("open", False), ("accepted_risk", False)]:
            with self.subTest(status=status):
                self.assertIs(api_client.to_slack_finding({"status": status})["is_suppressed"],
                              suppressed)

    def test_missing_fields_do_not_crash(self):
        mapped = api_client.to_slack_finding({})
        self.assertEqual(mapped["effective_severity"], "INFO")
        self.assertEqual(mapped["effective_cvss"], 0.0)
        self.assertFalse(mapped["is_suppressed"])

    def test_duration_is_computed_from_iso_timestamps(self):
        self.assertAlmostEqual(
            api_client._duration_s({"created_at": "2026-01-01T00:00:00+00:00",
                                    "finished_at": "2026-01-01T00:01:30+00:00"}), 90.0)

    def test_duration_tolerates_missing_or_bad_timestamps(self):
        self.assertEqual(api_client._duration_s({}), 0.0)
        self.assertEqual(api_client._duration_s({"created_at": "nope",
                                                 "finished_at": "also-nope"}), 0.0)


class CreateScanTests(unittest.TestCase):
    def test_posts_multipart_with_file_and_flags_and_returns_scan_id(self):
        seen = {}

        def handler(req):
            seen["method"] = req.method
            seen["path"] = req.url.path
            seen["auth"] = req.headers.get("x-api-key")
            body = req.read()
            seen["body"] = body
            return httpx.Response(200, json={"scan_id": "abc-123"})

        got = _run(_api(handler, "k1").create_scan(b"APKDATA", "app.apk", llm_enabled=True))

        self.assertEqual(got, "abc-123")
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["path"], "/api/v1/scans")
        self.assertEqual(seen["auth"], "k1")
        for needle in (b'app.apk', b'APKDATA', b'"llm_enabled"', b'true',
                       b'"assessment_enabled"', b'"ci_triggered_by"', b'slack'):
            self.assertIn(needle, seen["body"])

    def test_missing_scan_id_raises(self):
        with self.assertRaises(api_client.ApiError):
            _run(_api(lambda req: httpx.Response(200, json={})).create_scan(b"x", "a.apk"))

    def test_http_error_raises_with_body(self):
        with self.assertRaises(api_client.ApiError) as cm:
            _run(_api(lambda req: httpx.Response(413, text="too big")).create_scan(b"x", "a.apk"))
        self.assertIn("413", str(cm.exception))

    def test_transport_error_raises_api_error(self):
        def handler(req):
            raise httpx.ConnectError("nope")

        with self.assertRaises(api_client.ApiError):
            _run(_api(handler).create_scan(b"x", "a.apk"))


class WaitForScanTests(unittest.TestCase):
    def test_polls_until_done(self):
        states = iter([{"state": "queued"}, {"state": "running"}, {"state": "done", "exit_code": 0}])
        calls = {"n": 0}

        def handler(req):
            calls["n"] += 1
            return httpx.Response(200, json=next(states))

        detail = _run(_api(handler).wait_for_scan("s1", poll_interval=0))
        self.assertEqual(detail["state"], "done")
        self.assertEqual(calls["n"], 3)

    def test_error_state_is_returned_not_raised(self):
        """state=error is a valid completion — the caller decides how to report it."""
        detail = _run(_api(lambda req: httpx.Response(200, json={"state": "error"})).wait_for_scan("s1"))
        self.assertEqual(detail["state"], "error")

    def test_poll_callback_is_called_between_polls(self):
        states = iter([{"state": "queued"}, {"state": "done"}])
        ticks = []

        async def on_poll():
            ticks.append(1)

        _run(_api(lambda req: httpx.Response(200, json=next(states))).wait_for_scan(
            "s1", poll_interval=0, on_poll=on_poll))
        self.assertEqual(len(ticks), 1)

    def test_timeout_raises(self):
        with self.assertRaises(api_client.ApiError) as cm:
            _run(_api(lambda req: httpx.Response(200, json={"state": "running"})).wait_for_scan(
                "s1", poll_interval=0, overall_timeout=0.01))
        self.assertIn("still 'running'", str(cm.exception))


class FindingsAndArtifactTests(unittest.TestCase):
    def test_vulnerabilities_returns_list(self):
        rows = [{"rule_id": "R1", "severity": "HIGH"}]
        got = _run(_api(lambda req: httpx.Response(200, json=rows)).vulnerabilities("s1"))
        self.assertEqual(got, rows)

    def test_vulnerabilities_non_list_raises(self):
        with self.assertRaises(api_client.ApiError):
            _run(_api(lambda req: httpx.Response(200, json={"oops": True})).vulnerabilities("s1"))

    def test_artifact_404_returns_none(self):
        self.assertIsNone(
            _run(_api(lambda req: httpx.Response(404)).artifact("s1", "report")))

    def test_artifact_returns_bytes(self):
        got = _run(_api(lambda req: httpx.Response(200, content=b"<html/>")).artifact("s1", "report"))
        self.assertEqual(got, b"<html/>")

    def test_unknown_artifact_kind_raises_value_error(self):
        with self.assertRaises(ValueError):
            _run(_api(lambda req: httpx.Response(200)).artifact("s1", "bogus"))


class RunScanTests(unittest.TestCase):
    def _handler(self, detail, vulns):
        def handler(req):
            if req.method == "POST" and req.url.path == "/api/v1/scans":
                return httpx.Response(200, json={"scan_id": "s1"})
            if req.url.path == "/api/v1/scans/s1/vulnerabilities":
                return httpx.Response(200, json=vulns)
            return httpx.Response(200, json=detail)
        return handler

    def test_successful_scan_returns_formatter_ready_result(self):
        detail = {
            "state": "done", "bundle_id": "com.example", "bundle_executable": "App",
            "created_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:00:12+00:00",
            "vulnerability_counts": {"HIGH": 2, "MEDIUM": 1, "total": 3},
        }
        vulns = [{"rule_id": "R1", "title": "T", "severity": "HIGH", "status": "open"}]

        result = _run(api_client.run_scan(_api(self._handler(detail, vulns)), b"x", "app.apk",
                                          poll_interval=0))
        self.assertTrue(result["ok"])
        self.assertEqual(result["scan_id"], "s1")
        self.assertEqual(result["counts"]["HIGH"], 2)
        self.assertEqual(result["duration_s"], 12.0)
        self.assertEqual(len(result["vulnerabilities"]), 1)
        self.assertEqual(result["vulnerabilities"][0]["RuleId"], "R1")

    def test_failed_scan_returns_ok_false_without_fetching_findings(self):
        detail = {"state": "error", "vulnerability_counts": None}
        fetched = {"vulns": False}

        def handler(req):
            if req.method == "POST":
                return httpx.Response(200, json={"scan_id": "s1"})
            if req.url.path.endswith("/vulnerabilities"):
                fetched["vulns"] = True
            return httpx.Response(200, json=detail)

        result = _run(api_client.run_scan(_api(handler), b"x", "app.apk", poll_interval=0))
        self.assertFalse(result["ok"])
        self.assertEqual(result["vulnerabilities"], [])
        self.assertFalse(fetched["vulns"], "no point fetching findings for a failed scan")

    def test_progress_callback_is_wired_through(self):
        states = iter([{"state": "queued"}, {"state": "done", "vulnerability_counts": {"total": 0}}])
        ticks = []

        async def on_poll():
            ticks.append(1)

        def handler(req):
            if req.method == "POST":
                return httpx.Response(200, json={"scan_id": "s1"})
            if req.url.path.endswith("/vulnerabilities"):
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=next(states))

        _run(api_client.run_scan(_api(handler), b"x", "a.apk", poll_interval=0, progress=on_poll))
        self.assertEqual(len(ticks), 1)


class ConstructionTests(unittest.TestCase):
    def test_missing_base_url_raises(self):
        with self.assertRaises(api_client.ApiError):
            api_client.MalimiteApi("")

    def test_trailing_slash_is_normalised(self):
        self.assertEqual(api_client.MalimiteApi("http://h:7070/").base_url, "http://h:7070")


if __name__ == "__main__":
    unittest.main()
