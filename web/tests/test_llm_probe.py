"""Tests for the upload form's "Test Connection" probe and its route."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from web.app import llm_probe, main


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _run(coro):
    return asyncio.run(coro)


class ProbeTests(unittest.TestCase):
    def test_openai_ok_and_model_found(self):
        seen = {}

        def handler(req):
            seen["url"] = str(req.url)
            seen["auth"] = req.headers.get("authorization")
            return httpx.Response(200, json={"data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}]})

        r = _run(llm_probe.probe("openai", "sk-test", "gpt-4o", client=_client(handler)))
        self.assertTrue(r["ok"])
        self.assertTrue(r["model_found"])
        self.assertFalse(r["used_server_key"])
        self.assertEqual(seen["url"], "https://api.openai.com/v1/models")
        self.assertEqual(seen["auth"], "Bearer sk-test")
        self.assertNotIn("sk-test", r["message"])

    def test_unknown_model_is_reported_but_still_ok(self):
        r = _run(llm_probe.probe("openai", "sk-test", "nope",
                                 client=_client(lambda req: httpx.Response(200, json={"data": [{"id": "gpt-4o"}]}))))
        self.assertTrue(r["ok"])
        self.assertFalse(r["model_found"])
        self.assertIn("nope", r["message"])

    def test_rejected_key(self):
        r = _run(llm_probe.probe("claude", "sk-ant-bad", "",
                                 client=_client(lambda req: httpx.Response(401, json={"error": {}}))))
        self.assertFalse(r["ok"])
        self.assertIn("rejected", r["message"])

    def test_claude_uses_anthropic_headers(self):
        seen = {}

        def handler(req):
            seen.update(key=req.headers.get("x-api-key"), ver=req.headers.get("anthropic-version"))
            return httpx.Response(200, json={"data": [{"id": "claude-sonnet-5"}]})

        r = _run(llm_probe.probe("claude", "sk-ant-x", "claude-sonnet-5", client=_client(handler)))
        self.assertTrue(r["ok"] and r["model_found"])
        self.assertEqual(seen, {"key": "sk-ant-x", "ver": "2023-06-01"})

    def test_missing_key_without_server_key(self):
        with patch.object(llm_probe.scanner, "llm_env", return_value={}):
            r = _run(llm_probe.probe("deepseek", "", ""))
        self.assertFalse(r["ok"])
        self.assertIn("API key", r["message"])

    def test_server_key_fallback_is_flagged(self):
        with patch.object(llm_probe.scanner, "llm_env", return_value={"DEEPSEEK_API_KEY": "srv"}):
            r = _run(llm_probe.probe("deepseek", "", "",
                                     client=_client(lambda req: httpx.Response(200, json={"data": []}))))
        self.assertTrue(r["ok"])
        self.assertTrue(r["used_server_key"])

    def test_ollama_tag_matching(self):
        body = {"models": [{"name": "llama3:latest"}]}
        r = _run(llm_probe.probe("ollama", "", "llama3",
                                 client=_client(lambda req: httpx.Response(200, json=body))))
        self.assertTrue(r["ok"] and r["model_found"])

    def test_network_error(self):
        def handler(req):
            raise httpx.ConnectError("boom")

        r = _run(llm_probe.probe("openai", "sk-x", "", client=_client(handler)))
        self.assertFalse(r["ok"])
        self.assertIn("ConnectError", r["message"])

    def test_claude_oauth_reports_stored_session(self):
        with patch.object(llm_probe.anthropic_oauth, "is_configured", return_value=True):
            self.assertTrue(_run(llm_probe.probe("claude-oauth"))["ok"])
        with patch.object(llm_probe.anthropic_oauth, "is_configured", return_value=False):
            self.assertFalse(_run(llm_probe.probe("claude-oauth"))["ok"])

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            _run(llm_probe.probe("gemini"))


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    def test_route_delegates_to_probe(self):
        fake = {"ok": True, "provider": "openai", "message": "Connected.",
                "model_found": None, "used_server_key": False}
        with patch.object(main.settings, "api_key", ""), \
                patch.object(main.llm_probe, "probe", AsyncMock(return_value=fake)) as p:
            r = self.client.post("/api/v1/llm/test", json={"provider": "openai", "api_key": "k"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), fake)
        p.assert_awaited_once_with("openai", "k", "")

    def test_route_rejects_unknown_provider(self):
        with patch.object(main.settings, "api_key", ""):
            r = self.client.post("/api/v1/llm/test", json={"provider": "gemini"})
        self.assertEqual(r.status_code, 422)


if __name__ == "__main__":
    unittest.main()
