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

    def test_glm_uses_openai_compatible_models_endpoint(self):
        seen = {}

        def handler(req):
            seen["url"] = str(req.url)
            seen["auth"] = req.headers.get("authorization")
            return httpx.Response(200, json={"data": [{"id": "glm-4.6"}]})

        r = _run(llm_probe.probe("glm", "glm-test-key", "glm-4.6", client=_client(handler)))
        self.assertTrue(r["ok"])
        self.assertTrue(r["model_found"])
        self.assertEqual(seen["url"], "https://open.bigmodel.cn/api/paas/v4/models")
        self.assertEqual(seen["auth"], "Bearer glm-test-key")

    def test_glm_missing_key_without_server_key(self):
        with patch.object(llm_probe.scanner, "llm_env", return_value={}):
            r = _run(llm_probe.probe("glm", "", ""))
        self.assertFalse(r["ok"])
        self.assertIn("API key", r["message"])

    def test_bedrock_missing_credentials(self):
        r = _run(llm_probe.probe("bedrock", "", "", extra=None))
        self.assertFalse(r["ok"])
        self.assertIn("access key", r["message"])

    def test_bedrock_ok_lists_foundation_models(self):
        seen = {}

        def handler(req):
            seen["url"] = str(req.url)
            seen["has_auth"] = "Authorization" in req.headers
            return httpx.Response(200, json={"modelSummaries": [{"modelId": "anthropic.claude-sonnet-5-20260101-v1:0"}]})

        r = _run(llm_probe.probe(
            "bedrock", "", "anthropic.claude-sonnet-5-20260101-v1:0",
            client=_client(handler),
            extra={"access_key_id": "AKIAFAKE", "secret_access_key": "secret", "region": "us-west-2"},
        ))
        self.assertTrue(r["ok"])
        self.assertTrue(r["model_found"])
        self.assertFalse(r["used_server_key"])
        self.assertEqual(seen["url"], "https://bedrock.us-west-2.amazonaws.com/foundation-models")
        self.assertTrue(seen["has_auth"])  # SigV4 Authorization header present

    def test_bedrock_rejected_credentials(self):
        r = _run(llm_probe.probe(
            "bedrock", "", "",
            client=_client(lambda req: httpx.Response(403, text="AccessDenied")),
            extra={"access_key_id": "AKIAFAKE", "secret_access_key": "bad", "region": "us-east-1"},
        ))
        self.assertFalse(r["ok"])
        self.assertIn("rejected", r["message"])

    def test_bedrock_falls_back_to_server_config(self):
        with patch.object(llm_probe.scanner, "llm_env", return_value={
            "AWS_ACCESS_KEY_ID": "srv-key", "AWS_SECRET_ACCESS_KEY": "srv-secret", "AWS_REGION": "ap-south-1",
        }):
            r = _run(llm_probe.probe(
                "bedrock", "", "",
                client=_client(lambda req: httpx.Response(200, json={"modelSummaries": []})),
                extra={},
            ))
        self.assertTrue(r["ok"])
        self.assertTrue(r["used_server_key"])
        self.assertIn("ap-south-1", r["message"])


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
        # extra=None for every non-bedrock provider — only bedrock's access_key_id/
        # secret_access_key/region fields get threaded through (see test_route_passes_bedrock_extra).
        p.assert_awaited_once_with("openai", "k", "", extra=None)

    def test_route_passes_bedrock_extra(self):
        """Config tab's "Test Connection" on the Bedrock card POSTs access_key_id/
        secret_access_key/region alongside provider — the route must forward them as `extra`
        (see llm_probe._probe_bedrock) instead of silently dropping them."""
        fake = {"ok": True, "provider": "bedrock", "message": "Connected.",
                "model_found": None, "used_server_key": False}
        with patch.object(main.settings, "api_key", ""), \
                patch.object(main.llm_probe, "probe", AsyncMock(return_value=fake)) as p:
            r = self.client.post("/api/v1/llm/test", json={
                "provider": "bedrock", "access_key_id": "AKIAFAKE", "secret_access_key": "secret",
                "region": "eu-west-1",
            })
        self.assertEqual(r.status_code, 200)
        p.assert_awaited_once_with("bedrock", "", "",
                                   extra={"access_key_id": "AKIAFAKE", "secret_access_key": "secret", "region": "eu-west-1"})

    def test_route_rejects_unknown_provider(self):
        with patch.object(main.settings, "api_key", ""):
            r = self.client.post("/api/v1/llm/test", json={"provider": "gemini"})
        self.assertEqual(r.status_code, 422)


if __name__ == "__main__":
    unittest.main()
