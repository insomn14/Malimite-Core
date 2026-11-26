"""Custom Model API providers: store, resolve_llm, wire URLs/headers, probe, routes, CLI env."""
import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from web.app import llm_probe, main, scanner
from web.app.agent import llm, llm_config
from web.app.config import settings


class _Base(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = patch.object(settings, "llm_config_path", os.path.join(d.name, "llm-config.json"))
        p.start()
        self.addCleanup(p.stop)


class StoreTests(_Base):
    def test_roundtrip_keeps_key_when_blank_and_masks_status(self):
        llm_config.set_custom("opencode", name="OpenCode", base_url="https://opencode.ai/zen/v1/",
                              api_key="sk-secret-123456", models=["big-pickle", "big-pickle", " "])
        llm_config.set_custom("opencode", base_url="https://opencode.ai/zen/v1", models=["a"])
        c = llm_config.get_custom("opencode")
        self.assertEqual((c["api_key"], c["base_url"], c["models"], c["name"]),
                         ("sk-secret-123456", "https://opencode.ai/zen/v1", ["a"], "OpenCode"))
        st = llm_config.custom_status("opencode")
        self.assertNotIn("sk-secret-123456", json.dumps(st))
        self.assertTrue(st["configured"])

    def test_rejects_bad_ids_protocols_and_urls(self):
        for bad in ("", "OpenAI", "openai", "claude-oauth", "has space", "-x"):
            with self.assertRaises(ValueError, msg=bad):
                llm_config.set_custom(bad, base_url="https://x.io/v1")
        with self.assertRaises(ValueError):
            llm_config.set_custom("ok", protocol="gemini", base_url="https://x.io/v1")
        with self.assertRaises(ValueError):
            llm_config.set_custom("ok", base_url="ftp://x.io")

    def test_delete_clears_default(self):
        llm_config.set_custom("x1", base_url="http://localhost:1234/v1")
        llm_config.set_default("x1", "m")
        self.assertTrue(llm_config.delete_custom("x1"))
        self.assertEqual(llm_config.load()["default_provider"], "")


class ResolveAndWireTests(_Base):
    def test_resolve_uses_first_model_and_protocol(self):
        llm_config.set_custom("gw", protocol="anthropic", base_url="https://gw.io/v1", api_key="K", models=["m1", "m2"])
        cfg = llm.resolve_llm("none", "", "gw", None)
        self.assertEqual((cfg.provider, cfg.model, cfg.protocol, cfg.base_url), ("gw", "m1", "anthropic", "https://gw.io/v1"))
        self.assertEqual(llm.resolve_llm("gw", "m2", None, None).model, "m2")

    def test_resolve_without_model_errors(self):
        llm_config.set_custom("gw", base_url="https://gw.io/v1")
        with self.assertRaises(llm.LlmError):
            llm.resolve_llm("none", "", "gw", None)

    def test_chat_step_urls_and_auth_per_protocol(self):
        async def run(protocol):
            seen = {}

            def handler(req):
                seen["url"], seen["h"] = str(req.url), req.headers
                return httpx.Response(200, text="data: [DONE]\n\n")
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
                cfg = llm.LlmCfg("gw", "m", "KEY", "https://gw.io/v1", protocol=protocol)
                async for _ in llm.chat_step(cfg, "S", [{"role": "user", "content": [{"type": "text", "text": "hi"}]}], [], client=c):
                    pass
            return seen
        o = asyncio.run(run("openai"))
        self.assertEqual(o["url"], "https://gw.io/v1/chat/completions")
        self.assertEqual(o["h"]["authorization"], "Bearer KEY")
        a = asyncio.run(run("anthropic"))
        self.assertEqual(a["url"], "https://gw.io/v1/messages")
        self.assertEqual(a["h"]["x-api-key"], "KEY")


class HeaderTests(_Base):
    def test_opencode_gets_session_header_by_default_and_user_headers_win(self):
        llm_config.set_custom("oc", base_url="https://opencode.ai/inference/go/v1", api_key="K", models=["m"])
        cfg = llm.resolve_llm("none", "", "oc", None, session="scan-1")
        self.assertEqual(cfg.headers, {"x-opencode-session": "scan-1"})
        self.assertEqual(json.loads(scanner.llm_env("oc")["CUSTOM_HEADERS"]), {"x-opencode-session": "{session}"})
        llm_config.set_custom("gw", base_url="https://gw.io/v1", models=["m"], headers={"X-Team": "a-{session}"})
        self.assertEqual(llm.resolve_llm("none", "", "gw", None, session="s").headers, {"X-Team": "a-s"})

    def test_headers_are_sent_on_chat_step(self):
        seen = {}

        def handler(req):
            seen.update(req.headers)
            return httpx.Response(200, text="data: [DONE]\n\n")

        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
                cfg = llm.LlmCfg("gw", "m", "K", "https://gw.io/v1", protocol="openai", headers={"x-opencode-session": "abc"})
                async for _ in llm.chat_step(cfg, "S", [{"role": "user", "content": [{"type": "text", "text": "hi"}]}], [], client=c):
                    pass
        asyncio.run(run())
        self.assertEqual(seen["x-opencode-session"], "abc")

    def test_invalid_header_rejected(self):
        with self.assertRaises(ValueError):
            llm_config.set_custom("gw", base_url="https://gw.io/v1", headers={"bad name": "v"})
        with self.assertRaises(ValueError):
            llm_config.set_custom("gw", base_url="https://gw.io/v1", headers={"X": "a\nb"})


class ProbeAndEnvTests(_Base):
    def test_probe_custom_lists_models(self):
        def handler(req):
            self.assertEqual(str(req.url), "https://gw.io/v1/models")
            return httpx.Response(200, json={"data": [{"id": "a"}, {"id": "b"}]})
        c = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        r = asyncio.run(llm_probe.probe_custom("openai", "https://gw.io/v1/", "K", "a", client=c))
        self.assertTrue(r["ok"]); self.assertEqual(r["models"], ["a", "b"]); self.assertTrue(r["model_found"])

    def test_probe_custom_failures(self):
        c = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(401)))
        self.assertFalse(asyncio.run(llm_probe.probe_custom("openai", "https://gw.io/v1", "K", client=c))["ok"])
        self.assertFalse(asyncio.run(llm_probe.probe_custom("openai", "gw.io", "K"))["ok"])

    def test_cli_gets_custom_provider_and_env(self):
        llm_config.set_custom("gw", protocol="anthropic", base_url="https://gw.io/v1", api_key="K", models=["m1"])
        env = scanner.llm_env("gw")
        self.assertEqual((env["CUSTOM_PROTOCOL"], env["CUSTOM_BASE_URL"], env["CUSTOM_API_KEY"]),
                         ("anthropic", "https://gw.io/v1", "K"))
        self.assertEqual(scanner.llm_env("nope"), {})


class RouteTests(_Base):
    def setUp(self):
        super().setUp()
        self.client = TestClient(main.app)

    def test_put_list_default_delete(self):
        r = self.client.put("/api/v1/config/custom-providers/gw", json={
            "name": "GW", "protocol": "openai", "base_url": "https://gw.io/v1", "api_key": "sk-abcdef123456", "models": ["m"]})
        self.assertEqual(r.status_code, 200, r.text)
        listing = self.client.get("/api/v1/config/providers").json()
        gw = next(p for p in listing["providers"] if p["provider"] == "gw")
        self.assertTrue(gw["custom"]); self.assertNotIn("sk-abcdef123456", json.dumps(listing))
        self.assertEqual(self.client.put("/api/v1/config/default", json={"provider": "gw", "model": "m"}).status_code, 200)
        self.assertEqual(self.client.delete("/api/v1/config/providers/gw").status_code, 204)
        self.assertFalse(any(p["provider"] == "gw" for p in self.client.get("/api/v1/config/providers").json()["providers"]))

    def test_put_rejects_reserved_id(self):
        r = self.client.put("/api/v1/config/custom-providers/openai", json={"base_url": "https://gw.io/v1"})
        self.assertEqual(r.status_code, 422)


if __name__ == "__main__":
    unittest.main()
