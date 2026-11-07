"""Tests for the Config tab's persistent credential store (web/app/agent/llm_config.py) and the
/api/v1/config/* routes it backs. See tests/test_llm_probe.py for the "Test Connection" probe
and tests/test_scanner_cli_cmd.py for how scanner.llm_env() (resolved on top of this module)
feeds the spawned CLI subprocess.
"""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import main
from web.app.agent import llm_config
from web.app.config import settings


class LlmConfigStoreTests(unittest.TestCase):
    """Direct tests of the module's load/save/effective_fields logic — no HTTP involved."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.path = os.path.join(self._tmpdir.name, "llm-config.json")
        self._patch = patch.object(settings, "llm_config_path", self.path)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        # Isolate from whatever the real server's .env happens to have set, so these tests are
        # deterministic regardless of which machine/CI runner executes them.
        self._env_patches = [
            patch.object(settings, "openai_api_key", ""),
            patch.object(settings, "anthropic_api_key", ""),
            patch.object(settings, "deepseek_api_key", ""),
            patch.object(settings, "deepseek_base_url", "https://api.deepseek.com"),
            patch.object(settings, "ollama_base_url", "http://localhost:11434"),
            patch.object(settings, "aws_access_key_id", ""),
            patch.object(settings, "aws_secret_access_key", ""),
            patch.object(settings, "aws_region", "us-east-1"),
            patch.object(settings, "bedrock_model_id", ""),
            patch.object(settings, "glm_api_key", ""),
            patch.object(settings, "glm_base_url", "https://open.bigmodel.cn/api/paas/v4"),
        ]
        for p in self._env_patches:
            p.start()
            self.addCleanup(p.stop)

    def test_empty_store_reports_unconfigured(self):
        self.assertEqual(llm_config.load(), {"default_provider": "", "default_model": "", "providers": {}})
        self.assertFalse(llm_config.is_configured("openai"))
        self.assertFalse(llm_config.is_configured("claude"))
        self.assertFalse(llm_config.is_configured("deepseek"))
        self.assertFalse(llm_config.is_configured("bedrock"))
        self.assertFalse(llm_config.is_configured("glm"))

    def test_ollama_is_always_configured(self):
        # No secret required; a local Ollama instance with no stored config still "works" from
        # the upload form's point of view (see effective_fields' OLLAMA_BASE_URL default).
        self.assertTrue(llm_config.is_configured("ollama"))

    def test_set_and_get_provider_round_trips(self):
        stored = llm_config.set_provider("openai", api_key="sk-abc123456789")
        self.assertEqual(stored["api_key"], "sk-abc123456789")
        self.assertIn("updated_at", stored)
        self.assertTrue(llm_config.is_configured("openai"))
        self.assertEqual(llm_config.effective_fields("openai")["api_key"], "sk-abc123456789")

    def test_set_provider_merges_partial_updates(self):
        llm_config.set_provider("deepseek", api_key="sk-first", base_url="https://custom.example")
        llm_config.set_provider("deepseek", api_key="sk-rotated")  # base_url omitted
        fields = llm_config.effective_fields("deepseek")
        self.assertEqual(fields["api_key"], "sk-rotated")
        self.assertEqual(fields["base_url"], "https://custom.example")  # untouched by the partial update

    def test_set_provider_blank_fields_are_dropped_not_stored(self):
        llm_config.set_provider("openai", api_key="sk-real", base_url="   ")
        entry = llm_config.get_provider("openai")
        self.assertNotIn("base_url", entry)

    def test_set_provider_unknown_raises(self):
        with self.assertRaises(ValueError):
            llm_config.set_provider("not-a-real-provider", api_key="x")

    def test_bedrock_requires_both_access_key_and_secret(self):
        llm_config.set_provider("bedrock", access_key_id="AKIAFAKE")
        self.assertFalse(llm_config.is_configured("bedrock"))
        llm_config.set_provider("bedrock", secret_access_key="shh")
        self.assertTrue(llm_config.is_configured("bedrock"))

    def test_delete_provider(self):
        llm_config.set_provider("claude", api_key="sk-ant-x")
        self.assertTrue(llm_config.delete_provider("claude"))
        self.assertFalse(llm_config.is_configured("claude"))
        self.assertFalse(llm_config.delete_provider("claude"))  # already gone

    def test_env_fallback_used_when_nothing_stored(self):
        with patch.object(settings, "openai_api_key", "sk-from-env"):
            self.assertTrue(llm_config.is_configured("openai"))
            self.assertEqual(llm_config.effective_fields("openai")["api_key"], "sk-from-env")

    def test_stored_value_wins_over_env_fallback(self):
        with patch.object(settings, "openai_api_key", "sk-from-env"):
            llm_config.set_provider("openai", api_key="sk-from-ui")
            self.assertEqual(llm_config.effective_fields("openai")["api_key"], "sk-from-ui")

    def test_provider_status_never_echoes_raw_secret(self):
        llm_config.set_provider("openai", api_key="sk-supersecretvalue")
        status = llm_config.provider_status("openai")
        self.assertNotIn("sk-supersecretvalue", json.dumps(status))
        self.assertTrue(status["masked"]["api_key"].startswith("sk-s"))
        self.assertIn("...", status["masked"]["api_key"])
        self.assertEqual(status["source"], "ui")
        self.assertTrue(status["configured"])

    def test_provider_status_source_env_vs_ui_vs_none(self):
        self.assertEqual(llm_config.provider_status("deepseek")["source"], "none")
        with patch.object(settings, "deepseek_api_key", "sk-env"):
            self.assertEqual(llm_config.provider_status("deepseek")["source"], "env")
        llm_config.set_provider("deepseek", api_key="sk-ui")
        self.assertEqual(llm_config.provider_status("deepseek")["source"], "ui")

    def test_set_default_and_load(self):
        llm_config.set_default("claude", "claude-sonnet-5")
        data = llm_config.load()
        self.assertEqual(data["default_provider"], "claude")
        self.assertEqual(data["default_model"], "claude-sonnet-5")
        llm_config.set_default()  # no args clears it
        data = llm_config.load()
        self.assertEqual(data["default_provider"], "")

    def test_file_is_written_with_restrictive_permissions(self):
        llm_config.set_provider("openai", api_key="sk-x")
        mode = stat.S_IMODE(os.stat(settings.llm_config_path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_corrupted_file_falls_back_to_empty(self):
        Path(settings.llm_config_path).parent.mkdir(parents=True, exist_ok=True)
        Path(settings.llm_config_path).write_text("not valid json {{{")
        self.assertEqual(llm_config.load(), {"default_provider": "", "default_model": "", "providers": {}})


class ScannerLlmEnvIntegrationTests(unittest.TestCase):
    """scanner.llm_env() is the single point that resolves llm_config into the env-var shape
    the CLI subprocess (and llm.py's resolve_llm) actually consume — see scanner.py's llm_env
    docstring for the full priority order (per_req_key > Config tab > server .env bootstrap)."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._patch = patch.object(settings, "llm_config_path", os.path.join(self._tmpdir.name, "llm-config.json"))
        self._patch.start()
        self.addCleanup(self._patch.stop)
        for field, value in [
            ("openai_api_key", ""), ("anthropic_api_key", ""), ("deepseek_api_key", ""),
            ("aws_access_key_id", ""), ("aws_secret_access_key", ""), ("aws_region", "us-east-1"),
            ("glm_api_key", ""),
        ]:
            p = patch.object(settings, field, value)
            p.start()
            self.addCleanup(p.stop)

    def test_llm_env_reads_config_tab_openai_key(self):
        from web.app import scanner
        llm_config.set_provider("openai", api_key="sk-from-config-tab")
        env = scanner.llm_env("openai")
        self.assertEqual(env["OPENAI_API_KEY"], "sk-from-config-tab")

    def test_llm_env_per_request_key_overrides_config_tab(self):
        from web.app import scanner
        llm_config.set_provider("openai", api_key="sk-from-config-tab")
        env = scanner.llm_env("openai", "sk-per-request-override")
        self.assertEqual(env["OPENAI_API_KEY"], "sk-per-request-override")

    def test_llm_env_bedrock_includes_region_and_model(self):
        from web.app import scanner
        llm_config.set_provider("bedrock", access_key_id="AKIAFAKE", secret_access_key="shh",
                                region="eu-central-1", model_id="anthropic.claude-opus-5-20260101-v1:0")
        env = scanner.llm_env("bedrock")
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "AKIAFAKE")
        self.assertEqual(env["AWS_SECRET_ACCESS_KEY"], "shh")
        self.assertEqual(env["AWS_REGION"], "eu-central-1")
        self.assertEqual(env["BEDROCK_MODEL_ID"], "anthropic.claude-opus-5-20260101-v1:0")

    def test_llm_env_glm_includes_base_url(self):
        from web.app import scanner
        llm_config.set_provider("glm", api_key="glm-key", base_url="https://example.test/v4")
        env = scanner.llm_env("glm")
        self.assertEqual(env["GLM_API_KEY"], "glm-key")
        self.assertEqual(env["GLM_BASE_URL"], "https://example.test/v4")


class ConfigRouteTests(unittest.TestCase):
    """HTTP-level tests for /api/v1/config/* — see tests/test_llm_probe.py for /api/v1/llm/test."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._patches = [
            patch.object(main.settings, "api_key", ""),
            patch.object(settings, "llm_config_path", os.path.join(self._tmpdir.name, "llm-config.json")),
            patch.object(settings, "openai_api_key", ""),
            patch.object(settings, "anthropic_api_key", ""),
            patch.object(settings, "deepseek_api_key", ""),
            patch.object(settings, "aws_access_key_id", ""),
            patch.object(settings, "aws_secret_access_key", ""),
            patch.object(settings, "glm_api_key", ""),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = TestClient(main.app)

    def test_list_providers_includes_every_known_provider_plus_oauth(self):
        r = self.client.get("/api/v1/config/providers")
        self.assertEqual(r.status_code, 200)
        names = {p["provider"] for p in r.json()["providers"]}
        self.assertEqual(names, {"openai", "claude", "claude-oauth", "deepseek", "ollama", "bedrock", "glm"})

    def test_post_then_get_reflects_configured_status(self):
        r = self.client.post("/api/v1/config/providers/openai", json={"api_key": "sk-abc123456789"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["status"]["configured"])

        r = self.client.get("/api/v1/config/providers")
        openai_status = next(p for p in r.json()["providers"] if p["provider"] == "openai")
        self.assertTrue(openai_status["configured"])
        self.assertNotIn("sk-abc123456789", json.dumps(r.json()))

    def test_post_unknown_provider_422(self):
        r = self.client.post("/api/v1/config/providers/gemini-3", json={"api_key": "x"})
        self.assertEqual(r.status_code, 422)

    def test_post_claude_oauth_rejected(self):
        r = self.client.post("/api/v1/config/providers/claude-oauth", json={"api_key": "x"})
        self.assertEqual(r.status_code, 422)

    def test_delete_provider(self):
        self.client.post("/api/v1/config/providers/claude", json={"api_key": "sk-ant-x"})
        r = self.client.delete("/api/v1/config/providers/claude")
        self.assertEqual(r.status_code, 204)
        status = next(p for p in self.client.get("/api/v1/config/providers").json()["providers"]
                      if p["provider"] == "claude")
        self.assertFalse(status["configured"])

    def test_set_default(self):
        r = self.client.put("/api/v1/config/default", json={"provider": "deepseek", "model": "deepseek-flash"})
        self.assertEqual(r.status_code, 200)
        body = self.client.get("/api/v1/config/providers").json()
        self.assertEqual(body["default_provider"], "deepseek")
        self.assertEqual(body["default_model"], "deepseek-flash")

    def test_set_default_unknown_provider_422(self):
        r = self.client.put("/api/v1/config/default", json={"provider": "not-real", "model": ""})
        self.assertEqual(r.status_code, 422)

    def test_requires_auth_when_api_key_set(self):
        with patch.object(main.settings, "api_key", "secret-server-key"):
            r = self.client.get("/api/v1/config/providers")
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
