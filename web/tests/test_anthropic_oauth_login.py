"""Tests for the Config tab's "Login with Claude" browser OAuth flow — the Claude Code-style
single-code login (web/app/agent/anthropic_oauth.py's start_login/exchange_login_code) and the
/api/v1/auth/claude-oauth/start + /exchange routes it backs.

See tests/test_llm_config.py for the unrelated Config-tab API-key providers, and
core/src/main/java/io/malimite/core/AnthropicOAuthLogin.java for the CLI-side equivalent this
mirrors (minus the local callback server — see anthropic_oauth.py's module docstring for why).
"""
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi.testclient import TestClient

from web.app import main
from web.app.agent import anthropic_oauth
from web.app.config import settings


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class StartLoginTests(unittest.TestCase):
    def setUp(self):
        anthropic_oauth._pending_logins.clear()
        self.addCleanup(anthropic_oauth._pending_logins.clear)

    def test_returns_login_id_and_authorize_url(self):
        result = anthropic_oauth.start_login()
        self.assertIn("login_id", result)
        self.assertIn("authorize_url", result)
        self.assertGreater(len(result["login_id"]), 16)

    def test_authorize_url_has_expected_params(self):
        result = anthropic_oauth.start_login()
        parsed = urlparse(result["authorize_url"])
        self.assertEqual(f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                         anthropic_oauth.AUTHORIZE_URL)
        q = parse_qs(parsed.query)
        self.assertEqual(q["client_id"][0], anthropic_oauth.CLIENT_ID)
        self.assertEqual(q["redirect_uri"][0], anthropic_oauth.REDIRECT_URI)
        self.assertEqual(q["response_type"][0], "code")
        self.assertEqual(q["code_challenge_method"][0], "S256")
        self.assertIn("code_challenge", q)
        self.assertIn("state", q)
        # scope is space-joined in the query, split back out for comparison
        self.assertEqual(q["scope"][0], anthropic_oauth.SCOPES)

    def test_each_call_gets_a_distinct_login_id_and_verifier(self):
        a = anthropic_oauth.start_login()
        b = anthropic_oauth.start_login()
        self.assertNotEqual(a["login_id"], b["login_id"])
        self.assertNotEqual(
            anthropic_oauth._pending_logins[a["login_id"]].code_verifier,
            anthropic_oauth._pending_logins[b["login_id"]].code_verifier,
        )

    def test_pending_login_recorded_with_matching_state(self):
        result = anthropic_oauth.start_login()
        pending = anthropic_oauth._pending_logins[result["login_id"]]
        q = parse_qs(urlparse(result["authorize_url"]).query)
        self.assertEqual(pending.state, q["state"][0])

    def test_expired_logins_are_pruned_on_next_start(self):
        result = anthropic_oauth.start_login()
        login_id = result["login_id"]
        anthropic_oauth._pending_logins[login_id].created_at -= anthropic_oauth._LOGIN_TTL_SECONDS + 1
        anthropic_oauth.start_login()  # triggers _prune_expired_logins()
        self.assertNotIn(login_id, anthropic_oauth._pending_logins)


class SplitCodeAndStateTests(unittest.TestCase):
    """Parser for whatever the operator pastes back — mirrors
    AnthropicOAuthLogin.java's parseManualInput()."""

    def test_code_hash_state_format(self):
        # The exact shape Anthropic's code-display page hands back (see module docstring and
        # the screenshot this feature was built from): "<code>#<state>" as one string.
        code, state = anthropic_oauth._split_code_and_state("xuABC123#the-state-value", "the-state-value")
        self.assertEqual(code, "xuABC123")
        self.assertEqual(state, "the-state-value")

    def test_full_callback_url(self):
        code, state = anthropic_oauth._split_code_and_state(
            "https://platform.claude.com/oauth/code/callback?code=xuABC123&state=the-state-value",
            "the-state-value")
        self.assertEqual(code, "xuABC123")
        self.assertEqual(state, "the-state-value")

    def test_bare_code_equals_fragment(self):
        code, state = anthropic_oauth._split_code_and_state(
            "code=xuABC123&state=the-state-value", "the-state-value")
        self.assertEqual(code, "xuABC123")
        self.assertEqual(state, "the-state-value")

    def test_bare_code_with_no_state_falls_back_to_expected(self):
        code, state = anthropic_oauth._split_code_and_state("xuABC123", "expected-state")
        self.assertEqual(code, "xuABC123")
        self.assertEqual(state, "expected-state")

    def test_surrounding_whitespace_is_trimmed(self):
        code, state = anthropic_oauth._split_code_and_state(
            "  xuABC123#the-state-value  \n", "the-state-value")
        self.assertEqual(code, "xuABC123")
        self.assertEqual(state, "the-state-value")

    def test_empty_input_raises(self):
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError):
            anthropic_oauth._split_code_and_state("   ", "expected-state")


class ExchangeLoginCodeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._patch = patch.object(settings, "anthropic_oauth_path",
                                   os.path.join(self._tmpdir.name, "anthropic-oauth.json"))
        self._patch.start()
        self.addCleanup(self._patch.stop)
        anthropic_oauth._pending_logins.clear()
        self.addCleanup(anthropic_oauth._pending_logins.clear)

    async def test_unknown_login_id_rejected(self):
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code("does-not-exist", "code#state")
        self.assertIn("expired", str(ctx.exception).lower())

    async def test_successful_exchange_persists_credential_and_sends_expected_request(self):
        start = anthropic_oauth.start_login()
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        seen = {}

        def handler(req):
            import json as _json
            seen.update(_json.loads(req.content))
            return httpx.Response(200, json={
                "access_token": "sk-ant-oat01-newtoken",
                "refresh_token": "sk-ant-ort01-newrefresh",
                "expires_in": 3600,
            })

        result = await anthropic_oauth.exchange_login_code(
            login_id, f"xu-fake-code#{pending.state}", client=_client(handler))

        self.assertTrue(result.changed)
        self.assertEqual(seen["grant_type"], "authorization_code")
        self.assertEqual(seen["client_id"], anthropic_oauth.CLIENT_ID)
        self.assertEqual(seen["code"], "xu-fake-code")
        self.assertEqual(seen["state"], pending.state)
        self.assertEqual(seen["redirect_uri"], anthropic_oauth.REDIRECT_URI)
        self.assertEqual(seen["code_verifier"], pending.code_verifier)

        saved = anthropic_oauth._load()
        self.assertEqual(saved.access_token, "sk-ant-oat01-newtoken")
        self.assertEqual(saved.refresh_token, "sk-ant-ort01-newrefresh")

    async def test_login_id_is_single_use(self):
        start = anthropic_oauth.start_login()
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(200, json={
            "access_token": "sk-ant-oat01-a", "refresh_token": "sk-ant-ort01-a", "expires_in": 3600,
        }))
        await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError):
            await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)

    async def test_state_mismatch_rejected_and_login_consumed(self):
        start = anthropic_oauth.start_login()
        login_id = start["login_id"]
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code(login_id, "code#totally-wrong-state")
        self.assertIn("state mismatch", str(ctx.exception).lower())
        # Consumed even on a rejected attempt — no replay with a corrected state.
        self.assertNotIn(login_id, anthropic_oauth._pending_logins)

    async def test_anthropic_rejects_code_surfaces_clear_error(self):
        start = anthropic_oauth.start_login()
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(400, json={"error": "invalid_grant"}))
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code(login_id, f"bad-code#{pending.state}", client=client)
        self.assertIn("400", str(ctx.exception))

    async def test_network_error_surfaces_clear_error(self):
        start = anthropic_oauth.start_login()
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]

        def handler(req):
            raise httpx.ConnectError("boom")

        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=_client(handler))
        self.assertIn("ConnectError", str(ctx.exception))

    async def test_malformed_token_response_surfaces_clear_error(self):
        start = anthropic_oauth.start_login()
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(200, json={"unexpected": "shape"}))
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError):
            await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)

    async def test_changed_is_false_when_access_token_is_identical_to_stored(self):
        anthropic_oauth._save(anthropic_oauth._Credential("sk-ant-oat01-same", "sk-ant-ort01-x", 99999999999999))
        start = anthropic_oauth.start_login()
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(200, json={
            "access_token": "sk-ant-oat01-same", "refresh_token": "sk-ant-ort01-new", "expires_in": 3600,
        }))
        result = await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)
        self.assertFalse(result.changed)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._patches = [
            patch.object(main.settings, "api_key", ""),
            patch.object(settings, "anthropic_oauth_path", os.path.join(self._tmpdir.name, "anthropic-oauth.json")),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        anthropic_oauth._pending_logins.clear()
        self.addCleanup(anthropic_oauth._pending_logins.clear)
        self.client = TestClient(main.app)

    def test_start_route_returns_login_id_and_url(self):
        r = self.client.post("/api/v1/auth/claude-oauth/start")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("login_id", body)
        self.assertIn(anthropic_oauth.AUTHORIZE_URL, body["authorize_url"])

    def test_exchange_route_rejects_unknown_login_id(self):
        r = self.client.post("/api/v1/auth/claude-oauth/exchange",
                             json={"login_id": "bogus", "code": "code#state"})
        self.assertEqual(r.status_code, 422)

    def test_exchange_route_delegates_to_module(self):
        start = self.client.post("/api/v1/auth/claude-oauth/start").json()
        fake = anthropic_oauth.ImportResult(changed=True, fingerprint="sk-ant-oat...xyz")
        with patch.object(anthropic_oauth, "exchange_login_code") as mocked:
            async def _fake(*a, **kw):
                return fake
            mocked.side_effect = _fake
            r = self.client.post("/api/v1/auth/claude-oauth/exchange",
                                 json={"login_id": start["login_id"], "code": "xu-code#state"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"ok": True, "changed": True, "token_fingerprint": "sk-ant-oat...xyz"})
        mocked.assert_called_once_with(start["login_id"], "xu-code#state")

    def test_old_import_token_route_no_longer_exists(self):
        r = self.client.post("/api/v1/auth/claude-oauth/import-token",
                             json={"access_token": "x", "refresh_token": "y", "expires_at_ms": 1})
        self.assertEqual(r.status_code, 404)

    def test_status_route_still_works(self):
        r = self.client.get("/api/v1/auth/claude-oauth/status")
        self.assertEqual(r.status_code, 200)
        self.assertIn("configured", r.json())

    def test_requires_auth_when_api_key_set(self):
        with patch.object(main.settings, "api_key", "secret-server-key"):
            r = self.client.post("/api/v1/auth/claude-oauth/start")
        self.assertEqual(r.status_code, 401)

    def test_config_provider_post_points_to_new_endpoints(self):
        r = self.client.post("/api/v1/config/providers/claude-oauth", json={"api_key": "x"})
        self.assertEqual(r.status_code, 422)
        self.assertIn("/start", r.json()["detail"])
        self.assertIn("/exchange", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
