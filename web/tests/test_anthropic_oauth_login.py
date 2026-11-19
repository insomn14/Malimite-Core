"""Tests for the Config tab's "Login with Claude" browser OAuth flow —
web/app/agent/anthropic_oauth.py's start_login/login_status/exchange_login_code — and the
/api/v1/auth/claude-oauth/start + /login-status + /exchange routes they back.

Two redirect strategies, tried in order by start_login(): LOCAL_REDIRECT_URI (a loopback HTTP
listener this process opens, same host/port AnthropicOAuthLogin.java/`claude /login` use — no
copy/paste needed, the Config tab just polls login_status()) and REMOTE_REDIRECT_URI (Anthropic's
own code-display page, used only when the local bind fails) — see the module's own docstring for
why the remote path triggers Anthropic's extra 6-digit email verification and the local path
does not.

See tests/test_llm_config.py for the unrelated Config-tab API-key providers, and
core/src/main/java/io/malimite/core/AnthropicOAuthLogin.java for the CLI-side equivalent this
mirrors.
"""
import asyncio
import os
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx

from web.app import main
from web.app.agent import anthropic_oauth
from web.app.config import settings


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _send_callback(port: int, code: str, state: str = None, error: str = None) -> bytes:
    """Opens a raw TCP connection to the local listener and sends one GET /callback request,
    mimicking what the operator's browser does on Anthropic's redirect. Returns the raw
    response bytes (status line + headers + body) for assertions on the page shown to them.
    """
    params = []
    if code is not None:
        params.append(f"code={code}")
    if state is not None:
        params.append(f"state={state}")
    if error is not None:
        params.append(f"error={error}")
    query = "&".join(params)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET /callback?{query} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    await writer.drain()
    resp = await reader.read(8192)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return resp


class _OAuthTestCase(unittest.IsolatedAsyncioTestCase):
    """Shared setup: isolated credential path, isolated port (avoids colliding with a real
    `claude /login`/AnthropicOAuthLogin.java session that might be using the real 53692 on the
    machine actually running these tests), and pending-login cleanup between tests."""

    PORT = 54400  # overridden per subclass/test group below to avoid any cross-test collision

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self._path_patch = patch.object(settings, "anthropic_oauth_path",
                                        os.path.join(self._tmpdir.name, "anthropic-oauth.json"))
        self._path_patch.start()
        self.addCleanup(self._path_patch.stop)
        self._port_patch = patch.object(anthropic_oauth, "LOCAL_CALLBACK_PORT", self.PORT)
        self._port_patch.start()
        self.addCleanup(self._port_patch.stop)
        anthropic_oauth._pending_logins.clear()
        self.addCleanup(anthropic_oauth._pending_logins.clear)

    async def asyncTearDown(self):
        # Close any listener a test left bound — the next test class picks a different PORT,
        # but leaked listeners within the same port range would still fail oddly if cleanup is
        # ever skipped by an assertion failure mid-test.
        for pending in list(anthropic_oauth._pending_logins.values()):
            await pending.close_server()


class StartLoginLocalModeTests(_OAuthTestCase):
    PORT = 54401

    async def test_defaults_to_local_mode_on_a_free_port(self):
        result = await anthropic_oauth.start_login()
        self.assertEqual(result["mode"], "local")
        pending = anthropic_oauth._pending_logins[result["login_id"]]
        self.assertIsNotNone(pending.server)
        self.assertEqual(pending.redirect_uri, anthropic_oauth.LOCAL_REDIRECT_URI)

    async def test_authorize_url_uses_local_redirect_uri(self):
        result = await anthropic_oauth.start_login()
        q = parse_qs(urlparse(result["authorize_url"]).query)
        self.assertEqual(q["redirect_uri"][0], anthropic_oauth.LOCAL_REDIRECT_URI)
        self.assertEqual(q["client_id"][0], anthropic_oauth.CLIENT_ID)
        self.assertEqual(q["code_challenge_method"][0], "S256")
        self.assertIn("code_challenge", q)
        self.assertEqual(q["state"][0], anthropic_oauth._pending_logins[result["login_id"]].state)

    async def test_explicit_local_false_skips_straight_to_remote(self):
        result = await anthropic_oauth.start_login(local=False)
        self.assertEqual(result["mode"], "remote")
        pending = anthropic_oauth._pending_logins[result["login_id"]]
        self.assertIsNone(pending.server)
        self.assertEqual(pending.redirect_uri, anthropic_oauth.REMOTE_REDIRECT_URI)

    async def test_falls_back_to_remote_when_port_already_bound(self):
        # Occupy the port ourselves first, as a stand-in for "another AnthropicOAuthLogin.java
        # CLI login or a concurrent Malimite login is already using it".
        blocker = await asyncio.start_server(lambda r, w: None,
                                             host=anthropic_oauth.LOCAL_CALLBACK_HOST,
                                             port=anthropic_oauth.LOCAL_CALLBACK_PORT)
        try:
            result = await anthropic_oauth.start_login()
            self.assertEqual(result["mode"], "remote")
        finally:
            blocker.close()
            await blocker.wait_closed()

    async def test_each_call_gets_a_distinct_login_id_and_verifier(self):
        a = await anthropic_oauth.start_login(local=False)
        b = await anthropic_oauth.start_login(local=False)
        self.assertNotEqual(a["login_id"], b["login_id"])
        self.assertNotEqual(
            anthropic_oauth._pending_logins[a["login_id"]].code_verifier,
            anthropic_oauth._pending_logins[b["login_id"]].code_verifier,
        )


class LoginStatusLocalCallbackTests(_OAuthTestCase):
    PORT = 54402

    async def test_waiting_before_any_callback(self):
        result = await anthropic_oauth.start_login()
        status = await anthropic_oauth.login_status(result["login_id"])
        self.assertEqual(status, {"state": "waiting", "mode": "local"})

    async def test_remote_mode_reports_waiting_remote_not_pollable_to_done(self):
        result = await anthropic_oauth.start_login(local=False)
        status = await anthropic_oauth.login_status(result["login_id"])
        self.assertEqual(status, {"state": "waiting", "mode": "remote"})

    async def test_unknown_login_id_reports_not_found(self):
        status = await anthropic_oauth.login_status("does-not-exist")
        self.assertEqual(status, {"state": "not_found"})

    async def test_successful_callback_auto_exchanges_and_persists(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        seen = {}

        def handler(req):
            import json as _json
            seen.update(_json.loads(req.content))
            return httpx.Response(200, json={
                "access_token": "sk-ant-oat01-local", "refresh_token": "sk-ant-ort01-local",
                "expires_in": 3600,
            })

        resp_bytes = await _send_callback(self.PORT, "the-code", pending.state)
        self.assertIn(b"200", resp_bytes.split(b"\r\n")[0])

        with patch.object(httpx, "AsyncClient", return_value=_client(handler)):
            status = await anthropic_oauth.login_status(login_id)

        self.assertEqual(status["state"], "done")
        self.assertTrue(status["ok"])
        self.assertTrue(status["changed"])
        self.assertEqual(seen["code"], "the-code")
        self.assertEqual(seen["state"], pending.state)
        self.assertEqual(seen["redirect_uri"], anthropic_oauth.LOCAL_REDIRECT_URI)
        self.assertEqual(seen["code_verifier"], pending.code_verifier)

        saved = anthropic_oauth._load()
        self.assertEqual(saved.access_token, "sk-ant-oat01-local")

    async def test_login_id_consumed_after_done(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        await _send_callback(self.PORT, "the-code", pending.state)
        client = _client(lambda req: httpx.Response(200, json={
            "access_token": "a", "refresh_token": "b", "expires_in": 3600,
        }))
        with patch.object(httpx, "AsyncClient", return_value=client):
            await anthropic_oauth.login_status(login_id)
        status2 = await anthropic_oauth.login_status(login_id)
        self.assertEqual(status2, {"state": "not_found"})

    async def test_state_mismatch_reports_done_not_ok(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        resp_bytes = await _send_callback(self.PORT, "the-code", "totally-wrong-state")
        self.assertIn(b"400", resp_bytes.split(b"\r\n")[0])
        status = await anthropic_oauth.login_status(login_id)
        self.assertEqual(status["state"], "done")
        self.assertFalse(status["ok"])

    async def test_anthropic_error_param_reports_done_not_ok(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        resp_bytes = await _send_callback(self.PORT, code=None, state=pending.state, error="access_denied")
        self.assertIn(b"400", resp_bytes.split(b"\r\n")[0])
        status = await anthropic_oauth.login_status(login_id)
        self.assertEqual(status["state"], "done")
        self.assertFalse(status["ok"])

    async def test_anthropic_rejecting_the_code_at_exchange_time_reports_done_not_ok(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        await _send_callback(self.PORT, "bad-code", pending.state)
        client = _client(lambda req: httpx.Response(400, json={"error": "invalid_grant"}))
        with patch.object(httpx, "AsyncClient", return_value=client):
            status = await anthropic_oauth.login_status(login_id)
        self.assertEqual(status["state"], "done")
        self.assertFalse(status["ok"])
        self.assertIn("400", status["error"])

    async def test_unrelated_request_to_the_listener_returns_404(self):
        result = await anthropic_oauth.start_login()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.PORT)
        writer.write(b"GET /not-the-callback-path HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        resp = await reader.read(4096)
        writer.close()
        self.assertIn(b"404", resp.split(b"\r\n")[0])
        # The pending login is untouched by an unrelated request to the listener.
        status = await anthropic_oauth.login_status(result["login_id"])
        self.assertEqual(status, {"state": "waiting", "mode": "local"})


class CancelLoginTests(_OAuthTestCase):
    """cancel_login() — backs the Config tab's "Cancel" button, releasing a local-listener
    login's port immediately rather than waiting out its TTL/the background sweep."""

    PORT = 54405

    async def test_cancel_removes_pending_login_and_frees_the_port(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        self.assertIn(login_id, anthropic_oauth._pending_logins)

        cancelled = await anthropic_oauth.cancel_login(login_id)
        self.assertTrue(cancelled)
        self.assertNotIn(login_id, anthropic_oauth._pending_logins)

        # The port must be immediately re-bindable — not just eventually, after some TTL.
        s2 = await asyncio.start_server(lambda r, w: None, host="127.0.0.1", port=self.PORT)
        s2.close()
        await s2.wait_closed()

    async def test_cancel_remote_mode_login_is_a_no_op_server_side_but_still_succeeds(self):
        result = await anthropic_oauth.start_login(local=False)
        login_id = result["login_id"]
        cancelled = await anthropic_oauth.cancel_login(login_id)
        self.assertTrue(cancelled)
        self.assertNotIn(login_id, anthropic_oauth._pending_logins)

    async def test_cancel_unknown_login_id_returns_false_not_an_error(self):
        cancelled = await anthropic_oauth.cancel_login("does-not-exist")
        self.assertFalse(cancelled)

    async def test_cancelled_login_id_is_not_pollable_afterward(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        await anthropic_oauth.cancel_login(login_id)
        status = await anthropic_oauth.login_status(login_id)
        self.assertEqual(status, {"state": "not_found"})


class PruneLoopTests(_OAuthTestCase):
    """_prune_expired_logins() / start_prune_loop() — the background sweep that closes
    listeners left dangling by an abandoned or reloaded-mid-login Config tab, independent of
    whether any other request happens to trigger a prune (see module docstring/comments for the
    real incident this was built to fix: a reload mid-login left the server-side listener bound
    to port 53692 for the FULL old 10-minute TTL with nothing polling it anymore)."""

    PORT = 54406

    async def test_expired_local_login_is_pruned_and_port_freed(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        anthropic_oauth._pending_logins[login_id].created_at -= anthropic_oauth._LOCAL_LOGIN_TTL_SECONDS + 1

        await anthropic_oauth._prune_expired_logins()

        self.assertNotIn(login_id, anthropic_oauth._pending_logins)
        s2 = await asyncio.start_server(lambda r, w: None, host="127.0.0.1", port=self.PORT)
        s2.close()
        await s2.wait_closed()

    async def test_not_yet_expired_login_survives_a_prune_sweep(self):
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        await anthropic_oauth._prune_expired_logins()
        self.assertIn(login_id, anthropic_oauth._pending_logins)

    async def test_local_and_remote_logins_use_different_ttls(self):
        local_result = await anthropic_oauth.start_login()
        remote_result = await anthropic_oauth.start_login(local=False)
        local_pending = anthropic_oauth._pending_logins[local_result["login_id"]]
        remote_pending = anthropic_oauth._pending_logins[remote_result["login_id"]]

        # Aged past the LOCAL ttl but not the (longer) REMOTE ttl.
        age = anthropic_oauth._LOCAL_LOGIN_TTL_SECONDS + 1
        self.assertLess(age, anthropic_oauth._REMOTE_LOGIN_TTL_SECONDS)
        local_pending.created_at -= age
        remote_pending.created_at -= age

        self.assertTrue(local_pending.is_expired)
        self.assertFalse(remote_pending.is_expired)

    async def test_background_loop_closes_an_expired_listener_without_any_other_request(self):
        """The actual regression this fixes: nothing but the loop itself drives the prune —
        no /start, /login-status, or /exchange call happens in this test at all."""
        result = await anthropic_oauth.start_login()
        login_id = result["login_id"]
        anthropic_oauth._pending_logins[login_id].created_at -= anthropic_oauth._LOCAL_LOGIN_TTL_SECONDS + 1

        task = asyncio.create_task(anthropic_oauth.start_prune_loop())
        try:
            # The loop's own sleep is _PRUNE_SWEEP_INTERVAL_SECONDS; poll briefly for the
            # prune to land rather than sleeping the full interval in this test.
            for _ in range(50):
                if login_id not in anthropic_oauth._pending_logins:
                    break
                await asyncio.sleep(0.02)
            self.assertNotIn(login_id, anthropic_oauth._pending_logins)
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


class SplitCodeAndStateTests(unittest.TestCase):
    """Parser for whatever the operator pastes back on the remote (copy-paste) path — mirrors
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


class ExchangeLoginCodeRemoteModeTests(_OAuthTestCase):
    """exchange_login_code() — the manual-paste path. Exercised with local=False starts so the
    test never depends on a real listener; see LoginStatusLocalCallbackTests for the local path's
    OWN exchange (triggered automatically through login_status(), not this function)."""

    PORT = 54403

    async def test_unknown_login_id_rejected(self):
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code("does-not-exist", "code#state")
        self.assertIn("expired", str(ctx.exception).lower())

    async def test_successful_exchange_persists_credential_and_sends_expected_request(self):
        start = await anthropic_oauth.start_login(local=False)
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
        self.assertEqual(seen["redirect_uri"], anthropic_oauth.REMOTE_REDIRECT_URI)
        self.assertEqual(seen["code_verifier"], pending.code_verifier)

        saved = anthropic_oauth._load()
        self.assertEqual(saved.access_token, "sk-ant-oat01-newtoken")
        self.assertEqual(saved.refresh_token, "sk-ant-ort01-newrefresh")

    async def test_login_id_is_single_use(self):
        start = await anthropic_oauth.start_login(local=False)
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(200, json={
            "access_token": "sk-ant-oat01-a", "refresh_token": "sk-ant-ort01-a", "expires_in": 3600,
        }))
        await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError):
            await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)

    async def test_state_mismatch_rejected_and_login_consumed(self):
        start = await anthropic_oauth.start_login(local=False)
        login_id = start["login_id"]
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code(login_id, "code#totally-wrong-state")
        self.assertIn("state mismatch", str(ctx.exception).lower())
        self.assertNotIn(login_id, anthropic_oauth._pending_logins)

    async def test_anthropic_rejects_code_surfaces_clear_error(self):
        start = await anthropic_oauth.start_login(local=False)
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(400, json={"error": "invalid_grant"}))
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code(login_id, f"bad-code#{pending.state}", client=client)
        self.assertIn("400", str(ctx.exception))

    async def test_network_error_surfaces_clear_error(self):
        start = await anthropic_oauth.start_login(local=False)
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]

        def handler(req):
            raise httpx.ConnectError("boom")

        with self.assertRaises(anthropic_oauth.AnthropicOAuthError) as ctx:
            await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=_client(handler))
        self.assertIn("ConnectError", str(ctx.exception))

    async def test_malformed_token_response_surfaces_clear_error(self):
        start = await anthropic_oauth.start_login(local=False)
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(200, json={"unexpected": "shape"}))
        with self.assertRaises(anthropic_oauth.AnthropicOAuthError):
            await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)

    async def test_changed_is_false_when_access_token_is_identical_to_stored(self):
        anthropic_oauth._save(anthropic_oauth._Credential("sk-ant-oat01-same", "sk-ant-ort01-x", 99999999999999))
        start = await anthropic_oauth.start_login(local=False)
        login_id = start["login_id"]
        pending = anthropic_oauth._pending_logins[login_id]
        client = _client(lambda req: httpx.Response(200, json={
            "access_token": "sk-ant-oat01-same", "refresh_token": "sk-ant-ort01-new", "expires_in": 3600,
        }))
        result = await anthropic_oauth.exchange_login_code(login_id, f"code#{pending.state}", client=client)
        self.assertFalse(result.changed)


class RouteTests(_OAuthTestCase):
    PORT = 54404

    def setUp(self):
        super().setUp()
        self._api_key_patch = patch.object(main.settings, "api_key", "")
        self._api_key_patch.start()
        self.addCleanup(self._api_key_patch.stop)
        self._transport = httpx.ASGITransport(app=main.app)

    def _client(self):
        return httpx.AsyncClient(transport=self._transport, base_url="http://test")

    async def test_start_route_returns_login_id_and_local_mode_url(self):
        async with self._client() as c:
            r = await c.post("/api/v1/auth/claude-oauth/start")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("login_id", body)
        self.assertEqual(body["mode"], "local")
        q = parse_qs(urlparse(body["authorize_url"]).query)
        self.assertEqual(q["redirect_uri"][0], anthropic_oauth.LOCAL_REDIRECT_URI)

    async def test_start_route_honors_explicit_local_false(self):
        async with self._client() as c:
            r = await c.post("/api/v1/auth/claude-oauth/start", json={"local": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["mode"], "remote")

    async def test_login_status_route_round_trip(self):
        async with self._client() as c:
            start = (await c.post("/api/v1/auth/claude-oauth/start")).json()
            login_id = start["login_id"]

            r = await c.get("/api/v1/auth/claude-oauth/login-status", params={"login_id": login_id})
            self.assertEqual(r.json(), {"state": "waiting", "mode": "local"})

            pending = anthropic_oauth._pending_logins[login_id]
            await _send_callback(self.PORT, "xu-fake", pending.state)

            r = await c.get("/api/v1/auth/claude-oauth/login-status", params={"login_id": login_id})
            body = r.json()
            self.assertEqual(body["state"], "done")
            self.assertFalse(body["ok"])  # fake code — Anthropic really rejects it

    async def test_login_status_route_unknown_login_id(self):
        async with self._client() as c:
            r = await c.get("/api/v1/auth/claude-oauth/login-status", params={"login_id": "bogus"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"state": "not_found"})

    async def test_exchange_route_rejects_unknown_login_id(self):
        async with self._client() as c:
            r = await c.post("/api/v1/auth/claude-oauth/exchange",
                             json={"login_id": "bogus", "code": "code#state"})
        self.assertEqual(r.status_code, 422)

    async def test_exchange_route_delegates_to_module(self):
        async with self._client() as c:
            start = (await c.post("/api/v1/auth/claude-oauth/start", json={"local": False})).json()
            fake = anthropic_oauth.ImportResult(changed=True, fingerprint="sk-ant-oat...xyz")
            with patch.object(anthropic_oauth, "exchange_login_code") as mocked:
                async def _fake(*a, **kw):
                    return fake
                mocked.side_effect = _fake
                r = await c.post("/api/v1/auth/claude-oauth/exchange",
                                 json={"login_id": start["login_id"], "code": "xu-code#state"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json(), {"ok": True, "changed": True, "token_fingerprint": "sk-ant-oat...xyz"})
            mocked.assert_called_once_with(start["login_id"], "xu-code#state")

    async def test_old_import_token_route_no_longer_exists(self):
        async with self._client() as c:
            r = await c.post("/api/v1/auth/claude-oauth/import-token",
                             json={"access_token": "x", "refresh_token": "y", "expires_at_ms": 1})
        self.assertEqual(r.status_code, 404)

    async def test_status_route_still_works(self):
        async with self._client() as c:
            r = await c.get("/api/v1/auth/claude-oauth/status")
        self.assertEqual(r.status_code, 200)
        self.assertIn("configured", r.json())

    async def test_cancel_login_route_releases_the_port(self):
        async with self._client() as c:
            start = (await c.post("/api/v1/auth/claude-oauth/start")).json()
            login_id = start["login_id"]
            self.assertIn(login_id, anthropic_oauth._pending_logins)

            r = await c.delete(f"/api/v1/auth/claude-oauth/login/{login_id}")
            self.assertEqual(r.status_code, 204)
            self.assertNotIn(login_id, anthropic_oauth._pending_logins)

            # Re-pollable as not_found, and the port is genuinely free again.
            r = await c.get("/api/v1/auth/claude-oauth/login-status", params={"login_id": login_id})
            self.assertEqual(r.json(), {"state": "not_found"})
            s2 = await asyncio.start_server(lambda r, w: None, host="127.0.0.1", port=self.PORT)
            s2.close()
            await s2.wait_closed()

    async def test_cancel_login_route_unknown_id_still_204(self):
        async with self._client() as c:
            r = await c.delete("/api/v1/auth/claude-oauth/login/bogus")
        self.assertEqual(r.status_code, 204)

    async def test_requires_auth_when_api_key_set(self):
        with patch.object(main.settings, "api_key", "secret-server-key"):
            async with self._client() as c:
                r = await c.post("/api/v1/auth/claude-oauth/start")
        self.assertEqual(r.status_code, 401)

    async def test_config_provider_post_points_to_new_endpoints(self):
        async with self._client() as c:
            r = await c.post("/api/v1/config/providers/claude-oauth", json={"api_key": "x"})
        self.assertEqual(r.status_code, 422)
        self.assertIn("/start", r.json()["detail"])
        self.assertIn("/exchange", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
