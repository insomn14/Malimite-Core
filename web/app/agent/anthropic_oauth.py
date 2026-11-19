"""Runs the Claude Code-style OAuth login (Config tab) and refreshes the resulting credential.

Counterpart to AnthropicOAuthCredentials.java / AnthropicOAuthLogin.java. Unlike that file's
single flow, this module tries TWO redirect_uri strategies, in order:

1. LOCAL_REDIRECT_URI (http://127.0.0.1:53692/callback) — same loopback callback approach the
   Java CLI and Claude Code itself use, and the default here. This only works when the browser
   doing the signing-in and this server process share localhost (true for the normal "open
   http://127.0.0.1:7070 in your own browser" deployment — see start_login()'s `local` param).
   Anthropic trusts this redirect_uri as proof the request is coming from a real, present
   browser on the signing-in device, and skips any extra verification step.

2. REMOTE_REDIRECT_URI (https://platform.claude.com/oauth/code/callback) — Anthropic's own
   "show the code, let the user copy it" page, for when no local listener is reachable (the
   operator's browser is on a DIFFERENT machine than this server — a remote/SSH deployment).
   CONFIRMED BY DIRECT TESTING to trigger an *extra* identity-verification step (a 6-digit
   email code) that the localhost redirect does not: Anthropic appears to treat a non-loopback
   redirect_uri as less trustworthy and adds friction accordingly. Expect this step when using
   the remote path; it is normal and not a sign anything here is broken — enter the 6-digit
   code ON ANTHROPIC'S OWN PAGE, and the authorization-code page (the one with a code to paste
   back here) follows once that verification succeeds. Confirmed working in both code paths via
   earendil-works/pi's "copy_code" login method (same two redirect_uris, same client_id).

Either way the code comes back as `<code>#<state>` in one string if the user ends up pasting
it manually (REMOTE_REDIRECT_URI path, or a failed/raced LOCAL_REDIRECT_URI listen) — see
_split_code_and_state(). The local path normally needs no manual paste at all: the Config
tab polls claude_oauth_login_status() until the loopback listener reports a code, then
exchanges it automatically — see POLL_INTERVAL_SECONDS below and main.py's /login-status route.

See core/src/main/java/io/malimite/core/AnthropicOAuthLogin.java for the full OAuth 2.0
Authorization Code + PKCE flow (shared client_id/scopes/token_url) and for why the Messages API
will only honor the resulting token when paired with the beta/identity headers chat_step()
sends for provider="claude-oauth".
"""
import asyncio
import base64
import fcntl
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from ..config import settings

AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
# Same public native-app OAuth client id Claude Code itself uses; not a secret
# (see AnthropicOAuthLogin.java for the full explanation).
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

# Loopback listener this process opens for itself — identical host/port/path to
# AnthropicOAuthLogin.java's CALLBACK_HOST/CALLBACK_PORT/CALLBACK_PATH, so Anthropic's
# authorization server (which keys trust partly off this exact, well-known redirect_uri) treats
# a login started here the same as one started by `claude /login` or the Java CLI.
LOCAL_CALLBACK_HOST = "127.0.0.1"
LOCAL_CALLBACK_PORT = 53692
LOCAL_CALLBACK_PATH = "/callback"
LOCAL_REDIRECT_URI = f"http://{LOCAL_CALLBACK_HOST}:{LOCAL_CALLBACK_PORT}{LOCAL_CALLBACK_PATH}"
# Anthropic's own "show the code, let the user copy it" redirect_uri — see module docstring.
# Not a secret; it is Anthropic's own registered URL, not a server this app controls.
REMOTE_REDIRECT_URI = "https://platform.claude.com/oauth/code/callback"

# Back-compat alias: anything importing REDIRECT_URI (this module's own earlier shape, before
# the local-callback path existed) keeps working, pointed at the new default strategy.
REDIRECT_URI = LOCAL_REDIRECT_URI

SCOPES = ("org:create_api_key user:profile user:inference "
         "user:sessions:claude_code user:mcp_servers user:file_upload")

# How often the Config tab polls claude_oauth_login_status() while LOCAL_REDIRECT_URI's listener
# waits for the browser to redirect back. Exposed as a constant so the route/UI can agree on it
# without hardcoding the number twice.
POLL_INTERVAL_SECONDS = 1.5

# Required for the Messages API to accept an OAuth bearer token at all.
BETA_HEADER_VALUE = "claude-code-20250219,oauth-2025-04-20"
CLAUDE_CODE_IDENTITY = "You are Claude Code, Anthropic's official CLI for Claude."


class AnthropicOAuthError(Exception):
    """Safe to show to the user — never contains token values."""


@dataclass
class _Credential:
    access_token: str
    refresh_token: str
    expires_at_millis: int

    @property
    def is_expired(self) -> bool:
        return time.time() * 1000 >= self.expires_at_millis


def _path() -> Path:
    return Path(settings.anthropic_oauth_path)


def _load() -> Optional[_Credential]:
    p = _path()
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text("utf-8"))
        return _Credential(data["access_token"], data["refresh_token"], data["expires_at_millis"])
    except (OSError, ValueError, KeyError):
        return None


def _save(cred: _Credential) -> None:
    """Atomic write + best-effort 0600, mirroring AnthropicOAuthCredentials.save()."""
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".tmp-{time.monotonic_ns()}")
    tmp.write_text(json.dumps({
        "access_token": cred.access_token,
        "refresh_token": cred.refresh_token,
        "expires_at_millis": cred.expires_at_millis,
    }, indent=2), "utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass  # non-POSIX or the shared docker mount can't always honor this — not fatal
    tmp.replace(p)


# In-process serialization only (same event loop). NOT sufficient by itself —
# see _CrossProcessRefreshLock below for why a second, OS-level lock is also
# required.
_refresh_lock = asyncio.Lock()


def _refresh_lock_path() -> Path:
    store = _path()
    return store.with_name(store.name + ".lock")


class _CrossProcessRefreshLock:
    """Blocking, cross-process exclusive lock on a `.lock` file next to the
    credential (never the credential file itself — _save() replaces it via
    atomic rename, which would orphan a lock held on the old inode).

    Anthropic's refresh_token is SINGLE-USE: once spent, the server invalidates
    it (confirmed directly in production via a real HTTP 400, and by other
    projects hitting the identical symptom — e.g.
    github.com/router-for-me/CLIProxyAPI issue #6288 "refresh retry resends a
    single-use refresh token", and elizaOS/eliza issue #29954 "serialize OAuth2
    PKCE token refresh so concurrent loops don't double-spend the single-use
    refresh token").

    Malimite has TWO independent OS processes that can each decide a token
    needs refreshing at the same moment: this Python web service (AI Assistant
    chat) and the Java CLI (scan enrichment, ClaudeOAuthProvider). Each already
    serializes its OWN concurrent callers with an in-process lock (asyncio.Lock
    here, a plain Object monitor in Java) — but neither process can see the
    other's lock, so both can fire a refresh request with the same
    (soon-to-be-stale) refresh_token. Anthropic honors whichever request lands
    first and 400s the other.

    Uses fcntl.lockf() (POSIX advisory record locking, fcntl(F_SETLK) under the
    hood) rather than fcntl.flock() (BSD-style flock(2)) — empirically verified
    against Java's java.nio.channels.FileChannel.lock(): only lockf()
    interoperates with it on Linux; flock() does not block against it at all
    (different kernel locking mechanism entirely, despite both being
    "file locks" at the API level).
    """

    def __init__(self, path: Path):
        self._path = path
        self._file = None

    def __enter__(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a+")  # "a+": never truncates, creates if absent
        fcntl.lockf(self._file.fileno(), fcntl.LOCK_EX)  # blocks until acquired
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            fcntl.lockf(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None


async def get_access_token(client: Optional[httpx.AsyncClient] = None) -> str:
    """Returns a non-expired OAuth access token, refreshing and persisting it first if needed.

    Raises AnthropicOAuthError with a message safe to surface to the user
    (e.g. in the AI Assistant chat error banner) when no credential is on
    disk or the refresh itself fails.
    """
    cred = _load()
    if cred is None:
        raise AnthropicOAuthError(
            "No Anthropic OAuth session found on the server. The operator needs to run "
            "'malimite claude-login' (see core/README or the claude-login CLI subcommand).")
    if not cred.is_expired:
        return cred.access_token

    async with _refresh_lock:
        cred = _load() or cred  # re-read: another request may have refreshed while we waited

        def acquire_and_check():
            """Runs in a worker thread, holding the OS-level lock for its
            entire duration. Returns an already-valid credential (ours or
            another process's, re-read after the lock) or None if a real
            network refresh is still needed."""
            lock = _CrossProcessRefreshLock(_refresh_lock_path())
            lock.__enter__()
            try:
                current = _load() or cred
                if not current.is_expired:
                    # Another process (this one or the Java CLI) already
                    # refreshed while we waited for the lock.
                    lock.__exit__(None, None, None)
                    return current, None
                return current, lock  # caller must lock.__exit__() after persisting
            except BaseException:
                lock.__exit__(None, None, None)
                raise

        current, held_lock = await asyncio.to_thread(acquire_and_check)
        if held_lock is None:
            return current.access_token

        # We hold the cross-process lock (held_lock) and current.refresh_token
        # is still the one on disk — safe to spend it now.
        try:
            own = client is None
            client = client or httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10))
            try:
                resp = await client.post(TOKEN_URL, json={
                    "grant_type": "refresh_token",
                    "client_id": CLIENT_ID,
                    "refresh_token": current.refresh_token,
                })
                if resp.status_code != 200:
                    raise AnthropicOAuthError(
                        "Anthropic OAuth token refresh failed "
                        f"(HTTP {resp.status_code}). Re-run 'malimite claude-login' on the server.")
                data = resp.json()
            except httpx.HTTPError as e:
                raise AnthropicOAuthError(
                    f"Anthropic OAuth token refresh request failed: {type(e).__name__}") from None
            finally:
                if own:
                    await client.aclose()

            # Same 5-minute safety margin as AnthropicOAuthLogin.java's exchange/refresh.
            expires_at = int(time.time() * 1000) + data["expires_in"] * 1000 - 5 * 60 * 1000
            refreshed = _Credential(data["access_token"], data["refresh_token"], expires_at)
            # Persist while STILL holding the cross-process lock, so a
            # concurrent Java refresh (blocked waiting on the same lock) sees
            # our fresh token on its own post-lock re-check instead of racing
            # the file write.
            await asyncio.to_thread(_save, refreshed)
            return refreshed.access_token
        finally:
            await asyncio.to_thread(held_lock.__exit__, None, None, None)


def is_configured() -> bool:
    """True when a credential file exists on disk (does not check expiry/validity)."""
    return _load() is not None


# ── Import an already-completed `claude /login` session ─────────────────────
#
# A second, independent way to get claude-oauth working here, alongside the browser
# login flow below (start_login/exchange_login_code): reuse a session the official
# `claude` CLI already completed elsewhere, rather than signing in again through this
# app. Two equivalent ways to call it:
#   malimite claude-login --import                   (reads settings.claude_code_credentials_path)
#   POST /api/v1/auth/claude-oauth/import-claude-code (this module's web counterpart)
#
# CLAUDE_CODE_CREDENTIALS_PATH defaults to the official claude CLI's own file
# (~/.claude/.credentials.json) but web-compose.yml overrides it via the
# CLAUDE_CODE_CREDENTIALS_PATH env var to a synced copy instead — that file is
# correctly 0600 and owned by the host uid, unreadable by this container's own
# uid. Run ./sync-claude-oauth.sh (repo root) to produce that copy.


def claude_code_credentials_path() -> Path:
    """Where this process looks for an already-completed `claude /login` session.
    Safe to show in an error message — it's a path, not a secret."""
    return Path(settings.claude_code_credentials_path)


def claude_code_credentials_available() -> bool:
    """True when the official `claude` CLI's own session file is readable here."""
    return _read_claude_code_credential() is not None


def _read_claude_code_credential() -> Optional[_Credential]:
    path = claude_code_credentials_path()
    if not path.is_file():
        return None
    try:
        root = json.loads(path.read_text("utf-8"))
        oauth = root["claudeAiOauth"]
        return _Credential(oauth["accessToken"], oauth["refreshToken"], oauth["expiresAt"])
    except (OSError, ValueError, KeyError):
        return None


def _fingerprint(access_token: str) -> str:
    """Short, non-secret stand-in for an access token — safe to return in an
    API response or show in the UI so a caller can tell whether an import
    actually changed anything, without exposing the token itself."""
    return f"{access_token[:18]}...{access_token[-6:]}" if len(access_token) > 24 else "***"


class ImportResult:
    """Result of an import attempt, rich enough for the caller (CLI or web UI)
    to tell a genuinely-new token apart from re-importing the same one.

    The "same token" case matters specifically because of a real incident:
    `sync-claude-oauth.sh` writes CLAUDE_CODE_CREDENTIALS_PATH asynchronously
    relative to a human clicking "Import" in the browser — if the import
    request lands before the sync script finishes, it silently re-copies
    whatever was ALREADY there (old/invalid token) and still reports success,
    because nothing about the copy operation itself failed. The caller has no
    way to tell that happened from a bare `{"ok": true}`.
    """
    def __init__(self, changed: bool, fingerprint: str):
        self.changed = changed
        self.fingerprint = fingerprint


def import_from_claude_code() -> Optional[ImportResult]:
    """Copies the official `claude` CLI's stored session into this app's own
    token file. Returns None when no Claude Code session is found at all —
    this is a convenience auto-detect, not a hard dependency.

    `ImportResult.changed` is False when the imported access_token is
    byte-for-byte identical to what was already stored — almost always a sign
    that `sync-claude-oauth.sh` hadn't finished writing yet when this ran (see
    ImportResult's docstring), NOT that the import itself failed. Callers
    should surface this distinctly rather than reporting a flat "success".
    """
    cred = _read_claude_code_credential()
    if cred is None:
        return None
    previous = _load()
    changed = previous is None or previous.access_token != cred.access_token
    _save(cred)
    return ImportResult(changed=changed, fingerprint=_fingerprint(cred.access_token))


# ── Browser login (Config tab "Login with Claude") ──────────────────────────
#
# Mirrors AnthropicOAuthLogin.java's interactive flow much more closely than this module's
# first version did: start_login() now opens the SAME loopback HTTP listener the Java CLI and
# `claude /login` do (LOCAL_REDIRECT_URI), falling back to REMOTE_REDIRECT_URI (no listener,
# user pastes the code back by hand) only when that bind fails — e.g. the port is already in
# use, or this process genuinely has no local browser reachable at all. See module docstring
# for why REMOTE_REDIRECT_URI triggers an extra Anthropic-side identity-verification step that
# the local path does not.
#
# code_verifier never leaves this process — only an opaque, server-generated login_id is
# handed to the browser/client, so a client can never submit an exchange for a verifier it
# never had. Pending logins live in memory only (not on disk): they are secrets with a
# lifetime of minutes, not a credential worth persisting across a restart, and every consumer
# of this module already treats "click Login again" as a fine fallback.

# Local-listener logins (the default, and the path that avoids Anthropic's extra 6-digit
# email-verification step — see module docstring) expire much sooner than remote/copy-paste
# ones: a browser login is normally seconds, and a LEFT-OPEN local listener holds a real OS
# port (53692) that nothing else on the machine can bind until it's released — including a
# second Malimite login attempt, AnthropicOAuthLogin.java's own CLI, or any other local tool
# that happens to want that exact port. Found in testing: reloading the Config tab mid-login
# drops the browser-side poll (the in-memory JS state start_login() needs to resume polling is
# gone after a reload) while the SERVER-side listener keeps waiting — a short TTL plus the
# background sweep below (not just the old "only pruned when some other request happens to call
# _prune_expired_logins()" behavior) are what actually bounds how long that port stays stuck.
_LOCAL_LOGIN_TTL_SECONDS = 3 * 60
# Remote/copy-paste logins hold no OS resource, just an in-memory dict entry — fine to give the
# operator more slack reading a 6-digit email code, finding the right tab, etc. Still shorter
# than AnthropicOAuthLogin.java's 5-minute CLI default would suggest, deliberately: an abandoned
# remote login is pure dead weight once no longer needed, no reason to keep it around 10 minutes.
_REMOTE_LOGIN_TTL_SECONDS = 5 * 60
# How often the background sweep (see start_prune_loop()) runs, independent of whether any
# request happens to come in. Short enough that a reload-abandoned local listener's port is
# usable again well within a human's "oh, let me try that again" timeframe.
_PRUNE_SWEEP_INTERVAL_SECONDS = 20


@dataclass
class _PendingLogin:
    code_verifier: str
    state: str
    redirect_uri: str
    created_at: float
    # Populated only for the local-listener path (see _try_start_local_server()). A asyncio
    # Server plus the single-shot result slot its handler fills in; None on the remote
    # (copy-paste) path, which has nothing to listen for.
    server: Optional[asyncio.base_events.Server] = None
    result: "Optional[asyncio.Future]" = None

    @property
    def is_expired(self) -> bool:
        ttl = _LOCAL_LOGIN_TTL_SECONDS if self.server is not None else _REMOTE_LOGIN_TTL_SECONDS
        return time.time() - self.created_at >= ttl

    async def close_server(self) -> None:
        if self.server is not None:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass  # best-effort cleanup only — never let this mask the real result/error


_pending_logins: dict[str, _PendingLogin] = {}


async def _prune_expired_logins() -> None:
    expired = [k for k, v in _pending_logins.items() if v.is_expired]
    for k in expired:
        pending = _pending_logins.pop(k, None)
        if pending is not None:
            await pending.close_server()


async def start_prune_loop() -> None:
    """Background sweep that closes expired listeners even when nothing else happens to call
    _prune_expired_logins() — see _PRUNE_SWEEP_INTERVAL_SECONDS and _LOCAL_LOGIN_TTL_SECONDS's
    docstring for why this matters specifically for the local-listener path. Intended to be
    wrapped in an asyncio.create_task() from main.py's lifespan, alongside the existing
    retention sweep — cancel that task on shutdown the same way.
    """
    while True:
        try:
            await _prune_expired_logins()
        except Exception:
            pass  # best-effort; a failed sweep this tick is recovered by the next one
        await asyncio.sleep(_PRUNE_SWEEP_INTERVAL_SECONDS)


def _random_url_safe(num_bytes: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).rstrip(b"=").decode("ascii")


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


_CALLBACK_SUCCESS_HTML = (
    "<!doctype html><meta charset=utf-8><title>Signed in</title>"
    "<body style=font-family:system-ui;padding:2rem>"
    "<h2>Anthropic authentication completed.</h2>"
    "<p>You can close this tab and return to Malimite.</p></body>"
)
_CALLBACK_ERROR_HTML = (
    "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>"
    "<body style=font-family:system-ui;padding:2rem>"
    "<h2>{message}</h2></body>"
)


async def _handle_callback_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                      expected_state: str, result: "asyncio.Future") -> None:
    """Minimal single-request HTTP/1.1 handler — just enough to read one GET request line,
    answer it, and close. No routing, no keep-alive: AnthropicOAuthLogin.java's
    com.sun.net.httpserver.HttpServer does the equivalent with a real HTTP library; this uses
    raw asyncio streams instead purely to avoid adding a new dependency for one request.
    """
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        # Drain and discard headers — nothing here is read past the request line.
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not line or line in (b"\r\n", b"\n"):
                break

        try:
            method, target, _ = request_line.decode("latin-1").strip().split(" ", 2)
        except ValueError:
            method, target = "", ""

        parsed = urlparse(target)

        # A request to anything other than our one known path never touches `result` at all —
        # this listener has no other routes, but the loopback port is still reachable by
        # anything local (a stray browser prefetch, a port scanner, curl out of curiosity) and
        # none of that should be able to fail an in-flight login out from under the real
        # Anthropic redirect that's still coming. Only a GET to LOCAL_CALLBACK_PATH itself —
        # whether it's the success case or Anthropic's own error/state-mismatch response —
        # resolves (or fails) the pending login.
        if method != "GET" or parsed.path != LOCAL_CALLBACK_PATH:
            status, body = 404, _CALLBACK_ERROR_HTML.format(message="Not found.")
        else:
            q = parse_qs(parsed.query)
            code = (q.get("code") or [None])[0]
            state = (q.get("state") or [None])[0]
            error = (q.get("error") or [None])[0]

            if error:
                status, body = 400, _CALLBACK_ERROR_HTML.format(message=f"Anthropic reported an error: {error}")
            elif not code or not state:
                status, body = 400, _CALLBACK_ERROR_HTML.format(message="Missing code or state parameter.")
            elif state != expected_state:
                status, body = 400, _CALLBACK_ERROR_HTML.format(message="State mismatch.")
            else:
                status, body = 200, _CALLBACK_SUCCESS_HTML

            if not result.done():
                if status == 200:
                    result.set_result((code, state))
                else:
                    result.set_exception(AnthropicOAuthError(
                        "Anthropic's redirect to this server was missing or invalid — click "
                        "\"Login with Claude\" again."))

        body_bytes = body.encode("utf-8")
        response = (
            f"HTTP/1.1 {status} {'OK' if status == 200 else 'Error'}\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii") + body_bytes
        writer.write(response)
        await writer.drain()
    except Exception as e:
        if not result.done():
            result.set_exception(AnthropicOAuthError(f"Local callback handler failed: {type(e).__name__}"))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _try_start_local_server(state: str) -> "Optional[tuple[asyncio.base_events.Server, asyncio.Future]]":
    """Attempts to bind LOCAL_CALLBACK_HOST:LOCAL_CALLBACK_PORT. Returns (server, result_future)
    on success, or None if the bind itself fails (port already in use — e.g. another Malimite
    login in flight, or AnthropicOAuthLogin.java's own CLI login running concurrently on this
    same host — or any other OS-level reason) so the caller can fall back to the remote/copy
    path instead of failing the whole login outright.
    """
    result: "asyncio.Future" = asyncio.get_event_loop().create_future()
    try:
        server = await asyncio.start_server(
            lambda r, w: _handle_callback_connection(r, w, state, result),
            host=LOCAL_CALLBACK_HOST, port=LOCAL_CALLBACK_PORT)
    except OSError:
        return None
    return server, result


async def start_login(local: bool = True) -> dict:
    """Begins a new browser login: generates PKCE, stores the verifier server-side under a
    fresh opaque login_id, and returns the authorize URL to open plus that login_id (callers
    poll login_status(login_id) — the local path resolves on its own once the browser redirects
    back; the remote/copy-paste path needs exchange_login_code() called explicitly instead).

    `local=False` skips straight to REMOTE_REDIRECT_URI without attempting the loopback bind —
    used by main.py's route only if the operator explicitly asks for the copy-paste path (e.g.
    they already know this server and their browser are on different machines).
    """
    await _prune_expired_logins()
    verifier = _random_url_safe(32)
    challenge = _code_challenge(verifier)
    # Claude Code / AnthropicOAuthLogin.java reuse the verifier itself as the OAuth "state"
    # value — kept here only for parity with that flow, not as a secrecy requirement of its own
    # (code_verifier, which state is derived from, is never exposed to the client either way).
    state = verifier
    login_id = secrets.token_urlsafe(24)

    server = result = None
    redirect_uri = REMOTE_REDIRECT_URI
    if local:
        started = await _try_start_local_server(state)
        if started is not None:
            server, result = started
            redirect_uri = LOCAL_REDIRECT_URI

    _pending_logins[login_id] = _PendingLogin(
        code_verifier=verifier, state=state, redirect_uri=redirect_uri,
        created_at=time.time(), server=server, result=result)

    params = {
        "code": "true",
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return {
        "login_id": login_id,
        "authorize_url": f"{AUTHORIZE_URL}?{urlencode(params)}",
        "mode": "local" if server is not None else "remote",
    }


def _split_code_and_state(pasted: str, expected_state: str) -> tuple[str, str]:
    """Extracts (code, state) from whatever the user pasted — mirrors
    AnthropicOAuthLogin.java's parseManualInput() so both entry points accept the same inputs:
      1. A full redirect/callback URL (code & state as query params).
      2. Anthropic's code-display page's own `<code>#<state>` format (see module docstring).
      3. A bare `code=...` fragment.
      4. Just the bare code, with no state at all — expected_state is assumed (not every
         paste includes it, and code_verifier is still bound server-side via login_id).
    """
    pasted = pasted.strip()
    if not pasted:
        raise AnthropicOAuthError("Paste the authentication code Claude showed you.")

    try:
        parsed = urlparse(pasted)
        if parsed.scheme and parsed.query:
            q = parse_qs(parsed.query)
            code = (q.get("code") or [None])[0]
            state = (q.get("state") or [None])[0]
            if code:
                return code, state or expected_state
    except ValueError:
        pass

    if "#" in pasted:
        code, _, state = pasted.partition("#")
        return code.strip(), (state.strip() or expected_state)

    if "code=" in pasted:
        q = parse_qs(pasted)
        code = (q.get("code") or [None])[0]
        state = (q.get("state") or [None])[0]
        if code:
            return code, state or expected_state

    return pasted, expected_state


async def _exchange_tokens(code: str, state: str, redirect_uri: str, code_verifier: str,
                           client: Optional[httpx.AsyncClient] = None) -> ImportResult:
    """Shared token-exchange POST — called with a manually-pasted code (exchange_login_code())
    or one the local callback listener captured automatically (login_status()). Does not touch
    _pending_logins; callers own popping/closing that themselves.
    """
    own = client is None
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10))
    try:
        try:
            resp = await client.post(TOKEN_URL, json={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "state": state,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            })
        except httpx.HTTPError as e:
            raise AnthropicOAuthError(f"Token exchange request failed: {type(e).__name__}") from None

        if resp.status_code != 200:
            raise AnthropicOAuthError(
                f"Anthropic rejected the authorization code (HTTP {resp.status_code}). "
                "The code may be wrong, already used, or expired — click \"Login with Claude\" again.")

        try:
            data = resp.json()
            access_token = data["access_token"]
            refresh_token = data["refresh_token"]
            expires_in = data["expires_in"]
        except (ValueError, KeyError) as e:
            raise AnthropicOAuthError(f"Unexpected response from Anthropic's token endpoint: {e}") from None
    finally:
        if own:
            await client.aclose()

    # Same 5-minute safety margin as AnthropicOAuthLogin.java's exchange/refresh.
    expires_at = int(time.time() * 1000) + expires_in * 1000 - 5 * 60 * 1000
    previous = _load()
    changed = previous is None or previous.access_token != access_token
    cred = _Credential(access_token, refresh_token, expires_at)
    _save(cred)
    return ImportResult(changed=changed, fingerprint=_fingerprint(access_token))


async def exchange_login_code(login_id: str, pasted_code: str,
                              client: Optional[httpx.AsyncClient] = None) -> ImportResult:
    """Completes a login started by start_login(): parses whatever the operator pasted back,
    exchanges it for tokens, and persists the result. The pending login is consumed (removed)
    whether this succeeds or fails — a stale/failed attempt never lingers for a second try with
    the same login_id; the Config tab's only recovery path is clicking Login again, which is
    also what a human does with Claude Code itself on a failed paste. Works for EITHER redirect
    strategy (pending.redirect_uri carries whichever start_login() picked) — this is the manual
    path used by the remote/copy-paste flow and as a fallback if the local listener's own
    automatic capture (see login_status()) never fires.
    """
    await _prune_expired_logins()
    pending = _pending_logins.pop(login_id, None)
    if pending is None:
        raise AnthropicOAuthError(
            "This login attempt has expired or was already used — click \"Login with Claude\" again.")
    await pending.close_server()

    code, state = _split_code_and_state(pasted_code, pending.state)
    if not code:
        raise AnthropicOAuthError("Could not find an authorization code in what you pasted.")
    if state != pending.state:
        raise AnthropicOAuthError(
            "The pasted code doesn't match this login attempt (state mismatch) — "
            "click \"Login with Claude\" again and paste the code it shows you.")

    return await _exchange_tokens(code, state, pending.redirect_uri, pending.code_verifier, client)


async def login_status(login_id: str, client: Optional[httpx.AsyncClient] = None) -> dict:
    """Polled by the Config tab (see main.py's GET /auth/claude-oauth/login-status) while a
    local-listener login (start_login()'s default path) waits for the browser to redirect back.

    Returns one of:
      {"state": "waiting", "mode": "local"}                — still waiting, listener healthy.
      {"state": "waiting", "mode": "remote"}                — remote/copy-paste path; nothing to
                                                                poll for, caller must call
                                                                exchange_login_code() once the
                                                                user pastes a code.
      {"state": "done", "ok": true, "changed": ..., "token_fingerprint": ...}
      {"state": "done", "ok": false, "error": "..."}        — exchange failed; login_id is
                                                                already consumed either way.
      {"state": "not_found"}                                — unknown/expired/already-consumed
                                                                login_id.
    """
    await _prune_expired_logins()
    pending = _pending_logins.get(login_id)
    if pending is None:
        return {"state": "not_found"}

    if pending.server is None or pending.result is None:
        return {"state": "waiting", "mode": "remote"}

    if not pending.result.done():
        return {"state": "waiting", "mode": "local"}

    # The listener resolved (or errored) — consume the pending login exactly once, same as
    # exchange_login_code()'s single-use contract, regardless of which path got there first.
    _pending_logins.pop(login_id, None)
    await pending.close_server()

    try:
        code, state = pending.result.result()
    except AnthropicOAuthError as e:
        return {"state": "done", "ok": False, "error": str(e)}

    try:
        result = await _exchange_tokens(code, state, pending.redirect_uri, pending.code_verifier, client)
    except AnthropicOAuthError as e:
        return {"state": "done", "ok": False, "error": str(e)}

    return {"state": "done", "ok": True, "changed": result.changed, "token_fingerprint": result.fingerprint}


async def cancel_login(login_id: str) -> bool:
    """Backs the Config tab's "Cancel" button: immediately releases a local-listener login's
    OS port (53692) instead of waiting out _LOCAL_LOGIN_TTL_SECONDS/the background sweep (see
    start_prune_loop()) — those are the backstop for an ABANDONED login (closed tab, crashed
    browser), not the primary path for a deliberate cancel, which should free the port right
    away for whatever the operator tries next. Returns False (a no-op, not an error) for an
    unknown/already-finished login_id — cancelling something that's already gone is fine.
    """
    pending = _pending_logins.pop(login_id, None)
    if pending is None:
        return False
    await pending.close_server()
    return True
