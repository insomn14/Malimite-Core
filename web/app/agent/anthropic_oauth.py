"""Runs the Claude Code-style OAuth login (Config tab) and refreshes the resulting credential.

Counterpart to AnthropicOAuthCredentials.java / AnthropicOAuthLogin.java, but using the
*remote* variant of their flow instead of the *local-callback-server* one: this process has no
browser of its own and the browser doing the signing-in is the operator's, on a different
machine — a loopback redirect_uri (http://localhost:53692/callback, what the Java CLI and
Claude Code itself use when a browser runs on the SAME machine) would redirect the operator's
browser to a port on THEIR OWN machine that nothing is listening on. Anthropic has a second,
equally first-party redirect_uri for exactly this situation — the one Claude Code itself
switches to for remote/headless sessions (SSH, containers, CI) — that instead shows the user a
page with the authorization code to copy, no listener required on their end:
https://platform.claude.com/oauth/code/callback (confirmed via Claude Code's own remote-session
behavior and third-party reimplementations that special-cased it, e.g.
github.com/cheaper-inference/OmniRoute commit bb89379 "Use Anthropic's registered redirect_uri
... instead of dynamic server URL"). That page hands back the code as `<code>#<state>` in one
string — see _split_code_and_state().

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
# The "show the code, let the user copy it" redirect_uri — see module docstring. Not a secret;
# it is Anthropic's own registered URL, not a server this app controls.
REDIRECT_URI = "https://platform.claude.com/oauth/code/callback"
SCOPES = ("org:create_api_key user:profile user:inference "
         "user:sessions:claude_code user:mcp_servers user:file_upload")

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
# Mirrors AnthropicOAuthLogin.java's interactive flow, minus the local HTTP callback
# server (see module docstring for why): generate PKCE + an authorize URL, let the
# operator open it in THEIR browser, and accept the authorization code Anthropic's
# code-display page shows back instead of running our own loopback listener.
#
# code_verifier never leaves this process — only an opaque, server-generated login_id
# is handed to the browser, so a client can never submit an exchange for a verifier it
# never had. Pending logins live in memory only (not on disk): they are secrets with a
# lifetime of minutes, not a credential worth persisting across a restart, and every
# consumer of this module already treats "click Login again" as a fine fallback.

_LOGIN_TTL_SECONDS = 10 * 60  # generous vs. AnthropicOAuthLogin.java's 5-minute CLI default —
                               # a web tab left idle mid-flow is a more common/forgivable
                               # delay than a terminal session is.


@dataclass
class _PendingLogin:
    code_verifier: str
    state: str
    created_at: float

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at >= _LOGIN_TTL_SECONDS


_pending_logins: dict[str, _PendingLogin] = {}


def _prune_expired_logins() -> None:
    expired = [k for k, v in _pending_logins.items() if v.is_expired]
    for k in expired:
        del _pending_logins[k]


def _random_url_safe(num_bytes: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).rstrip(b"=").decode("ascii")


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def start_login() -> dict:
    """Begins a new browser login: generates PKCE, stores the verifier server-side under a
    fresh opaque login_id, and returns the authorize URL to open plus that login_id (the
    Config tab's "Submit code" call must echo it back — see exchange_login_code()).
    """
    _prune_expired_logins()
    verifier = _random_url_safe(32)
    challenge = _code_challenge(verifier)
    # Claude Code / AnthropicOAuthLogin.java reuse the verifier itself as the OAuth "state"
    # value — kept here only for parity with that flow, not as a secrecy requirement of its own
    # (code_verifier, which state is derived from, is never exposed to the client either way).
    state = verifier
    login_id = secrets.token_urlsafe(24)
    _pending_logins[login_id] = _PendingLogin(code_verifier=verifier, state=state, created_at=time.time())

    params = {
        "code": "true",
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return {"login_id": login_id, "authorize_url": f"{AUTHORIZE_URL}?{urlencode(params)}"}


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


async def exchange_login_code(login_id: str, pasted_code: str,
                              client: Optional[httpx.AsyncClient] = None) -> ImportResult:
    """Completes a login started by start_login(): parses whatever the operator pasted back,
    exchanges it for tokens, and persists the result. The pending login is consumed (removed)
    whether this succeeds or fails — a stale/failed attempt never lingers for a second try with
    the same login_id; the Config tab's only recovery path is clicking Login again, which is
    also what a human does with Claude Code itself on a failed paste.
    """
    _prune_expired_logins()
    pending = _pending_logins.pop(login_id, None)
    if pending is None:
        raise AnthropicOAuthError(
            "This login attempt has expired or was already used — click \"Login with Claude\" again.")

    code, state = _split_code_and_state(pasted_code, pending.state)
    if not code:
        raise AnthropicOAuthError("Could not find an authorization code in what you pasted.")
    if state != pending.state:
        raise AnthropicOAuthError(
            "The pasted code doesn't match this login attempt (state mismatch) — "
            "click \"Login with Claude\" again and paste the code it shows you.")

    own = client is None
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10))
    try:
        try:
            resp = await client.post(TOKEN_URL, json={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "state": state,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": pending.code_verifier,
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
