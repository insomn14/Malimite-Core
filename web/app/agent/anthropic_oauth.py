"""Reads and refreshes the Anthropic OAuth credential the Java CLI writes.

Counterpart to AnthropicOAuthCredentials.java / AnthropicOAuthLogin.java —
this module never runs the interactive login flow (no browser, no local
callback server here); it only consumes the token file that `malimite
claude-login` produced, and refreshes it in place when it is close to
expiring. See core/src/main/java/io/malimite/core/AnthropicOAuthLogin.java
for the full OAuth 2.0 Authorization Code + PKCE flow and for why the
Messages API will only honor this token when paired with the beta/identity
headers chat_step() sends for provider="claude-oauth".
"""
import asyncio
import fcntl
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from ..config import settings

TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
# Same public native-app OAuth client id Claude Code itself uses; not a secret
# (see AnthropicOAuthLogin.java for the full explanation).
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

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


# ── Import (no browser flow needed) ─────────────────────────────────────────
#
# This container has no browser, and the loopback callback server the OAuth flow
# needs (localhost:53692) isn't reachable from a browser running on the host
# anyway — so importing an already-completed login is the only practical way to
# get claude-oauth working here. Three equivalent ways to call it:
#   malimite claude-login --import               (reads settings.claude_code_credentials_path)
#   malimite claude-login --access-token ...      (manual, same values pasted)
#   POST /api/v1/auth/claude-oauth/import-token   (this module's web counterpart)
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


def import_manual(access_token: str, refresh_token: str, expires_at_millis: int) -> None:
    """Stores a caller-supplied token triple (e.g. pasted into a web form) as
    this app's own OAuth session, bypassing both the browser flow and the
    Claude Code auto-detect.
    """
    _save(_Credential(access_token, refresh_token, expires_at_millis))
