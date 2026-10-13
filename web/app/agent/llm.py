"""Minimal streaming tool-calling clients: Anthropic and OpenAI-compatible (openai/deepseek/ollama).

Neutral message format = Anthropic block lists:
  {"role": "user"|"assistant", "content": [text | tool_use | tool_result blocks]}
chat_step() yields events: {"type":"text","text"} | {"type":"tool_use","id","name","input"}
                           | {"type":"stop","reason"}
"""
import asyncio
import json
import random
import time
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import httpx

from .. import scanner
from ..config import settings
from . import anthropic_oauth

PROVIDERS = ("claude", "claude-oauth", "openai", "deepseek", "ollama")
_DEFAULT_MODEL = {"claude": "claude-sonnet-4-6", "claude-oauth": "claude-sonnet-4-6",
                  "openai": "gpt-4o-mini", "deepseek": "deepseek-v4-flash", "ollama": "llama3.1"}
_KEY_ENV = {"claude": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "deepseek": "DEEPSEEK_API_KEY"}
TRUNCATED = frozenset({"length", "max_tokens"})  # stop reasons meaning "cut off by the output limit" (openai-compat / anthropic)

# Transient HTTP statuses worth retrying — same set pi-ai's provider-retry layer uses
# (utils/provider-retry.js: 408/409/429/5xx) and that dsh-llm-retry documents as its
# normal-mode default (RATE_LIMIT/SERVER/TIMEOUT/TRANSPORT, 5 retries). 529 is
# Anthropic's "overloaded" status, not in the generic set but worth the same treatment.
RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504, 524, 529})
RETRYABLE_STATUS_MAX_RETRIES = 5

# Bounds for the exponential-backoff fallback when the provider gives no explicit
# delay — mirrors pi-ai's getRetryDelayMs(): min(0.5 * 2**attempt, 8) seconds, with
# up to 25% jitter shaved off (never added, so a retry never waits *longer* than the
# unjittered cap).
_BACKOFF_BASE_S = 0.5
_BACKOFF_CAP_S = 8.0
_BACKOFF_JITTER_RATIO = 0.25


def _retry_delay_seconds(headers: httpx.Headers, attempt: int) -> float:
    """How long to wait before the next retry, honoring the provider's own guidance.

    Checks `retry-after-ms` then `retry-after` (seconds, or an HTTP-date per RFC 9110)
    before falling back to exponential backoff — the same precedence
    utils/provider-retry.js's getRetryDelayMs() uses, because Anthropic's OAuth-subscription
    rate limiter (observed: short, request-count-based bursts distinct from the
    5h/7d quota reported in anthropic-ratelimit-unified-* headers) is the one most
    likely to actually send one of these.
    """
    retry_after_ms = headers.get("retry-after-ms")
    if retry_after_ms:
        try:
            return max(0.0, float(retry_after_ms) / 1000)
        except ValueError:
            pass
    retry_after = headers.get("retry-after")
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            try:
                from email.utils import parsedate_to_datetime
                target = parsedate_to_datetime(retry_after)
                return max(0.0, target.timestamp() - time.time())
            except (TypeError, ValueError):
                pass
    base = min(_BACKOFF_BASE_S * 2 ** attempt, _BACKOFF_CAP_S)
    return base * (1 - random.random() * _BACKOFF_JITTER_RATIO)


class LlmError(Exception):
    """Message is safe to show to the user (never contains keys)."""


@dataclass
class LlmCfg:
    provider: str
    model: str
    api_key: str
    base_url: str


def resolve_llm(scan_provider: str, scan_model: str,
                provider: Optional[str] = None, model: Optional[str] = None) -> LlmCfg:
    """Scan's provider/model unless overridden; key only from server settings (never meta.json)."""
    p = (provider or "").strip().lower() or (scan_provider if scan_provider in PROVIDERS else "") \
        or (settings.llm_provider if settings.llm_provider in PROVIDERS else "")
    if p not in PROVIDERS:
        raise LlmError("No LLM provider configured for this scan; choose one in the Assistant tab.")
    # a model saved for another provider is meaningless: inherit only when the provider matches
    m = (model or "").strip()
    if not m and p == scan_provider:
        m = scan_model
    if not m and p == settings.llm_provider:
        m = settings.llm_model
    m = m or _DEFAULT_MODEL[p]
    env = scanner.llm_env(p)
    # claude-oauth's "key" is a short-lived access token resolved per-request in
    # chat_step() (it can expire mid-session and needs an async refresh this sync
    # function can't do) — api_key stays empty here and is filled in just before
    # the HTTP call instead. ollama needs no key either; every other provider does.
    if p not in ("ollama", "claude-oauth"):
        key = env.get(_KEY_ENV.get(p, ""), "")
        if not key:
            raise LlmError(f"{_KEY_ENV[p]} is not configured on the server.")
    elif p == "claude-oauth" and not anthropic_oauth.is_configured():
        raise LlmError(
            "No Anthropic OAuth session found on the server. The operator needs to run "
            "'malimite claude-login'.")
    else:
        key = ""
    base = {"claude": "https://api.anthropic.com", "claude-oauth": "https://api.anthropic.com",
            "openai": "https://api.openai.com",
            "deepseek": env.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            "ollama": env.get("OLLAMA_BASE_URL", "http://localhost:11434")}[p]
    return LlmCfg(p, m, key, base.rstrip("/"))


# ── message translation ───────────────────────────────────────────────────────

def to_openai(system: str, messages: list[dict]) -> list[dict]:
    out: list[dict] = [{"role": "system", "content": system}]
    for m in messages:
        blocks = m["content"]
        if m["role"] == "assistant":
            text = "".join(b["text"] for b in blocks if b["type"] == "text")
            calls = [{"id": b["id"], "type": "function",
                      "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                     for b in blocks if b["type"] == "tool_use"]
            msg: dict = {"role": "assistant", "content": text or None}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
        else:
            for b in blocks:
                if b["type"] == "tool_result":
                    out.append({"role": "tool", "tool_call_id": b["tool_use_id"], "content": b["content"]})
            text = "".join(b["text"] for b in blocks if b["type"] == "text")
            if text:
                out.append({"role": "user", "content": text})
    return out


def _tools_anthropic(tools):
    return [{"name": t["name"], "description": t["description"], "input_schema": t["schema"]} for t in tools]


def _tools_openai(tools):
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                              "parameters": t["schema"]}} for t in tools]


def _args(raw) -> dict:
    if isinstance(raw, dict):  # some ollama models return an object, not a JSON string
        return raw
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {"_invalid_json": str(raw)[:200]}


# ── stream parsers (pure: take SSE `data:` payload strings) ───────────────────

async def parse_anthropic(data: AsyncIterator[str]) -> AsyncIterator[dict]:
    blocks: dict[int, dict] = {}
    reason = "end_turn"
    async for d in data:
        try:
            ev = json.loads(d)
        except ValueError:
            continue
        t = ev.get("type")
        if t == "content_block_start":
            cb = ev["content_block"]
            blocks[ev["index"]] = {"type": cb["type"], "id": cb.get("id"), "name": cb.get("name"), "json": ""}
        elif t == "content_block_delta":
            dl = ev["delta"]
            if dl.get("type") == "text_delta":
                yield {"type": "text", "text": dl["text"]}
            elif dl.get("type") == "input_json_delta" and ev["index"] in blocks:
                blocks[ev["index"]]["json"] += dl.get("partial_json", "")
        elif t == "content_block_stop":
            b = blocks.pop(ev["index"], None)
            if b and b["type"] == "tool_use":
                yield {"type": "tool_use", "id": b["id"], "name": b["name"], "input": _args(b["json"])}
        elif t == "message_delta":
            reason = ev.get("delta", {}).get("stop_reason") or reason
        elif t == "error":
            raise LlmError(ev.get("error", {}).get("message", "provider stream error")[:200])
    yield {"type": "stop", "reason": reason}


async def parse_openai(data: AsyncIterator[str]) -> AsyncIterator[dict]:
    calls: dict[int, dict] = {}
    reason = "stop"
    async for d in data:
        if d.strip() == "[DONE]":
            break
        try:
            ev = json.loads(d)
        except ValueError:
            continue
        for ch in ev.get("choices", []):
            dl = ch.get("delta") or {}
            if dl.get("content"):
                yield {"type": "text", "text": dl["content"]}
            for tc in dl.get("tool_calls") or []:
                c = calls.setdefault(tc.get("index", 0), {"id": None, "name": "", "args": ""})
                c["id"] = tc.get("id") or c["id"]
                fn = tc.get("function") or {}
                c["name"] += fn.get("name") or ""
                a = fn.get("arguments")
                if isinstance(a, dict):
                    c["args"] = a
                elif a:
                    c["args"] += a
            reason = ch.get("finish_reason") or reason
    for i, c in sorted(calls.items()):
        yield {"type": "tool_use", "id": c["id"] or f"call_{i}", "name": c["name"], "input": _args(c["args"])}
    yield {"type": "stop", "reason": "tool_use" if calls else reason}


# ── HTTP ──────────────────────────────────────────────────────────────────────

async def _sse(resp: httpx.Response) -> AsyncIterator[str]:
    async for line in resp.aiter_lines():
        if line.startswith("data:"):
            yield line[5:].strip()


async def chat_step(cfg: LlmCfg, system: str, messages: list[dict], tools: list[dict],
                    client: Optional[httpx.AsyncClient] = None, allow_tools: bool = True) -> AsyncIterator[dict]:
    """allow_tools=False keeps the tool definitions (history may contain tool blocks) but forbids new calls."""
    own = client is None
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(120, connect=15))

    if cfg.provider in ("claude", "claude-oauth"):
        url = f"{cfg.base_url}/v1/messages"
        if cfg.provider == "claude-oauth":
            # Resolved per-call (not in resolve_llm, which is sync): the access token can
            # expire mid-session and refreshing it needs an await. The Messages API only
            # honors an OAuth bearer token when these beta features AND the Claude Code
            # identity system-prompt line are both present — see
            # core/.../ClaudeOAuthProvider.java for the Java side of the same contract.
            try:
                access_token = await anthropic_oauth.get_access_token(client)
            except anthropic_oauth.AnthropicOAuthError as e:
                raise LlmError(str(e)) from None
            headers = {
                "Authorization": f"Bearer {access_token}",
                "anthropic-version": "2023-06-01",
                "anthropic-beta": anthropic_oauth.BETA_HEADER_VALUE,
                "anthropic-dangerous-direct-browser-access": "true",
            }
            # MUST be a two-block system array (identity block, then the real
            # prompt as its own block) — NOT a concatenated string. Confirmed by
            # direct testing: concatenating "<identity>\n\n<our prompt>" into one
            # string gets this OAuth token a 429 on every request once our prompt
            # is non-trivial (even ~50 extra characters triggers it), while the
            # exact same content split into two system blocks succeeds every
            # time. This matches Anthropic's own Claude Code CLI wire format and
            # pi-ai's reimplementation of it (see ClaudeOAuthProvider.java's
            # systemArray, built the same way) — apparently Anthropic validates
            # that an OAuth request "looks like" Claude Code at the message-shape
            # level, not just by string content, and a single merged block fails
            # that check even though a 429 is what comes back for it.
            effective_system = [
                {"type": "text", "text": anthropic_oauth.CLAUDE_CODE_IDENTITY},
                {"type": "text", "text": system},
            ]
        else:
            headers = {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01"}
            effective_system = system
        body = {"model": cfg.model, "max_tokens": settings.chat_max_output_tokens, "stream": True,
                "system": effective_system, "messages": messages, "tools": _tools_anthropic(tools)}
        if not allow_tools:
            body["tool_choice"] = {"type": "none"}
        parse = parse_anthropic
    else:
        url = f"{cfg.base_url}/v1/chat/completions"
        headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
        body = {"model": cfg.model, "stream": True, "max_tokens": settings.chat_max_output_tokens,
                "messages": to_openai(system, messages), "tools": _tools_openai(tools)}
        if not allow_tools:
            body["tool_choice"] = "none"
        parse = parse_openai

    try:
        max_retries = RETRYABLE_STATUS_MAX_RETRIES
        for attempt in range(max_retries + 1):
            # claude-oauth hits a much tighter short-burst rate limit on 429 than a paid
            # API key does — https://github.com/earendil-works/pi/issues/4621 and
            # https://dev.to/alexey-pelykh/claude-code-retries-rate-limit-errors-for-api-keys-not-for-your-max-plan-4p31
            # document the same subscription-side throttling. One retry at a flat 2s
            # delay (the old behavior here) burns through it almost immediately; this
            # mirrors pi-ai's own provider-retry backoff instead (see
            # utils/provider-retry.js: Retry-After[-ms] honored verbatim, else
            # exponential min(0.5*2^n, 8)s with jitter, 5 attempts by default).
            if cfg.provider == "claude-oauth" and attempt > 0:
                try:
                    access_token = await anthropic_oauth.get_access_token(client)
                except anthropic_oauth.AnthropicOAuthError as e:
                    raise LlmError(str(e)) from None
                headers["Authorization"] = f"Bearer {access_token}"
            async with client.stream("POST", url, headers=headers, json=body) as resp:
                if resp.status_code in RETRYABLE_STATUS and attempt < max_retries:
                    await asyncio.sleep(_retry_delay_seconds(resp.headers, attempt))
                    continue
                if resp.status_code != 200:
                    raw = (await resp.aread()).decode("utf-8", "replace")
                    try:
                        err = json.loads(raw).get("error", {})
                        msg = err.get("message") if isinstance(err, dict) else str(err)
                    except ValueError:
                        msg = raw
                    if resp.status_code == 429 and cfg.provider == "claude-oauth":
                        # Claude Pro/Max OAuth sessions hit a much tighter (and, empirically,
                        # fairly bursty/short-window) rate limit than a paid API key — see the
                        # citations above chat_step(). Already retried RETRYABLE_STATUS_MAX_RETRIES
                        # times with backoff by this point, so this is a real exhaustion, not a
                        # config problem; say so plainly instead of a bare HTTP 429.
                        raise LlmError(
                            "Claude (OAuth) is temporarily rate-limited by Anthropic — this happens "
                            "on Pro/Max subscription usage during bursts of requests, independent of "
                            "the server's ANTHROPIC_API_KEY quota. Wait a bit and try again.")
                    raise LlmError(f"{cfg.provider} returned HTTP {resp.status_code}: {(msg or '')[:200]}")
                async for ev in parse(_sse(resp)):
                    yield ev
                return
    except httpx.HTTPError as e:
        raise LlmError(f"{cfg.provider} request failed: {type(e).__name__}") from None
    finally:
        if own:
            await client.aclose()
