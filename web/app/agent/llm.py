"""Minimal streaming tool-calling clients: Anthropic, OpenAI-compatible (openai/deepseek/ollama/glm),
and Bedrock (Anthropic models hosted on AWS Bedrock, SigV4-signed, AWS event-stream framing).

Neutral message format = Anthropic block lists:
  {"role": "user"|"assistant", "content": [text | image | tool_use | tool_result blocks]}
  image block: {"type":"image","source":{"type":"base64","media_type":"image/png","data":"<b64>"}}
chat_step() yields events: {"type":"text","text"} | {"type":"tool_use","id","name","input"}
                           | {"type":"stop","reason"}
"""
import asyncio
import base64
import json
import logging
import random
import time
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import httpx

from .. import scanner
from ..config import settings
from . import anthropic_oauth, aws_eventstream, aws_sigv4

_log = logging.getLogger("malimite")

PROVIDERS = ("claude", "claude-oauth", "openai", "deepseek", "ollama", "bedrock", "glm")
_DEFAULT_MODEL = {"claude": "claude-sonnet-5", "claude-oauth": "claude-sonnet-5",
                  "openai": "gpt-4o-mini", "deepseek": "deepseek-flash", "ollama": "llama3.1",
                  "bedrock": "anthropic.claude-sonnet-5-20260101-v1:0", "glm": "glm-4.6"}
_KEY_ENV = {"claude": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
           "glm": "GLM_API_KEY"}
# Providers whose chat/completions transport format accepts an image content block at all. This is
# a provider (wire-format) capability, not a per-model one — DeepSeek's chat models and most
# Ollama-pulled models (anything that isn't llava/bakllava/moondream/etc.) will still reject or
# silently ignore an image even though the provider is listed here; there is no reliable way to
# query "does this exact model support vision" without a provider-specific models API call, so a
# non-vision model's own error response is left to surface instead of guessing per-model.
VISION_CAPABLE_PROVIDERS = frozenset({"claude", "claude-oauth", "openai", "ollama", "bedrock", "glm"})
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
    # Bedrock-only: SigV4 needs the raw credential pair + region, not a bearer token.
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = ""


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
    if p == "bedrock":
        if not env.get("AWS_ACCESS_KEY_ID") or not env.get("AWS_SECRET_ACCESS_KEY"):
            raise LlmError(
                "AWS Bedrock is not configured on the server. Add an access key/secret in the "
                "Config tab.")
        return LlmCfg(p, m, "", "", env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"],
                     env.get("AWS_REGION", "us-east-1"))
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
            "ollama": env.get("OLLAMA_BASE_URL", "http://localhost:11434"),
            "glm": env.get("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")}[p]
    return LlmCfg(p, m, key, base.rstrip("/"))


# ── message translation ───────────────────────────────────────────────────────

def _openai_image_part(b: dict) -> dict:
    src = b["source"]
    return {"type": "image_url",
            "image_url": {"url": f"data:{src['media_type']};base64,{src['data']}"}}


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
            images = [b for b in blocks if b["type"] == "image"]
            text = "".join(b["text"] for b in blocks if b["type"] == "text")
            if images:
                # OpenAI-compatible vision wire format: content is a list of typed parts, not a
                # bare string, whenever an image is present (text-only messages keep the plain
                # string form above — both are valid per-message, they just can't mix here).
                parts: list[dict] = []
                if text:
                    parts.append({"type": "text", "text": text})
                parts.extend(_openai_image_part(b) for b in images)
                out.append({"role": "user", "content": parts})
            elif text:
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
    # Diagnostics only (never yielded as events, never changes behavior): a round that ends with
    # no text and no tool_use looks identical from loop.py's side whether the stream was truly
    # empty or the model spent its whole output budget on a "thinking" block we silently drop
    # below (seen for real: claude-opus-5-5 reasons by default with no `thinking` request param,
    # and reasoning counts against the same max_tokens as the visible answer). Logged so the next
    # occurrence is diagnosable from stop_reason/usage instead of guessed at again.
    saw_visible = False
    block_types_seen: set[str] = set()
    usage: dict = {}
    async for d in data:
        try:
            ev = json.loads(d)
        except ValueError:
            continue
        t = ev.get("type")
        if t == "content_block_start":
            cb = ev["content_block"]
            block_types_seen.add(cb["type"])
            blocks[ev["index"]] = {"type": cb["type"], "id": cb.get("id"), "name": cb.get("name"), "json": ""}
        elif t == "content_block_delta":
            dl = ev["delta"]
            if dl.get("type") == "text_delta":
                saw_visible = True
                yield {"type": "text", "text": dl["text"]}
            elif dl.get("type") == "input_json_delta" and ev["index"] in blocks:
                blocks[ev["index"]]["json"] += dl.get("partial_json", "")
        elif t == "content_block_stop":
            b = blocks.pop(ev["index"], None)
            if b and b["type"] == "tool_use":
                saw_visible = True
                yield {"type": "tool_use", "id": b["id"], "name": b["name"], "input": _args(b["json"])}
        elif t in ("message_start", "message_delta"):
            reason = ev.get("delta", {}).get("stop_reason") or reason
            usage.update((ev.get("message") or {}).get("usage") or ev.get("usage") or {})
        elif t == "error":
            raise LlmError(ev.get("error", {}).get("message", "provider stream error")[:200])
    if not saw_visible:
        _log.warning("claude stream produced no visible text/tool_use: stop_reason=%s block_types=%s usage=%s",
                     reason, sorted(block_types_seen), usage)
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


async def _bedrock_sse(resp: httpx.Response) -> AsyncIterator[str]:
    """Unwraps Bedrock's event-stream framing into the same bare-JSON-string shape _sse()
    yields, so parse_anthropic() (built for the native Messages API's SSE) can be reused
    unchanged — InvokeModelWithResponseStream's per-chunk payload IS an Anthropic
    content_block_delta/message_start/etc. event, just base64-wrapped inside one more
    JSON envelope ({"bytes": "<b64>", ...}) and framed as an AWS event-stream message
    instead of a `data: ...` SSE line."""
    async for ev_headers, payload in aws_eventstream.iter_events(resp.aiter_bytes()):
        if ev_headers.get(":event-type") == "exception" or ev_headers.get(":message-type") == "exception":
            try:
                detail = json.loads(payload.decode("utf-8", "replace"))
            except ValueError:
                detail = {}
            raise LlmError(f"bedrock stream error: {str(detail.get('message') or payload)[:200]}")
        try:
            envelope = json.loads(payload.decode("utf-8", "replace"))
        except ValueError:
            continue
        b64 = envelope.get("bytes")
        if not b64:
            continue
        try:
            yield base64.b64decode(b64).decode("utf-8", "replace")
        except (ValueError, TypeError):
            continue


async def chat_step(cfg: LlmCfg, system: str, messages: list[dict], tools: list[dict],
                    client: Optional[httpx.AsyncClient] = None, allow_tools: bool = True) -> AsyncIterator[dict]:
    """allow_tools=False keeps the tool definitions (history may contain tool blocks) but forbids new calls."""
    own = client is None
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(120, connect=15))

    if cfg.provider == "bedrock":
        # Bedrock's Anthropic-model wire format is the Messages API body (system/messages/
        # tools, same shape _tools_anthropic() already builds) MINUS "model" — the model id
        # is part of the URL path instead, not a JSON field. anthropic_version replaces the
        # claude/claude-oauth branch's "anthropic-version" HEADER (Bedrock wants it IN the
        # body); max_tokens is still required.
        region = cfg.aws_region or "us-east-1"
        host = f"bedrock-runtime.{region}.amazonaws.com"
        url_path = f"/model/{cfg.model}/invoke-with-response-stream"
        url = f"https://{host}{url_path}"
        body = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": settings.chat_max_output_tokens,
                "system": system, "messages": messages, "tools": _tools_anthropic(tools)}
        if not allow_tools:
            body["tool_choice"] = {"type": "none"}
        body_bytes = json.dumps(body).encode("utf-8")
        headers = aws_sigv4.sign_request(
            method="POST", url_path=url_path, region=region, service="bedrock",
            access_key_id=cfg.aws_access_key_id, secret_access_key=cfg.aws_secret_access_key,
            host=host, body=body_bytes,
            extra_headers={"content-type": "application/json", "accept": "application/vnd.amazon.eventstream"},
        )
        try:
            max_retries = RETRYABLE_STATUS_MAX_RETRIES
            for attempt in range(max_retries + 1):
                if attempt > 0:
                    # SigV4 signatures are timestamped (X-Amz-Date) and AWS rejects a request
                    # signed more than ~5 minutes in the past — cheap to re-sign per attempt
                    # rather than risk a stale signature on a slow backoff.
                    headers = aws_sigv4.sign_request(
                        method="POST", url_path=url_path, region=region, service="bedrock",
                        access_key_id=cfg.aws_access_key_id, secret_access_key=cfg.aws_secret_access_key,
                        host=host, body=body_bytes,
                        extra_headers={"content-type": "application/json",
                                      "accept": "application/vnd.amazon.eventstream"},
                    )
                async with client.stream("POST", url, headers=headers, content=body_bytes) as resp:
                    if resp.status_code in RETRYABLE_STATUS and attempt < max_retries:
                        await asyncio.sleep(_retry_delay_seconds(resp.headers, attempt))
                        continue
                    if resp.status_code != 200:
                        raw = (await resp.aread()).decode("utf-8", "replace")
                        try:
                            msg = json.loads(raw).get("message", raw)
                        except ValueError:
                            msg = raw
                        raise LlmError(f"bedrock returned HTTP {resp.status_code}: {(msg or '')[:200]}")
                    async for ev in parse_anthropic(_bedrock_sse(resp)):
                        yield ev
                    return
        except httpx.HTTPError as e:
            raise LlmError(f"bedrock request failed: {type(e).__name__}") from None
        finally:
            if own:
                await client.aclose()
        return

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
