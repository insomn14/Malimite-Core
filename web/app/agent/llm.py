"""Minimal streaming tool-calling clients: Anthropic and OpenAI-compatible (openai/deepseek/ollama).

Neutral message format = Anthropic block lists:
  {"role": "user"|"assistant", "content": [text | tool_use | tool_result blocks]}
chat_step() yields events: {"type":"text","text"} | {"type":"tool_use","id","name","input"}
                           | {"type":"stop","reason"}
"""
import asyncio
import json
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import httpx

from .. import scanner
from ..config import settings

PROVIDERS = ("claude", "openai", "deepseek", "ollama")
_DEFAULT_MODEL = {"claude": "claude-sonnet-4-6", "openai": "gpt-4o-mini",
                  "deepseek": "deepseek-v4-flash", "ollama": "llama3.1"}
_KEY_ENV = {"claude": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "deepseek": "DEEPSEEK_API_KEY"}
MAX_TOKENS = 4096


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
    key = env.get(_KEY_ENV.get(p, ""), "")
    if p != "ollama" and not key:
        raise LlmError(f"{_KEY_ENV[p]} is not configured on the server.")
    base = {"claude": "https://api.anthropic.com", "openai": "https://api.openai.com",
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
    if cfg.provider == "claude":
        url = f"{cfg.base_url}/v1/messages"
        headers = {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01"}
        body = {"model": cfg.model, "max_tokens": MAX_TOKENS, "stream": True, "system": system,
                "messages": messages, "tools": _tools_anthropic(tools)}
        if not allow_tools:
            body["tool_choice"] = {"type": "none"}
        parse = parse_anthropic
    else:
        url = f"{cfg.base_url}/v1/chat/completions"
        headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
        body = {"model": cfg.model, "stream": True, "max_tokens": MAX_TOKENS,
                "messages": to_openai(system, messages), "tools": _tools_openai(tools)}
        if not allow_tools:
            body["tool_choice"] = "none"
        parse = parse_openai

    own = client is None
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(120, connect=15))
    try:
        for attempt in (0, 1):
            async with client.stream("POST", url, headers=headers, json=body) as resp:
                if resp.status_code in (429, 500, 502, 503, 529) and attempt == 0:
                    await asyncio.sleep(2)
                    continue
                if resp.status_code != 200:
                    raw = (await resp.aread()).decode("utf-8", "replace")
                    try:
                        err = json.loads(raw).get("error", {})
                        msg = err.get("message") if isinstance(err, dict) else str(err)
                    except ValueError:
                        msg = raw
                    raise LlmError(f"{cfg.provider} returned HTTP {resp.status_code}: {(msg or '')[:200]}")
                async for ev in parse(_sse(resp)):
                    yield ev
                return
    except httpx.HTTPError as e:
        raise LlmError(f"{cfg.provider} request failed: {type(e).__name__}") from None
    finally:
        if own:
            await client.aclose()
