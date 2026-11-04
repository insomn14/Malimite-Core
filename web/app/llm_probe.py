"""Connectivity check behind the upload form's "Test Connection" button.

Lists the provider's models with the supplied key (falling back to the server-configured key)
instead of spending a completion: cheap, side-effect free, and it proves both reachability and
that the key authenticates. The key is never echoed back in any message.
"""
from typing import Optional

import httpx

from . import scanner
from .agent import anthropic_oauth
from .agent.llm import PROVIDERS, _KEY_ENV

_TIMEOUT = httpx.Timeout(15, connect=8)


def _result(ok: bool, provider: str, message: str, *, model_found: Optional[bool] = None,
            used_server_key: bool = False) -> dict:
    return {"ok": ok, "provider": provider, "message": message,
            "model_found": model_found, "used_server_key": used_server_key}


def _model_listed(model: str, ids: list[str]) -> Optional[bool]:
    model = (model or "").strip()
    if not model:
        return None
    # ollama tags look like "llama3:latest"; a bare "llama3" means the same model
    return any(i == model or i.split(":", 1)[0] == model for i in ids)


async def probe(provider: str, api_key: str = "", model: str = "",
                client: Optional[httpx.AsyncClient] = None) -> dict:
    p = (provider or "").strip().lower()
    if p not in PROVIDERS:
        raise ValueError(f"Unknown LLM provider '{provider}'")

    if p == "claude-oauth":
        if anthropic_oauth.is_configured():
            return _result(True, p, "A Claude OAuth session is stored on the server.", used_server_key=True)
        return _result(False, p, "No Claude OAuth session is stored on the server yet.")

    supplied = (api_key or "").strip()
    env = scanner.llm_env(p, supplied)
    key = env.get(_KEY_ENV.get(p, ""), "")
    used_server_key = bool(key) and not supplied
    if p != "ollama" and not key:
        return _result(False, p, "Enter an API key (none is configured on the server either).")

    if p == "ollama":
        base = env.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        url, headers = f"{base}/api/tags", {}
    elif p == "claude":
        url = "https://api.anthropic.com/v1/models?limit=1000"
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    elif p == "openai":
        url, headers = "https://api.openai.com/v1/models", {"Authorization": f"Bearer {key}"}
    else:  # deepseek — same /v1 prefix the chat client uses against DEEPSEEK_BASE_URL
        base = env.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
        url, headers = f"{base}/v1/models", {"Authorization": f"Bearer {key}"}

    own = client is None
    client = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        resp = await client.get(url, headers=headers)
    except httpx.HTTPError as e:
        return _result(False, p, f"Could not reach {p}: {type(e).__name__}.", used_server_key=used_server_key)
    finally:
        if own:
            await client.aclose()

    if resp.status_code in (401, 403):
        return _result(False, p, "The provider rejected this API key.", used_server_key=used_server_key)
    if resp.status_code != 200:
        return _result(False, p, f"{p} returned HTTP {resp.status_code}.", used_server_key=used_server_key)

    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    items = payload.get("models" if p == "ollama" else "data", []) if isinstance(payload, dict) else []
    ids = [str(m.get("name" if p == "ollama" else "id", "")) for m in items if isinstance(m, dict)]
    found = _model_listed(model, ids)
    msg = "Connected" + (" using the server's key" if used_server_key else "") + "."
    if found is False:
        msg += f" Model '{model.strip()}' was not in the provider's model list."
    return _result(True, p, msg, model_found=found, used_server_key=used_server_key)
