"""Connectivity check behind the Config tab's "Test Connection" button (and the legacy
upload-form one — same endpoint, /api/v1/llm/test).

Lists the provider's models with the supplied key (falling back to the server-configured key)
instead of spending a completion: cheap, side-effect free, and it proves both reachability and
that the key authenticates. The key is never echoed back in any message.
"""
from typing import Optional

import httpx

from . import scanner
from .agent import anthropic_oauth, aws_sigv4
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


async def _probe_bedrock(api_key: str, model: str, extra: Optional[dict],
                         client: Optional[httpx.AsyncClient]) -> dict:
    """api_key is unused for bedrock (kept only for the shared probe() signature) — credentials
    come from `extra` (Config tab form) or the server's stored/env config. Uses the bedrock
    control-plane's ListFoundationModels (GET, no body) rather than invoking a model: proves the
    credential pair authenticates and the region is reachable without spending any tokens."""
    extra = extra or {}
    access_key_id = (extra.get("access_key_id") or "").strip()
    secret_access_key = (extra.get("secret_access_key") or "").strip()
    region = (extra.get("region") or "").strip()

    used_server_key = not (access_key_id and secret_access_key)
    if used_server_key:
        env = scanner.llm_env("bedrock")
        access_key_id = access_key_id or env.get("AWS_ACCESS_KEY_ID", "")
        secret_access_key = secret_access_key or env.get("AWS_SECRET_ACCESS_KEY", "")
        region = region or env.get("AWS_REGION", "")
    region = region or "us-east-1"

    if not access_key_id or not secret_access_key:
        return _result(False, "bedrock", "Enter an AWS access key ID and secret access key "
                                         "(none is configured on the server either).")

    host = f"bedrock.{region}.amazonaws.com"
    url_path = "/foundation-models"
    headers = aws_sigv4.sign_request(
        method="GET", url_path=url_path, region=region, service="bedrock",
        access_key_id=access_key_id, secret_access_key=secret_access_key,
        host=host, body=b"", extra_headers={})

    own = client is None
    client = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        resp = await client.get(f"https://{host}{url_path}", headers=headers)
    except httpx.HTTPError as e:
        return _result(False, "bedrock", f"Could not reach AWS Bedrock: {type(e).__name__}.",
                      used_server_key=used_server_key)
    finally:
        if own:
            await client.aclose()

    if resp.status_code in (401, 403):
        return _result(False, "bedrock", "AWS rejected this access key/secret pair (or it lacks "
                                         "bedrock:ListFoundationModels).", used_server_key=used_server_key)
    if resp.status_code != 200:
        return _result(False, "bedrock", f"AWS Bedrock returned HTTP {resp.status_code}.",
                      used_server_key=used_server_key)

    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    items = payload.get("modelSummaries", []) if isinstance(payload, dict) else []
    ids = [str(m.get("modelId", "")) for m in items if isinstance(m, dict)]
    found = _model_listed(model, ids)
    msg = "Connected" + (" using the server's credentials" if used_server_key else "") + f" to region {region}."
    if found is False:
        msg += f" Model '{model.strip()}' was not in the region's foundation model list."
    return _result(True, "bedrock", msg, model_found=found, used_server_key=used_server_key)


async def probe(provider: str, api_key: str = "", model: str = "",
                client: Optional[httpx.AsyncClient] = None, extra: Optional[dict] = None) -> dict:
    p = (provider or "").strip().lower()
    if p not in PROVIDERS:
        raise ValueError(f"Unknown LLM provider '{provider}'")

    if p == "claude-oauth":
        if anthropic_oauth.is_configured():
            return _result(True, p, "A Claude OAuth session is stored on the server.", used_server_key=True)
        return _result(False, p, "No Claude OAuth session is stored on the server yet.")

    if p == "bedrock":
        return await _probe_bedrock(api_key, model, extra, client)

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
    elif p == "glm":  # OpenAI-compatible /v1 prefix, same shape as deepseek below
        base = env.get("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4").rstrip("/")
        url, headers = f"{base}/models", {"Authorization": f"Bearer {key}"}
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
