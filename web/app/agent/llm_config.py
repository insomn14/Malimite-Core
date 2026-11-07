"""Persistent store for LLM provider credentials entered through the Config tab.

Counterpart to anthropic_oauth.py, but for the plain API-key providers (openai, claude,
deepseek, ollama, bedrock, glm) plus the scan-wide default provider/model. Anthropic OAuth
keeps its own dedicated file (anthropic-oauth.json) — this module never touches it; it only
tracks whether a claude-oauth session exists when reporting provider status.

Design goal (see the Config tab plan): a user should never have to paste an API key into the
upload form. Values saved here take priority over the matching *_API_KEY / AWS_* / GLM_*
environment variables in Settings, which remain a valid operator-managed bootstrap path (e.g.
CI deployments that provision the server via .env/compose and never touch the UI at all).

File shape (~/.malimite/llm-config.json by default — see Settings.llm_config_path):
    {
      "default_provider": "claude",
      "default_model": "claude-sonnet-5",
      "providers": {
        "openai":    {"api_key": "sk-...", "updated_at": "2026-...Z"},
        "claude":    {"api_key": "sk-ant-...", "updated_at": "..."},
        "deepseek":  {"api_key": "sk-...", "base_url": "https://api.deepseek.com", "updated_at": "..."},
        "ollama":    {"base_url": "http://localhost:11434", "updated_at": "..."},
        "bedrock":   {"access_key_id": "AKIA...", "secret_access_key": "...", "region": "us-east-1",
                       "model_id": "anthropic.claude-...", "updated_at": "..."},
        "glm":       {"api_key": "...", "base_url": "https://open.bigmodel.cn/api/paas/v4", "updated_at": "..."}
      }
    }

Never returns secret values to a caller that is going to hand them back to an HTTP response —
see mask()/provider_status() for the client-safe projection. Raw values are only read by
effective_env(), which feeds them straight into an outbound provider request header.
"""
import json
import time
from pathlib import Path
from typing import Optional

from ..config import settings

# Per-provider field names that hold a secret — masked (never echoed raw) by provider_status().
_SECRET_FIELDS = {
    "openai": ("api_key",),
    "claude": ("api_key",),
    "deepseek": ("api_key",),
    "ollama": (),  # no secret: base_url only
    "bedrock": ("access_key_id", "secret_access_key"),
    "glm": ("api_key",),
}

# Env var(s) each provider falls back to when nothing is stored in the config file —
# mirrors scanner.llm_env()'s old hardcoded mapping, now sourced from Settings fields
# instead (config.py) so both layers stay in sync with one definition.
_ENV_FALLBACK = {
    "openai": lambda: {"api_key": settings.openai_api_key},
    "claude": lambda: {"api_key": settings.anthropic_api_key},
    "deepseek": lambda: {"api_key": settings.deepseek_api_key, "base_url": settings.deepseek_base_url},
    "ollama": lambda: {"base_url": settings.ollama_base_url},
    "bedrock": lambda: {
        "access_key_id": settings.aws_access_key_id,
        "secret_access_key": settings.aws_secret_access_key,
        "region": settings.aws_region,
        "model_id": settings.bedrock_model_id,
    },
    "glm": lambda: {"api_key": settings.glm_api_key, "base_url": settings.glm_base_url},
}

KNOWN_PROVIDERS = tuple(_SECRET_FIELDS.keys())


def _path() -> Path:
    return Path(settings.llm_config_path)


def _empty() -> dict:
    return {"default_provider": "", "default_model": "", "providers": {}}


def load() -> dict:
    p = _path()
    if not p.is_file():
        return _empty()
    try:
        data = json.loads(p.read_text("utf-8"))
    except (OSError, ValueError):
        return _empty()
    if not isinstance(data, dict):
        return _empty()
    data.setdefault("default_provider", "")
    data.setdefault("default_model", "")
    if not isinstance(data.get("providers"), dict):
        data["providers"] = {}
    return data


def _save(data: dict) -> None:
    """Atomic write + best-effort 0600, same pattern as anthropic_oauth.py's _save()."""
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".tmp-{time.monotonic_ns()}")
    tmp.write_text(json.dumps(data, indent=2), "utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass  # non-POSIX or a shared docker mount can't always honor this — not fatal
    tmp.replace(p)


def get_provider(provider: str) -> Optional[dict]:
    return load()["providers"].get(provider)


def set_provider(provider: str, **fields) -> dict:
    """Stores (merges into) a provider's config entry. Unknown/None-valued fields are dropped
    so a partial update (e.g. just rotating api_key) never clobbers region/base_url etc."""
    if provider not in KNOWN_PROVIDERS:
        raise ValueError(f"Unknown LLM provider '{provider}'")
    data = load()
    current = dict(data["providers"].get(provider) or {})
    for k, v in fields.items():
        if v is None:
            continue
        v = v.strip() if isinstance(v, str) else v
        if v == "":
            continue
        current[k] = v
    current["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data["providers"][provider] = current
    _save(data)
    return current


def delete_provider(provider: str) -> bool:
    data = load()
    if provider not in data["providers"]:
        return False
    del data["providers"][provider]
    _save(data)
    return True


def set_default(provider: str = "", model: str = "") -> dict:
    data = load()
    data["default_provider"] = provider or ""
    data["default_model"] = model or ""
    _save(data)
    return data


def effective_fields(provider: str) -> dict:
    """Resolved field dict for one provider: stored config wins, env vars fill any gap.
    Returns {} for an unknown provider (and for claude-oauth, which has no key fields at all —
    see anthropic_oauth.py)."""
    if provider not in KNOWN_PROVIDERS:
        return {}
    stored = dict(load()["providers"].get(provider) or {})
    stored.pop("updated_at", None)
    fallback = _ENV_FALLBACK[provider]()
    merged = dict(fallback)
    merged.update({k: v for k, v in stored.items() if v})
    return merged


def is_configured(provider: str) -> bool:
    """True when the provider has everything it needs to make a request — stored config or
    env var fallback, either one. ollama needs no secret (local, often no-auth) so it always
    counts as configured; claude-oauth is reported by anthropic_oauth.is_configured() instead."""
    if provider == "ollama":
        return True
    required = _SECRET_FIELDS.get(provider)
    if not required:  # unknown provider, or a provider with no required secret fields
        return provider in KNOWN_PROVIDERS
    fields = effective_fields(provider)
    return all(fields.get(f) for f in required)


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def provider_status(provider: str) -> dict:
    """Client-safe snapshot for GET /api/v1/config/providers — never includes a raw secret."""
    stored = load()["providers"].get(provider) or {}
    fields = effective_fields(provider)
    # Any real (non-timestamp) key stored via the Config UI beats the env-var bootstrap, even
    # for a secret-free provider like ollama where "configured" is always true — a saved
    # base_url override still counts as "ui" rather than hiding behind the default "env".
    has_ui_value = any(k != "updated_at" and v for k, v in stored.items())
    source = "ui" if has_ui_value else ("env" if is_configured(provider) else "none")
    masked = {}
    for f in _SECRET_FIELDS.get(provider, ()):
        if fields.get(f):
            masked[f] = _mask(fields[f])
    non_secret = {k: v for k, v in fields.items() if k not in _SECRET_FIELDS.get(provider, ()) and v}
    return {
        "provider": provider,
        "configured": is_configured(provider),
        "source": source,
        "masked": masked,
        "fields": non_secret,
        "updated_at": stored.get("updated_at"),
    }
