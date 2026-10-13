"""Phase bucketing shared by the offensive Frida kit export (main.py) and the hook-target
recommendation tool (agent/tools.py). Split out so the agent package can use it without
importing main.py (which imports from agent/), which would be circular."""
import re

PHASE_DIRS = {
    "ENVIRONMENT": "01_environment",
    "TRANSPORT": "02_transport",
    "SECRETS": "03_secrets",
    "SESSION": "04_session",
}
CAT_TO_PHASE = {
    "ROOT_DETECTION": "ENVIRONMENT",
    "JAILBREAK": "ENVIRONMENT",
    "SSL_PINNING": "TRANSPORT",
    "CRYPTO": "SECRETS",
    "BIOMETRIC": "SESSION",
    "OTHER": "SESSION",
}


def normalize_phase(target: dict) -> str:
    phase = str(target.get("phase") or "").strip().upper()
    if phase in PHASE_DIRS:
        return phase
    cat = str(target.get("category") or "OTHER").strip().upper().replace("-", "_")
    return CAT_TO_PHASE.get(cat, "SESSION")


def slug(s: str, fallback: str = "target") -> str:
    t = re.sub(r"[^a-zA-Z0-9._-]+", "_", (s or "").strip())[:60].strip("_")
    return t or fallback
