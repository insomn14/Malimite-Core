"""Manages scan lifecycle: create, run CLI JAR, persist state."""
import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import settings
from .models import ScanDetail, ScanMeta


# ── helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scan_dir(scan_id: str) -> Path:
    return settings.scan_dir / scan_id


def _meta_path(scan_id: str) -> Path:
    return _scan_dir(scan_id) / "meta.json"


def _read_meta(scan_id: str) -> Optional[dict]:
    p = _meta_path(scan_id)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def _write_meta(scan_id: str, meta: dict) -> None:
    _meta_path(scan_id).write_text(json.dumps(meta, indent=2))


def _read_scan_json(scan_id: str) -> Optional[dict]:
    p = _scan_dir(scan_id) / "scan.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())


# ── public API ────────────────────────────────────────────────────────────────

def list_scans() -> list[ScanMeta]:
    if not settings.scan_dir.exists():
        return []
    result = []
    for d in sorted(settings.scan_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        m = _read_meta(d.name)
        if m:
            result.append(ScanMeta(**m))
    return result


def get_scan_detail(scan_id: str) -> Optional[ScanDetail]:
    meta = _read_meta(scan_id)
    if not meta:
        return None
    detail = ScanDetail(**meta)
    scan_json = _read_scan_json(scan_id)
    if scan_json:
        detail.bundle_id = scan_json.get("bundleIdentifier")
        detail.bundle_executable = scan_json.get("bundleExecutable")
        detail.platform = scan_json.get("platform")
        detail.is_swift = scan_json.get("isSwift")
        detail.is_universal = scan_json.get("isUniversal")
        detail.architectures = scan_json.get("architectures", [])
        detail.db_path = scan_json.get("dbPath")
        detail.ipa_path = scan_json.get("ipaPath") or scan_json.get("packagePath")
        detail.team_id = scan_json.get("bundleTeamId")
        detail.provisioning_profile = scan_json.get("provisioningProfile")
        detail.provisioning_expiry = scan_json.get("provisioningExpiry")
        detail.min_sdk = scan_json.get("minSdk")
        detail.target_sdk = scan_json.get("targetSdk")

    d = _scan_dir(scan_id)
    detail.has_sarif = (d / "findings.sarif").exists()
    detail.has_html = (d / "report.html").exists()
    detail.has_log = (d / "analysis.log").exists()

    # DB counts filled lazily by caller when needed
    return detail


def delete_scan(scan_id: str) -> bool:
    d = _scan_dir(scan_id)
    if not d.exists():
        return False
    import shutil
    shutil.rmtree(d)
    return True


async def regenerate_report(scan_id: str) -> bool:
    """
    Re-build report.html and findings.sarif for the given scan from its current
    SQLite state. Returns True on success. Used after triage updates so reports
    reflect reviewer decisions immediately.
    """
    d = _scan_dir(scan_id)
    if not d.exists():
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "java", "-cp", settings.cli_jar,
            "io.mailmite.core.ReportRenderer", str(d),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            import logging as _logging
            _logging.getLogger("mailmite").warning(
                "ReportRenderer failed for %s (rc=%s): %s",
                scan_id, proc.returncode, stderr.decode("utf-8", "replace")[:500])
            return False
        return True
    except Exception as exc:
        import logging as _logging
        _logging.getLogger("mailmite").warning(
            "ReportRenderer subprocess error for %s: %s", scan_id, exc)
        return False


async def create_scan(
    ipa_bytes: bytes,
    filename: str,
    llm_enabled: bool,
    llm_provider: str,
    llm_mode: str,
    llm_model: str,
    llm_api_key: str = "",
    assessment_enabled: bool = True,
) -> ScanMeta:
    settings.scan_dir.mkdir(parents=True, exist_ok=True)
    scan_id = str(uuid.uuid4())
    d = _scan_dir(scan_id)
    d.mkdir(parents=True)

    ext = ".apk" if filename.lower().endswith(".apk") else ".ipa"
    ipa_path = d / f"upload{ext}"
    ipa_path.write_bytes(ipa_bytes)

    meta = {
        "scan_id": scan_id,
        "filename": filename,
        "state": "queued",
        "created_at": _now(),
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "llm_enabled": llm_enabled,
        "llm_provider": llm_provider,
        "llm_mode": llm_mode,
        "llm_model": llm_model,
        "assessment_enabled": assessment_enabled,
        # not exposed in ScanMeta — only used internally by _run
        "_llm_api_key": llm_api_key,
    }
    _write_meta(scan_id, meta)
    asyncio.create_task(_run(scan_id, ipa_path, d, meta))
    return ScanMeta(**{k: v for k, v in meta.items() if not k.startswith("_")})


# ── background runner ─────────────────────────────────────────────────────────

async def _run(scan_id: str, ipa_path: Path, out_dir: Path, meta: dict) -> None:
    meta["state"] = "running"
    meta["started_at"] = _now()
    _write_meta(scan_id, meta)

    cmd = [
        "java", "-jar", settings.cli_jar,
        str(ipa_path),
        "--ghidra", settings.ghidra_home,
        "--out", str(out_dir),
        "--sarif",
        "--html",
    ]
    if meta["llm_enabled"] and meta["llm_provider"] not in ("none", ""):
        cmd += ["--llm",
                "--llm-provider", meta["llm_provider"],
                "--llm-mode", meta["llm_mode"]]
        if meta["llm_model"]:
            cmd += ["--llm-model", meta["llm_model"]]
    # Default CLI assessment=true; omit the flag when enabled so older picocli
    # jars with inverted --assessment polarity cannot disable the scan.
    if not meta.get("assessment_enabled", True):
        cmd += ["--no-assessment"]

    env = dict(os.environ)
    # Per-request key takes priority over the .env/settings key
    per_req_key = meta.get("_llm_api_key", "")
    provider = meta.get("llm_provider", "none")

    if provider == "openai":
        key = per_req_key or settings.openai_api_key
        if key:
            env["OPENAI_API_KEY"] = key
    elif provider == "claude":
        key = per_req_key or settings.anthropic_api_key
        if key:
            env["ANTHROPIC_API_KEY"] = key
    elif provider == "deepseek":
        key = per_req_key or settings.deepseek_api_key
        if key:
            env["DEEPSEEK_API_KEY"] = key
        if settings.deepseek_base_url:
            env["DEEPSEEK_BASE_URL"] = settings.deepseek_base_url
    elif provider == "ollama":
        env["OLLAMA_BASE_URL"] = settings.ollama_base_url or "http://localhost:11434"

    log_path = out_dir / "analysis.log"
    try:
        with open(log_path, "w") as log_fh:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=log_fh,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            exit_code = await proc.wait()
    except Exception as exc:
        log_path.write_text(f"Failed to start CLI: {exc}\n")
        exit_code = -1

    meta["state"] = "done" if exit_code == 0 else "error"
    meta["finished_at"] = _now()
    meta["exit_code"] = exit_code
    _write_meta(scan_id, meta)
