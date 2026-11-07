"""Malimite Python web service — wraps all Malimite-Core functionality."""
import asyncio
import hmac
import io
import json
import logging
import re
import time
import zipfile
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiofiles
from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auto_enhance, db, finding_fix, llm_probe, offensive_phases, scanner
from .agent import anthropic_oauth, llm_config, loop as agent_loop, ondemand, store as chat_store
from .agent.llm import PROVIDERS as LLM_PROVIDERS, VISION_CAPABLE_PROVIDERS, LlmError, resolve_llm
from .agent.tools import Ctx, valid_class_name
from .config import settings
from .models import ScanDetail, ScanMeta

_ACCEPTED_EXTENSIONS = (".ipa", ".apk", ".xapk")   # .xapk = split-APK bundle, merged into one APK by the CLI
_OFFENSIVE_MODE_ALIASES = frozenset({"offensive", "offense", "frida", "bypass"})
_FAST_MODE_ALIASES = frozenset({"summarize", "summary", "fast", "fast_scan", "fastscan"})
_FULL_MODE_ALIASES = frozenset({"find_vulns", "vulns", "vuln", "full", "full_scan", "fullscan"})
_AUTO_FIX_MODE_ALIASES = frozenset({"auto_fix", "autofix", "fix"})

_RETENTION_INTERVAL_S = 86400  # once a day is plenty for a days-granularity retention policy


async def _retention_loop() -> None:
    """Runs scanner.delete_expired_scans() once a day for as long as the app is up. A no-op loop
    (returns immediately each time) when scan_retention_days is 0 — still started unconditionally
    so flipping the setting takes effect on the next tick without a restart being required."""
    log = logging.getLogger("malimite")
    while True:
        try:
            scanner.delete_expired_scans()
        except Exception:
            log.warning("Scan retention sweep failed", exc_info=True)
        await asyncio.sleep(_RETENTION_INTERVAL_S)


@asynccontextmanager
async def _lifespan(_: FastAPI):
    log = logging.getLogger("malimite")
    n = scanner.scrub_stored_keys()
    if n:
        log.warning("removed plaintext per-upload LLM keys from %d meta.json file(s)", n)
    r = scanner.reap_stale_running_scans()
    if r:
        log.warning("marked %d scan(s) as errored: stuck queued/running from before this restart", r)
    if settings.scan_retention_days > 0:
        d = scanner.delete_expired_scans()
        if d:
            log.info("Retention: deleted %d expired scan(s) at startup", d)
    if not settings.api_key:
        log.warning("API_KEY is not set: anyone who can reach this port can upload scans, read results and "
                    "spend this server's LLM quota through the AI Assistant. Set API_KEY and/or bind to 127.0.0.1.")
    retention_task = asyncio.create_task(_retention_loop())
    try:
        yield
    finally:
        retention_task.cancel()
        try:
            await retention_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Malimite", version="0.1.0", docs_url="/docs", redoc_url=None, lifespan=_lifespan)

_WEB = Path(__file__).parent.parent
app.mount("/vendor", StaticFiles(directory=_WEB / "vendor"), name="vendor")


# ── auth ──────────────────────────────────────────────────────────────────────

def _check_auth(request: Request) -> None:
    if not settings.api_key:
        return
    key = request.headers.get("X-Api-Key", "")
    if not hmac.compare_digest(key.encode("utf-8"), settings.api_key.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid API key")


# ── UI ────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    html = (_WEB / "index.html").read_text()
    return HTMLResponse(html)


# ── scan CRUD ─────────────────────────────────────────────────────────────────

@app.get("/api/v1/scans", response_model=list[ScanMeta])
async def list_scans(request: Request):
    _check_auth(request)
    return scanner.list_scans()


@app.post("/api/v1/scans", response_model=ScanMeta, status_code=202)
async def create_scan(
    request: Request,
    file: UploadFile = File(...),
    llm_enabled: bool = Form(False),
    llm_provider: str = Form("none"),
    llm_mode: str = Form("summarize"),
    llm_model: str = Form(""),
    llm_api_key: str = Form(""),
    assessment_enabled: bool = Form(True),
    ios_light: bool = Form(False),
    decompiler: str = Form("jadx"),
    ci_pipeline_url: Optional[str] = Form(None),
    ci_commit_sha: Optional[str] = Form(None),
    ci_triggered_by: Optional[str] = Form(None),
):
    _check_auth(request)
    name = file.filename.lower()
    if not name.endswith(_ACCEPTED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Only .ipa, .apk or .xapk files are accepted")
    if decompiler not in ("jadx", "asc"):
        raise HTTPException(status_code=422, detail="decompiler must be 'jadx' or 'asc'")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    # Credential source, in priority order: (1) llm_api_key — a per-upload override, kept only
    # for CI pipelines/scripts that still POST it directly and never touch the Config tab;
    # (2) the Config tab's stored credentials; (3) the server's own *_API_KEY/.env bootstrap.
    # The upload form itself no longer collects a key at all — see index.html's
    # renderScanOptionsHtml(), which only offers providers llm_config already reports as
    # configured. This keeps a bare `curl -F llm_api_key=...` working unchanged.
    needs_key = llm_enabled and llm_provider in ("openai", "claude", "deepseek", "bedrock", "glm")
    if needs_key:
        env = scanner.llm_env(llm_provider, llm_api_key.strip())
        key_env_name = {
            "openai": "OPENAI_API_KEY", "claude": "ANTHROPIC_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
            "glm": "GLM_API_KEY",
        }.get(llm_provider)
        if llm_provider == "bedrock":
            configured = bool(env.get("AWS_ACCESS_KEY_ID") and env.get("AWS_SECRET_ACCESS_KEY"))
        else:
            configured = bool(env.get(key_env_name))
        if not configured:
            raise HTTPException(
                status_code=422,
                detail=f"Provider '{llm_provider}' is not configured on this server. "
                       f"Add it in the Config tab (or pass llm_api_key with this request).",
            )
    mode_norm = (llm_mode or "").strip().lower().replace("-", "_").replace(" ", "_")
    if mode_norm in _OFFENSIVE_MODE_ALIASES:
        if not llm_enabled or llm_provider in ("none", ""):
            raise HTTPException(
                status_code=422,
                detail="Offensive mode requires LLM Enrichment (select a provider).",
            )
        llm_mode = "offensive"
    elif mode_norm in _FAST_MODE_ALIASES:
        llm_mode = "summarize"
    elif mode_norm in _FULL_MODE_ALIASES:
        llm_mode = "find_vulns"
    elif mode_norm in _AUTO_FIX_MODE_ALIASES:
        llm_mode = "auto_fix"
    return await scanner.create_scan(
        data, file.filename,
        llm_enabled, llm_provider, llm_mode, llm_model, llm_api_key,
        assessment_enabled, ios_light, decompiler,
        ci_pipeline_url, ci_commit_sha, ci_triggered_by,
    )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(request: Request, scan_id: str):
    _check_auth(request)
    detail = scanner.get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Enrich with DB counts when available
    if detail.db_path and detail.bundle_executable and Path(detail.db_path).exists():
        try:
            counts = await db.get_counts(detail.db_path, detail.bundle_executable)
            detail.class_count = counts["class_count"]
            detail.function_count = counts["function_count"]
            detail.string_count = counts["string_count"]
            detail.entry_point_count = counts["entry_point_count"]
            detail.llm_finding_count = counts["llm_finding_count"]
            detail.vulnerability_counts = await db.get_vulnerability_counts(
                detail.db_path, detail.bundle_executable)
            # A scan that finished without storing a single class/function/string/entry point did
            # not come back "clean" — the analysis itself produced nothing (decompiler crash, killed
            # subprocess, failed ingest). Only judged once counts were actually read, so a scan whose
            # database is missing stays "unknown" rather than being reported as empty.
            detail.empty_result = (detail.state == "done"
                                   and not (detail.class_count or detail.function_count
                                            or detail.string_count or detail.entry_point_count))
        except Exception:
            pass
    return detail


@app.delete("/api/v1/scans/{scan_id}", status_code=204)
async def delete_scan(request: Request, scan_id: str):
    _check_auth(request)
    if not scanner.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")


# ── data endpoints ────────────────────────────────────────────────────────────

def _require_db(scan_id: str) -> tuple[str, str]:
    """Return (db_path, executable_name) or raise 404/409."""
    detail = scanner.get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    if detail.state != "done":
        raise HTTPException(status_code=409, detail=f"Scan state is '{detail.state}'")
    if not detail.db_path or not Path(detail.db_path).exists():
        raise HTTPException(status_code=404, detail="Database not found")
    if not detail.bundle_executable:
        raise HTTPException(status_code=404, detail="bundle_executable unknown")
    return detail.db_path, detail.bundle_executable


@app.get("/api/v1/scans/{scan_id}/functions")
async def get_functions(
    request: Request,
    scan_id: str,
    class_name: Optional[str] = None,
    page: int = 0,
    size: int = 50,
):
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    return await db.get_functions(db_path, exe, class_name, page, size)


@app.get("/api/v1/scans/{scan_id}/classes")
async def get_classes(request: Request, scan_id: str, query: str = "", limit: int = 200_000, offset: int = 0):
    """Class names only (no decompiled code) — the data source for the Functions tab's file tree.
    Unlike the chat agent's list_classes tool, the tree needs the whole inventory at once, so this
    route raises db.list_classes's default 200-row cap (a real app can have tens of thousands)."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    return await db.list_classes(db_path, exe, query, limit, offset, cap=200_000)


@app.get("/api/v1/scans/{scan_id}/source")
async def get_source(request: Request, scan_id: str, class_name: str, function_name: Optional[str] = None):
    """Stored decompiled code for one class (whole body) or one function."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    return await db.get_source(db_path, exe, class_name, function_name)


@app.get("/api/v1/scans/{scan_id}/code-search")
async def get_code_search(request: Request, scan_id: str, q: str, limit: int = 30):
    """Substring search over all stored decompiled code."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    return await db.search_code(db_path, exe, q, limit)


class DecompileRequest(BaseModel):
    tool: str
    target: str


@app.post("/api/v1/scans/{scan_id}/decompile")
async def post_decompile(request: Request, scan_id: str, req: DecompileRequest):
    """On-demand decompile of one Android class for the Functions tab, when nothing is stored yet.
    Android asc/jadx only — ghidra native targets (iOS Mach-O, Android .so) need a symbol/address
    picker this tab doesn't have, and stay reachable only through the AI Assistant's decompile tool.
    Shares its cache (and its concurrency limit) with that tool: both read/write the same
    AgentDecompiles table in <scan_dir>/<id>/chat.sqlite."""
    _check_auth(request)
    _require_db(scan_id)
    detail = scanner.get_scan_detail(scan_id)
    if req.tool not in ("asc", "jadx"):
        raise HTTPException(status_code=422,
                             detail="only asc/jadx is available here; ghidra targets go through the AI Assistant")
    if str(detail.platform or "").upper() != "ANDROID":
        raise HTTPException(status_code=422, detail="asc/jadx decompile is Android-only")
    if not valid_class_name(req.target):
        raise HTTPException(status_code=422, detail="invalid class name")

    scan_dir = scanner._scan_dir(scan_id)
    chat_db = chat_store.path_for(scan_dir)
    code = await chat_store.cache_get(chat_db, req.tool, "", req.target)
    cached = code is not None
    if code is None:
        try:
            res = await asyncio.wait_for(ondemand.decompile(scan_dir, req.tool, req.target, ""),
                                          timeout=settings.ghidra_ondemand_timeout)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="decompile timed out")
        if not res.get("ok"):
            raise HTTPException(status_code=502, detail=res.get("error") or "decompile failed")
        code = res["code"]
        await chat_store.cache_put(chat_db, req.tool, "", req.target, code)
    return {"tool": req.tool, "target": req.target, "code": code, "cached": cached}


@app.get("/api/v1/scans/{scan_id}/strings")
async def get_strings(
    request: Request,
    scan_id: str,
    q: Optional[str] = None,
    limit: int = Query(default=200, ge=0, le=2000),
    page: Optional[int] = Query(default=None, ge=1),
    size: int = Query(default=50, ge=10, le=200),
):
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    # Keep the original list response for callers that do not opt into pagination.
    if page is not None:
        return await db.get_strings_page(db_path, exe, q, page, size)
    return await db.get_strings(db_path, exe, q, limit)


@app.get("/api/v1/scans/{scan_id}/resources")
async def get_resources(
    request: Request, scan_id: str,
    q: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = Query(default=200, ge=0, le=2000),
    page: Optional[int] = Query(default=None, ge=1),
    size: int = Query(default=50, ge=10, le=200),
):
    _check_auth(request)
    db_path, _ = _require_db(scan_id)
    # Keep the original flat list response for callers that do not opt into pagination
    # (e.g. the raw API link on the Downloads tab).
    if page is not None:
        return await db.get_resources_page(db_path, type, q, page, size)
    return await db.get_resources(db_path, limit)


@app.get("/api/v1/scans/{scan_id}/entrypoints")
async def get_entry_points(request: Request, scan_id: str):
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    return await db.get_entry_points(db_path, exe)


@app.get("/api/v1/scans/{scan_id}/llm")
async def get_llm_findings(
    request: Request,
    scan_id: str,
    q: Optional[str] = None,
    page: Optional[int] = Query(default=None, ge=1),
    size: int = Query(default=50, ge=10, le=200),
    sort: Optional[str] = Query(default=None),
    sort_dir: Optional[str] = Query(default=None, alias="dir"),
):
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    # Keep the original list response for callers that do not opt into pagination
    # (Offensive tab, Frida kit export, and other in-repo consumers).
    if page is not None:
        return await db.get_llm_findings_page(
            db_path, exe, q, page, size, sort, sort_dir
        )
    return await db.get_llm_findings(db_path, exe)


def _parse_offensive_targets(finding_text: str) -> list[dict]:
    """Best-effort parse of cleaned/raw offensive_targets JSON from an LlmFindings row."""
    if not finding_text or not finding_text.strip():
        return []
    text = finding_text.strip()
    candidates: list[str] = [text]
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.I)
    if m:
        candidates.insert(0, m.group(1).strip())
    # Prefer last embedded {"offensive_targets":
    key = '"offensive_targets"'
    best = -1
    from_idx = 0
    while True:
        ki = text.find(key, from_idx)
        if ki < 0:
            break
        i = ki - 1
        while i >= 0 and text[i].isspace():
            i -= 1
        if i >= 0 and text[i] == "{":
            best = i
        from_idx = ki + 1
    if best >= 0:
        depth = 0
        in_str = False
        esc = False
        end = -1
        for i, c in enumerate(text[best:], start=best):
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
        if end > best:
            candidates.insert(0, text[best:end])

    for cand in candidates:
        try:
            obj = json.loads(cand)
        except Exception:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("offensive_targets"), list):
            return [t for t in obj["offensive_targets"] if isinstance(t, dict)]
    return []


@app.get("/api/v1/scans/{scan_id}/offensive/kit")
async def export_offensive_frida_kit(request: Request, scan_id: str):
    """Zip Frida kit: 01_environment/ … 04_session/ + README (authorized testing)."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    findings = await db.get_llm_findings(db_path, exe)
    targets: list[dict] = []
    for f in findings:
        mode = str(getattr(f, "mode", "") or "").upper()
        if mode and mode != "OFFENSIVE":
            continue
        for t in _parse_offensive_targets(getattr(f, "finding", "") or ""):
            row = dict(t)
            row["_phase"] = offensive_phases.normalize_phase(row)
            row["_fn"] = getattr(f, "function_name", "") or ""
            row["_cls"] = getattr(f, "class_name", "") or ""
            targets.append(row)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        readme = (
            "Malimite Offensive Frida kit\n"
            "============================\n\n"
            "AUTHORIZED TESTING ONLY. Use these scripts only on apps you are\n"
            "permitted to instrument.\n\n"
            "Suggested load order:\n"
            "  1. 01_environment/  — root / jailbreak / anti-Frida bypass\n"
            "  2. 02_transport/    — SSL pinning / MITM helpers\n"
            "  3. 03_secrets/      — crypto plaintext / key intercept\n"
            "  4. 04_session/      — biometric / token hooks\n\n"
            "Example:\n"
            "  frida -U -f <package> -l 01_environment/01_bypass.js --no-pause\n"
        )
        zf.writestr("README.md", readme)
        for folder in offensive_phases.PHASE_DIRS.values():
            zf.writestr(f"{folder}/.keep", "")
        counters = {p: 0 for p in offensive_phases.PHASE_DIRS}
        for t in targets:
            phase = t.get("_phase") or "SESSION"
            folder = offensive_phases.PHASE_DIRS.get(phase, "04_session")
            counters[phase] = counters.get(phase, 0) + 1
            n = counters[phase]
            script = (t.get("frida_script") or "").strip()
            if not script:
                continue
            title = offensive_phases.slug(str(t.get("title") or "target"), f"target_{n}")
            name = f"{n:02d}_{title}.js"
            header = (
                f"// Malimite Offensive — {t.get('title') or title}\n"
                f"// phase={phase} category={t.get('category') or ''} "
                f"priority={t.get('priority') or ''}\n"
                f"// from={t.get('_cls') or ''}.{t.get('_fn') or ''}\n"
                f"// {t.get('script_notes') or ''}\n\n"
            )
            zf.writestr(f"{folder}/{name}", header + script)
    data = buf.getvalue()
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition":
                f'attachment; filename="malimite-offensive-kit-{scan_id[:8]}.zip"'
        },
    )


@app.get("/api/v1/scans/{scan_id}/vulnerabilities")
async def get_vulnerabilities(request: Request, scan_id: str):
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    return await db.get_vulnerabilities(db_path, exe)


@app.get("/api/v1/scans/{scan_id}/assessments")
async def get_assessments(request: Request, scan_id: str):
    """Security-controls inventory (Assessment mode)."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    return await db.get_assessments(db_path, exe)


class VulnerabilityTriage(BaseModel):
    """Triage update payload — all fields optional, only supplied ones are changed."""
    status: Optional[str] = Field(
        default=None,
        pattern=r"^(open|false_positive|accepted_risk|fixed)$",
        description="Lifecycle status of the finding")
    override_severity: Optional[str] = Field(
        default=None,
        description="Override severity. Pass an empty string to clear an existing override.")
    override_cvss_score: Optional[float] = Field(
        default=None, ge=0.0, le=10.0,
        description="Override CVSS score (0.0-10.0)")
    override_note: Optional[str] = Field(
        default=None, max_length=2000,
        description="Reviewer note explaining the change")


@app.patch("/api/v1/scans/{scan_id}/vulnerabilities/{vuln_id}")
async def patch_vulnerability(
    request: Request,
    scan_id: str,
    vuln_id: int,
    triage: VulnerabilityTriage = Body(...),
):
    """Update triage fields for one vulnerability (status / override severity / note)."""
    _check_auth(request)
    db_path, _ = _require_db(scan_id)

    # Validate override severity if non-empty
    if triage.override_severity:
        if triage.override_severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            raise HTTPException(status_code=422,
                detail="override_severity must be CRITICAL|HIGH|MEDIUM|LOW|INFO or empty to clear")

    ok = await db.update_vulnerability_triage(
        db_path, vuln_id,
        status=triage.status,
        override_severity=triage.override_severity.upper() if triage.override_severity else triage.override_severity,
        override_cvss_score=triage.override_cvss_score,
        override_note=triage.override_note,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Re-render the static HTML + SARIF reports so a subsequent download reflects
    # the new triage state. Failures are non-fatal — the live UI still works.
    regenerated = await scanner.regenerate_report(scan_id)
    return {"updated": True, "report_regenerated": regenerated}


# ── AI Fix (per-finding Description/Evidence/Risk/PoC/Remediation rewrite) ────────────────────

class AiFixRequest(BaseModel):
    """All fields optional: provider/model override the scan default (same pattern as the
    AI Assistant chat tab); fields restricts which parts of the finding are rewritten."""
    provider: Optional[str] = None   # override; must be in agent.llm.PROVIDERS
    model: Optional[str] = None
    fields: Optional[list[str]] = Field(
        default=None,
        description="Subset of description|evidence|risk|poc_steps|remediation; default = all")


def _validate_fix_fields(fields: Optional[list[str]]) -> None:
    if fields:
        bad = [f for f in fields if f not in finding_fix.FIXABLE_FIELDS]
        if bad:
            raise HTTPException(status_code=422,
                detail=f"fields must be a subset of {list(finding_fix.FIXABLE_FIELDS)}; got {bad}")


@app.post("/api/v1/scans/{scan_id}/vulnerabilities/{vuln_id}/ai-fix")
async def ai_fix_vulnerability(
    request: Request,
    scan_id: str,
    vuln_id: int,
    req: AiFixRequest = Body(default_factory=AiFixRequest),
):
    """Calls the configured LLM to rewrite Description/Evidence/Risk/PoC/Remediation for one
    finding. Results are stored as reversible overrides (see db.update_vulnerability_ai_fix) —
    the original scanned fields are never modified. Shares the chat rate limit with the AI
    Assistant: both spend the same server-side LLM quota."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    _chat_rate_limit()

    row = await db.get_vulnerability_row(db_path, exe, vuln_id)
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    _validate_fix_fields(req.fields)

    detail = scanner.get_scan_detail(scan_id)
    try:
        cfg = resolve_llm(detail.llm_provider, detail.llm_model, req.provider, req.model)
    except LlmError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        fix = await auto_enhance.apply_ai_fix_to_row(db_path, exe, cfg, row, req.fields)
    except LlmError as e:
        raise HTTPException(status_code=502, detail=str(e))
    if fix is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    regenerated = await scanner.regenerate_report(scan_id)
    updated = await db.get_vulnerability_row(db_path, exe, vuln_id)
    return {"updated": True, "report_regenerated": regenerated, "vulnerability": updated}


@app.post("/api/v1/scans/{scan_id}/vulnerabilities/{vuln_id}/ai-fix/revert")
async def revert_ai_fix_vulnerability(request: Request, scan_id: str, vuln_id: int):
    """Clears a previously applied AI Fix, restoring the original scanned fields. A human's own
    manual triage override (status/severity/CVSS/note) is left untouched — see
    db.revert_vulnerability_ai_fix for the exact precedence rule."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)

    ok = await db.revert_vulnerability_ai_fix(db_path, vuln_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    regenerated = await scanner.regenerate_report(scan_id)
    updated = await db.get_vulnerability_row(db_path, exe, vuln_id)
    return {"updated": True, "report_regenerated": regenerated, "vulnerability": updated}


# ── Auto Enhance (bulk AI Fix over many findings, as a background job) ──────────────────────

class AutoEnhanceRequest(BaseModel):
    vuln_ids: list[int] = Field(min_length=1, description="Finding ids to enhance (one per unique issue)")
    provider: Optional[str] = None
    model: Optional[str] = None
    fields: Optional[list[str]] = Field(
        default=None,
        description="Subset of description|evidence|risk|poc_steps|remediation; default = all")


@app.post("/api/v1/scans/{scan_id}/auto-enhance", status_code=202)
async def start_auto_enhance(request: Request, scan_id: str, req: AutoEnhanceRequest):
    """Starts a background job that runs AI Fix on every listed finding (same reversible
    overrides as the per-finding endpoint), regenerating the report once at the end. Counts as
    ONE hit against the shared chat/AI Fix rate limit; the job itself paces its LLM calls with
    settings.auto_enhance_concurrency. One job per scan at a time (409 while one is running)."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    _validate_fix_fields(req.fields)

    ids = list(dict.fromkeys(req.vuln_ids))  # dedupe, keep order
    if len(ids) > auto_enhance.MAX_FINDINGS_PER_JOB:
        raise HTTPException(status_code=422,
            detail=f"At most {auto_enhance.MAX_FINDINGS_PER_JOB} findings per Auto Enhance run")

    running = auto_enhance.active_job_id(scan_id)
    if running:
        raise HTTPException(status_code=409,
            detail=f"An Auto Enhance job is already running for this scan ({running})")

    detail = scanner.get_scan_detail(scan_id)
    try:
        cfg = resolve_llm(detail.llm_provider, detail.llm_model, req.provider, req.model)
    except LlmError as e:
        raise HTTPException(status_code=400, detail=str(e))

    all_rows = {r["id"]: r for r in await db.get_vulnerabilities(db_path, exe)}
    missing = [i for i in ids if i not in all_rows]
    if missing:
        raise HTTPException(status_code=404, detail=f"Unknown vulnerability id(s): {missing[:20]}")
    rows = [all_rows[i] for i in ids]

    _chat_rate_limit()
    fields = [f for f in (req.fields or list(finding_fix.FIXABLE_FIELDS))]
    job = auto_enhance.create_job(scan_id, cfg, fields, rows)
    auto_enhance.start_job_task(
        job, cfg=cfg, db_path=db_path, exe=exe, rows=rows,
        scan_dir=settings.scan_dir / scan_id,
        regenerate=scanner.regenerate_report,
        concurrency=settings.auto_enhance_concurrency,
    )
    return auto_enhance.public_view(job)


@app.get("/api/v1/scans/{scan_id}/auto-enhance")
async def auto_enhance_overview(request: Request, scan_id: str):
    """The currently running job (if any) plus this scan's Activity Log, newest first."""
    _check_auth(request)
    _require_db(scan_id)
    jid = auto_enhance.active_job_id(scan_id)
    active = auto_enhance.get_job(jid) if jid else None
    return {
        "active": auto_enhance.public_view(active) if active else None,
        "history": auto_enhance.read_activity_log(settings.scan_dir / scan_id),
    }


@app.get("/api/v1/scans/{scan_id}/auto-enhance/jobs/{job_id}")
async def auto_enhance_job(request: Request, scan_id: str, job_id: str):
    """Live progress for one job; falls back to the persisted Activity Log after a restart."""
    _check_auth(request)
    _require_db(scan_id)
    job = _find_job(scan_id, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Auto Enhance job not found")
    return auto_enhance.public_view(job)


def _find_job(scan_id: str, job_id: str) -> Optional[dict]:
    """Live job if still in memory, else its persisted Activity Log entry (after a restart)."""
    job = auto_enhance.get_job(job_id)
    if job and job.get("scan_id") == scan_id:
        return job
    for entry in auto_enhance.read_activity_log(settings.scan_dir / scan_id):
        if entry.get("job_id") == job_id:
            return entry
    return None


@app.post("/api/v1/scans/{scan_id}/auto-enhance/jobs/{job_id}/cancel")
async def cancel_auto_enhance_job(request: Request, scan_id: str, job_id: str):
    """Cancel Batch: findings not started yet are skipped; in-flight ones finish normally."""
    _check_auth(request)
    _require_db(scan_id)
    job = auto_enhance.get_job(job_id)
    if not job or job.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Auto Enhance job not found")
    if job.get("state") not in ("queued", "running"):
        raise HTTPException(status_code=409, detail="This Auto Enhance job is not running")
    return auto_enhance.public_view(auto_enhance.request_cancel(job))


@app.post("/api/v1/scans/{scan_id}/auto-enhance/jobs/{job_id}/items/{vuln_id}/retry",
          status_code=202)
async def retry_auto_enhance_item(request: Request, scan_id: str, job_id: str, vuln_id: int):
    """Retry Finding: re-runs one failed/cancelled finding inside the same run, with the run's
    original provider/model/fields. Counts as one hit on the shared AI rate limit."""
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    job = _find_job(scan_id, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Auto Enhance job not found")
    item = next((it for it in job.get("items", []) if it.get("vuln_id") == vuln_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Finding is not part of this run")
    if item.get("state") not in ("failed", "cancelled"):
        raise HTTPException(status_code=409, detail="Only failed or cancelled findings can be retried")
    running = auto_enhance.active_job_id(scan_id)
    if running and running != job_id:
        raise HTTPException(status_code=409,
            detail=f"Another Auto Enhance job is running for this scan ({running})")
    row = await db.get_vulnerability_row(db_path, exe, vuln_id)
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    detail = scanner.get_scan_detail(scan_id)
    try:
        cfg = resolve_llm(detail.llm_provider, detail.llm_model, job.get("provider"), job.get("model"))
    except LlmError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _chat_rate_limit()
    try:
        job = auto_enhance.retry_item(
            job, row, cfg=cfg, db_path=db_path, exe=exe,
            scan_dir=settings.scan_dir / scan_id, regenerate=scanner.regenerate_report,
            concurrency=settings.auto_enhance_concurrency)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return auto_enhance.public_view(job)


def _learned_rules_path(platform: str) -> str:
    """Resolve store path for IOS or ANDROID (mirrors LearnedRulesStore.defaultPath)."""
    import os as _os
    home = _os.path.expanduser("~")
    plat = (platform or "IOS").upper()

    def _prefer(new_path: str, old_path: str) -> str:
        if _os.path.exists(new_path) or not _os.path.exists(old_path):
            return new_path
        return old_path

    if plat == "ANDROID":
        env = (_os.environ.get("MALIMITE_LEARNED_RULES_ANDROID")
               or _os.environ.get("MAILMITE_LEARNED_RULES_ANDROID"))
        if env:
            return env
        return _prefer(
            _os.path.join(home, ".malimite", "learned_rules_android.json"),
            _os.path.join(home, ".mailmite", "learned_rules_android.json"),
        )
    env = (_os.environ.get("MALIMITE_LEARNED_RULES_IOS")
           or _os.environ.get("MAILMITE_LEARNED_RULES_IOS")
           or _os.environ.get("MALIMITE_LEARNED_RULES")
           or _os.environ.get("MAILMITE_LEARNED_RULES"))
    if env:
        return env
    return _prefer(
        _os.path.join(home, ".malimite", "learned_rules.json"),
        _os.path.join(home, ".mailmite", "learned_rules.json"),
    )


def _load_learned_store(platform: str) -> dict:
    """Load one platform store; missing platform on rules defaults to the store platform."""
    import json as _json
    import os as _os
    plat = platform.upper()
    path = _learned_rules_path(plat)
    exists = _os.path.exists(path)
    if not exists:
        return {"platform": plat, "path": path, "exists": False, "count": 0, "rules": []}
    try:
        with open(path, "r") as fh:
            data = _json.load(fh)
        rules = []
        for r in data.get("rules", []):
            if not isinstance(r, dict):
                continue
            rule = dict(r)
            if not rule.get("platform"):
                rule["platform"] = plat
            else:
                rule["platform"] = str(rule["platform"]).upper()
            rules.append(rule)
        return {"platform": plat, "path": path, "exists": True, "count": len(rules), "rules": rules}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read learned rules ({plat}): {exc}")


@app.get("/api/v1/learned-rules")
async def get_learned_rules(request: Request, platform: Optional[str] = None):
    """Return LLM-learned rules from both iOS and Android stores.

    Optional ``platform`` query param (``IOS`` | ``ANDROID``) filters the rules list.
    Store path metadata is always returned for both platforms.
    """
    _check_auth(request)
    ios = _load_learned_store("IOS")
    android = _load_learned_store("ANDROID")
    stores = [ios, android]

    filt = (platform or "").strip().upper() or None
    if filt and filt not in ("IOS", "ANDROID"):
        raise HTTPException(status_code=400, detail="platform must be IOS or ANDROID")

    all_rules = []
    for store in stores:
        if filt and store["platform"] != filt:
            continue
        all_rules.extend(store["rules"])

    # Legacy top-level path/count point at iOS (or filtered store) for older clients.
    primary = next((s for s in stores if s["platform"] == (filt or "IOS")), ios)
    return {
        "stores": [
            {"platform": s["platform"], "path": s["path"], "exists": s["exists"], "count": s["count"]}
            for s in stores
        ],
        "path": primary["path"],
        "count": len(all_rules),
        "rules": all_rules,
        "platform": filt,
    }


# ── Claude OAuth (claude-oauth provider) ────────────────────────────────────
#
# No browser flow lives here: this container has no browser, and the loopback
# callback server the flow needs (localhost:53692) isn't reachable from a
# browser running on the host anyway. These routes only import an
# already-completed login — either auto-detected from the official `claude`
# CLI's own session file, or pasted directly — the same two paths
# `malimite claude-login --import` / `--access-token ...` expose on the CLI
# side (see ClaudeLoginCommand.java).

class ImportTokenRequest(BaseModel):
    access_token: str
    refresh_token: str
    expires_at_ms: int


@app.get("/api/v1/auth/claude-oauth/status")
async def claude_oauth_status(request: Request):
    _check_auth(request)
    configured = anthropic_oauth.is_configured()
    return {
        "configured": configured,
        "claude_code_detected": anthropic_oauth.claude_code_credentials_available(),
    }


@app.post("/api/v1/auth/claude-oauth/import-token")
async def claude_oauth_import_token(request: Request, req: ImportTokenRequest):
    _check_auth(request)
    if not req.access_token.startswith("sk-ant-oat"):
        raise HTTPException(status_code=422,
                             detail="access_token doesn't look like an OAuth token "
                                    "(expected it to start with 'sk-ant-oat').")
    anthropic_oauth.import_manual(req.access_token, req.refresh_token, req.expires_at_ms)
    return {"ok": True}


@app.post("/api/v1/auth/claude-oauth/import-claude-code")
async def claude_oauth_import_claude_code(request: Request):
    """Imports the session already stored by the official `claude` CLI
    (`claude /login`), if one is readable from this process.

    `changed=false` in the response means the imported access_token was
    byte-for-byte identical to what was already stored — almost always a sign
    that `./sync-claude-oauth.sh` (repo root) hadn't finished writing a fresh
    token yet when this ran (it's asynchronous relative to a human clicking
    "Import"), not that the import itself failed. This happened in production:
    a human clicked Import, the call reported HTTP 200, but the token
    underneath was still the old/invalid one because sync finished ~2 minutes
    later. Callers should treat changed=false + a still-failing chat/scan as
    "re-run sync-claude-oauth.sh, wait for it to actually finish, then
    import again" rather than a code bug.
    """
    _check_auth(request)
    result = anthropic_oauth.import_from_claude_code()
    if result is None:
        raise HTTPException(status_code=404,
                             detail=f"No Claude Code session found at "
                                    f"{anthropic_oauth.claude_code_credentials_path()}. "
                                    f"Run 'claude /login' first, wherever this process can read that file.")
    return {"ok": True, "changed": result.changed, "token_fingerprint": result.fingerprint}


class LlmTestRequest(BaseModel):
    provider: str
    api_key: str = Field("", max_length=4096)
    model: str = Field("", max_length=200)
    # Bedrock-only probe fields (see llm_probe._probe_bedrock); harmless no-ops for every
    # other provider. Kept on the shared request model rather than a bedrock-specific
    # endpoint so the Config tab's "Test Connection" button can POST the same shape
    # regardless of which provider card it's testing.
    access_key_id: str = Field("", max_length=256)
    secret_access_key: str = Field("", max_length=256)
    region: str = Field("", max_length=64)


@app.post("/api/v1/llm/test")
async def llm_test_connection(request: Request, req: LlmTestRequest):
    """Backs the Config tab's (and the legacy upload form's) "Test Connection" button: lists
    the provider's models with the given key (or the server's own key when none is supplied).
    Never spends a completion and never echoes the key back."""
    _check_auth(request)
    extra = {"access_key_id": req.access_key_id, "secret_access_key": req.secret_access_key,
            "region": req.region} if req.provider == "bedrock" else None
    try:
        return await llm_probe.probe(req.provider, req.api_key, req.model, extra=extra)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


# ── Config tab: persistent LLM provider credentials ─────────────────────────────

class LlmProviderConfigRequest(BaseModel):
    """Every field is optional and provider-specific; only non-empty ones are persisted
    (see llm_config.set_provider — a blank field never erases a previously saved value, use
    DELETE to actually remove a provider's config)."""
    api_key: str = Field("", max_length=4096)
    base_url: str = Field("", max_length=500)
    access_key_id: str = Field("", max_length=256)
    secret_access_key: str = Field("", max_length=256)
    region: str = Field("", max_length=64)
    model_id: str = Field("", max_length=200)


class LlmDefaultRequest(BaseModel):
    provider: str = Field("", max_length=64)
    model: str = Field("", max_length=200)


def _require_known_provider(provider: str) -> str:
    p = (provider or "").strip().lower()
    if p not in llm_config.KNOWN_PROVIDERS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown provider '{provider}'. Known: {', '.join(llm_config.KNOWN_PROVIDERS)}.",
        )
    return p


@app.get("/api/v1/config/providers")
async def list_config_providers(request: Request):
    """Every provider the upload form / AI Assistant / AI Fix can select, with its connection
    status (never a raw key — see llm_config.provider_status). claude-oauth is included here
    too (status proxied from anthropic_oauth) so the Config tab can show every provider card
    in one list instead of special-casing OAuth separately."""
    _check_auth(request)
    providers = [llm_config.provider_status(p) for p in llm_config.KNOWN_PROVIDERS]
    oauth_configured = anthropic_oauth.is_configured()
    providers.insert(1, {  # same visual slot as the old upload-form dropdown (right after "claude")
        "provider": "claude-oauth",
        "configured": oauth_configured,
        "source": "ui" if oauth_configured else "none",
        "masked": {},
        "fields": {},
        "updated_at": None,
    })
    data = llm_config.load()
    return {
        "providers": providers,
        "default_provider": data["default_provider"],
        "default_model": data["default_model"],
    }


@app.post("/api/v1/config/providers/{provider}")
async def set_config_provider(request: Request, provider: str, req: LlmProviderConfigRequest):
    """Saves (merges) one provider's credentials. claude-oauth is deliberately excluded —
    it has no key fields of its own; use /api/v1/auth/claude-oauth/* instead."""
    _check_auth(request)
    if provider == "claude-oauth":
        raise HTTPException(status_code=422, detail="claude-oauth has no key fields; use "
                                                     "/api/v1/auth/claude-oauth/import-token or "
                                                     "/import-claude-code instead.")
    p = _require_known_provider(provider)
    stored = llm_config.set_provider(
        p, api_key=req.api_key, base_url=req.base_url, access_key_id=req.access_key_id,
        secret_access_key=req.secret_access_key, region=req.region, model_id=req.model_id,
    )
    return {"ok": True, "status": llm_config.provider_status(p), "updated_at": stored.get("updated_at")}


@app.delete("/api/v1/config/providers/{provider}", status_code=204)
async def delete_config_provider(request: Request, provider: str):
    _check_auth(request)
    p = _require_known_provider(provider)
    llm_config.delete_provider(p)


@app.put("/api/v1/config/default")
async def set_config_default(request: Request, req: LlmDefaultRequest):
    """Sets the provider/model the upload form pre-selects. An empty provider clears the
    default (form falls back to the first configured provider)."""
    _check_auth(request)
    if req.provider and req.provider not in (*llm_config.KNOWN_PROVIDERS, "claude-oauth"):
        raise HTTPException(status_code=422, detail=f"Unknown provider '{req.provider}'.")
    data = llm_config.set_default(req.provider, req.model)
    return {"ok": True, "default_provider": data["default_provider"], "default_model": data["default_model"]}


# ── file downloads ────────────────────────────────────────────────────────────

@app.get("/api/v1/scans/{scan_id}/sarif")
async def get_sarif(request: Request, scan_id: str):
    _check_auth(request)
    detail = scanner.get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    p = settings.scan_dir / scan_id / "findings.sarif"
    await _ensure_report_fresh(scan_id, p, detail)
    if not p.exists():
        raise HTTPException(status_code=404, detail="SARIF not generated yet")
    return FileResponse(str(p), media_type="application/json",
                        filename=f"malimite-{scan_id[:8]}.sarif")


@app.get("/api/v1/scans/{scan_id}/package")
async def get_package(request: Request, scan_id: str):
    _check_auth(request)
    detail = scanner.get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    p = next((settings.scan_dir / scan_id).glob("upload.*"), None)
    if p is None:
        raise HTTPException(status_code=404, detail="Uploaded package not found")
    return FileResponse(str(p), media_type="application/octet-stream", filename=detail.filename)


@app.get("/api/v1/scans/{scan_id}/report", response_class=HTMLResponse)
async def get_report(request: Request, scan_id: str):
    _check_auth(request)
    detail = scanner.get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    p = settings.scan_dir / scan_id / "report.html"
    # Lazy regenerate if the report is missing or older than the latest triage update
    await _ensure_report_fresh(scan_id, p, detail)
    if not p.exists():
        raise HTTPException(status_code=404, detail="HTML report not generated yet")
    return HTMLResponse(p.read_text())


# Must match HtmlReporter.TEMPLATE_VERSION — bump both when the HTML layout changes.
_HTML_REPORT_TEMPLATE_VERSION = "8"
_HTML_REPORT_TEMPLATE_META = (
    f'<meta name="malimite-report-template" content="{_HTML_REPORT_TEMPLATE_VERSION}">'
)


def _html_template_stale(html_path: Path) -> bool:
    """True when report.html is missing or not generated by the current HtmlReporter."""
    if not html_path.exists():
        return True
    try:
        # Template meta is near the top of the file; avoid reading huge reports fully. The VA
        # report template (HtmlReporter TEMPLATE_VERSION >= "5") carries a long data-contract
        # comment before <head>, pushing the meta tag past 2048 bytes — 4096 covers it with margin.
        head = html_path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return True
    return _HTML_REPORT_TEMPLATE_META not in head


async def _ensure_report_fresh(scan_id: str, report_path: Path, detail) -> None:
    """Regenerate on-disk reports if triage is newer or the HTML template is stale."""
    if detail.state != "done":
        return
    if not detail.db_path or not Path(detail.db_path).exists() or not detail.bundle_executable:
        return

    html_path = settings.scan_dir / scan_id / "report.html"
    needs_regen = _html_template_stale(html_path) or not report_path.exists()

    # Find the max UpdatedAt across this scan's vulnerabilities
    if not needs_regen:
        import aiosqlite
        try:
            async with aiosqlite.connect(detail.db_path) as adb:
                async with adb.execute(
                    "SELECT MAX(UpdatedAt) FROM Vulnerabilities WHERE ExecutableName=?",
                    (detail.bundle_executable,)
                ) as cur:
                    row = await cur.fetchone()
            latest = row[0] if row and row[0] else 0
        except Exception:
            latest = 0

        # Rebuild when triage is newer than the on-disk artifact being served
        if latest != 0 and (report_path.stat().st_mtime * 1000) < latest:
            needs_regen = True

    if needs_regen:
        await scanner.regenerate_report(scan_id)


@app.get("/api/v1/scans/{scan_id}/log")
async def get_log(request: Request, scan_id: str, tail: int = 200):
    _check_auth(request)
    if not scanner.get_scan_detail(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    p = settings.scan_dir / scan_id / "analysis.log"
    if not p.exists():
        return JSONResponse({"lines": []})
    lines = p.read_text(errors="replace").splitlines()
    return JSONResponse({"lines": lines[-tail:]})


# ── AI assistant (chat agent) ─────────────────────────────────────────────────

_IMAGE_MEDIA_TYPES = frozenset({"image/png", "image/jpeg", "image/webp", "image/gif"})


class ChatAttachment(BaseModel):
    """A text/code file or an image, attached to one chat message.

    Text attachments are inlined into the message as a fenced code block (same as before this
    field existed, just supporting more than one). Image attachments become a provider-native
    vision content block — see agent/loop.py's use of `kind` and agent/llm.py's to_openai().
    """
    kind: str = Field(pattern="^(text|image)$")
    name: str = Field(min_length=1, max_length=255)
    # text attachments: raw file content. image attachments: base64-encoded bytes (no data: prefix).
    content: str = Field(min_length=1)
    media_type: Optional[str] = None  # required and validated for kind="image"; ignored for kind="text"

    def validate_against(self, s) -> Optional[str]:
        """Returns an error message, or None if this attachment is within the configured limits."""
        if self.kind == "text":
            if len(self.content) > s.chat_attachment_max_chars:
                return (f'"{self.name}" is too long ({len(self.content):,} characters, '
                        f'max {s.chat_attachment_max_chars:,}). Trim it and try again.')
        else:
            if self.media_type not in _IMAGE_MEDIA_TYPES:
                return f'"{self.name}" has an unsupported image type: {self.media_type!r}.'
            # content is base64; raw byte size is ~3/4 of the encoded string length.
            approx_bytes = len(self.content) * 3 // 4
            if approx_bytes > s.chat_attachment_max_image_bytes:
                return (f'"{self.name}" is too large ({approx_bytes:,} bytes, '
                        f'max {s.chat_attachment_max_image_bytes:,}). Use a smaller image.')
        return None


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    # Hard ceiling here is a generous upper bound only (Pydantic Field() needs a literal, not a
    # runtime settings value); the real, operator-configurable limit is
    # settings.chat_message_max_chars, enforced in chat() below alongside the attachment checks.
    message: str = Field(default="", max_length=200000)
    attachments: list[ChatAttachment] = Field(default_factory=list)
    provider: Optional[str] = None   # override; must be in agent.llm.PROVIDERS
    model: Optional[str] = None


class RenameChatRequest(BaseModel):
    title: str = Field(min_length=1, max_length=60)


_ACTIVE_CHATS: set[str] = set()  # one live stream per session
_CHAT_HITS: deque = deque()      # monotonic timestamps of recent chat requests (global sliding window)


def _chat_rate_limit() -> None:
    now = time.monotonic()
    while _CHAT_HITS and now - _CHAT_HITS[0] > 60:
        _CHAT_HITS.popleft()
    if len(_CHAT_HITS) >= settings.chat_rate_per_min:
        wait = max(1, int(60 - (now - _CHAT_HITS[0])) + 1)
        raise HTTPException(status_code=429, detail="Too many chat requests; try again shortly",
                            headers={"Retry-After": str(wait)})
    _CHAT_HITS.append(now)


def _sse(ev: dict) -> str:
    return f"data: {json.dumps(ev)}\n\n"


@app.post("/api/v1/scans/{scan_id}/chat")
async def chat(request: Request, scan_id: str, req: ChatRequest):
    _check_auth(request)
    db_path, exe = _require_db(scan_id)
    _chat_rate_limit()

    if not req.message.strip() and not req.attachments:
        raise HTTPException(status_code=422, detail="Message cannot be empty without at least one attachment")
    if len(req.message) > settings.chat_message_max_chars:
        raise HTTPException(status_code=422, detail=(
            f"Message is too long ({len(req.message):,} characters, "
            f"max {settings.chat_message_max_chars:,}). Trim it and try again."))
    if len(req.attachments) > settings.chat_attachment_max_count:
        raise HTTPException(status_code=422, detail=(
            f"Too many attachments ({len(req.attachments)}, max {settings.chat_attachment_max_count}). "
            f"Remove some and try again."))
    for att in req.attachments:
        err = att.validate_against(settings)
        if err:
            raise HTTPException(status_code=422, detail=err)

    detail = scanner.get_scan_detail(scan_id)
    scan_dir = scanner._scan_dir(scan_id)
    chat_db = chat_store.path_for(scan_dir)

    sess = None
    if req.session_id:
        sess = await chat_store.get_session(chat_db, req.session_id)
        if not sess:
            raise HTTPException(status_code=404, detail="Chat session not found")
    try:
        cfg = resolve_llm(sess["provider"] if sess else detail.llm_provider,
                          sess["model"] if sess else detail.llm_model,
                          req.provider, req.model)
    except LlmError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if any(a.kind == "image" for a in req.attachments) and cfg.provider not in VISION_CAPABLE_PROVIDERS:
        raise HTTPException(status_code=422, detail=(
            f"The '{cfg.provider}' provider does not accept image attachments. "
            f"Switch provider to one of: {', '.join(sorted(VISION_CAPABLE_PROVIDERS))}."))
    if sess:
        sid = sess["id"]
        if (cfg.provider, cfg.model) != (sess["provider"], sess["model"]):
            await chat_store.set_llm(chat_db, sid, cfg.provider, cfg.model)
    else:
        sid = await chat_store.create_session(chat_db, cfg.provider, cfg.model)
    if sid in _ACTIVE_CHATS:
        raise HTTPException(status_code=409, detail="This chat session is already generating")

    ctx = Ctx(scan_id=scan_id, db_path=db_path, exe=exe, platform=detail.platform or "",
              scan_dir=scan_dir, meta=scanner._read_scan_json(scan_id) or {})

    async def gen():
        # claimed here, not in the route: if the client vanishes before the first iteration the flag is never set
        if sid in _ACTIVE_CHATS:
            yield _sse({"type": "error", "message": "This chat session is already generating"})
            return
        _ACTIVE_CHATS.add(sid)
        try:
            yield _sse({"type": "session", "session_id": sid, "provider": cfg.provider, "model": cfg.model})
            atts = [a.model_dump() for a in req.attachments]
            async for ev in agent_loop.run_chat(ctx, chat_db, sid, req.message, cfg, attachments=atts):
                yield _sse(ev)
        except Exception:
            import logging
            logging.getLogger("malimite").exception("chat failed for scan %s", scan_id)
            yield _sse({"type": "error", "message": "internal error"})
        finally:
            _ACTIVE_CHATS.discard(sid)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/v1/scans/{scan_id}/chat")
async def get_chat(request: Request, scan_id: str, session_id: Optional[str] = None):
    _check_auth(request)
    _require_db(scan_id)
    chat_db = chat_store.path_for(scanner._scan_dir(scan_id))
    sessions = await chat_store.list_sessions(chat_db)
    sid = session_id or (sessions[0]["id"] if sessions else None)
    return {"sessions": sessions, "session_id": sid,
            "messages": await chat_store.history(chat_db, sid) if sid else []}


@app.delete("/api/v1/scans/{scan_id}/chat/{session_id}", status_code=204)
async def delete_chat(request: Request, scan_id: str, session_id: str):
    _check_auth(request)
    _require_db(scan_id)
    if not await chat_store.delete_session(chat_store.path_for(scanner._scan_dir(scan_id)), session_id):
        raise HTTPException(status_code=404, detail="Chat session not found")


@app.patch("/api/v1/scans/{scan_id}/chat/{session_id}")
async def rename_chat(request: Request, scan_id: str, session_id: str, req: RenameChatRequest):
    _check_auth(request)
    _require_db(scan_id)
    chat_db = chat_store.path_for(scanner._scan_dir(scan_id))
    if not await chat_store.set_title(chat_db, session_id, req.title):
        raise HTTPException(status_code=404, detail="Chat session not found")
    return {"ok": True}


@app.post("/api/v1/scans/{scan_id}/chat/{session_id}/fork")
async def fork_chat(request: Request, scan_id: str, session_id: str):
    _check_auth(request)
    _require_db(scan_id)
    chat_db = chat_store.path_for(scanner._scan_dir(scan_id))
    new_sid = await chat_store.fork_session(chat_db, session_id)
    if not new_sid:
        raise HTTPException(status_code=404, detail="Chat session not found")
    return {"session_id": new_sid}
