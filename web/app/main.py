"""Malimite Python web service — wraps all Malimite-Core functionality."""
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Optional

import aiofiles
from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from . import db, scanner
from .config import settings
from .models import ScanDetail, ScanMeta

_OFFENSIVE_MODE_ALIASES = frozenset({"offensive", "offense", "frida", "bypass"})
_FAST_MODE_ALIASES = frozenset({"summarize", "summary", "fast", "fast_scan", "fastscan"})
_FULL_MODE_ALIASES = frozenset({"find_vulns", "vulns", "vuln", "full", "full_scan", "fullscan"})
_AUTO_FIX_MODE_ALIASES = frozenset({"auto_fix", "autofix", "fix"})
_PHASE_DIRS = {
    "ENVIRONMENT": "01_environment",
    "TRANSPORT": "02_transport",
    "SECRETS": "03_secrets",
    "SESSION": "04_session",
}
_CAT_TO_PHASE = {
    "ROOT_DETECTION": "ENVIRONMENT",
    "JAILBREAK": "ENVIRONMENT",
    "SSL_PINNING": "TRANSPORT",
    "CRYPTO": "SECRETS",
    "BIOMETRIC": "SESSION",
    "OTHER": "SESSION",
}

app = FastAPI(title="Malimite", version="0.1.0", docs_url="/docs", redoc_url=None)

_WEB = Path(__file__).parent.parent


# ── auth ──────────────────────────────────────────────────────────────────────

def _check_auth(request: Request) -> None:
    if not settings.api_key:
        return
    key = request.headers.get("X-Api-Key", "")
    if key != settings.api_key:
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
):
    _check_auth(request)
    name = file.filename.lower()
    if not (name.endswith(".ipa") or name.endswith(".apk")):
        raise HTTPException(status_code=400, detail="Only .ipa or .apk files are accepted")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    needs_key = llm_enabled and llm_provider in ("openai", "claude", "deepseek")
    if llm_provider == "openai":
        effective_key = llm_api_key.strip() or settings.openai_api_key
        provider_label = "OPENAI_API_KEY"
    elif llm_provider == "claude":
        effective_key = llm_api_key.strip() or settings.anthropic_api_key
        provider_label = "ANTHROPIC_API_KEY"
    elif llm_provider == "deepseek":
        effective_key = llm_api_key.strip() or settings.deepseek_api_key
        provider_label = "DEEPSEEK_API_KEY"
    else:
        effective_key = ""
        provider_label = ""
    if needs_key and not effective_key:
        raise HTTPException(
            status_code=422,
            detail=f"{provider_label} is required when using provider '{llm_provider}'. "
                   f"Pass it in the llm_api_key field or set {provider_label} in the server .env.",
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
        assessment_enabled,
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
async def get_resources(request: Request, scan_id: str, limit: int = 200):
    _check_auth(request)
    db_path, _ = _require_db(scan_id)
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


def _normalize_phase(target: dict) -> str:
    phase = str(target.get("phase") or "").strip().upper()
    if phase in _PHASE_DIRS:
        return phase
    cat = str(target.get("category") or "OTHER").strip().upper().replace("-", "_")
    return _CAT_TO_PHASE.get(cat, "SESSION")


def _slug(s: str, fallback: str = "target") -> str:
    t = re.sub(r"[^a-zA-Z0-9._-]+", "_", (s or "").strip())[:60].strip("_")
    return t or fallback


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
            row["_phase"] = _normalize_phase(row)
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
        for folder in _PHASE_DIRS.values():
            zf.writestr(f"{folder}/.keep", "")
        counters = {p: 0 for p in _PHASE_DIRS}
        for t in targets:
            phase = t.get("_phase") or "SESSION"
            folder = _PHASE_DIRS.get(phase, "04_session")
            counters[phase] = counters.get(phase, 0) + 1
            n = counters[phase]
            script = (t.get("frida_script") or "").strip()
            if not script:
                continue
            title = _slug(str(t.get("title") or "target"), f"target_{n}")
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
_HTML_REPORT_TEMPLATE_VERSION = "4"
_HTML_REPORT_TEMPLATE_META = (
    f'<meta name="malimite-report-template" content="{_HTML_REPORT_TEMPLATE_VERSION}">'
)


def _html_template_stale(html_path: Path) -> bool:
    """True when report.html is missing or not generated by the current HtmlReporter."""
    if not html_path.exists():
        return True
    try:
        # Template meta is near the top of the file; avoid reading huge reports fully.
        head = html_path.read_text(encoding="utf-8", errors="replace")[:2048]
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
