"""Auto Enhance: runs AI Fix over many findings of one scan as a server-side background job.

A job applies the exact same per-finding logic as the single-finding AI Fix endpoint
(apply_ai_fix_to_row — finding_fix.fix_finding + db.update_vulnerability_ai_fix), so every
rewrite is still a reversible Override* column and the original scanned text is never touched.
What the job adds on top:

- runs in the background (survives the browser modal/tab being closed), with a small bounded
  concurrency so a 24-finding run doesn't take 24x one call's latency, nor hammer the provider;
- regenerates report.html / findings.sarif ONCE at the end instead of once per finding
  (each regeneration spawns a JVM — see scanner.regenerate_report);
- keeps per-finding progress for the UI to poll, and appends a summary of every finished run to
  <scan_dir>/auto_enhance_log.json (the modal's Activity Log tab).

One job per scan at a time: starting a second while one runs is rejected (409 in main.py), since
two jobs writing overrides on the same findings concurrently would race each other.
"""
import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Awaitable, Callable, Optional

from . import db, finding_fix
from .agent.llm import LlmCfg, LlmError

_log = logging.getLogger("malimite")

MAX_FINDINGS_PER_JOB = 200
DEFAULT_CONCURRENCY = 2
LOG_FILENAME = "auto_enhance_log.json"
MAX_LOG_ENTRIES = 50

_JOBS: dict[str, dict] = {}          # job_id -> job state (in memory; finished jobs also persisted)
_ACTIVE_BY_SCAN: dict[str, str] = {}  # scan_id -> job_id of the job currently running there
_TASKS: dict[str, asyncio.Task] = {}  # job_id -> task (keeps a strong ref so it isn't GC'd mid-run)
_RUNTIME: dict[str, dict] = {}        # job_id -> live execution context (cfg, semaphore, task set)


# ── shared single-finding apply (also used by main.py's per-finding AI Fix endpoint) ──────────

def source_location_for(row: dict) -> Optional[tuple[str, Optional[str]]]:
    """(class_name, function_name) whose decompiled code gives the LLM useful context, or None.
    Only FUNCTION findings carry a usable evidence_location ('Class.function' or bare 'function' —
    see VulnerabilityScanner.java / LlmEnricher.java); STRING/RESOURCE/BINARY/PLIST findings have
    no single function to attach, so the fix then proceeds from the finding text alone."""
    if (row.get("affected_type") or "").upper() != "FUNCTION":
        return None
    location = row.get("evidence_location") or ""
    if not location:
        return None
    if "." in location:
        class_name, _, function_name = location.rpartition(".")
    else:
        class_name, function_name = location, None
    if not class_name:
        return None
    return class_name, function_name


async def apply_ai_fix_to_row(db_path: str, exe: str, cfg: LlmCfg, row: dict,
                              fields: Optional[list[str]]) -> Optional[dict]:
    """Runs one AI Fix: optional decompiled-source context → LLM rewrite → reversible override
    write. Raises LlmError (safe to show the user) when the provider fails or returns nothing
    usable. Returns the sanitized fix that was written ({description, evidence, risk, poc_steps,
    remediation}, only the keys the model improved), or None when the row disappeared before
    the write. Does NOT regenerate the report — callers decide when (once per request, or once
    per Auto Enhance job)."""
    source_snippet = None
    loc = source_location_for(row)
    if loc:
        class_name, function_name = loc
        try:
            rows = await db.get_source(db_path, exe, class_name, function_name)
            if rows:
                source_snippet = rows[0]["code"]
        except Exception:
            source_snippet = None  # best-effort only

    fix = await finding_fix.fix_finding(cfg, row, source_snippet, fields)
    risk = fix.get("risk") or {}
    ok = await db.update_vulnerability_ai_fix(
        db_path, row["id"],
        description=fix.get("description"),
        evidence=fix.get("evidence"),
        poc_steps=fix.get("poc_steps"),
        remediation=fix.get("remediation"),
        severity=risk.get("severity"),
        cvss_score=risk.get("cvss"),
        provider=cfg.provider,
        model=cfg.model,
    )
    return fix if ok else None


# ── job registry ──────────────────────────────────────────────────────────────────────────────

def _now_ms() -> int:
    return int(time.time() * 1000)


def active_job_id(scan_id: str) -> Optional[str]:
    jid = _ACTIVE_BY_SCAN.get(scan_id)
    if jid and _JOBS.get(jid, {}).get("state") in ("queued", "running"):
        return jid
    return None


def get_job(job_id: str) -> Optional[dict]:
    return _JOBS.get(job_id)


def public_view(job: dict) -> dict:
    """JSON-safe copy for the API (drops nothing secret — the job never holds API keys)."""
    return json.loads(json.dumps(job))


def _log_path(scan_dir: Path) -> Path:
    return scan_dir / LOG_FILENAME


def read_activity_log(scan_dir: Path) -> list[dict]:
    """Finished runs for this scan, newest first. A corrupt/missing file reads as empty."""
    p = _log_path(scan_dir)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _append_activity_log(scan_dir: Path, job: dict) -> None:
    entries = [e for e in read_activity_log(scan_dir) if e.get("job_id") != job["job_id"]]
    entries.insert(0, public_view(job))
    entries = entries[:MAX_LOG_ENTRIES]
    try:
        tmp = _log_path(scan_dir).with_suffix(".json.tmp")
        tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        tmp.replace(_log_path(scan_dir))
    except OSError:
        _log.warning("Could not write Auto Enhance activity log in %s", scan_dir, exc_info=True)


CHANGE_CLIP = 2000  # chars of each rewritten field kept in the log for "View Details"


def _item_from_row(r: dict) -> dict:
    return {"vuln_id": r["id"], "rule_id": r.get("rule_id"), "title": r.get("title"),
            "category": r.get("category"),
            "severity": r.get("effective_severity") or r.get("severity"),
            "state": "pending", "error": None, "started_at": None, "finished_at": None,
            "duration_ms": None, "attempts": 0, "updated_fields": [], "changes": {}}


def _recount(job: dict) -> None:
    """Counters are always derived from item states, so cancel/retry can never drift them."""
    states = [it["state"] for it in job["items"]]
    job["succeeded"] = states.count("applied")
    job["failed"] = states.count("failed")
    job["cancelled"] = states.count("cancelled")
    job["completed"] = job["succeeded"] + job["failed"] + job["cancelled"]


def _changes_from_fix(fix: dict) -> tuple[list[str], dict]:
    """(updated field keys in canonical order, {field: new text}) from a sanitized fix."""
    fields, changes = [], {}
    for key in finding_fix.FIXABLE_FIELDS:
        if key == "risk":
            risk = fix.get("risk") or {}
            if risk.get("severity") or risk.get("cvss") is not None:
                fields.append("risk")
                parts = []
                if risk.get("severity"):
                    parts.append(f"Severity: {risk['severity']}")
                if risk.get("cvss") is not None:
                    parts.append(f"CVSS: {risk['cvss']}")
                changes["risk"] = " · ".join(parts)
        elif fix.get(key):
            fields.append(key)
            text = str(fix[key])
            changes[key] = text if len(text) <= CHANGE_CLIP else text[:CHANGE_CLIP] + "…"
    return fields, changes


def create_job(scan_id: str, cfg: LlmCfg, fields: list[str], rows: list[dict]) -> dict:
    job = {
        "job_id": uuid.uuid4().hex[:12],
        "scan_id": scan_id,
        "state": "queued",
        "provider": cfg.provider,
        "model": cfg.model,
        "fields": list(fields),
        "created_at": _now_ms(),
        "started_at": None,
        "finished_at": None,
        "total": len(rows),
        "completed": 0,
        "succeeded": 0,
        "failed": 0,
        "cancelled": 0,
        "cancel_requested": False,
        "report_regenerated": None,
        "error": None,
        "items": [_item_from_row(r) for r in rows],
    }
    _JOBS[job["job_id"]] = job
    _ACTIVE_BY_SCAN[scan_id] = job["job_id"]
    return job


async def _process_item(job: dict, rt: dict, row: dict) -> None:
    item = next(it for it in job["items"] if it["vuln_id"] == row["id"])
    async with rt["sem"]:
        if job.get("cancel_requested"):
            item["state"] = "cancelled"
            item["finished_at"] = _now_ms()
            _recount(job)
            return
        item.update(state="running", error=None, started_at=_now_ms(),
                    finished_at=None, duration_ms=None, updated_fields=[], changes={})
        item["attempts"] = (item.get("attempts") or 0) + 1
        try:
            fix = await apply_ai_fix_to_row(rt["db_path"], rt["exe"], rt["cfg"], row, job["fields"])
            if fix is not None:
                item["state"] = "applied"
                item["updated_fields"], item["changes"] = _changes_from_fix(fix)
                rt["applied"] += 1
            else:
                item["state"] = "failed"
                item["error"] = "Finding no longer exists"
        except LlmError as e:
            item["state"] = "failed"
            item["error"] = str(e)[:300]
        except Exception as e:  # never let one finding kill the job
            _log.warning("Auto Enhance item %s failed", row["id"], exc_info=True)
            item["state"] = "failed"
            item["error"] = f"Unexpected error: {type(e).__name__}"
        finally:
            item["finished_at"] = _now_ms()
            item["duration_ms"] = item["finished_at"] - (item["started_at"] or item["finished_at"])
            _recount(job)


def _schedule(job: dict, rt: dict, row: dict) -> None:
    rt["tasks"].add(asyncio.get_running_loop().create_task(_process_item(job, rt, row)))


async def _drive(job: dict, rt: dict) -> dict:
    """Waits until every scheduled item (including ones a retry adds mid-run) has finished,
    then regenerates the report once if anything was applied during this drive."""
    try:
        regenerated_for = 0
        while True:
            while rt["tasks"]:
                done, _ = await asyncio.wait(rt["tasks"], return_when=asyncio.FIRST_COMPLETED)
                rt["tasks"] -= done
            if rt["applied"] > regenerated_for:
                regenerated_for = rt["applied"]
                job["report_regenerated"] = await rt["regenerate"](job["scan_id"])
            # A retry may have been queued while the report was regenerating: keep going.
            # (No await between this check and the synchronous finally block below.)
            if not rt["tasks"]:
                break
        job["state"] = "cancelled" if job.get("cancel_requested") else "done"
    except Exception as e:
        _log.warning("Auto Enhance job %s crashed", job["job_id"], exc_info=True)
        job["state"] = "error"
        job["error"] = f"{type(e).__name__}: {e}"[:300]
    finally:
        _recount(job)
        job["finished_at"] = _now_ms()
        if _ACTIVE_BY_SCAN.get(job["scan_id"]) == job["job_id"]:
            _ACTIVE_BY_SCAN.pop(job["scan_id"], None)
        _RUNTIME.pop(job["job_id"], None)
        _TASKS.pop(job["job_id"], None)
        _append_activity_log(rt["scan_dir"], job)
    return job


def _runtime(cfg: LlmCfg, db_path: str, exe: str, scan_dir: Path,
             regenerate: Callable[[str], Awaitable[bool]], concurrency: int) -> dict:
    return {"cfg": cfg, "db_path": db_path, "exe": exe, "scan_dir": scan_dir,
            "regenerate": regenerate, "sem": asyncio.Semaphore(max(1, concurrency)),
            "tasks": set(), "applied": 0}


async def run_job(job: dict, *, cfg: LlmCfg, db_path: str, exe: str, rows: list[dict],
                  scan_dir: Path, regenerate: Callable[[str], Awaitable[bool]],
                  concurrency: int = DEFAULT_CONCURRENCY) -> dict:
    """Executes a created job to completion. Per-finding failures are recorded on the item and
    never abort the rest of the run. The report is regenerated once, only if anything applied."""
    job["state"] = "running"
    job["started_at"] = _now_ms()
    rt = _runtime(cfg, db_path, exe, scan_dir, regenerate, concurrency)
    _RUNTIME[job["job_id"]] = rt
    for r in rows:
        _schedule(job, rt, r)
    return await _drive(job, rt)


def start_job_task(job: dict, **kwargs) -> asyncio.Task:
    task = asyncio.get_running_loop().create_task(run_job(job, **kwargs))
    _TASKS[job["job_id"]] = task
    return task


def request_cancel(job: dict) -> dict:
    """Findings not started yet are skipped (marked cancelled); ones already talking to the LLM
    finish normally, so nothing is left half-written."""
    if job.get("state") in ("queued", "running"):
        job["cancel_requested"] = True
    return job


def retry_item(job: dict, row: dict, *, cfg: LlmCfg, db_path: str, exe: str, scan_dir: Path,
               regenerate: Callable[[str], Awaitable[bool]],
               concurrency: int = DEFAULT_CONCURRENCY) -> dict:
    """Re-runs one failed/cancelled finding inside the same job (the Activity Log keeps a single
    entry per run). A running job just queues it; a finished job is re-opened for that item.
    Callers must ensure no OTHER job is running on the scan (main.py returns 409)."""
    item = next((it for it in job["items"] if it["vuln_id"] == row["id"]), None)
    if item is None:
        raise KeyError(row["id"])
    rt = _RUNTIME.get(job["job_id"])
    running = rt is not None and job["state"] in ("queued", "running")
    if running and job.get("cancel_requested"):
        raise ValueError("This batch is being cancelled; retry once it has stopped")
    item.update(state="pending", error=None, started_at=None, finished_at=None, duration_ms=None,
                updated_fields=[], changes={})
    _recount(job)
    if running:
        _schedule(job, rt, row)
        return job
    job["cancel_requested"] = False
    _JOBS[job["job_id"]] = job
    _ACTIVE_BY_SCAN[job["scan_id"]] = job["job_id"]
    job.update(state="running", finished_at=None, error=None)
    rt = _runtime(cfg, db_path, exe, scan_dir, regenerate, concurrency)
    _RUNTIME[job["job_id"]] = rt
    _schedule(job, rt, row)
    _TASKS[job["job_id"]] = asyncio.get_running_loop().create_task(_drive(job, rt))
    return job
