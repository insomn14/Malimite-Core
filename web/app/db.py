"""Async SQLite queries against the analysis.sqlite produced by the CLI."""
import aiosqlite
from pathlib import Path
from typing import Optional

from .models import FunctionItem, FunctionPage, LlmFinding, ResourceItem, StringItem


async def _open(db_path: str):
    return await aiosqlite.connect(db_path)


# Columns added in the triage feature — kept as a list so older DBs created
# before the triage feature can be migrated forward on first read.
_TRIAGE_COLUMNS = [
    ("Status",            "TEXT DEFAULT 'open'"),
    ("OverrideSeverity",  "TEXT"),
    ("OverrideCvssScore", "REAL"),
    ("OverrideNote",      "TEXT"),
    ("UpdatedAt",         "INTEGER"),
]


async def _ensure_triage_columns(db) -> None:
    """ALTER TABLE Vulnerabilities to add any missing triage columns."""
    async with db.execute("PRAGMA table_info(Vulnerabilities)") as cur:
        rows = await cur.fetchall()
    existing = {r[1].lower() for r in rows}  # column names (case-insensitive)
    for col, decl in _TRIAGE_COLUMNS:
        if col.lower() not in existing:
            try:
                await db.execute(f"ALTER TABLE Vulnerabilities ADD COLUMN {col} {decl}")
                await db.commit()
            except Exception:
                pass  # best-effort migration; concurrent process may have added it


# ── counts ────────────────────────────────────────────────────────────────────

async def get_counts(db_path: str, executable: str) -> dict:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT COUNT(DISTINCT ParentClass) FROM Functions WHERE ExecutableName=?",
            (executable,)
        ) as cur:
            row = await cur.fetchone()
            class_count = row[0] if row else 0

        async with db.execute(
            "SELECT COUNT(*) FROM Functions WHERE ExecutableName=?",
            (executable,)
        ) as cur:
            row = await cur.fetchone()
            func_count = row[0] if row else 0

        async with db.execute(
            "SELECT COUNT(*) FROM MachoStrings WHERE ExecutableName=?",
            (executable,)
        ) as cur:
            row = await cur.fetchone()
            str_count = row[0] if row else 0

        async with db.execute(
            "SELECT COUNT(*) FROM EntryPoints WHERE ExecutableName=?",
            (executable,)
        ) as cur:
            row = await cur.fetchone()
            ep_count = row[0] if row else 0

        async with db.execute(
            "SELECT COUNT(*) FROM LlmFindings WHERE ExecutableName=?",
            (executable,)
        ) as cur:
            row = await cur.fetchone()
            llm_count = row[0] if row else 0

    return {
        "class_count": class_count,
        "function_count": func_count,
        "string_count": str_count,
        "entry_point_count": ep_count,
        "llm_finding_count": llm_count,
    }


# ── functions ─────────────────────────────────────────────────────────────────

async def get_classes(db_path: str, executable: str) -> list[str]:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT DISTINCT ParentClass FROM Functions WHERE ExecutableName=? ORDER BY ParentClass",
            (executable,)
        ) as cur:
            rows = await cur.fetchall()
    return [r[0] for r in rows if r[0]]


async def get_functions(
    db_path: str,
    executable: str,
    class_name: Optional[str],
    page: int,
    size: int,
) -> FunctionPage:
    size = min(size, 200)
    offset = page * size
    classes = await get_classes(db_path, executable)

    async with aiosqlite.connect(db_path) as db:
        if class_name:
            count_sql = "SELECT COUNT(*) FROM Functions WHERE ParentClass=? AND ExecutableName=?"
            fetch_sql = """SELECT FunctionName, DecompilationCode FROM Functions
                           WHERE ParentClass=? AND ExecutableName=?
                           LIMIT ? OFFSET ?"""
            params_count = (class_name, executable)
            params_fetch = (class_name, executable, size, offset)
        else:
            count_sql = "SELECT COUNT(*) FROM Functions WHERE ExecutableName=?"
            fetch_sql = """SELECT FunctionName, DecompilationCode FROM Functions
                           WHERE ExecutableName=?
                           LIMIT ? OFFSET ?"""
            params_count = (executable,)
            params_fetch = (executable, size, offset)

        async with db.execute(count_sql, params_count) as cur:
            row = await cur.fetchone()
            total = row[0] if row else 0

        async with db.execute(fetch_sql, params_fetch) as cur:
            rows = await cur.fetchall()

    items = [FunctionItem(function_name=r[0], decompiled=r[1]) for r in rows]
    return FunctionPage(class_name=class_name, page=page, size=size,
                        total=total, items=items, classes=classes)


# ── strings ───────────────────────────────────────────────────────────────────

async def get_strings(
    db_path: str,
    executable: str,
    query: Optional[str],
    limit: int,
) -> list[StringItem]:
    limit = min(limit, 2000)
    async with aiosqlite.connect(db_path) as db:
        if query:
            sql = """SELECT address, value, segment, label FROM MachoStrings
                     WHERE ExecutableName=? AND value LIKE ? LIMIT ?"""
            params = (executable, f"%{query}%", limit)
        else:
            sql = """SELECT address, value, segment, label FROM MachoStrings
                     WHERE ExecutableName=? LIMIT ?"""
            params = (executable, limit)

        async with db.execute(sql, params) as cur:
            rows = await cur.fetchall()

    return [StringItem(address=r[0], value=r[1], segment=r[2], label=r[3]) for r in rows]


# ── resources ─────────────────────────────────────────────────────────────────

async def get_resources(db_path: str, limit: int) -> list[ResourceItem]:
    limit = min(limit, 2000)
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT resourceId, value, type FROM ResourceStrings LIMIT ?",
            (limit,)
        ) as cur:
            rows = await cur.fetchall()
    return [ResourceItem(resource_id=r[0], value=r[1], type=r[2]) for r in rows]


# ── entry points ──────────────────────────────────────────────────────────────

async def get_entry_points(db_path: str, executable: str) -> list[str]:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT ClassName, FunctionName FROM EntryPoints WHERE ExecutableName=?",
            (executable,)
        ) as cur:
            rows = await cur.fetchall()
    return [f"{r[0]}.{r[1]}" if r[0] else r[1] for r in rows]


# ── LLM findings ──────────────────────────────────────────────────────────────

async def get_vulnerabilities(db_path: str, executable: str) -> list[dict]:
    async with aiosqlite.connect(db_path) as db:
        await _ensure_triage_columns(db)
        # Sort: active before suppressed, then effective severity (CRITICAL→LOW),
        # then effective CVSS DESC, then RuleId for stability.
        async with db.execute(
            """SELECT id, RuleId, Title, Category, Severity, CvssScore, Cwe, Description,
                      AffectedType, AffectedName, Evidence, EvidenceLocation,
                      PocSteps, Remediation, ReferenceUrl,
                      COALESCE(Status,'open'), OverrideSeverity, OverrideCvssScore,
                      OverrideNote, UpdatedAt
               FROM Vulnerabilities WHERE ExecutableName=?
               ORDER BY
                 CASE WHEN COALESCE(Status,'open') IN ('false_positive','fixed') THEN 1 ELSE 0 END,
                 CASE UPPER(COALESCE(OverrideSeverity, Severity, ''))
                     WHEN 'CRITICAL' THEN 0
                     WHEN 'HIGH'     THEN 1
                     WHEN 'MEDIUM'   THEN 2
                     WHEN 'LOW'      THEN 3
                     WHEN 'INFO'     THEN 4
                     ELSE 5
                 END,
                 COALESCE(OverrideCvssScore, CvssScore) DESC,
                 RuleId""",
            (executable,)
        ) as cur:
            rows = await cur.fetchall()
    out = []
    for r in rows:
        sev = r[4] or "INFO"
        cvss = r[5] or 0.0
        override_sev = r[16]
        override_cvss = r[17]
        out.append({
            "id":                 r[0],
            "rule_id":            r[1],
            "title":              r[2],
            "category":           r[3],
            "severity":           sev,
            "cvss_score":         cvss,
            "cwe":                r[6],
            "description":        r[7],
            "affected_type":      r[8],
            "affected_name":      r[9],
            "evidence":           r[10],
            "evidence_location":  r[11],
            "poc_steps":          r[12],
            "remediation":        r[13],
            "reference_url":      r[14],
            # triage fields
            "status":             r[15],
            "override_severity":  override_sev,
            "override_cvss_score": override_cvss,
            "override_note":      r[18],
            "updated_at":         r[19],
            # derived: effective values after triage override
            "effective_severity": override_sev or sev,
            "effective_cvss_score": override_cvss if override_cvss is not None else cvss,
            "is_false_positive":  (r[15] == "false_positive"),
        })
    return out


async def update_vulnerability_triage(
    db_path: str,
    vuln_id: int,
    status: str | None = None,
    override_severity: str | None = None,
    override_cvss_score: float | None = None,
    override_note: str | None = None,
) -> bool:
    sets = []
    args = []
    if status is not None:
        sets.append("Status=?");           args.append(status)
    if override_severity is not None:
        # "" means clear the override
        sets.append("OverrideSeverity=?"); args.append(override_severity or None)
    if override_cvss_score is not None:
        sets.append("OverrideCvssScore=?"); args.append(override_cvss_score)
    if override_note is not None:
        sets.append("OverrideNote=?");     args.append(override_note or None)
    sets.append("UpdatedAt=?")
    args.append(int(__import__("time").time() * 1000))

    sql = f"UPDATE Vulnerabilities SET {', '.join(sets)} WHERE id=?"
    args.append(vuln_id)

    async with aiosqlite.connect(db_path) as db:
        await _ensure_triage_columns(db)
        async with db.execute(sql, args) as cur:
            await db.commit()
            return cur.rowcount > 0


async def get_vulnerability_counts(db_path: str, executable: str) -> dict:
    """
    Counts use effective severity (override takes priority) and exclude
    findings marked as false-positive or fixed.
    """
    async with aiosqlite.connect(db_path) as db:
        await _ensure_triage_columns(db)
        async with db.execute(
            """SELECT COALESCE(OverrideSeverity, Severity) AS sev,
                      COALESCE(Status,'open') AS status,
                      COUNT(*)
               FROM Vulnerabilities
               WHERE ExecutableName=?
               GROUP BY sev, status""",
            (executable,)
        ) as cur:
            rows = await cur.fetchall()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
              "suppressed": 0, "false_positive": 0}
    for sev, status, n in rows:
        if status in ("false_positive", "fixed"):
            counts["suppressed"] += n
            if status == "false_positive":
                counts["false_positive"] += n
            continue
        if sev in counts:
            counts[sev] += n
    counts["total"] = counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"] + counts["LOW"] + counts["INFO"]
    return counts


async def get_llm_findings(db_path: str, executable: str) -> list[LlmFinding]:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT FunctionName, ClassName, Mode, Finding FROM LlmFindings WHERE ExecutableName=?",
            (executable,)
        ) as cur:
            rows = await cur.fetchall()
    return [LlmFinding(function_name=r[0], class_name=r[1], mode=r[2], finding=r[3])
            for r in rows]
