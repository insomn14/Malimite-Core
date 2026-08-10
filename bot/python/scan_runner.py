"""
Wraps the Malimite CLI JAR — runs it as a subprocess against a downloaded
IPA, then reads findings back from the resulting SQLite database.

Standalone: does not talk to the FastAPI web service.
"""
import asyncio
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class ScanRunner:
    """One-shot scanner: download → analyze → read results."""

    def __init__(
        self,
        cli_jar: str,
        ghidra_home: str = "/usr/share/ghidra",
        scan_root: str = "/tmp/malimite-slack",
        llm_provider: str = "none",
        llm_mode: str = "summarize",
        llm_model: str = "",
        openai_api_key: str = "",
        anthropic_api_key: str = "",
        deepseek_api_key: str = "",
        deepseek_base_url: str = "https://api.deepseek.com",
        ollama_base_url: str = "http://localhost:11434",
    ):
        self.cli_jar         = cli_jar
        self.ghidra_home     = ghidra_home
        self.scan_root       = Path(scan_root)
        self.scan_root.mkdir(parents=True, exist_ok=True)
        self.llm_provider    = llm_provider
        self.llm_mode        = llm_mode
        self.llm_model       = llm_model
        self.openai_api_key  = openai_api_key
        self.anthropic_api_key = anthropic_api_key
        self.deepseek_api_key = deepseek_api_key
        self.deepseek_base_url = deepseek_base_url
        self.ollama_base_url = ollama_base_url

    async def run(self, ipa_bytes: bytes, ipa_filename: str) -> dict:
        """
        Run a complete scan and return:
        {
          "scan_id": "...",
          "ok": bool,
          "exit_code": int,
          "duration_s": float,
          "scan_dir": Path,
          "report_html": Path | None,
          "sarif": Path | None,
          "bundle_id": str | None,
          "bundle_executable": str | None,
          "counts": {...},
          "vulnerabilities": [...]  # sorted critical→low, active only
        }
        """
        scan_id = str(uuid.uuid4())
        scan_dir = self.scan_root / scan_id
        scan_dir.mkdir(parents=True)

        ipa_path = scan_dir / ipa_filename
        ipa_path.write_bytes(ipa_bytes)

        cmd = [
            "java", "-jar", self.cli_jar,
            str(ipa_path),
            "--ghidra", self.ghidra_home,
            "--out", str(scan_dir),
            "--sarif",
            "--html",
        ]
        if self.llm_provider != "none":
            cmd += ["--llm", "--llm-provider", self.llm_provider, "--llm-mode", self.llm_mode]
            if self.llm_model:
                cmd += ["--llm-model", self.llm_model]

        env = dict(os.environ)
        if self.llm_provider == "openai" and self.openai_api_key:
            env["OPENAI_API_KEY"] = self.openai_api_key
        if self.llm_provider == "claude" and self.anthropic_api_key:
            env["ANTHROPIC_API_KEY"] = self.anthropic_api_key
        if self.llm_provider == "deepseek" and self.deepseek_api_key:
            env["DEEPSEEK_API_KEY"] = self.deepseek_api_key
        if self.llm_provider == "deepseek" and self.deepseek_base_url:
            env["DEEPSEEK_BASE_URL"] = self.deepseek_base_url
        if self.llm_provider == "ollama":
            env["OLLAMA_BASE_URL"] = self.ollama_base_url

        log_path = scan_dir / "analysis.log"
        t0 = datetime.now(timezone.utc)
        with open(log_path, "w") as log_fh:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=log_fh, stderr=asyncio.subprocess.STDOUT, env=env,
            )
            exit_code = await proc.wait()
        duration_s = (datetime.now(timezone.utc) - t0).total_seconds()

        result: dict[str, Any] = {
            "scan_id":           scan_id,
            "ok":                exit_code == 0,
            "exit_code":         exit_code,
            "duration_s":        duration_s,
            "scan_dir":          scan_dir,
            "log":               log_path,
            "report_html":       None,
            "sarif":             None,
            "bundle_id":         None,
            "bundle_executable": None,
            "counts":            {},
            "vulnerabilities":   [],
        }
        if exit_code != 0:
            return result

        # Read scan.json for bundle metadata
        scan_json = scan_dir / "scan.json"
        if scan_json.exists():
            meta = json.loads(scan_json.read_text())
            result["bundle_id"]         = meta.get("bundleIdentifier")
            result["bundle_executable"] = meta.get("bundleExecutable")
            db_path = meta.get("dbPath")
            if db_path and Path(db_path).exists():
                result["counts"]          = _read_counts(db_path, result["bundle_executable"])
                result["vulnerabilities"] = _read_vulnerabilities(db_path, result["bundle_executable"])

        html = scan_dir / "report.html"
        if html.exists(): result["report_html"] = html
        sarif = scan_dir / "findings.sarif"
        if sarif.exists(): result["sarif"] = sarif

        return result


# ── SQLite readers ────────────────────────────────────────────────────────────

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _read_counts(db_path: str, executable: Optional[str]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
              "suppressed": 0, "total": 0}
    if not executable:
        return counts
    try:
        with sqlite3.connect(db_path) as db:
            db.row_factory = sqlite3.Row
            cur = db.execute(
                """SELECT COALESCE(OverrideSeverity, Severity) AS sev,
                          COALESCE(Status,'open') AS status,
                          COUNT(*) AS n
                   FROM Vulnerabilities WHERE ExecutableName=?
                   GROUP BY sev, status""",
                (executable,)
            )
            for row in cur:
                if row["status"] in ("false_positive", "fixed"):
                    counts["suppressed"] += row["n"]
                    continue
                sev = (row["sev"] or "INFO").upper()
                if sev in counts:
                    counts[sev] += row["n"]
    except sqlite3.OperationalError:
        return counts
    counts["total"] = sum(counts[k] for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    return counts


def _read_vulnerabilities(db_path: str, executable: Optional[str]) -> list[dict]:
    if not executable:
        return []
    try:
        with sqlite3.connect(db_path) as db:
            db.row_factory = sqlite3.Row
            cur = db.execute(
                """SELECT id, RuleId, Title, Category, Severity, CvssScore, Cwe,
                          Description, AffectedType, AffectedName, Evidence,
                          EvidenceLocation, PocSteps, Remediation, ReferenceUrl,
                          COALESCE(Status,'open') AS Status, OverrideSeverity, OverrideCvssScore,
                          OverrideNote
                   FROM Vulnerabilities WHERE ExecutableName=?""",
                (executable,)
            )
            rows = [dict(r) for r in cur]
    except sqlite3.OperationalError:
        return []

    # Compute effective severity/cvss + sort
    for r in rows:
        r["effective_severity"] = (r.get("OverrideSeverity") or r.get("Severity") or "INFO").upper()
        r["effective_cvss"]     = r.get("OverrideCvssScore") if r.get("OverrideCvssScore") is not None else (r.get("CvssScore") or 0.0)
        r["is_suppressed"]      = r["Status"] in ("false_positive", "fixed")

    rows.sort(key=lambda v: (
        1 if v["is_suppressed"] else 0,
        _SEV_RANK.get(v["effective_severity"], 5),
        -v["effective_cvss"],
        v.get("RuleId") or "",
    ))
    return rows
