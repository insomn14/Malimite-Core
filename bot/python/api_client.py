"""HTTP client for the Malimite web API — what the Slack bot uses instead of running the CLI
itself.

Why the bot talks to the API rather than shelling out to `malimite-cli.jar`:

* one scan path. A scan created here goes through `POST /api/v1/scans`, exactly like the Web UI,
  the watcher daemon and any CI pipeline — so it shows up in the Web UI for triage, AI Fix and
  Auto Enhance afterwards instead of landing in a private directory nobody reviews;
* no duplicated toolchain. The server already has Ghidra/JADX installed and sized for it; the bot
  host only needs Python.

Only the fields the Slack formatters need are mapped (see `to_slack_finding`); nothing here
re-implements the server's severity/grouping logic — `vulnerability_counts` is read straight from
the scan detail the server computes.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Optional

import httpx

SUPPRESSED_STATUSES = ("false_positive", "fixed")

_TIMEOUT = httpx.Timeout(60.0, connect=10.0)


class ApiError(RuntimeError):
    """Any failure talking to the Malimite API, or the scan itself ending in an error state."""


def _duration_s(detail: dict) -> float:
    """Seconds between created_at and finished_at, when both are usable ISO timestamps."""
    try:
        started = datetime.fromisoformat(detail["created_at"])
        finished = datetime.fromisoformat(detail["finished_at"])
    except (KeyError, TypeError, ValueError):
        return 0.0
    return max(0.0, (finished - started).total_seconds())


def to_slack_finding(v: dict) -> dict:
    """Map one API vulnerability record onto the key names bot/python/slack_format.py renders.
    Effective (triage/AI-Fix overridden) values win, matching what the Web UI shows."""
    status = str(v.get("status") or "open").lower()
    return {
        "RuleId": v.get("rule_id") or "",
        "Title": v.get("title") or "Untitled finding",
        "effective_severity": str(v.get("effective_severity") or v.get("severity") or "INFO").upper(),
        "effective_cvss": float(v.get("effective_cvss_score") or v.get("cvss_score") or 0.0),
        "is_suppressed": status in SUPPRESSED_STATUSES,
        "Description": v.get("effective_description") or v.get("description") or "",
        "EvidenceLocation": v.get("evidence_location") or v.get("affected_name") or "",
        "AffectedName": v.get("affected_name") or "",
        "Remediation": v.get("effective_remediation") or v.get("remediation") or "",
        "ReferenceUrl": v.get("reference_url") or "",
    }


class MalimiteApi:
    """Minimal async client: create a scan, wait for it, read findings, fetch artifacts."""

    def __init__(self, base_url: str, api_key: str = "",
                 client: Optional[httpx.AsyncClient] = None):
        self.base_url = (base_url or "").rstrip("/")
        if not self.base_url:
            raise ApiError("MALIMITE_URL is not configured")
        self._headers = {"X-Api-Key": api_key} if api_key else {}
        self._client = client          # injected in tests; created per-call otherwise

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        # Headers go on every request rather than only on the client we build ourselves: an
        # injected client (tests, or a caller sharing one connection pool) would otherwise send
        # unauthenticated requests, which the server answers with 401.
        own = self._client is None
        client = self._client or httpx.AsyncClient(timeout=_TIMEOUT, headers=self._headers)
        try:
            resp = await client.request(method, self._url(path), headers=self._headers, **kwargs)
        except httpx.HTTPError as exc:
            raise ApiError(f"{method} {path} failed: {exc}") from exc
        finally:
            if own:
                await client.aclose()
        return resp

    async def create_scan(self, data: bytes, filename: str, *,
                          llm_enabled: bool = False,
                          assessment_enabled: bool = True) -> str:
        resp = await self._request(
            "POST", "/api/v1/scans",
            data={"llm_enabled": "true" if llm_enabled else "false",
                  "assessment_enabled": "true" if assessment_enabled else "false",
                  "ci_triggered_by": "slack"},
            files={"file": (filename, data, "application/octet-stream")},
        )
        if resp.status_code >= 400:
            raise ApiError(f"upload failed: HTTP {resp.status_code} {resp.text[:200]}")
        scan_id = (resp.json() or {}).get("scan_id")
        if not scan_id:
            raise ApiError("upload response did not include a scan_id")
        return scan_id

    async def wait_for_scan(self, scan_id: str, *, poll_interval: float = 5.0,
                            overall_timeout: float = 1800.0, on_poll=None) -> dict:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + overall_timeout
        while True:
            resp = await self._request("GET", f"/api/v1/scans/{scan_id}")
            if resp.status_code >= 400:
                raise ApiError(f"status check failed: HTTP {resp.status_code} {resp.text[:200]}")
            detail = resp.json() or {}
            state = detail.get("state")
            if state in ("done", "error"):
                return detail
            if loop.time() >= deadline:
                raise ApiError(f"scan {scan_id} still '{state}' after {overall_timeout:.0f}s")
            if on_poll is not None:
                await on_poll()
            await asyncio.sleep(poll_interval)

    async def vulnerabilities(self, scan_id: str) -> list[dict]:
        resp = await self._request("GET", f"/api/v1/scans/{scan_id}/vulnerabilities")
        if resp.status_code >= 400:
            raise ApiError(f"findings fetch failed: HTTP {resp.status_code} {resp.text[:200]}")
        payload = resp.json()
        if not isinstance(payload, list):
            raise ApiError(f"unexpected findings payload: {type(payload).__name__}")
        return payload

    async def artifact(self, scan_id: str, kind: str) -> Optional[bytes]:
        """Fetch report.html ('report') or findings.sarif ('sarif'). Returns None when the server
        has no such artifact for this scan (a normal outcome, not an error)."""
        path = {"report": "/report", "sarif": "/sarif"}.get(kind)
        if not path:
            raise ValueError(f"unknown artifact kind {kind!r}")
        resp = await self._request("GET", f"/api/v1/scans/{scan_id}{path}")
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise ApiError(f"artifact fetch failed: HTTP {resp.status_code} {resp.text[:200]}")
        return resp.content


async def run_scan(api: MalimiteApi, data: bytes, filename: str, *,
                   llm_enabled: bool = False,
                   poll_interval: float = 5.0,
                   overall_timeout: float = 1800.0,
                   progress=None) -> dict:
    """Create a scan, wait for it, and return everything the Slack formatters need.

    ``progress`` is an optional zero-arg coroutine awaited between polls, used by the bot to keep
    editing its "still scanning" message.

    Raises ApiError on transport/poll failures. A scan that finished in the error state comes back
    with ok=False so the bot can tell the user the server reported a failure.
    """
    scan_id = await api.create_scan(data, filename, llm_enabled=llm_enabled)
    detail = await api.wait_for_scan(scan_id, poll_interval=poll_interval,
                                     overall_timeout=overall_timeout, on_poll=progress)

    counts = dict(detail.get("vulnerability_counts") or {})
    counts.setdefault("total", 0)

    result: dict[str, Any] = {
        "ok": detail.get("state") == "done",
        "scan_id": scan_id,
        "bundle_id": detail.get("bundle_id") or "—",
        "bundle_executable": detail.get("bundle_executable") or "—",
        "duration_s": _duration_s(detail),
        "counts": counts,
        "vulnerabilities": [],
    }
    if not result["ok"]:
        return result

    raw = await api.vulnerabilities(scan_id)
    result["vulnerabilities"] = [to_slack_finding(v) for v in raw]
    return result
