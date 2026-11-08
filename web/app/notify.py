"""Outbound Slack notification when a scan finishes.

One-way and text-only on purpose: this tells a security team that a scan completed and how bad
it looks, with a link back to the web UI for the actual report. It never uploads artifacts, so
the message stays small and nothing proprietary leaves the server beyond a filename and counts.

Two properties matter more than features here:

* It fires for EVERY scan that finishes, regardless of how it was started — Web UI upload, the
  watcher daemon, `malimite-ci` from a pipeline, or a direct API call all take the same
  `scanner._run()` path, so none of them can silently skip the alert.
* It is best-effort. A missing/broken webhook, a Slack outage, or an unparseable scan database
  is logged and swallowed — notification trouble must never turn into a failed scan.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from .config import settings

log = logging.getLogger(__name__)

# Same emoji vocabulary as tools/malimite-ci and bot/python/slack_format.py, so a channel that
# receives messages from more than one of these surfaces looks consistent.
_SEV_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":large_orange_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":large_blue_circle:",
    "INFO": ":white_circle:",
}

_VALID_THRESHOLDS = ("NONE", "LOW", "MEDIUM", "HIGH")

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Keep a reference to fire-and-forget notification tasks so they cannot be garbage-collected
# mid-flight, and so shutdown can see whether anything is still in progress.
_NOTIFY_TASKS: set[asyncio.Task] = set()


def should_notify(counts: dict, min_severity: str, state: str) -> bool:
    """Decide whether this finished scan is worth an alert.

    A scan that did NOT finish cleanly (state error) always alerts: a silently failed scan is
    strictly worse than a noisy one, and there are no counts to reason about in that case.

    Threshold semantics deliberately mirror the CLI/malimite-ci --fail-on ladder so operators
    only have one vocabulary to learn: HIGH means critical/high, MEDIUM adds medium, LOW means
    any finding at all, NONE means never (only failed scans still alert).
    """
    if state != "done":
        return True
    threshold = (min_severity or "HIGH").strip().upper()
    if threshold not in _VALID_THRESHOLDS:
        log.warning("Unknown slack_notify_min_severity %r; falling back to HIGH", min_severity)
        threshold = "HIGH"
    if threshold == "NONE":
        return False
    crit = int(counts.get("CRITICAL") or 0)
    high = int(counts.get("HIGH") or 0)
    med = int(counts.get("MEDIUM") or 0)
    if threshold == "HIGH":
        return crit > 0 or high > 0
    if threshold == "MEDIUM":
        return crit > 0 or high > 0 or med > 0
    # LOW: any recorded finding counts, including INFO.
    return any(int(counts.get(s) or 0) > 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))


def _severity_line(counts: dict) -> Optional[str]:
    parts = [
        f"{_SEV_EMOJI[s]} *{int(counts.get(s) or 0)}* {s.capitalize()}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if int(counts.get(s) or 0) > 0
    ]
    return " · ".join(parts) if parts else None


def build_payload(scan_id: str, filename: str, state: str, counts: dict,
                  executable: Optional[str] = None,
                  base_url: str = "") -> dict:
    """Slack Block Kit payload. Text only — no file uploads, by design."""
    if state != "done":
        headline = ":warning: *Scan failed*"
        detail = f"The scan did not complete (state: `{state}`). Check the server's log for this scan."
    else:
        total = int(counts.get("total") or 0)
        if total == 0:
            headline = ":white_check_mark: *No active findings*"
        else:
            headline = f":mag: *{total} finding{'s' if total != 1 else ''} detected*"
        detail = None

    label = filename or scan_id
    header_text = f"Malimite scan: {label}"
    # Slack rejects the WHOLE message (not just truncates) if a header exceeds 150 chars, so a
    # long APK/IPA filename must not be allowed to silently drop the alert.
    if len(header_text) > 150:
        header_text = header_text[:147] + "..."

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header_text}},
        {"type": "section", "text": {"type": "mrkdwn", "text": headline}},
    ]
    if detail:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": detail}})

    sev = _severity_line(counts) if state == "done" else None
    if sev:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": sev}})

    context: list[str] = []
    if base_url:
        context.append(f"<{base_url.rstrip('/')}/#/scan/{scan_id}|View report>")
    if executable:
        context.append(f"`{executable}`")
    context.append(f"Scan ID: `{scan_id[:8]}…`")
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(context)}]})

    return {"blocks": blocks}


async def post(url: str, payload: dict, client: Optional[httpx.AsyncClient] = None) -> bool:
    """POST a payload to a Slack Incoming Webhook. Returns True on success, False on any failure —
    never raises, so a caller in the scan-completion path cannot be derailed by Slack."""
    own = client is None
    client = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        resp = await client.post(url, json=payload)
        if resp.status_code >= 400:
            log.warning("Slack notification rejected: HTTP %s %s", resp.status_code, resp.text[:200])
            return False
        return True
    except httpx.HTTPError as exc:
        log.warning("Slack notification failed: %s", exc)
        return False
    except Exception:
        log.warning("Slack notification failed unexpectedly", exc_info=True)
        return False
    finally:
        if own:
            await client.aclose()


async def notify_scan_finished(scan_id: str, filename: str, state: str, counts: dict,
                               executable: Optional[str] = None) -> bool:
    """Send the alert for one finished scan if the configured policy says so. Safe to call for
    every scan: returns immediately when no webhook is configured or the threshold isn't met."""
    url = (settings.slack_webhook_url or "").strip()
    if not url:
        return False
    if not should_notify(counts, settings.slack_notify_min_severity, state):
        return False
    payload = build_payload(scan_id, filename, state, counts, executable=executable,
                            base_url=(settings.public_base_url or "").strip())
    ok = await post(url, payload)
    if ok:
        log.info("Slack notified for scan %s (state=%s)", scan_id, state)
    return ok


def schedule_scan_finished(scan_id: str, filename: str, state: str, counts: dict,
                           executable: Optional[str] = None) -> None:
    """Fire-and-forget from scanner._run(): runs off the current task so a slow or unreachable
    webhook cannot keep a scan's concurrency slot occupied after the CLI has already exited."""
    if not (settings.slack_webhook_url or "").strip():
        return
    task = asyncio.create_task(
        notify_scan_finished(scan_id, filename, state, counts, executable=executable))
    _NOTIFY_TASKS.add(task)
    task.add_done_callback(_NOTIFY_TASKS.discard)
