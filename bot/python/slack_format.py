"""
Convert scan results into Slack Block Kit messages.
Block Kit ref: https://api.slack.com/block-kit
"""
from typing import Any

_SEV_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH":     ":large_orange_circle:",
    "MEDIUM":   ":large_yellow_circle:",
    "LOW":      ":large_blue_circle:",
    "INFO":     ":white_circle:",
}


def queued(filename: str) -> list[dict]:
    """First reply when an IPA is dropped — sets expectations."""
    return [
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f":hourglass_flowing_sand: *Scan queued* — `{filename}`\n"
                    f"Decompiling with Ghidra and running MSTG checks. "
                    f"This typically takes *3–10 minutes* depending on app size."}},
    ]


def progress(filename: str, elapsed_s: int) -> list[dict]:
    return [{"type": "section", "text": {"type": "mrkdwn",
        "text": f":gear: *Still scanning* `{filename}` — {elapsed_s}s elapsed"}}]


def failure(filename: str, error_text: str) -> list[dict]:
    body = error_text[:400] if error_text else "(see attached log)"
    return [
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f":x: *Scan failed* — `{filename}`\n```{body}```"}},
    ]


def summary(filename: str, result: dict) -> list[dict]:
    """Top-of-thread summary card with counts + bundle metadata."""
    counts = result.get("counts", {}) or {}
    total  = counts.get("total", 0)
    crit   = counts.get("CRITICAL", 0)
    high   = counts.get("HIGH", 0)
    med    = counts.get("MEDIUM", 0)
    low    = counts.get("LOW", 0)
    supp   = counts.get("suppressed", 0)

    headline = ":white_check_mark: *No security findings*" if total == 0 \
               else f":mag: *{total} finding{'s' if total != 1 else ''} detected*"

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text",
            "text": f"Mailmite scan: {filename}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Bundle ID*\n`{result.get('bundle_id','—')}`"},
            {"type": "mrkdwn", "text": f"*Executable*\n`{result.get('bundle_executable','—')}`"},
            {"type": "mrkdwn", "text": f"*Duration*\n{int(result.get('duration_s',0))}s"},
            {"type": "mrkdwn", "text": f"*Scan ID*\n`{result.get('scan_id','')[:8]}…`"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": headline}},
    ]

    if total > 0:
        sev_line = " · ".join([
            f"{_SEV_EMOJI['CRITICAL']} *{crit}* Critical",
            f"{_SEV_EMOJI['HIGH']} *{high}* High",
            f"{_SEV_EMOJI['MEDIUM']} *{med}* Medium",
            f"{_SEV_EMOJI['LOW']} *{low}* Low",
        ])
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": sev_line}})
    if supp:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
            "text": f"_+{supp} suppressed (false positive / fixed)_"}]})

    blocks.append({"type": "divider"})
    return blocks


def top_findings(vulnerabilities: list[dict], limit: int = 5) -> list[dict]:
    """Render the top N active findings as Slack sections, sorted CRIT→LOW."""
    actives = [v for v in vulnerabilities if not v.get("is_suppressed")]
    if not actives:
        return []

    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn",
        "text": f"*Top {min(limit, len(actives))} findings* (sorted by severity)"}}]

    for v in actives[:limit]:
        sev   = v.get("effective_severity", "INFO")
        cvss  = v.get("effective_cvss", 0.0)
        title = v.get("Title", "Untitled finding")
        rid   = v.get("RuleId", "")
        desc  = (v.get("Description") or "")[:240]
        loc   = (v.get("EvidenceLocation") or v.get("AffectedName") or "")[:80]
        rem   = (v.get("Remediation") or "")[:240]
        ref   = v.get("ReferenceUrl") or ""

        text = (
            f"{_SEV_EMOJI.get(sev,':white_circle:')} *{sev}* · CVSS {cvss:.1f} · `{rid}`\n"
            f"*{title}*\n"
            f"{desc}\n"
            f":dart: _Affected:_ `{loc}`\n"
            f":wrench: _Fix:_ {rem}"
        )
        if ref:
            text += f"\n<{ref}|Reference>"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
        blocks.append({"type": "divider"})

    if len(actives) > limit:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
            "text": f"_+{len(actives) - limit} more findings in the attached HTML report._"}]})
    return blocks


def help_message() -> list[dict]:
    return [
        {"type": "header", "text": {"type": "plain_text", "text": "Mailmite Slack Bot"}},
        {"type": "section", "text": {"type": "mrkdwn",
            "text": "*How to use:*\n"
                    "• Send (or DM) any `.ipa` file to start a scan.\n"
                    "• I'll reply in this thread when the analysis is complete.\n"
                    "• HTML report and SARIF will be attached to the result message.\n\n"
                    "*Commands:*\n"
                    "• `mailmite help` — this help\n"
                    "• `mailmite version` — bot + CLI version info"}},
        {"type": "context", "elements": [{"type": "mrkdwn",
            "text": "_Scans run locally on the bot host. No data leaves your infrastructure unless LLM enrichment is enabled._"}]},
    ]
