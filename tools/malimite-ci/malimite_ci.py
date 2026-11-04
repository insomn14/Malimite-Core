#!/usr/bin/env python3
"""
malimite-ci — thin HTTP client for CI/CD pipelines (Bitbucket Pipelines, Jenkins, etc).

Uploads an APK/IPA/XAPK to a running malimite-web server, waits for the scan to
finish, fetches the findings, and exits non-zero when the highest active severity
meets or exceeds the --fail-on threshold.

Zero third-party dependencies (stdlib only: urllib) so it runs on any CI runner
without a pip install step.

Why this script computes the severity gate itself instead of trusting the scan's
own exit_code or the CLI's --fail-on flag:
  - The web service's POST /scans response exit_code reflects subprocess success/
    failure only (did the CLI crash), never a severity policy.
  - malimite-cli.jar's own --fail-on flag is not passed through by the web service
    when it runs the CLI as a subprocess, so it has no effect via this API path
    even though the flag exists.
This script is therefore the single place severity-gating policy lives for anyone
driving Malimite from a pipeline over the REST API.

Usage:
    malimite_ci.py --url http://malimite.internal:7070 --api-key "$MALIMITE_API_KEY" \\
        --file app-release.apk --fail-on HIGH

Exit codes:
    0  scan completed, no finding at/above --fail-on (or --fail-on NONE)
    1  scan completed, a finding at/above --fail-on was found (the "fail the build" case)
    2  usage / configuration error (bad args, file not found, no API key when required)
    3  could not reach the server, or request failed (network/auth/HTTP error)
    4  scan itself errored or exceeded --timeout while still running
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Optional

# Matches Main.computeExitCode()'s semantics exactly (core/cli's --fail-on), so this script
# behaves the same whether a pipeline gates a build via the CLI directly or via this script
# calling the API:
#   HIGH   -> trips only on CRITICAL/HIGH findings
#   MEDIUM -> trips on CRITICAL/HIGH/MEDIUM findings
#   LOW    -> trips on ANY active finding at all, including INFO (not "severity >= LOW")
#   NONE   -> never trips
SUPPRESSED_STATUSES = {"false_positive", "fixed"}  # matches VulnerabilityRecord.isSuppressed()


class MalimiteCiError(Exception):
    """Raised for conditions that should set a specific, documented exit code."""

    def __init__(self, message: str, exit_code: int):
        super().__init__(message)
        self.exit_code = exit_code


def _request(url: str, api_key: Optional[str], method: str = "GET",
             data: Optional[bytes] = None, headers: Optional[dict] = None,
             timeout: float = 30.0) -> dict:
    req_headers = dict(headers or {})
    if api_key:
        req_headers["X-Api-Key"] = api_key
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            detail = json.loads(body).get("detail", body.decode("utf-8", "replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            detail = body.decode("utf-8", "replace")
        raise MalimiteCiError(
            f"{method} {url} -> HTTP {e.code}: {detail}", exit_code=3) from e
    except urllib.error.URLError as e:
        raise MalimiteCiError(f"{method} {url} -> could not connect: {e.reason}", exit_code=3) from e
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        raise MalimiteCiError(f"{method} {url} -> non-JSON response: {e}", exit_code=3) from e


def _multipart_body(file_path: str, fields: dict) -> tuple[bytes, str]:
    """Builds a multipart/form-data body by hand (stdlib has no client-side helper)."""
    boundary = uuid.uuid4().hex
    parts: list[bytes] = []

    def add_field(name: str, value: str) -> None:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
            .encode("utf-8")
        )

    for name, value in fields.items():
        add_field(name, value)

    filename = os.path.basename(file_path)
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f'Content-Type: {content_type}\r\n\r\n'.encode("utf-8")
    )
    parts.append(file_bytes)
    parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    body = b"".join(parts)
    return body, f"multipart/form-data; boundary={boundary}"


def detect_ci_metadata() -> dict[str, str]:
    """Best-effort pipeline/commit/triggered-by detection from well-known CI env vars. Returns
    only the keys it could determine — callers should let explicit --ci-* flags take priority
    over this, since an operator running the script by hand has no env vars to detect from."""
    detected: dict[str, str] = {}

    # Bitbucket Pipelines
    if os.environ.get("BITBUCKET_BUILD_NUMBER"):
        repo = os.environ.get("BITBUCKET_REPO_FULL_NAME", "")
        build = os.environ["BITBUCKET_BUILD_NUMBER"]
        if repo:
            detected["ci_pipeline_url"] = f"https://bitbucket.org/{repo}/pipelines/results/{build}"
        if os.environ.get("BITBUCKET_COMMIT"):
            detected["ci_commit_sha"] = os.environ["BITBUCKET_COMMIT"]
        detected["ci_triggered_by"] = "bitbucket-pipelines"

    # Jenkins
    elif os.environ.get("JENKINS_URL") or os.environ.get("BUILD_URL"):
        if os.environ.get("BUILD_URL"):
            detected["ci_pipeline_url"] = os.environ["BUILD_URL"]
        if os.environ.get("GIT_COMMIT"):
            detected["ci_commit_sha"] = os.environ["GIT_COMMIT"]
        detected["ci_triggered_by"] = "jenkins"

    # GitHub Actions (covers the repo's own ipa-scan.yml if it's ever pointed at a live server)
    elif os.environ.get("GITHUB_ACTIONS") == "true":
        server = os.environ.get("GITHUB_SERVER_URL", "")
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        if server and repo and run_id:
            detected["ci_pipeline_url"] = f"{server}/{repo}/actions/runs/{run_id}"
        if os.environ.get("GITHUB_SHA"):
            detected["ci_commit_sha"] = os.environ["GITHUB_SHA"]
        detected["ci_triggered_by"] = "github-actions"

    return detected


def upload_scan(base_url: str, api_key: Optional[str], file_path: str,
                llm_enabled: bool, assessment_enabled: bool, timeout: float,
                ci_pipeline_url: Optional[str] = None, ci_commit_sha: Optional[str] = None,
                ci_triggered_by: Optional[str] = None) -> str:
    fields = {
        "llm_enabled": "true" if llm_enabled else "false",
        "assessment_enabled": "true" if assessment_enabled else "false",
    }
    if ci_pipeline_url:
        fields["ci_pipeline_url"] = ci_pipeline_url
    if ci_commit_sha:
        fields["ci_commit_sha"] = ci_commit_sha
    if ci_triggered_by:
        fields["ci_triggered_by"] = ci_triggered_by
    body, content_type = _multipart_body(file_path, fields)
    result = _request(
        f"{base_url}/api/v1/scans", api_key, method="POST", data=body,
        headers={"Content-Type": content_type}, timeout=timeout,
    )
    scan_id = result.get("scan_id")
    if not scan_id:
        raise MalimiteCiError(f"Upload succeeded but no scan_id in response: {result}", exit_code=3)
    return scan_id


def poll_scan(base_url: str, api_key: Optional[str], scan_id: str,
              poll_interval: float, overall_timeout: float) -> dict:
    deadline = time.monotonic() + overall_timeout
    while True:
        detail = _request(f"{base_url}/api/v1/scans/{scan_id}", api_key, timeout=30.0)
        state = detail.get("state")
        if state == "done":
            return detail
        if state == "error":
            raise MalimiteCiError(
                f"Scan {scan_id} failed (exit_code={detail.get('exit_code')}); "
                f"check the server's analysis.log for this scan", exit_code=4)
        if time.monotonic() >= deadline:
            raise MalimiteCiError(
                f"Scan {scan_id} still '{state}' after {overall_timeout:.0f}s timeout", exit_code=4)
        time.sleep(poll_interval)


def fetch_vulnerabilities(base_url: str, api_key: Optional[str], scan_id: str) -> list[dict]:
    result = _request(f"{base_url}/api/v1/scans/{scan_id}/vulnerabilities", api_key, timeout=60.0)
    if not isinstance(result, list):
        raise MalimiteCiError(f"Unexpected /vulnerabilities response shape: {type(result)}", exit_code=3)
    return result


def active_findings(vulnerabilities: list[dict]) -> list[dict]:
    """Findings that count toward the severity gate: excludes false_positive/fixed, mirroring
    VulnerabilityRecord.isSuppressed() (core) and SarifExporter's MALIMITE004 filter."""
    return [v for v in vulnerabilities if v.get("status") not in SUPPRESSED_STATUSES]


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in findings:
        sev = str(v.get("effective_severity") or v.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def should_fail(findings: list[dict], fail_on: str) -> bool:
    if fail_on == "NONE":
        return False
    has_high = has_medium = has_any = False
    for v in findings:
        sev = str(v.get("effective_severity") or v.get("severity") or "INFO").upper()
        has_any = True
        if sev in ("CRITICAL", "HIGH"):
            has_high = True
        elif sev == "MEDIUM":
            has_medium = True
    if fail_on == "HIGH":
        return has_high
    if fail_on == "MEDIUM":
        return has_high or has_medium
    if fail_on == "LOW":
        return has_any
    return False


# Matches bot/python/slack_format.py's emoji convention (consistent visual language across both
# Malimite Slack surfaces) without importing it: that module depends on slack-bolt, which this
# script deliberately avoids to stay stdlib-only.
_SEV_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":large_orange_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":large_blue_circle:",
    "INFO": ":white_circle:",
}


def build_slack_payload(scan_id: str, scan_url: str, filename: str, fail_on: str,
                        fail: bool, counts: dict[str, int], total_findings: int,
                        ci_pipeline_url: Optional[str] = None,
                        ci_triggered_by: Optional[str] = None) -> dict:
    """Slack Incoming Webhook payload (Block Kit) — sent for every completed scan, regardless of
    --fail-on verdict, so the security team has full visibility even when the build itself isn't
    gated (see tools/malimite-ci/README.md's "Monitoring mode" section for why that's a
    deliberate, supported configuration rather than a workaround)."""
    verdict_text = (
        f":rotating_light: *Build gate: FAIL* (--fail-on {fail_on})" if fail
        else f":white_check_mark: Build gate: pass (--fail-on {fail_on})"
    )
    headline = (":white_check_mark: *No active findings*" if total_findings == 0
                else f":mag: *{total_findings} finding{'s' if total_findings != 1 else ''} detected*")

    # Slack's header block enforces a hard 150-char limit on plain_text and REJECTS the whole
    # message if exceeded — not just truncates. A long APK/IPA filename could realistically blow
    # past this, so truncate defensively rather than let a long filename silently drop the
    # notification entirely (the one thing this feature exists to guarantee).
    header_text = f"Malimite scan: {filename}"
    if len(header_text) > 150:
        header_text = header_text[:147] + "..."

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": header_text}},
        {"type": "section", "text": {"type": "mrkdwn", "text": headline}},
    ]

    sev_parts = [f"{_SEV_EMOJI[s]} *{counts.get(s, 0)}* {s.capitalize()}"
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s)]
    if sev_parts:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": " · ".join(sev_parts)}})

    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": verdict_text}})

    context_parts = [f"<{scan_url}|View full report>"]
    if ci_pipeline_url:
        context_parts.append(f"<{ci_pipeline_url}|Pipeline run>")
    if ci_triggered_by:
        context_parts.append(f"Triggered by: {ci_triggered_by}")
    context_parts.append(f"Scan ID: `{scan_id[:8]}…`")
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": " · ".join(context_parts)}]})

    return {"blocks": blocks}


def send_slack_notification(webhook_url: str, payload: dict, timeout: float = 10.0) -> None:
    """Best-effort: a Slack delivery failure (bad URL, Slack outage, network blip) is logged to
    stderr but never changes the process exit code. A notification side-channel must not become a
    new way for an otherwise-clean build to fail — the --fail-on verdict computed from the scan
    itself is the only thing allowed to do that."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        print("Slack notification sent.")
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"warning: could not send Slack notification: {e}", file=sys.stderr)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Upload an APK/IPA to a Malimite web server, wait for the scan, "
                    "and fail the build if a finding at/above --fail-on is present.")
    p.add_argument("--url", required=True,
                    help="Base URL of the malimite-web server, e.g. http://malimite.internal:7070")
    p.add_argument("--api-key", default=os.environ.get("MALIMITE_API_KEY"),
                    help="X-Api-Key value; defaults to $MALIMITE_API_KEY")
    p.add_argument("--file", required=True, help="Path to the .ipa/.apk/.xapk to scan")
    p.add_argument("--fail-on", choices=["NONE", "LOW", "MEDIUM", "HIGH"], default="HIGH",
                    help="Exit 1 if an active finding reaches this severity (default: HIGH)")
    p.add_argument("--llm-enabled", action="store_true",
                    help="Enable LLM enrichment for this scan (uses the server's configured "
                        "provider; slower, costs API quota — off by default for CI)")
    p.add_argument("--no-assessment", action="store_true",
                    help="Disable the Security Assessment controls inventory for this scan")
    p.add_argument("--timeout", type=float, default=1800.0,
                    help="Max seconds to wait for the scan to finish (default: 1800 = 30 min)")
    p.add_argument("--poll-interval", type=float, default=5.0,
                    help="Seconds between status polls (default: 5)")
    p.add_argument("--json-out", default=None,
                    help="Write a machine-readable summary to this path (scan_id, severity "
                        "counts, verdict) for downstream CI steps")
    p.add_argument("--ci-pipeline-url", default=None,
                    help="Link to this pipeline run, shown in the web UI. Auto-detected on "
                        "Bitbucket Pipelines, Jenkins, and GitHub Actions when unset")
    p.add_argument("--ci-commit-sha", default=None,
                    help="Commit SHA this scan was built from. Auto-detected when unset")
    p.add_argument("--ci-triggered-by", default=None,
                    help="Free-form label for what started this scan (default: "
                        "auto-detected CI system name, e.g. 'jenkins')")
    p.add_argument("--no-ci-autodetect", action="store_true",
                    help="Disable CI environment auto-detection entirely (only explicit --ci-* "
                        "flags are used, if any)")
    p.add_argument("--slack-webhook-url", default=os.environ.get("MALIMITE_SLACK_WEBHOOK_URL"),
                    help="Slack Incoming Webhook URL. When set, a summary is posted for EVERY "
                        "completed scan regardless of --fail-on verdict (so a security team has "
                        "full visibility even in monitoring mode, --fail-on NONE). Defaults to "
                        "$MALIMITE_SLACK_WEBHOOK_URL. A delivery failure is logged but never "
                        "changes the process exit code")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.file):
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2
    base_url = args.url.rstrip("/")

    ci_meta = {} if args.no_ci_autodetect else detect_ci_metadata()
    ci_pipeline_url = args.ci_pipeline_url or ci_meta.get("ci_pipeline_url")
    ci_commit_sha = args.ci_commit_sha or ci_meta.get("ci_commit_sha")
    ci_triggered_by = args.ci_triggered_by or ci_meta.get("ci_triggered_by")

    try:
        print(f"Uploading {args.file} to {base_url} ...")
        scan_id = upload_scan(
            base_url, args.api_key, args.file,
            llm_enabled=args.llm_enabled, assessment_enabled=not args.no_assessment,
            timeout=120.0,
            ci_pipeline_url=ci_pipeline_url, ci_commit_sha=ci_commit_sha,
            ci_triggered_by=ci_triggered_by,
        )
        print(f"scan_id={scan_id}")
        print(f"View in the web UI: {base_url}/#/scan/{scan_id}")

        print("Waiting for the scan to finish ...")
        detail = poll_scan(base_url, args.api_key, scan_id, args.poll_interval, args.timeout)
        print(f"Scan finished in {detail.get('started_at')} -> {detail.get('finished_at')}")

        vulnerabilities = fetch_vulnerabilities(base_url, args.api_key, scan_id)
        active = active_findings(vulnerabilities)
        counts = severity_counts(active)
        fail = should_fail(active, args.fail_on)

        print(f"Findings (active, excluding false_positive/fixed): {len(active)} of {len(vulnerabilities)} total")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if counts.get(sev):
                print(f"  {sev}: {counts[sev]}")
        print(f"--fail-on {args.fail_on}: {'FAIL' if fail else 'PASS'}")

        if args.slack_webhook_url:
            payload = build_slack_payload(
                scan_id, f"{base_url}/#/scan/{scan_id}", os.path.basename(args.file),
                args.fail_on, fail, counts, len(active),
                ci_pipeline_url=ci_pipeline_url, ci_triggered_by=ci_triggered_by,
            )
            send_slack_notification(args.slack_webhook_url, payload)

        if args.json_out:
            summary = {
                "scan_id": scan_id,
                "scan_url": f"{base_url}/#/scan/{scan_id}",
                "fail_on": args.fail_on,
                "verdict": "fail" if fail else "pass",
                "total_findings": len(vulnerabilities),
                "active_findings": len(active),
                "severity_counts": counts,
            }
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
            print(f"Wrote summary to {args.json_out}")

        return 1 if fail else 0

    except MalimiteCiError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.exit_code


if __name__ == "__main__":
    sys.exit(main())
