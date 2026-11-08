"""
Malimite — standalone Slack bot.

Listens via Socket Mode (no public endpoint required), accepts `.ipa`/`.apk`/`.xapk` uploads in a
DM or a channel it's been invited to, asks a running Malimite web server to scan the file, and
posts the results back as Slack messages (summary, top findings, HTML report + SARIF attached).

The bot does NOT run the scanner itself: it calls the same `POST /api/v1/scans` the Web UI uses,
so every scan it starts also appears in the Web UI for triage / AI Fix / Auto Enhance, and the
bot host needs no Ghidra/JADX install.

ENV vars (see .env.example):
  SLACK_APP_TOKEN        xapp-... (Socket Mode token)
  SLACK_BOT_TOKEN        xoxb-... (OAuth bot token)
  MALIMITE_URL           base URL of the malimite-web server (required), e.g. http://malimite:7070
  MALIMITE_API_KEY       server API key, if the server has API_KEY configured
  ALLOWED_SLACK_CHANNELS comma-separated channel IDs allowed to start scans (default: any channel
                         the bot is in). Strongly recommended in a shared workspace: any member of
                         an allowed channel can spend this server's scan capacity.
  LLM_ENABLED            true|false — ask the server for LLM enrichment (default: false)
  MAX_IPA_MB             reject uploads larger than this many MB (default: 300)
  TOP_FINDINGS           how many findings to render in the thread (default: 5)
  SCAN_TIMEOUT_S         give up waiting for the scan after this many seconds (default: 1800)
  POLL_INTERVAL_S        seconds between status polls (default: 5)
"""
import asyncio
import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler
from slack_sdk.errors import SlackApiError

from api_client import ApiError, MalimiteApi, run_scan
import slack_format as fmt

# ── config ───────────────────────────────────────────────────────────────────

load_dotenv(Path(__file__).parent / ".env")

SLACK_APP_TOKEN  = os.environ.get("SLACK_APP_TOKEN")
SLACK_BOT_TOKEN  = os.environ.get("SLACK_BOT_TOKEN")
MALIMITE_URL     = os.environ.get("MALIMITE_URL", "").rstrip("/")
MALIMITE_API_KEY = os.environ.get("MALIMITE_API_KEY", "")

LLM_ENABLED   = os.environ.get("LLM_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")
MAX_IPA_BYTES = int(os.environ.get("MAX_IPA_MB", "300")) * 1024 * 1024
TOP_FINDINGS  = int(os.environ.get("TOP_FINDINGS", "5"))
SCAN_TIMEOUT  = float(os.environ.get("SCAN_TIMEOUT_S", "1800"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL_S", "5"))

ALLOWED_CHANNELS = {
    c.strip() for c in os.environ.get("ALLOWED_SLACK_CHANNELS", "").split(",") if c.strip()
}

if not SLACK_APP_TOKEN or not SLACK_BOT_TOKEN:
    print("ERROR: SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set", file=sys.stderr)
    sys.exit(2)
if not MALIMITE_URL:
    print("ERROR: MALIMITE_URL must be set (base URL of the malimite-web server)", file=sys.stderr)
    sys.exit(2)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("malimite.slack")

app = AsyncApp(token=SLACK_BOT_TOKEN)
api = MalimiteApi(MALIMITE_URL, MALIMITE_API_KEY)

# Avoid double-handling the same upload — Slack may deliver the event twice
_handled_files: set[str] = set()


# ── helpers ──────────────────────────────────────────────────────────────────

def _channel_allowed(channel: str) -> bool:
    """No allowlist configured means every channel the bot is in may start scans."""
    return not ALLOWED_CHANNELS or channel in ALLOWED_CHANNELS


async def _download_file(client, url_private: str) -> bytes:
    """Use the bot token to fetch the file bytes from Slack's CDN."""
    import httpx
    async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0)) as s:
        resp = await s.get(url_private, headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"})
        resp.raise_for_status()
        return resp.content


async def _process_upload(client, channel: str, thread_ts: str, file_info: dict) -> None:
    """End-to-end: download → scan on the server → post results to the same thread."""
    fname = file_info.get("name") or "upload.apk"
    size  = file_info.get("size") or 0

    if not _channel_allowed(channel):
        log.warning("Rejected upload from non-allowed channel %s", channel)
        await client.chat_postMessage(
            channel=channel, thread_ts=thread_ts,
            text=":no_entry_sign: This channel isn't allowed to start Malimite scans.")
        return

    if size > MAX_IPA_BYTES:
        await client.chat_postMessage(
            channel=channel, thread_ts=thread_ts,
            text=f":x: File too large: {size/1024/1024:.1f} MB exceeds {MAX_IPA_BYTES/1024/1024:.0f} MB limit.")
        return

    queued_msg = await client.chat_postMessage(
        channel=channel, thread_ts=thread_ts,
        text=f":hourglass_flowing_sand: Scan queued — {fname}",
        blocks=fmt.queued(fname),
    )

    started = asyncio.get_running_loop().time()

    async def _on_poll() -> None:
        """Keep the queued message honest instead of posting a new one every minute."""
        elapsed = int(asyncio.get_running_loop().time() - started)
        try:
            await client.chat_update(
                channel=channel, ts=queued_msg["ts"],
                blocks=fmt.progress(fname, elapsed),
                text=f"Still scanning {fname}…")
        except SlackApiError:
            pass  # message may have been deleted/edited by a user

    try:
        data = await _download_file(client, file_info["url_private"])
        log.info("Downloaded %s (%d bytes), submitting to %s", fname, len(data), MALIMITE_URL)
        result = await run_scan(
            api, data, fname,
            llm_enabled=LLM_ENABLED,
            poll_interval=POLL_INTERVAL,
            overall_timeout=SCAN_TIMEOUT,
            progress=_on_poll,
        )
    except (ApiError, Exception) as e:      # noqa: B014 - explicit: any failure must reach the user
        log.exception("Scan failed")
        await client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                                      blocks=fmt.failure(fname, str(e)))
        return

    if not result["ok"]:
        await client.chat_postMessage(
            channel=channel, thread_ts=thread_ts,
            blocks=fmt.failure(fname, "The server reported this scan as failed; "
                                     "check its analysis log for details."))
        return

    # Compose results into the thread
    await client.chat_postMessage(
        channel=channel, thread_ts=thread_ts,
        blocks=fmt.summary(fname, result),
        text=f"Scan complete: {fname}",
    )

    top = fmt.top_findings(result["vulnerabilities"], limit=TOP_FINDINGS)
    if top:
        await client.chat_postMessage(channel=channel, thread_ts=thread_ts,
                                      blocks=top, text="Top findings")

    # Attach the artifacts (HTML report + SARIF) to the thread. Fetched from the server rather
    # than read off local disk, because the scan lives on the server now.
    for kind, filename, title in [
        ("report", f"{Path(fname).stem}-report.html", f"{fname} — HTML report"),
        ("sarif",  f"{Path(fname).stem}-findings.sarif", f"{fname} — SARIF 2.1"),
    ]:
        try:
            blob = await api.artifact(result["scan_id"], kind)
        except ApiError as e:
            log.warning("Could not fetch %s artifact: %s", kind, e)
            continue
        if not blob:
            continue
        try:
            await client.files_upload_v2(
                channel=channel,
                thread_ts=thread_ts,
                content=blob,
                filename=filename,
                title=title,
                initial_comment=None,
            )
        except SlackApiError as e:
            log.warning("Could not upload %s: %s", kind, e.response.get("error"))


# ── event handlers ───────────────────────────────────────────────────────────

@app.event("file_shared")
async def on_file_shared(event, client):
    """Fired whenever any file is shared — we filter for .ipa/.apk/.xapk."""
    file_id = event.get("file_id") or event.get("file", {}).get("id")
    channel = event.get("channel_id") or event.get("channel")
    if not file_id or file_id in _handled_files:
        return
    _handled_files.add(file_id)

    info = await client.files_info(file=file_id)
    f = info["file"]
    name = (f.get("name") or "").lower()
    if not name.endswith((".ipa", ".apk", ".xapk")):
        return  # ignore other uploads silently

    # Thread the reply off the original file's message timestamp if available
    thread_ts = f.get("timestamp")
    if isinstance(thread_ts, (int, float)):
        thread_ts = f"{thread_ts:.6f}"

    log.info("Upload detected: %s in channel %s", name, channel)
    await _process_upload(client, channel, thread_ts, f)


@app.message(re.compile(r"^malimite\s+help\b", re.IGNORECASE))
async def on_help(message, say):
    await say(blocks=fmt.help_message(), thread_ts=message.get("ts"))


@app.message(re.compile(r"^malimite\s+version\b", re.IGNORECASE))
async def on_version(message, say):
    await say(text=f"Malimite bot · server: `{MALIMITE_URL}` · "
                   f"LLM enrichment: `{'on' if LLM_ENABLED else 'off'}` · "
                   f"channels: `{'restricted' if ALLOWED_CHANNELS else 'any'}`",
               thread_ts=message.get("ts"))


@app.event("message")
async def on_message_noop(message, logger):
    # Required to avoid "unhandled event" warnings in Bolt
    pass


@app.event("app_mention")
async def on_mention(event, say, client):
    await say(blocks=fmt.help_message(), thread_ts=event.get("ts"))


# ── entry point ──────────────────────────────────────────────────────────────

async def main():
    handler = AsyncSocketModeHandler(app, SLACK_APP_TOKEN)
    log.info("Malimite Slack bot starting (Socket Mode) — server=%s", MALIMITE_URL)
    await handler.start_async()


if __name__ == "__main__":
    asyncio.run(main())
