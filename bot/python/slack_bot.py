"""
Mailmite — standalone Slack bot.

Listens via Socket Mode (no public endpoint required), accepts .ipa file
uploads in DM or channels where it's a member, runs Mailmite CLI as a
subprocess, then posts results back as Slack messages with the HTML report
and SARIF file attached.

ENV vars (see .env.example):
  SLACK_APP_TOKEN    xapp-... (Socket Mode token)
  SLACK_BOT_TOKEN    xoxb-... (OAuth bot token)
  MAILMITE_CLI_JAR   path to mailmite-cli.jar
  GHIDRA_HOME        path to Ghidra install (e.g. /usr/share/ghidra)
  SCAN_ROOT          where to store scan outputs (default: /tmp/mailmite-slack)
  LLM_PROVIDER       none|openai|claude|deepseek|ollama   (default: none)
  LLM_MODE           summarize|find_vulns|auto_fix
  LLM_MODEL          override (optional)
  OPENAI_API_KEY     (if LLM_PROVIDER=openai)
  ANTHROPIC_API_KEY  (if LLM_PROVIDER=claude)
  DEEPSEEK_API_KEY   (if LLM_PROVIDER=deepseek)
  DEEPSEEK_BASE_URL  (default https://api.deepseek.com)
  OLLAMA_BASE_URL    (default http://localhost:11434)
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

from scan_runner import ScanRunner
import slack_format as fmt

# ── config ───────────────────────────────────────────────────────────────────

load_dotenv(Path(__file__).parent / ".env")

SLACK_APP_TOKEN    = os.environ.get("SLACK_APP_TOKEN")
SLACK_BOT_TOKEN    = os.environ.get("SLACK_BOT_TOKEN")
MAILMITE_CLI_JAR   = os.environ.get(
    "MAILMITE_CLI_JAR",
    str(Path(__file__).resolve().parent.parent.parent / "cli/target/mailmite-cli.jar"))
GHIDRA_HOME        = os.environ.get("GHIDRA_HOME", "/usr/share/ghidra")
SCAN_ROOT          = os.environ.get("SCAN_ROOT", "/tmp/mailmite-slack")

LLM_PROVIDER       = os.environ.get("LLM_PROVIDER", "none")
LLM_MODE           = os.environ.get("LLM_MODE", "summarize")
LLM_MODEL          = os.environ.get("LLM_MODEL", "")
OPENAI_API_KEY     = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")
DEEPSEEK_API_KEY   = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL  = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
OLLAMA_BASE_URL    = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

MAX_IPA_BYTES      = int(os.environ.get("MAX_IPA_MB", "300")) * 1024 * 1024
TOP_FINDINGS       = int(os.environ.get("TOP_FINDINGS", "5"))

if not SLACK_APP_TOKEN or not SLACK_BOT_TOKEN:
    print("ERROR: SLACK_APP_TOKEN and SLACK_BOT_TOKEN must be set", file=sys.stderr)
    sys.exit(2)
if not Path(MAILMITE_CLI_JAR).exists():
    print(f"ERROR: MAILMITE_CLI_JAR not found: {MAILMITE_CLI_JAR}", file=sys.stderr)
    sys.exit(2)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("mailmite.slack")

app    = AsyncApp(token=SLACK_BOT_TOKEN)
runner = ScanRunner(
    cli_jar=MAILMITE_CLI_JAR,
    ghidra_home=GHIDRA_HOME,
    scan_root=SCAN_ROOT,
    llm_provider=LLM_PROVIDER,
    llm_mode=LLM_MODE,
    llm_model=LLM_MODEL,
    openai_api_key=OPENAI_API_KEY,
    anthropic_api_key=ANTHROPIC_API_KEY,
    deepseek_api_key=DEEPSEEK_API_KEY,
    deepseek_base_url=DEEPSEEK_BASE_URL,
    ollama_base_url=OLLAMA_BASE_URL,
)

# Avoid double-handling the same upload — Slack may deliver the event twice
_handled_files: set[str] = set()


# ── helpers ──────────────────────────────────────────────────────────────────

async def _download_file(client, url_private: str) -> bytes:
    """Use the bot token to fetch the file bytes from Slack's CDN."""
    import aiohttp
    async with aiohttp.ClientSession(headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}) as s:
        async with s.get(url_private) as r:
            r.raise_for_status()
            return await r.read()


async def _process_ipa(client, channel: str, thread_ts: str, file_info: dict) -> None:
    """End-to-end: download → scan → post results to the same thread."""
    fname = file_info.get("name") or "upload.ipa"
    size  = file_info.get("size") or 0

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

    # Periodic "still working" pings
    progress_task = asyncio.create_task(
        _progress_pings(client, channel, queued_msg["ts"], fname))

    try:
        ipa_bytes = await _download_file(client, file_info["url_private"])
        log.info("Downloaded %s (%d bytes), running CLI", fname, len(ipa_bytes))
        result = await runner.run(ipa_bytes, fname)
    except Exception as e:
        progress_task.cancel()
        log.exception("Scan failed")
        await client.chat_postMessage(channel=channel, thread_ts=thread_ts,
            blocks=fmt.failure(fname, str(e)))
        return

    progress_task.cancel()

    if not result["ok"]:
        # Surface last lines of the log
        log_text = result["log"].read_text(errors="replace") if result.get("log") else ""
        tail = "\n".join(log_text.strip().splitlines()[-10:])
        await client.chat_postMessage(channel=channel, thread_ts=thread_ts,
            blocks=fmt.failure(fname, tail))
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

    # Attach the artifacts (HTML report + SARIF) to the thread
    for label, path, title in [
        ("html-report", result.get("report_html"), f"{fname} — HTML report"),
        ("sarif",       result.get("sarif"),       f"{fname} — SARIF 2.1"),
    ]:
        if path and Path(path).exists():
            try:
                await client.files_upload_v2(
                    channel=channel,
                    thread_ts=thread_ts,
                    file=str(path),
                    title=title,
                    initial_comment=None,
                )
            except SlackApiError as e:
                log.warning("Could not upload %s: %s", label, e.response.get("error"))


async def _progress_pings(client, channel: str, queued_ts: str, fname: str) -> None:
    """Update the 'queued' message every 60s while the scan runs."""
    started = asyncio.get_running_loop().time()
    try:
        while True:
            await asyncio.sleep(60)
            elapsed = int(asyncio.get_running_loop().time() - started)
            try:
                await client.chat_update(
                    channel=channel, ts=queued_ts,
                    blocks=fmt.progress(fname, elapsed),
                    text=f"Still scanning {fname}…")
            except SlackApiError:
                pass  # message may have been replaced
    except asyncio.CancelledError:
        pass


# ── event handlers ───────────────────────────────────────────────────────────

@app.event("file_shared")
async def on_file_shared(event, client):
    """Fired whenever any file is shared — we filter for .ipa."""
    file_id = event.get("file_id") or event.get("file", {}).get("id")
    channel = event.get("channel_id") or event.get("channel")
    if not file_id or file_id in _handled_files:
        return
    _handled_files.add(file_id)

    info = await client.files_info(file=file_id)
    f = info["file"]
    name = (f.get("name") or "").lower()
    if not name.endswith(".ipa"):
        return  # ignore non-IPA uploads silently

    # Thread the reply off the original file's message timestamp if available
    thread_ts = f.get("timestamp")
    if isinstance(thread_ts, (int, float)):
        thread_ts = f"{thread_ts:.6f}"

    log.info("IPA upload detected: %s in channel %s", name, channel)
    await _process_ipa(client, channel, thread_ts, f)


@app.message(re.compile(r"^mailmite\s+help\b", re.IGNORECASE))
async def on_help(message, say):
    await say(blocks=fmt.help_message(), thread_ts=message.get("ts"))


@app.message(re.compile(r"^mailmite\s+version\b", re.IGNORECASE))
async def on_version(message, say):
    await say(text=f"Mailmite CLI: `{Path(MAILMITE_CLI_JAR).name}` · "
                   f"LLM provider: `{LLM_PROVIDER}` · Ghidra: `{GHIDRA_HOME}`",
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
    log.info("Mailmite Slack bot starting (Socket Mode) — CLI=%s", MAILMITE_CLI_JAR)
    await handler.start_async()


if __name__ == "__main__":
    asyncio.run(main())
