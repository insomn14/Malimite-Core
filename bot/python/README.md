# Malimite — Slack Bot

Run Malimite from Slack. The bot is a thin client: it sends the uploaded file to a running
**malimite-web** server and posts the results back into the Slack thread.

- Listens via **Socket Mode** — the bot connects outbound to Slack over WebSocket, so you don't
  need a public HTTPS endpoint, ngrok, or a reverse proxy.
- Drop an `.ipa` / `.apk` / `.xapk` in a DM or a channel where the bot is invited → it asks the
  server to scan the file and replies in a thread with a severity summary, the top findings, and
  the full HTML report + SARIF as attachments.
- **The bot does not scan locally.** It calls the same `POST /api/v1/scans` the web UI uses, so
  every scan it starts also shows up in the web UI for triage / AI Fix / Auto Enhance afterwards,
  and the bot host needs no Ghidra/JADX install — just Python.

> Looking for one-way notifications instead (a text alert when a scan finds something serious,
> with no interaction at all)? That is built into the server itself — set `SLACK_WEBHOOK_URL` in
> `web/.env` and see [`web/app/notify.py`](../../web/app/notify.py). It covers **every** scan,
> including uploads from the web UI and the watcher, not just Slack ones.

---

## 1. Create the Slack App (one-time, ~3 minutes)

1. Go to https://api.slack.com/apps → **Create New App** → *From scratch*.
   Give it a name like "Malimite" and pick your workspace.

2. **Enable Socket Mode**
   *Sidebar → Socket Mode* → toggle **Enable Socket Mode** ON.
   Slack will prompt you to create an **app-level token**. Give it a name (e.g. `socket-mode`) and
   the scope `connections:write`. Save the `xapp-…` token — this becomes `SLACK_APP_TOKEN`.

3. **Add OAuth Bot scopes**
   *Sidebar → OAuth & Permissions → Scopes → Bot Token Scopes*. Add these:
   - `chat:write` — post messages
   - `files:read` — download the uploaded app package
   - `files:write` — upload report.html / findings.sarif back to Slack
   - `channels:history` *(optional, for channel uploads)*
   - `im:history` *(for DM uploads)*
   - `app_mentions:read` *(so users can `@malimite help`)*

4. **Subscribe to events**
   *Sidebar → Event Subscriptions* → toggle ON.
   Under **Subscribe to bot events**, add:
   - `file_shared` — the main trigger
   - `app_mention`
   - `message.im` *(DM uploads)*
   - `message.channels` *(uploads in invited channels)*

5. **Install the app**
   *Sidebar → Install App → Install to Workspace*. Approve.
   Copy the **Bot User OAuth Token** (`xoxb-…`) — this becomes `SLACK_BOT_TOKEN`.

---

## 2. Prerequisites

You need a reachable **malimite-web** server. See
[`deploy/EC2_DEPLOYMENT.md`](../../deploy/EC2_DEPLOYMENT.md) for standing one up (or run
`python -m uvicorn app.main:app` locally from `web/`).

The bot host only needs Python 3.9+ and outbound HTTPS to Slack and to that server.

---

## 3. Configure the bot

```bash
cd bot/python
cp .env.example .env
$EDITOR .env
```

Required:
- `SLACK_APP_TOKEN` — the `xapp-…` from step 2
- `SLACK_BOT_TOKEN` — the `xoxb-…` from step 5
- `MALIMITE_URL` — base URL of the server, e.g. `http://malimite.internal:7070`
- `MALIMITE_API_KEY` — the server's `API_KEY`, if it has one set (otherwise requests get 401)

Recommended in a shared workspace:
- `ALLOWED_SLACK_CHANNELS` — comma-separated channel IDs allowed to start scans. Without it, any
  channel the bot is invited to can start scans (and spend the server's capacity / LLM quota).

Optional:
- `LLM_ENABLED=true` — ask the server for LLM enrichment (slower, costs its LLM quota). The
  provider and key are configured on the **server** (`web/.env`), not here.
- `MAX_IPA_MB`, `TOP_FINDINGS`, `SCAN_TIMEOUT_S`, `POLL_INTERVAL_S` — tuning knobs, see
  [`.env.example`](.env.example).

Install and start:

```bash
cd bot/python
pip install -r requirements.txt
./run.sh
```

You should see:
```
INFO malimite.slack: Malimite Slack bot starting (Socket Mode) — server=http://malimite.internal:7070
INFO slack_bolt.AsyncApp: A new session has been established
```

---

## 4. Use it

In any DM with the bot, or in a channel where you've invited it:

| What you do | What the bot does |
|---|---|
| Drop an `.ipa` / `.apk` / `.xapk` | :hourglass_flowing_sand: queues on the server, then replies in the thread |
| `malimite help` | shows usage |
| `malimite version` | shows which server this bot talks to, and its settings |
| `@malimite` mention | shows help |

The bot replies in a **thread** off the original upload, so the channel stays clean.

---

## 5. As a systemd service (optional)

```ini
# /etc/systemd/system/malimite-slack.service
[Unit]
Description=Malimite Slack Bot
After=network-online.target

[Service]
Type=simple
User=malimite
WorkingDirectory=/opt/malimite/bot/python
EnvironmentFile=/opt/malimite/bot/python/.env
ExecStart=/usr/bin/python3 /opt/malimite/bot/python/slack_bot.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now malimite-slack
sudo journalctl -fu malimite-slack
```

---

## Architecture

```
┌──────────┐   WebSocket (Socket Mode)    ┌────────────────────┐
│  Slack   │ ◀────────────────────────────│ slack_bot.py       │
│  Cloud   │                              │  (Python + Bolt)   │
└──────────┘                              └──┬─────────────────┘
                                             │ HTTP: POST /api/v1/scans,
                                             │       GET  /scans/{id},
                                             │       GET  /vulnerabilities, /report, /sarif
                                             ▼
                                          ┌────────────────────────────┐
                                          │ malimite-web (FastAPI)     │
                                          │  → malimite-cli.jar        │
                                          │  → Ghidra / JADX           │
                                          │  → report.html, SARIF      │
                                          │  → same scan shown in the  │
                                          │    web UI for triage       │
                                          └────────────────────────────┘
```

- Bot host needs outbound HTTPS to Slack (443) and to the Malimite server only. No inbound traffic.
- Scan artifacts live on the **server** (under its `SCAN_DIR`), not on the bot host.
- `api_client.py` is the whole server interface — it has unit tests that mock HTTP, so no server or
  Slack workspace is required to run them: `python -m unittest discover bot/python -p "test_*.py"`.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ERROR: MALIMITE_URL must be set` on start | `.env` missing `MALIMITE_URL` |
| Bot replies "scan failed" with HTTP 401 | `MALIMITE_API_KEY` missing/wrong for a server that has `API_KEY` set |
| `"socket_mode_request_failed"` on startup | `SLACK_APP_TOKEN` wrong scope — must have `connections:write` |
| Bot sees the file but never starts a scan | `file_shared` event not subscribed, or bot not in the channel |
| ":no_entry_sign: This channel isn't allowed…" | `ALLOWED_SLACK_CHANNELS` is set and this channel isn't in it |
| `not_in_channel` when uploading reports | Bot needs to be invited to the channel (`/invite @malimite`) |
| `file_upload_failed` | Missing `files:write` bot scope |
| Scan appears stuck | The scan runs on the server — check its log at `SCAN_DIR/<scan_id>/analysis.log` |
| LLM ignored | `LLM_ENABLED` is false here, or the **server** has no provider/API key configured |
