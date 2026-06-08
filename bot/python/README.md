# Mailmite — Slack Bot (standalone)

Run Mailmite from Slack with **no web service required**.

- Listens via **Socket Mode** — bot connects outbound to Slack over WebSocket, so you don't need a public HTTPS endpoint, ngrok, or a reverse proxy.
- Uploads an `.ipa` in DM or a channel where the bot is invited → bot replies in a thread with a severity-sorted summary, top findings, plus the full HTML report and SARIF as attachments.
- No FastAPI, no Redis, no MinIO. One Python process + the existing Mailmite CLI JAR.

---

## 1. Create the Slack App (one-time, ~3 minutes)

1. Go to https://api.slack.com/apps → **Create New App** → *From scratch*.
   Give it a name like "Mailmite" and pick your workspace.

2. **Enable Socket Mode**
   *Sidebar → Socket Mode* → toggle **Enable Socket Mode** ON.
   Slack will prompt you to create an **app-level token**. Give it a name (e.g. `socket-mode`) and the scope `connections:write`. Save the `xapp-…` token — this becomes `SLACK_APP_TOKEN`.

3. **Add OAuth Bot scopes**
   *Sidebar → OAuth & Permissions → Scopes → Bot Token Scopes*. Add these:
   - `chat:write` — post messages
   - `files:read` — download uploaded IPAs
   - `files:write` — upload report.html / findings.sarif back to Slack
   - `channels:history` *(optional, for channel uploads)*
   - `im:history` *(for DM uploads)*
   - `app_mentions:read` *(so users can `@mailmite help`)*

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

## 2. Configure the bot host

```bash
cd /home/vagrant/Tools/RE/Mailmite-Core/bot/python
cp .env.example .env
$EDITOR .env       # paste xapp- and xoxb- tokens, set Ghidra path
```

Required:
- `SLACK_APP_TOKEN` = the `xapp-…` from step 2
- `SLACK_BOT_TOKEN` = the `xoxb-…` from step 5
- `GHIDRA_HOME` = where Ghidra is installed (default `/usr/share/ghidra`)
- `MAILMITE_CLI_JAR` = path to the built fat JAR (default `../../cli/target/mailmite-cli.jar`)

Optional LLM enrichment:
- `LLM_PROVIDER=deepseek` + `DEEPSEEK_API_KEY=sk-…` (models: `deepseek-v4-flash`, `deepseek-v4-pro`, `deepseek-chat`, `deepseek-reasoner`)
- `LLM_PROVIDER=claude` + `ANTHROPIC_API_KEY=sk-ant-…`, or
- `LLM_PROVIDER=openai` + `OPENAI_API_KEY=sk-…`, or
- `LLM_PROVIDER=ollama` (local — set `OLLAMA_BASE_URL` if not localhost)

---

## 3. Build the CLI JAR (if you haven't yet)

```bash
cd /home/vagrant/Tools/RE/Mailmite-Core
mvn package -DskipTests -pl core,cli
# Produces cli/target/mailmite-cli.jar
```

---

## 4. Start the bot

```bash
cd bot/python
./run.sh
```

You should see:
```
INFO mailmite.slack: Mailmite Slack bot starting (Socket Mode) — CLI=…/mailmite-cli.jar
INFO slack_bolt.AsyncApp: A new session has been established
```

---

## 5. Use it

In any DM with the bot, or in a channel where you've invited it:

| What you do | What the bot does |
|---|---|
| Drop an `.ipa` file | :hourglass_flowing_sand: queues + scans + replies in thread |
| `mailmite help` | shows usage |
| `mailmite version` | shows CLI/Ghidra/LLM config |
| `@mailmite` mention | shows help |

The bot replies in a **thread** off the original upload, so the channel stays clean.

---

## 6. As a systemd service (optional)

```ini
# /etc/systemd/system/mailmite-slack.service
[Unit]
Description=Mailmite Slack Bot
After=network-online.target

[Service]
Type=simple
User=mailmite
WorkingDirectory=/opt/mailmite/bot/python
EnvironmentFile=/opt/mailmite/bot/python/.env
ExecStart=/usr/bin/python3 /opt/mailmite/bot/python/slack_bot.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mailmite-slack
sudo journalctl -fu mailmite-slack
```

---

## Architecture diagram

```
┌──────────┐   WebSocket (Socket Mode)    ┌────────────────────┐
│  Slack   │ ◀────────────────────────────│ slack_bot.py       │
│  Cloud   │                              │  (Python + Bolt)   │
└──────────┘                              └──┬─────────────────┘
                                             │ subprocess
                                             ▼
                                          ┌────────────────────┐
                                          │ mailmite-cli.jar   │
                                          │  → analyzeHeadless │
                                          │  → MSTG scanner    │
                                          │  → optional LLM    │
                                          │  → report.html,    │
                                          │    findings.sarif  │
                                          └────────────────────┘
```

- Bot host needs outbound HTTPS to Slack (port 443) and to LLM provider if enabled.
- No inbound traffic. Bot is invisible to the internet.
- All scan artifacts stay on the bot host under `SCAN_ROOT`.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `"socket_mode_request_failed"` on startup | `SLACK_APP_TOKEN` wrong scope — must have `connections:write` |
| Bot sees file but never starts a scan | `file_shared` event not subscribed, or bot not in the channel |
| `not_in_channel` when uploading reports | Bot needs to be invited to the channel (`/invite @mailmite`) |
| `file_upload_failed` | Missing `files:write` bot scope |
| Scan hangs > 10 min | Check `analysis.log` under `SCAN_ROOT/<scan_id>/` — usually Ghidra issue |
| LLM ignored | `LLM_PROVIDER` is `none`, or API key env var missing |
