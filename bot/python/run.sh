#!/usr/bin/env bash
# Run the Malimite Slack bot.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if ! python3 -c "import slack_bolt" &>/dev/null; then
  echo "Installing dependencies…"
  pip3 install --user -r requirements.txt
fi

exec python3 slack_bot.py
