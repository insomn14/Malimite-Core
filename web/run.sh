#!/usr/bin/env bash
# Starts the Mailmite Python web service.
# Usage: ./run.sh [--port 7070] [--scan-dir /tmp/mailmite-scans]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Install deps if needed
if ! python3 -c "import fastapi" &>/dev/null; then
  echo "Installing dependencies..."
  pip3 install -r requirements.txt
fi

exec python3 -m uvicorn app.main:app \
  --host "${HOST:-0.0.0.0}" \
  --port "${PORT:-7070}" \
  --reload \
  "$@"
