#!/usr/bin/env bash
# Copies host-side Anthropic OAuth material into ~/.malimite-docker/, the
# directory web-compose.yml mounts read-write into the web container at
# /home/malimite/.malimite. Two independent sources, sync whichever you have:
#
#   1. ~/.malimite/anthropic-oauth.json — Malimite's own token, written by
#      `java -jar cli/target/malimite-cli.jar claude-login` (the interactive
#      browser flow run directly against Malimite's own OAuth client).
#   2. ~/.claude/.credentials.json — the official `claude` CLI's session,
#      written by `claude /login`. Malimite's web UI ("Import from Claude Code
#      CLI" button) and `malimite claude-login --import` both read the synced
#      copy of this to reuse that login without running their own OAuth flow.
#
# Why a separate directory instead of mounting either source directly: the
# container's service runs as an unprivileged uid (10001) distinct from the
# host user's uid, and both source files are 0600 (correctly — they're bearer
# credentials) so the container can't read them as-is. Rather than loosening
# permissions on your real ~/.malimite or ~/.claude (which also hold other,
# unrelated files), this copies just the OAuth material into one small
# directory with permissions both sides can use — chmod 777 scoped to that
# directory alone, not to anything in your home directory's original locations.
#
# Run this:
#   - right after `java -jar cli/target/malimite-cli.jar claude-login`, and/or
#   - right after `claude /login`
#   - again any time either credential is refreshed/re-issued
#
# The container refreshes its own copy of (1) in place afterward (access
# tokens expire roughly hourly); you only need to re-run this script after a
# fresh *host-side* login, not on every restart. (2) is a one-shot import —
# the container doesn't write back to its copy of the Claude Code credential.
#
# After syncing (2), this ALSO calls the running web service's
# import-claude-code endpoint so the new token takes effect immediately —
# without this, syncing only refreshes claude-code-credentials.json; the file
# the service actually authenticates with (anthropic-oauth.json) stays
# whatever it was until something separately calls import. That gap bit in
# production twice: once because the import button was clicked before this
# script finished writing (a timing race), once because the script ran but
# nobody re-clicked import afterward at all (this one). Automating the import
# call here removes the second failure mode entirely; the web UI's "Import
# from Claude Code CLI" button is still there for when the container was
# down during sync, or for the first-ever sync before API_KEY exists.
set -euo pipefail

DEST_DIR="$HOME/.malimite-docker"
mkdir -p "$DEST_DIR"
chmod 777 "$DEST_DIR"   # must stay writable by the container's uid 10001, not just the host user

synced_anything=false

MALIMITE_SRC="$HOME/.malimite/anthropic-oauth.json"
if [ -f "$MALIMITE_SRC" ]; then
  install -m 666 "$MALIMITE_SRC" "$DEST_DIR/anthropic-oauth.json"
  echo "Synced $MALIMITE_SRC -> $DEST_DIR/anthropic-oauth.json"
  synced_anything=true
fi

CLAUDE_CODE_SRC="$HOME/.claude/.credentials.json"
if [ -f "$CLAUDE_CODE_SRC" ]; then
  install -m 644 "$CLAUDE_CODE_SRC" "$DEST_DIR/claude-code-credentials.json"
  echo "Synced $CLAUDE_CODE_SRC -> $DEST_DIR/claude-code-credentials.json"
  synced_anything=true
fi

if [ "$synced_anything" = false ]; then
  echo "error: neither $MALIMITE_SRC nor $CLAUDE_CODE_SRC exists." >&2
  echo "Run one of:" >&2
  echo "  java -jar cli/target/malimite-cli.jar claude-login   # Malimite's own OAuth login" >&2
  echo "  claude /login                                         # official Claude Code CLI login" >&2
  exit 1
fi

# ── Auto-import into the running web service, if we can ────────────────────
#
# Best-effort only: a missing .env, an unreachable service, or any HTTP
# failure here is NOT fatal — the sync above already succeeded, and the web
# UI's own "Import from Claude Code CLI" button remains available as a
# fallback (e.g. before the container's first start, when API_KEY doesn't
# exist in deploy/.env yet).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/deploy/.env"
WEB_URL="${MALIMITE_WEB_URL:-http://127.0.0.1:7070}"

if [ -f "$CLAUDE_CODE_SRC" ] && [ -f "$ENV_FILE" ]; then
  API_KEY="$(grep -m1 '^API_KEY=' "$ENV_FILE" | cut -d= -f2-)"
  if [ -n "$API_KEY" ]; then
    response="$(curl -fsS -m 10 -X POST -H "X-Api-Key: $API_KEY" \
      "$WEB_URL/api/v1/auth/claude-oauth/import-claude-code" 2>&1)" \
      && import_ok=true || import_ok=false
    if [ "$import_ok" = true ]; then
      if printf '%s' "$response" | grep -q '"changed":true'; then
        echo "Imported into the running web service — new token now active."
      else
        echo "Web service already had this exact token (no change needed)."
      fi
    else
      echo "note: could not reach the web service to auto-import ($WEB_URL) — is the container up?" >&2
      echo "      The sync above still succeeded; use the web UI's \"Import from Claude Code CLI\"" >&2
      echo "      button once the container is running, or re-run this script then." >&2
    fi
  fi
fi
