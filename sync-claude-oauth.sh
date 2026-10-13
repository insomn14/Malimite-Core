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
