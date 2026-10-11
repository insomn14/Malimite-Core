#!/bin/sh
# Start as root only long enough to hand the (possibly root-owned, pre-existing) scan volume to the
# unprivileged service user, then drop privileges for the real process.
set -e
UID_SVC=10001
DIR="${SCAN_DIR:-/var/malimite/scans}"
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DIR"
  [ "$(stat -c %u "$DIR")" = "$UID_SVC" ] || chown -R "$UID_SVC:$UID_SVC" "$DIR"
  exec setpriv --reuid="$UID_SVC" --regid="$UID_SVC" --clear-groups "$@"
fi
exec "$@"
