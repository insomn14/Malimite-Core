#!/usr/bin/env bash
# Malimite-Core Web — helper to build/start/stop/logs the web service.
# Runs the web on port 7070 (free; does not collide with 8000/8080).
#
# Usage:
#   ./web-docker.sh up       # build + start daemon on 7070
#   ./web-docker.sh build    # build image only
#   ./web-docker.sh down     # stop container (keep volume)
#   ./web-docker.sh logs     # tail logs
#   ./web-docker.sh port     # show published port
set -euo pipefail

COMPOSE="docker compose -f deploy/web-compose.yml"
IMG="malimite-web:latest"

case "${1:-up}" in
  up)
    "$COMPOSE" up -d
    echo
    echo "Malimite Web running → http://localhost:7070  (API docs: http://localhost:7070/docs)"
    ;;
  build)
    docker build -f deploy/web.Dockerfile -t "$IMG" .
    ;;
  down)
    "$COMPOSE" down
    ;;
  logs)
    "$COMPOSE" logs -f
    ;;
  port)
    docker port malimite-web
    ;;
  *)
    echo "usage: $0 {up|build|down|logs|port}" >&2
    exit 2
    ;;
esac
