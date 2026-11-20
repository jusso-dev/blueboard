#!/usr/bin/env bash
# One-command local demo: a board, a mock Microsoft tenant with three incidents, and a scripted agent.
# Needs only Docker (Compose v2). No Azure account, Entra app or model key. See docs/DEMO.md.
#
#   ./scripts/demo.sh up       build, start, wait for health, print the URL
#   ./scripts/demo.sh logs     follow the board and agent logs
#   ./scripts/demo.sh down     stop and remove everything, including the database volume
#
# Uses your current Docker context. To pick another: DOCKER_CONTEXT=<name> ./scripts/demo.sh up
set -euo pipefail

cd "$(dirname "$0")/.."
compose=(docker compose -f docker-compose.demo.yml)
web=http://localhost:3417
api=http://localhost:7370

die() { echo "demo: $*" >&2; exit 1; }

wait_for() {
  local url="$1" what="$2" tries="${3:-120}"
  local i=0
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    i=$((i + 1))
    [[ $i -ge $tries ]] && die "$what did not become ready at $url (see: ${compose[*]} logs)"
    sleep 2
  done
}

case "${1:-up}" in
  up)
    command -v docker >/dev/null || die "Docker is required"
    docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose)"
    command -v curl >/dev/null || die "curl is required"
    echo "Building and starting the demo (first run downloads images and takes a few minutes)..."
    "${compose[@]}" up -d --build
    echo "Waiting for the board API..."
    wait_for "$api/api/healthz" "the board API"
    echo "Waiting for the web app..."
    wait_for "$web/healthz" "the web app"
    echo
    echo "blueboard demo is running. Microsoft APIs are mocked; approved actions are dry runs."
    echo "  Open:  $web/dev-login   (sign in as 'SOC Analyst (dev)' to approve)"
    echo "  MCP:   $api/runtime/webhooks/mcp   (Authorization: Bearer dev:my-agent)"
    echo "  Stop:  ./scripts/demo.sh down"
    ;;
  logs) "${compose[@]}" logs -f api agent ;;
  down) "${compose[@]}" down -v ;;
  *) die "usage: $0 up | logs | down" ;;
esac
