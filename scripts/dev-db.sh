#!/usr/bin/env bash
# Local PostgreSQL + Azurite for development, on the Docker context you name (default: current).
#   DOCKER_CONTEXT=orbstack ./scripts/dev-db.sh up | down
set -euo pipefail
ctx=(--context "${DOCKER_CONTEXT:-$(docker context show)}")
case "${1:-up}" in
  up)
    docker "${ctx[@]}" run -d --name blueboard-dev-pg -e POSTGRES_PASSWORD=devpass -e POSTGRES_DB=blueboard \
      -p 127.0.0.1:55432:5432 postgres:16-alpine >/dev/null 2>&1 || docker "${ctx[@]}" start blueboard-dev-pg >/dev/null
    docker "${ctx[@]}" run -d --name blueboard-azurite -p 127.0.0.1:20000:10000 -p 127.0.0.1:20001:10001 -p 127.0.0.1:20002:10002 \
      mcr.microsoft.com/azure-storage/azurite azurite --blobHost 0.0.0.0 --queueHost 0.0.0.0 --tableHost 0.0.0.0 --skipApiVersionCheck >/dev/null 2>&1 ||
      docker "${ctx[@]}" start blueboard-azurite >/dev/null
    echo "PostgreSQL 127.0.0.1:55432 · Azurite 127.0.0.1:20000-20002 (context ${ctx[1]})"
    ;;
  down) docker "${ctx[@]}" rm -f blueboard-dev-pg blueboard-azurite >/dev/null && echo removed ;;
  *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
