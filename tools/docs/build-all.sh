#!/usr/bin/env bash
# Rebuilds every blueboard PDF and editable Word deliverable (walkthroughs, deployment guide,
# administrator SOPs, developer guide, security controls, and solution design document).
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
python3 tools/docs/build-guides.py "$@"
python3 tools/docs/build-admin-docs.py
