#!/usr/bin/env bash
# End-to-end publisher for blueboard's Azure architecture diagram and complete PDF/Word
# documentation suite, followed by automated integrity and link verification.
#
# Usage:
#   ./tools/docs/publish-all.sh                 # rebuild diagram + all PDF/DOCX + verify
#   ./tools/docs/publish-all.sh --skip-diagram  # rebuild PDF/DOCX only (offline) + verify
#   ./tools/docs/publish-all.sh --combined-only # skip per-chapter walkthrough PDFs/DOCXs
#   ./tools/docs/publish-all.sh --check-only    # verify existing outputs without rebuilding
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"

skip_diagram=0
check_only=0
combined_only=0

for arg in "$@"; do
  case "$arg" in
    --skip-diagram) skip_diagram=1 ;;
    --check-only) check_only=1 ;;
    --combined-only) combined_only=1 ;;
    -h|--help)
      sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown option '$arg'" >&2
      exit 1
      ;;
  esac
done

if [[ "$check_only" -eq 0 ]]; then
  if [[ "$skip_diagram" -eq 0 ]]; then
    ./scripts/build-architecture-diagram.sh
  fi
  if [[ "$combined_only" -eq 1 ]]; then
    ./tools/docs/build-all.sh --combined-only
  else
    ./tools/docs/build-all.sh
  fi
fi

if [[ "$combined_only" -eq 1 ]]; then
  python3 tools/docs/verify-docs.py --combined-only
else
  python3 tools/docs/verify-docs.py
fi
