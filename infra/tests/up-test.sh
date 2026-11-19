#!/usr/bin/env bash
# Stub bodies are written literally into scripts that expand them later.
# shellcheck disable=SC2016
#
# Tests infra/up.sh without Azure: the step scripts and the az CLI are stubs. Checks that a failed step resumes,
# that the privileged step becomes a hand-off file, that a re-run after the hand-off finishes, that the first deploy
# asks for read permissions only, that state.json never holds anything secret-looking, and that the old
# .deploy/<env>.env state migrates. bash 3.2 compatible.
#
#   ./infra/tests/up-test.sh
set -euo pipefail

REAL_INFRA="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export REAL_INFRA WORK
export BB_STATE_DIR="$WORK/out" BB_INFRA="$WORK/infra" BB_ENV=uptest BB_YES=1
mkdir -p "$BB_INFRA" "$WORK/bin" "$WORK/root/.deploy"

fails=0
pass() { printf '  ok   %s\n' "$*"; }
fail() {
  printf '  FAIL %s\n' "$*"
  fails=$((fails + 1))
}
jqok() { jq -e "$1" "$2" >/dev/null; }
check() { # <description> <command...>
  local what="$1"
  shift
  if "$@"; then pass "$what"; else fail "$what"; fi
}

# ── stubs ────────────────────────────────────────────────────────────────────────────────────────
cat >"$WORK/bin/az" <<'EOF'
#!/usr/bin/env bash
# Directory roles come from STUB_ROLES; app role assignments on the board identity from STUB_GRANTED.
case "$*" in
  *directoryRole*) [[ -n "${STUB_ROLES:-}" ]] && echo "$STUB_ROLES"; exit 0 ;;
  *appRoleAssignments*) echo "${STUB_GRANTED:-0}"; exit 0 ;;
  *get-access-token*) exit 1 ;;
esac
exit 0
EOF
chmod +x "$WORK/bin/az"
export PATH="$WORK/bin:$PATH"

stub() { # <name> <body>
  printf '#!/usr/bin/env bash\nset -euo pipefail\nsource "$REAL_INFRA/lib.sh"\necho "%s ran" >>"$WORK/calls"\n%s\n' "$1" "$2" >"$BB_INFRA/$1"
  chmod +x "$BB_INFRA/$1"
}
stub preflight.sh ':'
stub entra-app.sh 'state_set BOARD_API_CLIENT_ID 11111111-2222-3333-4444-555555555555; state_set BOARD_API_AUDIENCE api://blueboard-uptest; state_set BOARD_API_SP_ID 66666666-7777-8888-9999-000000000000'
# deploy fails while $WORK/deploy-fails exists.
stub deploy.sh '[[ -f "$WORK/deploy-fails" ]] && { echo "simulated failure" >&2; exit 1; }; state_set API_MI_PRINCIPAL_ID aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee; state_set WEB_HOST web.example.net; state_set API_HOST api.example.net'
stub grant-permissions.sh 'echo "grant ${READ_ONLY:+READ_ONLY=$READ_ONLY }${ACTIONS:+ACTIONS=$ACTIONS }$*" >>"$WORK/calls"'

up() { "$REAL_INFRA/up.sh" >"$WORK/last.log" 2>&1; }
state="$BB_STATE_DIR/$BB_ENV/state.json"
handoff="$BB_STATE_DIR/$BB_ENV/handoff.md"
ran() { grep -c "^$1 ran" "$WORK/calls" 2>/dev/null || true; }

echo "up.sh"

# 1. A failure in deploy stops the run; the earlier steps are recorded.
touch "$WORK/deploy-fails"
if up; then fail "deploy failure should fail the run"; else pass "deploy failure fails the run"; fi
check "failure message says how to resume" grep -q "resumes here" "$WORK/last.log"
check "preflight and entra-app recorded as done" jqok '.steps.preflight and .steps["entra-app"] and (.steps.deploy == null)' "$state"

# 2. Re-run resumes: preflight and entra-app are skipped, deploy runs; no PRA role, so a hand-off is written.
rm -f "$WORK/deploy-fails"
check "re-run exits 0 at the hand-off" up
check "preflight ran once" test "$(ran preflight.sh)" = 1
check "entra-app ran once" test "$(ran entra-app.sh)" = 1
check "hand-off file written" test -f "$handoff"
check "hand-off has the exact command with ids" grep -q "READ_ONLY=1 ./infra/grant-permissions.sh aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee 11111111-2222-3333-4444-555555555555" "$handoff"
check "grant-permissions not run without the role" test "$(grep -c '^grant ' "$WORK/calls" || true)" = 0
check "permissions not marked done" jqok '.steps.permissions == null' "$state"

# 3. After the privileged person ran it, the deployer's re-run sees the grants and finishes.
STUB_GRANTED=12 up
check "re-run after hand-off finishes" grep -q "is up" "$WORK/last.log"
check "permissions marked done" jqok '.steps.permissions != null' "$state"
check "hand-off file removed once done" test ! -f "$handoff"

# 4. With the role, the step runs grant-permissions itself, read-only unless ACTIONS is set.
rm -f "$state" "$WORK/calls"
STUB_ROLES="Privileged Role Administrator" up
check "grant ran read-only by default" grep -q "^grant READ_ONLY=1 aaaaaaaa" "$WORK/calls"
rm -f "$state" "$WORK/calls"
STUB_ROLES="Global Administrator" ACTIONS="run_av_scan isolate_device" AGENT_PRINCIPAL_IDS="a1 a2" up
check "ACTIONS passed through, agents appended" grep -q "^grant ACTIONS=run_av_scan isolate_device aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee 11111111-2222-3333-4444-555555555555 a1 a2" "$WORK/calls"

# 5. Nothing secret-looking ever lands in state.json, and lib.sh refuses such keys.
check "state.json has no secret-like keys or values" bash -c '! grep -Eiq "secret|password|key=|token" "$1"' _ "$state"
if (source "$REAL_INFRA/lib.sh" && state_set NOTIFY_WEBHOOK_SECRET x) >/dev/null 2>&1; then
  fail "state_set should refuse NOTIFY_WEBHOOK_SECRET"
else
  pass "state_set refuses secret-like keys"
fi

# 6. Australia only.
if LOCATION=westus2 "$REAL_INFRA/up.sh" >/dev/null 2>&1; then fail "non-Australian region accepted"; else pass "non-Australian region refused"; fi

# 7. The old .deploy/<env>.env state moves into state.json once.
rm -rf "$BB_STATE_DIR"
mkdir -p "$REAL_INFRA/../.deploy"
legacy="$REAL_INFRA/../.deploy/uptest-legacy.env"
printf "BOARD_API_CLIENT_ID=abc\nAPI_HOST=api.example.net\n" >"$legacy"
if (
  export BB_ENV=uptest-legacy
  source "$REAL_INFRA/lib.sh"
  state_load >/dev/null
  [[ "$BOARD_API_CLIENT_ID" == abc ]]
); then pass "legacy .deploy state migrated"; else fail "legacy .deploy state migrated"; fi
check "legacy file renamed" test -f "$legacy.migrated"
rm -f "$legacy" "$legacy.migrated"
rmdir "$REAL_INFRA/../.deploy" 2>/dev/null || true

echo
if [[ $fails -eq 0 ]]; then echo "up.sh: all checks passed"; else
  echo "up.sh: $fails check(s) failed (last log below)"
  cat "$WORK/last.log"
  exit 1
fi
