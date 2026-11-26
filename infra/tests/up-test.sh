#!/usr/bin/env bash
# Stub bodies are written literally into scripts that expand them later.
# shellcheck disable=SC2016
#
# Tests infra/up.sh without Azure: the step scripts and the az CLI are stubs. Checks that a failed step resumes,
# that the privileged step becomes a hand-off file, that a re-run after the hand-off finishes only once every
# permission is granted, that the first deploy asks for read permissions only, that POLICY_FILE, ACTIONS and
# AGENT_PRINCIPAL_IDS are remembered, that state.json never holds anything secret-looking, and that the old
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
stub deploy.sh '[[ -f "$WORK/deploy-fails" ]] && { echo "simulated failure" >&2; exit 1; }; echo "deploy POLICY_FILE=${POLICY_FILE:-}" >>"$WORK/calls"; state_set API_MI_PRINCIPAL_ID aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee; state_set WEB_HOST web.example.net; state_set API_HOST api.example.net'
# groups fails while $WORK/groups-fails exists (the deployer lacks Groups Administrator).
stub entra-groups.sh '[[ -f "$WORK/groups-fails" ]] && { echo "Insufficient privileges" >&2; exit 1; }; state_set GROUP_ANALYSTS_ID g-analysts; state_set GROUP_APPROVERS_ID g-approvers; state_set GROUP_ADMINS_ID g-admins'
# CHECK=1 (up.sh asking whether the hand-off was done) succeeds only when STUB_GRANTED=all.
stub grant-permissions.sh 'args="${READ_ONLY:+READ_ONLY=$READ_ONLY }${ACTIONS:+ACTIONS=$ACTIONS }$*"
if [[ "${CHECK:-}" == 1 ]]; then echo "check $args" >>"$WORK/calls"; [[ "${STUB_GRANTED:-}" == all ]]; exit; fi
echo "grant $args" >>"$WORK/calls"'

up() { "$REAL_INFRA/up.sh" >"$WORK/last.log" 2>&1; }
state="$BB_STATE_DIR/$BB_ENV/state.json"
handoff="$BB_STATE_DIR/$BB_ENV/handoff.md"
ran() { grep -c "^$1 ran" "$WORK/calls" 2>/dev/null || true; }

echo "up.sh"

# 1. A failure in deploy stops the run; the earlier steps are recorded. Groups can't be created (no directory role):
#    that's a hand-off note, not a failure.
touch "$WORK/deploy-fails" "$WORK/groups-fails"
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
check "groups refusal is a hand-off note" grep -q "BB_ENV=uptest ./infra/entra-groups.sh" "$handoff"
check "hand-off has the Conditional Access step" grep -q "conditional-access.sh" "$handoff"
check "groups not marked done after a refusal" jqok '.steps.groups == null' "$state"
rm -f "$WORK/groups-fails"

# 3. Some permissions granted but not all: still handed off. Once all are there, the re-run finishes.
STUB_GRANTED=some up
check "partial grant keeps the hand-off" test -f "$handoff"
check "partial grant: permissions not marked done" jqok '.steps.permissions == null' "$state"
check "hand-off check uses the same settings as the grant" grep -q "^check READ_ONLY=1 aaaaaaaa" "$WORK/calls"
STUB_GRANTED=all up
check "re-run after hand-off finishes" grep -q "is up" "$WORK/last.log"
check "permissions marked done" jqok '.steps.permissions != null' "$state"
check "hand-off file removed once done" test ! -f "$handoff"
check "groups step ran once allowed and is recorded" jqok '.steps.groups != null and .GROUP_APPROVERS_ID == "g-approvers"' "$state"
check "final summary lists the group ids" grep -q "approvers g-approvers" "$WORK/last.log"

# 4. With the role, the step runs grant-permissions itself, read-only unless ACTIONS is set.
rm -f "$state" "$WORK/calls"
STUB_ROLES="Privileged Role Administrator" up
check "grant ran read-only by default" grep -q "^grant READ_ONLY=1 aaaaaaaa" "$WORK/calls"
rm -f "$state" "$WORK/calls"
STUB_ROLES="Global Administrator" ACTIONS="run_av_scan isolate_device" AGENT_PRINCIPAL_IDS="a1 a2" up
check "ACTIONS passed through, agents appended" grep -q "^grant ACTIONS=run_av_scan isolate_device aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee 11111111-2222-3333-4444-555555555555 a1 a2" "$WORK/calls"

# 4b. A bare re-run remembers POLICY_FILE (as an absolute path), ACTIONS and AGENT_PRINCIPAL_IDS; FOO= clears one.
rm -f "$state" "$WORK/calls"
echo '{}' >"$WORK/policy.json"
(cd "$WORK" && POLICY_FILE=policy.json ACTIONS="run_av_scan" AGENT_PRINCIPAL_IDS="a1" up)
check "POLICY_FILE saved as an absolute path" test "$(jq -r .POLICY_FILE "$state")" = "$(cd "$WORK" && pwd)/policy.json"
rm -f "$WORK/calls"
STUB_ROLES="Privileged Role Administrator" BB_REDO=permissions up
check "bare re-run deploys the remembered POLICY_FILE" grep -qx "deploy POLICY_FILE=$(cd "$WORK" && pwd)/policy.json" "$WORK/calls"
check "bare re-run grants the remembered ACTIONS and agents" grep -q "^grant ACTIONS=run_av_scan aaaaaaaa.* a1$" "$WORK/calls"
rm -f "$WORK/calls"
STUB_ROLES="Privileged Role Administrator" BB_REDO=permissions ACTIONS='' up
check "ACTIONS= clears the remembered value (read-only again)" grep -q "^grant READ_ONLY=1 aaaaaaaa" "$WORK/calls"

# 4c. The release is remembered for the re-run after a hand-off; BB_RELEASE= clears it.
rm -f "$state"
BB_RELEASE=v9.9.9 up
check "BB_RELEASE remembered in state" test "$(jq -r .BB_RELEASE "$state")" = v9.9.9
BB_RELEASE='' up
check "BB_RELEASE= clears it" test "$(jq -r .BB_RELEASE "$state")" = ""

# 5. Nothing secret-looking ever lands in state.json, and lib.sh refuses such keys.
check "state.json has no secret-like keys or values" bash -c '! grep -Eiq "secret|password|key=|token" "$1"' _ "$state"
if (source "$REAL_INFRA/lib.sh" && state_set NOTIFY_WEBHOOK_SECRET x) >/dev/null 2>&1; then
  fail "state_set should refuse NOTIFY_WEBHOOK_SECRET"
else
  pass "state_set refuses secret-like keys"
fi

# 5b. Release packages: checksums are enforced before anything is deployed.
rel="$WORK/mirror/v9.9.9"
mkdir -p "$rel"
echo api >"$rel/blueboard-api-v9.9.9.zip"
echo web >"$rel/blueboard-web-v9.9.9.zip"
(cd "$rel" && (sha256sum blueboard-*.zip 2>/dev/null || shasum -a 256 blueboard-*.zip) >blueboard-v9.9.9.sha256)
fetch() { (source "$REAL_INFRA/lib.sh" && BB_RELEASE_URL="file://$WORK/mirror" BB_RELEASE_SKIP_ATTESTATION=1 release_fetch "$1") >"$WORK/fetch.log" 2>&1; }
check "release with matching checksums is accepted" fetch v9.9.9
echo tampered >"$rel/blueboard-web-v9.9.9.zip"
check "release cached under its source, not just its tag" bash -c 'ls -d "$1"/releases/*/v9.9.9 >/dev/null' _ "$BB_STATE_DIR"
mkdir -p "$WORK/mirror2/v9.9.9"
echo other >"$WORK/mirror2/v9.9.9/blueboard-api-v9.9.9.zip"
cp "$rel/blueboard-web-v9.9.9.zip" "$rel/blueboard-v9.9.9.sha256" "$WORK/mirror2/v9.9.9/"
if (source "$REAL_INFRA/lib.sh" && BB_RELEASE_URL="file://$WORK/mirror2" BB_RELEASE_SKIP_ATTESTATION=1 release_fetch v9.9.9) >/dev/null 2>&1; then
  fail "a second source with the same tag reused the first source's verified cache"
else
  pass "same tag from another source is fetched and verified on its own"
fi
rm -rf "$BB_STATE_DIR/releases"
if fetch v9.9.9; then fail "tampered release package accepted"; else pass "tampered release package refused"; fi
check "tampered package deleted" test ! -f "$BB_STATE_DIR/releases/v9.9.9/blueboard-web-v9.9.9.zip"
if fetch "v1;rm -rf /"; then fail "malformed release tag accepted"; else pass "malformed release tag refused"; fi

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
