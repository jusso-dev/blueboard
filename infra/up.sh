#!/usr/bin/env bash
# One command from an empty subscription to a running board. Resumable: each finished step is recorded in
# infra/out/<env>/state.json and skipped next time, so after a failure fix the cause and run it again.
#
#   BB_ENV=test ./infra/up.sh
#   BB_ENV=prod BB_PROFILE=production POLICY_FILE=policy.json ./infra/up.sh
#
# Steps:
#   1. preflight     read-only checks (tools, sign-in, Azure and Entra roles)
#   2. entra-app     app registration, app roles, Board.Access scope
#   3. deploy        Bicep, Function App, web app, sign-in redirect, health and setup checks
#   4. permissions   Graph + Defender application permissions for the board identity. Runs only if you hold
#                    Privileged Role Administrator or Global Administrator; otherwise writes
#                    infra/out/<env>/handoff.md with the exact command for the person who does.
#
# Settings (environment, remembered in state.json for the next run; set one empty, e.g. ACTIONS=, to clear it):
#   RESOURCE_GROUP     default rg-blueboard-<env>
#   LOCATION           australiaeast (default) or australiasoutheast
#   BB_PROFILE         mvp (default) or production (private networking, Key Vault, HA, audit export)
#   POLICY_FILE        your reviewed policy.json (default: policy.example.json)
#   ACTIONS            brokered actions to grant write permissions for. Unset: read permissions only (READ_ONLY=1),
#                      so a first deploy can't change anything in the tenant
#   AGENT_PRINCIPAL_IDS  agent service principal object ids (space separated) to give the three agent roles
#   BB_REDO=<step>     run one step again even though it's recorded as done (deploy is always re-run)
# deploy.sh also remembers its other non-secret settings (TI_*, NOTIFY_* hosts and mail, WEBHOOK_ALLOWED_HOSTS, …),
# but not BROKER_EXECUTE. Secrets (webhook URLs, keys) are never stored: pass them on every run, or deploy.sh warns
# that it will clear them.
#
# It never asks for broader roles than each step needs and never escalates: see docs/DEPLOYMENT.md § Roles.
source "$(dirname "$0")/lib.sh"
BB_INFRA="${BB_INFRA:-$BB_ROOT/infra}"

: "${BB_ENV:?set BB_ENV (e.g. test)}"
[[ "$BB_ENV" =~ ^[a-z0-9][a-z0-9-]{0,20}$ ]] || die "BB_ENV must be lowercase letters, digits and dashes"
require az jq
state_load

RESOURCE_GROUP="${RESOURCE_GROUP:-rg-blueboard-$BB_ENV}"
LOCATION="${LOCATION:-australiaeast}"
BB_PROFILE="${BB_PROFILE:-mvp}"
case "$LOCATION" in australiaeast | australiasoutheast) ;; *) die "LOCATION must be australiaeast or australiasoutheast (blueboard stays in Australia)" ;; esac
case "$BB_PROFILE" in mvp | production) ;; *) die "BB_PROFILE must be mvp or production" ;; esac
export RESOURCE_GROUP LOCATION BB_PROFILE
state_set BB_ENV "$BB_ENV"
state_set RESOURCE_GROUP "$RESOURCE_GROUP"
state_set LOCATION "$LOCATION"
state_set BB_PROFILE "$BB_PROFILE"
# Absolute, so a re-run from another folder deploys the same policy.
if [[ -n "${POLICY_FILE:-}" ]]; then
  [[ -f "$POLICY_FILE" ]] || die "POLICY_FILE $POLICY_FILE not found"
  POLICY_FILE="$(cd "$(dirname "$POLICY_FILE")" && pwd)/$(basename "$POLICY_FILE")"
  export POLICY_FILE
fi
state_set POLICY_FILE "${POLICY_FILE:-}"
state_set ACTIONS "${ACTIONS:-}"
state_set AGENT_PRINCIPAL_IDS "${AGENT_PRINCIPAL_IDS:-}"
[[ -n "${BB_REDO:-}" ]] && step_clear "$BB_REDO"

run_step() { # <name> <description> <command...>
  local name="$1" what="$2"
  shift 2
  if step_done "$name"; then
    log "step $name: done earlier ($(jq -r --arg s "$name" '.steps[$s]' "$(state_file)")), skipping"
    return 0
  fi
  log "step $name: $what"
  if ! "$@"; then
    die "step $name failed. Fix the cause above, then run BB_ENV=$BB_ENV ./infra/up.sh again: it resumes here."
  fi
  step_mark "$name"
}

# The first deploy can't write to the tenant: read permissions only unless ACTIONS is set.
if [[ -z "${ACTIONS:-}" ]]; then
  GRANT_ENV=(READ_ONLY=1)
  GRANT_NOTE="read permissions only (READ_ONLY=1): every brokered action will fail until write permissions are added"
else
  GRANT_ENV=("ACTIONS=$ACTIONS")
  GRANT_NOTE="write permissions for: $ACTIONS"
fi

run_step preflight "read-only checks" "$BB_INFRA/preflight.sh"
run_step entra-app "app registration" "$BB_INFRA/entra-app.sh"
state_load
# Deploy rolls out the current commit, so it runs every time (it's idempotent).
step_clear deploy
run_step deploy "infrastructure ($BB_PROFILE), API and web app" "$BB_INFRA/deploy.sh"
state_load
: "${API_MI_PRINCIPAL_ID:?deploy did not record the board identity (API_MI_PRINCIPAL_ID)}"
: "${BOARD_API_CLIENT_ID:?entra-app did not record BOARD_API_CLIENT_ID}"

grant_cmd() {
  printf '%s ' "${GRANT_ENV[@]}"
  printf './infra/grant-permissions.sh %s %s' "$API_MI_PRINCIPAL_ID" "$BOARD_API_CLIENT_ID"
  [[ -n "${AGENT_PRINCIPAL_IDS:-}" ]] && printf ' %s' "$AGENT_PRINCIPAL_IDS"
  [[ -n "${NOTIFY_MAIL_FROM:-}" ]] && printf ' # add NOTIFY_MAIL=1 for approver email (Mail.Send)'
  return 0
}

write_handoff() {
  local file
  file="$(state_dir)/handoff.md"
  cat >"$file" <<EOF
# blueboard ($BB_ENV): one step for a Privileged Role Administrator

The board is deployed, but its managed identity has no Microsoft Graph or Defender permissions yet, so it can't read
incidents. Granting application permissions needs **Privileged Role Administrator** (or Global Administrator) in
Entra, which the person who deployed doesn't hold.

## What to run

From a checkout of the blueboard repository, signed in with \`az login\` to tenant \`${AZURE_TENANT_ID:-<tenant>}\`:

\`\`\`sh
$(grant_cmd)
\`\`\`

This grants $GRANT_NOTE.

| | |
|---|---|
| Board identity (managed identity object id) | \`$API_MI_PRINCIPAL_ID\` |
| Board app registration (client id) | \`$BOARD_API_CLIENT_ID\` |
| Resource group | \`$RESOURCE_GROUP\` ($LOCATION) |

## Permissions to review before running

Read (always): Microsoft Graph SecurityIncident.Read.All, SecurityAlert.Read.All, ThreatHunting.Read.All,
User.Read.All, IdentityRiskyUser.Read.All, RoleManagement.Read.Directory; Defender for Endpoint Machine.Read.All,
File.Read.All, Ip.Read.All, Url.Read.All.

Write: $( [[ -n "${ACTIONS:-}" ]] && echo "one per action in ACTIONS (see the table in docs/SECURITY.md § Permissions the board holds)." || echo "none on this run." )

Every permission is tenant-wide and explained in docs/SECURITY.md § Permissions the board holds.

## Adding write permissions later

When the board has run in dry run for a while and policy.json is reviewed, grant only the writes you will broker:

\`\`\`sh
ACTIONS="run_av_scan collect_investigation_package add_incident_comment" ./infra/grant-permissions.sh $API_MI_PRINCIPAL_ID $BOARD_API_CLIENT_ID
\`\`\`

## Afterwards

Tell the deployer. They run \`BB_ENV=$BB_ENV ./infra/up.sh\` again, which finds the permissions in place, finishes, and
prints the setup checklist. Tokens pick up new permissions within about an hour (restart the Function App to force it).
EOF
  echo "$file"
}

# After a hand-off, the privileged person has granted the permissions: reading the identity's assignments needs no
# special role, so the deployer's re-run checks that every permission for these settings (reads, ACTIONS, agent
# roles) is in place, with the same list grant-permissions.sh would grant, and finishes.
already_granted() {
  env "${GRANT_ENV[@]}" CHECK=1 "$BB_INFRA/grant-permissions.sh" "$API_MI_PRINCIPAL_ID" "$BOARD_API_CLIENT_ID" ${agents[@]+"${agents[@]}"}
}

grant_or_handoff() {
  local agents=()
  read -r -a agents <<<"${AGENT_PRINCIPAL_IDS:-}"
  if grep -qxE "Global Administrator|Privileged Role Administrator" <<<"$(my_directory_roles)"; then
    env "${GRANT_ENV[@]}" "$BB_INFRA/grant-permissions.sh" "$API_MI_PRINCIPAL_ID" "$BOARD_API_CLIENT_ID" ${agents[@]+"${agents[@]}"}
    return
  fi
  if [[ -f "$(state_dir)/handoff.md" ]] && already_granted; then
    log "permissions were granted after the hand-off"
    return 0
  fi
  local file
  file="$(write_handoff)"
  warn "you don't hold Privileged Role Administrator, so the permissions step is handed off."
  printf '\n  Send this file to a Privileged Role Administrator:\n    %s\n\n' "$file"
  return 2
}

if ! step_done permissions; then
  log "step permissions: $GRANT_NOTE"
  set +e
  grant_or_handoff
  rc=$?
  set -e
  case "$rc" in
    0)
      step_mark permissions
      rm -f "$(state_dir)/handoff.md"
      ;;
    2)
      state_set HANDOFF "$(state_dir)/handoff.md"
      log "stopped at the privileged step. Everything else is done; re-run this command after the hand-off."
      exit 0
      ;;
    *) die "step permissions failed. Fix the cause above, then run BB_ENV=$BB_ENV ./infra/up.sh again." ;;
  esac
else
  log "step permissions: done earlier, skipping (BB_REDO=permissions to grant again, e.g. with ACTIONS=…)"
fi

log "setup checks"
run_setup_checks "${API_HOST:-}" "${BOARD_API_AUDIENCE:-}"

cat <<EOF

blueboard ($BB_ENV, $BB_PROFILE) is up.
  Board        https://${WEB_HOST:-<web>}
  Setup        https://${WEB_HOST:-<web>}/setup   (Board.Admin)
  MCP          https://${API_HOST:-<api>}/runtime/webhooks/mcp
  State        $(state_file)

Next: assign people to roles (docs/DEPLOYMENT.md § Deploy, step 4) and connect your agents.
EOF
