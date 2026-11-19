#!/usr/bin/env bash
# Grants the board's managed identity its Microsoft Graph and Defender for Endpoint application
# permissions, and gives agent identities their blueboard app roles. Idempotent.
#
#   ./infra/grant-permissions.sh <board-mi-principal-id> <board-api-app-client-id> [<agent-principal-id> ...]
#   READ_ONLY=1 ./infra/grant-permissions.sh ...      # read permissions only: no brokered actions possible
#   ACTIONS="isolate_device run_av_scan" ./infra/grant-permissions.sh ...   # only the writes you will broker
#   NOTIFY_MAIL=1 ./infra/grant-permissions.sh ...    # also Mail.Send for approver email (scope it with an
#                                                       # application access policy: docs/OPERATIONS.md)
#   TI_MSTI=1 ./infra/grant-permissions.sh ...        # add ThreatIntelligence.Read.All (Microsoft Threat Intelligence lookups)
#
# publish_ti_indicator needs no Graph permission: it needs the Azure role Microsoft Sentinel Contributor on the
# Sentinel workspace (main.bicep assignSentinelContributor, or the az role assignment in docs/THREAT_INTEL.md).
#
# Needs: Privileged Role Administrator (or Global Administrator) in Entra. Application permissions
# are tenant-wide: review docs/SECURITY.md § Permissions before running.
source "$(dirname "$0")/lib.sh"

[[ $# -ge 2 ]] || die "usage: $0 <board-mi-principal-id> <board-api-app-client-id> [<agent-principal-id> ...]"
BOARD_MI="$1"
BOARD_API_APP="$2"
shift 2
require az jq
check_az_context

GRAPH_APP=00000003-0000-0000-c000-000000000000
MDE_APP=fc780465-2017-40d4-a0c5-307022471b92 # WindowsDefenderATP

assign() { # <principal-id> <resource-sp-id> <app-role-id> <label>
  local have
  have="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$1/appRoleAssignments" \
    --query "value[?appRoleId=='$3' && resourceId=='$2'] | length(@)" -o tsv)"
  if [[ "$have" != "0" ]]; then
    printf '  = %s\n' "$4"
    return
  fi
  az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$1/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"principalId\":\"$1\",\"resourceId\":\"$2\",\"appRoleId\":\"$3\"}" >/dev/null
  printf '  + %s\n' "$4"
}

grant() { # <resource-app-id> <permission>
  local sp role
  sp="$(az ad sp show --id "$1" --query id -o tsv)"
  role="$(az ad sp show --id "$1" --query "appRoles[?value=='$2'].id | [0]" -o tsv)"
  [[ -n "$role" ]] || die "no application permission $2 on $1"
  assign "$BOARD_MI" "$sp" "$role" "$2"
}

# Write permission needed per brokered action (keep in sync with api/Blueboard.Api/Ops/Permissions.cs; a unit test checks).
# Plain function instead of an associative array so this runs on macOS's bash 3.2.
perm_for() {
  case "$1" in
    isolate_device | release_device) echo "$MDE_APP Machine.Isolate" ;;
    run_av_scan) echo "$MDE_APP Machine.Scan" ;;
    collect_investigation_package) echo "$MDE_APP Machine.CollectForensics" ;;
    block_indicator) echo "$MDE_APP Ti.ReadWrite.All" ;;
    disable_user) echo "$GRAPH_APP User.EnableDisableAccount.All" ;;
    revoke_sessions) echo "$GRAPH_APP User.RevokeSessions.All" ;;
    reset_password) echo "$GRAPH_APP User-PasswordProfile.ReadWrite.All" ;;
    purge_email) echo "$GRAPH_APP SecurityAnalyzedMessage.ReadWrite.All" ;;
    update_incident | add_incident_comment) echo "$GRAPH_APP SecurityIncident.ReadWrite.All" ;;
    publish_ti_indicator) echo "AZURE_RBAC" ;;
    *) return 1 ;;
  esac
}
ALL_ACTIONS="isolate_device release_device run_av_scan collect_investigation_package block_indicator disable_user revoke_sessions reset_password purge_email update_incident add_incident_comment publish_ti_indicator"

log "read permissions (incident ingest, hunting, entity lookups)"
for p in SecurityIncident.Read.All SecurityAlert.Read.All ThreatHunting.Read.All User.Read.All IdentityRiskyUser.Read.All RoleManagement.Read.Directory; do
  grant "$GRAPH_APP" "$p"
done
for p in Machine.Read.All File.Read.All Ip.Read.All Url.Read.All; do grant "$MDE_APP" "$p"; done
if [[ "${TI_MSTI:-}" == "1" ]]; then
  log "Microsoft Threat Intelligence (TI_MSTI=1)"
  grant "$GRAPH_APP" ThreatIntelligence.Read.All
fi

if [[ "${READ_ONLY:-}" == "1" ]]; then
  warn "READ_ONLY=1: no write permissions granted, every brokered action will fail at execution"
else
  actions="${ACTIONS:-$ALL_ACTIONS}"
  log "write permissions for brokered actions: $actions"
  done_perms=" "
  for a in $actions; do
    perm="$(perm_for "$a")" || die "unknown action $a"
    if [[ "$perm" == "AZURE_RBAC" ]]; then
      warn "$a needs Microsoft Sentinel Contributor on the workspace, not a Graph permission (see docs/THREAT_INTEL.md)"
      continue
    fi
    case "$done_perms" in *" $perm "*) continue ;; esac
    done_perms="$done_perms$perm "
    # shellcheck disable=SC2086
    grant $perm
  done
fi

if [[ "${NOTIFY_MAIL:-}" == "1" ]]; then
  log "Mail.Send for approver email: limit it to the notification mailbox with an application access policy"
  grant "$GRAPH_APP" Mail.Send
  warn "Mail.Send is tenant-wide until you run New-ApplicationAccessPolicy (docs/OPERATIONS.md § Email)"
fi

if [[ $# -gt 0 ]]; then
  BOARD_SP="$(az ad sp show --id "$BOARD_API_APP" --query id -o tsv)"
  for AGENT in "$@"; do
    log "agent $AGENT: board app roles (never Board.Approve or Board.Admin)"
    for R in Board.Post Board.Hunt Board.RequestActions; do
      RID="$(az ad sp show --id "$BOARD_API_APP" --query "appRoles[?value=='$R'].id | [0]" -o tsv)"
      assign "$AGENT" "$BOARD_SP" "$RID" "$R"
    done
  done
fi

log "done. Tokens pick up new permissions within ~1 hour (restart the board revision to force it)."
