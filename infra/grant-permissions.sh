#!/usr/bin/env bash
# Grants the board's managed identity its Microsoft Graph and Defender for Endpoint application
# permissions, and gives agent identities their blueboard app roles. Idempotent.
#
#   ./infra/grant-permissions.sh <board-mi-principal-id> <board-api-app-client-id> [<agent-principal-id> ...]
#                                                     # read permissions only (the default; READ_ONLY=1 says so
#                                                     # explicitly): no brokered actions possible
#   ACTIONS="isolate_device run_av_scan" ./infra/grant-permissions.sh ...   # only the writes you will broker
#   ACTIONS=all ./infra/grant-permissions.sh ...      # every write permission (not recommended)
#   CHECK=1 ./infra/grant-permissions.sh ...          # grant nothing: exit 1 if any permission the same settings
#                                                     # would grant is missing (no special role needed)
#   NOTIFY_MAIL=1 ./infra/grant-permissions.sh ...    # also Mail.Send for approver email (scope it with an
#                                                       # application access policy: docs/OPERATIONS.md)
#   TI_MSTI=1 ./infra/grant-permissions.sh ...        # add ThreatIntelligence.Read.All (Microsoft Threat Intelligence lookups)
#   PURVIEW_LABELS=1 ./infra/grant-permissions.sh ... # add InformationProtectionPolicy.Read.All (Purview sensitivity labels)
#   PURVIEW_GUARD=1 ./infra/grant-permissions.sh ...  # add Content.Process.All (Purview processContent guard on posts)
#   EXPOSURE=1 ./infra/grant-permissions.sh ...       # add SecurityRecommendation.Read.All (MDE) for list_exposure_recommendations
#
# create_detection_rule / disable_detection_rule: target defender uses CustomDetection.ReadWrite.All (Graph v1.0); target
# sentinel needs Microsoft Sentinel Contributor on the workspace (ARM), like publish_ti_indicator. Any intune_* action
# also grants DeviceManagementManagedDevices.Read.All so the board can resolve managed device ↔ Entra device ↔ MDE ids.
# intune_expedite_quality_update uses the Windows Autopatch deployment API, which is Graph beta only.
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

missing=""
assign() { # <principal-id> <resource-sp-id> <app-role-id> <label>
  local have
  have="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$1/appRoleAssignments" \
    --query "value[?appRoleId=='$3' && resourceId=='$2'] | length(@)" -o tsv)"
  if [[ "$have" != "0" ]]; then
    printf '  = %s\n' "$4"
    return
  fi
  if [[ "${CHECK:-}" == "1" ]]; then
    printf '  - %s (not granted)\n' "$4"
    missing="$missing $4"
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
    restrict_app_execution | unrestrict_app_execution) echo "$MDE_APP Machine.RestrictExecution" ;;
    stop_and_quarantine_file) echo "$MDE_APP Machine.StopAndQuarantine" ;;
    tag_device) echo "$MDE_APP Machine.ReadWrite.All" ;;
    block_indicator | unblock_indicator) echo "$MDE_APP Ti.ReadWrite.All" ;;
    disable_user | enable_user) echo "$GRAPH_APP User.EnableDisableAccount.All" ;;
    revoke_sessions) echo "$GRAPH_APP User.RevokeSessions.All" ;;
    reset_password) echo "$GRAPH_APP User-PasswordProfile.ReadWrite.All" ;;
    confirm_user_compromised | dismiss_user_risk) echo "$GRAPH_APP IdentityRiskyUser.ReadWrite.All" ;;
    disable_service_principal) echo "$GRAPH_APP Application.ReadWrite.All" ;;
    purge_email) echo "$GRAPH_APP SecurityAnalyzedMessage.ReadWrite.All" ;;
    update_incident | add_incident_comment) echo "$GRAPH_APP SecurityIncident.ReadWrite.All" ;;
    create_detection_rule | disable_detection_rule) echo "$GRAPH_APP CustomDetection.ReadWrite.All" ;;
    intune_sync_device | intune_update_defender_signatures) echo "$GRAPH_APP DeviceManagementManagedDevices.PrivilegedOperations.All" ;;
    intune_expedite_quality_update) echo "$GRAPH_APP WindowsUpdates.ReadWrite.All" ;;
    publish_ti_indicator) echo "AZURE_RBAC" ;;
    *) return 1 ;;
  esac
}
ALL_ACTIONS="isolate_device release_device run_av_scan collect_investigation_package restrict_app_execution unrestrict_app_execution stop_and_quarantine_file tag_device block_indicator unblock_indicator disable_user enable_user revoke_sessions reset_password confirm_user_compromised dismiss_user_risk disable_service_principal purge_email update_incident add_incident_comment publish_ti_indicator create_detection_rule disable_detection_rule intune_sync_device intune_update_defender_signatures intune_expedite_quality_update"

log "read permissions (incident ingest, hunting, entity lookups)"
for p in SecurityIncident.Read.All SecurityAlert.Read.All ThreatHunting.Read.All User.Read.All IdentityRiskyUser.Read.All RoleManagement.Read.Directory; do
  grant "$GRAPH_APP" "$p"
done
for p in Machine.Read.All File.Read.All Ip.Read.All Url.Read.All; do grant "$MDE_APP" "$p"; done
if [[ "${TI_MSTI:-}" == "1" ]]; then
  log "Microsoft Threat Intelligence (TI_MSTI=1)"
  grant "$GRAPH_APP" ThreatIntelligence.Read.All
fi
if [[ "${PURVIEW_LABELS:-}" == "1" ]]; then
  log "Microsoft Purview sensitivity labels (PURVIEW_LABELS=1)"
  grant "$GRAPH_APP" InformationProtectionPolicy.Read.All
fi
if [[ "${EXPOSURE:-}" == "1" ]]; then
  log "Defender Vulnerability Management recommendations (EXPOSURE=1)"
  grant "$MDE_APP" SecurityRecommendation.Read.All
fi
if [[ "${PURVIEW_GUARD:-}" == "1" ]]; then
  log "Microsoft Purview processContent content guard (PURVIEW_GUARD=1)"
  grant "$GRAPH_APP" Content.Process.All
fi

# Read-only unless ACTIONS names the writes (or ACTIONS=all): a bare run can't change anything in the tenant.
if [[ "${READ_ONLY:-}" == "1" || -z "${ACTIONS:-}" ]]; then
  warn "read permissions only (set ACTIONS to add writes): every brokered action will fail at execution"
else
  actions="$ACTIONS"
  [[ "$actions" == "all" ]] && actions="$ALL_ACTIONS"
  log "write permissions for brokered actions: $actions"
  done_perms=" "
  for a in $actions; do
    perm="$(perm_for "$a")" || die "unknown action $a"
    if [[ "$perm" == "AZURE_RBAC" ]]; then
      warn "$a needs Microsoft Sentinel Contributor on the workspace, not a Graph permission (see docs/THREAT_INTEL.md)"
      continue
    fi
    case "$a" in
      create_detection_rule | disable_detection_rule)
        warn "$a with target sentinel also needs Microsoft Sentinel Contributor on the workspace (see docs/THREAT_INTEL.md)" ;;
      intune_*)
        case "$done_perms" in *" $GRAPH_APP DeviceManagementManagedDevices.Read.All "*) ;; *)
          done_perms="$done_perms$GRAPH_APP DeviceManagementManagedDevices.Read.All "
          grant "$GRAPH_APP" DeviceManagementManagedDevices.Read.All ;;
        esac ;;
    esac
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

if [[ "${CHECK:-}" == "1" ]]; then
  if [[ -n "$missing" ]]; then
    warn "not granted yet:$missing"
    exit 1
  fi
  log "every permission for these settings is granted"
  exit 0
fi
log "done. Tokens pick up new permissions within ~1 hour (restart the board revision to force it)."
