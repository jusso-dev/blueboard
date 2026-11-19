#!/usr/bin/env bash
# Grants the board's managed identity its Microsoft Graph / Defender application permissions, and
# gives an agent identity its blueboard app roles. Run as a Privileged Role Administrator or Global
# Administrator after `az deployment group create`. Review the permission list before running.
#
#   ./infra/grant-permissions.sh <board-identity-principal-id> <board-api-app-client-id> [<agent-principal-id> ...]
set -euo pipefail

BOARD_MI="$1"; BOARD_API_APP="$2"; shift 2

GRAPH_APP=00000003-0000-0000-c000-000000000000
MDE_APP=fc780465-2017-40d4-a0c5-307022471b92   # WindowsDefenderATP

grant() { # <resource-app-id> <permission-value>
  local sp role
  sp=$(az ad sp show --id "$1" --query id -o tsv)
  role=$(az ad sp show --id "$1" --query "appRoles[?value=='$2'].id | [0]" -o tsv)
  [ -n "$role" ] || { echo "no app role $2 on $1" >&2; exit 1; }
  az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$BOARD_MI/appRoleAssignments" \
    --body "{\"principalId\":\"$BOARD_MI\",\"resourceId\":\"$sp\",\"appRoleId\":\"$role\"}" >/dev/null \
    && echo "granted $2" || echo "skipped $2 (already assigned?)"
}

# Ingest + enrichment (read)
grant $GRAPH_APP SecurityIncident.Read.All
grant $GRAPH_APP SecurityAlert.Read.All
grant $GRAPH_APP ThreatHunting.Read.All
grant $GRAPH_APP User.Read.All
grant $GRAPH_APP IdentityRiskyUser.Read.All
grant $GRAPH_APP RoleManagement.Read.Directory
grant $MDE_APP Machine.Read.All
grant $MDE_APP File.Read.All
grant $MDE_APP Ip.Read.All
grant $MDE_APP Url.Read.All

# Brokered actions (write). Remove any you will not use.
grant $GRAPH_APP SecurityIncident.ReadWrite.All     # update/close/comment incidents
grant $GRAPH_APP User.EnableDisableAccount.All      # disable_user
grant $GRAPH_APP User.RevokeSessions.All            # revoke_sessions
grant $GRAPH_APP User-PasswordProfile.ReadWrite.All # reset_password
grant $GRAPH_APP SecurityAnalyzedMessage.ReadWrite.All # purge_email
grant $MDE_APP Machine.Isolate
grant $MDE_APP Machine.Scan
grant $MDE_APP Machine.CollectForensics
grant $MDE_APP Ti.ReadWrite.All                     # block_indicator

# Agent identities: blueboard app roles (never Board.Approve: approval is for humans).
BOARD_SP=$(az ad sp show --id "$BOARD_API_APP" --query id -o tsv)
for AGENT in "$@"; do
  for R in Board.Post Board.Hunt Board.RequestActions; do
    RID=$(az ad sp show --id "$BOARD_API_APP" --query "appRoles[?value=='$R'].id | [0]" -o tsv)
    az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$AGENT/appRoleAssignments" \
      --body "{\"principalId\":\"$AGENT\",\"resourceId\":\"$BOARD_SP\",\"appRoleId\":\"$RID\"}" >/dev/null \
      && echo "agent $AGENT: $R" || echo "agent $AGENT: $R skipped"
  done
done
