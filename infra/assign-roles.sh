#!/usr/bin/env bash
# Assigns blueboard app roles to a user, group or service principal (agent). Idempotent.
#
#   BB_ENV=prod ./infra/assign-roles.sh <object-id> Board.Post Board.Hunt Board.RequestActions
#   BB_ENV=prod ./infra/assign-roles.sh <soc-leads-group-id> Board.Post Board.Approve
#
# Needs: owner of the enterprise application, or Cloud Application Administrator /
# Application Administrator. Board.Approve and Board.Admin are refused for service principals:
# agents must never approve their own containment.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV}"
[[ $# -ge 2 ]] || die "usage: $0 <principal-object-id> <role> [role...]"
require az jq
check_az_context
state_load
: "${BOARD_API_SP_ID:?run infra/entra-app.sh first}"

principal="$1"
shift

type="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/directoryObjects/$principal" \
  --query '"@odata.type"' -o tsv)" || die "no directory object $principal"
case "$type" in
  "#microsoft.graph.user") endpoint="users" ;;
  "#microsoft.graph.group") endpoint="groups" ;;
  "#microsoft.graph.servicePrincipal") endpoint="servicePrincipals" ;;
  *) die "unsupported principal type $type" ;;
esac

for role in "$@"; do
  if [[ "$endpoint" == "servicePrincipals" && ("$role" == "Board.Approve" || "$role" == "Board.Admin") ]]; then
    die "refusing to give $role to a service principal: approvals and admin are for people only"
  fi
  role_id="$(az ad sp show --id "$BOARD_API_SP_ID" --query "appRoles[?value=='$role'].id | [0]" -o tsv)"
  [[ -n "$role_id" ]] || die "unknown role $role"
  existing="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/$endpoint/$principal/appRoleAssignments" \
    --query "value[?appRoleId=='$role_id' && resourceId=='$BOARD_API_SP_ID'] | length(@)" -o tsv)"
  if [[ "$existing" != "0" ]]; then
    log "$role already assigned"
    continue
  fi
  az rest --method POST --uri "https://graph.microsoft.com/v1.0/$endpoint/$principal/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"principalId\":\"$principal\",\"resourceId\":\"$BOARD_API_SP_ID\",\"appRoleId\":\"$role_id\"}" >/dev/null
  log "assigned $role"
done
