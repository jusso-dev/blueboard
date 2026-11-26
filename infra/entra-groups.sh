#!/usr/bin/env bash
# Role-based access through Microsoft Entra security groups. Idempotent.
#
#   BB_ENV=prod ./infra/entra-groups.sh
#   BB_ENV=prod GROUP_APPROVERS_ID=<existing-group-object-id> ./infra/entra-groups.sh   # adopt a group you already have
#   BB_ENV=prod GROUP_ADD_ME=1 ./infra/entra-groups.sh   # also put the signed-in deployer in the admins group
#
# Creates (or adopts) three security groups and gives each its blueboard app roles on the enterprise application:
#
#   <prefix>-analysts    Board.Post Board.Hunt Board.RequestActions   work incidents, hunt, propose containment
#   <prefix>-approvers   Board.Post Board.Hunt Board.Approve          approve or deny containment (people only)
#   <prefix>-admins      Board.Post Board.Admin                       setup, participants, broker pause, reports
#
# <prefix> is GROUP_PREFIX (default blueboard-<env>). After this, access is managed by group membership (or your
# IGA / access-package process), never by assigning roles to individuals. Agents are not put in groups: give each
# agent identity its roles directly (AGENT_PRINCIPAL_IDS in up.sh, or assign-roles.sh), so they can never inherit
# Board.Approve or Board.Admin.
#
# Notes:
#   - Assigning app roles to groups needs Microsoft Entra ID P1 (or higher). Nested groups are not honoured:
#     put people directly in these groups (a dynamic group or access package is fine).
#   - Roles arrive in the access token, so a membership change takes effect at the person's next token (sign out
#     and in, or within about an hour). To cut access immediately, disable the person on Admin → Participants.
#
# Needs: Groups Administrator or User Administrator (or a tenant that lets users create security groups) to create
# groups, and owner of the enterprise application or Cloud Application Administrator to assign roles.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV}"
require az jq
check_az_context
state_load
: "${BOARD_API_SP_ID:?run infra/entra-app.sh first}"

prefix="${GROUP_PREFIX:-blueboard-$BB_ENV}"
[[ "$prefix" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,40}$ ]] || die "GROUP_PREFIX must be letters, digits, '.', '_' or '-'"

# persona | state key | roles | description
PERSONAS=(
  "analysts|GROUP_ANALYSTS_ID|Board.Post Board.Hunt Board.RequestActions|SOC analysts: work incidents, hunt and propose containment on blueboard ($BB_ENV)"
  "approvers|GROUP_APPROVERS_ID|Board.Post Board.Hunt Board.Approve|SOC leads: approve or deny brokered containment on blueboard ($BB_ENV). People only."
  "admins|GROUP_ADMINS_ID|Board.Post Board.Admin|blueboard ($BB_ENV) administrators: setup, participants, broker pause, reports"
)

ensure_group() { # <state-key> <display-name> <description> -> prints object id
  local key="$1" name="$2" desc="$3" id="${!1:-}" type
  if [[ -n "$id" ]]; then
    type="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/groups/$id?\$select=id,securityEnabled" \
      --query securityEnabled -o tsv 2>/dev/null)" || die "$key=$id is not a group in this tenant"
    [[ "$type" == "true" ]] || die "$key=$id is not a security-enabled group"
    log "using group $id for $name" >&2
    echo "$id"
    return
  fi
  id="$(az ad group list --filter "displayName eq '$name'" --query '[0].id' -o tsv 2>/dev/null || true)"
  if [[ -n "$id" ]]; then
    log "group $name exists ($id)" >&2
  else
    log "creating security group $name" >&2
    id="$(az ad group create --display-name "$name" --mail-nickname "$name" --description "$desc" --query id -o tsv)" ||
      die "could not create $name: needs Groups Administrator or User Administrator. Create it yourself and pass $key=<object-id>"
  fi
  echo "$id"
}

for p in "${PERSONAS[@]}"; do
  IFS='|' read -r persona key roles desc <<<"$p"
  id="$(ensure_group "$key" "$prefix-$persona" "$desc")"
  state_set "$key" "$id"
  # shellcheck disable=SC2086 # roles is a space-separated list on purpose
  "$BB_ROOT/infra/assign-roles.sh" "$id" $roles
  printf -v "$key" '%s' "$id"
done

if [[ "${GROUP_ADD_ME:-}" == "1" ]]; then
  me="$(az ad signed-in-user show --query id -o tsv 2>/dev/null)" || die "GROUP_ADD_ME=1 needs a signed-in user, not a service principal"
  if [[ "$(az ad group member check --group "$GROUP_ADMINS_ID" --member-id "$me" --query value -o tsv)" == "true" ]]; then
    log "you are already in $prefix-admins"
  else
    az ad group member add --group "$GROUP_ADMINS_ID" --member-id "$me"
    log "added you to $prefix-admins (sign out and in to the board to pick up Board.Admin)"
  fi
fi

cat <<EOF

Access groups ready (manage access by membership from now on):
  $prefix-analysts    $GROUP_ANALYSTS_ID   Board.Post Board.Hunt Board.RequestActions
  $prefix-approvers   $GROUP_APPROVERS_ID   Board.Post Board.Hunt Board.Approve
  $prefix-admins      $GROUP_ADMINS_ID   Board.Post Board.Admin

Put at least two people in $prefix-approvers: nobody can approve their own request.
Next: BB_ENV=$BB_ENV ./infra/conditional-access.sh   (Conditional Access baseline for these groups)
EOF
