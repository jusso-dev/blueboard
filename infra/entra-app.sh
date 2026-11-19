#!/usr/bin/env bash
# Creates (or updates) the blueboard API app registration in Microsoft Entra ID. Idempotent.
#
#   BB_ENV=prod ./infra/entra-app.sh                   # create / update the registration
#   BB_ENV=prod BOARD_FQDN=<fqdn> ./infra/entra-app.sh # also add the sign-in redirect URI (deploy.sh does this)
#
# Needs: Application Administrator, Cloud Application Administrator or Application Developer.
#
# What it sets up:
#   - single-tenant app "blueboard-<env>" with App ID URI api://blueboard-<env>
#   - the five app roles from infra/board-api-app-roles.json (Board.Post … Board.Admin)
#   - ID tokens for Container Apps built-in sign-in (no client secret is created)
#   - an enterprise application with "assignment required", so only users, groups and agents you
#     assign a role to can get a token at all
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV}"
require az jq
check_az_context
state_load

name="blueboard-${BB_ENV}"
uri="api://${name}"

app_id="$(az ad app list --filter "displayName eq '$name'" --query '[0].appId' -o tsv)"
if [[ -z "$app_id" ]]; then
  log "creating app registration $name"
  app_id="$(az ad app create --display-name "$name" --sign-in-audience AzureADMyOrg \
    --enable-id-token-issuance true --query appId -o tsv)"
else
  log "app registration $name exists ($app_id)"
fi

az ad app update --id "$app_id" --identifier-uris "$uri" --enable-id-token-issuance true
# App roles: fixed ids so re-running never orphans an assignment.
az ad app update --id "$app_id" --app-roles @"$BB_ROOT/infra/board-api-app-roles.json"
# v2 access tokens (the board validates the v2 issuer first).
az ad app update --id "$app_id" --set api.requestedAccessTokenVersion=2

if [[ -n "${BOARD_FQDN:-}" ]]; then
  log "redirect URI https://$BOARD_FQDN/.auth/login/aad/callback"
  az ad app update --id "$app_id" --web-redirect-uris "https://$BOARD_FQDN/.auth/login/aad/callback" \
    --web-home-page-url "https://$BOARD_FQDN"
fi

sp_id="$(az ad sp list --filter "appId eq '$app_id'" --query '[0].id' -o tsv)"
if [[ -z "$sp_id" ]]; then
  log "creating enterprise application"
  sp_id="$(az ad sp create --id "$app_id" --query id -o tsv)"
fi
log "assignment required on the enterprise application"
az ad sp update --id "$sp_id" --set appRoleAssignmentRequired=true

state_set BOARD_API_CLIENT_ID "$app_id"
state_set BOARD_API_AUDIENCE "$uri"
state_set BOARD_API_SP_ID "$sp_id"

cat <<EOF

App registration ready.
  client id   $app_id
  audience    $uri
  enterprise  $sp_id (assignment required)

Next: assign people to roles (Entra admin centre → Enterprise applications → $name → Users and groups),
or run: BB_ENV=$BB_ENV ./infra/assign-roles.sh <group-or-user-object-id> Board.Post Board.Hunt Board.RequestActions
EOF
