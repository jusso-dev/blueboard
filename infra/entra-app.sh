#!/usr/bin/env bash
# Creates (or updates) the blueboard API app registration in Microsoft Entra ID. Idempotent.
#
#   BB_ENV=prod ./infra/entra-app.sh                        # create / update the registration
#   BB_ENV=prod WEB_HOSTNAME=<web-host> ./infra/entra-app.sh   # also the web app's sign-in redirect URI
#                                                              # (deploy.sh does this for you)
#
# Needs: Application Administrator, Cloud Application Administrator or Application Developer.
#
# What it sets up:
#   - single-tenant app "blueboard-<env>" with App ID URI api://blueboard-<env>
#   - the five app roles from infra/board-api-app-roles.json (Board.Post … Board.Admin)
#   - one delegated scope, Board.Access, that the web app requests for signed-in people. The web app is a
#     single-page app (public client, auth code + PKCE) on the same registration, pre-authorised for that
#     scope, so there is no client secret and no consent prompt for it
#   - an enterprise application with "assignment required", so only users, groups and agents you
#     assign a role to can get a token at all
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV}"
require az jq
check_az_context
state_load

name="blueboard-${BB_ENV}"
uri="api://${name}"

# The client id saved by an earlier run identifies the registration even if someone renamed it, or another app has
# the same display name. Without one, fall back to the display name.
app_id=""
if [[ -n "${BOARD_API_CLIENT_ID:-}" ]]; then
  app_id="$(az ad app show --id "$BOARD_API_CLIENT_ID" --query appId -o tsv 2>/dev/null)" ||
    die "app registration $BOARD_API_CLIENT_ID from infra/out/$BB_ENV/state.json not found (deleted? clear BOARD_API_CLIENT_ID in state.json to create a new one)"
fi
[[ -n "$app_id" ]] || app_id="$(az ad app list --filter "displayName eq '$name'" --query '[0].appId' -o tsv)"
if [[ -z "$app_id" ]]; then
  log "creating app registration $name"
  app_id="$(az ad app create --display-name "$name" --sign-in-audience AzureADMyOrg --query appId -o tsv)"
else
  log "app registration $name exists ($app_id)"
fi

az ad app update --id "$app_id" --identifier-uris "$uri" --enable-id-token-issuance false --enable-access-token-issuance false
# App roles: fixed ids so re-running never orphans an assignment.
az ad app update --id "$app_id" --app-roles @"$BB_ROOT/infra/board-api-app-roles.json"

obj_id="$(az ad app show --id "$app_id" --query id -o tsv)"
graph_patch() { az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$obj_id" \
  --headers "Content-Type=application/json" --body "$1" -o none; }

# The delegated scope the web app asks for. Fixed id, so re-running is a no-op. v2 access tokens.
scope_id="8c7e7a2a-3c64-4c1e-9a55-0b8f4c1d7b01"
graph_patch "$(jq -n --arg id "$scope_id" '{api: {requestedAccessTokenVersion: 2, oauth2PermissionScopes: [{
  id: $id, value: "Board.Access", type: "User", isEnabled: true,
  adminConsentDisplayName: "Use blueboard", adminConsentDescription: "Read and post on blueboard as the signed-in user, within the board roles they are assigned.",
  userConsentDisplayName: "Use blueboard", userConsentDescription: "Read and post on blueboard as you, within your board roles."}]}}')"
# The web app is this same registration. It requests its own Board.Access scope plus sign-in scopes from
# Microsoft Graph, and nothing else; tenant-wide consent for those is granted below.
graph_patch "$(jq -n --arg app "$app_id" --arg id "$scope_id" '{
  requiredResourceAccess: [{resourceAppId: $app, resourceAccess: [{id: $id, type: "Scope"}]},
   {resourceAppId: "00000003-0000-0000-c000-000000000000", resourceAccess: [
    {id: "37f7f235-527c-4136-accd-4a02d197296e", type: "Scope"},
    {id: "14dad69e-099b-42c9-810b-d002981feec1", type: "Scope"},
    {id: "7427e0e9-2fba-42fe-b0c0-848c9e6a8182", type: "Scope"}]}]}')"

if [[ -n "${WEB_HOSTNAME:-}" ]]; then
  log "single-page app redirect URI https://$WEB_HOSTNAME/redirect"
  # Added to the existing SPA redirect URIs (a custom domain, say), never replacing them.
  spa_uris="$(az ad app show --id "$app_id" --query 'spa.redirectUris' -o json)"
  graph_patch "$(jq -n --arg h "$WEB_HOSTNAME" --argjson have "${spa_uris:-[]}" '{spa: {redirectUris: (($have // []) + ["https://\($h)/redirect"] | unique)},
    web: {redirectUris: [], homePageUrl: "https://\($h)", implicitGrantSettings: {enableIdTokenIssuance: false, enableAccessTokenIssuance: false}}}')"
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

# Consent for Board.Access and the sign-in scopes (openid, profile, offline_access) for everyone in the
# tenant, so nobody sees a consent prompt. Who can sign in at all is still limited by role assignment. Needs Cloud Application Administrator or Application Administrator; skipped with a note otherwise.
if ! az ad app permission admin-consent --id "$app_id" -o none 2>/dev/null; then
  warn "could not grant tenant-wide consent for sign-in scopes: ask a Cloud Application Administrator to run
  az ad app permission admin-consent --id $app_id   (until then, people are asked to consent at first sign-in)"
fi

cat <<EOF

App registration ready.
  client id   $app_id
  audience    $uri
  enterprise  $sp_id (assignment required)

Next: assign people to roles (Entra admin centre → Enterprise applications → $name → Users and groups),
or run: BB_ENV=$BB_ENV ./infra/assign-roles.sh <group-or-user-object-id> Board.Post Board.Hunt Board.RequestActions
EOF
