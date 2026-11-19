#!/usr/bin/env bash
# End-to-end deployment of blueboard to Azure. Idempotent: re-run it to roll out a new version.
#
#   BB_ENV=prod RESOURCE_GROUP=rg-blueboard-prod POLICY_FILE=policy.json ./infra/deploy.sh
#
# Optional:
#   LOCATION=australiaeast  australiaeast (default) or australiasoutheast: every resource goes there
#   WEB_SKU=B1              App Service plan for the web front end
#   INGEST_ENABLED=true     poll Defender for incidents (default true)
#   BROKER_EXECUTE=false    leave false until policy.json is reviewed (see docs/SECURITY.md)
#   POLICY_FILE=…           your reviewed policy (default: policy.example.json)
#   BB_ALLOW_DIRTY=1        deploy from a working tree with uncommitted changes
#   BB_YES=1                skip confirmation prompts (CI)
#
# Steps (each is safe to repeat):
#   1. checks            5. sign-in: the web app's redirect URI on the app registration
#   2. providers + RG    6. build + deploy the C# Function App (migrations run at start-up)
#   3. main.bicep        7. build the React site + its ASP.NET Core host, deploy to the Web App
#   4. outputs           8. health checks, then print the admin-only steps
#
# Needs (docs/DEPLOYMENT.md § Roles): Owner on the resource group (or Contributor + RBAC Administrator),
# owner of the app registration from infra/entra-app.sh, .NET 10 SDK, Node 22 + pnpm.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV (e.g. prod)}"
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
LOCATION="${LOCATION:-australiaeast}"
case "$LOCATION" in australiaeast | australiasoutheast) ;; *) die "LOCATION must be australiaeast or australiasoutheast (blueboard stays in Australia)" ;; esac
WEB_SKU="${WEB_SKU:-B1}"
INGEST_ENABLED="${INGEST_ENABLED:-true}"
BROKER_EXECUTE="${BROKER_EXECUTE:-false}"
PREFIX="${PREFIX:-blueboard}"
POLICY_FILE="${POLICY_FILE:-$BB_ROOT/policy.example.json}"

require az jq git dotnet pnpm zip curl
check_az_context
state_load
: "${BOARD_API_CLIENT_ID:?run BB_ENV=$BB_ENV ./infra/entra-app.sh first}"
: "${BOARD_API_AUDIENCE:?run BB_ENV=$BB_ENV ./infra/entra-app.sh first}"

[[ -f "$POLICY_FILE" ]] || die "POLICY_FILE $POLICY_FILE not found"
jq -e '.protected_users and .protected_devices' "$POLICY_FILE" >/dev/null || die "$POLICY_FILE is not a valid blueboard policy"
if [[ "$BROKER_EXECUTE" == "true" && "$POLICY_FILE" == *policy.example.json ]]; then
  die "BROKER_EXECUTE=true needs your own POLICY_FILE (the example lists contoso.com placeholders)"
fi

cd "$BB_ROOT" || die "cannot cd to $BB_ROOT"
if [[ -n "$(git status --porcelain)" && "${BB_ALLOW_DIRTY:-}" != "1" ]]; then
  die "working tree has uncommitted changes: commit first, or set BB_ALLOW_DIRTY=1"
fi
VERSION="$(git rev-parse --short HEAD)"

if [[ "$BROKER_EXECUTE" == "true" ]]; then
  warn "BROKER_EXECUTE=true: approved actions will isolate devices, disable users and block indicators in your tenant."
  confirm "Have you reviewed policy.json and tested every action in a non-production tenant?"
fi
log "deploying blueboard $VERSION → $RESOURCE_GROUP ($LOCATION) · env $BB_ENV · broker execute: $BROKER_EXECUTE"
confirm "Continue?"

# 2. providers + resource group ----------------------------------------------------------------
for ns in Microsoft.Web Microsoft.Storage Microsoft.DBforPostgreSQL Microsoft.OperationalInsights Microsoft.Insights Microsoft.ManagedIdentity; do
  [[ "$(az provider show -n "$ns" --query registrationState -o tsv)" == "Registered" ]] || {
    log "registering $ns"
    az provider register -n "$ns" --wait
  }
done
az group create -n "$RESOURCE_GROUP" -l "$LOCATION" --tags app=blueboard env="$BB_ENV" -o none

# 3. infrastructure -----------------------------------------------------------------------------
log "infrastructure (Web App, Function App, PostgreSQL, storage, monitoring) in $LOCATION"
out="$(az deployment group create -g "$RESOURCE_GROUP" -n "blueboard-main" -f infra/main.bicep \
  -p location="$LOCATION" webSkuName="$WEB_SKU" namePrefix="$PREFIX" \
  boardApiClientId="$BOARD_API_CLIENT_ID" boardApiAudience="$BOARD_API_AUDIENCE" \
  ingestEnabled="$INGEST_ENABLED" brokerExecute="$BROKER_EXECUTE" policyJson=@"$POLICY_FILE" \
  --query properties.outputs -o json)"

# 4. outputs ------------------------------------------------------------------------------------
WEB_NAME="$(jq -r .webName.value <<<"$out")"
WEB_HOST="$(jq -r .webHostname.value <<<"$out")"
API_NAME="$(jq -r .apiName.value <<<"$out")"
API_HOST="$(jq -r .apiHostname.value <<<"$out")"
API_MI="$(jq -r .apiIdentityPrincipalId.value <<<"$out")"
state_set WEB_HOST "$WEB_HOST"
state_set API_HOST "$API_HOST"
state_set API_MI_PRINCIPAL_ID "$API_MI"

# 5. sign-in --------------------------------------------------------------------------------------
log "sign-in: single-page app redirect URI for https://$WEB_HOST"
WEB_HOSTNAME="$WEB_HOST" "$BB_ROOT/infra/entra-app.sh" >/dev/null ||
  warn "could not update the app registration (needs app owner or Cloud Application Administrator): run BB_ENV=$BB_ENV WEB_HOSTNAME=$WEB_HOST ./infra/entra-app.sh"

# 6. Function App ---------------------------------------------------------------------------------
log "building the C# Function App"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
dotnet publish api/Blueboard.Api -c Release -o "$build/api" --nologo -v q
(cd "$build/api" && zip -qr "$build/api.zip" .)
log "deploying $API_NAME"
az functionapp deploy -g "$RESOURCE_GROUP" -n "$API_NAME" --src-path "$build/api.zip" --type zip -o none

# 7. Web App -------------------------------------------------------------------------------------
log "building the React site and its host"
(cd web && pnpm install --frozen-lockfile --silent && pnpm build)
dotnet publish web/host -c Release -o "$build/web" --nologo -v q
(cd "$build/web" && zip -qr "$build/web.zip" .)
log "deploying $WEB_NAME"
az webapp deploy -g "$RESOURCE_GROUP" -n "$WEB_NAME" --src-path "$build/web.zip" --type zip -o none

# 8. health ---------------------------------------------------------------------------------------
log "health check"
ok=""
for _ in $(seq 1 30); do
  if curl -fsS "https://$API_HOST/api/healthz" >/dev/null 2>&1; then ok=1 && break; fi
  sleep 10
done
[[ "$ok" == "1" ]] || die "https://$API_HOST/api/healthz did not respond (see Application Insights)"
curl -fsS "https://$WEB_HOST/healthz" >/dev/null || die "https://$WEB_HOST/healthz did not respond"

cat <<EOF

blueboard $VERSION is live.
  Web (analysts)   https://$WEB_HOST
  MCP (agents)     https://$API_HOST/runtime/webhooks/mcp   (Entra bearer token for $BOARD_API_AUDIENCE)

Remaining one-time steps (need Entra admin roles, see docs/DEPLOYMENT.md):

  1. Microsoft Graph + Defender permissions for the API (Privileged Role Administrator):
       ./infra/grant-permissions.sh $API_MI $BOARD_API_CLIENT_ID

  2. Assign people to blueboard roles (Cloud Application Administrator or enterprise app owner):
       BB_ENV=$BB_ENV ./infra/assign-roles.sh <analysts-group-id>  Board.Post Board.Hunt Board.RequestActions
       BB_ENV=$BB_ENV ./infra/assign-roles.sh <approvers-group-id> Board.Post Board.Approve
       BB_ENV=$BB_ENV ./infra/assign-roles.sh <admins-group-id>    Board.Post Board.Admin

  3. Agents: give each agent identity Board.Post, Board.Hunt, Board.RequestActions
     (./infra/assign-roles.sh <agent-principal-id> ...) and point it at the MCP URL above.

  4. Review docs/SECURITY.md, then redeploy with your POLICY_FILE and BROKER_EXECUTE=true.
EOF
