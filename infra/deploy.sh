#!/usr/bin/env bash
# End-to-end deployment of blueboard to Azure. Idempotent: re-run it to roll out a new version.
#
#   BB_ENV=prod RESOURCE_GROUP=rg-blueboard-prod LOCATION=australiaeast \
#   FOUNDRY_RESOURCE=my-foundry FOUNDRY_ACCOUNT_ID=/subscriptions/.../accounts/my-foundry \
#     ./infra/deploy.sh
#
# Optional:
#   IMAGE_TAG=<tag>        defaults to the git short SHA (refuses a dirty tree unless BB_ALLOW_DIRTY=1)
#   BB_BUILD=acr|docker    build in Azure Container Registry (default) or with local docker + push
#   INGEST_ENABLED=true    poll Defender for incidents (default true)
#   BROKER_EXECUTE=false   leave false until policy.json is reviewed (see docs/SECURITY.md)
#   POLICY_FILE=policy.json  your reviewed policy (default: policy.example.json); mounted read-only
#   BB_YES=1               skip confirmation prompts (CI)
#
# Steps (each is safe to repeat):
#   1. preflight context    6. Entra redirect URI for the board's FQDN
#   2. resource providers   7. run the migration job and wait for it
#   3. foundation.bicep     8. health check
#   4. build + push images  9. print the admin steps that need Entra privileges (grant-permissions.sh)
#   5. main.bicep
#
# Needs (see docs/DEPLOYMENT.md § Roles): Owner on the resource group (or Contributor + RBAC
# Administrator), and an app registration from infra/entra-app.sh.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV (e.g. prod)}"
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
: "${LOCATION:?set LOCATION}"
: "${FOUNDRY_RESOURCE:?set FOUNDRY_RESOURCE (Foundry resource name hosting the Claude deployments)}"
FOUNDRY_ACCOUNT_ID="${FOUNDRY_ACCOUNT_ID:-}"
INGEST_ENABLED="${INGEST_ENABLED:-true}"
BROKER_EXECUTE="${BROKER_EXECUTE:-false}"
BB_BUILD="${BB_BUILD:-acr}"
PREFIX="${PREFIX:-blueboard}"
POLICY_FILE="${POLICY_FILE:-$BB_ROOT/policy.example.json}"
[[ -f "$POLICY_FILE" ]] || die "POLICY_FILE $POLICY_FILE not found"
jq -e '.protected_users and .protected_devices' "$POLICY_FILE" >/dev/null || die "$POLICY_FILE is not a valid blueboard policy"

require az jq git
check_az_context
state_load
: "${BOARD_API_CLIENT_ID:?run BB_ENV=$BB_ENV ./infra/entra-app.sh first}"
: "${BOARD_API_AUDIENCE:?run BB_ENV=$BB_ENV ./infra/entra-app.sh first}"

cd "$BB_ROOT" || die "cannot cd to $BB_ROOT"
if [[ -z "${IMAGE_TAG:-}" ]]; then
  if [[ -n "$(git status --porcelain)" && "${BB_ALLOW_DIRTY:-}" != "1" ]]; then
    die "working tree has uncommitted changes: commit first, or set IMAGE_TAG / BB_ALLOW_DIRTY=1"
  fi
  IMAGE_TAG="$(git rev-parse --short HEAD)"
fi

if [[ "$BROKER_EXECUTE" == "true" && "$POLICY_FILE" == *policy.example.json ]]; then
  die "BROKER_EXECUTE=true needs your own POLICY_FILE (the example lists contoso.com placeholders)"
fi
if [[ "$BROKER_EXECUTE" == "true" ]]; then
  warn "BROKER_EXECUTE=true: approved actions will isolate devices, disable users and block indicators in your tenant."
  confirm "Have you reviewed policy.json and tested every action in a non-production tenant?"
fi

echo
log "deploying blueboard $IMAGE_TAG → $RESOURCE_GROUP ($LOCATION) · env $BB_ENV · broker execute: $BROKER_EXECUTE"
confirm "Continue?"

# 2. providers ----------------------------------------------------------------------------------
for ns in Microsoft.App Microsoft.ContainerRegistry Microsoft.DBforPostgreSQL Microsoft.OperationalInsights Microsoft.ManagedIdentity Microsoft.CognitiveServices; do
  [[ "$(az provider show -n "$ns" --query registrationState -o tsv)" == "Registered" ]] || {
    log "registering $ns"
    az provider register -n "$ns" --wait
  }
done

# 3. foundation ---------------------------------------------------------------------------------
az group create -n "$RESOURCE_GROUP" -l "$LOCATION" --tags app=blueboard env="$BB_ENV" -o none
log "foundation (registry + managed identities)"
found="$(az deployment group create -g "$RESOURCE_GROUP" -n "blueboard-foundation" \
  -f infra/foundation.bicep -p location="$LOCATION" namePrefix="$PREFIX" --query properties.outputs -o json)"
ACR_NAME="$(jq -r .acrName.value <<<"$found")"
ACR_SERVER="$(jq -r .acrLoginServer.value <<<"$found")"
BOARD_MI="$(jq -r .boardIdentityPrincipalId.value <<<"$found")"
AGENT_MI="$(jq -r .agentIdentityPrincipalId.value <<<"$found")"
state_set ACR_NAME "$ACR_NAME"
state_set BOARD_MI_PRINCIPAL_ID "$BOARD_MI"
state_set AGENT_MI_PRINCIPAL_ID "$AGENT_MI"

# 4. images -------------------------------------------------------------------------------------
BOARD_IMAGE="$ACR_SERVER/blueboard-board:$IMAGE_TAG"
TOOLS_IMAGE="$ACR_SERVER/blueboard-tools:$IMAGE_TAG"
if [[ "$BB_BUILD" == "acr" ]]; then
  log "building images in ACR (no local docker needed)"
  az acr build -r "$ACR_NAME" -t "blueboard-board:$IMAGE_TAG" --target board --platform linux/amd64 . -o none
  az acr build -r "$ACR_NAME" -t "blueboard-tools:$IMAGE_TAG" --target tools --platform linux/amd64 . -o none
else
  require docker
  log "building images locally (docker context: $(docker context show)) and pushing"
  az acr login -n "$ACR_NAME"
  docker build --platform linux/amd64 --target board -t "$BOARD_IMAGE" .
  docker build --platform linux/amd64 --target tools -t "$TOOLS_IMAGE" .
  docker push "$BOARD_IMAGE"
  docker push "$TOOLS_IMAGE"
fi

# 5. apps ---------------------------------------------------------------------------------------
log "main deployment (Container Apps, PostgreSQL, Log Analytics)"
main="$(az deployment group create -g "$RESOURCE_GROUP" -n "blueboard-main" -f infra/main.bicep \
  -p location="$LOCATION" namePrefix="$PREFIX" acrLoginServer="$ACR_SERVER" \
  boardImage="$BOARD_IMAGE" toolsImage="$TOOLS_IMAGE" \
  boardApiClientId="$BOARD_API_CLIENT_ID" boardApiAudience="$BOARD_API_AUDIENCE" \
  foundryResource="$FOUNDRY_RESOURCE" foundryAccountId="$FOUNDRY_ACCOUNT_ID" \
  ingestEnabled="$INGEST_ENABLED" brokerExecute="$BROKER_EXECUTE" policyJson=@"$POLICY_FILE" \
  --query properties.outputs -o json)"
BOARD_FQDN="$(jq -r .boardFqdn.value <<<"$main")"
JOB="$(jq -r .migrateJobName.value <<<"$main")"
state_set BOARD_FQDN "$BOARD_FQDN"

# 6. sign-in redirect ---------------------------------------------------------------------------
log "sign-in redirect for https://$BOARD_FQDN"
az ad app update --id "$BOARD_API_CLIENT_ID" --web-redirect-uris "https://$BOARD_FQDN/.auth/login/aad/callback" \
  --web-home-page-url "https://$BOARD_FQDN" ||
  warn "could not update the app registration (needs app owner / Application Administrator): add the redirect URI by hand"

# 7. migrations ---------------------------------------------------------------------------------
log "running database migrations ($JOB)"
exec_name="$(az containerapp job start -g "$RESOURCE_GROUP" -n "$JOB" --query name -o tsv)"
for _ in $(seq 1 60); do
  status="$(az containerapp job execution show -g "$RESOURCE_GROUP" -n "$JOB" --job-execution-name "$exec_name" \
    --query properties.status -o tsv 2>/dev/null || echo Unknown)"
  case "$status" in
    Succeeded) log "migrations applied" && break ;;
    Failed | Stopped | Degraded) die "migration job $exec_name: $status (see Log Analytics: ContainerAppConsoleLogs_CL)" ;;
  esac
  sleep 10
done
[[ "$status" == "Succeeded" ]] || die "migration job did not finish in 10 minutes"

# 8. health -------------------------------------------------------------------------------------
log "health check"
for _ in $(seq 1 30); do
  if curl -fsS "https://$BOARD_FQDN/api/healthz" >/dev/null 2>&1; then ok=1 && break; fi
  sleep 10
done
[[ "${ok:-}" == "1" ]] || die "https://$BOARD_FQDN/api/healthz did not respond"

# 9. hand-off -----------------------------------------------------------------------------------
cat <<EOF

blueboard $IMAGE_TAG is running at https://$BOARD_FQDN

Remaining one-time steps (need Entra admin roles, see docs/DEPLOYMENT.md):

  1. Microsoft Graph + Defender permissions for the board (Privileged Role Administrator):
       ./infra/grant-permissions.sh $BOARD_MI $BOARD_API_CLIENT_ID $AGENT_MI

  2. Assign people to blueboard roles (Application Administrator or enterprise app owner):
       BB_ENV=$BB_ENV ./infra/assign-roles.sh <analysts-group-id>  Board.Post Board.Hunt Board.RequestActions
       BB_ENV=$BB_ENV ./infra/assign-roles.sh <approvers-group-id> Board.Post Board.Approve
       BB_ENV=$BB_ENV ./infra/assign-roles.sh <admins-group-id>    Board.Post Board.Admin

  3. Foundry: deploy $FOUNDRY_RESOURCE models claude-opus-5-5 and the fallback model.
     ${FOUNDRY_ACCOUNT_ID:+(Cognitive Services User for the agent identity was assigned by Bicep.)}${FOUNDRY_ACCOUNT_ID:-Assign "Cognitive Services User" on the Foundry resource to principal $AGENT_MI.}

  4. Review docs/SECURITY.md, then mount policy.json and redeploy with BROKER_EXECUTE=true.
EOF
