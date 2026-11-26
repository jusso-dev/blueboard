#!/usr/bin/env bash
# End-to-end deployment of blueboard to Azure. Idempotent: re-run it to roll out a new version.
#
#   BB_ENV=prod RESOURCE_GROUP=rg-blueboard-prod POLICY_FILE=policy.json ./infra/deploy.sh
#
# Optional:
#   LOCATION=australiaeast  australiaeast (default) or australiasoutheast: every resource goes there
#   BB_PROFILE=mvp          mvp (default) or production: private networking, Key Vault, high-availability
#                           PostgreSQL, always-ready API instance, audit log to Sentinel (docs/OPERATIONS.md)
#   WEB_SKU=B1              App Service plan for the web front end (production always uses P0v3)
#   INGEST_ENABLED=true     poll Defender for incidents (default true)
#   BROKER_EXECUTE=false    leave false until policy.json is reviewed (see docs/SECURITY.md)
#   POLICY_FILE=…           your reviewed policy (default: policy.example.json)
#   TI_PWNWATCH_ENABLED, TI_KEV_ENABLED, TI_EPSS_ENABLED, TI_NVD_ENABLED, TI_OSV_ENABLED,
#   TI_SENTINEL_ENABLED, TI_EXPOSURE_ENABLED, TI_MSTI_ENABLED=false   threat intel sources (docs/THREAT_INTEL.md)
#   NVD_API_KEY=…           optional, raises the NVD rate limit
#   SENTINEL_WORKSPACE_ID=… resource id of the Sentinel workspace for publish_ti_indicator
#   ASSIGN_SENTINEL_CONTRIBUTOR=false   give the board Microsoft Sentinel Contributor on that workspace
#   BB_RELEASE=vX.Y.Z       deploy that GitHub release's packages (checksums verified; build provenance too when the
#                           GitHub CLI is signed in) instead of building from source. Needs only az, jq, curl and zip,
#                           so it runs in Azure Cloud Shell. Check out the same tag so main.bicep matches.
#                           BB_RELEASE_REPO=owner/repo for a fork
#   BB_ALLOW_DIRTY=1        deploy from a working tree with uncommitted changes
#   BB_YES=1                skip confirmation prompts (CI)
#   Approver notifications (docs/OPERATIONS.md), all optional. URLs and the HMAC key are passed as secure
#   parameters, never written to state or printed:
#   NOTIFY_TEAMS_WEBHOOK_URL, NOTIFY_WEBHOOK_URL, NOTIFY_WEBHOOK_SECRET, NOTIFY_ALLOWED_HOSTS,
#   NOTIFY_MAIL_FROM, NOTIFY_MAIL_TO, NOTIFY_REMIND_MINUTES (default 15), BOARD_WEB_URL (custom domain)
#   ALERT_EMAILS=…          operational alert recipients, space or comma separated (infra/alerts.bicep; docs/OPERATIONS.md)
#   RETENTION_DAYS=0        data retention: 0 keeps everything; 30 or more removes resolved incidents, threads and finished
#                           actions older than that, daily (audit_log is kept). Preview: blueboard retention --days N
#   DB_RUNTIME_ROLE=true    serve requests as a least-privilege PostgreSQL role (blueboard-id-db); false: the Entra admin
#   EXTRA_CORS_ORIGINS=…    more web origins for the API's CORS list, space or comma separated (a custom domain:
#                           https://board.example.com). The default web host is always allowed
#   Agent webhooks (docs/AGENTS.md), off unless both are set:
#   WEBHOOK_ALLOWED_HOSTS   exact host names agents may subscribe, comma separated
#   WEBHOOK_SIGNING_KEY     base64 of 32+ random bytes (secure parameter; Key Vault in production)
#
# The non-secret settings above are remembered in infra/out/<env>/state.json, so a bare re-run deploys the same
# configuration (set one empty, e.g. NOTIFY_MAIL_TO=, to clear it). Not remembered: BROKER_EXECUTE (dry run unless
# you pass it, so a redeploy never undoes an emergency BROKER_EXECUTE=false), BB_ALLOW_DIRTY, BB_YES, and the secure
# values, which you pass on every run: if one was passed last time and not this time, deploy.sh warns that this
# deploy clears it.
#
# Steps (each is safe to repeat):
#   1. checks            5. sign-in: the web app's redirect URI on the app registration
#   2. providers + RG    6. build + deploy the C# Function App (migrations run at start-up)
#   3. main.bicep        7. build the React site + its ASP.NET Core host, deploy to the Web App
#   4. outputs           8. health and setup checks, then print the admin-only steps
#
# Needs (docs/DEPLOYMENT.md § Roles): Owner on the resource group (or Contributor + RBAC Administrator),
# owner of the app registration from infra/entra-app.sh, .NET 10 SDK, Node 22 + pnpm.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV (e.g. prod)}"
# Saved settings first (the environment wins), so the defaults below apply only to settings never given.
state_load
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
LOCATION="${LOCATION:-australiaeast}"
case "$LOCATION" in australiaeast | australiasoutheast) ;; *) die "LOCATION must be australiaeast or australiasoutheast (blueboard stays in Australia)" ;; esac
WEB_SKU="${WEB_SKU:-B1}"
BB_PROFILE="${BB_PROFILE:-mvp}"
case "$BB_PROFILE" in mvp | production) ;; *) die "BB_PROFILE must be mvp or production" ;; esac
INGEST_ENABLED="${INGEST_ENABLED:-true}"
BROKER_EXECUTE="${BROKER_EXECUTE:-false}"
PREFIX="${PREFIX:-blueboard}"
TI_PARAMS=()
for f in PWNWATCH KEV EPSS NVD OSV SENTINEL EXPOSURE MSTI; do
  v="TI_${f}_ENABLED"
  name="ti$(printf '%s' "$f" | cut -c1)$(printf '%s' "$f" | cut -c2- | tr '[:upper:]' '[:lower:]')Enabled"
  TI_PARAMS+=("$name=${!v:-false}")
done
TI_PARAMS+=("sentinelWorkspaceResourceId=${SENTINEL_WORKSPACE_ID:-}" "assignSentinelContributor=${ASSIGN_SENTINEL_CONTRIBUTOR:-false}")
POLICY_FILE="${POLICY_FILE:-$BB_ROOT/policy.example.json}"
CORS_JSON="$(jq -cn --arg o "${EXTRA_CORS_ORIGINS:-}" '[$o | splits("[ ,]+") | select(length > 0)]')"
ALERT_JSON="$(jq -cn --arg o "${ALERT_EMAILS:-}" '[$o | splits("[ ,]+") | select(length > 0)]')"
DB_RUNTIME_ROLE="${DB_RUNTIME_ROLE:-true}"
RETENTION_DAYS="${RETENTION_DAYS:-0}"
if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || { [[ "$RETENTION_DAYS" -ne 0 ]] && [[ "$RETENTION_DAYS" -lt 30 ]]; }; then
  die "RETENTION_DAYS must be 0 (keep everything) or at least 30"
fi
case "$DB_RUNTIME_ROLE" in true | false) ;; *) die "DB_RUNTIME_ROLE must be true or false" ;; esac

RELEASE_DIR=""
if [[ -n "${BB_RELEASE:-}" ]]; then
  require az jq git zip curl
  RELEASE_DIR="$(release_fetch "$BB_RELEASE")"
  checked_out="$(git -C "$BB_ROOT" describe --tags --exact-match 2>/dev/null || git -C "$BB_ROOT" rev-parse --short HEAD)"
  [[ "$checked_out" == "$BB_RELEASE" ]] ||
    warn "deploying $BB_RELEASE packages with infrastructure from $checked_out: git checkout $BB_RELEASE so they match"
else
  require az jq git dotnet pnpm zip curl
fi
check_az_context
: "${BOARD_API_CLIENT_ID:?run BB_ENV=$BB_ENV ./infra/entra-app.sh first}"
: "${BOARD_API_AUDIENCE:?run BB_ENV=$BB_ENV ./infra/entra-app.sh first}"

[[ -f "$POLICY_FILE" ]] || die "POLICY_FILE $POLICY_FILE not found"
# Saved as an absolute path, so a re-run from another folder finds the same file.
POLICY_FILE="$(cd "$(dirname "$POLICY_FILE")" && pwd)/$(basename "$POLICY_FILE")"
jq -e '.protected_users and .protected_devices' "$POLICY_FILE" >/dev/null || die "$POLICY_FILE is not a valid blueboard policy"
# Same strict parser as the Function App: an unknown key would stop it at start-up, so catch it before deploying.
if [[ -n "$RELEASE_DIR" && -x "$RELEASE_DIR/tools/blueboard" ]]; then
  "$RELEASE_DIR/tools/blueboard" policy-check "$POLICY_FILE" >/dev/null \
    || die "$POLICY_FILE failed the policy check (run: $RELEASE_DIR/tools/blueboard policy-check $POLICY_FILE)"
elif command -v dotnet >/dev/null 2>&1; then
  dotnet run --project "$BB_ROOT/api/Blueboard.Tools" -c Release -- policy-check "$POLICY_FILE" >/dev/null \
    || die "$POLICY_FILE failed the policy check (run: dotnet run --project api/Blueboard.Tools -- policy-check $POLICY_FILE)"
else
  die "can't check $POLICY_FILE: release $BB_RELEASE has no policy-check tool for $(release_rid) and the .NET SDK isn't installed"
fi
if [[ "$BROKER_EXECUTE" == "true" && "$POLICY_FILE" == *policy.example.json ]]; then
  die "BROKER_EXECUTE=true needs your own POLICY_FILE (the example lists contoso.com placeholders)"
fi

cd "$BB_ROOT" || die "cannot cd to $BB_ROOT"
if [[ -n "$(git status --porcelain)" && "${BB_ALLOW_DIRTY:-}" != "1" ]]; then
  die "working tree has uncommitted changes: commit first, or set BB_ALLOW_DIRTY=1"
fi
VERSION="${BB_RELEASE:-$(git rev-parse --short HEAD)}"

if [[ "$BROKER_EXECUTE" == "true" ]]; then
  warn "BROKER_EXECUTE=true: approved actions will isolate devices, disable users and block indicators in your tenant."
  confirm "Have you reviewed policy.json and tested every action in a non-production tenant?"
fi
# Secure settings are never stored. state.json records only short labels for the ones passed last time, so a re-run
# without one warns before this deployment clears it.
secure_label() {
  case "$1" in
    NOTIFY_TEAMS_WEBHOOK_URL) echo teams ;; NOTIFY_WEBHOOK_URL) echo webhook ;; NOTIFY_WEBHOOK_SECRET) echo hmac ;;
    NVD_API_KEY) echo nvd ;; WEBHOOK_SIGNING_KEY) echo signing ;;
  esac
}
passed=""
for v in NOTIFY_TEAMS_WEBHOOK_URL NOTIFY_WEBHOOK_URL NOTIFY_WEBHOOK_SECRET NVD_API_KEY WEBHOOK_SIGNING_KEY; do
  if [[ -n "${!v:-}" ]]; then
    passed="$passed $(secure_label "$v")"
  elif [[ " ${SECURE_SETTINGS_PASSED:-} " == *" $(secure_label "$v") "* ]]; then
    warn "$v was set on the last deploy but not now: this deploy clears it. Pass it again (it is never stored) to keep it."
  fi
done

log "deploying blueboard $VERSION → $RESOURCE_GROUP ($LOCATION) · env $BB_ENV · profile $BB_PROFILE · broker execute: $BROKER_EXECUTE"
confirm "Continue?"

# 2. providers + resource group ----------------------------------------------------------------
providers="Microsoft.Web Microsoft.Storage Microsoft.DBforPostgreSQL Microsoft.OperationalInsights Microsoft.Insights Microsoft.ManagedIdentity"
[[ "$BB_PROFILE" == "production" ]] && providers="$providers Microsoft.Network Microsoft.KeyVault Microsoft.App"
for ns in $providers; do
  [[ "$(az provider show -n "$ns" --query registrationState -o tsv)" == "Registered" ]] || {
    log "registering $ns"
    az provider register -n "$ns" --wait
  }
done
az group create -n "$RESOURCE_GROUP" -l "$LOCATION" --tags app=blueboard env="$BB_ENV" -o none

# 3. infrastructure -----------------------------------------------------------------------------
log "infrastructure ($BB_PROFILE profile: Web App, Function App, PostgreSQL, storage, monitoring) in $LOCATION"
# Secure values go in a private parameters file (mode 600, deleted on exit) so they never appear in the process list.
params="$(mktemp)"
trap 'rm -f "$params"' EXIT
chmod 600 "$params"
jq -n --rawfile policy "$POLICY_FILE" \
  --arg teams "${NOTIFY_TEAMS_WEBHOOK_URL:-}" --arg hook "${NOTIFY_WEBHOOK_URL:-}" --arg hmac "${NOTIFY_WEBHOOK_SECRET:-}" \
  --arg nvd "${NVD_API_KEY:-}" --arg signing "${WEBHOOK_SIGNING_KEY:-}" --argjson cors "$CORS_JSON" --argjson alerts "$ALERT_JSON" \
  '{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#", contentVersion: "1.0.0.0",
    parameters: {policyJson: {value: $policy}, notifyTeamsWebhookUrl: {value: $teams}, notifyWebhookUrl: {value: $hook},
                 notifyWebhookSecret: {value: $hmac}, nvdApiKey: {value: $nvd}, webhookSigningKey: {value: $signing},
                 extraCorsOrigins: {value: $cors}, alertEmails: {value: $alerts}}}' >"$params"
out="$(az deployment group create -g "$RESOURCE_GROUP" -n "blueboard-main" -f infra/main.bicep \
  -p @"$params" \
  -p location="$LOCATION" webSkuName="$WEB_SKU" namePrefix="$PREFIX" profile="$BB_PROFILE" \
  boardApiClientId="$BOARD_API_CLIENT_ID" boardApiAudience="$BOARD_API_AUDIENCE" \
  ingestEnabled="$INGEST_ENABLED" brokerExecute="$BROKER_EXECUTE" dbRuntimeRole="$DB_RUNTIME_ROLE" retentionDays="$RETENTION_DAYS" \
  notifyAllowedHosts="${NOTIFY_ALLOWED_HOSTS:-}" notifyMailFrom="${NOTIFY_MAIL_FROM:-}" notifyMailTo="${NOTIFY_MAIL_TO:-}" \
  notifyRemindMinutes="${NOTIFY_REMIND_MINUTES:-15}" webBaseUrl="${BOARD_WEB_URL:-}" \
  webhookAllowedHosts="${WEBHOOK_ALLOWED_HOSTS:-}" \
  "${TI_PARAMS[@]}" \
  --query properties.outputs -o json)"
rm -f "$params"

# 4. outputs ------------------------------------------------------------------------------------
WEB_NAME="$(jq -r .webName.value <<<"$out")"
WEB_HOST="$(jq -r .webHostname.value <<<"$out")"
API_NAME="$(jq -r .apiName.value <<<"$out")"
API_HOST="$(jq -r .apiHostname.value <<<"$out")"
API_MI="$(jq -r .apiIdentityPrincipalId.value <<<"$out")"
state_set WEB_HOST "$WEB_HOST"
state_set API_HOST "$API_HOST"
state_set API_MI_PRINCIPAL_ID "$API_MI"
state_set WEB_NAME "$WEB_NAME"
state_set API_NAME "$API_NAME"
state_set RESOURCE_GROUP "$RESOURCE_GROUP"
state_set BB_PROFILE "$BB_PROFILE"
# The non-secret settings this deploy used, so a bare re-run deploys the same configuration.
for v in LOCATION WEB_SKU PREFIX INGEST_ENABLED POLICY_FILE SENTINEL_WORKSPACE_ID ASSIGN_SENTINEL_CONTRIBUTOR \
  NOTIFY_ALLOWED_HOSTS NOTIFY_MAIL_FROM NOTIFY_MAIL_TO NOTIFY_REMIND_MINUTES BOARD_WEB_URL EXTRA_CORS_ORIGINS \
  ALERT_EMAILS DB_RUNTIME_ROLE RETENTION_DAYS \
  WEBHOOK_ALLOWED_HOSTS TI_PWNWATCH_ENABLED TI_KEV_ENABLED TI_EPSS_ENABLED TI_NVD_ENABLED TI_OSV_ENABLED \
  TI_SENTINEL_ENABLED TI_EXPOSURE_ENABLED TI_MSTI_ENABLED; do
  state_set "$v" "${!v:-}"
done
state_set SECURE_SETTINGS_PASSED "${passed# }"

# 5. sign-in --------------------------------------------------------------------------------------
log "sign-in: single-page app redirect URI for https://$WEB_HOST"
WEB_HOSTNAME="$WEB_HOST" "$BB_ROOT/infra/entra-app.sh" >/dev/null ||
  warn "could not update the app registration (needs app owner or Cloud Application Administrator): run BB_ENV=$BB_ENV WEB_HOSTNAME=$WEB_HOST ./infra/entra-app.sh"

# 6. Function App ---------------------------------------------------------------------------------
if [[ -n "$RELEASE_DIR" ]]; then
  log "deploying $API_NAME from release $BB_RELEASE"
  az functionapp deploy -g "$RESOURCE_GROUP" -n "$API_NAME" --src-path "$RELEASE_DIR/blueboard-api-$BB_RELEASE.zip" --type zip -o none
  log "deploying $WEB_NAME from release $BB_RELEASE"
  az webapp deploy -g "$RESOURCE_GROUP" -n "$WEB_NAME" --src-path "$RELEASE_DIR/blueboard-web-$BB_RELEASE.zip" --type zip -o none
else
  log "building the C# Function App"
  build="$(mktemp -d)"
  trap 'rm -rf "$build" "$params"' EXIT
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
fi

# 8. health ---------------------------------------------------------------------------------------
log "health check"
ok=""
for _ in $(seq 1 30); do
  if curl -fsS "https://$API_HOST/api/healthz" >/dev/null 2>&1; then ok=1 && break; fi
  sleep 10
done
[[ "$ok" == "1" ]] || die "https://$API_HOST/api/healthz did not respond (see Application Insights)"
curl -fsS "https://$WEB_HOST/healthz" >/dev/null || die "https://$WEB_HOST/healthz did not respond"

# The setup checklist runs inside the Function App with its own identity; the CLI can't use that identity from
# here, so this calls the deployed /api/setup with your token (Board.Admin). Same checks as `blueboard doctor`.
log "setup checks (https://$WEB_HOST/setup)"
run_setup_checks "$API_HOST" "$BOARD_API_AUDIENCE"

cat <<EOF

blueboard $VERSION is live.
  Web (analysts)   https://$WEB_HOST
  MCP (agents)     https://$API_HOST/runtime/webhooks/mcp   (Entra bearer token for $BOARD_API_AUDIENCE)

Remaining one-time steps (need Entra admin roles, see docs/DEPLOYMENT.md):

  1. Microsoft Graph + Defender permissions for the API (Privileged Role Administrator):
       READ_ONLY=1 ./infra/grant-permissions.sh $API_MI $BOARD_API_CLIENT_ID
     (./infra/up.sh does this, or writes infra/out/$BB_ENV/handoff.md for the person who can)

  2. Access groups with their board roles (Groups Administrator + enterprise app owner; up.sh does this):
       BB_ENV=$BB_ENV ./infra/entra-groups.sh       then manage access by group membership
     and the Conditional Access baseline (Conditional Access Administrator, docs/ENTERPRISE-ACCESS.md):
       BB_ENV=$BB_ENV ./infra/conditional-access.sh

  3. Agents: give each agent identity Board.Post, Board.Hunt, Board.RequestActions
     (./infra/assign-roles.sh <agent-principal-id> ...) and point it at the MCP URL above.

  4. Review docs/SECURITY.md, then redeploy with your POLICY_FILE and BROKER_EXECUTE=true.
EOF
