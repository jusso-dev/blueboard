#!/usr/bin/env bash
# Read-only checks before a deployment. Changes nothing.
#
#   BB_ENV=prod RESOURCE_GROUP=rg-blueboard ./infra/preflight.sh     # LOCATION defaults to australiaeast
#
# Checks: tools, az sign-in, subscription/tenant, resource providers, your Azure RBAC on the
# subscription or resource group, and whether you can create app registrations in Entra.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV (e.g. prod)}"
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
LOCATION="${LOCATION:-australiaeast}"

require az jq
check_az_context

fail=0
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad() {
  printf '  \033[31m✗\033[0m %s\n' "$*"
  fail=1
}
note() { printf '  \033[33m!\033[0m %s\n' "$*"; }

log "Region"
case "$LOCATION" in
  australiaeast | australiasoutheast) ok "$LOCATION (every resource is created here)" ;;
  *) bad "LOCATION must be australiaeast or australiasoutheast: blueboard keeps its data in Australia" ;;
esac

log "Tools"
if az bicep version >/dev/null 2>&1; then ok "bicep"; else bad "az bicep install"; fi
if [[ -n "${BB_RELEASE:-}" ]]; then
  ok "BB_RELEASE=$BB_RELEASE: deploys the release's packages, so the .NET SDK and pnpm aren't needed"
  if curl -fsSIL -o /dev/null "https://github.com/${BB_RELEASE_REPO:-jusso-dev/blueboard}/releases/download/$BB_RELEASE/blueboard-$BB_RELEASE.sha256"; then
    ok "release $BB_RELEASE is published"
  else
    bad "release $BB_RELEASE not found at github.com/${BB_RELEASE_REPO:-jusso-dev/blueboard}/releases"
  fi
else
  if dotnet --list-sdks 2>/dev/null | grep -q "^10\."; then ok ".NET 10 SDK"; else bad "install the .NET 10 SDK (or deploy a release: BB_RELEASE=vX.Y.Z)"; fi
  if command -v pnpm >/dev/null 2>&1; then ok "pnpm"; else bad "install pnpm: corepack enable (or deploy a release: BB_RELEASE=vX.Y.Z)"; fi
fi
if command -v zip >/dev/null 2>&1; then ok "zip"; else bad "install zip"; fi
if [[ "$(az functionapp list-flexconsumption-locations --query "[?name=='$LOCATION'] | length(@)" -o tsv 2>/dev/null)" == "1" ]]; then
  ok "Flex Consumption is available in $LOCATION"
else
  bad "Flex Consumption isn't available in $LOCATION (az functionapp list-flexconsumption-locations)"
fi

log "Resource providers"
providers="Microsoft.Web Microsoft.Storage Microsoft.DBforPostgreSQL Microsoft.OperationalInsights Microsoft.Insights Microsoft.ManagedIdentity"
[[ "${BB_PROFILE:-mvp}" == "production" ]] && providers="$providers Microsoft.Network Microsoft.KeyVault Microsoft.App"
for ns in $providers; do
  state="$(az provider show -n "$ns" --query registrationState -o tsv 2>/dev/null || echo Unknown)"
  if [[ "$state" == "Registered" ]]; then ok "$ns"; else note "$ns is $state: deploy.sh will register it (needs */register/action)"; fi
done

log "Azure RBAC for $(az account show --query user.name -o tsv)"
me="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
if [[ -z "$me" ]]; then
  note "signed in as a service principal: check its roles manually"
else
  sub_scope="/subscriptions/$AZURE_SUBSCRIPTION_ID"
  rg_scope="$sub_scope/resourceGroups/$RESOURCE_GROUP"
  roles="$(az role assignment list --assignee "$me" --all --include-inherited --include-groups \
    --query "[?scope=='$sub_scope' || scope=='$rg_scope'].roleDefinitionName" -o tsv 2>/dev/null | sort -u)"
  while IFS= read -r r; do [[ -n "$r" ]] && printf '    %s\n' "$r"; done <<<"$roles"
  if grep -qxE "Owner|User Access Administrator|Role Based Access Control Administrator" <<<"$roles"; then
    ok "can create role assignments (storage data roles, monitoring publisher)"
  else
    bad "need Owner, or Contributor + Role Based Access Control Administrator, on the resource group"
  fi
  if grep -qxE "Owner|Contributor" <<<"$roles"; then ok "can create resources"; else bad "need Contributor (or Owner) on the resource group"; fi
fi

log "Microsoft Entra"
dir_roles="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?\$select=displayName" \
  --query 'value[].displayName' -o tsv 2>/dev/null || true)"
[[ -z "$dir_roles" ]] || while IFS= read -r r; do printf '    %s\n' "$r"; done <<<"$dir_roles"
if grep -qxE "Global Administrator|Privileged Role Administrator" <<<"$dir_roles"; then
  ok "can grant Graph / Defender application permissions (grant-permissions.sh)"
else
  note "grant-permissions.sh needs a Privileged Role Administrator (or Global Administrator) to run it"
fi
if grep -qxE "Global Administrator|Application Administrator|Cloud Application Administrator|Application Developer" <<<"$dir_roles"; then
  ok "can create the app registration (entra-app.sh)"
else
  can_reg="$(az rest --method GET --uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' \
    --query 'defaultUserRolePermissions.allowedToCreateApps' -o tsv 2>/dev/null || echo false)"
  if [[ "$can_reg" == "true" ]]; then
    ok "users may register apps in this tenant"
  else
    bad "need Application Administrator, Cloud Application Administrator or Application Developer for entra-app.sh"
  fi
fi

echo
if [[ $fail -eq 0 ]]; then log "preflight passed"; else die "preflight found problems (see ✗ above)"; fi
