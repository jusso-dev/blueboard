#!/usr/bin/env bash
# Read-only checks before a deployment. Changes nothing.
#
#   BB_ENV=prod RESOURCE_GROUP=rg-blueboard LOCATION=australiaeast ./infra/preflight.sh
#
# Checks: tools, az sign-in, subscription/tenant, resource providers, your Azure RBAC on the
# subscription or resource group, and whether you can create app registrations in Entra.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV (e.g. prod)}"
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
: "${LOCATION:?set LOCATION (e.g. australiaeast)}"

require az jq
check_az_context

fail=0
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad() {
  printf '  \033[31m✗\033[0m %s\n' "$*"
  fail=1
}
note() { printf '  \033[33m!\033[0m %s\n' "$*"; }

log "Azure CLI extensions"
if az extension show -n containerapp >/dev/null 2>&1; then ok "containerapp extension"; else bad "az extension add -n containerapp"; fi
if az bicep version >/dev/null 2>&1; then ok "bicep"; else bad "az bicep install"; fi

log "Resource providers"
for ns in Microsoft.App Microsoft.ContainerRegistry Microsoft.DBforPostgreSQL Microsoft.OperationalInsights Microsoft.ManagedIdentity Microsoft.CognitiveServices; do
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
    ok "can create role assignments (AcrPull, Cognitive Services User)"
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

log "Docker"
if docker info >/dev/null 2>&1; then ok "docker daemon reachable ($(docker context show))"; else note "docker not running: deploy.sh builds in ACR by default (BB_BUILD=acr)"; fi

echo
if [[ $fail -eq 0 ]]; then log "preflight passed"; else die "preflight found problems (see ✗ above)"; fi
