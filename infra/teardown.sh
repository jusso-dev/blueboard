#!/usr/bin/env bash
# Removes a blueboard environment. Destructive: deletes the resource group (database included)
# and, with DELETE_APP=1, the Entra app registration. Asks twice unless BB_YES=1.
#
#   BB_ENV=dev RESOURCE_GROUP=rg-blueboard-dev ./infra/teardown.sh
#   BB_ENV=dev RESOURCE_GROUP=rg-blueboard-dev DELETE_APP=1 ./infra/teardown.sh
#
# The Graph / Defender permissions granted to the board's managed identity go away with the identity.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV}"
: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
require az
check_az_context
state_load

[[ "$(az group exists -n "$RESOURCE_GROUP")" == "true" ]] || die "resource group $RESOURCE_GROUP does not exist"
tag="$(az group show -n "$RESOURCE_GROUP" --query "tags.app" -o tsv)"
[[ "$tag" == "blueboard" ]] || die "$RESOURCE_GROUP is not tagged app=blueboard: refusing to delete it"

az resource list -g "$RESOURCE_GROUP" --query "[].{type:type,name:name}" -o table
warn "this deletes every resource above, including the PostgreSQL server and its backups"
confirm "Delete resource group $RESOURCE_GROUP?"
if [[ "${BB_YES:-}" != "1" ]]; then
  read -r -p "Type the resource group name to confirm: " typed
  [[ "$typed" == "$RESOURCE_GROUP" ]] || die "aborted"
fi
az group delete -n "$RESOURCE_GROUP" --yes
log "deleted $RESOURCE_GROUP"

if [[ "${DELETE_APP:-}" == "1" && -n "${BOARD_API_CLIENT_ID:-}" ]]; then
  confirm "Delete app registration $BOARD_API_CLIENT_ID (blueboard-$BB_ENV)?"
  az ad app delete --id "$BOARD_API_CLIENT_ID"
  log "deleted app registration"
fi
rm -f "$(state_file)"
