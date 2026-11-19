# Shared helpers for the infra/*.sh scripts. Source it; don't run it.
# shellcheck shell=bash

set -euo pipefail

BB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BB_STATE_DIR="${BB_STATE_DIR:-$BB_ROOT/.deploy}"
mkdir -p "$BB_STATE_DIR"
chmod 700 "$BB_STATE_DIR"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

require() {
  for cmd in "$@"; do command -v "$cmd" >/dev/null 2>&1 || die "missing required tool: $cmd"; done
}

# Non-secret deployment outputs (ids and names only) are kept in .deploy/<env>.env so later steps can reuse them.
state_file() { echo "$BB_STATE_DIR/${BB_ENV:?set BB_ENV}.env"; }

state_set() {
  local key="$1" value="$2" file
  file="$(state_file)"
  touch "$file"
  grep -v "^${key}=" "$file" >"$file.tmp" || true
  printf '%s=%q\n' "$key" "$value" >>"$file.tmp"
  mv "$file.tmp" "$file"
}

state_load() {
  local file
  file="$(state_file)"
  # shellcheck disable=SC1090
  [[ -f "$file" ]] && source "$file"
  return 0
}

confirm() {
  [[ "${BB_YES:-}" == "1" ]] && return 0
  local reply
  read -r -p "$1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || die "aborted"
}

# Make sure we deploy into the subscription and tenant the operator expects.
check_az_context() {
  local sub tenant user
  sub="$(az account show --query id -o tsv)" || die "run 'az login' first"
  tenant="$(az account show --query tenantId -o tsv)"
  user="$(az account show --query user.name -o tsv)"
  if [[ -n "${AZURE_SUBSCRIPTION_ID:-}" && "$sub" != "$AZURE_SUBSCRIPTION_ID" ]]; then
    die "signed in to subscription $sub but AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID (az account set -s ...)"
  fi
  if [[ -n "${AZURE_TENANT_ID:-}" && "$tenant" != "$AZURE_TENANT_ID" ]]; then
    die "signed in to tenant $tenant but AZURE_TENANT_ID=$AZURE_TENANT_ID"
  fi
  log "subscription $sub · tenant $tenant · as $user"
  AZURE_SUBSCRIPTION_ID="$sub"
  AZURE_TENANT_ID="$tenant"
}
