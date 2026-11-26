# Shared helpers for the infra/*.sh scripts. Source it; don't run it.
# shellcheck shell=bash

set -euo pipefail

BB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Deployment state: infra/out/<env>/state.json (ids, names, URLs and completed steps; never a secret). Git ignores it.
BB_STATE_DIR="${BB_STATE_DIR:-$BB_ROOT/infra/out}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

require() {
  for cmd in "$@"; do command -v "$cmd" >/dev/null 2>&1 || die "missing required tool: $cmd"; done
}

state_dir() {
  local d="$BB_STATE_DIR/${BB_ENV:?set BB_ENV}"
  mkdir -p "$d"
  chmod 700 "$d"
  echo "$d"
}
state_file() { echo "$(state_dir)/state.json"; }

# Keys that could ever hold a secret are refused, so state.json stays safe to share with whoever runs the next step.
state_key_ok() {
  [[ "$1" =~ ^[A-Z][A-Z0-9_]*$ ]] || return 1
  case "$1" in *SECRET* | *PASSWORD* | *TOKEN* | *KEY* | *CREDENTIAL* | *WEBHOOK_URL*) return 1 ;; esac
  return 0
}

state_set() {
  local key="$1" value="$2" file
  state_key_ok "$key" || die "refusing to store $key in deployment state (it could hold a secret)"
  file="$(state_file)"
  [[ -f "$file" ]] || echo '{}' >"$file"
  jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$file" >"$file.tmp"
  mv "$file.tmp" "$file"
}

# Steps finished by up.sh, with when they finished: re-running skips them.
step_done() {
  local file
  file="$(state_file)"
  [[ -f "$file" ]] && jq -e --arg s "$1" '.steps[$s] != null' "$file" >/dev/null
}

step_mark() {
  local file
  file="$(state_file)"
  [[ -f "$file" ]] || echo '{}' >"$file"
  jq --arg s "$1" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.steps[$s] = $t' "$file" >"$file.tmp"
  mv "$file.tmp" "$file"
}

step_clear() {
  local file
  file="$(state_file)"
  [[ -f "$file" ]] || return 0
  jq --arg s "$1" 'del(.steps[$s])' "$file" >"$file.tmp"
  mv "$file.tmp" "$file"
}

# Loads every saved value into the shell (a value already set in the environment wins, even an empty one, so
# FOO= clears a remembered setting). Older checkouts kept the same
# values in .deploy/<env>.env: they are moved into state.json once, and the old file is renamed *.migrated.
state_load() {
  local file legacy line key value
  file="$(state_file)"
  legacy="$BB_ROOT/.deploy/${BB_ENV}.env"
  if [[ -f "$legacy" && ! -f "$file" ]]; then
    log "moving deployment state from .deploy/${BB_ENV}.env to infra/out/${BB_ENV}/state.json"
    echo '{}' >"$file"
    while IFS= read -r line; do
      [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
      # Copy both groups first: state_key_ok runs its own match, which resets BASH_REMATCH.
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
      state_key_ok "$key" || continue
      # The old file used printf %q quoting; ids and host names never need unquoting beyond this.
      value="${value#\'}"
      value="${value%\'}"
      state_set "$key" "$value"
    done <"$legacy"
    mv "$legacy" "$legacy.migrated"
  fi
  [[ -f "$file" ]] || return 0
  while IFS=$'\t' read -r key value; do
    state_key_ok "$key" || continue
    [[ -n "${!key+x}" ]] && continue
    printf -v "$key" '%s' "$value"
    export "${key?}"
  done < <(jq -r 'to_entries[] | select(.key != "steps") | [.key, (.value | tostring)] | @tsv' "$file")
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

# Entra directory roles of the signed-in user (empty for a service principal or without directory read).
my_directory_roles() {
  az rest --method GET --uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?\$select=displayName" \
    --query 'value[].displayName' -o tsv 2>/dev/null || true
}

# Runs the deployed board's setup checks (the API equivalent of `blueboard doctor`) with the operator's own Entra
# token. Needs Board.Admin on the board; prints one line per check. Never fails the caller: it's a report.
run_setup_checks() { # <api-host> <audience>
  local token body status
  [[ -n "$1" && -n "$2" ]] || return 0
  if ! token="$(az account get-access-token --scope "$2/Board.Access" --query accessToken -o tsv 2>/dev/null)"; then
    warn "couldn't get a board token for the setup checks. Consent once with: az login --scope $2/Board.Access (you also need Board.Admin), or open /setup on the board"
    return 0
  fi
  body="$(mktemp)"
  status="$(curl -sS -o "$body" -w '%{http_code}' -H "Authorization: Bearer $token" "https://$1/api/setup?fresh=true" || echo 000)"
  unset token
  case "$status" in
    200)
      jq -r '.checks[] | "\(.status | ascii_upcase | .[0:7] | . + "        " | .[0:8])\(.name): \(.detail)" + (if .status != "ok" and .fix then "\n          How to fix: \(.fix)" else "" end)' "$body"
      jq -e '.ok' "$body" >/dev/null || warn "at least one setup check failed (see above, or open /setup on the board)"
      ;;
    401 | 403) warn "setup checks need the Board.Admin role on the board (assign-roles.sh <your-object-id> Board.Post Board.Admin), then open /setup" ;;
    *) warn "setup checks returned HTTP $status: open https://<web>/setup once the API is up" ;;
  esac
  rm -f "$body"
}

# ── Release packages (BB_RELEASE=vX.Y.Z) ──────────────────────────────────────────────────────────
# Deploying a published release instead of building from source: no .NET SDK, Node or pnpm, so it runs in Azure
# Cloud Shell. Every file is checked against the release's SHA-256 list; with the GitHub CLI signed in, the build
# provenance attestation is verified too.
release_rid() {
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) echo linux-x64 ;;
    Linux-aarch64) echo linux-arm64 ;;
    Darwin-arm64) echo osx-arm64 ;;
    Darwin-x86_64) echo osx-x64 ;;
    *) echo unknown ;;
  esac
}

# Downloads (once) and verifies the release's packages into infra/out/releases/<source>/<tag>; prints that folder.
# <source> is a hash of where the packages come from (repository or mirror URL), so the same tag from a fork or a
# mirror never reuses another source's cached files.
release_fetch() { # <tag>
  local tag="$1" repo="${BB_RELEASE_REPO:-jusso-dev/blueboard}" dir base f want have tools source
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "BB_RELEASE must be a release tag like v1.2.0"
  # BB_RELEASE_URL: a mirror of the release assets (an internal artefact store), <url>/<tag>/<file>.
  base="${BB_RELEASE_URL:+${BB_RELEASE_URL%/}/$tag}"
  base="${base:-https://github.com/$repo/releases/download/$tag}"
  source="$( (printf '%s' "$base" | sha256sum 2>/dev/null || printf '%s' "$base" | shasum -a 256) | cut -c1-12)"
  dir="$BB_STATE_DIR/releases/$source/$tag"
  mkdir -p "$dir"
  tools="blueboard-tools-$tag-$(release_rid).tar.gz"
  for f in "blueboard-$tag.sha256" "blueboard-api-$tag.zip" "blueboard-web-$tag.zip"; do
    [[ -s "$dir/$f" ]] || curl -fsSL --retry 3 -o "$dir/$f" "$base/$f" || die "couldn't download $base/$f (is $tag published?)"
  done
  # The policy-check tool ships from releases after v1.0.0. Optional: without it, deploy.sh uses dotnet if present.
  [[ -s "$dir/$tools" ]] || curl -fsSL --retry 3 -o "$dir/$tools" "$base/$tools" 2>/dev/null || rm -f "$dir/$tools"
  for f in "$dir"/blueboard-*.zip "$dir"/blueboard-tools-*.tar.gz; do
    [[ -f "$f" ]] || continue
    want="$(awk -v n="$(basename "$f")" '$2 == n || $2 == "*"n {print $1}' "$dir/blueboard-$tag.sha256")"
    [[ -n "$want" ]] || die "$(basename "$f") is not listed in blueboard-$tag.sha256"
    have="$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f") | awk '{print $1}')"
    [[ "$want" == "$have" ]] || { rm -f "$f"; die "checksum mismatch for $(basename "$f"): deleted, re-run to download again"; }
  done
  if [[ "${BB_RELEASE_SKIP_ATTESTATION:-}" != "1" ]] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    # Every file that will be deployed or run, the operator CLI included, before anything is extracted.
    for f in "$dir"/blueboard-api-*.zip "$dir"/blueboard-web-*.zip "$dir"/blueboard-tools-*.tar.gz; do
      [[ -f "$f" ]] || continue
      gh attestation verify "$f" --repo "$repo" >/dev/null 2>&1 ||
        die "build provenance for $(basename "$f") did not verify (gh attestation verify $f --repo $repo)"
    done
    log "release $tag: checksums and build provenance verified" >&2
  else
    log "release $tag: checksums verified (sign in to the GitHub CLI to verify build provenance too)" >&2
  fi
  # Unpacked fresh from the archive verified above on every run, never reused: a binary left by an earlier run is
  # removed, and without a verified archive there is no tool (deploy.sh then falls back to the .NET SDK).
  rm -rf "$dir/tools"
  if [[ -f "$dir/$tools" ]]; then
    mkdir -p "$dir/tools" && tar -xzf "$dir/$tools" -C "$dir/tools"
  fi
  echo "$dir"
}
