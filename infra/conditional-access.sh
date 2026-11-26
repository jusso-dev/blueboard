#!/usr/bin/env bash
# Conditional Access baseline for the blueboard app and its access groups (from infra/entra-groups.sh). Idempotent.
#
#   BB_ENV=prod ./infra/conditional-access.sh                          # write the policies as JSON for review
#   BB_ENV=prod CA_EXCLUDE_IDS="<break-glass-1> <break-glass-2>" CA_APPLY=1 ./infra/conditional-access.sh
#                                                                      # create / update them in report-only mode
#   BB_ENV=prod CA_APPLY=1 CA_STATE=on ./infra/conditional-access.sh   # enforce, after reviewing the sign-in logs
#
# Three policies, all scoped to the blueboard app (client id from entra-app.sh):
#   1. blueboard-<env>: phishing-resistant MFA       analysts, approvers, admins
#      (CA_MFA_STRENGTH=mfa for ordinary MFA while people enrol passkeys / Windows Hello / FIDO2)
#   2. blueboard-<env>: compliant device for approvers and admins
#      (compliant or Microsoft Entra hybrid joined: whoever approves containment does it from a managed device)
#   3. blueboard-<env>: 4-hour sign-in for approvers and admins (CA_SIGNIN_HOURS)
#
# CA_EXCLUDE_IDS: object ids of users or groups to exclude from every policy: always your break-glass accounts.
# CA_STATE: report-only (default) or on. Start in report-only and check the sign-in logs' "Report-only" tab first.
#
# Writes infra/out/<env>/conditional-access/*.json either way. Without CA_APPLY=1 nothing in the tenant changes.
# Needs (CA_APPLY=1): Conditional Access Administrator (or Security Administrator), Microsoft Entra ID P1, and a
# Graph token with Policy.ReadWrite.ConditionalAccess; if the Azure CLI token lacks it, the script prints the
# Microsoft Graph PowerShell commands to run instead.
source "$(dirname "$0")/lib.sh"

: "${BB_ENV:?set BB_ENV}"
require az jq
check_az_context
state_load
: "${BOARD_API_CLIENT_ID:?run infra/entra-app.sh first}"
for k in GROUP_ANALYSTS_ID GROUP_APPROVERS_ID GROUP_ADMINS_ID; do
  [[ -n "${!k:-}" ]] || die "$k is not set: run BB_ENV=$BB_ENV ./infra/entra-groups.sh first (or pass the group object ids)"
done

case "${CA_STATE:-report-only}" in
  report-only) state="enabledForReportingButNotEnforced" ;;
  on) state="enabled" ;;
  *) die "CA_STATE must be report-only or on" ;;
esac
# Built-in authentication strengths (the same ids in every tenant).
case "${CA_MFA_STRENGTH:-phishing-resistant}" in
  phishing-resistant) strength="00000000-0000-0000-0000-000000000004" ;;
  passwordless) strength="00000000-0000-0000-0000-000000000003" ;;
  mfa) strength="00000000-0000-0000-0000-000000000002" ;;
  *) die "CA_MFA_STRENGTH must be phishing-resistant, passwordless or mfa" ;;
esac
hours="${CA_SIGNIN_HOURS:-4}"
[[ "$hours" =~ ^[0-9]+$ && "$hours" -ge 1 && "$hours" -le 23 ]] || die "CA_SIGNIN_HOURS must be 1-23"

# Exclusions: split into users and groups (Conditional Access keeps them apart).
ex_users=()
ex_groups=()
for id in ${CA_EXCLUDE_IDS:-}; do
  t="$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/directoryObjects/$id" --query '"@odata.type"' -o tsv 2>/dev/null)" ||
    die "CA_EXCLUDE_IDS: no directory object $id"
  case "$t" in
    "#microsoft.graph.user") ex_users+=("$id") ;;
    "#microsoft.graph.group") ex_groups+=("$id") ;;
    *) die "CA_EXCLUDE_IDS: $id is a $t, not a user or group" ;;
  esac
done
[[ ${#ex_users[@]} -gt 0 || ${#ex_groups[@]} -gt 0 ]] ||
  warn "CA_EXCLUDE_IDS is empty: exclude your break-glass accounts before you set CA_STATE=on"

json_ids() { if [[ $# -gt 0 ]]; then printf '%s\n' "$@" | jq -R . | jq -cs .; else echo '[]'; fi; }
EXU="$(json_ids ${ex_users[@]+"${ex_users[@]}"})"
EXG="$(json_ids ${ex_groups[@]+"${ex_groups[@]}"})"
ALL="$(json_ids "$GROUP_ANALYSTS_ID" "$GROUP_APPROVERS_ID" "$GROUP_ADMINS_ID")"
PRIV="$(json_ids "$GROUP_APPROVERS_ID" "$GROUP_ADMINS_ID")"

policy() { # <name> <include-groups-json> <grant-json|null> <session-json|null>
  jq -n --arg name "$1" --arg state "$state" --arg app "$BOARD_API_CLIENT_ID" \
    --argjson inc "$2" --argjson exu "$EXU" --argjson exg "$EXG" --argjson grant "$3" --argjson session "$4" '{
      displayName: $name, state: $state,
      conditions: {
        clientAppTypes: ["all"],
        applications: {includeApplications: [$app]},
        users: {includeGroups: $inc, excludeUsers: $exu, excludeGroups: $exg}
      },
      grantControls: $grant, sessionControls: $session}'
}

out="$(state_dir)/conditional-access"
mkdir -p "$out"
name="blueboard-$BB_ENV"
policy "$name: phishing-resistant MFA" "$ALL" \
  "$(jq -cn --arg s "$strength" '{operator: "OR", authenticationStrength: {id: $s}}')" null >"$out/1-mfa.json"
policy "$name: compliant device for approvers and admins" "$PRIV" \
  '{"operator":"OR","builtInControls":["compliantDevice","domainJoinedDevice"]}' null >"$out/2-device.json"
policy "$name: $hours-hour sign-in for approvers and admins" "$PRIV" null \
  "$(jq -cn --argjson h "$hours" '{signInFrequency: {isEnabled: true, type: "hours", value: $h, authenticationType: "primaryAndSecondaryAuthentication", frequencyInterval: "timeBased"}}')" \
  >"$out/3-signin-frequency.json"
log "wrote 3 policies to $out (state: ${CA_STATE:-report-only})"

powershell_hint() {
  cat <<EOF

To apply them with Microsoft Graph PowerShell instead (as a Conditional Access Administrator):

  Connect-MgGraph -TenantId $AZURE_TENANT_ID -Scopes Policy.ReadWrite.ConditionalAccess,Policy.Read.All
  Get-ChildItem $out/*.json | ForEach-Object {
    New-MgIdentityConditionalAccessPolicy -BodyParameter (Get-Content \$_ -Raw | ConvertFrom-Json -AsHashtable) }
EOF
}

if [[ "${CA_APPLY:-}" != "1" ]]; then
  log "review the JSON, then re-run with CA_APPLY=1 (report-only) to create them"
  powershell_hint
  exit 0
fi

base="https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
for f in "$out"/*.json; do
  display="$(jq -r .displayName "$f")"
  existing="$(az rest --method GET --uri "$base" --uri-parameters "\$filter=displayName eq '$display'" \
    --query 'value[0].id' -o tsv 2>/dev/null)" || {
    warn "couldn't read Conditional Access policies (needs Conditional Access Administrator and Policy.Read.All)"
    powershell_hint
    exit 1
  }
  if [[ -n "$existing" && "$existing" != "None" ]]; then
    az rest --method PATCH --uri "$base/$existing" --headers "Content-Type=application/json" --body @"$f" -o none ||
      { powershell_hint; die "could not update '$display'"; }
    log "updated: $display"
  else
    az rest --method POST --uri "$base" --headers "Content-Type=application/json" --body @"$f" -o none ||
      { powershell_hint; die "could not create '$display'"; }
    log "created: $display"
  fi
done
log "done. Watch Entra sign-in logs (Conditional Access → Report-only) for a week before CA_STATE=on."
