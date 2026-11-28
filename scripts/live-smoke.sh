#!/usr/bin/env bash
# Read-only smoke test of a LIVE board as its own agent identity (Entra client credentials with a certificate).
# Never requests actions, posts messages or changes policy. The token stays in memory and is never printed.
#
#   TENANT=<tenant id> CLIENT_ID=<agent app id> AUDIENCE=<api://blueboard-...> CERT_PEM=<key+cert pem> CERT_CRT=<cert> \
#     ./scripts/live-smoke.sh <board-url>
set -uo pipefail

board="${1:?board url}"
api="$board/api"
mcp="$board/runtime/webhooks/mcp"
: "${TENANT:?}" "${CLIENT_ID:?}" "${AUDIENCE:?}" "${CERT_PEM:?}" "${CERT_CRT:?}"
pass=0
fail=0
failed=()
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
ok() { pass=$((pass + 1)); echo "  ok   $*"; }
bad() { fail=$((fail + 1)); failed+=("$*"); echo "  FAIL $*"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# Client assertion (RFC 7523), signed with the agent's private key.
now=$(date +%s)
x5t=$(openssl x509 -in "$CERT_CRT" -outform DER | openssl dgst -sha1 -binary | b64url)
hdr=$(printf '{"alg":"RS256","typ":"JWT","x5t":"%s"}' "$x5t" | b64url)
pl=$(printf '{"aud":"https://login.microsoftonline.com/%s/oauth2/v2.0/token","iss":"%s","sub":"%s","jti":"%s","nbf":%d,"exp":%d}' \
  "$TENANT" "$CLIENT_ID" "$CLIENT_ID" "$(cat /proc/sys/kernel/random/uuid)" "$now" "$((now + 300))" | b64url)
sig=$(printf '%s.%s' "$hdr" "$pl" | openssl dgst -sha256 -sign "$CERT_PEM" | b64url)
token=$(curl -sS -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "scope=$AUDIENCE/.default" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$hdr.$pl.$sig" | jq -r '.access_token // empty')
[[ -n "$token" ]] || { echo "could not get an agent token"; exit 2; }
ok "agent token from Entra (certificate)"

session=""
rpc() {
  local out sid
  out=$(curl -sS -D "$headers" -X POST "$mcp" -H "authorization: Bearer $token" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' ${session:+-H "mcp-session-id: $session"} -d "$1")
  sid=$(tr -d '\r' <"$headers" | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
  [[ -n "$sid" ]] && session="$sid"
  if grep -q '^data:' <<<"$out"; then out=$(printf '%s\n' "$out" | sed -n 's/^data: *//p' | tail -1); fi
  printf '%s' "$out"
}
tool() {
  local args="${2:-}"; [[ -n "$args" ]] || args='{}'
  rpc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$args}}" | jq -r '.result.content[0].text // .error.message // empty'
}
is_json() { jq -e . >/dev/null 2>&1 <<<"$1"; }
rcode() { curl -sS -o /dev/null -w '%{http_code}' -H "authorization: Bearer $token" "$api/$1"; }

check "healthz" curl -fsS "$api/healthz"
check "openapi lists the new routes" test "$(curl -fsS "$api/openapi.json" | jq '[.paths | keys[] | select(test("policy/automation|manage/agents|timeline|exposure|detections|connectors"))] | length')" -ge 8
rpc '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"live-smoke","version":"1"}}}' >/dev/null
rpc '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null || true
me=$(tool whoami)
check "MCP whoami as the agent ($(jq -r .handle <<<"$me"))" test "$(jq -r .kind <<<"$me")" = agent
n=$(rpc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq '.result.tools | length')
check "MCP lists the new tools ($n)" test "$n" -ge 50
kinds=$(tool list_action_types | jq 'if type=="array" then length else ([.kinds[]?, .action_types[]?] | length) end')
check "30 action kinds ($kinds)" test "$kinds" -ge 30
pb=$(tool list_playbooks)
check "playbooks load, incl. emerging-threat ($(jq '.playbooks|length' <<<"$pb"))" test "$(jq '[.playbooks[]|select(.id=="emerging-threat-detection")]|length' <<<"$pb")" -eq 1
inc=$(tool list_incidents '{"limit":1}' | jq -r 'if type=="array" then .[0] else (.incidents[0]) end | (.graph_id // .id) // empty')
if [[ -n "$inc" ]]; then
  check "timeline on a real incident" is_json "$(tool get_incident_timeline "{\"incident\":\"$inc\"}")"
  check "graph on a real incident" is_json "$(tool get_incident_graph "{\"incident\":\"$inc\"}")"
fi
check "agent feedback readable" is_json "$(tool get_agent_feedback)"
check "exposure ranking against the real tenant" is_json "$(tool prioritize_exposures '{"limit":5}')"
check "agent sees automation read-only (can_edit=false)" test "$(curl -sS -H "authorization: Bearer $token" "$api/policy/automation" | jq -r .can_edit)" = false
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "authorization: Bearer $token" -H 'content-type: application/json' -d '{"paused":true,"reason":"agent tries kill switch"}' "$api/policy/automation/pause")
check "agent can't use the kill switch ($code)" test "$code" = 403
check "agent can't read agent budgets ($(rcode manage/agents/budgets))" test "$(rcode manage/agents/budgets)" = 403
check "agent REST reads still work under metering ($(rcode policy))" test "$(rcode policy)" = 200

echo
echo "live-smoke: $pass passed, $fail failed"
((fail == 0)) || { printf '  - %s\n' "${failed[@]}"; exit 1; }
