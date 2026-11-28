#!/usr/bin/env bash
# Checks a running demo (./scripts/demo.sh up) over MCP the way an agent would: three incidents ingested from the
# mock tenant, each with the scripted agent's finding, ioc and verdict, and at least one action per incident
# waiting for approval with policy notes. Used by the demo-smoke CI job. Needs curl and jq.
#
#   ./scripts/demo-smoke.sh [board-url]     default http://localhost:7370
set -euo pipefail

board="${1:-http://localhost:7370}"
mcp="$board/runtime/webhooks/mcp"
token="Bearer dev:enrichment-agent"
deadline=$((SECONDS + ${SMOKE_TIMEOUT:-180}))
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT

die() { echo "demo-smoke: $*" >&2; exit 1; }

# One JSON-RPC call; prints the result object. The MCP endpoint may answer as JSON or as one SSE event.
rpc() {
  local body="$1" out
  out=$(curl -fsS -D "$headers" -X POST "$mcp" \
    -H "authorization: $token" -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
    ${session:+-H "mcp-session-id: $session"} -d "$body")
  local sid
  sid=$(tr -d '\r' <"$headers" | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
  [[ -n "$sid" ]] && session="$sid"
  if [[ "$out" == data:* || "$out" == event:* ]]; then out=$(printf '%s\n' "$out" | sed -n 's/^data: *//p' | tail -1); fi
  printf '%s' "$out"
}

# Calls a tool and prints its text result (board tools return JSON text, or "error: ...").
tool() {
  local name="$1" args="{}"
  [[ $# -ge 2 ]] && args="$2"
  rpc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"$name\",\"arguments\":$args}}" | jq -r '.result.content[0].text'
}

echo "waiting for $board/api/healthz"
until curl -fsS -o /dev/null "$board/api/healthz"; do
  [[ $SECONDS -lt $deadline ]] || die "board not healthy"
  sleep 3
done

session=""
rpc '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo-smoke","version":"1"}}}' >/dev/null
rpc '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null || true

me=$(tool whoami | jq -r .handle)
[[ "$me" == "enrichment-agent" ]] || die "whoami returned '$me'"

while :; do
  feed=$(tool read_feed '{"after_seq":0,"limit":200}')
  actions_ok=1
  incidents=$(printf '%s' "$feed" | jq '[.messages[] | select(.type=="incident" and .parent_id==null)] | length')
  for t in finding ioc verdict action_request; do
    n=$(printf '%s' "$feed" | jq --arg t "$t" '[.messages[] | select(.type==$t) | .incident_graph_id] | unique | length')
    [[ "$n" -ge 3 ]] || actions_ok=0
  done
  if [[ "$incidents" -ge 3 && "$actions_ok" -eq 1 ]]; then break; fi
  [[ $SECONDS -lt $deadline ]] || die "after ${SMOKE_TIMEOUT:-180}s: $incidents incidents; each needs a finding, ioc, verdict and action request"
  sleep 3
done
echo "ok: $incidents incidents, each with a finding, ioc, verdict and action request"

# Pending actions, over MCP: each action_request message names its action; get_action gives its live status.
pending=0
for id in $(printf '%s' "$feed" | jq -r '.messages[] | select(.type=="action_request") | .payload.action_id'); do
  [[ "$(tool get_action "{\"action_id\":\"$id\"}" | jq -r .status)" == "pending_approval" ]] && pending=$((pending + 1))
done
per_incident=$(printf '%s' "$feed" | jq '[.messages[] | select(.type=="action_request" and .payload.status=="pending_approval") | .incident_graph_id] | unique | length')
[[ "$pending" -ge 3 && "$per_incident" -ge 3 ]] || die "expected pending actions on 3 incidents, got $pending pending on $per_incident"
echo "ok: $pending actions pending approval across $per_incident incidents"

# Enrichment went through the board (and so the audit log), answered by the mock tenant.
lookup=$(tool lookup_entity '{"kind":"user","value":"ana.lopez@contoso.com"}')
[[ "$(printf '%s' "$lookup" | jq -r .user.displayName)" == "Ana Lopez" ]] || die "lookup_entity did not return fixture data: $lookup"
echo "ok: lookup_entity returns fixture data"

# Okta connector (mocked): read-only context for the same user, wrapped as untrusted data.
okta=$(tool lookup_okta_user '{"user":"ana.lopez@contoso.com"}')
[[ "$(printf '%s' "$okta" | jq -r .untrusted_data.status)" == "ACTIVE" ]] || die "lookup_okta_user did not return mock Okta data: $okta"
echo "ok: lookup_okta_user returns mock Okta data"
echo "demo-smoke passed"
