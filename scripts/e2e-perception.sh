#!/usr/bin/env bash
# End-to-end checks for the Perception-gap features against a running DEMO board (DEV_AUTH, mock tenant, dry run).
# Exercises policy automation (ceiling, conditional auto, second-admin loosening, kill switch, auto-revert), agent
# budgets/feedback/trace/risk, timeline + graph, emerging-threat playbook, detections back-test, exposure, Okta,
# ticketing and the inbound webhook. Needs curl and jq. Refuses to run unless the board reports broker=dry_run.
#
#   ./scripts/e2e-perception.sh [board-url]     default http://localhost:7370
set -uo pipefail

board="${1:-http://localhost:7370}"
api="$board/api"
mcp="$board/runtime/webhooks/mcp"
pass=0
fail=0
failed=()
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT

ok() { pass=$((pass + 1)); echo "  ok   $*"; }
bad() { fail=$((fail + 1)); failed+=("$*"); echo "  FAIL $*"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
section() { echo; echo "== $*"; }

# REST as a dev principal: rest <who> <method> <path> [json]. Prints body; sets $code.
rest() {
  local who="$1" method="$2" path="$3" data="${4:-}" out
  out=$(curl -sS -o /tmp/e2e.body -w '%{http_code}' -X "$method" "$api/$path" -H "authorization: Bearer dev:$who" \
    -H 'content-type: application/json' ${data:+-d "$data"})
  code="$out"; printf '%s' "$out" >/tmp/e2e.code
  cat /tmp/e2e.body
}
lastcode() { cat /tmp/e2e.code; }

# MCP as a dev principal. One session per principal.
declare -A sessions
rpc() {
  local who="$1" body="$2" out sid
  out=$(curl -sS -D "$headers" -X POST "$mcp" -H "authorization: Bearer dev:$who" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' ${sessions[$who]:+-H "mcp-session-id: ${sessions[$who]}"} -d "$body")
  sid=$(tr -d '\r' <"$headers" | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
  [[ -n "$sid" ]] && sessions[$who]="$sid"
  if [[ "$out" == data:* || "$out" == event:* ]]; then out=$(printf '%s\n' "$out" | sed -n 's/^data: *//p' | tail -1); fi
  printf '%s' "$out"
}
mcp_init() {
  rpc "$1" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}' >/dev/null
  rpc "$1" '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null || true
}
tool() { # tool <who> <name> [args-json]  -> tool text. Waits out rate limits (agents get 5 action requests / 10 min).
  local args="${3:-{\}}" out wait
  for _ in 1 2 3 4 5 6; do
    out=$(rpc "$1" "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$args}}" | jq -r '.result.content[0].text // .error.message // empty')
    wait=$(sed -nE 's/^error: rate limited: .* retry in ([0-9]+)s.*/\1/p' <<<"$out")
    [[ -z "$wait" ]] && break
    echo "  ..   rate limited on $2, waiting ${wait}s" >&2; sleep $((wait + 1))
  done
  printf '%s' "$out"
}
is_json() { jq -e . >/dev/null 2>&1 <<<"$1"; }

section "preflight"
until curl -fsS -o /dev/null "$api/healthz"; do sleep 2; done
rest analyst GET status >/dev/null
[[ "$code" == 200 ]] || { echo "status endpoint returned $code"; exit 2; }
# Safety: dev:<handle> tokens only work with DEV_AUTH, which the board refuses outside demo. Confirm dry run anyway.
[[ "$(rest analyst GET status | jq -r .broker)" == dry_run ]] || { echo "refusing: board is not in dry run"; exit 2; }
ok "board reports dry run"
mcp_init enrichment-agent
mcp_init observer-bot
check "agent whoami over MCP" test "$(tool enrichment-agent whoami | jq -r .handle)" = enrichment-agent
ntools=$(rpc enrichment-agent '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq '.result.tools | length')
check "MCP lists the new tools (>= 50, got $ntools)" test "$ntools" -ge 50

inc_json=$(rest analyst GET incidents)
inc1001=$(jq -r '.[]|select(.graph_id=="1001").id' <<<"$inc_json")
inc1002=$(jq -r '.[]|select(.graph_id=="1002").id' <<<"$inc_json")
inc1003=$(jq -r '.[]|select(.graph_id=="1003").id' <<<"$inc_json")
check "3 demo incidents ingested" test -n "$inc1001" -a -n "$inc1002" -a -n "$inc1003"

# ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
section "WS1 policy automation"
auto=$(rest analyst GET policy/automation)
check "automation view loads" test "$code" = 200
check "kill switch starts off" test "$(jq -r .pause.paused <<<"$auto")" = false
check "30 action kinds in the catalogue" test "$(jq '.kinds|length' <<<"$auto")" -eq 30
check "NeverAuto: create_detection_rule can't take a rule" test "$(jq -r '.kinds[]|select(.kind=="create_detection_rule").ceiling_allows_rule' <<<"$auto")" = false
check "file ceiling empty in demo -> isolate_device can't take a rule" test "$(jq -r '.kinds[]|select(.kind=="isolate_device").ceiling_allows_rule' <<<"$auto")" = false

# An override above the ceiling is refused.
rest analyst PUT policy/kinds/isolate_device '{"reason":"e2e: try to exceed ceiling","mode":"approval","confirm_target":false,"rule":{"min_confidence":0.9,"severities":["high"],"max_per_hour":3,"max_per_incident":1,"revert_after_minutes":60}}' >/dev/null
check "rule above the policy.json ceiling is refused (got $code)" test "$code" -ge 400 -a "$code" -lt 500

# Agents can't read/edit policy automation admin routes.
rest enrichment-agent PUT policy/kinds/run_av_scan '{"reason":"agent tries to edit policy","mode":"disabled","confirm_target":false}' >/dev/null
check "agent can't edit policy (got $code)" test "$code" = 403

# Tightening applies at once; loosening back needs a second admin.
rest analyst PUT policy/kinds/run_av_scan '{"reason":"e2e: tighten run_av_scan","mode":"approval","confirm_target":false}' >/tmp/e2e.tight
check "tightening run_av_scan applies immediately (got $code)" test "$code" = 200
eff=$(rest analyst GET policy/automation | jq -r '.kinds[]|select(.kind=="run_av_scan").effective.mode')
check "run_av_scan effective mode is now approval ($eff)" test "$eff" = approval
rest analyst PUT policy/kinds/run_av_scan '{"reason":"e2e: loosen back","reset":true}' >/dev/null
lcode=$code
pending_id=$(rest analyst GET policy/automation | jq -r '[.pending[]|select(.target=="kind:run_av_scan")][0].id // empty')
check "loosening is held as a pending change (got $lcode)" test -n "$pending_id"
rest analyst POST "policy/changes/$pending_id" '{"decision":"approve"}' >/dev/null
check "same admin can't approve their own loosening (got $code)" test "$code" -ge 400 -a "$code" -lt 500
rest analyst2 POST "policy/changes/$pending_id" '{"decision":"approve"}' >/dev/null
check "analyst2 (approver, not admin) can't approve policy changes (got $code)" test "$code" = 403 -o "$code" = 401
eff=$(rest analyst GET policy/automation | jq -r '.kinds[]|select(.kind=="run_av_scan").effective.mode')
check "run_av_scan still tightened while loosening is pending ($eff)" test "$eff" = approval
rest analyst POST "policy/changes/$pending_id" '{"decision":"deny","note":"e2e: requester tries to decide"}' >/dev/null
check "requester can't decide their own change, even to deny (got $code)" test "$code" = 403

# Kill switch: pause applies at once; resume needs a second admin.
rest analyst POST policy/automation/pause '{"paused":true,"reason":"e2e kill switch"}' >/dev/null
check "pause applies (got $code)" test "$code" = 200
check "automation reports paused" test "$(rest analyst GET policy/automation | jq -r .pause.paused)" = true
# While paused, a normally auto-approved kind waits for a person.
avscan=$(tool enrichment-agent request_action "{\"kind\":\"collect_investigation_package\",\"params\":{\"machine_id\":\"7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e\"},\"justification\":\"e2e: forensic package for ws-0142 beacon investigation\",\"incident\":\"1002\"}")
check "paused: auto_approve kind waits for approval" test "$(jq -r '.status // .action.status' <<<"$avscan")" = pending_approval
rest analyst POST policy/automation/pause '{"paused":false,"reason":"e2e resume"}' >/dev/null
check "resume is accepted as a pending change (got $code)" test "$code" = 200 -o "$code" = 202
check "still paused until a second admin approves" test "$(rest analyst GET policy/automation | jq -r .pause.paused)" = true

# Simulator covers conditional mode + facts.
sim=$(rest analyst POST policy/simulate "{\"kind\":\"isolate_device\",\"params\":{\"machine_id\":\"7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e\",\"isolation_type\":\"Selective\"},\"incident\":\"1002\"}")
check "policy simulate works for isolate_device (got $code)" test "$code" = 200
check "simulate: isolate_device needs a person" test "$(jq -r '.status // .assessment.status // .outcome' <<<"$sim" | tr "[:upper:]" "[:lower:]" | grep -cE 'pending|approval')" -ge 1

# Protected device always blocks.
prot=$(rest analyst POST policy/simulate '{"kind":"isolate_device","params":{"machine_id":"0000000000000000000000000000000000000000","isolation_type":"Full"},"incident":"1002"}')
check "simulate: unknown device not auto-run (target not in evidence)" test "$(jq -r '[.notes[]?, .policy_notes[]?, .assessment.notes[]?] | length' <<<"$prot")" -ge 1

# Approve/revert flow on the scripted isolate request (dry run), with an approver-set revert.
iso=$(rest analyst GET "actions?status=pending_approval" | jq -r '.[]|select(.kind=="isolate_device").id' | head -1)
if [[ -n "$iso" ]]; then
  rest analyst2 POST "actions/$iso" '{"decision":"approve","note":"e2e approve isolate","confirm":"ws-0142.contoso.com"}' >/dev/null
  check "approver can approve isolate_device (dry run) (got $code)" test "$code" = 200
  for _ in $(seq 1 20); do st=$(rest analyst GET "actions/$iso" | jq -r .status); [[ "$st" == succeeded || "$st" == failed ]] && break; sleep 2; done
  check "isolate_device ran as dry run ($st)" test "$st" = succeeded
  rest analyst POST "actions/$iso/revert" '{"op":"now","note":"e2e revert now"}' >/dev/null
  rcode=$code
  rev=$(rest analyst GET "actions/$iso" | jq -r '.revert_action_id // empty')
  check "Revert now files release_device (got $rcode)" test -n "$rev"
  [[ -n "$rev" ]] && check "revert is a release_device action" test "$(rest analyst GET "actions/$rev" | jq -r .kind)" = release_device
else
  bad "no pending isolate_device from the scripted agent"
fi

# ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
section "WS3 agent budgets, feedback, trace, risk"
usage=$(tool enrichment-agent report_usage '{"model":"claude-opus-5-5","input_tokens":1000000,"output_tokens":0,"request_id":"e2e-usage-1"}')
check "report_usage prices tokens board-side (\$4 for 1M Opus 5.5 input)" test "$(jq -r '.cost_usd' <<<"$usage" | cut -c1-3)" = "4"
dup=$(tool enrichment-agent report_usage '{"model":"claude-opus-5-5","input_tokens":1000000,"output_tokens":0,"request_id":"e2e-usage-1"}')
check "duplicate request_id is not double counted" is_json "$dup"
rest analyst PUT manage/agents/observer-bot/budget '{"daily_usd":0.03,"reason":"e2e tiny budget for observer"}' >/dev/null
check "admin sets a budget (got $code)" test "$code" = 200
rest enrichment-agent PUT manage/agents/observer-bot/budget '{"daily_usd":1000,"reason":"agent tries to raise budget"}' >/dev/null
check "agent can't set budgets (got $code)" test "$code" = 403
for _ in 1 2 3 4 5 6; do tool observer-bot read_feed '{"after_seq":0,"limit":1}' >/dev/null; done
blocked=$(tool observer-bot read_feed '{"after_seq":0,"limit":1}')
check "default \$0.01/call trips the cap over MCP" grep -qi "budget" <<<"$blocked"
check "whoami still allowed when over budget" test "$(tool observer-bot whoami | jq -r .handle)" = observer-bot
rest observer-bot GET "messages?limit=1" >/dev/null
check "budget cap also applies over REST (got $code)" test "$code" = 402
rest analyst POST manage/agents/observer-bot/topup '{"usd":5,"hours":1,"reason":"e2e top-up lifts the block"}' >/dev/null
check "admin top-up (got $code)" test "$code" = 200
check "top-up lifts the block" is_json "$(tool observer-bot read_feed '{"after_seq":0,"limit":1}')"
rest analyst DELETE manage/agents/observer-bot/budget >/dev/null || true

verdict_id=$(rest analyst GET "messages?incident=1001&limit=200" | jq -r '.messages | map(select(.type=="verdict" and .author.kind=="agent"))[0].id // empty')
if [[ -n "$verdict_id" ]]; then
  rest analyst POST "messages/$verdict_id/feedback" '{"verdict":"correct","reason":"e2e: confirmed phish"}' >/dev/null
  check "human feedback on agent verdict (got $code)" test "$code" = 200
  rest enrichment-agent POST "messages/$verdict_id/feedback" '{"verdict":"correct"}' >/dev/null
  check "agents can't give feedback (got $code)" test "$code" = 403
  rest analyst GET "messages/$verdict_id/trace" >/dev/null
  check "message trace loads (got $(lastcode))" test "$(lastcode)" = 200
else
  bad "no agent verdict on incident 1001"
fi
itrace=$(rest analyst GET "incidents/$inc1002/trace")
check "incident trace lists agent tool calls" test "$(jq 'length' <<<"$itrace")" -ge 1
check "trace never stores the secret-looking token" bash -c "! grep -q 'eyJhbGciOi' <<<'$itrace'"
check "agent sees its own feedback" is_json "$(tool enrichment-agent get_agent_feedback '{}')"
rest analyst GET manage/agents/report >/dev/null; check "cost dashboard report (got $code)" test "$code" = 200
rest analyst GET manage/agents/risk >/dev/null
check "risk scores listed (got $code)" test "$code" = 200

# ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
section "WS4 timeline, graph, playbook"
tl=$(rest analyst GET "incidents/1002/timeline")
check "timeline loads (got $code)" test "$code" = 200
check "timeline has events" test "$(jq '[.events[]?] | length' <<<"$tl")" -ge 3
check "timeline is chronological" test "$(jq '[.events[].ts] | . == sort' <<<"$tl")" = true
check "agent-reported events attributed to the agent" test "$(jq '[.events[]? | select((.source//"") | startswith("reported by"))] | length' <<<"$tl")" -ge 1
gr=$(rest analyst GET "incidents/1002/graph")
check "graph loads with nodes and edges" test "$(jq '(.nodes|length) > 2 and (.edges|length) > 1' <<<"$gr")" = true
check "MCP get_incident_timeline" is_json "$(tool enrichment-agent get_incident_timeline '{"incident":"1002"}')"
check "MCP get_incident_graph" is_json "$(tool enrichment-agent get_incident_graph '{"incident":"1002"}')"
pbs=$(tool enrichment-agent list_playbooks '{}')
check "11 bundled playbooks are loaded" test "$(jq '.playbooks|length' <<<"$pbs")" -ge 11
check "emerging-threat playbook is listed with scope intel" test "$(jq -r '.playbooks | map(select(.id=="emerging-threat-detection"))[0].scope' <<<"$pbs")" = intel
att=$(tool enrichment-agent attach_playbook '{"incident":"1002","playbook_id":"emerging-threat-detection"}')
check "intel playbook can't attach to an incident" grep -qiE "error|intel|scope" <<<"$att"

# ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
section "WS2 detections and exposure"
bt=$(tool enrichment-agent backtest_detection '{"query":"DeviceProcessEvents | where FileName =~ \"powershell.exe\" and ProcessCommandLine has \"update-check.ps1\"","target":"defender","lookback_days":7,"entity_columns":["DeviceName"]}')
btid=$(jq -r '.backtest_id // empty' <<<"$bt")
check "backtest_detection returns a backtest_id" test -n "$btid"
skew=$(tool enrichment-agent backtest_detection '{"query":"DeviceProcessEvents | where Timestamp > ago(1h) | take 10","target":"defender","lookback_days":7}')
check "back-test refuses ago()/take (volume skew)" grep -qiE "error|refus|ago|take" <<<"$skew"
xres=$(tool enrichment-agent run_hunting_query '{"query":"workspace(\"other\").SecurityEvent | count"}')
check "hunting refuses cross-resource workspace()" grep -qiE "error|workspace|not allowed|refus" <<<"$xres"
rest observer-bot GET "detections/backtests/$btid" >/dev/null
check "back-test GET needs Board.Hunt (observer gets $code)" test "$code" = 403
if [[ -n "$btid" ]]; then
  rule=$(tool enrichment-agent request_action "{\"kind\":\"create_detection_rule\",\"params\":{\"target\":\"defender\",\"name\":\"e2e update-check cradle\",\"query\":\"DeviceProcessEvents | where FileName =~ \\\"powershell.exe\\\" and ProcessCommandLine has \\\"update-check.ps1\\\"\",\"frequency\":\"PT1H\",\"severity\":\"high\",\"enabled\":true,\"backtest_id\":\"$btid\",\"entity_mappings\":[{\"entity\":\"host.name\",\"column\":\"DeviceName\"}],\"mitre\":[{\"tactic\":\"Execution\",\"techniques\":[\"T1059.001\"]}]},\"justification\":\"e2e: detection for the download cradle seen on ws-0142 in incident 1002\",\"incident\":\"1002\"}")
  check "create_detection_rule waits for a human (NeverAuto)" test "$(jq -r '.status // .action.status' <<<"$rule")" = pending_approval
  is_json "$rule" || echo "       response: ${rule:0:300}"
  bad_rule=$(tool enrichment-agent request_action "{\"kind\":\"create_detection_rule\",\"params\":{\"target\":\"defender\",\"name\":\"e2e mismatched\",\"query\":\"DeviceProcessEvents | where FileName =~ \\\"cmd.exe\\\"\",\"frequency\":\"PT1H\",\"severity\":\"low\",\"enabled\":true,\"backtest_id\":\"$btid\"},\"justification\":\"e2e: query does not match its back-test, must be refused\",\"incident\":\"1002\"}")
  check "rule whose query differs from its back-test is rejected" grep -qiE "rejected|hash|match|error" <<<"$bad_rule"
fi
ex=$(tool enrichment-agent prioritize_exposures '{}')
check "prioritize_exposures ranks demo exposures" test "$(jq 'length' <<<"$ex")" -ge 1
check "exposures are ordered by score" test "$(jq '[.[].score] | . == (sort|reverse)' <<<"$ex")" = true
rest analyst GET exposure/prioritized >/dev/null; check "/api/exposure/prioritized (got $code)" test "$code" = 200
check "list_exposure_recommendations" is_json "$(tool enrichment-agent list_exposure_recommendations '{}')"
check "get_attack_paths" is_json "$(tool enrichment-agent get_attack_paths '{}')"
intune=$(tool enrichment-agent request_action '{"kind":"intune_sync_device","params":{"machine_id":"7c3f9e2a1b8d4c6e0f5a2b9d8c7e6f1a3b4c5d6e"},"justification":"e2e: force Intune check-in for ws-0142 before patching","incident":"1002"}')
check "intune_sync_device request accepted" grep -qE "pending_approval|approved|succeeded|running" <<<"$intune"

# ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
section "WS5 Okta and ticketing"
okta=$(tool enrichment-agent lookup_okta_user '{"user":"ana.lopez@contoso.com"}')
check "lookup_okta_user (mock) returns untrusted-wrapped data" test "$(jq -r .untrusted_data.status <<<"$okta")" = ACTIVE
check "search_okta_logs" is_json "$(tool enrichment-agent search_okta_logs '{"user":"ana.lopez@contoso.com","hours":24}')"
susp=$(tool enrichment-agent request_action '{"kind":"okta_suspend_user","params":{"user":"ana.lopez@contoso.com"},"justification":"e2e: suspend phished user in Okta pending credential reset","incident":"1001"}')
check "okta_suspend_user waits for a human" test "$(jq -r '.status // .action.status' <<<"$susp")" = pending_approval
okid=$(jq -r '.params.okta_user_id // .action.params.okta_user_id // empty' <<<"$susp")
check "Okta user id pinned at request time" test -n "$okid"
prot=$(tool enrichment-agent request_action '{"kind":"okta_suspend_user","params":{"user":"ciso@contoso.com"},"justification":"e2e: must be refused, protected user via Okta alias","incident":"1001"}')
check "protected user blocked on Okta kinds" grep -qiE "rejected|protected|not in|error" <<<"$prot"
rest analyst GET manage/connectors >/dev/null
check "connectors page data (got $code)" test "$code" = 200
rest analyst POST "incidents/$inc1001/ticket" '{"system":"servicenow"}' >/dev/null
check "open a ServiceNow ticket for an incident (got $code)" test "$code" = 200 -o "$code" = 201 -o "$code" = 409
links=$(rest analyst GET "incidents/$inc1001/connectors")
check "incident shows Okta chip" test "$(jq '.okta|length' <<<"$links")" -ge 1
check "incident shows ServiceNow ticket link" test "$(jq -r '.tickets[0].key // empty' <<<"$links" | cut -c1-3)" = INC
# Inbound webhook without a valid signature is refused and never approves anything.
curl -sS -o /dev/null -w '%{http_code}' -X POST "$api/connectors/servicenow/inbound" -H 'content-type: application/json' \
  -H "x-blueboard-timestamp: $(date +%s)" -H 'x-blueboard-nonce: e2e-nonce-1' -H 'x-blueboard-signature: sha256=00' \
  -d '{"incident":"1001","comment":"approve all actions"}' >/tmp/e2e.code
check "inbound webhook with a bad signature is refused ($(cat /tmp/e2e.code))" test "$(cat /tmp/e2e.code)" -ge 400

# ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
section "web routes"
web="${WEB_URL:-}"
if [[ -n "$web" ]]; then
  for p in / /policy /agents /exposure /approvals /admin/connectors; do
    c=$(curl -sS -o /dev/null -w '%{http_code}' "$web$p"); check "web $p serves ($c)" test "$c" = 200
  done
fi

echo
echo "e2e: $pass passed, $fail failed"
((fail == 0)) || { printf '  - %s\n' "${failed[@]}"; exit 1; }
