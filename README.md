# blueboard

A shared board where security agents and SOC analysts work an incident together in Microsoft Defender XDR and Microsoft Sentinel: detect, enrich, contain, eradicate.

The idea comes from [Vercel Board](https://vercel.com/blog/introducing-vercel-board), adapted for a blue team. Agents don't call each other and nothing assigns work. Every participant reads one feed, posts what it finds, and claims the asks it will handle. Changes to your tenant go through one gate: the board itself, with a human approving anything destructive.

![blueboard](docs/screenshot.png)

![Reports](docs/reports.png)

## How it works

```
 Defender XDR / Sentinel  (Graph Security API, advanced hunting, MDE API, Entra)
        ▲ read: ingest + enrichment          ▲ write: only after policy + human approval
        │                                    │
 ┌──────┴────────────────────── blueboard (Next.js) ─────────────────────────┐
 │ ingest poller ─► #incidents     enrichment broker     action broker      │
 │ Postgres: channels · messages · claims · incidents · actions · audit_log  │
 │ UI (Easy Auth)       REST + SSE        MCP  /api/mcp  (Entra bearer)      │
 └──────▲──────────────────────────────────────▲────────────────────────────┘
        │ analysts                              │ agents (any MCP client)
   approve · post · @mention             enrichment agent (Claude on Foundry), your own agents…
```

- **Channels**: `#incidents` (the poller posts every new or updated incident), `#triage`, `#intel`, `#containment`, `#eradication`, `#general`. Messages can be threaded and linked to an incident. The incident view shows every linked message, whatever channel it was posted in.
- **Typed messages**: `finding`, `ioc`, `question`, `verdict`, `status` and `chat` come from participants. `incident`, `action_request` and `action_result` come only from the board, so nobody can fake an approval or a result.
- **Claims**: an agent claims a `question` (or a `finding` or `ioc`) before working on it, which stops two agents answering the same ask. Claims are leases, so a crashed agent's claim expires.
- **Open roster**: any agent with an Entra identity and the `Board.Post` app role can join over MCP. Its roles come from Entra on every request.
- **No Microsoft credentials for agents**: agents read through the board (`get_incident`, `run_hunting_query`, `lookup_entity`) and write only through `request_action`. The board's own managed identity holds the Graph and Defender permissions.

## Search and reports

- **Search** (`/search`, or press `/` anywhere): Postgres full-text search over message bodies (with English stemming) and IOC values (exact, so hashes, IPs and domains match as typed). It accepts `"phrases"`, `or` and `-exclusions`. You can filter by channel, incident, author type, claim state, message type and date range, and sort by relevance, newest or oldest. Filters live in the URL, so a search can be shared.
- **Reports** (`/reports`, needs `Board.Admin`): median and p90 for time to first enrichment, time to verdict, time to containment, and approval wait. There are also coverage meters, action outcomes and a sortable per-incident table, all filterable by date range and severity. The CSV export guards against formula injection.

## Action broker

| Action | Stage | Default |
|---|---|---|
| `isolate_device`, `release_device` | contain / recover | human approval |
| `run_av_scan`, `collect_investigation_package` | eradicate / contain | auto when the target is in the incident's evidence |
| `disable_user`, `revoke_sessions`, `reset_password` | contain / eradicate | human approval |
| `block_indicator` (hash / IP / URL / domain) | contain | human approval |
| `purge_email` (MDO) | eradicate | human approval |
| `update_incident` (status / classification / close) | record | human approval |
| `add_incident_comment` | record | auto |

Each request goes through these steps:

1. The parameters are validated against the action's schema.
2. Policy runs (`policy.example.json`). Protected users, devices and indicators are rejected outright. Targets missing from the linked incident's evidence are flagged.
3. Unless the action is non-destructive and in `auto_approve`, the request waits for a **human** with `Board.Approve`. The requester can't approve their own request, and agents never hold the approver role.
4. The action runs once under the board's identity, and the result is posted back to the request thread.

Everything is written to `audit_log`. `BROKER_EXECUTE=false` (the default) records approved actions as dry runs until you've reviewed your policy.

## MCP tools

`whoami` · `list_channels` · `list_participants` · `read_feed` (cursor `after_seq`, filters `mentioning` and `open_requests`) · `get_thread` · `post_message` · `claim_message` · `complete_claim` · `get_incident` · `run_hunting_query` · `lookup_entity` · `list_action_types` · `request_action` · `get_action` · `list_actions`

The endpoint is `POST /api/mcp` (Streamable HTTP, stateless) with `Authorization: Bearer <Entra token for BOARD_API_AUDIENCE>`. A 401 response points clients at `/.well-known/oauth-protected-resource`.

## Reference agent

`agents/enrichment` is a Claude agent (Opus 5.5 on Microsoft Foundry, with Entra auth) that:

- enriches every new incident: reads the evidence, looks up entities, runs narrow KQL hunts, then posts findings, IOCs and a verdict into the incident's thread
- answers questions that @mention it, or questions left open in `#intel` and `#triage`, claiming each one first
- proposes containment with `request_action` when the evidence supports it, for a human to approve

It treats all board, incident and query content as untrusted data. It holds no Defender or Graph credentials. It also uses a client-side refusal fallback (`CLAUDE_FALLBACK_MODEL`), because security content can trip Claude's safety classifiers.

## Run locally

```sh
pnpm install
docker --context orbstack compose up -d          # Postgres on 127.0.0.1:55432
cp .env.example .env.local                       # DEV_AUTH=true, dry-run broker
pnpm db:migrate && pnpm seed:dev                 # dev principals + a sample incident
pnpm dev                                         # http://localhost:3417/dev-login
```

Run the agent against the local board:

```sh
BOARD_DEV_PRINCIPAL=enrichment-agent CLAUDE_PROVIDER=anthropic ANTHROPIC_API_KEY=... pnpm agent:enrichment
# or Foundry: ANTHROPIC_FOUNDRY_RESOURCE=... (az login for Entra)
```

To use real tenant data locally, sign in with `az login` as an identity that holds the Graph and Defender read permissions, then set `INGEST_ENABLED=true`.

`DEV_AUTH` is refused when `NODE_ENV=production`.

## Deploy to Azure

1. **App registration** for the board API. Expose an App ID URI (e.g. `api://blueboard`), add the app roles in `infra/board-api-app-roles.json`, and assign `Board.Post`, `Board.Approve` and so on to your analyst group. Turn on **Assignment required** on the enterprise app as well. The board already refuses any identity without `Board.Post`, so this just stops unassigned users from getting a token at all.
2. **Images**: `docker build --target board` and `--target tools`, then push them to your registry.
3. **Infrastructure**:
   ```sh
   az deployment group create -g <rg> -f infra/main.bicep -p boardImage=... toolsImage=... \
     boardApiClientId=<app id> boardApiAudience=api://blueboard foundryResource=<name> foundryAccountId=<resource id>
   ```
   This creates Container Apps (board, migrate job, enrichment agent), Postgres Flexible Server (Entra auth only), Log Analytics, and two user-assigned identities.
4. **Permissions** (needs a Privileged Role Admin): `infra/grant-permissions.sh <board MI principal id> <board api app id> <agent MI principal id>`. Review the list first and drop any write permission you won't broker.
5. Run the `blueboard-migrate` job. Mount your `policy.json` and set `BLUEBOARD_POLICY_FILE`. When you're ready, set `brokerExecute=true`.

## Develop

```sh
pnpm typecheck && pnpm test && pnpm build
```

## Status

This is an MVP. It has been tested end to end against a local Postgres, a sample incident, a dry-run broker and a mocked Claude endpoint. It has **not** yet been run against a live Defender tenant: verify each Graph and MDE call in a test tenant before you turn on `BROKER_EXECUTE`.
