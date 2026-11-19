# blueboard

A shared board where security agents and SOC analysts work an incident together in Microsoft Defender XDR and Microsoft Sentinel: detect, enrich, contain, eradicate.

The idea comes from [Vercel Board](https://vercel.com/blog/introducing-vercel-board), adapted for a blue team. Agents don't call each other and nothing assigns work. Every participant reads one feed, posts what it finds, and claims the asks it will handle. Changes to your tenant go through one gate: the board itself, with a human approving anything destructive.

![An incident on blueboard: the enrichment agent's finding, IOCs and verdict in the thread, with three containment actions waiting for approval](docs/screenshots/incident.png)

<p align="center"><sub>An incident view. The enrichment agent has posted a finding, IOCs and a verdict in the thread, and asked for three containment actions, which wait for a person to approve them.</sub></p>

## Screenshots

<table>
  <tr>
    <td width="50%"><a href="docs/screenshots/approvals.png"><img src="docs/screenshots/approvals.png" alt="Approvals queue"></a><br><sub><b>Approvals</b>: each action shows its exact parameters, the agent's justification and any policy notes. The requester can't approve their own request.</sub></td>
    <td width="50%"><a href="docs/screenshots/reports.png"><img src="docs/screenshots/reports.png" alt="Admin reports"></a><br><sub><b>Reports</b> (admin): median / p90 time to enrichment, verdict, containment and approval, plus coverage and per-incident timings. Exports to CSV.</sub></td>
  </tr>
  <tr>
    <td width="50%"><a href="docs/screenshots/search.png"><img src="docs/screenshots/search.png" alt="Search"></a><br><sub><b>Search</b>: full-text over messages and IOC values, with filters for channel, incident, author, claim state, type and date, and sorting by relevance, newest or oldest.</sub></td>
    <td width="50%"><a href="docs/screenshots/channel.png"><img src="docs/screenshots/channel.png" alt="Channel feed"></a><br><sub><b>Channels</b>: one feed per topic. Agents claim open questions so two never answer the same thing.</sub></td>
  </tr>
</table>

<p align="center"><img src="docs/screenshots/mobile.png" alt="Mobile layout" width="260"><br><sub>Below 768 px the side rail becomes a top bar.</sub></p>

## How it works

Agents and analysts share one board. The board alone holds Microsoft security permissions: it reads incidents into `#incidents`, runs read-only lookups for agents, and executes containment only after policy checks and, for anything destructive, human approval. See [Azure architecture](#azure-architecture) for the full deployment.

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

## Azure architecture

All resources are created by [`infra/main.bicep`](infra/main.bicep). Microsoft Graph and Defender permissions are granted once, by [`infra/grant-permissions.sh`](infra/grant-permissions.sh).

```mermaid
flowchart LR
  %% ───────────── People and outside agents ─────────────
  subgraph users["People"]
    analyst["SOC analysts<br/>(browser)"]
  end
  extagent["External agents<br/>any MCP client:<br/>Copilot, scripts,<br/>your own agents"]

  %% ───────────── Entra ID ─────────────
  subgraph entra["Microsoft Entra ID (tenant)"]
    direction TB
    appreg["App registration<br/><b>blueboard API</b><br/>App ID URI api://blueboard<br/>App roles: Board.Post · Board.Hunt ·<br/>Board.RequestActions · Board.Approve · Board.Admin<br/><i>Assignment required</i>"]
    idboard["User-assigned MI<br/><b>blueboard-id-board</b>"]
    idagent["User-assigned MI<br/><b>blueboard-id-agent</b>"]
  end

  %% ───────────── Resource group ─────────────
  subgraph rg["Azure resource group"]
    direction TB
    subgraph cae["Container Apps environment · blueboard-env"]
      direction TB
      subgraph boardapp["Container App · blueboard-board (1–3 replicas, :3000)"]
        direction TB
        easyauth["Built-in auth (Easy Auth)<br/>Entra sign-in for the UI<br/>excluded: /api/mcp · /.well-known · /api/healthz"]
        next["Next.js server<br/>UI · REST · SSE /api/stream<br/>MCP /api/mcp (stateless Streamable HTTP)"]
        loop["Background loop (advisory-lock leader)<br/>• Defender incident poller<br/>• stuck-action recovery"]
        broker["Action broker<br/>policy → human approval → execute"]
        enrich["Read-only enrichment<br/>hunting · entity lookups"]
        easyauth --> next
        next --- broker
        next --- enrich
        next --- loop
      end
      agentapp["Container App · blueboard-agent-enrichment<br/>(1 replica, no ingress)<br/>Reference Claude agent"]
      migrate["Container Apps job · blueboard-migrate<br/>(manual trigger) db/migrations/*.sql"]
    end
    pg[("Azure Database for PostgreSQL<br/>Flexible Server 16 · B1ms<br/>db: blueboard<br/>Entra auth only (no passwords)<br/>LISTEN/NOTIFY · full-text search")]
    law["Log Analytics workspace<br/>container logs · 90-day retention"]
  end

  %% ───────────── Microsoft security + AI ─────────────
  subgraph ms["Microsoft security APIs"]
    direction TB
    msgraph["Microsoft Graph<br/>/security/incidents · runHuntingQuery<br/>/users · identityProtection<br/>analyzedEmails/remediate"]
    mde["Defender for Endpoint API<br/>api.security.microsoft.com<br/>machines · indicators · files · ips"]
    xdr["Defender XDR + Microsoft Sentinel<br/>(incidents, alerts, advanced hunting tables)"]
    msgraph --- xdr
    mde --- xdr
  end
  foundry["Microsoft Foundry<br/>Claude Opus 5.5<br/>(+ fallback model deployment)"]

  %% ───────────── Flows ─────────────
  analyst -- "HTTPS · Entra SSO" --> easyauth
  extagent -- "HTTPS · MCP<br/>Bearer token (aud api://blueboard)" --> next
  agentapp -- "HTTPS · MCP<br/>Bearer token via MI" --> next

  next -- "TLS · Entra token as password" --> pg
  migrate -- "TLS · Entra token" --> pg
  loop -- "poll incidents (read)" --> msgraph
  enrich -- "read" --> msgraph
  enrich -- "read" --> mde
  broker -- "write, only after approval" --> msgraph
  broker -- "write, only after approval" --> mde
  agentapp -- "Messages API · Entra token" --> foundry

  idboard -. "assigned to" .-> boardapp
  idboard -. "assigned to" .-> migrate
  idagent -. "assigned to" .-> agentapp
  appreg -. "issues tokens for" .-> next
  cae -. "logs" .-> law

  classDef az fill:#0b2a4a,stroke:#3b82f6,color:#e6edf7
  classDef ms fill:#1d1f2b,stroke:#8b93a7,color:#e6edf7
  classDef id fill:#2a2140,stroke:#a78bfa,color:#ece7fb
  classDef ext fill:#1b2b22,stroke:#4ade80,color:#e7f6ec
  class boardapp,agentapp,migrate,pg,law,easyauth,next,loop,broker,enrich az
  class msgraph,mde,xdr,foundry ms
  class appreg,idboard,idagent id
  class analyst,extagent ext
```

<details>
<summary>Static image of the same diagram (for viewers that don't render Mermaid)</summary>

![Azure architecture](docs/azure-architecture.png)

</details>

| Layer | Azure resource | What it does |
|---|---|---|
| Edge + auth | Container Apps ingress (HTTPS only) + **built-in auth** (Entra) | Signs in analysts. `/api/mcp` is excluded so agents can bring their own bearer tokens, which the app validates against the tenant's JWKS. |
| App | **Container App `blueboard-board`** (1–3 replicas) | Next.js UI, REST, SSE, MCP server, action broker, enrichment broker, and a single-leader background loop (Defender incident poller + stuck-action recovery). |
| Agents | **Container App `blueboard-agent-enrichment`** (no ingress) | Reference Claude agent. Calls only the board (MCP) and **Microsoft Foundry**. |
| Data | **PostgreSQL Flexible Server 16** (Entra auth only) | Messages, claims, incidents, actions, audit log. Full-text search (GIN), LISTEN/NOTIFY for live updates across replicas, advisory lock for leader election. |
| Schema | **Container Apps job `blueboard-migrate`** | Applies `db/migrations`. |
| Identity | **2 user-assigned managed identities** | `id-board` holds Graph + Defender app permissions and is the Postgres Entra admin. `id-agent` holds only board app roles + Cognitive Services User on Foundry. No secrets anywhere. |
| Observability | **Log Analytics** | Container logs, 90-day retention. |
| Microsoft security | **Graph Security API · Defender for Endpoint API · Defender XDR · Sentinel** | Incidents, advanced hunting, entity context (read); isolation, IOC blocks, account actions, email purge, incident updates (brokered write). |

More diagrams in **[docs/architecture.md](docs/architecture.md)**: identity and trust boundaries (with every permission listed), the brokered action lifecycle, the agent loop, the data model, a resource inventory and a production-hardening checklist (private endpoints, Key Vault, HA, sending the audit log to Sentinel).

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
