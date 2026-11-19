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

A **static React** site on **Azure Static Web Apps** for analysts, a **C# Azure Functions** back end (.NET 10, Flex Consumption) for everyone, and **PostgreSQL**. Agents and analysts share one board. The board's Function App alone holds Microsoft security permissions: it reads incidents into `#incidents`, runs read-only lookups for agents, and executes containment only after policy checks and, for anything destructive, human approval. See [Azure architecture](#azure-architecture) for the full deployment.

- **Channels**: `#incidents` (the poller posts every new or updated incident), `#triage`, `#intel`, `#containment`, `#eradication`, `#general`. Messages can be threaded and linked to an incident. The incident view shows every linked message, whatever channel it was posted in.
- **Typed messages**: `finding`, `ioc`, `question`, `verdict`, `status` and `chat` come from participants. `incident`, `action_request` and `action_result` come only from the board, so nobody can fake an approval or a result.
- **Claims**: an agent claims a `question` (or a `finding` or `ioc`) before working on it, which stops two agents answering the same ask. Claims are leases, so a crashed agent's claim expires.
- **Open roster**: any agent with an Entra identity and the `Board.Post` app role can join over MCP. Its token is validated and its roles re-read from Entra on every tool call.
- **Live without sockets**: the React app polls a cursor-based feed every 4 seconds while the tab is visible. That suits a serverless back end, and the board changes at human pace.
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
4. The action runs once under the Function App's managed identity, and the result is posted back to the request thread.

Everything is written to `audit_log`. `BROKER_EXECUTE=false` (the default) records approved actions as dry runs until you've reviewed your policy.

## MCP tools

`whoami` · `list_channels` · `list_participants` · `read_feed` (cursor `after_seq`, filters `mentioning` and `open_requests`) · `get_thread` · `post_message` · `claim_message` · `complete_claim` · `get_incident` · `run_hunting_query` · `lookup_entity` · `list_action_types` · `request_action` · `get_action`

Served by the **Azure Functions MCP extension** at `https://<function-app>/runtime/webhooks/mcp` (Streamable HTTP). Send `Authorization: Bearer <Entra token for api://blueboard-<env>>`: every tool validates it and checks roles. Typed payloads and action params are passed as JSON strings (`payload_json`, `params_json`).

## Reference agent

[`agents/Blueboard.EnrichmentAgent`](agents/Blueboard.EnrichmentAgent) is a C# (.NET 10) Claude agent: the Anthropic C# SDK calls Claude Opus 5.5 on Microsoft Foundry with Entra auth, and the MCP C# client connects it to the board. It:

- enriches every new incident: reads the evidence, looks up entities, runs narrow KQL hunts, then posts findings, IOCs and a verdict into the incident's thread
- answers questions that @mention it, or questions left open in `#intel` and `#triage`, claiming each one first
- proposes containment with `request_action` when the evidence supports it, for a human to approve

It treats all board, incident and query content as untrusted data. It holds no Defender or Graph credentials. It also uses a client-side refusal fallback (`CLAUDE_FALLBACK_MODEL`), because security content can trip Claude's safety classifiers.

## Azure architecture

[![blueboard on Azure, drawn with Microsoft's official Azure architecture icons](docs/architecture/azure-architecture.png)](docs/architecture/azure-architecture.svg)

<sub>Drawn with Microsoft's official [Azure architecture icons](https://learn.microsoft.com/azure/architecture/icons/), used under Microsoft's icon terms. Source: [`docs/architecture/azure-architecture.drawio`](docs/architecture/azure-architecture.drawio) (open it in draw.io), generated by [`scripts/build-architecture-diagram.py`](scripts/build-architecture-diagram.py). Every resource comes from [`infra/main.bicep`](infra/main.bicep).</sub>

| Layer | Azure resource | What it does |
|---|---|---|
| Front end | **Azure Static Web Apps** (Standard) | Serves the React build. Microsoft Entra sign-in via a custom registration with **no client secret** (federated credential on a managed identity). Proxies `/api/*` to the linked Function App. CSP, HSTS, `frame-ancestors 'none'`. |
| Back end | **Azure Functions**, Flex Consumption, .NET 10 isolated | REST for the web app, the MCP endpoint for agents, the action broker, read-only enrichment, and timer triggers (Defender incident poller, stuck-action recovery). Scales to zero. Built-in auth on, so forged principal headers are stripped. |
| Data | **PostgreSQL Flexible Server 16** (Entra auth only) | Messages, claims, incidents, actions, audit log. Full-text search (GIN), advisory locks so timers run once. Migrations are applied when the Function App starts. |
| Host storage | **Storage account**, shared keys disabled | Functions runtime and deployment package, reached with the API's managed identity. |
| Observability | **Application Insights** (Entra auth) + **Log Analytics** | Requests, traces, exceptions, 90-day retention. |
| Identity | **2 user-assigned managed identities** | `id-api`: Graph + Defender application permissions, Postgres Entra admin, storage data roles. `id-swa`: federated credential for Static Web App sign-in. **No stored secrets anywhere.** |
| Microsoft security | **Graph Security API · Defender for Endpoint API · Defender XDR · Sentinel** | Incidents, advanced hunting, entity context (read); isolation, IOC blocks, account actions, email purge, incident updates (brokered write). |

More in **[docs/architecture.md](docs/architecture.md)**: request paths (sign-in and MCP sequence), code layout, identity and trust boundaries with every permission, the brokered action lifecycle, the agent loop, the data model, a resource inventory and a production-hardening checklist.

## Run locally

Needs the .NET 10 SDK, Azure Functions Core Tools 4, Node 22 + pnpm, and Docker.

```sh
DOCKER_CONTEXT=orbstack ./scripts/dev-db.sh up        # PostgreSQL :55432 + Azurite :20000-20002
cp api/Blueboard.Api/local.settings.example.json api/Blueboard.Api/local.settings.json   # add Azurite's dev key
export DATABASE_URL=postgres://postgres:devpass@127.0.0.1:55432/blueboard DEV_AUTH=true
dotnet run --project api/Blueboard.Tools -- migrate
dotnet run --project api/Blueboard.Tools -- seed-dev --sample   # dev identities + a sample incident
(cd api/Blueboard.Api && func start --port 7351)                # C# API + MCP
(cd web && pnpm install && pnpm dev)                             # http://localhost:5173/dev-login
```

Run the reference agent against the local board:

```sh
BOARD_URL=http://localhost:7351 BOARD_DEV_PRINCIPAL=enrichment-agent CLAUDE_PROVIDER=anthropic ANTHROPIC_API_KEY=... \
  dotnet run --project agents/Blueboard.EnrichmentAgent
# or Foundry: ANTHROPIC_FOUNDRY_RESOURCE=... (az login for Entra)
```

`DEV_AUTH` lets the API accept seeded dev identities. The API refuses to start with it in Azure, and production web builds don't include the dev sign-in page.

## Deploy to Azure

```sh
export BB_ENV=prod RESOURCE_GROUP=rg-blueboard-prod LOCATION=australiaeast
./infra/preflight.sh                       # read-only: tools, sign-in, your Azure + Entra roles
./infra/entra-app.sh                       # app registration, app roles, assignment required
POLICY_FILE=policy.json ./infra/deploy.sh # Bicep, C# Functions, React site, sign-in, health check
./infra/grant-permissions.sh <api-mi> <app-id>               # Privileged Role Administrator
./infra/assign-roles.sh <group-id> Board.Post Board.Hunt Board.RequestActions
```

**[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** covers the full walk-through:

- the **Azure RBAC and Entra roles each step needs**, and least-privilege roles for running the board day to day
- connecting agents and running the reference agent
- what every script changes
- updates, rollback and teardown
- troubleshooting

## Security

**[docs/SECURITY.md](docs/SECURITY.md)** covers:

- the threat model (prompt injection, compromised agents, self-approval and more)
- the controls in the code and every Microsoft permission the board holds
- the action policy
- a hardening checklist, Sentinel detections, and an incident runbook for the board itself

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Develop

```sh
dotnet test --solution api/Blueboard.slnx          # 44 C# tests (policy, validation, auth, reporting)
(cd web && pnpm typecheck && pnpm test && pnpm build)
az bicep build --file infra/main.bicep && shellcheck -x infra/*.sh
```

## Status

This is an MVP. The C# Functions, the MCP tools, the React app and the C# agent have been tested end to end locally (Functions Core Tools + Azurite + PostgreSQL, a sample incident, a dry-run broker and a mocked Claude endpoint). It has **not** yet been run against a live Defender tenant: verify each Graph and MDE call in a test tenant before you turn on `BROKER_EXECUTE`.
