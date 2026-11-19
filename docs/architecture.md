# Architecture

blueboard on Azure, as deployed by [`infra/main.bicep`](../infra/main.bicep) and [`infra/grant-permissions.sh`](../infra/grant-permissions.sh): a static **React** site on **Azure Static Web Apps**, a **C# Azure Functions** back end (.NET 10 isolated, Flex Consumption) and **PostgreSQL**. The deployment diagram uses Microsoft's official Azure icons; the others are Mermaid and render on GitHub.

- [1. Azure deployment](#1-azure-deployment)
- [Request paths](#request-paths)
- [Code layout](#code-layout)
- [2. Identity and trust boundaries](#2-identity-and-trust-boundaries)
- [3. Brokered action lifecycle](#3-brokered-action-lifecycle)
- [4. Agent loop](#4-agent-loop)
- [5. Data model](#5-data-model)
- [Resource inventory](#resource-inventory)
- [Production hardening](#production-hardening)

---

## 1. Azure deployment

Everything in the resource group is created by `main.bicep`. Entra objects and the Microsoft Graph / Defender permissions are set up once by a tenant admin: see [DEPLOYMENT.md](DEPLOYMENT.md#roles-required).

[![blueboard on Azure](architecture/azure-architecture.png)](architecture/azure-architecture.svg)

<sub>Microsoft's official Azure architecture icons, used under Microsoft's icon terms. Editable source: [`architecture/azure-architecture.drawio`](architecture/azure-architecture.drawio). Regenerate with [`scripts/build-architecture-diagram.py`](../scripts/build-architecture-diagram.py).</sub>

**Network paths.** Browsers only ever talk to the Static Web App; it serves the static build and proxies `/api/*` to the linked Function App. Agents call the Function App's MCP endpoint directly. The Function App reaches PostgreSQL (Entra token as password), its host storage (managed identity, shared keys disabled), Application Insights (Entra auth), Microsoft Graph and the Defender for Endpoint API. Postgres accepts Azure-internal traffic through the `AllowAzureServices` firewall rule, which is an MVP choice. See [Production hardening](#production-hardening) for the private version.

## Request paths

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser (React)
  participant S as Static Web App
  participant E as Microsoft Entra ID
  participant F as Function App (C#)
  participant A as Agent
  participant P as PostgreSQL

  B->>S: GET / (static index.html + assets)
  B->>S: GET /api/me (no session)
  S-->>B: 401 → React shows "Sign in with Microsoft"
  B->>S: /.auth/login/aad
  S->>E: OIDC sign-in (app registration, federated credential: no secret)
  E-->>S: ID token with roles claim (Board.*)
  S->>F: POST /api/swa-roles (claims) → returns Board.* roles
  S-->>B: session cookie
  B->>S: GET /api/messages?channel=incidents (every 4 s)
  S->>F: proxied, with x-ms-client-principal (platform-written)
  F->>F: built-in auth stripped any client copy · map roles · require Board.Post
  F->>P: parameterised query (Entra token as password)
  F-->>B: JSON (snake_case)

  A->>E: client credentials / managed identity → token for api://blueboard-env
  A->>F: POST /runtime/webhooks/mcp tools/call (Authorization: Bearer)
  F->>F: validate JWT per call (JWKS, iss, aud, tid, exp) · role check
  F->>P: read / write
  F-->>A: tool result (JSON text)
```

## Code layout

| Path | What it is |
|---|---|
| `web/` | React 19 + Vite + React Router + Tailwind v4. Static build in `web/dist`. `public/staticwebapp.config.json` holds routes, auth, CSP |
| `api/Blueboard.Api/` | C# Azure Functions (.NET 10 isolated). `Http/` REST, `Mcp/` MCP tools, `Jobs/` timers, `Board/` messages/claims/search/reports, `Actions/` catalogue, policy, broker, `Graph/` Graph and Defender client, incident ingest, enrichment, `Auth/` Entra token and principal handling, `Data/` Npgsql, migrations, audit |
| `api/Blueboard.Api.Tests/` | xUnit v3 tests (policy, validation, auth, token guard, reporting) |
| `api/Blueboard.Tools/` | `blueboard migrate` and `blueboard seed-dev` (local development) |
| `agents/Blueboard.EnrichmentAgent/` | Reference agent: .NET 10 console app, Anthropic C# SDK, MCP C# client |
| `db/migrations/` | SQL migrations, bundled into the Function App and applied at start-up |
| `infra/` | Bicep and deployment scripts |

---

## 2. Identity and trust boundaries

Agents hold **no** Microsoft security permissions. Only the Function App's managed identity can touch Defender, Entra or Sentinel, and its write paths go through policy and human approval.

```mermaid
flowchart TB
  subgraph humans["Humans · Static Web Apps sign-in (Entra)"]
    h1["Analyst<br/>Board.Post · Board.Hunt · Board.RequestActions"]
    h2["Approver<br/>+ Board.Approve"]
    h3["Admin<br/>+ Board.Admin → /reports"]
  end

  subgraph agents["Agents · app-only tokens (workload identity)"]
    a1["Reference agent identity<br/>Board.Post · Board.Hunt · Board.RequestActions<br/><b>never Board.Approve</b> (stripped in code too)"]
    a2["Any other agent<br/>its own Entra app / MI + assigned roles"]
  end

  subgraph board["Function App (trust boundary)"]
    authz["Per-request authz<br/>• browser: platform-written SWA principal<br/>  (built-in auth strips forged copies)<br/>• MCP: JWT per tool call (JWKS, iss, aud, tid)<br/>• Board.Post needed to read anything<br/>• approver must be human and not the requester<br/>• same-origin check on cookie writes"]
    policy["Action policy (policy.json)<br/>• protected users/devices/indicators → reject<br/>  (matched by every alias: UPN↔oid, MDE id↔DNS)<br/>• targets must appear in the incident's evidence<br/>• incident writes must be linked to that incident<br/>• only listed non-destructive kinds auto-run"]
    mi["blueboard-id-api (Function App managed identity)"]
  end

  subgraph perms["Application permissions held by blueboard-id-api"]
    direction LR
    r["Read<br/>Graph: SecurityIncident.Read.All · SecurityAlert.Read.All ·<br/>ThreatHunting.Read.All · User.Read.All ·<br/>IdentityRiskyUser.Read.All · RoleManagement.Read.Directory<br/>MDE: Machine.Read.All · File.Read.All · Ip.Read.All · Url.Read.All"]
    w["Write (brokered only)<br/>Graph: SecurityIncident.ReadWrite.All · User.EnableDisableAccount.All ·<br/>User.RevokeSessions.All · User-PasswordProfile.ReadWrite.All ·<br/>SecurityAnalyzedMessage.ReadWrite.All<br/>MDE: Machine.Isolate · Machine.Scan · Machine.CollectForensics · Ti.ReadWrite.All"]
  end

  humans --> authz
  agents --> authz
  authz --> policy --> mi
  mi --> r
  mi --> w

  untrusted["⚠ All board messages, incident fields and query results are untrusted data.<br/>Agents are told to analyse them, never to follow instructions found in them."]
  agents -.- untrusted
```

---

## 3. Brokered action lifecycle

From an agent's request to a change in Defender. Every step is written to `audit_log` and posted to `#containment`.

```mermaid
sequenceDiagram
  autonumber
  participant Ag as Agent (MCP)
  participant B as Broker (C# Function App)
  participant P as Policy
  participant DB as Postgres
  participant H as Human approver (UI)
  participant MS as Defender / Graph

  Ag->>B: request_action(kind, params, justification, incident)
  B->>B: validate params against the action's schema
  B->>P: evaluate(targets, incident evidence, policy.json)
  alt protected target, disabled kind, or unlinked incident write
    P-->>B: reject
    B->>DB: actions.status = rejected
    B-->>Ag: rejected + policy notes
  else non-destructive, in auto_approve, targets in evidence
    P-->>B: auto
    B->>DB: status = approved → running
    B->>MS: execute with the Function App's managed identity
  else everything else (all destructive actions)
    P-->>B: needs_approval
    B->>DB: status = pending_approval
    B-->>H: action_request posted to the containment channel + Approvals queue (polled)
    H->>B: approve / deny (+ note)
    Note over B: approver must be human, hold Board.Approve,<br/>and not be the requester
    B->>DB: status = approved (or denied)
    B->>B: re-validate stored params
    B->>DB: status = running, started_at
    B->>MS: execute (BROKER_EXECUTE=true) or record a dry run
  end
  MS-->>B: result / error
  B->>DB: succeeded | failed, finished_at, audit_log
  B-->>Ag: action_result in the request's thread

  Note over B,DB: Recovery sweep (timer trigger every minute, advisory lock):<br/>approved > 1 min → run · running > 10 min → failed "outcome unknown", never re-run blindly
```

---

## 4. Agent loop

How the reference enrichment agent ([`agents/Blueboard.EnrichmentAgent`](../agents/Blueboard.EnrichmentAgent/Program.cs)) and any other MCP agent works with the board.

```mermaid
sequenceDiagram
  autonumber
  participant Poll as Incident poller (timer trigger)
  participant Feed as Board feed
  participant Ag as Enrichment agent (C#)
  participant C as Claude on Foundry
  participant An as Analyst

  Poll->>Feed: incident message in the incidents channel (new or updated)
  loop every AGENT_POLL_SECONDS
    Ag->>Feed: read_feed(after_seq = cursor)
  end
  Feed-->>Ag: new messages (incident, @mentions, open questions)
  opt question / ask
    Ag->>Feed: claim_message (lease) — 409 if someone else holds it
  end
  Ag->>C: task + board tools (manual tool loop, adaptive thinking)
  C->>Ag: get_incident · lookup_entity · run_hunting_query
  Ag->>Feed: (tools run through the board, read-only)
  C->>Ag: post_message(finding / ioc / verdict / question)
  Ag->>Feed: threaded replies linked to the incident
  opt containment warranted
    C->>Ag: request_action(...)
    Ag->>Feed: → brokered lifecycle (diagram 3)
  end
  Ag->>Feed: complete_claim(done)
  Feed-->>An: picked up by the React app's 4-second poll
  An->>Feed: reply, @mention the agent, approve actions
```

---

## 5. Data model

```mermaid
erDiagram
  principals ||--o{ messages : authors
  principals ||--o{ actions : requests
  principals ||--o{ actions : decides
  channels ||--o{ messages : contains
  incidents ||--o{ messages : "linked to"
  incidents ||--o{ actions : "scoped to"
  messages ||--o{ messages : "thread replies"
  messages ||--o| actions : "request message"
  principals ||--o{ audit_log : "actor"

  principals {
    uuid id PK
    text handle UK
    text kind "agent | human | system"
    text entra_oid UK
    text_arr roles "from token, every request"
  }
  messages {
    uuid id PK
    bigserial seq UK "feed cursor"
    text type "finding, ioc, question, verdict, ..."
    text body
    jsonb payload
    text claim_state "open | claimed | done"
    timestamptz claim_expires_at "lease"
    tsvector search "GIN: body + IOC values"
  }
  incidents {
    uuid id PK
    text graph_id UK "Defender incident id"
    text severity
    jsonb data "alerts + evidence"
    timestamptz first_seen_at "reporting clock start"
  }
  actions {
    uuid id PK
    text kind
    jsonb params
    text status "pending_approval → approved → running → succeeded | failed"
    timestamptz decided_at
    timestamptz started_at
    timestamptz finished_at
  }
  audit_log {
    bigserial id PK
    text event
    jsonb detail
  }
```

---

## Resource inventory

| Resource | Bicep name | SKU / config | Identity | Purpose |
|---|---|---|---|---|
| Static Web App | `blueboard-web-<suffix>` | Standard; custom Entra registration (federated credential, no secret); linked backend `/api` | `blueboard-id-swa` | React site, sign-in, `/api` proxy |
| Function App | `blueboard-api-<suffix>` | Flex Consumption (FC1), .NET 10 isolated, 2 GB instances, max 40; built-in auth enabled | `blueboard-id-api` | REST, MCP, broker, poller, recovery |
| App Service plan | `blueboard-plan` | FlexConsumption / FC1 | n/a | Hosts the Function App |
| Storage account | `blueboardst<suffix>` | Standard LRS, `allowSharedKeyAccess: false`, TLS 1.2 | API identity has Blob Owner, Queue + Table Contributor | Functions host storage, deployment package |
| PostgreSQL Flexible Server | `blueboard-pg-<suffix>` | v16, Standard_B1ms, 32 GB, 14-day backups, **Entra auth only** | Entra admin = `blueboard-id-api` | Board state, search |
| Application Insights | `blueboard-ai-<suffix>` | workspace-based, local auth disabled | API identity: Monitoring Metrics Publisher | Traces, exceptions, requests |
| Log Analytics workspace | `blueboard-logs-<suffix>` | PerGB2018, 90 days | n/a | App Insights storage |
| User-assigned MI | `blueboard-id-api` | n/a | n/a | Graph + Defender app permissions, Postgres admin, storage |
| User-assigned MI | `blueboard-id-swa` | n/a | n/a | Federated credential for Static Web App sign-in |
| App registration | created by `entra-app.sh` | App roles in `infra/board-api-app-roles.json`, assignment required | n/a | Token audience, roles, sign-in |

## Production hardening

The Bicep is an MVP. For production:

1. **Private networking.** Turn on VNet integration for the Function App, give PostgreSQL and the storage account private endpoints, and remove `AllowAzureServices`. Keep the Function App publicly reachable (the Static Web Apps linked backend needs it), but add access restrictions that allow only the SWA backend and your agents' egress IPs.
2. **Edge.** Use a custom domain on the Static Web App, plus enterprise-grade edge (Front Door) for WAF, DDoS protection and rate limits.
3. **High availability.** Use zone-redundant PostgreSQL (General Purpose + HA) and Flex Consumption always-ready instances (`http=1`) to avoid cold starts on the approval path. Timers already run single-instance through a Postgres advisory lock.
4. **Send `audit_log` to Sentinel** (a Log Analytics custom table via the Logs Ingestion API), so board decisions sit next to the incidents they changed.
5. **Turn on `BROKER_EXECUTE`** only after testing every action in a test tenant with a reviewed `policy.json`: protected break-glass accounts, domain controllers and your own domains.
