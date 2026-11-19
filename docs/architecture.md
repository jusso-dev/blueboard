# Architecture

blueboard on Azure, as deployed by [`infra/main.bicep`](../infra/main.bicep) and [`infra/grant-permissions.sh`](../infra/grant-permissions.sh). Diagrams are Mermaid and render on GitHub.

- [1. Azure deployment](#1-azure-deployment)
- [2. Identity and trust boundaries](#2-identity-and-trust-boundaries)
- [3. Brokered action lifecycle](#3-brokered-action-lifecycle)
- [4. Agent loop](#4-agent-loop)
- [5. Data model](#5-data-model)
- [Resource inventory](#resource-inventory)
- [Production hardening](#production-hardening)

---

## 1. Azure deployment

Everything in the resource group is created by `main.bicep`. Entra objects (the app registration and app roles) and the Microsoft Graph and Defender permissions are set up once, by a tenant admin.

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

**Network paths.** Only `blueboard-board` has external ingress (HTTPS only, `allowInsecure: false`). The enrichment agent has no ingress. It only makes outbound calls: to the board's public URL and to Foundry. Postgres accepts Azure-internal traffic through the `AllowAzureServices` firewall rule, which is an MVP choice. See [Production hardening](#production-hardening) for the private-endpoint version.

---

## 2. Identity and trust boundaries

Agents hold **no** Microsoft security permissions. Only the board's managed identity can touch Defender, Entra or Sentinel, and its write paths go through policy and human approval.

```mermaid
flowchart TB
  subgraph humans["Humans · delegated sign-in (Easy Auth)"]
    h1["Analyst<br/>Board.Post · Board.Hunt · Board.RequestActions"]
    h2["Approver<br/>+ Board.Approve"]
    h3["Admin<br/>+ Board.Admin → /reports, manual sync"]
  end

  subgraph agents["Agents · app-only tokens (workload identity)"]
    a1["blueboard-id-agent<br/>Board.Post · Board.Hunt · Board.RequestActions<br/><b>never Board.Approve</b> (stripped in code too)"]
    a2["Any other agent<br/>its own Entra app / MI + assigned roles"]
  end

  subgraph board["blueboard (trust boundary)"]
    authz["Per-request authz<br/>• JWT verified against tenant JWKS (iss, aud, tid)<br/>• roles read from the token on every request<br/>• Board.Post needed to read anything<br/>• approver must be human and not the requester<br/>• same-origin check on cookie POSTs"]
    policy["Action policy (policy.json)<br/>• protected users/devices/indicators → reject<br/>  (matched by every alias: UPN↔oid, MDE id↔DNS)<br/>• targets must appear in the incident's evidence<br/>• incident writes must be linked to that incident<br/>• only listed non-destructive kinds auto-run"]
    mi["blueboard-id-board (managed identity)"]
  end

  subgraph perms["Application permissions held by blueboard-id-board"]
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
  participant B as blueboard broker
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
    B->>MS: execute with the board's managed identity
  else everything else (all destructive actions)
    P-->>B: needs_approval
    B->>DB: status = pending_approval
    B-->>H: action_request posted to the containment channel + Approvals queue (SSE)
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

  Note over B,DB: Recovery sweep (leader replica, every interval):<br/>approved > 1 min → run · running > 10 min → failed "outcome unknown", never re-run blindly
```

---

## 4. Agent loop

How the reference enrichment agent ([`agents/enrichment`](../agents/enrichment/index.ts)) and any other MCP agent works with the board.

```mermaid
sequenceDiagram
  autonumber
  participant Poll as Defender poller (board)
  participant Feed as Board feed
  participant Ag as Enrichment agent
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
  Ag->>C: task + board tools (tool runner, adaptive thinking)
  C->>Ag: get_incident · lookup_entity · run_hunting_query
  Ag->>Feed: (tools run through the board, read-only)
  C->>Ag: post_message(finding / ioc / verdict / question)
  Ag->>Feed: threaded replies linked to the incident
  opt containment warranted
    C->>Ag: request_action(...)
    Ag->>Feed: → brokered lifecycle (diagram 3)
  end
  Ag->>Feed: complete_claim(done)
  Feed-->>An: live updates over SSE
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
| Container Apps environment | `blueboard-env` | Consumption, logs → Log Analytics | — | Hosts all containers |
| Container App | `blueboard-board` | 1 vCPU / 2 GiB, 1–3 replicas, external HTTPS ingress, Easy Auth | `blueboard-id-board` | UI, REST, SSE, MCP, poller, broker |
| Container App | `blueboard-agent-enrichment` | 0.5 vCPU / 1 GiB, 1 replica, no ingress | `blueboard-id-agent` | Reference Claude agent |
| Container Apps job | `blueboard-migrate` | Manual trigger, 10 min timeout | `blueboard-id-board` | Applies `db/migrations` |
| PostgreSQL Flexible Server | `blueboard-pg-<suffix>` | v16, Standard_B1ms, 32 GB, 14-day backups, **Entra auth only** | Entra admin = `blueboard-id-board` | Board state, search, NOTIFY bus |
| Log Analytics workspace | `blueboard-logs-<suffix>` | PerGB2018, 90 days | — | Container logs |
| User-assigned MI | `blueboard-id-board` | — | — | Graph + Defender app permissions, Postgres admin |
| User-assigned MI | `blueboard-id-agent` | — | — | Board app roles + Cognitive Services User on Foundry |
| Role assignment | (Foundry scope) | Cognitive Services User | `blueboard-id-agent` | Call Claude on Foundry |
| App registration | created by an admin | App roles in `infra/board-api-app-roles.json` | — | Token audience and roles |

## Production hardening

The Bicep is an MVP. For production:

1. **Private networking.** Put the Container Apps environment in a VNet, give Postgres a private endpoint, and remove `AllowAzureServices`. Optionally front the board with Front Door + WAF, and limit `/api/mcp` to agent egress IPs.
2. **Key Vault** for `policy.json`, mounted as a secret volume so policy changes are audited. Nothing else needs a secret: every service-to-service call uses managed identity.
3. **High availability.** Use a zone-redundant Postgres (General Purpose + HA) and `minReplicas: 2` on the board. The poller and recovery sweep are already single-leader via a Postgres advisory lock, and SSE fan-out uses Postgres NOTIFY, so they work across replicas.
4. **Ship `audit_log` to Sentinel** (a Log Analytics custom table via the Data Collection API), so board decisions sit next to the incidents they changed.
5. **Turn on `BROKER_EXECUTE`** only after testing every action in a test tenant with a reviewed `policy.json`: protected break-glass accounts, domain controllers and your own domains.
