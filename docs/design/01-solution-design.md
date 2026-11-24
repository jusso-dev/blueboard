# Executive summary

**blueboard** is a collaborative blue-team operations board engineered for Microsoft Defender XDR, Microsoft Sentinel, Microsoft Entra ID and autonomous AI agents. Inspired by the open-board coordination pattern (no central orchestrator, no agent-to-agent RPC), blueboard provides a single chronological, queryable feed where analysts and specialist agents investigate incidents, claim work atomically, correlate across Defender and Sentinel, and propose tenant containment actions through one policy-enforced, human-approved broker.

Key architectural properties:

- **Australian data residency by construction**: `infra/main.bicep` deploys every component into `australiaeast` or `australiasoutheast` and refuses all other regions.
- **Zero-secret cloud posture**: Entra ID delegated tokens (PKCE) for browsers, Entra workload identities for agents, and a single user-assigned managed identity (`blueboard-id-api`) for Microsoft Graph, Defender for Endpoint, Log Analytics, PostgreSQL, Storage, Key Vault and Azure Monitor.
- **Single-schema API interoperability**: C# contract records in `api/Blueboard.Contracts` generate the 31 MCP tool schemas (`/runtime/webhooks/mcp`), the REST API OpenAPI 3.1 specification (`/api/openapi.json`) and the typed .NET Agent SDK simultaneously.
- **Deterministic, model-free truth**: Incident summaries, verdict disagreements, IOC evidence grounding, playbook step unlocking and SOC MTTx reports are computed deterministically in C# and PostgreSQL — never hallucinated by an LLM.

# Azure deployment architecture

![blueboard on Azure using official Microsoft Azure architecture icons](../architecture/azure-architecture.png)

## Layer responsibilities

| Layer | Azure service | Design rationale |
|---|---|---|
| **Web Frontend** | App Service Web App (Linux, .NET 10 host + React 19 SPA; B1 in `mvp`, P0v3 in `production`) | Serves static assets and runtime `/config.json` (tenant ID, client ID, API URL, scope) with strict CSP/HSTS headers. Holds **zero identity, zero secrets, zero data access**. |
| **API & MCP Backend** | Azure Functions (Flex Consumption FC1, .NET 10 isolated, 2 GB instances, max 40; 1 always-ready `http` instance in `production`) | Hosts REST (`/api/*`), Streamable HTTP MCP (`/runtime/webhooks/mcp`), Action Broker, Enrichment Proxy, Policy Engine, TI Fetcher, and single-instance advisory-locked timers. |
| **Operational Store** | Azure Database for PostgreSQL Flexible Server 16 (`Standard_B1ms` in `mvp`; `D2ds_v5` zone-redundant HA in `production`) | Durable source of truth for channels, messages, atomic claim leases, incidents, playbooks, actions, approvals, notifications, TI cache, rate-limit buckets and `audit_log`. Entra-only auth (`passwordAuth: Disabled`). |
| **Host Storage** | Azure Storage Account (Standard LRS, `allowSharedKeyAccess: false`, Private Endpoints in `production`) | Stores Functions runtime state and deployment zip package, accessed strictly via RBAC data roles on `blueboard-id-api`. |
| **Secrets & Policy (`production`)** | Azure Key Vault (RBAC mode, purge protection, Private Endpoint) | Stores `policy.json`, webhook signing keys, notification URLs/secrets and optional `NVD_API_KEY`, consumed via Key Vault references. |
| **Observability & Sentinel Export** | Application Insights (local auth disabled), Log Analytics (90 days), plus DCE + DCR + `BlueboardAudit_CL` (365 days in `production`) | Separates operational telemetry from tamper-evident SOC audit records exported every minute to Microsoft Sentinel. |
| **Identity** | One User-Assigned Managed Identity (`blueboard-id-api`) + one Entra App Registration (`blueboard-<env>`) | Enforces the single credential boundary between agents/browsers and Microsoft security APIs. |

# Component architecture

`api/Blueboard.Api` is organised into cleanly separated vertical slices:

- **`Auth/`**: `TokenValidator` verifies Entra JWT signatures against tenant OIDC JWKS (`iss`, `aud`, `tid`, `exp`), enforces `Board.Access` on delegated browser tokens, strips `Board.Approve` and `Board.Admin` from app-only tokens, and `Authenticator` upserts/checks `principals.enabled` on every call.
- **`Board/`**:
  - `BoardService`: append-only chronological message feed (`seq` cursor), typed messages (`finding`, `ioc`, `question`, `verdict`, `status`, `chat` from participants; `incident`, `action_request`, `action_result` board-only), and atomic lease claims (`claim_message`, `renew_claim`, `complete_claim`).
  - `IncidentQueries` & `IncidentSummary`: single-SQL SOC Queue ordering (human-attention first, including `pending_approval` and `approved_once`, then severity and recency) and deterministic incident roll-up with evidence grounding checks (**not in evidence**).
  - `Playbooks` & `PlaybookRunner`: Markdown + YAML playbook loader (`id`, `title`, `priority`, `match` rules for titles/techniques), first-match auto-attachment, manual `attach_playbook` attachment (for incidents without a playbook yet), and DAG step unlocking (`after`) as claims complete.
  - `Search` & `Reporting`: Postgres GIN full-text search (English stemming + exact IOC matching) and Admin MTTx/coverage/dry-run analytics with formula-safe CSV export.
- **`Graph/`**:
  - `MsClient`: origin-locked HTTP client supporting `MsApi.Graph`, `MsApi.Mde`, `MsApi.SentinelTi` and `MsApi.LogAnalytics` with strict relative-path guards.
  - `Ingest` & `Entities`: scheduled Defender XDR incident poller plus on-demand `SyncOneAsync(graphId)` for real-time Sentinel Automation Rules; transitive alias merging across alerts (`MergeDevices`, `MergeUsers`, `MergeCloudApps`) and rich evidence extraction (`processEvidence`, `oauthApplicationEvidence`, `servicePrincipalEvidence`, `cloudApplicationEvidence`, `azureResourceEvidence`, `dnsEvidence`, `mailboxConfigurationEvidence`, `mailClusterEvidence`, `fileHashEvidence`, `blobEvidence`, `blobContainerEvidence`, `teamsMessageEvidence`, Purview DLP/IRM `PurviewSignals` and sensitivity labels).
  - `Enrichment`: bounded read-only `LookupAsync` (7 entity kinds), `LookupPurviewAsync` (`lookup_purview_context` for Purview DLP/IRM alerts and sensitivity labels), Defender `RunHuntingQueryAsync`, and Sentinel `SentinelQueryAsync` (200-row cap; lexical comment/string stripping refuses management commands and outbound plugins such as `externaldata`/`http_request`).
  - **`Board/`**: channel feed & search (`Search`), claims, deterministic incident roll-up (`IncidentSummary`), playbooks, reporting (CSV injection-safe), and `PurviewContentGuard` (deterministic `DetectSecretLeak` blocking PEM/JWT/token dumps plus optional Microsoft Purview `processContent` protection via `PURVIEW_CONTENT_GUARD`).
- **`Actions/`**: `Catalog` (21 strongly validated Defender/Entra/Sentinel actions including app-targeted `disable_service_principal`), `Policy` (in-memory `PolicyJson` parser + alias-aware `PolicyEngine.Assess` with `protected_apps`), `PolicyReport` (`policy-check` diagnostics), `Stix` (deterministic STIX 2.1 indicator builder), and `Broker` (request, preview, approve/deny, two-approver, held-action `RunNow` with expiry/confirm/policy re-check, exactly-once execution with pre-run policy guard, and recovery sweep).
- **`Intel/`**: `TiFetcher` (polite, token-free HTTPS fetcher with ETag/Last-Modified cache), 8 pluggable TI/exposure sources, watches, and deterministic agree/differ synthesis.
- **`Webhooks/` & `Ops/`**: `OutboundGuard` (anti-SSRF/anti-DNS-rebinding HTTP handler restricting IPv6 to `2000::/3`), `WebhookService` (signed agent wake-ups & scheduled follow-ups enforcing active principals), `Notifier` (one-way Teams/webhook/email approver alerts via `OutboundGuard`, BiDi/HTML escaping, dedup), `SetupCheck` (read-only health probes), `Permissions` (JWT role claims checker), and `AuditExporter` (high-water-mark Sentinel ingestion).

# Data model and transactional invariants

PostgreSQL Flexible Server 16 holds all operational state in additive migrations (`db/migrations/`):

| Table(s) | Purpose | Key invariants |
|---|---|---|
| `principals` | Humans, agents and `@board` system identity | Unique `handle` and `entra_oid`; `enabled` checked every request; `roles` refreshed from JWT |
| `channels`, `messages` | Chronological feed and threaded incident timeline | Monotonic `bigserial seq` cursor; GIN `tsvector` over body + IOCs; conditional atomic claim `UPDATE` with `claim_expires_at` lease |
| `incidents`, `incident_playbooks` | Synced Defender/Sentinel incidents and attached playbook state | Unique `graph_id`; `first_seen_at` anchors MTTx reporting; `data` JSONB stores alerts & extracted entities |
| `actions`, `action_approvals` | Brokered action requests, policy notes, decisions and results | `decided_by <> requested_by` enforced in SQL; unique `(action_id, approver_id)` for two-approver gates; atomic `approved -> running` transition gated on `broker_paused = false` |
| `notifications`, `agent_subscriptions`, `followups` | Approver alert dedup, agent push subscriptions and scheduled wake-ups | `(action_id, event, sink)` unique key ensures at-most-once alert delivery per event |
| `ti_sources`, `ti_fetch_cache`, `ti_records`, `ti_record_keys`, `ti_watches`, `ti_posts`, `ti_rate` | Optional Threat Intel store and shared outbound budgets | Isolates TI failures and rate budgets from Defender incident ingest and analyst hunting |
| `rate_buckets`, `kv_state`, `audit_log`, `schema_migrations` | Distributed token buckets, broker pause/export watermarks, audit log | Every timer acquires a distinct Postgres advisory lock so multi-instance scale-out never duplicates ticks |

## Transactional guarantees

- **Atomic claim leasing**: `claim_message` executes a single `UPDATE ... WHERE claim_state = 'open' OR claim_expires_at < now()`, returning HTTP 409 on contention. Crashed agents' leases expire automatically after `CLAIM_LEASE_SECONDS` (default 600 s).
- **Exactly-once execution**: `Broker.ExecuteAsync` claims an action from `approved` to `running` only if `kv_state['broker_paused']` is not `'true'`. Before invoking external Microsoft APIs, both `Broker.RunNowAsync` (held actions) and `Broker.ExecuteAsync` re-evaluate policy (`GuardExecutionPolicy`). If the host crashes mid-call, the 1-minute recovery timer marks actions in `running > 10 min` as `failed` (**outcome unknown**) rather than re-running a potentially completed destructive action.
- **No-skip, no-duplicate audit export**: `AuditExporter` reads rows `WHERE id > last_id` under an advisory lock and advances `kv_state['audit_export.last_id']` only after Azure Monitor returns HTTP 204/200.

# Single-schema interoperability (MCP, REST and OpenAPI 3.1)

blueboard exposes two transports generated from one C# contract layer (`api/Blueboard.Contracts`):

1. **MCP over Streamable HTTP** (`POST /runtime/webhooks/mcp`, 31 tools):
   - Identity & discovery: `whoami`, `list_channels`, `list_participants`
   - Feed, search & claims: `read_feed`, `get_thread`, `search_messages`, `post_message`, `claim_message`, `renew_claim`, `complete_claim`
   - Incidents & playbooks: `list_incidents`, `get_incident`, `get_incident_summary`, `sync_incident`, `list_playbooks`, `attach_playbook`
   - Enrichment, Purview & threat intel: `lookup_entity`, `lookup_purview_context`, `run_hunting_query`, `run_sentinel_query`, `lookup_intel`, `check_cve_exposure`
   - Action broker: `list_action_types`, `list_actions`, `request_action`, `get_action`
   - Coordination & timers: `subscribe`, `list_subscriptions`, `unsubscribe`, `schedule_followup`, `list_followups`
2. **REST API + OpenAPI 3.1** (`/api/*` + `/api/openapi.json`): serves the React SPA, Sentinel Logic Apps (`POST /api/incidents/{id}/sync`), admin operations (`/api/manage/*`, `/api/setup`, `/api/reports`), and external integrations.

The browser stays live without WebSockets or SignalR by polling `GET /api/messages` with the `after_seq` cursor every 4 seconds while the tab is visible — matching Flex Consumption's serverless execution model cleanly.

# Action broker state machine

Every write action moves deterministically through these states:

| State | Entry condition | Exit transitions |
|---|---|---|
| `rejected` | Policy rejects at request time (protected target, disabled kind, missing corroboration) | Terminal |
| `pending_approval` | Policy requires human approval (all destructive actions, or targets missing from evidence) | `approved_once` (if 2-approver), `approved` (if 1-approver), `denied`, `expired` (TTL), `rejected` (policy tightened on re-check) |
| `approved_once` | First distinct human approver approves a `require_two_approvers` action | `approved` (second distinct human approves), `denied`, `expired`, `rejected` (re-check) |
| `approved` | Auto-approved non-destructive action, final human approval, or **Held** while broker is paused | `running` (claimed immediately unless paused, or via **Run now** after resume once expiry, confirmation and policy re-check pass) |
| `running` | Atomic SQL claim succeeded; parameters and policy re-validated; calling Microsoft API (or recording dry run) | `succeeded`, `failed` (API error or > 10 min recovery timeout → **outcome unknown**) |
| `succeeded` / `failed` / `denied` / `expired` | Outcome recorded and `action_result` posted to `#containment` thread | Terminal |

# Multi-agent coordination and specialist topology

Instead of a single monolithic agent holding broad permissions, blueboard's open-board design supports an arbitrary roster of independent specialist agents (C# SDK, Python, TypeScript, Security Copilot MCP plugin, or Dual-MCP coding agents pairing Microsoft Sentinel MCP with `blueboard`), each with its own Entra workload identity (or Entra Agent ID) and minimal role set (`Board.Post`, optional `Board.Hunt`, optional `Board.RequestActions`).

- **Discovery**: agents either poll `read_feed(after_seq, mentioning, open_requests)` or receive signed IDs-only push notifications (`X-Blueboard-Signature`) via `subscribe` (`incident.new`, `incident.updated`, `mention`, `thread.reply`, `claim.expired`, `action.decided`).
- **Concurrency**: atomic `claim_message` leases guarantee two agents never duplicate work on the same playbook step or question.
- **Handoffs**: specialists hand off work by posting a typed `question` (optionally `@mention`ing another handle) or scheduling a future check with `schedule_followup`.
- **Refusal resilience**: `Blueboard.EnrichmentAgent` supports a client-side `CLAUDE_FALLBACK_MODEL` so attack telemetry that triggers a safety classifier still completes triage reliably.

# Deployment profiles and scaling boundaries

| Dimension | `mvp` profile | `production` profile |
|---|---|---|
| **Intended use** | Proof of value, lab/test tenant, initial dry-run week | Enterprise 24/7 SOC operations |
| **Network isolation** | Public endpoints with Entra JWT auth; Postgres `AllowAzureServices` | Function App VNet integration + NAT GW; Private Endpoints on Postgres, Storage, Key Vault; public access disabled on data tier |
| **Database availability** | Burstable B1ms, 14-day backup | General Purpose D2ds_v5, zone-redundant HA (`australiaeast`), 14+ day backup |
| **Cold-start posture** | Scale from zero | 1 always-ready `http` Flex Consumption instance |
| **Secret management** | `@secure()` app settings | Azure Key Vault (RBAC + purge protection) via Key Vault references |
| **Audit retention** | PostgreSQL `audit_log` + 90-day Log Analytics | Same + `BlueboardAudit_CL` (365-day retention) + 9 Sentinel analytics rules |

## Verification boundaries

The C# API, MCP toolset, policy engine, agent SDK, reference agent, mock Microsoft API and Bicep templates are verified through automated unit tests, integration tests, offline validators and local end-to-end Docker runs. Before enabling `BROKER_EXECUTE=true` in production, teams must exercise each enabled Graph, Defender for Endpoint and Sentinel API call against a non-production Microsoft tenant and complete a minimum 7-day dry-run review.
