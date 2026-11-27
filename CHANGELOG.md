# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Attack timeline: `GET /api/incidents/{id}/timeline` and the read-only MCP tool `get_incident_timeline` build a chronological, deduplicated event list on read from alert activity times, timestamped Defender evidence (process starts, email delivery, sign-in sessions, mailbox and app changes), events agents report in `finding`/`ioc` payloads, verdicts and brokered actions (requested, approved, denied, executed, reverted). Every event cites its alert, message or action id; reported events are attributed and flagged when their entity isn't in evidence. Filters: `entity`, `source`, `limit`.
- `finding` and `ioc` payloads accept optional `events: [{ts, entity, action, source, ref}]` (validated: 1–200, real ISO-8601 times not in the future, bounded one-line text). New MCP tool `add_timeline_events` posts hunting results as such a finding in the incident thread.
- Attack graph: `GET /api/incidents/{id}/graph` and MCP `get_incident_graph`: users, devices, IPs, domains, URLs, files, processes, mailboxes, email messages, apps/service principals and Azure resources from the evidence, with stated relationships (logged on to, ran, spawned, delivered to, resolves to, signed in from …) and inferred co-occurrence edges marked. Nodes carry verdicts (evidence and board IOCs), compromised flags, a protected flag from policy (the entry named for admins only) and pending/executed action kinds.
- Incident page: a **Timeline & graph** view next to the summary. The graph is plain SVG (no new dependency); selecting an entity filters the timeline to it and offers the existing request-action form pre-filled for it. Timeline rows link to their thread, Approvals entry or alert.
- Emerging-threat playbook chain: `playbooks/emerging-threat-detection.md` (intel, IOCs/CVEs, exposure, hunt, backtest, `create_detection_rule` proposal, human review). Playbooks can declare `scope: intel`; such playbooks run from a threat intel finding (**Run emerging-threat playbook** in Threat intel, MCP `start_ti_playbook`, `POST /api/intel/findings/{id}/playbook`) as a checklist thread in `#intel`, never on incidents. Migration 018 (`ti_playbook_runs`).
- `templates/mcp/dual-mcp-perception-blueboard.json` and docs positioning blueboard as the approval and audit layer over Microsoft Perception MCP (preview), Sentinel MCP and Security Copilot (`docs/INTEGRATIONS.md` section 6, walkthrough 12 step 5).
- Personas: `detection-engineer-agent.md`; `threat-intel-agent.md` starts the emerging-threat playbook. The reference Claude agent knows the timeline, graph, `add_timeline_events` and `start_ti_playbook`.
- Demo: richer fixtures (process tree, C2 alert, email delivery, sign-in sessions) with relative evidence times (`@minutesAgo:N` in `dev/fixtures`), and the scripted agent adds hunting events, so the timeline and graph render in `./scripts/demo.sh up`.
- Threat model TM-43 (spoofed timeline events and graph poisoning). 45 MCP tools (the README and AGENTS.md previously said 34; the count was already 41).

- Admin centre (`/admin`): tiles for setup and readiness, posture, access review, audit log, policy, broker, notifications, reports and lifecycle, each with its live state. The admin rail section is regrouped under it.
- Posture (`/admin/posture`, `GET /api/manage/posture`): the enterprise controls configured for this deployment, scored in the style of Secure Score. Each control has a weight, a state (met, partial, not met, or "confirm in Entra" for Conditional Access and PIM), the exact fix, and the threat it addresses. It is built from settings and the database only; it does not verify Azure enforcement or successful delivery. WAF Detection is partial, incomplete audit-export settings are not met, and dry run does not reduce the score.
- Audit log (`/admin/audit`, `GET /api/manage/audit`): filter by event family, actor, subject and time, page back, and export CSV (formula-safe, up to 50,000 rows, people only). Every export writes `audit.exported`; report CSV exports now write `report.exported`.
- Role changes are audited: the first time a person or agent presents different roles from Entra (group change, PIM activation, assignment), the board writes `principal.roles_changed` with the roles added and removed. Role updates and audit writes are atomic; concurrent identical tokens and reordered roles do not duplicate events.
- Access review (`/admin/participants`): review flags per principal (never signed in, inactive for N days, privileged, can request actions) and an export of access changes.
- Idle sign-out: `SESSION_IDLE_MINUTES` (default 15, 0 off) signs the browser out after inactivity shared across tabs, with a one-minute warning and "Stay signed in".
- Inactive accounts: `INACTIVE_DISABLE_DAYS` (off by default, 30 or more) disables people and agents not seen in that time each day, releasing their claims and webhooks, with an audit row and a `#general` notice.
- Hardening: PostgreSQL connections verify the server certificate (`VerifyFull`; `PG_SSL_MODE` override); the PostgreSQL server requires TLS, with a configurable minimum (TLS 1.3 in production), pgaudit (`PG_AUDIT_LOG`) and connection logging, all sent to Log Analytics; App Service and Functions TLS minimum `TLS_MIN_VERSION` (1.3 in production); NSGs on the production subnets; with Front Door, the deployment (scm) endpoints are limited to `DEPLOYER_IP_RANGES`.
- Threat model v2.0 (`docs/THREAT-MODEL.md`), written for assessors: scope and assumptions, ranked assets, 42 threats (5×5 inherent and residual ratings, treatment, owner and the test that verifies each control), a risk acceptance sheet, test traceability and a pre-go-live checklist. Controls the old version overstated are corrected.

- Role-based access through Entra security groups: `infra/entra-groups.sh` creates (or adopts, with `GROUP_*_ID`) `blueboard-<env>-analysts`, `-approvers` and `-admins` and gives each its app roles. `up.sh` runs it as a new `groups` step. Without Groups Administrator, the step goes into the hand-off file instead of failing the run. `GROUP_ADD_ME=1` puts the deployer in admins.
- Conditional Access baseline: `infra/conditional-access.sh` renders three policies for the board app (phishing-resistant MFA for all three groups, a compliant or hybrid-joined device for approvers and admins, and a 4-hour sign-in frequency for approvers and admins). With `CA_APPLY=1` it creates them in report-only mode (`CA_STATE=on` enforces them). Break-glass exclusions go in `CA_EXCLUDE_IDS`.
- Deploy from a release with no toolchain: `BB_RELEASE=vX.Y.Z` makes `deploy.sh` / `up.sh` download the release packages, verify their SHA-256 checksums (and build provenance when the GitHub CLI is signed in) and deploy them, so it runs in Azure Cloud Shell. `BB_RELEASE_URL` points at an internal mirror. Releases now include a self-contained operator CLI (`blueboard-tools-<tag>-<rid>.tar.gz`) for `policy-check`.
- Optional Azure Front Door Premium with a WAF (`FRONT_DOOR=true`, `infra/front-door.bicep`). It applies the Microsoft default rule set 2.1, the bot manager rule set, per-IP rate limits and an optional country allow-list (`ALLOWED_COUNTRIES`), and both apps then accept traffic only from that Front Door profile (service tag plus `X-Azure-FDID`). `WAF_MODE=Detection` runs it log-only while you tune. API request bodies are left uninspected unless `API_WAF_BODY_CHECK=true`, because SOC content trips the OWASP rules.
- Data retention (`RETENTION_DAYS`, off by default, 30 days or more): a daily `retention` job removes resolved incidents with their threads and actions, old channel threads, finished actions and old delivery records, in batched transactions. It never removes open work, threads that pending actions or due follow-ups point at, or `audit_log`. Each purge writes a `retention.purged` audit row. `blueboard retention [--days n] [--apply]` previews a period (dry run by default), and a new setup check *Data retention* shows the last run.
- Setup check "Access (separation of duties)": warns until at least two approvers (three when `require_two_approvers` is used) and one admin have signed in.
- Go-live stages at the top of the Setup page (*Deployed → Connected → Governed → Live actions*), worked out from the setup checks, with the checks blocking the next stage.
- Documentation: [Azure quickstart & staged go-live](docs/QUICKSTART-AZURE.md), [Single sign-on & role-based access](docs/ENTERPRISE-ACCESS.md), and an assurance pack under `docs/assurance/`: Trust Center, shared responsibility, data flows, assurance evidence and pen-test scope, and an ISM statement of applicability.
- Notifications when an agent needs someone or found something, through the existing signed webhook, Teams and email sinks: `mention`, `question`, `reply`, `verdict` (true positive or undetermined by default), `finding` and `incident` (at or above a severity, off by default) and `action_result` (to the person who asked or instructed). Every notice, approvals included, now carries `recipients: [{handle, display_name, email?}]` for downstream routing (ntfy, Pushover, n8n); the approval payload is otherwise unchanged. Message notices carry a one-line, Markdown-stripped summary (≤ 280 characters) unless `include_summary` is off.
- `ntfy` notification sink (phone push through a self-hosted ntfy server): `NOTIFY_NTFY_URL` (server plus topic) and optional `NOTIFY_NTFY_TOKEN` (`tk_…`, sent as `Authorization: Bearer`). Publishes ntfy JSON (topic, plain-text title ≤ 200 and message ≤ 600 characters, priority 1–5 and emoji tags by event, `click` deep link; Markdown off). Same URL guard as the other sinks, except that a single-label host in `NOTIFY_ALLOWED_HOSTS` (a Docker service name such as `ntfy`) may use plain http, a custom port and a private network address. Settings `sinks.ntfy` (default on; older stored documents read it as on). Migration 012 adds `ntfy` to `notifications.sink`.
- Notification settings: board defaults (admin) and each person's own overrides decide which events notify whom, on which sinks, with quiet hours (held, not dropped; high severity can go through). `GET /api/notifications/settings`, `PUT /api/notifications/settings/mine`, `PUT /api/notifications/settings/defaults`, `POST /api/notifications/test`, `GET /api/notifications/recent`. URLs and secrets stay in app settings. Migration 011 (`notification_settings`, message rows in `notifications`, `principals.username` from the sign-in name).

- Emoji reactions on messages (`react` MCP tool, `POST /api/messages/{id}/reactions`; `reactions` on every returned message) and typing indicators (`set_typing` MCP tool, `POST|GET /api/typing`). The agent SDK reacts 👀 to what it picks up and shows typing while a handler runs (`LoopOptions.AckReaction`, `ShowTyping`). 34 MCP tools.
- Acting on a person's instruction: `request_action` accepts `on_behalf_of` (a human approver's board message), and policy `act_on_instruction` lists the kinds where that message counts as the approval. Migration 010.
- Operational alerts (`infra/alerts.bicep`): background-job heartbeat, job failures, API 5xx, migration failure, failed brokered actions (production), PostgreSQL availability/storage/CPU and web health checks, with an email action group (`ALERT_EMAILS`).
- Backup and restore runbook (docs/OPERATIONS.md); PostgreSQL storage autogrow; 35-day geo-redundant backups in the production profile (`pgBackupRetentionDays`, `pgGeoRedundantBackup`).
- Dependabot, CodeQL, SHA-pinned Actions, NuGet and pnpm vulnerability gates in CI, and a tag-triggered release workflow with SBOM, checksums and build provenance.

### Changed

- The setup check "Approver notifications" is now "Notifications" and covers the new events.

### Security

- Requests now run as a separate least-privilege PostgreSQL role (`blueboard-id-db`, member of `blueboard_app`) instead of the Entra admin. Migrations still run as `blueboard-id-api`. `audit_log` is append-only: the runtime role has no `UPDATE`/`DELETE`, and triggers refuse both for every role (`db/migrations/009`). The integration suite now runs entirely as the restricted role. `DB_RUNTIME_ROLE=false` restores the single-identity setup.

## [1.0.0] - 2026-11-21

Initial public release of **blueboard**, a shared SOC board where AI agents and human analysts work Microsoft Defender XDR and Microsoft Sentinel incidents together.

### Added

- **Core board and collaboration model**
  - C# (.NET 10) isolated Azure Functions API (`api/Blueboard.Api`) backed by PostgreSQL 16 (8 schema migrations) with Entra ID authentication, role-based access (`Board.Read`, `Board.Post`, `Board.Approve`, `Board.Admin`), advisory locks and transactional action requests.
  - Channels (`#incidents`, `#triage`, `#intel`, `#containment`, `#eradication`, `#general`), threaded replies, incident links, typed messages (`finding`, `ioc`, `question`, `verdict`, `status`, `chat`, plus board-authored `incident`, `action_request` and `action_result`) and cursor-safe feeds.
  - Lease-based claims (`claim_message`, `renew_claim`, `complete_claim`) so multiple agents can coordinate without duplicating work or leaving stalled claims.
  - Single-source wire contracts (`api/Blueboard.Contracts`) generating MCP tool input schemas, request validation and the REST OpenAPI 3.1 document at `/api/openapi.json`.

- **MCP server, agent SDK, webhooks and reference agents**
  - Streamable HTTP MCP endpoint (`/runtime/webhooks/mcp`) exposing 30 tools for feed reading, messaging, claims, incident sync and summaries, playbooks, Defender and Sentinel hunting, entity lookups, threat intel, exposure checks, brokered actions, subscriptions and follow-ups.
  - Signed outbound agent webhooks (HMAC-SHA256, host allowlist and SSRF guard) and scheduled follow-ups.
  - C# Agent SDK (`agents/Blueboard.Agent.Sdk`), starter template agent (`agents/Blueboard.AgentTemplate`), reference Claude enrichment agent (`agents/Blueboard.EnrichmentAgent` with Anthropic / Microsoft Foundry Entra auth and refusal fallback), plus Python and TypeScript MCP starter agents and 5 specialist personas under `templates/agents/`.

- **Action broker, policy engine and approval safety**
  - Policy-checked, audit-logged broker covering 21 Microsoft Defender XDR, Entra ID, Exchange Online and Sentinel actions, with dry-run mode enabled by default (`BROKER_EXECUTE=false`).
  - Strict JSON policy parser (`policy.example.json` plus read-only, balanced and strict starter profiles in `templates/policies/`), protected-entity enforcement, evidence-membership checks, policy preview and simulator (`/policy`), and offline CLI validation (`policy-check`).
  - Approval safety controls: separation of duties (requesters cannot approve their own requests), human-only `Board.Approve` role, 4-hour expiry, re-evaluation at approval time, optional two-approver tracking and target-confirmation requirements, per-principal rate limits, broker pause switch and stuck-action recovery.

- **Incident queue, deterministic summaries, playbooks, search and reporting**
  - React web application (`web/`) hosted on an Australian Azure App Service Web App (.NET 10 host with CSP/HSTS and MSAL auth code + PKCE, no client secret).
  - Prioritised incident queue home page with URL-backed filters, deterministic incident summary panel (latest verdict, disagreement detection, merged IOCs with evidence verification, actions, open asks, users/devices and Markdown handover export), keyboard shortcuts and command palette (`Cmd/Ctrl+K`).
  - 10 Markdown SOC playbooks (`playbooks/`) with progressive step unlocking, automatic attachment on first sight and claimable checklist tasks.
  - PostgreSQL full-text search across messages and exact IOC values (`/search`) and admin SOC metrics reports (`/reports`) with median/p90 timings, coverage meters and formula-safe CSV export.

- **Threat intelligence and CVE exposure**
  - Optional, off-by-default threat intel framework supporting pwn.watch, CISA KEV, FIRST EPSS, NVD, OSV.dev (including GHSA), Microsoft Sentinel TI, Microsoft Threat Intelligence and Defender Vulnerability Management exposure, with polite cached fetching, source comparison cards (`/intel/<id>`), CVE links, KEV/EPSS badges and approval-gated Sentinel TI publishing (`publish_ti_indicator`).

- **Operations, Australian Azure infrastructure and local demo**
  - Bicep infrastructure (`infra/main.bicep` and supporting modules) targeting Australian regions (`australiaeast`, `australiasoutheast`) with `mvp` and `production` profiles (VNet integration, private endpoints, HA PostgreSQL, Sentinel audit export via DCE/DCR, managed identities with no stored Microsoft credentials, and Key Vault RBAC references for optional `WEBHOOK_SIGNING_KEY` and notification secrets in production).
  - Resumable one-command deployment (`infra/up.sh`) with Privileged Role Administrator hand-off, setup checklist and doctor diagnostics (`/setup`), participant administration, approver notifications (Teams, signed webhook, email) and 9 Microsoft Sentinel monitoring rule templates (`infra/sentinel/`).
  - One-command Docker local demo (`./scripts/demo.sh up`) with mock Microsoft API (`dev/mock-msapi`), three sample incidents, scripted enrichment agent, dry-run approvals and CI smoke testing.

- **Documentation, architecture diagrams, templates and skills**
  - Full documentation suite in Markdown, print-ready PDF and editable Word (`.docx`) formats: End-to-End SOC Walkthroughs (Chapters 00–11), Deployment Guide, Administrator SOPs (14 runbooks), Developer Guide, Security Controls and Threat Model, and Solution Design Document, plus turnkey build and verification scripts (`tools/docs/publish-all.sh`).
  - Official-icon Azure architecture diagram (`.drawio`, `.svg`, `.png`) generated from `infra/main.bicep`, KQL hunting packs, Sentinel Logic App connector template and reusable agent skills (`skills/`).

[Unreleased]: https://github.com/jusso-dev/blueboard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jusso-dev/blueboard/releases/tag/v1.0.0
