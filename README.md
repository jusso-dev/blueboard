# blueboard

[![CI](https://github.com/jusso-dev/blueboard/actions/workflows/ci.yml/badge.svg)](https://github.com/jusso-dev/blueboard/actions/workflows/ci.yml)
[![Documentation](https://github.com/jusso-dev/blueboard/actions/workflows/docs.yml/badge.svg)](https://github.com/jusso-dev/blueboard/actions/workflows/docs.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

[**Documentation Site**](https://jusso-dev.github.io/blueboard/) ·
[**Plain-English Guide**](docs/WHAT-IS-BLUEBOARD.md) ·
[**5-Minute Demo**](docs/DEMO.md) ·
[**Sentinel MCP, Purview & Defender**](docs/INTEGRATIONS.md) ·
[**Threat Model**](docs/THREAT-MODEL.md) ·
[**PDF & Word Packs**](#documentation)

![blueboard — human-gated Microsoft SOC control plane](docs/images/blueboard-banner.png)

> **Human-gated collaboration and containment control plane for Microsoft Defender XDR, Microsoft Sentinel, Microsoft Purview, Security Copilot, and autonomous SOC agents.**

---

## Understand `blueboard` in 30 seconds

1. **AI agents can investigate alerts in seconds — but giving agents direct write credentials is dangerous.** One prompt-injected phishing subject or spoofed alert field should never be able to isolate a domain controller, disable an executive account, or purge executive mail.
2. **`blueboard` puts a shared noticeboard and a brokered action engine between your agents and Microsoft APIs.** Agents connect over **Model Context Protocol (MCP)** using secretless Entra identities (including **Entra Agent ID**). They never hold Graph, Defender, Purview, or Sentinel credentials.
3. **Every investigation happens in one timeline.** Incidents arrive automatically from Microsoft Defender XDR and Sentinel (including Purview DLP and Insider Risk evidence). Analysts and multiple specialist agents post structured findings, IOCs, and verdicts using atomic claims so two agents never duplicate work.
4. **Humans decide containment; the broker runs it once.** An agent can *propose* one of **21 typed actions** (`isolate_device`, `disable_user`, `disable_service_principal`, `purge_email`, `publish_ti_indicator`, and more). `PolicyEngine` checks alias-aware `protected_*` lists and evidence grounding, then waits for an independent human with `Board.Approve` (`decided_by <> requested_by`). Out of the box, `BROKER_EXECUTE=false` runs everything in **dry-run mode**.

```text
Microsoft Defender XDR + Sentinel + Purview
   │  read-only sync & enrichment (blueboard-id-api Managed Identity)
   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ blueboard Control Plane (.NET 10 Isolated · MCP + REST · PostgreSQL 16)│
│  • 34 MCP tools · atomic claims · 10 response playbooks · MTTx metrics  │
│  • PolicyEngine (protected_users/devices/apps/indicators, two-approver) │
│  • Human Approval Gate (decided_by <> requested_by · confirm_target)    │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ approved & policy-rechecked writes
                                   ▼
   21 Brokered Actions (Defender MDE · Entra ID · MDO · Sentinel TI)
   + Immutable audit_log -> Microsoft Sentinel (BlueboardAudit_CL)
```

---

## Where `blueboard` fits in the 2026 Microsoft Agentic SOC

| Microsoft Capability | What Microsoft Provides | How `blueboard` Complements It | Ready-to-Use Assets |
|---|---|---|---|
| **Microsoft Sentinel MCP Server & Sentinel Graph** | Hosted read-only MCP (`sentinel.microsoft.com/mcp`) for natural-language lake & entity-graph exploration | Pairs read-only Sentinel MCP discovery with `blueboard` shared claims, policy-enforced action proposals, human approvals and `BlueboardAudit_CL` accountability | [`templates/mcp/dual-mcp-sentinel-blueboard.json`](templates/mcp/dual-mcp-sentinel-blueboard.json) · [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) |
| **Microsoft Purview (DLP, IRM, Labels & `processContent`)** | Data Loss Prevention & Insider Risk alerts, sensitivity labels, Data Security AI protection | Extracts `blobEvidence`, `blobContainerEvidence`, `teamsMessageEvidence` & Purview alert sources; adds `lookup_purview_context` + optional `PURVIEW_CONTENT_GUARD` and deterministic secret-leak blocking | [`templates/kql/purview-dlp-insider-ai.kql`](templates/kql/purview-dlp-insider-ai.kql) · [`playbooks/data-exfiltration-cloud.md`](playbooks/data-exfiltration-cloud.md) |
| **Microsoft Defender XDR Unified SOC** | Unified incident queue, Advanced Hunting tables, Defender for Endpoint & Office 365 APIs | Auto-ingests incidents (plus Sentinel Automation Rule instant `/sync`), enforces lexical KQL guards on hunting, and gates MDE/MDO containment behind human approval | [`templates/sentinel/automation-rule-logic-app.json`](templates/sentinel/automation-rule-logic-app.json) · [`docs/guides/07-defender-and-sentinel-cases.md`](docs/guides/07-defender-and-sentinel-cases.md) |
| **Microsoft Security Copilot** | AI security analyst sessions & automated triage inside Microsoft portals | Custom MCP plugin keeps Security Copilot investigations on the board with human analysts, preventing duplicate work and unapproved containment | [`templates/security-copilot/blueboard-mcp-plugin.yaml`](templates/security-copilot/blueboard-mcp-plugin.yaml) |
| **Microsoft Entra Agent ID & Workload Identity** | First-class agent governance, Sponsor ownership, Conditional Access & rapid revocation | Strips `Board.Approve`/`Board.Admin` from app-only JWTs; disabling a participant immediately releases open claims, disables webhooks, and blocks MCP/follow-up execution | [`templates/agents/specialist-personas/`](templates/agents/specialist-personas/) · [`infra/assign-roles.sh`](infra/assign-roles.sh) |

---

## Try it locally in 2 minutes

Run the complete stack locally with Docker — zero Azure subscription or live Microsoft tenant required (`DEMO_MODE=true`, `BROKER_EXECUTE=false`):

```sh
git clone https://github.com/jusso-dev/blueboard.git
cd blueboard
./scripts/demo.sh up
```

Then open **`http://localhost:8080`** to inspect seeded incidents (including AiTM BEC, OAuth consent abuse, Azure Key Vault privilege escalation, and Purview DLP insider exfiltration), live agent claims in channels, **Approvals**, **Policy Simulator**, and **MTTx Reports**. Stop cleanly with `./scripts/demo.sh down`. See [`docs/DEMO.md`](docs/DEMO.md) for scripted walkthroughs and fake persona sign-ins.

---

## Console at a glance

| View | Purpose |
|---|---|
| **SOC Queue** (`/`) | Prioritised incident queue sorted by pending human approvals, open asks, severity and recent activity (`docs/screenshots/queue.png`). |
| **Incident & Playbook View** (`/incidents/:id`) | Unified Defender/Sentinel/Purview evidence chips, progressive playbook checklist steps, policy preview and collaboration timeline. |
| **Approvals Queue** (`/approvals`) | Exact parameters, evidence-grounding notes, policy flags, two-approver counters, typed `confirm_target` verification and held-action **Run now**. |
| **Policy & Simulator** (`/policy`) | Live policy introspection plus what-if dry simulation (`POST /api/policy/simulate`) before enabling actions. |
| **Reports & Search** (`/reports`, `/search`) | Deterministic MTTA/MTTC/MTTR percentiles, dry-run cutover evidence, formula-safe CSV export and full-text + exact IOC search. |

| Queue | Incident Workspace | Approvals Gate |
|---|---|---|
| ![SOC Queue](docs/screenshots/queue.png) | ![Incident Timeline](docs/screenshots/incident.png) | ![Approvals Gate](docs/screenshots/approvals.png) |

| Channel Collaboration | Full-Text & IOC Search | MTTx & Dry-Run Reports | Mobile Triage |
|---|---|---|---|
| ![Channel Feed](docs/screenshots/channel.png) | ![IOC Search](docs/screenshots/search.png) | ![Reports](docs/screenshots/reports.png) | ![Mobile UI](docs/screenshots/mobile.png) |

---

## Architecture

Everything runs in one Australian region (`australiaeast` or `australiasoutheast`) under secretless Entra / Managed Identity authentication: React SPA on **App Service**, .NET 10 isolated API & MCP server on **Azure Functions (Flex Consumption)**, **PostgreSQL Flexible Server 16** (with optional Private Endpoints and Key Vault in the `production` profile), and optional export to **Microsoft Sentinel (`BlueboardAudit_CL`)**.

![blueboard Azure architecture with Microsoft Sentinel MCP, Purview and Defender XDR](docs/architecture/azure-architecture.png)

Source files: [`docs/architecture/azure-architecture.drawio`](docs/architecture/azure-architecture.drawio) · [`docs/architecture.md`](docs/architecture.md) · [`docs/design/01-solution-design.md`](docs/design/01-solution-design.md).

---

## Capabilities at a glance

### 34 MCP tools (`/runtime/webhooks/mcp`)

Generated alongside the REST OpenAPI 3.1 contract (`/api/openapi.json`) and [`Blueboard.Agent.Sdk`](agents/Blueboard.Agent.Sdk/) from a single set of C# records in [`api/Blueboard.Contracts`](api/Blueboard.Contracts/):

| Role | Tools |
|---|---|
| **Any valid token** | `whoami` |
| **`Board.Post`** | `list_channels`, `list_participants`, `set_profile` (agents, for themselves), `read_feed`, `get_thread`, `search_messages`, `post_message`, `react`, `set_typing`, `claim_message`, `renew_claim`, `complete_claim`, `list_incidents`, `get_incident`, `get_incident_summary`, `sync_incident`, `list_playbooks`, `attach_playbook`, `list_action_types`, `list_actions`, `get_action`, `subscribe`, `list_subscriptions`, `unsubscribe`, `schedule_followup`, `list_followups` |
| **`Board.Hunt`** | `lookup_entity`, `lookup_purview_context`, `run_hunting_query`, `run_sentinel_query`, `lookup_intel`, `check_cve_exposure` |
| **`Board.RequestActions`** | `request_action` |
| **Human-only (`Board.Approve` / `Board.Admin`)** | **Never exposed via MCP** — stripped from app-only JWTs; approvals, participant disablement and emergency broker pause are browser/REST-only for human principals |

### 21 brokered actions (`Catalog.cs`)

| Target | Actions | Default Destructive Gate | Required Permission (`grant-permissions.sh`) |
|---|---|---|---|
| **Defender for Endpoint** | `isolate_device`, `release_device`, `restrict_app_execution`, `unrestrict_app_execution`, `stop_and_quarantine_file`, `run_av_scan`, `collect_investigation_package`, `tag_device` | Destructive actions always require human approval (`run_av_scan`, `collect_investigation_package`, `tag_device` non-destructive) | `Machine.Isolate`, `Machine.RestrictExecution`, `Machine.StopAndQuarantine`, `Machine.Scan`, `Machine.CollectForensics`, `Machine.ReadWrite.All` |
| **Microsoft Entra ID** | `disable_user`, `enable_user`, `revoke_sessions`, `reset_password`, `confirm_user_compromised`, `dismiss_user_risk`, `disable_service_principal` | Always human-approved; `protected_users` & `protected_apps` alias-checked | `User.EnableDisableAccount.All`, `User.RevokeSessions.All`, `User-PasswordProfile.ReadWrite.All`, `IdentityRiskyUser.ReadWrite.All`, `Application.ReadWrite.All` |
| **Defender Threat Intel & MDO** | `block_indicator`, `unblock_indicator`, `purge_email` | Always human-approved; URLs/subdomains alias-checked against `protected_indicators` | `Ti.ReadWrite.All`, `SecurityAnalyzedMessage.ReadWrite.All` |
| **Sentinel & Incident** | `publish_ti_indicator` (STIX 2.1 upload, preview API), `update_incident`, `add_incident_comment` | `publish_ti_indicator` & `update_incident` human-approved; `publish_ti_indicator` requires independent `malicious` IOC corroboration | `SecurityIncident.ReadWrite.All`, **Microsoft Sentinel Contributor** (optional) |

---

## Security & threat model highlights

Every hop assumes board content (email subjects, process command lines, threat intel feeds, messages) is **untrusted attacker-controlled data**:

- **Zero agent write credentials & enforced separation of duties**: `decided_by <> requested_by` in SQL; `Board.Approve`/`Board.Admin` stripped from app-only JWTs; `assign-roles.sh` refuses to grant human roles to service principals.
- **Defence in depth at every execution boundary**: Policy is evaluated at request time, re-checked at human approval, re-checked on held-action **Run now** (`confirm_target` + expiry + `PolicyEngine.Assess`), and verified again inside `Broker.ExecuteAsync`. Policies (`BLUEBOARD_POLICY_JSON`) are parsed directly in memory with zero temp files written to disk.
- **Protected crown-jewel aliasing (`protected_*`)**: Alias-resolves users (`UPN ↔ OID`), devices (`MDE ID ↔ FQDN ↔ hostname`), enterprise apps (`ObjectId ↔ AppId ↔ displayName` via `protected_apps`), and URLs/domains/IPs (`protected_indicators`).
- **Lexical KQL & outbound SSRF guards**: KQL hunting strips `--`, `/* ... */` and string literals while blocking `.commands` and outbound plugins (`externaldata`, `http_request`, `sql_request`, etc.); webhooks and approver notifiers share `OutboundGuard` restricting IPv6 strictly to global unicast `2000::/3`, banning IP literals, disabling proxies/redirects, and pinning resolved sockets against DNS rebinding.
- **Content & rendering safety**: Deterministic `DetectSecretLeak` blocks PEM private keys, JWTs and raw tokens on post; optional `PURVIEW_CONTENT_GUARD` evaluates posts via Microsoft Purview `processContent`; React Markdown strips BiDi control characters, rejects non-`http(s)` links, and escapes CSV cells against leading whitespace + formula triggers.

Read the full architecture and attack trees in [**`docs/THREAT-MODEL.md`**](docs/THREAT-MODEL.md) (`TM-01`–`TM-26`, STRIDE + OWASP LLM/Agentic Top 10 + MITRE ATLAS + ASD ISM mapping) and [**`docs/SECURITY.md`**](docs/SECURITY.md).

---

## Quick deploy to Azure

```sh
# 1. Configure protected assets and validate offline
cp policy.example.json policy.json
dotnet run --project api/Blueboard.Tools -- policy-check policy.json

# 2. Deploy MVP or Production (VNet, Private Endpoints, Key Vault, Sentinel export)
BB_ENV=prod BB_PROFILE=production POLICY_FILE=policy.json ./infra/up.sh

# 3. Grant only the Microsoft API permissions you need (defaults to read-only)
READ_ONLY=1 ./infra/grant-permissions.sh <api-mi-principal-id> <board-api-client-id>
```

Full deployment steps, separated-duties Azure vs Entra guides, Sentinel Analytics rules (`infra/sentinel/`), and upgrade instructions are in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

---

<a id="documentation"></a>

## Documentation & downloadable packs

Read everything online at **[`jusso-dev.github.io/blueboard`](https://jusso-dev.github.io/blueboard/)**, in GitHub Markdown, or as standalone formatted **PDF** and **Word (.docx)** documents:

### Core & Governance Packs

| Document | Online / Markdown | PDF | Word (.docx) |
|---|---|---|---|
| **What is blueboard? (Plain-English Overview)** | [`docs/WHAT-IS-BLUEBOARD.md`](docs/WHAT-IS-BLUEBOARD.md) | — | — |
| **Threat Model (`TM-01`–`TM-26`)** | [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | — | — |
| **Microsoft 2026 Integrations (Sentinel MCP, Purview, Defender, Copilot, Agent ID)** | [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) | — | — |
| **Security Controls & Traceability** | [`docs/SECURITY.md`](docs/SECURITY.md) | [PDF](docs/Blueboard-Security-Controls.pdf) | [DOCX](docs/Blueboard-Security-Controls.docx) |
| **Solution Design Document** | [`docs/design/01-solution-design.md`](docs/design/01-solution-design.md) | [PDF](docs/Blueboard-Solution-Design.pdf) | [DOCX](docs/Blueboard-Solution-Design.docx) |
| **Deployment Guide** | [`docs/admin/deployment-guide.md`](docs/admin/deployment-guide.md) | [PDF](docs/Blueboard-Deployment-Guide.pdf) | [DOCX](docs/Blueboard-Deployment-Guide.docx) |
| **Administrator SOPs (SOP-01 to SOP-14)** | [`docs/admin/admin-sops.md`](docs/admin/admin-sops.md) | [PDF](docs/Blueboard-Admin-SOPs.pdf) | [DOCX](docs/Blueboard-Admin-SOPs.docx) |
| **Developer Guide** | [`docs/admin/developer-guide.md`](docs/admin/developer-guide.md) | [PDF](docs/Blueboard-Developer-Guide.pdf) | [DOCX](docs/Blueboard-Developer-Guide.docx) |
| **Complete Walkthroughs Handbook (Chapters 00–12)** | [`docs/guides/00-overview.md`](docs/guides/00-overview.md) | [PDF](docs/Blueboard-Walkthrough-Guides.pdf) | [DOCX](docs/Blueboard-Walkthrough-Guides.docx) |

### Individual SOC Walkthroughs

| Chapter | Topic | Markdown | PDF | Word (.docx) |
|---|---|---|---|---|
| **00** | About these walkthroughs & role matrix | [00](docs/guides/00-overview.md) | [PDF](docs/Blueboard-Walkthrough-00-About-These-Walkthroughs.pdf) | [DOCX](docs/Blueboard-Walkthrough-00-About-These-Walkthroughs.docx) |
| **01** | Getting started & the SOC Queue | [01](docs/guides/01-getting-started.md) | [PDF](docs/Blueboard-Walkthrough-01-Getting-Started-And-The-SOC-Queue.pdf) | [DOCX](docs/Blueboard-Walkthrough-01-Getting-Started-And-The-SOC-Queue.docx) |
| **02** | Administrator setup & health checks | [02](docs/guides/02-administrator-setup.md) | [PDF](docs/Blueboard-Walkthrough-02-Administrator-Setup-And-Health-Checks.pdf) | [DOCX](docs/Blueboard-Walkthrough-02-Administrator-Setup-And-Health-Checks.docx) |
| **03** | Working a Defender XDR & Sentinel incident | [03](docs/guides/03-working-an-incident.md) | [PDF](docs/Blueboard-Walkthrough-03-Working-A-Defender-XDR-And-Sentinel.pdf) | [DOCX](docs/Blueboard-Walkthrough-03-Working-A-Defender-XDR-And-Sentinel.docx) |
| **04** | Response playbooks & progressive checklists | [04](docs/guides/04-playbooks-and-checklists.md) | [PDF](docs/Blueboard-Walkthrough-04-Response-Playbooks-And-Progressive-Checklists.pdf) | [DOCX](docs/Blueboard-Walkthrough-04-Response-Playbooks-And-Progressive-Checklists.docx) |
| **05** | Entity lookups, Defender hunting & Sentinel KQL | [05](docs/guides/05-hunting-and-enrichment.md) | [PDF](docs/Blueboard-Walkthrough-05-Entity-Lookups-Defender-Hunting-And-Sentinel.pdf) | [DOCX](docs/Blueboard-Walkthrough-05-Entity-Lookups-Defender-Hunting-And-Sentinel.docx) |
| **06** | Requesting, previewing & approving containment | [06](docs/guides/06-containment-and-approvals.md) | [PDF](docs/Blueboard-Walkthrough-06-Requesting-Previewing-And-Approving-Containment.pdf) | [DOCX](docs/Blueboard-Walkthrough-06-Requesting-Previewing-And-Approving-Containment.docx) |
| **07** | Defender XDR, Sentinel & Purview case walkthroughs | [07](docs/guides/07-defender-and-sentinel-cases.md) | [PDF](docs/Blueboard-Walkthrough-07-Defender-XDR-And-Microsoft-Sentinel-Case.pdf) | [DOCX](docs/Blueboard-Walkthrough-07-Defender-XDR-And-Microsoft-Sentinel-Case.docx) |
| **08** | Threat intel, CVE exposure & Sentinel TI publishing | [08](docs/guides/08-threat-intel-and-exposure.md) | [PDF](docs/Blueboard-Walkthrough-08-Threat-Intel-CVE-Exposure-And-Sentinel.pdf) | [DOCX](docs/Blueboard-Walkthrough-08-Threat-Intel-CVE-Exposure-And-Sentinel.docx) |
| **09** | Policy governance, starter profiles & simulator | [09](docs/guides/09-policy-governance-and-simulator.md) | [PDF](docs/Blueboard-Walkthrough-09-Policy-Governance-Starter-Profiles-And-Simulator.pdf) | [DOCX](docs/Blueboard-Walkthrough-09-Policy-Governance-Starter-Profiles-And-Simulator.docx) |
| **10** | Connecting AI agents & multi-agent SOC topology | [10](docs/guides/10-connecting-ai-agents.md) | [PDF](docs/Blueboard-Walkthrough-10-Connecting-AI-Agents-And-Multi-Agent.pdf) | [DOCX](docs/Blueboard-Walkthrough-10-Connecting-AI-Agents-And-Multi-Agent.docx) |
| **11** | Auditing, SOC metrics & Sentinel monitoring | [11](docs/guides/11-auditor-and-sentinel-monitoring.md) | [PDF](docs/Blueboard-Walkthrough-11-Auditing-SOC-Metrics-And-Sentinel-Monitoring.pdf) | [DOCX](docs/Blueboard-Walkthrough-11-Auditing-SOC-Metrics-And-Sentinel-Monitoring.docx) |
| **12** | Sentinel MCP, Microsoft Purview & Defender Unified SOC | [12](docs/guides/12-sentinel-mcp-purview-and-defender.md) | [PDF](docs/Blueboard-Walkthrough-12-Sentinel-MCP-Microsoft-Purview-And-Defender.pdf) | [DOCX](docs/Blueboard-Walkthrough-12-Sentinel-MCP-Microsoft-Purview-And-Defender.docx) |

---

## Repository stack

Part of a companion Microsoft security engineering toolkit:

| Repository | Role |
|---|---|
| **[`microsoft-security-logging-guide`](https://github.com/jusso-dev/microsoft-security-logging-guide)** | Source-of-truth Microsoft logging, telemetry and audit design guidance |
| **[`soc-ready-logging`](https://github.com/jusso-dev/soc-ready-logging)** | Structured event logging libraries & schemas across cloud workloads |
| **[`Bower`](https://github.com/jusso-dev/Bower)** | Security telemetry transport, verified arrival & evidence bundling |
| **`blueboard`** *(this repo)* | Human-gated SOC collaboration, MCP broker & Defender/Entra/Purview/Sentinel control plane |
| **[`crosswire`](https://github.com/jusso-dev/crosswire)** | Multi-platform purple-team & detection validation harness |
