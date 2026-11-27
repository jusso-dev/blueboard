# blueboard

[![CI](https://github.com/jusso-dev/blueboard/actions/workflows/ci.yml/badge.svg)](https://github.com/jusso-dev/blueboard/actions/workflows/ci.yml)
[![Documentation](https://github.com/jusso-dev/blueboard/actions/workflows/docs.yml/badge.svg)](https://github.com/jusso-dev/blueboard/actions/workflows/docs.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

[**Documentation Site**](https://jusso-dev.github.io/blueboard/) ·
[**Plain-English Guide**](docs/WHAT-IS-BLUEBOARD.md) ·
[**5-Minute Demo**](docs/DEMO.md) ·
[**Sentinel MCP, Purview & Defender**](docs/INTEGRATIONS.md) ·
[**Threat Model**](docs/THREAT-MODEL.md) ·
[**Azure Quickstart**](docs/QUICKSTART-AZURE.md) ·
[**Trust Center**](docs/assurance/TRUST-CENTER.md) ·
[**PDF & Word Packs**](#documentation)

![blueboard — human-gated Microsoft SOC control plane](docs/images/blueboard-banner.png)

> **Human-gated collaboration and containment control plane for Microsoft Defender XDR, Microsoft Sentinel, Microsoft Purview, Security Copilot, and autonomous SOC agents.**

---

## Understand `blueboard` in 30 seconds

1. **AI agents can investigate alerts in seconds — but giving agents direct write credentials is dangerous.** One prompt-injected phishing subject or spoofed alert field should never be able to isolate a domain controller, disable an executive account, or purge executive mail.
2. **`blueboard` puts a shared noticeboard and a brokered action engine between your agents and Microsoft APIs.** Agents connect over **Model Context Protocol (MCP)** using secretless Entra identities (including **Entra Agent ID**). They never hold Graph, Defender, Purview, or Sentinel credentials.
3. **Every investigation happens in one timeline.** Incidents arrive automatically from Microsoft Defender XDR and Sentinel (including Purview DLP and Insider Risk evidence). Analysts and multiple specialist agents post structured findings, IOCs, and verdicts using atomic claims so two agents never duplicate work.
4. **Humans decide containment; the broker runs it once.** An agent can *propose* one of **25 typed actions** (`isolate_device`, `disable_user`, `disable_service_principal`, `purge_email`, `publish_ti_indicator`, `okta_suspend_user`, and more). `PolicyEngine` checks alias-aware `protected_*` lists and evidence grounding, then waits for an independent human with `Board.Approve` (`decided_by <> requested_by`). Out of the box, `BROKER_EXECUTE=false` runs everything in **dry-run mode**.

```text
Microsoft Defender XDR + Sentinel + Purview
   │  read-only sync & enrichment (blueboard-id-api Managed Identity)
   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ blueboard Control Plane (.NET 10 Isolated · MCP + REST · PostgreSQL 16)│
│  • 45 MCP tools · attack timeline & graph · 11 playbooks · MTTx metrics │
│  • PolicyEngine (protected_users/devices/apps/indicators, two-approver) │
│  • Human Approval Gate (decided_by <> requested_by · confirm_target)    │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ approved & policy-rechecked writes
                                   ▼
   25 Brokered Actions (Defender MDE · Entra ID · MDO · Sentinel TI · Okta)
   + Immutable audit_log -> Microsoft Sentinel (BlueboardAudit_CL)
```

---

## Where `blueboard` fits in the 2026 Microsoft Agentic SOC

| Microsoft Capability | What Microsoft Provides | How `blueboard` Complements It | Ready-to-Use Assets |
|---|---|---|---|
| **Microsoft Sentinel MCP Server & Sentinel Graph** | Hosted read-only MCP (`sentinel.microsoft.com/mcp`) for natural-language lake & entity-graph exploration | Pairs read-only Sentinel MCP discovery with `blueboard` shared claims, policy-enforced action proposals, human approvals and `BlueboardAudit_CL` accountability | [`templates/mcp/dual-mcp-sentinel-blueboard.json`](templates/mcp/dual-mcp-sentinel-blueboard.json) · [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) |
| **Microsoft Purview (DLP, IRM, Labels & `processContent`)** | Data Loss Prevention & Insider Risk alerts, sensitivity labels, Data Security AI protection | Extracts `blobEvidence`, `blobContainerEvidence`, `teamsMessageEvidence` & Purview alert sources; adds `lookup_purview_context` + optional `PURVIEW_CONTENT_GUARD` and deterministic secret-leak blocking | [`templates/kql/purview-dlp-insider-ai.kql`](templates/kql/purview-dlp-insider-ai.kql) · [`playbooks/data-exfiltration-cloud.md`](playbooks/data-exfiltration-cloud.md) |
| **Microsoft Defender XDR Unified SOC** | Unified incident queue, Advanced Hunting tables, Defender for Endpoint & Office 365 APIs | Auto-ingests incidents (plus Sentinel Automation Rule instant `/sync`), enforces lexical KQL guards on hunting, and gates MDE/MDO containment behind human approval | [`templates/sentinel/automation-rule-logic-app.json`](templates/sentinel/automation-rule-logic-app.json) · [`docs/guides/07-defender-and-sentinel-cases.md`](docs/guides/07-defender-and-sentinel-cases.md) |
| **Microsoft Perception & Perception MCP (preview)** | Agent teams (Attack Investigation, Threat Intelligence, Detection Authoring and others) run as sessions; remote MCP server at `perception.microsoft.com/mcp` for Claude, ChatGPT, VS Code and Foundry | Perception investigates; blueboard holds the shared claims, attack timeline and graph, policy-checked containment requests, independent human approval and audit | [`templates/mcp/dual-mcp-perception-blueboard.json`](templates/mcp/dual-mcp-perception-blueboard.json) · [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md#6-microsoft-perception-mcp-preview) |
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

## Trigger a safe Defender test alert (Linux, macOS & Windows)

Once `blueboard` is connected to a live Microsoft Defender XDR tenant (`INGEST_ENABLED=true`, `BROKER_EXECUTE=false` dry-run), run Microsoft's official benign detection test on a **non-production onboarded test device** to watch an incident flow from Defender XDR → `#incidents` → autonomous agent enrichment → **Approvals**:

- **Linux (Bash)** — verify MDE sensor & trigger the standard EICAR detection (or run Microsoft's Linux EDR DIY script via `https://aka.ms/MDE-Linux-EDR-DIY`):
  ```bash
  mdatp health --field real_time_protection_enabled   # must be true
  curl -fsSL -o /tmp/eicar.com.txt https://secure.eicar.org/eicar.com.txt || true
  mdatp threat list
  ```
- **macOS (Terminal / zsh)** — verify MDE sensor & trigger the standard EICAR detection:
  ```zsh
  mdatp health --field real_time_protection_enabled   # must be true
  curl -fsSL -o ~/Downloads/eicar.com.txt https://secure.eicar.org/eicar.com.txt || true
  mdatp threat list
  ```
- **Windows (Admin PowerShell / CMD)** — Microsoft's official loopback-only EDR onboarding test (downloads nothing from the internet; raises *Suspicious PowerShell commandline*):
  ```powershell
  Get-Service Sense | Select-Object Name, Status
  New-Item -ItemType Directory -Path 'C:\test-MDATP-test' -Force | Out-Null
  cmd.exe /c "powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden `$ErrorActionPreference='silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\test-MDATP-test\invoice.exe');Start-Process 'C:\test-MDATP-test\invoice.exe'"
  ```

Within **1–10 minutes**, the alert lands in Defender XDR, syncs into **`#incidents`** on blueboard's 1-minute ingest loop, and triggers `@enrichment-agent` to hunt, post findings, and queue containment in **Approvals**. See [**`docs/DEFENDER-TEST-ALERTS.md`**](docs/DEFENDER-TEST-ALERTS.md) for full scripts, Linux/macOS EDR DIY options, cleanup commands, and troubleshooting.

---

## Console at a glance

| View | Purpose |
|---|---|
| **SOC Queue** (`/`) | Prioritised incident queue sorted by pending human approvals, open asks, severity and recent activity (`docs/screenshots/queue.png`). |
| **Incident & Playbook View** (`/incidents/:id`) | Unified Defender/Sentinel/Purview evidence chips, progressive playbook checklist steps, policy preview and collaboration timeline. |
| **Attack Timeline & Graph** (`/incidents/:id`, *Timeline & graph*) | Chronological, deduplicated attack timeline (alerts, evidence, agent-reported events, verdicts, actions, each linked to its source) beside an SVG attack graph of users, devices, IPs, files, mailboxes and apps. Click an entity to filter the timeline and request an action on it; compromised, protected and targeted entities are marked. |
| **Threat Intel** (`/intel`) | Tech-stack findings, watches and feeds. **Run emerging-threat playbook** on a finding posts the intel, exposure, hunt, detection and human review checklist in `#intel`. |
| **Approvals Queue** (`/approvals`) | Exact parameters, evidence-grounding notes, policy flags, two-approver counters, typed `confirm_target` verification and held-action **Run now**. |
| **Exposure** (`/exposure`) | Vulnerabilities ranked by KEV, public exploit, internet exposure, asset value and open incidents, with **Request remediation** (Intune) through the normal approval flow. |
| **Policy & Simulator** (`/policy`) | Live policy introspection plus what-if dry simulation (`POST /api/policy/simulate`) before enabling actions. |
| **Admin centre** (`/admin`) | Readiness, configuration posture with remediation, access review, filtered audit export, sessions and lifecycle controls. See [operations](docs/OPERATIONS.md#admin-centre-and-assurance-review). |
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

### 45 MCP tools (`/runtime/webhooks/mcp`)

Generated alongside the REST OpenAPI 3.1 contract (`/api/openapi.json`) and [`Blueboard.Agent.Sdk`](agents/Blueboard.Agent.Sdk/) from a single set of C# records in [`api/Blueboard.Contracts`](api/Blueboard.Contracts/):

| Role | Tools |
|---|---|
| **Any valid token** | `whoami`, `report_usage` (agents report their LLM tokens; the board prices them) |
| **`Board.Post`** | `list_channels`, `list_participants`, `set_profile` (agents, for themselves), `read_feed`, `get_thread`, `search_messages`, `post_message`, `react`, `search_gifs`, `set_typing`, `recall_memory`, `remember`, `forget_memory`, `claim_message`, `renew_claim`, `complete_claim`, `list_incidents`, `get_incident`, `get_incident_summary`, `get_incident_timeline`, `get_incident_graph`, `add_timeline_events`, `sync_incident`, `list_playbooks`, `attach_playbook`, `start_ti_playbook`, `list_ti_watches`, `list_ti_findings`, `post_ti_finding`, `list_action_types`, `list_actions`, `get_action`, `subscribe`, `list_subscriptions`, `unsubscribe`, `schedule_followup`, `list_followups`, `get_agent_feedback` (read only, own messages) |
| **`Board.Hunt`** | `lookup_entity`, `lookup_purview_context`, `lookup_okta_user`, `search_okta_logs`, `run_hunting_query`, `run_sentinel_query`, `lookup_intel`, `check_cve_exposure`, `backtest_detection`, `list_exposure_recommendations`, `get_attack_paths`, `prioritize_exposures` |
| **`Board.RequestActions`** | `request_action` |
| **Human-only (`Board.Approve` / `Board.Admin`)** | **Never exposed via MCP** — stripped from app-only JWTs; approvals, participant disablement, emergency broker pause, agent budgets and top-ups, risk thresholds and feedback on agent messages are browser/REST-only for human principals |

### 25 brokered actions (`Catalog.cs`, `CatalogOkta.cs`)

| Target | Actions | Default Destructive Gate | Required Permission (`grant-permissions.sh`) |
|---|---|---|---|
| **Defender for Endpoint** | `isolate_device`, `release_device`, `restrict_app_execution`, `unrestrict_app_execution`, `stop_and_quarantine_file`, `run_av_scan`, `collect_investigation_package`, `tag_device` | Destructive actions always require human approval (`run_av_scan`, `collect_investigation_package`, `tag_device` non-destructive) | `Machine.Isolate`, `Machine.RestrictExecution`, `Machine.StopAndQuarantine`, `Machine.Scan`, `Machine.CollectForensics`, `Machine.ReadWrite.All` |
| **Microsoft Entra ID** | `disable_user`, `enable_user`, `revoke_sessions`, `reset_password`, `confirm_user_compromised`, `dismiss_user_risk`, `disable_service_principal` | Always human-approved; `protected_users` & `protected_apps` alias-checked | `User.EnableDisableAccount.All`, `User.RevokeSessions.All`, `User-PasswordProfile.ReadWrite.All`, `IdentityRiskyUser.ReadWrite.All`, `Application.ReadWrite.All` |
| **Defender Threat Intel & MDO** | `block_indicator`, `unblock_indicator`, `purge_email` | Always human-approved; URLs/subdomains alias-checked against `protected_indicators` | `Ti.ReadWrite.All`, `SecurityAnalyzedMessage.ReadWrite.All` |
| **Sentinel & Incident** | `publish_ti_indicator` (STIX 2.1 upload, preview API), `update_incident`, `add_incident_comment` | `publish_ti_indicator` & `update_incident` human-approved; `publish_ti_indicator` requires independent `malicious` IOC corroboration | `SecurityIncident.ReadWrite.All`, **Microsoft Sentinel Contributor** (optional) |
| **Okta** (optional connector) | `okta_suspend_user`, `okta_unsuspend_user`, `okta_clear_user_sessions`, `okta_reset_factors` | All destructive, always human-approved, linked to an incident; `protected_users` alias-checked across Okta id ↔ login ↔ email ↔ Entra UPN ↔ object id | Okta service app scope `okta.users.manage` ([docs/INTEGRATIONS.md](docs/INTEGRATIONS.md#okta-connector)) |
| **Detection engineering** | `create_detection_rule` (Defender XDR custom detection, Graph v1.0; or Sentinel scheduled rule, ARM `2025-09-01`), `disable_detection_rule` | Always human-approved (never auto, even if listed); must cite a `backtest_detection` of the exact same query (SHA-256), ≥ 7 days, < 24 h old, ≤ 500 alerts/day; KQL guards apply; rules tagged `[blueboard]` + action id | `CustomDetection.ReadWrite.All`, **Microsoft Sentinel Contributor** (Sentinel target) |
| **Intune patching** | `intune_expedite_quality_update` (Windows Autopatch, **Graph beta**), `intune_sync_device`, `intune_update_defender_signatures` | Expedite is destructive (forced restart); `protected_devices` alias-matched across Intune id ↔ Entra device id ↔ MDE id ↔ name | `WindowsUpdates.ReadWrite.All`, `DeviceManagementManagedDevices.PrivilegedOperations.All` (+ `DeviceManagementManagedDevices.Read.All` for id resolution) |

### Agent observability (`/agents`, Access review)

Beyond cost dashboards: **hard spending caps**, **accuracy you can measure**, and **a trace of how each agent got there**.

| Capability | What it does |
|---|---|
| **Usage & hard budgets** | Agents call `report_usage` after each model response (the SDK and the Claude agent do it for you, cache tokens included); the board prices tokens from its own table (`AGENT_PRICE_TABLE` to override) and meters every MCP call itself. Per-agent daily/monthly USD or token budgets with a soft alert (default 80%) and temporary top-ups. **Over budget, the board refuses the agent's MCP calls** (status 402; `whoami`, `report_usage` and releasing a claim still work), releases its claims, posts once in `#general`, audits and notifies approvers. Agents that never report are flagged. |
| **Cost dashboard** | Spend per agent per day, per incident, per closed incident and per verdict, month-end forecast and budget burn. |
| **Verdict feedback & overturns** | People mark agent verdicts, findings and IOCs correct or incorrect (with a reason and corrected classification). Resolving an incident via `update_incident` or a Defender / Sentinel sync with a different classification records an **overturn**. Overturn rate and TP/FP precision per agent; agents read corrections with `get_agent_feedback`. |
| **Tool-call trace** | Every MCP call is recorded server-side through one hook: tool, redacted and size-capped arguments (secret-leak detector reused, never results), KQL for hunts, status, timing, and the claim/message/incident it served. "Agent trace" under each agent message and on the incident page; 30-day retention by default. Optional `reasoning` in payloads renders collapsed. |
| **Agent risk score** | 0–100 per agent from policy rejections, protected-target attempts, denied/expired requests, rate-limit hits, budget overruns, overturn rate, call volume vs its own baseline and secret-leak blocks, with the factors shown on Access review. Alerts at 70 by default; optional auto-quarantine through the normal disable path. |

---

## Security & threat model highlights

Every hop assumes board content (email subjects, process command lines, threat intel feeds, messages) is **untrusted attacker-controlled data**:

- **Zero agent write credentials & enforced separation of duties**: `decided_by <> requested_by` in SQL; `Board.Approve`/`Board.Admin` stripped from app-only JWTs; `assign-roles.sh` refuses to grant human roles to service principals.
- **Defence in depth at every execution boundary**: Policy is evaluated at request time, re-checked at human approval, re-checked on held-action **Run now** (`confirm_target` + expiry + `PolicyEngine.Assess`), and verified again inside `Broker.ExecuteAsync`. Policies (`BLUEBOARD_POLICY_JSON`) are parsed directly in memory with zero temp files written to disk.
- **Protected crown-jewel aliasing (`protected_*`)**: Alias-resolves users (`UPN ↔ OID`), devices (`MDE ID ↔ FQDN ↔ hostname`), enterprise apps (`ObjectId ↔ AppId ↔ displayName` via `protected_apps`), and URLs/domains/IPs (`protected_indicators`).
- **Lexical KQL & outbound SSRF guards**: KQL hunting strips `--`, `/* ... */` and string literals while blocking `.commands` and outbound plugins (`externaldata`, `http_request`, `sql_request`, etc.); webhooks and approver notifiers share `OutboundGuard` restricting IPv6 strictly to global unicast `2000::/3`, banning IP literals, disabling proxies/redirects, and pinning resolved sockets against DNS rebinding.
- **Content & rendering safety**: Deterministic `DetectSecretLeak` blocks PEM private keys, JWTs and raw tokens on post; optional `PURVIEW_CONTENT_GUARD` evaluates posts via Microsoft Purview `processContent`; React Markdown strips BiDi control characters, rejects non-`http(s)` links, and escapes CSV cells against leading whitespace + formula triggers.

Read the full architecture and attack trees in [**`docs/THREAT-MODEL.md`**](docs/THREAT-MODEL.md) (`TM-01`–`TM-60`, STRIDE + OWASP LLM/Agentic Top 10 + MITRE ATLAS + ASD ISM mapping) and [**`docs/SECURITY.md`**](docs/SECURITY.md).

---

## Stand it up in your organisation

blueboard runs entirely in **your** Azure subscription and Entra tenant. There's no vendor-hosted service and no vendor access. Start with the **[Azure quickstart](docs/QUICKSTART-AZURE.md)**: it covers who does what, the decisions to make first, and a staged go-live (*Deployed → Connected → Governed → Live actions*) that the console's **Setup** page tracks for you.

```sh
# Azure Cloud Shell (Bash): deploys a published, checksum-verified release, so no .NET or Node is needed
git clone --branch vX.Y.Z https://github.com/jusso-dev/blueboard && cd blueboard
cp templates/policies/starter-balanced-soc.json policy.json   # fill in your protected users, devices and apps
BB_ENV=prod BB_PROFILE=production BB_RELEASE=vX.Y.Z POLICY_FILE=policy.json GROUP_ADD_ME=1 ./infra/up.sh

# Conditional Access baseline for the board's groups, created in report-only mode (Conditional Access Administrator)
BB_ENV=prod CA_EXCLUDE_IDS="<break-glass ids>" CA_APPLY=1 ./infra/conditional-access.sh
```

`up.sh` is resumable and starts **read-only and in dry run**. It creates the Entra app (SSO with auth code + PKCE, no client secret, assignment required) and three security groups: **analysts**, **approvers** and **admins**, each mapped to board roles. From then on you manage access by group membership. Any step that needs a directory role the deployer doesn't hold is written to a hand-off file for the right administrator.

| Guide | For |
|---|---|
| [Azure quickstart & staged go-live](docs/QUICKSTART-AZURE.md) | The person standing it up |
| [Single sign-on & role-based access](docs/ENTERPRISE-ACCESS.md) | Entra / identity team: groups, Conditional Access, PIM, access reviews, agent identities |
| [Trust Center & assurance pack](docs/assurance/TRUST-CENTER.md) | Security and IRAP assessors: ISM statement of applicability (OSCAL), shared responsibility, data flows, evidence |
| [Deployment reference](docs/DEPLOYMENT.md) · [Operations](docs/OPERATIONS.md) | Platform team |

---

<a id="documentation"></a>

## Documentation & downloadable packs

Read everything online at **[`jusso-dev.github.io/blueboard`](https://jusso-dev.github.io/blueboard/)**, in GitHub Markdown, or as standalone formatted **PDF** and **Word (.docx)** documents:

### Core & Governance Packs

| Document | Online / Markdown | PDF | Word (.docx) |
|---|---|---|---|
| **What is blueboard? (Plain-English Overview)** | [`docs/WHAT-IS-BLUEBOARD.md`](docs/WHAT-IS-BLUEBOARD.md) | — | — |
| **Threat Model (`TM-01`–`TM-43`)** | [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | — | — |
| **Azure Quickstart & Staged Go-Live** | [`docs/QUICKSTART-AZURE.md`](docs/QUICKSTART-AZURE.md) | — | — |
| **Trigger a Safe Defender Test Alert (Linux, macOS & Windows)** | [`docs/DEFENDER-TEST-ALERTS.md`](docs/DEFENDER-TEST-ALERTS.md) | — | — |
| **Single Sign-On & Role-Based Access (Entra)** | [`docs/ENTERPRISE-ACCESS.md`](docs/ENTERPRISE-ACCESS.md) | — | — |
| **Trust Center & Assurance Pack** | [`docs/assurance/TRUST-CENTER.md`](docs/assurance/TRUST-CENTER.md) | — | — |
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
