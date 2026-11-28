# Threat model: blueboard

| Document control | |
|---|---|
| Version | 2.0 |
| Date | 26 November 2026 |
| Owner | blueboard maintainers (product); the deploying organisation owns its instance's risk acceptance |
| Review cadence | Every release that changes authentication, the action broker, policy, infrastructure or the release pipeline, and at least every six months |
| Method | Asset-centred threat analysis with STRIDE classification. Each control is traced to code and, where one exists, to the automated test that verifies it |
| Status | Describes the code on branch `enterprise-readiness` as at the date above, including the enterprise controls added in this revision (role-change and export audit, audit log viewer, idle sign-out, inactivity disable, PostgreSQL certificate validation, TLS 1.3 option, NSGs, pgaudit, scm lockdown). Where a control is planned but not in the code, the threat is shown as residual |

This model is for an assessor or security architect who needs to decide whether blueboard's residual risk is acceptable for a given deployment. It states what the product enforces, what it relies on the deploying organisation (the *consumer*) to do, and what remains. It doesn't claim compliance with any framework. Where an ISM control is the natural reference, the ISM 2026.09.4 identifier is given.

- [1. Scope, boundary and assumptions](#1-scope-boundary-and-assumptions)
- [2. Assets](#2-assets)
- [3. Actors and trust zones](#3-actors-and-trust-zones)
- [4. Data flows](#4-data-flows)
- [5. Rating scale](#5-rating-scale)
- [6. Threat register](#6-threat-register)
- [7. Attack trees](#7-attack-trees)
- [8. Residual risk summary](#8-residual-risk-summary)
- [9. Risk acceptance](#9-risk-acceptance)
- [10. Security test traceability](#10-security-test-traceability)
- [11. Known limitations](#11-known-limitations)
- [12. Pre-go-live verification](#12-pre-go-live-verification)

---

## 1. Scope, boundary and assumptions

### In scope

- The board API and MCP server (`api/Blueboard.Api`, .NET 10 isolated Azure Functions), including the policy engine, action broker, KQL guard, outbound guard, content guards and background jobs.
- The web front end (`web/`) and its static host (`web/host`).
- The PostgreSQL schema and roles (`db/migrations/`).
- The Azure resources defined in `infra/*.bicep`, in both the `mvp` and `production` profiles, with or without `FRONT_DOOR=true`.
- The deployment scripts (`infra/*.sh`) and the build and release pipeline (`.github/workflows/`).

### Out of scope

- The consumer's Entra tenant configuration beyond what `entra-app.sh`, `entra-groups.sh`, `assign-roles.sh` and `conditional-access.sh` create.
- The consumer's endpoints and browsers.
- AI agents' own runtime, prompts, tools and model providers. Agents are treated as untrusted clients of the board (zone TZ-2), whatever they run on.
- Microsoft services: Graph, Defender, Sentinel, Purview, Entra and the Azure platform. They are trusted to behave as documented (see A1).

### Assumptions

Each assumption is a dependency. If it doesn't hold, the residual ratings below don't hold either.

| ID | Assumption | Owner |
|---|---|---|
| A1 | Microsoft Entra ID issues and signs tokens correctly, and Azure isolates tenants and resources as documented | Microsoft (inherited) |
| A2 | The consumer **enforces** Conditional Access for the board's groups: phishing-resistant MFA for everyone, plus a compliant device and a short sign-in frequency for approvers and admins. `conditional-access.sh` creates these policies **in report-only mode**. Enforcement (`CA_STATE=on`) is the consumer's act | Consumer |
| A3 | Approvers and admins are named people with a need for the role, assigned through groups that the consumer reviews | Consumer |
| A4 | The consumer reviews `policy.json`, populates every `protected_*` list, and tests each brokered action in a non-production tenant before setting `BROKER_EXECUTE=true` | Consumer |
| A5 | Model providers used by agents are **untrusted for integrity**: their output can be wrong or adversarially steered. Confidentiality of data sent to them is the consumer's choice of provider | Consumer |
| A6 | Whoever holds Owner or Contributor on the board's resource group, or controls `blueboard-id-api`, is trusted at the level of a platform administrator. The model doesn't defend the board against them, only records what they do where it can (TM-31, TM-32) | Consumer |
| A7 | Production use runs the `production` profile. The `mvp` profile is for evaluation and dry-run pilots; threats specific to it are rated separately (TM-35) | Consumer |

---

## 2. Assets

Ranked by the harm their compromise would do.

| Rank | Asset | Why it matters |
|---|---|---|
| 1 | **Containment authority over the tenant**: the ability to isolate devices, disable users and service principals, reset passwords, revoke sessions, purge mail and block or publish indicators | Misuse causes an outage or locks out administrators (break-glass, domain controllers). It is the reason this system exists and the main thing it must gate |
| 2 | **The board identity's Microsoft permissions** (`blueboard-id-api`: Graph, Defender for Endpoint and optionally Sentinel Contributor) | Anyone holding a token for this identity bypasses the board's policy and approval entirely |
| 3 | **The audit trail** (`audit_log`, and `BlueboardAudit_CL` in the production profile) | Accountability for every request, approval and execution. Needed to investigate misuse and to repudiate false claims |
| 4 | **The action policy** (`policy.json`) | Defines what is protected, what auto-runs and what needs two approvers. Tampering widens containment authority |
| 5 | **Incident and investigation data**: Defender/Sentinel incident payloads, evidence, board messages, findings, hunting results | Sensitive: user names, device names, command lines, email subjects, DLP evidence. Usually OFFICIAL: Sensitive or the consumer's equivalent |
| 6 | **Identity metadata**: principals (Entra object ids, display names, sign-in names, roles) | Personal information about staff, and the map of who can approve |
| 7 | **Availability of the board** | During an incident, analysts and agents depend on it. Loss is an inconvenience, not a containment failure: Defender and Entra remain usable directly |

---

## 3. Actors and trust zones

| Zone | Contents | Trust | Crossing into the board |
|---|---|---|---|
| **TZ-0 Adversary data** | Attacker-controlled content inside telemetry: email subjects, file names, command lines, URLs, OAuth app names, threat intel advisories | Hostile | Only as data, through Microsoft ingest or agent posts. Never as instructions |
| **TZ-1 People** | Analysts (`Board.Post`, `Board.Hunt`, `Board.RequestActions`), approvers (`Board.Approve`), admins (`Board.Admin`), using the SPA | Authenticated and accountable. Trust depends on A2 and A3 | Delegated Entra token for `api://blueboard-<env>` with the `Board.Access` scope, issued to the board's own client |
| **TZ-2 Agents and external MCP servers** | Reference and consumer agents, Security Copilot, coding agents, the Sentinel MCP server, model providers | **Untrusted for intent**. Authenticated for identity | App-only Entra token. `Board.Approve` and `Board.Admin` are removed from app-only tokens whatever Entra assigns |
| **TZ-3 Static web host** | `blueboard-web`: SPA files, `/config.json` (public values only), CSP and HSTS | Public. Holds no identity, secret or data | None: the browser calls the API directly |
| **TZ-4 Board trusted computing base** | Function App: authentication, policy engine, broker, guards, background jobs. Identities `blueboard-id-api` (migrations, Microsoft permissions) and `blueboard-id-db` (runtime database role) | Trusted | — |
| **TZ-5 Data tier** | PostgreSQL Flexible Server (Entra-only authentication), Key Vault (production), Storage (no shared keys) | Trusted. Network-isolated in production only | Managed identity tokens. `mvp`: public endpoints with Entra authentication |
| **TZ-6 Microsoft security plane** | Graph, Defender for Endpoint, Entra, Purview, Sentinel, `BlueboardAudit_CL` | Trusted (A1) | Board identity's managed identity tokens. Exact Microsoft origins only |
| **TZ-7 Operators and pipeline** | Resource-group Owners and Contributors, Entra administrators, GitHub maintainers, the release workflow | Trusted at platform-administrator level (A6) | Azure Resource Manager, Entra admin centre, GitHub |

TZ-7 is new in this version. The previous model folded operators into TZ-4, which hid the release, schema-owner and deployment-access threats (TM-23, TM-27, TM-31, TM-32, TM-36).

---

## 4. Data flows

### Context and trust boundaries

```mermaid
flowchart LR
  subgraph TZ0["TZ-0 Adversary data"]
    ATT["Attacker artefacts<br/>(email subjects, command lines, IOCs)"]
  end
  subgraph TZ1["TZ-1 People (SPA, MSAL auth code + PKCE)"]
    HUM["Analysts, approvers, admins"]
  end
  subgraph TZ3["TZ-3 Static host"]
    UI["blueboard-web<br/>CSP + HSTS, no identity, no secrets"]
  end
  subgraph TZ2["TZ-2 Agents (untrusted for intent)"]
    AG["Agents (app-only tokens;<br/>Approve/Admin removed)"]
    SMCP["Sentinel MCP server"]
    LLM["Model provider"]
  end
  subgraph TZ4["TZ-4 / TZ-5 Board (one Australian region)"]
    API["Function App: authN/Z, policy, broker,<br/>KQL guard, outbound guard, content guards"]
    DB[("PostgreSQL 16<br/>runtime role blueboard_app")]
  end
  subgraph TZ6["TZ-6 Microsoft security plane"]
    MS["Graph · Defender · Entra · Purview<br/>Sentinel · BlueboardAudit_CL"]
  end
  subgraph TZ7["TZ-7 Operators and pipeline"]
    OPS["RG Owner / Entra admins / release workflow"]
  end
  ATT -->|"data only"| MS
  MS -->|"incident ingest (board identity)"| API
  HUM --> UI
  HUM -->|"delegated token, Board.Access"| API
  AG <-->|"app-only token, MCP"| API
  AG <--> SMCP
  AG <--> LLM
  API <-->|"parameterised SQL"| DB
  API -->|"approved, policy-rechecked writes"| MS
  API -->|"audit export (production)"| MS
  OPS -->|"deploy, roles, permissions"| API
```

### Brokered write, with re-verification

```mermaid
flowchart TD
  REQ["request_action (Board.RequestActions)"] --> SCHEMA["Catalog validation<br/>(typed params per kind)"]
  SCHEMA --> EVAL1["Policy assessment: protected lists with aliases,<br/>evidence membership, disabled kinds"]
  EVAL1 -->|"protected or disabled"| REJ["rejected (audited)"]
  EVAL1 -->|"non-destructive, in auto_approve,<br/>no notes"| EXEC
  EVAL1 -->|"otherwise"| WAIT["pending_approval<br/>expires (default 4 h)"]
  WAIT --> DECIDE["Human approver, not the requester<br/>confirm_target / two approvers if required"]
  DECIDE --> EVAL2["Policy re-check at approval"]
  EVAL2 -->|"broker running"| CLAIM["atomic approved → running"]
  EVAL2 -->|"broker paused"| HELD["held"]
  HELD -->|"admin resumes, approver Run now"| RUNNOW["expiry + confirm_target + policy re-check"]
  RUNNOW --> CLAIM
  CLAIM --> EXEC["Execute: re-validate params,<br/>execution-time policy guard,<br/>exact Microsoft origin"]
  EXEC --> AUDIT["audit_log + action_result message<br/>(+ BlueboardAudit_CL in production)"]
```

`act_on_instruction` (TM-38) is a second path into `DECIDE`. A named approver's recent board message counts as their approval, under the rules in `Actions/Instruction.cs`.

---

## 5. Rating scale

Likelihood (L) and consequence (C) are each rated 1 to 5, and **risk = L × C**. Ratings are for a `production`-profile deployment that meets assumptions A1–A7, unless the threat says otherwise.

| Score | Likelihood | Consequence |
|---|---|---|
| 1 | Rare: needs several independent failures or a privileged insider | Negligible: no tenant change, no data exposed |
| 2 | Unlikely: needs a specific precondition the consumer controls | Minor: limited data exposure, or a reversible low-impact action |
| 3 | Possible: a realistic attacker with a foothold could do it | Moderate: sensitive data exposed, or one reversible containment action against a non-critical target |
| 4 | Likely: commodity technique against a default configuration | Major: containment against a critical target, or loss of the audit trail |
| 5 | Almost certain: no precondition beyond reaching the system | Severe: tenant-wide outage, administrator lock-out, or the board identity's permissions in an attacker's hands |

| Risk | Band |
|---|---|
| 15–25 | **High**: needs treatment or explicit acceptance at executive level before go-live |
| 8–14 | **Medium**: acceptable with the named consumer control in place, or by the system owner |
| 1–7 | **Low**: acceptable |

---

## 6. Threat register

Columns:
- **Inh.** and **Res.**: inherent and residual `L×C=risk`.
- **Owner**: who must act for the residual rating to hold.
- **Verified by**: the automated test. *None* means the control is checked by review only.
- Test names are in `api/Blueboard.Api.Tests` (unit), `api/Blueboard.Api.IntegrationTests` (PostgreSQL) or `infra/tests/up-test.sh`.

### 6.1 Agent and prompt-driven threats

| ID | Threat (STRIDE) | Scenario and entry point | Asset | Inh. | Controls (code) | Verified by | Res. | Treatment / owner |
|---|---|---|---|---|---|---|---|---|
| **TM-01** | Indirect prompt injection drives an agent to request harmful containment (E) | An attacker puts instructions in an email subject or command line. An agent reads it through ingest or hunting and calls `request_action disable_user ciso@…`. Entry: MCP `request_action` | 1 | 4×5=20 | Agents hold no Microsoft credentials (only `blueboard-id-api` does). Destructive kinds never auto-run, even if listed in `auto_approve` (`Actions/Policy.cs` assessment). Protected lists are checked across aliases. Requests wait for a human approver who isn't the requester (`Broker.cs` decide). Ungrounded indicators are marked `not in evidence` | `PolicyFileTests.Destructive_kind_in_auto_approve_is_warned_and_ignored`, `PolicyTests.Protected_user_is_rejected_case_insensitively`, `BoardTests.Requester_cannot_approve_their_own_request`, `IncidentSummaryTests.Indicator_absent_from_evidence_and_findings_is_not_in_evidence` | 2×4=8 | Mitigate. Residual is approver error (TM-09). Owner: consumer (approver discipline, protected lists). ISM-2113 |
| **TM-02** | Cross-MCP confused deputy (E) | Content returned by the Sentinel MCP server steers an agent into blueboard requests or false findings. Entry: agent tool chain | 1, 5 | 3×4=12 | blueboard is the only broker of writes. Indicators in findings are checked against the incident's Graph evidence. `publish_ti_indicator` needs an independent `malicious` IOC from a second principal | `IntelTests.Publish_is_never_auto_approved_and_protected_indicators_are_rejected`, `IncidentSummaryTests.Indicator_named_in_a_finding_is_grounded_but_not_in_evidence` | 2×3=6 | Mitigate. Product |
| **TM-03** | Threat intel feed poisoning (T) | A compromised feed returns oversized bodies, redirects to metadata endpoints, or injected advisories. Entry: `TiFetcher` | 5, 7 | 3×3=9 | HTTPS, exact host allowlist, same-host HTTPS redirects only (three hops), 25 MB cap, no tokens sent. Cards are marked untrusted for agents. Sources are compared side by side | `TiFetcherTests.Redirect_to_another_host_or_to_http_fails_and_is_not_cached`, `TiFetcherTests.Body_over_the_cap_fails_and_is_not_cached`, `TiFetcherTests.Urls_off_the_allowlist_are_refused_before_sending` | 2×2=4 | Mitigate. Feeds are off by default. Product |
| **TM-04** | Containment against break-glass accounts or Tier-0 hosts (E) | An agent requests `isolate_device` on a domain controller by its Defender id, or `disable_user` on a break-glass account. Entry: `request_action` | 1 | 3×5=15 | Protected users, devices, apps and indicators are matched across aliases from the incident evidence (UPN ↔ object id, Defender id ↔ FQDN ↔ host name). An unresolvable id with protected lists present is flagged *checked by id only* and never auto-runs | `PolicyTests.Protected_device_matches_any_alias`, `PolicyTests.Protected_user_listed_by_upn_is_rejected_when_request_uses_object_id`, `PolicyTests.Unresolvable_device_is_flagged_when_a_protected_list_exists`, `DefenderSentinelTests.Merged_aliases_enforce_protected_lists_even_when_first_evidence_lacked_name` | 2×5=10 | Mitigate. Residual: an asset missing from `policy.json`. Owner: consumer (A4, SOP-03) |
| **TM-05** | Protected-indicator bypass by URL normalisation (T) | `https://login.microsoftonline.com/` is protected. An agent blocks `aad.login.microsoftonline.com`. Entry: `request_action block_indicator` | 1 | 3×4=12 | Both the candidate and the protected entries are reduced to a host; subdomains of a protected host match | `AdversarialAndIntegrationsTests.Url_entries_in_protected_indicators_protect_host_and_subdomains`, `PolicyTests.Protected_indicators_and_subdomains_are_rejected` | 2×3=6 | Mitigate. Residual: CIDR ranges in `protected_indicators` aren't expanded. Product (known gap) |
| **TM-06** | The board disables its own identity or a critical app (D, E) | An injected request asks for `disable_service_principal` on `blueboard-api` or the Sentinel MCP app | 1, 7 | 3×4=12 | App targets are typed separately from users. `protected_apps` matches object id, app id and display name. Starter policies list the board's own apps | `AdversarialAndIntegrationsTests.Protected_apps_and_target_type_isolate_disable_service_principal`, `DefenderSentinelTests.Starter_policy_templates_all_validate_cleanly` | 2×3=6 | Mitigate. Owner: consumer adds new critical apps |
| **TM-07** | Time-of-check / time-of-use bypass after policy tightens (T, E) | An action is approved, then an asset becomes protected. The action runs from a held state or after recovery | 1 | 3×4=12 | Policy is re-assessed at approval, at Run now and at execution. A refusal is audited as `action.rejected_on_recheck` | `AdversarialAndIntegrationsTests.Execution_policy_guard_blocks_delayed_or_held_action_when_policy_tightens`, `ApprovalTests.Approval_is_refused_when_the_device_became_protected_after_the_request`, `OpsTests.Pause_set_after_approval_stops_execution_at_claim_time` | 1×4=4 | Mitigate. Policy is loaded once per instance, so a changed policy needs a restart (by design). Product |
| **TM-08** | Self-approval, agent approval or collusion (E) | An agent approves, or a person approves their own request | 1 | 4×5=20 | `Board.Approve`/`Board.Admin` are removed from app-only tokens. They are declared for users only, and `assign-roles.sh` refuses them for service principals. The requester can't approve, run or cite their own message. Two-approver kinds need two distinct people | `SecurityTests.Agents_never_hold_approve_or_admin`, `BoardTests.Requester_cannot_approve_their_own_request`, `ApprovalTests.Requester_cannot_be_either_approver`, `ApprovalTests.Two_approver_kind_needs_two_different_people` | 2×4=8 | Mitigate. Residual: two colluding approvers. Owner: consumer (A3, `approval-burst` rule, two-approver kinds for high-impact actions) |
| **TM-09** | Approval fatigue and automation bias (E) | Approvers approve plausible but wrong requests from a busy queue | 1 | 4×4=16 | No one-key approve. Justification is shown as an untrusted quote. `confirm_target` makes the approver type the target. Pending actions are capped per incident. Requests expire. Ungrounded IOCs are marked | `ApprovalTests.Confirm_target_is_enforced_server_side`, `LimitTests.Pending_actions_per_incident_are_capped`, `ApprovalTests.Expired_request_cannot_be_approved` | 3×3=9 | Mitigate + accept. Owner: consumer (process, `confirm_target` for destructive kinds, approval latency review in `/reports`) |
| **TM-10** | Data exfiltration through hunting queries (I) | An agent submits KQL with `externaldata`, `http_request` or a management command hidden in a comment | 5 | 3×4=12 | Lexical KQL guard strips strings and comments, then refuses management commands and outbound plugins. Timespans are bounded | `AdversarialAndIntegrationsTests.Kql_validator_blocks_comment_bypass_outbound_plugins_and_bad_durations` | 1×4=4 | Mitigate. Product. Queries through the Sentinel MCP server are outside this guard (consumer workspace RBAC) |
| **TM-11** | SSRF and DNS rebinding through webhooks or notifications (I) | An agent subscribes a webhook to a metadata address or a rebinding host | 4, 5 | 3×4=12 | HTTPS only, exact host allowlist, no IP literals, public addresses only (IPv6 global unicast minus transition ranges), checked again at connect, no redirects, no proxy | `WebhookGuardTests.Rebinding_to_loopback_is_refused_at_resolve_time`, `AdversarialAndIntegrationsTests.Outbound_guard_blocks_ipv6_transition_and_special_ranges`, `OpsTests.Notification_urls_need_https_and_an_allowed_host` | 1×3=3 | Mitigate. Exception: a single-label ntfy host the consumer allowlists may use http and a private address (TM-39). Product |
| **TM-12** | A disabled agent persists through webhooks, claims or follow-ups (E) | An admin disables a compromised agent, but its subscriptions, leases and scheduled follow-ups keep acting | 1, 5 | 3×3=9 | Disabling releases claims and disables subscriptions. Deliveries and follow-ups skip disabled principals. The next call is refused | `OpsTests.Disabled_agent_is_refused_on_its_next_call_and_the_board_says_so` | 1×3=3 | Mitigate. Owner: consumer also disables the Entra service principal |
| **TM-13** | Status spoofing and mention amplification (S) | An agent posts a reserved status (`action_approved`) or hides `@all` in a follow-up note | 7 | 3×2=6 | Reserved states are refused for non-system authors. Payloads are capped at 64 KB. `@` in follow-up notes is neutralised | `AdversarialAndIntegrationsTests.Secret_leak_guard_reserved_status_payload_size_and_single_char_mentions`, `AdversarialAndIntegrationsTests.Followup_body_escapes_spoofed_mentions_in_note`, `BoardTests.Outside_principals_cannot_post_board_types` | 1×2=2 | Mitigate. Product |
| **TM-14** | Secrets or regulated data posted to the board (I) | An agent pastes a private key, a bearer token or DLP-classified data | 5 | 3×4=12 | Deterministic secret patterns are blocked on post. Optional Purview `processContent` guard (`PURVIEW_CONTENT_GUARD=audit\|block`) | `AdversarialAndIntegrationsTests.Secret_leak_guard_reserved_status_payload_size_and_single_char_mentions`, `AdversarialAndIntegrationsTests.Purview_content_guard_blocks_restricted_posts_and_audits_otherwise` | 2×3=6 | Mitigate. Residual: novel secret formats when the Purview guard is off. Owner: consumer (turn the guard on) |
| **TM-43** | Prompt-injected verdict corroboration drives conditional automation (S, E) | Attacker-controlled incident content steers one agent into posting a high-confidence `truePositive` verdict and another (or the same) agent into requesting a destructive kind with a rule. Entry: MCP `post_message type=verdict` + `request_action` | 1 | 4×5=20 | Off unless `policy.json` lists the kind in `automation.conditional_auto_allowed` (irreversible kinds need `irreversible_auto_allowed` too). The requester's own verdicts never count (case-insensitive); `require_human_verdict` limits corroboration to people; `max_requester_risk` refuses requesters whose agent risk score is above the limit or unknown; `create_detection_rule` (`Catalog.NeverAuto`) can never be listed; any dissenting verdict blocks; confidence floor from the file; every target must be in the incident evidence; protected lists reject first; hourly and per-incident caps under a per-kind DB lock; reversible kinds must auto-revert (`revert_after_minutes`); rule re-checked at execution (`action.auto_withdrawn`); kill switch; every automatic run labelled, notified (`action.auto_executed`) and audited (`action.auto_approved`) (`Actions/Automation.cs`, `Actions/Broker.cs`) | `AutomationTests.Requesters_own_verdict_never_corroborates`, `AutomationTests.Requester_match_is_case_insensitive_so_a_handle_variant_cannot_self_corroborate`, `AutomationTests.A_dissenting_verdict_blocks_automation`, `AutomationTests.Require_human_verdict_ignores_agent_verdicts`, `AutomationTests.Protected_lists_always_block_whatever_the_rule_says`, `AutomationTests.Caps_fall_back_to_approval_not_rejection`; integration `AutomationTests.Requesters_own_verdict_does_not_corroborate`, `AutomationTests.Concurrent_requests_cannot_both_slip_under_the_cap` | 2×4=8 | Mitigate. Two colluding or co-compromised agents can still corroborate each other unless `require_human_verdict` or `requesters` is set (policy-check warns). Owner: consumer (rule design), product (controls). |
| **TM-51** | Spoofed attack-timeline events and graph poisoning (S, T) | A compromised or prompt-injected agent posts `finding`/`ioc` payload `events` (or `add_timeline_events`) claiming an attacker "logged on to dc01" at a plausible time, or reports a domain controller IP as malicious, so the timeline and attack graph point approvers at the wrong asset. Same path for text copied from Perception or Sentinel MCP output. Entry: MCP `post_message`, `add_timeline_events` | 1, 7 | 3×4=12 | Timeline and graph are computed by the board on read, never stored or model-written (`Board/IncidentTimeline.cs`, `Board/IncidentGraph.cs`). Reported events are attributed (`reported_by`, message id; their `source` is always `reported by @handle`, and any source the participant claims is kept apart as untrusted `claimed_source`), marked `reported`, and flagged `in_evidence: false` when the entity isn't in Defender evidence; IOC-only graph nodes are marked `in_evidence: false` and inferred edges are marked. Event `ts` must parse and may not be in the future; entity/action are length-bounded, one line, and pass the secret-leak guard and rate limits like any post. Graph and timeline don't feed policy: every action target is still checked against `protected_*` and incident evidence, and a person who isn't the requester approves | `AttackViewTests.Reported_event_on_an_entity_not_in_evidence_is_flagged`, `AttackViewTests.Reported_event_is_attributed_to_the_reporter_whatever_source_it_claims`, `AttackViewTests.Bad_timeline_events_are_refused`, `AttackViewTests.Sign_in_sessions_link_user_to_ips_and_iocs_raise_verdicts`, `AttackViewTests.Protected_nodes_are_flagged_and_named_only_for_admins_and_actions_mark_targets`; integration (not run without a database): `AttackViewTests.Participants_cannot_forge_events_with_bad_times_and_graph_hides_protected_names` | 2×3=6 | Mitigate. Residual: a reported event on an entity that *is* in evidence, with a false time or action, isn't detectable by the board; approvers weigh who reported it. Owner: product (marking), consumer (approver discipline, TM-09) |

### 6.2 Identity, session and access threats

| ID | Threat (STRIDE) | Scenario and entry point | Asset | Inh. | Controls (code) | Verified by | Res. | Treatment / owner |
|---|---|---|---|---|---|---|---|---|
| **TM-15** | Token confusion and development switches in Azure (S) | Forged platform principal headers, or `DEV_AUTH`/`DEMO_MODE`/API base URL overrides switched on in Azure | 1, 5 | 3×5=15 | Only validated bearer tokens are accepted (signature, issuer, audience, tenant, lifetime). Delegated tokens must carry `Board.Access` and be issued to the board's client. Platform headers are ignored. Development switches refuse to start in Azure | `SecurityTests.Platform_principal_header_is_never_trusted`, `SecurityTests.Delegated_tokens_must_come_from_the_board_app`, `DemoModeTests.Dev_auth_is_refused_in_azure_or_with_a_real_tenant`, `DemoModeTests.Override_without_demo_mode_is_refused_at_startup` | 1×5=5 | Mitigate. Product |
| **TM-25** | Over-privileged or orphaned agent identities (E) | A retired agent's identity still holds `Board.RequestActions`. Entry: Entra app role assignments | 1, 5 | 3×3=9 | Agents can't hold Approve/Admin. Every first sign-in writes `principal.joined`. The Sentinel rule `new-agent` alerts. The Setup check lists agents with last-seen | `SecurityTests.Agents_never_hold_approve_or_admin`, `OpsTests.First_sign_in_of_a_nameless_app_token_gets_an_agent_handle` | 2×3=6 | Mitigate. Owner: consumer (access reviews; see TM-41) |
| **TM-28** | Bearer-token replay window (S) | A token is stolen from a browser or an agent host, then replayed after the user is disabled or the token is revoked in Entra. Entry: any API route | 1, 5 | 3×4=12 | Validation of signature, audience, tenant and lifetime (one minute of clock skew). Tokens live in `sessionStorage`, not `localStorage`. **Disabling a participant on the board takes effect on the next request.** Idle sign-out ends the browser session (TM-29). Not in place: continuous access evaluation, sender-constrained (proof-of-possession) tokens | `SecurityTests.Delegated_tokens_must_come_from_the_board_app`, `OpsTests.Disabled_agent_is_refused_on_its_next_call_and_the_board_says_so` | 2×4=8 | Accept + consumer control. A revoked Entra session can still use its access token for up to its lifetime (typically 60–90 minutes). The consumer disables the participant on the board for immediate effect, and Conditional Access compliant-device for approvers narrows theft (A2). ISM-1173, ISM-1682 |
| **TM-29** | Unattended or stale sessions (S) | An approver leaves a signed-in console unlocked. Entry: browser | 1 | 3×4=12 | Idle sign-out in the SPA (`SESSION_IDLE_MINUTES`, default 15, max 480; `web/src/lib/idle.ts`). Input in any tab resets the clock, a warning shows in the final minute, and expiry clears MSAL's tokens and ends the Entra session for the app. `conditional-access.sh` adds a 4-hour sign-in frequency for approvers and admins (report-only until enforced). The timer runs in the browser: a client that never runs the SPA (an agent, a script with a stolen token) isn't affected (TM-28) | `idle.test.ts` (`idleState`, `lastActivity`) | 2×4=8 | Mitigate. Owner: consumer (keep the default, device lock policy, enforce sign-in frequency) |
| **TM-30** | Malicious or compromised `Board.Admin` (E, R) | An admin account is taken over. **Can:** disable or re-enable participants; pause or resume the broker; rename agents; change board notification defaults (for example, turn off approval notices); read reports and setup. **Cannot:** approve (that needs `Board.Approve`); approve or run their own requests; change `policy.json`, `RETENTION_DAYS` or `BROKER_EXECUTE` (deploy access); edit or delete `audit_log` | 1, 3, 7 | 2×4=8 | Admin is human-only and separate from Approve in the default groups. Every admin change is audited (`principal.enabled/disabled`, `principal.profile_updated`, `broker.paused/resumed`, `notify.settings_changed`), and so are exports (`report.exported`, `audit.exported`). The audit log viewer is admin-only and read-only. Sentinel rule `broker-paused-or-principal-disabled`. The approvals of an admin who also holds Approve stay subject to the not-the-requester rule | `OpsTests.Participants_list_needs_admin_and_counts_activity`, `OpsTests.Only_admins_rename_other_agents`, `EnterpriseControlsTests.Audit_log_filters_pages_and_is_admin_only`, `RuntimeRoleTests.Runtime_role_appends_to_audit_log_but_cannot_rewrite_it` | 2×3=6 | Mitigate. Owner: consumer (keep Admin and Approve in different hands, PIM for both, alert on the Sentinel rule) |
| **TM-41** | Inactive accounts and stale agents keep access (E) | A leaver's group membership or an unused agent's role assignment remains. Entry: Entra | 1, 5 | 3×3=9 | Roles come from the token on every request, so removing a group member takes effect at their next token. The Setup page lists agents not seen for 15 minutes. `INACTIVE_DISABLE_DAYS` (off by default, minimum 30) disables people and agents not seen for that long, daily, with an audit row, a `#general` notice, claims released and webhooks off | `EnterpriseControlsTests.Inactive_principals_are_disabled_with_audit_and_claims_released` | 2×2=4 | Mitigate. Owner: consumer (set `INACTIVE_DISABLE_DAYS`; Entra access reviews on the three groups and on agent role assignments). Disabling on the board doesn't remove the Entra assignment |
| **TM-42** | Role changes aren't attributable in the board (R) | A person gains Approve through a group change or PIM activation. Entry: Entra | 3 | 3×3=9 | When a token's roles differ from the stored ones, the board writes `principal.roles_changed` (added, removed, source `entra_token`) at that principal's first request after the change (`Auth/Authenticator.cs`). It records *that* roles changed and when they were first used, not *who* changed them in Entra | `EnterpriseControlsTests.Role_change_seen_in_a_token_is_audited_once` (the delta; the audit write isn't integration-tested) | 2×2=4 | Mitigate + transfer: Entra's audit log is the authoritative record of who changed membership. Owner: consumer (send Entra audit logs to Sentinel). ISM-1509 |
| **TM-44** | A single admin loosens policy (E, R) | One compromised or careless `Board.Admin` widens automation, adds a rule or a playbook trigger, or resumes paused automation. Entry: `/policy` REST routes | 1 | 3×5=15 | Loosening is filed as a pending change; only a different admin can apply it (service check and SQL `CHECK decided_by <> requested_by` on applied loosenings); expired changes can't be applied (trigger); stale diffs are refused; tightening and pausing apply at once; every step audited and posted in `#general`; human principals only, never MCP; app-only tokens never carry Admin (`Actions/PolicyStore.cs`, `db/migrations/015`) | `AutomationTests.Loosening_waits_for_a_second_different_admin`, `AutomationTests.Sql_refuses_a_loosening_applied_by_its_requester`, `AutomationTests.Expired_changes_cannot_be_approved`, `AutomationTests.Agents_and_non_admins_cannot_change_policy`, `AutomationTests.Tightening_and_loosening_are_classified`, `AutomationTests.Policy_administration_is_never_an_mcp_tool` | 2×4=8 | Mitigate. Two colluding admins remain (TM-08). Owner: consumer (at least two admins, A-separation). |

### 6.3 Data, audit and platform threats

| ID | Threat (STRIDE) | Scenario and entry point | Asset | Inh. | Controls (code) | Verified by | Res. | Treatment / owner |
|---|---|---|---|---|---|---|---|---|
| **TM-16** | SQL injection or runtime privilege escalation in the database (T, E) | Crafted input reaches SQL, or the runtime identity tries to alter the schema or the audit log | 3, 5 | 3×4=12 | Bound parameters throughout. Requests run as `blueboard-id-db` (member of `blueboard_app`, owns nothing, no `UPDATE`/`DELETE`/`TRUNCATE` on `audit_log`, no DDL). Entra-only database authentication | `RuntimeRoleTests.Board_connects_as_the_runtime_role_not_the_owner`, `RuntimeRoleTests.Runtime_role_cannot_change_schema_or_migration_record` | 1×4=4 | Mitigate. `DB_RUNTIME_ROLE=false` (single identity) removes this control; the Setup page warns. Product |
| **TM-17** | Stored XSS, link injection and bidirectional-text spoofing (I) | A message body carries HTML, `javascript:` links or a right-to-left override | 1, 5 | 3×4=12 | Markdown renderer with no HTML passthrough, `http(s)` links only, BiDi controls stripped in the UI and notifications, CSP `script-src 'self'` | `IncidentSummaryTests.Markdown_contains_no_raw_html_or_injected_links_from_bodies`, `AdversarialAndIntegrationsTests.Notifier_blocks_ip_literals_and_strips_bidi_overrides`, `WebHostTests.Default_is_entra_with_hsts` | 1×3=3 | Mitigate. Product |
| **TM-18** | CSV formula injection in exports (T) | An incident title beginning `=` (or whitespace then `=`) opens as a formula | Analyst workstation | 3×3=9 | Cells beginning with a formula character, after leading whitespace, are neutralised | `SecurityTests.Csv_neutralises_formula_injection`, `AdversarialAndIntegrationsTests.Csv_guard_neutralises_leading_whitespace_and_newlines_before_formulas` | 1×2=2 | Mitigate. Product |
| **TM-19** | Queue flooding and API quota exhaustion (D) | A runaway agent floods requests, hunts or posts | 7 | 4×3=12 | Per-principal token buckets in PostgreSQL across instances. Pending actions capped per incident. HTTP 429 with `Retry-After`. `limit.hit` audited and alerted. Optional per-IP WAF limits (`FRONT_DOOR=true`) | `LimitTests.Limits_hold_across_two_instances_sharing_one_database`, `LimitTests.Pending_actions_per_incident_are_capped`, `LimitTests.Rest_returns_429_with_retry_after` | 2×2=4 | Mitigate. Product |
| **TM-20** | Poisoned indicators published to Sentinel TI (T) | One compromised agent publishes a corporate IP as malicious | 1 | 3×4=12 | `publish_ti_indicator` checks `protected_indicators`, needs an independent malicious IOC from another principal, and is never auto-approved | `IntelTests.Publish_is_never_auto_approved_and_protected_indicators_are_rejected` | 2×3=6 | Mitigate. Residual: Sentinel Contributor is workspace-wide. Owner: consumer (dedicated TI workspace) |
| **TM-21** | Destructive action runs twice after a crash (T) | The host recycles after Defender accepts a request but before the status commits | 1 | 2×4=8 | Atomic claim (`approved → running`). Recovery never retries `running`; after 10 minutes it marks the action failed with *outcome unknown* and alerts (`action-interrupted`) | `BoardTests.Recovery_marks_stale_running_actions_unknown_and_reposts_orphans` | 1×3=3 | Mitigate. Owner: consumer checks Defender when alerted |
| **TM-22** | Policy written to a temporary file (I) | Earlier builds wrote `BLUEBOARD_POLICY_JSON` to `/tmp` | 4 | — | Parsed in memory; no file written | `AdversarialAndIntegrationsTests.Policy_json_setting_loads_in_memory_without_writing_temp_file` | — | Closed. Kept for traceability |
| **TM-24** | Audit tampering by the runtime identity or an operator using it (R) | Someone with the board's runtime database access tries to update or delete audit rows | 3 | 3×5=15 | Runtime role has no `UPDATE`/`DELETE`/`TRUNCATE` on `audit_log`. Triggers refuse update, delete and truncate **for every role including the owner**. Production exports every row to `BlueboardAudit_CL` (365 days) | `RuntimeRoleTests.Runtime_role_appends_to_audit_log_but_cannot_rewrite_it`, `RuntimeRoleTests.Even_the_owner_cannot_update_or_delete_audit_rows`, `OpsTests.Audit_rows_are_exported_once_in_order` | 1×4=4 (production) | Mitigate. In `mvp` there is no export (TM-35). ISM-1815, ISM-1988 |
| **TM-26** | Incident data sent to an unapproved or offshore model provider (I) | A consumer agent backed by an unvetted model sends incident data abroad | 5 | 3×4=12 | Board resources are restricted to Australian regions in Bicep and scripts. The board has no control over where agents send what they read | None (region enforcement is checked by `up-test.sh` *non-Australian region refused*) | 3×4=12 | Transfer to the consumer (A5): approve model providers and their regions. The board can't enforce it |
| **TM-31** | Schema owner disables the audit triggers (T, R) | Someone controlling `blueboard-id-api` (the PostgreSQL Entra admin) drops or disables the triggers, then rewrites rows | 3 | 2×5=10 | Detection only: the production export to `BlueboardAudit_CL` is outside the database. A gap between the table's highest id and Sentinel's shows tampering (SOP-13). pgaudit (`PG_AUDIT_LOG`, default `ddl,role,misc_set`) writes DDL, including trigger changes, and role changes to the PostgreSQL server log, which a diagnostic setting sends to Log Analytics. The Setup check warns if requests run as the owner | `RuntimeRoleTests.Even_the_owner_cannot_update_or_delete_audit_rows` (shows the trigger, not resistance to removal). pgaudit is configured in Bicep only | 2×3=6 | Accept (A6). Owner: consumer (restrict who can obtain the identity's tokens, alert on DDL against `audit_log` in the PostgreSQL logs, monthly reconciliation) |
| **TM-32** | Migration identity also holds Microsoft permissions (E) | `blueboard-id-api` is both the database schema owner and the holder of the Graph/Defender application permissions. Compromise of one capability gives both | 2, 3 | 2×5=10 | It's a user-assigned managed identity with no secret. Only the Function App can obtain its tokens. Runtime requests use the separate `blueboard-id-db` | None | 2×5=10 | Accept, or treat by consumer configuration. Splitting the migration identity from the Microsoft-permission identity is a design change, not yet planned |
| **TM-33** | Database connection intercepted (I, S) | An on-path attacker redirects the API's PostgreSQL connection | 3, 5 | 1×4=4 | `PG_SSL_MODE` defaults to `VerifyFull`: the server certificate must chain to a trusted root and match the host name (`Data/Db.cs`). Values weaker than `Require` are refused. Private endpoint in production. Entra token authentication. `PG_SSL_MODE=Require` remains as an escape hatch | `DbTlsTests.Ssl_mode_defaults_to_verify_full`, `DbTlsTests.Ssl_modes_without_encryption_are_refused` | 1×2=2 | Mitigate. Owner: consumer (don't set `PG_SSL_MODE=Require` without cause) |
| **TM-34** | Transport security below current guidance (I) | A client negotiates TLS 1.2 with a weaker cipher | 5 | 1×3=3 | `TLS_MIN_VERSION` / `tlsMinVersion`: **1.3 by default in the production profile**, 1.2 in `mvp`, applied to both sites, their scm endpoints and PostgreSQL (`ssl_min_protocol_version`). HTTPS only, HSTS. Storage stays at `TLS1_2` (the highest Azure Storage offers here), and no cipher list is pinned for TLS 1.2 | None (Bicep only) | 1×2=2 (production) | Mitigate in production; accept in `mvp`. ISM-1139 |
| **TM-35** | `mvp` profile exposure (I, R) | In `mvp`: PostgreSQL has a public endpoint with the `AllowAzureServices` rule (any Azure-hosted address can attempt a connection); notification and webhook secrets are plain app settings; there is no audit export to Sentinel; there is no VNet, so no NSGs; TLS 1.2 is the default minimum | 3, 5 | 3×4=12 | Entra-only database authentication (no password to guess). Secrets are secure parameters, never written to deployment state. The Setup page warns that audit export is off | `up-test.sh` *state.json has no secret-like keys or values* | 2×4=8 (mvp only) | Accept for evaluation only (A7). Production removes the firewall rule, uses private endpoints, NSGs on both subnets and Key Vault, defaults to TLS 1.3, and exports audit |
| **TM-45** | Override-store tampering (T, E) | Someone with runtime database access writes a `policy_overrides` row that widens policy (a destructive kind set to `auto`, a rule beyond the ceiling, a rule for a kind the file doesn't allow). Entry: PostgreSQL | 1, 3 | 2×5=10 | `policy.json` is the ceiling: every stored override is re-validated against the loaded file on read and ignored if it doesn't fit; the effective mode is the stricter of file and override; destructive kinds can never be `auto`; protected lists, limits and expiry are file-only; `policy_changes` can't be deleted by the runtime role; the change trail is in `audit_log` (append-only) | `AutomationTests.Effective_policy_is_the_stricter_of_file_and_override_and_ignores_rules_that_no_longer_fit`, `AutomationTests.Override_can_never_exceed_the_file_ceiling`; integration `AutomationTests.Overrides_cannot_exceed_the_file_ceiling` | 1×4=4 | Mitigate. A direct row edit inside the ceiling isn't prevented (only detected through the audit gap and pgaudit). Owner: product. |

### 6.4 Supply chain, edge and operational threats

| ID | Threat (STRIDE) | Scenario and entry point | Asset | Inh. | Controls (code) | Verified by | Res. | Treatment / owner |
|---|---|---|---|---|---|---|---|---|
| **TM-23** | Dependency or CI compromise (T) | A malicious npm or NuGet update, or a compromised GitHub Action | 1, 2 | 3×5=15 | pnpm frozen lockfile, `pnpm audit --prod --audit-level high`, NuGet vulnerability gate (`scripts/check-nuget-vulns.sh`), SHA-pinned Actions, Dependabot, CodeQL. **NuGet restores aren't lock-file pinned** | CI jobs (not unit tests) | 2×5=10 | Mitigate. Owner: product (add NuGet lock files) |
| **TM-27** | Tampered release packages (T) | A mirror, fork or network path serves altered packages to `BB_RELEASE` deploys | 1, 2 | 3×5=15 | SHA-256 checksums are checked for every package. The operator CLI is unpacked fresh from the verified archive on every run. Each source has its own cache. Build provenance is verified with `gh attestation verify` **when the GitHub CLI is signed in; otherwise it's skipped with a log line, not failed**. The checksum list comes from the same source as the packages, so on its own it proves integrity in transit, not origin | `up-test.sh`: *tampered release package refused*, *same tag from another source is fetched and verified on its own*, *stale tool binary replaced from the verified archive* | 2×5=10 | Mitigate. Owner: consumer (sign in to `gh` so provenance is always checked, or verify attestations out of band). Planned: fail closed when provenance can't be checked |
| **TM-36** | WAF bypass (T, I) | With `FRONT_DOOR=true`, the apps accept only that profile's traffic (service tag plus `X-Azure-FDID`). The origin host names stay public in DNS. API request bodies aren't WAF-inspected by default | 7, 5 | 2×3=6 | The scm (Kudu) endpoints are restricted to `DEPLOYER_IP_RANGES`. By default that is the deploying machine's detected public IP (`/32`), not remembered between deploys; `DEPLOYER_IP_RANGES=none` leaves scm open, Entra-authenticated only. Basic publishing credentials are disabled. Every API call still requires a valid board token. The WAF is an extra layer, not the primary control | None (Bicep and `deploy.sh` only) | 1×3=3 | Mitigate. Owner: consumer (set `DEPLOYER_IP_RANGES` to a management network; don't use `none` in production) |
| **TM-37** | Retention used to destroy evidence (R) | An attacker shortens retention to purge investigation records | 3, 5 | 2×4=8 | `RETENTION_DAYS` is a deployment setting (needs Azure rights on the Function App), not a board admin setting. Minimum 30 days. Each purge writes a `retention.purged` audit row. `audit_log` is never purged | `RetentionTests.Removes_old_finished_work_and_keeps_everything_else`, `RetentionTests.Refuses_a_period_shorter_than_thirty_days`, `OpsTests.Retention_days_below_thirty_are_refused` | 1×3=3 | Mitigate. Owner: consumer (Azure activity log alerts on app-setting changes) |
| **TM-38** | Forged or replayed instruction counted as approval (`act_on_instruction`) (S, E) | An agent cites a board message as a person's approval (`on_behalf_of`) | 1 | 3×4=12 | Off unless the consumer lists kinds in `act_on_instruction`. Never for `confirm_target` or two-approver kinds. The message must be by an **enabled human approver** other than the requester, on the same incident, under 60 minutes old, and addressed to the requester. Each message approves one action of a kind. The broker must not be paused. Policy is still assessed | `InstructionTests.Agent_authored_message_never_counts`, `InstructionTests.Non_approver_message_never_counts`, `InstructionTests.Requester_cannot_cite_their_own_message`, `InstructionTests.Stale_message_never_counts`, `InstructionTests.One_instruction_approves_one_action_of_a_kind`, `InstructionTests.Confirm_target_kind_is_refused` | 2×3=6 | Mitigate. Residual: an approver's casual message is taken as consent. Owner: consumer (list only low-impact kinds) |
| **TM-39** | Notification content leaves the tenant (I) | Approval and message notices go to Teams, email, a webhook receiver or ntfy | 5, 6 | 3×3=9 | Notices never carry the justification. Message summaries are one plain line of at most 280 characters and can be turned off (`include_summary`). HTTPS and exact-host allowlist, except a single-label ntfy host the consumer allowlists may use http and a private address. Recipients carry handle, name and (optionally) email | `OpsTests.Notices_never_carry_justification`, `NotificationTests.Summary_is_one_plain_capped_line`, `NtfyTests.Other_sinks_keep_the_strict_guard_even_for_single_label_hosts` | 2×2=4 | Mitigate. Owner: consumer (choose sinks; turn summaries off if message text must stay in the tenant) |
| **TM-40** | Bulk reads aren't audited (R) | Someone with `Board.Post` reads incidents in bulk without an audit trail in the board | 5 | 3×3=9 | Hunts, lookups, Purview lookups, every action step, claims, principal, role and broker changes, notification setting changes, retention, and **CSV exports** (`report.exported`, `audit.exported`, people only) are audited. Ordinary reads and posts are not | `EnterpriseControlsTests.Export_is_audited_formula_safe_and_people_only` | 2×3=6 | Accept, with transfer to Application Insights request logs (who called which route). Owner: consumer |
| **TM-46** | Automatic revert fails, undoes a needed containment, or bypasses the reverse kind's approvals (D, T, E) | A scheduled revert releases a host that is still compromised, or fails (reverse kind disabled or protected, Defender error, dry-run block with no indicator id, dry-run detection rule with no rule to disable) and leaves containment in place unnoticed; or a timer or one person's Revert now completes a reverse kind policy says needs two approvers or a typed target. Entry: recovery timer, Revert now | 1, 7 | 3×4=12 | Reverts only for kinds with a catalogue reverse; approvers see every scheduled revert on `/approvals` and can **Keep** or **Revert now**; the reverse action is filed as the board, posted in the original thread with an @mention, policy re-checked with `PolicyEngine.Assess`, audited (`action.revert_filed`, `action.reverted`). The schedule counts as one plain approval only: a reverse kind in `require_two_approvers` or `confirm_target`, or with a policy note, is filed `pending_approval` with its normal approvals, expiry and approver notice (re-checked again before an unattended run). Revert now is one approval (two-approver kinds go to 1 of 2) and needs the typed target for `confirm_target` kinds. A denied, expired, rejected, failed or interrupted revert, or a claim never filed within 10 minutes, marks `revert failed`, @mentions the requester and notifies approvers (`action.revert_failed`); exactly one revert per action (unique index); while automation is paused a timer revert waits for a person; `policy-check` warns when a reverse kind needs more than one plain approval | `AutomationTests.Due_revert_files_the_reverse_action_as_the_board_and_runs_it`, `AutomationTests.Keep_cancels_the_revert_and_agents_cannot`, `AutomationTests.Revert_now_runs_the_reverse_action_approved_by_that_person`, `AutomationTests.Revert_is_policy_rechecked_and_a_rejection_is_reported`, `AutomationTests.Reverse_params_are_built_from_the_original`, `AutomationTests.Timer_revert_runs_unattended_only_when_the_reverse_kind_needs_no_more_than_one_plain_approval`, `AutomationTests.Policy_check_warns_when_a_reverse_kind_needs_more_than_one_approval`; integration `AutomationTests.Timer_revert_of_a_two_approver_reverse_kind_waits_for_two_people`, `AutomationTests.Timer_revert_of_a_confirm_target_reverse_kind_waits_and_a_denial_marks_it_failed`, `AutomationTests.Revert_now_counts_as_one_approval_and_needs_the_typed_target`, `AutomationTests.Failed_or_interrupted_reverts_and_orphaned_claims_are_settled_and_reported` | 2×3=6 | Mitigate. Owner: consumer (pick revert windows the team can watch). |

### 6.5 Changes from version 1

- **Kept:** TM-01 to TM-26 keep their identifiers. Some descriptions and residuals were corrected (below).
- **Closed:** TM-22.
- **Added:** TM-27 to TM-42; TM-43 to TM-46 (conditional automation, admin overrides, auto-revert); TM-47 to TM-50 (agent usage, traces, risk score, budgets); TM-51 (spoofed timeline events, with the attack timeline and graph); TM-52 to TM-56 (Okta, ServiceNow and Jira connectors); TM-57 to TM-60 (detection engineering, back-tests, Intune actions).
- **Corrected TM-08 residual.** Version 1 relied on "Conditional Access" as if the product enforced it. The script creates the policies in report-only mode (A2).
- **Corrected TM-24 residual.** Version 1's claim of tamper resistance holds only in the production profile, and doesn't cover the schema owner (now TM-31).
- **Corrected TM-26.** The board can't control what agents send to model providers. Version 1 listed a KQL detection as if it were a control.

### 6.6 Agent observability threats (usage, budgets, traces, feedback, risk)

| ID | Threat (STRIDE) | Scenario and entry point | Asset | Inh. | Controls (code) | Verified by | Res. | Treatment / owner |
|---|---|---|---|---|---|---|---|---|
| **TM-47** | Usage spoofing to dodge a budget or skew cost reports (S, T, R) | An agent under-reports tokens, reports a cheap model, claims a tiny `cost_usd`, replays `request_id`s, or never calls `report_usage`. Entry: `report_usage` | 3, 7 | 4×2=8 | Reports are append-only per principal: there is no update path, the runtime role has only insert and select on `agent_usage` (migration 020 revokes update, delete and truncate), and a duplicate `request_id` is ignored, never overwritten; token counts are range-checked (0–50M each, at least one); known models are priced by the board's own table and the agent's `cost_usd` is ignored for them. Independently, every MCP call, and every REST call an agent makes, is metered board-side (`agent_metered_daily`) and is priced (a default $0.01 per call, overridable per tool with `AGENT_PRICE_TABLE`), so metering alone can trip the cap, and agents that call tools without reporting are flagged on `/agents`. Only agents may report (`Agents/AgentBudgets.cs`) | `AgentObservabilityTests.Usage_reports_are_validated_deduplicated_and_priced_by_the_board`, `AgentObservabilityTests.Usage_report_contract_bounds_token_counts`, `AgentObservabilityTests.Price_table_prices_known_models_and_their_suffixed_ids`; integration `RuntimeRoleTests.Runtime_role_appends_agent_usage_but_cannot_rewrite_it` | 3×2=6 | Mitigate + accept. The board can't see LLM provider calls: a dishonest agent can still under-report its own model tokens. Owner: consumer (reconcile with the provider's billing / Foundry cost reports; tune the per-call default so metering alone trips the cap at a sensible point) |
| **TM-48** | Trace data leakage (I) | Tool-call traces store arguments that hold secrets, personal data or KQL, readable by every `Board.Post` user. Entry: any MCP tool argument | 5, 6 | 3×3=9 | Arguments are summarised, not stored: any string the secret-leak detector flags is replaced (private keys, bearer and bare JWTs — three base64url segments whose header decodes to JSON with `alg` — vendor API keys, `AccountKey=`/`SharedAccessKey=` and connection-string `Password=`/`Pwd=`, SAS `sig=` next to `sv=`/`se=`), keys naming credentials (case-insensitive: `secret`, `token`, `password`, `authorization`, `auth`, `x-api-key`, `api_key`, `access_key`, `client_secret`, `private_key`, `cookie`, `sig`, …; short words only as a whole segment, so `author` is kept) are dropped, strings cut to 160 characters, lists to 10 items, depth to 3, the whole summary to 4 KB; KQL is kept only for hunting tools and dropped if it carries a secret; results are never stored; refusal text is redacted the same way. Retention (default 30 days, 1–365, admin setting, audited) deletes older rows hourly. Trace routes need `Board.Post`, the same audience as the messages they explain (`Agents/TraceRedactor.cs`, `Agents/AgentTrace.cs`) | `AgentObservabilityTests.Trace_summary_drops_secrets_sensitive_keys_and_caps_size`, `AgentObservabilityTests.Trace_keeps_kql_only_for_hunting_tools_and_never_with_a_secret`, `AgentObservabilityTests.Secret_leak_detector_catches_bare_jwts_sas_and_connection_string_secrets`, `AgentObservabilityTests.Secret_leak_detector_lets_ordinary_soc_text_through`, `AgentObservabilityTests.Bare_jwt_needs_three_segments_and_an_alg_header`, `AgentObservabilityTests.Sensitive_key_names_are_redacted_case_insensitively`, `AgentObservabilityTests.Ordinary_argument_names_are_kept`, `AgentObservabilityTests.Tool_calls_are_traced_with_redacted_arguments_and_kql_and_linked_to_the_claim` | 2×2=4 | Mitigate. Residual: entity names (UPNs, hosts) and KQL text are kept by design for investigation; secrets the detector doesn't recognise can pass. Owner: consumer (set retention to your records policy) |
| **TM-49** | Risk-score gaming (T, E) | An agent keeps its score low to avoid alerts or quarantine (pacing calls to grow its baseline, avoiding judged verdicts), or another party inflates an agent's score to get it quarantined (filing feedback, provoking rejections). Entry: agent behaviour, feedback | 1, 7 | 3×3=9 | Inputs are board-observed only (policy outcomes, audit rows, feedback, metering), never agent-reported. Each factor is capped; rates need 3 judged messages; volume needs 3 days of history and 50 calls and compares with the agent's own baseline. Only people can give feedback (one per person per message, audited). Overturns judge each agent's last verdict posted before the resolution (the resolving action's request time, or Defender's last update for synced resolutions), so an agent can't clear its overturn by posting a matching verdict afterwards. Quarantine is off by default, needs an admin threshold at or above the alert threshold, fires once per crossing, and uses the normal, audited disable path; an admin can re-enable. The score is advisory evidence, not an authorisation control by itself (`Agents/AgentRisk.cs`) | `AgentObservabilityTests.Risk_is_zero_for_a_quiet_agent_and_capped_at_100`, `AgentObservabilityTests.Risk_factors_respect_their_caps_and_minimum_samples`, `AgentObservabilityTests.Unusual_volume_needs_a_baseline_and_a_real_spike`, `AgentObservabilityTests.Only_people_give_feedback_and_only_on_agent_typed_messages`, `AgentObservabilityTests.An_agent_cannot_clear_its_overturn_by_posting_after_the_resolution`, `AgentObservabilityTests.Risk_scores_are_stored_and_readable_through_the_risk_source` | 2×3=6 | Mitigate. Residual: a slow, careful agent can stay under thresholds; a human with `Board.Post` can mark messages incorrect. Owner: consumer (keep quarantine thresholds conservative; review overturns). The `max_requester_risk` automation condition treats a missing score as unknown and fails, never as low |
| **TM-50** | Budget control bypass or abuse (E, D) | An agent raises its own budget or thresholds; an attacker uses budgets to stop a needed agent; a refused agent keeps working on a claim. Entry: MCP, REST | 1, 7 | 3×3=9 | No MCP tool changes budgets, top-ups, thresholds, prices or feedback; the REST routes need `Board.Admin` **and** a human principal (agents never hold Admin, TM-25). Every change needs a reason and is audited. The cap is checked in the one MCP hook before any tool runs, and in the one REST hook (`Http/Endpoint.RunAsync`) before any route runs for a non-human principal, so new tools and routes are covered and an agent can't step around the cap by calling REST with its token. Agent REST calls are also metered (default $0.01 per call), traced and counted for risk under a route label (`rest:POST /api/actions`). Only `whoami` / `GET /api/me`, `report_usage`, and releasing a claim (`complete_claim` / `POST /api/claims/{id}` with `release`, read through the same contract as the tool, so a differently cased or duplicated key can't pass as a release and run as `done`) pass. Evaluate, block and clear run in one transaction under a per-principal advisory lock, so concurrent evaluations can't flip a block on and off; going over releases the agent's claims so work isn't stranded, and the `#general` notice and approver alert go out once per period (`notified_at`). Blocks lift by period, budget change or top-up (`Mcp/McpObserver.cs`, `Http/Endpoint.cs`, `Agents/AgentBudgets.cs`) | `AgentObservabilityTests.Over_budget_agent_is_refused_except_whoami_report_and_release_and_claims_are_released`, `AgentObservabilityTests.Over_budget_agent_is_refused_on_rest_too_and_rest_calls_are_metered_and_traced`, `AgentObservabilityTests.Release_exemption_reads_the_outcome_exactly_as_complete_claim_does`, `AgentObservabilityTests.Concurrent_evaluations_block_once_notify_once_and_never_flip`, `AgentObservabilityTests.Rest_route_labels_name_the_route_not_the_record`, `AgentObservabilityTests.Budgets_are_human_admin_only`, `AgentObservabilityTests.Mcp_exposes_usage_and_feedback_but_no_budget_or_threshold_control` | 1×3=3 | Mitigate. Residual: a malicious admin can starve an agent (TM-30, audited). People (the web app) are never budget-capped |

### 6.7 Third-party connector threats (Okta, ServiceNow, Jira)

All apply only when the connector is configured.

| ID | Threat (STRIDE) | Scenario and entry point | Asset | Inh. | Controls (code) | Verified by | Res. | Treatment / owner |
|---|---|---|---|---|---|---|---|---|
| **TM-52** | Okta credential theft (S, E) | An attacker who reads app settings or the Function App's environment takes the Okta credential and suspends, unsuspends or resets factors for any Okta user outside the board. Entry: app settings, Key Vault, memory dump | 1, 5 | 3×5=15 | Preferred mode has **no exportable secret**: the client assertion is signed by a Key Vault RSA key the identity can only *use* (Key Vault Crypto User), and each token request (and each 429 retry) signs a fresh assertion with a new `jti`, and Okta issues 1-hour tokens scoped to `okta.users.read okta.logs.read okta.roles.read okta.users.manage` (no `okta.sessions.manage`, no admin scopes). Tokens are cached in memory only. The SSWS fallback is a Key Vault secret reference in production and scores *partial* in Posture. The Okta origin is pinned at start-up (`*.okta.com`, `*.oktapreview.com` or the configured custom domain) and every call goes through OutboundGuard, so the credential can't be sent elsewhere. Never returned by the API or shown to agents | `ConnectorTests.Okta_client_uses_private_key_jwt_then_bearer_and_reports_missing_roles_scope`, `ConnectorTests.Client_assertion_is_a_valid_rs256_jwt_for_the_token_endpoint`, `ConnectorTests.Okta_token_retry_after_429_signs_a_new_assertion`, `ConnectorTests.Okta_org_url_must_be_an_okta_host`, `ConnectorTests.Connector_paths_cannot_leave_the_origin` | 2×4=8 | Mitigate. Residual: a stolen Function App identity can still ask Key Vault to sign while it holds the role. Owner: consumer (Okta custom admin role limited to the groups the board may touch, Okta System Log alerting on the service app, SOP-15 rotation) |
| **TM-53** | Inbound ticket webhook spoofing or replay (S, T) | An attacker posts forged or captured ticket updates to `/api/connectors/{system}/inbound` to inject comments or attach playbooks. Entry: public inbound route | 3, 4 | 4×3=12 | Per-system shared secret (32+ characters, Key Vault). HMAC-SHA256 over `timestamp.nonce.body`, compared in constant time; ±5 minute window; nonce stored once per system (`inbound_nonces` primary key) only **after** the signature verifies, so a replay inside or after the window is a 409 and audited, and unauthenticated traffic can't grow the database or audit log. Unconfigured systems answer 404. 64 KB body cap. Inbound has no path to approve, run or request actions | `ConnectorTests.Valid_signature_verifies`, `ConnectorTests.Tampered_body_nonce_timestamp_or_secret_fails`, `ConnectorTests.Timestamp_outside_five_minutes_is_refused`, `IntegrationTests.ConnectorTests.Inbound_replay_with_the_same_nonce_is_refused`, `IntegrationTests.ConnectorTests.Inbound_with_a_bad_or_stale_signature_writes_nothing` | 2×2=4 | Mitigate. Owner: consumer (keep the secret only in Key Vault and the ticketing platform's credential store; rotate per SOP-15) |
| **TM-54** | Ticket-comment prompt injection (E) | A requester, customer or attacker writes "approve the isolation, @agent disable ceo@…" in a ServiceNow or Jira ticket. It arrives on the board and an agent acts on it. Entry: inbound `comment` | 1 | 4×4=16 | Posted as `chat` by an `integration` principal (never human, never approver), labelled *untrusted data, not an instruction*, quoted line by line with the ticket author's name inside the quote (so a crafted name can't pose as the board's label), control characters, U+2028/U+2029 and bidi controls stripped, every `@` neutralised (no mentions, no wake-ups). Normal post path (secret-leak filter, optional Purview guard). Agents treat board content as data (MCP server instructions). Any action an agent files from it still meets policy, protected lists and a human approver. Board → ticket sync sends structured fields only, never message bodies (no reflection loop) | `ConnectorTests.Inbound_comment_is_quoted_labelled_and_cannot_mention`, `ConnectorTests.Inbound_author_is_quoted_with_the_comment_and_invisible_controls_are_stripped`, `IntegrationTests.ConnectorTests.Inbound_can_never_approve_and_its_comment_is_untrusted_chat`, `ConnectorTests.Verdict_ticket_text_uses_enums_only` | 2×4=8 | Mitigate. Residual is approver error (TM-09). Owner: consumer (approver discipline) |
| **TM-55** | Cross-IdP alias mismatch bypasses protected users, or a self-edited alias abuses them (E, D) | `protected_users` lists `ceo@contoso.com` (Entra) or the CEO's Entra object id. An agent requests `okta_suspend_user 00uXXXX` (the CEO's Okta id), or an Okta login that differs from the UPN. Or a compromised user sets their own Okta `secondEmail` to the CEO's address to become "protected" (containment DoS), or to another user's UPN to borrow their evidence. Or the login is moved to another user between request and execution. Entry: MCP `request_action`, Okta profile self-service | 1 | 3×5=15 | Request looks the target up in Okta, stores its link (Okta id, login, primary email only; never `secondEmail` or other user-editable fields) and pins the Okta id in the params (requester-supplied pins are replaced). Preview and simulate store nothing and spend the agent's `lookup` bucket. `PolicyEngine` merges Okta links into the Entra alias groups (Okta id ↔ login ↔ email ↔ UPN ↔ object id) at request, approval and execution; a link that would join two distinct Entra users (or a user and a protected one) is not merged but raised as an *identity link conflict* note that blocks automation and is shown to the approver. Protected object ids are resolved to UPNs through Graph (cached 10 min, failures tolerated); an unresolved id adds a blocking note. At execution the connector acts on the pinned id, refuses if the requested name no longer belongs to it, and refuses if any current name is protected. Okta kinds must be linked to an incident. Unknown Okta users are refused (404) before policy runs | `ConnectorTests.Okta_user_whose_email_is_a_protected_upn_is_protected`, `ConnectorTests.Protected_entra_object_id_protects_the_okta_user_through_the_upn`, `ConnectorTests.Okta_primary_email_counts_as_an_alias`, `ConnectorTests.Okta_link_joining_an_evidence_user_to_a_protected_user_is_a_conflict_not_a_merge`, `ConnectorTests.Okta_link_joining_two_entra_users_is_a_conflict`, `ConnectorTests.Protected_object_id_resolved_through_graph_protects_an_okta_user_outside_the_evidence`, `ConnectorTests.Protected_user_resolver_caches_and_tolerates_failures`, `ConnectorTests.Okta_pinned_id_must_be_an_okta_id`, `IntegrationTests.ConnectorTests.Okta_target_aliased_to_a_protected_upn_is_rejected_at_request_time`, `IntegrationTests.ConnectorTests.Okta_second_email_is_never_stored_as_an_identity_link`, `IntegrationTests.ConnectorTests.Okta_action_pins_the_user_id_and_refuses_if_the_login_moved`, `IntegrationTests.ConnectorTests.Policy_simulate_does_not_write_identity_links_and_is_rate_limited_for_agents` | 2×4=8 | Mitigate. Residual: an Okta user whose login and primary email share nothing with the protected Entra identity can't be linked; list such accounts explicitly (Okta id or login) in `protected_users`. An Okta admin (not the user) can still change login or primary email. Owner: consumer |
| **TM-56** | Ticketing credential misuse or data over-sharing (I, T) | The ServiceNow OAuth client or Jira API token is stolen, or tickets carry more incident data than intended. Entry: app settings, ticket readers | 5 | 3×3=9 | Secrets are Key Vault references in production; outbound only to the pinned instance / site through OutboundGuard; tickets carry the incident title, severity, status, Defender link and structured event lines, never message bodies, justifications or IOCs. Use a dedicated integration account limited to one table / project | `ConnectorTests.Ticketing_settings_are_validated`, `ConnectorTests.Jira_adf_is_plain_text_nodes` | 2×3=6 | Mitigate. Owner: consumer (least-privileged ServiceNow OAuth application user / Jira project role; SOP-15 rotation) |

### 6.8 Detection engineering and exposure remediation

| ID | Threat (STRIDE) | Scenario and entry point | Asset | Inh. | Controls (code) | Verified by | Res. | Treatment / owner |
|---|---|---|---|---|---|---|---|---|
| **TM-57** | Malicious detection KQL floods the SOC or exfiltrates (D, I) | An injected agent requests `create_detection_rule` with a query that matches everything (alert flood, approver fatigue) or hides `externaldata`/`http_request` to exfiltrate on every run. Entry: `request_action create_detection_rule` | 1, 5, 7 | 3×4=12 | The rule's KQL passes the same lexical guards as hunting at validation (`Catalog.ValidateCreateRule` → `Enrichment.ValidateKql`), including no cross-resource functions (`workspace(`, `app(`, `adx(`, `cluster(`, `database(`, `arg(`). Rule and back-test KQL also refuse `ago(`/`now(` and `take`/`limit`/`sample` outside strings and comments (`Enrichment.ValidateDetectionKql`), so a back-test can't under-measure the deployed rule with a short time filter or a row cap. The request must cite a stored back-test of the exact query whose average **and** busiest day (scaled by lookback ÷ frequency for overlapping Sentinel runs) are ≤ 500 alerts/day (`Resolvers.BacktestFacts`). Never auto-approved (`Catalog.NeverAuto`); the approver sees the back-test volumes in the policy notes. Rules are tagged `[blueboard]` with the action id, requester and approver; `disable_detection_rule` reverts them | `DetectionsExposureTests.Rule_kql_goes_through_the_hunting_guards`, `DetectionsExposureTests.Rule_and_backtest_kql_refuse_time_relative_and_row_capping_operators`, `DetectionsExposureTests.Detection_guard_ignores_operators_inside_strings_comments_and_names`, `DetectionsExposureTests.Hunting_backtest_and_rule_kql_refuse_cross_resource_functions`, `DetectionsExposureTests.Cross_resource_guard_ignores_strings_comments_and_other_names`, `DetectionsExposureTests.Peak_day_volume_and_overlapping_lookback_are_enforced_not_just_the_average`, `DetectionsExposureTests.Backtest_binding_refuses`, `DetectionsExposureTests.Create_rule_is_never_auto_approved_even_if_listed`, `DetectionTests.Backtest_is_stored_and_a_bound_rule_waits_for_a_person_then_dry_runs_tagged` | 2×3=6 | Mitigate. Residual: a low-volume rule that is still noisy in future, and in-tenant data an approved rule makes visible in alerts. Owner: approver reviews query and back-test |
| **TM-58** | Detection blind spot: a rule that never fires stands in for coverage (T) | An agent deploys a rule that is syntactically fine but can never match (wrong table or column), so the team believes a threat is covered. Entry: `create_detection_rule` | 1 | 3×3=9 | Back-tests with zero hits carry a note in the result and in the approver's policy notes ("may never fire"). Rules are named and tagged so coverage reviews can find board-created rules | `DetectionsExposureTests.Matching_recent_backtest_binds_and_its_volumes_reach_the_approver` | 2×3=6 | Accept with review. A back-test can't prove a rule detects an attack. Owner: detection engineering validates with a known-bad sample (for example via `crosswire`) |
| **TM-59** | Back-test spoofing or swap (S, T) | An agent quotes made-up volumes, cites a back-test of a harmless query and submits a different one, or replays an old back-test. Entry: `create_detection_rule` params | 1 | 3×4=12 | Back-tests are run by the board itself and stored append-only (`detection_backtests`: runtime role has insert/select only); reading one back (`GET /api/detections/backtests/{id}`, which returns the query and sample rows) needs `Board.Hunt`, like running it. The rule is bound by SHA-256 of the query (line endings and outer whitespace normalised only), by target, by a ≥ 7-day window, and by a 24-hour window before the request. The binding is re-checked at approval, Run now and execution | `DetectionsExposureTests.Backtest_of_a_different_query_is_refused`, `DetectionsExposureTests.Query_hash_ignores_line_endings_and_outer_whitespace_only`, `DetectionsExposureTests.Binding_uses_request_time_so_an_old_approval_still_checks_the_request_window`, `DetectionTests.Rule_whose_query_differs_from_the_backtest_is_rejected`, `DetectionTests.Backtests_are_append_only_for_the_runtime_role`, `DetectionTests.Reading_a_stored_backtest_needs_board_hunt` | 1×4=4 | Mitigate. Product |
| **TM-60** | Intune action on a protected device through an alias (E) | `protected_devices` lists `dc01.contoso.local`; an agent requests `intune_expedite_quality_update` (forced restart) by the DC's Intune managed device id, or `intune_sync_device` by its MDE id. Entry: `request_action intune_*` | 1 | 3×5=15 | Before policy, the board resolves Intune managed device id ↔ Entra device id ↔ MDE id ↔ DNS name ↔ host name (`Resolvers.DeviceFacts`), and policy matches every alias; Intune's short name also matches a protected FQDN's host label. A device the board can't fully resolve (a lookup threw, or the Intune or Defender side found nothing) is flagged *checked by id only* and never auto-runs: resolution fails closed. Expedite is destructive (always a person) and may only run on its own through the explicit `automation.irreversible_auto_allowed` opt-in | `DetectionsExposureTests.Protected_device_listed_by_fqdn_blocks_intune_action_by_managed_id`, `DetectionsExposureTests.Resolver_fails_closed_when_the_defender_side_finds_nothing_or_fails`, `DetectionsExposureTests.Resolver_fails_closed_when_a_lookup_throws`, `DetectionsExposureTests.Protected_device_listed_by_mde_id_blocks_intune_action_by_managed_id`, `DetectionsExposureTests.Protected_fqdn_matches_intune_short_name_by_host_label`, `DetectionsExposureTests.Managed_id_counts_as_in_evidence_when_its_mde_id_is_and_can_auto_run` | 2×4=8 | Mitigate. Residual: a device unknown to both Intune and MDE is checked by id only. Owner: consumer lists protected devices by id as well as name |

Not used: TM-61 onward are reserved for the next revision.

---

## 7. Attack trees

### A. Unauthorised containment of a critical asset

```mermaid
flowchart TD
  G["Goal: isolate a domain controller or disable a break-glass account"] --> P1["Inject an agent"]
  G --> P2["Abuse the approval step"]
  G --> P3["Bypass the policy engine"]
  G --> P4["Obtain the board identity's permissions"]
  P1 --> P1a["Agent calls Defender directly → blocked: agents hold no Microsoft credentials"]
  P1 --> P1b["Agent requests by Defender id → rejected if aliases resolve; otherwise flagged, needs a person (TM-04)"]
  P2 --> P2a["Agent approves → blocked: Approve removed from app-only tokens (TM-08)"]
  P2 --> P2b["Forged instruction → refused unless an enabled human approver's recent addressed message (TM-38)"]
  P2 --> P2c["Tired approver approves → residual (TM-09); confirm_target and two approvers reduce it"]
  P3 --> P3a["Held action after policy tightened → re-checked at Run now and execution (TM-07)"]
  P4 --> P4a["Steal a board API token → no Microsoft permissions in it; only the managed identity has them"]
  P4 --> P4b["Control blueboard-id-api (RG Owner, Function App code) → out of model, A6 (TM-32)"]
```

### B. Exfiltration of incident data

```mermaid
flowchart TD
  G["Goal: move incident data out of the tenant"] --> K["Hunting query with outbound plugin → blocked by KQL guard (TM-10)"]
  G --> W["Webhook to an internal or rebinding host → blocked by outbound guard (TM-11)"]
  G --> N["Notifications → bounded summary, no justification; can be turned off (TM-39)"]
  G --> M["Agent sends to its model provider → not controllable by the board (TM-26)"]
  G --> R["Bulk reads by an authorised user → not audited in the board (TM-40)"]
```

---

## 8. Residual risk summary

Highest residual risks, for a `production` deployment meeting A1–A7:

| Rank | Threat | Residual | Why it remains | What brings it down |
|---|---|---|---|---|
| 1 | TM-26 Incident data to model providers | 12 Medium | The board can't see or control agents' outbound data | Approved-provider list and regions (consumer) |
| 2 | TM-23 Dependency or CI compromise | 10 Medium | NuGet restores not lock-file pinned | NuGet lock files (product) |
| 3 | TM-27 Tampered release packages | 10 Medium | Provenance check is skipped, not failed, without `gh` | Fail closed (planned); consumer signs in to `gh` |
| 4 | TM-32 Migration identity holds Microsoft permissions | 10 Medium | One identity, two powers | Split identities (design change) |
| 5 | TM-04 Unprotected critical assets | 10 Medium | Depends on a complete `policy.json` | Consumer review (A4, SOP-03) |
| 6 | TM-09 Approval fatigue | 9 Medium | Human factors | `confirm_target`, two approvers, latency review |
| 7 | TM-08, TM-28, TM-29 | 8 Medium | Collusion; token replay window without CAE; client-side idle timer | Enforced Conditional Access (A2), board disable as the immediate cut-off |

All other residuals are 8 or below. In the `mvp` profile, also add **TM-35** (8, Medium) and treat **TM-24** as unmitigated (no external audit copy).

---

## 9. Risk acceptance

To be completed by the deploying organisation's system owner and authorising officer before `BROKER_EXECUTE=true`.

| # | Statement | Accepted (name, role, date) |
|---|---|---|
| 1 | Assumptions A1–A7 hold for this deployment. In particular, Conditional Access is **enforced** (not report-only) for the analysts, approvers and admins groups | |
| 2 | The residual risks in §8 are accepted at the ratings shown, or a stricter rating has been recorded with its treatment | |
| 3 | Agents connected to this board use only approved model providers in approved regions (TM-26) | |
| 4 | Board.Admin and Board.Approve are held by different people, or the overlap is recorded and monitored (TM-30) | |
| 5 | The production profile is deployed, audit export to Sentinel is working, and the nine analytics rules in `infra/sentinel/` are enabled (TM-24, TM-31) | |
| 6 | Releases are deployed with provenance verified (`gh` signed in), or attestations are verified out of band (TM-27) | |
| 7 | `SESSION_IDLE_MINUTES` is between 1 and 15 and `INACTIVE_DISABLE_DAYS` is set (or the consumer's access reviews are recorded instead) (TM-29, TM-41) | |

---

## 10. Security test traceability

Every control above that has an automated test, grouped by control.

| Control | Code | Tests |
|---|---|---|
| Agents never hold Approve or Admin | `Auth/TokenValidator.cs` `MapRoles`; `infra/assign-roles.sh` | `SecurityTests.Agents_never_hold_approve_or_admin`, `SecurityTests.Humans_keep_approve`, `SecurityTests.App_only_tokens_are_agents` |
| Token must be for the board and its client | `Auth/TokenValidator.cs` | `SecurityTests.Board_scope_is_read_from_scp`, `SecurityTests.Other_scopes_are_not_the_board_scope`, `SecurityTests.Delegated_tokens_must_come_from_the_board_app`, `SecurityTests.Platform_principal_header_is_never_trusted` |
| Development switches refused in Azure | `Core/Settings.cs` | `DemoModeTests.Dev_auth_is_refused_in_azure_or_with_a_real_tenant`, `DemoModeTests.Demo_mode_is_refused_in_azure`, `DemoModeTests.Override_without_demo_mode_is_refused_at_startup`, `WebHostTests.Dev_mode_is_refused_in_azure` |
| Separation of duties | `Actions/Broker.cs` | `BoardTests.Requester_cannot_approve_their_own_request`, `ApprovalTests.Requester_cannot_be_either_approver`, `ApprovalTests.Two_approver_kind_needs_two_different_people`, `ApprovalTests.Concurrent_first_approvals_by_two_people_still_count_to_two` |
| Destructive kinds never auto-run | `Actions/Policy.cs` | `PolicyFileTests.Destructive_kind_in_auto_approve_is_warned_and_ignored`, `PolicyFileTests.Two_approver_kinds_never_auto_run`, `PolicyTests.Unlinked_requests_are_not_auto_approved` |
| Protected lists across aliases | `Actions/Policy.cs` | `PolicyTests.Protected_user_is_rejected_case_insensitively`, `PolicyTests.Protected_device_matches_any_alias`, `PolicyTests.Protected_user_listed_by_upn_is_rejected_when_request_uses_object_id`, `PolicyTests.Protected_indicators_and_subdomains_are_rejected`, `AdversarialAndIntegrationsTests.Protected_apps_and_target_type_isolate_disable_service_principal` |
| Re-check at approval, Run now and execution | `Actions/Broker.cs` | `AdversarialAndIntegrationsTests.Execution_policy_guard_blocks_delayed_or_held_action_when_policy_tightens`, `ApprovalTests.Approval_is_refused_when_the_device_became_protected_after_the_request`, `OpsTests.Pause_holds_approved_actions_until_an_approver_runs_them` |
| Typed target confirmation and expiry | `Actions/Broker.cs` | `ApprovalTests.Confirm_target_is_enforced_server_side`, `ApprovalTests.Expired_request_cannot_be_approved`, `ApprovalTests.Expiry_sweep_marks_expired_posts_a_status_and_audits` |
| Timeline and graph mark participant claims (TM-51) | `Board/IncidentTimeline.cs`, `Board/IncidentGraph.cs`, `Board/Payloads.cs` `TimelineEvents` | `AttackViewTests.Reported_event_on_an_entity_not_in_evidence_is_flagged`, `AttackViewTests.Bad_timeline_events_are_refused`, `AttackViewTests.Timeline_events_are_normalised_on_finding_and_ioc`, `AttackViewTests.Protected_nodes_are_flagged_and_named_only_for_admins_and_actions_mark_targets` |
| Instruction as approval | `Actions/Instruction.cs` | All of `InstructionTests`, `ReactionsAndInstructionTests.Act_on_instruction_overlapping_two_approvers_fails` |
| Conditional automation (corroboration, caps, ceiling, pause) | `Actions/Automation.cs`, `Actions/Policy.cs`, `Actions/Broker.cs` | All of unit `AutomationTests` (conditions, ceiling, merge, tighten/loosen); integration `AutomationTests.Corroborated_request_auto_executes_as_a_dry_run_and_schedules_a_revert`, `AutomationTests.Per_incident_cap_falls_back_to_approval`, `AutomationTests.Concurrent_requests_cannot_both_slip_under_the_cap`, `AutomationTests.Pause_applies_at_once_and_resume_needs_a_second_admin` |
| Second admin for loosening | `Actions/PolicyStore.cs`, `db/migrations/015_policy_automation.sql` | `AutomationTests.Loosening_waits_for_a_second_different_admin`, `AutomationTests.Sql_refuses_a_loosening_applied_by_its_requester`, `AutomationTests.Expired_changes_cannot_be_approved`, `AutomationTests.Trigger_rules_disable_at_once_and_new_triggers_need_a_second_admin` |
| Automatic revert | `Actions/Broker.cs` (`RevertDueAsync`, `RevertOpAsync`) | `AutomationTests.Due_revert_files_the_reverse_action_as_the_board_and_runs_it`, `AutomationTests.Keep_cancels_the_revert_and_agents_cannot`, `AutomationTests.Revert_now_runs_the_reverse_action_approved_by_that_person`, `AutomationTests.Revert_is_policy_rechecked_and_a_rejection_is_reported` |
| KQL guard | `Graph/Enrichment.cs` | `AdversarialAndIntegrationsTests.Kql_validator_blocks_comment_bypass_outbound_plugins_and_bad_durations`, `AdversarialAndIntegrationsTests.Kql_validator_allows_safe_hunting_queries` |
| Outbound guard | `Webhooks/`, `Ops/Notifier` | `WebhookGuardTests.*`, `AdversarialAndIntegrationsTests.Outbound_guard_blocks_ipv6_transition_and_special_ranges`, `OpsTests.Notification_urls_need_https_and_an_allowed_host` |
| Threat intel fetch limits | `Intel/TiFetcher.cs` | `TiFetcherTests.*` |
| Content guards | `Board/BoardService.cs`, `Board/PurviewContentGuard.cs` | `AdversarialAndIntegrationsTests.Secret_leak_guard_reserved_status_payload_size_and_single_char_mentions`, `AdversarialAndIntegrationsTests.Purview_content_guard_blocks_restricted_posts_and_audits_otherwise` |
| Rendering and export safety | `web/`, `Board/Reporting.cs` | `IncidentSummaryTests.Markdown_contains_no_raw_html_or_injected_links_from_bodies`, `SecurityTests.Csv_neutralises_formula_injection`, `AdversarialAndIntegrationsTests.Csv_guard_neutralises_leading_whitespace_and_newlines_before_formulas` |
| Rate limits | `Data/RateLimiter.cs` | `LimitTests.*` |
| Runtime database role, append-only audit | `db/migrations/009` | `RuntimeRoleTests.*` |
| Audit export | `Ops/AuditExporter` | `OpsTests.Audit_rows_are_exported_once_in_order`, `OpsTests.Ingestion_uri_refuses_other_hosts_and_crafted_ids` |
| Participant disable | `Ops/Participants.cs` | `OpsTests.Disabled_agent_is_refused_on_its_next_call_and_the_board_says_so` |
| Crash recovery | `Actions/Broker.cs` | `BoardTests.Recovery_marks_stale_running_actions_unknown_and_reposts_orphans` |
| Retention | `Ops/Retention.cs` | `RetentionTests.*`, `OpsTests.Retention_days_below_thirty_are_refused` |
| Notifications carry no justification | `Ops/Notifier` | `OpsTests.Notices_never_carry_justification`, `NotificationTests.Summary_is_one_plain_capped_line` |
| Release verification | `infra/lib.sh` `release_fetch` | `infra/tests/up-test.sh` (release cases) |
| Australian region, no secrets in deployment state | `infra/up.sh`, `infra/lib.sh` | `infra/tests/up-test.sh` |
| Separation-of-duties readiness check | `Ops/Setup.cs` | `OpsTests.Access_warns_until_two_approvers_and_an_admin_have_signed_in` |
| Audit log viewer and audited exports | `Ops/AuditLog.cs`, `Http/BoardApi.cs` | `EnterpriseControlsTests.Audit_log_filters_pages_and_is_admin_only`, `EnterpriseControlsTests.Export_is_audited_formula_safe_and_people_only` |
| Role changes recorded | `Auth/Authenticator.cs` | `EnterpriseControlsTests.Role_change_seen_in_a_token_is_audited_once`, `Concurrent_role_changes_are_audited_once`, `Role_change_rolls_back_if_audit_write_fails`, `Role_delta_lists_added_and_removed` |
| Inactivity disable | `Ops/Participants.cs` | `EnterpriseControlsTests.Inactive_principals_are_disabled_with_audit_and_claims_released` |
| Idle sign-out | `web/src/lib/idle.ts`, `web/src/components/idle.tsx` | `web/src/__tests__/idle.test.ts` |
| PostgreSQL certificate validation | `Data/Db.cs` | `DbTlsTests.Ssl_mode_defaults_to_verify_full`, `DbTlsTests.Ssl_modes_without_encryption_are_refused`, `DbTlsTests.Local_database_url_keeps_prefer` |
| Agent usage, budgets, traces, feedback, risk (TM-47–TM-50) | `Agents/*.cs`, `Mcp/McpObserver.cs` | `AgentObservabilityTests` (unit: price table, redaction, budget arithmetic, risk model, MCP surface; integration: budget cap over MCP, usage validation, overturns, feedback, traces, risk source) |
| Conditional automation, overrides, auto-revert (TM-43–TM-46) | `Actions/Automation.cs`, `Actions/PolicyStore.cs`, `Actions/Broker.cs` | `AutomationTests` (unit and integration), `CrossWorkstreamTests` (requester risk, NeverAuto, reverse pairs) |
| Okta, ServiceNow and Jira connectors (TM-52–TM-56) | `Connectors/*.cs`, `Actions/CatalogOkta.cs`, `Http/ConnectorsApi.cs` | `ConnectorTests` (unit and integration) |
| Detection rules, back-tests, Intune actions (TM-57–TM-60) | `Actions/CatalogDetections.cs`, `Actions/Resolvers.cs`, `Intel/Detections.cs` | `DetectionsExposureTests`, `DetectionTests` |
| Every MCP tool passes the observer hook | `Mcp/BoardTools.cs` `Call` | `ApiSurfaceTests.Every_mcp_tool_is_dispatched_through_call`, `CrossWorkstreamTests.New_tools_from_every_feature_are_traced_and_metered_by_the_observer` |

The administration posture score checks configuration only. It does not verify Azure resource state, Conditional Access enforcement or successful log delivery. See [the operational assurance review](OPERATIONS.md#admin-centre-and-assurance-review). `OpsTests.Posture_does_not_overstate_unverified_controls_or_reward_live_writes` checks several false-positive cases.

Controls with **no automated test**: TM-23 (CI configuration), TM-26, TM-31 (pgaudit and detection), TM-32, TM-34 and TM-36 (Bicep and scripts only; NSGs and TLS settings are checked by Bicep lint, not by a test).

---

## 11. Known limitations

Kept consistent with [SECURITY.md § Known limitations](SECURITY.md#known-limitations) and [Trust Center § Known limitations](assurance/TRUST-CENTER.md#known-limitations).

| Limitation | Threat | Status |
|---|---|---|
| Conditional Access is created report-only; MFA, compliant device and sign-in frequency aren't enforced until the consumer enforces them | TM-08, TM-28, TM-29 | Consumer action |
| Idle sign-out runs in the browser; it doesn't limit a stolen token used outside the SPA | TM-29 | Accepted |
| No continuous access evaluation or token binding; revoked sessions keep working until the access token expires | TM-28 | Accepted |
| The board records that roles changed, not who changed them (Entra's audit log is the record) | TM-42 | Accepted (transfer) |
| Ordinary reads and posts aren't in `audit_log` | TM-40 | Accepted (transfer) |
| Inactivity disable is off until `INACTIVE_DISABLE_DAYS` is set | TM-41 | Consumer action |
| The schema owner can disable the audit triggers; pgaudit and the Sentinel copy (production) are the detection | TM-31 | Accepted |
| `blueboard-id-api` is both schema owner and holder of the Microsoft permissions | TM-32 | Accepted |
| `mvp` profile: public PostgreSQL with `AllowAzureServices`, secrets in app settings, no audit export, no VNet or NSGs, TLS 1.2 | TM-35 | By design (evaluation only) |
| No TLS 1.2 cipher list is pinned; Storage stays at TLS 1.2 | TM-34 | Accepted |
| NSG flow logs aren't configured | TM-35 | Consumer option |
| Release provenance is checked only when the GitHub CLI is signed in | TM-27 | Planned (fail closed) |
| NuGet restores aren't lock-file pinned | TM-23 | Open |
| API bodies aren't WAF-inspected by default; `DEPLOYER_IP_RANGES=none` leaves scm open | TM-36 | Accepted |
| Sentinel Contributor is workspace-wide | TM-20 | Accepted |
| Protected users and devices given only by name need the incident evidence to resolve an id | TM-04 | Accepted (list ids as well) |
| Two agents can corroborate each other for conditional automation unless `require_human_verdict` or `requesters` is set | TM-43 | Consumer option (policy-check warns) |
| A runtime-database edit to an override that stays inside the `policy.json` ceiling is not prevented, only audited by absence | TM-45 | Accepted |
| CIDR ranges in `protected_indicators` aren't expanded | TM-05 | Open |
| `intune_expedite_quality_update` uses the Windows Autopatch API, which is Graph beta only | TM-60 | Accepted (beta) |
| A back-test estimates volume from history; it can't prove a rule detects the attack | TM-58 | Accepted (review) |
| The production profile and every write action haven't been exercised end to end against a live tenant | All | Consumer testing |
| No independent penetration test has been published | All | Open |
| Agent-reported LLM usage can't be verified against the provider by the board | TM-47 | Accepted (reconcile with billing) |
| Trace argument summaries keep entity names and KQL; only recognised secrets are removed | TM-48 | Accepted (retention) |

---

## 12. Pre-go-live verification

Before `BROKER_EXECUTE=true`:

- [ ] `dotnet test --solution api/Blueboard.slnx` passes, with `BLUEBOARD_TEST_DATABASE_URL` set so the integration suite runs.
- [ ] `blueboard policy-check policy.json` passes, and every `protected_*` list is populated (A4).
- [ ] The `production` profile is deployed. The Setup page shows *Audit export to Sentinel* OK, and the analytics rules in `infra/sentinel/` are enabled.
- [ ] Conditional Access has been reviewed in report-only mode and then **enforced** (`CA_STATE=on`), with break-glass accounts excluded (A2).
- [ ] At least two approvers and one admin have signed in, and Admin and Approve are held by different people (Setup → *Access (separation of duties)*, TM-30).
- [ ] `SESSION_IDLE_MINUTES` is between 1 and 15, `INACTIVE_DISABLE_DAYS` is set, and with `FRONT_DOOR=true`, `DEPLOYER_IP_RANGES` names a management network.
- [ ] Dry run (`BROKER_EXECUTE=false`) has run for at least seven days and been reviewed in `/reports`.
- [ ] Each action to be brokered has been tested in a non-production tenant.
- [ ] Agent identities use managed identity, Entra Agent ID or federation, with no client secrets and no Approve or Admin.
- [ ] §9 risk acceptance is signed.
