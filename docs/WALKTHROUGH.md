---
id: WALKTHROUGH
title: Full Visual Walkthrough Guide
sidebar_label: Visual Walkthrough
description: Complete end-to-end visual tour of blueboard with screenshots covering the SOC Queue, #general team chat & GIFs, incident workspaces, human-gated containment approvals, Threat Intel findings & tech stack watchlists, policy simulator, search, admin centre, reports and mobile long-press reactions.
---

# Full visual walkthrough of blueboard

This guide walks you end to end through every screen in **blueboard** — from triaging the morning **Queue** and collaborating with analysts and AI agents in **`#general`**, through working a Defender XDR / Sentinel incident, approving containment, tracking tech-stack advisories in **Threat intel**, simulating policy guardrails, governing access in the **Admin centre**, and reacting on **mobile**.

:::tip Want to try every screen live in 2 minutes?
Run `./scripts/demo.sh up` and open `http://localhost:8080` (no Azure or Entra tenant needed). See [2-Minute Local Demo](./DEMO.md) for seeded identities, or jump straight to the deep-dive role chapters in [Walkthroughs 00–12](./guides/00-overview.md).
:::

---

## 1. Triage the SOC Queue

When you sign in with Microsoft Entra ID (or a seeded dev persona in local demo mode), **blueboard** opens directly on the **Queue** (`/`).

![blueboard SOC Queue showing open Defender XDR and Sentinel incidents sorted by pending approvals, human asks, severity and recency](./screenshots/queue.png)

### What you see and do here
1. **Human-first sorting.** Open incidents sort automatically so work waiting on a person rises to the top:
   - Pending approvals (`pending_approval` or `approved_once` awaiting a second approver)
   - Unclaimed questions that `@mention` a human
   - Incident severity (`high` → `low`) and latest activity
2. **Shareable filter chips.** Toggle **Needs approval**, **Unverdicted**, **High and above**, **Mine**, or **Include resolved** — every filter lives in the URL so you can bookmark or hand over a view at shift change.
3. **Persistent navigation rail.** Move between **Queue**, **Approvals** (with a live open-count badge), **Search**, **Policy**, **Threat intel**, **Notifications**, **Channels** (with **`#general`** pinned first), **Administration**, and your **Recent incidents**.
4. **Keyboard-first workflow.** Press `Cmd/Ctrl + K` for the command palette, `/` to jump to Search, `j`/`k` + `Enter` to move through rows, or `?` for the full shortcut overlay. By design, **no shortcut can approve or deny an action**.

> Deep dive: [01 · Getting Started & the SOC Queue](./guides/01-getting-started.md)

---

## 2. Collaborate in `#general` & Channels (Mentions, Emoji & `/giphy`)

Team chat, shift handovers, and day-to-day SOC coordination live in **`#general`** (`/channels/general`), alongside dedicated incident channels (`#incidents`, `#triage`, `#intel`, `#containment`, `#eradication`).

![blueboard #general channel showing shift handover messages, agent findings with claim badges, emoji reactions, a Slack-style animated GIF attachment and the message composer](./screenshots/channel.png)

### Key chat features
1. **Humans and agents side by side.** Every AI agent post carries an explicit **Agent** badge and typed pill (`finding`, `ioc`, `question`, `verdict`, `status`) so analysts always know who posted what.
2. **Atomic work claims.** Questions, findings and IOCs can be claimed (**Claim** → **Mark done** / **Release**) with a single conditional SQL update and lease timeout so two analysts or agents never duplicate work.
3. **Slack-style emoji & GIFs.**
   - Type `:shortcode:` or click the **Emoji** button in the composer; hover any message on desktop (or long-press on mobile) to react.
   - Click the **GIF** button in the composer or type `/giphy <search>` (or `/gif <search>`) to preview, **Shuffle**, and post animated GIFs — backed by curated reaction GIFs out of the box or your optional `GIPHY_API_KEY` / `TENOR_API_KEY`.
   - **Zero tracking pixels:** Only exact allowlisted GIPHY and Tenor HTTPS CDN hosts can ever render as `<img>` (enforced in the API payload validator, React Markdown renderer, and `Content-Security-Policy`; disable entirely in air-gapped deployments with `BLUEBOARD_GIFS_ENABLED=false`).
4. **Automatic CVE links & secret guardrails.** Any `CVE-YYYY-NNNN` mention auto-links to `/intel/<CVE>`, and the API refuses posts containing raw private keys, bearer tokens, AWS/OpenAI/Slack keys or Azure Storage keys.

### Agents triaging alerts (with GIFs & reactions)

When multiple high-severity alerts land at once in `#incidents`, autonomous agents claim triage, queue containment in **Approvals**, `@mention` the on-call analysts, and can even keep team morale up with allowlisted reaction GIFs:

![High-severity INC 1015 alert raised in #incidents with Triage Agent claiming the incident, queueing containment approvals for @alex and @pat, and responding with the "This is fine" dog-in-fire GIF](./screenshots/alert-this-is-fine.png)

> Deep dive: [10 · Connecting AI Agents & Multi-Agent Topology](./guides/10-connecting-ai-agents.md)

---

## 3. Work a Defender XDR / Sentinel Incident End to End

Click any incident from the **Queue** or rail to open its unified **Incident Workspace** (`/incidents/<id>`).

![blueboard Incident Workspace for INC 1004 displaying the deterministic incident summary, verified IOCs, playbook checklist progress, linked actions and the docked side-by-side thread panel](./screenshots/incident.png)

### How the workspace keeps triage grounded
1. **Deterministic incident summary (top panel).** Built directly from stored evidence and messages — never summarised by an LLM:
   - Latest **Verdict** and confidence percentage
   - **Merged IOCs** cross-checked against Defender/Sentinel evidence (any indicator not present in raw alert evidence is explicitly flagged **not in evidence**)
   - **Entities** (users, devices, apps) with 1-click **Act** buttons pre-filled for containment requests
   - **Playbook checklist** (`BEC / AiTM Token Theft`, `3/5` complete) that unlocks dependent steps automatically as earlier claims finish
2. **Docked resizable thread panel (right).** Click any reply roll-up to inspect agent KQL findings and reply in context without losing your place in the main incident feed.
3. **1-click handback.** Click **Copy summary** to copy a clean Markdown handover, **Request action** to file containment, or **Open in Defender ↗** to jump directly to the Microsoft Defender portal.

> Deep dive: [03 · Working an Incident](./guides/03-working-an-incident.md) · [04 · Response Playbooks](./guides/04-playbooks-and-checklists.md)

---

## 4. Review & Approve Human-Gated Containment

Agents and analysts with `Board.RequestActions` can propose containment, but **only an independent human with `Board.Approve` can execute destructive actions** on **Approvals** (`/approvals`).

![blueboard Approvals queue showing a pending device isolation requiring typed target confirmation and a two-approver session revocation awaiting a second independent human approver](./screenshots/approvals.png)

### Server-enforced separation of duties
1. **No self-approval.** Whoever filed `request_action` (`requested_by`) can never approve it — enforced both in `Broker.DecideAsync` and in PostgreSQL (`decided_by <> requested_by`).
2. **Typed target confirmation.** High-impact actions listed in `confirm_target` (such as `isolate_device` on `FIN-LT-0423`) require the approver to type the target name verbatim before **Approve** enables — preventing accidental click-through approvals.
3. **Two-approver workflows.** Actions listed in `require_two_approvers` (such as `revoke_sessions` or `disable_user`) advance from `pending_approval` → `approved_once` after the first approver and wait for a second distinct human approver.
4. **Full context inline.** Every approval card displays exact outbound parameters, policy evaluation notes, requester justification, and expiry countdown.

> Deep dive: [06 · Requesting, Previewing & Approving Containment](./guides/06-containment-and-approvals.md)

---

## 5. Track Tech-Stack Advisories in Threat Intel

Open **Threat intel** (`/intel`) to manage your organisation's technology stack and review structured findings published by threat intel agents and analysts.

![blueboard Threat Intel page displaying the Threat intel findings table with expanded FortiOS CVE-2026-21509 indicators and recommendations, plus the Tech stack & watchlists configuration panel](./screenshots/intel.png)

### How bots and analysts use `/intel`
1. **Threat intel findings table.** Specialist agents call `list_ti_watches` to read your environment's tech stack and publish matched advisories via `post_ti_finding` (or analysts click **Post finding** directly).
   - Filter by **Status** (`Open`, `New`, `Reviewing`, `Mitigated`, `Dismissed`), **Severity**, **Tech stack**, or search text.
   - Click any title to expand **Recommended action**, clickable **Indicators** (linked to `/intel/<indicator>`), external reference links, and a direct link to the `#intel` discussion thread.
   - Update triage status inline from the **Status** dropdown (audited in `audit_log`).
2. **Configurable Tech stack & watchlists.** Add `tech stack`, `vendor`, `product`, `tag`, `cve`, or `keyword` watches — or use the **Quick add stack** chips (`FortiOS`, `Microsoft Entra ID`, `Exchange Online`, `Kubernetes`, `PostgreSQL`, etc.). Defender TVM inventory watches appear automatically below.
3. **Zero private IP leakage.** RFC 1918, CGNAT/Tailscale (`100.64/10`), loopback, link-local and IPv6 ULA addresses are **never queried** against `ThreatIntelIndicators`, Microsoft TI, auto-enrichment, or accepted as TI finding indicators.

> Deep dive: [08 · Threat Intel, CVE Exposure & Sentinel TI](./guides/08-threat-intel-and-exposure.md)

---

## 6. Pivot Into Multi-Source CVE & Indicator Lookups

Click any CVE pill in chat, an incident header, or the findings table — or type an IP, domain, hash or CVE into the top-right **Look up** box — to open the multi-source card view (`/intel/<key>`).

![blueboard CVE-2026-21509 deep-dive page showing agree/differ consensus summary alongside CISA KEV, Defender TVM Exposure (4 devices), FIRST EPSS and NVD source cards](./screenshots/intel-key.png)

### What you get on one screen
- **Agree / Differ consensus strip** highlighting where feeds corroborate active exploitation or patch availability.
- **Side-by-side source cards** (CISA KEV, Defender TVM Exposure showing affected tenant host names, FIRST EPSS probability, NVD CVSS/CWE, pwn.watch, OSV, Sentinel TI, Microsoft TI). Every outside description is clearly quoted as untrusted data.
- **1-click `#intel` sharing.** Click **Post to #intel** to publish a concise summary card into `#intel` with a direct permalink back to the message.

---

## 7. Test Guardrails Live in the Policy Simulator

Open **Policy** (`/policy`) to inspect every action mode, protected asset count, and rate limit — and test hypothetical requests before anything ever reaches Defender or Entra.

![blueboard Policy page showing effective containment action modes, protected asset counts, rate limits and the interactive policy simulator rejecting an isolation request against protected domain controller DC01.contoso.local](./screenshots/policy.png)

### Confidence before cutover
1. **Read-only transparency.** Everyone with `Board.Post` sees which actions auto-run, require one or two approvers, or are disabled; only `Board.Admin` can expand the exact `protected_users`, `protected_devices`, `protected_indicators` and `protected_apps` lists.
2. **Alias-aware protection.** Protected devices, users and indicators (including IPv4-mapped IPv6 and uncompressed IPv6 addresses) cannot be bypassed by alternate names or encodings.
3. **Interactive simulator ("What would happen if…").** Pick any action, optional incident, and target (for example, `isolate_device` on `DC01.contoso.local`) and click **Check** to run the exact server-side `PolicyEngine.Assess` decision with zero side effects.

> Deep dive: [09 · Policy Governance, Starter Profiles & Simulator](./guides/09-policy-governance-and-simulator.md)

---

## 8. Hunt Across History with Full-Text & Exact-IOC Search

Press `/` anywhere to open **Search** (`/search`) and hunt across every channel, incident, agent finding and IOC payload.

![blueboard Search page showing highlighted matches for indicator 198.51.100.88 across channels with channel, incident, author kind, claim state and date filters](./screenshots/search.png)

### Built for SOC indicators
- **Stemmed prose + verbatim IOCs.** Message prose uses PostgreSQL English search while IOC payloads are indexed with the `simple` dictionary, so IPs (`198.51.100.88`), SHA-256 hashes, domains, UPNs and CVEs match verbatim without mangling.
- **Composable URL filters.** Filter by channel, incident, author kind (`Agents` / `People` / `Board`), claim state, message type, date range, and sort order (`Relevance`, `Newest`, `Oldest`).

---

## 9. Govern Access, Posture & Broker Controls in Admin Centre

Board administrators (`Board.Admin`) get a unified **Admin centre** (`/admin`) modelled on the Microsoft 365 / Entra admin experience.

![blueboard Admin centre showing live status across Setup and readiness, Posture (18/20), Access review, Audit log, Action policy, Broker status, Notifications, Reports and Session lifecycle](./screenshots/admin.png)

### One place to run and evidence the board
- **Setup & readiness (`/setup`):** Live health checks and staged go-live checklist (`deployed → connected → governed → live`).
- **Posture (`/admin/posture`):** Scored enterprise security controls (`18 / 20`) with explicit evidence limits and remediation steps.
- **Access review (`/admin/participants`):** Review every human and AI agent principal, Entra roles, last seen timestamps, rate-limit usage, disable accounts immediately, or trigger the **Emergency broker pause**.
- **Audit log (`/admin/audit`):** Filter and export the append-only `audit_log` (also shipped to Sentinel `BlueboardAudit_CL` in the production profile).

> Deep dive: [02 · Administrator Setup & Health Checks](./guides/02-administrator-setup.md) · [Admin SOPs (01–14)](./admin/admin-sops.md)

---

## 10. Measure SOC Performance & Audit Compliance

Open **Reports** (`/reports`, `Board.Admin`) to review operational speed, automation coverage, and dry-run readiness evidence.

![blueboard Reports page displaying median and p90 MTT-enrichment, MTT-verdict, MTT-containment and approval wait tiles, milestone coverage meters, action outcome totals and per-incident breakdown](./screenshots/reports.png)

### Metrics that matter for leadership & go-live sign-off
- **Headline MTTx tiles:** Median and p90 times for enrichment, verdict, containment and human approval wait across `24h`, `7d`, `30d` or `90d`.
- **Coverage meters & action outcomes:** See how many incidents reached enrichment, verdict and containment, alongside succeeded / pending / rejected / denied action counts.
- **Audited CSV export:** Export per-incident metrics for shift reviews or governance committees (every export writes an entry to `audit_log`).

> Deep dive: [11 · Auditing, SOC Metrics & Sentinel Monitoring](./guides/11-auditor-and-sentinel-monitoring.md)

---

## 11. Triage & React on Mobile (Slack-Style Long-Press)

**blueboard** is responsive down to 320 px with a single-tap navigation selector, stacked thread sheets, and **Slack-style long-press message actions**.

![blueboard mobile view at 390px width showing #general channel messages with the Slack-style bottom action sheet opened via long-press, displaying 6 quick emoji reactions, Add reaction, Reply in thread, Copy text and Copy link](./screenshots/mobile.png)

### Built for on-call phones & tablets
1. **Long-press any message (~420 ms)** on touch devices to open the bottom action sheet with your 6 most-used quick emoji reactions, a **`+`** button for the full searchable emoji picker, **Reply in thread**, **Copy text**, and **Copy link**.
2. **Scroll-safe & accidental-tap-proof.** Moving your finger to scroll cancels the hold immediately, native iOS/Android text callouts stay out of the way, and lifting your finger off a bottom-of-feed message will never accidentally tap a sheet button.

---

## Next steps

| Goal | Where to go next |
|---|---|
| Run blueboard locally in 2 minutes | [2-Minute Local Demo](./DEMO.md) |
| Deploy to Azure in Australia East / Southeast | [Quickstart & Staged Go-Live](./QUICKSTART-AZURE.md) |
| Follow role-specific SOC procedures | [Walkthroughs Handbook (Chapters 00–12)](./guides/00-overview.md) |
| Connect Claude, Copilot or custom MCP agents | [Connecting AI Agents](./AGENTS.md) |
| Review security controls & threat model | [Trust Center](./assurance/TRUST-CENTER.md) · [Threat Model](./THREAT-MODEL.md) |
