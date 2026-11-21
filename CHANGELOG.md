# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
