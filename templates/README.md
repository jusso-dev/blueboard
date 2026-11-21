# Blueboard Starter Templates

Ready-to-use templates to make Blueboard immediately interoperable across languages, agent harnesses, policies, and Microsoft Defender XDR / Sentinel environments.

## Policies (`templates/policies/`)

Validate any policy locally before deploying with `dotnet run --project api/Blueboard.Tools -- policy-check <file>`:

- [`starter-readonly.json`](policies/starter-readonly.json) — Week-1 read-only pilot (all write actions disabled except `add_incident_comment`).
- [`starter-balanced-soc.json`](policies/starter-balanced-soc.json) — Balanced SOC profile: auto-approves non-destructive forensics, requires human approval for containment, and enforces two-approver + typed confirmation for high-impact user, service-principal, email and TI writes.
- [`starter-strict-regulated.json`](policies/starter-strict-regulated.json) — Zero auto-approve, two-approver + typed confirmation across destructive containment actions, tight expiry and agent rate limits.

## Interoperable Agent Starters (`templates/agents/`)

Blueboard speaks standard Streamable HTTP MCP (`/runtime/webhooks/mcp`) with Entra bearer tokens (or `BOARD_DEV_PRINCIPAL` in local demo):

- [`python-mcp-agent/`](agents/python-mcp-agent) — Zero-framework Python MCP agent with cursor persistence, atomic claiming, and webhook HMAC verification.
- [`typescript-mcp-agent/`](agents/typescript-mcp-agent) — TypeScript / Node.js starter using `@modelcontextprotocol/sdk` and `@azure/identity`.
- [`specialist-personas/`](agents/specialist-personas) — 5 Vercel-Board-style specialist agent blueprints (`triage-agent`, `sentinel-hunter-agent`, `threat-intel-agent`, `containment-advisor-agent`, `comms-handover-agent`).

## Microsoft Sentinel & Defender KQL (`templates/kql/` & `templates/sentinel/`)

- [`sentinel/automation-rule-logic-app.json`](sentinel/automation-rule-logic-app.json) — ARM template for a Sentinel Automation Rule + Managed Identity Logic App that calls `POST /api/incidents/{id}/sync` within seconds of incident creation.
- [`kql/phishing-bec.kql`](kql/phishing-bec.kql) — Email recipient scoping, URL clicks, inbox forwarding rules, outbound BEC blast radius.
- [`kql/endpoint-powershell-ransomware.kql`](kql/endpoint-powershell-ransomware.kql) — Process trees, fleet hash/command hunts, lateral movement ports, persistence.
- [`kql/identity-aitm-token-theft.kql`](kql/identity-aitm-token-theft.kql) — Session cookie replay, password spray / MFA fatigue summaries, post-compromise MFA registrations.
- [`kql/oauth-app-consent-abuse.kql`](kql/oauth-app-consent-abuse.kql) — Consent grants, service principal sign-ins, app `MailItemsAccessed`.
- [`kql/cloud-azure-privesc.kql`](kql/cloud-azure-privesc.kql) — Azure RBAC writes, VM RunCommand, Key Vault secret enumeration.
- [`kql/sentinel-blueboard-audit.kql`](kql/sentinel-blueboard-audit.kql) — Auditing Blueboard itself via `BlueboardAudit_CL`.

## Sample Defender & Sentinel Incident Fixtures (`templates/incidents/`)

Realistic Graph Security API incident payloads exercising cloud app, service principal, mailbox rule, DNS, and Azure resource evidence:
- [`bec-aitm-inbox-rule.json`](incidents/bec-aitm-inbox-rule.json)
- [`oauth-app-consent.json`](incidents/oauth-app-consent.json)
- [`azure-keyvault-privesc.json`](incidents/azure-keyvault-privesc.json)
