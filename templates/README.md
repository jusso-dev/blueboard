# Blueboard Starter Templates

Ready-to-use templates to make Blueboard immediately interoperable across languages, agent harnesses, policies, and Microsoft Defender XDR / Sentinel environments.

## Policies (`templates/policies/`)

Validate any policy locally before deploying with `dotnet run --project api/Blueboard.Tools -- policy-check <file>`:

- [`starter-readonly.json`](policies/starter-readonly.json) — Week-1 read-only pilot (all write actions disabled except `add_incident_comment`).
- [`starter-balanced-soc.json`](policies/starter-balanced-soc.json) — Balanced SOC profile: auto-approves non-destructive forensics, requires human approval for containment, and enforces two-approver + typed confirmation for high-impact user, service-principal, email and TI writes.
- [`starter-strict-regulated.json`](policies/starter-strict-regulated.json) — Zero auto-approve, two-approver + typed confirmation across destructive containment actions, tight expiry and agent rate limits.

## Dual-MCP, Security Copilot & Specialist Agents (`templates/mcp/`, `templates/security-copilot/`, `templates/agents/`)

Blueboard speaks standard Streamable HTTP MCP (`/runtime/webhooks/mcp`) with Entra bearer tokens (or `BOARD_DEV_PRINCIPAL` in local demo):

- [`mcp/dual-mcp-sentinel-blueboard.json`](mcp/dual-mcp-sentinel-blueboard.json) — Dual-MCP client setup pairing Microsoft Sentinel's managed MCP server (`/mcp/triage`, `/mcp/data-exploration`, `/mcp/graph`) with `blueboard`.
- [`security-copilot/blueboard-mcp-plugin.yaml`](security-copilot/blueboard-mcp-plugin.yaml) — Microsoft Security Copilot MCP plugin manifest connecting Copilot & custom YAML agents to `blueboard`.
- [`agents/python-mcp-agent/`](agents/python-mcp-agent) — Zero-framework Python MCP agent with cursor persistence, atomic claiming, follow-up wakeup handling, and webhook HMAC verification.
- [`agents/typescript-mcp-agent/`](agents/typescript-mcp-agent) — TypeScript / Node.js starter using `@modelcontextprotocol/sdk` and `@azure/identity`.
- [`agents/specialist-personas/`](agents/specialist-personas) — 5 specialist agent blueprints (`triage-agent`, `sentinel-hunter-agent`, `threat-intel-agent`, `containment-advisor-agent`, `comms-handover-agent`).

## Microsoft Sentinel, Defender & Purview KQL (`templates/kql/` & `templates/sentinel/`)

- [`sentinel/automation-rule-logic-app.json`](sentinel/automation-rule-logic-app.json) — ARM template for a Sentinel Automation Rule + Managed Identity Logic App that calls `POST /api/incidents/{id}/sync` within seconds of incident creation.
- [`kql/phishing-bec.kql`](kql/phishing-bec.kql) — Email recipient scoping, URL clicks, inbox forwarding rules, outbound BEC blast radius.
- [`kql/endpoint-powershell-ransomware.kql`](kql/endpoint-powershell-ransomware.kql) — Process trees, fleet hash/command hunts, lateral movement ports, persistence.
- [`kql/identity-aitm-token-theft.kql`](kql/identity-aitm-token-theft.kql) — Session cookie replay, password spray / MFA fatigue summaries, post-compromise MFA registrations.
- [`kql/oauth-app-consent-abuse.kql`](kql/oauth-app-consent-abuse.kql) — Consent grants, service principal sign-ins, app `MailItemsAccessed`.
- [`kql/cloud-azure-privesc.kql`](kql/cloud-azure-privesc.kql) — Azure RBAC writes, VM RunCommand, Key Vault secret enumeration.
- [`kql/purview-dlp-insider-ai.kql`](kql/purview-dlp-insider-ai.kql) — Purview DLP alerts, sensitivity label downgrades, mass SharePoint/OneDrive downloads, Insider Risk correlation, and generative AI / Copilot prompt uploads.
- [`kql/sentinel-blueboard-audit.kql`](kql/sentinel-blueboard-audit.kql) — Auditing Blueboard itself via `BlueboardAudit_CL`.

## Sample Defender, Sentinel & Purview Incident Fixtures (`templates/incidents/`)

Realistic Graph Security API incident payloads exercising cloud app, service principal, mailbox rule, Purview DLP / Insider Risk, blob storage, DNS, and Azure resource evidence:
- [`bec-aitm-inbox-rule.json`](incidents/bec-aitm-inbox-rule.json)
- [`oauth-app-consent.json`](incidents/oauth-app-consent.json)
- [`azure-keyvault-privesc.json`](incidents/azure-keyvault-privesc.json)
- [`purview-dlp-insider-exfil.json`](incidents/purview-dlp-insider-exfil.json)
