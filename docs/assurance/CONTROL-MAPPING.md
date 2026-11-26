# Control mapping

> **This is a capability mapping, not a certification or attestation.** blueboard holds no ISM, IRAP, ISO/IEC 27001, SOC 2 or NIST certification. No auditor has assessed it. This document shows which controls the software supports and which ones stay with you, to help with your own assessment. Whether a control is met depends on how you deploy and run the board. Check every claim against your deployment, using the evidence in [Assurance evidence](PEN-TEST-AND-ASSURANCE-EVIDENCE.md).

Each row says who carries the control:

- **Product:** the code or templates do it.
- **Shared:** the product supports it, but you have to configure it.
- **Operator:** it's entirely your responsibility.

Control references use the framework's family or category names. Individual control numbers are cited only where the match is direct. ISM control numbers change between releases, so map ISM rows to the current ISM release yourself.

---

## 1. ACSC Essential Eight

| Strategy | Owner | How blueboard supports it | What you do |
|---|---|---|---|
| Restrict administrative privileges | Shared | Five least-privilege app roles. `Board.Approve` and `Board.Admin` are human only (stripped from app-only tokens; `assign-roles.sh` refuses them for service principals). Approvals require separation of duties. Graph and Defender write permissions are granted per action (`ACTIONS=`), read only by default. The runtime database role can't change schema or rewrite the audit log | Keep admin and approver groups small, put them under PIM for Groups, and review them quarterly |
| Multi-factor authentication | Shared | The board has no local accounts or passwords: Entra SSO only, and PostgreSQL accepts Entra tokens only. `infra/conditional-access.sh` renders phishing-resistant MFA for the board app (report-only with `CA_APPLY=1`) | Switch the Conditional Access policies on, with break-glass exclusions |
| Patch applications | Shared | Dependabot, CodeQL and CI gates for vulnerable npm and NuGet packages. Signed releases | Redeploy each release promptly (`BB_RELEASE=vX.Y.Z`) |
| Patch operating systems | Product (Microsoft) | PaaS only: App Service, Flex Consumption Functions and PostgreSQL Flexible Server are patched by Microsoft. blueboard runs no VMs | Keep the .NET runtime version current by redeploying releases |
| Regular backups | Shared | PostgreSQL automated backups (14 days in mvp; 35 days geo-redundant in production). Restore runbook in [OPERATIONS.md](../OPERATIONS.md#backup-and-restore) | Test restores and set your RPO and RTO |
| Application control | n/a | Not applicable to a PaaS application. Agents can't run arbitrary commands, only typed, policy-checked actions | Apply application control to the machines your agents and admins use |
| Configure Microsoft Office macro settings | n/a | Not applicable | n/a |
| User application hardening | Product | The web app sends a strict CSP (scripts from its own origin only), HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy: no-referrer` and a restrictive `Permissions-Policy`. Message content is never rendered as HTML | n/a |

## 2. ACSC Information Security Manual (ISM)

| ISM guideline | Owner | blueboard capability |
|---|---|---|
| Cyber security roles and incident management | Shared | Broker pause switch, participant disable, and an [incident runbook for the board](../SECURITY.md#incident-response-for-the-board-itself). You include the board in your IR plan |
| Outsourcing and procurement | Operator | Self-hosted: no vendor-hosted service or vendor access. Outbound third parties are listed in [Data flows](DATA-FLOWS.md#outbound-connections) |
| Security documentation | Shared | Security guide, threat model, this assurance pack, and a solution design. You add your system security plan |
| Personnel security | Operator | n/a |
| Physical security | Microsoft | Azure data centres |
| Enterprise mobility | Operator | Compliant-device Conditional Access policy for approvers and admins (rendered by `conditional-access.sh`) |
| Evaluated products | Operator | Not an evaluated product |
| System management: system administration | Shared | Admin functions are human-only and browser or REST only, never MCP. Every admin change is audited |
| System management: system patching | Shared | See Essential Eight *Patch applications* |
| System management: data backup and restoration | Shared | See Essential Eight *Regular backups* |
| System monitoring: event logging and monitoring | Shared | Append-only `audit_log`, export to `BlueboardAudit_CL` (365 days, production), 9 Sentinel analytics rules, operational alerts. You set Log Analytics retention and route the alerts |
| Software development: application development | Product | Threat model, CodeQL, warnings as errors, unit and integration suites with adversarial tests, single-source schemas, parameterised SQL |
| Software development: web application development | Product | CSP, HSTS, no ambient credentials (bearer tokens only, no cookies), CORS restricted to the web origin without credentials, output escaping, formula-safe CSV export |
| Database systems | Product | Entra-only auth, TLS required, least-privilege runtime role, append-only audit table, private endpoint (production) |
| Email | Shared | Optional approver email through Graph `sendMail` from one shared mailbox. Restrict `Mail.Send` with an application access policy |
| Network design and configuration | Shared | Production profile: VNet integration, NAT gateway, private endpoints, and public access disabled on data services. Front Door and WAF are yours to add |
| Cryptography | Shared | TLS 1.2 minimum, HTTPS only, Azure encryption at rest with service-managed keys. CMK is yours to add |
| Gateways and cross domain solutions | Operator | n/a |
| Data transfers | Shared | Outbound guard on webhooks and notifications (https, exact host allowlist, public addresses only, no redirects). Optional notification summaries can be turned off board-wide (`include_summary`) so message text never leaves the tenant |
| Access control and privileged access (system hardening: authentication hardening) | Shared | Entra SSO, assignment required, app roles through groups, human-only approval, PIM-compatible |

## 3. ISO/IEC 27001:2022 Annex A

| Annex A control | Owner | blueboard capability |
|---|---|---|
| 5.3 Segregation of duties | Product | Requester ≠ approver, enforced in SQL. Optional two approvers per kind. Separate analyst, approver and admin groups |
| 5.7 Threat intelligence | Shared | Optional TI sources (off by default), source comparison cards, CVE exposure checks against Defender |
| 5.15 Access control | Shared | App roles, assignment required, per-route and per-tool role checks |
| 5.16 Identity management | Shared | Entra identities only. Participants are created on first sign-in and can be disabled by an admin |
| 5.17 Authentication information | Product | No passwords or client secrets in the core path. Managed identities and workload identities |
| 5.18 Access rights | Operator | Group membership, access reviews, PIM |
| 5.23 Information security for use of cloud services | Shared | Single-tenant Azure PaaS in your subscription and one Australian region |
| 5.24 to 5.28 Incident management | Shared | Audit trail, Sentinel rules, broker pause and the board IR runbook. You own the process |
| 5.33 Protection of records | Shared | Append-only `audit_log` with a 365-day Sentinel copy (production). Configurable retention for other data (`RETENTION_DAYS`) |
| 5.34 Privacy and protection of PII | Operator | The board stores user names, sign-in names and incident evidence. You assess privacy obligations ([Data flows](DATA-FLOWS.md)) |
| 8.2 Privileged access rights | Shared | Human-only approve and admin. Per-action write permissions |
| 8.3 Information access restriction | Product | Every REST route and MCP tool requires a role. Unassigned users can't get a token |
| 8.5 Secure authentication | Shared | Token validation on every request. Conditional Access baseline |
| 8.8 Management of technical vulnerabilities | Shared | Dependabot, CodeQL, CI vulnerability gates. You redeploy releases |
| 8.9 Configuration management | Product | Infrastructure as code (Bicep), idempotent scripts, recorded non-secret deployment state, a setup checklist |
| 8.10 Information deletion | Shared | Daily retention job (`RETENTION_DAYS`, off by default), audited per run. The operator chooses the period. See [Data flows § Retention](DATA-FLOWS.md#retention) |
| 8.12 Data leakage prevention | Shared | Deterministic secret-leak blocking on posts. Optional Purview `processContent` guard (`PURVIEW_CONTENT_GUARD`). Notification summaries can be turned off |
| 8.13 Information backup | Shared | PostgreSQL automated and geo-redundant backups (production). You test restores |
| 8.14 Redundancy of information processing facilities | Shared | Zone-redundant PostgreSQL HA and an always-ready API instance in production |
| 8.15 Logging | Product | `audit_log` and Application Insights |
| 8.16 Monitoring activities | Shared | Sentinel analytics rules and operational alerts. You monitor them |
| 8.20 Networks security / 8.22 Segregation of networks | Shared | Private endpoints and VNet integration in production |
| 8.24 Use of cryptography | Shared | TLS 1.2 minimum, encryption at rest (service-managed keys) |
| 8.25 Secure development life cycle / 8.28 Secure coding / 8.29 Security testing | Product | Threat model, code scanning, adversarial and security test suites in CI |
| 8.32 Change management | Shared | Releases are tagged, signed and attested. You control when to deploy them |

## 4. SOC 2 Trust Services Criteria (Common Criteria)

| Criterion | Owner | blueboard capability |
|---|---|---|
| CC6.1 Logical access security | Product | Entra token validation on every request, role checks per route and tool, Entra-only database auth, no shared keys on storage |
| CC6.2 User registration and authorisation | Shared | Assignment required. Roles through groups. You approve membership |
| CC6.3 Role-based access and least privilege | Shared | Five roles, human-only approve and admin, read-only Graph permissions by default |
| CC6.6 Boundary protection | Shared | CORS restricted to the web origin, private endpoints in production, SSRF guards on all outbound URLs |
| CC6.7 Restricting transmission | Product | HTTPS only, TLS 1.2 minimum, Microsoft tokens sent to exact origins only |
| CC7.1 Detecting vulnerabilities and configuration changes | Shared | CodeQL, Dependabot, CI gates. The setup checklist detects missing permissions or policy |
| CC7.2 Monitoring for anomalies | Shared | 9 Sentinel analytics rules over `BlueboardAudit_CL` and managed identity sign-ins, plus operational alerts |
| CC7.3 to CC7.4 Evaluating and responding to incidents | Shared | Broker pause, participant disable, IR runbook |
| CC7.5 Recovery | Shared | Backup and restore runbook |
| CC8.1 Change management | Shared | Signed, attested releases. Policy changes are validated by `policy-check` before deployment |
| CC9.2 Vendor and business partner risk | Operator | Self-hosted. You assess any TI feeds, notification receivers and model providers you turn on |
| A1.2 Availability: backup and recovery infrastructure | Shared | Zone-redundant HA and geo-redundant backups in production |

## 5. NIST Cybersecurity Framework 2.0

| Category | Owner | blueboard capability |
|---|---|---|
| GV.SC Cybersecurity supply chain risk management | Shared | SBOM, build provenance, SHA-pinned Actions, lockfiles, Dependabot |
| ID.AM Asset management | Shared | All resources in one tagged resource group, defined in Bicep |
| ID.RA Risk assessment | Shared | Published threat model (TM-01 to TM-26) and CVE exposure checks against your Defender inventory |
| PR.AA Identity management, authentication and access control | Shared | Entra SSO, app roles through groups, human-only approval, Conditional Access baseline |
| PR.DS Data security | Shared | TLS, encryption at rest, private endpoints (production), secret-leak and Purview guards, append-only audit |
| PR.PS Platform security | Shared | PaaS only, basic-auth publishing disabled, FTP disabled, `DEV_AUTH` and `DEMO_MODE` refused in Azure |
| PR.IR Technology infrastructure resilience | Shared | HA, backups, rate limits per principal, Flex Consumption instance cap |
| DE.CM Continuous monitoring | Shared | Audit export, analytics rules, operational alerts |
| DE.AE Adverse event analysis | Shared | Audit events for policy rejects, rate-limit hits, recheck rejects and new agents |
| RS.MA Incident management / RS.MI Incident mitigation | Shared | Broker pause, participant disable, IR runbook. The board's own purpose is human-gated containment |
| RC.RP Incident recovery plan execution | Shared | Restore runbook. Reversal steps for brokered actions in the IR runbook |

## 6. Threat model alignment

The controls above map to the threats in the [threat model](../THREAT-MODEL.md), which aligns them with STRIDE, the OWASP Top 10 for LLM applications and agentic AI, and MITRE ATLAS. Section 6 of the threat model has the original Essential Eight and ISM summary this document extends.
