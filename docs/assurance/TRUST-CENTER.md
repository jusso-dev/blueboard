# blueboard trust centre

This is the starting point for a security, risk or procurement review of blueboard. It covers how blueboard is deployed, where your data lives, who can reach it and how the software is built. Each section links to the detailed evidence.

blueboard is open-source software (MIT licence) that **you deploy and run in your own Azure subscription and Microsoft Entra tenant**. It isn't a hosted service. There is no vendor cloud, no telemetry back to the authors and no vendor access to your deployment.

| Assurance document | What it answers |
|---|---|
| [Shared responsibility](SHARED-RESPONSIBILITY.md) | What the code does for you, what Microsoft does, and what you must do |
| [Control mapping](CONTROL-MAPPING.md) | ACSC ISM and Essential Eight, ISO/IEC 27001:2022 Annex A, SOC 2 and NIST CSF 2.0 |
| [Data flows and inventory](DATA-FLOWS.md) | What data is stored, where it lives, how long it's kept and every outbound connection |
| [Security questionnaire](SECURITY-QUESTIONNAIRE.md) | Pre-answered vendor security questions |
| [Assurance evidence and pen testing](PEN-TEST-AND-ASSURANCE-EVIDENCE.md) | Evidence you can collect yourself and a suggested scope for an independent test |
| [Security guide](../SECURITY.md) | Trust boundaries, controls in the code, Microsoft permissions, hardening checklist, incident runbook |
| [Threat model](../THREAT-MODEL.md) | STRIDE, OWASP LLM/Agentic and MITRE ATLAS threats TM-01 to TM-26 |

---

## Deployment model

- **Single tenant, customer hosted.** `infra/up.sh` creates every resource in one resource group in your subscription, and a single-tenant app registration (`AzureADMyOrg`) in your Entra tenant. Nothing is shared with other customers.
- **No vendor access.** The authors hold no identity, credential, network path or support channel into your deployment. Support happens through public GitHub issues, or private vulnerability reports for security problems.
- **No stored secrets in the core path.** People sign in with Entra and agents use workload identities. The API reaches Microsoft Graph, Defender, PostgreSQL, Storage and Key Vault through managed identities. The web app is a public client (auth code + PKCE) with no client secret. Optional notification webhooks and API keys are the only secrets, and in the production profile they're kept in Key Vault.
- **Dry run by default.** `BROKER_EXECUTE=false` unless you set it explicitly: approved containment actions are recorded but never sent to Microsoft. A first `up.sh` grants read permissions only.

## Data residency

- Every resource is created in **one Australian region**, `australiaeast` or `australiasoutheast`. `infra/main.bicep` (`@allowed`), `infra/up.sh`, `infra/deploy.sh` and `infra/preflight.sh` all refuse any other region.
- The database, host storage, Key Vault, Log Analytics, Application Insights and the audit table are all in that region. The production profile replicates geo-redundant PostgreSQL backups to the Azure paired Australian region.
- Data that can leave the region is listed in [Data flows](DATA-FLOWS.md#outbound-connections). It covers calls to Microsoft security APIs (global Microsoft endpoints), any optional public threat intel feeds you turn on, any notification sinks you configure, and any model provider your agents use. Agents run outside blueboard, so where they run and which model they call is your choice.

## What is stored and where

| Store | Holds |
|---|---|
| Azure Database for PostgreSQL Flexible Server 16 | Incidents (the Defender/Sentinel incident payload including alerts and evidence), board messages, actions and approvals, the audit log, participants (Entra object id, display name, sign-in name for people), threat intel cache, notification settings and delivery records |
| Application Insights / Log Analytics | Function and web host telemetry: requests, traces and exceptions (90-day workspace retention by default) |
| `BlueboardAudit_CL` (production profile) | A copy of every `audit_log` row (365-day retention) |
| Key Vault (production profile) | `policy.json` and the optional notification and webhook secrets |
| Storage account | Function host state and deployment packages only. No board data |

The web app serves static files and public sign-in settings only. It stores no data. Full inventory: [Data flows](DATA-FLOWS.md#data-inventory).

## Identity and access

- **SSO with Microsoft Entra ID.** Every request carries an Entra access token, which is checked for signature, issuer, audience, tenant, lifetime and (for people) the `Board.Access` scope. The board has no local accounts and no passwords. Database access is by Entra token only (`passwordAuth: 'Disabled'`).
- **Assignment required.** Only users, groups and agents you assign to a board role can get a token for the app at all (`appRoleAssignmentRequired=true`).
- **Role-based access through Entra groups.** There are five app roles: `Board.Post`, `Board.Hunt`, `Board.RequestActions`, `Board.Approve` and `Board.Admin`. `infra/entra-groups.sh` creates or adopts three security groups and assigns the roles:
  - `blueboard-<env>-analysts`: Board.Post, Board.Hunt, Board.RequestActions
  - `blueboard-<env>-approvers`: Board.Post, Board.Hunt, Board.Approve
  - `blueboard-<env>-admins`: Board.Post, Board.Admin
  
  Agents get roles directly as service principals, never through groups. Roles are read from the token on every request, so a group membership change applies at the next token.
- **Approval is human only.** `Board.Approve` and `Board.Admin` are removed from app-only tokens in code (`TokenValidator.MapRoles`), and `assign-roles.sh` refuses to give them to service principals. The approver can't be the requester (`decided_by <> requested_by`, enforced in SQL). Two approvers can be required per action kind.
- **Conditional Access baseline.** `infra/conditional-access.sh` renders a baseline into `infra/out/<env>/conditional-access/`. With `CA_APPLY=1` it creates the policies in report-only mode: phishing-resistant MFA for the board app, a compliant device for approvers and admins, and a 4-hour sign-in frequency for approvers and admins. You decide when to switch them on.
- **Separation-of-duties check.** The Setup page and `blueboard doctor` show "Access (separation of duties)" as a warning while there are fewer than two enabled human approvers.

## Encryption

| | In transit | At rest |
|---|---|---|
| Browser ↔ web app, browser and agents ↔ API | HTTPS only (`httpsOnly: true`), TLS 1.2 minimum, FTP disabled, HSTS on the web app | n/a |
| API ↔ PostgreSQL | TLS required (`SslMode.Require`) | Azure-managed encryption at rest (service-managed keys) |
| API ↔ Storage | TLS 1.2 minimum, shared keys disabled (identity only) | Azure Storage encryption (service-managed keys) |
| API ↔ Microsoft APIs, feeds, sinks | HTTPS only. Microsoft tokens are sent only to exact Microsoft origins (`MsClient`) | n/a |
| Key Vault (production) | Private endpoint | RBAC mode, soft delete (90 days) and purge protection |

Customer-managed keys (CMK) aren't configured by the templates. If you need CMK for PostgreSQL or Storage, add it to your deployment. See [Shared responsibility](SHARED-RESPONSIBILITY.md).

## Network isolation

- **`mvp` profile:** the API and web app are public endpoints that need an Entra token for every request. PostgreSQL is public with the `AllowAzureServices` firewall rule and Entra-only authentication.
- **`production` profile** (`BB_PROFILE=production`):
  - The Function App has VNet integration, with outbound traffic through a NAT gateway with one static IP.
  - PostgreSQL, Storage (blob, queue and table) and Key Vault are reachable only through **private endpoints**, with public access disabled.
  - The PostgreSQL firewall rule is removed. PostgreSQL runs with zone-redundant HA (same-zone HA in Australia Southeast, which has no availability zones).
- Front Door and WAF aren't deployed by the templates. They're documented as an optional addition in [architecture.md](../architecture.md#production-hardening).

## Logging and audit

- **Append-only `audit_log`.** Security-relevant events are written to the database: action requests, approvals, holds, executions, failures, expiries and policy re-check rejects; hunting queries and entity lookups; claims; principals joining, being disabled or changing profile; broker pause and resume; rate-limit hits; webhook subscriptions; notification failures; and Purview guard results. Ordinary reads and chat posts are kept in their own tables, not in the audit log. HTTP requests are in Application Insights. The runtime database role can only `SELECT` and `INSERT` on it, and triggers refuse `UPDATE`, `DELETE` and `TRUNCATE` for every role, including the owner (`db/migrations/009`).
- **Export to Sentinel.** In the production profile, audit rows are shipped every minute to `BlueboardAudit_CL` (365-day retention). This copy is the tamper-evident record. Nine analytics rule templates are in `infra/sentinel/`.
- **Operational alerts.** `infra/alerts.bicep` alerts on job heartbeat and failures, API 5xx errors, migration failure, failed brokered actions, and PostgreSQL availability, storage and CPU.

## Secure development

The repository's own release process covers:

- **Code scanning and dependencies:** CodeQL code scanning (`.github/workflows/codeql.yml`) and weekly grouped Dependabot updates for NuGet, npm, pip and GitHub Actions.
- **Pinned CI:** GitHub Actions are pinned to full commit SHAs.
- **CI gates:** CI fails on high-severity production npm advisories (`pnpm audit --prod --audit-level high`) and on vulnerable NuGet packages (`scripts/check-nuget-vulns.sh`). .NET builds treat warnings as errors.
- **Every push:** unit and integration test suites, a policy-check, Bicep build and lint, shellcheck, and a local end-to-end demo smoke test.
- **Tagged releases:** an SPDX SBOM, SHA-256 checksums and a Sigstore build provenance attestation for the API and web packages and the compiled ARM template (`.github/workflows/release.yml`). `BB_RELEASE=vX.Y.Z` deploys those signed artefacts after verifying their checksums, so it runs in Azure Cloud Shell without .NET or pnpm.

## Outbound connections and third parties

blueboard has **no sub-processors of its own**. Every outbound connection is either to Microsoft for the security APIs you deploy it for, or to something you switch on and control:

| Category | Default | Examples |
|---|---|---|
| Microsoft security and platform APIs | On | Microsoft Graph, Defender for Endpoint API, Log Analytics query API, Azure Monitor ingestion |
| Public threat intel feeds | **Off** (each one opt-in) | pwn.watch, CISA KEV, FIRST EPSS, NVD, OSV.dev |
| Notification sinks | **Off** until configured | Teams workflow, signed webhook, Graph `sendMail`, ntfy |
| Agent webhooks | **Off** until `WEBHOOK_ALLOWED_HOSTS` and `WEBHOOK_SIGNING_KEY` are set | Hosts you allowlist |
| Model providers | Not part of the board | Reference agents call Claude on Microsoft Foundry (Entra auth) or, if configured, the Anthropic API. These run outside the board and you deploy them |

Each connection is listed with its host and the setting that controls it in [Data flows](DATA-FLOWS.md#outbound-connections).

## Vulnerability disclosure

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/jusso-dev/blueboard/security/advisories/new). Don't open a public issue. You'll get an acknowledgement within five working days. Only the latest release and `main` receive fixes. See [SECURITY.md](../../SECURITY.md).

## Known limitations

These are stated plainly so they can be tracked in your risk register:

- **No automated data retention or purge.** Incidents, messages, actions and `audit_log` rows are kept until you delete them, and `audit_log` can't be deleted by design. Set your retention requirement and plan for it ([Data flows](DATA-FLOWS.md#retention)).
- **No customer-managed keys** in the templates.
- **No WAF or Front Door** in the templates.
- **The production profile hasn't been deployed to a live subscription by the authors.** Run `az deployment group what-if` first. The `mvp` profile has been deployed against a live Defender tenant in read-only, dry-run mode.
- **Brokered write actions haven't all been exercised end to end against a live tenant.** Test each one in a non-production tenant before setting `BROKER_EXECUTE=true`.
- **No independent penetration test has been published.** See [Assurance evidence](PEN-TEST-AND-ASSURANCE-EVIDENCE.md#independent-penetration-test) for a suggested scope.
- **The migration identity owns the schema**, so someone controlling it could drop the audit triggers. The Sentinel copy is the tamper-evident record ([SECURITY.md § Known limitations](../SECURITY.md#known-limitations)).
