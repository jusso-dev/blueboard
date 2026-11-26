# Shared responsibility model

blueboard runs in **your** Azure subscription and Entra tenant. There is no vendor-operated part, so responsibilities are split three ways:

- **blueboard (the code and templates):** what the software and its deployment scripts do when used as documented.
- **Microsoft:** the Azure platform and Entra ID services blueboard is built on, under Microsoft's own shared responsibility model for PaaS.
- **You (the operator):** everything about how the board is configured, who can use it, and how it's run day to day.

"Provides" means it's on by default or done by the scripts. "Supports" means it's available but you have to turn it on.

## Responsibility matrix

| Area | blueboard provides | Microsoft provides | You must |
|---|---|---|---|
| **Physical, host and platform security** | n/a | Data centres, hosts, hypervisor, PaaS runtime patching (App Service, Functions, PostgreSQL Flexible Server, Storage, Key Vault) | Choose the subscription and region (`australiaeast` or `australiasoutheast`) |
| **Identity provider** | Single-tenant app registration, five app roles, `Board.Access` scope, *assignment required* (`infra/entra-app.sh`) | Entra ID authentication, token issuance, MFA, Conditional Access, PIM, access reviews | Own the tenant, the app registration and the enterprise application |
| **Groups and membership** | `infra/entra-groups.sh` creates or adopts `blueboard-<env>-analysts`, `-approvers` and `-admins` and assigns their roles | Group management and dynamic membership | Decide who goes in each group, keep approvers and analysts separate, and keep at least two enabled human approvers (the Setup page warns when there are fewer) |
| **Conditional Access** | `infra/conditional-access.sh` renders a baseline: phishing-resistant MFA for the board app, a compliant device and a 4-hour sign-in frequency for approvers and admins. `CA_APPLY=1` creates the policies in report-only mode | Conditional Access engine and sign-in logs | Review the report-only results, exclude your break-glass accounts, switch the policies **on**, and keep them on |
| **Privileged access (PIM)** | Roles are read from the token on every request, so PIM-activated group membership takes effect at the next sign-in | Privileged Identity Management for groups | Put `blueboard-<env>-approvers` and `-admins` under PIM for Groups with approval and time limits (recommended) |
| **Access reviews** | Admin → Participants lists every principal with last-seen time. Disabling a participant blocks it at once | Entra access reviews | Review group membership and agent role assignments at least quarterly |
| **Agent identity lifecycle** | Agents use workload identities with no Microsoft security permissions. Approve and Admin are stripped from app-only tokens. Disabling a participant releases its claims and stops its webhooks and follow-ups | Managed identities, workload identity federation, Entra Agent ID | Create, own and retire each agent identity. Use managed identities or federation, never client secrets. Remove role assignments when an agent is retired |
| **Board identity permissions** | `grant-permissions.sh` grants read permissions only unless you list `ACTIONS=`. The Setup page shows what the token actually carries | Graph and Defender permission enforcement | Have a Privileged Role Administrator review and grant only the write permissions for actions you will broker |
| **Action policy** | Strict parser, `policy-check`, alias-aware protected lists, evidence check, simulator, policy re-check at approval and execution | n/a | Write and review `policy.json` (break-glass accounts, domain controllers, your own domains, critical apps), store it privately, and re-review it when your estate changes |
| **Turning on execution** | `BROKER_EXECUTE=false` by default. `deploy.sh` refuses `true` with the example policy and asks for confirmation | n/a | Run in dry run long enough to trust the requests, test every action in a non-production tenant, then decide to set `BROKER_EXECUTE=true` |
| **Approving actions** | Shows the approver the exact parameters, policy notes and evidence grounding. Enforces separation of duties, expiry, optional typed confirmation and two approvers | n/a | Train approvers and keep approval queues small. Approvers are accountable for what they approve |
| **Network** | `production` profile: VNet integration, NAT gateway, private endpoints for PostgreSQL, Storage and Key Vault, public access disabled on them | Azure networking, private link, DDoS Network Protection (basic) | Choose the profile. Add Front Door and WAF, a custom domain and IP restrictions if your policy requires them |
| **Encryption** | HTTPS only, TLS 1.2 minimum, TLS required to PostgreSQL, Key Vault RBAC with purge protection (production) | Encryption at rest with service-managed keys for PostgreSQL, Storage and Log Analytics | Add customer-managed keys if your policy requires them (not in the templates) |
| **Secrets** | No secret in the core path. Optional secrets go in Key Vault in production and are never written to deployment state | Key Vault | Rotate any notification webhook URLs, HMAC keys and API keys you configure |
| **Patching blueboard** | Dependabot, CodeQL, vulnerability gates in CI, signed releases with SBOM and provenance | Runtime patching for the PaaS services | **Redeploy new releases** (`BB_RELEASE=vX.Y.Z ./infra/deploy.sh` or from source). A deployed board doesn't update itself |
| **Logging and monitoring** | Append-only `audit_log`, export to `BlueboardAudit_CL` (production), 9 Sentinel analytics rule templates, operational alerts (`infra/alerts.bicep`) | Log Analytics, Sentinel, Azure Monitor alerting | Set `ALERT_EMAILS`, deploy the Sentinel rules, route alerts to your SOC and respond to them. Set Log Analytics retention to meet your audit requirement |
| **Backup and recovery** | PostgreSQL automated backups (14 days in mvp, 35 days geo-redundant in production), restore runbook in [OPERATIONS.md](../OPERATIONS.md#backup-and-restore) | Backup storage and point-in-time restore | **Test a restore** at least once a year. Decide your RPO and RTO |
| **Data retention and deletion** | Optional daily retention job (`RETENTION_DAYS`, off by default) that removes resolved incidents, old threads and finished actions, records each purge in the audit log, and keeps `audit_log` append-only | Storage, backup expiry, and Log Analytics table retention | Choose the retention period and set `RETENTION_DAYS`, preview it with `blueboard retention`, and set Log Analytics and backup retention to match |
| **Incident response for the board** | Broker pause switch, participant disable, runbook in [SECURITY.md](../SECURITY.md#incident-response-for-the-board-itself) | Entra sign-in logs, managed identity sign-in logs, Graph activity logs | Include blueboard in your IR plan and practise the pause-and-revoke runbook |
| **Agents and model providers** | Reference agents and templates. Agents can only request actions, not run them | Microsoft Foundry (if you use it) | Choose where agents run and which model provider they use, and assess that provider's data handling |
| **Compliance** | [Control mapping](CONTROL-MAPPING.md) and evidence you can collect yourself | Microsoft compliance offerings (Service Trust Portal) | Carry out your own assessment. blueboard holds no certification or attestation |

## Minimum operator checklist

Before go-live, the operator should be able to tick every line:

- [ ] Board deployed with `BB_PROFILE=production`, or the `mvp` profile accepted as a documented risk.
- [ ] Analysts, approvers and admins are in separate Entra groups (`infra/entra-groups.sh`), with at least two enabled human approvers.
- [ ] Conditional Access baseline reviewed in report-only mode, then turned on, with break-glass accounts excluded.
- [ ] Approver and admin groups under PIM (recommended).
- [ ] `policy.json` reviewed by a second person and passing `policy-check`.
- [ ] Write permissions granted only for the actions in use.
- [ ] `ALERT_EMAILS` set and the Sentinel analytics rules deployed.
- [ ] A restore tested, with the RPO and RTO recorded.
- [ ] A retention requirement recorded for board data.
- [ ] Dry run completed and every action tested in a non-production tenant before `BROKER_EXECUTE=true`.
- [ ] A named owner for redeploying security releases.
