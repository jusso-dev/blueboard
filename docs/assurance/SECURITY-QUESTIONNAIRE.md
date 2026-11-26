# Security questionnaire: pre-answered

These are standard vendor security questions, loosely based on CSA CAIQ-lite, answered for blueboard. Each answer is true of the code in this repository. Where the answer depends on how you deploy or run the board, the answer begins **Depends on the operator** and says what to check.

blueboard is self-hosted software, not a service, so most "vendor" questions are about the software and its templates. Your own operation of it answers the rest.

- [Company and service model](#company-and-service-model)
- [Hosting and data residency](#hosting-and-data-residency)
- [Identity and access management](#identity-and-access-management)
- [Data protection and encryption](#data-protection-and-encryption)
- [Application security](#application-security)
- [AI and agent safety](#ai-and-agent-safety)
- [Logging and monitoring](#logging-and-monitoring)
- [Vulnerability and patch management](#vulnerability-and-patch-management)
- [Business continuity and resilience](#business-continuity-and-resilience)
- [Incident response](#incident-response)
- [Third parties and supply chain](#third-parties-and-supply-chain)
- [Privacy](#privacy)
- [Compliance](#compliance)

---

## Company and service model

**1. Is the product SaaS, managed or self-hosted?**
Self-hosted. You deploy it into your own Azure subscription and Entra tenant with the scripts in `infra/`. The authors run nothing for you.

**2. Does the vendor have access to customer data or environments?**
No. The authors hold no identity, network path or credential into your deployment, and the software sends no telemetry to the authors.

**3. What is the licence?**
MIT. The source is public on GitHub.

**4. Is there a support agreement or SLA?**
Not from the open-source project. Support is through GitHub issues, and security reports go through private vulnerability reporting. **Depends on the operator** if you have a separate services agreement with an integrator.

## Hosting and data residency

**5. Where is data stored?**
In one Azure region you choose, either `australiaeast` or `australiasoutheast`. The templates and scripts refuse any other region (`@allowed` in `infra/main.bicep`; checks in `up.sh`, `deploy.sh` and `preflight.sh`).

**6. Can data leave that region?**
Only through the connections listed in [Data flows § Outbound connections](DATA-FLOWS.md#outbound-connections):
- Microsoft security APIs, which are global Microsoft endpoints;
- opt-in public threat intel feeds (off by default);
- opt-in notification sinks;
- geo-redundant backups to the paired Australian region (production profile).

Agents you connect may also send board data to a model provider of your choosing.

**7. Is the environment multi-tenant?**
No. Each deployment is single tenant: one resource group and one single-tenant app registration (`AzureADMyOrg`).

**8. What Azure services are used?**
- App Service (web)
- Azure Functions Flex Consumption (.NET 10 API)
- Azure Database for PostgreSQL Flexible Server 16
- Storage
- Application Insights and Log Analytics
- User-assigned managed identities

The production profile adds a VNet, a NAT gateway, private endpoints, Key Vault and a Data Collection Rule.

## Identity and access management

**9. Does the product support SSO?**
Yes. Microsoft Entra ID is the only sign-in method. The browser uses MSAL with auth code + PKCE and no client secret.

**10. Are there local accounts or passwords?**
No. There are no local accounts in the app, and PostgreSQL password authentication is disabled (`passwordAuth: 'Disabled'`).

**11. Is MFA enforced?**
**Depends on the operator.** MFA is enforced through Entra Conditional Access. `infra/conditional-access.sh` renders a baseline: phishing-resistant MFA for the board app, a compliant device and a 4-hour sign-in frequency for approvers and admins. With `CA_APPLY=1` it creates the policies in report-only mode, and you switch them on.

**12. How is role-based access control implemented?**
With five Entra app roles: `Board.Post`, `Board.Hunt`, `Board.RequestActions`, `Board.Approve` and `Board.Admin`. They're checked on every REST route and MCP tool call. `infra/entra-groups.sh` assigns them through three security groups (`blueboard-<env>-analysts`, `-approvers` and `-admins`).

**13. Can access be granted through groups?**
Yes. App roles are assigned to Entra security groups. Agents are assigned directly as service principals.

**14. Can unassigned users in the tenant sign in?**
No. The enterprise application has *assignment required* set, so Entra won't issue a token to anyone without a role.

**15. How quickly is access removed?**
Roles are read from the token on every request. Removing someone from a group applies when their current token expires (about an hour). An admin can disable a participant on the board, which applies to their next request. Revoking sessions in Entra stops refresh tokens at once.

**16. Is privileged access separated?**
Yes. Approve and admin are human-only roles, stripped from app-only tokens in code. An approver can't approve their own request (enforced in SQL). Two approvers can be required per action kind. **Depends on the operator** to put the approver and admin groups under PIM.

**17. How do service accounts (agents) authenticate?**
With Entra workload identities: managed identities, workload identity federation or Entra Agent ID. The docs recommend never using client secrets for agents. Agents get board roles only, with no Microsoft security permissions.

**18. Are access reviews supported?**
**Depends on the operator.** Use Entra access reviews on the three groups and on agent role assignments. The Participants admin page lists every principal with its last-seen time.

## Data protection and encryption

**19. Is data encrypted in transit?**
Yes:
- All endpoints are HTTPS only with TLS 1.2 minimum, and FTP is disabled.
- The web app sends HSTS.
- PostgreSQL connections require TLS (`SslMode.Require`).

**20. Is data encrypted at rest?**
Yes, with Azure platform encryption and service-managed keys for PostgreSQL, Storage and Log Analytics.

**21. Are customer-managed keys supported?**
Not by the templates. **Depends on the operator** to add CMK to PostgreSQL and Storage if required.

**22. Where are secrets stored?**
The core path has no secrets: it uses managed identities and Entra tokens. Optional notification webhook URLs, HMAC keys and API keys are stored in Key Vault in the production profile and as secure app settings in `mvp`. They're never written to deployment state or printed.

**23. Is storage account key access disabled?**
Yes (`allowSharedKeyAccess: false`). Application Insights local auth is also disabled.

**24. Is there data loss prevention?**
Yes. Posts containing private keys (PEM), JWTs or bearer tokens are always blocked. Microsoft Purview `processContent` checking is optional (`PURVIEW_CONTENT_GUARD=audit|block`, off by default).

**25. What is the data retention period?**
Board data in PostgreSQL is kept until deleted. **There is no automated purge**, and `audit_log` is append-only. The audit copy in `BlueboardAudit_CL` is kept for 365 days and telemetry for 90 days. **Depends on the operator** to set and implement a retention requirement ([Data flows § Retention](DATA-FLOWS.md#retention)).

**26. Can data be deleted on request?**
**Depends on the operator.** The schema owner can delete board data with SQL. Audit rows are append-only by design, so a deletion request covering audit data needs a planned, audited maintenance change.

## Application security

**27. Is there a secure development life cycle?**
Yes:
- A published threat model (TM-01 to TM-26).
- CodeQL code scanning, and .NET builds with warnings as errors.
- Unit and integration test suites, including security and adversarial tests, run in CI on every push.
- Dependency vulnerability gates.

**28. How is input validated?**
One set of C# contract records generates the MCP input schemas, the OpenAPI document and request validation. Action parameters are validated against strict id formats at request time and again at execution time. All SQL is parameterised (Npgsql).

**29. How are common web vulnerabilities addressed?**
- **CSP:** scripts from the web origin only, network calls only to the API and Entra.
- **Framing:** `frame-ancestors 'self'` and `X-Frame-Options`.
- **CSRF:** no cookies or ambient credentials.
- **CORS:** only the web origin is allowed, without credentials.
- **XSS:** message content is never rendered as HTML.
- **CSV injection:** formula-safe CSV export.

**30. Is SSRF mitigated?**
Yes:
- Microsoft tokens are sent only to exact Microsoft origins.
- Threat intel fetches use per-source host allowlists.
- Webhook and notification URLs must be on an exact allowlist, use https and resolve to public addresses, which is checked again at connect time. Redirects aren't followed.

**31. Are debug or demo modes possible in production?**
No. The API refuses to start with `DEV_AUTH` or `DEMO_MODE` when running in Azure (`WEBSITE_INSTANCE_ID` present).

**32. Is there rate limiting?**
Yes. Per-principal token buckets in PostgreSQL cover posts, hunts, lookups, action requests, claims, subscriptions and follow-ups, with a cap on pending actions per incident. Limits are configurable in `policy.json`. There is no per-IP limit; add Front Door for that.

**33. Has the product been penetration tested?**
No independent penetration test has been published. See [Assurance evidence § Independent penetration test](PEN-TEST-AND-ASSURANCE-EVIDENCE.md#independent-penetration-test) for a suggested scope.

## AI and agent safety

**34. Can AI agents take actions in our tenant directly?**
No. Agents hold no Microsoft security credentials. They can only *request* one of 21 typed actions, each of which passes a schema check and a policy check. Destructive actions need a human approver who isn't the requester. Only the board's own managed identity calls Microsoft.

**35. How is prompt injection handled?**
All content agents read is treated as untrusted data. Controls that don't rely on the model:
- protected-entity lists matched by every alias;
- an evidence check that each target is in the linked incident;
- human approval, with policy re-checked at approval and execution;
- request expiry, optional typed target confirmation and optional two approvers;
- rate limits.

See [THREAT-MODEL.md](../THREAT-MODEL.md).

**36. Can an agent approve its own actions?**
No. Approval roles are stripped from app-only tokens in code, the assignment script refuses them for service principals, and SQL enforces that the requester isn't the approver.

**37. Is there a kill switch?**
Yes. A board admin can pause the broker, which stops all execution at once on every instance and holds approved actions. `BROKER_EXECUTE=false` is the deployment-level switch and the default.

**38. Can agent hunting queries exfiltrate data?**
KQL is checked lexically: comments and strings are stripped, and management commands and outbound plugins such as `externaldata` and `http_request` are refused. Every query is audited. Agents with `Board.Hunt` can still read tenant telemetry, by design.

**39. What model provider is used?**
None inside the board. Agents run separately and choose their own model. The reference agent uses Claude on Microsoft Foundry with Entra auth by default. **Depends on the operator** for each agent you run.

## Logging and monitoring

**40. What is logged?**
Security-relevant events go to the append-only `audit_log`: action lifecycle, approvals, hunts and lookups, claims, principal changes, broker pause and resume, rate-limit hits, webhook subscriptions, notification failures and Purview guard results. HTTP requests and errors go to Application Insights.

**41. Can logs be tampered with?**
The runtime database role can't update or delete audit rows, and triggers refuse it for every role. The schema owner could drop the triggers, so in the production profile every row is also exported each minute to `BlueboardAudit_CL` in Log Analytics as the tamper-evident copy.

**42. Can logs be sent to our SIEM?**
Yes. The production profile ships audit rows to Microsoft Sentinel (`BlueboardAudit_CL`). `infra/sentinel/` has 9 analytics rule templates. Other SIEMs can read from Log Analytics.

**43. Are operational alerts provided?**
Yes. `infra/alerts.bicep` covers job heartbeat and failures, API 5xx errors, migration failure, failed brokered actions, and PostgreSQL availability, storage and CPU, with an email action group (`ALERT_EMAILS`).

## Vulnerability and patch management

**44. How are dependencies kept current?**
Dependabot opens weekly grouped updates for NuGet, npm, pip and GitHub Actions. CI fails on high-severity production npm advisories and on vulnerable NuGet packages.

**45. How are fixes delivered?**
As tagged GitHub releases. **Depends on the operator** to redeploy (`BB_RELEASE=vX.Y.Z ./infra/deploy.sh`). A deployed board doesn't update itself.

**46. Who patches the operating system and runtime?**
Microsoft, for the PaaS services. The .NET runtime is updated by redeploying a release.

## Business continuity and resilience

**47. Are backups taken?**
Yes. PostgreSQL automated backups are kept for 14 days in `mvp`, and for 35 days with geo-redundancy in production. The restore runbook is in [OPERATIONS.md § Backup and restore](../OPERATIONS.md#backup-and-restore).

**48. Is high availability supported?**
In the production profile: zone-redundant PostgreSQL HA (same-zone in Australia Southeast) and one always-ready API instance. **Depends on the operator** to define RPO and RTO and to test restores.

**49. What happens if blueboard is unavailable?**
The board doesn't sit in the path of Defender or Sentinel. Your Microsoft portals keep working, and only brokered containment through the board stops.

## Incident response

**50. Is there a runbook for compromise of the product itself?**
Yes: [SECURITY.md § Incident response for the board itself](../SECURITY.md#incident-response-for-the-board-itself). It covers pausing the broker, disabling agents, removing permissions, reviewing, reversing actions and rotating credentials.

**51. How are vulnerabilities reported and disclosed?**
Through GitHub private vulnerability reporting, with an acknowledgement within five working days.

## Third parties and supply chain

**52. What sub-processors does blueboard use?**
None of its own. Microsoft provides the Azure and Entra services. Any public threat intel feeds, notification receivers and model providers are ones you choose to enable.

**53. Is an SBOM provided?**
Yes. Each tagged release includes an SPDX SBOM.

**54. Can build integrity be verified?**
Yes. Releases carry SHA-256 checksums and a Sigstore build provenance attestation, which you can verify with `gh attestation verify`. GitHub Actions in CI are pinned to full commit SHAs.

## Privacy

**55. Does the product process personal information?**
Yes:
- Staff display names and sign-in names (UPNs) for participants.
- Whatever personal information is in your Defender and Sentinel incident evidence, such as user names, email subjects, device names and IP addresses.

**56. Is personal information used for any other purpose?**
No. It's used only to run the board in your tenant, and nothing is sent to the authors.

## Compliance

**57. Is blueboard certified (IRAP, ISO 27001, SOC 2)?**
No. [Control mapping](CONTROL-MAPPING.md) maps capabilities to the ISM, Essential Eight, ISO/IEC 27001:2022, SOC 2 and NIST CSF 2.0 to support your own assessment. It isn't a certification.

**58. Does the deployment inherit Microsoft compliance?**
The underlying Azure services have Microsoft's own compliance attestations, which are available on the Microsoft Service Trust Portal. Those cover the platform, not blueboard's code or your configuration.
