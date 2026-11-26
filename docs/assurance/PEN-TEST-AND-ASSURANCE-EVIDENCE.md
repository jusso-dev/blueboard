# Assurance evidence and penetration testing

This page lists the evidence you can collect yourself to show a deployment of blueboard is configured as claimed. It also gives a suggested scope for an independent penetration test.

> **No independent penetration test of blueboard has been published.** The evidence below comes from the software's own checks and tests. An independent test of your own deployment is recommended before you set `BROKER_EXECUTE=true` in production.

- [Evidence you can collect](#evidence-you-can-collect)
- [Verifying a release](#verifying-a-release)
- [Running the test suites](#running-the-test-suites)
- [Configuration evidence in Azure and Entra](#configuration-evidence-in-azure-and-entra)
- [Independent penetration test](#independent-penetration-test)

---

## Evidence you can collect

| Evidence | How to collect it | What it shows |
|---|---|---|
| **Setup checklist** | Open `/setup` as a `Board.Admin` and save the page, or call `GET /api/setup?fresh=true` with an admin token and keep the JSON | Database and migrations, Entra auth, incident ingest, the read and write permissions the board's token actually carries, broker mode, the policy in force, agents, notifications, audit export, and access separation of duties (fewer than two enabled human approvers is a warning). No check writes to your tenant |
| **`blueboard doctor`** | On the Function App's own environment: `dotnet run --project api/Blueboard.Tools -- doctor --json`. `infra/deploy.sh` and `infra/up.sh` print the same checks after each deploy | The same checklist as text or JSON. Exits 1 if any check failed, so it works as a pipeline gate |
| **Policy check** | `dotnet run --project api/Blueboard.Tools -- policy-check policy.json`, or the `blueboard-tools-<tag>-<rid>.tar.gz` tool shipped with releases | Each action kind's mode (disabled, human, auto), typed-confirmation and two-approver settings, expiry, protected list counts, rate limits and warnings |
| **Policy simulator** | `/policy` in the board, or `POST /api/policy/simulate` | What the policy would decide for a given target, before turning anything on |
| **Dry-run report** | `/reports` (admin), exported to CSV | What would have run during dry run, with timings, for the go-live decision |
| **Audit trail** | `BlueboardAudit_CL` in Log Analytics (production profile), or `select * from audit_log` as a database reader | Who requested, approved and ran each action. Policy rejects, rate-limit hits, principal changes and broker pauses |
| **Sentinel analytics rules** | The templates in `infra/sentinel/`, deployed to your workspace | Detection coverage for misuse of the board: approval bursts, protected-target rejects, a new agent, board identity misuse, and others |
| **Threat model** | [THREAT-MODEL.md](../THREAT-MODEL.md) | Threats TM-01 to TM-26 with their mitigations and residual risk |
| **ISM statement of applicability** | [ISM-SOA.md](ISM-SOA.md) | Each ISM control's disposition, implementation, evidence, consumer responsibility and gap |

## Verifying a release

Each tagged release (`.github/workflows/release.yml`) publishes:

- the API and web packages;
- the compiled ARM template;
- an SPDX SBOM;
- a SHA-256 checksum file;
- a Sigstore build provenance attestation.

```sh
tag=vX.Y.Z
gh release download "$tag" --repo jusso-dev/blueboard --dir "release-$tag"
cd "release-$tag"

# Checksums
sha256sum -c "blueboard-$tag.sha256"          # macOS: shasum -a 256 -c

# Build provenance: built by this repository's release workflow from the tagged commit
gh attestation verify "blueboard-api-$tag.zip" --repo jusso-dev/blueboard
gh attestation verify "blueboard-web-$tag.zip" --repo jusso-dev/blueboard
gh attestation verify "blueboard-main-$tag.json" --repo jusso-dev/blueboard
gh attestation verify "blueboard-tools-$tag-linux-x64.tar.gz" --repo jusso-dev/blueboard   # releases after v1.0.0

# Software bill of materials
jq '.packages | length' "blueboard-$tag.spdx.json"
```

`BB_RELEASE=vX.Y.Z ./infra/up.sh` checks the checksums on every deploy, and runs `gh attestation verify` as well when `gh` is installed. See [DEPLOYMENT.md § Deploy a release from Azure Cloud Shell](../DEPLOYMENT.md#deploy-a-release-from-azure-cloud-shell).

Keep the SBOM with your release records and scan it with your own tooling (for example Microsoft Defender for Cloud, Dependency-Track or Grype).

## Running the test suites

CI runs every suite on each push to GitHub-hosted runners. To reproduce the results yourself from a checkout of the release tag:

```sh
# Unit tests: API (including SecurityTests and AdversarialAndIntegrationsTests) and agent SDK
dotnet test --solution api/Blueboard.slnx -c Release
dotnet test --project agents/Blueboard.Agent.Sdk.Tests -c Release

# Integration tests against PostgreSQL 16 (run as the restricted runtime role)
BLUEBOARD_TEST_DATABASE_URL=postgres://postgres:<password>@127.0.0.1:5432/postgres \
  dotnet test --solution api/Blueboard.slnx -c Release

# Web: tests, types and the production dependency audit
cd web && pnpm install --frozen-lockfile && pnpm audit --prod --audit-level high && pnpm typecheck && pnpm test

# Dependency vulnerability gate for NuGet
./scripts/check-nuget-vulns.sh
```

| Suite | Examples of what it covers |
|---|---|
| `api/Blueboard.Api.Tests/SecurityTests.cs` | The token guard refuses look-alike origins and dot-segment paths. Agents never hold approve or admin. Delegated tokens must carry the board scope and come from the board web app. Platform principal headers are never trusted. CSV formula injection is neutralised |
| `api/Blueboard.Api.Tests/AdversarialAndIntegrationsTests.cs` | Policy loads in memory with no temp file. Protected indicators cover subdomains. Protected apps can't be disabled. Held actions are blocked when the policy tightens. The KQL guard blocks comment bypasses and outbound plugins. The outbound guard blocks IPv6 transition and special ranges. BiDi characters are stripped from notifications. The secret-leak guard works. Purview content guard |
| `api/Blueboard.Api.Tests/OpsTests.cs` | Setup checks; `Microsoft_checks_never_write` fails the build if a check sends a write |
| `api/Blueboard.Api.Tests/WebhookGuardTests.cs`, `PolicyTests.cs`, `PolicyFileTests.cs` | Webhook SSRF guard, policy evaluation and alias matching, strict policy parsing |
| `api/Blueboard.Api.IntegrationTests/ApprovalTests.cs`, `RuntimeRoleTests.cs`, `LimitTests.cs` | Separation of duties and two-approver flows in SQL. The append-only audit log and least-privilege runtime role. Rate limits |
| `web/src/__tests__` | Markdown rendering safety, auth, live updates, actions |

## Configuration evidence in Azure and Entra

Commands an assessor can run read-only against your deployment (replace `<rg>`, `<env>` and the resource names):

```sh
# Region and resources
az resource list -g <rg> --query "[].{name:name, type:type, location:location}" -o table

# HTTPS only, TLS 1.2, FTP and basic-auth publishing off
az functionapp show -g <rg> -n <api> --query "{httpsOnly:httpsOnly, tls:siteConfig.minTlsVersion, ftps:siteConfig.ftpsState}"
az resource show -g <rg> -n scm --namespace Microsoft.Web --parent sites/<api> \
  --resource-type basicPublishingCredentialsPolicies --query properties.allow

# PostgreSQL: Entra only, no public access (production), backups
az postgres flexible-server show -g <rg> -n <pg> \
  --query "{auth:authConfig, public:network.publicNetworkAccess, backup:backup, ha:highAvailability.mode}"

# Storage: no shared keys, TLS 1.2
az storage account show -g <rg> -n <storage> --query "{sharedKey:allowSharedKeyAccess, tls:minimumTlsVersion, public:publicNetworkAccess}"

# Entra: assignment required, and who holds which role
az ad sp show --id <board-sp-id> --query appRoleAssignmentRequired
az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<board-sp-id>/appRoleAssignedTo" \
  --query "value[].{who:principalDisplayName, type:principalType, role:appRoleId}" -o table

# Microsoft permissions held by the board identity
az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<api-mi-principal-id>/appRoleAssignments" \
  --query "value[].{resource:resourceDisplayName, role:appRoleId}" -o table
```

For Conditional Access, keep the files `infra/conditional-access.sh` rendered into `infra/out/<env>/conditional-access/`, and an export of the live policies from the Entra admin centre showing their state (report-only or on).

## Independent penetration test

**Suggested scope** for a test of a deployed board. Use a non-production tenant, with `BROKER_EXECUTE=true` and only test-safe actions granted.

1. **Authentication and authorisation**
   - Token validation: wrong tenant, audience, scope or client, expired tokens, unsigned tokens.
   - Role checks on every REST route and MCP tool.
   - An agent token trying approve and admin operations.
   - Delegated tokens from other client apps.
   - Forged identity headers.
2. **Approval integrity**
   - Self-approval.
   - Getting round two-approver and typed-confirmation rules.
   - Race conditions on approve and run (exactly-once execution).
   - Expired and held actions.
   - Changing the policy between request and execution.
3. **Policy bypass**
   - Protected users, devices, apps and indicators named by an alias: object id, UPN, MDE id, DNS name, subdomain, or a different case.
   - Targets not in the incident's evidence.
   - Parameter injection into Graph and Defender paths.
4. **Agent and prompt-injection paths**
   - Crafted incident titles, email subjects and command lines flowing into agent prompts.
   - KQL guard bypasses: comments, strings, outbound plugins, management commands.
   - Secret-leak guard evasion.
5. **SSRF and egress**
   - Agent webhook subscriptions and notification URLs: IP literals, DNS rebinding, IPv6 transition ranges, redirects, metadata endpoints.
   - Threat intel fetcher redirects.
6. **Web client**
   - Stored XSS through messages and markdown.
   - CSP effectiveness and clickjacking.
   - CSV formula injection in exports.
   - Token handling in the browser.
7. **Infrastructure (production profile)**
   - Public reachability of PostgreSQL, Storage and Key Vault.
   - Function App CORS.
   - Basic-auth publishing.
   - Managed identity token misuse.
   - Least privilege of the runtime database role and the append-only audit log.
8. **Denial of service by a principal**
   - Rate limits per principal.
   - The pending-action cap.
   - Behaviour at the Flex Consumption instance cap.

**Out of scope:** the Microsoft services themselves (Entra, Defender, Graph), which are covered by Microsoft's own testing and rules of engagement. Follow the [Microsoft Cloud penetration testing rules of engagement](https://www.microsoft.com/msrc/pentest-rules-of-engagement) when testing in Azure.

Report findings to the project through [private vulnerability reporting](https://github.com/jusso-dev/blueboard/security/advisories/new).
