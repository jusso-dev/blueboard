# blueboard Developer Guide

This guide explains how to build, run, test and safely extend **blueboard**. Every server-side security invariant is backed by automated xUnit v3 tests; read the security constraints in sections 5–7 before modifying `Actions/`, `Auth/`, `Graph/` or `Webhooks/`.

## Document control

| Item | Value |
|---|---|
| Document | blueboard Developer Guide |
| Version | 2.1 |
| Date | 25-11-2026 |
| Status | Published |
| Owner | blueboard engineering team |
| Audience | C#/.NET engineers, TypeScript/React engineers, AI agent builders, detection engineers |
| Related | Deployment Guide; Administrator SOPs; Security Controls; Solution Design Document; Walkthrough Guides |

## Contents

1. [Repository layout](#1-repository-layout)
2. [Local development environment](#2-local-development-environment)
3. [Running tests and static checks](#3-running-tests-and-static-checks)
4. [Single-schema contract workflow (`Blueboard.Contracts`)](#4-single-schema-contract-workflow-blueboardcontracts)
5. [Adding a new Defender or Sentinel action safely](#5-adding-a-new-defender-or-sentinel-action-safely)
6. [Adding a new MCP tool and Agent SDK method](#6-adding-a-new-mcp-tool-and-agent-sdk-method)
7. [Database migrations and transactional invariants](#7-database-migrations-and-transactional-invariants)
8. [Playbooks, KQL templates and incident fixtures](#8-playbooks-kql-templates-and-incident-fixtures)
9. [Building the banner, architecture diagram, docs site and PDF/Word suite](#9-building-the-banner-architecture-diagram-docs-site-and-pdfword-suite)
10. [Release and pull-request checklist](#10-release-and-pull-request-checklist)

## 1. Repository layout

| Path | Responsibility |
|---|---|
| `api/Blueboard.Contracts/` | Shared C# request/response records, webhook signature helper (`WebhookSignature`), and tool metadata — single source of truth for MCP schemas, OpenAPI 3.1 (`/api/openapi.json`) and validation |
| `api/Blueboard.Api/` | C# .NET 10 isolated Azure Functions app: `Actions/` (catalogue, policy, broker), `Auth/` (Entra JWT validator, principal), `Board/` (feed, claims, summaries, playbooks, search, reporting, `PurviewContentGuard`), `Data/` (Npgsql, migrations, audit, rate limiter), `Graph/` (`MsClient`, ingest, entity extraction, enrichment, Purview alerts & labels), `Http/` (REST endpoints, OpenAPI), `Intel/` (TI fetcher, sources, KQL/STIX builders), `Jobs/` (timer triggers), `Mcp/` (34 MCP tools), `Ops/` (setup/doctor checks, notifier, permissions), `Webhooks/` (`OutboundGuard`, delivery, follow-ups) |
| `api/Blueboard.Api.Tests/` | xUnit v3 unit & PostgreSQL integration tests (policy, alias matching, parameter validation, token guard, permissions sync, Defender/Sentinel enrichment, playbooks, reporting, webhooks) |
| `api/Blueboard.Tools/` | Offline & operational CLI: `migrate`, `seed-dev`, `policy-check`, `playbooks`, `doctor` |
| `agents/Blueboard.Agent.Sdk/` | Typed .NET 10 MCP client covering all 34 tools (including `lookup_purview_context`), cursor/claim/lease loop (`AgentLoop`), `WorkItem` helpers, and webhook HMAC verifier |
| `agents/Blueboard.Agent.Sdk.Tests/` | xUnit v3 tests for SDK loop, claim leasing and helpers |
| `agents/Blueboard.EnrichmentAgent/` | Reference Claude enrichment agent (Microsoft Foundry or Anthropic API + `AGENT_MODE=scripted` for local demo) |
| `agents/Blueboard.AgentTemplate/` | Minimal copy-paste C# starter agent |
| `dev/mock-msapi/` | Local mock Graph / Defender for Endpoint / Log Analytics / Sentinel STIX server for demo & offline testing |
| `web/` | React 19 + Vite + Tailwind v4 + MSAL frontend, plus `web/host/` (.NET 10 static host with CSP/HSTS) |
| `db/migrations/` | Strictly additive SQL migrations bundled into `Blueboard.Api` and applied on start-up |
| `playbooks/` | 10 bundled Markdown response playbooks with YAML frontmatter |
| `templates/` | Starter policies, Python/TypeScript MCP agents, specialist personas, KQL library, Sentinel Logic App, incident fixtures |
| `skills/` | Reusable agent skills (`blueboard/SKILL.md` for SOC MCP participation, `azure-architecture-diagram/SKILL.md` for official-icon Azure diagrams, `publish-docs/SKILL.md` for PDF/Word docs publishing) |
| `infra/` | `main.bicep`, `up.sh`, `deploy.sh`, `entra-app.sh`, `grant-permissions.sh`, `assign-roles.sh`, `preflight.sh`, `teardown.sh`, `sentinel/*.json` |
| `docs/` & `tools/docs/` | Markdown guides, admin/security/design docs, print styles, and Pandoc + WeasyPrint PDF/DOCX publishing scripts |

## 2. Local development environment

### 2.1 Prerequisites

- `.NET 10 SDK`
- Azure Functions Core Tools v4 (`func`)
- Docker (for PostgreSQL 16 + Azurite)
- `Node 22` + `pnpm` (if working on `web/`)
- `pandoc`, `weasyprint`, `python3` (if rebuilding PDF/Word docs)

### 2.2 Fastest demo (Docker only)

```sh
./scripts/demo.sh up
# Open http://localhost:3417/dev-login
```

Starts PostgreSQL, Azurite, `mock-msapi`, `Blueboard.Api`, the web host and a scripted enrichment agent with three sample incidents and dry-run approvals.

### 2.3 Full local dev stack (edit-compile-debug)

```sh
./scripts/dev-db.sh up                                  # Postgres :55432 + Azurite :20000-20002
cp api/Blueboard.Api/local.settings.example.json api/Blueboard.Api/local.settings.json
export DATABASE_URL=postgres://postgres:devpass@127.0.0.1:55432/blueboard
export DEV_AUTH=true

dotnet run --project api/Blueboard.Tools -- migrate
dotnet run --project api/Blueboard.Tools -- seed-dev --sample

(cd api/Blueboard.Api && func start --port 7351)        # REST + MCP on :7351
(cd web && pnpm install && pnpm dev)                    # Web on :5173/dev-login
```

To exercise Defender/Sentinel API calls locally without a live tenant, run `dev/mock-msapi` and set `DEMO_MODE=true` alongside `DEV_AUTH=true`. Both flags are hard-refused whenever `WEBSITE_INSTANCE_ID` is present (Azure).

## 3. Running tests and static checks

```sh
# 1. API unit tests (.NET 10 requires --solution for .slnx)
dotnet test --solution api/Blueboard.slnx

# 2. API + PostgreSQL integration tests (requires running local Postgres)
BLUEBOARD_TEST_DATABASE_URL=postgres://postgres:devpass@127.0.0.1:55432/blueboard_test \
  dotnet test --solution api/Blueboard.slnx

# 3. Agent SDK tests & builds
dotnet test --project agents/Blueboard.Agent.Sdk.Tests/Blueboard.Agent.Sdk.Tests.csproj
dotnet build agents/Blueboard.EnrichmentAgent
dotnet build agents/Blueboard.AgentTemplate
dotnet build dev/mock-msapi

# 4. Offline playbook & starter policy validation
dotnet run --project api/Blueboard.Tools -- playbooks
for p in policy.example.json templates/policies/*.json; do
  dotnet run --project api/Blueboard.Tools -- policy-check "$p"
done

# 5. Infrastructure & script lint
az bicep build --file infra/main.bicep
shellcheck -x -P infra infra/*.sh
shellcheck -x tools/docs/*.sh

# 6. Web frontend (when web/ dependencies are installed)
(cd web && pnpm typecheck && pnpm test && pnpm build)
```

Treat compiler warnings as errors (`TreatWarningsAsErrors` is enabled in the C# projects).

## 4. Single-schema contract workflow (`Blueboard.Contracts`)

Request inputs are declared **once** as C# records in `api/Blueboard.Contracts/Requests.cs` and tool descriptors in `api/Blueboard.Contracts/Tools.cs`:

- `Mcp/McpSchemas.cs` generates MCP JSON `inputSchema` directly from those records.
- `Http/OpenApi.cs` generates `/api/openapi.json` (OpenAPI 3.1) from the same contracts and includes both `BoardApi` and `OpsApi`.
- `agents/Blueboard.Agent.Sdk` compiles directly against `Blueboard.Contracts`.

Whenever you add or rename a request field, update the contract record once and every transport (REST, OpenAPI, MCP, SDK) stays automatically in sync.

## 5. Adding a new Defender or Sentinel action safely

Adding a brokered action touches **six** coordinated files — an xUnit test fails the build if `Catalog.cs`, `Permissions.cs` and `infra/grant-permissions.sh` drift out of sync:

1. **`api/Blueboard.Api/Actions/Catalog.cs`**:
   - Add the `ActionSpec` with `Kind`, `Stage`, `Destructive` (default `true` for anything that alters tenant state), `Validate` (strict regex / enum / range validation on every parameter), `Targets` (so `PolicyEngine` checks `protected_*` and incident evidence), and `ExecuteAsync` (using `MsClient` with relative paths — never bypass `MsClient.BuildUri`!).
2. **`api/Blueboard.Api/Ops/Permissions.cs`**:
   - Map the action kind to its exact Microsoft Graph / MDE application permission (or Azure RBAC role) so `/setup` and `blueboard doctor` verify it.
3. **`infra/grant-permissions.sh`**:
   - Add the exact same mapping to `perm_for()` and `ALL_ACTIONS`. Keep POSIX/bash 3.2 compatibility (macOS ships bash 3.2; do not use associative arrays).
4. **`api/Blueboard.Api/Board/Reporting.cs`**:
   - Include the action in containment/stage reporting sets if applicable.
5. **`dev/mock-msapi/Program.cs`**:
   - Add a realistic mock route so the demo and local testing can exercise the action end to end.
6. **Tests & docs**:
   - Add parameter validation, policy protection, and alias-resolution tests in `api/Blueboard.Api.Tests/` (see `DefenderSentinelTests.cs` and `PolicyTests.cs`).
   - Update `docs/guides/06-containment-and-approvals.md` and `docs/security/01-security.md`.

**Security non-negotiables for new actions**:
- Never pass unvalidated strings into URL paths (reject `/`, `\`, `?`, `#`, `..`).
- Never send Microsoft tokens outside `MsOrigins` (`graph.microsoft.com`, `api.security.microsoft.com`, `api.ti.sentinel.azure.com`, `api.loganalytics.io`).
- Never allow destructive actions to auto-approve.

## 6. Adding a new MCP tool and Agent SDK method

1. Define the input record in `api/Blueboard.Contracts/Requests.cs` and register tool metadata in `api/Blueboard.Contracts/Tools.cs`.
2. Add the `[Function]` + `[McpToolTrigger]` method in `api/Blueboard.Api/Mcp/BoardTools.cs`:
   - First line MUST authenticate and enforce roles (`AuthAsync` + `Require(...)`).
   - Apply rate limiting (`RateLimiter`) before calling external Microsoft APIs.
   - Write an `audit_log` row for reads against Microsoft security APIs or state mutations.
3. Add a typed wrapper method in `agents/Blueboard.Agent.Sdk/BoardConnection.cs`.
4. Update `skills/blueboard/SKILL.md` and starter templates if agents should discover the tool.
5. Add unit/integration test coverage in `api/Blueboard.Api.Tests/` and `agents/Blueboard.Agent.Sdk.Tests/`.

## 7. Database migrations and transactional invariants

- **Additive only**: place new files in `db/migrations/NNN_description.sql`. Never drop or rename columns/tables used by the previous release so rollbacks stay safe.
- **Advisory locks**: every background timer (`ingest`, `recovery`, `notify`, `webhooks`, `export-audit`, `ti-*`) acquires a dedicated PostgreSQL advisory lock so multi-instance scale-out never duplicates work.
- **Exactly-once execution**: `Broker.ExecuteAsync` transitions `approved -> running` inside a single conditional SQL `UPDATE` that simultaneously verifies `broker_paused` is false. The recovery sweep marks actions stuck in `running > 10 min` as `failed` (**outcome unknown**) and **never** re-executes them.
- **No self-approval**: enforced both in `Broker.DecideAsync` and in SQL (`decided_by <> requested_by`).
- **Parameterised SQL only**: every Npgsql command uses bound parameters (`@p`), never string interpolation.

## 8. Playbooks, KQL templates and incident fixtures

- **Playbooks (`playbooks/*.md`)**: validated by `blueboard playbooks` and `PlaybookTests.cs`. Always set explicit `priority` (lower integer wins) and avoid ambiguous broad matches.
- **KQL templates (`templates/kql/*.kql`)**: keep queries scoped with time filters, explicit `project` columns and `take` / `summarize` so Defender and Sentinel quotas are respected.
- **Incident fixtures (`templates/incidents/*.json`)**: use strictly RFC 2606 / RFC 5737 fictitious domains (`contoso.com`, `*.example`) and documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Never commit real customer identifiers or secrets.

## 9. Building the banner, architecture diagram, docs site and PDF/Word suite

The repository includes turnkey scripts and reusable agent skills (`skills/azure-architecture-diagram/SKILL.md` and `skills/publish-docs/SKILL.md`) for reproducing the README hero banner (`scripts/build-banner.py`), the official Microsoft Azure icon architecture diagram (`scripts/build-architecture-diagram.sh`), the full PDF/Word documentation suite (`pandoc`, `weasyprint`, `rsvg-convert` and Python 3 stdlib), and the Docusaurus 3.10 site (`website/`):

```sh
# One-command full rebuild + verification (diagram + all 19 PDFs & 19 DOCXs)
./tools/docs/publish-all.sh

# Reproduce only the official-icon Azure architecture diagram (.drawio, .svg, .png)
./scripts/build-architecture-diagram.sh

# Rebuild only PDF/Word deliverables (offline) and verify links/images
./tools/docs/publish-all.sh --skip-diagram

# Verify existing diagram, PDFs, DOCXs and relative Markdown links without rebuilding
./tools/docs/publish-all.sh --check-only

# Build the Docusaurus static site locally
(cd website && npm ci && npm run typecheck && npm run build)
```

Build outputs are written directly to `docs/architecture/azure-architecture.{drawio,svg,png}` and `docs/Blueboard-*.{pdf,docx}` (plus static HTML output in `website/build/`). Temporary build artefacts (`reference.docx`, intermediate HTML) are cleaned up automatically.

## 10. Release and pull-request checklist

- [ ] `dotnet test --project api/Blueboard.Api.Tests -c Release` and `dotnet test --project agents/Blueboard.Agent.Sdk.Tests -c Release` pass with 0 warnings and 0 failures (plus DB integration tests when Postgres is available).
- [ ] `dotnet run --project api/Blueboard.Tools -- playbooks` and `policy-check` pass on all bundled playbooks and starter policies.
- [ ] `az bicep build --file infra/main.bicep`, `shellcheck -x -e SC1091 -s bash infra/*.sh`, `(cd web && pnpm typecheck && pnpm test && pnpm build)` and `(cd website && npm run typecheck && npm run build)` pass.
- [ ] Any new action is synchronised across `Catalog.cs`, `Permissions.cs`, `grant-permissions.sh`, `Reporting.cs`, `mock-msapi` and tests.
- [ ] Any security-relevant change is reflected in `docs/SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/security/01-security.md` and `docs/design/01-solution-design.md`, and `./tools/docs/build-all.sh` succeeds cleanly.
