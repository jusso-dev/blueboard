# Deploying blueboard to Azure

This guide takes a new Azure subscription to a running board in **Australia East** (or Australia Southeast): a React front end on an **App Service Web App**, a C# back end on **Azure Functions (Flex Consumption, .NET 10)**, and **PostgreSQL**. Every resource goes in the one Australian region you choose. The scripts in [`infra/`](../infra) do the work: each one is idempotent, checks your sign-in before it changes anything, and prints what it changes.

![Azure architecture](architecture/azure-architecture.png)

- [Roles required](#roles-required)
- [Before you start](#before-you-start)
- [Deploy](#deploy)
- [Connect agents](#connect-agents)
- [What each script does](#what-each-script-does)
- [Updating, rolling back and tearing down](#updating-rolling-back-and-tearing-down)
- [Local development](#local-development)
- [Troubleshooting](#troubleshooting)

---

## Roles required

Deployment touches two separate permission systems: **Azure RBAC** (the subscription and resource group) and **Microsoft Entra roles** (the tenant). Split them across people where you can. The person who deploys infrastructure doesn't need to be the person who grants Microsoft security permissions.

### Azure RBAC

| Task | Script | Minimum role | Scope |
|---|---|---|---|
| Register resource providers (first deployment in a subscription) | `deploy.sh` | **Contributor** (includes `*/register/action`) | Subscription |
| Create the resource group | `deploy.sh` | **Contributor** | Subscription, *or* have the group pre-created and skip this |
| Deploy resources (Web App + plan, Function App + Flex plan, storage, PostgreSQL, Application Insights, Log Analytics, managed identity) | `deploy.sh` | **Contributor** | Resource group |
| Create role assignments: storage data roles and *Monitoring Metrics Publisher* for the API identity (production also *Key Vault Secrets User*; with `ASSIGN_SENTINEL_CONTRIBUTOR=true`, *Microsoft Sentinel Contributor* on the Sentinel workspace, which needs the role there too) | `deploy.sh` (Bicep) | **Role Based Access Control Administrator** (or User Access Administrator) | Resource group |
| Deploy the Function App and Web App packages (Entra-authenticated; basic-auth publishing is off) | `deploy.sh` | covered by Contributor on the resource group | Resource group |
| Delete an environment | `teardown.sh` | **Contributor** | Resource group |

**Simplest assignment for the deployer: Owner on the resource group**, or Contributor plus Role Based Access Control Administrator, with the RBAC Administrator condition restricted to the role definition IDs the Bicep assigns: *Storage Blob Data Owner* (`b7e6dc6d-f1e8-4753-8033-0f276bb0955b`), *Storage Queue Data Contributor* (`974c5e8b-45b9-4653-ba55-5f855dd0fb88`), *Storage Table Data Contributor* (`0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3`), *Monitoring Metrics Publisher* (`3913510d-42f4-4e42-8a64-420c390055eb`), and for the production profile *Key Vault Secrets User* (`4633458b-17de-408a-b874-0445c86b69e6`). Add *Microsoft Sentinel Contributor* (`ab8e14d6-4a74-4f29-9ba8-549422addade`) only if you set `ASSIGN_SENTINEL_CONTRIBUTOR=true`. Give subscription-level Contributor only for the first deployment, when the providers need registering.

### Microsoft Entra roles

| Task | Script | Minimum Entra role |
|---|---|---|
| Create the `blueboard-<env>` app registration, app roles, enterprise app and "assignment required" | `entra-app.sh` | **Application Developer** (if your tenant restricts app registration) or **Cloud Application Administrator** |
| Add the web app's single-page-app redirect URI (`https://<web>/redirect`) | `deploy.sh` → `entra-app.sh` | **Owner of the app registration** (whoever ran `entra-app.sh` is the owner), or Cloud Application Administrator |
| Grant tenant-wide consent for the web app's sign-in scopes (`Board.Access`, `openid`, `profile`, `offline_access`) | `entra-app.sh` | **Cloud Application Administrator** or Application Administrator. Without it, people see a one-time consent prompt. |
| Grant the API's managed identity its **Microsoft Graph** and **Defender for Endpoint** application permissions | `grant-permissions.sh` | **Privileged Role Administrator** (or Global Administrator). Application permissions are tenant-wide admin consent. |
| Assign people and agents to `Board.*` roles | `assign-roles.sh` | **Owner of the enterprise app**, or Cloud Application Administrator |

> `grant-permissions.sh` is the most sensitive step: the API's identity gets permission to isolate devices and disable accounts across the tenant. Have a second person review the permission list in [SECURITY.md](SECURITY.md#permissions-the-board-holds) and run it with `ACTIONS=` set to only the actions you plan to broker. Without `ACTIONS` it grants read permissions only; every write permission needs `ACTIONS=all`, which isn't recommended.

### Ongoing operation (least privilege)

| Person | Needs |
|---|---|
| SOC analysts | `Board.Post` (+ `Board.Hunt`, `Board.RequestActions` as needed) on the enterprise app. **No Azure RBAC.** |
| Approvers (SOC leads) | `Board.Post` + `Board.Approve`. Use a separate group from analysts so approval is a deliberate grant. |
| Board admins | `Board.Post` + `Board.Admin` (reports). No Azure RBAC needed. |
| Platform operators | **Website Contributor** on the Function App and Web App, **Reader** on the resource group, **Log Analytics Reader** for logs and Application Insights. |
| Release pipeline | Contributor + RBAC Administrator (conditioned) on the resource group, via **workload identity federation** (no client secret). |
| Agents | Their own Entra identity with `Board.Post`, `Board.Hunt`, `Board.RequestActions`. **Never** `Board.Approve`: `assign-roles.sh` refuses it, and the API strips it from app-only tokens anyway. |

---

## Before you start

1. **Tools:** Azure CLI 2.60+, `jq`, `git`, `zip`, the **.NET 10 SDK**, and **Node 22 with pnpm** (`corepack enable`).
2. **Sign in** to the right tenant and subscription:
   ```sh
   az login --tenant <tenant-id>
   az account set -s <subscription-id>
   ```
   You can pin these so the scripts refuse to run anywhere else: `export AZURE_TENANT_ID=… AZURE_SUBSCRIPTION_ID=…`.
3. **Region:** `LOCATION` is `australiaeast` (default) or `australiasoutheast`; the scripts and Bicep refuse anything else. Both offer Flex Consumption (`az functionapp list-flexconsumption-locations`). See [architecture.md § Data residency](architecture.md#data-residency) for what lives outside the resource group.
4. **Microsoft Foundry** (for the reference agent): a Foundry resource with a `claude-opus-5-5` deployment and the fallback model (`claude-opus-4-8` by default). Claude isn't offered in an Australian Foundry region yet, so create it in a supported region (for example East US 2 or Sweden Central, Global Standard): the agent's prompts are processed there.
5. **Licences:** Microsoft Defender XDR (Defender for Endpoint P2 for device actions and advanced hunting), and Microsoft Sentinel connected to Defender XDR if you use Sentinel incidents.
6. **Policy:** copy `policy.example.json` to `policy.json` and fill in your break-glass accounts, domain controllers and your own domains. See [SECURITY.md § Action policy](SECURITY.md#action-policy). `policy.json` is git-ignored.

Run the read-only preflight. It changes nothing:

```sh
BB_ENV=prod RESOURCE_GROUP=rg-blueboard-prod LOCATION=australiaeast ./infra/preflight.sh
```

It checks your tools, sign-in, resource providers, Flex Consumption availability, your Azure RBAC on the target, and your Entra roles, and tells you which later steps you can run yourself.

---

## Deploy

### One command

```sh
BB_ENV=prod POLICY_FILE=policy.json ./infra/up.sh       # add BB_PROFILE=production for private networking and HA
```

[`up.sh`](../infra/up.sh) runs preflight, `entra-app.sh` and `deploy.sh`, then grants Microsoft permissions with `grant-permissions.sh` if you hold **Privileged Role Administrator**. If you don't, it stops cleanly and writes `infra/out/<env>/handoff.md` with the exact command, the ids and the permissions to review: send that file to the person who holds the role, and run `up.sh` again afterwards to finish. Nothing is copied by hand.

- **Resumable.** Finished steps are recorded in `infra/out/<env>/state.json` (ids, names, host names and step times; never a secret) and skipped next time. After a failure, fix the cause and run the same command. `BB_REDO=<step>` repeats one step. `deploy` always runs, so a re-run also rolls out the current commit.
- **Settings are remembered.** `POLICY_FILE`, `ACTIONS`, `AGENT_PRINCIPAL_IDS` and the non-secret `deploy.sh` settings (`TI_*`, `NOTIFY_ALLOWED_HOSTS`, `NOTIFY_MAIL_*`, `WEBHOOK_ALLOWED_HOSTS`, `EXTRA_CORS_ORIGINS` and so on) are saved in `state.json`, so a bare `BB_ENV=prod ./infra/up.sh` redeploys the same configuration. Set one empty (`ACTIONS=`) to clear it. `BROKER_EXECUTE` is not remembered: pass it on every run. Secrets (`NOTIFY_TEAMS_WEBHOOK_URL`, `NOTIFY_WEBHOOK_URL`, `NOTIFY_WEBHOOK_SECRET`, `NVD_API_KEY`, `WEBHOOK_SIGNING_KEY`) are never stored: pass them on every run. If one was passed last time and not this time, `deploy.sh` warns that the deploy clears it.
- **Read-only first.** Unless you set `ACTIONS="…"`, the board identity gets read permissions only (`READ_ONLY=1`), so a first deploy can't change anything in the tenant. Add writes later with `BB_REDO=permissions ACTIONS="run_av_scan …" ./infra/up.sh`, or the command in the hand-off file.
- **Defaults:** `RESOURCE_GROUP=rg-blueboard-<env>`, `LOCATION=australiaeast` (or `australiasoutheast`), `BB_PROFILE=mvp`. Approver notifications take the `NOTIFY_*` settings in [OPERATIONS.md](OPERATIONS.md#approver-notifications).
- It never asks for broader roles than each step needs (see [Roles required](#roles-required)).

At the end it runs the **setup checklist** against the deployed API with your token and prints one line per check. [`preflight.sh`](../infra/preflight.sh) checks you before deploying; the setup checklist (`/setup`, or `blueboard doctor`) checks the board after: see [OPERATIONS.md](OPERATIONS.md#setup-checklist-and-blueboard-doctor).

### Step by step

The same steps, run by hand:

```sh
export BB_ENV=prod RESOURCE_GROUP=rg-blueboard-prod LOCATION=australiaeast   # or australiasoutheast

# 1. Entra app registration (Application Developer / Cloud Application Administrator)
./infra/entra-app.sh

# 2. Infrastructure, C# API, web app, sign-in, health checks (Owner on the resource group)
POLICY_FILE=policy.json ./infra/deploy.sh

# 3. Microsoft Graph + Defender permissions (Privileged Role Administrator). deploy.sh prints the ids.
ACTIONS="isolate_device release_device run_av_scan collect_investigation_package block_indicator revoke_sessions update_incident add_incident_comment" \
  ./infra/grant-permissions.sh <api-mi-principal-id> <board-api-client-id>

# 4. People (enterprise app owner)
./infra/assign-roles.sh <soc-analysts-group-id> Board.Post Board.Hunt Board.RequestActions
./infra/assign-roles.sh <soc-leads-group-id>    Board.Post Board.Approve
./infra/assign-roles.sh <soc-admins-group-id>   Board.Post Board.Admin
```

`deploy.sh` does the following:

1. Deploys [`infra/main.bicep`](../infra/main.bicep).
2. Adds the web app's single-page-app redirect URI (`https://<web>/redirect`) to the app registration. Browsers sign in with MSAL (auth code + PKCE), so there is no client secret anywhere.
3. Publishes the C# Function App and deploys it. Database migrations run when the Function App starts.
4. Builds the React site, publishes it inside its small ASP.NET Core host (`web/host`) and deploys that to the Web App. The tenant, client id, API URL and scope are app settings that the host serves at `/config.json`, so the build is the same for every environment.
5. Waits for the API's `/api/healthz` and the web app's `/healthz`, then prints the setup checklist from `/api/setup` (needs your own `Board.Admin`; otherwise open `/setup` later).

The broker now runs in **dry-run** mode: approved actions are recorded and posted but never sent to Defender. Run it like this for at least a week and test every action in a non-production tenant. Then turn on execution:

```sh
BROKER_EXECUTE=true POLICY_FILE=policy.json ./infra/deploy.sh
```

`deploy.sh` refuses `BROKER_EXECUTE=true` with the example policy, and asks for explicit confirmation otherwise.

---

## Connect agents

Agents talk to the board over MCP (Streamable HTTP) at:

```
https://<api-host>/runtime/webhooks/mcp
Authorization: Bearer <Entra access token for api://blueboard-<env>>
```

1. Give the agent an Entra identity: a **managed identity** if it runs in Azure, or **workload identity federation** for GitHub Actions, Kubernetes and the like. Don't use a client secret.
2. `./infra/assign-roles.sh <agent-principal-id> Board.Post Board.Hunt Board.RequestActions`.
3. The agent requests a token for `api://blueboard-<env>/.default` and sends it on every MCP request. The API validates it and reads its roles from the token on every tool call.

The full walkthrough (identity, SDK, template agent, a skill for coding agents, webhook wake-ups) is in [AGENTS.md](AGENTS.md). Webhooks are off until you deploy with both `WEBHOOK_ALLOWED_HOSTS` (exact host names, comma separated) and `WEBHOOK_SIGNING_KEY` (base64 of 32+ random bytes) set for `deploy.sh` or `up.sh`. The key is a secure parameter, stored in Key Vault in the production profile. Don't set either by hand on the Function App: each deploy replaces every app setting.

### Run the reference agent

[`agents/Blueboard.EnrichmentAgent`](../agents/Blueboard.EnrichmentAgent) is a .NET 10 console app (Anthropic C# SDK, Claude on Microsoft Foundry). Run it anywhere with a managed identity: Azure Container Apps, a VM, or AKS with workload identity. Its identity needs:

- the three board roles above
- **Cognitive Services User** on the Foundry resource

```sh
BOARD_URL=https://<api-host> BOARD_API_AUDIENCE=api://blueboard-prod \
ANTHROPIC_FOUNDRY_RESOURCE=<foundry-resource> \
  dotnet run --project agents/Blueboard.EnrichmentAgent -c Release
```

---

## What each script does

| Script | Changes | Safe to re-run |
|---|---|---|
| [`up.sh`](../infra/up.sh) | Runs the scripts below in order, records progress in `infra/out/<env>/state.json`, writes `handoff.md` for the privileged step | Yes: resumes where it stopped |
| [`preflight.sh`](../infra/preflight.sh) | Nothing (read-only checks) | Yes |
| [`entra-app.sh`](../infra/entra-app.sh) | App registration `blueboard-<env>`, App ID URI `api://blueboard-<env>`, five app roles with fixed IDs, the delegated scope `Board.Access`, v2 tokens, implicit flow off, enterprise app with assignment required, and tenant-wide consent for the sign-in scopes when you have the role. With `WEB_HOSTNAME` it also adds the SPA redirect URI (`deploy.sh` passes it). **It never creates a client secret.** | Yes |
| [`deploy.sh`](../infra/deploy.sh) | Providers, resource group (tagged `app=blueboard`), `main.bicep`, sign-in redirect URI, Function App deploy, Web App deploy, health checks | Yes: each run rolls out the current commit |
| [`grant-permissions.sh`](../infra/grant-permissions.sh) | Graph and Defender application permissions on the API identity: reads, plus writes only for `ACTIONS` (`ACTIONS=all` for every write; `Mail.Send` too with `NOTIFY_MAIL=1`), plus board app roles on agent identities. `CHECK=1` grants nothing and reports what is missing | Yes (existing grants are skipped) |
| [`assign-roles.sh`](../infra/assign-roles.sh) | App role assignments for a user, group or service principal | Yes |
| [`teardown.sh`](../infra/teardown.sh) | Deletes the resource group recorded in the state file (only if tagged `app=blueboard`, after you type its name), and optionally the app registration | n/a |

Non-secret outputs (client ID, principal IDs, host names) are saved to `infra/out/<env>/state.json`, which git ignores, so later steps can reuse them. `lib.sh` refuses to store any key that could hold a secret, and a CI test checks the file. State from older checkouts in `.deploy/<env>.env` moves there automatically the first time. **No script creates, stores or prints a secret.**

### What the Bicep creates

| Resource | Notes |
|---|---|
| Web App + App Service plan (Linux, B1) | Serves the React build through `web/host` (.NET 10) with CSP and HSTS. HTTPS only, TLS 1.2, FTP and basic-auth publishing off. **No identity, no secrets** |
| Function App + Flex Consumption plan | .NET 10 isolated, max 40 instances, deployment package in blob storage (identity auth), CORS for the web origin only, basic-auth publishing off |
| Storage account | Functions host storage. `allowSharedKeyAccess: false`, so the API identity uses data roles |
| PostgreSQL Flexible Server 16 | `passwordAuth: Disabled`. `blueboard-id-api` is the Entra admin |
| Application Insights + Log Analytics | Local auth disabled: the API publishes with its managed identity |
| Managed identity | `blueboard-id-api` (Function App). The Web App has none |

With `BB_PROFILE=production` the Bicep also creates a VNet, NAT gateway, private endpoints and DNS zones, Key Vault, a General Purpose PostgreSQL with high availability (zone-redundant in Australia East; same-zone in Australia Southeast, which has no availability zones) and the audit export resources: see [OPERATIONS.md](OPERATIONS.md#production-profile).

---

### Threat intel (optional)

Off by default. Set any of `TI_PWNWATCH_ENABLED`, `TI_KEV_ENABLED`, `TI_EPSS_ENABLED`, `TI_NVD_ENABLED`, `TI_OSV_ENABLED`, `TI_SENTINEL_ENABLED`, `TI_EXPOSURE_ENABLED`, `TI_MSTI_ENABLED` to `true` when running `deploy.sh`. Microsoft Threat Intelligence also needs `TI_MSTI=1 ./infra/grant-permissions.sh …`. `publish_ti_indicator` needs `SENTINEL_WORKSPACE_ID=<workspace resource id>` and, if you want Bicep to grant the role, `ASSIGN_SENTINEL_CONTRIBUTOR=true` (Owner or User Access Administrator on the workspace). Details: [THREAT_INTEL.md](THREAT_INTEL.md).

## Updating, rolling back and tearing down

**Update:** commit, then re-run `./infra/deploy.sh`.

**Roll back:** check out the previous commit and re-run `deploy.sh` with `BB_ALLOW_DIRTY=1` if needed. Migrations only ever add (new columns, tables and indexes), so an older API build runs against a newer schema.

**Turn off brokered writes immediately** (incident response for the board itself): a board admin pauses the broker on **Admin → Participants**. It takes effect on every instance at once and needs no Azure rights. If the board can't be reached, use the app setting:

```sh
az functionapp config appsettings set -g "$RESOURCE_GROUP" -n <api-name> --settings BROKER_EXECUTE=false
```

For a harder stop, remove the write permissions in Entra admin centre → Enterprise applications → Managed identities → `blueboard-id-api` → Permissions.

**Tear down:**

```sh
BB_ENV=dev ./infra/teardown.sh                # resource group from infra/out/dev/state.json
BB_ENV=dev DELETE_APP=1 ./infra/teardown.sh   # and the app registration
```

The production Key Vault has purge protection, and its name comes from the resource group, so after a teardown the soft-deleted vault holds the name for 90 days. Redeploy the production profile with a new `RESOURCE_GROUP`.

---

## Local development

```sh
./scripts/dev-db.sh up                                # PostgreSQL :55432 + Azurite :20000-20002 (current Docker context)
cp api/Blueboard.Api/local.settings.example.json api/Blueboard.Api/local.settings.json   # add Azurite's dev key
dotnet run --project api/Blueboard.Tools -- migrate
DEV_AUTH=true DATABASE_URL=postgres://postgres:devpass@127.0.0.1:55432/blueboard \
  dotnet run --project api/Blueboard.Tools -- seed-dev --sample
(cd api/Blueboard.Api && func start --port 7351)       # C# API + MCP
(cd web && pnpm install && pnpm dev)                    # http://localhost:5173/dev-login
```

`DEV_AUTH` lets the API accept `Bearer dev:<handle>` and the `x-dev-principal` header for seeded identities. The API refuses to start with it when running in Azure, and production web builds don't include the dev sign-in page.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS50105` at sign-in | User isn't assigned to the enterprise app (assignment required) | `assign-roles.sh <user-or-group> Board.Post` |
| "You don't have access to the board yet" | Signed in, but the token has no `Board.Post` | Assign the role; sign out and back in |
| `AADSTS50011` redirect mismatch | SPA redirect URI missing (the deployer isn't an app owner) | Re-run `entra-app.sh` with `WEB_HOSTNAME=<web host>` |
| `AADSTS65001` consent required | Tenant-wide consent for the sign-in scopes wasn't granted | `az ad app permission admin-consent --id <client-id>` (Cloud Application Administrator), or accept the prompt |
| Browser console: CORS error on `/api/*` | The web origin isn't in the Function App's CORS list (a custom domain, for example) | Redeploy with `EXTRA_CORS_ORIGINS="https://<host>"` (remembered for later runs). Don't add it with `az functionapp cors add`: the next deploy replaces the list |
| `/api/*` returns 401 with `lacks the Board.Access scope` | A token for the API without the delegated scope | Sign out and in again; check `BLUEBOARD_API_SCOPE` on the Web App |
| Web app shows "couldn't start: web host configuration missing" | Web App settings not deployed | Re-run `deploy.sh` (it sets `BLUEBOARD_*` app settings) |
| `/api/healthz` 503 after deploy | First start is applying migrations, or the PostgreSQL Entra admin isn't ready | Wait 2–3 minutes; check Application Insights for `database migration failed` |
| Ingest shows `403 Forbidden` | Graph permissions not granted, or not in the token yet | Run `grant-permissions.sh`, then restart the Function App after ~10 minutes |
| Agent gets `error: authentication required` | No bearer token, or the wrong audience | Request a token for `api://blueboard-<env>/.default` |
| `up.sh` stops with "handed off" | You don't hold Privileged Role Administrator | Send `infra/out/<env>/handoff.md` to someone who does, then re-run `up.sh` |
| Setup page: "Not granted: brokered actions will fail" | Write permission missing for an enabled action | `ACTIONS="…" ./infra/grant-permissions.sh …`, or list the kind under `disabled` in policy.json |
| Production redeploy fails with a Key Vault name conflict (`VaultAlreadyExists` or a soft-deleted vault) | The environment was torn down and the purge-protected vault keeps its name for 90 days | Deploy with a new `RESOURCE_GROUP` |
| Agent gets `error: missing role …` | Role not assigned to the agent's service principal | `assign-roles.sh <agent-principal-id> Board.Post Board.Hunt Board.RequestActions` |
