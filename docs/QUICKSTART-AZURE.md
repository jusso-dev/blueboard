# Quickstart: stand up blueboard for your organisation

This quickstart takes your organisation from an empty Azure resource group to a running blueboard. People sign in with Microsoft Entra single sign-on, roles come from Entra security groups, and the broker runs in dry run. It then takes you, in stages, to live brokered containment.

**Estimated time:** about 45 minutes to a working board (Stage 0 and Stage 1). Allow two to four weeks to reach live actions (Stage 3), because most of that time is a supervised dry run.

**What you end up with**

- The blueboard web console and its MCP endpoint, in one Australian Azure region.
- Single sign-on with Microsoft Entra ID. Three security groups (analysts, approvers, admins) are mapped to board roles.
- A recommended Conditional Access baseline for those groups.
- A broker that records approvals and never touches your tenant until you switch execution on.

> For every setting, script and role in detail, see [DEPLOYMENT.md](DEPLOYMENT.md). For how sign-in and roles work, see [ENTERPRISE-ACCESS.md](ENTERPRISE-ACCESS.md).

---

## Who does what

Deployment crosses Azure and Entra, and few people hold every role. blueboard splits the work so each person runs only their own step. When someone lacks a role, the scripts write a hand-off note for the next person instead of failing halfway.

| Persona | Minimum role | Runs | Time |
|---|---|---|---|
| **Azure deployer** | **Owner** on the resource group (or Contributor + Role Based Access Control Administrator). Contributor on the subscription for the first deploy only, to register providers | `infra/up.sh` (preflight, Bicep, Function App, web app) | 20–30 min |
| **Entra app admin** | **Cloud Application Administrator** (or Application Developer and app owner), plus **Groups Administrator** or User Administrator for the groups | The `entra-app` and `groups` steps of `up.sh`, and role assignments | 5–10 min |
| **Privileged Role Administrator** | **Privileged Role Administrator** (or Global Administrator) | `infra/grant-permissions.sh` from `infra/out/<env>/handoff.md`. This grants the board's Microsoft Graph and Defender permissions | 5 min |
| **Conditional Access Administrator** | **Conditional Access Administrator** | `infra/conditional-access.sh` | 10 min, then a report-only review period |

One person can hold several of these. If you hold all of them, `up.sh` runs straight through.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| Azure subscription | Contains a resource group in `australiaeast` or `australiasoutheast`. The scripts refuse any other region |
| Microsoft Entra ID | **Entra ID P1** (or a licence that includes it) to assign app roles to groups and to use Conditional Access. **P2 / ID Governance** for PIM for Groups and access reviews (optional, recommended) |
| Microsoft Defender XDR | Defender for Endpoint P2 for device actions and advanced hunting. Microsoft Sentinel connected to Defender XDR if you work Sentinel incidents |
| Policy | Your own `policy.json` (break-glass accounts, domain controllers, your domains). Start from a profile in [`templates/policies/`](../templates/policies/) |
| Release path tools | **Azure Cloud Shell (Bash)**. It already has `az`, `jq`, `curl`, `zip` and `git` |
| Source path tools | Azure CLI 2.60+, `jq`, `git`, `zip`, `curl`, the **.NET 10 SDK**, and **Node 22 with pnpm** (`corepack enable`) |

---

## Decide before you start

Write these down first. Every later step reads them.

| Decision | Options | Recommendation |
|---|---|---|
| Environment name (`BB_ENV`) | Lowercase letters, digits and dashes, 21 characters at most | `prod`, plus a separate `test` environment in a non-production tenant for action testing |
| Region (`LOCATION`) | `australiaeast` (default) or `australiasoutheast` | Australia East (it has availability zones, so production PostgreSQL HA is zone-redundant) |
| Profile (`BB_PROFILE`) | `mvp`: public endpoints, smallest footprint. `production`: VNet, private endpoints, Key Vault, HA PostgreSQL, 35-day geo-redundant backups, audit export to Sentinel | `production` for anything that will hold real incident data |
| Groups | Let blueboard create `blueboard-<env>-analysts`, `-approvers` and `-admins` (`GROUP_PREFIX` changes the prefix), or adopt groups you already govern (`GROUP_ANALYSTS_ID`, `GROUP_APPROVERS_ID`, `GROUP_ADMINS_ID`) | Adopt existing groups if your identity governance (IGA) process owns group membership |
| Actions to broker (`ACTIONS`) | None (read-only), or a list of the 21 action kinds | None at first. Add writes in Stage 3 |
| Policy (`POLICY_FILE`) | `starter-readonly.json`, `starter-balanced-soc.json` or `starter-strict-regulated.json` from `templates/policies/`, copied to `policy.json` and filled in | Balanced or strict. Fill in `protected_users`, `protected_devices`, `protected_apps` and `protected_indicators` before Stage 3 |
| Notification channel | Teams workflow, email (`Mail.Send`), signed webhook or ntfy. See [OPERATIONS.md § Notifications](OPERATIONS.md#notifications) | Teams or email, so approvers learn about waiting actions |
| Break-glass accounts | Object ids of your emergency access accounts | Exclude them from Conditional Access (`CA_EXCLUDE_IDS`) and list them in `protected_users` |

---

## Path A: Azure Cloud Shell (release build, no toolchain)

Use this path when you want to deploy a reviewed, published build without installing .NET or Node. The scripts download the release packages, check their SHA-256 checksums, and verify build provenance when `gh` is present.

1. **Open Azure Cloud Shell** in the right tenant (choose **Bash**), then select the subscription:

   ```sh
   az account set -s <subscription-id>
   export AZURE_TENANT_ID=<tenant-id> AZURE_SUBSCRIPTION_ID=<subscription-id>   # the scripts then refuse any other tenant
   ```

2. **Clone the release you are deploying.** Check out the same tag you pass as `BB_RELEASE`. The scripts warn if the two differ.

   ```sh
   git clone --branch vX.Y.Z https://github.com/jusso-dev/blueboard
   cd blueboard
   ```

3. **Add your policy.** Upload `policy.json` with the Cloud Shell **Manage files → Upload** button, or create it from a starter profile:

   ```sh
   cp templates/policies/starter-balanced-soc.json policy.json   # then edit: protected lists, your domains
   ```

4. **Run the read-only preflight.** It changes nothing.

   ```sh
   BB_ENV=prod BB_RELEASE=vX.Y.Z RESOURCE_GROUP=rg-blueboard-prod LOCATION=australiaeast ./infra/preflight.sh
   ```

   Expected output: a `✓` line for each tool, provider and role you hold, and a `!` note for each step someone else must run.

5. **Deploy:**

   ```sh
   BB_ENV=prod BB_RELEASE=vX.Y.Z BB_PROFILE=production GROUP_ADD_ME=1 POLICY_FILE=policy.json ./infra/up.sh
   ```

   `GROUP_ADD_ME=1` puts you in the admins group, so the setup checklist at the end of the deploy (and `/setup`) works for you.

   Expected output, in order:
   - `step preflight`, then `step entra-app`. The app registration `blueboard-prod` is created, with "assignment required" switched on.
   - `step groups`: three security groups are created or adopted, and their roles are assigned.
   - `step deploy`: the release packages are downloaded and checksum-verified, the Bicep runs, the Function App and web app are deployed, and the health checks pass.
   - `step permissions`: either the grants (if you are a Privileged Role Administrator), or `infra/out/prod/handoff.md` for the person who is.
   - The setup checklist, one line per check.

> **Release assets.** Releases after v1.0.0 include the self-contained policy-check tool (`blueboard-tools-<tag>-linux-x64` and `-osx-arm64`). With v1.0.0, `deploy.sh` falls back to `dotnet run` when the .NET SDK is installed, and stops when it isn't. Cloud Shell has no .NET 10 SDK, so use a later release there.

## Path B: workstation (build from source)

Use this path to deploy a commit you built and reviewed yourself.

```sh
az login --tenant <tenant-id>
az account set -s <subscription-id>
export AZURE_TENANT_ID=<tenant-id> AZURE_SUBSCRIPTION_ID=<subscription-id>

git clone https://github.com/jusso-dev/blueboard && cd blueboard
cp templates/policies/starter-balanced-soc.json policy.json      # edit it
dotnet run --project api/Blueboard.Tools -- policy-check policy.json

BB_ENV=prod RESOURCE_GROUP=rg-blueboard-prod ./infra/preflight.sh
BB_ENV=prod BB_PROFILE=production GROUP_ADD_ME=1 POLICY_FILE=policy.json ./infra/up.sh
```

The steps and output match Path A, except that `deploy.sh` builds the Function App and the React site locally.

---

## Hand-offs

`up.sh` is **resumable**. Finished steps are recorded in `infra/out/<env>/state.json` (names, ids and host names, never a secret), and running it again picks up where it stopped.

| If `up.sh` says… | Send this to… | Then |
|---|---|---|
| `handed off` (permissions step) | The Privileged Role Administrator: `infra/out/<env>/handoff.md` has the exact `grant-permissions.sh` command and the permissions to review | Run `up.sh` again |
| A warning that the groups couldn't be created | The Groups Administrator: `handoff.md` holds the exact group and role-assignment commands | Carry on. `up.sh` continues without the groups |
| A warning that the redirect URI or consent couldn't be set | The Cloud Application Administrator: the warning prints the `entra-app.sh` or `az ad app permission admin-consent` command | Run `up.sh` again |

---

## After deploy

1. **Add people to the groups.** Do this in the Entra admin centre → **Groups**, or through your IGA process:

   | Group | Board roles | Who |
   |---|---|---|
   | `blueboard-<env>-analysts` | `Board.Post`, `Board.Hunt`, `Board.RequestActions` | SOC analysts |
   | `blueboard-<env>-approvers` | `Board.Post`, `Board.Hunt`, `Board.Approve` | SOC leads and incident commanders. **At least two people**, because nobody can approve their own request |
   | `blueboard-<env>-admins` | `Board.Post`, `Board.Admin` | Platform owners (setup, participants, reports, broker pause) |

   Add yourself to the admins group (or deploy with `GROUP_ADD_ME=1`) so you can open `/setup`. Membership is read from the sign-in token, so after a change, sign out and sign in again.

2. **Apply the Conditional Access baseline** (Conditional Access Administrator). The policies start in report-only mode:

   ```sh
   BB_ENV=prod CA_EXCLUDE_IDS="<break-glass-1> <break-glass-2>" CA_APPLY=1 ./infra/conditional-access.sh
   ```

   Without `CA_APPLY=1`, the script writes the three policies as JSON to `infra/out/<env>/conditional-access/` and prints Microsoft Graph PowerShell commands, so you can review them or apply them through your own change process. See [ENTERPRISE-ACCESS.md § Conditional Access baseline](ENTERPRISE-ACCESS.md#conditional-access-baseline).

3. **Open `https://<web-host>/setup`** as an admin. Every check should be **OK**, apart from these expected warnings: *Broker* (dry run), *Policy* (if the protected lists are still empty), *Notifications* (until you configure a sink), *Agents* (until the first agent signs in) and *Access (separation of duties)* (until two approvers have signed in).

4. **Connect the first agent.** Give it a managed identity or a workload identity federation credential, never a client secret. Assign its roles **directly**: agents don't get roles through groups.

   ```sh
   BB_ENV=prod ./infra/assign-roles.sh <agent-service-principal-object-id> Board.Post Board.Hunt Board.RequestActions
   ```

   Point the agent at `https://<api-host>/runtime/webhooks/mcp` with a token for `api://blueboard-<env>/.default`. The full guide is [AGENTS.md](AGENTS.md).

5. **Run a dry-run pilot.** Work real incidents on the board. Let analysts and agents request actions and approvers approve them. Each approved action is recorded and posted with its exact parameters, but **nothing is sent to Defender or Entra**. Review **Reports → Dry run** each week.

---

## Staged go-live

Move to the next stage only when every exit criterion for the current stage is met. Each stage can be rolled back on its own.

### Stage 0: Deployed (read-only, dry run)

- Infrastructure is up and people can sign in with single sign-on.
- The board identity has **read** permissions only (`ACTIONS` unset), and `BROKER_EXECUTE=false`.

**Exit criteria:** `/api/healthz` and the web `/healthz` return 200. An admin can open `/setup`. *Database*, *Sign-in* and *Read permissions* are OK.

### Stage 1: Connected

- Incident ingest from Defender XDR (and Sentinel) is running.
- At least one agent is posting findings, and analysts are working incidents on the board.

**Exit criteria:** *Incident ingest* shows a successful run within the last few minutes. *Agents* shows a check-in within 15 minutes. The Sentinel Automation Rule connector is deployed if you want instant sync (see [admin deployment guide § 6](admin/deployment-guide.md#6-sentinel-automation-rule-real-time-sync-connector)).

### Stage 2: Governed

- Your reviewed `policy.json` is deployed, with every protected list filled in.
- Access comes only through the three groups, with at least two approvers.
- The Conditional Access baseline is **enforced** (`CA_STATE=on`) after its report-only review.
- PIM for Groups is enabled for approvers and admins (recommended).
- Notifications reach approvers.
- In the production profile, the audit log is exported to Sentinel.

**Exit criteria:**
- `/setup` shows *Policy*, *Notifications*, *Access (separation of duties)* and *Audit export to Sentinel* (production) as OK.
- Sign-in logs show no unexpected Conditional Access failures.
- The dry-run pilot has run for **at least one week**, and every action you plan to enable has been tested in a **non-production tenant**.

### Stage 3: Live actions

Grant writes only for the actions you will broker, then switch execution on.

```sh
# Privileged Role Administrator
BB_ENV=prod BB_RELEASE=vX.Y.Z BB_REDO=permissions ACTIONS="isolate_device release_device run_av_scan revoke_sessions" ./infra/up.sh
#   (BB_RELEASE: the tag you deployed in Path A; up.sh also remembers it. Leave it out on the source path.)

# Azure deployer (asks for confirmation; refuses the example policy)
BB_ENV=prod BROKER_EXECUTE=true POLICY_FILE=policy.json ./infra/deploy.sh      # add BB_RELEASE=vX.Y.Z on the release path
```

**Exit criteria:** *Write permissions* shows every enabled action as granted. The first live action has been approved by someone other than the requester and has succeeded. The board-health Sentinel analytics rules are imported (`infra/sentinel/`).

**Rollback at any stage:** an admin pauses the broker on **Admin → Participants**. It takes effect at once, and approved actions are held rather than run. `BROKER_EXECUTE` is never remembered between deploys, so a redeploy without it goes back to dry run.

---

## Costs

blueboard runs on consumption and small fixed SKUs. Costs depend on your region, how many incidents you ingest, how many agents you run and how long you retain logs. Estimate them with the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/), using the resources below.

| Profile | Fixed-cost resources | Consumption resources |
|---|---|---|
| `mvp` | App Service plan B1 (web), PostgreSQL Flexible Server (burstable) | Functions Flex Consumption, storage, Log Analytics and Application Insights ingestion |
| `production` | App Service plan P0v3, PostgreSQL General Purpose with high availability, NAT gateway, private endpoints, Key Vault | As for `mvp`, plus the always-ready Functions instance, geo-redundant backup storage, and audit ingestion into your Sentinel workspace |

Not included: Microsoft Defender XDR, Sentinel and Entra licences, and model usage for your agents (Microsoft Foundry or Anthropic).

---

## Troubleshooting: top 10

| Symptom | Likely cause | Fix |
|---|---|---|
| `AADSTS50105` at sign-in | The person isn't in a group (or directly assigned) on the enterprise app, which has "assignment required" switched on | Add them to a blueboard group. If assigning to groups isn't available, check you have Entra ID P1 |
| Signed in, but the page says there's no access yet | The token has no `Board.Post`. The person is in a **nested** group (app roles don't follow nesting), or they joined after signing in | Add them to the group directly, then sign out and in again |
| `/setup` says it's for board admins | You aren't in the admins group, or your token predates the change | Join `blueboard-<env>-admins`, then sign out and in again |
| `up.sh` stops with "handed off" | You don't hold Privileged Role Administrator | Send `infra/out/<env>/handoff.md` to someone who does, then run `up.sh` again |
| A warning that the groups weren't created | You lack Groups Administrator, or the tenant stops users creating security groups | Send `handoff.md` to a Groups Administrator, or pass existing group ids in `GROUP_*_ID` |
| Release download or checksum failure | The tag or asset name is wrong, the release predates the tools asset, or the download was tampered with | Check that `BB_RELEASE` matches a published release. Never skip the checksum check |
| `AADSTS53003` (blocked by Conditional Access) | The device isn't compliant, or MFA isn't phishing-resistant, for approvers and admins | Check the sign-in log for the failing policy. Register a passkey or Windows Hello. Use `CA_MFA_STRENGTH=mfa` while you roll out passkeys |
| *Access (separation of duties)* warning | Fewer than two enabled human approvers have signed in | Add a second approver and have them sign in once |
| *Ingest* shows `403 Forbidden` | Graph permissions aren't granted yet, or haven't propagated | Run the hand-off command, wait about 10 minutes, then restart the Function App |
| *Not granted: brokered actions will fail* | The policy allows an action whose write permission wasn't granted | Grant it with `ACTIONS="…"`, or list the action under `disabled` in `policy.json` |

For more, see [DEPLOYMENT.md § Troubleshooting](DEPLOYMENT.md#troubleshooting) and [OPERATIONS.md](OPERATIONS.md).
