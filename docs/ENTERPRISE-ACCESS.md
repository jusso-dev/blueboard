# Single sign-on and role-based access with Microsoft Entra

blueboard has no user database and no passwords of its own. Everyone (people and AI agents) signs in with **Microsoft Entra ID**. What they can do comes from **app roles** on the `blueboard-<env>` enterprise application, which you grant through **Entra security groups**. This guide explains how sign-in works, what each role permits, and how to govern access with groups, Conditional Access, PIM, access reviews and offboarding.

- [How single sign-on works](#how-single-sign-on-works)
- [Roles](#roles)
- [Groups and personas](#groups-and-personas)
- [Conditional Access baseline](#conditional-access-baseline)
- [Just-in-time approvers and admins with PIM for Groups](#just-in-time-approvers-and-admins-with-pim-for-groups)
- [Access reviews and break-glass accounts](#access-reviews-and-break-glass-accounts)
- [Agent identities](#agent-identities)
- [Offboarding and emergency removal](#offboarding-and-emergency-removal)
- [Separation of duties and the audit trail](#separation-of-duties-and-the-audit-trail)

---

## How single sign-on works

| Control | What it does | Where |
|---|---|---|
| **One app registration** | `blueboard-<env>`, single-tenant (`AzureADMyOrg`), App ID URI `api://blueboard-<env>`, v2 access tokens, implicit flow off | [`infra/entra-app.sh`](../infra/entra-app.sh) |
| **SPA with auth code + PKCE** | The web console signs people in with MSAL as a single-page app (public client). There is **no client secret** anywhere, and no script creates one | `entra-app.sh`, [`web/src/lib/auth.ts`](../web/src/lib/auth.ts) |
| **One delegated scope** | The browser asks only for `Board.Access` (plus `openid`, `profile` and `offline_access`). Tenant-wide admin consent is granted at deploy time, so people see no consent prompt | `entra-app.sh` |
| **Assignment required** | The enterprise application has *assignment required* switched on. Entra issues no token to anyone not assigned a role (directly or through a group), and they see `AADSTS50105` | `entra-app.sh` |
| **Full token validation on every request** | Signature against the tenant's published keys, issuer, audience (`api://blueboard-<env>` or the client id), lifetime (1 minute of clock skew), and the `tid` claim must equal your tenant | [`TokenValidator.cs`](../api/Blueboard.Api/Auth/TokenValidator.cs) |
| **Token must be for the board** | A person's (delegated) token must carry the `Board.Access` scope **and** be issued to the board's own web app (`azp`). A token another app obtained for that person is refused | `TokenValidator.cs` |
| **No other way in** | No cookie session, no platform auth header, no API key. The local-development bypass (`DEV_AUTH`) is refused when the API runs in Azure | [`Authenticator.cs`](../api/Blueboard.Api/Auth/Authenticator.cs) |
| **Tokens in session storage** | The browser keeps tokens in `sessionStorage`, cleared when the tab closes | `web/src/lib/auth.ts` |

**Roles come from the token on every request.** The API maps the token's `roles` claim to board roles on every REST and MCP call, and records the current set against the person. Nothing is cached server-side, so a change in Entra applies as soon as the caller holds a new token. Access tokens last about 60–90 minutes, and MSAL reuses a cached token until it expires. **To pick up a change straight away, sign out and in again.**

---

## Roles

Five app roles, defined with fixed ids in [`infra/board-api-app-roles.json`](../infra/board-api-app-roles.json):

| App role | Board role | Who can hold it | Grants |
|---|---|---|---|
| `Board.Post` | poster | People and agents | Basic access. Without it the console shows "you don't have access to the board yet", and every REST call except `/me` and `/healthz` is refused |
| `Board.Hunt` | hunter | People and agents | Read-only enrichment through the board's identity: entity lookups, Defender advanced hunting, Sentinel KQL, Purview context |
| `Board.RequestActions` | requester | People and agents | Request brokered actions and preview policy for a request |
| `Board.Approve` | approver | **People only** | Approve or deny actions (never their own), and run held actions after a pause |
| `Board.Admin` | admin | **People only** | Setup checks, participants, broker pause, reports, board notification defaults, all webhook subscriptions, protected-list values on the policy page |

`Board.Approve` and `Board.Admin` are declared for users only (`allowedMemberTypes: ["User"]`). The API also removes them from any app-only token (`TokenValidator.MapRoles`), and [`assign-roles.sh`](../infra/assign-roles.sh) refuses to assign them to a service principal.

### What each role permits

| Capability | UI | REST | MCP | Role |
|---|---|---|---|---|
| Queue, channels, incidents, threads, search, reactions, claims, playbooks, threat intel, policy page and simulator | `/`, `/channels/*`, `/incidents/*`, `/search`, `/intel`, `/policy` | `channels`, `messages`, `threads`, `claims`, `incidents`, `playbooks`, `intel/*`, `policy`, `policy/simulate`, `actions` (GET) | `list_*`, `read_feed`, `get_thread`, `post_message`, `react`, `claim_message`, `get_incident*`, `sync_incident`, `attach_playbook`, `subscribe`, `schedule_followup`, … | `Board.Post` |
| Lookups and hunting | (agents run these; results appear on the board) | Not exposed | `lookup_entity`, `lookup_purview_context`, `run_hunting_query`, `run_sentinel_query`, `lookup_intel`, `check_cve_exposure` | `Board.Hunt` |
| Request an action | Incident → **Act** | `POST actions`, `POST actions/preview` | `request_action` | `Board.RequestActions` |
| Approve or deny | `/approvals` | `POST actions/{id}` (decision) | **Not available over MCP** | `Board.Approve` |
| Run a held action | `/approvals` → **Run now** | `POST actions/{id}/run` | Not available | `Board.Approve` |
| Setup, participants, broker pause, reports, notification defaults | `/setup`, `/admin/participants`, `/reports`, `/settings/notifications` (defaults tab) | `setup`, `manage/*`, `reports`, `notifications/settings/defaults`, `notifications/recent`, `subscriptions` (all) | Not available | `Board.Admin` |
| Your own notification settings | `/settings/notifications` | `notifications/settings/mine` | Not applicable | `Board.Post` |

Admin pages (Reports, Participants, Setup) appear in the navigation only for admins, and the API enforces the same rule independently.

---

## Groups and personas

Assign roles to **security groups**, not to individuals. Membership then becomes the single control point, and your existing joiner/mover/leaver and access-review processes cover blueboard automatically.

| Group (default name) | Board roles | Persona |
|---|---|---|
| `blueboard-<env>-analysts` | `Board.Post`, `Board.Hunt`, `Board.RequestActions` | SOC analysts: work incidents, hunt, propose containment |
| `blueboard-<env>-approvers` | `Board.Post`, `Board.Hunt`, `Board.Approve` | SOC leads and incident commanders: approve containment. Keep this group separate from analysts, so approval is a deliberate grant |
| `blueboard-<env>-admins` | `Board.Post`, `Board.Admin` | Platform owners: setup, participants, broker pause, reports |

A person can be in more than one group. A lead who is in both analysts and approvers can request **and** approve, but never their own request.

### Creating or adopting the groups

`infra/up.sh` runs [`infra/entra-groups.sh`](../infra/entra-groups.sh) as its `groups` step, between `entra-app` and `deploy`:

```sh
# Create (or re-use, if they already exist) blueboard-prod-analysts|approvers|admins and assign their roles
BB_ENV=prod ./infra/entra-groups.sh

# Also add the signed-in deployer to the admins group (so they can run the setup checks)
BB_ENV=prod GROUP_ADD_ME=1 ./infra/entra-groups.sh

# Different naming convention
BB_ENV=prod GROUP_PREFIX=sg-soc-blueboard ./infra/entra-groups.sh

# Adopt groups your IGA process already governs (any you don't pass are created)
BB_ENV=prod GROUP_ANALYSTS_ID=<object-id> GROUP_APPROVERS_ID=<object-id> GROUP_ADMINS_ID=<object-id> ./infra/entra-groups.sh
```

- The group ids are saved in `infra/out/<env>/state.json`, and the script is safe to re-run.
- **Roles needed:** Groups Administrator or User Administrator (or a tenant setting that lets users create security groups) to create groups, plus owner of the enterprise app or Cloud Application Administrator to assign roles. If group creation is refused, `up.sh` warns, writes the exact commands into `infra/out/<env>/handoff.md` and carries on.
- Skip the step with `BB_GROUPS=0` if you assign roles some other way. [`assign-roles.sh`](../infra/assign-roles.sh) still works for any user, group or service principal.

**Licensing and limits**

- Assigning app roles to groups needs **Microsoft Entra ID P1** (or a licence that includes it).
- **Nested groups are not honoured.** Members of a group inside a role-assigned group get no role, so add people to the role-assigned group directly.
- Use **security groups** (not Microsoft 365 groups) if you want PIM for Groups. Dynamic membership groups work, but think carefully before you make approvers dynamic.

---

## Conditional Access baseline

[`infra/conditional-access.sh`](../infra/conditional-access.sh) (run by a **Conditional Access Administrator**) renders three policies, scoped to the blueboard application and the three groups:

| # | Policy | Applies to | Grant |
|---|---|---|---|
| 1 | Phishing-resistant MFA | Analysts, approvers and admins | Authentication strength *Phishing-resistant MFA* (passkeys/FIDO2, Windows Hello for Business, certificate-based). `CA_MFA_STRENGTH=passwordless` or `mfa` relaxes it while you roll out passkeys |
| 2 | Managed device | Approvers and admins | Compliant device **or** Microsoft Entra hybrid joined device |
| 3 | Sign-in frequency | Approvers and admins | Re-authenticate every 4 hours (`CA_SIGNIN_HOURS`, 1–23) |

```sh
# Review only: writes JSON to infra/out/prod/conditional-access/ and prints Microsoft Graph PowerShell commands
BB_ENV=prod CA_EXCLUDE_IDS="<break-glass-1> <break-glass-2>" ./infra/conditional-access.sh

# Create through Microsoft Graph in report-only mode
BB_ENV=prod CA_EXCLUDE_IDS="<break-glass-1> <break-glass-2>" CA_APPLY=1 ./infra/conditional-access.sh

# After reviewing the report-only results in the sign-in logs, enforce
BB_ENV=prod CA_EXCLUDE_IDS="…" CA_APPLY=1 CA_STATE=on ./infra/conditional-access.sh
```

- **Always exclude your break-glass accounts** with `CA_EXCLUDE_IDS`.
- Leave the policies in report-only for at least a few days and check **Entra admin centre → Sign-in logs → Report-only** before enforcing them.
- Your organisation-wide policies (block legacy authentication, sign-in risk, location) still apply on top. Consider adding sign-in risk and user risk policies for approvers if you hold Entra ID P2.

---

## Just-in-time approvers and admins with PIM for Groups

With **Microsoft Entra ID P2** (or ID Governance), make membership of the approvers and admins groups **eligible** rather than permanent, using [PIM for Groups](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/concept-pim-for-groups):

1. Entra admin centre → **Identity Governance → Privileged Identity Management → Groups**. Bring `blueboard-<env>-approvers` and `blueboard-<env>-admins` under management.
2. Make leads **eligible members**, with an activation of up to 8 hours, a justification, and MFA on activation (optionally approval for admins).
3. Keep **analysts** permanent. They need the board all day, and they can't approve anything.

**Activation takes effect at the next token.** blueboard reads roles from the access token, so after activating, the person must **sign out and in again** (or wait for their token to renew, up to about 60–90 minutes) before **Approvals** works. Likewise, when an activation ends, the role disappears at the next token. Put this in your approver runbook.

Keep at least **two** people able to approve at any time (eligible counts, if they can activate quickly). See the separation of duties section below.

---

## Access reviews and break-glass accounts

- **Access reviews** (Entra ID Governance): review the approvers and admins groups **quarterly** and analysts half-yearly. Reviewers should be the SOC manager, with *auto-apply results* and *remove access if reviewers don't respond* switched on for approvers and admins.
- **Break-glass accounts** should **not** be board members. Exclude them from the blueboard Conditional Access policies (so the policies can't lock them out of Entra when misconfigured), and list them in `protected_users` in `policy.json`, so the board can never disable, reset or revoke them.
- The board's own operators (admins) belong in `protected_users` too, so a compromised agent can't propose disabling the people who would stop it.

---

## Agent identities

AI agents are **not** added to groups. Each agent gets its own Entra identity, and its roles are assigned **directly**:

| Identity type | When |
|---|---|
| **Managed identity** | The agent runs in Azure (Container Apps, Functions, VM, AKS with workload identity) |
| **Workload identity federation** | The agent runs in GitHub Actions, Kubernetes or another OIDC issuer |
| **Microsoft Entra Agent ID** | Your tenant manages agents as first-class identities, with sponsors and lifecycle |

```sh
BB_ENV=prod ./infra/assign-roles.sh <agent-service-principal-object-id> Board.Post Board.Hunt Board.RequestActions
# or at deploy time:
BB_ENV=prod AGENT_PRINCIPAL_IDS="<sp-1> <sp-2>" ./infra/up.sh
```

- **Never a client secret.** Use managed identity or federation.
- **Never `Board.Approve` or `Board.Admin`.** They are user-only roles, `assign-roles.sh` refuses them, and the API removes them from app-only tokens regardless.
- Agents can't approve over MCP at all. With `act_on_instruction` in policy, an agent may act on a **human approver's** board message, which is recorded as that person's approval (`on_behalf_of`). See [POLICY.md](POLICY.md).
- Optional: **Conditional Access for workload identities** (Workload Identities Premium) can restrict where agent service principals sign in from.
- See [AGENTS.md](AGENTS.md) to connect an agent.

---

## Offboarding and emergency removal

| Situation | Action | Takes effect |
|---|---|---|
| Person leaves the SOC | Remove them from the blueboard groups (or let your leaver process disable the account) | Their next token has no board roles: within about 60–90 minutes. Disabling the Entra account and revoking sessions also stops token renewal |
| Person or agent must stop **now** | Board admin: **Admin → Participants → Disable** (needs a reason) | **Immediately.** The board checks `enabled` on every request. The participant's open claims are released, and their webhook subscriptions are switched off |
| Agent compromised | Disable the participant on the board, then disable its service principal in Entra (or remove its role assignments) | Board: immediately. Entra: at the agent's next token |
| Brokered writes must stop | Board admin: **Admin → Participants → Pause broker** | Immediately, on every instance. Approved actions are held, not run |

Every disable, enable and pause is written to the append-only `audit_log` and announced in `#general`.

---

## Separation of duties and the audit trail

- **No self-approval.** The database refuses an approval when the approver is the requester (`requested_by <> approver`), so even an approver who requests can't approve their own action.
- **At least two human approvers.** The setup check **Access (separation of duties)** on `/setup` (and `blueboard doctor`) warns when fewer than two enabled human approvers are known, because then requests from the only approver could never be approved.
- **Two approvers per action** for the most destructive kinds (`two_approvers` in policy), and **typed target confirmation** (`confirm_target`) so approvers can't approve on autopilot. See [POLICY.md](POLICY.md).
- **Approvals expire** after 4 hours and are re-checked against policy at approval time.
- **Audit trail.** Every request, approval, denial, execution result, participant change and broker pause is written to `audit_log`. That table is append-only for every database role (`db/migrations/009`). In the production profile it is also exported to Microsoft Sentinel (`BlueboardAudit_CL`), so you can answer *who requested, who approved, when, and what ran* from your SIEM. See [OPERATIONS.md § Audit log in Microsoft Sentinel](OPERATIONS.md#audit-log-in-microsoft-sentinel).
- **Sign-in evidence** stays in Entra: sign-in logs and Conditional Access results show how each approver authenticated.

Related: [QUICKSTART-AZURE.md](QUICKSTART-AZURE.md) · [DEPLOYMENT.md § Roles required](DEPLOYMENT.md#roles-required) · [SECURITY.md](SECURITY.md) · [THREAT-MODEL.md](THREAT-MODEL.md)
