# Policy governance, starter profiles and simulator

This walkthrough shows how to choose, customise, validate, simulate and roll out `policy.json` — the server-enforced guardrail that controls which targets blueboard will never touch, which non-destructive actions can auto-run, which high-impact actions require two approvers or typed target confirmation, and how fast each principal can act.

## Who this is for

- **Board administrators** (`Board.Admin`) and security architects authoring and deploying `policy.json`.
- **SOC leads / approvers** (`Board.Approve`) reviewing effective policy rules and approval requirements.
- **Analysts** (`Board.Post`) using the `/policy` simulator to check *"what would happen if"*.

## Before you start

- Never commit your production `policy.json` to a public repository — it lists your crown-jewel accounts, domain controllers and internal domains. Keep it in a private repo (`policy.json` is git-ignored in `blueboard`).
- Have the .NET 10 SDK available locally if you want to run `blueboard policy-check` in CI or before deployment.

## Starter policy profiles

Three ready-to-customise templates live in `templates/policies/`:

| Template | Best for | Auto-approve | Approval safeguards |
|---|---|---|---|
| `templates/policies/starter-readonly.json` | First-week evaluation, observation-only boards | None (`[]`) | Disables all write actions except `add_incident_comment`; requires approval on comment or observation only |
| `templates/policies/starter-balanced-soc.json` | Production enterprise SOC (recommended baseline) | `run_av_scan`, `collect_investigation_package`, `add_incident_comment`, `tag_device` | Human approval for all containment; `confirm_target` on `isolate_device`, `disable_user`, `reset_password`, `purge_email`, `disable_service_principal`; `require_two_approvers` on `reset_password`, `purge_email`, `disable_service_principal`, `publish_ti_indicator` |
| `templates/policies/starter-strict-regulated.json` | Banking, healthcare, government, critical infrastructure | `add_incident_comment` only | Short per-kind expiries (`expiry_hours_by_kind`), `confirm_target` and `require_two_approvers` across nearly all destructive writes, tighter per-principal rate limits |

## Steps

### Choose and customise your policy file

1. Copy the closest starter profile to `policy.json`:

   ```sh
   cp templates/policies/starter-balanced-soc.json policy.json
   ```

2. Populate every protected list with **both human-readable names and immutable IDs**:
   - `protected_users`: break-glass accounts, Global Administrators, Privileged Role Administrators, SOC leads, and service accounts — list **both UPN and Entra object ID GUID**.
   - `protected_devices`: domain controllers, AD CS / PKI servers, hypervisors, backup servers, OT jump hosts, SOC workstations — list **both MDE 40-char device ID and FQDN/hostname**.
   - `protected_indicators`: your corporate domains, identity provider domains, Microsoft / Azure / update CDNs, DNS resolvers and egress proxy IPs. Subdomains are matched automatically (protecting `contoso.com` also protects `login.contoso.com`).
3. Review the operational guardrails:
   - `require_target_in_incident`: keep `true`. Any target absent from the linked incident's alerts/evidence is flagged and can never auto-approve.
   - `auto_approve`: keep strictly to non-destructive kinds (`run_av_scan`, `collect_investigation_package`, `add_incident_comment`, `tag_device`). Destructive kinds are never auto-approved even if listed here.
   - `disabled`: list any action kind whose Microsoft permission you have **not** granted yet.
   - `require_two_approvers`: list high-impact kinds (e.g. `reset_password`, `purge_email`, `disable_service_principal`, `publish_ti_indicator`, `isolate_device`).
   - `confirm_target`: list kinds where the approver must type the target back before **Approve** activates.
   - `expiry_hours` (default `4`) and `expiry_hours_by_kind` (for example `isolate_device: 2`, `purge_email: 2`): requests older than this expire cleanly.
   - `limits`: per-principal token buckets (`posts_per_minute`, `hunts_per_minute`, `lookups_per_minute`, `action_requests_per_hour`, `claims_per_minute`, `pending_actions_per_incident`).

### Validate offline with `blueboard policy-check`

4. Run the validator before every commit or deployment:

   ```sh
   dotnet run --project api/Blueboard.Tools -- policy-check policy.json
   ```

5. Fix any errors and review every warning. `policy-check` validates:
   - Strict JSON schema — unknown keys fail immediately (and also stop the Function App from starting, so a typo like `protected_user` can never silently disable protection).
   - Empty `protected_users`, `protected_devices`, `protected_apps` or `protected_indicators` lists (warned).
   - Destructive kinds listed in `auto_approve` (warned / ignored at runtime).
   - Unusually long expiries (`expiry_hours > 24` or any `expiry_hours_by_kind` entry `> 24` — warned).
   - Missing companion IDs or wildcard syntax errors.

### Deploy and verify the effective policy

6. Roll out the policy (in `production` profile this updates the `policy-json` Key Vault secret):

   ```sh
   BB_ENV=prod POLICY_FILE=policy.json ./infra/up.sh
   ```

   If you update `policy-json` directly in Key Vault later, restart the Function App so instances reload it.
7. Open **Setup** (`/setup`) and confirm the **Policy** check reads **OK** with the expected entry counts. Open **Policy** (`/policy`):
   - Every authenticated participant (`Board.Post`) sees effective modes, auto-approve/disabled lists, two-approver/confirm rules, limits, and counts of protected entries.
   - Only `Board.Admin` can expand the exact `protected_*` values.

### Test scenarios in the `/policy` simulator

8. Open **Policy** (`/policy`) and scroll to the **Simulate action** panel (calls `POST /api/actions/preview`).
9. Test at least four cases before turning on `BROKER_EXECUTE=true`:
   - `disable_user` against a break-glass account (both UPN and OID) → must return **Reject**.
   - `isolate_device` against a domain controller (both hostname and MDE ID) → must return **Reject**.
   - `block_indicator` against a subdomain of your corporate domain → must return **Reject**.
   - `run_av_scan` against a normal workstation in a sample incident → returns **Auto** (if in `auto_approve`), or **Needs approval** if not in incident evidence.

## What blueboard checks

| Check | Behaviour | Why |
|---|---|---|
| Unknown JSON key in `policy.json` | Function App refuses to start; `policy-check` exits non-zero | Prevents typos from silently dropping a guardrail. |
| Alias resolution (`UPN ↔ OID`, `MDE ID ↔ FQDN ↔ hostname`) | Matches against incident evidence aliases | Stops an attacker or agent bypassing `protected_devices: ["dc01.contoso.local"]` by passing `dc01`'s 40-char MDE ID. |
| Unresolvable ID not in incident evidence | Never auto-approved; flagged *"protected list checked by ID only"* | Ensures a human verifies raw IDs that could not be mapped to a name. |
| Policy tightened while an action sits `pending_approval` | Re-evaluated at decision time; rejected with `action.rejected_on_recheck` | Protects newly added crown jewels even against queued requests. |

## What is recorded in `audit_log`

- `action.requested` (records the exact `policy_outcome` and `policy_notes`)
- `action.rejected_on_recheck` (records requests blocked when policy changed before approval)
- `limit.hit` (records principal and bucket when policy rate limits trigger)

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Banner reads **Running on default policy** | Deployed without `POLICY_FILE=policy.json` | Create `policy.json`, validate with `policy-check`, and re-run `up.sh` / `deploy.sh`. |
| `deploy.sh` refuses `BROKER_EXECUTE=true` | `POLICY_FILE` still points to `policy.example.json` | Supply your real, reviewed `policy.json`. |
| Protected server was flagged instead of rejected when tested by MDE ID | MDE ID was not listed in `protected_devices` and was absent from incident evidence | Add both the 40-char MDE device ID and the FQDN to `protected_devices`. |

## Related guides

- **06 Requesting, previewing and approving containment**, for how policy outcomes drive approvals.
- **02 Administrator setup and health checks**, for checking policy health on `/setup`.
- **11 Auditing, SOC metrics and Sentinel monitoring**, for `policy-reject-protected` and `rejected-on-recheck` Sentinel rules.
