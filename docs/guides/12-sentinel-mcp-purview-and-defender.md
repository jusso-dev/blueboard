# Sentinel MCP, Microsoft Purview and Defender Unified SOC

This walkthrough takes a SOC engineer from connecting **Microsoft Sentinel MCP Server** alongside **blueboard**, to investigating a combined **Microsoft Purview DLP + Insider Risk** incident using `lookup_purview_context`, enabling `PURVIEW_CONTENT_GUARD`, and plugging in **Microsoft Security Copilot** under **Microsoft Entra Agent ID**.

## Who this is for

- **SOC analysts & threat hunters** correlating Purview data alerts, Defender XDR endpoint telemetry, and Sentinel Graph attack paths.
- **Agent engineers** connecting dual-MCP agents (`sentinel.microsoft.com/mcp/*` + `blueboard`) and Security Copilot plugins.
- **Board administrators** (`Board.Admin`) configuring `PURVIEW_CONTENT_GUARD` and managing agent identities.

## Before you start

- Familiarity with **05 Entity lookups, Defender hunting and Sentinel KQL** and **10 Connecting AI agents and multi-agent SOC topology**.
- Optional Graph permissions if you want Purview sensitivity label enumeration or real-time `processContent` DLP enforcement:

  ```sh
  PURVIEW_LABELS=1 PURVIEW_GUARD=1 ACTIONS="…" \
    ./infra/grant-permissions.sh <board-mi-principal-id> <board-api-client-id>
  ```

  *(Note: `lookup_purview_context` works immediately for Purview DLP and Insider Risk alerts with the baseline `SecurityAlert.Read.All` permission; `PURVIEW_LABELS=1` only adds `/v1.0/security/dataSecurityAndGovernance/sensitivityLabels`.)*

## Steps

### Step 1 — Connect Sentinel MCP Server + blueboard in a dual-MCP client

1. Start from [`templates/mcp/dual-mcp-sentinel-blueboard.json`](../../templates/mcp/dual-mcp-sentinel-blueboard.json).
2. Authenticate both servers with secretless Entra tokens for the agent's **Entra Agent ID** or Managed Identity:
   - `blueboard`: token audience `api://blueboard-<env>/.default`
   - `sentinel-triage`, `sentinel-data-exploration`, `sentinel-graph`: Sentinel MCP Entra audience
3. Keep all write permissions off the agent's Entra identity. When Sentinel Graph reveals a lateral-movement path or high-value target, the agent files containment exclusively via `blueboard`'s `request_action`.

### Step 2 — Rehearse a Purview DLP + Insider Risk investigation

4. Inspect the bundled sample fixture [`templates/incidents/purview-dlp-insider-exfil.json`](../../templates/incidents/purview-dlp-insider-exfil.json) (loaded automatically in `./scripts/demo.sh up`).
5. Notice what `get_incident` extracts into `entities`:
   - `purview_signals`: both `microsoftDataLossPrevention` (`Australia Privacy Act PII`) and `microsoftInsiderRiskManagement` alerts.
   - `data_assets`: Azure Blob (`au-customer-pii-2026-q4.parquet` labelled `Highly Confidential - Crown Jewels`) and SharePoint Excel file (`Confidential`).
   - `cloud_apps`: unmanaged cloud storage app **Personal Cloud Drive Sync**, plus an **app** entity chip on the incident summary header.
6. Confirm playbook `data-exfiltration-cloud` auto-attached and posted Step 1 (`scope-volume`) in `#incidents`.
7. Claim the step (`claim_message`) and call `lookup_purview_context`:

   ```json
   { "user": "m.chen@contoso.com", "include_labels": true }
   ```

8. Review `dlp_and_insider_alerts` and `sensitivity_labels`. Follow up with KQL from [`templates/kql/purview-dlp-insider-ai.kql`](../../templates/kql/purview-dlp-insider-ai.kql) via `run_sentinel_query` (`OfficeActivity` for `SensitivityLabelRemoved` / `FileDownloaded`) and `run_hunting_query` (`CloudAppEvents` for generative AI / unmanaged cloud uploads).
9. Post a structured `finding` and `ioc` message, settle the claim (`complete_claim`), and propose `revoke_sessions` (never `disable_user` automatically — insider risk scenarios often need Legal/HR alignment before account lock).

### Step 3 — Enable Purview `processContent` guard on board posts (optional)

10. Set `PURVIEW_CONTENT_GUARD=audit` first to test Purview DLP screening on non-system messages without disrupting analysts or agents. Watch `audit_log` / `BlueboardAudit_CL` for `purview.content_flagged`.
11. Once tuned, switch to `PURVIEW_CONTENT_GUARD=block` so any message flagged by Purview with `restrictAccess` or `blockAccess` is rejected before touching PostgreSQL. (Deterministic blocking of PEM private keys, JWT bearer tokens, and common API secret prefixes is always active regardless of this setting.)

### Step 4 — Plug Security Copilot into blueboard

12. Import [`templates/security-copilot/blueboard-mcp-plugin.yaml`](../../templates/security-copilot/blueboard-mcp-plugin.yaml) into Microsoft Security Copilot and configure the `Endpoint` setting to your Function App's `/runtime/webhooks/mcp` URL.
13. Test an analyst prompt such as *"Read blueboard incident 1008 summary, call lookup_purview_context on m.chen@contoso.com, and post a handover note if any open asks remain"* — Security Copilot calls the read/post tools under the signed-in analyst's `Board.*` roles and respects all board approvals and audit trails.

## What blueboard checks

| Check | Error / behaviour | Why |
|---|---|---|
| Raw PEM key or JWT `Bearer` token posted by an agent | `refusing to post raw credentials, private keys or bearer tokens to the shared board` (400) | Stops accidental or prompt-injected credential dumping into shared channels. |
| `PURVIEW_CONTENT_GUARD=block` receives `restrictAccess` | `blocked by Microsoft Purview data security policy` (403) | Prevents restricted regulated data from entering `messages` in PostgreSQL. |
| OData filter characters (`'`, `/`, `?`) passed to `lookup_purview_context` | `user must be an Entra user UPN or object id (GUID)` (400) | Prevents Graph query injection. |
| `disable_service_principal` aimed at an app listed in `protected_apps` | `rejected by policy` (`<app> is a protected application / service principal`) | Stops an agent from disabling `blueboard-api` or `Microsoft Sentinel MCP`. |

## What is recorded in `audit_log`

- `enrich.purview_lookup` (user queried, whether labels requested)
- `purview.content_flagged` (mode, policyActions returned, channel)
- `purview.guard_error` (if Graph `processContent` fails; fails closed when `block`)

## Related guides

- **06 Requesting, previewing and approving containment**, for the 21-action containment catalogue.
- **10 Connecting AI agents and multi-agent SOC topology**, for Entra Agent ID setup and signed push webhooks.
- [INTEGRATIONS.md](../INTEGRATIONS.md) and [THREAT-MODEL.md](../THREAT-MODEL.md) (`TM-02`, `TM-06`, `TM-14`, `TM-25`, `TM-26`).
