---
id: azure-privilege-escalation
title: Azure & Defender for Cloud privilege escalation
priority: 20
match:
  titles: ["Key Vault", "role assignment", "privilege escalation in Azure", "Global Administrator", "Owner role", "subscription admin"]
  techniques: ["T1098.003", "T1552.005", "T1078.004"]
  service_sources: ["microsoftDefenderForCloud"]
steps:
  - id: scope-arm-activity
    stage: triage
    title: Audit Azure Activity, RBAC changes and Key Vault access
    detail: Use run_sentinel_query against AzureActivity, AuditLogs and AzureDiagnostics (KeyVault) for the caller identity, subscription and resource group over the last 72h. Post a finding with every write/elevate operation.
  - id: inspect-identity
    stage: investigate
    title: Inspect the calling user or service principal and its sign-in origin
    detail: Call lookup_entity (user or service_principal) and correlate CallerIpAddress / user-agent against known CI/CD runners, jump hosts and PIM activations.
    after: [scope-arm-activity]
  - id: check-blast-radius
    stage: investigate
    title: Identify newly created credentials, VMs, automation accounts or federated trusts
    detail: Check AzureActivity and AuditLogs for new role assignments, storage SAS/keys listed, VM RunCommand executions, or new federated identity credentials.
    after: [scope-arm-activity]
  - id: contain-identity
    stage: contain
    title: Revoke sessions or disable the compromised cloud identity
    detail: For a human account request revoke_sessions / disable_user; for a workload identity request disable_service_principal. Verify protected_users first.
    after: [inspect-identity]
    suggested_action: revoke_sessions
  - id: publish-iocs
    stage: contain
    title: Publish confirmed attacker IPs to Sentinel Threat Intelligence
    after: [inspect-identity, check-blast-radius]
    suggested_action: publish_ti_indicator
  - id: record
    stage: record
    title: Post verdict, remediation steps for cloud owners and update incident
    after: [contain-identity, publish-iocs]
    suggested_action: add_incident_comment
---

# Azure & Defender for Cloud privilege escalation

Use this for Microsoft Defender for Cloud and Microsoft Sentinel incidents involving Azure RBAC elevation (`T1098.003`), Key Vault secret enumeration (`T1552.005`), or suspicious control-plane operations (`AzureActivity`).
