---
id: oauth-app-consent-abuse
title: Illicit OAuth consent grant & service principal abuse
priority: 25
match:
  titles: ["OAuth", "consent grant", "illicit consent", "malicious application", "service principal", "application credential"]
  techniques: ["T1528", "T1550.001", "T1098.001"]
steps:
  - id: inspect-app
    stage: triage
    title: Inspect the OAuth application or service principal
    detail: Call lookup_entity with kind=service_principal (or oauth_app) to inspect publisher verification, creation date, reply URLs, delegated oauth_grants and app_role_assignments. Post a finding.
  - id: scope-consents
    stage: investigate
    title: Find every user who consented and what permissions were granted
    detail: Query AuditLogs (Sentinel) or CloudAppEvents for 'Consent to application', 'Add delegated permission grant', 'Add app role assignment', and 'Add service principal credentials'. Flag high-risk scopes (Mail.Read, Files.Read.All, Directory.ReadWrite.All, offline_access).
    after: [inspect-app]
  - id: audit-app-activity
    stage: investigate
    title: Audit Graph, Exchange and SharePoint activity performed by the app
    detail: Query MicrosoftGraphActivityLogs, OfficeActivity (MailItemsAccessed) and AADServicePrincipalSignInLogs (Sentinel) for the appId / servicePrincipalId.
    after: [inspect-app]
  - id: disable-sp
    stage: contain
    title: Disable the malicious service principal in Entra ID
    detail: Stops the app from obtaining new tokens tenant-wide. Verify it is not a business-critical internal app before requesting.
    after: [scope-consents]
    suggested_action: disable_service_principal
  - id: revoke-users
    stage: contain
    title: Revoke sessions for users who consented to the malicious app
    after: [scope-consents]
    suggested_action: revoke_sessions
  - id: block-reply-urls
    stage: contain
    title: Block attacker reply URLs / phishing domains in Defender
    after: [inspect-app, audit-app-activity]
    suggested_action: block_indicator
  - id: record
    stage: record
    title: Post verdict, exposed data summary and update Defender / Sentinel incident
    after: [disable-sp, revoke-users, block-reply-urls]
    suggested_action: add_incident_comment
---

# Illicit OAuth consent grant & service principal abuse

Use this when a user consents to an unverified OAuth app requesting Mail/Files/Graph scopes, or when a service principal has unexpected credentials added (`T1098.001`) or anomalous sign-ins (`T1528`).
