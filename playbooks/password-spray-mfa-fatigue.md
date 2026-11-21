---
id: password-spray-mfa-fatigue
title: Password spray, credential stuffing & MFA fatigue
priority: 15
match:
  titles: ["MFA fatigue", "MFA spam", "multiple MFA", "credential stuffing", "brute force"]
  techniques: ["T1110.003", "T1110.004", "T1621"]
steps:
  - id: scope-campaign
    stage: triage
    title: Quantify targeted accounts, source IPs and error codes
    detail: Query AADSignInEventsBeta / SigninLogs for the source IPs and targeted users. Separate failed attempts (50126, 50053, 50074) from ANY successful sign-in (ErrorCode == 0) or MFA approval. Post a finding.
  - id: identify-compromised
    stage: investigate
    title: Identify any account with a successful sign-in or MFA prompt accepted
    detail: For any user who succeeded or accepted an MFA prompt from an attacker IP, check subsequent AuditLogs (new MFA devices, inbox rules) and SigninLogs.
    after: [scope-campaign]
  - id: confirm-risk
    stage: contain
    title: Mark compromised user(s) as High risk in Entra ID Protection
    after: [identify-compromised]
    suggested_action: confirm_user_compromised
  - id: revoke-and-reset
    stage: eradicate
    title: Revoke sessions and force password reset for compromised accounts
    after: [identify-compromised]
    suggested_action: revoke_sessions
  - id: block-source-ips
    stage: contain
    title: Block dedicated attacker infrastructure if non-shared
    detail: Verify source IPs are not shared corporate VPNs, residential proxies, or ISP NATs before requesting block_indicator or publish_ti_indicator.
    after: [scope-campaign]
    suggested_action: block_indicator
  - id: record
    stage: record
    title: Post verdict and document targeted vs compromised accounts on the incident
    after: [confirm-risk, revoke-and-reset, block-source-ips]
    suggested_action: add_incident_comment
---

# Password spray, credential stuffing & MFA fatigue

Use this for password spraying (`T1110.003`), credential stuffing (`T1110.004`), and MFA push-bombing (`T1621`). The top priority is distinguishing noisy failed attempts from the one account that succeeded.
