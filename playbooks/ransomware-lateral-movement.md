---
id: ransomware-lateral-movement
title: Ransomware, credential theft & lateral movement
priority: 30
match:
  titles: ["ransomware", "shadow copy", "vssadmin", "LSASS", "credential dump", "lateral movement", "PsExec", "human-operated"]
  techniques: ["T1486", "T1490", "T1003", "T1021"]
steps:
  - id: scope-patient-zero
    stage: triage
    title: Identify patient zero, execution chain and compromised accounts
    detail: Inspect DeviceProcessEvents and DeviceLogonEvents around the first alert. Identify the initial access vector, parent process tree, and every account logged on to the host (especially privileged/domain admin sessions).
  - id: collect-forensics
    stage: contain
    title: Collect forensic investigation package before remediation
    detail: Preserve volatile evidence and process/registry artefacts from the affected endpoint(s).
    suggested_action: collect_investigation_package
  - id: isolate-host
    stage: contain
    title: Isolate compromised endpoint(s) from the network
    detail: Use Full isolation for workstations; evaluate Selective isolation or restrict_app_execution for critical servers if approved by incident commander.
    after: [scope-patient-zero]
    suggested_action: isolate_device
  - id: hunt-lateral
    stage: investigate
    title: Hunt for lateral movement, SMB/WMI/RDP hops and credential reuse
    detail: Query DeviceNetworkEvents (ports 445, 3389, 5985/5986, 135), DeviceLogonEvents, and IdentityLogonEvents across the fleet for the same compromised accounts, hashes, or source IP.
    after: [scope-patient-zero]
  - id: contain-accounts
    stage: contain
    title: Disable or revoke sessions for exposed privileged accounts
    detail: Check policy protected_users before requesting; coordinate break-glass / KRBTGT reset with AD admins if domain admin credentials were exposed in LSASS.
    after: [hunt-lateral]
    suggested_action: revoke_sessions
  - id: eradicate-payload
    stage: eradicate
    title: Quarantine malicious binaries and block C2 / staging indicators
    detail: Use stop_and_quarantine_file for confirmed malicious SHA-1 binaries and block_indicator for C2 IPs/domains/hashes.
    after: [isolate-host, hunt-lateral]
    suggested_action: block_indicator
  - id: scan-verify
    stage: recover
    title: Run full AV scan and verify clean state before releasing isolation
    after: [eradicate-payload]
    suggested_action: run_av_scan
  - id: record
    stage: record
    title: Post final verdict, timeline and update Defender / Sentinel incident
    after: [scan-verify, contain-accounts, collect-forensics]
    suggested_action: add_incident_comment
---

# Ransomware, credential theft & lateral movement

High-priority response checklist for human-operated ransomware precursors: LSASS dumping (`T1003`), lateral movement (`T1021`), shadow copy deletion (`T1490`), or mass file encryption (`T1486`).

Collect forensics early, isolate fast, and hunt across the fleet before assuming the incident is contained to a single host.
