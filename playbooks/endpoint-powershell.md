---
id: endpoint-powershell
title: Malicious PowerShell on an endpoint
match:
  categories: ["Execution"]
  titles: ["PowerShell", "download cradle", "encoded command"]
  techniques: ["T1059.001"]
steps:
  - id: review-command
    stage: triage
    title: Decode and explain the command line
    detail: Decode any encoded command. Post what it does, what it downloaded and from where, as a finding.
  - id: scope-device
    stage: investigate
    title: Scope activity on the device
    detail: Process tree, network connections, new services, scheduled tasks and run keys around the alert time.
  - id: hunt-fleet
    stage: investigate
    title: Hunt for the same activity on other devices
    detail: Search DeviceProcessEvents and DeviceNetworkEvents for the same command, hash or domain across the fleet.
    after: [review-command]
  - id: isolate
    stage: contain
    title: Isolate the device if it is compromised
    after: [scope-device]
    suggested_action: isolate_device
  - id: block-iocs
    stage: contain
    title: Block the download URL, domain and file hashes
    after: [review-command]
    suggested_action: block_indicator
  - id: scan
    stage: eradicate
    title: Run a full antivirus scan and confirm it is clean
    after: [isolate]
    suggested_action: run_av_scan
  - id: record
    stage: record
    title: Post a verdict and note the outcome on the Defender incident
    after: [scan, hunt-fleet, block-iocs]
    suggested_action: add_incident_comment
---

# Malicious PowerShell on an endpoint

Use this for Defender for Endpoint alerts on suspicious PowerShell: download cradles, encoded commands, or script
execution that fetches a payload.
