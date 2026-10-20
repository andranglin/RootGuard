# Lateral Movement: End-to-End Investigation

**Status:** Operational framework, not production-validated. **Reviewed:** 20 October 2026. **Owner:** Incident Commander / CSIRT.

> Preserve evidence, record UTC times and approvals, and do not delay urgent containment when material harm is ongoing. All example queries require schema, permission and environmental validation.

## Incident command and recordkeeping

Record incident ID, trigger, affected business services, severity, roles, initial scope and confidence. Maintain a decision log with timestamps, approvers, evidence references, operational impact and communications. Assign SOC investigation, endpoint/identity response, legal/privacy, business recovery and executive liaison roles as needed.


## 1. Trigger and assessment

Unexpected remote logons, service creation, RDP, SMB, WinRM, WMI, remote PowerShell or cross-host privileged access. Legitimate IT administration and automation can appear similar.

**Telemetry:** Source/target Windows Security 4624 and 4648, System 7045 where configured, Sysmon if deployed, Defender `DeviceProcessEvents` and `DeviceNetworkEvents`, network flows and change records.

### Illustrative process hunting

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("psexec.exe", "wmic.exe", "winrs.exe", "mstsc.exe")
    or ProcessCommandLine has_any ("Invoke-Command", "Enter-PSSession")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, ReportId
| order by Timestamp desc
```

This is a noisy investigative pivot, not a comprehensive malicious movement detector. Tools may be renamed and remote APIs used without these executables.

## 2. Verify and scope

1. Record source, target, time, account, protocol and claimed activity.
2. Confirm whether successful authentication and execution occurred; connections alone cannot prove execution.
3. Correlate host process, target service, task, PowerShell and logon telemetry.
4. Build a timestamped host-to-host movement graph identifying privilege changes and exposed identities.
5. Check access to domain controllers, administrative platforms, file servers, backup systems and sensitive data.
6. Record changes approved by IT operations to avoid false attribution.

## 3. Containment

Restrict confirmed compromised hosts and privileged accounts through approved endpoint and identity processes. Coordinate restrictions on remote administration, preserving legitimate emergency-management channels. Capture necessary volatile evidence when safe; do not delay urgent containment if spread continues.

## 4. Eradication

Remove attacker-created tasks, services and tooling after forensic preservation. Rotate exposed credentials, remediate exploited access, audit privileged group membership and improve tiered administration. Check all known hop endpoints for persistence, not just the triggering host.

## 5. Recovery

Return cleaned/rebuilt hosts and accounts to service in dependency order, with validated remote administration baselines, access control and EDR coverage. Monitor for renewed logons, new services, process execution and abnormal east-west connections.

## 6. Closure

Document graph of confirmed/probable movement, initial access hypothesis, attacker objectives, evidence gaps, lateral techniques, business impact and control improvements.

**Exit criteria:** No known unauthorised movement path remains, exposed privileges addressed, hosts restored with owner approval, heightened monitoring established.

[Lateral movement runbook](../runbooks/lateral-movement-investigation-runbook.md) · [Windows artefact interpretation](../field-guides/windows-artifact-interpretation.md)
