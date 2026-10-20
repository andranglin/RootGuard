# Ransomware: End-to-End Investigation

**Status:** Operational framework, not production-validated. **Reviewed:** 20 October 2026. **Owner:** Incident Commander / CSIRT.

> Preserve evidence, record UTC times and approvals, and do not delay urgent containment when material harm is ongoing. All example queries require schema, permission and environmental validation.

## Incident command and recordkeeping

Record incident ID, trigger, affected business services, severity, roles, initial scope and confidence. Maintain a decision log with timestamps, approvers, evidence references, operational impact and communications. Assign SOC investigation, endpoint/identity response, legal/privacy, business recovery and executive liaison roles as needed.


## 1. Detection and declaration

**Triggers:** Encryption alerts, mass file modifications, ransom notes, suspicious backups deletion, unusual remote execution or an extortion notice. Activate incident command; prioritise people, critical services and prevention of further propagation.

**Telemetry:** Defender XDR `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`; EDR alerts; Windows logs; identity events; hypervisor, backup, firewall and cloud audit evidence. Verify each source and retention.

### Illustrative endpoint hunting

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("vssadmin", "wbadmin", "bcdedit")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, ReportId
| order by Timestamp desc
```

This is a high-noise administrative-utility search, **not** a ransomware detection rule. Benign actions may match; many destructive methods will not.

## 2. Triage and scope

1. Verify affected hosts and shares and whether encryption or spread is active.
2. Identify critical identity, backup, virtualisation and management infrastructure at risk.
3. Preserve representative process trees, ransom notes, file samples and timeline details through authorised collection.
4. Trace likely initial access, privileges, credential abuse, persistence and remote execution without assuming the first encrypted host was the entry point.
5. Examine possible exfiltration independently using file, network and cloud evidence; record what cannot be established.

## 3. Containment

Isolate confirmed impacted hosts and restrict propagation routes using approved emergency procedures; safeguard backup and identity management systems. Weigh evidence preservation against ongoing damage. Coordinate privileged account restrictions, network segmentation and recovery access with system owners. Avoid indiscriminate shutdown or domain-wide changes without incident-command authorisation.

## 4. Eradication and recovery

Identify and remediate initial access and persistence, remove unauthorised tooling, rotate exposed secrets, rebuild affected hosts from trusted baselines and restore **verified** clean backups. Stage recovery by business dependency; validate data integrity, logging, endpoint protections and administrator access before reconnecting systems.

## 5. External engagement and closure

Assess data exposure and applicable notification requirements with privacy/legal teams; record insurer, law enforcement and extortion-response decisions. Payment is not an assurance of recovery. Maintain enhanced monitoring and conduct a cross-functional lessons-learned review.

**Exit criteria:** Spread contained, attacker pathways removed, backups and service restoration tested, ownership sign-off, recurrence monitoring and corrective actions assigned.

[Detailed ransomware runbook](../runbooks/ransomware-investigation-and-response-runbook.md) · [Evidence integrity](../field-guides/evidence-acquisition-and-integrity.md)
