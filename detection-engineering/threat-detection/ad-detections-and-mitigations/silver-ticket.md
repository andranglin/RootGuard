# Silver Ticket: Detection and Response

**ATT&CK:** [T1558.002](https://attack.mitre.org/techniques/T1558/002/) 
**Reviewed:** 20 October 2026 
**Validation:** Concept / unvalidated; verify on representative services.

## Threat overview

A Silver Ticket is a forged Kerberos service ticket created using a compromised service key. Its scope is tied to the targeted service and key, unlike a Golden Ticket using `krbtgt` material. Some services may accept a forged ticket without the expected KDC exchange, although PAC validation and modern service protections can alter that behaviour. Successful access is not guaranteed.

## Detection hypothesis

A target host or application records unexpected Kerberos-authenticated access without a corresponding service-ticket request visible at the domain controllers, supported by suspicious service-account or endpoint behaviour.

**Critical limitation:** Missing Event 4769 is not proof of a Silver Ticket. DC logs may be incomplete, ticket requests can predate the investigated event, and the request may have been processed by another DC.

## Prerequisites

- Windows target-server Security Event **4624**, with details such as logon type, account, authentication package and source address.
- Domain controller Event **4769** where collected, application/service audit logs, and endpoint telemetry.
- Service identity/SPN inventory and information about the suspected service-key exposure.

## KQL: Review Kerberos-authenticated target logons

The following is an **unvalidated triage query**, not a Silver Ticket detector. Field availability varies by the `SecurityEvent` collection path.

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where AuthenticationPackageName =~ "Kerberos"
| extend AccountName = tostring(Account),
 SourceAddress = tostring(IpAddress)
| summarize Logons=count(), Accounts=make_set(AccountName, 30),
 Sources=make_set(SourceAddress, 20)
 by Computer, LogonType, bin(TimeGenerated, 1h)
| order by Logons desc
```

Use the output to select unusual resource-server authentication events and correlate manually with DC service-ticket requests. A count-based query cannot establish that a ticket was forged.

## Analyst response

1. Review full Event 4624 records and identify service, account, logon type and source.
2. Inspect application access logs and independent endpoint activity.
3. Compare with available DC 4769 events, accounting for missing telemetry and ticket reuse.
4. Investigate service-account credentials, SPNs, delegation settings and relevant encryption keys.
5. If service-key compromise is suspected, follow approved rotation and incident containment procedures; assess dependent workloads before changing credentials.

## Defensive controls

Prioritise gMSAs and long, managed service secrets where supported; enforce least privilege, restrict administrative access to service hosts, collect resource-server authentication logs and use supported Kerberos hardening controls with compatibility tests.

## References

- [MITRE ATT&CK: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/)
- [Microsoft: Event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Detection Validation Checklist](../detection-validation-checklist.md)
