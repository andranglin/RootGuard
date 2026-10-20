# Golden Ticket: Detection and Response

> **RootGuard technical reference** · **Environment:** Verify product, platform and telemetry prerequisites · **Validation:** Refer to the status below; examples are not automatically production-ready.

**ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/)  
**Reviewed:** 20 October 2026  
**Validation:** Concept / unvalidated; verify all fields and behaviour in an authorised lab.

## Threat overview

A Golden Ticket is a forged Kerberos ticket-granting ticket (TGT), typically created using compromised `krbtgt` key material. The attacker may construct claims for a principal and use the forged TGT to request service tickets. The resulting access depends on domain policy, ticket validity, cryptographic material, service behaviour and other controls. A forged ticket does **not** guarantee indefinite or unlimited access.

## Investigation hypothesis

Find unusual Kerberos service-ticket or logon behaviour consistent with forged TGT usage, particularly following compromise of a domain controller, replication rights or `krbtgt` credentials. There is no single Windows event ID that definitively establishes a Golden Ticket.

## Required telemetry

- Domain controller Security events **4768** (TGT request) and **4769** (service ticket request) where auditing is enabled.
- Relevant host authentication events **4624**, DC security logs and identity/network telemetry.
- Reliable time synchronisation, domain-controller coverage, retained ticket-related fields and account lifecycle context.

**Caveat:** A missing matching 4768 record for a 4769 event does not prove a forged ticket. The TGT may have been obtained earlier, from another DC, or outside the log retention window.

## Example KQL: Service-ticket activity for investigation

**Status: Concept / unvalidated.** This is an investigation pivot, not a Golden Ticket signature. Confirm that `Account`, `ServiceName` and `IpAddress` are populated in your collected `SecurityEvent` events.

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| extend Requester = tostring(Account),
         Service = tostring(ServiceName),
         SourceAddress = tostring(IpAddress)
| where isnotempty(Requester)
| summarize Requests=count(), DistinctServices=dcount(Service),
            Services=make_set(Service, 30),
            Sources=make_set(SourceAddress, 20)
    by Requester, bin(TimeGenerated, 1h)
| order by DistinctServices desc, Requests desc
```

Review unexpected privileged account activity, unusual services, anomalous sources and changes in account lifecycle state. Baseline common management tools and service workloads before setting thresholds.

## Analyst workflow

1. Preserve DC and affected endpoint logs and record coverage limitations.
2. Investigate the account and relevant Kerberos service-ticket events.
3. Review indicators of domain-controller compromise, directory replication abuse or `krbtgt` key exposure.
4. Correlate suspicious tickets with resource-server logons and endpoint activity.
5. Escalate suspected domain compromise using the organisation's identity recovery procedures.

## Containment and recovery

If `krbtgt` material may be compromised, recovery must be planned across all domain controllers and dependent systems. Microsoft guidance commonly requires **two carefully staged `krbtgt` password resets**, allowing replication and ticket lifetime considerations between changes. Do not reset it twice immediately or without a tested recovery plan. Address the root cause first and verify domain health.

## Limits and references

Ticket anomalies may be benign; these queries are not independently validated. Do not describe missing KDC evidence as proof of forgery.

- [MITRE ATT&CK: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
- [Microsoft: Event 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Detection Validation Checklist](../detection-validation-checklist.md)
