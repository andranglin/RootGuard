# Lab 03: Kerberos Logon Triage Case Study

**Level:** Intermediate · **Data:** Synthetic · **Validation:** Reasoning exercise, not production telemetry testing.

## Scenario

An analyst investigates an unusual burst of successful Kerberos-authenticated network logons to a resource server. Determine which source is unusual and what additional evidence is needed before suspecting ticket forgery.

## Synthetic KQL

```kusto
let HostLogons = datatable(TimeGenerated:datetime, Computer:string,
    Account:string, Source:string, LogonType:int)[
  datetime(2026-10-20T11:00:00Z), "FILE01", "CONTOSO\\analyst1", "192.0.2.30", 3,
  datetime(2026-10-20T11:01:00Z), "FILE01", "CONTOSO\\analyst2", "192.0.2.30", 3,
  datetime(2026-10-20T11:02:00Z), "FILE01", "CONTOSO\\admin1", "192.0.2.30", 3,
  datetime(2026-10-20T11:03:00Z), "FILE01", "CONTOSO\\analyst3", "192.0.2.30", 3,
  datetime(2026-10-20T11:04:00Z), "FILE01", "CONTOSO\\analyst1", "198.51.100.10", 3
];
HostLogons
| summarize Logons=count(), DistinctAccounts=dcount(Account),
            Accounts=make_set(Account, 20)
    by Computer, Source, bin(TimeGenerated, 1h)
| order by DistinctAccounts desc
```

## Expected findings

The synthetic source `192.0.2.30` produces four events involving four different accounts; `198.51.100.10` produces one event. The pattern deserves investigation but **does not prove a forged ticket**. Review device ownership, jump-server or NAT behaviour, original Security Event 4624 data, DC 4769 records and application evidence.

## Deliverable

Write an analyst note distinguishing **observation**, **hypothesis** and **confirmed conclusion**, and explain why missing DC evidence is insufficient for a Silver Ticket determination.

Related: [Silver Ticket guidance](../detection-engineering/threat-detection/ad-detections-and-mitigations/silver-ticket.md).
