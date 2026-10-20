# Lab 02: Kerberos Ticket Investigation

**Type:** Read-only analysis of synthetic telemetry  
**Level:** Intermediate  
**ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)  
**Status:** Synthetic learning exercise, not validation of production telemetry

## Objective

Identify a source with an unusual spread of service-ticket requests, investigate alternative explanations and propose telemetry needed to validate the Kerberoasting hypothesis.

## Scenario

Synthetic Windows domain-controller event records show two requesting accounts: a maintenance service requesting several SPNs and an ordinary workstation user requesting a smaller set of service SPNs. Determine which observations deserve follow-up and why counts are not conclusive evidence.

## Run the synthetic investigation

```kusto
let Tickets = datatable(
    TimeGenerated:datetime, RequestingAccount:string,
    ClientAddress:string, TargetService:string
)[
    datetime(2026-10-20T09:00:00Z), "user-a", "192.0.2.10", "HTTP/web01",
    datetime(2026-10-20T09:01:00Z), "user-a", "192.0.2.10", "MSSQLSvc/db01",
    datetime(2026-10-20T09:02:00Z), "user-a", "192.0.2.10", "HTTP/app01",
    datetime(2026-10-20T09:03:00Z), "user-a", "192.0.2.10", "CIFS/files01",
    datetime(2026-10-20T09:04:00Z), "user-a", "192.0.2.10", "HTTP/web02",
    datetime(2026-10-20T09:00:00Z), "svc-maintenance", "198.51.100.22", "HTTP/web01",
    datetime(2026-10-20T09:01:00Z), "svc-maintenance", "198.51.100.22", "HTTP/web01"
];
Tickets
| summarize Requests=count(),
            Services=dcount(TargetService),
            SPNs=make_set(TargetService, 20)
  by RequestingAccount, ClientAddress, bin(TimeGenerated, 15m)
| order by Services desc
```

## Expected findings

Two rows appear. `user-a` has **five requests for five unique SPNs**. `svc-maintenance` has **two requests for one unique SPN**. The former merits further triage but does not establish malicious intent. Consider whether a deployment tool, shared workstation or ordinary application caused the pattern.

## Analyst deliverable

Prepare an investigation note with (1) the hypothesis, (2) observed events, (3) competing explanations, (4) evidence needed from real domain controllers and endpoints, and (5) proportionate response steps. Include the limitations of Event 4769.

## Next step

Compare this exercise against [Kerberoasting detection guidance](../detection-engineering/threat-detection/ad-detections-and-mitigations/kerberoasting.md), and use the [validation checklist](../detection-engineering/threat-detection/detection-validation-checklist.md) before considering a production analytic.
