# Lab 04: Windows Endpoint Triage Timeline

**Data:** Fictional, read-only KQL `datatable` records  
**Status:** Synthetic investigation exercise, not forensic validation  
**Goal:** Reconstruct an event sequence without overclaiming compromise.

## Scenario

A Windows workstation exhibits a suspicious command interpreter process after a document viewer launches. Review the timeline to identify observables, potential explanations and evidence still needed.

```kusto
let Events = datatable(TimeGenerated:datetime, Host:string, EventType:string,
    Process:string, ParentProcess:string, Note:string)[
 datetime(2026-10-20T09:00:00Z), "WS-01", "Process", "winword.exe", "explorer.exe", "Document opened",
 datetime(2026-10-20T09:02:00Z), "WS-01", "Process", "powershell.exe", "winword.exe", "Unusual child process",
 datetime(2026-10-20T09:03:00Z), "WS-01", "Network", "powershell.exe", "winword.exe", "Outbound connection observed",
 datetime(2026-10-20T09:07:00Z), "WS-01", "Service", "unknownsvc", "services.exe", "New service record"
];
Events
| order by TimeGenerated asc
```

## Expected outcome

Four ordered events appear between 09:00 and 09:07 UTC. The PowerShell child process and later service record require investigation, but these synthetic entries lack command lines, hashes, network destinations, user context and trustworthy causality.

## Exercise

Document the timeline, at least three further evidence sources, the difference between chronology and causation, and a containment decision with business-impact considerations.

Related: [Endpoint triage field guide](../defensive-security/dfir/field-guides/windows-endpoint-triage.md).
