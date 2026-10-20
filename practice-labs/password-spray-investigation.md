# Lab 01: Investigating a Password-Spray Pattern

**Level:** Foundational to intermediate  
**Focus:** Entra ID sign-in investigation, aggregation and triage  
**ATT&CK:** [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)  
**Validation status:** Synthetic-data reasoning exercise; not a production detection

## Objectives

- Recognise one source producing failures across multiple distinct user accounts.
- Investigate a subsequent successful authentication without assuming account compromise.
- Evaluate blind spots, noise and remediation decisions.

## Prerequisites

A KQL environment that supports the Kusto `datatable` operator. The lab does not query tenant logs or require a Microsoft Sentinel connector.

## Scenario

During a 15-minute window, `203.0.113.50` appears to attempt access to several accounts. The addresses used here belong to documentation ranges and the identities are fictional. Determine whether the pattern warrants investigation.

## Synthetic telemetry

Copy and run this complete query. These records are *illustrative*, not an exact replica of the Microsoft Entra `SigninLogs` schema.

```kusto
let SyntheticSignins = datatable(
    TimeGenerated:datetime, IPAddress:string, UserPrincipalName:string,
    ResultType:string, AppDisplayName:string
)[
    datetime(2026-10-20T10:00:00Z), "203.0.113.50", "ada@example.invalid", "50126", "Office",
    datetime(2026-10-20T10:01:00Z), "203.0.113.50", "ben@example.invalid", "50126", "Office",
    datetime(2026-10-20T10:02:00Z), "203.0.113.50", "cy@example.invalid", "50126", "Office",
    datetime(2026-10-20T10:03:00Z), "203.0.113.50", "dee@example.invalid", "50126", "Office",
    datetime(2026-10-20T10:04:00Z), "203.0.113.50", "eve@example.invalid", "50126", "Office",
    datetime(2026-10-20T10:06:00Z), "203.0.113.50", "ben@example.invalid", "0", "Office",
    datetime(2026-10-20T10:02:00Z), "198.51.100.20", "fran@example.invalid", "50126", "Office",
    datetime(2026-10-20T10:04:00Z), "198.51.100.20", "fran@example.invalid", "50126", "Office"
];
let Failures = SyntheticSignins
| where ResultType == "50126"
| summarize FailureCount=count(), DistinctUsers=dcount(UserPrincipalName),
            TargetUsers=make_set(UserPrincipalName, 20)
    by IPAddress, Window=bin(TimeGenerated, 15m)
| where DistinctUsers >= 5;
let Successes = SyntheticSignins
| where ResultType == "0"
| project IPAddress, SuccessTime=TimeGenerated, SuccessfulUser=UserPrincipalName;
Failures
| join kind=leftouter Successes on IPAddress
| project IPAddress, Window, FailureCount, DistinctUsers, TargetUsers,
          SuccessTime, SuccessfulUser
| order by FailureCount desc
```

## Expected observation

The query should return **one row** for `203.0.113.50`, with **five failed sign-ins across five distinct accounts**, followed by a successful sign-in recorded for `ben@example.invalid` at **10:06 UTC**. The other IP should be excluded because it targets only one identity. The result indicates behaviour consistent with a password-spray hypothesis; it does not establish credential compromise, MFA completion or session access.

## Analyst questions

1. What makes the distribution of failed attempts different from a single-account password guessing attempt?
2. What additional sign-in fields or audit sources would you review to understand the successful event?
3. How could shared NAT gateways, identity-provider behaviour or legitimate automation create similar patterns?
4. What should be escalated, and what would justify containment?

## Extending into a real tenant

For an authorised investigation, assess real `SigninLogs` records using `TimeGenerated`, `IPAddress`, `UserPrincipalName`, `ResultType`, conditional access outcomes, device context, authentication details and relevant non-interactive logs. **Do not simply substitute the synthetic table with a live table and declare the query production-ready.** Confirm connector availability, schema, authentication-result semantics, ingestion delay, thresholds and privacy requirements first.

## Completion criteria

Produce a short investigation record containing hypothesis, query result, affected accounts, corroborating telemetry to request, at least two benign alternatives, confidence level and next actions.

## References

- [Microsoft: SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- [RootGuard detection validation checklist](../detection-engineering/threat-detection/detection-validation-checklist.md)
