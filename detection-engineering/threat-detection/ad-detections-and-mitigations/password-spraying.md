# Password Spraying: Detection and Investigation

**ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)  
**Review date:** 20 October 2026  
**Validation:** Concept / unvalidated; verify with your environment's telemetry.

## Detection hypothesis

A single source attempts authentication against many distinct identities over a short period, potentially followed by successful access to one of those identities. No event alone confirms credential compromise.

## Microsoft Entra sign-in hunting

**Requirements:** Microsoft Entra interactive sign-ins ingested into Microsoft Sentinel's `SigninLogs` table. The query is intended for exploratory triage, not immediate scheduled alerting.

```kusto
let Lookback = 24h;
let Window = 15m;
let MinimumUsers = 5;
let Failures =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    | where ResultType == "50126"
    | where isnotempty(IPAddress) and isnotempty(UserPrincipalName)
    | summarize FailedAttempts=count(),
                TargetedUsers=dcount(UserPrincipalName),
                Accounts=make_set(UserPrincipalName, 30)
        by IPAddress, WindowStart=bin(TimeGenerated, Window)
    | where TargetedUsers >= MinimumUsers;
Failures
| order by TargetedUsers desc, FailedAttempts desc
```

**Interpretation:** Error 50126 commonly indicates invalid username or password, but this filter is not an exhaustive inventory of unsuccessful sign-ins. Analyse other result codes and non-interactive sign-in sources according to your investigative context. A shared NAT, VPN, proxy or automation can aggregate unrelated users behind one IP.

## Correlate with later successful sign-ins

Use results from the first query to identify relevant source IPs and accounts, then inspect successful and interrupted sign-ins. For an exploratory source-based view:

```kusto
let SuspiciousSources = (
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == "50126"
    | where isnotempty(IPAddress) and isnotempty(UserPrincipalName)
    | summarize Users=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 15m)
    | where Users >= 5
    | distinct IPAddress
);
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress in (SuspiciousSources)
| project TimeGenerated, IPAddress, UserPrincipalName, ResultType,
          AppDisplayName, ConditionalAccessStatus, CorrelationId
| order by IPAddress asc, TimeGenerated asc
```

**Limitations:** A result code of 0 does not independently establish that every authentication requirement was completed or that a usable session was issued. Review authentication details, conditional access, device/session context and subsequent activity. Source IPs alone may not uniquely identify a device or attacker.

## On-premises Active Directory

Collect appropriate domain-controller authentication telemetry (such as Event 4771 and 4776 where applicable) and validate field semantics before adapting the analytic. Endpoint Event 4625 alone cannot reliably replace domain-controller coverage. Account lockout behaviour and authentication protocols change the pattern.

## Investigation workflow

1. Validate the events, time window, sign-in type and normal source behaviour.
2. Identify the distinct accounts and their sensitivity.
3. Review authentication outcomes and whether any session was established.
4. Correlate with endpoint, identity, device and user activity.
5. Escalate with supporting evidence; take containment actions under approved response procedures.

## Mitigation

Use phishing-resistant MFA where possible, password protection against known weak values, risk-based identity controls, least privilege and active monitoring. MFA significantly reduces the risk of password-only takeover but does not prevent password-guessing attempts and cannot be treated as universal protection against all downstream session attacks.

## Validation limitations and references

These queries have not been run against a tenant or approved test dataset for this publication. The thresholds are illustrative. Consult the [Detection Validation Checklist](../detection-validation-checklist.md).

- [Microsoft SigninLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [MITRE ATT&CK: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
