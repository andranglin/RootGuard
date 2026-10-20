# AS-REP Roasting: Detection and Mitigation

## Overview

AS-REP roasting (MITRE ATT&CK T1558.004) targets Active Directory user accounts configured **not to require Kerberos pre-authentication**. An unauthenticated requester can ask the Key Distribution Center (KDC) for an authentication response and obtain material suitable for offline password guessing. The offline cracking stage is not visible to domain controller event logs.

**Detection hypothesis:** An unexpected host requests Kerberos TGTs for accounts without pre-authentication, potentially across several accounts or from uncommon source addresses.

## Prerequisites and telemetry

- Collect domain controller Security Event **4768** (Kerberos authentication ticket requested), including successful events, into Microsoft Sentinel's `SecurityEvent` table.
- Verify actual XML field names and values in your environment. In `SecurityEvent`, `EventData` commonly contains a `PreAuthType` element. Source events and field availability vary by collection path and OS version.
- **Pre-authentication type `0`** signifies no pre-authentication. **Result code `0x12` does not**: it means `KDC_ERR_CLIENT_REVOKED`. A successful event typically has result code `0x0`.
- AS-REP roasting may consist of just one request, so high-volume thresholds alone are insufficient.

## Query 1: Successful requests without pre-authentication

This is a **concept / unvalidated** hunting query for a Sentinel workspace using the `SecurityEvent` table. Confirm successful field extraction using actual records before using it as an alert.

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4768
| extend PreAuthType = extract(@"<Data Name=['""]PreAuthType['""]>([^<]*)</Data>", 1, tostring(EventData))
| extend ResultCode = tostring(Status)
| where PreAuthType == "0"
| where isempty(ResultCode) or ResultCode in~ ("0x0", "0")
| project TimeGenerated, Computer, Account, TargetUserName, IpAddress,
          PreAuthType, ResultCode, EventData
| order by TimeGenerated desc
```

**Interpretation:** An event with no pre-authentication warrants review, especially for privileged accounts and unusual hosts. It does not independently prove malicious activity. If `Status` is not populated, confirm the success result in the original Windows event rather than assuming it.

## Query 2: Account and source concentration

```kusto
let NoPreAuthRequests =
    SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4768
    | extend PreAuthType = extract(@"<Data Name=['""]PreAuthType['""]>([^<]*)</Data>", 1, tostring(EventData))
    | where PreAuthType == "0"
    | extend SourceAddress = tostring(IpAddress),
             TargetAccount = tostring(TargetUserName)
    | where isnotempty(TargetAccount);
NoPreAuthRequests
| summarize Requests=count(),
            DistinctAccounts=dcount(TargetAccount),
            Accounts=make_set(TargetAccount, 50),
            DomainControllers=make_set(Computer, 20),
            FirstSeen=min(TimeGenerated),
            LastSeen=max(TimeGenerated)
  by SourceAddress
| order by DistinctAccounts desc, Requests desc
```

Investigate unexpected IP addresses, concentrations of target accounts, and deviations from normal authentication patterns. A low event count can still be suspicious. Domain controller events may contain client address formats that need normalisation.

## Validate exposed accounts in Active Directory

Requires the ActiveDirectory PowerShell module and appropriate read permissions.

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `
    -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName, Enabled, DoesNotRequirePreAuth
```

Review business justifications and remove the **Do not require Kerberos preauthentication** setting where possible. Apply strong, unique credentials to remaining exceptions and monitor them closely. MFA for unrelated interactive authentication flows does **not** by itself stop offline guessing of material obtained from AS-REP roasting.

## Analyst triage

1. Verify Event 4768 details and confirm the request was successful with pre-authentication type 0.
2. Determine whether the target account is expected to have pre-authentication disabled.
3. Investigate the source host, account sensitivity, request volume, and contemporaneous activity.
4. Review successful logons, credential use and endpoint telemetry associated with identified accounts.
5. If compromise is suspected, follow the organisation's credential containment and incident response procedures.

## Limitations and validation status

**Status: Concept / unvalidated.** These queries have not been executed against the reader's workspace. The examples require Event 4768 collection, valid `EventData` XML, matching ingestion schema, and local tuning. Failure to observe events does not establish absence of AS-REP roasting.

## References

- [Microsoft: Security Event 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Microsoft: Parsing text in Azure Monitor logs](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/parse-text)
- [Detection Validation Checklist](../detection-validation-checklist.md)
