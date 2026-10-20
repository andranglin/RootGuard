# Kerberoasting: Detection and Investigation

> **RootGuard technical reference** · **Environment:** Verify product, platform and telemetry prerequisites · **Validation:** Refer to the status below; examples are not automatically production-ready.

**ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)  
**Review date:** 20 October 2026  
**Validation:** Concept / unvalidated; domain-controller telemetry must be confirmed.

## Threat overview

Kerberoasting involves requesting Kerberos service tickets for service principal names (SPNs), obtaining material encrypted with a service account's key and attempting offline password recovery. A normal service ticket request is **not evidence by itself** of malicious activity. Weak passwords and overprivileged traditional service accounts amplify the risk.

## Evidence to collect

- Windows domain-controller Security Event **4769**, with the relevant audit policy and collection enabled.
- Requesting account, client address, target service/SPN, ticket encryption details and result.
- Account/SPN inventory, service account privileges, device and process telemetry where available.
- Environment-specific normal service ticket volumes and application dependencies.

The event format and available encryption fields can differ with Windows updates and ingestion pipelines. Do not assume all event schemas have identical ticket-encryption fields.

## KQL: Unusual volume of service-ticket requests

The following is a **concept / unvalidated** hunt for the Microsoft Sentinel `SecurityEvent` table. This is a volume-oriented triage aid, not definitive Kerberoasting detection.

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| extend RequestingAccount = tostring(Account),
         ClientAddress = tostring(IpAddress),
         TargetService = tostring(ServiceName)
| where isnotempty(RequestingAccount) and isnotempty(TargetService)
| summarize Requests=count(),
            Services=dcount(TargetService),
            TargetServices=make_set(TargetService, 30)
    by RequestingAccount, ClientAddress, WindowStart=bin(TimeGenerated, 15m)
| where Services >= 5
| order by Services desc, Requests desc
```

**Interpretation:** A client requesting several different SPNs in a short period merits investigation after normal activity is baselined. Common applications and management tools can legitimately request many tickets. Requests for one unusually sensitive account may matter even without a volume spike.

## Additional investigation

1. Verify the original 4769 events and their actual requesting accounts, SPNs and ticket types.
2. Examine unexpected RC4-based ticket use only where the recorded encryption type and policy context make this meaningful; RC4 alone is not proof of attack.
3. Check service-account privilege, SPN configuration, password protections and host behaviour.
4. Correlate with endpoint execution, logon events and subsequent service-account use.
5. Treat offline cracking as a visibility limitation. A ticket request does not prove a password has been recovered.

## Hardening

Prefer managed service accounts, including gMSAs where appropriate, and long random service-account passwords. Minimise service-account privilege, remove unnecessary SPNs, phase out weak cryptography with compatibility testing, restrict administrative logons and monitor changes to sensitive accounts.

## Known limitations

- These query fields must be verified against your collected events.
- Ticket request telemetry does not expose an offline cracking attempt.
- Ticket-volume thresholds vary widely by service and environment.
- Microsoft Entra cloud sign-in logs are **not** a substitute for on-premises domain-controller 4769 evidence.

## References

- [MITRE ATT&CK: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft: Event 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Detection Validation Checklist](../detection-validation-checklist.md)
