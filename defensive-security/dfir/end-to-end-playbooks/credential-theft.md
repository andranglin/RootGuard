# Credential Theft: End-to-End Investigation

**Status:** Operational framework, not production-validated. **Reviewed:** 20 October 2026. **Owner:** Incident Commander / CSIRT.

> Preserve evidence, record UTC times and approvals, and do not delay urgent containment when material harm is ongoing. All example queries require schema, permission and environmental validation.

## Incident command and recordkeeping

Record incident ID, trigger, affected business services, severity, roles, initial scope and confidence. Maintain a decision log with timestamps, approvers, evidence references, operational impact and communications. Assign SOC investigation, endpoint/identity response, legal/privacy, business recovery and executive liaison roles as needed.


## 1. Trigger and classification

Alerts for suspicious logins, new privileged credentials, anomalous MFA method registration, LSASS access, token theft, OAuth permission abuse or AD replication anomalies. Distinguish passwords, password hashes, Kerberos keys/tickets, session tokens and application secrets; each has different invalidation and persistence risks.

**Telemetry:** `SigninLogs`, `AuditLogs`, Defender endpoint tables, relevant DC security events, application permission and privileged access logs. Confirm data collection before inferring absence.

### Illustrative Microsoft Sentinel identity pivot

```kusto
SigninLogs
| where TimeGenerated > ago(48h)
| where UserPrincipalName =~ "analyst@example.invalid"
| project TimeGenerated, UserPrincipalName, IPAddress,
          AppDisplayName, ResultType, ConditionalAccessStatus, CorrelationId
| order by TimeGenerated desc
```

Result codes and Conditional Access status alone do not prove token security, established sessions or data access. Replace the fictional UPN.

## 2. Initial triage

1. Confirm the alerted account, device, workload and evidence type.
2. Review sign-ins, authentication details, method registration and privileged role changes.
3. Correlate endpoint activity, suspicious credential access and anomalous administration.
4. Define affected tenants/domains, privileges, possible data access and confidence.
5. Escalate domain-controller or privileged workload identity compromise rapidly.

## 3. Scope and preserve evidence

Review other accounts on the source device, app grants, credential additions, session traces, mailbox and data exports. Use event time and device/identity correlation, not IP alone. Preserve authentication and audit records before rotating credentials where feasible.

## 4. Containment

Coordinate account disablement or access restrictions, revoke relevant sessions, rotate affected passwords and service/app secrets and remove illegitimate credentials or authentication methods. Session revocation and password changes have different limits; verify effective invalidation. Avoid service disruption from unplanned privileged credential rotations.

## 5. Eradication and recovery

Remove endpoint malware/persistence and malicious grants; re-establish controlled authentication method enrolment, restore least-privilege access and review privileged access policies. Validate clean sign-ins, absence of unauthorised activity and application availability.

## 6. Closure

Document affected identity classes, potential data exposure, root cause, recovered access, investigation limitations, decision record and monitoring period.

**Exit criteria:** Compromised credential classes addressed, sessions reviewed/revoked where applicable, persistence eliminated, privileges audited and business owner sign-off recorded.

[Identity attack runbook](../runbooks/identity-attack-investigation-runbook.md) · [DCSync](../../../detection-engineering/threat-detection/ad-detections-and-mitigations/dcsync.md)
