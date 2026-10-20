# Credential Theft: Operational Incident Investigation Playbook

> **RootGuard technical reference** · **Environment:** Verify product, platform and telemetry prerequisites · **Validation:** Refer to the status below; examples are not automatically production-ready.

**Operational status:** Practitioner workflow; KQL syntax and outcomes require testing against your deployed product schema. Not production-validated. 
**Review:** 20 October 2026 · **Owner:** SOC/CSIRT · **Authorisation:** Follow local incident command, privacy and evidence procedures.

> **Important:** Queries below are *investigation pivots*, not finished alerts. Microsoft Defender XDR Advanced Hunting and Microsoft Sentinel Log Analytics use different tables and schema. Execute each query only in its stated environment. Preserve evidence, record approvals and do not delay urgent containment when harm is ongoing.

## 1. Activate, assess and preserve

1. Create an incident record with UTC start/end, reporting source, owner, severity and affected business services.
2. Confirm the alert is based on real telemetry; capture original record IDs, device/user identifiers and time bounds.
3. Establish whether emergency containment is required; coordinate with incident command, asset owners and identity/network teams.
4. Preserve relevant logs, incident exports and endpoint artefacts through approved tools. Track collection time, retention gaps and custody.
5. Keep **observations**, **hypotheses** and **confirmed conclusions** in separate notes.

**Technology coverage:** Microsoft Entra, Defender XDR, Windows AD, workload identities 
**Trigger:** suspicious authentication, token exposure, credential addition, role change or endpoint credential-access alert.

## 2. Confirm telemetry prerequisites

Check table availability, licences, audit policy, retention, time synchronisation, analyst permissions and actual column values. Confirm the intended query portal and lookback before running any example.

## 3. First-pass detection and triage

```kusto
// Microsoft Sentinel / Log Analytics (NOT Defender Advanced Hunting)
let User = "analyst@example.invalid";
SigninLogs
| where TimeGenerated > ago(72h) and UserPrincipalName =~ User
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
 ResultType, ConditionalAccessStatus, CorrelationId
| order by TimeGenerated desc
```

**Interpretation:** Inspect raw results, corroborate the triggering event and separate noise from suspicious behaviour. A matching record does not confirm malicious intent.

## 4. Expand scope with a second pivot

```kusto
// Microsoft Sentinel / Log Analytics; identity governance changes
AuditLogs
| where TimeGenerated > ago(72h)
| where OperationName has_any ("credential","authentication method","app role","permission")
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources
| order by TimeGenerated desc
```

Use the actual event/identity/device identifiers from step 3, taking care not to assume correlation from time proximity or shared IP alone. Record missing data sources.

## 5. Cross-validate with independent telemetry

```kusto
// Defender XDR; endpoint-originating credential access hypothesis
DeviceProcessEvents
| where Timestamp > ago(72h)
| where ProcessCommandLine has_any ("lsass","comsvcs.dll","procdump")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
 InitiatingProcessFileName, SHA1
| order by Timestamp desc
```

Record row identifiers, time, host, account, source, context and uncertainty. Investigate normal administrative activity and known operational changes before alleging malicious execution.

## 6. Analyst decision tree

- **Positive result with corroboration:** Broaden investigation across affected identities, devices, services and time; assess incident severity and urgent containment.
- **Positive result without corroboration:** Review raw source events, collection health, change tickets and alternate explanations.
- **No result:** Confirm telemetry exists, table/time filters are correct, permissions and retention sufficient. Absence is not proof of safety.
- **Evidence of ongoing harm:** Escalate immediate containment without waiting for full causal proof.

### Questions to answer

Which secret type was exposed: password, session token, Kerberos material, certificate or application secret? What privileges and sessions are implicated? Are new auth methods, consents or credentials present? Is account takeover demonstrated or only attempted?

## 7. Containment: approvals, execution and verification

Coordinate user account restriction, session revocation and approved credential rotation appropriate to the secret type. Remove unauthorised app credentials/permissions or authentication methods. Password changes alone may not invalidate all sessions and app credentials.

For every action record: approver, command/control used, timestamp, target, expected impact, evidence changes, rollback plan and verification result. Use tenant-approved UI/API workflows rather than copying untested destructive commands.

## 8. Eradication and recovery

Identify the root cause and persistence, remove only confirmed unauthorised access paths, remediate weaknesses, rebuild or restore from trusted baselines where necessary. Verify log visibility and functional access after recovery. Obtain business owner acceptance before closing.

## 9. Closure criteria and deliverables

Exposed credential classes inventoried and invalidated as appropriate; access and persistence reviewed; restored authentication confirmed; privileged blast radius assessed.

| Deliverable | Minimum content |
| --- | --- |
| Incident timeline | UTC timestamps, event IDs, user/device, provenance and confidence |
| Evidence register | Source, collector, time, retention and integrity information |
| Scope matrix | Confirmed / suspected / excluded assets and identities |
| Decision log | Approvals, containment trade-offs, actions and outcomes |
| Findings | Evidence-backed conclusions, benign alternatives and unknowns |
| Follow-up | Recovery tests, monitoring, accountable owners and deadlines |

## 10. References and operational caveats

- [RootGuard evidence acquisition](../field-guides/evidence-acquisition-and-integrity.md)
- [RootGuard triage field guide](../field-guides/windows-endpoint-triage.md)
- [Microsoft Defender advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Microsoft Sentinel data source schema reference](https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference)

**Validation status:** Documented and linked, not executed against the reader's tenant. Verify every query, action, source and result before incorporation into production procedures.
