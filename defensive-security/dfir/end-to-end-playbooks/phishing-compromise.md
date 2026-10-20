# Phishing Compromise

Investigate a suspected phishing incident, identify affected users and devices, and determine whether account or mailbox access was misused.

**Environment:** Microsoft Defender XDR, Defender for Office 365, Microsoft Entra ID  
**Validation:** Investigation queries require local testing  
**Reviewed:** 20 October 2026

## 1. Before you begin

1. Create an incident record with UTC start/end, reporting source, owner, severity and affected business services.
2. Confirm the alert is based on real telemetry; capture original record IDs, device/user identifiers and time bounds.
3. Establish whether emergency containment is required; coordinate with incident command, asset owners and identity/network teams.
4. Preserve relevant logs, incident exports and endpoint artefacts through approved tools. Track collection time, retention gaps and custody.
5. Keep **observations**, **hypotheses** and **confirmed conclusions** in separate notes.

**Technology coverage:** Defender for Office 365, Defender XDR, Entra ID, Exchange Online 
**Trigger:** malicious email, user click, credential submission, mailbox change or suspicious endpoint execution.

## 2. Confirm telemetry prerequisites

Check table availability, licences, audit policy, retention, time synchronisation, analyst permissions and actual column values. Confirm the intended query portal and lookback before running any example.

## 3. First-pass detection and triage

```kusto
// Microsoft Defender XDR Advanced Hunting; replace the sample recipient
let TargetMailbox = "analyst@example.invalid";
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress =~ TargetMailbox
| project Timestamp, NetworkMessageId, RecipientEmailAddress,
 SenderFromAddress, Subject, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

**Interpretation:** Inspect raw results, corroborate the triggering event and separate noise from suspicious behaviour. A matching record does not confirm malicious intent.

## 4. Expand scope with a second pivot

```kusto
// Microsoft Defender XDR; paste a verified NetworkMessageId from the first query
let Message = "REPLACE_WITH_NETWORK_MESSAGE_ID";
EmailUrlInfo
| where Timestamp > ago(7d) and NetworkMessageId == Message
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLocation
```

Use the actual event/identity/device identifiers from step 3, taking care not to assume correlation from time proximity or shared IP alone. Record missing data sources.

## 5. Cross-validate with independent telemetry

```kusto
// Microsoft Defender XDR; endpoint execution pivot after obtaining device name
let Host = "REPLACE_WITH_DEVICE_NAME";
DeviceProcessEvents
| where Timestamp > ago(48h) and DeviceName =~ Host
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","msedge.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
 InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by Timestamp desc
```

Record row identifiers, time, host, account, source, context and uncertainty. Investigate normal administrative activity and known operational changes before alleging malicious execution.

## 6. Analyst decision tree

- **Positive result with corroboration:** Broaden investigation across affected identities, devices, services and time; assess incident severity and urgent containment.
- **Positive result without corroboration:** Review raw source events, collection health, change tickets and alternate explanations.
- **No result:** Confirm telemetry exists, table/time filters are correct, permissions and retention sufficient. Absence is not proof of safety.
- **Evidence of ongoing harm:** Escalate immediate containment without waiting for full causal proof.

### Questions to answer

Did the message arrive? Was the URL merely present or clicked? Did the person enter credentials? Did a usable session result? Did a mailbox rule or OAuth grant persist? Were any messages/data accessed?

## 7. Containment: approvals, execution and verification

Use approved Explorer/Defender investigation and remediation to quarantine matching messages. Confirm user activity and use Entra session revocation/account restriction when supported by evidence. Review inbox rules, forwarding, authentication methods, OAuth grants and endpoint compromise; isolate affected endpoint when justified.

For every action record: approver, command/control used, timestamp, target, expected impact, evidence changes, rollback plan and verification result. Use tenant-approved UI/API workflows rather than copying untested destructive commands.

## 8. Eradication and recovery

Identify the root cause and persistence, remove only confirmed unauthorised access paths, remediate weaknesses, rebuild or restore from trusted baselines where necessary. Verify log visibility and functional access after recovery. Obtain business owner acceptance before closing.

## 9. Closure criteria and deliverables

Recipient population and click coverage understood; identity and endpoint compromise dispositioned; illicit rules/grants removed if confirmed; sessions/access reassessed; enhanced monitoring assigned.

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
