# Phishing Compromise: End-to-End Investigation

**Status:** Practitioner procedure; adapt to approved organisational policies and validate queries locally.  
**Owner:** Incident Commander / CSIRT  
**Last reviewed:** 20 October 2026

> **Safety and evidence:** Preserve relevant evidence and timestamps, respect access approvals and legal/privacy requirements, and do not delay urgent containment to finish collection. A single indicator or KQL result does not prove compromise.

## Incident governance and decision checkpoints

| Stage | Decision and record |
| --- | --- |
| Declare | Incident ID, severity, affected business services, initial confidence, decision owner |
| Scope | Confirm affected identities, hosts, tenants, data and known evidence gaps |
| Contain | Select reversible measures where feasible; obtain approvals and record business impact |
| Eradicate | Remove verified persistence and underlying access paths, after understanding cause |
| Recover | Restore approved services and monitor for recurrence, with explicit acceptance criteria |
| Close | Document timeline, confidence, exposure, lessons, follow-up owners and review dates |

**Roles:** SOC investigator develops hypotheses and evidence timeline; endpoint/identity teams validate and execute technical changes; incident command approves response, engages business owner, legal/privacy and communications as required. Retain command/output logs and decisions.


## Trigger and scope

Reported malicious message, Defender for Office alert, suspicious click or attachment execution, user-reported credential submission, anomalous mailbox rules, or unexpected cloud account access. Distinguish email delivery from **credential theft**, **session compromise**, **endpoint execution** and **account misuse**; they require different evidence and containment.

**Required sources:** Microsoft Defender for Office 365 `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` where available; `SigninLogs`, `AuditLogs`, Exchange mailbox audit, Defender endpoint telemetry and security incidents. Verify licensing, retention and exact schema. Message ID fields are not interchangeable.

## 1. Initial triage (SOC)

1. Preserve original message as evidence, including internet headers, URLs, attachment names/hashes and message identifiers. Avoid visiting URLs on an analyst endpoint.
2. Confirm sender authentication, message disposition, actual recipients, delivery actions and user interaction.
3. Establish user-reported actions: message opened, link clicked, file launched, credentials submitted or unexpected MFA prompt.
4. Correlate sign-ins, session/device details, audit events and endpoint process activity around the interaction.
5. Record initial affected users, confidence and containment decision.

### Illustrative Sentinel email pivot

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress =~ "analyst@example.invalid"
| project Timestamp, RecipientEmailAddress, SenderFromAddress,
          Subject, NetworkMessageId, DeliveryAction, ThreatTypes
| order by Timestamp desc
```

Replace the fictional mailbox, verify permissions/schema, and pivot by the exact `NetworkMessageId` across relevant Defender tables. This is a triage search, not proof of malicious activity.

## 2. Scope and investigation

- Find all recipients, delivered copies, user clicks, attachment execution and subsequent related messages.
- For likely credential theft, review sign-in results, authentication requirements, session behaviour, newly added credentials, OAuth consent, conditional access, and sensitive resource access.
- For mailbox misuse, assess inbox rules, forwarding settings, sent items, delegated access and application permissions.
- For endpoint execution, correlate document process ancestry, command line, downloaded files, persistence and network connections.
- Preserve a UTC timeline and track each finding as confirmed/possible/unsubstantiated.

## 3. Containment decisions

- Coordinate removal/quarantine of delivered messages via approved Defender controls after identifying impacted mailboxes.
- Where account compromise is supported, revoke active sessions and reset credentials or enforce reauthentication through approved identity processes; investigate persistent tokens, registered authentication methods, app credentials and delegated access.
- Isolate a compromised endpoint when justified, considering loss of volatile evidence and operational impact.
- For suspected BEC, coordinate finance/banking recall and stakeholder notifications immediately if payment fraud is possible.

## 4. Eradication and recovery

Remove malicious mailbox rules, unauthorised apps/consents and persistence; address compromised devices; validate MFA/Conditional Access controls; restore mailbox access and monitor sign-ins, mail actions and endpoint activity. Only release the account/device after ownership confirms risk is acceptable.

## 5. Closure and evidence

Record impacted recipients, interaction counts, compromised identities, evidence of data access/exfiltration, message lineage, control failures and reasons for ruling out alternatives. Document business/legal reporting decisions and an approved user communication.

**Exit criteria:** Delivery spread understood; compromise vectors remediated; sessions and access reviewed; recurrence monitored; handover complete.

## Further reading

[Defender email investigation](../playbooks/kql-defender-and-sentinel/mdo-office.md) · [BEC runbook](../runbooks/business-email-compromise-bec-investigation-runbook.md) · [Evidence integrity](../field-guides/evidence-acquisition-and-integrity.md)
