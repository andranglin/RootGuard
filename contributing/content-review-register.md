# Technical Content Review Register

**Review baseline:** 20 October 2026  
**Scope:** Initial priority-based review, not a complete certification of the repository.

| Content | Priority | Status | Reason | Next action |
| --- | --- | --- | --- | --- |
| [AS-REP Roasting](../detection-engineering/threat-detection/ad-detections-and-mitigations/authentication-server-response-as-rep-roasting.md) | High | Rewritten; lab validation pending | Historical Kerberos status-code and query defects corrected in first pass | Verify current Windows Event 4768 field rendering and execute queries |
| [DCSync](../detection-engineering/threat-detection/ad-detections-and-mitigations/dcsync.md) | High | Rewritten; lab validation pending | Historical replication-event and AD permission guidance corrected in first pass | Test required audit/SACL configuration against lab DC |
| [Password Spraying](../detection-engineering/threat-detection/ad-detections-and-mitigations/password-spraying.md) | High | Legacy; technical review required | Queries contain an ambiguous joined aggregate and unverified assumptions | Rewrite event-specific detections after obtaining representative telemetry |
| [Kerberoasting](../detection-engineering/threat-detection/ad-detections-and-mitigations/kerberoasting.md) | High | Legacy; technical review required | Mixes domain-controller ticket telemetry with claims about unrelated platforms | Verify 4769 schema, relevant ticket encryption metadata and platform scope |
| [Detection validation checklist](../detection-engineering/threat-detection/detection-validation-checklist.md) | Medium | Published standard | Process guidance only | Apply to new detections consistently |
| [Password spray lab](../practice-labs/password-spray-investigation.md) | Medium | Synthetic exercise | Designed to demonstrate KQL logic; not operational telemetry validation | Run example in Kusto environment and record results |

## Rules for continued review

- Review high-risk operational commands and misleading event semantics before editorial polish.
- Prioritise frequently referenced pages, incident-response actions and detections likely to be pasted into SIEM rules.
- A missing review record does **not** mean an article is validated.
- Track owner, test evidence, last reviewed date, data-source requirements and outstanding defects for each reviewed article.

## Acceptance criteria for marking a detection validated

Evidence must identify product versions, source tables, sample events, execution results, expected benign behaviour, false positives and deployment limitations. Do not infer validation merely because a KQL query appears syntactically plausible.
