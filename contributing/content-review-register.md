# Technical Content Review Register

**Review baseline:** 20 October 2026  
**Scope:** Initial priority-based review, not a complete certification of the repository.

| Content | Priority | Status | Reason | Next action |
| --- | --- | --- | --- | --- |
| [AS-REP Roasting](../detection-engineering/threat-detection/ad-detections-and-mitigations/authentication-server-response-as-rep-roasting.md) | High | Rewritten; lab validation pending | Historical Kerberos status-code and query defects corrected in first pass | Verify current Windows Event 4768 field rendering and execute queries |
| [DCSync](../detection-engineering/threat-detection/ad-detections-and-mitigations/dcsync.md) | High | Rewritten; lab validation pending | Historical replication-event and AD permission guidance corrected in first pass | Test required audit/SACL configuration against lab DC |
| [Password Spraying](../detection-engineering/threat-detection/ad-detections-and-mitigations/password-spraying.md) | High | Rewritten; lab validation pending | Replaced ambiguous legacy query with focused Entra sign-in hunting and explicit limitations | Execute in a tenant and verify SigninLogs schema and thresholds |
| [Kerberoasting](../detection-engineering/threat-detection/ad-detections-and-mitigations/kerberoasting.md) | High | Rewritten; lab validation pending | Focused the guide on domain-controller 4769, with scoped hunting and caveats | Verify collected fields and baseline service-ticket activity |
| [Detection validation checklist](../detection-engineering/threat-detection/detection-validation-checklist.md) | Medium | Published standard | Process guidance only | Apply to new detections consistently |
| [Password spray lab](../practice-labs/password-spray-investigation.md) | Medium | Synthetic exercise | Designed to demonstrate KQL logic; not operational telemetry validation | Run example in Kusto environment and record results |

| [Golden Ticket](../detection-engineering/threat-detection/ad-detections-and-mitigations/golden-ticket.md) | High | Rewritten; lab validation pending | Clarified forged-TGT limitations, DC evidence gaps and staged krbtgt recovery | Execute representative event triage and review recovery with AD specialists |
| [Silver Ticket](../detection-engineering/threat-detection/ad-detections-and-mitigations/silver-ticket.md) | High | Rewritten; lab validation pending | Clarified service-ticket scope, missing 4769 ambiguity and host telemetry | Validate against lab resource-server logs and service configurations |

| [PowerShell live triage](../defensive-security/dfir/initial-triage-and-response/evidence-collection/acquire-triage-data-using-powershell.md) | High | Rewritten; runtime validation pending | Removed execution-policy bypass and replaced broad untested collection script with limited, documented live triage | Verify cmdlets and exports on representative Windows builds |
| [Memory acquisition](../defensive-security/dfir/initial-triage-and-response/evidence-collection/acquire-triage-memory-image.md) | High | Rewritten; tool validation pending | Explicit version, driver and sensitive evidence requirements; no unverified flags | Test approved acquisition tool/version and hash transfer workflow |
| [KAPE acquisition](../defensive-security/dfir/initial-triage-and-response/evidence-collection/acquire-triage-image-using-kape.md) | High | Rewritten; tool validation pending | Distinguished targeted artefact collection from full forensic imaging, removed unverified flag combinations | Validate approved KAPE version and Target selections |
| [FTK imaging](../defensive-security/dfir/initial-triage-and-response/evidence-collection/acquire-image-using-ftk.md) | High | Rewritten; tool validation pending | Clarified physical/logical selection, write-blocking and verification scope | Test selected FTK version and image format in lab |

## Rules for continued review

- Review high-risk operational commands and misleading event semantics before editorial polish.
- Prioritise frequently referenced pages, incident-response actions and detections likely to be pasted into SIEM rules.
- A missing review record does **not** mean an article is validated.
- Track owner, test evidence, last reviewed date, data-source requirements and outstanding defects for each reviewed article.

## Acceptance criteria for marking a detection validated

Evidence must identify product versions, source tables, sample events, execution results, expected benign behaviour, false positives and deployment limitations. Do not infer validation merely because a KQL query appears syntactically plausible.
