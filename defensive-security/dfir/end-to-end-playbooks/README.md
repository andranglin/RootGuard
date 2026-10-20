# Operational Incident Investigation Playbooks

Use the [Analyst-to-Response Handoff Checklist](response-handoff-checklist.md) for formal scoping, approvals, containment decisions and verification.

The incident lifecycle can be followed using the [standard investigation diagram](../../../design-system/diagram-patterns.md). Each playbook presents prerequisites, investigative pivots, response decisions and verification criteria.

Practical, phase-based workflows that connect initial alert triage with containment, forensic scoping, eradication, safe recovery and post-incident activities.

- [Phishing Compromise](phishing-compromise.md): malicious email, credential or session exposure and account misuse
- [Ransomware](ransomware.md): active encryption, lateral spread and recovery integrity
- [Credential Theft](credential-theft.md): password, session and privileged identity compromise
- [Lateral Movement](lateral-movement.md): remote execution, service creation and cross-host access

These are stepwise operational guides with KQL triage pivots, second-stage investigations, containment decisions and closure criteria. The downloadable CSV case studies remain optional learning material, not prerequisites for incident response.

These are investigation *playbooks*, complementing detailed existing [DFIR runbooks](../runbooks/README.md). They do not replace incident-specific judgement or emergency containment authority.

## How to use

Start from the relevant **trigger**, confirm required logs and telemetry, build an evidence timeline, record decisions and use the exit criteria. Each playbook includes illustrative KQL designed for Microsoft Sentinel where specified. **No KQL on this page is independently production-validated.**

See [Evidence Acquisition and Integrity](../field-guides/evidence-acquisition-and-integrity.md) and [Windows Endpoint Triage](../field-guides/windows-endpoint-triage.md).
