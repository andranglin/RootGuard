---
description: Incident investigation, forensic evidence and operational response guidance
cover: ../../.gitbook/assets/RootGuardDFIRLandingPage.png
coverY: 0
layout:
  width: default
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Digital Forensics & Incident Response

**Investigate with evidence. Contain with control. Recover with verification.**

Use this section for practical incident workflows, evidence acquisition, Windows and Linux investigations, and technical reference material. Begin with the operational incident category or the artefact you need to examine.

## Respond to an incident

| Incident type | Operational playbook |
| --- | --- |
| Malicious email and identity misuse | [Phishing compromise](end-to-end-playbooks/phishing-compromise.md) |
| Encryption, propagation or extortion | [Ransomware](end-to-end-playbooks/ransomware.md) |
| Compromised accounts, secrets or sessions | [Credential theft](end-to-end-playbooks/credential-theft.md) |
| Cross-host remote access or execution | [Lateral movement](end-to-end-playbooks/lateral-movement.md) |

## Collect and analyse evidence

- [Windows endpoint triage](field-guides/windows-endpoint-triage.md): initial assessment, prioritisation and scope.
- [Evidence acquisition and integrity](field-guides/evidence-acquisition-and-integrity.md): preservation, hashes and custody.
- [Windows artefact interpretation](field-guides/windows-artifact-interpretation.md): execution and file-system evidence and its limitations.
- [Windows forensic workflows](window-forensics/README.md) and [Linux forensics](linux-forensics/README.md).
- [Detailed runbooks](runbooks/README.md): deeper technical guidance, subject to documented validation status.

## Operational standards

Confirm the data source, permissions, telemetry coverage and product-specific schema before using a query. Separate observations from hypotheses, capture approvals before making impactful changes, and record what cannot be established.

**Validation matters:** The linked runbooks underwent targeted static safety review, but their remaining KQL and administrative actions require authorised environment testing. See the [Runbook Execution and Validation Matrix](runbooks/runbook-execution-validation-matrix.md).

## Additional references

[DFIR playbook index](end-to-end-playbooks/README.md) · [Forensic tooling references](playbooks/README.md) · [Optional practice exercises](../../practice-labs/README.md)
