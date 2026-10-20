# Practical Exercises

This area is for **optional learning and investigative reasoning**, not for operational incident procedures. Use the [operational playbooks](../defensive-security/dfir/end-to-end-playbooks/README.md) when responding to a real incident.

The exercises below use synthetic data. They can help develop evidence interpretation and report writing, but they do not reproduce production Microsoft 365, Windows or endpoint telemetry.

## Short exercises

| Exercise | Focus |
| --- | --- |
| [01 · Password spraying](password-spray-investigation.md) | Sign-in patterns and false-positive considerations |
| [02 · Kerberos ticket requests](kerberos-ticket-investigation.md) | SPN activity and event limitations |
| [03 · Kerberos logon triage](kerberos-triage-case-study.md) | Evidence supporting, but not proving, forged ticket hypotheses |
| [04 · Windows endpoint timeline](windows-timeline-triage.md) | Process, network and service chronology |

## Case-study packages

[Investigation case studies](case-studies/README.md) contain fictional CSV records, analyst prompts and marking criteria. These remain teaching exercises and should not be mistaken for lab-captured forensic evidence.

## For practitioners

For immediately applicable guidance, begin with [Windows endpoint triage](../defensive-security/dfir/field-guides/windows-endpoint-triage.md), [Evidence acquisition and integrity](../defensive-security/dfir/field-guides/evidence-acquisition-and-integrity.md), or [the incident playbook library](../defensive-security/dfir/end-to-end-playbooks/README.md).
