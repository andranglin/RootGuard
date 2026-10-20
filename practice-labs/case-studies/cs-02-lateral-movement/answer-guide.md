# Instructor Answer Guide: Windows Remote Execution and Privileged Lateral Movement

This answer guide supports the [advanced investigation brief](README.md) and [72-row evidence file](extended-evidence.csv). The original eight-row `evidence.csv` is retained as an introductory micro-exercise.

## Model assessment

A high-quality response separates **recorded fact** (a synthetic row), **hypothesis** (possible malicious behaviour) and **conclusion** (supported by multiple independent sources). No event in the enlarged dataset alone establishes an actual intrusion.

**Priority review:** LM-023 flags a service executable path that requires service-control events, file-hash provenance and change ticket evidence. It does not independently prove attacker-installed malware.

## Minimum acceptable submission

- Evidence and chain-of-custody limitations documented.
- At least 12 cited evidence IDs in a UTC timeline, without assuming chronological sequence proves causation.
- Entity correlation and explicit uncertainty over shared IPs and accounts.
- Three competing hypotheses and falsification tests.
- Containment decision with approver, potential service impact and evidence-preservation implications.
- A detection improvement proposal with prerequisites, false-positive hypotheses and safe tests.
- A report describing what is *not* established.

## Score out of 100

Use the weighted rubric in [the case brief](README.md). Penalise unsupported assertion, particularly claims of confirmed compromise, human attribution, completed authentication, credential theft or data loss based on these synthetic records alone.

## Instructor debrief

Debrief missing provenance, alternate normal operational causes, incomplete authentication context, difference between detection engineering and forensic proof, and how analysts should report uncertainty to incident command. Recommend repeat exercise after providing richer authentic-looking but non-sensitive lab telemetry.
