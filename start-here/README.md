# Start Here

**Choose the task you need to perform.** RootGuard organises guidance around incident investigation, technical evidence and defensive engineering.

## Workflows

| Your objective | Recommended first page |
| --- | --- |
| Respond to an active incident | [Operational incident playbooks](../defensive-security/dfir/end-to-end-playbooks/README.md) |
| Triage a Windows endpoint | [Windows endpoint triage](../defensive-security/dfir/field-guides/windows-endpoint-triage.md) |
| Preserve or acquire evidence | [Evidence acquisition and integrity](../defensive-security/dfir/field-guides/evidence-acquisition-and-integrity.md) |
| Hunt identity threats | [AD detection references](../detection-engineering/threat-detection/ad-detections-and-mitigations/README.md) |
| Develop and assess detections | [Threat detection engineering](../detection-engineering/threat-detection/README.md) |
| Study investigation concepts | [Learning paths](../learning-paths/README.md) |
| Explore architecture decisions | [Security architecture](../security-architecture/README.md) |

## A reliable investigation workflow

1. Define the alert, affected assets and potential business impact.
2. Confirm which logs and permissions are available; note collection gaps.
3. Execute appropriate read-only investigation steps in the specified tool.
4. Correlate independent evidence and distinguish observations from hypotheses.
5. Record containment decisions and execute changes only with the required approvals.
6. Validate remediation and document the handover, findings and remaining uncertainty.

## Content labels

**Operational playbook** — step-by-step investigative workflow with decision gates and response criteria.

**Technical reference** — focused explanation of a technique, artefact, query or platform.

**Practical exercise** — optional synthetic training material, never evidence from a real incident.

**Validation status** — technical claims may be subject to static review, syntax testing, lab verification or production validation. Follow the label on each document.

For command and query testing, use the [Runbook Execution and Validation Matrix](../defensive-security/dfir/runbooks/runbook-execution-validation-matrix.md).

## Browse further

[DFIR resource hub](../defensive-security/dfir/README.md) · [Technical documentation standards](../contributing/README.md) · [About RootGuard](../welcome/who-am-i/README.md)
