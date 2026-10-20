---
description: Practical cybersecurity investigation, detection and defensive engineering
cover: .gitbook/assets/RootGuardLandingPage.png
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

# RootGuard

**Security operations. Detection engineering. Digital forensics.**

RootGuard is an independent technical reference for security practitioners investigating incidents, developing detections and strengthening defensive environments. Start with a task, follow the evidence, and use the linked procedures as a starting point for your own authorised environment.

## Start with your objective

| I need to… | Go to |
| --- | --- |
| Investigate phishing, ransomware, credential theft or lateral movement | [Operational incident playbooks](defensive-security/dfir/end-to-end-playbooks/README.md) |
| Collect and interpret Windows endpoint evidence | [DFIR field guides](defensive-security/dfir/field-guides/README.md) |
| Build or review an AD or identity detection | [Detection engineering](detection-engineering/threat-detection/README.md) |
| Understand a technique or forensic artefact | [Digital forensics and incident response](defensive-security/dfir/README.md) |
| Study a topic systematically | [Learning paths](learning-paths/README.md) |
| Find contributor standards and review status | [Documentation standards](contributing/README.md) |

## Featured operational resources

### Incident investigation

- [Phishing compromise](defensive-security/dfir/end-to-end-playbooks/phishing-compromise.md): trace email delivery, user activity, endpoint evidence and account exposure.
- [Ransomware response](defensive-security/dfir/end-to-end-playbooks/ransomware.md): scope encryption, attack paths, backup impact and controlled recovery.
- [Credential theft](defensive-security/dfir/end-to-end-playbooks/credential-theft.md): examine sign-ins, changes to credentials, permissions and sessions.
- [Lateral movement](defensive-security/dfir/end-to-end-playbooks/lateral-movement.md): correlate logons, processes and remote administration.

### Investigation foundations

- [Windows endpoint triage](defensive-security/dfir/field-guides/windows-endpoint-triage.md)
- [Evidence acquisition and integrity](defensive-security/dfir/field-guides/evidence-acquisition-and-integrity.md)
- [Windows forensic artefact interpretation](defensive-security/dfir/field-guides/windows-artifact-interpretation.md)

## How to use this reference

For consistent article layouts and diagrams, see the [RootGuard documentation design system](design-system/README.md).

**1. Check the prerequisites.** Identify the product and query execution environment, the required audit settings, retention and permissions.

**2. Investigate, then corroborate.** A matching event is an observation, not a finding of compromise. Correlate multiple sources and document limitations.

**3. Control operational changes.** Containment and eradication require appropriate authorisation, evidence preservation and post-action checks.

**4. Verify validation status.** Many examples are conceptual or have undergone static safety review only. They are not presented as production-certified detections.

See the [runbook validation framework](defensive-security/dfir/runbooks/runbook-execution-validation-matrix.md) before relying on operational scripts.

## About RootGuard

RootGuard maintains separate **operational playbooks**, **technical references** and **optional practical exercises**. The primary purpose is to support real defensive investigations, not to present fictional datasets as operational tooling.

[Start Here](start-here/README.md) · [About the Author](welcome/who-am-i/README.md) · [Contributing and technical standards](contributing/README.md)
