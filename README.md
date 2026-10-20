---
cover: .gitbook/assets/RootGuardLandingPage.png
coverY: 0
coverHeight: 236
layout:
  width: default
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# RootGuard

#### Security Operations, Detection Engineering & Incident Response

**Practical guidance for cybersecurity practitioners.**

RootGuard is an independent cybersecurity knowledge base for practitioners working across detection engineering, threat hunting, digital forensics and incident response, cloud and identity security, and defensive security architecture.

The aim is to turn complex security concepts into usable investigation workflows, KQL and PowerShell examples, technical references, and operational playbooks. Each example should be reviewed and adapted to its environment, available telemetry, and applicable permissions before use.

#### Core Objectives

* **Identity Security:** Mitigation strategies for Active Directory and Entra ID vectors.
* **Digital Forensics & IR:** Methodologies for surgical breach reconstruction.
* **Detection Engineering:** Development of high-fidelity alerting logic.

***

### Find what you need

| Your objective | Start here |
| --- | --- |
| New to RootGuard | [Start Here](start-here/README.md) |
| Follow a structured learning route | [Guided Learning Paths](learning-paths/README.md) |
| Investigate a security incident | [Digital Forensics & Incident Response](defensive-security/dfir/README.md) |
| Build or validate a detection | [Threat Detection & Hunting](detection-engineering/threat-detection/README.md) |
| Review secure design decisions | [Security Architecture & Engineering](security-architecture/README.md) |
| Contribute or review guidance | [Documentation Standards](contributing/README.md) |

> **Using technical content:** Confirm prerequisites and product versions before executing commands. Detection examples without reproducible validation evidence are not production-ready rules.

***

### Technical Modules

#### 🛡️ Detection Engineering & KQL

High-signal logic for detecting evasion techniques.

* **Identity Forgery:** Golden/Silver Ticket analysis.
* **Credential Attacks:** Kerberoasting, AS-REP Roasting, and DCSync detection.
* **Lateral Movement:** Pass-the-Ticket and Overpass-the-Hash validation.
* **Cloud Security:** Entra ID compromise and privilege escalation monitoring.
* _**Scope:** Example queries for Microsoft Sentinel and Microsoft Defender XDR; validate table availability and schema before use._

#### 🔬 Windows Forensics & DFIR

Deep-dive artifact analysis for evidence verification.

* **Execution Evidence:** Registry analysis (ShimCache, AmCache, UserAssist).
* **Timeline Reconstruction:** Event Logs, Prefetch, SRUM, and BAM data.
* **Attack Patterns:** Correlating persistence mechanisms and lateral movement.
* _**Output:** Structured timelines and correlation playbooks._

#### 🩸 Incident Response Playbooks

Lifecycle management from detection to recovery.

* **Triage:** Rapid assessment protocols.
* **Containment:** Privilege escalation isolation.
* **Recovery:** Ransomware response procedures.
* **Data Protection:** Exfiltration detection and blocking at the wire.

#### ⚔️ Offensive Security for Defenders

Adversary tradecraft analysis for proactive hardening.

* **Access Vectors:** Credential stuffing, spraying, and brute-force patterns.
* **Lateral Movement:** Analysis of PsExec, WMI, and WinRM traffic.
* **Exploitation:** Post-exploitation techniques and "living-off-the-land" binaries.

#### 🕸️ Malware & Network Forensics

Artifact dissection and traffic analysis.

* Static and dynamic malware analysis workflows.
* PCAP investigation using Wireshark and TShark.
* IOC extraction and behavioural hunting rule generation.

***

### The RootGuard Standard

<table data-header-hidden><thead><tr><th width="164.9091796875"></th><th></th></tr></thead><tbody><tr><td><strong>Feature</strong></td><td><strong>Operational Value</strong></td></tr><tr><td>Actionable Utility</td><td>Prioritises exact commands, queries, log samples, and execution steps over theory.</td></tr><tr><td>Platform Agnostic</td><td>Core principles apply universally, supported by deep integration with the Microsoft ecosystem.</td></tr><tr><td>Living Intelligence</td><td>Continuously updated based on emerging threats and operational feedback.</td></tr><tr><td>Defender Centric</td><td>Focused on practical defensive workflows, with validation and limitations identified where relevant.</td></tr></tbody></table>

***

### Access the Arsenal

* [Detection Engineering](detection-engineering/threat-detection/attack-triage-playbooks-kql-triage/README.md): AD Attacks & KQL Triage
* [Defensive Security](defensive-security/dfir/README.md): Windows Forensics & IR Strategies
* [Offensive Security](offensive-security/hacking/exploitation-and-lateral-movement/README.md): Exploitation & Password Attacks
* [Knowledge Base](knowledge-base/junior-analyst-skills/README.md): Security operations concepts, technical references, and investigation notes
* [About the Author](welcome/who-am-i/README.md): Operational Background

***

**RootGuard:** Learn the systems. Validate the evidence. Improve the defence.

_**Authorised for defensive operations only. Ensure compliance with all applicable legal frameworks and ethical standards.**_
