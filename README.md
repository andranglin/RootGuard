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

#### Operational Defence & Incident Response Procedures

**Practical. Field-Tested. Enterprise-Ready.**

RootGuard serves as a comprehensive field manual for SOC analysts, detection engineers, and incident responders operating in high-threat environments. Moving beyond theoretical certification checklists, this repository focuses on immediate operational utility for active defence scenarios.

We provide high-density, deployment-ready resources: precision KQL queries, forensic artifact breakdowns, and structured playbooks designed to detect, contain, and eradicate sophisticated threats.

#### Core Objectives

* **Identity Security:** Mitigation strategies for Active Directory and Entra ID vectors.
* **Digital Forensics & IR:** Methodologies for surgical breach reconstruction.
* **Detection Engineering:** Development of high-fidelity alerting logic.

***

### Technical Modules

#### 🛡️ Detection Engineering & KQL

High-signal logic for detecting evasion techniques.

* **Identity Forgery:** Golden/Silver Ticket analysis.
* **Credential Attacks:** Kerberoasting, AS-REP Roasting, and DCSync detection.
* **Lateral Movement:** Pass-the-Ticket and Overpass-the-Hash validation.
* **Cloud Security:** Entra ID compromise and privilege escalation monitoring.
* _**Scope:** Deployable queries optimised for Microsoft Sentinel & Defender._

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

<table data-header-hidden><thead><tr><th width="164.9091796875"></th><th></th></tr></thead><tbody><tr><td><strong>Feature</strong></td><td><strong>Operational Value</strong></td></tr><tr><td>Actionable Utility</td><td>Prioritises exact commands, queries, log samples, and execution steps over theory.</td></tr><tr><td>Platform Agnostic</td><td>Core principles apply universally, supported by deep integration with the Microsoft ecosystem.</td></tr><tr><td>Living Intelligence</td><td>Continuously updated based on emerging threats and operational feedback.</td></tr><tr><td>Defender Centric</td><td>Derived from active incident response engagements and real-world breach data.</td></tr></tbody></table>

***

### Access the Arsenal

* [Detection Engineering](https://rootguard.gitbook.io/cyberops/detection-engineering/attack-triage-playbooks-kql-triage): AD Attacks & KQL Triage
* [Defensive Security](https://rootguard.gitbook.io/cyberops/detection-engineering/ad-detections-and-mitigations): Windows Forensics & IR Strategies
* [Offensive Security](https://rootguard.gitbook.io/cyberops/offensive-security/exploitation-and-lateral-movement): Exploitation & Password Attacks
* [Learning Hub](https://rootguard.gitbook.io/cyberops): Core Skills & Career Development
* [About the Author](https://www.google.com/search?q=https://rootguard.gitbook.io/cyberops/about-the-author): Operational Background

***

**RootGuard:** Elevating the defensive baseline.

_**Authorised for defensive operations only. Ensure compliance with all applicable legal frameworks and ethical standards.**_
