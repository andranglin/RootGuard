---
description: Digital Forensics & Incident Response
---

# Digital Forensics & Incident Response (DFIR)

The discipline of investigating, containing, and remediating cyber incidents—combining investigative rigour with operational speed.

***

### What is DFIR?

DFIR integrates two complementary capabilities:

| Digital Forensics                        | Incident Response            |
| ---------------------------------------- | ---------------------------- |
| Evidence preservation & chain of custody | Real-time threat containment |
| Timeline reconstruction                  | Rapid triage & escalation    |
| Artifact & malware analysis              | Eradication & recovery       |
| Attribution & root cause                 | Stakeholder coordination     |

Together, they enable organisations to detect intrusions, understand scope, eliminate threats, and prevent recurrence.

***

### Why DFIR Matters

Modern adversaries move fast. The data speaks for itself:

| Metric                                    | Current State                    |
| ----------------------------------------- | -------------------------------- |
| Median time to exfiltration               | **2 days** (45% within 24 hours) |
| Ransomware dwell time                     | **5 days**                       |
| Average breach cost                       | **$4.88M**                       |
| Breaches involving cloud data             | **82%**                          |
| Repeat incidents (incomplete remediation) | **67%**                          |

_Sources: IBM Cost of a Data Breach 2024, Mandiant M-Trends 2024, Unit 42 IR Report 2024_

Without effective DFIR, organisations face extended dwell times, incomplete remediation, regulatory penalties, and catastrophic business disruption.

***

### The Threat Landscape

**What we're up against:**

* **Nation-state APTs** — Salt Typhoon, Volt Typhoon conducting multi-year intrusions using LOTL techniques
* **RaaS Operations** — LockBit, BlackCat, Qilin, RansomHub with double/triple extortion (87% of attacks)
* **Supply Chain Attacks** — Snowflake breach (165+ customers), credential theft at scale
* **Identity Compromise** — Stolen credentials remain top attack vector (292 days to detect)
* **AI-Enhanced Threats** — GenAI-powered phishing, deepfakes, automated reconnaissance

***

### DFIR Capabilities

#### Detection & Hunting

Proactive threat hunting, behavioural analytics, XDR correlation, and anomaly detection across hybrid environments.

#### Investigation & Forensics

Timeline reconstruction, memory forensics, cloud audit analysis, malware reverse engineering, and artifact examination.

#### Containment & Eradication

Rapid isolation, lateral movement prevention, persistence removal, and validated clean-state recovery.

#### Intelligence & Prevention

IOC extraction, TTP mapping to MITRE ATT\&CK, detection engineering, and lessons learned integration.

***

### Quantified Impact

Investments in DFIR capabilities deliver measurable returns:

| Capability                      | Impact                                   |
| ------------------------------- | ---------------------------------------- |
| AI/automation in prevention     | **$2.2M** cost reduction                 |
| Tested IR plan + dedicated team | **$248K** savings                        |
| Law enforcement engagement      | **\~$1M** savings, 63% avoid ransom      |
| XDR implementation              | **29 days** faster containment           |
| Internal detection capability   | **$1M** savings vs external notification |

***

### Core Tooling

| Category           | Examples                         |
| ------------------ | -------------------------------- |
| Endpoint Forensics | Velociraptor, KAPE, CyLR         |
| Memory Analysis    | Volatility, MemProcFS            |
| Log Analysis       | Chainsaw, Hayabusa, SIEM/XDR     |
| Network Forensics  | Zeek, Wireshark, full PCAP       |
| Cloud Forensics    | Native audit logs, CIEM tools    |
| Automation         | SOAR platforms, custom playbooks |

***

### Getting Started

\{% hint style="info" %\} This resource covers practical DFIR workflows, investigation techniques, detection engineering, and operational playbooks for security practitioners working in hybrid enterprise environments. \{% endhint %\}

**What you'll find here:**

* Investigation playbooks for common incident types
* KQL and detection queries for threat hunting
* Forensic artifact analysis guides
* Response procedures and checklists
* Tool configurations and automation scripts
