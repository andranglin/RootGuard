---
cover: ../../.gitbook/assets/RootGuardHackingLandingPage.png
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
  metadata:
    visible: true
---

# Hacking

Authorised simulated attacks against systems and networks to identify vulnerabilities before adversaries do—providing defenders with an attacker's perspective.

***

### What is Penetration Testing?

Penetration testing (pentesting) is the controlled practice of attacking your own environment to discover exploitable weaknesses. Unlike vulnerability scanning, pentesting validates whether vulnerabilities can actually be exploited and chains them together to demonstrate real-world impact.

| Vulnerability Assessment        | vs | Penetration Testing   |
| ------------------------------- | -- | --------------------- |
| Identifies potential weaknesses |    | Proves exploitability |
| Automated scanning              |    | Manual + automated    |
| Breadth-focused                 |    | Depth-focused         |
| "This could be vulnerable"      |    | "I got Domain Admin"  |

**The goal:** Find and fix weaknesses before threat actors exploit them.

***

### Why SOC Analysts Should Care

Pentesting directly improves defensive operations:

| Pentest Output          | SOC Benefit                |
| ----------------------- | -------------------------- |
| Attack paths documented | Detection rule development |
| Techniques used         | Purple team validation     |
| Controls bypassed       | Gap identification         |
| Dwell time achieved     | MTTD benchmarking          |
| Logs generated          | Alert tuning opportunities |

\{% hint style="info" %\} **Key insight:** Every pentest is a detection engineering opportunity. If the red team moved laterally undetected, your detections have gaps. \{% endhint %\}

***

### Types of Penetration Testing

<table><thead><tr><th width="190">Type</th><th width="199">Scope</th><th>Focus</th></tr></thead><tbody><tr><td><strong>External</strong></td><td>Internet-facing assets</td><td>Perimeter defences, web apps, VPN, email</td></tr><tr><td><strong>Internal</strong></td><td>Inside the network</td><td>Lateral movement, privilege escalation, AD</td></tr><tr><td><strong>Web Application</strong></td><td>Specific applications</td><td>OWASP Top 10, business logic flaws</td></tr><tr><td><strong>Wireless</strong></td><td>WiFi networks</td><td>Rogue APs, WPA2 attacks, segmentation</td></tr><tr><td><strong>Social Engineering</strong></td><td>Human element</td><td>Phishing, vishing, physical access</td></tr><tr><td><strong>Cloud</strong></td><td>AWS/Azure/GCP</td><td>Misconfigurations, IAM, storage exposure</td></tr></tbody></table>

***

### Pentest vs Red Team vs Purple Team

| Engagement      | Objective                 | SOC Awareness    |
| --------------- | ------------------------- | ---------------- |
| **Pentest**     | Find vulnerabilities      | Usually informed |
| **Red Team**    | Test detection & response | Typically blind  |
| **Purple Team** | Collaborative improvement | Fully integrated |

**For SOC improvement:** Purple team exercises deliver the most value—attackers and defenders working together to validate and enhance detections in real-time.

***

### The Pentest Lifecycle

```bash
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│    Recon     │ →  │ Enumeration  │ →  │Exploitation  │
│              │    │              │    │              │
│ OSINT        │    │ Port scanning│    │ Initial      │
│ DNS enum     │    │ Service ID   │    │ access       │
│ Email harvest│    │ Vuln scanning│    │ Payload exec │
└──────────────┘    └──────────────┘    └──────────────┘
                                               │
┌──────────────┐    ┌──────────────┐           ▼
│  Reporting   │ ←  │Post-Exploit  │    ┌──────────────┐
│              │    │              │    │  Priv Esc    │
│ Findings     │    │ Persistence  │    │              │
│ Evidence     │    │ Lateral move │    │ Local admin  │
│ Remediation  │    │ Data access  │    │ Domain admin │
└──────────────┘    └──────────────┘    └──────────────┘
```

***

### Standard Techniques (What to Detect)

<table><thead><tr><th width="184">Phase</th><th>Techniques</th><th>Detection Opportunities</th></tr></thead><tbody><tr><td><strong>Recon</strong></td><td>DNS enumeration, port scanning</td><td>Firewall logs, IDS alerts</td></tr><tr><td><strong>Initial Access</strong></td><td>Phishing, exploit public apps</td><td>Email gateway, WAF, EDR</td></tr><tr><td><strong>Execution</strong></td><td>PowerShell, scripting engines</td><td>Script block logging, AMSI</td></tr><tr><td><strong>Persistence</strong></td><td>Scheduled tasks, registry, services</td><td>Sysmon, autoruns monitoring</td></tr><tr><td><strong>Priv Esc</strong></td><td>Token manipulation, UAC bypass</td><td>Sensitive privilege use</td></tr><tr><td><strong>Credential Access</strong></td><td>LSASS dump, Kerberoasting</td><td>Credential access events</td></tr><tr><td><strong>Lateral Movement</strong></td><td>PsExec, WMI, RDP, SMB</td><td>Logon events, network auth</td></tr><tr><td><strong>Exfiltration</strong></td><td>DNS tunneling, cloud storage</td><td>DLP, proxy logs, DNS analytics</td></tr></tbody></table>

\{% hint style="warning" %\} **Detection gap check:** Review pentest reports for techniques that went undetected. Each one is a detection engineering backlog item. \{% endhint %\}

***

### Pentesting's Role in Security Programs

#### Validates Controls

Confirms whether security investments actually stop attacks—or just generate dashboards.

#### Tests Detection Capability

Reveals blind spots in logging, alerting, and response procedures.

#### Demonstrates Risk

Translates technical vulnerabilities into business impact for executive communication.

#### Meets Compliance

Required by PCI-DSS, HIPAA, SOC 2, and numerous regulatory frameworks.

#### Drives Prioritisation

Exploitable vulnerabilities get fixed faster than theoretical ones.

***

### Leveraging Pentest Results as a SOC Analyst

**During the engagement:**

* Monitor for pentest activity (if aware)—validate your detections fire
* Note timestamps of attacker actions for log correlation
* Track which alerts triggered and which didn't

**After the engagement:**

* Request detailed logs of all techniques attempted
* Map findings to MITRE ATT\&CK techniques
* Build or tune detections for gaps identified
* Create purple team scenarios from successful attack paths
* Update runbooks with observed attack patterns

***

### Key Metrics from Pentesting

| Metric                            | What It Measures                  |
| --------------------------------- | --------------------------------- |
| Time to initial access            | Perimeter effectiveness           |
| Time to Domain Admin              | Internal control strength         |
| Techniques undetected             | Detection coverage gaps           |
| Mean time to detect (if red team) | SOC responsiveness                |
| Critical findings count           | Overall security posture          |
| Remediation time                  | Vulnerability management maturity |

***

### Building Offensive Awareness

SOC analysts benefit from understanding attacker methodology:

| Skill                      | Defensive Application              |
| -------------------------- | ---------------------------------- |
| Basic exploitation         | Understand what alerts mean        |
| Privilege escalation paths | Recognise post-compromise activity |
| AD attack techniques       | Detect Kerberoasting, DCSync, etc. |
| Evasion methods            | Anticipate detection bypasses      |
| C2 frameworks              | Identify beacon behaviour          |

**Resources:**

* TryHackMe / HackTheBox — Hands-on practice
* PNPT / OSCP — Structured learning paths
* Atomic Red Team — Technique simulation
* MITRE ATT\&CK — Technique reference

***

### Quick Wins

1. **Read pentest reports** — Understand what was found and how
2. **Map to ATT\&CK** — Translate findings into detection opportunities
3. **Request raw logs** — Correlate pentest activity with your telemetry
4. **Build detections** — Create rules for techniques that bypassed controls
5. **Run atomic tests** — Simulate techniques to validate new detections
6. **Join purple teams** — Collaborate directly with offensive testers

***

_Penetration testing tells you what's broken. Detection engineering ensures you see it next time._
