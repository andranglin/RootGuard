# Foundational Prompt Structure

### Introduction

Below is a **structured set of AI prompt patterns and concrete examples**, designed explicitly for **DFIR and SOC investigations**. These are written from the perspective of an experienced **Cyber/SOC Analyst**, aligned with modern SOC tooling (Defender XDR, Sentinel, Splunk, Velociraptor, KQL, PowerShell) and framed to support **repeatable, high-fidelity investigations**.

The intent is to help **operationalise AI as a junior analyst, investigation assistant, and threat-hunting co-pilot**, not as a decision-maker.

### 1. Foundational Prompt Structure (Recommended Standard)

Use this structure consistently to maximise signal and minimise hallucination:

**Prompt Template**

```bash
You are a senior DFIR and SOC analyst.

Context:
- Environment: [Cloud / Hybrid / On-prem]
- Platform(s): [Defender XDR, Sentinel, Splunk, Velociraptor, etc.]
- Time window: [UTC]
- Scope: [Users, hosts, IPs, tenants]

Objective:
- [Detection | Triage | Investigation | Threat Hunt | Root Cause Analysis]

Data Provided:
- [Logs, alerts, KQL output, timelines, artefacts]

Constraints:
- Assume enterprise Windows environment
- Map findings to MITRE ATT&CK
- Prioritise evidence-based conclusions
- Highlight uncertainties and next steps

Output Required:
- Findings summary
- Indicators of compromise
- Likely attacker objectives
- Recommended containment actions
- Follow-up queries or artefacts to collect
```

***

### 2. SOC Alert Triage Prompts

#### Example 1 – Defender XDR Alert Triage

```bash
You are a Tier-2 SOC analyst.

Analyse the following Microsoft Defender XDR alert:

[Paste alert JSON or text]

Tasks:
- Determine if the alert is true positive or false positive
- Identify affected entities (user, device, process)
- Map activity to MITRE ATT&CK techniques
- Assess potential blast radius
- Recommend immediate response actions

Assume:
- Windows enterprise environment
- Hybrid Entra ID + MDE deployment
```

***

#### Example 2 – Sentinel Incident Analysis

```bash
You are performing SOC incident triage in Microsoft Sentinel.

Given this incident:
- Incident severity: High
- Triggered analytics rules: [list]
- Entities involved: [list]

Tasks:
- Correlate alerts into a single attack narrative
- Identify the initial access vector
- Determine if lateral movement occurred
- Recommend containment and eradication steps
- Suggest KQL queries to validate assumptions
```

***

### 3. DFIR Investigation Prompts

#### Example 3 – Host-Based Forensics (Windows)

```bash
You are conducting a DFIR investigation on a Windows host.

Evidence available:
- Windows Security Logs
- Sysmon logs
- MDE Advanced Hunting output
- Command-line history
- Scheduled tasks

Objective:
- Identify signs of attacker execution or persistence
- Determine if credential access occurred
- Identify suspicious parent-child process relationships

Output:
- Timeline of malicious activity
- MITRE ATT&CK mapping
- Confidence level of compromise
- Artefacts to preserve for legal or post-incident review
```

***

#### Example 4 – Memory and Process Analysis

```bash
You are assisting with memory forensics.

Given:
- Volatility 3 output (pslist, netscan, cmdline)
- Suspicious process name: [process]
- Host role: Domain Controller

Tasks:
- Assess whether the process is malicious or abused
- Identify injected code or abnormal network connections
- Determine likely attacker tooling
- Recommend next forensic steps
```

***

### 4. Threat Hunting Prompts

#### Example 5 – Hypothesis-Driven Threat Hunt

{% code overflow="wrap" %}
```bash
You are a threat hunter.

Hypothesis:
"An attacker has obtained valid credentials and is performing discovery and lateral movement using native Windows tools."

Tasks:
- Identify relevant MITRE ATT&CK techniques
- Propose KQL queries to detect this behaviour
- Explain expected false positives
- Define success criteria for the hunt

Environment:
- Defender XDR + Sentinel
- Windows endpoints and servers
```
{% endcode %}

***

#### Example 6 – Living-off-the-Land (LOLBins)

```bash
You are hunting for Living-off-the-Land activity.

Focus:
- PowerShell
- rundll32
- mshta
- wmic
- certutil

Tasks:
- Identify suspicious execution patterns
- Provide detection logic (KQL or SPL)
- Explain how attackers typically abuse these binaries
- Suggest hardening or detection improvements
```

***

### 5. Log Analysis and Query Generation

#### Example 7 – KQL Query Refinement

```bash
You are a SOC engineer assisting with KQL.

Given this objective:
"Detect suspicious command-line activity related to credential dumping"

Tasks:
- Write an efficient KQL query using DeviceProcessEvents
- Include exclusions to reduce noise
- Explain each part of the query
- Suggest tuning improvements
```

***

#### Example 8 – Velociraptor DFIR Queries

```bash
You are supporting a DFIR investigation using Velociraptor.

Objective:
- Identify persistence mechanisms on Windows endpoints

Tasks:
- Suggest relevant VQL artefacts
- Explain what each artefact collects
- Identify indicators of malicious persistence
```

***

### 6. Incident Response & Decision Support Prompts

#### Example 9 – Containment Strategy

```bash
You are advising on incident containment.

Scenario:
- Confirmed credential compromise
- Possible lateral movement
- No confirmed data exfiltration yet

Tasks:
- Recommend immediate containment steps
- Identify actions that risk evidence destruction
- Propose a phased response plan
- Highlight business-impact considerations
```

***

### 7. Executive and Reporting Prompts

#### Example 10 – Post-Incident Report Drafting

```bash
You are preparing a DFIR executive summary.

Audience:
- CISO
- Legal
- Senior leadership

Tasks:
- Summarise the incident in plain language
- Explain attacker objectives and impact
- Avoid technical jargon
- Clearly state what is known, unknown, and assumed
- Provide forward-looking recommendations
```

***

### 8. Best Practices for Using AI in SOC & DFIR

**Always:**

* Provide logs, not conclusions
* Ask for evidence-based reasoning
* Request MITRE ATT\&CK mapping
* Ask for uncertainty and confidence levels
* Use AI for analysis acceleration, not authority

**Never:**

* Blindly trust AI verdicts
* Use AI outputs without validation
* Treat AI as legal or forensic final authority
