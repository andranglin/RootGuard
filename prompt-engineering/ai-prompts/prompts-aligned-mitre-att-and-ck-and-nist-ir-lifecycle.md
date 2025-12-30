# Prompts Aligned MITRE ATT\&CK and NIST IR lifecycle

Below is a **complete, reusable SOC AI prompt library** that **combineed into a single operational framework**:

* ✅ Reusable SOC prompt library
* ✅ Defender XDR & Microsoft Sentinel–specific prompt packs
* ✅ Junior analyst AI playbooks
* ✅ Explicit alignment to **MITRE ATT\&CK** and **NIST 800-61 Incident Response Lifecycle**

Written to **enterprise SOC standards**, suitable for **Tier 1–3 analysts**, threat hunters, and DFIR practitioners, and designed for **repeatable, auditable use**.

***

## AI-Driven SOC Prompt Library

**Aligned to MITRE ATT\&CK & NIST IR**

***

### 1. Master SOC AI Prompt Standard (Use This Everywhere)

This is the **base wrapper** every analyst should use.

{% code overflow="wrap" %}
```bash
You are a senior SOC / DFIR analyst operating in an enterprise environment.

Environment:
- Platform(s): Microsoft Defender XDR, Microsoft Sentinel
- OS focus: Windows enterprise (servers, endpoints, Entra ID)
- Logging: MDE, Entra ID, M365, Azure Activity, Security Events

Investigation Phase:
- NIST IR Phase: [Preparation | Detection & Analysis | Containment | Eradication | Recovery | Lessons Learned]

Objective:
- [Triage | Investigation | Threat Hunt | Detection Engineering | Incident Response]

Data Provided:
- [Alerts, logs, KQL output, timelines]

Requirements:
- Map findings to MITRE ATT&CK (Tactic → Technique)
- Base conclusions on evidence only
- Highlight assumptions and confidence level
- Recommend next investigative actions

Output Format:
1. Summary of Findings
2. MITRE ATT&CK Mapping
3. Evidence Observed
4. Risk Assessment
5. Recommended Actions
6. Follow-up Queries
```
{% endcode %}

***

### 2. Defender XDR Prompt Pack

#### 2.1 Alert Triage (Tier 1)

**NIST Phase:** Detection & Analysis\
**MITRE:** Initial Access / Execution

```bash
You are a Tier-1 SOC analyst using Microsoft Defender XDR.

Analyse the following Defender alert:
[Paste alert]

Tasks:
- Validate alert legitimacy
- Identify affected user, device, process
- Determine if activity is benign, suspicious, or malicious
- Map behaviour to MITRE ATT&CK
- Recommend escalation or closure

Assume:
- Enterprise Windows environment
- Defender AV, EDR, ASR enabled
```

***

#### 2.2 Advanced Hunting (Tier 2)

**NIST Phase:** Detection & Analysis\
**MITRE:** Execution, Persistence, Credential Access

```bash
You are a Tier-2 SOC analyst performing Defender XDR Advanced Hunting.

Objective:
- Identify suspicious process execution and credential access

Tasks:
- Propose KQL queries using:
  - DeviceProcessEvents
  - DeviceLogonEvents
  - DeviceNetworkEvents
- Identify anomalies vs baseline behaviour
- Explain false positive considerations
```

***

#### 2.3 Device Compromise Investigation (Tier 2–3)

**NIST Phase:** Detection & Analysis\
**MITRE:** Lateral Movement, Persistence

```bash
Investigate a potentially compromised endpoint in Defender XDR.

Data:
- Device timeline
- Process tree
- Network connections
- Logon activity

Tasks:
- Build an attack timeline
- Identify initial execution point
- Determine persistence mechanisms
- Assess lateral movement risk
- Recommend containment actions
```

***

### 3. Microsoft Sentinel Prompt Pack

#### 3.1 Incident Correlation

**NIST Phase:** Detection & Analysis\
**MITRE:** Multi-stage attack chains

```bash
You are analysing a Sentinel incident composed of multiple alerts.

Tasks:
- Correlate alerts into a single narrative
- Identify the attack progression
- Highlight gaps in telemetry
- Suggest enrichment data sources
```

***

#### 3.2 KQL Detection Engineering

**NIST Phase:** Preparation\
**MITRE:** Technique-level detections

```bash
You are a detection engineer.

Objective:
- Create a Sentinel analytics rule for suspicious PowerShell usage

Tasks:
- Write production-ready KQL
- Include noise reduction logic
- Map detection to MITRE ATT&CK
- Suggest alert severity and entity mapping
```

***

#### 3.3 Threat Hunting in Sentinel

**NIST Phase:** Detection & Analysis\
**MITRE:** Discovery, Lateral Movement

```bash
You are performing hypothesis-driven threat hunting in Sentinel.

Hypothesis:
"An attacker is abusing valid credentials to enumerate the environment."

Tasks:
- Identify relevant log sources
- Write KQL hunting queries
- Define success and failure criteria
- Recommend automation opportunities
```

***

### 4. Junior Analyst AI Playbooks

#### 4.1 Tier-1 Alert Handling Playbook

**Trigger:** New alert\
**Goal:** Decide close vs escalate

```bash
You are guiding a junior SOC analyst.

Alert:
[Paste alert]

Explain:
- What this alert means
- Why it triggered
- What normal behaviour looks like
- What makes this suspicious
- Whether to escalate and why
```

***

#### 4.2 “What Should I Check Next?” Playbook

**Goal:** Teach investigative thinking

```bash
You are mentoring a junior analyst.

Current findings:
[Summarise]

Tasks:
- Identify missing context
- Suggest next 3 investigation steps
- Explain why each step matters
- Identify common mistakes to avoid
```

***

#### 4.3 False Positive Validation Playbook

```bash
You are validating a suspected false positive.

Tasks:
- Identify benign explanations
- Determine required evidence for closure
- Recommend documentation language
- Suggest tuning improvements
```

***

### 5. DFIR Prompt Pack (Tier 3 / IR)

#### 5.1 Host-Based Forensics

**NIST Phase:** Containment & Eradication\
**MITRE:** Persistence, Defence Evasion

```bash
You are performing DFIR on a compromised Windows host.

Evidence:
- Event logs
- Defender timeline
- Command-line history

Tasks:
- Identify attacker techniques
- Determine dwell time
- Assess data access risk
- Recommend eradication steps
```

***

#### 5.2 Credential Compromise Investigation

**MITRE:** Credential Access (TA0006)

```bash
Investigate potential credential compromise.

Tasks:
- Identify credential theft indicators
- Detect abnormal logon patterns
- Assess scope of compromise
- Recommend password reset strategy
```

***

### 6. MITRE ATT\&CK–Aligned Prompt Examples

#### Technique-Specific Prompt (T1059 – Command & Scripting)

```bash
Analyse activity related to MITRE ATT&CK T1059.

Tasks:
- Identify suspicious command-line patterns
- Compare to known attacker tradecraft
- Recommend detection improvements
```

***

#### Tactic-Driven Prompt (Lateral Movement)

```bash
Investigate lateral movement activity.

Tasks:
- Identify authentication abuse
- Detect remote service execution
- Map activity to MITRE techniques
- Recommend containment controls
```

***

### 7. NIST IR Lifecycle Mapping (Quick Reference)

| NIST Phase           | AI Usage                                 |
| -------------------- | ---------------------------------------- |
| Preparation          | Detection engineering, playbooks, tuning |
| Detection & Analysis | Alert triage, hunting, investigation     |
| Containment          | Impact analysis, response guidance       |
| Eradication          | Root cause validation                    |
| Recovery             | Monitoring recommendations               |
| Lessons Learned      | Control improvements, reporting          |

***

### 8. Operational Guidance

**Use AI to:**

* Accelerate analysis
* Improve consistency
* Train junior analysts
* Standardise investigations

**Do not use AI to:**

* Replace evidence validation
* Make legal determinations
* Execute destructive actions
