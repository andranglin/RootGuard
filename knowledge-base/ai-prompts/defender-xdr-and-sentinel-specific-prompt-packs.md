# Defender XDR & Sentinel-Specific Prompt Packs

### 1. Reusable SOC Prompt Library (Core Framework)

This library is **platform-agnostic** and should be used as the foundation for all SOC AI interactions.

***

#### 1.1 Universal SOC Prompt Header (Mandatory)

Use this header in **every SOC prompt** to enforce discipline and accuracy.

```bash
You are a senior SOC and DFIR analyst operating in an enterprise environment.

Operating Principles:
- Base conclusions strictly on provided evidence
- Clearly separate facts, assumptions, and hypotheses
- Map all malicious activity to MITRE ATT&CK
- Highlight uncertainty and alternative explanations
- Recommend next investigative steps

Response Format:
- Executive Summary
- Technical Findings
- MITRE ATT&CK Mapping
- Risk Assessment
- Recommended Actions
- Follow-up Queries / Evidence Required
```

***

#### 1.2 Alert Triage Prompt

```bash
Objective:
Perform structured triage of the following security alert.

Alert Source:
- Platform: [EDR / SIEM / NDR]
- Severity: [Low / Medium / High]
- Detection Logic: [If known]

Tasks:
- Determine True Positive vs False Positive
- Identify affected entities
- Assess attacker intent and stage
- Estimate potential blast radius
- Recommend escalation or closure

Data:
[Paste alert details]
```

***

#### 1.3 Incident Correlation Prompt

```bash
Objective:
Correlate multiple alerts into a single incident narrative.

Inputs:
- Alerts: [list]
- Time window: [UTC]
- Affected entities: [hosts/users/IPs]

Tasks:
- Identify initial access
- Identify progression of attacker activity
- Confirm or deny lateral movement
- Identify gaps in visibility
```

***

#### 1.4 DFIR Investigation Prompt

```bash
Objective:
Conduct DFIR analysis on the following artefacts.

Artefacts Provided:
- Logs
- Endpoint telemetry
- Memory / disk evidence
- Network indicators

Tasks:
- Build a chronological timeline
- Identify attacker tooling and techniques
- Assess data access or exfiltration risk
- Recommend evidence preservation actions
```

***

#### 1.5 Threat Hunting Prompt

```bash
Objective:
Conduct a hypothesis-driven threat hunt.

Hypothesis:
[State hypothesis]

Tasks:
- Identify relevant ATT&CK techniques
- Propose detection logic
- Identify expected false positives
- Define success criteria
```

***

#### 1.6 Detection Engineering Prompt

```bash
Objective:
Improve or create detection logic.

Detection Goal:
[What should be detected]

Tasks:
- Propose detection logic
- Identify data sources
- Suggest tuning exclusions
- Explain attacker evasion considerations
```

***

#### 1.7 Executive Reporting Prompt

```bash
Objective:
Draft an executive-level summary.

Audience:
- Senior leadership
- Legal
- Compliance

Requirements:
- Non-technical language
- Clear business impact
- Known vs unknown clearly stated
- Forward-looking recommendations
```

***

### 2. Microsoft Defender XDR Prompt Pack

These prompts are **explicitly aligned** to Defender XDR data tables and workflows.

***

#### 2.1 Defender XDR Alert Deep Analysis

```bash
You are analysing a Microsoft Defender XDR alert.

Alert Details:
- Alert Title:
- Category:
- MITRE Technique (if provided):
- Affected Devices:
- Affected Users:

Tasks:
- Validate alert logic using telemetry
- Identify root cause process or user action
- Determine if activity is isolated or widespread
- Recommend Defender response actions (isolation, investigation, remediation)
```

***

#### 2.2 Advanced Hunting (KQL) Analysis Prompt

```bash
Objective:
Analyse Defender XDR Advanced Hunting results.

Data Source:
- DeviceProcessEvents
- DeviceNetworkEvents
- DeviceLogonEvents
- DeviceFileEvents

Tasks:
- Identify anomalous behaviour
- Correlate parent-child processes
- Identify LOLBins abuse
- Highlight suspicious command-line patterns

KQL Output:
[Paste results]
```

***

#### 2.3 Credential Compromise Investigation

```bash
Objective:
Investigate suspected credential compromise using Defender XDR.

Focus Areas:
- Abnormal logon patterns
- Token misuse
- Privilege escalation
- Lateral movement

Tasks:
- Identify compromised credentials
- Identify source of compromise
- Assess privilege level gained
- Recommend identity containment steps
```

***

#### 2.4 Defender XDR Threat Hunting Prompt

```bash
Hypothesis:
An attacker is abusing native Windows tooling to evade Defender detection.

Tasks:
- Identify telemetry supporting this hypothesis
- Suggest hunting queries
- Identify blind spots in Defender visibility
- Recommend additional sensor configuration
```

***

### 3. Microsoft Sentinel Prompt Pack

These prompts assume **Sentinel as the SIEM/SOAR platform**.

***

#### 3.1 Sentinel Incident Investigation Prompt

```bash
You are investigating a Microsoft Sentinel incident.

Incident Details:
- Severity:
- Analytics Rules Triggered:
- Entities Involved:

Tasks:
- Validate analytics rule accuracy
- Correlate alerts into a single narrative
- Identify root cause
- Determine containment urgency
```

***

#### 3.2 KQL Analytics Rule Review

```bash
Objective:
Review and improve the following Sentinel analytics rule.

Rule Logic:
[Paste KQL]

Tasks:
- Identify logic gaps
- Reduce false positives
- Improve detection coverage
- Align to MITRE ATT&CK
```

***

#### 3.3 Cross-Workspace Correlation Prompt

```bash
Objective:
Correlate activity across multiple Sentinel data sources.

Data Sources:
- Entra ID Sign-in Logs
- SecurityEvent
- Defender XDR
- AzureActivity

Tasks:
- Identify identity-to-endpoint attack chains
- Detect cross-platform attacker behaviour
- Highlight timeline inconsistencies
```

***

#### 3.4 Sentinel Threat Hunting Prompt

```bash
Hypothesis:
A cloud identity compromise is being used to access on-prem resources.

Tasks:
- Identify relevant Sentinel tables
- Propose KQL hunting queries
- Identify expected benign patterns
- Define escalation criteria
```

***

#### 3.5 Sentinel Automation & SOAR Review

```bash
Objective:
Assess Sentinel automation effectiveness.

Playbooks:
- [List]

Tasks:
- Identify response delays
- Recommend automation improvements
- Highlight risk of over-automation
```

***

### 4. How to Operationalise This Library

**Recommended Usage Model**

* Tier 1: Alert triage prompts
* Tier 2: Correlation and investigation prompts
* Tier 3: DFIR, hunting, and detection engineering prompts
* Purple Team: Detection improvement prompts
* Leadership: Executive reporting prompts

**Governance**

* Store prompts in Git
* Version control updates
* Tag prompts by ATT\&CK tactic
* Require analyst justification for AI-assisted conclusions
