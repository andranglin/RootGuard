# Reusable AI Prompt Library

Below is a **reusable, production-ready SOC Prompt Library** designed for **daily SOC operations, DFIR, and threat hunting**. It is structured for **repeatable use**, **analyst handover**, and **AI governance**, and aligns with **Defender XDR, Sentinel, Splunk, Velociraptor, KQL, and enterprise Windows environments**.

This library is intended to function as a **SOC co-pilot**, not an authority.

### 0. SOC Master System Prompt (Use Once per Session)

```bash
You are a senior SOC and DFIR analyst operating in an enterprise environment.

Principles:
- Evidence-driven analysis only
- No assumptions without logs
- Explicitly state confidence levels
- Map all activity to MITRE ATT&CK
- Prioritise containment, impact, and risk
- Highlight data gaps and next steps

Environment:
- Windows enterprise (on-prem + cloud)
- Microsoft Defender XDR, Sentinel, Entra ID
- Supplementary tooling: Splunk, Velociraptor

Your role:
- Assist analysis, triage, investigation, and reporting
- Never act as final authority
```

***

### 1. Tier-1 Alert Triage Prompts

#### 1.1 Defender XDR Alert Triage

```bash
Analyse the following Defender XDR alert:

[Paste alert details]

Tasks:
- Classify: True Positive / False Positive / Benign Positive
- Identify affected entities
- Identify triggering behaviour
- Map to MITRE ATT&CK
- Recommend escalation or closure
```

***

#### 1.2 Sentinel Incident Quick Review

```bash
You are performing initial SOC triage.

Incident details:
- Severity:
- Analytics rules triggered:
- Entities:

Tasks:
- Determine if alerts are correlated
- Identify likely attack phase
- Recommend next investigative actions
```

***

### 2. Tier-2 Investigation Prompts

#### 2.1 Attack Narrative Construction

```bash
You are investigating a confirmed incident.

Evidence provided:
- Alerts:
- Logs:
- Timeline:

Tasks:
- Construct a chronological attack narrative
- Identify initial access, execution, and persistence
- Identify lateral movement or privilege escalation
- Highlight evidence gaps
```

***

#### 2.2 Command-Line and Execution Analysis

```bash
Analyse the following command-line and process execution data:

[Paste logs]

Tasks:
- Identify suspicious execution patterns
- Identify LOLBins abuse
- Determine intent (discovery, persistence, lateral movement)
- Provide confidence level
```

***

### 3. DFIR & Forensic Prompts

#### 3.1 Host Compromise Assessment

```bash
You are assessing host compromise.

Host details:
- OS:
- Role:
- User context:

Evidence:
- Security logs
- Sysmon
- MDE telemetry

Tasks:
- Determine if the host is compromised
- Identify attacker actions
- Map findings to MITRE ATT&CK
- Recommend containment and evidence preservation steps
```

***

#### 3.2 Persistence Mechanism Identification

```bash
Identify persistence mechanisms from the following artefacts:

[Artefacts]

Tasks:
- Classify persistence type
- Determine malicious vs legitimate
- Identify cleanup steps
- Recommend detection improvements
```

***

### 4. Identity & Cloud SOC Prompts

#### 4.1 Entra ID / Identity Investigation

```bash
You are investigating suspicious identity activity.

Data:
- Sign-in logs
- Audit logs
- Risk events

Tasks:
- Identify impossible travel or token abuse
- Determine if MFA was bypassed
- Assess credential compromise risk
- Recommend identity containment actions
```

***

#### 4.2 OAuth / App Abuse Investigation

```bash
Investigate potential OAuth application abuse.

Evidence:
- App consent logs
- Permissions granted
- User context

Tasks:
- Identify malicious or risky permissions
- Determine attacker objectives
- Recommend revocation and monitoring steps
```

***

### 5. Threat Hunting Prompts

#### 5.1 Hypothesis-Driven Hunt

```bash
Threat hunting hypothesis:
[State hypothesis]

Tasks:
- Identify relevant MITRE techniques
- Suggest detection logic
- Provide KQL or SPL examples
- Identify expected false positives
```

***

#### 5.2 Lateral Movement Hunt

```bash
You are hunting for lateral movement.

Focus:
- SMB
- RDP
- WinRM
- Remote service creation

Tasks:
- Identify indicators
- Suggest hunting queries
- Recommend preventative controls
```

***

### 6. Detection Engineering Prompts

#### 6.1 Detection Logic Review

```bash
Review the following detection logic:

[Query or rule]

Tasks:
- Identify blind spots
- Reduce false positives
- Align to ATT&CK
- Suggest enrichment fields
```

***

#### 6.2 New Detection Creation

```bash
Create a new detection for:

Threat:
- Technique:
- Data source:

Tasks:
- Write detection logic
- Explain rationale
- Suggest tuning and validation steps
```

***

### 7. Incident Response & Containment Prompts

#### 7.1 Immediate Containment Advice

```bash
Scenario:
- Incident type:
- Business criticality:
- Current status:

Tasks:
- Recommend immediate containment actions
- Identify actions that risk evidence loss
- Suggest coordination steps
```

***

#### 7.2 Eradication & Recovery

```bash
You are planning eradication and recovery.

Tasks:
- Identify persistence removal steps
- Recommend credential reset scope
- Validate clean state
- Suggest post-incident monitoring
```

***

### 8. Reporting & Executive Prompts

#### 8.1 Analyst Case Notes

```bash
Generate concise SOC case notes from the following data:

[Data]

Format:
- What happened
- What was affected
- What was done
- What remains open
```

***

#### 8.2 Executive Summary

```bash
Create an executive summary.

Audience: CISO / Leadership

Requirements:
- Non-technical language
- Business impact focus
- Clear risk assessment
- Forward-looking recommendations
```

***

### 9. Quality Control & Analyst Training Prompts

#### 9.1 Junior Analyst Review

```bash
Review the following SOC analysis:

[Analysis]

Tasks:
- Identify gaps or incorrect assumptions
- Suggest improvements
- Rate investigation quality
```

***

#### 9.2 Lessons Learned

```bash
Based on this incident:

[Summary]

Tasks:
- Identify detection failures
- Recommend control improvements
- Suggest SOC process enhancements
```

***

### 10. Governance & Safe Use Prompt

```bash
Before finalising conclusions:
- Confirm evidence supports findings
- Identify assumptions
- Validate against at least two data sources
- Clearly label confidence level
```

***

### How to Operationalise This Library

**Recommended Use**

* Store in SOC wiki or playbook
* Link prompts to incident types
* Embed into SOAR workflows
* Standardise across Tier-1 to Tier-3

**Forward-Looking**

* Use prompts to train junior analysts
* Improve consistency across shifts
* Reduce MTTR without reducing rigour
