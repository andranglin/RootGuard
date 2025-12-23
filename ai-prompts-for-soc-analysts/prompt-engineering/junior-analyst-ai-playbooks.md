# Junior Analyst AI Playbooks

Below is a **complete, reusable SOC AI framework** consisting of **three tightly integrated components**:

1. **Reusable SOC Prompt Library (Core)**
2. **Microsoft Defender XDR & Sentinel–Specific Prompt Packs**
3. **Junior Analyst AI Playbooks (Operationalised for Tier-1 → Tier-2)**

Written to be **enterprise-ready**, **repeatable**, and **defensible** in regulated SOC environments.

## 1. Reusable SOC Prompt Library (Core)

This library is **platform-agnostic** and should be treated as your **SOC AI baseline**.\
Each prompt is designed to be copied verbatim and populated with evidence.

***

### 1.1 Alert Triage Prompt (Universal)

{% code overflow="wrap" %}
```bash
You are a Tier-2 SOC analyst.

Context:
- Alert source:
- Alert severity:
- Detection logic:
- First seen (UTC):
- Last seen (UTC):

Evidence Provided:
- Alert details:
- Entities involved:
- Relevant logs or hunting output:

Tasks:
1. Determine whether this alert represents malicious, benign, or suspicious activity.
2. Identify the affected user(s), host(s), process(es), and IP(s).
3. Map observed activity to MITRE ATT&CK techniques.
4. Assess potential blast radius.
5. Provide a confidence level and justification.
6. Recommend next investigative or response steps.

Constraints:
- Evidence-based conclusions only
- Explicitly state assumptions
```
{% endcode %}

***

### 1.2 Investigation Expansion Prompt

```bash
You are conducting an active SOC investigation.

Known Facts:
- Initial alert:
- Confirmed indicators:
- Affected assets:

Unknowns:
- Initial access vector
- Persistence mechanisms
- Lateral movement
- Data access or exfiltration

Tasks:
- Build a probable attack chain
- Identify gaps in evidence
- Recommend logs or artefacts required to close gaps
- Suggest detection queries to validate hypotheses
```

***

### 1.3 Threat Hunting Prompt (Hypothesis-Driven)

```bash
You are a threat hunter.

Hypothesis:
[State attacker behaviour hypothesis clearly]

Environment:
- Operating system(s):
- Identity provider:
- EDR/XDR platform:
- SIEM:

Tasks:
- Identify relevant MITRE ATT&CK techniques
- Define suspicious vs normal behaviour
- Propose detection logic
- List expected false positives
- Define success criteria for the hunt
```

***

### 1.4 Incident Response Decision Support Prompt

```bash
You are advising the incident response lead.

Incident Status:
- Confidence of compromise:
- Scope:
- Business impact:
- Containment already applied:

Tasks:
- Recommend immediate containment actions
- Identify actions that could destroy forensic evidence
- Propose short-term and long-term remediation
- Highlight risks of under- or over-containment
```

***

## 2. Defender XDR Prompt Pack

These prompts are **optimised for Defender XDR telemetry and workflows**.

***

### 2.1 Defender XDR Alert Analysis

```bash
You are a Microsoft Defender XDR specialist.

Analyse the following Defender alert:
[Paste alert]

Tasks:
- Identify the detection source (MDE, MDI, MDO, Entra ID)
- Identify execution, persistence, or credential access indicators
- Correlate across endpoint, identity, and email telemetry
- Map to MITRE ATT&CK
- Recommend response actions within Defender XDR
```

***

### 2.2 Advanced Hunting (KQL) Support

```bash
You are assisting with Defender XDR Advanced Hunting.

Objective:
[Detection or investigation goal]

Tasks:
- Recommend relevant tables (e.g., DeviceProcessEvents, IdentityLogonEvents)
- Write KQL queries aligned to the objective
- Explain query logic
- Suggest tuning to reduce noise
```

***

### 2.3 Identity-Based Attack Analysis (Entra ID / MDI)

```bash
You are analysing a potential identity compromise.

Evidence:
- Entra ID sign-in logs
- MDI alerts
- Risk detections

Tasks:
- Identify abnormal authentication patterns
- Assess credential theft or token abuse
- Identify lateral movement via identity
- Recommend account containment actions
```

***

### 2.4 Endpoint Compromise Investigation

```bash
You are investigating a suspected compromised endpoint using Defender XDR.

Tasks:
- Identify initial execution vector
- Review command-line activity
- Identify persistence mechanisms
- Assess data access and staging
- Recommend isolation or live response actions
```

***

## 3. Microsoft Sentinel Prompt Pack

Optimised for **SIEM correlation, analytics rules, and incidents**.

***

### 3.1 Sentinel Incident Correlation

```bash
You are investigating a Microsoft Sentinel incident.

Incident details:
- Severity:
- Analytics rules triggered:
- Entities involved:

Tasks:
- Correlate alerts into a single narrative
- Identify kill chain progression
- Identify gaps in telemetry
- Recommend additional queries or data sources
```

***

### 3.2 Analytics Rule Validation

```bash
You are reviewing a Sentinel analytics rule.

Rule logic:
[Paste KQL]

Tasks:
- Explain what behaviour is detected
- Identify weaknesses or bypass opportunities
- Recommend tuning or thresholds
- Suggest complementary detections
```

***

### 3.3 Post-Incident Detection Engineering

```bash
You are performing detection engineering after an incident.

Incident summary:
- Root cause:
- Techniques used:

Tasks:
- Identify detection gaps
- Propose new Sentinel analytics rules
- Recommend UEBA or fusion improvements
```

***

## 4. Junior Analyst AI Playbooks

These are **step-by-step AI-assisted workflows** designed for **Tier-1 analysts**, with escalation paths.

***

### 4.1 Tier-1 Alert Handling Playbook

**Trigger:** New SOC alert

**AI Prompt Used:**

* Universal Alert Triage Prompt

**Expected Output:**

* Verdict (TP / FP / Suspicious)
* Affected entities
* Escalation decision

**Escalate If:**

* Credential access suspected
* Persistence identified
* Multiple hosts/users involved

***

### 4.2 Endpoint Investigation Playbook

**Trigger:** Suspicious endpoint alert

**Steps:**

1. Run Defender XDR Alert Analysis prompt
2. Ask AI to summarise command-line activity
3. Identify persistence indicators
4. Decide: isolate, monitor, or escalate

**Escalate If:**

* SYSTEM-level execution
* Credential dumping indicators
* Unknown persistence mechanism

***

### 4.3 Identity Compromise Playbook

**Trigger:** Risky sign-in or MDI alert

**Steps:**

1. Use Identity-Based Attack Analysis prompt
2. Validate logon source and device
3. Identify token misuse or MFA bypass
4. Decide: password reset, sign-out, disable account

***

### 4.4 Threat Hunt Escalation Playbook (Tier-2)

**Trigger:** Confirmed malicious behaviour

**Steps:**

1. Convert incident into a hunt hypothesis
2. Use Threat Hunting Prompt
3. Validate scope expansion
4. Feed findings into detection engineering

***

## 5. Governance & Safe Use Controls

**Mandatory Rules for Analysts**

* AI outputs must be validated against logs
* AI is advisory, not authoritative
* All conclusions must cite evidence
* Assumptions must be explicitly stated

**Recommended Integration**

* Embed prompts into SOC runbooks
* Store approved prompts in a central repository
* Version-control prompt changes
* Restrict use for legal or HR decisions
