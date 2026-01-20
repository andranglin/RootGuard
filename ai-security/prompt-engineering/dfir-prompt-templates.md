# DFIR Prompt Templates

Below is a streamlined library for IR use cases. Prompts emphasise structured analysis, MITRE ATT\&CK mapping, evidence-based reasoning, and are aligned with NIST/SANS recommendations.&#x20;

They treat AI as an accelerator and co-pilot—not a decision-maker or legal authority. Always validate AI outputs against primary sources, organisational policies, and verified tools.&#x20;

Provide raw data/logs (not interpretations) to reduce bias/hallucination.

### Foundational IR Prompt Wrapper (Recommended Standard)

Use this as the base for all IR prompts to enforce consistency.

{% code overflow="wrap" %}
```bash
You are a senior incident response analyst following NIST SP 800-61r2 and SANS Incident Handlers Handbook.

Context:
- Environment: [Hybrid / Cloud / On-prem]
- Platforms/Tools: [Defender XDR, Sentinel, Splunk, Velociraptor, Volatility, Wireshark, etc.]
- Time window: [UTC dates/times]
- Scope: [Affected systems, users, networks, data at risk]

Incident Phase (NIST):
- [Preparation | Detection and Analysis | Containment, Eradication, and Recovery | Post-Incident Activity]

Objective:
- [Triage | Scoping | Enrichment | Forensic Analysis | Containment Planning | Recovery | Lessons Learned | Root Cause]

Data Provided:
- [Raw alerts, logs, IOCs, timelines, artefacts, etc.]

Constraints & Requirements:
- Map all malicious activity to MITRE ATT&CK Enterprise tactics/techniques (e.g., TA0001 Initial Access → T1190 Exploit Public-Facing Application)
- Base conclusions strictly on evidence; clearly separate facts, assumptions, hypotheses
- Assign confidence levels (High/Medium/Low or 0-100%)
- Highlight uncertainties, alternative explanations, and next investigative steps
- Prioritise CIA triad impact (Confidentiality, Integrity, Availability)

Output Format:
- Executive Summary
- Key Findings & Timeline (use table if applicable)
- MITRE ATT&CK Mapping
- IOCs & Evidence
- Risk/Impact Assessment
- Recommended Actions (phased, prioritised)
- Follow-up Queries / Artefacts Needed
```
{% endcode %}

### 1. Initial Triage and Scoping Prompt

**Purpose**: NIST Detection and Analysis phase – Quickly classify alerts, filter FPs, scope impact, and prioritise.

#### Prompt Template:

{% code overflow="wrap" %}
```bash
[Use Foundational Wrapper above, then add:]

Objective: Initial Triage and Scoping

Data Provided: Alert details: [INSERT ALERT LOGS, e.g., Defender XDR JSON, Sentinel incident, IDS/SIEM event]
Environment context: [INSERT e.g., affected hosts, user roles, network segments]
Known threats: [INSERT e.g., recent CVEs, threat intel feeds]

Tasks:
1. Classify as benign/suspicious/malicious with confidence level and evidence-based justification.
2. Map to MITRE ATT&CK (tactic + technique + sub-technique if applicable).
3. Estimate blast radius and potential impact using CIA triad.
4. Recommend immediate actions (e.g., isolate endpoint, query logs, collect memory image).
5. Suggest priority (P1–P4) and next triage steps.

Output in structured format: include 'priority' field and 'next_steps' array.
```
{% endcode %}

**Best Practices**: Paste raw alert text/JSON. If AI has tools, add: "Use web search to check IOC reputation or related campaigns."

### 2. Threat Intelligence Enrichment Prompt

**Purpose**: Detection and Analysis / Containment – Correlate IOCs with external sources for attribution and response planning.

#### Prompt Template:

{% code overflow="wrap" %}
```bash
[Use Foundational Wrapper]

Objective: Threat Intelligence Enrichment

IOC list: [INSERT e.g., IPs: 185.220.101.12, hashes: SHA256=abc123..., domains: malicious.c2.com]
Incident context: [e.g., suspected ransomware precursor, credential theft]

Tasks:
1. Query reliable sources (VirusTotal, OTX, AbuseIPDB, MITRE) for reputation/associations.
2. Identify potential threat actors/campaigns with evidence.
3. Map IOCs to MITRE ATT&CK TTPs.
4. Assess FP risk and confidence scores (0-100%).
5. Recommend containment (e.g., firewall block, EDR policy).

Output as markdown table: IOC | Reputation | ATT&CK Mapping | Confidence | Recommended Action. Include source citations.
```
{% endcode %}

**Best Practices:** Anonymise sensitive IOCs if needed. Manually verify cited sources.

### 3. Forensic Analysis Assistance Prompt

**Purpose**: Containment, Eradication, and Recovery – Analyse artefacts to reconstruct the attack chain and support eradication.

#### Prompt Template:

{% code overflow="wrap" %}
```bash
[Use Foundational Wrapper]

Objective: Forensic Analysis

Artifacts: [INSERT e.g., Volatility pslist/netscan output, Sysmon logs, registry keys, cmd history]
Timeline: [INSERT key timestamps]
Hypothesis: [e.g., initial access via phishing → credential dumping → lateral movement]

Tasks:
1. Reconstruct chronological attack timeline.
2. Identify anomalies, persistence, execution, credential access; link to MITRE ATT&CK.
3. Suggest tools/commands (e.g., Autoruns, strings, PowerShell Get-ItemProperty).
4. Evaluate root cause/entry vector with evidence.
5. Recommend safe eradication steps + verification.

Output as forensic report: Executive Summary, Timeline Table, Findings, Recommendations.
```
{% endcode %}

**Best Practices:** Use redacted/sample data initially.&#x20;

If code-capable AI, add: "Write Python code (using pandas if needed) to parse sample logs."

### 4. Containment and Recovery Planning Prompt

**Purpose**: Containment, Eradication, and Recovery – Develop phased plans minimising disruption.

#### Prompt Template:

{% code overflow="wrap" %}
```bash
[Use Foundational Wrapper]

Objective: Containment and Recovery Planning

Incident summary: [e.g., confirmed AD credential compromise, lateral movement via WMI]
Affected scope: [e.g., 12 hosts, finance data at risk]
Business constraints: [e.g., no downtime during quarter-end, GDPR reporting required]

Tasks:
1. Prioritised containment actions with risk assessments (e.g., isolate VLAN, disable accounts).
2. Recovery roadmap (backup validation, patching, monitoring).
3. Stakeholder communication templates (e.g., CISO brief, user notification).
4. Success metrics (e.g., no re-infection after 72h).
5. Post-recovery testing steps.

Output as markdown phased table: Phase | Actions | Responsible | Timeline | Dependencies.
```
{% endcode %}

**Best Practices:** Customise with org tools (e.g., Sentinel playbooks).&#x20;

Test in simulations.

### 5. Lessons Learned and Reporting Prompt

**Purpose**: Post-Incident Activity – Summarise, identify gaps, improve future preparedness.

#### Prompt Template:

{% code overflow="wrap" %}
```bash
[Use Foundational Wrapper]

Objective: Lessons Learned & Reporting

Incident timeline/key events: [INSERT chronology]
Response effectiveness: [INSERT e.g., MTTD 4h, MTTR 18h, resources used]
Root cause findings: [e.g., unpatched CVE-2025-XXXX]

Tasks:
1. Perform 5 Whys root cause analysis.
2. Evaluate strengths/weaknesses (e.g., EDR detection gap).
3. Recommend preventive measures (policies, training, detections).
4. Draft executive summary + report sections.
5. Suggest IR playbook updates (e.g., enhance ATT&CK coverage).

Output as professional report: Introduction, Analysis (incl. metrics table), Recommendations (action items table), Appendices.
```
{% endcode %}

**Best Practices:** Use anonymised data. Iterate with team review. Track recommendation implementation.

### Additional IR-Specific Prompts (from DFIR Library – Non-Redundant)

#### Containment Strategy (Quick Decision Support)

{% code overflow="wrap" %}
```bash
[Use Foundational Wrapper]

Objective: Containment Strategy

Scenario: Confirmed credential compromise, possible lateral movement, no exfil yet.

Tasks:
- Immediate containment steps
- Actions risking evidence destruction
- Phased response plan
- Business impact considerations
```
{% endcode %}

### Post-Incident Executive Summary

```bash
[Use Foundational Wrapper]

Objective: Executive Reporting

Audience: CISO, Legal, Leadership

Tasks:
- Plain-language summary
- Attacker objectives & impact
```
