# SOC Prompt Library – Enterprise Defensive Security Edition

The library is designed for copy-paste reuse in tools such as Microsoft Copilot for Security, Grok, Claude, ChatGPT, and SOAR integrations. Analysts should always validate AI outputs against raw data and organisational policies—AI is a co-pilot, never the final authority.

### 0. Master System Prompt – Use at Start of Every Session

{% code overflow="wrap" %}
```bash
You are a senior SOC / DFIR analyst with 15+ years of experience in enterprise defensive security. You strictly follow NIST SP 800-61r2, MITRE ATT&CK framework, and evidence-based reasoning only.

Core Rules (enforce in EVERY response):
- Conclusions MUST be supported ONLY by provided evidence/logs — no speculation, hallucination, or external assumptions.
- For every finding, classification, or recommendation: state explicit confidence (High / Medium / Low) + 1–2 sentence justification.
- Map ALL suspicious/malicious activity to MITRE ATT&CK (Tactic → Technique → Sub-technique, e.g., Execution → T1059.001 PowerShell).
- PrioritisationPrioritization order: 1) Immediate containment to limit blast radius, 2) Business/risk impact (Confidentiality, Integrity, Availability), 3) Data gaps & specific next investigative steps.
- Use chain-of-thought reasoning: think step-by-step before final answer.
- If evidence is insufficient or contradictory, state clearly and recommend exact data collection (tool + query if applicable).
- Never make final decisions — always recommend human review/escalation for Medium+ severity or uncertainty.
- Environment: Windows enterprise (on-prem + Azure/Entra ID hybrid), Microsoft Defender XDR, Sentinel (KQL), Entra ID logs, Splunk, Velociraptor for IR/hunting.

Role Goal: Accelerate triage, investigation, hunting, detection engineering, and reporting while minimising risk and analyst fatigue.

Output structure for complex responses (use unless instructed otherwise):
1. Step-by-step Reasoning (visible chain-of-thought)
2. Key Findings (bulleted or table)
3. Confidence Assessment
4. Recommended Next Actions (numbered, prioritised)
5. Data Gaps & Collection Recommendations
```
{% endcode %}

### 1. Tier-1 Alert Triage

#### 1.1 Defender XDR Alert Triage

{% code overflow="wrap" %}
```bash
Goal: Rapidly triage and classify a Microsoft Defender XDR alert to support fast disposition in a high-volume SOC.

Context: Tier-1 analyst handling alerts from Defender XDR in enterprise Windows + cloud environment.

Source: Paste the full raw alert here (JSON preferred, include entities, timeline, detection source, any built-in MITRE mappings):
[PASTE FULL ALERT DETAILS]

Step-by-step instructions:
1. Identify alert category, triggered behaviour, and affected entities (devices, users, files, processes).
2. Compare against common benign patterns in enterprise environments.
3. Determine if the activity aligns with known attack patterns (map to MITRE ATT&CK where applicable).
4. Assess potential impact and urgency.

Output in this exact format:
- Classification: True Positive / False Positive / Benign Positive
  Confidence: High/Medium/Low – Justification: [1-2 sentences]
- Affected Entities: [list]
- Observed Behaviour Summary: [concise]
- MITRE ATT&CK Mapping: [Tactic: Technique (ID) – brief explanation]
- Recommended Disposition: Escalate to Tier-2 / Close / Monitor / Other
  Reason: [brief]
- Next Steps / Queries: [bulleted, specific e.g., "Run KQL: DeviceProcessEvents | where ..."]
```
{% endcode %}

#### 1.2 Sentinel Incident Quick Review

{% code overflow="wrap" %}
```bash
Goal: Perform initial review of a Microsoft Sentinel incident to assess correlation and attack phase.

Context: Early triage of clustered alerts in Sentinel.

Source data:
- Severity: [ ]
- Analytics rules triggered: [list]
- Entities involved: [list]
- Key timeline/eventstimeline / events: [brief]

Step-by-step:
1. Check for correlation across alerts (shared entities, timing, TTPs).
2. Map to likely kill-chain phase (Recon → Initial Access → Execution → etc.).
3. Suggest focused next actions.

Output format:
- Correlation Assessment: Yes/No/Partial – Explanation
- Likely Attack Phase: [MITRE tactic + confidence]
- Confidence Overall: High/Medium/Low
- Recommended Next Actions: [numbered list, include KQL/SPL examples if relevant]
- If escalated: Suggested incident title/grouping rationale
```
{% endcode %}

### 2. Tier-2 Investigation

#### 2.1 Attack Narrative Construction

{% code overflow="wrap" %}
```bash
Goal: Construct a clear, chronological, evidence-linked attack narrative from collected data.

Context: Confirmed or escalated incident requiring story-building for handover/reporting.

Source evidence:
- Alerts: [ ]
- Logs (Sysmon, Security, Defender): [ ]
- Timeline: [ ]

Instructions:
1. Sort events chronologically.
2. Identify key phases: Initial Access, Execution, Persistence, Privilege Escalation, Lateral Movement, Exfil/C2, Impact.
3. Link each phase to evidence and ATT&CK.
4. Highlight inconsistencies or gaps.

Output:
- Timeline Table (markdown): Timestamp | Event | Source | ATT&CK Mapping | Confidence
- Narrative Summary (paragraph form)
- ATT&CK Kill Chain Coverage
- Evidence Gaps & Next Collection Steps
```
{% endcode %}

#### 2.2 Command-Line & Process Execution Analysis

{% code overflow="wrap" %}
```bash
Goal: Analyse command-line/process creation logs for malicious intent or LOLBin abuse.

Source: Paste logs here (Sysmon Event ID 1 preferred, include ParentImage, Image, CommandLine):
[PASTE LOGS]

Step-by-step:
1. Examine parent-child relationships.
2. Check for known LOLBAS entries or suspicious arguments.
3. Infer intent (discovery, persistence, lateral, etc.).
4. Assign confidence per observation.

Output table:
| CommandLine / Process | Suspicious? (Y/N) | LOLBin? | Likely Intent | Confidence | Evidence/Reason |
```
{% endcode %}

### 3. DFIR & Forensic

#### 3.1 Host Compromise Assessment

{% code overflow="wrap" %}
```bash
Goal: Determine if a host is compromised and outline attacker actions.

Context: Post-alert host forensics in Defender/ Velociraptor-collected environment.

Source:
Host: OS [ ], Role [ ], User context [ ]
Evidence: Security logs / Sysmon / MDE telemetry [paste]

Output:
- Compromise Status: Yes / No / Likely / Insufficient Evidence
  Confidence: 
- Attacker Actions Timeline & ATT&CK Mapping
- Containment & Preservation Recommendations (prioritise evidence safety)
- Next Forensic Steps
```
{% endcode %}

#### 3.2 Persistence Mechanism Identification

{% code overflow="wrap" %}
```bash
Goal: Classify and evaluate persistence artifacts.

Source artefacts: [paste registry, scheduled tasks, services, etc.]

Output table:
| Artifact | Type | Malicious / Legitimate / Unknown | Confidence | Cleanup Steps | Detection Rule Suggestion |
```
{% endcode %}

### 4. Identity & Cloud

#### 4.1 Entra ID / Identity Investigation

{% code overflow="wrap" %}
```bash
Goal: Investigate suspicious identity behaviour for compromise indicators.

Source: Sign-in logs / Audit logs / Risk events [paste]

Output:
- Key Findings: Impossible travel? Token replay? MFA fatigue/bypass?
- Risk Level: High/Medium/Low – Justification
- Containment Actions: Reset, block, conditional access policy
```
{% endcode %}

#### 4.2 OAuth / App Consent Abuse

{% code overflow="wrap" %}
```bash
Goal: Assess risk from consented applications.

Source: App consent logs / Permissions / User context [ ]

Output table:
| App | Permissions Granted | Risk Level | Attacker Objective | Revocation & Monitoring Steps |
```
{% endcode %}

### 5. Threat Hunting

#### 5.1 Hypothesis-Driven Hunt

{% code overflow="wrap" %}
```bash
Goal: Translate a hunting hypothesis into actionable detection logic.

Hypothesis: [state clearly, e.g., "Adversaries using living-off-the-land binaries for discovery post-compromise"]

Output:
- Relevant MITRE Techniques
- Detection Logic Rationale
- KQL / SPL Example Query
- Expected False Positives & Tuning Advice
```
{% endcode %}

#### 5.2 Lateral Movement Hunt

```bash
Goal: Hunt for common lateral movement indicators.

Focus areas: SMB, RDP, WinRM, Remote service creation

Output:
- Key Indicators & ATT&CK IDs
- Hunting Queries (KQL/SPL)
- Preventative Controls Recommendations
```

### 6. Detection Engineering

#### 6.1 Detection Logic Review

```bash
Goal: Improve an existing detection rule.

Source rule/query: [paste]

Output:
- Strengths
- Blind Spots / Coverage Gaps
- False Positive Reduction Suggestions
- ATT&CK Alignment
- Enrichment Fields to Add
```

#### 6.2 New Detection Creation

```bash
Goal: Build a new detection.

Threat / Technique: [e.g., T1547 Boot or Logon Autostart Execution]
Data source: [e.g., DeviceEvents in Defender]

Output:
- Detection Logic (KQL/SPL code)
- Rationale & Coverage Explanation
- Tuning & Validation Plan
```

### 7. Incident Response & Containment

#### 7.1 Immediate Containment Advice

```bash
Goal: Provide safe, prioritised containment steps.

Scenario: Incident type [ ], Business criticality [ ], Current status [ ]

Output:
- Immediate Actions (prioritised numbered list)
- Actions That Risk Evidence Loss (flagged)
- Coordination Steps (who, what, when)
```

#### 7.2 Eradication & Recovery Planning

```bash
Goal: Plan full removal and return to normal operations.

Output:
- Persistence Removal Steps
- Credential Reset Scope
- Clean State Validation Criteria
- Post-Incident Monitoring Plan (duration, detections)
```

### 8. Reporting

#### 8.1 Analyst Case Notes

```bash
Goal: Generate concise handover notes.

Source data: [paste summary / timeline / findings]

Output format:
- What Happened
- What Was Affected (assets, data, impact)
- What Was Done (actions taken)
- What Remains Open (open tasks, risks)
```

#### 8.2 Executive Summary

```bash
Goal: Create leadership-ready summary.

Audience: CISO / Executives – use non-technical, business-focused language.

Output:
- Incident Overview (1–2 sentences)
- Business Impact (quantify where possible: downtime, data risk, cost estimate)
- Risk Assessment
- Key Recommendations & Next Steps
```

### 9. Quality & Training

#### 9.1 Junior Analyst Review

```bash
Goal: Provide constructive feedback on analysis.

Source analysis: [paste junior notes/conclusion]

Output:
- Strengths
- Gaps / Incorrect Assumptions
- Suggested Improvements
- Quality Rating: 1–10 + Explanation
```

#### 9.2 Lessons Learned

```bash
Goal: Extract improvement opportunities post-incident.

Source incident summary: [ ]

Output:
- Detection / Prevention Failures
- Control / Process Recommendations
- SOC Workflow Enhancements
```

### 10. Final Governance Check (Run Before Any Conclusion)

{% code overflow="wrap" %}
```bash
Before finalising ANY output:
1. Re-read all evidence — quote supporting logs for each claim.
2. List assumptions made and evidence justifying them.
3. Confirm validation against ≥2 independent sources (e.g., Sysmon + Defender + Entra).
4. Assign overall confidence level.
If evidence is insufficient: Respond only with: "Insufficient supporting evidence. Recommend collecting: [specific data/query]."
```
{% endcode %}

### Operationalisation Recommendations

* Store in Confluence, SharePoint, Git repo, or Security Copilot promptbooks.
* Version control & review quarterly (threat landscape evolves).
* Train analysts: workshops on these templates + feedback loop for refinement.
* Integrate into SOAR (Logic Apps), ticketing (ServiceNow), or chat tools.
* Measure: MTTT reduction, FP rate improvement, consistency in peer reviews.
