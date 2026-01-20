# Incident Response AI Prompt Templates

### Introduction

As a cybersecurity professional in defensive security, below I have created a set of enterprise-grade AI prompt templates tailored for incident response (IR) practitioners. These prompts are designed to leverage AI tools to enhance efficiency, accuracy, and consistency in IR processes.&#x20;

They follow best practices from frameworks like NIST SP 800-61r2, SANS, and MITRE ATT\&CK, emphasising structured analysis, risk mitigation, and documentation.

#### Each template includes:

* **Purpose:** A brief description of when and why to use it.
* **Prompt Template:** A customisable prompt you can copy-paste into an AI tool, with placeholders (e.g., \[DETAILS]) for specific incident data.
* **Best Practices:** Tips for refinement and usage.

These prompts assume access to AI with web search, code execution, or data analysis capabilities for deeper insights. Always validate AI outputs against verified sources and organisational policies.

### 1. Initial Triage and Scoping Prompt

* **Purpose:** Use during the identification phase to quickly assess alerts, prioritise incidents, and scope potential impacts. Helps filter false positives and gather initial intelligence.
*   **Prompt Template:**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">You are an expert incident response analyst following NIST SP 800-61r2 guidelines. Analyse the following security alert for a potential incident:

    - Alert details: [INSERT ALERT LOGS, e.g., IDS alert, endpoint detection, or SIEM event].
    - Environment context: [INSERT ENVIRONMENT INFO, e.g., affected systems, network segments, user roles].
    - Known threats: [INSERT RELEVANT INTEL, e.g., recent CVEs or TTPs from MITRE ATT&#x26;CK].

    Perform the following steps:
    1. Classify the alert as benign, suspicious, or malicious, with confidence level (low/medium/high) and justification.
    2. Map to MITRE ATT&#x26;CK techniques if applicable (e.g., Tactic: Initial Access, Technique: T1190).
    3. Recommend immediate triage actions, such as log queries, endpoint isolation, or artifact collection.
    4. Estimate potential impact (e.g., data exfiltration risk, lateral movement potential) based on CIA triad (Confidentiality, Integrity, Availability).
    5. Suggest tools for further investigation (e.g., Volatility for memory forensics, Wireshark for network capture).

    Output in a structured JSON format for easy parsing, including a 'priority' field (P1-P4) and 'next_steps' array.
    </code></pre>
* **Best Practices:** Input raw logs to avoid bias. If the AI has tool access, add instructions like "Use web search to check for related IOCs." Review for overconfidence in classifications.

### 2. Threat Intelligence Enrichment Prompt

* **Purpose:** Enrich indicators of compromise (IOCs) during the identification or containment phase by correlating with external threat intel sources, aiding in attribution and response planning.
*   **Prompt Template:**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">Act as a threat intelligence analyst specialising in defensive cybersecurity. Given the following IOCs from an ongoing incident:

    - IOC list: [INSERT IOCs, e.g., IP addresses, hashes, domains, file paths].
    - Incident context: [INSERT DETAILS, e.g., suspected malware family, affected assets].

    Execute these tasks:
    1. Query reliable sources (e.g., VirusTotal, AlienVault OTX, MITRE ATT&#x26;CK) for reputation and associations using web search or integrated tools.
    2. Identify potential threat actors or campaigns (e.g., APT groups) with evidence-based attribution.
    3. Map IOCs to MITRE ATT&#x26;CK framework, listing relevant tactics, techniques, and procedures (TTPs).
    4. Assess false positive risk and provide confidence scores (0-100%) for each IOC.
    5. Recommend containment strategies, such as blocking rules for firewalls or EDR policies.

    Present results in a markdown table with columns: IOC, Reputation, ATT&#x26;CK Mapping, Confidence, and Recommended Action. Include citations for all external intel.
    </code></pre>
* **Best Practices:** Use specific IOCs to focus the AI. If privacy is a concern, anonymise data. Cross-verify AI-cited sources manually to ensure accuracy.

### 3. Forensic Analysis Assistance Prompt

* **Purpose**: Support the eradication phase by guiding forensic artefact analysis, such as log parsing or malware reverse engineering, without requiring specialised tools.
*   **Prompt Template:**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">You are a digital forensics expert adhering to chain-of-custody principles. Analyze the provided forensic artifacts from an incident:

    - Artifacts: [INSERT DATA, e.g., memory dump excerpts, registry keys, or command-line logs].
    - Timeline: [INSERT EVENT TIMELINE, e.g., timestamps of suspicious activities].
    - Hypothesis: [INSERT INITIAL HYPOTHESIS, e.g., ransomware infection via phishing].

    Follow these steps:
    1. Parse and timeline the artifacts to reconstruct the attack chain.
    2. Identify anomalies (e.g., unusual processes, persistence mechanisms) and link to MITRE ATT&#x26;CK (e.g., Technique: T1547 for boot persistence).
    3. Suggest forensic tools and commands (e.g., Autoruns for Windows persistence, strings for binary analysis).
    4. Evaluate root cause and entry vector with supporting evidence.
    5. Provide eradication steps, including safe removal methods and verification checks.

    Structure the response as a forensic report: Executive Summary, Timeline Table, Findings, Recommendations. Use bullet points for clarity.
    </code></pre>
* **Best Practices:** Provide redacted or sample data to test. If the AI supports code execution, add "Write and execute Python code using libraries like pandas for log parsing." Ensure outputs align with legal evidentiary standards.

### 4. Containment and Recovery Planning Prompt

* **Purpose:** Aid in the containment and recovery phases by generating step-by-step plans to isolate threats and restore operations, minimising downtime.
*   **Prompt Template:**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">Serve as an incident response coordinator using the SANS Incident Handlers Handbook. Develop a containment and recovery plan for this incident:

    - Incident summary: [INSERT OVERVIEW, e.g., detected lateral movement in Active Directory].
    - Affected scope: [INSERT DETAILS, e.g., compromised hosts, data at risk].
    - Business constraints: [INSERT INFO, e.g., critical systems that cannot be offline, compliance requirements like GDPR].

    Generate:
    1. Prioritised containment actions (e.g., network segmentation, account lockouts) with risk assessments.
    2. Recovery roadmap, including backups validation, patching, and monitoring for re-infection.
    3. Communication templates for stakeholders (e.g., CISO briefing, user notifications).
    4. Metrics for success (e.g., MTTD/MTTR targets).
    5. Post-recovery testing steps to ensure resilience.

    Output as a phased Gantt-style table in markdown, with columns: Phase, Actions, Responsible Party, Timeline, Dependencies.
    </code></pre>
* **Best Practices: Customise with organisation-specific tools (e.g., Splunk for monitoring).** Simulate scenarios first to refine. Integrate with IR playbooks for consistency.

### 5. Lessons Learned and Reporting Prompt

* **Purpose:** Facilitate the lessons learned phase by summarising incidents, identifying gaps, and recommending improvements for future preparedness.
*   **Prompt Template:**

    <pre class="language-bash" data-overflow="wrap"><code class="lang-bash">Function as a post-incident review facilitator following NIST guidelines. Summarise and analyse this closed incident for lessons learned:

    - Incident timeline and key events: [INSERT CHRONOLOGY].
    - Response effectiveness: [INSERT METRICS, e.g., time to contain, resources used].
    - Root cause analysis: [INSERT FINDINGS, e.g., unpatched vulnerability].

    Perform:
    1. Root cause analysis using 5 Whys methodology.
    2. Evaluate response strengths and weaknesses (e.g., detection gaps in EDR).
    3. Recommend preventive measures (e.g., updated policies, training, tool enhancements).
    4. Draft an executive summary and full report sections.
    5. Suggest updates to IR playbooks based on MITRE ATT&#x26;CK coverage.

    Deliver in a professional report format: Introduction, Analysis, Recommendations, Appendices. Use tables for metrics and action items.
    </code></pre>
* **Best Practices:** Input anonymised data to maintain confidentiality. Use this iteratively with team feedback. Track implementation of recommendations in follow-ups.
