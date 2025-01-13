---
icon: laptop-code
cover: ../../../../.gitbook/assets/Screenshot 2025-01-04 152247.png
coverY: 0
layout:
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Triage Types and Processes

## **Introduction**

**Incident triage** is the process of evaluating and prioritising cybersecurity incidents based on their severity, impact, and urgency. It is a critical step in the **Incident Response (IR) process**, helping organisations focus resources on the most significant threats and ensure efficient incident handling.

### **Key Objectives of Incident Triage**

1. **Classification**: Determine whether an event is a true incident (malicious activity) or a benign issue (false positive).
2. **Prioritisation**: Assign urgency levels based on potential business impact.
3. **Scoping**: Identify the affected systems, users, and data to understand the scale of the incident.
4. **Escalation**: Route the incident to the appropriate team or personnel for further analysis and response.

### **Steps in Incident Triage**

1. **Initial Detection**:
   * Analyse alerts from detection systems (e.g., SIEM, IDS/IPS, EDR).
   * Verify the alert's authenticity to eliminate false positives.
2. **Classification**:
   * Categorise the incident type (e.g., malware infection, phishing, data exfiltration).
   * Reference incident taxonomy frameworks (e.g., VERIS, NIST categories).
3. **Impact Assessment**:
   * Evaluate the potential damage (e.g., data loss, service downtime, reputation).
   * Consider the criticality of affected systems (e.g., production servers vs. endpoints).
4. **Severity Rating**:
   * Assign a severity level based on predefined criteria:
     * **Critical**: High-impact incidents requiring immediate action.
     * **High**: Significant incidents with potential for widespread impact.
     * **Medium**: Contained incidents with limited impact.
     * **Low**: Minor incidents or benign events.
5. **Correlation**:
   * Cross-reference the incident with known Indicators of Compromise (IOCs).
   * Check for patterns that might indicate a larger campaign or threat actor activity.
6. **Scope Definition**:
   * Identify the number of affected assets, users, or systems.
   * Determine whether the incident is isolated or part of a broader attack.
7. **Documentation**:
   * Record details about the incident, including:
     * Alert sources.
     * Affected systems.
     * Initial analysis findings.
     * Assigned severity and priority.
8. **Escalation and Assignment**:
   * Escalate the incident to the appropriate response team.
   * Communicate relevant details and context to ensure an effective response.

### **Key Considerations for Effective Triage**

* **Use of Triage Frameworks**:
  * Implement structured triage processes such as SANS, NIST, or FIRST guidelines.
  * Customise frameworks to align with your organisation's risk tolerance and priorities.
* **Automation**:
  * Leverage SOAR platforms or SIEM correlation rules to automate initial triage tasks (e.g., enrichment, severity assignment).
* **Threat Intelligence**:
  * Integrate threat intelligence to enrich alerts and provide context for decision-making.
* **Training**:
  * Ensure SOC analysts are trained to accurately recognise and classify different types of incidents.

### **Benefits of Effective Triage**

1. **Prioritised Response**:
   * Ensures critical incidents are addressed promptly.
2. **Efficient Resource Allocation**:
   * Avoids wasting resources on low-priority or false-positive alerts.
3. **Improved Response Accuracy**:
   * Reduces the likelihood of misclassifying incidents.
4. **Enhanced Visibility**:
   * Provides a clear understanding of incident trends and recognise

## **Define an Incident Triage Framework**

A well-structured framework ensures consistency in prioritising incidents. The following is a basic approach to incident triage:

### **Incident Classification Categories**

1. **Type of Incident**:
   * Malware Infection
   * Phishing Attempt
   * Data Exfiltration
   * Unauthorised Access
   * Denial of Service (DoS/DDoS)
   * Insider Threat
2. **Severity Levels**:
   * **Critical**: Immediate action required; impacts key systems or data.
   * **High**: Significant risk but contained; potential for escalation.
   * **Medium**: Moderate impact; can be scheduled for resolution.
   * **Low**: Minor or negligible risk; non-urgent.
3. **Impact Factors**:
   * **Asset Criticality**: How important is the affected system to the organization?
   * **Business ImpacUnauthorised** incident disrupt operations, revenue, or reputation?
   * **Data Sensitivity**: Does it involve regulated or highly confidential data?
   * **Scope**: How widespread is the issue (single endpoint, network, organisation-wide)?

### **Triage Workflow**

1. **Detection**: Receive alerts from monitoring tools (SIEM, IDS/IPS, EDR, etc.).
2. **Verification**: Confirm alert authenticity to reduce false positives.
3. **Enrichment**organisationdata with:
   * Threat intelligence (e.g., IP reputation, file hashes).
   * Past incidents and patterns.
4. **Prioritisation**: Assign severity based on predefined criteria.
5. **Escalation**: Notify the appropriate team or personnel with organisation-wide**Triage Decision Matrix**

Create a decision matrix to standardise triage decisions. The following is an example:

| **Impact** | **Criticality** | **Scope**         | **Severity** |
| ---------- | --------------- | ----------------- | ------------ |
| High       | High            | Organisation-wide | Critical     |
| High       | Medium          | Multiple systems  | High         |
| Medium     | Medium          | Single system     | Medium       |
| Low        | Low             | Single system     | Low          |

***

### **Automate Incident Triage**

Use automation tools to speed up repetitive tasks where possible.&#x20;

**Automation Tools**

1. **SIEM Platforms (e.g., Splunk, Elastic, Sentinel SIEM)**:
   * Automate log aggregation and correlation.
   * Use custom queries to assign severity based on alert conditions.
2. **SOAR Platforms (e.g., Palo Alto Cortex XSOAR, Splunk Phantom)**:
   * Automate alert enrichment (e.g., pulling threat intelligence data).
   * Trigger containment actions (e.g., isolating endpoints).
3. **EDR/XDR Solutions (e.g., Microsoft Defender, CrowdStrike)**:
   * Automate detection of suspicious behaviour on endpoints.
   * Integrate with SOAR or SIEM to triage alerts.

#### **Automated Triage Actions**

1. **Alert Enrichment**:
   * Use threat intelligence feeds (VirusTotal, AbuseIPDB) to score IOCs.
   * Tag alerts with contextual information (e.g., domain age, file reputation).
2. **Initial Investigation**:
   * Pull data from logs (e.g., DNS requests, user authentications).
   * Compare with historical data for anomalies.
3. **Severity Assignment**:
   * Use predefined rules to classify alerts into severity levels.
   * Example:
     * **Critical**: Lateral movement detected in a critical asset.
     * **High**: Failed login attempts followed by suspicious file activity.
4. **Escalation**:
   * Auto-assign incidents to teams based on severity and type.
   * Notify relevant stakeholders through integrated communication tools (e.g., Slack, Teams).

### **Incident Triage Dashboard**

Build a dashboard to monitor and manage triaged incidents effectively.

**Recommended Metrics for the Dashboard:**

* Number of alerts received and triaged.
* Percentage of false positives.
* Average time to triage.
* Severity breakdown (Critical, High, Medium, Low).
* Open vs. resolved incidents.

#### **Example Dashboard Platforms:**

* **Splunk**: Use prebuilt templates or custom SPL queries.
* **Elastic SIEM**: Leverage Kibana for visualization.
* **Microsoft Sentinel**: Create analytic rules and dashboards.

### **Triage Playbook Template**

Below is a generic template for structuring triage processes:

**Incident Triage Playbook Template**

1. **Input**:
   * Alert source: SIEM, EDR, user report.
   * Alert type: Malware, Unauthorized Access, Phishing, etc.
2. **Initial Actions**:
   * Verify alert.
   * Cross-check with threat intelligence.
3. **Analysis**:
   * Identify affected systems, users, and data.
   * Determine incident type and scope.
4. **Classification**:
   * Assign severity (Critical, High, Medium, Low).
   * Document business impact.
5. **Escalation**:
   * Notify the appropriate response team.
   * Assign response team lead and ensure handover.

**Note:** Below are some generic sample **queries** for **Splunk**, **Microsoft Defender**, and **Microsoft Sentinel (KQL)** to detect and investigate common attack techniques. The respective sections will provide more specific and detailed queries and approaches to investigations.

Note: Use the provided incident triage sections for a more detailed guide on processes and tools

### **Splunk Queries**

**1. Phishing Email Detection**

{% code overflow="wrap" %}
```csharp
index=email_logs sourcetype="email"
| search subject="*" attachment="*"
| eval malicious_attachment=if(like(attachment, "%.exe") OR like(attachment, "%.vbs") OR like(attachment, "%.js"), "Yes", "No")
| table _time, sender, recipient, subject, attachment, malicious_attachment
| where malicious_attachment="Yes"
```
{% endcode %}

**2. Credential Dumping (Mimikatz)**

{% code overflow="wrap" %}
```csharp
index=windows sourcetype="WinEventLog:Security"
EventCode=4688
| search "NewProcessName"="C:\\Windows\\System32\\cmd.exe" "CommandLine"="*mimikatz*"
| table _time, ComputerName, User, CommandLine
```
{% endcode %}

**3. Lateral Movement via SMB**

{% code overflow="wrap" %}
```csharp
index=network sourcetype="bro:smb"
| stats count by id.orig_h, id.resp_h, smb_cmd
| where smb_cmd="SMB2_WRITE" OR smb_cmd="SMB2_READ"
| table id.orig_h, id.resp_h, smb_cmd
```
{% endcode %}

**4. Suspicious PowerShell Execution**

{% code overflow="wrap" %}
```csharp
index=windows sourcetype="WinEventLog:Security"
EventCode=4104
| search ScriptBlockText="*Invoke-Mimikatz*" OR ScriptBlockText="*New-Object Net.WebClient*"
| table _time, ComputerName, User, ScriptBlockText
```
{% endcode %}

#### **Microsoft Defender Queries**

**1. Phishing Email Detection**

{% code overflow="wrap" %}
```csharp
EmailEvents
| where ThreatType == "Phish"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatType
```
{% endcode %}

**2. Credential Dumping Detection**

{% code overflow="wrap" %}
```csharp
DeviceProcessEvents
| where FileName in ("lsass.exe", "dumpert.exe", "mimikatz.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, AccountName
```
{% endcode %}

**3. Lateral Movement (RDP/SMB Activity)**

{% code overflow="wrap" %}
```csharp
DeviceNetworkEvents
| where RemotePort in (3389, 445)
| summarize count() by RemoteIP, DeviceName, RemotePort
```
{% endcode %}

**4. Suspicious PowerShell Commands**

{% code overflow="wrap" %}
```csharp
DeviceProcessEvents
| where ProcessCommandLine contains "PowerShell" and (ProcessCommandLine contains "DownloadString" or ProcessCommandLine contains "Invoke-Mimikatz")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
{% endcode %}

#### **Microsoft Sentinel (KQL Queries)**

**1. Phishing Campaign Detection**

{% code overflow="wrap" %}
```csharp
OfficeActivity
| where Operation == "Send" and EmailSubject contains "Invoice" and AttachmentCount > 0
| project TimeGenerated, UserId, EmailSubject, AttachmentNames
```
{% endcode %}

**2. Credential Dumping Tools**

{% code overflow="wrap" %}
```csharp
SecurityEvent
| where EventID == 4688 and CommandLine contains "mimikatz"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
```
{% endcode %}

**3. Lateral Movement via Pass-the-Hash**

{% code overflow="wrap" %}
```csharp
SecurityEvent
| where EventID == 4624 and LogonType == 3
| summarize count() by Computer, Account, SourceNetworkAddress
| where count_ > 5
```
{% endcode %}

**4. Suspicious File Downloads**

{% code overflow="wrap" %}
```csharp
DeviceFileEvents
| where FileName endswith ".exe" and InitiatingProcessCommandLine contains "powershell"
| project Timestamp, DeviceName, FileName, InitiatingProcessCommandLine
```
{% endcode %}
