---
layout:
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

# AXIOM Cyber Data Collection

### <mark style="color:purple;">1. Case Creation</mark>

Create a new case to organise and store all the evidence collected throughout the investigation.

<mark style="color:orange;">**Case Creation:**</mark>\
Launch the AXIOM Process and select _<mark style="color:green;">Create New Cas</mark><mark style="color:green;">**e**</mark>_

<mark style="color:orange;">**Add Case Information:**</mark>\
Case Number: Assign a case number for tracking purposes, <mark style="color:green;">INC</mark>_<mark style="color:green;">-1001</mark>_ \
Case type: Select the appropriate case type, for example _<mark style="color:green;">Intrusion/incident response</mark>_

<mark style="color:orange;">**Select Location For Case Files Storage**</mark>**:**\
Folder Name: Provide a meaningful name, such as <mark style="color:green;">\<hostname></mark> <mark style="color:green;"></mark>_<mark style="color:green;">- Intrusion Investigation</mark>_ \
File path: _<mark style="color:green;">A:\CASES</mark>_

<mark style="color:orange;">**Select Location For Acquired Evidence Storage:**</mark>\
Folder Name: Provide a meaningful name, such as <mark style="color:green;">\<hostname></mark> <mark style="color:green;"></mark>_<mark style="color:green;">- Intrusion Investigation</mark>_ \
File path: _<mark style="color:green;">A:\CASES</mark>_

<mark style="color:orange;">**Add Scan Information:**</mark>\
Scanned by: <mark style="color:green;">\<investigator name></mark>

NEXT: _<mark style="color:green;">Go to Evident Sources</mark>_

### <mark style="color:purple;">2. Evidence Sources</mark>

#### <mark style="color:purple;">**Remote Computer**</mark>

<mark style="color:purple;">**Create New Agent**</mark>

<mark style="color:orange;">**General Agent Settings:**</mark>\
The agent will be saved to the default location: _<mark style="color:green;">C:\AXIOM-Agents</mark>_ \
Agent ID: _<mark style="color:green;">optional</mark>_ \
Operating System: _<mark style="color:green;">Windows</mark>_

<mark style="color:orange;">**Agent Masking Details:**</mark>\
File name: _<mark style="color:green;">AXIOM-Agent.exe</mark>_ \
&#x20;              SHOW MORE DETAILS (add as required or leave as is)

<mark style="color:orange;">**Survive Shutdown of Endpoint:**</mark>\
Based on the investigation scenario, Leave or select: _<mark style="color:green;">Keep the agent running on the endpoint after a  shutdown</mark>_

<mark style="color:orange;">**Connectivity Details:**</mark>\
Examiner workstation hostname or IP address: _<mark style="color:green;">\<IP address of examiner's workstation></mark>_\
Por&#x74;_: <mark style="color:green;">\<Portnumber></mark>_ (8080)\
Reconnect delay: _<mark style="color:green;">10</mark>_ <mark style="color:green;"></mark><mark style="color:green;">seconds</mark> \
Disconnected Keep alive: _<mark style="color:green;">1</mark>_ <mark style="color:green;"></mark><mark style="color:green;">day</mark> (up to you)

Next, _<mark style="color:green;">Create Agent</mark>_

#### <mark style="color:purple;">**Create Agent**</mark>

<mark style="color:orange;">**Review Agent Details**</mark>\
<mark style="color:green;">**<**</mark><mark style="color:green;">Review details></mark>

<mark style="color:orange;">**Deploy Agent**</mark>\
Select: _<mark style="color:green;">Deploy Agent</mark>_\
Endpoint IP address: _<mark style="color:green;">Remote host IP address</mark>_ \
Username: _<mark style="color:green;">Investigator AD username</mark>_ \
Password: _<mark style="color:green;">AD password</mark>_ \
Agent location on endpoint: _<mark style="color:green;">C:\Windows\Temp</mark>_

Next: _<mark style="color:green;">Deploy Agent</mark>_\
\
&#xNAN;_<mark style="color:orange;">Deployment in Progress</mark>_\
Select: _<mark style="color:green;">Connect to Agent</mark>_ \
Select: _<mark style="color:green;">Connect to Endpoint</mark>_

<mark style="color:orange;">**Select Items to Download**</mark>\
&#xNAN;_<mark style="color:green;">Review and Select the Data From the Endpoint</mark>_ \
_<mark style="color:green;">Targeted Locations:</mark> Select all available options_ \
&#xNAN;_<mark style="color:green;">Files and Drives:</mark> Files and Folders_ \
_Select: <mark style="color:green;">Files and Folders as appropriate to investigations</mark>_

_<mark style="color:green;">Select Memory to Download</mark>_ \
Select: _<mark style="color:green;">Individual processes</mark>_ \
OR \
&#xNAN;_<mark style="color:green;">Full memory acquisition</mark>_

Important Note: <mark style="color:green;">Leave the tool to capture the data until finished; don't navigate away.</mark> \
Depending on the size and amount of files to be downloaded, it could take some time

When data capture is complete, select Next for the final section of EVIDENCE SOURCES: _<mark style="color:green;">Preparing Selected Items</mark>_ \
Note: AXIOM will archive and do its final checks. When complete, click: _<mark style="color:green;">Go to Evidence Sources</mark>_ and next click _<mark style="color:green;">Go to Processing Details</mark>_

### <mark style="color:purple;">3. Processing Details</mark>

PROCESSING DETAILS allow additional IOCs or search keywords to be added to the search.

<mark style="color:purple;">**Data Processing Options**</mark>\
<mark style="color:orange;">**Quick Scan**</mark><mark style="color:orange;">:</mark> A faster option focusing on key artefact types and providing quick insights into major evidence categories. \
<mark style="color:orange;">**Full Scan**</mark><mark style="color:orange;">:</mark> Performs a comprehensive scan of all collected data, including a deeper search for deleted files, file system artefacts, and more granular evidence. \
<mark style="color:orange;">**Custom Scan**</mark><mark style="color:orange;">:</mark> Customise the scan to focus on specific artefact types, such as system logs, user activity, or network traffic.

Add Keywords to Search\
Keyword Search Types:

## <mark style="color:purple;">Examine and Explorer</mark>

### <mark style="color:purple;">4. Artifacts Details</mark>

Like processing details, artefact details allow you to add certain artefacts to the process. \
Click: _<mark style="color:green;">Go to Analyse Evidence</mark>_

<mark style="color:orange;">**Key Artifact Categories for Windows Networks**</mark>\
AXIOM will automatically identify and categorise computer artefacts into the following: \
<mark style="color:orange;">**Windows Event Logs**</mark><mark style="color:orange;">:</mark> Analyse event logs for system events, including security logs, application logs, and system errors. \
<mark style="color:orange;">**User Activity Logs**</mark><mark style="color:orange;">:</mark> Examine user activity, including login history, accessed files, and deleted files. <mark style="color:orange;">**Browser Artifacts**</mark><mark style="color:orange;">:</mark> Investigate browser history, downloads, cookies, and cache files for evidence of malicious activity or data exfiltration. \
<mark style="color:orange;">**Network Connections**</mark><mark style="color:orange;">:</mark> Review network connection logs to identify unauthorised or suspicious connections. \
<mark style="color:orange;">**Registry Keys**</mark><mark style="color:orange;">:</mark> Look at key Registry entries for evidence of persistence mechanisms (e.g., startup programs, run keys). \
<mark style="color:orange;">**Memory Analysis**</mark><mark style="color:orange;">:</mark> If you collected memory dumps, examine the volatile data for running processes, open network connections, and malware. \
<mark style="color:orange;">**Email and Communication Logs**</mark><mark style="color:orange;">:</mark> Investigate user communications, such as emails or messaging apps, for phishing attempts or suspicious links.

<mark style="color:purple;">**Timeline Generation**</mark>\
Generate a <mark style="color:orange;">**timeline**</mark> of system activity to help correlate suspicious events across multiple artefacts. This is especially useful for understanding the sequence of events in an attack, such as initial compromise, lateral movement, and data exfiltration.

### <mark style="color:purple;">5. Analyse Evidence</mark>

Click: _<mark style="color:green;">Analyse Evidence,</mark>_ AXIOM will process and analyse the evidence

**Key Areas of Focus for Intrusion Analysis**

<mark style="color:purple;">**Initial Access Vector**</mark>\
<mark style="color:orange;">**Phishing Emails**</mark><mark style="color:orange;">:</mark> Investigate user emails and attachments for phishing attempts or malicious links. <mark style="color:orange;">**Browser Downloads**</mark><mark style="color:orange;">:</mark> Check browser history and downloads for drive-by downloads or malicious files. <mark style="color:orange;">**Suspicious User Activity**</mark><mark style="color:orange;">:</mark> Analyse user activity logs to identify abnormal logins or suspicious file access.

<mark style="color:purple;">**Privilege Escalation**</mark>\
Once attackers gain access to a Windows system, they often attempt to escalate privileges to gain complete control. \
<mark style="color:orange;">**Windows Event Logs**</mark><mark style="color:orange;">:</mark> Examine Security and System event logs for failed login attempts, new user accounts, or privilege escalation events. \
<mark style="color:orange;">**Registry Changes**</mark><mark style="color:orange;">:</mark> Analyse changes to the Windows Registry that might indicate the attacker-enabled persistence mechanisms. \
<mark style="color:orange;">**User Account Control (UAC)**</mark><mark style="color:orange;">:</mark> Check for attempts to bypass UAC or changes in user group membership (e.g., adding a user to the Administrators group).

<mark style="color:purple;">**Lateral Movement**</mark>\
<mark style="color:orange;">**Authentication Logs**</mark><mark style="color:orange;">:</mark> Review logins across multiple systems to identify signs of lateral movement. This includes failed or successful remote login attempts (e.g., RDP, SMB). \
<mark style="color:orange;">**Network Traffic**</mark><mark style="color:orange;">:</mark> Investigate network traffic between compromised and other systems to detect lateral movement. \
<mark style="color:orange;">**Remote Execution Tools**</mark><mark style="color:orange;">:</mark> Check for remote execution tools like PsExec, WMI, or PowerShell for unauthorised access.

<mark style="color:purple;">**Persistence Mechanisms**</mark>\
<mark style="color:orange;">**Startup Items**</mark><mark style="color:orange;">:</mark> Analyse startup programs to detect malware configured to persist across reboots. <mark style="color:orange;">**Scheduled Tasks**</mark><mark style="color:orange;">:</mark> Look for suspicious scheduled tasks created by attackers to maintain persistence. <mark style="color:orange;">**Registry Keys**</mark><mark style="color:orange;">:</mark> Investigate specific registry keys associated with persistence mechanisms (e.g., Run, RunOnce, etc.). **Services**: Identify any unusual or new services installed on the system that might be used to maintain access.

<mark style="color:purple;">**Data Exfiltration**</mark>\
<mark style="color:orange;">**File Access Logs**</mark><mark style="color:orange;">:</mark> Review file access logs for evidence of large-scale file transfers, particularly from sensitive directories. \
<mark style="color:orange;">**Network Traffic Logs**</mark><mark style="color:orange;">:</mark> Examine outbound traffic to external IP addresses or abnormal network ports, which may indicate data exfiltration. \
<mark style="color:orange;">**Cloud Storage**</mark><mark style="color:orange;">:</mark> If applicable, investigate cloud storage activity (e.g., OneDrive, Dropbox) for unauthorised uploads.

<mark style="color:purple;">**Malware Analysis**</mark>\
<mark style="color:orange;">**Executable Files**</mark><mark style="color:orange;">:</mark> Analyse suspicious executable files using hash matching or reverse engineering techniques. \
<mark style="color:orange;">**Malicious Scripts**</mark><mark style="color:orange;">:</mark> Investigate using PowerShell or batch scripts to execute malware or maintain persistence. \
<mark style="color:orange;">**Malware Indicators**</mark><mark style="color:orange;">:</mark> Look for common malware indicators such as suspicious processes, files in unusual directories, or hidden files.

### <mark style="color:purple;">6. Reporting and Documentation</mark>

<mark style="color:orange;">**Report Generation**</mark>\
Use the _"<mark style="color:green;">Generate Report</mark>"_ function in AXIOM Cyber to compile your findings. \
Reports can include: \
<mark style="color:orange;">**Executive Summary**</mark><mark style="color:orange;">:</mark> High-level overview of the intrusion, highlighting key findings and actions taken. <mark style="color:orange;">**Timeline of Events**</mark><mark style="color:orange;">:</mark> Detailed timeline showing key events such as the initial compromise, escalation of privileges, lateral movement, and data exfiltration. \
<mark style="color:orange;">**Technical Details**</mark><mark style="color:orange;">:</mark> Detailed technical evidence, including logs, malware samples, suspicious network connections, and file access details. Reports can be exported in PDF, HTML, or CSV formats for easy sharing with stakeholders.

**Sharing and Collaboration**\
If necessary, share the reports with relevant teams (e.g., management, legal, IT) and law enforcement. Use screenshots, file exports, and summaries of key findings to provide actionable insights into how the intrusion occurred and what remediation steps are required.

### <mark style="color:purple;">7. Post-Intrusion Remediation</mark>

Based on the findings of your analysis, provide recommendations to mitigate the damage caused by the intrusion and prevent future incidents. \
Common remediation actions include: \
<mark style="color:orange;">**Patching Vulnerabilities**</mark><mark style="color:orange;">:</mark> Identify and patch security vulnerabilities exploited during the attack. \
<mark style="color:orange;">**Improving Access Controls**</mark><mark style="color:orange;">:</mark> Strengthen access control policies to prevent unauthorised access. <mark style="color:orange;">**Implementing Monitoring**</mark><mark style="color:orange;">:</mark> Set up or improve security monitoring tools to detect similar intrusions in the future. \
<mark style="color:orange;">**Network segmentation**</mark><mark style="color:orange;">:</mark> segment the network to limit lateral movement between systems.
