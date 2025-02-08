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

# Learning to Investigate Suspicious Process Execution Using Windows Event Logs and KQL Queries

Investigating suspicious process execution using **Windows Security Logs**, **Microsoft Defender XDR**, and **KQL (Kusto Query Language)** in **Microsoft Sentinel**. Below are **extensive KQL query examples** to help you detect, analyse, and respond to malicious activity effectively.

***

### **Phase 1: Understand Windows Event Logs & KQL Basics**

#### **Objective**: Gain foundational knowledge of Windows Event Logs and KQL for querying logs in Microsoft Sentinel.

**Key Actions:**

1. **Learn the Basics of Windows Event Logs**:
   * **Log Types**:
     * **Security Logs**: Track authentication, privilege changes, and access control.
     * **System Logs**: Record system-level events like service startups and hardware issues.
     * **Application Logs**: Log application-specific events.
   * **Event IDs**:
     * **Process Creation**: Event ID `4688` (native Windows logging).
     * **Account Logon**: Event ID `4624` (successful logon) and `4625` (failed logon).
     * **File Access**: Event ID `4663` (file access attempts).
2. **Understand KQL in Microsoft Sentinel**:
   * Learn how to write queries in **KQL** to filter, analyse, and visualise data in Sentinel.
   * Use the **Schema Explorer** in Sentinel to explore available tables (e.g., `SecurityEvent`, `DeviceEvents`).
3. **Set Up a Lab Environment**:
   * Use **Windows 10/11** or **Windows Server** in a virtual machine (e.g., VirtualBox, VMware).
   * Simulate malicious activity using tools like **Atomic Red Team**, **Cobalt Strike**, or **Metasploit**.
   * Connect your lab environment to **Microsoft Sentinel** for log ingestion.
4. **Basic KQL Queries**:
   * Example: Query all process creation events from Security Logs:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4688
| project TimeGenerated, Account, NewProcessName, ParentProcessName, Process, SubjectAccount, Activity, CommandLine
```
{% endcode %}

Example: Query Defender XDR process creation events:

```kusto
DeviceEvents
| where ActionType == "ProcessCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, CommandLine
```

### **Phase 2: Detect Suspicious Process Execution**

#### **Objective**: Use KQL to detect suspicious process execution patterns in Sentinel and Defender XDR.

**Key Actions:**

1. **Focus on Key Event IDs**:
   * **Process Creation**: Event ID `4688` (native Windows logging).
   * **Network Connections**: Use Defender XDR logs (`DeviceNetworkEvents`) to track network activity.
2. **Write Advanced KQL Queries**:
   * **Detect Unusual Parent-Child Relationships**:
     * Look for `explorer.exe` spawning `powershell.exe`:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4688
| extend ParentProcessName = tostring(parse_json(EventData).ParentProcessName)
| where ParentProcessName contains "explorer.exe" and ProcessName contains "powershell.exe"
| project TimeGenerated, Account, ParentProcessName, ProcessName, CommandLine
```
{% endcode %}

**Detect Suspicious Command-Line Arguments**:

* Look for encoded PowerShell commands:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4688
| where ProcessName contains "powershell.exe" and CommandLine contains "-EncodedCommand"
| project TimeGenerated, Account, ProcessName, CommandLine
```
{% endcode %}

**Detect Processes in Unexpected Locations**:

* Look for processes running from `AppData` or `Users\Public:`

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4688
| where ProcessName has_any ("C:\\Users\\Public", "C:\\Users\\AppData")
| project TimeGenerated, Account, ProcessName, CommandLine
```
{% endcode %}

**Detect Lateral Movement via PsExec**:

* Look for `PsExec` usage, which is often used for lateral movement:

```kusto
SecurityEvent
| where EventID == 4688
| where ProcessName contains "psexec.exe"
| project TimeGenerated, Account, ProcessName, CommandLine
```

**Detect Scheduled Task Creation**:

* Look for scheduled tasks being created:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4698
| project TimeGenerated, Account, TaskName, TaskContent
```
{% endcode %}

**Detect Remote Logons**:

* Look for remote logons (Event ID `4624` with Logon Type `10`):

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4624
| extend LogonType = tostring(parse_json(EventData).LogonType)
| where LogonType == "10"
| project TimeGenerated, Account, IpAddress, LogonType
```
{% endcode %}

**Correlate Events with Defender XDR**:

* Combine process creation logs with Defender XDR logs to identify suspicious outbound traffic:

{% code overflow="wrap" %}
```kusto
let SuspiciousProcesses = SecurityEvent
| where EventID == 4688
| where ProcessName contains "powershell.exe" and CommandLine contains "-EncodedCommand"
| project ProcessId, ProcessName, CommandLine;
DeviceNetworkEvents
| join kind=inner (SuspiciousProcesses) on $left.ProcessId == $right.ProcessId
| project Timestamp, ProcessName, CommandLine, RemoteIP, RemotePort
```
{% endcode %}

**Use Defender XDR for Detection**:

* Query Defender XDR logs for suspicious process execution:

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType == "ProcessCreated"
| where FileName contains "powershell.exe"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, CommandLine
```
{% endcode %}

* Detect suspicious file modifications:

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where ActionType == "FileCreated" or ActionType == "FileModified"
| where FolderPath has_any ("C:\\Users\\Public", "C:\\Users\\AppData")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```
{% endcode %}

### **Phase 3: Investigate and Analyse**

#### **Objective**: Perform in-depth analysis of suspicious process execution.

**Key Actions:**

1. **Extract IOCs (Indicators of Compromise)**:
   * Extract file paths, command-line arguments, IP addresses, and user accounts from logs:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4688
| extend IOC = extract("http[s]?://([a-zA-Z0-9.-]+)", 1, CommandLine)
| where isnotempty(IOC)
| distinct IOC
```
{% endcode %}

**Map Activity to MITRE ATT\&CK**:

* Map suspicious PowerShell activity to **Execution (T1059):**

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4688
| where ProcessName contains "powershell.exe"
| extend Technique = "T1059 - Command and Scripting Interpreter"
| project TimeGenerated, ProcessName, CommandLine, Technique
```
{% endcode %}

**Reconstruct the Attack Chain**:

* Build a timeline of events by correlating process creation, network connections, and file modifications:

{% code overflow="wrap" %}
```kusto
let ProcessCreation = SecurityEvent
| where EventID == 4688
| project TimeGenerated, ProcessId, ProcessName, CommandLine;
let NetworkConnections = DeviceNetworkEvents
| project Timestamp, ProcessId, RemoteIP, RemotePort;
ProcessCreation
| join kind=inner (NetworkConnections) on $left.ProcessId == $right.ProcessId
| project TimeGenerated, ProcessName, CommandLine, RemoteIP, RemotePort
```
{% endcode %}

**Detect Persistence Mechanisms**:

* Look for registry modifications that could indicate persistence:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4657
| extend RegistryKey = tostring(parse_json(EventData).ObjectValueName)
| where RegistryKey contains "Run" or RegistryKey contains "Startup"
| project TimeGenerated, Account, RegistryKey, NewValue
```
{% endcode %}

**Detect Credential Dumping**:

* Look for processes accessing sensitive files like `lsass.exe`:

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where FileName == "lsass.exe"
| where InitiatingProcessFileName contains "procdump.exe" or InitiatingProcessFileName contains "mimikatz.exe"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
{% endcode %}

### **Phase 4: Respond and Mitigate**

#### **Objective**: Automate detection and response workflows using KQL in Sentinel and Defender XDR.

**Key Actions:**

1. **Automate Detection**:
   * Create detection rules in Sentinel for suspicious process execution:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4688
| where ProcessName contains "powershell.exe" and CommandLine contains "-EncodedCommand"
| extend Severity = "High"
| project TimeGenerated, ProcessName, CommandLine, Severity
```
{% endcode %}

**Develop Playbooks**:

* Use Azure Logic Apps to automate responses:
  * Example: Isolate a device when suspicious PowerShell activity is detected:

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType == "ProcessCreated"
| where FileName contains "powershell.exe" and InitiatingProcessCommandLine contains "-EncodedCommand"
| extend Action = "IsolateDevice"
| project DeviceName, Action
```
{% endcode %}

**Leverage Threat Intelligence**:

* Enrich logs with threat intelligence feeds:

{% code overflow="wrap" %}
```kusto
let ThreatIntel = externaldata(RemoteIP:string, ThreatType:string)
[@"https://example.com/threat-intel-feed.csv"];
DeviceNetworkEvents
| join kind=inner (ThreatIntel) on $left.RemoteIP == $right.RemoteIP
| project Timestamp, RemoteIP, ThreatType
```
{% endcode %}

### **Phase 5: Continuous Monitoring & Improvement**

#### **Objective**: Continuously monitor and improve detection capabilities.

**Key Actions:**

1. **Review and Update Queries**:
   * Regularly review KQL queries to adapt to evolving threats.
   * Example: Add new IOCs or behaviours to existing queries.
2. **Leverage Defender XDR Analytics**:
   * Use Defender XDR’s built-in analytics to detect advanced threats and correlate them with custom KQL queries.
3. **Contribute to the Community**:
   * Share your KQL queries, playbooks, and findings with the cybersecurity community.

### **Final Thoughts**

While there are different approaches to investigating suspicious process execution using **Windows Security Logs**, **Microsoft Sentinel**, and **Defender XDR** with **KQL**, by leveraging the KQL query examples provided, you’ll be able to detect, analyse, and respond to malicious activity effectively.
