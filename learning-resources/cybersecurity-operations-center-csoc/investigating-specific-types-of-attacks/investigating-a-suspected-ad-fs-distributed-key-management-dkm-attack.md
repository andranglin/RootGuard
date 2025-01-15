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

# Investigating a Suspected AD FS Distributed Key Management (DKM) Attack

### Investigating a **suspected AD FS Distributed Key Management (DKM) attack** on an endpoint using **KQL (Kusto Query Language)** and **Microsoft Defender.**

***

#### **Step 1: Understand the Attack Context**

The AD FS DKM key is crucial for securing sensitive AD FS configuration data. Attackers targeting this key often aim to compromise AD FS configurations for lateral movement, privilege escalation, or data exfiltration.

Common TTPs (Tactics, Techniques, and Procedures) include:

* Using tools like `Mimikatz` or `PowerShell` to dump sensitive keys.
* Accessing AD FS-related directories (`%ADFS_DATA%\Keys`).
* Privilege escalation or credential theft for unauthorised access.

***

#### **Step 2: Queries for Microsoft Defender Using KQL**

Below are some KQL queries and an approach tailored to identify suspicious activities associated with AD FS DKM attacks.

***

**1. File Access to AD FS DKM Key Directory**

**Purpose:** Detect unauthorized file access attempts to AD FS DKM key directories.

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where FolderPath contains "ADFS_DATA" and FileName endswith ".pfx"
| where ActionType in ("FileAccessed", "FileModified")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

//Expanded Query
DeviceFileEvents
| where FolderPath contains "ADFS_DATA" and FileName endswith ".pfx"
| where ActionType in ("FileAccessed", "FileModified")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (DeviceProcessEvents
    | project DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountDomain
) on $left.DeviceName == $right.DeviceName and $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountDomain
| order by Timestamp desc
```
{% endcode %}

***

#### **2. Process Interacting with DKM-Related Files**

**Purpose:** Identify processes attempting to interact with AD FS-related files.

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where FileName contains "adfs" or FolderPath contains "ADFS_DATA"
| where InitiatingProcessFileName has_any ("mimikatz.exe", "adfind.exe", "powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, AccountName
| order by Timestamp desc

//Expanded Query
DeviceProcessEvents
| where FileName contains "adfs" or FolderPath contains "ADFS_DATA"
| where InitiatingProcessFileName has_any ("mimikatz.exe", "adfind.exe", "powershell.exe")
| extend AccountDomain = split(AccountName, "\\")[0], AccountUser = split(AccountName, "\\")[1]
| join kind=leftouter (DeviceNetworkEvents
    | project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
) on $left.DeviceName == $right.DeviceName and $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, AccountDomain, AccountUser, RemoteIP, RemotePort
| order by Timestamp desc
```
{% endcode %}

***

**3. Suspicious PowerShell Commands**

**Purpose:** Detect PowerShell commands targeting AD FS or attempting to export sensitive configurations.

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("ADFS", "export", "keys", "Get-AdfsConfiguration")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc

// Expanded Query
DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("ADFS", "export", "keys", "Get-AdfsConfiguration")
| extend AccountDomain = split(AccountName, "\\")[0], AccountUser = split(AccountName, "\\")[1]
| join kind=leftouter (DeviceNetworkEvents
    | project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
) on $left.DeviceName == $right.DeviceName and $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
| project Timestamp, DeviceName, ProcessCommandLine, AccountDomain, AccountUser, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```
{% endcode %}

***

**4. Privilege Escalation or Credential Dumping Attempts**

**Purpose:** Spot attempts to dump credentials or escalate privileges using known tools.

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in ("mimikatz.exe", "adfind.exe", "dsquery.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc

// Expanded Query
DeviceProcessEvents
| where InitiatingProcessFileName in ("mimikatz.exe", "adfind.exe", "dsquery.exe")
| extend AccountDomain = split(AccountName, "\\")[0], AccountUser = split(AccountName, "\\")[1]
| join kind=leftouter (DeviceNetworkEvents
    | project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
) on $left.DeviceName == $right.DeviceName and $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountDomain, AccountUser, RemoteIP, RemotePort
| order by Timestamp desc
```
{% endcode %}

***

**5. Elevated Access Logon Events**

**Purpose:** Highlight unusual elevated access that might indicate compromised credentials.

{% code overflow="wrap" %}
```kusto
DeviceLogonEvents
| where LogonType in ("Elevated", "Interactive")
| where AccountName != "SYSTEM"
| project Timestamp, AccountName, DeviceName, LogonType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

//Expanded Query
// Filter DeviceProcessEvents for specific files and commands
DeviceProcessEvents
| where InitiatingProcessFileName in ("mimikatz.exe", "adfind.exe", "dsquery.exe")
// Extend AccountDomain and AccountUser from AccountName
| extend AccountDomain = tostring(split(AccountName, "\\")[0]), AccountUser = tostring(split(AccountName, "\\")[1])
// Join with DeviceNetworkEvents to enrich data with network information
| join kind=leftouter (
    DeviceNetworkEvents
    | project DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
) on $left.DeviceName == $right.DeviceName and $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
// Project relevant columns
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountDomain, AccountUser, RemoteIP, RemotePort
// Filter events within the last 30 days
| where Timestamp >= ago(30d)
// Summarize results to get a quick overview
| summarize Count = count() by Timestamp, DeviceName, InitiatingProcessFileName, AccountDomain, AccountUser
// Order by Timestamp in descending order
| order by Timestamp desc
```
{% endcode %}

***

**6. Unusual Network Connections**

**Purpose:** Uncover potential outbound connections for data exfiltration or communication with Command and Control (C2) servers.

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("powershell.exe", "mimikatz.exe")
| where RemoteUrl != "" or isnotempty(RemoteIP)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc

// Expanded Query
// Filter DeviceNetworkEvents for specific processes and network activity
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("powershell.exe", "mimikatz.exe")
| where RemoteUrl != "" or isnotempty(RemoteIP)
// Extend AccountDomain and AccountUser from InitiatingProcessAccountName
| extend AccountDomain = tostring(split(InitiatingProcessAccountName, "\\")[0]), AccountUser = tostring(split(InitiatingProcessAccountName, "\\")[1])
// Join with DeviceProcessEvents to enrich data with process information
| join kind=leftouter (
    DeviceProcessEvents
    | project DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
) on $left.DeviceName == $right.DeviceName and $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
// Project relevant columns
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, AccountDomain, AccountUser
// Filter events within the last 30 days
| where Timestamp >= ago(30d)
// Summarize results to get a quick overview
| summarize Count = count() by Timestamp, DeviceName, InitiatingProcessFileName, AccountDomain, AccountUser
// Order by Timestamp in descending order
| order by Timestamp desc
```
{% endcode %}

***

**7. DKM File Access Correlated with User Accounts**

**Purpose:** Correlate DKM key access with user logon events.

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where FolderPath contains "ADFS_DATA" and FileName endswith ".pfx"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType
| join kind=inner (
    DeviceLogonEvents
    | project AccountName, Timestamp, DeviceName, LogonType
) on DeviceName
| project Timestamp, AccountName, DeviceName, FolderPath, FileName, ActionType, LogonType
| order by Timestamp desc

//Expanded Query
// Filter DeviceFileEvents for specific folder and file type
DeviceFileEvents
| where FolderPath contains "ADFS_DATA" and FileName endswith ".pfx"
// Join with DeviceLogonEvents to enrich data with logon information
| join kind=inner (
    DeviceLogonEvents
    | project AccountName, Timestamp, DeviceName, LogonType
) on $left.DeviceName == $right.DeviceName
// Project relevant columns
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, LogonType, AccountName
// Filter events within the last 30 days
| where Timestamp >= ago(30d)
// Summarize results to get a quick overview
| summarize Count = count() by Timestamp, DeviceName, AccountName, LogonType
// Order by Timestamp in descending order
| order by Timestamp desc
```
{% endcode %}

***

#### **Step 3: Investigation in Microsoft Defender**

1. **Use the Advanced Hunting Tool:**
   * Navigate to **Microsoft Defender Security Center** > **Advanced Hunting**.
   * Run the KQL queries above to identify suspicious activities.
2. **Analyse Alerts:**
   * Look for triggered alerts on tools like `Mimikatz`, AD FS-related processes, or privilege escalation.
   * Review correlated incidents for further insights.
3. **Investigate Incident Timeline:**
   * Examine the sequence of events to determine:
     * When the attack started.
     * How the attacker accessed the AD FS system.
     * Whether there was lateral movement or data exfiltration.

***

#### **Step 4: Mitigation Steps**

* **Isolate the Compromised Endpoint:**
  * Use Defender to isolate the endpoint from the network.
* **Audit and Rotate the DKM Keys:**
  * Regenerate the DKM key if compromise is suspected.
  * Follow Microsoft's guidance for secure key management.
* **Patch and Harden AD FS Servers:**
  * Apply the latest patches and updates to AD FS servers.
  * Implement stricter access controls and monitoring.
* **Monitor and Validate Security Controls:**
  * Enable logging for AD FS and monitor suspicious activities.
  * Use threat intelligence feeds to update IoC detections.

***

#### **Step 5: Post-Incident Actions**

* **Review Lessons Learned:**
  * Conduct a post-mortem to understand weaknesses in your AD FS deployment.
  * Train staff on detecting and preventing AD FS-related threats.
* **Implement Enhanced Monitoring:**
  * Use continuous monitoring for sensitive AD FS operations.
  * Integrate Defender alerts with SIEM for real-time analysis.
