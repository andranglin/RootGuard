# Hunting Ransomware Indicators

## Introduction

**Hunting for ransomware indicators** involves proactively identifying signs of ransomware activity within an environment to mitigate threats before they result in significant damage. Ransomware often exhibits a predictable lifecycle, including initial access, privilege escalation, lateral movement, and encryption of files. Key indicators include unusual process executions, such as suspicious PowerShell commands or unauthorised access to critical directories, as well as the presence of tools like Mimikatz or Cobalt Strike used for credential theft and persistence. Monitoring high volumes of file modifications, unexpected spikes in CPU usage, and unusual file extensions can help uncover encryption activities indicative of ransomware attacks.

Effective ransomware hunting leverages threat intelligence, security frameworks like MITRE ATT\&CK, and tools capable of analysing endpoint, network, and identity data. By using platforms like Microsoft Sentinel, Splunk, or Defender for Endpoint, analysts can deploy custom queries to detect lateral movement, unauthorised access attempts, or anomalous traffic patterns to external IPs. Behavioural analysis, such as identifying accounts accessing large numbers of files or systems attempting unauthorised registry changes, is critical. Hunting for these ransomware indicators allows security teams to identify early warning signs, enabling swift remediation and minimising potential impact.

The following is a set of KQL queries that can be used to detect and analyse malicious or suspicious activities in your environment. The queries are designed to quickly grab the necessary information that will allow the investigator to determine whether the activity warrants deeper analysis or escalation.

**Note**: On some occasions, hopefully, at a minimum, you will have to customise the queries for the environment where they are being used. Queries will only work if the data is available.

### 1. **Identify Initial Compromise**

Ransomware typically begins with an initial compromise, often through email phishing, malicious files, or vulnerable services. Using KQL, you can identify this stage by looking for suspicious login events, email attachments, or newly downloaded executables. **Example KQL Query to Detect Suspicious File Downloads:**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".js" | where FolderPath startswith "C:\\Users\\Public\\Downloads\\" or FolderPath startswith "C:\\Temp\\" | where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe") | project DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, Timestamp
```
{% endcode %}

This query identifies downloads of executables or scripts from common locations associated with drive-by downloads or phishing attacks. **Example Query for Anomalous Logins:**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where Timestamp > ago(1d) | where LogonType == "RemoteInteractive" or LogonType == "Network" | where AccountName endswith "$" == false | where AccountDomain != "ExpectedDomain" | summarize count() by AccountName, DeviceName | where count_ > 3
```
{% endcode %}

This query highlights suspicious logins, focusing on potentially compromised accounts showing remote access patterns.

### 2. **Trace Lateral Movement and Privilege Escalation**

Once the ransomware gains a foothold, it often uses tools like `PsExec`, `WMIC`, or PowerShell for lateral movement and privilege escalation. **Advanced KQL for Detecting Lateral Movement via Remote Commands:**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessFileName in ("psexec.exe", "wmic.exe", "powershell.exe") | where ProcessCommandLine contains "Invoke-Command" or ProcessCommandLine contains "-EncodedCommand" | summarize count() by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName | where count_ > 5 | project DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
```
{% endcode %}

This query detects high-frequency remote command executions associated with lateral movement. **Identifying Privilege Escalation Attempts:**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessFileName == "powershell.exe" | where ProcessCommandLine has_any ("Add-LocalGroupMember", "net localgroup administrators") | project DeviceName, InitiatingProcessFileName, ProcessCommandLine, Timestamp
```
{% endcode %}

### 3. **Detect Encryption Activity**

Ransomware often renames or appends specific file extensions during encryption. Monitoring high-frequency file access events can help detect these activities early. **High-Frequency File Modification Query:**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where Timestamp > ago(1h) | where FileName endswith ".encrypted" or FileName endswith ".lock" or FileName contains "." | summarize EventCount = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName | where InitiatingProcessAccountName !in ("system", "network service")| where EventCount > 50 | project DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, EventCount
```
{% endcode %}

This query flags devices with high volumes of file changes, indicating potential encryption.

### 4. **Persistence Mechanisms and Cleanup**

Ransomware often sets up persistence by modifying registry keys or scheduling tasks to maintain access or re-execute encryption. **Detecting Malicious Registry Modifications:**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey contains "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" | where RegistryValueName contains "Startup" | where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "mshta.exe", "svchost.exe") | project DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData, Timestamp
```
{% endcode %}

This query finds unusual registry modifications commonly used for persistence. **Scheduled Tasks for Persistence:**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/create" | where InitiatingProcessFileName !in~ ("officesvcmgr.exe", "cscript.exe") | where AccountName !in~ ("system") | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine
```
{% endcode %}

This query identifies any creation of scheduled tasks, often used by ransomware for persistence.

### 5. **Analyse Network Traffic for C2 Communication**

After deployment, ransomware may communicate with a Command-and-Control (C2) server to report status or receive encryption keys. **Query for C2-like Network Activity:**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP != "trusted_IP_list" and RemoteUrl contains "unknown_domain" | summarize ConnectionCount = count() by DeviceName, RemoteIP, RemoteUrl | where ConnectionCount > 10 | project DeviceName, RemoteIP, RemoteUrl, ConnectionCount
```
{% endcode %}

Replace `"trusted_IP_list"` and `"unknown_domain"` with internal baselines and known indicators of C2.

### 6. **Isolate Affected Devices**

To contain the ransomware, isolate affected devices to prevent further spread. Microsoft Defender supports device isolation actions that can be managed from the portal.

#### 7. **Post-Incident Analysis and Cleanup**

Once containment is achieved, review the timeline of events, perform cleanup, and ensure that no persistence mechanisms remain. Use the timeline to correlate events and understand the attack flow. **Example Timeline Query:**

{% code overflow="wrap" %}
```cs
union DeviceLogonEvents, DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents | where DeviceName == "Affected_Device_Name" | order by Timestamp asc | project Timestamp, InitiatingProcessFileName, FileName, RemoteIP, AccountName
```
{% endcode %}

#### Step 1: Detection and Triage

Use KQL to identify initial indicators of compromise (IoCs) that suggest a ransomware attack.

**Identify Suspicious File Creation Patterns (Encryption Activity)**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where ActionType in ("FileCreated", "FileModified") | summarize ModificationRate = count() by DeviceName, FileName, FolderPath, ActionType, bin(Timestamp, 5m) | where ModificationRate > 100 | project DeviceName, Timestamp, ModificationRate, ActionType, FileName, FolderPath | order by ModificationRate desc
```
{% endcode %}

**Detect Ransomware-Associated Extensions**

Track new file extensions commonly associated with ransomware encryption:

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where ActionType == "FileCreated" | where FileName endswith_any (".encrypted", ".locked", ".enc", ".cry", ".crypt") | project Timestamp, DeviceName, FolderPath, FileName
```
{% endcode %}

#### Step 2: Analyse Initial Access and Execution

Examine logs to identify the initial entry point and execution methods. Attackers commonly use phishing emails or exploit vulnerabilities to gain initial access.

**Identify Malicious PowerShell or CMD Commands**

Advanced script execution monitoring helps uncover potential ransomware scripts:

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessFileName in ("powershell.exe", "cmd.exe") | where ProcessCommandLine contains_any ("-Enc", "-e", "Invoke-Mimikatz", "Add-MpPreference") | project Timestamp, DeviceName, FileName, ProcessCommandLine | order by Timestamp desc
```
{% endcode %}

**Detect Suspicious Downloads (Initial Payload)**

Malicious downloads often precede ransomware execution. Identify uncommon network locations used by `powershell.exe` or `bitsadmin.exe`:

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where InitiatingProcessFileName in ("powershell.exe", "bitsadmin.exe") | where RemoteIPType == "Public" and InitiatingProcessCommandLine contains "http" | summarize by Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteIP
```
{% endcode %}

#### Step 3: Contain and Isolate

At this stage, focus on isolating infected devices and identifying lateral movement attempts.

**Detect Credential Dumping or Reconnaissance**

Check for tools that can be used to gather credentials, such as `mimikatz` or suspicious usage of `lsass.exe`:

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("mimikatz.exe", "procdump.exe", "lsass.exe") | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine | where ProcessCommandLine contains_any ("lsass", "dump", "credentials") | order by Timestamp desc
```
{% endcode %}

**Identify Lateral Movement (Remote Connections)**

Detect RDP or SMB connections to determine if the attacker is moving laterally within the network:

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType in ("InboundConnectionAccepted", "RemoteDesktop") | where RemoteIPType == "Internal" | summarize ConnectionCount = count() by DeviceName, RemoteIP | where ConnectionCount > 5  // Adjust threshold based on network norms | order by ConnectionCount desc
```
{% endcode %}

#### Step 4: Eradication

Remove ransomware artifacts, persistence mechanisms, and any backdoors the attacker may have established.

**Locate and Delete Suspicious Scheduled Tasks**

Attackers often use scheduled tasks to maintain persistence. Identify any unusual tasks created:

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "schtasks.exe" | where ProcessCommandLine contains "create" | where AccountName !in~ ("system") | project Timestamp, DeviceName, AccountName, ProcessCommandLine | order by Timestamp desc
```
{% endcode %}

**Identify Registry Modifications for Persistence**

Check for registry modifications in areas associated with persistence:

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where ActionType == "RegistryValueSet" | where RegistryKey contains @"\Software\Microsoft\Windows\CurrentVersion\Run" | where InitiatingProcessAccountName !in~ ("system", "skype", "sys_uk_oraclegrid") | project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
{% endcode %}

#### Step 5: Recovery and Post-Incident Analysis

defencesRestore affected systems, monitor for reinfection, and perform a post-mortem analysis to strengthen defences.

**Review High-Risk User Logons**

Identify unusual logins during the ransomware incident period, particularly those that may indicate compromised accounts:

{% code title="" overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "Network" | where Timestamp between (datetime(2024-10-20T00:00:00Z)..datetime(2024-10-20T23:59:59Z)) | where AccountName !endswith "$" | where  AccountName !contains "sys_" | project Timestamp, DeviceName, AccountName, LogonType, ActionType | order by Timestamp desc
```
{% endcode %}

**Monitor Outbound Data Transfers (Potential Exfiltration)**

Check for large data transfers to external IPs, which may indicate data exfiltration:

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "ConnectionSuccess" | where RemoteIPType == "Public" and LocalPort in ("80", "443") | summarize DataTransferred = sum(SentBytes + ReceivedBytes) by DeviceName, RemoteIP, bin(Timestamp, 1h) | where DataTransferred > 10000000 // Threshold for significant transfer, adjust as needed
```
{% endcode %}

### Advanced Analysis Queries

**Detecting Living-Off-the-Land Techniques (LOLBins)**

Use KQL to find legitimate Windows binaries commonly used in attacks, such as `rundll32`, `regsvr32`, and `mshta`.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("rundll32.exe", "regsvr32.exe", "mshta.exe") | where ProcessCommandLine in~ ("javascript:" "http" "dll" "shellcode") | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
{% endcode %}

**Searching for Known Ransomware Hashes (if available)**

Match file hashes to known ransomware signatures to confirm the presence of ransomware:

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where SHA256 in ("<hash1>", "<hash2>", "<hash3>")  // Replace with known ransomware hashes | project Timestamp, DeviceName, FolderPath, FileName, SHA256
```
{% endcode %}

### Summary

These advanced KQL queries offer a thorough approach to detecting and responding to ransomware in a Windows environment with Microsoft Defender. Each step ensures effective discovery, containment, and eradication of ransomware artifacts. Adjust thresholds based on your environment's baseline and use the collected insights for further security hardening.

### **1. Initial Preparation**

* **Log into Microsoft 365 Defender**: Access the **Advanced Hunting** console to begin the search.
* **Identify Initial Indicators of Compromise (IOCs)**: Gather any preliminary information, like file hashes, known malicious IP addresses, or suspicious processes flagged by the security team.

### **2. Advanced KQL Queries for Ransomware Detection**

**a. Step 1: Identify Suspicious Process Executions**

Ransomware often starts with specific processes like `powershell.exe`, `cmd.exe`, or custom executables that perform encryption, shadow deletion, and disabling recovery features.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessFileName in ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "svchost.exe") | where InitiatingProcessCommandLine contains ("vssadmin" "bcdedit" "cipher" "wbadmin" "shadow" "delete" "disable") | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName, InitiatingProcessAccountName | order by Timestamp desc
```
{% endcode %}

**Explanation**: This query captures any instances where processes with encryption or shadow deletion commands have been executed, often used by ransomware to prevent data recovery.

**b. Step 2: Discover File Encryption or Mass File Modification Patterns**

Ransomware modifies or creates encrypted files in bulk. Identify file events with specific file extensions or high volumes.

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where ActionType in ("FileModified", "FileCreated") | where FolderPath contains "Users" or FolderPath contains "Documents" | extend EncryptedExtension = extract("(\.[a-zA-Z]{4,7})$", 1, FileName) | where EncryptedExtension in (".locked", ".crypted", ".enc", ".encrypted") | summarize EncryptedFiles = count() by DeviceName, EncryptedExtension | where EncryptedFiles > 100
```
{% endcode %}

**Explanation**: This query identifies a high volume of file modifications or creations with extensions commonly linked to ransomware. Adjust `EncryptedFiles` threshold based on the environment's normal activity.

**c. Step 3: Detect C2 or External Communication Activity**

Outbound communication to unknown or malicious IP addresses is common in ransomware attacks, either to receive encryption keys or exfiltrate data.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIPType == "Public" and Protocol == "TCP" | where isnotempty(RemoteIP) | summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP, RemotePort, DeviceName, InitiatingProcessFileName | where Connections > 5 and (FirstSeen < ago(1d) or LastSeen > ago(1h)) | join kind=leftouter (ThreatIntelligenceIndicator     | project TI_IP = NetworkIP, ThreatType, Description) on $left.RemoteIP == $right.TI_IP | project Timestamp = LastSeen, DeviceName, RemoteIP, ThreatType, Description, Connections, InitiatingProcessFileName
```
{% endcode %}

**Explanation**: This query detects connections to external IPs with a high connection count. It joins with known threat intelligence data to highlight potential C2 communication.

**d. Step 4: Identify New or Modified Services for Persistence**

Ransomware often adds itself as a service or modifies existing services to maintain persistence.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ActionType == "ServiceInstalled" or ActionType == "ServiceModified" | where InitiatingProcessAccountName contains "SYSTEM" or AccountDomain contains "NT AUTHORITY" | project Timestamp, DeviceName, InitiatingProcessFileName, ServiceName, ServiceDescription, AccountName
```
{% endcode %}

**Explanation**: This query focuses on service installations or modifications initiated by SYSTEM accounts, likely indicating persistence mechanisms for ransomware.

**e. Step 5: Detect Registry Changes for Persistence or Disabling Security Features**

Registry modifications related to persistence or disabling security features (such as tampering with antivirus settings) are typical in ransomware incidents.

{% code overflow="wrap" %}
```kusto
DeviceRegistryEvents | where ActionType in ("RegistryKeyValueCreated", "RegistryKeyValueModified") | where RegistryKey has_any ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies", "SYSTEM\\CurrentControlSet\\Services") | where RegistryValueData contains ("disable" "off" "false" "0x0") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```
{% endcode %}

**Explanation**: This query filters registry modifications to keys used for persistence or disabling security controls, targeting any suspicious values.

**f. Step 6: Identify File Renaming or High-Frequency File Creation Patterns**

Many ransomware variants rename or duplicate files with different extensions, often as part of the encryption process.

{% code overflow="wrap" %}
```kusto
DeviceFileEvents 
| where ActionType == "FileRenamed" 
| where FileName !endswith ".xml" 
| where FileName !endswith ".wer" 
| summarize RenameCount = count() by DeviceName, FileName, FolderPath 
| where RenameCount > 50
```
{% endcode %}

**Explanation**: This query identifies directories with high volumes of file renaming, indicating mass encryption.
