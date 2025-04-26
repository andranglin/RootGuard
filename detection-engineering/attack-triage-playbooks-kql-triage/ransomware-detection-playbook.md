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

# Ransomware Detection Playbook

### Introduction: The Need for Effective Ransomware Detection Capabilities

Ransomware remains one of the most disruptive and financially damaging cyber threats facing organisations today. Modern ransomware attacks have evolved beyond simple file encryption, incorporating double and triple extortion tactics, data exfiltration, and persistent lateral movement to maximise impact. Adversaries exploit vulnerabilities, compromised credentials, and social engineering tactics to gain initial access, then deploy stealthy techniques to evade detection before executing their attack. Given the increasing sophistication of ransomware groups and the expanding attack surface across cloud, hybrid, and on-premises environments, organisations must adopt a proactive and multi-layered detection approach.

Effective ransomware detection capabilities and processes are critical to identifying and mitigating attacks before they escalate into full-scale incidents. A robust detection strategy should integrate real-time endpoint and network monitoring, behavioural analytics, anomaly detection, and threat intelligence. Security tools such as Endpoint Detection and Response (EDR), Extended Detection and Response (XDR), and Security Information and Event Management (SIEM) solutions play a crucial role in detecting ransomware indicators, including unauthorised file encryption, unusual privilege escalation, and rapid file modifications.

To stay ahead of ransomware threats, organisations must implement continuous threat-hunting, automated alerting, and incident response playbooks designed for rapid containment and recovery. By enhancing visibility, leveraging advanced analytics, and strengthening security controls, organisations can improve their ability to detect and prevent ransomware attacks, minimising financial and operational damage while ensuring business continuity.

### Table of Contents

1. Initial Detection of Ransomware Activity
   * Identify Suspicious File Modifications
   * Detect Unusual Encryption Activities
   * Advanced Network Traffic Analysis
2. Persistence Mechanisms
   * Registry Persistence Indicators
   * Scheduled Task Creation
   * Startup Folder Monitoring
3. Privilege Escalation Indicators
   * Detect Abnormal Account Activity
   * Credential Dumping Attempts
   * Privilege Escalation via Exploits
4. Lateral Movement
   * SMB-Based Propagation
   * Lateral Movement via Remote Execution
   * Advanced Detection of SSH Movement
5. Data Exfiltration Detection
   * Large Data Transfers to External IPs
   * Anomalous Cloud Storage Activity
   * DNS or HTTPS Exfiltration
6. Incident Response and Containment
   * Isolate Affected Systems
   * Identify Indicators of Compromise (IoCs)
   * Incident Timeline Reconstruction
7. Conclusion

***

This playbook provides advanced KQL queries and techniques to detect, analyse, and respond to ransomware compromises across an enterprise. Each section offers multiple query options with detailed descriptions and expected results.

### 1. **Initial Detection of Ransomware Activity**

#### Query Option 1: Identify Suspicious File Modifications

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileModified", "FileRenamed")
| where FileName endswith ".txt" or FileName endswith ".log"
| where FolderPath contains "Desktop" or FolderPath contains "Documents"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType
```

**Description:** Detects suspicious modifications to common file types often targeted by ransomware. Results display modified file details and locations.

#### Query Option 2: Detect Unusual Encryption Activities

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName endswith ".encrypted" or FileName matches regex @"\.\w{4,6}" and not (FileName contains ".txt" or FileName contains ".doc")
| summarize EncryptedCount = count() by DeviceName, FolderPath
| where EncryptedCount > 50
| project DeviceName, FolderPath, EncryptedCount
```
{% endcode %}

**Description:** Flags potential ransomware encryption activities by analysing file extensions and volume of encrypted files. Results highlight affected folders and devices.

#### Query Option 3: Advanced Network Traffic Analysis

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and BytesSent > 1000000
| summarize TotalBytesSent = sum(BytesSent) by DeviceName, RemoteIPAddress
| where TotalBytesSent > 10000000
| project DeviceName, RemoteIPAddress, TotalBytesSent
```

**Description:** Identifies devices with unusually large outbound traffic, indicating possible ransomware communication or exfiltration. Results include devices, IPs, and data volumes.

***

### 2. **Persistence Mechanisms**

#### Query Option 1: Registry Persistence Indicators

{% code overflow="wrap" %}
```kusto
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKeyPath has_any ("Run", "RunOnce", "Policies\\Explorer")
| project Timestamp, DeviceName, RegistryKeyPath, RegistryValueName, RegistryValueData
```
{% endcode %}

**Description:** Detects registry keys often modified by ransomware for persistence. Results display registry paths and modified values.

#### Query Option 2: Scheduled Task Creation

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Description:** Identifies the creation of scheduled tasks, often used for persistence. Results include initiating accounts and devices.

#### Query Option 3: Startup Folder Monitoring

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath contains "Startup" and FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Description:** Flags executables added to startup folders, a common persistence technique. Results display file details and timestamps.

***

### 3. **Privilege Escalation Indicators**

#### Query Option 1: Detect Abnormal Account Activity

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonStatus != "Success"
| summarize FailedAttempts = count() by AccountName, DeviceName
| where FailedAttempts > 20
| project AccountName, DeviceName, FailedAttempts
```

**Description:** Detects accounts with repeated failed login attempts. Results highlight potentially compromised accounts.

#### Query Option 2: Credential Dumping Attempts

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("procdump.exe", "lsass.exe") and ProcessCommandLine contains "-ma"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```
{% endcode %}

**Description:** Flags attempts to dump credentials from memory. Results show processes and associated devices.

#### Query Option 3: Privilege Escalation via Exploits

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(\\bexploit\\b|\\belevate\\b|\\bprivilege\\b)"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```
{% endcode %}

**Description:** Detects commands used for privilege escalation. Results display timestamps, devices, and associated accounts.

***

### 4. **Lateral Movement**

#### Query Option 1: SMB-Based Propagation

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath startswith "\\\\" and FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Description:** Detects executable files being accessed over SMB shares. Results highlight potential ransomware propagation paths.

#### Query Option 2: Lateral Movement via Remote Execution

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains_any ("psexec", "wmic")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```

**Description:** Tracks remote execution commands used for lateral movement. Results include initiating accounts and devices.

#### Query Option 3: Advanced Detection of SSH Movement

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Network" and ProcessName == "ssh"
| project Timestamp, DeviceName, AccountName, RemoteIPAddress
```

**Description:** Flags SSH-based lateral movement. Results include accounts and associated devices.

***

### 5. **Data Exfiltration Detection**

#### Query Option 1: Large Data Transfers to External IPs

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 10000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Identifies significant outbound data transfers. Results include source devices and data volumes.

#### Query Option 2: Anomalous Cloud Storage Activity

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteDnsDomain endswith "amazonaws.com" or RemoteDnsDomain endswith "blob.core.windows.net"
| summarize TotalData = sum(BytesSent) by RemoteDnsDomain, DeviceName
| where TotalData > 50000000
| project RemoteDnsDomain, DeviceName, TotalData
```
{% endcode %}

**Description:** Tracks large data uploads to cloud storage services. Results display domain names and data volumes.

#### Query Option 3: DNS or HTTPS Exfiltration

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol in ("DNS", "HTTPS") and strlen(RemoteDnsDomain) > 50
| summarize QueryCount = count() by RemoteDnsDomain
| where QueryCount > 100
| project RemoteDnsDomain, QueryCount
```

**Description:** Detects DNS or HTTPS exfiltration based on query patterns. Results include domain names and query counts.

***

### 6. **Incident Response and Containment**

#### Query Option 1: Isolate Affected Systems

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPAddress in ("<IoC-IP-List>")
| project Timestamp, DeviceName, RemoteIPAddress
```

**Description:** Identifies systems communicating with known malicious IPs. Results assist in isolation efforts.

#### Query Option 2: Identify Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceFileEvents
| where SHA256 in ("<IoC-Hash-List>")
| project Timestamp, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs (hashes) with process and file events. Results display impacted devices and files.

#### Query Option 3: Incident Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, ProcessCommandLine, RemoteIPAddress, FileName
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a timeline of ransomware-related activities. Results provide a comprehensive incident overview.

***

### 7. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
