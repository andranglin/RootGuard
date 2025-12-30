# Windows Intrusion Detection Playbook

### Introduction: The Need for Effective Windows Intrusion Detection Capabilities

Windows-based environments remain a primary target for cyber threats due to their widespread use in enterprise networks, making effective intrusion detection a critical component of any security strategy. Attackers frequently exploit misconfigurations, unpatched vulnerabilities, and credential-based attacks to gain unauthorised access, establish persistence, and move laterally within Windows infrastructures. Advanced threats, including fileless malware, PowerShell abuse, and living-off-the-land (LotL) techniques, make it increasingly difficult to detect malicious activities using traditional security measures alone.

Effective Windows intrusion detection capabilities and processes are essential to identifying and mitigating security threats before they escalate into full-scale breaches. A robust detection strategy should integrate Security Information and Event Management (SIEM) solutions, Endpoint Detection and Response (EDR), User and Entity Behavior Analytics (UEBA), and advanced log analysis to monitor Windows Security Event Logs, process execution, authentication attempts, and privilege escalation activities. Additionally, leveraging threat intelligence, anomaly detection, and automated correlation techniques enhances the ability to detect stealthy adversary behaviours.

To stay ahead of attackers, organisations must implement continuous monitoring, proactive threat-hunting, and rapid incident response processes tailored for Windows environments. By strengthening detection capabilities and response mechanisms, security teams can effectively identify and neutralise Windows-based intrusions, protecting critical systems, sensitive data, and overall enterprise security.

### Table of Contents

1. Initial Detection of Intrusion Activity
   * Identify Suspicious Login Activity
   * Detect Anomalous Process Execution
   * Monitor Unusual Network Connections
2. Privilege Escalation Indicators
   * Track Abnormal Use of Admin Tools
   * Detect Suspicious Privilege Elevation Commands
   * Identify Credential Dumping Attempts
3. Persistence Mechanisms
   * Detect Registry Key Modifications
   * Monitor Startup Folder Changes
   * Identify Scheduled Task Creation
4. Lateral Movement Detection
   * SMB Lateral Movement
   * RDP Session Monitoring
   * WMI Remote Execution
5. Data Exfiltration Indicators
   * Monitor Large Data Transfers
   * Detect Data Compression Tools
   * Identify DNS Tunneling Activity
6. Incident Response and Containment
   * Isolate Compromised Systems
   * Correlate Indicators of Compromise (IoCs)
   * Timeline Reconstruction
7. Conclusion

***

This playbook provides advanced KQL queries and techniques for detecting and analysing Windows intrusions across an organisation using Microsoft Defender and Sentinel. Each section includes multiple query options with detailed descriptions and expected results.

### 1. **Initial Detection of Intrusion Activity**

#### Query Option 1: Identify Suspicious Login Activity

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Network" and IsExternalIP == true
| summarize LoginCount = count() by AccountName, RemoteIP
| where LoginCount > 5
| project AccountName, RemoteIP, LoginCount
```

**Description:** Flags accounts with repeated logins from external IPs, potentially indicating compromised credentials. Results display accounts, IPs, and login counts.

#### Query Option 2: Detect Anomalous Process Execution

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains_any ("powershell", "cmd", "wscript") and ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```
{% endcode %}

**Description:** Identifies encoded or obfuscated commands executed via common scripting tools. Results display command details and associated devices.

#### Query Option 3: Monitor Unusual Network Connections

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and BytesSent > 5000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Tracks devices with large outbound data transfers to public IPs. Results include device and destination IP details.

***

### 2. **Privilege Escalation Indicators**

#### Query Option 1: Track Abnormal Use of Admin Tools

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in ("psexec.exe", "wmic.exe", "taskmgr.exe")
| summarize ToolUsageCount = count() by DeviceName, AccountName, FileName
| where ToolUsageCount > 3
| project DeviceName, AccountName, FileName, ToolUsageCount
```

**Description:** Flags excessive use of administrative tools often leveraged for privilege escalation. Results display device and user details.

#### Query Option 2: Detect Suspicious Privilege Elevation Commands

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains_any ("runas", "whoami", "net user")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```

**Description:** Detects commands executed to elevate privileges. Results display command lines, devices, and accounts.

#### Query Option 3: Identify Credential Dumping Attempts

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName == "lsass.exe" and InitiatingProcessFileName in ("procdump.exe", "rundll32.exe")
| project Timestamp, DeviceName, FileName, InitiatingProcessCommandLine
```
{% endcode %}

**Description:** Flags tools attempting to access LSASS for credential dumping. Results highlight devices and initiating processes.

***

### 3. **Persistence Mechanisms**

#### Query Option 1: Detect Registry Key Modifications

{% code overflow="wrap" %}
```kusto
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKeyPath has_any ("Run", "RunOnce", "Services")
| project Timestamp, DeviceName, RegistryKeyPath, RegistryValueName, RegistryValueData
```
{% endcode %}

**Description:** Identifies changes to registry keys often used for persistence. Results include registry paths and modified values.

#### Query Option 2: Monitor Startup Folder Changes

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath contains "Startup" and FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Description:** Detects executables added to startup folders. Results display file details and timestamps.

#### Query Option 3: Identify Scheduled Task Creation

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Description:** Flags commands used to create scheduled tasks. Results include devices and initiating accounts.

***

### 4. **Lateral Movement Detection**

#### Query Option 1: SMB Lateral Movement

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath startswith "\\\\" and FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Description:** Identifies executables accessed on SMB shares, potentially indicating lateral movement. Results include file paths and timestamps.

#### Query Option 2: RDP Session Monitoring

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 3389 and Direction == "Inbound"
| project Timestamp, DeviceName, RemoteIPAddress
```

**Description:** Tracks inbound RDP sessions. Results include devices and remote IPs.

#### Query Option 3: WMI Remote Execution

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains "wmic" and ProcessCommandLine contains "/node:"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```

**Description:** Detects usage of WMI for remote execution. Results display command details and associated accounts.

***

### 5. **Data Exfiltration Indicators**

#### Query Option 1: Monitor Large Data Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 10000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Flags large outbound data transfers. Results highlight devices and destination IPs.

#### Query Option 2: Detect Data Compression Tools

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("7z.exe", "winrar.exe", "tar.exe")
| project Timestamp, DeviceName, ProcessCommandLine
```

**Description:** Identifies the use of compression tools, often used before exfiltration. Results display processes and associated devices.

#### Query Option 3: Identify DNS Tunneling Activity

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol == "DNS" and strlen(RemoteDnsDomain) > 50
| summarize QueryCount = count() by RemoteDnsDomain, DeviceName
| where QueryCount > 100
| project RemoteDnsDomain, DeviceName, QueryCount
```

**Description:** Detects DNS tunneling based on unusual domain names and high query counts. Results display domains and associated devices.

***

### 6. **Incident Response and Containment**

#### Query Option 1: Isolate Compromised Systems

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPAddress in ("<IoC-IP-List>")
| project Timestamp, DeviceName, RemoteIPAddress
```

**Description:** Identifies systems communicating with known malicious IPs, aiding in isolation efforts. Results display affected devices.

#### Query Option 2: Correlate Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents
| where SHA256 in ("<IoC-Hash-List>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with device events. Results include devices, files, and associated hashes.

#### Query Option 3: Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, ProcessCommandLine, RemoteIPAddress, FileName
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a timeline of intrusion activities to provide a comprehensive incident overview. Results display event sequences.

***

### 7. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
