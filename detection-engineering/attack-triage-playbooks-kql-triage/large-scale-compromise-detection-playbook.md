# Large-Scale Compromise Detection Playbook

### Introduction: The Need for Effective Large-Scale Compromise Detection Capabilities

In today’s interconnected digital landscape, organisations face an increasing risk of large-scale cyber compromises, ranging from nation-state attacks and ransomware campaigns to supply chain breaches and widespread credential theft. Threat actors employ advanced techniques such as coordinated lateral movement, fileless malware, and privilege escalation to infiltrate and persist within enterprise environments undetected. Given the complexity and scale of modern IT ecosystems—including cloud, hybrid, and on-premises infrastructures—detecting such compromises requires a proactive and multilayered approach.

Effective detection capabilities and processes for large-scale compromises are essential to identifying, analysing, and mitigating security threats before they result in catastrophic data breaches or operational disruptions. A comprehensive detection strategy must incorporate real-time network monitoring, behavioural analytics, anomaly detection, threat intelligence integration, and automation-driven response mechanisms. Security Information and Event Management (SIEM), Extended Detection and Response (XDR), and threat-hunting frameworks play a crucial role in correlating signals across endpoints, networks, and identities to uncover signs of compromise at scale.

To minimise dwell time and reduce the impact of widespread attacks, organisations must implement continuous monitoring, forensic analysis, and adaptive detection methodologies. By leveraging machine learning, automation, and human-driven threat-hunting, security teams can enhance their ability to detect and respond to large-scale compromises effectively, strengthening their overall cyber resilience in an evolving threat landscape.

### Table of Contents

1. Initial Detection and Scoping
   * Identify Compromised Hosts
   * Detect Unusual Authentication Activity
   * Advanced Network Traffic Analysis
2. Threat Persistence Mechanisms
   * Registry Key Persistence
   * Scheduled Task Creation
   * Startup Folder Monitoring
3. Privilege Escalation Indicators
   * Detect Abnormal Process Behavior
   * Credential Dumping Activities
   * Privilege Escalation via Exploits
4. Lateral Movement
   * Remote Desktop Protocol (RDP) Activity
   * Lateral Movement via SMB Shares
   * SSH Lateral Movement
5. Data Exfiltration Detection
   * Monitor Large Data Transfers
   * Anomalous Cloud Storage Access
   * DNS Tunneling Detection
6. Incident Response and Containment
   * Isolate Compromised Systems
   * Identify Indicators of Compromise (IoCs)
   * Timeline Reconstruction
7. Conclusion

***

This playbook provides KQL queries and techniques to detect and analyse large-scale compromises across uan organisation. Each section includes multiple query options with detailed descriptions and expected outcomes.

### 1. **Initial Detection and Scoping**

#### Query Option 1: Identify Compromised Hosts

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonStatus != "Success"
| summarize FailureCount = count() by DeviceName, AccountName, RemoteIP
| where FailureCount > 50
| project DeviceName, AccountName, RemoteIP, FailureCount
```

**Description:** Detects hosts with repeated failed login attempts, indicative of brute force attacks. Results include device names, accounts, and source IPs.

#### Query Option 2: Detect Unusual Authentication Activity

{% code overflow="wrap" %}
```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Network" and IsExternalIP == true
| summarize SuccessfulLogons = count() by AccountName, RemoteIP
| where SuccessfulLogons > 10
| project AccountName, RemoteIP, SuccessfulLogons
```
{% endcode %}

**Description:** Flags accounts with high numbers of successful logons from external IPs, which may indicate credential compromise. Results display accounts and associated IPs.

#### Query Option 3: Advanced Network Traffic Analysis

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and BytesSent > 1000000
| summarize TotalBytesSent = sum(BytesSent) by DeviceName, RemoteIPAddress
| where TotalBytesSent > 10000000
| project DeviceName, RemoteIPAddress, TotalBytesSent
```

**Description:** Identifies devices sending large amounts of data to public IPs, potentially indicative of exfiltration. Results show devices, IPs, and data volumes.

***

### 2. **Threat Persistence Mechanisms**

#### Query Option 1: Registry Key Persistence

```kusto
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKeyPath has_any ("Run", "RunOnce", "CurrentVersion\\Policies")
| project Timestamp, DeviceName, RegistryKeyPath, RegistryValueData
```

**Description:** Detects modifications to registry keys often used for persistence. Results include key paths and modified values.

#### Query Option 2: Scheduled Task Creation

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Description:** Identifies commands used to create scheduled tasks. Results include devices and associated accounts.

#### Query Option 3: Startup Folder Monitoring

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath contains "Startup" and FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Description:** Flags executables added to startup folders. Results include file paths and timestamps.

***

### 3. **Privilege Escalation Indicators**

#### Query Option 1: Detect Abnormal Process Behavior

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains_any ("whoami", "net user", "nltest")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```

**Description:** Searches for commands used to enumerate accounts and privileges. Results include command lines and initiating accounts.

#### Query Option 2: Credential Dumping Activities

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in ("procdump.exe", "lsass.exe") and ProcessCommandLine contains "-ma"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```
{% endcode %}

**Description:** Detects attempts to dump credentials from LSASS. Results show processes and associated devices.

#### Query Option 3: Privilege Escalation via Exploits

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(\\bexploit\\b|\\belevate\\b|\\bprivilege\\b)"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```
{% endcode %}

**Description:** Flags potential exploitation activities. Results display timestamps, commands, and associated accounts.

***

### 4. **Lateral Movement**

#### Query Option 1: Remote Desktop Protocol (RDP) Activity

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 3389 and RemoteIPType == "Private"
| project Timestamp, DeviceName, RemoteIPAddress
```

**Description:** Tracks RDP connections within the environment. Results include devices and remote IPs.

#### Query Option 2: Lateral Movement via SMB Shares

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath startswith "\\\\" and FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName
```

**Description:** Identifies executable files accessed on SMB shares. Results display file paths and timestamps.

#### Query Option 3: SSH Lateral Movement

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Network" and ProcessName == "ssh"
| project Timestamp, DeviceName, AccountName, RemoteIPAddress
```

**Description:** Flags SSH-based lateral movement. Results include accounts and associated devices.

***

### 5. **Data Exfiltration Detection**

#### Query Option 1: Monitor Large Data Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 10000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Detects significant data transfers. Results include source devices and data volumes.

#### Query Option 2: Anomalous Cloud Storage Access

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

#### Query Option 3: DNS Tunneling Detection

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol == "DNS" and strlen(RemoteDnsDomain) > 50
| summarize QueryCount = count() by RemoteDnsDomain
| where QueryCount > 100
| project RemoteDnsDomain, QueryCount
```

**Description:** Detects DNS tunneling based on query patterns. Results include domain names and query counts.

***

### 6. **Incident Response and Containment**

#### Query Option 1: Isolate Compromised Systems

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPAddress in ("<IoC-IP-List>")
| project Timestamp, DeviceName, RemoteIPAddress
```

**Description:** Identifies devices communicating with known malicious IPs. Results assist in system isolation efforts.

#### Query Option 2: Identify Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceFileEvents
| where SHA256 in ("<IoC-Hash-List>")
| project Timestamp, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs (hashes) with process and file events. Results display impacted devices and files.

#### Query Option 3: Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, ProcessCommandLine, RemoteIPAddress, FileName
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a timeline of activities during the incident. Results provide a comprehensive incident overview.

***

### 7. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
