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

# Linux Intrusion Detection Playbook

### Introduction: The Need for Effective Linux Intrusion Detection Capabilities

Linux systems are a fundamental part of enterprise infrastructure, powering cloud environments, servers, and critical applications. As their adoption increases, so do the threats targeting them, ranging from privilege escalation and unauthorised access to rootkits, fileless malware, and advanced persistent threats (APTs). Attackers often leverage stealthy techniques such as living-off-the-land (LotL) tactics, kernel-level exploits, and misconfiguration abuse to evade detection, making traditional security approaches insufficient for Linux environments.

Effective Linux intrusion detection capabilities and processes are essential for identifying, analysing, and mitigating security threats before they escalate into full-scale incidents. A robust detection strategy should combine real-time system monitoring, anomaly-based detection, log analysis, behavioural analytics, and integration with Security Information and Event Management (SIEM) solutions. Additionally, leveraging Endpoint Detection and Response (EDR), host-based intrusion detection systems (HIDS), and proactive threat-hunting methodologies enhances visibility into suspicious activities.

To stay ahead of adversaries, security teams must implement continuous monitoring, automated alerting, and forensic investigation processes tailored to Linux environments. By establishing a well-defined intrusion detection framework, organisations can improve their security resilience, minimise attack dwell time, and protect critical assets from evolving cyber threats.

### Table of Contents

1. Initial Compromise Detection
   * Detect Suspicious Processes
   * Identify Exploited Services
   * Advanced Suspicious Command Detection
2. Persistence Mechanisms
   * Detect Cronjob Modifications
   * Monitor SSH Key Additions
   * Advanced Persistence Detection via Startup Scripts
3. Privilege Escalation and Credential Theft
   * Detect Sudo Abuse
   * Credential Dumping Attempts
   * Advanced Kernel Exploit Detection
4. Lateral Movement Detection
   * Detect SSH Lateral Movement
   * Monitor File Transfers via SCP or Rsync
5.
   * Monitor File Transfers via SCP or Rsync
   * Advanced Detection of Exploited Protocols
6. Data Exfiltration Indicators
   * Large Data Transfers via Network
   * Use of Compression Tools
   * DNS or HTTPS Exfiltration
7. Post-Incident Investigation
   * Correlation of File Hashes
   * Compromised User Accounts
   * Incident Timeline Reconstruction
8. Conclusion

***

This playbook provides a structured approach to investigating Linux-based intrusions in an enterprise environment. Each section focuses on specific detection and analysis phases using advanced queries and techniques.

### 1. **Initial Compromise Detection**

The first step is identifying the initial point of compromise, often involving malicious processes or exploited services.

#### Query Option 1: Detect Suspicious Processes

```kusto
SyslogEvent
| where TimeGenerated > ago(24h)
| where ProcessName != "" and (CPUUsage > 20 or MemoryUsage > 20)
| project TimeGenerated, HostName, ProcessName, CommandLine, CPUUsage, MemoryUsage
```

**Description:** Detects processes with unusually high CPU or memory usage. Results include timestamps, hostnames, and resource utilization details.

#### Query Option 2: Identify Exploited Services

```kusto
SyslogEvent
| where TimeGenerated > ago(24h)
| where Port in (22, 80, 443) and Status == "Listening"
| project TimeGenerated, HostName, Port, ProcessName, CommandLine
```

**Description:** Identifies active listening services on common ports (SSH, HTTP, HTTPS). Results include process details and ports.

#### Query Option 3: Advanced Suspicious Command Detection

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where CommandLine contains_any ("sudo", "wget", "curl", "base64", "nc", "ncat")
| project TimeGenerated, HostName, UserName, CommandLine
```

**Description:** Searches for potentially malicious commands executed in the shell. Results include timestamps, users, and command details.

***

### 2. **Persistence Mechanisms**

Attackers often use persistence techniques to maintain access.

#### Query Option 1: Detect Cronjob Modifications

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where ProcessName == "cron" and CommandLine contains "edit"
| project TimeGenerated, HostName, UserName, CommandLine
```

**Description:** Tracks cronjob modifications. Results show command-line entries associated with cron edits.

#### Query Option 2: Monitor SSH Key Additions

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where FilePath endswith "authorized_keys" and ActionType == "FileModified"
| project TimeGenerated, HostName, UserName, FilePath
```

**Description:** Identifies modifications to SSH authorized\_keys files. Results display timestamps, hosts, and file paths.

#### Query Option 3: Advanced Persistence Detection via Startup Scripts

{% code overflow="wrap" %}
```kusto
SyslogEvent
| where TimeGenerated > ago(30d)
| where FilePath startswith "/etc/systemd/system" or FilePath startswith "/etc/init.d"
| where ActionType == "FileCreated" or ActionType == "FileModified"
| project TimeGenerated, HostName, FilePath, UserName
```
{% endcode %}

**Description:** Detects changes in startup scripts, which may indicate persistence. Results show modified or created files.

***

### 3. **Privilege Escalation and Credential Theft**

Detecting privilege escalation and credential theft attempts is crucial to mitigating further damage.

#### Query Option 1: Detect Sudo Abuse

{% code overflow="wrap" %}
```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where CommandLine contains "sudo" and CommandLine contains "COMMAND"
| project TimeGenerated, HostName, UserName, CommandLine
```
{% endcode %}

**Description:** Identifies sudo command usage. Results include command details, users, and timestamps.

#### Query Option 2: Credential Dumping Attempts

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where CommandLine contains_any ("hashcat", "john", "pwdump")
| project TimeGenerated, HostName, UserName, CommandLine
```

**Description:** Detects potential credential dumping attempts. Results display commands executed by users.

#### Query Option 3: Advanced Kernel Exploit Detection

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where Message contains_any ("segfault", "exploit", "kernel panic")
| project TimeGenerated, HostName, Message
```

**Description:** Analyzes kernel logs for signs of exploit attempts. Results provide timestamps and messages.

***

### 4. **Lateral Movement Detection**

Attackers often spread across the network after the initial compromise.

#### Query Option 1: Detect SSH Lateral Movement

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where ProcessName == "ssh" and CommandLine contains "Accepted publickey"
| project TimeGenerated, HostName, UserName, SourceIP, DestinationIP
```

**Description:** Identifies SSH public key logins. Results include source and destination IPs.

#### Query Option 2: Monitor File Transfers via SCP or Rsync

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where CommandLine contains_any ("scp", "rsync")
| project TimeGenerated, HostName, UserName, CommandLine
```

**Description:** Tracks file transfer activities. Results display commands and associated users.

#### Query Option 3: Advanced Detection of Exploited Protocols

```kusto
NetworkEvent
| where TimeGenerated > ago(7d)
| where RemotePort in (22, 111) and BytesSent > 1000000
| project TimeGenerated, HostName, RemoteIPAddress, RemotePort, BytesSent
```

**Description:** Monitors network traffic on commonly exploited protocols. Results highlight large data transfers.

***

### 5. **Data Exfiltration Indicators**

Signs of data exfiltration should be promptly identified to mitigate loss.

#### Query Option 1: Large Data Transfers via Network

```kusto
NetworkEvent
| where TimeGenerated > ago(7d)
| where Direction == "Outbound" and BytesSent > 5000000
| project TimeGenerated, HostName, RemoteIPAddress, BytesSent
```

**Description:** Identifies large outbound data transfers. Results display destinations and transfer sizes.

#### Query Option 2: Use of Compression Tools

```kusto
SyslogEvent
| where TimeGenerated > ago(7d)
| where CommandLine contains_any ("tar", "gzip", "7z")
| project TimeGenerated, HostName, UserName, CommandLine
```

**Description:** Detects the use of compression tools, often a precursor to exfiltration. Results show commands and users.

#### Query Option 3: DNS or HTTPS Exfiltration

```kusto
NetworkEvent
| where TimeGenerated > ago(7d)
| where Protocol in ("DNS", "HTTPS") and strlen(RemoteDnsDomain) > 50
| project TimeGenerated, HostName, RemoteDnsDomain, BytesSent
```

**Description:** Monitors DNS and HTTPS traffic for anomalies. Results display domain names and data volumes.

***

### 6. **Post-Incident Investigation**

Once the threat is contained, further investigation can determine the scope and impact.

#### Query Option 1: Correlation of File Hashes

```kusto
FileEvent
| where TimeGenerated > ago(30d)
| where SHA256 in ("<known-malicious-hash-1>", "<known-malicious-hash-2>")
| project TimeGenerated, HostName, FilePath, SHA256
```

**Description:** Compares file hashes with known malicious hashes. Results include file paths and matching hashes.

#### Query Option 2: Compromised User Accounts

```kusto
SyslogEvent
| where TimeGenerated > ago(30d)
| where Message contains "Invalid user"
| project TimeGenerated, HostName, UserName, SourceIP
```

**Description:** Tracks invalid login attempts targeting non-existent users. Results include usernames and source IPs.

#### Query Option 3: Incident Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union SyslogEvent, FileEvent, NetworkEvent
| where TimeGenerated > ago(30d)
| project TimeGenerated, EventType = $table, HostName, CommandLine, FilePath, RemoteIPAddress
| order by TimeGenerated asc
```
{% endcode %}

**Description:** Combines multiple data sources to reconstruct an incident timeline. Results provide a comprehensive view of activities.

***

### Conclusion

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
