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

# Playbook: Investigating Insider Abuse Detection Using KQL

### Table of Contents

1. Initial Detection of Insider Abuse
   * Monitor Unusual File Access
   * Detect Suspicious Privileged Account Activity
   * Identify Abnormal Login Patterns
2. Sensitive Data Access and Exfiltration
   * Detect Large File Transfers
   * Monitor Cloud Storage Uploads
   * Identify Potential Data Exfiltration via Email
3. Privilege Escalation Indicators
   * Track Unusual Process Execution
   * Detect Privilege Escalation Attempts
   * Identify Abnormal Use of Admin Tools
4. Persistent Abuse Indicators
   * Monitor for Unauthorised Access Persistence
   * Detect Persistent Privileged User Accounts
   * Advanced Credential Abuse Analysis
5. Incident Response and Containment
   * Isolate Malicious Insider Activity
   * Correlate Indicators of Compromise (IoCs)
   * Timeline Reconstruction
6. Conclusion

***

This playbook outlines advanced techniques for detecting and analysing insider abuse across an organisation using KQL queries for Microsoft Defender and Sentinel. Each section provides multiple query options, detailed descriptions, and expected outcomes.

### 1. **Initial Detection of Insider Abuse**

#### Query Option 1: Monitor Unusual File Access

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileRead", "FileCopied", "FileDeleted")
| where FolderPath contains "Sensitive" or FolderPath contains "Confidential"
| summarize FileAccessCount = count() by DeviceName, AccountName, FolderPath
| where FileAccessCount > 10
| project DeviceName, AccountName, FolderPath, FileAccessCount
```

**Description:** Identifies unusual access to sensitive or confidential file locations. Results display user accounts, devices, and accessed file paths.

#### Query Option 2: Detect Suspicious Privileged Account Activity

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName endswith "<privileged_domain>"
| summarize LoginCount = count() by UserPrincipalName, IPAddress
| where LoginCount > 5
| project UserPrincipalName, IPAddress, LoginCount
```

**Description:** Tracks privileged accounts with repeated logins from the same IP, potentially indicating abuse. Results highlight accounts and IPs.

#### Query Option 3: Identify Abnormal Login Patterns

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where Location != "<expected_location>"
| summarize LoginCount = count() by UserPrincipalName, Location, IPAddress
| where LoginCount > 1
| project UserPrincipalName, Location, IPAddress, LoginCount
```

**Description:** Detects logins from unexpected geolocations. Results include user accounts, login locations, and IP addresses.

***

### 2. **Sensitive Data Access and Exfiltration**

#### Query Option 1: Detect Large File Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 10000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Flags large outbound data transfers that could indicate data exfiltration. Results display devices and remote IPs.

#### Query Option 2: Monitor Cloud Storage Uploads

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteDnsDomain contains_any ("amazonaws.com", "blob.core.windows.net", "googleapis.com")
| summarize TotalBytesSent = sum(BytesSent) by DeviceName, RemoteDnsDomain
| where TotalBytesSent > 5000000
| project DeviceName, RemoteDnsDomain, TotalBytesSent
```
{% endcode %}

**Description:** Tracks significant data uploads to cloud storage services. Results highlight devices, domains, and data volumes.

#### Query Option 3: Identify Potential Data Exfiltration via Email

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(24h)
| where RecipientDomain != "<organization_domain>" and SenderEmailAddress contains "<sensitive_keywords>"
| summarize EmailCount = count() by SenderEmailAddress, RecipientDomain
| where EmailCount > 5
| project SenderEmailAddress, RecipientDomain, EmailCount
```
{% endcode %}

**Description:** Detects emails sent to external domains with sensitive keywords, indicating potential exfiltration. Results include sender and recipient details.

***

### 3. **Privilege Escalation Indicators**

#### Query Option 1: Track Unusual Process Execution

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains_any ("whoami", "net user", "nltest")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```
{% endcode %}

**Description:** Flags commands commonly used to enumerate accounts and privileges. Results include the device and account executing the commands.

#### Query Option 2: Detect Privilege Escalation Attempts

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(\\bexploit\\b|\\belevate\\b|\\bprivilege\\b)"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```
{% endcode %}

**Description:** Identifies commands potentially used for privilege escalation. Results highlight timestamps, accounts, and associated devices.

#### Query Option 3: Identify Abnormal Use of Admin Tools

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in ("psexec.exe", "wmic.exe")
| summarize ToolUsageCount = count() by DeviceName, AccountName, FileName
| where ToolUsageCount > 3
| project DeviceName, AccountName, FileName, ToolUsageCount
```

**Description:** Tracks the use of administrative tools often leveraged for abuse. Results display devices and users.

***

### 4. **Persistent Abuse Indicators**

#### Query Option 1: Monitor for Unauthorized Access Persistence

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "TokenBased" and AccountName != "<authorized_accounts>"
| project Timestamp, DeviceName, AccountName, LogonType
```

**Description:** Detects persistent access via token-based authentication for unauthorized accounts. Results include accounts and devices.

#### Query Option 2: Detect Persistent Privileged User Accounts

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName endswith "<privileged_domain>"
| summarize PersistentLogins = count() by UserPrincipalName
| where PersistentLogins > 10
| project UserPrincipalName, PersistentLogins
```

**Description:** Flags privileged accounts with unusually high login activity. Results display account names and login counts.

#### Query Option 3: Advanced Credential Abuse Analysis

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationMethod contains "Token" and UserPrincipalName in ("<sensitive_accounts>")
| project Timestamp, UserPrincipalName, AuthenticationMethod, IPAddress
```
{% endcode %}

**Description:** Identifies repeated token-based authentications for sensitive accounts. Results include usernames and IPs.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Malicious Insider Activity

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in ("<compromised_accounts>")
| project Timestamp, UserPrincipalName, IPAddress, Location
```
{% endcode %}

**Description:** Tracks recent activity for compromised accounts. Results assist in isolating the insider's activity.

#### Query Option 2: Correlate Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents
| where SHA256 in ("<IoC_hashes>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with device activities. Results display impacted devices and file details.

#### Query Option 3: Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, ProcessCommandLine, RemoteIPAddress, FileName
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a timeline of insider activities to provide a comprehensive view of the incident. Results show sequence and context.

***

### 6. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
