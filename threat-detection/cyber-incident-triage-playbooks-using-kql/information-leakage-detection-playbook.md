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

# Information Leakage Detection Playbook

### Introduction: The Need for Effective Information Leakage Detection Capabilities

Information leakage—whether intentional or accidental—poses a significant risk to organisations, potentially exposing sensitive data such as intellectual property, customer records, financial information, or proprietary business strategies. Cybercriminals, malicious insiders, and negligent employees can all contribute to data leaks, leading to regulatory violations, financial losses, and reputational damage. With the growing adoption of cloud services, remote work, and third-party integrations, the attack surface for data exposure continues to expand, making proactive detection more critical than ever.

Effective information leakage detection capabilities and processes are essential to identifying and mitigating data exposure before it results in security incidents. A robust detection strategy should integrate Data Loss Prevention (DLP) solutions, User and Entity Behavior Analytics (UEBA), anomaly detection, and real-time log monitoring through Security Information and Event Management (SIEM) systems. Additionally, endpoint and network monitoring tools, along with content inspection technologies, can help detect unauthorised data transfers, email exfiltration, or file-sharing anomalies.

To prevent and mitigate information leakage risks, organisations must implement continuous monitoring, risk-based access controls, and automated alerting mechanisms. Security awareness training, data classification policies, and strict access management can further reduce the likelihood of accidental leaks. By strengthening detection capabilities and response processes, businesses can protect sensitive information, ensure regulatory compliance, and safeguard their competitive advantage.

### Table of Contents

1. Initial Detection of Information Leakage
   * Identify Access to Sensitive Files
   * Detect Unusual Data Transfers
   * Analyse Email Activity for Leakage Patterns
2. Compromised Account Indicators
   * Failed Login Attempts to Sensitive Systems
   * Logins from Unusual Locations
   * Suspicious Account Privilege Escalation
3. Data Exfiltration Indicators
   * Detect Large Data Transfers
   * Monitor Uploads to Cloud Storage
   * Identify Anomalous Email Attachments
4. Threat Persistence Indicators
   * Monitor Unauthorised Access Persistence
   * Detect Persistent Email Rules
   * Track Credential Misuse
5. Incident Response and Containment
   * Isolate Affected Accounts and Devices
   * Correlate Indicators of Compromise (IoCs)
   * Incident Timeline Reconstruction
6. Conclusion

***

This playbook provides a comprehensive guide for detecting, analysing, and responding to information leakage compromises across an organisation using KQL queries in Microsoft Defender and Sentinel. Each section includes multiple query options, detailed descriptions, and expected outcomes.

### 1. **Initial Detection of Information Leakage**

#### Query Option 1: Identify Access to Sensitive Files

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileRead", "FileCopied")
| where FolderPath contains_any ("Confidential", "Sensitive", "Restricted")
| summarize FileAccessCount = count() by DeviceName, AccountName, FolderPath
| where FileAccessCount > 5
| project DeviceName, AccountName, FolderPath, FileAccessCount
```

**Description:** Detects access to folders labelled as sensitive or confidential. Results include devices, users, and accessed file paths.

#### Query Option 2: Detect Unusual Data Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 5000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Identifies devices with large outbound data transfers that may indicate exfiltration. Results include devices and destination IPs.

#### Query Option 3: Analyse Email Activity for Leakage Patterns

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where RecipientDomain != "<organization_domain>"
| summarize EmailCount = count() by SenderEmailAddress, RecipientDomain
| where EmailCount > 10
| project SenderEmailAddress, RecipientDomain, EmailCount
```

**Description:** Tracks emails sent to external domains, highlighting potential information leakage. Results include sender and recipient details.

***

### 2. **Compromised Account Indicators**

#### Query Option 1: Failed Login Attempts to Sensitive Systems

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "Failure"
| where ResourceDisplayName contains_any ("Finance", "HR", "IP")
| summarize FailureCount = count() by UserPrincipalName, IPAddress
| where FailureCount > 3
| project UserPrincipalName, IPAddress, FailureCount
```

**Description:** Flags failed login attempts to sensitive systems, possibly indicating brute force or unauthorised access attempts. Results include usernames and IPs.

#### Query Option 2: Logins from Unusual Locations

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where Location != "<expected_location>"
| summarize LoginCount = count() by UserPrincipalName, Location, IPAddress
| where LoginCount > 1
| project UserPrincipalName, Location, IPAddress, LoginCount
```

**Description:** Detects logins from unexpected geolocations. Results include account names, login locations, and associated IPs.

#### Query Option 3: Suspicious Account Privilege Escalation

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine contains "add-admin" or ProcessCommandLine contains "privilege"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
{% endcode %}

**Description:** Identifies privilege escalation commands executed by accounts. Results include device and account details.

***

### 3. **Data Exfiltration Indicators**

#### Query Option 1: Detect Large Data Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 10000000
| summarize TotalBytesSent = sum(BytesSent) by DeviceName, RemoteIPAddress
| where TotalBytesSent > 50000000
| project DeviceName, RemoteIPAddress, TotalBytesSent
```

**Description:** Detects significant outbound data transfers, potentially indicating exfiltration. Results include devices and destination IPs.

#### Query Option 2: Monitor Uploads to Cloud Storage

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteDnsDomain contains_any ("amazonaws.com", "blob.core.windows.net", "googleapis.com")
| summarize UploadVolume = sum(BytesSent) by DeviceName, RemoteDnsDomain
| where UploadVolume > 5000000
| project DeviceName, RemoteDnsDomain, UploadVolume
```
{% endcode %}

**Description:** Tracks uploads to popular cloud storage services. Results highlight devices, domains, and upload sizes.

#### Query Option 3: Identify Anomalous Email Attachments

```kusto
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileType in ("zip", "rar", "tar", "7z")
| summarize AttachmentCount = count() by SenderEmailAddress, FileName
| where AttachmentCount > 3
| project SenderEmailAddress, FileName, AttachmentCount
```

**Description:** Flags emails with suspicious file attachments, often used for data exfiltration. Results display senders and attachment details.

***

### 4. **Threat Persistence Indicators**

#### Query Option 1: Monitor Unauthorised Access Persistence

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "TokenBased" and AccountName != "<authorized_accounts>"
| project Timestamp, DeviceName, AccountName, LogonType
```

**Description:** Detects token-based authentication attempts by unauthorised accounts. Results include account names and devices.

#### Query Option 2: Detect Persistent Email Rules

```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where RuleName contains "auto-forward" or RuleName contains "leak"
| project Timestamp, UserId, RuleName, RecipientDomain
```

**Description:** Identifies persistent email rules set up to forward emails externally. Results include rule details and affected accounts.

#### Query Option 3: Track Credential Misuse

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationMethod == "Token" and UserPrincipalName in ("<sensitive_accounts>")
| project Timestamp, UserPrincipalName, AuthenticationMethod, IPAddress
```
{% endcode %}

**Description:** Flags repeated use of token-based authentications for sensitive accounts, potentially indicating credential abuse. Results include account details and IPs.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Affected Accounts and Devices

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in ("<compromised_accounts>")
| project Timestamp, UserPrincipalName, IPAddress, Location
```

**Description:** Tracks activity from compromised accounts to support isolation efforts. Results assist in mitigating the incident.

#### Query Option 2: Correlate Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceFileEvents, EmailEvents
| where SHA256 in ("<IoC_hashes>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with activities across file, email, and process events. Results highlight impacted devices and files.

#### Query Option 3: Incident Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union EmailEvents, DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, SenderEmailAddress, ProcessCommandLine, RemoteIPAddress
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a comprehensive timeline of events to provide context for the information leakage incident. Results display activity sequences.

***

### 6. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
