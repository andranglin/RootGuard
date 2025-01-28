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

# Playbook: Investigating Social Engineering Detection Using KQL

### Table of Contents

1. Initial Detection of Social Engineering Attempts
   * Identify Suspicious Emails
   * Detect Malicious URL Activity
   * Unusual File Access Following Social Engineering Campaigns
2. Compromised Account Indicators
   * Failed Login Attempts and Account Lockouts
   * Logins from Unusual Locations
   * Unusual Privilege Elevation Attempts
3. Payload Delivery and Execution
   * Malicious Attachments Execution
   * Command and Control Communication Detection
   * Abnormal Process Execution
4. Threat Persistence Indicators
   * Persistent Email Rules Creation
   * OAuth Application Abuse
   * Credential Reuse Patterns
5. Incident Response and Containment
   * Isolate Affected Accounts and Devices
   * Correlate Indicators of Compromise (IoCs)
   * Timeline Reconstruction
6. Conclusion

***

This playbook outlines a structured methodology to detect, analyse, and respond to social engineering compromises using advanced KQL queries within Microsoft Defender and Sentinel. Each section provides multiple query options, detailed descriptions, and expected results.

### 1. **Initial Detection of Social Engineering Attempts**

#### Query Option 1: Identify Suspicious Emails

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where Subject matches regex @"(verify|urgent|important|action required)"
| where SenderDomain endswith ".xyz" or SenderDomain endswith ".ru"
| project Timestamp, SenderEmailAddress, RecipientEmailAddress, Subject, SenderIP
```

**Description:** Detects emails with suspicious subjects or domains that are frequently used in social engineering campaigns. Results provide sender and recipient details.

#### Query Option 2: Detect Malicious URL Activity

```kusto
UrlClickEvents
| where Timestamp > ago(24h)
| where Url contains_any ("bit.ly", "tinyurl.com", "redirect")
| summarize ClickCount = count() by UserId, Url
| where ClickCount > 3
| project UserId, Url, ClickCount
```

**Description:** Tracks users clicking on potentially malicious URLs, indicating interaction with phishing links. Results display users and associated URLs.

#### Query Option 3: Unusual File Access Following Social Engineering Campaigns

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath contains_any ("Finance", "HR", "Sensitive")
| summarize FileAccessCount = count() by DeviceName, AccountName, FolderPath
| where FileAccessCount > 10
| project DeviceName, AccountName, FolderPath, FileAccessCount
```
{% endcode %}

**Description:** Identifies users accessing sensitive files unusually, potentially due to social engineering exploitation. Results include account and device details.

***

### 2. **Compromised Account Indicators**

#### Query Option 1: Failed Login Attempts and Account Lockouts

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "Failure"
| summarize FailureCount = count() by UserPrincipalName, IPAddress
| where FailureCount > 5
| project UserPrincipalName, IPAddress, FailureCount
```

**Description:** Flags accounts with repeated login failures, which may indicate password guessing or credential stuffing. Results include usernames and IPs.

#### Query Option 2: Logins from Unusual Locations

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where Location != "<expected_location>"
| summarize LoginCount = count() by UserPrincipalName, Location, IPAddress
| where LoginCount > 1
| project UserPrincipalName, Location, IPAddress, LoginCount
```
{% endcode %}

**Description:** Detects accounts logging in from unexpected geolocations. Results display user details, login locations, and associated IPs.

#### Query Option 3: Unusual Privilege Elevation Attempts

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains_any ("net user", "whoami", "nltest")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```
{% endcode %}

**Description:** Identifies privilege elevation commands executed by compromised accounts. Results include command details and associated accounts.

***

### 3. **Payload Delivery and Execution**

#### Query Option 1: Malicious Attachments Execution

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where FileType in ("exe", "vbs", "bat") and FileName endswith_any (".exe", ".vbs", ".bat")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
```
{% endcode %}

**Description:** Detects execution of suspicious attachments commonly used in social engineering campaigns. Results display file execution details and associated devices.

#### Query Option 2: Command and Control Communication Detection

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and BytesSent > 50000
| summarize TotalDataSent = sum(BytesSent) by DeviceName, RemoteIPAddress
| where TotalDataSent > 500000
| project DeviceName, RemoteIPAddress, TotalDataSent
```

**Description:** Tracks devices sending significant data to public IPs, potentially indicating command and control traffic. Results include devices and IPs.

#### Query Option 3: Abnormal Process Execution

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ParentFileName in ("outlook.exe", "winword.exe")
| where ProcessCommandLine contains_any ("powershell", "cmd")
| project Timestamp, DeviceName, ParentFileName, ProcessCommandLine
```

**Description:** Identifies processes spawned by email clients or documents that may indicate phishing payload execution. Results display parent processes and commands.

***

### 4. **Threat Persistence Indicators**

#### Query Option 1: Persistent Email Rules Creation

```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where ActionType == "Create" and RuleName contains_any ("auto-forward", "phish")
| project Timestamp, UserId, RuleName, RecipientDomain
```

**Description:** Detects persistent email rules configured to forward messages externally. Results include user accounts and rule details.

#### Query Option 2: OAuth Application Abuse

```kusto
OAuthEvents
| where Timestamp > ago(7d)
| where ApprovalStatus == "Granted" and AppName != "TrustedApp"
| project Timestamp, UserPrincipalName, AppName, AppId, ApprovalStatus
```

**Description:** Identifies unauthorized OAuth applications approved by users. Results display app names and associated accounts.

#### Query Option 3: Credential Reuse Patterns

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationMethod == "Token" and UserPrincipalName in ("<sensitive_accounts>")
| project Timestamp, UserPrincipalName, AuthenticationMethod, IPAddress
```
{% endcode %}

**Description:** Flags repeated use of tokens for sensitive accounts, potentially indicating credential abuse. Results include accounts and IPs.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Affected Accounts and Devices

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in ("<compromised_accounts>")
| project Timestamp, UserPrincipalName, IPAddress, Location
```

**Description:** Tracks recent activity from compromised accounts, aiding in isolation efforts. Results assist in incident containment.

#### Query Option 2: Correlate Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceNetworkEvents, EmailEvents
| where SHA256 in ("<IoC_hashes>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with activities across process, network, and email events. Results highlight affected systems and artifacts.

#### Query Option 3: Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union EmailEvents, DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, SenderEmailAddress, ProcessCommandLine, RemoteIPAddress
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a timeline of social engineering-related activities to provide context and incident analysis. Results display event sequences.

***

### 6. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
