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

# Playbook: Investigating Scam Detection Using KQL

### Table of Contents

1. Initial Detection of Scam Activity
   * Identify Scam Emails
   * Detect Unusual Click Activity on Scam URLs
   * Monitor Unusual Outbound Network Traffic
2. Compromised Account Indicators
   * Login from Unusual Locations
   * Suspicious Email Rule Creation
   * Abnormal Authentication Patterns
3. Financial and Data Theft Indicators
   * Monitor Unusual File Access
   * Detect Outbound Data Transfers
   * Identify Use of Financial Manipulation Tools
4. Threat Persistence
   * Persistent Email Rules
   * OAuth Application Abuse
   * Advanced Indicators of Credential Abuse
5. Incident Response and Containment
   * Isolate Compromised Accounts and Systems
   * Identify Indicators of Compromise (IoCs)
   * Timeline Reconstruction
6. Conclusion

***

This playbook provides a structured approach to detecting and analysing scam compromises within an organisation using Microsoft Defender and Sentinel. Each section includes advanced KQL queries with descriptions and expected results.

### 1. **Initial Detection of Scam Activity**

#### Query Option 1: Identify Scam Emails

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where Subject matches regex @"(urgent|invoice|payment|security alert|verify)"
| where SenderDomain endswith ".xyz" or SenderDomain endswith ".ru"
| project Timestamp, SenderEmailAddress, Subject, RecipientEmailAddress, SenderIP
```

**Description:** Identifies emails with suspicious subjects or domains commonly associated with scams. Results include sender details, recipients, and IP addresses.

#### Query Option 2: Detect Unusual Click Activity on Scam URLs

```kusto
UrlClickEvents
| where Timestamp > ago(24h)
| where Url contains_any ("bit.ly", "tinyurl.com", "ow.ly", "redirect")
| summarize ClickCount = count() by UserId, Url
| where ClickCount > 5
| project UserId, Url, ClickCount
```

**Description:** Detects users clicking on shortened or suspicious URLs multiple times, which may indicate interaction with scam links. Results display users and URLs.

#### Query Option 3: Monitor Unusual Outbound Network Traffic

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and Protocol in ("HTTP", "HTTPS")
| summarize TotalRequests = count() by DeviceName, RemoteIPAddress
| where TotalRequests > 100
| project DeviceName, RemoteIPAddress, TotalRequests
```

**Description:** Monitors devices generating a high volume of outbound requests to public IPs, potentially to scam domains. Results highlight affected devices and IPs.

***

### 2. **Compromised Account Indicators**

#### Query Option 1: Login from Unusual Locations

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where Location != "<expected_location>"
| summarize LoginCount = count() by UserPrincipalName, Location, IPAddress
| where LoginCount > 1
| project UserPrincipalName, Location, IPAddress, LoginCount
```

**Description:** Detects logins from unexpected geolocations. Results include user accounts, locations, and IP addresses.

#### Query Option 2: Suspicious Email Rule Creation

{% code overflow="wrap" %}
```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where ActionType == "Create" and RuleConditions contains "forward" and RecipientDomain != "<organization_domain>"
| project Timestamp, UserId, RuleName, RuleConditions
```
{% endcode %}

**Description:** Flags email forwarding rules to external domains, a common indicator of account compromise. Results display affected users and rule details.

#### Query Option 3: Abnormal Authentication Patterns

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "Failure" and AuthenticationMethod != "ExpectedMethod"
| summarize FailureCount = count() by UserPrincipalName, IPAddress
| where FailureCount > 5
| project UserPrincipalName, IPAddress, FailureCount
```

**Description:** Identifies repeated authentication failures using unexpected methods. Results highlight affected users and associated IPs.

***

### 3. **Financial and Data Theft Indicators**

#### Query Option 1: Monitor Unusual File Access

```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileRead", "FileCopied")
| where FolderPath contains "Finance" or FolderPath contains "Payroll"
| summarize FileAccessCount = count() by DeviceName, UserName
| where FileAccessCount > 10
| project DeviceName, UserName, FileAccessCount
```

**Description:** Tracks high-volume file access in sensitive folders, such as finance or payroll directories. Results display devices and users involved.

#### Query Option 2: Detect Outbound Data Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 5000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Identifies significant outbound data transfers, potentially indicating exfiltration. Results include source devices and destination IPs.

#### Query Option 3: Identify Use of Financial Manipulation Tools

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine contains_any ("macro", "vba", "excel.exe")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```

**Description:** Flags processes that may indicate financial data manipulation. Results include process details and associated accounts.

***

### 4. **Threat Persistence**

#### Query Option 1: Persistent Email Rules

```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where RuleName contains "auto-forward" or RuleName contains "scam"
| project Timestamp, UserId, RuleName, RecipientDomain
```

**Description:** Detects persistent email forwarding rules. Results include rule names and associated accounts.

#### Query Option 2: OAuth Application Abuse

```kusto
OAuthEvents
| where Timestamp > ago(7d)
| where AppName != "TrustedApp" and ApprovalStatus == "Granted"
| project Timestamp, UserPrincipalName, AppName, AppId, ApprovalStatus
```

**Description:** Identifies unauthorized OAuth application approvals. Results include app details and affected accounts.

#### Query Option 3: Advanced Indicators of Credential Abuse

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationDetails contains "Token" and UserPrincipalName in ("<sensitive_accounts>")
| project Timestamp, UserPrincipalName, AuthenticationDetails, IPAddress
```
{% endcode %}

**Description:** Flags token-based authentication for sensitive accounts, potentially indicating abuse. Results include accounts and IPs.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Compromised Accounts and Systems

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in ("<compromised_accounts>")
| project Timestamp, UserPrincipalName, IPAddress, Location
```

**Description:** Tracks recent activity for known compromised accounts. Results help in isolating accounts.

#### Query Option 2: Identify Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceFileEvents, EmailEvents
| where SHA256 in ("<IoC-hashes>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with email, file, and process events. Results display impacted devices and files.

#### Query Option 3: Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union EmailEvents, DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, SenderEmailAddress, ProcessCommandLine, RemoteIPAddress
| order by Timestamp asc
```
{% endcode %}

**Description:** Combines data sources to create a comprehensive timeline of scam-related activities. Results provide a detailed incident overview.

***

### 6. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
