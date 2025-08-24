# Phishing Email Compromise Detection Playbook

### Introduction: The Need for Effective Phishing Email Compromise Detection Capabilities

Phishing remains one of the most prevalent and effective attack vectors used by cybercriminals to gain unauthorised access to enterprise environments. Attackers continuously refine their tactics, leveraging social engineering, credential harvesting, business email compromise (BEC), and malicious attachments or links to bypass traditional security controls. As email remains the primary communication tool for businesses, detecting phishing-based compromises is critical to preventing account takeovers, financial fraud, and data breaches.

Effective phishing email compromise detection capabilities and processes are essential to identifying and mitigating threats before they lead to widespread organisational impact. A robust detection strategy should include advanced email filtering, anomaly detection, behavioural analysis, and integration with threat intelligence feeds to recognise phishing indicators in real-time. Security solutions such as Security Email Gateways (SEGs), Endpoint Detection and Response (EDR), and Security Information and Event Management (SIEM) platforms enhance visibility into suspicious email activities, including unauthorised logins, unusual email forwarding rules, and abnormal communication patterns.

To combat phishing threats effectively, organisations must adopt a multi-layered defence approach that includes continuous monitoring, automated alerting, and user awareness training. By strengthening detection capabilities and response processes, security teams can proactively identify and neutralise phishing attacks before they escalate into full-scale security incidents, ensuring better protection for users, credentials, and sensitive business assets.

### Table of Contents

1. Initial Detection of Phishing Activity
   * Identify Suspicious Emails
   * Detect Unusual URL Clicks
   * Advanced Network Traffic Analysis
2. Compromised Account Indicators
   * Multiple Login Failures
   * Logins from Unusual Locations
   * Suspicious Email Forwarding Rules
3. Malicious Payload Delivery
   * Identify Malicious Attachments
   * Detect Command Execution from Email Clients
   * Advanced Process Analysis
4. Threat Persistence
   * Unauthorised OAuth Application Approvals
   * Persistent Email Rules
   * Advanced Token Abuse Indicators
5. Incident Response and Containment
   * Isolate Compromised Accounts
   * Identify Indicators of Compromise (IoCs)
   * Incident Timeline Reconstruction
6. Conclusion

***

This playbook provides advanced KQL queries and techniques to assist in detecting and analysing phishing compromises across an enterprise. Each section includes multiple query options with detailed descriptions and expected results.

### 1. **Initial Detection of Phishing Activity**

#### Query Option 1: Identify Suspicious Emails

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(24h)
| where Subject matches regex @"(urgent|password|verify|security|update)" or SenderDomain endswith ".xyz" or ".info"
| project Timestamp, SenderEmailAddress, Subject, RecipientEmailAddress, SenderIP
```
{% endcode %}

**Description:** Detects emails with suspicious subjects or domains commonly associated with phishing. Results include sender details and recipients.

#### Query Option 2: Detect Unusual URL Clicks

```kusto
UrlClickEvents
| where Timestamp > ago(24h)
| where Url contains_any ("bit.ly", "tinyurl.com", "ow.ly", "redirect")
| summarize ClickCount = count() by UserId, Url
| where ClickCount > 5
| project UserId, Url, ClickCount
```

**Description:** Identifies users clicking on potentially malicious shortened URLs multiple times. Results highlight URLs and affected users.

#### Query Option 3: Advanced Network Traffic Analysis

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and Protocol == "HTTP" and Url contains "/login"
| summarize TotalRequests = count() by DeviceName, Url, RemoteIPAddress
| project DeviceName, RemoteIPAddress, Url, TotalRequests
```

**Description:** Flags devices connecting to suspicious login pages. Results include device details, URLs, and request counts.

***

### 2. **Compromised Account Indicators**

#### Query Option 1: Multiple Login Failures

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonStatus != "Success"
| summarize FailureCount = count() by AccountName, DeviceName
| where FailureCount > 10
| project AccountName, DeviceName, FailureCount
```

**Description:** Detects accounts with repeated failed login attempts, indicating brute force or compromised credentials. Results highlight affected accounts.

#### Query Option 2: Logins from Unusual Locations

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where IsExternalIP == true
| summarize LoginCount = count() by AccountName, RemoteIP, GeoLocation
| where LoginCount > 3
| project AccountName, RemoteIP, GeoLocation, LoginCount
```

**Description:** Identifies accounts logging in from external or geographically unusual locations. Results display account details and geolocations.

#### Query Option 3: Suspicious Email Forwarding Rules

{% code overflow="wrap" %}
```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where ActionType == "Create" and RuleConditions contains "forward" and RecipientDomain != "<your_domain>"
| project Timestamp, UserId, RecipientDomain, RuleName, RuleConditions
```
{% endcode %}

**Description:** Flags newly created email forwarding rules to external domains. Results include rule details and affected users.

***

### 3. **Malicious Payload Delivery**

#### Query Option 1: Identify Malicious Attachments

```kusto
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileType in ("exe", "vbs", "js", "bat")
| summarize AttachmentCount = count() by FileName, SenderEmailAddress
| where AttachmentCount > 1
| project FileName, SenderEmailAddress, AttachmentCount
```

**Description:** Detects suspicious file types commonly used in phishing payloads. Results display filenames and sender details.

#### Query Option 2: Detect Command Execution from Email Clients

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ParentFileName contains "outlook.exe" and (CommandLine contains "powershell" or CommandLine contains "cmd")
| project Timestamp, DeviceName, CommandLine, ParentFileName
```
{% endcode %}

**Description:** Identifies processes executed from email clients, potentially indicating payload activation. Results include command details and originating processes.

#### Query Option 3: Advanced Process Analysis

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine matches regex @"(powershell|curl|wget|base64)"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
```
{% endcode %}

**Description:** Flags suspicious commands executed on devices, often associated with phishing payloads. Results display commands and associated accounts.

***

### 4. **Threat Persistence**

#### Query Option 1: Unauthorized OAuth Application Approvals

```kusto
OAuthEvents
| where Timestamp > ago(7d)
| where ApprovalStatus == "Granted" and AppName != "TrustedApp"
| project Timestamp, AccountName, AppName, AppId, ApprovalStatus
```

**Description:** Detects unauthorized OAuth application approvals. Results include app names, account details, and approval statuses.

#### Query Option 2: Persistent Email Rules

```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where ActionType == "Create" and RuleName contains "auto-forward"
| project Timestamp, UserId, RuleName, RecipientDomain
```

**Description:** Identifies persistent forwarding rules created in compromised accounts. Results highlight rule details and associated accounts.

#### Query Option 3: Advanced Token Abuse Indicators

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "TokenBased" and AccountName in ("<sensitive_accounts>")
| project Timestamp, DeviceName, AccountName, LogonType
```

**Description:** Flags token-based logons for sensitive accounts, potentially indicating token abuse. Results include account details and logon types.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Compromised Accounts

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where AccountName in ("<compromised_account_list>")
| project Timestamp, AccountName, DeviceName, RemoteIPAddress
```

**Description:** Identifies recent activity from known compromised accounts. Results assist in containment efforts.

#### Query Option 2: Identify Indicators of Compromise (IoCs)

```kusto
union EmailEvents, DeviceProcessEvents
| where SHA256 in ("<IoC-Hash-List>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with email and process activities. Results highlight impacted systems and files.

#### Query Option 3: Incident Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union EmailEvents, DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, SenderEmailAddress, CommandLine, RemoteIPAddress
| order by Timestamp asc
```
{% endcode %}

**Description:** Combines multiple data sources to reconstruct a timeline of phishing-related activities. Results provide a holistic view of the incident.

***

### 6. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
