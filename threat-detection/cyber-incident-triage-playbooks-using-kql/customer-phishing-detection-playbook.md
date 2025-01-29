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

# Customer Phishing Detection Playbook

### Introduction: The Need for Effective Customer Phishing Detection Capabilities

Customer phishing attacks pose a significant threat to businesses, targeting customers with fraudulent emails, fake websites, and impersonation schemes designed to steal credentials, financial information, or sensitive personal data. Cybercriminals exploit trust in well-known brands by creating convincing phishing campaigns that mimic legitimate communications, leading to account takeovers, financial fraud, and reputational damage for organisations. As phishing tactics grow more sophisticated—leveraging AI-generated emails, brand spoofing, and advanced social engineering techniques—businesses must implement proactive detection capabilities to protect their customers and brand integrity.

Effective customer phishing detection capabilities and processes are essential for identifying and mitigating phishing campaigns before they cause widespread harm. A robust detection strategy should include brand monitoring, domain spoofing detection, real-time threat intelligence, and machine learning-based anomaly detection to identify fraudulent emails, websites, and social media scams. Security solutions such as DMARC (Domain-based Message Authentication, Reporting & Conformance), AI-driven email filtering, and Security Information and Event Management (SIEM) platforms help enhance visibility into phishing threats targeting customers.

To combat customer phishing effectively, organisations must implement continuous monitoring, automated alerting, and rapid response mechanisms, including takedown services for fraudulent domains. Additionally, proactive customer education and awareness initiatives can help mitigate the risks of phishing scams. By strengthening detection capabilities and response processes, businesses can protect their customers, reduce fraud-related losses, and maintain trust in their brand.

### Table of Contents

1. Initial Detection of Phishing Campaign
   * Identify Suspicious Emails Targeting Customers
   * Detect Malicious URL Activity
   * Analyse Unusual Traffic from Customer Accounts
2. Compromised Customer Account Indicators
   * Failed Login Attempts
   * Unusual Login Patterns
   * Email Forwarding or Auto-Reply Rules
3. Threat Delivery and Payload Analysis
   * Malicious Attachments
   * URL Redirect Chains
   * Advanced Payload Execution Monitoring
4. Threat Persistence
   * Monitoring for Persistent Phishing Rules
   * OAuth Application Exploitation
   * Indicators of Repeated Credential Abuse
5. Incident Response and Containment
   * Isolate Affected Accounts and Devices
   * Correlate Indicators of Compromise (IoCs)
   * Timeline Reconstruction
6. Conclusion

***

This playbook provides a structured approach to detecting and investigating customer phishing compromises within an organisation using KQL queries with Microsoft Defender and Sentinel. Each section contains multiple query options, detailed descriptions, and expected results.

### 1. **Initial Detection of Phishing Campaign**

#### Query Option 1: Identify Suspicious Emails Targeting Customers

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where Subject matches regex @"(verify|update|account|payment|login)"
| where RecipientDomain contains "<customer_domain>"
| project Timestamp, SenderEmailAddress, RecipientEmailAddress, Subject, SenderIP
```

**Description:** Detects phishing emails targeting customers by analysing suspicious subjects and sender details. Results include email headers and sender IPs.

#### Query Option 2: Detect Malicious URL Activity

```kusto
UrlClickEvents
| where Timestamp > ago(24h)
| where Url contains_any ("bit.ly", "tinyurl.com", "redirect", "phish")
| summarize ClickCount = count() by RecipientEmailAddress, Url
| where ClickCount > 3
| project RecipientEmailAddress, Url, ClickCount
```

**Description:** Tracks customers clicking on malicious URLs multiple times. Results include recipient email addresses and associated URLs.

#### Query Option 3: Analyse Unusual Traffic from Customer Accounts

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and Protocol == "HTTP"
| summarize TotalRequests = count() by DeviceName, RemoteIPAddress
| where TotalRequests > 50
| project DeviceName, RemoteIPAddress, TotalRequests
```

**Description:** Identifies devices with high volumes of outbound traffic to public IPs, potentially communicating with phishing infrastructure. Results display affected devices and IPs.

***

### 2. **Compromised Customer Account Indicators**

#### Query Option 1: Failed Login Attempts

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "Failure"
| summarize FailureCount = count() by UserPrincipalName, IPAddress
| where FailureCount > 5
| project UserPrincipalName, IPAddress, FailureCount
```

**Description:** Detects customers with repeated failed login attempts, possibly due to credential stuffing or phishing. Results show usernames and IP addresses.

#### Query Option 2: Unusual Login Patterns

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where Location != "<expected_location>"
| summarize LoginCount = count() by UserPrincipalName, Location, IPAddress
| where LoginCount > 1
| project UserPrincipalName, Location, IPAddress, LoginCount
```

**Description:** Flags logins from unexpected geolocations. Results include account names, locations, and associated IPs.

#### Query Option 3: Email Forwarding or Auto-Reply Rules

{% code overflow="wrap" %}
```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where ActionType == "Create" and RuleConditions contains "forward" and RecipientDomain != "<customer_domain>"
| project Timestamp, UserId, RuleName, RuleConditions
```
{% endcode %}

**Description:** Detects the creation of email rules that forward emails externally, a common indicator of compromised accounts. Results display affected accounts and rule details.

***

### 3. **Threat Delivery and Payload Analysis**

#### Query Option 1: Malicious Attachments

```kusto
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileType in ("exe", "vbs", "js", "bat", "hta")
| summarize AttachmentCount = count() by FileName, SenderEmailAddress
| where AttachmentCount > 1
| project FileName, SenderEmailAddress, AttachmentCount
```

**Description:** Flags suspicious attachments often used in phishing campaigns. Results show filenames and associated senders.

#### Query Option 2: URL Redirect Chains

```kusto
UrlClickEvents
| where Timestamp > ago(24h)
| where Url contains "redirect" or Url contains "login"
| summarize RedirectChain = make_list(Url) by RecipientEmailAddress
| project RecipientEmailAddress, RedirectChain
```

**Description:** Maps URL redirect chains to identify phishing paths. Results include recipient emails and redirect URLs.

#### Query Option 3: Advanced Payload Execution Monitoring

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ParentFileName in ("outlook.exe", "winword.exe") and (CommandLine contains_any ("powershell", "cmd"))
| project Timestamp, DeviceName, CommandLine, ParentFileName
```
{% endcode %}

**Description:** Identifies processes spawned by email clients or documents, indicating possible phishing payload execution. Results display command details and parent processes.

***

### 4. **Threat Persistence**

#### Query Option 1: Monitoring for Persistent Phishing Rules

```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where RuleName contains "forward" or RuleName contains "auto-reply"
| project Timestamp, UserId, RuleName, RecipientDomain
```

**Description:** Detects persistent email rules created in customer accounts. Results include rule details and affected users.

#### Query Option 2: OAuth Application Exploitation

```kusto
OAuthEvents
| where Timestamp > ago(7d)
| where ApprovalStatus == "Granted" and AppName != "TrustedApp"
| project Timestamp, UserPrincipalName, AppName, AppId, ApprovalStatus
```

**Description:** Identifies unauthorized OAuth application approvals. Results include application names and associated accounts.

#### Query Option 3: Indicators of Repeated Credential Abuse

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationMethod == "Token" and UserPrincipalName in ("<sensitive_customer_accounts>")
| project Timestamp, UserPrincipalName, AuthenticationMethod, IPAddress
```
{% endcode %}

**Description:** Flags repeated token-based authentication attempts for sensitive customer accounts. Results include usernames and IPs.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Affected Accounts and Devices

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in ("<compromised_customer_accounts>")
| project Timestamp, UserPrincipalName, IPAddress, Location
```

**Description:** Tracks activity from known compromised accounts. Results assist in isolating accounts.

#### Query Option 2: Correlate Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, EmailEvents, DeviceNetworkEvents
| where SHA256 in ("<IoC_hashes>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with processes, email, and network activities. Results highlight impacted devices and files.

#### Query Option 3: Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union EmailEvents, DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, SenderEmailAddress, CommandLine, RemoteIPAddress
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a timeline of phishing-related activities to provide a comprehensive view of the incident. Results show sequence and context.

***

### 6. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
