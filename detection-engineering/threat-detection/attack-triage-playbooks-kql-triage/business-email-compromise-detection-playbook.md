# Business Email Compromise Detection Playbook

### Introduction: The Need for Effective Business Email Compromise Detection Capabilities

Business Email Compromise (BEC) has become one of the most financially damaging cyber threats, leveraging social engineering, email spoofing, and compromised accounts to manipulate employees, executives, and partners into authorising fraudulent transactions or disclosing sensitive information. Unlike traditional phishing attacks, BEC often lacks obvious malicious payloads, making it difficult to detect with standard security measures. Attackers use tactics such as executive impersonation, vendor invoice fraud, and payroll diversion to bypass security controls and exploit human trust. As these attacks grow more sophisticated, organisations need advanced detection capabilities to mitigate the risks effectively.

Effective BEC detection capabilities and processes are essential to identifying and preventing fraudulent email-based attacks before they result in financial losses or data breaches. A robust detection strategy should integrate AI-powered email security, domain authentication technologies like DMARC (Domain-based Message Authentication, Reporting & Conformance), anomaly-based behaviour monitoring, and real-time threat intelligence. Security solutions such as Security Email Gateways (SEGs), Security Information and Event Management (SIEM) systems, and User and Entity Behavior Analytics (UEBA) enhance visibility into suspicious login activity, email forwarding rule changes, and abnormal communication patterns.

To combat BEC effectively, organisations must implement continuous email monitoring, automated alerting, and employee awareness training programs to recognise social engineering tactics. Strengthening authentication measures, such as multi-factor authentication (MFA) and strict access controls, further reduces the risk of compromise. By enhancing detection capabilities and response processes, businesses can proactively defend against BEC attacks, safeguarding financial assets, sensitive data, and organisational integrity.

### Table of Contents

1. Initial Detection of Business Email Compromise
   * Identify Suspicious Email Activity
   * Detect Unusual Login Behavior
   * Monitor Email Rule Modifications
2. Account Compromise Indicators
   * Failed Login Attempts and Credential Abuse
   * Unauthorised Email Forwarding Rules
   * Unusual Multi-Factor Authentication (MFA) Events
3. Suspicious Financial Transactions
   * Monitor Financial Email Conversations
   * Detect Fraudulent Payment Requests
   * Identify Suspicious Vendor Email Changes
4. Data Exfiltration Indicators
   * Large Volume Email Forwarding
   * Monitor File Attachments with Sensitive Data
   * Detect Unusual Data Transfers to External Recipients
5. Incident Response and Containment
   * Isolate Compromised Accounts
   * Correlate Indicators of Compromise (IoCs)
   * Incident Timeline Reconstruction
6. Conclusion

***

This playbook provides an in-depth approach to detecting, analysing, and responding to Business Email Compromise (BEC) threats across an organisation using Microsoft Defender and Sentinel. Each section includes multiple query options, descriptions, and expected outcomes to aid in effective detection and response.

### 1. **Initial Detection of Business Email Compromise**

#### Query Option 1: Identify Suspicious Email Activity

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(24h)
| where SenderIPAddress in ("<known_malicious_ips>") or SenderDomain in ("<suspect_domains>")
| project Timestamp, SenderEmailAddress, RecipientEmailAddress, Subject, SenderIPAddress
```
{% endcode %}

**Description:** Detects emails sent from known malicious IPs or domains commonly associated with BEC attacks. Results include sender details, recipient addresses, and timestamps.

#### Query Option 2: Detect Unusual Login Behavior

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where Location != "<expected_location>"
| summarize LoginCount = count() by UserPrincipalName, Location, IPAddress
| where LoginCount > 1
| project UserPrincipalName, Location, IPAddress, LoginCount
```

**Description:** Flags user logins from unexpected geolocations, which may indicate compromised accounts. Results display user accounts, login locations, and associated IPs.

#### Query Option 3: Monitor Email Rule Modifications

```kusto
EmailRulesEvents
| where Timestamp > ago(24h)
| where ActionType == "Create" and RuleConditions contains "forward"
| project Timestamp, UserId, RuleName, RuleConditions
```

**Description:** Identifies newly created email forwarding rules, a common tactic used in BEC. Results include rule details and affected users.

***

### 2. **Account Compromise Indicators**

#### Query Option 1: Failed Login Attempts and Credential Abuse

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "Failure"
| summarize FailureCount = count() by UserPrincipalName, IPAddress
| where FailureCount > 5
| project UserPrincipalName, IPAddress, FailureCount
```

**Description:** Detects repeated login failures, which may indicate brute-force or credential stuffing attacks. Results display affected users and associated IPs.

#### Query Option 2: Unauthorised Email Forwarding Rules

```kusto
EmailRulesEvents
| where Timestamp > ago(7d)
| where ActionType == "Create" and RecipientDomain != "<organisation_domain>"
| project Timestamp, UserId, RuleName, RecipientDomain
```

**Description:** Flags unauthorised email forwarding rules to external domains. Results highlight affected users and forwarding details.

#### Query Option 3: Unusual Multi-Factor Authentication (MFA) Events

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationMethod != "ExpectedMethod"
| project Timestamp, UserPrincipalName, AuthenticationMethod, IPAddress
```

**Description:** Identifies suspicious MFA activity, such as new authentication methods added to accounts. Results include affected accounts and authentication types.

***

### 3. **Suspicious Financial Transactions**

#### Query Option 1: Monitor Financial Email Conversations

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where Subject contains_any ("invoice", "payment", "wire transfer")
| project Timestamp, SenderEmailAddress, RecipientEmailAddress, Subject
```

**Description:** Detects emails related to financial transactions, which may indicate potential BEC fraud. Results display email senders, recipients, and subjects.

#### Query Option 2: Detect Fraudulent Payment Requests

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where Subject contains "urgent payment" or Body contains "change payment details"
| project Timestamp, SenderEmailAddress, RecipientEmailAddress, Subject, Body
```

**Description:** Identifies emails requesting urgent or fraudulent payment changes. Results include sender details, recipients, and email content.

#### Query Option 3: Identify Suspicious Vendor Email Changes

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(7d)
| where SenderEmailAddress != "<official_vendor_email>" and Subject contains "invoice"
| project Timestamp, SenderEmailAddress, RecipientEmailAddress, Subject
```
{% endcode %}

**Description:** Flags vendor emails that may have been altered to redirect payments. Results display email addresses and subjects.

***

### 4. **Data Exfiltration Indicators**

#### Query Option 1: Large Volume Email Forwarding

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where RecipientDomain != "<organisation_domain>"
| summarize ForwardedEmails = count() by SenderEmailAddress
| where ForwardedEmails > 50
```

**Description:** Identifies high-volume email forwarding, indicating potential data exfiltration. Results include sender details and forwarding counts.

#### Query Option 2: Monitor File Attachments with Sensitive Data

```kusto
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileType in ("pdf", "xlsx", "csv") and FileSize > 5000000
| project Timestamp, SenderEmailAddress, FileName, FileSize
```

**Description:** Flags large sensitive file attachments sent via email. Results highlight senders and file details.

#### Query Option 3: Detect Unusual Data Transfers to External Recipients

```kusto
EmailEvents
| where Timestamp > ago(24h)
| where RecipientDomain != "<organisation_domain>"
| summarize SentEmails = count() by SenderEmailAddress, RecipientDomain
| where SentEmails > 20
```

**Description:** Monitors excessive email communication with external recipients. Results include sender details and recipient domains.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Compromised Accounts

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in ("<compromised_accounts>")
| project Timestamp, UserPrincipalName, IPAddress, Location
```

**Description:** Tracks activity from compromised accounts, aiding in containment. Results assist in security response efforts.

#### Query Option 2: Correlate Indicators of Compromise (IoCs)

```kusto
union EmailEvents, DeviceProcessEvents, DeviceNetworkEvents
| where SHA256 in ("<IoC_hashes>")
| project Timestamp, DeviceName, FileName, SHA256
```

**Description:** Correlates known IoCs with email, process, and network events. Results highlight affected systems and artifacts.

***

### 6. **Conclusion**

This playbook provides an organised approach to detecting, analysing, and responding to Business Email Compromise threats. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
