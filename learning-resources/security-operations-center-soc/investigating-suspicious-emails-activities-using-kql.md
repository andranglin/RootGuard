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

# Investigating Suspicious Emails Activities Using KQL

Investigating phishing emails using **Kusto Query Language (KQL)** in Microsoft Sentinel and Microsoft Defender XDR. This will involve querying data from various sources, such as email logs, threat intelligence feeds, endpoint telemetry, and more.

### **1. Understand the Data Sources**

Before writing queries, it’s important to know which tables contain relevant data:

* **Email Logs:** `EmailEvents` (from Microsoft 365 Defender or Defender for Office 365).
* **Threat Intelligence:** `ThreatIntelligenceIndicator`.
* **Endpoint Data:** `DeviceEvents`, `DeviceFileEvents,` `DeviceNetworkEvents` (from Defender for Endpoint).
* **Alerts:** `SecurityAlert`.

### **2. Identify Suspicious Emails**

Start by identifying suspicious emails that may indicate phishing attempts. Look for indicators like:

* Emails with malicious attachments or links.
* Emails sent from suspicious domains or IP addresses.
* Emails flagged by Microsoft Defender for Office 365.

**Example Query: Find Emails with Malicious Attachments**

{% code overflow="wrap" %}
```kusto
EmailEvents
| where ThreatTypes has "Malware" or ThreatTypes has "Phish"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, AttachmentCount, UrlCount, EmailAction, ThreatNames
| sort by Timestamp desc
```
{% endcode %}

**Example Query: Emails from External Domains**

{% code overflow="wrap" %}
```kusto
EmailEvents
| where SenderFromDomain !endswith ".com" and SenderFromDomain !endswith ".net"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, SenderFromDomain, UrlCount, EmailAction
| sort by Timestamp desc
```
{% endcode %}

#### **Example Query: Find Emails from Suspicious Senders**

{% code overflow="wrap" %}
```kusto
EmailEvents
| where SenderFromAddress contains "phishingdomain.com"
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, InternetMessageId
| sort by Timestamp desc
```
{% endcode %}

**Example Query: Find Emails with Malicious Attachments**

{% code overflow="wrap" %}
```kusto
EmailAttachmentInfo
| where FileType == "exe" or FileType == "zip" or FileType == "js"
| join kind=inner (EmailEvents) on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256
| sort by Timestamp desc
```
{% endcode %}

**Example Query:** **Find Emails with Suspicious URLs**

{% code overflow="wrap" %}
```kusto
EmailUrlInfo
| where Url contains "login" or Url contains "password"
| join kind=inner (EmailEvents) on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, Url
| sort by Timestamp desc
```
{% endcode %}

**Example Query: Correlate Phishing Alerts with Email Data**

{% code overflow="wrap" %}
```kusto
Alert
| where AlertName contains "Phish"
| join kind=inner (EmailEvents) on $left.AlertId == $right.NetworkMessageId
| project Timestamp, AlertName, Subject, SenderFromAddress, RecipientEmailAddress, InternetMessageId
| sort by Timestamp desc
```
{% endcode %}

**Example Query: Investigate User Activity Post-Phishing**

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailAction == "Click" or EmailAction == "Open"
| join kind=inner (EmailUrlInfo) on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, Url, EmailAction
| sort by Timestamp desc
```
{% endcode %}

### **3. Correlate with Threat Intelligence**

Check if the sender's domain or IP address matches known malicious indicators from threat intelligence feeds.

**Example Query: Match Email Senders with Threat Intelligence**

{% code overflow="wrap" %}
```kusto
EmailEvents
| join kind=inner (
    ThreatIntelligenceIndicator
    | where IndicatorType == "domain" or IndicatorType == "url"
) on $left.SenderFromDomain == $right.IndicatorValue
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, IndicatorValue, Description
| sort by Timestamp desc
```
{% endcode %}

### **4. Investigate Clicked Links**

If users clicked on links in phishing emails, investigate the URLs they visited.

**Example Query: Find Clicked URLs**

{% code overflow="wrap" %}
```kusto
EmailUrlInfo
| where ActionType == "Clicked"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Url, UrlChain
| sort by Timestamp desc
```
{% endcode %}

**Example Query: Check URL Reputation**

{% code overflow="wrap" %}
```kusto
EmailUrlInfo
| join kind=inner (
    ThreatIntelligenceIndicator
    | where IndicatorType == "url"
) on $left.Url == $right.IndicatorValue
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Url, IndicatorValue, Description
| sort by Timestamp desc
```
{% endcode %}

### **5. Analyse Endpoint Activity**

If a user downloaded a malicious attachment or visited a malicious link, check for suspicious activity on their device.

**Example Query: File Execution After Email Delivery**

{% code overflow="wrap" %}
```kusto
EmailAttachmentInfo
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileCreated"
) on $left.SHA256 == $right.SHA256
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, SHA256, DeviceName
| sort by Timestamp desc
```
{% endcode %}

**Example Query: Network Connections After Email Click**

{% code overflow="wrap" %}
```kusto
EmailUrlInfo
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteUrl contains "malicious-domain.com"
) on $left.RecipientEmailAddress == $right.AccountUpn
| project Timestamp, RecipientEmailAddress, RemoteUrl, RemoteIP, DeviceName
| sort by Timestamp desc
```
{% endcode %}

### **6. Review Security Alerts**

Look for alerts generated by Microsoft Defender for Office 365 or Defender for Endpoint related to phishing.

**Example Query: Phishing Alerts**

{% code overflow="wrap" %}
```kusto
AlertInfo
| where Title contains "phish" or Title contains "suspicious email"
| project TimeGenerated, Title, Severity, AttackTechniques, Category, AlertId, DetectionSource
| sort by TimeGenerated desc
```
{% endcode %}

### **7. Visualise and Summarise Findings**

Use KQL to summarise and visualise your findings for reporting or further analysis.

**Example Query: Count of Phishing Emails by Sender Domain**

```kusto
EmailEvents
| where ThreatTypes has "Phish"
| summarize PhishingEmailCount = count() by SenderFromDomain
| sort by PhishingEmailCount desc
| render columnchart
```

**Example Query: Top Recipients of Phishing Emails**

```kusto
EmailEvents
| where ThreatTypes has "Phish"
| summarize PhishingEmailCount = count() by RecipientEmailAddress
| sort by PhishingEmailCount desc
| render piechart
```

### **8. Automate Investigation**

To streamline investigations, consider creating:

* **Hunting Queries**: Save frequently used queries in Sentinel for quick access.
* **Playbooks**: Use Azure Logic Apps to automate responses, such as blocking malicious domains or notifying affected users.

### **Key Tips**

* **Filter Noise**: Use filters like `where` clauses to narrow down results and focus on high-priority events.
* **Time Range**: Specify a time range (`| where TimeGenerated > ago(7d)`) to limit the scope of your queries.
* **Collaboration**: Share findings with your security team using workbooks or dashboards in Sentinel.
