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

# Identify and Investigate Phishing Attacks with KQL

To detect potential phishing emails sent to users using KQL in Microsoft Sentinel or Microsoft Defender for Office 365, you can leverage the `EmailEvents` table. Below are some examples that can be used to identify suspicious emails:

#### 1. **Basic Query to Detect Emails with Suspicious Attachments**

Phishing emails often contain malicious attachments. Look for emails with suspicious file extensions.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where AttachmentCount > 0
| mv-expand Attachments
| where isnotempty(Attachments.FileName)
| where Attachments.FileName endswith ".exe" 
    or Attachments.FileName endswith ".scr" 
    or Attachments.FileName endswith ".vbs" 
    or Attachments.FileName endswith ".js" 
    or Attachments.FileName endswith ".bat"
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject, Attachments.FileName
```
{% endcode %}

#### 2. **Detect Emails with Suspicious URLs**

Phishing emails often contain links to malicious websites. Check for emails containing URLs and filters based on known suspicious domains.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where UrlCount > 0
| mv-expand Urls
| where isnotempty(Urls.Url)
| where Urls.Url contains "phishingsite.com" 
    or Urls.Url contains "malicioussite.com"
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject, Urls.Url
```
{% endcode %}

#### 3. **Detect Emails from External Senders with High-Risk Indicators**

Identify emails from external senders with high-risk indicators such as spoofed display names or mismatched sender domains.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where ThreatTypes has "Spoof" or ThreatTypes has "Phish"
| where SenderFromAddress !endswith "yourcompany.com"
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes
```
{% endcode %}

#### 4. **Detect Emails with Spoofed Display Names**

Attackers often spoof display names to make emails appear as though it's from a trusted source. Look for these cases.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where SenderFromAddress !endswith "yourcompany.com"
| where SenderDisplayName != SenderFromAddress
| project TimeReceived, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject
```
{% endcode %}

#### 5. **Detect Emails with High Spam Confidence Level (SCL)**

Microsoft assigns a Spam Confidence Level (SCL) to emails. A higher SCL indicates a higher likelihood of spam or phishing.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where SpamConfidenceLevel >= 5
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject, SpamConfidenceLevel
```
{% endcode %}

#### 6. **Detect Emails with Phishing Keywords in the Subject**

Phishing emails often use specific keywords in the subject line to lure victims. Look for common phishing-related keywords.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where Subject contains "urgent" 
    or Subject contains "password" 
    or Subject contains "verify" 
    or Subject contains "account" 
    or Subject contains "login"
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject
```
{% endcode %}

#### 7. **Detect Emails with Mismatched Sender Domains**

Identify emails where the sender's domain does not match the domain in the email address, which could indicate spoofing.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
| where SenderDomain != "yourcompany.com"
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject, SenderDomain
```
{% endcode %}

#### 8. **Detect Emails with High Volume Sent to Multiple Users**

Phishing campaigns often target multiple users at once. Check for emails sent to a large number of recipients.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| summarize RecipientCount = dcount(RecipientEmailAddress) by SenderFromAddress, Subject
| where RecipientCount > 10
| project SenderFromAddress, Subject, RecipientCount
```
{% endcode %}

#### 9. **Detect Emails with Malware Detected**

Identify emails where malware was detected by Microsoft Defender for Office 365.

{% code overflow="wrap" %}
```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where ThreatTypes has "Malware"
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes
```
{% endcode %}

#### 10. **Detect Emails with Anomalous Sender Behavior**

Look for emails from senders who have never communicated with your organisation before, which could indicate a phishing attempt.

```kusto
EmailEvents
| where EmailDirection == "Inbound"
| where SenderFromAddress !in (
    EmailEvents
    | where EmailDirection == "Outbound"
    | distinct SenderFromAddress
)
| project TimeReceived, SenderFromAddress, RecipientEmailAddress, Subject
```

#### Notes:

* Replace `"yourcompany.com"` with your actual company domain.
* You can adjust the thresholds (e.g., `SpamConfidenceLevel`, `RecipientCount`) based on your organisation's risk tolerance.
* These queries can be further customised based on your organisation's specific needs and threat intelligence.
