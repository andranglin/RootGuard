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

# Gaining Access to the Network

### Introduction

The first phase of the Unified Kill Chain model is **Gaining an Initial Foothold.** The first stage within this phase is the **Gaining Access to the Network**. This stage focuses on how the adversaries infiltrate a target environment to establish unauthorised access. This phase is critical, as it lays the foundation for subsequent stages of an attack, such as lateral movement and data exfiltration. Understanding the tactics and techniques attackers use during this phase is essential for effective threat detection, investigation, and response. The following techniques are commonly employed by attackers to achieve initial access in, for example, a Windows environment:

* **Exploiting Public-Facing Applications**: Attackers often target vulnerabilities in web applications or services exposed to the internet, such as web servers or APIs, to inject malicious code or gain unauthorised access.
* **Phishing**: Malicious emails designed to trick users into clicking on links or opening attachments containing malware remain one of the most prevalent methods for gaining initial access.
* **External Remote Services**: Attackers exploit poorly secured remote access protocols like RDP, VPNs, or SSH to gain a foothold, often using brute force or stolen credentials.
* **Valid Accounts**: Using compromised or stolen credentials, attackers log in as legitimate users to bypass basic security measures.
* **Drive-by Compromise**: By hosting malicious code on compromised or rogue websites, attackers trick users into downloading malware during regular browsing.
* **Supply Chain Compromise**: Adversaries infiltrate third-party vendors or software providers to distribute malware through legitimate software updates or packages.
* **Trusted Relationships**: Exploiting relationships with trusted third-party vendors or partners to gain access to internal systems.
* **Replication Through Removable Media**: The use of infected USB drives or other removable media to deliver malicious payloads when connected to the target system.

By applying the **Unified Kill Chain model**, investigators can systematically analyse the techniques used during this phase, identify relevant indicators of compromise (IOCs), and map the attacker’s behaviour to defensive strategies. This structured approach enhances detection and response efforts, enabling defenders to disrupt adversaries early in the attack lifecycle.

### The following are basic KQL, Velociraptor, and Splunk queries used to investigate these techniques.

KQL (Microsoft Sentinel), Velociraptor VQL, and Splunk SPL to investigate each of the techniques in **Phase 1 – Gaining an Initial Foothold**, along with descriptions of what each query does and multiple query examples for each technique.

### **1. Exploiting Public-Facing Applications**

Attackers often exploit vulnerabilities in public-facing applications, such as web servers or APIs, to gain unauthorised access.

#### **KQL Queries**

{% tabs %}
{% tab title="1. dentify SQL Injection Attempts" %}
**Identify SQL Injection Attempts**

_Description_: Searches for potential SQL injection patterns in application logs, such as "select \*" or explicit "sql injection" alerts.

```kusto
AzureDiagnostics
| where Message contains "sql injection" or Message contains "select *"
| summarize count() by Message, ClientIP, TimeGenerated
```
{% endtab %}

{% tab title="2. Detect Unusual POST Requests" %}
**Detect Unusual POST Requests**

```kusto
AzureDiagnostics
| where Method == "POST" and UrlPath contains ".php"
| summarize count() by ClientIP, UrlPath, TimeGenerated
```

_Description_: Identifies suspicious POST requests targeting `.php` files, often used in web application attacks.
{% endtab %}

{% tab title="3. Monitor Error Messages Suggesting Vulnerabilities" %}
**Monitor Error Messages Suggesting Vulnerabilities**

{% code overflow="wrap" %}
```kusto
AzureDiagnostics
| where Message contains "500 Internal Server Error" or Message contains "unauthorized"
| summarize count() by ClientIP, Message, TimeGenerated
```
{% endcode %}

_Description_: Detects repeated error messages that could indicate exploitation attempts.
{% endtab %}
{% endtabs %}

#### **Velociraptor VQL**

{% tabs %}
{% tab title="1. Search for Command Execution in Logs" %}
```csharp
SELECT * FROM Audit.WindowsEventLogs
WHERE EventID = 4688 AND EventData.CommandLine =~ "cmd.exe /c"
```

_Description_: Identifies suspicious command-line executions that attackers might trigger through exploited applications.
{% endtab %}

{% tab title="2. Detect Web Shell Creation" %}
**Detect Web Shell Creation**

```csharp
SELECT * FROM FileSystem 
WHERE path =~ "C:\\inetpub\\wwwroot\\*.aspx"
```

_Description_: Searches for newly created web shell files in common IIS server directories.
{% endtab %}

{% tab title="3. Identify Abnormal HTTP Traffic" %}
I**dentify Abnormal HTTP Traffic**

{% code overflow="wrap" %}
```csharp
SELECT * FROM Network.HTTP
WHERE UserAgent =~ "sqlmap"
```
{% endcode %}

_Description_: Detects traffic from automated tools like SQLmap, often used for exploitation.
{% endtab %}
{% endtabs %}

#### **Splunk SPL**

{% tabs %}
{% tab title="1. SQL Injection Detection" %}
```splunk-spl
index=web_logs sourcetype=access_combined
| search uri_query="*union*" OR uri_query="*select*" 
| stats count by clientip, uri_query
```

_Description_: Searches for SQL injection attempts by filtering for SQL keywords in URL queries.
{% endtab %}

{% tab title="2. POST Requests with Large Payloads" %}
**POST Requests with Large Payloads**

```splunk-spl
index=web_logs sourcetype=access_combined
| search method="POST" content_length > 10000
| stats count by clientip, uri
```

_Description_: Detects large POST requests, potentially used for uploading malicious payloads.
{% endtab %}

{% tab title="3. Frequent 404 Errors" %}
**Frequent 404 Errors**

```csharp
index=web_logs sourcetype=access_combined
| search status="404"
| stats count by clientip, uri
```

_Description_: Flags repeated 404 errors, which may indicate probing or scanning activities.
{% endtab %}
{% endtabs %}

***

### **2. Phishing**

Attackers deliver malicious payloads or steal credentials through phishing emails.

#### **KQL Queries**

{% tabs %}
{% tab title="1. Identify Emails from Suspicious Domains" %}
**Identify Emails from Suspicious Domains**

```kusto
EmailEvents
| where SenderDomain endswith ".ru" or SenderDomain endswith ".cn"
| summarize count() by Sender, Subject, ReceivedTime
```

_Description_: Searches for emails from unusual or high-risk domains.
{% endtab %}

{% tab title="2. Monitor for Malicious Attachments" %}
**Monitor for Malicious Attachments**

```kusto
EmailAttachmentInfo
| where FileName endswith ".exe" or FileName endswith ".docm"
| summarize count() by FileName, Sender, ReceivedTime
```

_Description_: Identifies emails containing potentially malicious attachments.
{% endtab %}

{% tab title="3. Flag Emails with Suspicious Subjects" %}
**Flag Emails with Suspicious Subjects**

```kusto
EmailEvents
| where Subject contains "urgent" or Subject contains "invoice"
| summarize count() by Sender, Subject, ReceivedTime
```

_Description_: Look for common phishing subject lines, such as "urgent" or "invoice."
{% endtab %}
{% endtabs %}

#### **Velociraptor VQL**

{% tabs %}
{% tab title="1. Search for Suspicious Office Documents" %}
**Search for Suspicious Office Documents**

```csharp
SELECT * FROM FileSystem
WHERE filename =~ ".*\\.docm$"
```

_Description_: Finds recently created Office documents with macros enabled.
{% endtab %}

{% tab title="2. Identify PowerShell Commands" %}
**Identify PowerShell Commands**

```csharp
SELECT * FROM Processes
WHERE cmdline =~ ".*PowerShell.*DownloadString.*"
```

_Description_: Detects PowerShell usage commonly associated with malicious payloads.
{% endtab %}

{% tab title="3. Monitor New Executables in Downloads Folder" %}
**Monitor New Executables in Downloads Folder**

```csharp
SELECT * FROM FileSystem
WHERE path =~ "C:\\Users\\*\\Downloads\\*.exe"
```

_Description_: Flags newly downloaded executables.
{% endtab %}
{% endtabs %}

#### **Splunk SPL**

{% tabs %}
{% tab title="1. Email Attachment Analysis" %}
**Email Attachment Analysis**

```splunk-spl
index=email sourcetype=mail_logs
| search attachment="*.exe" OR attachment="*.docm"
| stats count by sender, attachment
```

_Description_: Identifies suspicious attachments in emails.
{% endtab %}

{% tab title="2. High Volume Emails from Single Sender" %}
**High Volume Emails from Single Sender**

```kusto
index=email sourcetype=mail_logs
| stats count by sender
| where count > 5
```

_Description_: Flags high email volume from a single sender, potentially indicative of phishing campaigns.
{% endtab %}

{% tab title="3. Keywords in Email Subject" %}
**Keywords in Email Subject**

```splunk-spl
index=email sourcetype=mail_logs
| search subject="*urgent*" OR subject="*payment*"
| stats count by sender, subject
```

_Description_: Searches for phishing-like keywords in email subjects.
{% endtab %}
{% endtabs %}

***

### **3. External Remote Services**

Attackers exploit remote access services like RDP, VPNs, or SSH to gain a foothold.

#### **KQL Queries**

{% tabs %}
{% tab title="1. Detect RDP Authentication Failures" %}
**Detect RDP Authentication Failures**

```kusto
SecurityEvent
| where EventID == 4625 and LogonType == 10
| summarize count() by Account, IPAddress, TimeGenerated
```

_Description_: Flags failed RDP login attempts (LogonType 10).
{% endtab %}

{% tab title="2. VPN Logon from Unusual Locations" %}
**VPN Logon from Unusual Locations**

```kusto
SigninLogs
| where AppDisplayName == "VPN" and Location != "ExpectedLocation"
| summarize count() by UserPrincipalName, Location, TimeGenerated
```

_Description_: Detects VPN logins from unexpected geographic locations.
{% endtab %}

{% tab title="3. Repeated Brute-Force Attempts" %}
**Repeated Brute-Force Attempts**

{% code overflow="wrap" %}
```kusto
SigninLogs
| where Status == "Failure" and ResultDescription contains "Invalid credentials"
| summarize Count=count() by UserPrincipalName, IPAddress, TimeGenerated
```
{% endcode %}

_Description_: Identifies accounts targeted by brute-force attacks.
{% endtab %}
{% endtabs %}

#### **Velociraptor VQL**

{% tabs %}
{% tab title="1. Search for Failed Logins" %}
**Search for Failed Logins**

```csharp
SELECT * FROM Audit.WindowsEventLogs
WHERE EventID = 4625 AND EventData.LogonType = "10"
```

_Description_: Finds failed login attempts for RDP sessions.
{% endtab %}

{% tab title="2. Monitor Remote Services" %}
**Monitor Remote Services**

```csharp
SELECT * FROM Processes
WHERE cmdline =~ ".*mstsc.exe.*"
```

_Description_: Tracks usage of the `mstsc.exe` utility for remote desktop sessions.
{% endtab %}

{% tab title="3. Monitor for VPN Software Execution" %}
**Monitor for VPN Software Execution**

```csharp
SELECT * FROM Processes
WHERE cmdline =~ ".*openvpn.*"
```

_Description_: Detects OpenVPN usage, which could indicate unauthorized remote access.
{% endtab %}
{% endtabs %}

#### **Splunk SPL**

{% tabs %}
{% tab title="1. Failed RDP Logins" %}
**Failed RDP Logins**

```splunk-spl
index=authentication sourcetype=windows:security
| search EventCode=4625 LogonType=10
| stats count by AccountName, src_ip
```

_Description_: Flags failed RDP login attempts.
{% endtab %}

{% tab title="2. VPN Logins from New Locations" %}
**VPN Logins from New Locations**

```kusto
index=authentication sourcetype=vpn_logs
| stats dc(Location) by user
| where dc(Location) > 1
```

_Description_: Identifies VPN logins from unusual locations for the same user.
{% endtab %}

{% tab title="3. Repeated Login Failures" %}
**Repeated Login Failures**

```kusto
index=authentication sourcetype=windows:security
| search EventCode=4625
| stats count by src_ip, AccountName
```

_Description_: Highlights accounts targeted by repeated login failures.
{% endtab %}
{% endtabs %}

***

The included **descriptions** and **multiple queries for each technique** should aid the investigations using KQL, Velociraptor, and Splunk, ultimately enhancing the detection and response capabilities in a Windows environment.
