# Collection (TA0009) Techniques

### Introduction

**Threat Description and Potential Impact**

The **Collection** technique under the MITRE ATT\&CK framework involves adversaries gathering information of interest after gaining access to a system. This data may include sensitive files, user credentials, clipboard contents, screenshots, or logs. Collection activities are often preparatory steps for exfiltration and can significantly impact an organization's operations if left undetected. The compromise of intellectual property, customer data, financial records, or privileged credentials can lead to data breaches, financial loss, reputational damage, and compliance violations.

This guide explores investigative strategies for detecting collection activities using Kusto Query Language (KQL). Each technique is paired with a practical and **advanced** query to suit different levels of investigation complexity.

***

### **1. File Access in Sensitive Directories**

**Description**: Adversaries may target sensitive files stored in user directories or shared network drives.

**Effective Query**

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where ActionType in ("FileAccessed", "FileRead")
| where FolderPath startswith @"C:\Users" or FolderPath contains "SharedDrive"
| summarize Count = count() by FolderPath, InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| order by Count desc
```
{% endcode %}

**Advanced Query**

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where ActionType in ("FileAccessed", "FileRead")
| where FolderPath startswith @"C:\Users" or FolderPath contains "SharedDrive"
| where FileName endswith ".docx" or FileName endswith ".xlsx" or FileName endswith ".pdf"  // Focus on sensitive documents
| join kind=inner (DeviceProcessEvents | where InitiatingProcessIntegrityLevel !contains "High") on $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
| summarize Count = count() by FolderPath, FileName, InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| order by Count desc
```
{% endcode %}

***

### **2. Clipboard Monitoring**

**Description**: Adversaries may monitor clipboard content to collect sensitive information like passwords or documents.

**Effective Query**

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType == "ClipboardAccess"
| summarize Count = count() by InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| order by Count desc
```
{% endcode %}

**Advanced Query**

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType == "ClipboardAccess"
| join kind=inner (DeviceProcessEvents | where CommandLine contains "powershell" or CommandLine contains "cmd.exe") on $left.InitiatingProcessFileName == $right.InitiatingProcessFileName
| summarize ClipboardCount = count(), Commands = makeset(CommandLine) by InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| where ClipboardCount > 5
| order by ClipboardCount desc
```
{% endcode %}

***

### **3. Keylogging Activity**

**Description**: Adversaries may use keylogging to capture user keystrokes, collecting credentials or sensitive data.

**Effective Query**

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType in ("KeyloggerDetected", "KeyboardCapture")
| summarize Count = count() by InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| order by Count desc
```
{% endcode %}

**Advanced Query**

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType in ("KeyloggerDetected", "KeyboardCapture")
| join kind=inner (SecurityEvent | where EventID == 4624 and LogonType in (3, 10)) on $left.DeviceName == $right.Computer
| summarize KeyloggerCount = count(), SuspiciousLogonCount = countif(LogonType == 10) by InitiatingProcessFileName, AccountName, DeviceName, IpAddress, TimeGenerated
| where KeyloggerCount > 3 and SuspiciousLogonCount > 2
| order by KeyloggerCount desc
```
{% endcode %}

***

### **4. Screen Capture**

**Description**: Adversaries may capture screen content to gather sensitive information.

**Effective Query**

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType == "ScreenCapture"
| summarize Count = count() by InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| order by Count desc
```
{% endcode %}

**Advanced Query**

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where ActionType == "ScreenCapture"
| join kind=inner (SecurityEvent | where EventID == 4672 and Privileges contains "SeDebugPrivilege") on $left.DeviceName == $right.Computer
| summarize ScreenCaptureCount = count(), PrivilegeEscalationCount = countif(Privileges contains "SeDebugPrivilege") by InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| where ScreenCaptureCount > 2 and PrivilegeEscalationCount > 0
| order by ScreenCaptureCount desc
```
{% endcode %}

***

### **5. Archiving Sensitive Data**

**Description**: Adversaries may compress files for easier exfiltration.

**Effective Query**

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in ("winrar.exe", "7z.exe", "zip.exe")
| summarize Count = count() by InitiatingProcessFileName, AccountName, DeviceName, CommandLine, TimeGenerated
| order by Count desc
```
{% endcode %}

**Advanced Query**

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in ("winrar.exe", "7z.exe", "zip.exe")
| where CommandLine contains "C:\Users" or CommandLine contains "SharedDrive"
| summarize Count = count() by InitiatingProcessFileName, AccountName, DeviceName, CommandLine, TimeGenerated
| where Count > 2
| order by Count desc
```
{% endcode %}

***

### **6. File Exfiltration**

**Description**: Adversaries may exfiltrate data to external cloud storage or file-sharing services.

**Effective Query**

{% code overflow="wrap" %}
```kusto
NetworkConnections
| where RemoteUrl contains "drive.google.com" or RemoteUrl contains "dropbox.com"
| summarize Count = count() by RemoteUrl, InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| order by Count desc
```
{% endcode %}

**Advanced Query**

{% code overflow="wrap" %}
```kusto
let ArchiveActivity = DeviceProcessEvents
| where InitiatingProcessFileName in ("winrar.exe", "7z.exe", "zip.exe")
| summarize ArchiveCount = count() by InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated;

NetworkConnections
| where RemoteUrl contains "drive.google.com" or RemoteUrl contains "dropbox.com"
| join kind=inner (ArchiveActivity) on DeviceName
| summarize ExfiltrationCount = count(), ArchiveActivityCount = max(ArchiveCount) by RemoteUrl, InitiatingProcessFileName, AccountName, DeviceName, TimeGenerated
| where ExfiltrationCount > 2
| order by ExfiltrationCount desc
```
{% endcode %}

***

#### This investigative guide provides actionable steps for detecting adversary activity related to the **Collection** technique in a Windows environment. By using **effective** queries for quick insights and **advanced** queries for deeper correlations, security teams can uncover malicious behaviour, assess its impact, and respond effectively. Regular monitoring of these activities can help organisations minimise risks associated with data theft and maintain robust security.

#### Jump In
