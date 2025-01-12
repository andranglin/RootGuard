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

# Collection (TA0009)

### **Sub-technique: T1119 - Automated Collection**

**Objective**: Detect automated collection of data for exfiltration.&#x20;

1. **Identify Automated File Collection**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FileName has_any ("robocopy", "xcopy", "copy")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc

// Extended Search
DeviceFileEvents
| where FileName has_any ("robocopy", "xcopy", "copy")
| summarize FileCopyCount = count() by DeviceName, FileName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("robocopy", "xcopy", "copy")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, FileName, FileCopyCount, ProcessCount, ConnectionCount
| order by FileCopyCount desc
```
{% endcode %}

**Purpose**: Detect automated file copying commands.

2. **Detection of Large Data Archives**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FileName endswith ".zip" or FileName endswith ".rar"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp desc

//More expanded search
DeviceFileEvents
| where FileName endswith ".zip" or FileName endswith ".rar"
| summarize ArchiveFileCount = count() by DeviceName, FileName, FolderPath
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("zip", "rar")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, FileName, FolderPath, ArchiveFileCount, ProcessCount, ConnectionCount
| order by ArchiveFileCount desc
```
{% endcode %}

**Purpose**: Monitor the creation of large archive files.

3. **Suspicious Data Collection Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("backup", "sync", "archive")
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc

//More expansive search
DeviceProcessEvents
| where ProcessCommandLine has_any ("backup", "sync", "archive")
| summarize ProcessCount = count() by DeviceName, ProcessCommandLine
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, ProcessCommandLine, ProcessCount, ArchiveFileCount, ConnectionCount
| order by ProcessCount desc
```
{% endcode %}

**Purpose**: Detect scripts or commands used for data collection.

4. **Detect Collection of Network Traffic Data**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("tcpdump", "wireshark", "netsh")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp desc

//Extended search
DeviceProcessEvents
| where ProcessCommandLine has_any ("tcpdump", "wireshark", "netsh")
| summarize ProcessCount = count() by DeviceName, ProcessCommandLine
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".pcap" or FileName endswith ".cap"
    | summarize FileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, ProcessCommandLine, ProcessCount, FileCount, ConnectionCount
| order by ProcessCount desc
```
{% endcode %}

**Purpose**: Identify network traffic data collection.

5. **Monitor for Data Collection via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Out-File", "Export-Csv")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp desc

//Extended Search
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Out-File", "Export-Csv")
| summarize ProcessCount = count() by DeviceName, ProcessCommandLine
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".csv" or FileName endswith ".txt"
    | summarize FileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, ProcessCommandLine, ProcessCount, FileCount, ConnectionCount
| order by ProcessCount desc
```
{% endcode %}

**Purpose**: Detect PowerShell commands used to export data.

6. **Detect Database Dumps**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("mysqldump", "pg_dump", "mongodump")
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc
 
 //Extended Search
 DeviceProcessEvents
| where ProcessCommandLine has_any ("mysqldump", "pg_dump", "mongodump")
| summarize ProcessCount = count() by DeviceName, ProcessCommandLine
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".sql" or FileName endswith ".dump"
    | summarize FileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3306 or RemotePort == 5432 or RemotePort == 27017
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, ProcessCommandLine, ProcessCount, FileCount, ConnectionCount
| order by ProcessCount desc
```
{% endcode %}

**Purpose**: Identify database dump commands.

7. **Monitor for Automated Collection via Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents 
| where ProcessCommandLine has_any (".bat", ".ps1", ".sh") and ProcessCommandLine has_any ("copy", "export", "backup") 
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath

//Extended Search
DeviceProcessEvents
| where ProcessCommandLine has_any (".bat", ".ps1", ".sh") and ProcessCommandLine has_any ("copy", "export", "backup")
| summarize ProcessCount = count() by DeviceName, ProcessCommandLine
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, ProcessCommandLine, ProcessCount, ArchiveFileCount, ConnectionCount
| order by ProcessCount desc
```
{% endcode %}

**Purpose**: Detect scripts used for data collection.

8. **Identify Collection of Sensitive Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FileName has_any ("passwords.txt", "confidential.docx")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp desc

//Extended Search
DeviceFileEvents
| where FileName has_any ("passwords.txt", "confidential.docx")
| summarize FileAccessCount = count() by DeviceName, FileName, FolderPath, InitiatingProcessAccountName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("copy", "move", "delete")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, FileName, FolderPath, InitiatingProcessAccountName, FileAccessCount, ProcessCount, ConnectionCount
| order by FileAccessCount desc
```
{% endcode %}

**Purpose**: Monitor access to sensitive files.

9. **Detect Use of Cloud Services for Data Collection**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents 
| where RemoteIP in ("cloud_storage_ip_list") 
| summarize count() by RemoteIP, LocalIP 
| where count() > 10

//Extended Search
DeviceNetworkEvents
| where RemoteIP in ("cloud_storage_ip_list")
| summarize ConnectionCount = count() by RemoteIP, DeviceName
| where ConnectionCount > 10
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("upload", "sync", "backup")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ConnectionCount, ArchiveFileCount, ProcessCount
| order by ConnectionCount desc
```
{% endcode %}

```
_Purpose_: Monitor data collection via cloud services.
```

10\. **Monitor for Data Collection via Network Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents 
| where RemotePort == 445 
| summarize count() by RemoteIP, LocalIP 
| where count() > 20

//Extended Search
DeviceNetworkEvents
| where RemotePort == 445
| summarize ConnectionCount = count() by RemoteIP, DeviceName
| where ConnectionCount > 20
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("copy", "move", "delete")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ConnectionCount, ArchiveFileCount, ProcessCount
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Identify data collection via network shares.
