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

# Discovery (TA0007)

### **Sub-technique: T1083 - File and Directory Discovery**

**Objective**: Detect reconnaissance activities aimed at discovering sensitive files and directories.

1. **Detect Directory Listing Commands**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("dir", "ls")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName

//Advanced Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("dir", "ls")
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify commands used to list directory contents.

2. **Monitor Access to Sensitive Directories**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceFileEvents
| where FolderPath has_any ("C:\\Users", "C:\\Windows\\System32", "C:\\ProgramData")
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FolderPath has_any ("C:\\Users", "C:\\Windows\\System32", "C:\\ProgramData")
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect access to directories likely to contain sensitive information.

3. **Detect Searches for Specific File Types**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceFileEvents 
| where FileName endswith ".txt" or FileName endswith ".docx" 
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FileName endswith ".txt" or FileName endswith ".docx"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor searches for file types that may contain sensitive data.

4. **Identify Access to Security Configuration Files**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceFileEvents 
| where FileName in ("secpol.msc", "gpedit.msc") 
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FileName in ("secpol.msc", "gpedit.msc")
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect access to files used to configure security settings.

5. **Monitor for Password Files**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceFileEvents 
| where FileName has_any ("password", "credentials") 
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FileName has_any ("password", "credentials")
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify attempts to locate files that may contain passwords.

6. **Detect Unauthorized Access to Network Shares**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceNetworkEvents 
| where RemotePort == 445 
| summarize count() by RemoteIP, LocalIP 
| where count() > 50

//Advanced Search
DeviceNetworkEvents
| where RemotePort == 445
| summarize count() by RemoteIP, LocalIP
| where count() > 50
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceFileEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize FileEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, RemoteIP, LocalIP, NetworkEventCount, FileEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor excessive access to network shares.

7. **Detect Access to Administrator Directories**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceFileEvents 
| where FolderPath has "C:\\Users\\Administrator" 
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FolderPath has "C:\\Users\\Administrator"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify access to administrator directories.

8. **Monitor for Hidden File Access**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FileAttributes has "Hidden"
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FileAttributes has "Hidden"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect attempts to access hidden files.

9. **Detect Access to Backup Directories**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceFileEvents
| where FolderPath has "Backup"
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FolderPath has "Backup"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify access to backup directories.

10. **Detect Enumeration of Program Files Directory**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceFileEvents
| where FolderPath has "C:\\Program Files"
| project Timestamp, DeviceName, FileName, FolderPath

//Advanced Search
DeviceFileEvents
| where FolderPath has "C:\\Program Files"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("dir", "ls", "powershell", "cmd", "explorer", "taskmgr", "regedit", "notepad", "msconfig", "services", "mmc", "control", "winword", "excel", "outlook", "chrome", "firefox", "edge", "svchost", "wscript", "cscript", "schtasks", "wmic")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor attempts to enumerate the Program Files directory.
