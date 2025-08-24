# Impact (TA0040)

### **Sub-technique: T1486 - Data Encrypted for Impact**

**Objective**: Detect encryption of data to cause harm, such as ransomware attacks.&#x20;

1. **Detect Encryption Tools in Use**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("encrypt", "ransom")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify the use of encryption tools associated with ransomware.

2. **Monitor for Mass File Renaming**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where ActionType == "FileRenamed"
| summarize eventCount = count() by FileName, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| where eventCount > 100
| project FileName, DeviceName, eventCount, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by eventCount desc
```
{% endcode %}

**Purpose**: Detect mass renaming of files that may indicate encryption.

3. **Detect Ransomware Note Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FileName in ("ransomnote.txt", "readme.txt")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify the creation of ransomware note files.

4. **Monitor for Unusual File Extensions**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FileName has_any (".locked", ".crypt", ".enc")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

// Extended Search
DeviceFileEvents
| where FileName has_any (".locked", ".crypt", ".enc")
| extend FileSize = tolong(FileSize)
| summarize eventCount = count(), TotalFileSize = sum(FileSize) by Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| where eventCount > 10
| project Timestamp, DeviceName, FileName, FolderPath, eventCount, TotalFileSize, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect unusual file extensions that might indicate encryption.

5. **Detect File Deletion After Encryption**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where ActionType == "FileDeleted" and FileName has_any (".bak", ".tmp")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc

//Extended Search
DeviceFileEvents
| where ActionType == "FileDeleted" and FileName has_any (".bak", ".tmp")
| extend FileSize = tolong(FileSize)
| summarize eventCount = count(), TotalFileSize = sum(FileSize) by Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| where eventCount > 10
| project Timestamp, DeviceName, FileName, FolderPath, eventCount, TotalFileSize, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify deletion of backup or temporary files after encryption.

6. **Monitor for Encryption via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has "encrypt"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc

// Extended Search
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has "encrypt"
| summarize eventCount = count() by Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| where eventCount > 5
| project Timestamp, DeviceName, ProcessCommandLine, eventCount, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect encryption commands executed via PowerShell.

7. **Detect Use of Known Ransomware Executables**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("wannacry", "cryptolocker")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc

//Extended Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("wannacry", "cryptolocker")
| extend ProcessDuration = datetime_diff('second', now(), ProcessCreationTime)
| summarize eventCount = count(), TotalProcessDuration = sum(ProcessDuration) by Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| where eventCount > 5
| project Timestamp, DeviceName, ProcessCommandLine, eventCount, TotalProcessDuration, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify known ransomware executables.

8. **Monitor for Suspicious Network Encryption Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("openssl", "gpg")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc

//Extended Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("openssl", "gpg")
| extend ProcessDuration = datetime_diff('second', now(), ProcessCreationTime)
| summarize eventCount = count(), TotalProcessDuration = sum(ProcessDuration) by Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| where eventCount > 5
| project Timestamp, DeviceName, ProcessCommandLine, eventCount, TotalProcessDuration, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect network encryption tools that may be used maliciously.

9. **Detect Unusual Volume of File Modifications**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where ActionType == "FileModified"
| summarize eventCount = count() by DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| where eventCount > 1000
| project DeviceName, FileName, FolderPath, eventCount, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by eventCount desc

//Extended Search
DeviceFileEvents
| where ActionType == "FileModified"
| extend FileSize = tolong(FileSize)
| summarize eventCount = count(), TotalFileSize = sum(FileSize) by Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| where eventCount > 1000
| project Timestamp, DeviceName, FileName, FolderPath, eventCount, TotalFileSize, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify a large number of file modifications, which may indicate encryption.

10. **Monitor for Attempts to Disable Antivirus**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("disable", "stop") and ProcessCommandLine has_any ("antivirus", "defender")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc

//Extended Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("disable", "stop") and ProcessCommandLine has_any ("antivirus", "defender")
| extend ProcessDuration = datetime_diff('second', now(), ProcessCreationTime)
| summarize eventCount = count(), TotalProcessDuration = sum(ProcessDuration) by Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| where eventCount > 5
| project Timestamp, DeviceName, ProcessCommandLine, eventCount, TotalProcessDuration, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect attempts to disable antivirus protections before encryption.
