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

# Impact (TA0040)

### **Sub-technique: T1486 - Data Encrypted for Impact**

**Objective**: Detect encryption of data to cause harm, such as ransomware attacks.&#x20;

1. **Detect Encryption Tools in Use**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("encrypt", "ransom") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify the use of encryption tools associated with ransomware.

2. **Monitor for Mass File Renaming**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Rename" | summarize count() by FileExtension, DeviceName | where count() > 100
```
{% endcode %}

**Purpose**: Detect mass renaming of files that may indicate encryption.

3. **Detect Ransomware Note Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName in ("ransomnote.txt", "readme.txt") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Identify the creation of ransomware note files.

4. **Monitor for Unusual File Extensions**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension in (".locked", ".crypt", ".enc") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Detect unusual file extensions that might indicate encryption.

5. **Detect File Deletion After Encryption**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Delete" and FileExtension in (".bak", ".tmp") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Identify deletion of backup or temporary files after encryption.

6. **Monitor for Encryption via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "encrypt" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect encryption commands executed via PowerShell.

7. **Detect Use of Known Ransomware Executables**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("wannacry", "cryptolocker") | project Timestamp, DeviceName, ProcessCommandLine`
```
{% endcode %}

**Purpose**: Identify known ransomware executables.

8. **Monitor for Suspicious Network Encryption Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("openssl", "gpg") | project Timestamp, DeviceName, ProcessCommandLine`
```
{% endcode %}

**Purpose**: Detect network encryption tools that may be used maliciously.

9. **Detect Unusual Volume of File Modifications**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Modify" | summarize count() by DeviceName | where count() > 1000`
```
{% endcode %}

**Purpose**: Identify a large number of file modifications, which may indicate encryption.

10. **Monitor for Attempts to Disable Antivirus**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("disable", "stop") and ProcessCommandLine has_any ("antivirus", "defender") | project Timestamp, DeviceName, ProcessCommandLine`
```
{% endcode %}

**Purpose**: Detect attempts to disable antivirus protections prior to encryption.
