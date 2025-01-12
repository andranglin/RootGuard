---
icon: laptop-code
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

# Defender & Sentinel - KQL Use Cases

## <mark style="color:blue;">12. Exfiltration (TA0010)</mark>

**Sub-technique: T1041 - Exfiltration Over C2 Channel**

**Objective**: Detect data exfiltration over command and control channels.&#x20;

1. **Detect Large Data Transfers to Unknown IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where BytesSent > 1000000 | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

**Purpose**: Identify large data transfers to unknown IP addresses.

2. **Monitor for DNS-Based Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 | summarize count() by RemoteIP, LocalIP | where count() > 100
```
{% endcode %}

**Purpose**: Detect DNS-based exfiltration.

3. **Detect HTTP POST Requests Used for Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has "POST" | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor for HTTP POST requests used to exfiltrate data.

4. **Monitor for Data Exfiltration via Cloud Storage**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("cloud_storage_ip_list") | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Identify data uploads to cloud storage services.

5. **Detect Exfiltration via FTP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 21 | where BytesSent > 1000000 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Detect large data transfers over FTP.

6. **Monitor for Email-Based Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 25 or RemotePort == 587 | where BytesSent > 100000 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Identify data exfiltration attempts via email.

7. **Detect Use of Encrypted Channels for Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 or RemotePort == 22 | where BytesSent > 500000 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Monitor for data exfiltration over encrypted channels.

8. **Identify Data Exfiltration via WebSocket**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and ProcessCommandLine has "websocket" | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect WebSocket connections used for exfiltration.

9. **Monitor for Data Exfiltration via Network Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 | summarize count() by RemoteIP, LocalIP | where count() > 20
```
{% endcode %}

**Purpose**: Identify data exfiltration via network shares.

10. **Detect Use of Unknown Protocols for Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol not in ("TCP", "UDP", "ICMP") | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

**Purpose**: Monitor for exfiltration over unknown or unusual protocols.

## <mark style="color:blue;">13. Impact (TA0040)</mark>

**Sub-technique: T1486 - Data Encrypted for Impact**

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
