---
icon: laptop-code
---

# Impact (TA0040) Techniques

### <mark style="color:blue;">Introduction</mark>

Forensically investigating the impact of a compromise on workstations and server systems is an essential step in understanding the extent of damage, the data affected, and what steps are necessary for recovery and future prevention. This process involves a thorough examination of affected systems to identify the scope of the attack, assess the damage, and uncover the methods used by the attackers.

#### Understanding Possible Impacts

* **Data Exfiltration:** Determining if sensitive data was accessed or stolen.
* **Data Destruction:** Assessing if any data was deleted or corrupted.
* **System Compromise:** Evaluating the integrity of the operating system and critical software.
* **Service Disruption:** Identifying if key services were disrupted or disabled.
* **Persistence:** Checking for any signs that the attacker has established ongoing access.
* **Lateral Movement:** Investigating whether the compromise spread to other systems in the network.

#### Data Collection and Preservation

* **Forensic Imaging:** Use tools like FTK Imager or dd to create exact copies of affected systems' hard drives.
* **Memory Capture:** Use tools like Magnet RAM Capture or WinPmem to capture volatile memory.
* **Log Collection:** Secure all relevant logs, including system logs, application logs, security logs, and network logs.

#### Assessing Data Exfiltration

* **Network Traffic Analysis:** Use tools like Wireshark or Tcpdump to analyse network traffic for signs of data being sent to external locations.
* **Log Analysis:** Check firewall, web proxy, and server logs for unusual outbound traffic.

#### Evaluating Data Integrity

* **File System Analysis:** Examine the file system for signs of deletion, alteration, or encryption of files.
* **Data Recovery Techniques:** Use data recovery tools to attempt to restore deleted or corrupted files.

#### System Compromise Assessment

* **Malware Analysis:** Look for and analyse any malware that may have been used in the attack.
* **Rootkit Detection:** Employ rootkit detection tools to uncover any stealthy malware or tools used by the attackers.
* **Integrity Checks:** Run integrity checks on critical system files and configurations.

#### Service Disruption Analysis

* **System and Application Logs:** Review these logs for service stop events, crashes, or configuration changes that could indicate sabotage.
* **Dependency Checks:** Ensure that critical services and applications are functioning properly and depend on uncompromised components.

#### Investigating Persistence Mechanisms

* **Startup Items:** Check for unauthorised scripts or programs in startup locations.
* **Scheduled Tasks and Cron Jobs:** Look for any tasks that may provide ongoing access or trigger malicious activities.
* **Registry (Windows):** Examine registry keys commonly used for persistence.

#### Lateral Movement Investigation

* **Active Directory and Network Logs:** Analyse these logs for signs of credential use on multiple systems.
* **Endpoint Detection and Response (EDR) Data:** Review EDR data for patterns that suggest movement across the network.

#### Documentation and Reporting

* **Detailed Documentation:** Record all findings, methodologies, and evidence paths.
* **Impact Report:** Prepare a detailed report summarising the impact, including data loss, system integrity issues, and business disruption.

#### Post-Investigation Actions

* **Remediation and Mitigation:** Implement necessary measures to recover data, restore services, and secure the network.
* **Incident Review and Policy Update:** Conduct a thorough review of the incident to improve future security posture and incident response capabilities.

#### Key Considerations

* **Legal and Compliance Factors:** Ensure the investigation complies with legal and regulatory requirements.
* **Chain of Custody:** Maintain an accurate chain of custody for all forensic evidence.
* **Confidentiality:** Handle all data securely, maintaining confidentiality and integrity throughout the process.

Forensic investigations into the impact of a compromise require a multi-faceted approach, combining technical analysis with an understanding of business operations and data sensitivity. Tailoring the investigation to the specifics of the incident and the environment is essential for a comprehensive assessment.

### <mark style="color:blue;">Using KQL to Investigate Impact Activities in an Environment Using Defender/Sentinel</mark>

Impact techniques are used by adversaries to disrupt availability or compromise the integrity of systems and data. These techniques often result in data destruction, system corruption, or operational disruption.

### <mark style="color:blue;">**1. T1485 - Data Destruction**</mark>

**Objective**: Detect and investigate attempts to destroy data on compromised systems.&#x20;

1. **Detect Use of File Deletion Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("del", "erase", "rm") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify commands that delete files, potentially indicating data destruction.

2. **Monitor for Use of Disk Wiping Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("cipher /w", "sdelete", "diskpart") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of tools designed to wipe disk data securely.

3. **Identify File Deletions in Critical Directories**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Delete" and FolderPath startswith_any ("C:\\Windows\\System32", "C:\\Program Files") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for file deletions in critical system directories.

4. **Detect Use of `vssadmin` to Delete Shadow Copies**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete shadows" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to delete Volume Shadow Copies, which are often used to recover deleted files.

5. **Monitor for Use of `format` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "format" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of the `format` command, which can be used to destroy data on a disk.

6. **Identify Deletion of Log Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Delete" and FileName endswith_any (".log", ".evtx") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the deletion of log files, which could indicate an attempt to cover tracks after data destruction.

### <mark style="color:blue;">**2. T1490 - Inhibit System Recovery**</mark>

**Objective**: Detect and investigate attempts to inhibit system recovery, such as disabling backups or deleting system restore points.&#x20;

1. **Detect Use of `vssadmin` to Delete Shadow Copies**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete shadows" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to delete Volume Shadow Copies to prevent recovery.

2. **Monitor for Disabling of Windows Backup**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("wbadmin", "disable backup") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect commands that disable Windows Backup functionality.

3. **Identify Deletion of Backup Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Delete" and FileName endswith_any (".bak", ".vhd", ".vhdx") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the deletion of backup files that could be used for recovery.

4. **Detect Disabling of System Restore**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "SystemRestore" and RegistryValueName == "DisableSR" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to the registry that disable System Restore.

5. **Monitor for Use of `bcdedit` to Modify Boot Configuration**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "bcdedit" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect use of `bcdedit` to modify the boot configuration, which could inhibit system recovery.

6. **Identify Deactivation of System Protection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Disable-ComputerRestore" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the deactivation of system protection features.

### <mark style="color:blue;">**3. T1486 - Data Encrypted for Impact**</mark>

**Objective**: Detect and investigate attempts to encrypt data to prevent access, often as part of a ransomware attack.&#x20;

1. **Detect Execution of Known Ransomware Processes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ransomware", "cryptolocker", "wannacry") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the execution of known ransomware processes.

2. **Monitor for Unusual File Renaming Activities**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Rename" and FileName endswith_any (".encrypted", ".locked", ".crypt") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect files being renamed with typical ransomware file extensions.

3. **Identify Bulk File Modifications**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileOperation == "Write" and FileExtension != ".tmp" | summarize ModificationCount = count() by DeviceName, InitiatingProcessAccountName, FolderPath | where ModificationCount > 1000 | project Timestamp, DeviceName, FolderPath, ModificationCount, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for bulk file modifications that may indicate encryption.

4. **Detect Use of `vssadmin` to Delete Shadow Copies**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete shadows" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to delete Volume Shadow Copies before encryption.

5. **Monitor for Creation of New Encrypted Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension in (".encrypted", ".locked", ".crypt") | project Timestamp, DeviceName, FileName, FolderPath, FileOperation, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the creation of files with extensions typically associated with encrypted files.

6. **Identify Use of Encryption Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("aescrypt", "gpg", "openssl enc") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the execution of known encryption tools that could be used maliciously.

### <mark style="color:blue;">**4. T1499 - Endpoint Denial of Service**</mark>

**Objective**: Detect and investigate attempts to deny service on a single host or device, rendering it unusable.&#x20;

1. **Detect High CPU Usage by a Single Process**

{% code overflow="wrap" %}
```cs
DevicePerformanceEvents | where CounterName == "Processor" and CounterValue > 90 | project Timestamp, DeviceName, ProcessName, CounterValue, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes causing high CPU usage that may indicate a DoS attack on the endpoint.

2. **Monitor for Excessive Memory Usage**

{% code overflow="wrap" %}
```cs
DevicePerformanceEvents | where CounterName == "Memory" and CounterValue > 90 | project Timestamp, DeviceName, ProcessName, CounterValue, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect processes using excessive memory, potentially causing a denial of service on the endpoint.

3. **Identify Disk I/O Overload**

{% code overflow="wrap" %}
```cs
DevicePerformanceEvents | where CounterName == "Disk I/O" and CounterValue > 1000 | project Timestamp, DeviceName, ProcessName, CounterValue, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for processes causing excessive disk I/O, which could indicate a DoS attack.

4. **Detect Network Saturation by a Single Process**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | summarize NetworkUsage = sum(TotalBytes) by DeviceName, ProcessName, InitiatingProcessAccountName | where NetworkUsage > 1000000000 | project Timestamp, DeviceName, ProcessName, NetworkUsage, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes consuming large amounts of network bandwidth, potentially causing a DoS on the endpoint.

5. **Monitor for Forced Shutdowns or Reboots**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType in ("Shutdown", "Reboot") and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect unauthorized shutdowns or reboots that may be part of a DoS attack.

6. **Identify Disabling of Network Interfaces**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "NetworkInterfaceDisabled" | project Timestamp, DeviceName, NetworkAdapter, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for network interfaces being disabled, which could render the device unreachable.

### <mark style="color:blue;">**5. T1529 - System Shutdown/Reboot**</mark>

**Objective**: Detect and investigate unauthorized attempts to shut down or reboot a system, potentially causing disruption.

1. **Detect Use of Shutdown or Reboot Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("shutdown", "reboot", "shutdown /r") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify commands that initiate a system shutdown or reboot.

2. **Monitor for Forced Reboots**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "shutdown /r /f" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect forced reboots that could indicate malicious intent.

3. **Identify Unauthorized System Shutdowns**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "Shutdown" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for shutdown events initiated by non-admin users.

4. **Detect System Shutdowns After Malicious Activity**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "shutdown" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify shutdowns following suspicious or malicious activity.

5. **Monitor for Reboots Following File Modifications**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "shutdown /r" | join kind=inner (DeviceFileEvents | where FileOperation == "Write") on $left.DeviceName == $right.DeviceName | project Timestamp, DeviceName, ProcessCommandLine, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect reboots that occur shortly after file modifications, which may indicate tampering.

6. **Identify Attempts to Disable or Reboot Critical Services**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("net stop", "sc stop", "shutdown /r") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for commands that attempt to stop critical services before shutting down or rebooting the system.

### <mark style="color:blue;">**6. T1491.001 - Defacement: Internal Defacement**</mark>

**Objective**: Detect and investigate attempts to deface or alter internal systems, such as web pages or internal documentation.

1. **Detect Modifications to Internal Web Pages**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "C:\\inetpub\\wwwroot" and FileOperation == "Write" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to files in the web server directory, which could indicate defacement.

2. **Monitor for Unauthorized Changes to Internal Documentation**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath contains "\\Documentation\\" and FileOperation == "Write" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to internal documentation files that could indicate defacement.

3. **Identify Use of Web Editing Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("notepad", "vi", "nano") and FolderPath startswith "C:\\inetpub\\wwwroot" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of text editors on web server directories, which could indicate an attempt to deface web pages.

4. **Detect Upload of New Web Content via FTP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 21 and RequestMethod == "PUT" | project Timestamp, DeviceName, RemoteIP, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify file uploads to a web server via FTP, which could be used to deface the site.

5. **Monitor for Changes to Internal Signage or Displays**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath contains "\\Signage\\" and FileOperation == "Write" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to files used for internal digital signage, which could indicate defacement.

6. **Identify Unusual Activity on Intranet Servers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "intranet" and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for unusual activity on intranet servers that could be related to defacement attempts.
