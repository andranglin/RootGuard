---
icon: laptop-code
---

# Lateral Movement (TA0008) Techniques

### <mark style="color:blue;">Introduction</mark>

Forensically investigating lateral movement techniques on workstations and server systems is crucial to understanding how an attacker moves within a network after gaining initial access. Lateral movement involves techniques that enable an attacker to access and control remote systems within a network.

#### Understanding Common Lateral Movement Techniques

* **Remote Services:** Such as RDP, SSH, VNC.
* **Exploitation of Trust:** Utilising valid credentials or exploiting trusted relationships between systems.
* **Use of File Shares: Accessing network shares to move files or execute code.**
* **Pass-the-Hash/Pass-the-Ticket:** Stealing and reusing authentication tokens.
* **Remote Execution Tools:** Tools like PsExec or remote scripting like PowerShell Remoting.

#### Initial Data Collection

* **Forensic Imaging:** Create exact copies of the hard drives of affected systems using tools like FTK Imager or dd.
* **Memory Capture:** Capture volatile memory from systems using tools like WinPmem or Magnet RAM Capture.
* **Log Collection:** Gather security logs, system logs, application logs, and especially Windows Event Logs.

#### Analysing Remote Access

* **Security and System Logs:** Review logs for signs of remote access activities, like RDP logins (Event ID 4624 with logon type 10).
* **Authentication Logs:** Examine logs for abnormal authentication patterns or use of unusual user accounts.

#### Network Traffic Analysis

* **Network Monitoring Tools:** Use tools like Wireshark or Tcpdump to analyse network traffic for remote access protocols or unusual internal traffic patterns.
* **Flow Data Analysis:** Review NetFlow data for evidence of lateral movements.

#### Investigating Account Usage

* **User Account Analysis:** Look for evidence of unauthorised use of user accounts, especially privileged ones.
* **Pass-the-Hash/Pass-the-Ticket Detection:** Analyse memory dumps or security logs for signs of these techniques.

#### File and Directory Analysis

* **File Access and Movement:** Check file access logs for indications of files being accessed or moved in a manner consistent with lateral movement.
* **Artefact Analysis:** Look for artefacts left by remote execution tools or scripts.

#### Analysing Use of Remote Services

* **RDP, SSH, and Other Protocols:** Examine logs and settings related to these services for unauthorised access or configuration changes.
* **Service Configuration:** Review the configuration of services commonly used for lateral movement.

#### Specialised Forensic Tools Usage

* **Forensic Suites:** Tools like EnCase, Autopsy, or X-Ways for comprehensive analysis.
* **Sysinternals Suite:** For in-depth analysis of Windows systems, including tools like Process Explorer and TCPView.

#### Documentation and Reporting

* **Detailed Documentation:** Record all findings, processes used and evidence paths.
* **Forensic Report:** Compile a comprehensive report detailing the lateral movement investigation.

#### Post-Investigation Actions

* **Mitigation and Remediation:** Implement necessary measures to contain and eradicate the attacker's presence.
* **Recovery:** Restore affected systems from clean backups.
* **Enhancing Defenses:** Update security policies and tools based on the findings.

#### Key Considerations

* **Chain of Custody:** Maintain an accurate chain of custody for all forensic evidence.
* **Legal Compliance:** Ensure that the investigation complies with legal requirements.
* **Data Confidentiality:** Maintain the confidentiality and integrity of data throughout the investigation.

Lateral movement investigations require a detailed and methodical approach, as attackers often use sophisticated methods to avoid detection. Tailor the investigation to the specifics of the incident and the environment in which you are operating.

### <mark style="color:blue;">Using KQL to Investigate Lateral Movement Activities in an Environment Using Defender/Sentinel</mark>

Lateral Movement techniques involve adversaries trying to move through the network to gain access to other systems and sensitive data.

### <mark style="color:blue;">**1. T1021.001 - Remote Desktop Protocol (RDP)**</mark>

**Objective**: Detect attempts to use RDP to move laterally across systems.&#x20;

1. **Detect RDP Logon Activity**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" | project Timestamp, AccountName, LogonType, DeviceName, LogonResult
```
{% endcode %}

_Purpose_: Identify logons that use Remote Desktop Protocol.

2. **Monitor for Unusual RDP Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 3389 | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect RDP connections from unusual IP addresses or at odd hours.

3. **Identify Multiple RDP Sessions from a Single Account**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" | summarize RDPCount = count() by AccountName, DeviceName | where RDPCount > 3 | project Timestamp, AccountName, DeviceName, RDPCount
```
{% endcode %}

_Purpose_: Monitor for multiple RDP sessions initiated by the same account in a short time frame.

4. **Detect Suspicious RDP Session Initiation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mstsc.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of Remote Desktop Connection client.

5. **Monitor for RDP Session Shadowing**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "shadow.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of shadow sessions, which allow viewing or controlling an active RDP session.

6. **Identify Unauthorized RDP Access Attempts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Failed" | project Timestamp, AccountName, DeviceName, LogonResult
```
{% endcode %}

_Purpose_: Monitor for failed RDP logon attempts, which may indicate unauthorized access attempts.

### <mark style="color:blue;">**2. T1021.002 - SMB/Windows Admin Shares**</mark>

**Objective**: Detect attempts to use SMB shares for lateral movement, such as administrative shares or file shares.&#x20;

1. **Detect Access to Admin Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and RemoteIP != "127.0.0.1" and FolderPath has_any ("\\ADMIN$", "\\C$") | project Timestamp, DeviceName, RemoteIP, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to access administrative shares like `ADMIN$` or `C$`.

2. **Monitor for Lateral Movement Using `PsExec`**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "PsExec.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of `PsExec`, a tool commonly used for lateral movement via SMB.

3. **Identify File Transfers Over SMB**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "\\\\" and FileOperation == "Create" | project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for files being copied over SMB shares, which may indicate data exfiltration or tool transfer.

4. **Detect Attempts to Map Network Drives**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "net use" and ProcessCommandLine has_not ("\\domain") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to map network drives using the `net use` command.

5. **Monitor for Unauthorized Access to Hidden Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and FolderPath has_any ("\\IPC$", "\\print$") | project Timestamp, DeviceName, RemoteIP, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to access hidden administrative shares like `IPC$`.

6. **Identify Use of WMI for SMB-Based Lateral Movement**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("wmic", "process call create") and ProcessCommandLine has "\\\\" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for WMI commands used to execute processes remotely over SMB.

### <mark style="color:blue;">**3. T1075 - Pass the Hash**</mark>

**Objective**: Detect attempts to use stolen NTLM hashes to authenticate to other systems without needing the associated plaintext password.&#x20;

1. **Detect Unusual NTLM Logon Events**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AuthenticationPackage == "NTLM" | project Timestamp, AccountName, DeviceName, LogonType, LogonResult
```
{% endcode %}

_Purpose_: Identify NTLM logon events that may indicate pass-the-hash attacks.

2. **Monitor for NTLM Authentication Without Interactive Logon**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType != "Interactive" and AuthenticationPackage == "NTLM" | project Timestamp, AccountName, DeviceName, LogonType, LogonResult
```
{% endcode %}

_Purpose_: Detect NTLM authentication attempts where no interactive logon occurred, potentially indicating pass-the-hash.

3. **Identify High-Frequency NTLM Logons**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AuthenticationPackage == "NTLM" | summarize LogonCount = count() by AccountName, DeviceName | where LogonCount > 5 | project Timestamp, AccountName, DeviceName, LogonCount
```
{% endcode %}

_Purpose_: Monitor for multiple NTLM logon attempts in a short time frame.

4. **Detect Use of Mimikatz for Pass-the-Hash**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("mimikatz", "sekurlsa::pth") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of Mimikatz, a tool commonly used for pass-the-hash attacks.

5. **Monitor for Suspicious NTLM Network Traffic**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and Protocol == "TCP" and Direction == "Inbound" | project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol
```
{% endcode %}

_Purpose_: Detect inbound NTLM traffic that could indicate pass-the-hash attempts.

6. **Identify NTLM Logons from Non-Domain Systems**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AuthenticationPackage == "NTLM" and AccountDomain != "YourDomain" | project Timestamp, AccountName, AccountDomain, DeviceName, LogonResult
```
{% endcode %}

_Purpose_: Monitor for NTLM logons originating from non-domain systems, which may indicate an attack.

### <mark style="color:blue;">**4. T1021.004 - SSH**</mark>

**Objective**: Detect attempts to use SSH for lateral movement, particularly in environments that use SSH for remote management.&#x20;

1. **Detect SSH Logons**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "Network" and ProcessCommandLine has "ssh" | project Timestamp, AccountName, DeviceName, LogonType, LogonResult
```
{% endcode %}

_Purpose_: Identify SSH logon events, especially those originating from unusual locations.

2. **Monitor for Failed SSH Logon Attempts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "Network" and ProcessCommandLine has "ssh" and LogonResult == "Failed" | project Timestamp, AccountName, DeviceName, LogonType, LogonResult
```
{% endcode %}

_Purpose_: Detect failed SSH logon attempts, which may indicate brute force attacks.

3. **Identify SSH Connections from Unusual IP Addresses**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 22 | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor SSH connections from IP addresses that are not commonly seen.

4. **Detect Use of SSH for File Transfer**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("scp", "rsync") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify SSH-based file transfer commands like `scp` or `rsync`.

5. **Monitor for SSH Key Usage**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ssh" and ProcessCommandLine has ".pem" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect SSH logons using private key files, which could indicate key theft or unauthorized access.

6. **Identify Lateral Movement via SSH in WSL**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ssh" and FolderPath has "C:\\Users\\" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for SSH lateral movement attempts within Windows Subsystem for Linux (WSL).

### <mark style="color:blue;">**5. T1563 - Remote Service Session Hijacking**</mark>

**Objective**: Detect attempts to hijack existing remote sessions, such as RDP, VNC, or SSH sessions, to move laterally without establishing a new connection.&#x20;

1. **Detect Suspicious RDP Shadowing Sessions**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "shadow.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of the `shadow.exe` tool for RDP session hijacking.

2. **Monitor for VNC Session Hijacking Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName has_any ("vncviewer.exe", "winvnc.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect VNC session hijacking attempts using known VNC clients.

3. **Identify SSH Session Hijacking Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ssh" and ProcessCommandLine has_any ("-O control", "-o ProxyCommand") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for SSH commands attempting to hijack existing sessions.

4. **Detect Attempts to Reuse Existing RDP Sessions**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "tscon" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to switch or reuse existing RDP sessions using `tscon`.

5. **Monitor for Suspicious Use of `rdesktop` (Linux)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "rdesktop" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to hijack or reconnect to RDP sessions using `rdesktop`.

6. **Identify Attempts to Hijack Remote Desktop Services**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "qwinsta" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of `qwinsta` to enumerate and hijack remote desktop sessions.

### <mark style="color:blue;">**6. T1091 - Replication Through Removable Media**</mark>

**Objective**: Detect attempts to spread malware or access credentials by replicating data through removable media.&#x20;

1. **Detect Removable Media Insertion**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "RemovableMediaInserted" | project Timestamp, DeviceName, RemovableMediaName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify when removable media is inserted into the system, which could be used for lateral movement.

2. **Monitor for Files Transferred to Removable Media**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "E:\\" | project Timestamp, DeviceName, FileName, FolderPath, FileOperation, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect files being copied to removable media, potentially as part of data exfiltration or spreading malware.

3. **Identify Execution of Files from Removable Media**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FolderPath startswith "E:\\" and ProcessCommandLine has ".exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the execution of files from removable media.

4. **Detect Suspicious Scripts on Removable Media**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "E:\\" and FileExtension in (".vbs", ".bat", ".ps1") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify potentially malicious scripts on removable media.

5. **Monitor for Autorun Configurations on Removable Media**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName == "autorun.inf" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the presence of `autorun.inf` files that could automatically execute malicious content.

6. **Identify Data Transfer to Unusual Removable Media Devices**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "E:\\" and DeviceName has "Unknown" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for data transfers to unrecognized or unusual removable media devices.

### <mark style="color:blue;">**7. T1021.006 - Windows Remote Management (WinRM)**</mark>

**Objective**: Detect attempts to use WinRM for lateral movement, particularly in environments where PowerShell Remoting is used for remote management.&#x20;

1. **Detect WinRM Logon Activity**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "Network" and ProcessCommandLine has "winrm" | project Timestamp, AccountName, DeviceName, LogonType, LogonResult
```
{% endcode %}

_Purpose_: Identify logons that use WinRM for remote management.

2. **Monitor for Use of PowerShell Remoting via WinRM**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "Enter-PSSession" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of PowerShell Remoting, which uses WinRM to execute commands remotely.

3. **Identify Unusual WinRM Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 5985 or RemotePort == 5986 | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor WinRM connections from unusual IP addresses or during off-hours.

4. **Detect Unauthorized WinRM Configurations**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "winrm" and ProcessCommandLine has_any ("set", "config") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to WinRM configurations that could enable lateral movement.

5. **Monitor for Use of `Invoke-Command` via WinRM**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "Invoke-Command" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of `Invoke-Command` to execute PowerShell commands remotely via WinRM.

6. **Identify Suspicious WinRM Logon Failures**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "Network" and ProcessCommandLine has "winrm" and LogonResult == "Failed" | project Timestamp, AccountName, DeviceName, LogonResult
```
{% endcode %}

_Purpose_: Monitor for failed WinRM logon attempts, which may indicate unauthorized access attempts.
