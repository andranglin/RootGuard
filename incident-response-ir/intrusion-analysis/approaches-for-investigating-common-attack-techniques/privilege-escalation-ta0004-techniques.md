---
icon: laptop-code
---

# Privilege Escalation (TA0004) Techniques

## <mark style="color:blue;">Introduction</mark>

Investigating privilege escalation incidents forensically on workstations and server systems is critical in identifying how an attacker or malicious user gained elevated access. Privilege escalation can occur in various ways, such as exploiting system vulnerabilities, misconfigurations, or leveraging stolen credentials.

#### Understanding Privilege Escalation

* **Vertical Escalation:** Attacker gains higher-level privileges (e.g., regular user to administrator).
* **Horizontal Escalation:** Attacker expands access across accounts at the same privilege level.
* **Common Techniques:** Exploiting vulnerabilities, password cracking, manipulating user accounts, token manipulation, etc.

#### Data Collection and Preservation

* **Forensic Imaging:** Create forensic images of affected systems using tools like FTK Imager or dd.
* **Memory Capture:** Use tools like WinPmem or Magnet RAM Capture to capture live memory.
* **Log Collection:** Collect relevant logs, including security logs, system logs, application logs, and audit logs.

#### Initial Analysis and Identification

* **Security Logs Analysis:** Look for anomalous login activities, especially Event IDs 4624 (successful login), 4625 (failed login), and 4672 (special privileges assigned).
* **Account Review:** Examine user accounts for unauthorised creation, modification, or elevation of privileges.
* **System and Application Logs:** Check for logs indicating changes in system settings or application configurations that could lead to privilege escalation.

#### In-Depth Investigation

* **Vulnerability Exploitation:** Identify if any known vulnerabilities have been exploited for privilege escalation. Tools like Nessus or OpenVAS can help retrospectively identify vulnerabilities.
* **Group Policy Analysis:** Review group policies for misconfigurations that may have allowed privilege escalation.
* **File and Registry Analysis:** Look for unauthorised modifications in critical system files and registry entries that could indicate privilege changes.

#### Artifact Analysis

* **Windows Registry:** Investigate keys related to user accounts and privileges.
* **Event Tracing Logs:** Examine ETL files for evidence of privilege escalation activities.
* **Scheduled Tasks:** Check for any scheduled tasks created or modified by unauthorised users.
* **Service Configuration:** Analyse services to see if any have been modified to run with higher privileges.

#### Network Analysis (if applicable)

* Analyse network traffic for signs of lateral movement or external communications that might be related to the privilege escalation.

#### Use of Specialised Forensic Tools

* **Forensic Suites:** Tools like EnCase, X-Ways Forensics, or Autopsy for comprehensive analysis.
* **Windows-specific Tools:** Windows Event Viewer, Sysinternals Suite, AccessChk, and Process Monitor.

#### Documentation and Reporting

* **Detailed Documentation:** Document every step, including tools used, findings, and methodologies.
* **Forensic Report:** Prepare a comprehensive report detailing the privilege escalation incident and its impact.

#### Post-Investigation Actions

* **Remediation and Mitigation:** Implement necessary fixes, security updates, and policy changes.
* **Recovery:** Restore systems and data from backups if necessary.
* **Lessons Learned:** Conduct a review to improve security posture and response strategies.

#### Key Considerations

* **Legal and Compliance:** Ensure all investigative actions comply with legal and organisational guidelines.
* **Chain of Custody:** Maintain a clear chain of custody for all forensic evidence.
* **Confidentiality and Integrity:** Handle all data securely and maintain its integrity.

Each privilege escalation incident is unique and might require a customised approach. Tailor the investigation to the specifics of the case and the environment in which you are operating.

## <mark style="color:blue;">Using KQL to Investigate Privilege Escalation Activities in an Environment Using Defender/Sentinel</mark>

Privilege Escalation techniques allow adversaries to gain higher-level permissions on a system. These elevated privileges may be used to execute malicious actions, access sensitive data, or move laterally across the network.

### <mark style="color:blue;">**1. T1055 - Process Injection**</mark>

**Objective**: Detect attempts to inject code into the address space of another process to gain elevated privileges or evade detection.&#x20;

1. **Detect Remote Thread Injection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify remote thread injection attempts used for privilege escalation.

2. **Monitor for DLL Injection Techniques**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("LoadLibrary", "RtlCreateUserThread", "WriteProcessMemory") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect DLL injection techniques that may be used to gain elevated privileges.

3. **Identify Process Hollowing Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ZwUnmapViewOfSection", "SetThreadContext", "ResumeThread") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for process hollowing attempts where the memory of a legitimate process is replaced with malicious code.

4. **Detect APC Injection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "NtQueueApcThread" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify APC (Asynchronous Procedure Call) injection used for executing code in the context of another process.

5. **Monitor for PowerShell Injection Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "Invoke-Expression" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell commands attempting process injection for privilege escalation.

6. **Identify Shellcode Injection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for shellcode injection techniques.

7. **Detect Process Doppelgänging**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("NtCreateTransaction", "TxF") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify process doppelgänging techniques that exploit NTFS transactions.

8. **Monitor for Windows API Calls Related to Injection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("NtMapViewOfSection", "SetThreadContext", "RtlCreateUserThread") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect Windows API calls commonly used in process injection techniques.

9. **Identify Process Injection via Code Cavitation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ZwMapViewOfSection", "ZwCreateSection", "ZwCreateThreadEx") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for code cavitation, where code is injected into a remote process using lesser-known API functions.

10. **Detect Hijacking of Process Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("Image File Execution Options", "Debugger") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of Image File Execution Options (IFEO) to hijack process execution for privilege escalation.

### <mark style="color:blue;">**2. T1543 - Create or Modify System Process**</mark>

**Objective**: Detect the creation or modification of system processes (e.g., services, daemons) to gain elevated privileges.&#x20;

1. **Detect New Service Creation with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessAccountName == "SYSTEM" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine
```
{% endcode %}

_Purpose_: Identify the creation of new services running with elevated privileges.

2. **Monitor for Modifications to Existing Services**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceModified" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to existing services that may be used for privilege escalation.

3. **Identify Services Configured to Auto Start**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and ServiceStartType == "Auto" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for services configured to start automatically, potentially providing persistence with elevated privileges.

4. **Detect Services Executing Suspicious Commands**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessCommandLine has_any ("powershell.exe", "cmd.exe", "wscript.exe") | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify services executing commands commonly used for malicious activities.

5. **Monitor for Services Running from Non-Standard Locations**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessFolderPath has_not "C:\\Windows\\System32" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect services running executables from unusual or non-standard locations, which may indicate privilege escalation.

6. **Identify Suspicious Service Names or Descriptions**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and (ServiceName has_any ("backdoor", "rat", "trojan") or ServiceDescription has_any ("backdoor", "rat", "trojan")) | project Timestamp, DeviceName, ServiceName, ServiceDescription, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for services with suspicious names or descriptions that may indicate malicious intent.

7. **Detect Service Installation by Non-Admin Accounts**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify services installed by non-administrative accounts.

8. **Monitor for Service Execution Using System Accounts**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessAccountName == "SYSTEM" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine
```
{% endcode %}

_Purpose_: Detect services installed with the SYSTEM account, potentially indicating an attempt to gain SYSTEM-level privileges.

9. **Identify Unusual Service Start Types**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and ServiceStartType in ("Manual", "DelayedAutoStart") | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for services with unusual start types that may indicate malicious persistence mechanisms.

10. **Detect Services Associated with Common Attack Tools**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessCommandLine has_any ("mimikatz", "metasploit", "cobalt strike") | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify services installed with commands associated with common attack tools.

### <mark style="color:blue;">**3. T1068 - Exploitation for Privilege Escalation**</mark>

**Objective**: Detect the exploitation of vulnerabilities that allow an adversary to escalate privileges.&#x20;

1. **Detect Known Exploits for Privilege Escalation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("CVE-2017-0144", "CVE-2018-8453", "CVE-2019-0841") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to exploit known vulnerabilities for privilege escalation.

2. **Monitor for Exploit-Related Processes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("exploit", "overflow", "buffer") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect processes related to exploitation activities.

3. **Identify Unusual Kernel Driver Loads**

{% code overflow="wrap" %}
```cs
DeviceDriverEvents | where DriverFileName has_any ("exploit.sys", "malware.sys") | project Timestamp, DeviceName, DriverFileName, DriverSigned
```
{% endcode %}

_Purpose_: Monitor for the loading of kernel drivers associated with exploitation.

4. **Detect PowerShell Execution of Exploit Code**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Invoke-Exploit", "Invoke-Native") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands executing exploit code.

5. **Monitor for Privilege Escalation via Exploited Services**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceModified" and InitiatingProcessCommandLine has_any ("exploit", "buffer") | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to services that may indicate privilege escalation through exploitation.

6. **Identify Exploit Attempts Targeting System Processes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("lsass.exe", "winlogon.exe") and ProcessCommandLine has_any ("overflow", "exploit") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for exploit attempts targeting critical system processes.

7. **Detect Use of Exploitation Frameworks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("metasploit", "cobalt strike", "empire") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of exploitation frameworks commonly used for privilege escalation.

8. **Monitor for Malicious Use of Debugging Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("windbg.exe", "ntsd.exe", "ollydbg.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of debugging tools that may be used to exploit vulnerabilities.

9. **Identify Vulnerability Scanners Running on High Privileged Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("nmap", "nessus", "openvas") and TokenElevationType == "Full" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for vulnerability scanners running with elevated privileges, potentially used to identify exploitable vulnerabilities.

10. **Detect Attempts to Exploit Privilege Escalation Vulnerabilities via Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any (".ps1", ".vbs", ".bat") and ProcessCommandLine has_any ("exploit", "elevation") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify scripts attempting to exploit privilege escalation vulnerabilities.

### <mark style="color:blue;">**4. T1548 - Abuse Elevation Control Mechanism**</mark>

**Objective**: Detect abuse of elevation control mechanisms (e.g., UAC bypass) to gain elevated privileges.

1. **Detect UAC Bypass via Fodhelper**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "fodhelper.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to bypass User Account Control (UAC) using Fodhelper.

2. **Monitor for UAC Bypass via Event Viewer**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "eventvwr.exe" and ProcessCommandLine has "mmc.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect UAC bypass attempts using the Event Viewer.

3. **Identify UAC Bypass via ComputerDefaults**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ComputerDefaults.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for UAC bypass attempts using ComputerDefaults.

4. **Detect UAC Bypass via SilentCleanup**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "SilentCleanup" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify UAC bypass attempts using the SilentCleanup task.

5. **Monitor for UAC Bypass via sdclt.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "sdclt.exe" and ProcessCommandLine has "Control_RunDLL" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect UAC bypass attempts using sdclt.exe.

6. **Identify UAC Bypass via Registry Key Modification**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for registry key modifications used in UAC bypass attacks.

7. **Detect UAC Bypass via wscript.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wscript.exe" and ProcessCommandLine has_any ("cscript", "vbscript") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify UAC bypass attempts using wscript.exe.

8. **Monitor for UAC Bypass via DllHost.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "dllhost.exe" and ProcessCommandLine has_any ("comsvcs.dll", "mmc.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect UAC bypass attempts using DllHost.exe.

9. **Identify UAC Bypass via Sysprep**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "sysprep.exe" and ProcessCommandLine has "unattend.xml" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for UAC bypass attempts using the Sysprep tool.

10. **Detect UAC Bypass via Task Scheduler**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks" and ProcessCommandLine has "/RL HIGHEST" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify UAC bypass attempts using the Task Scheduler with elevated privileges.

### <mark style="color:blue;">**5. T1134 - Access Token Manipulation**</mark>

**Objective**: Detect manipulation of access tokens to impersonate other users or escalate privileges.&#x20;

1. **Detect Token Impersonation Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ImpersonateLoggedOnUser", "DuplicateTokenEx", "SetThreadToken") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to impersonate another user's token.

2. **Monitor for Use of Mimikatz to Steal Tokens**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("mimikatz", "sekurlsa::pth", "sekurlsa::tspkg") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of Mimikatz to steal tokens for privilege escalation.

3. **Identify Process Privilege Elevation via Token Duplication**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("DuplicateTokenEx", "CreateProcessWithTokenW") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for token duplication attempts that may indicate privilege escalation.

4. **Detect Manipulation of Tokens via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Invoke-TokenManipulation", "Get-TokenPrivs") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands attempting token manipulation.

5. **Monitor for Token Privileges Adjustments**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("AdjustTokenPrivileges", "SetTokenInformation") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect adjustments to token privileges that may be used to gain elevated access.

6. **Identify Token Manipulation Using WinAPI Calls**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("OpenProcessToken", "SetTokenInformation", "AdjustTokenPrivileges") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for attempts to manipulate access tokens using Windows API calls.

7. **Detect Token Manipulation by Non-Admin Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("DuplicateTokenEx", "ImpersonateLoggedOnUser") and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify token manipulation attempts by non-administrative users.

8. **Monitor for Process Creation Using Stolen Tokens**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "CreateProcessWithTokenW" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the creation of processes using stolen or duplicated tokens.

9. **Identify Suspicious Token Privilege Enabling**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("SeDebugPrivilege", "SeImpersonatePrivilege") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for suspicious enabling of token privileges that may indicate an attempt to escalate privileges.

10. **Detect Token Manipulation Using Third-Party Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("incognito", "privilege escalation") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify token manipulation attempts using third-party tools.

### <mark style="color:blue;">**6. T1078 - Valid Accounts**</mark>

**Objective**: Detect the use of valid accounts to gain elevated privileges.

1. **Detect Use of Default or Well-Known Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountDomain == "NT AUTHORITY" or AccountDomain == "BUILTIN" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Identify logons using default or well-known accounts that may be used for privilege escalation.

2. **Monitor for Unusual Account Activity by Admin Users**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountDomain != "NT AUTHORITY" and AccountDomain != "BUILTIN" | where AccountName endswith "admin" or AccountName endswith "administrator" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Detect unusual activity by accounts with administrative privileges.

3. **Identify Logons Using Service Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName startswith "svc_" or AccountName endswith "_svc" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Monitor for logons using service accounts that may indicate privilege escalation.

4. **Detect Lateral Movement Using Valid Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" or LogonType == "Network" | where AccountName has_any ("admin", "administrator", "svc_") | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Identify lateral movement attempts using valid accounts.

5. **Monitor for Logon Attempts by Non-Privileged Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName has_not_any ("admin", "administrator", "svc_") | where LogonType == "Interactive" or LogonType == "RemoteInteractive" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Detect logon attempts by non-privileged accounts that may be attempting privilege escalation.

6. **Identify Attempted Use of Disabled or Expired Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountEnabled == "false" or AccountExpires < now() | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Monitor for attempts to use disabled or expired accounts.

7. **Detect Suspicious Use of Local Administrator Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName == "Administrator" and AccountDomain == "DeviceName" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Identify suspicious logon attempts using local Administrator accounts.

8. **Monitor for Account Usage Outside of Normal Hours**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonTime between (datetime(22:00:00) .. datetime(06:00:00)) | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Detect account usage outside of normal business hours that may indicate privilege escalation.

9. **Identify Use of Stolen Credentials**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" and AccountName has_any ("admin", "administrator", "svc_") | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Monitor for failed logon attempts that may indicate the use of stolen credentials.

10. **Detect Use of Valid Accounts by Non-Standard Processes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessAccountName has_any ("admin", "administrator", "svc_") | where ProcessCommandLine has_not_any ("cmd.exe", "powershell.exe", "explorer.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of valid accounts by processes that are not typically associated with administrative tasks.

### <mark style="color:blue;">**7. T1547 - Boot or Logon Autostart Execution**</mark>

**Objective**: Detect mechanisms that automatically execute code with elevated privileges upon boot or user logon.&#x20;

1. **Detect Modifications to Registry Run Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to registry keys that execute programs at startup, which may be used for privilege escalation.

2. **Monitor for New Entries in the Startup Folder**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect new files added to the Startup folder that may be used to execute code with elevated privileges.

3. **Identify Modifications to Winlogon Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for changes to Winlogon keys that may indicate privilege escalation attempts.

4. **Detect Creation of New Services Set to Auto Start**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and ServiceStartType == "Auto" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of new services configured to start automatically, potentially providing elevated privileges.

5. **Monitor for New Logon Scripts**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "Scripts\\Logon" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the creation of new logon scripts that may be used for privilege escalation.

6. **Identify Modifications to the Shell Registry Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for changes to the Shell registry key that can be used to persist elevated privileges.

7. **Detect New DLLs Added to Startup Folders**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileExtension == ".dll" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify DLL files added to startup folders for privilege escalation.

8. **Monitor for Creation of WMI Event Subscriptions**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "EventFilter" and ProcessCommandLine has "create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the creation of WMI event subscriptions that can be used for persistent privilege escalation.

9. **Identify Modifications to the Userinit Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for changes to the Userinit registry key, which can be used to launch programs with elevated privileges at logon.

10. **Detect Creation of Hidden Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" and ProcessCommandLine has "/RU SYSTEM" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of hidden or system-level scheduled tasks that may be used to persist elevated privileges.

### <mark style="color:blue;">**8. T1055.001 - Dynamic-link Library Injection**</mark>

**Objective**: Detect DLL injection techniques used to execute code in the context of another process, potentially with elevated privileges.&#x20;

1. **Detect DLL Injection Using LoadLibrary**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "LoadLibrary" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of the LoadLibrary API for DLL injection.

2. **Monitor for DLL Injection Using CreateRemoteThread**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "CreateRemoteThread" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to inject DLLs using the CreateRemoteThread API.

3. **Identify DLL Injection via NtMapViewOfSection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "NtMapViewOfSection" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DLL injection attempts using the NtMapViewOfSection API.

4. **Detect DLL Injection via AppInit\_DLLs**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify modifications to the AppInit\_DLLs registry key, which can be used for DLL injection.

5. **Monitor for DLL Injection via SetWindowsHookEx**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "SetWindowsHookEx" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to inject DLLs using the SetWindowsHookEx API.

6. **Identify DLL Injection via RtlCreateUserThread**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "RtlCreateUserThread" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DLL injection attempts using the RtlCreateUserThread API.

7. **Detect DLL Injection Using CreateProcessWithTokenW**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "CreateProcessWithTokenW" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify DLL injection attempts using the CreateProcessWithTokenW API.

8. **Monitor for DLL Injection via Code Cavitation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ZwMapViewOfSection" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect code cavitation techniques where DLLs are injected using lesser-known API functions.

9. **Identify DLL Injection via Process Hollowing**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ZwUnmapViewOfSection", "NtCreateSection", "SetThreadContext") and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DLL injection attempts using process hollowing techniques.

10. **Detect DLL Injection via Malicious Services**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessCommandLine has ".dll" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify DLL injection attempts via malicious services.
