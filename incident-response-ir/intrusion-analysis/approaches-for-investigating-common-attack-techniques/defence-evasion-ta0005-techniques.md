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

# Defence Evasion (TA0005) Techniques

### <mark style="color:blue;">Introduction</mark>

Forensically investigating defence evasion involves understanding and identifying the methods used by attackers to avoid detection and bypass security measures on workstations and server systems. Defence evasion is a critical tactic in the MITRE ATT\&CK framework, and it includes techniques like disabling security software, deleting logs, obfuscation, rootkits, privilege escalation, and more.

#### Understanding Defence Evasion Techniques

* **Disabling Security Software:** Check for evidence of disabled or tampered antivirus, firewalls, or other security tools.
* **Log Tampering:** Look for signs of altered or deleted logs.
* **Obfuscation and Encoding:** Identify the use of obfuscation in scripts and commands to evade detection.
* **Rootkits:** Search for evidence of rootkits that hide malicious activity.
* **File Deletion and Hiding:** Investigate techniques to hide or delete files.
* **Privilege Escalation:** Ascertain if elevation of privileges was part of the evasion strategy.

#### Data Collection and Preservation

* **Forensic Imaging:** Create complete images of affected systems using tools like FTK Imager or dd.
* **Memory Capture:** Use tools like WinPmem or Magnet RAM Capture for memory imaging.
* **Log Collection:** Gather all relevant logs, including security, system, and application logs.

#### Investigation of Security Software Tampering

* **Antivirus and EDR Logs:** Check the logs of antivirus or EDR solutions for signs of deactivation or bypass.
* **Firewall Configuration:** Review firewall settings for unauthorised changes.
* **Windows Defender:** Look for changes in Windows Defender settings, especially using PowerShell commands or Group Policy modifications.

#### Log Analysis

* **Event Logs:** Examine Windows Event Logs for evidence of cleared logs (Event ID 1102 for Windows security log clearance).
* **SIEM Systems:** If a SIEM system is in use, analyse it for gaps or inconsistencies in log data.
* **Security Log Review:** Examine logs for signs of clearing or tampering (e.g., Windows Event ID 1102 indicates security log clearance).
* **Audit Log Settings:** Verify if audit settings were altered to evade detection.
* **File Access Logs:** Check logs for access to sensitive files or logs by unauthorised users or processes.

#### Investigating Obfuscation Techniques

* &#x20;**Script Analysis:** Examine any found scripts for obfuscation techniques like base64 encoding, concatenation, or use of uncommon scripting languages.
* **Command-Line Analysis:** Review command-line history for obfuscated or encoded commands.

#### Rootkit Detection

* **Rootkit Scanners:** Utilize rootkit detection tools like GMER or Rootkit Revealer.
* **Memory Analysis:** Analyse system memory for signs of kernel-level rootkits.

#### Analysis of File and Directory Changes

* **File Integrity Monitoring Tools:** Review reports from file integrity monitoring solutions.
* **Recycle Bin Analysis:** Check the Recycle Bin for recently deleted files.
* **Alternate Data Streams:** Search for hidden data in NTFS Alternate Data Streams.

#### Network Traffic Analysis

* **Network Monitoring Tools:** Use tools like Wireshark or tcpdump to analyse network traffic for signs of data exfiltration or C2 communication.
* **DNS Query Logs:** Review DNS logs for unusual or repeated queries, which could indicate covert channels.

#### Use of Specialised Forensic Tools

* **Forensic Suites:** Tools like EnCase, AXIOM Cyber, Binalyze-Air or Autopsy for comprehensive system analysis.
* **Sysinternals Suite:** Tools like Process Explorer, Autoruns, and TCPView for detailed system analysis.

#### Documentation and Reporting

* **Detailed Documentation:** Keep a detailed record of all findings, tools used, and methods applied.
* **Forensic Report:** Prepare a comprehensive report detailing the evasion techniques identified and their impact.

#### Post-Investigation Actions

* **Remediation and Mitigation:** Implement security measures to counter the identified evasion techniques.
* **Recovery:** Restore systems from clean backups if necessary.
* **Security Posture Enhancement:** Update security policies and tools based on findings.

#### Key Considerations

* **Chain of Custody:** Maintain an accurate chain of custody for all evidence.
* **Legal and Compliance:** Ensure compliance with legal and organisational guidelines during the investigation.
* **Confidentiality and Integrity:** Maintain confidentiality and integrity of data throughout the investigation process.

Each case of defence evasion can be unique, requiring a tailored approach depending on the specifics of the incident and the environment.

### <mark style="color:blue;">Using KQL to Investigate Privilege Escalation Activities in an Environment Using Defender/Sentinel</mark>

Defence Evasion techniques allow adversaries to avoid detection throughout their compromise activities.

### <mark style="color:blue;">**1. T1027 - Obfuscated Files or Information**</mark>

**Objective**: Detect the use of obfuscation techniques to hide malicious code or evade detection.

1. **Detect Obfuscated PowerShell Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine matches regex @"-e\s*[A-Za-z0-9+/=]+" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify obfuscated PowerShell commands using encoded scripts.

2. **Monitor for Suspicious Command Line Encodings**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine matches regex @"(?i)-encodedcommand\s+[A-Za-z0-9+/=]{50,}" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect suspicious command-line encodings that may indicate obfuscation.

3. **Identify Obfuscated Batch Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "cmd.exe" and ProcessCommandLine has_any ("^", "%") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for batch scripts with obfuscated commands.

4. **Detect Obfuscated JavaScript Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension == ".js" and FileContent contains "eval" and FileContent matches regex @"(?i)base64" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

_Purpose_: Identify obfuscated JavaScript files that may contain hidden malicious code.

5. **Monitor for Obfuscated Scripts in Office Macros**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessFileName in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") and ProcessCommandLine matches regex @"(?i)base64" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect obfuscated scripts embedded in Office macros.

6. **Identify Suspicious Use of XOR Encoding**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "xor" and ProcessCommandLine has_any ("powershell", "cmd.exe", "wscript.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of XOR encoding in commands, which may be used to obfuscate malicious actions.

7. **Detect Obfuscated PowerShell Commands with Special Characters**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine contains_any ("$()", "`", "%%", "^") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands using special characters for obfuscation.

8. **Monitor for Use of Obfuscation Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ConfuserEx", "obfuscator", "Dotfuscator") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of known obfuscation tools that may be used to evade detection.

9. **Identify Scripts Using Base64 Encoding**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("base64", "decode") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for scripts using Base64 encoding to obscure their content.

10. **Detect Obfuscated Malware Executables**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension == ".exe" and FileName matches regex @"^[A-Fa-f0-9]{32}$" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

_Purpose_: Identify obfuscated malware executables with hexadecimal filenames.

### <mark style="color:blue;">**2. T1070 - Indicator Removal on Host**</mark>

**Objective**: Detect attempts to delete or alter artifacts to remove evidence of an intrusion.

1. **Detect Clearing of Windows Event Logs**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wevtutil" and ProcessCommandLine has "cl" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to clear Windows event logs using `wevtutil`.

2. **Monitor for Deletion of Prefetch Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Prefetch" and FileOperation == "Delete" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect deletion of prefetch files which may be used to cover tracks.

3. **Identify Clearing of Security Event Logs**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Clear-EventLog" and ProcessCommandLine has "Security" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for clearing of security event logs using PowerShell.

4. **Detect Attempts to Delete Log Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("\\Logs", "\\LogFiles") and FileOperation == "Delete" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to delete log files, which could indicate a cover-up.

5. **Monitor for Use of `auditpol` to Disable Logging**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "auditpol" and ProcessCommandLine has "/disable" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to disable audit logging using `auditpol`.

6. **Identify Tampering with Windows Defender Logs**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History" and FileOperation == "Delete" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for tampering with Windows Defender logs.

7. **Detect Disabling of Windows Event Logging Services**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceStopped" and ServiceName == "EventLog" | project Timestamp, DeviceName, ServiceName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to disable Windows Event Logging services.

8. **Monitor for Changes to Windows Firewall Logs**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "C:\\Windows\\System32\\LogFiles\\Firewall" and FileOperation == "Delete" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect deletion or tampering with Windows Firewall logs.

9. **Identify Deletion of Registry Keys Related to Logging**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\System\\CurrentControlSet\\Services\\EventLog" and RegistryValueName == "Start" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for deletion of registry keys associated with logging.

10. **Detect Modifications to Log Retention Policies**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\System\\CurrentControlSet\\Services\\EventLog" and RegistryValueName == "Retention" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to log retention policies that may be aimed at reducing forensic visibility.

### <mark style="color:blue;">**3. T1112 - Modify Registry**</mark>

**Objective**: Detect unauthorized modifications to the Windows Registry that may be used to evade detection.&#x20;

1. **Detect Modifications to Security-Related Registry Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for modifications to registry keys related to security settings.

2. **Identify Changes to Userinit Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to the Userinit registry key that could be used for persistence and evasion.

3. **Monitor for Disabling of Windows Defender via Registry**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Policies\\Microsoft\\Windows Defender" and RegistryValueName == "DisableAntiSpyware" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify registry changes that disable Windows Defender.

4. **Detect Changes to UAC Settings in Registry**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" and RegistryValueName == "EnableLUA" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for modifications to User Account Control (UAC) settings.

5. **Identify Modifications to Auto-Run Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect changes to auto-run registry keys that may be used for persistence and evasion.

6. **Monitor for Changes to Windows Firewall Rules via Registry**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" and RegistryValueName == "EnableFirewall" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify registry modifications that disable or weaken Windows Firewall rules.

7. **Detect Changes to Registry Keys Associated with LSA Protection**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\System\\CurrentControlSet\\Control\\Lsa" and RegistryValueName == "RunAsPPL" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for changes to LSA (Local Security Authority) protection settings.

8. **Identify Tampering with Logging Settings in Registry**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Security" and RegistryValueName == "MaxSize" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect tampering with log size limits in the registry.

9. **Monitor for Changes to SMB Signing Settings in Registry**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" and RegistryValueName == "EnableSecuritySignature" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to SMB signing settings that could be used to weaken network security.

10. **Detect Modifications to Registry Keys Related to Credential Storage**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" and RegistryValueName == "CachedLogonsCount" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for changes to registry keys that affect the storage of cached credentials.

### <mark style="color:blue;">**4. T1218 - System Binary Proxy Execution**</mark>

**Objective**: Detect the use of trusted system binaries to execute malicious code and evade detection.&#x20;

1. **Detect Use of mshta.exe for Malicious Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mshta.exe" and ProcessCommandLine has_any (".vbs", ".js", "http") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of mshta.exe to execute scripts from external sources.

2. **Monitor for Execution via rundll32.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "rundll32.exe" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountNam
```
{% endcode %}

_Purpose_: Detect the use of rundll32.exe to execute DLLs.

3. **Identify Execution of Suspicious Scripts via wscript.exe or cscript.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("wscript.exe", "cscript.exe") and ProcessCommandLine has_any (".vbs", ".js") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the execution of scripts via wscript.exe or cscript.exe.

4. **Detect Use of regsvr32.exe to Execute Remote Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and ProcessCommandLine has "http" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of regsvr32.exe to execute remote scripts.

5. **Monitor for Execution via cmd.exe or powershell.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("cmd.exe", "powershell.exe") and ProcessCommandLine has_any ("wget", "curl", "Invoke-WebRequest") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

{% code overflow="wrap" %}
```
Purpose: Detect the use of cmd.exe or powershell.exe to download and execute content from the web.
```
{% endcode %}

6\. **Identify Use of bitsadmin.exe for File Transfers**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "bitsadmin.exe" and ProcessCommandLine has_any ("Transfer", "Upload", "Download") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

```
Purpose: Monitor for the use of bitsadmin.exe to transfer files.
```

7\. **Detect Use of control.exe to Execute Malicious Content**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "control.exe" and ProcessCommandLine has_any ("msc", ".cpl") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of control.exe to execute control panel items maliciously.

8. **Monitor for Execution of Malicious Content via odbcconf.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "odbcconf.exe" and ProcessCommandLine has "/S" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of odbcconf.exe to execute ODBC configuration scripts.

9. **Identify Malicious Use of iexpress.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "iexpress.exe" and ProcessCommandLine has_any ("SED", "package") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of iexpress.exe to create or execute malicious self-extracting packages.

10. **Detect Execution of Malicious Macros via msiexec.exe**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "msiexec.exe" and ProcessCommandLine has "/q" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of msiexec.exe to execute malicious MSI files silently.

### <mark style="color:blue;">**5. T1036 - Masquerading**</mark>

**Objective**: Detect attempts to rename files or use file names that mimic legitimate files to evade detection.&#x20;

1. **Detect Processes Running with Suspicious File Names**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName has_any ("explorer.exe", "svchost.exe", "winlogon.exe") and FolderPath has_not "C:\\Windows\\System32" | project Timestamp, DeviceName, ProcessCommandLine, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes running with common Windows file names from non-standard locations.

2. **Monitor for Files Created with System File Names**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has_any ("svchost.exe", "taskhost.exe", "lsass.exe") and FolderPath has_not "C:\\Windows\\System32" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect creation of files with system file names in unusual directories.

3. **Identify Suspicious Use of Extensionless Executables**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName has_not ".exe" and ProcessCommandLine has_any ("powershell", "cmd", "wscript") | project Timestamp, DeviceName, ProcessCommandLine, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for execution of extensionless files that may be used to hide malicious activity.

4. **Detect Renaming of Known Tools to Bypass Detection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName has_any ("notepad.exe", "calc.exe") and ProcessCommandLine has_any ("mimikatz", "nc.exe") | project Timestamp, DeviceName, ProcessCommandLine, FileName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the renaming of known hacking tools to legitimate Windows file names.

5. **Monitor for Use of Hidden Files and Directories**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "C:\\ProgramData" and FileName startswith "." | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect creation or use of hidden files and directories.

6. **Identify Executables Using Double File Extensions**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith (".exe.txt", ".doc.exe", ".pdf.exe") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for files using double extensions to masquerade as non-executable files.

7. **Detect Execution of Renamed Windows Utilities**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("cmd.exe", "powershell.exe", "rundll32.exe") and ProcessCommandLine has_any ("svchost", "lsass", "taskmgr") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the execution of renamed Windows utilities.

8. **Monitor for DLLs Masquerading as System Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension == ".dll" and FileName has_any ("shell32.dll", "kernel32.dll") and FolderPath has_not "C:\\Windows\\System32" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect DLLs that are masquerading as legitimate system files.

9. **Identify Renaming of Malicious Scripts to Safe Extensions**

```cs
DeviceFileEvents | where FileExtension in (".txt", ".log") and FileName has_any (".ps1", ".vbs", ".js") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```

_Purpose_: Monitor for the renaming of malicious scripts to file types that are generally considered safe.

10. **Detect Creation of Shortcut Files with Misleading Icons**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension == ".lnk" and FileName has_any ("notepad.lnk", "cmd.lnk", "explorer.lnk") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of shortcut files that are designed to mislead users into executing malicious content.

### <mark style="color:blue;">**6. T1078 - Valid Accounts**</mark>

**Objective**: Detect the use of valid accounts to avoid detection or gain unauthorized access.&#x20;

1. **Detect Unusual Logon Activity for Privileged Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName endswith "admin" or AccountName endswith "administrator" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Monitor for unusual logon activity involving privileged accounts.

2. **Identify Logons Using Service Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName startswith "svc_" or AccountName endswith "_svc" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Detect logons using service accounts that may be used to evade detection.

3. **Monitor for Use of Default or Well-Known Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName in ("Administrator", "Guest", "DefaultAccount") | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Identify the use of default or well-known accounts.

4. **Detect Logons During Unusual Hours**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonTime between (datetime(22:00:00) .. datetime(06:00:00)) | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Monitor for logon activity outside of normal business hours that may indicate unauthorized access.

5. **Identify Logons Using Expired or Disabled Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountEnabled == "false" or AccountExpires < now() | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Detect attempts to use expired or disabled accounts.

6. **Monitor for Remote Logons Using Valid Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" or LogonType == "Network" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Identify remote logons using valid accounts that may be part of lateral movement.

7. **Detect Sudden Changes in Privileges for Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where PrivilegeElevated == "true" and AccountName has_not_any ("admin", "administrator") | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Monitor for sudden changes in privileges for non-admin accounts.

8. **Identify Use of Stolen Credentials**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" and AccountName has_any ("admin", "administrator", "svc_") | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Detect failed logon attempts that may indicate the use of stolen credentials.

9. **Monitor for Suspicious Logons Using Valid Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName has_any ("admin", "administrator", "svc_") and LogonType == "Interactive" | project Timestamp, AccountName, AccountDomain, LogonType, DeviceName
```
{% endcode %}

_Purpose_: Identify suspicious logons using valid accounts that typically do not log on interactively.

10. **Detect Use of Valid Accounts for Unusual Processes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessAccountName has_any ("admin", "administrator", "svc_") and ProcessCommandLine has_not_any ("cmd.exe", "powershell.exe", "explorer.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of valid accounts by processes that are not typically associated with administrative tasks.

### <mark style="color:blue;">**7. T1202 - Indirect Command Execution**</mark>

**Objective**: Detect indirect methods of command execution, such as using legitimate tools or services, to evade detection.&#x20;

1. **Detect Execution via Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName`
```
{% endcode %}

_Purpose_: Identify the creation of scheduled tasks for indirect command execution.

2. **Monitor for Execution via Registry Auto-Run Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect execution of commands via registry auto-run keys.

3. **Identify Commands Executed via WMI**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has_any ("process call create", "path win32_process") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for commands executed via Windows Management Instrumentation (WMI).

4. **Detect Indirect Execution via COM Object Hijacking**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "regsvr32.exe" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify indirect command execution via COM object hijacking.

5. **Monitor for Execution via Service Binary**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "sc config" and ProcessCommandLine has "binpath=" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modification of service binaries for indirect command execution.

6. **Identify Execution via Task Scheduler**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks" and ProcessCommandLine has_any ("/TN", "/TR", "/SC") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the creation of scheduled tasks that execute commands indirectly.

7. **Detect Execution via Office Macros**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") and ProcessCommandLine has "macro" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify command execution through Office macros.

8. **Monitor for Execution via Remote Desktop Services**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Detect command execution through Remote Desktop Services.

9. **Identify Execution via Group Policy Objects (GPOs)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "gpo.ps1" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for commands executed via GPO scripts.

10. **Detect Execution via Software Deployment Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ccmexec.exe", "msiexec.exe") and ProcessCommandLine has "/i" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify command execution using software deployment tools

### <mark style="color:blue;">**8. T1497 - Virtualization/Sandbox Evasion**</mark>

**Objective**: Detect techniques used to evade detection in virtualized or sandboxed environments.&#x20;

1. **Detect Queries for Virtual Machine Artifacts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("vmware", "VirtualBox", "Hyper-V", "vbox") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes querying for virtualization-related artifacts.

2. **Monitor for Use of CPUID Instruction**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "cpuid" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of the CPUID instruction to identify virtualization.

3. **Identify Execution of Known Sandbox Detection Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("sandbox", "unpack", "vm") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for execution of tools designed to detect sandboxes or virtual environments.

4. **Detect Time Delay Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("sleep", "timeout") and ProcessCommandLine matches regex @"\d{5,}" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes that include long time delays to evade sandbox detection.

5. **Monitor for Use of Anti-Debugging Techniques**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("IsDebuggerPresent", "CheckRemoteDebuggerPresent") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect anti-debugging techniques used to evade detection in analysis environments.

6. **Identify Processes Checking for Mouse or Keyboard Input**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("GetAsyncKeyState", "GetCursorPos") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for processes that check for user input to determine if they are running in a sandbox.

7. **Detect Processes Checking for Sandbox Registry Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\System\\CurrentControlSet\\Services\\Disk\\Enum", "HKLM\\Software\\VMware, Inc.") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes querying for registry keys associated with virtualization.

8. **Monitor for Network Artifacts of Virtualization**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("192.168.56.1", "192.168.1.1", "10.0.2.15") | project Timestamp, DeviceName, RemoteIP, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect network traffic indicative of virtualized environments.

9. **Identify Processes Checking for Virtualized CPU Features**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("inl %ebx", "mov %ecx, %eax") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for low-level CPU instructions that may be used to detect virtualization.

10. **Detect Processes Attempting to Disable Virtualization Detection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("vmmemctl", "vmxnet3", "vmtoolsd") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes attempting to disable or interfere with virtualization detection mechanisms.
