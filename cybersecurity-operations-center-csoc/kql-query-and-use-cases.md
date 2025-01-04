---
icon: laptop-code
---

# KQL Query and Use Cases

## <mark style="color:blue;">1. Reconnaissance (TA0043)</mark>

**Sub-technique: T1595.001 - Scanning IP Blocks**

**Objective**: Detect network scanning activities indicative of reconnaissance.&#x20;

1. **Detect Multiple Ports Scanned from a Single IP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | summarize port_count=count() by RemoteIP, LocalPort | where port_count > 20
```
{% endcode %}

**Purpose**: Identify IP addresses scanning multiple ports.

2. **Identify Rapid Scanning Behaviour**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP != "127.0.0.1" | summarize time_diff=min(TimeGenerated), count() by RemoteIP, LocalPort | where count_ > 50
```
{% endcode %}

**Purpose**: Detect scanning activity that occurs in a short time span.

3. **Suspicious Network Scanning Patterns**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where LocalPort in (22, 23, 80, 443, 3389) | summarize count() by RemoteIP, LocalIP | where count() > 10`
```
{% endcode %}

**Purpose**: Detect scanning on commonly targeted ports.

4. **Identify Outbound Port Scanning**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where InitiatingProcessFileName == "nmap.exe" | project Timestamp, DeviceName, RemoteIP, LocalPort
```
{% endcode %}

**Purpose**: Detect known scanning tools like Nmap.

5. **Multiple Failed Connection Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "ConnectionFailed" | summarize count() by RemoteIP, LocalIP | where count() > 100
```
{% endcode %}

**Purpose**: Identify failed connections that could indicate scanning.

6. **Identify ICMP Echo Requests (Ping Sweeps)**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol == "ICMP" | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Detect ICMP ping sweeps across multiple IP addresses.

7. **Scan for SMB Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where LocalPort == 445 | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

**Purpose**: Identify scanning activity targeting SMB shares.

8. **HTTP GET Request Flooding**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where LocalPort == 80 and ActionType == "ConnectionSuccess" | summarize count() by RemoteIP, LocalIP | where count() > 100
```
{% endcode %}

**Purpose**: Detect flooding of HTTP GET requests from a single IP.

9. **Identify DNS Query Flooding**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 and ActionType == "Query" | summarize count() by RemoteIP | where count() > 200
```
{% endcode %}

**Purpose**: Detect excessive DNS queries that may indicate scanning.

10. **High Number of SYN Packets**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "SYN" | summarize count() by RemoteIP | where count() > 500
```
{% endcode %}

**Purpose**: Detect a high volume of SYN packets, which could indicate a SYN flood or scanning.

## <mark style="color:blue;">2. Initial Access (TA0001)</mark>

**Sub-technique: T1078.001 - Default Accounts**

**Objective**: Detect unauthorized access using default accounts.&#x20;

1. **Default Account Logins**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("Administrator", "Guest", "root") | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

**Purpose**: Monitor login events using default accounts.

2. **Detect Administrator Account Usage**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName == "Administrator" | summarize count() by DeviceName, LogonTime | where count() > 1
```
{% endcode %}

**Purpose**: Identify unusual usage of the Administrator account.

3. **Guest Account Logins**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName == "Guest" | summarize count() by DeviceName, LogonTime
```
{% endcode %}

**Purpose**: Detect any use of the Guest account.

4. **Multiple Failed Login Attempts for Default Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("Administrator", "Guest", "root") and LogonResult == "Failed" | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Identify failed login attempts for default accounts.

5. **Detect Unauthorized Access Attempts to Default Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("Administrator", "Guest") and LogonType != "Local" | summarize count() by TargetUserName, DeviceName, LogonType
```
{% endcode %}

**Purpose**: Detect remote access attempts to default accounts.

6. **Logins from Multiple IPs for Default Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("Administrator", "Guest") | summarize count() by TargetUserName, IPAddress | where count() > 1
```
{% endcode %}

**Purpose**: Identify default account logins from multiple IPs.

7. **Identify Default Accounts with Elevated Privileges**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("Administrator", "Guest") | summarize Privileges = max(TokenElevationType) by TargetUserName
```
{% endcode %}

**Purpose**: Monitor default accounts for elevation to administrative privileges.

8. **Detect Default Account Creation**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "NewUserCreated" and TargetUserName in ("Administrator", "Guest") | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Identify the creation of default accounts.

9. **Detect Changes to Default Account Permissions**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "UserAccountControlChanged" and TargetUserName in ("Administrator", "Guest") | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Monitor for permission changes to default accounts.

10. **Detect Default Account Logins During Off-Hours**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("Administrator", "Guest") and hour(LogonTime) < 6 or hour(LogonTime) > 18 | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

**Purpose**: Identify off-hour logins using default accounts.

## <mark style="color:blue;">3. Execution (TA0002)</mark>

**Sub-technique: T1059.001 - PowerShell**

**Objective**: Detect malicious PowerShell script execution.&#x20;

1. **Detect PowerShell Script Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify PowerShell script execution.

2. **Detect Obfuscated PowerShell Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine matches regex "(?i)[^a-zA-Z0-9\s]" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect obfuscated PowerShell commands.

3. **PowerShell Download and Execute**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Invoke-WebRequest" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify PowerShell commands downloading and executing content.

4. **Detect PowerShell Executed from Suspicious Directories**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine matches regex "C:\\Users\\[^\\]+\\AppData\\Local\\Temp" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect PowerShell execution from temporary directories.

5. **Detect PowerShell Encoded Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "EncodedCommand" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify PowerShell commands executed with encoded strings.

6. **Monitor PowerShell for Command Line Length**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and strlen(ProcessCommandLine) > 1000 | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect long command-line executions that could indicate complex scripts.

7. **PowerShell Execution by Non-Admin Users**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor PowerShell usage by non-administrative users.

8. **PowerShell Process Chaining**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("cmd.exe", "wscript.exe") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect PowerShell chained with other interpreters.

9. **Detect PowerShell Execution via Macro**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "WINWORD.EXE" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify PowerShell executed from Microsoft Word macros.

10. **Monitor PowerShell Remoting**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "Enter-PSSession" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect the use of PowerShell Remoting.

## <mark style="color:blue;">4. Persistence (TA0003)</mark>

**Sub-technique: T1547.001 - Registry Run Keys / Startup Folder**

**Objective**: Detect persistence mechanisms using registry run keys or startup folders.&#x20;

1. **Registry Run Key Modifications**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("Run", "RunOnce", "Startup") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

**Purpose**: Detect modifications to registry run keys.

2. **Startup Folder File Additions**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Monitor new files added to the startup folder.

3. **Detect Registry Changes for Auto-Start Programs**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

**Purpose**: Monitor changes to registry keys that control auto-start programs.

4. **Monitor for Suspicious StartUp Folder Activity**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Detect suspicious file creation in the startup folder.

5. **Detect DLLs Added to Startup**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileExtension == ".dll" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Identify DLL files added to startup folders.

6. **Registry Persistence via RunOnce Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "RunOnce" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

**Purpose**: Monitor the RunOnce registry key for persistence.

7. **Detect Hidden Files in Startup Folder**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileAttributes has "Hidden" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Identify hidden files in startup folders.

8. **Monitor Registry Modifications by Non-Admins**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("Run", "RunOnce", "Startup") and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, RegistryKey, RegistryValueName
```
{% endcode %}

**Purpose**: Detect registry modifications by non-administrative users.

9. **Detect Changes to Windows Startup Programs**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

**Purpose**: Monitor for changes to startup programs in the registry.

10. **Monitor Startup Folder for Script Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileExtension in (".bat", ".vbs", ".ps1") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Detect script files added to startup folders.

## <mark style="color:blue;">5. Privilege Escalation (TA0004)</mark>

**Sub-technique: T1068 - Exploitation for Privilege Escalation**

**Objective**: Detect exploitation attempts to gain higher privileges on the system.&#x20;

1. **Processes Running with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ElevatedToken == "True" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify processes running with elevated privileges.

2. **Known Exploitation Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("mimikatz", "procdump", "secretsdump") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect known exploitation tools.

3. **New Driver Installation**

{% code overflow="wrap" %}
```cs
DeviceDriverEvents | where ActionType == "DriverInstalled" | project Timestamp, DeviceName, DriverName, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Monitor new driver installations that may be used for privilege escalation.

4. **Kernel Module Load Events**

{% code overflow="wrap" %}
```cs
DeviceImageLoadEvents | where FileName endswith ".sys" | project Timestamp, DeviceName, FileName, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Detect loading of new kernel modules.

5. **Exploitation via Process Injection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessCommandLine has_any ("inject", "reflective") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify process injection attempts.

6. **Detect UAC Bypass Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "bypassuac" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Monitor attempts to bypass User Account Control.

7. **Privilege Escalation via Service Creation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "sc create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Detect service creation attempts that may be used for privilege escalation.

8. **Detecting Usage of Exploit Mitigation Bypass**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("exploit", "mitigation", "bypass") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify attempts to bypass exploit mitigation controls.

9. **Privilege Escalation Using Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor for scheduled tasks used for privilege escalation.

10. **Detect Privilege Escalation via Windows Installer**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "msiexec" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify privilege escalation attempts using Windows Installer.

## <mark style="color:blue;">6. Defence Evasion (TA0005)</mark>

**Sub-technique: T1070.001 - Clear Windows Event Logs**

**Objective**: Detect attempts to clear event logs to evade detection.&#x20;

1. **Detect Security Log Cleared Events**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "SecurityLogCleared" | project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify when security logs are cleared.

2. **Detect System Log Cleared Events**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "SystemLogCleared" | project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Monitor for system log clearing.

3. **Detect Application Log Cleared Events**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "ApplicationLogCleared" | project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify when application logs are cleared.

4. **Monitor for Log Deletion Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wevtutil cl" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect usage of log clearing commands.

5. **Identify Unauthorized Log Clearing Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("clear", "delete") and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect log clearing attempts by non-administrative users.

6. **Monitor for Event Log Service Restarts**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ServiceName == "EventLog" and ActionType == "StartService" | project Timestamp, DeviceName, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify restarts of the Event Log service.

7. **Detect Cleared Logs via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Clear-EventLog" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor PowerShell commands used to clear event logs.

8. **Suspicious Access to Event Log Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "System32\\winevt\\Logs" | summarize count() by FileName, DeviceName | where count() > 1
```
{% endcode %}

**Purpose**: Identify suspicious access to log files.

9. **Detect Log Clearing via Script**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any (".bat", ".cmd") and ProcessCommandLine has "wevtutil" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect scripts used to clear event logs.

10. **Monitor Changes to Audit Policy**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Security" | project Timestamp, DeviceName, RegistryKey, ActionType
```
{% endcode %}

**Purpose**: Monitor changes to audit policies that could impact logging.

## <mark style="color:blue;">7. Credential Access (TA0006)</mark>

**Sub-technique: T1003.001 - LSASS Memory**

**Objective**: Detect attempts to dump credentials from LSASS memory.&#x20;

1. **Monitor for Suspicious LSASS Access**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "lsass.exe" and ProcessCommandLine has "dump" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

\*\*Purpose: Detect suspicious access to LSASS memory.

2. **Detect Credential Dumping Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("mimikatz", "procdump", "secretsdump") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify known credential dumping tools.

3. **Monitor LSASS for Suspicious Memory Reads**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "lsass.exe" and ActionType == "ReadMemory" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Detect suspicious memory reads from LSASS.

4. **Detect LSASS Process Termination Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "lsass.exe" and ActionType == "TerminateProcess" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Monitor for attempts to terminate LSASS.

5. **Suspicious DLL Injections into LSASS**

{% code overflow="wrap" %}
```cs
DeviceImageLoadEvents | where InitiatingProcessFileName == "lsass.exe" and FileName endswith ".dll" | project Timestamp, DeviceName, FileName, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Detect DLL injections into LSASS.

6. **Unauthorized LSASS Access by Non-System Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "lsass.exe" and InitiatingProcessAccountName != "SYSTEM" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify unauthorized LSASS access by non-system accounts.

7. **Detect Procdump Used Against LSASS**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "procdump" and ProcessCommandLine has "lsass.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Monitor for Procdump usage to dump LSASS.

8. **Monitor for LSASS Process Duplicates**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "lsass.exe" and ActionType == "CreateProcess" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Detect the creation of duplicate LSASS processes.

9. **Identify LSASS Access Using Handle Duplication**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "DuplicateHandle" and FileName == "lsass.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Monitor for handle duplication used to access LSASS.

10. **Detect LSASS Credential Dumping via Task Scheduler**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("schtasks", "taskschd.msc") and ProcessCommandLine has "lsass.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify attempts to schedule tasks that dump LSASS credentials.

## <mark style="color:blue;">8. Discovery (TA0007)</mark>

**Sub-technique: T1083 - File and Directory Discovery**

**Objective**: Detect reconnaissance activities aimed at discovering sensitive files and directories.

1. **Detect Directory Listing Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("dir", "ls") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Identify commands used to list directory contents.

2. **Monitor Access to Sensitive Directories**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("C:\\Users", "C:\\Windows\\System32", "C:\\ProgramData") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Detect access to directories likely to contain sensitive information.

3. **Detect Searches for Specific File Types**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".txt" or FileName endswith ".docx" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Monitor searches for file types that may contain sensitive data.

4. **Identify Access to Security Configuration Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName in ("secpol.msc", "gpedit.msc") | project Timestamp, DeviceName, FileName, FolderPath`
```
{% endcode %}

**Purpose**: Detect access to files used to configure security settings.

5. **Monitor for Password Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has_any ("password", "credentials") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Identify attempts to locate files that may contain passwords.

6. **Detect Unauthorized Access to Network Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Monitor excessive access to network shares.

7. **Detect Access to Administrator Directories**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "C:\\Users\\Administrator" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Identify access to administrator directories.

8. **Monitor for Hidden File Access**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileAttributes has "Hidden" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Detect attempts to access hidden files.

9. **Detect Access to Backup Directories**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "Backup" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Identify access to backup directories.

10. **Detect Enumeration of Program Files Directory**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "C:\\Program Files" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Monitor attempts to enumerate the Program Files directory.

## <mark style="color:blue;">9. Lateral Movement (TA0008)</mark>

**Sub-technique: T1021.001 - Remote Desktop Protocol (RDP)**

**Objective**: Detect lateral movement using RDP.&#x20;

1. **Monitor RDP Connections from Unusual IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 3389 | summarize count() by RemoteIP, LocalIP | where count() > 5
```
{% endcode %}

**Purpose**: Detect RDP connections from unknown IP addresses.

2. **Identify Multiple Failed RDP Login Attempts**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Failed" | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Monitor failed RDP login attempts.

3. **Detect RDP Connections During Off-Hours**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and hour(LogonTime) < 6 or hour(LogonTime) > 18 | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Identify RDP sessions initiated during unusual hours.

4. **Monitor for Suspicious RDP Session Creation**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" | summarize count() by TargetUserName, DeviceName, IPAddress | where count() > 1
```
{% endcode %}

**Purpose**: Detect multiple RDP sessions created by the same user.

5. **Detect RDP Session Disconnections**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Logoff" | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Monitor for frequent disconnections of RDP sessions.

6. **Monitor RDP Access to Administrative Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 3389 and LocalPort == 445 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Detect RDP sessions accessing administrative shares.

7. **Detect RDP Connections from Multiple Locations**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" | summarize locations=make_set(IPAddress) by TargetUserName | where array_length(locations) > 1
```
{% endcode %}

**Purpose**: Identify users connecting via RDP from multiple locations.

8. **Monitor for RDP Session Hijacking**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and ActionType == "SessionReconnected" | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Detect hijacking of active RDP sessions.

9. **Detect RDP Brute Force Attempts**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Failed" | summarize count() by TargetUserName, DeviceName | where count() > 10
```
{% endcode %}

**Purpose**: Identify brute force attempts targeting RDP.

10. **Monitor RDP Connection with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and TokenElevationType == "Full" | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

**Purpose**: Detect RDP sessions initiated with elevated privileges.

## <mark style="color:blue;">10. Collection (TA0009)</mark>

**Sub-technique: T1119 - Automated Collection**

**Objective**: Detect automated collection of data for exfiltration.&#x20;

1. **Identify Automated File Collection**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where ProcessCommandLine has_any ("robocopy", "xcopy", "copy") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect automated file copying commands.

2. **Detection of Large Data Archives**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".zip" or FileName endswith ".rar" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Monitor the creation of large archive files.

3. **Suspicious Data Collection Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("backup", "sync", "archive") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect scripts or commands used for data collection.

4. **Detect Collection of Network Traffic Data**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("tcpdump", "wireshark", "netsh") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify network traffic data collection.

5. **Monitor for Data Collection via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Out-File", "Export-Csv") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect PowerShell commands used to export data.

6. **Detect Database Dumps**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("mysqldump", "pg_dump", "mongodump") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify database dump commands.

7. **Monitor for Automated Collection via Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any (".bat", ".ps1", ".sh") and ProcessCommandLine has_any ("copy", "export", "backup") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect scripts used for data collection.

8. **Identify Collection of Sensitive Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has_any ("passwords.txt", "confidential.docx") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Monitor access to sensitive files.

9. **Detect Use of Cloud Services for Data Collection**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("cloud_storage_ip_list") | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

```
_Purpose_: Monitor data collection via cloud services.
```

10\. **Monitor for Data Collection via Network Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 | summarize count() by RemoteIP, LocalIP | where count() > 20
```
{% endcode %}

**Purpose**: Identify data collection via network shares.

## <mark style="color:blue;">11. Command and Control (TA0011)</mark>

**Sub-technique: T1071.001 - Web Protocols**

**Objective**: Detect command and control (C2) communications using web protocols.&#x20;

1. **Detect Suspicious Web Traffic**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Identify unusual web traffic patterns.

2. **Monitor for Web Protocols Used by Malware**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("curl", "wget") | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect web protocols commonly used by malware.

3. **Identify Outbound HTTP POST Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 and ProcessCommandLine has "POST" | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor for outbound HTTP POST requests used for C2.

4. **Detect Long-Lived HTTP Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | summarize avg(DurationSeconds) by RemoteIP, LocalIP | where avg_DurationSeconds > 600
```
{% endcode %}

**Purpose**: Identify long-lived HTTP connections that could indicate C2.

5. **Monitor for Unusual DNS Queries**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 and ActionType == "Query" | summarize count() by RemoteIP | where count() > 200
```
{% endcode %}

**Purpose**: Detect excessive DNS queries.

6. **Detect Use of Web Shells**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".aspx" or FileName endswith ".php" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

**Purpose**: Monitor for the presence of web shells on servers.

7. **Identify HTTPS Traffic to Unusual Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and RemoteIP !in ("known_good_ips") | summarize count() by RemoteIP, LocalIP | where count() > 20
```
{% endcode %}

**Purpose**: Detect HTTPS traffic to unusual or unknown domains.

8. **Monitor for Suspicious User-Agents**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("User-Agent: Mozilla", "User-Agent: curl") | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect unusual or spoofed user-agents in web traffic.

9. **Detect Traffic to Known Malicious Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("known_malicious_ips") | summarize count() by RemoteIP, LocalIP`
```
{% endcode %}

**Purpose**: Identify traffic to known malicious IP addresses.

10. **Identify Suspicious WebSocket Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and ProcessCommandLine has "websocket" | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor for WebSocket connections used for C2.

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
