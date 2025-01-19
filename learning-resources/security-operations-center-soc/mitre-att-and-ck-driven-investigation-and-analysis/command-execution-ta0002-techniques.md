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

# Command Execution (TA0002) Techniques

### Introduction

Investigating command execution on a network, particularly in Windows workstations and servers, is crucial to understanding the extent and impact of a security incident. This process involves identifying and analysing the commands that an attacker executes after gaining access.

#### Understanding Common Command Execution Sources

* **Command-Line Interface (CLI):** Windows Command Prompt, PowerShell, and Unix/Linux terminals.
* **Scripts:** Batch files, PowerShell scripts, VBS scripts, etc.
* **Scheduled Tasks:** Tasks that execute commands at specified times.
* **Remote Execution Tools:** Tools like PsExec or remote desktop applications.
* **Application Execution:** Applications that execute system command

#### Collecting Data

* **System Logs:** Collect and examine Windows Event Logs, primarily focusing on the Security, System, and Application logs.
* **Command History:** In Windows, check PowerShell and Command Prompt history. PowerShell logs can be found in Event Viewer under "Windows Logs" > "Application and Services Logs" > "Windows PowerShell".
* **Scheduled Tasks and Startup Programs:** Check for any unknown or modified scheduled tasks and startup programs that could execute commands.

#### Analysing Execution Artifacts

* **Prefetch Files:** Analyse Prefetch files in Windows to identify executed programs.
* Registry Analysis: Examine registry keys associated with command execution, like Run, RunOnce, and PowerShell's Transcription logging.
* **File System Analysis:** Check the creation and modification dates of suspicious files.
* **Shellbags:** Analyse shellbags for evidence of command execution via Windows Explorer.
* **Command-Line Interface (CLI):** Windows Command Prompt, PowerShell, and Unix/Linux terminals.
* **Scripts:** Batch files, PowerShell scripts, VBScripts, etc.
* **Scheduled Tasks:** Tasks that execute commands at specified times.
* **Remote Execution Tools:** Tools like PsExec or remote desktop applications.
* **Application Execution:** Applications that execute system command

#### Memory Forensics

* Use tools like Volatility to analyse memory dumps for evidence of recently executed commands or processes.

#### Network Traffic Analysis

* **Check for Command & Control Traffic:** Analyse network traffic logs for any signs of command and control communication, which might indicate remote execution of commands.
* **Data Exfiltration:** Look for patterns or large data transfers that might indicate data being collected and sent out.

#### Analysis of Command Execution

* **Windows Command Line Logs:** Windows logs command line activity in Event ID 4688. These logs show the command line process creation events.
* **PowerShell Logging:** Review PowerShell script block logging (Event ID 4104), module logging, and transcription logs for executed commands.
* **Bash History (for Unix/Linux):** Analyse the .bash\_history file for executed commands.
* **Scheduled Tasks Analysis:** Investigate the Windows Task Scheduler and cron jobs (for Unix/Linux) for any scheduled tasks running commands.
* **Remote Execution Tools Logs:** Examine logs from tools like PsExec or remote desktop software

#### User Account and Authentication Logs

* Review logs related to user authentication and account usage, particularly focusing on any elevation of privileges or use of administrative accounts.

#### Correlation and Timeline Analysis

* Correlate the gathered data to build a timeline of events, which will help you understand the sequence and scope of the executed commands.

#### Malware and Script Analysis

* If any scripts or malware are found, analyse them to determine their functionality and the commands they execute.

#### Interviews and Internal Investigations

* Talk to relevant personnel who might provide insights into usual and unusual command executions, especially in the case of internal threats.

#### Reporting and Documentation

* Document all findings, methodologies, and evidence in a detailed report for future reference and potential legal proceedings.

Investigating command execution requires a thorough analysis of various data sources, including system logs, memory, and network traffic. Each step, from data collection to detailed analysis and reporting, is crucial in understanding the scope and impact of the executed commands. Maintaining an updated knowledge of forensic tools and techniques is essential for effective investigation in the ever-evolving landscape of cybersecurity threats.

### <mark style="color:blue;">Using KQL to Investigate Command Execution Activities in an Environment Using Defender/Sentinel</mark>

Note: While there are other methods and tools for investigating these kinds of attacks, the goal is to tackle them from a beginner's point of view without utilising intricate KQL queries that a Level 1 SOC analyst wouldn't find difficult to comprehend. Other areas on the site will demonstrate the same process using other tools, such as Splunk, Velociraptor, or Eric Zimmerman Tools.

Execution techniques involve adversaries running malicious code on a target system. These techniques are crucial in the attack chain as they enable the adversary to execute their payloads, gain persistence, escalate privileges, and move laterally within the network.

### <mark style="color:blue;">**1. T1059 - Command and Scripting Interpreter**</mark>

**Objective**: Detect the use of command and scripting interpreters to execute malicious commands or scripts.

1. **Detect PowerShell Script Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify instances of PowerShell being used to execute scripts.

2. **Detect CMD.exe Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "cmd.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of the command prompt to run commands.

3. **Identify the Use of Python Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "python.exe" or FileName == "pythonw.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect execution of Python scripts on the system.

4. **Monitor for VBScript Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wscript.exe" or FileName == "cscript.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the execution of VBScript files.

5. **Detect Bash Script Execution via WSL**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "bash.exe" or FileName == "wsl.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of Bash scripting via the Windows Subsystem for Linux (WSL).

6. **Identify JavaScript Execution via Node.js**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "node.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the execution of JavaScript files using Node.js.

7. **Detect PowerShell Command with Encoded Parameters**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "EncodedCommand" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify obfuscated PowerShell commands using encoded parameters.

8. **Monitor for Scripting Engine Execution via Office Macros**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") | where ProcessCommandLine has_any (".vbs", ".js", "powershell") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect the use of Office applications to execute scripts.

9. **Detect WMI Command Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of Windows Management Instrumentation (WMI) to execute commands.

10. **Monitor for JScript Execution via MSHTA**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mshta.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the execution of JScript or VBScript using the MSHTA utility.

### <mark style="color:blue;">**2. T1047 - Windows Management Instrumentation**</mark>

**Objective**: Detect the use of WMI to execute commands or scripts remotely on the target system.&#x20;

1. **Detect Remote WMI Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "process call create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of WMI to remotely execute processes.

2. **Monitor WMI Commands Creating New Processes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "process call create" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect WMI commands that create new processes on the system.

3. **Identify WMI Execution via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Get-WmiObject" or ProcessCommandLine has "Invoke-WmiMethod" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for WMI usage through PowerShell.

4. **Detect Suspicious WMI Execution with Credentials**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has " /user:" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify WMI execution using specific credentials, which may indicate lateral movement.

5. **Monitor for WMI Execution from Non-Admin Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect WMI execution by non-administrative accounts.

6. **Identify WMI Execution to Start Services**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "service" and ProcessCommandLine has "start" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Monitor for WMI commands used to start services.

7. **Detect WMI Execution for File Transfer**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "CIM_DataFile" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify WMI usage for file transfers.

8. **Monitor for WMI Execution of Suspicious Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has_any (".vbs", ".js", "powershell") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect the execution of scripts through WMI.

9. **Identify WMI Execution to Modify Registry**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "RegWrite" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for WMI commands that modify the Windows registry.

10. **Detect WMI Execution of DLL Files**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has ".dll" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of WMI to execute DLL files.

### <mark style="color:blue;">**3. T1203 - Exploitation for Client Execution**</mark>

**Objective**: Detect exploitation attempts targeting client applications to execute malicious code.

1. **Detect Exploitation Attempts in Web Browsers**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("iexplore.exe", "chrome.exe", "firefox.exe", "edge.exe") | where ProcessCommandLine has_any ("exploit", "shellcode", "heap spray") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify exploitation attempts targeting web browsers.

2. **Monitor for Office Application Exploits**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") | where ProcessCommandLine has_any (".hta", ".exe", ".dll") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect exploitation attempts in Microsoft Office applications.

3. **Identify Adobe Reader Exploitation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "acrord32.exe" | where ProcessCommandLine has_any (".exe", ".dll", "powershell") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for exploitation of Adobe Reader.

4. **Detect Exploitation via Email Clients**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("outlook.exe", "thunderbird.exe") | where ProcessCommandLine has_any ("exploit", "shellcode") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify exploitation attempts targeting email clients.

5. **Monitor for PDF Exploitation Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "acrord32.exe" | where ProcessCommandLine has_any (".js", "powershell", ".vbs") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect exploitation attempts involving PDF files.

6. **Detect Exploitation via Media Players**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("wmplayer.exe", "vlc.exe") | where ProcessCommandLine has_any ("exploit", "shellcode", "overflow") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for exploitation attempts targeting media players.

7. **Identify Java Application Exploitation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "java.exe" or FileName == "javaw.exe" | where ProcessCommandLine has_any ("exploit", "shellcode") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect exploitation attempts in Java applications.

8. **Monitor for Flash Player Exploitation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "flashplayer.exe" | where ProcessCommandLine has_any (".js", "powershell", ".vbs") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify exploitation attempts in Adobe Flash Player.

9. **Detect Exploitation via Browsing History**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("iexplore.exe", "chrome.exe", "firefox.exe", "edge.exe") | where ProcessCommandLine has_any ("history", "cookies") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for exploitation attempts using browsing history.

10. **Identify Exploitation Using Document Macros**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") | where ProcessCommandLine has "macro" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of macros in document exploitation.

### <mark style="color:blue;">**4. T1106 - Native API**</mark>

**Objective**: Detect the use of native Windows APIs to execute malicious code or commands.&#x20;

1. **Detect Use of Windows API Calls**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("CreateProcess", "VirtualAlloc", "LoadLibrary") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify processes making direct API calls.

2. **Monitor for Execution via CreateProcess API**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "CreateProcess" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect execution of processes using the CreateProcess API.

3. **Identify Use of LoadLibrary API**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "LoadLibrary" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the loading of dynamic link libraries (DLLs) using the LoadLibrary API.

4. **Detect Memory Allocation via VirtualAlloc**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "VirtualAlloc" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify memory allocation attempts using the VirtualAlloc API.

5. **Monitor for Remote Thread Injection via CreateRemoteThread**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "CreateRemoteThread" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect remote thread injection using the CreateRemoteThread API.

6. **Identify API Calls for Process Injection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("NtQueueApcThread", "RtlCreateUserThread", "WriteProcessMemory") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of APIs commonly associated with process injection.

7. **Detect API Calls for Code Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("WinExec", "ShellExecute", "CreateProcess") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for API calls used to execute code.

8. **Identify Use of API for Privilege Escalation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("AdjustTokenPrivileges", "SetThreadToken") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect API usage for privilege escalation.

9. **Monitor for API Calls Modifying System Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has_any ("kernel32.dll", "ntdll.dll", "user32.dll") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

_Purpose_: Identify attempts to modify system files via API calls.

10. **Detect API Calls for Network Communications**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ProcessCommandLine has_any ("send", "recv", "connect") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for API calls initiating network communications.

### <mark style="color:blue;">**5. T1202 - Indirect Command Execution**</mark>

**Objective**: Detect the use of indirect methods to execute commands, such as through application features, scripting, or automated tasks.

1. **Detect Execution via Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of scheduled tasks for command execution.

2. **Monitor for Execution via Registry Autorun**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

_Purpose_: Detect the use of registry autorun keys for indirect command execution.

3. **Identify Execution via Office Macros**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") | where ProcessCommandLine has "macro" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for command execution via Office macros.

4. **Detect Execution via Task Scheduler**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "at" or ProcessCommandLine has "schtasks" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of Task Scheduler for indirect command execution.

5. **Monitor for Execution via WMI Event Subscriptions**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "wmi event" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of WMI event subscriptions for command execution.

6. **Identify Execution via Application Debugging**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("windbg.exe", "cdb.exe", "ntsd.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for command execution using application debugging tools.

7. **Detect Execution via Service Binary**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "sc config" and ProcessCommandLine has "binpath=" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the modification of service binaries for command execution.

8. **Monitor for Execution via COM Object Hijacking**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "regsvr32" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of COM objects for indirect command execution.

9. **Identify Execution via Autorun.inf Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName == "autorun.inf" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

_Purpose_: Monitor for the use of autorun.inf files for command execution.

10. **Detect Execution via Remote Desktop Services**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Identify command execution through Remote Desktop Services.

### <mark style="color:blue;">**6. T1072 - Software Deployment Tools**</mark>

**Objective**: Detect the use of software deployment tools to execute malicious code on multiple systems.&#x20;

1. **Detect Execution via SCCM**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ccmexec.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of System Center Configuration Manager (SCCM) for command execution.

2. **Monitor for Execution via Ansible**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ansible-playbook" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of Ansible for software deployment and command execution.

3. **Identify Execution via Puppet**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "puppet apply" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of Puppet for executing commands on systems.

4. **Detect Execution via Chef**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "chef-client" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for command execution using Chef.

5. **Monitor for Execution via SaltStack**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "salt-call" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of SaltStack for command execution.

6. **Detect Execution via PowerShell DSC**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Start-DscConfiguration" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of PowerShell Desired State Configuration (DSC) for command execution.

7. **Identify Execution via GPO Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "gpo.ps1" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of Group Policy Object (GPO) scripts for executing commands.

8. **Monitor for Execution via Remote Software Installation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "msiexec" and ProcessCommandLine has "/i" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify remote software installations used for command execution.

9. **Detect Execution via Orchestrator Runbooks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "orchestrator" and ProcessCommandLine has "runbook" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of Orchestrator Runbooks to execute commands.

10. **Identify Execution via Custom Deployment Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any (".ps1", ".bat", ".sh") and ProcessCommandLine has "deploy" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect custom deployment scripts used for executing commands on multiple systems.

### <mark style="color:blue;">**7. T1117 - Regsvr32**</mark>

**Objective**: Detect the use of regsvr32.exe to execute DLLs or scripts, potentially as part of a living-off-the-land attack.&#x20;

1. **Detect Regsvr32 Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify instances where regsvr32.exe is used to execute DLLs or scripts.

2. **Monitor for Regsvr32 with Suspicious Parameters**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and ProcessCommandLine has_any ("/s", "/u", "/i") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect regsvr32 executions with suspicious command-line parameters.

3. **Identify Regsvr32 Executing Remote Files**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and ProcessCommandLine has "http://" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for regsvr32 executing remote files.

4. **Detect Regsvr32 Used for Script Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and ProcessCommandLine has_any (".vbs", ".js") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify regsvr32 executions that involve running scripts.

5. **Monitor for Regsvr32 with Unusual DLLs**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and ProcessCommandLine has ".dll" | where ProcessCommandLine has_not_any ("kernel32.dll", "user32.dll") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect regsvr32 used to execute unusual or suspicious DLLs.

6. **Identify Regsvr32 Executing from Non-Standard Locations**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and FolderPath has_not "C:\\Windows\\System32" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for regsvr32 executing from non-standard locations.

7. **Detect Regsvr32 with Network Connectivity**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and ProcessCommandLine has_any (".dll", ".ocx") and ProcessCommandLine has "http://" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify regsvr32 executions that involve network connectivity.

8. **Monitor for Regsvr32 Execution by Non-Admin Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect regsvr32 usage by non-administrative accounts.

9. **Identify Regsvr32 with High Privileges**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and TokenElevationType == "Full" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for regsvr32 executions with elevated privileges.

10. **Detect Regsvr32 Used in Conjunction with UAC Bypass**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" and ProcessCommandLine has_any ("bypass", "UAC") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify regsvr32 executions associated with UAC bypass techniques.

### <mark style="color:blue;">**8. T1086 - PowerShell**</mark>

**Objective**: Detect the use of PowerShell for executing commands and scripts, which is often used in attacks.&#x20;

1. **Detect PowerShell Script Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify instances where PowerShell is used to execute scripts.

2. **Monitor for Obfuscated PowerShell Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine matches regex "(?i)[^a-zA-Z0-9\s]" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect obfuscated PowerShell commands.

3. **Identify PowerShell Commands Downloading Files**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Invoke-WebRequest" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for PowerShell commands that download files from the internet.

4. **Detect PowerShell Commands Executing Encoded Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "EncodedCommand" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell executions with encoded commands.

5. **Monitor for PowerShell Execution with Admin Privileges**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and TokenElevationType == "Full" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell commands executed with administrative privileges.

6. **Identify PowerShell Execution from Office Applications**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and InitiatingProcessFileName in ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell commands executed from Office applications.

7. **Detect PowerShell Commands Modifying the Registry**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Set-ItemProperty" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for PowerShell commands that modify the Windows registry.

8. **Monitor for PowerShell Commands Invoking WMI**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Get-WmiObject" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands that invoke WMI.

9. **Detect PowerShell Commands Executing System Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has_any ("cmd.exe", "sc.exe", "net.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountNam
```
{% endcode %}

_Purpose_: Monitor for PowerShell commands that execute system commands.

10. **Identify PowerShell Execution via Script Block Logging**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "PowerShellScriptBlockLogging" | project Timestamp, DeviceName, InitiatingProcessCommandLine, ScriptBlockText
```
{% endcode %}

_Purpose_: Detect PowerShell execution using script block logging.
