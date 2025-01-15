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

# KAPE

### 1. Initial Access

**1.1. Phishing: Spearphishing Attachment (T1566.001)**

**Objective:** Identify and collect evidence of malicious email attachments that may have been used to gain initial access. **Instruction:** Use KAPE to collect email attachments and other potential malicious files stored in temporary internet files, downloads, and user directories.

**KAPE Target Query: Phishing\_Email\_Attachments**

```cs
Description: Collect email attachments from cache and temp directories. 
Target: Files 
Paths:   
- '%UserProfile%\AppData\Local\Microsoft\Windows\INetCache\Content.IE5\*.exe'   
- '%UserProfile%\AppData\Local\Temp\*.docx'   
- '%UserProfile%\Downloads\*.pdf'   
- '%UserProfile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\*.exe'
```

**KAPE Target Query: Recent\_Executables**

```cs
Description: Collect recently created executables from common download locations. 
Target: Files 
Paths:   
- '%UserProfile%\Desktop\*.exe'   
- '%UserProfile%\Downloads\*.exe'   
- '%UserProfile%\Documents\*.exe'
```

**KAPE Target Query: Malicious\_Office\_Documents**

```cs
Description: Collect potentially malicious Office documents from user directories. 
Target: Files 
Paths:   
- '%UserProfile%\AppData\Local\Temp\*.docx'   
- '%UserProfile%\AppData\Local\Temp\*.xlsm'   
- '%UserProfile%\Documents\*.docm'
```

**KAPE Target Query: Suspicious\_PDF\_Files**

{% code overflow="wrap" %}
```cs
Description: Collect PDF files from user directories that might have been used in spearphishing attacks. 
Target: Files 
Paths:   
- '%UserProfile%\AppData\Local\Temp\*.pdf'   
- '%UserProfile%\Downloads\*.pdf'
```
{% endcode %}

**KAPE Target Query: Internet\_Cache\_Artifacts**

{% code overflow="wrap" %}
```cs
Description: Collect cached internet files that could reveal downloaded malicious content. 
Target: Files 
Paths:   
- '%UserProfile%\AppData\Local\Microsoft\Windows\INetCache\*'   
- '%UserProfile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\*'
```
{% endcode %}

### 2. Execution

**2.1. Command and Scripting Interpreter: PowerShell (T1059.001)**

**Objective:** Detect and collect artifacts related to PowerShell usage, which may indicate the execution of malicious scripts. **Instruction:** Use KAPE to collect PowerShell logs, history, and scripts to analyze potential malicious activity.

**KAPE Target Query: PowerShell\_Execution\_Logs**

```cs
Description: Collect PowerShell event logs to detect executed commands. 
Target: EventLogs 
LogNames:   
- 'Microsoft-Windows-PowerShell/Operational'   
- 'Windows PowerShell'
```

**KAPE Target Query: PowerShell\_History**

{% code overflow="wrap" %}
```cs
Description: Collect PowerShell command history from user profiles. 
Target: Registry 
Keys:   - 'HKEY_CURRENT_USER\Software\Microsoft\Windows\PowerShell\5.0\PromptedCommandHistory'   
- 'HKEY_CURRENT_USER\Software\Microsoft\Windows\PowerShell\1\ShellIds\Microsoft.PowerShell'
```
{% endcode %}

**KAPE Target Query: PowerShell\_Scripts**

```cs
Description: Collect PowerShell scripts from user directories. Target: Files 
Paths:   
- '%UserProfile%\Documents\*.ps1'   
- '%UserProfile%\Desktop\*.ps1'   
- '%UserProfile%\AppData\Local\Temp\*.ps1'
```

**KAPE Target Query: Encoded\_PowerShell\_Commands**

{% code overflow="wrap" %}
```cs
Description: Collect evidence of encoded PowerShell commands that might indicate obfuscated execution. 
Target: Registry 
Keys:   
- 'HKEY_CURRENT_USER\Software\Microsoft\Windows\PowerShell\5.0\PromptedCommandHistory'
```
{% endcode %}

**KAPE Target Query: PowerShell\_Module\_Usage**

{% code overflow="wrap" %}
```cs
Description: Collect PowerShell module logs to detect usage of potentially malicious modules. 
Target: EventLogs 
LogNames:   
- 'Microsoft-Windows-PowerShell/Operational'   
- 'Windows PowerShell'
```
{% endcode %}

### 3. Persistence

**3.1. Registry Run Keys / Startup Folder (T1547.001)**

**Objective:** Collect evidence of persistence mechanisms established through Registry run keys and startup folders.

**Instruction:** Use KAPE to collect registry keys and startup folder items that could indicate persistence mechanisms.

**KAPE Target Query: Registry\_Run\_Keys**

{% code overflow="wrap" %}
```cs
Description: Collect registry Run keys commonly used for persistence. 
Target: Registry 
Keys:   
- 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run' - 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'   - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'   
- 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'`
```
{% endcode %}

**KAPE Target Query: Startup\_Folder\_Items**

```cs
Description: Collect executable files from startup folders used for persistence. 
Target: Files 
Paths:   
- '%UserProfile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*'   
- '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\*'
```

**KAPE Target Query: Winlogon\_Persistence**

```cs
Description: Collect Winlogon registry keys used for persistence. Target: Registry 
Keys:   
- 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
```

**KAPE Target Query: Scheduled\_Tasks\_Persistence**

```cs
Description: Collect scheduled tasks that may have been created for persistence. 
Target: Files 
Paths:   - '%SystemRoot%\System32\Tasks\*'
```

**KAPE Target Query: Userinit\_Registry\_Keys**

```cs
Description: Collect Userinit registry keys that may be used for persistence. 
Target: Registry 
Keys:   
- 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'
```

### 4. Privilege Escalation

**4.1. Scheduled Task/Job (T1053.005)**

**Objective:** Detect and collect evidence of scheduled tasks used to escalate privileges. **Instruction:** Use KAPE to collect artifacts related to scheduled tasks that could be used for privilege escalation.

**KAPE Target Query: Scheduled\_Tasks**

{% code overflow="wrap" %}
```cs
Description: Collect all scheduled tasks from the system to identify any malicious tasks. 
Target: Files 
Paths:   - '%SystemRoot%\System32\Tasks\*'
```
{% endcode %}

**KAPE Target Query: At\_Job\_Artifacts**

{% code overflow="wrap" %}
```cs
Description: Collect evidence of AT jobs that might have been used for privilege escalation. 
Target: Files 
Paths:   - '%SystemRoot%\Tasks\*.job'
```
{% endcode %}

**KAPE Target Query: Task\_Scheduler\_Logs**

```cs
Description: Collect Task Scheduler event logs to analyze scheduled task executions. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-TaskScheduler/Operational'
```

**KAPE Target Query: User\_Created\_Scheduled\_Tasks**

```cs
Description: Collect user-created scheduled tasks to detect unauthorized tasks. 
Target: Files 
Paths:   - '%SystemRoot%\System32\Tasks\*'
```

**KAPE Target Query: Persistence\_via\_Scheduled\_Tasks**

{% code overflow="wrap" %}
```cs
Description: Collect scheduled tasks and their associated files to detect persistence mechanisms. 
Target: Files 
Paths:   
- '%SystemRoot%\System32\Tasks\*'   
- '%SystemRoot%\Tasks\*.job'
```
{% endcode %}

### 5. Defense Evasion

**5.1. Obfuscated Files or Information (T1027)**

**Objective:** Detect and collect evidence of obfuscated files and scripts used to evade detection. **Instruction:** Use KAPE to collect obfuscated or encoded files that may indicate an attempt to evade detection.

**KAPE Target Query: Encoded\_PowerShell\_Scripts**

```cs
Description: Collect encoded PowerShell scripts from user directories. 
Target: Files 
Paths:   
- '%UserProfile%\Documents\*.ps1'   
- '%UserProfile%\Desktop\*.ps1'   
- '%UserProfile%\AppData\Local\Temp\*.ps1'
```

**KAPE Target Query: Encoded\_Batch\_Files**

```cs
Description: Collect encoded batch files from user directories. Target: Files 
Paths:   
- '%UserProfile%\Documents\*.bat'   
- '%UserProfile%\Desktop\*.bat'   
- '%UserProfile%\AppData\Local\Temp\*.bat'
```

**KAPE Target Query: XOR\_Encrypted\_Files**

```cs
Description: Collect XOR encrypted files that might be used to evade detection. 
Target: Files 
Paths:   - '%UserProfile%\Documents\*.xor'
```

**KAPE Target Query: Obfuscated\_Scripts**

```cs
Description: Collect obfuscated scripts from user directories. Target: Files 
Paths:   
- '%UserProfile%\AppData\Local\Temp\*.vbs'   
- '%UserProfile%\AppData\Local\Temp\*.js'
```

**KAPE Target Query: Encrypted\_Payloads**

```cs
Description: Collect encrypted payloads that may be used to hide malicious activity. 
Target: Files 
Paths:   - '%UserProfile%\AppData\Local\Temp\*.enc'
```

### 6. Credential Access

**6.1. OS Credential Dumping: LSASS Memory (T1003.001)**

**Objective:** Detect and collect artifacts related to attempts to dump credentials from LSASS. **Instruction:** Use KAPE to collect evidence of credential dumping activities involving LSASS.

**KAPE Target Query: LSASS\_Process\_Dump**

{% code overflow="wrap" %}
```cs
Description: Collect memory dumps of the LSASS process to investigate credential dumping. 
Target: Memory 
ProcessName: lsass.exe
```
{% endcode %}

**KAPE Target Query: Security\_Event\_Logs**

{% code overflow="wrap" %}
```cs
Description: Collect Windows Security event logs to identify credential dumping attempts. 
Target: EventLogs 
LogNames:   - 'Security'
```
{% endcode %}

**KAPE Target Query: LSASS\_Handles**

{% code overflow="wrap" %}
```cs
Description: Collect information on handles opened by the LSASS process to detect suspicious access. 
Target: Memory 
ProcessName: lsass.exe
```
{% endcode %}

**KAPE Target Query: Credential\_Dumping\_Tools**

```cs
Description: Collect known credential dumping tools such as Mimikatz or ProcDump. 
Target: Files 
Paths:   
- '%SystemRoot%\System32\mimikatz.exe'   
- '%SystemRoot%\System32\procdump.exe'
```

**KAPE Target Query: LSASS\_Memory\_Analysis**

```cs
Description: Collect and analyze LSASS memory for evidence of credential dumping. 
Target: Memory 
ProcessName: lsass.exe
```

### 7. Discovery

**7.1. System Information Discovery (T1082)**

**Objective:** Detect and collect artifacts related to the gathering of system information. **Instruction:** Use KAPE to collect evidence of system information discovery activities, such as system enumeration commands.

**KAPE Target Query: System\_Info\_Commands**

```cs
Description: Collect evidence of system information commands executed on the system. 
Target: Files 
Paths:   
- '%UserProfile%\AppData\Local\Temp\systeminfo.txt'   
- '%UserProfile%\AppData\Local\Temp\hostname.txt'
```

**KAPE Target Query: WMI\_Query\_Logs**

{% code overflow="wrap" %}
```cs
Description: Collect logs of WMI queries to detect system information gathering activities. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-WMI-Activity/Operational'
```
{% endcode %}

**KAPE Target Query: Registry\_System\_Information**

```cs
Description: Collect registry information related to the system's configuration. 
Target: Registry 
Keys:   - 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion'
```

**KAPE Target Query: System\_Processes**

```cs
Description: Collect a list of running processes to analyze system activity. 
Target: Memory
```

**KAPE Target Query: Network\_Configuration**

{% code overflow="wrap" %}
```cs
Description: Collect network configuration information, such as IP addresses and routing tables. 
Target: Files 
Paths:   
- '%SystemRoot%\System32\drivers\etc\hosts'   
- '%SystemRoot%\System32\drivers\etc\network'
```
{% endcode %}

### 8. Collection

**8.1. Data from Local System (T1005)**

**Objective:** Detect and collect artifacts related to data collection from the local system. -**Instruction:** Use KAPE to collect sensitive files and directories that may have been targeted by an attacker.

**KAPE Target Query: Sensitive\_Files**

```cs
Description: Collect sensitive files from user directories. Target: Files 
Paths:   
- '%UserProfile%\Documents\*.docx'   
- '%UserProfile%\Documents\*.xlsx'   
- '%UserProfile%\Desktop\*.pdf'`
```

**KAPE Target Query: Recently\_Accessed\_Files**

{% code overflow="wrap" %}
```cs
Description: Collect recently accessed files to identify potential data exfiltration. 
Target: Files 
Paths:   
- '%UserProfile%\Documents\*.docx'   
- '%UserProfile%\Downloads\*.xlsx'   
- '%UserProfile%\Desktop\*.pdf'`
```
{% endcode %}

**KAPE Target Query: USB\_Device\_Logs**

{% code overflow="wrap" %}
```cs
Description: Collect logs related to USB devices to detect data collection via removable media. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
```
{% endcode %}

**KAPE Target Query: Clipboard\_Data**

{% code overflow="wrap" %}
```cs
Description: Collect clipboard data that may have been used to copy sensitive information. 
Target: Memory
```
{% endcode %}

**KAPE Target Query: Print\_Spooler\_Logs**

```cs
Description: Collect print spooler logs to detect printing of sensitive data. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-PrintService/Operational'
```

### 9. Exfiltration

**9.1. Exfiltration Over C2 Channel (T1041)**

**Objective:** Detect and collect artifacts related to data exfiltration over command-and-control (C2) channels. **Instruction:** Use KAPE to collect evidence of data exfiltration over network connections.

**KAPE Target Query: Network\_Traffic\_Logs**

```cs
Description: Collect network traffic logs to analyze for signs of data exfiltration. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-Sysmon/Operational'
```

**KAPE Target Query: DNS\_Logs**

```cs
Description: Collect DNS logs to detect communication with known C2 domains. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-DNS-Client/Operational'
```

**KAPE Target Query: HTTP\_Request\_Logs**

```cs
Description: Collect HTTP request logs to detect data exfiltration via web channels. 
Target: Files 
Paths:   - '%SystemRoot%\System32\LogFiles\W3SVC1\*.log'
```

**KAPE Target Query: SMB\_Traffic\_Logs**

```cs
Description: Collect SMB traffic logs to detect data exfiltration via shared drives. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-SMBClient/Operational'
```

**KAPE Target Query: FTP\_Traffic\_Logs**

```cs
Description: Collect FTP traffic logs to detect data exfiltration via FTP. 
Target: Files 
Paths:   - '%SystemRoot%\System32\LogFiles\FTP\*'
```

### 10. Impact

**10.1. Data Destruction (T1485)**

**Objective:** Detect and collect evidence of data destruction activities, such as file deletion or wiping. **Instruction:** Use KAPE to collect logs and artifacts related to data destruction attempts. **KAPE Target Query: File\_Deletion\_Logs**

{% code overflow="wrap" %}
```cs
Description: Collect logs related to file deletion activities to detect data destruction. 
Target: EventLogs 
LogNames:   
- 'Security'   
- 'Microsoft-Windows-Security-Auditing'
```
{% endcode %}

**KAPE Target Query: Volume\_Shadow\_Copy\_Logs**

{% code overflow="wrap" %}
```cs
Description: Collect Volume Shadow Copy logs to detect attempts to delete or alter backups. 
Target: EventLogs 
LogNames:   - 'Microsoft-Windows-StorageManagement/Operational'
```
{% endcode %}

**KAPE Target Query: Disk\_Wipe\_Tools**

```cs
Description: Collect known disk wiping tools from the system. Target: Files 
Paths:   
- '%SystemRoot%\System32\sdelete.exe'   
- '%SystemRoot%\System32\eraser.exe'
```

**KAPE Target Query: Audit\_Policy\_Logs**

{% code overflow="wrap" %}
```cs
Description: Collect audit policy logs to detect changes in logging that may indicate data destruction. 
Target: EventLogs 
LogNames:   - 'Security'
```
{% endcode %}

**KAPE Target Query: Recycle\_Bin\_Files**

```cs
Description: Collect files from the Recycle Bin to detect recently deleted items. 
Target: 
Files Paths:   
- '%UserProfile%\$Recycle.Bin\*'
```

### Additional Resources

Eric Zimmerman's Tools:  [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md) A comprehensive set of DFIR tools accompanied by excellent user guides.&#x20;

{% file src="../.gitbook/assets/SANS DFIR Eric Zimmerman CommandLine Tools.pdf" %}
