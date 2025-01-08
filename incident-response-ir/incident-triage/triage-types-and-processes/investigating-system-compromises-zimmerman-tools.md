---
icon: laptop-code
---

# Investigating System Compromises - Zimmerman Tools

## <mark style="color:blue;">1. Initial Access</mark>

### 1.1. Phishing: Spearphishing Attachment (T1566.001)

**Objective:** Detect and collect evidence of malicious email attachments that might have been used to gain initial access.

**Tool: MFTECmd (Master File Table Parser)**

**Instruction:** Parse the Master File Table (MFT) to identify recently accessed or created files that may include malicious email attachments. **Command:**

```cs
MFTECmd.exe -d C:\ -o C:\Output\ -csv C:\Output\MFTECmd_Output.csv
```

**Analysis:** Review the output for files with extensions like `.exe`, `.docx`, or `.pdf` in directories such as `Downloads`, `Temp`, or `INetCache`.

**Tool: RBCmd (Recycle Bin Command Line)**

**Instruction:** Check the Recycle Bin for recently deleted files that could have been malicious attachments. **Command:**

```cs
RBCmd.exe -d C:\$Recycle.Bin\ -csv C:\Output\RBCmd_Output.csv
```

**Analysis:** Look for files with suspicious names or extensions in the output CSV.

**Tool: LECmd (LNK File Explorer Command Line)**

**Instruction:** Parse LNK files to identify recently accessed files, including those accessed via phishing attachments. **Command:**

```cs
LECmd.exe -d C:\Users\ -csv C:\Output\LECmd_Output.csv
```

**Analysis:** Look for LNK files pointing to unusual or suspicious file paths, particularly in the `Downloads` and `Documents` directories.

**Tool: JLECmd (Jump List Explorer Command Line)**

**Instruction:** Analyze Jump Lists to determine recently accessed files or programs that could be related to phishing. **Command:**

```cs
JLECmd.exe -d C:\Users\ -csv C:\Output\JLECmd_Output.csv
```

**Analysis:** Review the Jump Lists for references to potentially malicious documents or executables.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Windows Event Logs to detect file execution events related to email attachments. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx -csv C:\Output\Security_Events.csv`
```
{% endcode %}

**Analysis:** Focus on Event IDs 4688 (Process Creation) and 4656 (Handle Operation) to detect the execution of suspicious files.

## <mark style="color:blue;">2. Execution</mark>

### 2.1. Command and Scripting Interpreter: PowerShell (T1059.001)

**Objective:** Detect and analyze PowerShell usage, which may indicate the execution of malicious scripts.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Windows Event Logs for PowerShell activity to identify potentially malicious scripts. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx -csv C:\Output\PowerShell_Logs.csv
```
{% endcode %}

**Analysis:** Review Event IDs 4103 (Script Block Logging), 4104 (Script Block Logging – Detailed), and 4105 (Execution Events) for signs of malicious activity.

**Tool: Registry Explorer**

**Instruction:** Manually explore PowerShell-related registry keys for command history or changes in execution policies. - **Path:** `HKEY_CURRENT_USER\Software\Microsoft\PowerShell\` - **Analysis:** Check `ConsoleHost` and `ExecutionPolicy` subkeys for suspicious entries or policies that deviate from the organization's standards.

**Tool: PECmd (Prefetch Explorer Command Line)**

**Instruction:** Analyze Prefetch files to identify evidence of executed PowerShell scripts. **Command:**

```cs
PECmd.exe -d C:\Windows\Prefetch\ -csv C:\Output\Prefetch_Output.csv
```

**Analysis:** Review the Prefetch entries for PowerShell executables and scripts that may indicate suspicious activity.

**Tool: AppCompatCacheParser**

**Instruction:** Examine the Application Compatibility Cache to find evidence of executed PowerShell scripts. **Command:**

{% code overflow="wrap" %}
```cs
AppCompatCacheParser.exe -d C:\Windows\System32\config\SYSTEM -csv C:\Output\AppCompatCache_Output.csv
```
{% endcode %}

**Analysis:** Look for PowerShell-related entries that suggest recent script execution.

**Tool: RECmd (Registry Explorer Command Line)**

**Instruction:** Search the registry for persistence mechanisms involving PowerShell, such as scripts set to run at startup. **Command:**

{% code overflow="wrap" %}
```cs
RECmd.exe -r C:\Windows\System32\config\SOFTWARE -b C:\Output\ -csv C:\Output\PowerShell_Persistence.csv
```
{% endcode %}

**Analysis:** Focus on `Run` and `RunOnce` registry keys for references to PowerShell scripts or commands.

## <mark style="color:blue;">3. Persistence</mark>

### 3.1. Registry Run Keys / Startup Folder (T1547.001)

**Objective:** Detect and collect evidence of persistence mechanisms established through registry run keys and startup folders.

**Tool: RECmd (Registry Explorer Command Line)**

**Instruction:** Scan the registry for run keys that might be used for persistence. **Command:**

{% code overflow="wrap" %}
```cs
RECmd.exe -r C:\Windows\System32\config\SOFTWARE -b C:\Output\ -csv C:\Output\Registry_RunKeys.csv
```
{% endcode %}

**Analysis:** Look for suspicious entries in `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`.

**Tool: PECmd (Prefetch Explorer Command Line)**

**Instruction:** Analyze Prefetch files to identify programs that persist through system startup. **Command:**

```cs
PECmd.exe -d C:\Windows\Prefetch\ -csv C:\Output\Prefetch_Output.csv
```

**Analysis:** Look for executables associated with persistence, particularly those starting automatically on boot.

**Tool: JLECmd (Jump List Explorer Command Line)**

**Instruction:** Investigate Jump Lists for references to programs or scripts used for persistence. **Command:**

```cs
JLECmd.exe -d C:\Users\ -csv C:\Output\JumpLists_Persistence.csv
```

**Analysis:** Focus on Jump Lists pointing to unusual executables or scripts that could be used for persistence.

**Tool: LECmd (LNK File Explorer Command Line)**

**Instruction:** Examine LNK files for references to executables that might have been set to run at startup. **Command:**

```cs
LECmd.exe -d C:\Users\ -csv C:\Output\LNK_Persistence.csv
```

**Analysis:** Analyze LNK files that point to suspicious executables or scripts potentially set up for persistence.

**Tool: Registry Explorer**

**Instruction:** Use Registry Explorer to manually inspect the `Run` keys for persistence mechanisms. **Path:**

```cs
 HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
```

**Analysis:** Look for any entries pointing to unusual executables or scripts, especially those stored in non-standard directories.

## <mark style="color:blue;">4. Privilege Escalation</mark>

### 4.1. Scheduled Task/Job (T1053.005)

**Objective:** Detect and analyze scheduled tasks that may have been created to escalate privileges.

**Tool: Scheduled Task Parser (STS)**

**Instruction:** Parse and analyze scheduled tasks on the system to identify those used for privilege escalation. **Command:**

```cs
STS.exe -d C:\Windows\System32\Tasks\ -csv C:\Output\Scheduled_Tasks.csv
```

**Analysis:** Review the output for scheduled tasks that are set to run with elevated privileges or under unusual accounts.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Event Logs related to the creation and execution of scheduled tasks. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx -csv C:\Output\Scheduled_Tasks_Events.csv
```
{% endcode %}

**Analysis:** Look for Event IDs 106 (Task Created) and 200 (Task Action Started) for signs of suspicious task creation.

**Tool: RECmd (Registry Explorer Command Line)**

**Instruction:** Search the registry for scheduled tasks that may be used for privilege escalation. **Command:**

{% code overflow="wrap" %}
```cs
RECmd.exe -r C:\Windows\System32\config\SOFTWARE -b C:\Output\ -csv C:\Output\Scheduled_Task_Registry.csv
```
{% endcode %}

**Analysis:** Focus on registry entries related to tasks scheduled to run with high privileges.

**Tool: Registry Explorer**

**Instruction:** Manually inspect registry keys related to scheduled tasks. **Path:** \`

```cs
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
```

**Analysis:** Look for any tasks with elevated privileges or unusual triggers.

**Tool: MFTECmd (Master File Table Parser)**

**Instruction:** Parse the MFT for evidence of scheduled task files that may have been deleted or modified. **Command:**

```cs
MFTECmd.exe -d C:\ -o C:\Output\Scheduled_Task_MFT.csv
```

**Analysis:** Look for traces of deleted or altered scheduled tasks that may have been used for privilege escalation.

## <mark style="color:blue;">5. Defence Evasion</mark>

### 5.1. Obfuscated Files or Information (T1027)

**Objective:** Detect and analyse obfuscated files and scripts used to evade detection.

**Tool: RECmd (Registry Explorer Command Line)**

**Instruction:** Search the registry for encoded or obfuscated scripts and commands that may indicate defense evasion. **Command:**

{% code overflow="wrap" %}
```cs
RECmd.exe -r C:\Windows\System32\config\SOFTWARE -b C:\Output\ -csv C:\Output\Obfuscated_Registry.csv
```
{% endcode %}

**Analysis:** Look for obfuscated entries in `PowerShell` and `WScript` registry keys.

**Tool: LECmd (LNK File Explorer Command Line)**

**Instruction:** Analyze LNK files for references to obfuscated scripts or files that may have been used to evade detection. **Command:**

```cs
LECmd.exe -d C:\Users\ -csv C:\Output\Obfuscated_LNK.csv
```

**Analysis:** Look for LNK files pointing to obfuscated or encoded scripts.

**Tool: JLECmd (Jump List Explorer Command Line)**

**Instruction:** Analyze Jump Lists for references to obfuscated scripts or files that may have been executed. **Command:**

```cs
JLECmd.exe -d C:\Users\ -csv C:\Output\Obfuscated_JumpLists.csv
```

**Analysis:** Review Jump Lists for evidence of encoded or obfuscated scripts being executed.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Event Logs to identify the execution of obfuscated scripts or commands. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx -csv C:\Output\Obfuscated_Scripts.csv
```
{% endcode %}

**Analysis:** Look for Event IDs indicating the execution of encoded or obfuscated scripts, especially under PowerShell.

**Tool: MFTECmd (Master File Table Parser)**

**Instruction:** Parse the MFT to identify files that have been obfuscated or encoded as part of defense evasion tactics. **Command:**

```cs
MFTECmd.exe -d C:\ -o C:\Output\Obfuscated_Files_MFT.csv
```

**Analysis:** Look for encoded or obfuscated files that may have been used to hide malicious activity.

## <mark style="color:blue;">6. Credential Access</mark>

### 6.1. OS Credential Dumping: LSASS Memory (T1003.001)

**Objective:** Detect and analyze attempts to dump credentials from the LSASS process.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Security Event Logs for evidence of credential dumping attempts. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx -csv C:\Output\Security_Events.csv
```
{% endcode %}

**Analysis:** Focus on Event IDs 4624 (Successful Logon), 4625 (Failed Logon), and 4656 (Handle Opened) for signs of credential dumping.

**Tool: RBCmd (Recycle Bin Command Line)**

**Instruction:** Check the Recycle Bin for deleted tools used for credential dumping, such as Mimikatz. **Command:**

```cs
RBCmd.exe -d C:\$Recycle.Bin\ -csv C:\Output\RBCmd_Output.csv
```

**Analysis:** Look for deleted files related to known credential dumping tools.

**Tool: PECmd (Prefetch Explorer Command Line)**

**Instruction:** Analyze Prefetch files for evidence of credential dumping tools being executed. **Command:**

```cs
PECmd.exe -d C:\Windows\Prefetch\ -csv C:\Output\Prefetch_Output.csv
```

**Analysis:** Look for entries related to known credential dumping tools like `mimikatz.exe`.

**Tool: MFTECmd (Master File Table Parser**

**Instruction:** Parse the MFT to identify files related to credential dumping tools being created or executed. **Command:**

```cs
MFTECmd.exe -d C:\ -o C:\Output\MFTECmd_Credential_Dumping.csv
```

**Analysis:** Look for entries related to known credential dumping tools in the MFT.

**Tool: RECmd (Registry Explorer Command Line)**

**Instruction:** Search the registry for references to credential dumping tools or activity. **Command:**

{% code overflow="wrap" %}
```cs
RECmd.exe -r C:\Windows\System32\config\SYSTEM -b C:\Output\ -csv C:\Output\Registry_Credential_Dumping.csv
```
{% endcode %}

**Analysis:** Check for suspicious entries in `Run` keys or other autorun locations referencing credential dumping tools.

## <mark style="color:blue;">7. Discovery</mark>

### 7.1. System Information Discovery (T1082)

**Objective:** Detect and collect evidence of system information discovery commands executed by an attacker.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Event Logs for system information discovery activities. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Microsoft-Windows-Security-Auditing.evtx -csv C:\Output\System_Info_Logs.csv
```
{% endcode %}

**Analysis:** Look for Event IDs indicating the execution of commands like `systeminfo`, `ipconfig`, and `hostname`.

**Tool: Registry Explorer**

**Instruction:** Manually check the registry for evidence of executed system information discovery commands. **Path:**

```kusto
HKEY_CURRENT_USER\Software\Microsoft\Command Processor\AutoRun
```

**Analysis:** Look for any command execution history indicating system information discovery.

**Tool: PECmd (Prefetch Explorer Command Line)**

**Instruction:** Analyze Prefetch files for evidence of system information discovery commands being executed. **Command:**

```cs
PECmd.exe -d C:\Windows\Prefetch\ -csv C:\Output\Prefetch_System_Info.csv
```

**Analysis:** Look for Prefetch entries related to `cmd.exe`, `systeminfo.exe`, `ipconfig.exe`, and other discovery tools.

**Tool: MFTECmd (Master File Table Parser)**

**Instruction:** Parse the MFT to identify files related to system information discovery tools being created or executed. **Command:**

```cs
MFTECmd.exe -d C:\ -o C:\Output\System_Info_MFT.csv
```

**Analysis:** Look for entries related to system discovery commands in directories like `System32`.

**Tool: JLECmd (Jump List Explorer Command Line)**

**Instruction:** Analyze Jump Lists for evidence of executed system discovery commands. **Command:**

```cs
JLECmd.exe -d C:\Users\ -csv C:\Output\JumpLists_System_Info.csv
```

**Analysis:** Review the output for Jump List entries related to system information discovery tools or commands.

## <mark style="color:blue;">8. Collection</mark>

### 8.1. Data from Local System (T1005)

**Objective:** Detect and collect artifacts related to data collection from the local system.

**Tool: MFTECmd (Master File Table Parser)**

**Instruction:** Parse the MFT for evidence of files being accessed or copied for data exfiltration. **Command:**

```cs
MFTECmd.exe -d C:\ -o C:\Output\Data_Collection_MFT.csv
```

**Analysis:** Look for files accessed or copied in user directories like `Documents` and `Downloads`.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Security Event Logs for evidence of file access and copying. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx -csv C:\Output\File_Access_Logs.csv
```
{% endcode %}

**Analysis:** Focus on Event IDs such as 4663 (File Accessed) to detect data collection activities.

**Tool: RECmd (Registry Explorer Command Line)**

**Instruction:** Search for registry keys related to file access or data collection tools. **Command:**

{% code overflow="wrap" %}
```cs
RECmd.exe -r C:\Windows\System32\config\SYSTEM -b C:\Output\ -csv C:\Output\Data_Collection_Registry.csv
```
{% endcode %}

**Analysis:** Look for registry entries referencing known data collection tools or scripts.

**Tool: JLECmd (Jump List Explorer Command Line)**

**Instruction:** Analyze Jump Lists for evidence of recently accessed files that may have been collected for exfiltration. **Command:**

```cs
JLECmd.exe -d C:\Users\ -csv C:\Output\JumpLists_Data_Collection.csv
```

**Analysis:** Review Jump Lists for references to sensitive files in user directories.

**Tool: LECmd (LNK File Explorer Command Line)**

**Instruction:** Examine LNK files for shortcuts to files that may have been collected by an attacker. **Command:**

```cs
LECmd.exe -d C:\Users\ -csv C:\Output\LNK_Data_Collection.csv
```

**Analysis:** Focus on LNK files pointing to sensitive or recently accessed files.

## <mark style="color:blue;">9. Exfiltration</mark>

### 9.1. Exfiltration Over C2 Channel (T1041)

**Objective:** Detect and collect artifacts related to data exfiltration over command-and-control (C2) channels.

**Tool: EvtxECmd (Windows Event Log Parser)**

**Instruction:** Parse Event Logs for evidence of data exfiltration over network connections. **Command:**

{% code overflow="wrap" %}
```cs
EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx -csv C:\Output\Sysmon_Network_Logs.csv
```
{% endcode %}

**Analysis:** Look for Event IDs related to network connections, focusing on unusual outbound traffic that may indicate data exfiltration.

**Tool: PECmd (Prefetch Explorer Command Line)**

**Instruction:** Analyze Prefetch files to identify executables used for data exfiltration, such as FTP clients or custom exfiltration tools. **Command:**

```cs
PECmd.exe -d C:\Windows\Prefetch\ -csv C:\Output\Exfiltration_Prefetch.csv
```

**Analysis:** Look for Prefetch entries associated with network utilities or tools commonly used for exfiltration.

**Tool: Registry Explorer**

**Instruction:** Check the registry for configuration changes related to network settings or proxies that could facilitate data exfiltration. **Path:**

```cs
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\
```

**Analysis:** Look for changes to proxy settings, VPN configurations, or other network-related keys.

**Tool: MFTECmd (Master File Table Parser)**

**Instruction:** Parse the MFT to identify files that were staged for exfiltration, such as large archives or compressed files. **Command:**

```cs
MFTECmd.exe -d C:\ -o C:\Output\Exfiltration_MFT.csv
```

**Analysis:** Look for large files or directories with recent modification dates in directories like `Downloads` or `Desktop`.

**Tool: JLECmd (Jump List Explorer Command Line)**

**Instruction:** Analyze Jump Lists for references to network tools or applications that may have been used for data exfiltration. **Command:**

```cs
JLECmd.exe -d C:\Users\ -csv C:\Output\JumpLists_Exfiltration.csv
```

**Analysis:** Review Jump Lists for evidence of data transfer applications, such as FTP clients, VPNs, or remote desktop tools.

For more on Eric Zimmerman's Tools, visit his website at: [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)

{% file src="../../../.gitbook/assets/Eric Zimmerman's Tools Commandline Cheatsheet.pdf" %}
