---
icon: laptop-code
---

# Investigating System Compromises - Sysinternals Tools

## <mark style="color:blue;">1. Initial Access</mark>

### 1.1. Phishing: Spearphishing Attachment (T1566.001)

**Objective:** Detect and collect evidence of malicious email attachments that may have been used to gain initial access.

**Tool: Procmon (Process Monitor)**

**Instruction:** Use Procmon to monitor and filter file system activity related to email clients (e.g., Outlook). - **Steps:** 1. Launch Procmon. 2. Set a filter: `Process Name is OUTLOOK.EXE` (or any other email client). 3. Monitor for file writes to directories like `Downloads`, `Temp`, or `INetCache`. 4. Save the capture for detailed analysis.

**Tool: Sigcheck (Signature Verification Tool)**

**Instruction:** Verify the digital signatures of executables found in suspicious directories, such as downloads or temporary folders. **Command:**

{% code overflow="wrap" %}
```powershell
sigcheck.exe -e -v C:\Users\%USERNAME%\Downloads\*.exe > C:\Output\sigcheck_results.txt`
```
{% endcode %}

**Analysis:** Review the output for unsigned or suspicious executables.

**Tool: Streams (Alternate Data Streams Viewer)**

**Instruction:** Check for Alternate Data Streams (ADS) that might hide malicious attachments. **Command:**

```cs
streams.exe -s C:\Users\%USERNAME%\Downloads\ > C:\Output\streams_output.txt
```

**Analysis:** Look for files with unexpected ADS, indicating potential hidden content.

**Tool: Autoruns**

**Instruction:** Identify startup programs that might have been introduced by a phishing attack. **Steps:** 1. Launch Autoruns. 2. Filter by `Logon` and `Startup` entries. 3. Review for suspicious entries, especially those with unusual file paths or unsigned binaries.

**Tool: Strings (String Extraction Utility)**

**Instruction:** Extract and analyze strings from suspicious files to identify hidden scripts or commands. **Command:**

{% code overflow="wrap" %}
```cs
strings.exe C:\Users\%USERNAME%\Downloads\suspicious.exe > C:\Output\strings_output.txt
```
{% endcode %}

**Analysis:** Search the extracted strings for URLs, IP addresses, or encoded scripts that may indicate malicious activity.

## <mark style="color:blue;">2. Execution</mark>

### 2.1. Command and Scripting Interpreter: PowerShell (T1059.001)

**Objective:** Detect and analyze PowerShell usage that may indicate the execution of malicious scripts.

**Tool: Procmon (Process Monitor)**

**Instruction:** Monitor and filter PowerShell activity to detect suspicious commands. **Steps:** 1. Launch Procmon. 2. Set a filter: `Process Name is powershell.exe`. 3. Focus on command-line arguments, especially those containing `-enc` (indicating encoded scripts). 4. Save the filtered results for analysis.

**Tool: Autoruns**

**Instruction:** Check for PowerShell scripts configured to run at startup. **Steps:** 1. Open Autoruns and navigate to the `Logon` tab. 2. Look for entries where PowerShell is used in the command line. 3. Investigate any scripts or commands set to run automatically.

**Tool: Strings**

**Instruction:** Extract strings from PowerShell script files to identify obfuscated or malicious content. **Command:**

```cs
strings.exe C:\Users\%USERNAME%\Documents\*.ps1 > C:\Output\strings_output.txt`
```

**Analysis:** Review the extracted strings for suspicious commands, URLs, or encoded content.

**Tool: PsExec (Remote Execution Tool)**

**Instruction:** Use PsExec to remotely execute PowerShell commands and check for running scripts. **Command:**

{% code overflow="wrap" %}
```cs
psexec.exe \\TARGET -s powershell.exe Get-Process | Where-Object {$_.Name -eq 'powershell'}
```
{% endcode %}

**Analysis:** Identify unauthorized or suspicious PowerShell processes running on remote systems.

**Tool: ProcDump (Process Dump Utility)**

**Instruction:** Use ProcDump to capture the memory of a running PowerShell process for further analysis. **Command:**

```cs
procdump.exe -ma powershell.exe C:\Output\powershell_dump.dmp
```

**Analysis:** Analyze the memory dump using forensic tools to search for suspicious scripts or commands.

## <mark style="color:blue;">3. Persistence</mark>

### 3.1. Registry Run Keys / Startup Folder (T1547.001)

**Objective:** Detect persistence mechanisms that use registry run keys or startup folders.

**Tool: Autoruns**

**Instruction:** Identify programs configured to run at startup through registry keys or startup folders. **Steps:** 1. Open Autoruns and navigate to the `Logon` tab. 2. Review all entries, focusing on unknown or unsigned executables. 3. Pay attention to file paths in `Temp` or non-standard directories.

**Tool: Reg (Registry Command Line Tool)**

**Instruction:** Manually query and export registry run keys for offline analysis. **Command:**

{% code overflow="wrap" %}
```cs
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run > C:\Output\run_keys.txt reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run >> C:\Output\run_keys.txt
```
{% endcode %}

**Analysis:** Review the output for suspicious entries, particularly those pointing to non-standard executables.

**Tool: Procmon**

**Instruction:** Monitor registry changes to detect new or modified persistence mechanisms. **Steps:** 1. Launch Procmon. 2. Set a filter: `Operation is RegSetValue`. 3. Monitor changes to keys such as

```cs
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
```

```
    5. Save the logs for analysis.
```

**Tool: PsExec**

**Instruction:** Remotely query registry run keys on multiple machines to detect persistence. **Command:**

{% code overflow="wrap" %}
```cs
psexec.exe \\TARGET -s reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
```
{% endcode %}

**Analysis:** Collect and analyze registry entries for potential persistence mechanisms across multiple systems.

**Tool: Autorunsc (Command-Line Autoruns)**

**Instruction:** Use Autorunsc to script the collection of autorun entries across multiple systems. **Command:**

```cs
autorunsc.exe -a * > C:\Output\autoruns_output.txt
```

**Analysis:** Review the output for suspicious autorun entries, focusing on unknown or unsigned executables.

## <mark style="color:blue;">4. Privilege Escalation</mark>

### 4.1. Scheduled Task/Job (T1053.005)

**Objective:** Detect and analyze scheduled tasks that may have been created for privilege escalation.

**Tool: Autoruns**

**Instruction:** Identify and analyze scheduled tasks configured to run with elevated privileges. - **Steps:** 1. Open Autoruns and navigate to the `Scheduled Tasks` tab. 2. Review tasks for unusual or unknown executables. 3. Investigate tasks set to run with high privileges or under the SYSTEM account.

**Tool: Tasklist (Task List Utility)**

**Instruction:** List all scheduled tasks running on the system and check their privilege levels. **Command:**

```cs
tasklist /v > C:\Output\tasklist_output.txt
```

**Analysis:** Review the output for tasks running under SYSTEM or other high-privilege accounts.

**Tool: Procmon**

**Instruction:** Monitor the creation and execution of scheduled tasks. - **Steps:** 1. Set filters in Procmon: `Process Name is taskeng.exe` and `Operation is Process Create`. 2. Capture task creation and execution events. 3. Save the log for further analysis.

**Tool: Schtasks (Scheduled Task Command Line Utility)**

**Instruction:** Use Schtasks to query and manage scheduled tasks on the local or remote systems. **Command:**

```cs
schtasks /query /fo LIST /v > C:\Output\scheduled_tasks.txt
```

**Analysis:** Review the list of scheduled tasks for suspicious entries, especially those running with elevated privileges.

**Tool: PsExec**

**Instruction:** Remotely check for scheduled tasks on multiple systems. **Command:**

{% code overflow="wrap" %}
```cs
psexec.exe \\TARGET -s schtasks /query /FO LIST > C:\Output\scheduled_tasks_output.txt
```
{% endcode %}

**Analysis:** Collect and analyze scheduled task configurations from remote systems for signs of privilege escalation.

## <mark style="color:blue;">5. Defence Evasion</mark>

### 5.1. Obfuscated Files or Information (T1027)

**Objective:** Detect and analyze obfuscated files and scripts used to evade detection.

**Tool: Strings**

**Instruction:** Analyze files for hidden or obfuscated commands by extracting readable strings. **Command:**

```cs
strings.exe C:\Path\To\SuspiciousFile.exe > C:\Output\strings_output.txt
```

**Analysis:** Look for encoded scripts, obfuscated URLs, or suspicious commands within the file.

**Tool: Sigcheck**

**Instruction:** Identify files that may have been modified or obfuscated to evade detection. **Command:**

```cs
sigcheck.exe -e -v C:\Path\To\SuspiciousFile.exe > C:\Output\sigcheck_results.txt
```

**Analysis:** Focus on files with invalid or missing digital signatures.

**Tool: Procmon**

**Instruction:** Monitor processes for the execution of obfuscated or encoded scripts. **Steps:** 1. Set a filter: `Process Name is powershell.exe` or `Process Name is cmd.exe`. 2. Capture command-line arguments involving `-enc` or obfuscated scripts. 3. Save the logs for further analysis.

**Tool: Autoruns**

**Instruction:** Identify obfuscated scripts or executables set to run at startup. **Steps:** 1. Filter by `Logon` or `Scheduled Tasks`. 2. Look for suspicious entries with unusual file paths or encoded commands. 3. Investigate any unknown or unsigned entries.

**Tool: Streams**

**Instruction:** Use Streams to detect hidden data within files using Alternate Data Streams (ADS). **Command:**

```cs
streams.exe -s C:\Path\To\Directory > C:\Output\streams_output.txt
```

**Analysis:** Look for files with unexpected ADS, which could indicate hidden malicious content.

## <mark style="color:blue;">6. Credential Access</mark>

### 6.1. OS Credential Dumping: LSASS Memory (T1003.001)

**Objective:** Detect and analyse attempts to dump credentials from the LSASS process.

**Tool: Procmon**

**Instruction:** Monitor for processes that attempt to access LSASS memory. **Steps:** 1. Set a filter: `Process Name is lsass.exe` and `Operation is Process Create`. 2. Monitor for suspicious processes like `procdump.exe` or `mimikatz.exe`. 3. Save the logs for detailed analysis.

**Tool: Autoruns**

**Instruction:** Check for credential dumping tools configured to run at startup. **Steps:** 1. Filter by `Logon` or `Scheduled Tasks`. 2. Look for entries related to known tools like `mimikatz`. 3. Investigate any unknown or unsigned entries.

**Tool: Sigcheck**

**Instruction:** Verify the integrity of system binaries, particularly LSASS, to ensure they haven’t been tampered with. **Command:**

```cs
sigcheck.exe -e -v C:\Windows\System32\lsass.exe > C:\Output\sigcheck_lsass.txt
```

**Analysis:** Ensure that LSASS and other critical system binaries have valid signatures

**Tool: PsExec**

**Instruction:** Remotely check for running processes that may be attempting credential dumping on other systems. **Command:**

```cs
psexec.exe \\TARGET -s tasklist /svc | findstr /i "lsass procdump mimikatz"
```

**Analysis:** Identify any unauthorized processes interacting with LSASS.

**Tool: ProcDump**

**Instruction:** Use ProcDump to safely capture the LSASS process memory for offline analysis. **Command:**

```cs
procdump.exe -ma lsass.exe C:\Output\lsass_dump.dmp
```

**Analysis:** Analyse the dump file with a forensic tool to detect signs of credential dumping.

## <mark style="color:blue;">7. Discovery</mark>

### 7.1. System Information Discovery (T1082)

**Objective:** Detect and collect evidence of system information discovery commands executed by an attacker.

**Tool: Procmon**

**Instruction:** Monitor for system information discovery commands. **Steps:** 1. Set filters: `Process Name is cmd.exe` and `Operation is Process Create`. 2. Capture commands like `systeminfo`, `ipconfig`, or `hostname`. 3. Save the logs for further analysis.

**Tool: PsExec**

**Instruction:** Use PsExec to remotely execute and check for system information discovery commands. **Command:**

{% code overflow="wrap" %}
```cs
psexec.exe \\TARGET cmd.exe /c "systeminfo & ipconfig & netstat -an" > C:\Output\sysinfo_output.txt
```
{% endcode %}

**Analysis:** Compare the output with expected system configurations to detect unauthorized commands.

**Tool: Autoruns**

**Instruction:** Check for scripts or executables configured to run at startup that may perform system discovery. **Steps:** 1. Filter by `Logon` or `Scheduled Tasks`. 2. Look for suspicious entries that run discovery commands. 3. Investigate any unknown or unsigned entries.

**Tool: Strings**

**Instruction:** Extract and analyze strings from scripts or batch files for system discovery commands. **Command:**

```cs
strings.exe C:\Path\To\SuspiciousFile.bat > C:\Output\strings_sysinfo.txt
```

**Analysis:** Look for common system discovery commands such as `systeminfo`, `ipconfig`, and `tasklist`.

**Tool: Tasklist**

**Instruction:** Use Tasklist to list all running tasks and check for system discovery tools. **Command:**

```cs
tasklist /v > C:\Output\tasklist_output.txt
```

**Analysis:** Review the list of running processes for known discovery tools or suspicious activity.

## <mark style="color:blue;">8. Collection</mark>

### 8.1. Data from Local System (T1005)

**Objective:** Detect and collect artifacts related to data collection from the local system.

**Tool: Procmon**

**Instruction:** Monitor file system access, especially in sensitive directories like `Documents` or `Downloads`. **Steps:** 1. Set filters: `Operation is ReadFile` or `WriteFile` targeting sensitive directories. 2. Capture events where files are accessed or copied. 3. Save the logs for further analysis.

**Tool: PsExec**

**Instruction:** Use PsExec to remotely check for recently accessed files on other systems. **Command:**

{% code overflow="wrap" %}
```cs
psexec.exe \\TARGET cmd.exe /c "dir /s /od C:\Users\%USERNAME%\Documents\ > C:\Output\recent_docs.txt"
```
{% endcode %}

{% code overflow="wrap" %}
```
- **Analysis:** Review the list of recently accessed files for sensitive documents or unauthorized access.
```
{% endcode %}

**Tool: Autoruns**

**Instruction:** Check for programs or scripts configured to collect data at startup. **Steps:** 1. Filter by `Logon` or `Scheduled Tasks`. 2. Look for suspicious entries that access or move files. 3. Investigate any unknown or unsigned entries.

**Tool: Strings**

**Instruction:** Analyse scripts or executables for commands related to data collection. **Command:**

```cs
strings.exe C:\Path\To\SuspiciousFile.exe > C:\Output\strings_collection.txt
```

**Analysis:** Look for commands or paths related to copying or exfiltrating data, especially to external drives or network shares.

**Tool: Streams**

**Instruction:** Use Streams to detect hidden data within files using Alternate Data Streams (ADS). **Command:**

```cs
streams.exe -s C:\Users\%USERNAME%\Documents\ > C:\Output\streams_output.txt
```

**Analysis:** Check for files with unexpected ADS, indicating potential data hiding or exfiltration.

## <mark style="color:blue;">9. Exfiltration</mark>

### 9.1. Exfiltration Over C2 Channel (T1041)

**Objective:** Detect and analyse data exfiltration attempts over command-and-control (C2) channels.

**Tool: Procmon**

**Instruction:** Monitor network activity, especially outbound connections that may be used for exfiltration. **Steps:** 1. Set filters: `Operation is TCP Connect` and monitor outbound traffic. 2. Focus on connections to unusual or suspicious IP addresses. 3. Save the logs for further analysis.

**Tool: PsExec**

**Instruction:** Remotely check for network activity on multiple systems. **Command:**

```cs
psexec.exe \\TARGET netstat -an > C:\Output\netstat_output.txt
```

**Analysis:** Review the output for unexpected or suspicious connections, particularly outbound traffic to external IP addresses.

**Tool: Strings**

**Instruction:** Analyse scripts or executables for embedded network commands used for exfiltration. **Command:**

```cs
strings.exe C:\Path\To\SuspiciousFile.exe > C:\Output\strings_exfiltration.txt
```

**Analysis:** Look for URLs, IP addresses, or FTP commands that may be used to exfiltrate data.

**Tool: Autoruns**

**Instruction:** Identify programs or scripts set to run at startup that may be used for data exfiltration. **Steps:** 1. Filter by `Logon` or `Scheduled Tasks`. 2. Look for suspicious entries that establish network connections or move files to external locations. 3. Investigate any unknown or unsigned entries.

**Tool: ProcDump**

**Instruction:** Use ProcDump to capture the memory of processes suspected of data exfiltration for further analysis. **Command:**

```cs
procdump.exe -ma C:\Path\To\SuspiciousProcess.exe C:\Output\exfiltration_dump.dmp
```

**Analysis:** Analyse the memory dump for signs of data transfer or communication with C2 servers.
