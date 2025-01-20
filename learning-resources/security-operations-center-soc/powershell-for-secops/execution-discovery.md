---
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

# Execution Discovery

### **Introduction**

PowerShell is a powerful and versatile tool for security operations (SecOps) teams, offering robust capabilities for investigating and responding to threats in enterprise networks. Its seamless integration with the Windows operating system and comprehensive library of cmdlets make it particularly effective for conducting **Execution Discovery** activities during digital forensics and incident response (DFIR) investigations. Execution Discovery focuses on uncovering evidence of malicious or unauthorized code execution, a common tactic used by attackers to deliver payloads, execute scripts, or run exploit tools. PowerShell enables SecOps teams to efficiently detect and analyze these activities, facilitating swift and precise incident response.

***

### **Capabilities of PowerShell for Execution Discovery in DFIR**

**1. Process and Command-Line Monitoring:**

PowerShell provides deep visibility into running processes and their associated command-line arguments. This allows analysts to detect suspicious or unauthorised execution, such as malicious scripts, encoded commands, or exploit tools. It is particularly effective in identifying processes spawned by unusual parent-child relationships, which often indicate attacker activity.

**2. Analysis of PowerShell Script Execution:**

Since attackers frequently abuse PowerShell to execute scripts or payloads, PowerShell's built-in logging and query capabilities are invaluable for analysing script block logs and event data. This helps security teams uncover evidence of malicious PowerShell usage, including obfuscated or encoded commands designed to evade detection.

**3. Scheduled Task and Service Analysis:**

Attackers often use scheduled tasks or services to execute malicious payloads. PowerShell enables analysts to investigate existing tasks, startup items, and service configurations to identify unauthorised or anomalous entries linked to execution discovery activities.

**4. Binary and DLL Execution Detection:**

PowerShell can be used to inspect binaries and dynamic link libraries (DLLs) executed on a system. This includes monitoring for unsigned or unusual executables and DLLs loaded by processes, providing evidence of potentially malicious activity.

**5. Memory and File Analysis:**

PowerShell facilitates memory analysis by enabling the extraction of process memory for forensic examination. Additionally, it can identify files dropped by attackers for execution, such as staged payloads or tools, and extract metadata for further analysis.

**6. Event Log and Telemetry Analysis:**

PowerShell’s ability to query event logs allows analysts to investigate execution-related events, such as process creation logs, PowerShell operation logs, and security logs. This aids in correlating events to identify patterns indicative of malicious execution activities.

***

### **Efficiency Provided by PowerShell in Execution Discovery**

1. **Granular Visibility**: PowerShell offers fine-grained visibility into processes, logs, and system events, enabling precise detection and investigation of execution discovery activities.
2. **Scalability**: With PowerShell Remoting, SecOps teams can scale investigations across hundreds or thousands of endpoints, ensuring comprehensive coverage in large enterprise environments.
3. **Real-Time Detection**: PowerShell enables real-time querying and monitoring of execution-related data, reducing the time required to identify and respond to threats.
4. **Automation and Repeatability**: By automating routine tasks, such as process analysis or log queries, PowerShell ensures consistent and efficient investigation workflows.
5. **Customisable Detection**: PowerShell scripts can be tailored to align with organisational baselines and the **MITRE ATT\&CK framework**, focusing on specific execution techniques or adversarial behaviours.
6. **Integration with Security Tools**: PowerShell integrates seamlessly with tools like Microsoft Sentinel, Defender for Endpoint, and other SIEM platforms, enabling enriched detection and streamlined incident response workflows.

***

By leveraging the capabilities of PowerShell, SecOps teams can effectively identify and investigate execution discovery activities, facilitating rapid containment and mitigation while strengthening the organisation’s overall security posture.

### Execution Discovery

### 1. **Monitoring Process Execution**

**1.1. Detecting New Executable Processes**

**Purpose**: Identify newly started executable processes.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**1.2. Detecting Unusual Command Line Parameters**

**Purpose**: Identify processes with unusual or suspicious commandline parameters.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[9].Value -match '-exec bypass'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

### 2. **PowerShell Script Execution Monitoring**

**2.1. Detecting Encoded PowerShell Commands**

**Purpose**: Identify potentially malicious encoded PowerShell commands.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |  Where-Object {$_.Message -match '-enc'}
```
{% endcode %}

**2.2. Monitoring PowerShell Script Block Logging**

**Purpose**: Capture details of executed PowerShell scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

### 3. **Identifying Execution of Scripting Languages**

**3.1. Detecting VBScript Execution**

**Purpose**: Identify execution of VBScript, which could indicate malicious activity.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[5].Value -match 'wscript.exe|cscript.exe'}
```
{% endcode %}

**3.2. Monitoring JScript Execution**

**Purpose**: Detect the execution of JScript files.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[5].Value -match 'wscript.exe|cscript.exe'} | Where-Object {$_.Properties[9].Value -match '\.js$'}
```
{% endcode %}

### 4. **Malicious Use of Built-in Tools**

**4.1. Monitoring Mshta Execution**

**Purpose**: Identify the use of `mshta.exe`, which can be used to execute malicious scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'mshta.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**4.2. Detecting Usage of Rundll32**

**Purpose**: Identify malicious usage of `rundll32.exe`.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'rundll32.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

### 5. **Macro Execution and Document Exploits**

**5.1. Detecting Office Macro Execution**

**Purpose**: Identify when Office applications execute macros, which may indicate macro-based malware.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Office-Alerts'; ID=300} | Where-Object {$_.Message -match 'Macro'}
```
{% endcode %}

**5.2. Monitoring Malicious Document Execution**

**Purpose**: Detect execution of malicious documents, such as those with embedded exploits.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Office-Alerts'; ID=300} | Where-Object {$_.Message -match '.docm|.xlsm|.pptm'}
```
{% endcode %}

### 6. **Windows Management Instrumentation (WMI) Execution**

**6.1. Detecting WMI Command Execution**

**Purpose**: Identify commands executed via WMI, often used for remote execution.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} |  Where-Object {$_.Message -match 'CommandLineEventConsumer'}
```
{% endcode %}

**6.2. Monitoring WMI Subscription Events**

**Purpose**: Detect suspicious WMI subscriptions, which can be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5858} | Where-Object {$_.Message -match 'FilterToConsumerBinding'}
```
{% endcode %}

### 7. **Execution via Services and Tasks**

**7.1. Detecting Service Execution**

**Purpose**: Monitor the creation or modification of services that execute commands.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} |  Where-Object {$_.Properties[1].Value -notin 'KnownGoodServices'}
```
{% endcode %}

**7.2. Monitoring Scheduled Task Creation**

**Purpose**: Identify the creation of scheduled tasks for executing commands.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | Select-Object TaskName, @{n='Actions';e={$_.Actions}}
```
{% endcode %}

### 8. **Credential Dumping and Usage**

**8.1. Detecting LSASS Memory Access**

**Purpose**: Identify attempts to access LSASS memory for credential dumping.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} |  Where-Object {$_.Properties[9].Value -match 'lsass.exe'}
```
{% endcode %}

**8.2. Monitoring Mimikatz Usage**

**Purpose**: Detect the use of Mimikatz, a tool commonly used for credential dumping.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[9].Value -match 'mimikatz'}
```
{% endcode %}

### 9. **Execution of Exploit Tools**

**9.1. Detecting Exploit Framework Usage**

**Purpose**: Identify the execution of known exploit frameworks like Metasploit.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[9].Value -match 'metasploit'}
```
{% endcode %}

**9.2. Monitoring the Use of Cobalt Strike**

**Purpose**: Detect the use of Cobalt Strike, a popular post-exploitation tool.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[9].Value -match 'cobaltstrike'}
```
{% endcode %}

### 10. **Script and Binary Obfuscation**

**10.1. Detecting Obfuscated PowerShell Scripts**

**Purpose**: Identify the use of obfuscated PowerShell scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |  Where-Object {$_.Message -match '(FromBase64String|Invoke-Expression)'}
```
{% endcode %}

**10.2. Monitoring Executables with Uncommon File Extensions**

**Purpose**: Detect executables disguised with uncommon file extensions.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[5].Value -match '\.scr|\.pif|\.bat'}
```
{% endcode %}

### **Additional Discovery Techniques**

### 1. **Monitoring Script Execution**

**1.1. Detecting PowerShell Script Execution**

**Purpose**: Identify the execution of PowerShell scripts, especially those with potentially malicious content.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

**1.2. Monitoring Batch File Execution**

**Purpose**: Detect the execution of batch files, which may indicate malicious script usage.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match '\.bat'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

### 2. **Malicious Use of Legitimate Tools**

**2.1. Detecting the Use of Mshta**

**Purpose**: Identify the use of`mshta.exe` often used to execute malicious scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'mshta.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**2.2. Monitoring for RunDLL32 Execution**

**Purpose**: Detect the use of `rundll32.exe` to execute DLL files, which may be used for malicious purposes.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'rundll32.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

### 3. **Unauthorised Software and Tool Usage**

**3.1. Detecting Unauthorized Software Installation**

**Purpose**: Identify the installation of unauthorized software, which may indicate malicious intent.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=11707} | Select-Object TimeCreated, @{n='ProductName';e={$_.Properties[0].Value}}, @{n='InstalledBy';e={$_.Properties[1].Value}}
```
{% endcode %}

**3.2. Monitoring Portable Executables**

**Purpose**: Detect the use of portable executables, which can bypass security controls.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\Downloads" -Recurse -Include *.exe, *.com, *.scr | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

### 4. **Remote Command Execution**

**4.1. Monitoring for Remote PowerShell Execution**

**Purpose**: Detect unauthorized use of PowerShell for remote command execution.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103} | Where-Object {$_.Message -match 'Remote'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Message}}
```
{% endcode %}

**4.2. Detecting WMI Command Execution**

**Purpose**: Identify commands executed via Windows Management Instrumentation (WMI).

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} | Where-Object {$_.Message -match 'CommandLineEventConsumer'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Message}}
```
{% endcode %}

### 5. **Execution of Scripting Languages**

**5.1. Monitoring VBScript Execution**

**Purpose**: Detect execution of VBScript files, which may be used for malicious purposes.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'wscript.exe|cscript.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**5.2. Detecting JScript Execution**

**Purpose**: Identify the execution of JScript files, which can be used to execute malicious scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'wscript.exe|cscript.exe'} | Where-Object {$_.Properties[9].Value -match '\.js$'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

### 6. **Executable and DLL Injection**

**6.1. Detecting Code Injection Attempts**

**Purpose**: Monitor for attempts to inject code into other processes.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {$_.Properties[9].Value -match 'AccessMask: 0x1F0FFF'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='HandleID';e={$_.Properties[7].Value}}
```
{% endcode %}

**6.2. Monitoring DLL Injection via RunDLL32**

**Purpose**: Detect the use of `rundll32.exe` for DLL injection.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'rundll32.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

### 7. **Malicious Use of System Tools**

**7.1. Detecting Usage of CertUtil**

**Purpose**: Identify the use of `certutil.exe` which can be misused for malicious purposes.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'certutil.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**7.2. Monitoring for Bitsadmin Usage**

**Purpose**: Detect the use of bi`tsadmin.exe` , which can be used for data transfer.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'bitsadmin.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

### 8. **Application Whitelisting Bypass**

**8.1. Detecting Application Whitelisting Bypass via LOLBins**

**Purpose**: Identify the use of living-off-the-land binaries (LOLBins) to bypass security controls.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'rundll32.exe|regsvr32.exe|mshta.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**8.2. Monitoring Bypass Attempts via Dynamic Invocation**

**Purpose**: Detect attempts to bypass application whitelisting using dynamic invocation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'Invoke-Expression|Invoke-Command'} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

### 9. **Macro and Script Exploitation**

**9.1. Monitoring for Malicious Office Macros**

**Purpose**: Detect the execution of potentially malicious macros in Office documents.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Office-Alerts'; ID=300} | Where-Object {$_.Message -match 'macro'} | Select-Object TimeCreated, @{n='DocumentName';e={$_.Message}}
```
{% endcode %}

**9.2. Detecting Malicious Scripts via Document Execution**

**Purpose**: Identify the execution of scripts embedded in documents.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'Invoke-Mimikatz'} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

### 10. **Exploitation Tools and Post-Exploitation Frameworks**

**10.1. Detecting Cobalt Strike Beacon Execution**

**Purpose**: Identify the execution of Cobalt Strike beacons.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'cobaltstrike'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**10.2. Monitoring for Metasploit Framework Usage**

**Purpose**: Detect the use of Metasploit, a popular penetration testing tool.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'metasploit'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}
