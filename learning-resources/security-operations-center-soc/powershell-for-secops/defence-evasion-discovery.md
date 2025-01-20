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

# Defence Evasion Discovery

### **Introduction**

PowerShell is a powerful and flexible tool for security operations (SecOps) teams, providing extensive capabilities to detect, investigate, and mitigate cyber threats in enterprise environments. Its deep integration with Windows, robust scripting functionality, and rich cmdlet library make it invaluable for digital forensics and incident response (DFIR) investigations. One of the critical areas where PowerShell excels is in uncovering **Defense Evasion Discovery** activities. Defence evasion involves techniques used by attackers to bypass security mechanisms, hide malicious activity, or maintain persistence without detection. PowerShell enables SecOps teams to efficiently identify these activities, providing actionable insights to contain and mitigate threats.

***

### **Capabilities of PowerShell for Defense Evasion Discovery in DFIR**

**1. Monitoring for Evasion Techniques in Logs:**

PowerShell can query event logs to uncover evidence of evasion techniques, such as clearing security logs, disabling auditing, or modifying log retention policies. It can also detect anomalies in event generation that may indicate tampering or suppression of logging.

**2. Detecting Obfuscated and Malicious Scripts:**

Attackers often use obfuscated scripts to evade detection. PowerShell’s script block logging and cmdlets allow analysts to analyse suspicious or encoded commands, helping to identify and decode potentially malicious scripts used in evasion tactics.

**3. Identifying Disabled Security Tools:**

Attackers may attempt to disable antivirus software, firewalls, or endpoint detection and response (EDR) solutions. PowerShell can monitor system configurations and services to detect disabled or tampered security tools.

**4. Detecting DLL Injection and Code Execution Evasion:**

PowerShell facilitates the detection of suspicious processes or loaded DLLs that attackers use for stealthy code execution. Analysts can also identify uncommon parent-child process relationships indicative of evasion attempts.

**5. Analysing Permissions and Policy Modifications:**

Attackers may alter permissions, policies, or access control lists (ACLs) to evade detection. PowerShell provides tools to inspect and audit these configurations, helping to identify unauthorised changes that could indicate evasion activities.

**6. Investigating File and Registry Manipulations:**

PowerShell can uncover hidden files, altered file attributes, or suspicious registry keys that attackers use to mask their presence. This includes identifying the use of hidden directories, renamed files, or registry-based persistence mechanisms.

**7. Detecting Network Traffic Evasion:**

PowerShell can analyse network configurations and active connections to detect signs of traffic redirection, tunnelling, or the use of non-standard protocols aimed at evading network monitoring systems.

***

### **Efficiency Provided by PowerShell in Defense Evasion Discovery**

1. **Comprehensive System Visibility**: PowerShell provides detailed insights into processes, configurations, logs, and other system components, enabling thorough detection of defence evasion activities.
2. **Real-Time Analysis: PowerShell’s dynamic querying capabilities allow security teams to monitor and analyse system behaviour in real-time, reducing the time needed to identify evasion attempts.**
3. **Scalability**: With **PowerShell Remoting**, analysts can perform defence evasion discovery across multiple systems simultaneously, making it efficient for large-scale investigations.
4. **Automation of Detection Tasks**: PowerShell scripts can automate repetitive tasks, such as scanning for disabled security tools or analysing logs for tampering, ensuring consistency and saving valuable time.
5. **Customisable Detection**: PowerShell enables the creation of tailored scripts to detect specific evasion techniques, aligning investigations with frameworks like **MITRE ATT\&CK** and organisational threat profiles.
6. **Integration with Security Ecosystems**: PowerShell integrates seamlessly with security platforms such as Microsoft Sentinel, Defender for Endpoint, and SIEM tools, allowing enriched data collection and automated incident responses.

***

By leveraging PowerShell’s extensive capabilities, SecOps teams can efficiently uncover and respond to defence evasion activities, ensuring threats are detected and mitigated swiftly to protect enterprise systems and maintain security integrity.

### Defence Evasion Discovery

### 1. **Antivirus and Security Tools Interference**

**1.1. Detecting Disabling of Antivirus Software**

**Purpose**: Identify attempts to disable or modify antivirus settings.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Where-Object {$_.Properties[0].Value -match 'Antivirus'} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[5].Value}}
```
{% endcode %}

**1.2. Monitoring Modifications to Windows Defender**

**Purpose**: Detect changes to Windows Defender settings that could indicate tampering.

{% code overflow="wrap" %}
```powershell
Get-MpPreference | Select-Object -Property DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableScriptScanning
```
{% endcode %}

### 2. **Log Deletion and Tampering**

**2.1. Detecting Clearing of Security Event Logs**

**Purpose**: Identify attempts to clear security event logs to cover tracks.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102}
```

**2.2. Monitoring for Deletion of Log Files**

**Purpose**: Detect deletion of log files, which may indicate an attempt to remove evidence.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\System32\winevt\Logs\" -Filter "*.evtx" |  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

### 3. **Obfuscation Techniques**

**3.1. Detecting Encoded PowerShell Commands**

**Purpose**: Identify the use of encoded commands to obfuscate PowerShell scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match '-enc'}
```
{% endcode %}

**3.2. Monitoring Use of Base64 Encoding**

**Purpose**: Detect use of Base64 encoding, which can be used to obfuscate scripts or payloads.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'FromBase64String'}
```
{% endcode %}

### 4. **Bypassing User Account Control (UAC)**

**4.1. Detecting UAC Bypass Attempts**

**Purpose**: Identify registry or system changes indicative of UAC bypass attempts.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin
```
{% endcode %}

**4.2. Monitoring for SilentElevation Usage**

**Purpose**: Detect the use of SilentElevation to bypass UAC prompts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4673} | Where-Object {$_.Properties[0].Value -match 'SeImpersonatePrivilege'}
```
{% endcode %}

### 5. **Hiding Artifacts and File Manipulation**

**5.1. Detecting Hidden Files and Directories**

**Purpose**: Identify hidden files or directories that may be used to conceal malicious activities.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\*" -Force | Where-Object {($_.Attributes -match 'Hidden') -or ($_.Attributes -match 'System')}
```
{% endcode %}

**5.2. Monitoring for Alternate Data Streams (ADS)**

**Purpose**: Detect the use of alternate data streams to hide data.

```powershell
Get-Item -Path "C:\*" -Stream *
```

### 6. **Code Injection and Process Manipulation**

**6.1. Monitoring for Process Injection Attempts**

**Purpose**: Detect attempts to inject code into other processes.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {$_.Properties[9].Value -match 'AccessMask: 0x1F0FFF'}
```
{% endcode %}

**6.2. Detecting Unusual Parent-Child Process Relationships**

**Purpose**: Identify unusual process hierarchies that may indicate process hollowing or other injection techniques.

{% code overflow="wrap" %}
```powershell
Get-CimInstance -ClassName Win32_Process |  Select-Object ProcessId, Name, ParentProcessId | Where-Object {($_.ParentProcessId -ne 0) -and ($_.Name -match "cmd.exe|powershell.exe")}
```
{% endcode %}

### 7. **Modifying System Settings for Evasion**

**7.1. Monitoring Changes to Host Firewall Settings**

**Purpose**: Detect changes to firewall rules that may allow unauthorized network traffic.

{% code overflow="wrap" %}
```powershell
Get-NetFirewallRule -PolicyStore ActiveStore |  Where-Object {($_.Action -eq 'Allow') -and ($_.Enabled -eq 'True')}
```
{% endcode %}

**7.2. Detecting Modifications to Network Security Settings**

**Purpose**: Identify changes to network security settings that could indicate evasion.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" | Select-Object Description, SettingID, IPAddress, DefaultIPGateway
```
{% endcode %}

### 8. **Application Whitelisting and Execution Control Bypass**

**8.1. Detecting AppLocker Policy Changes**

**Purpose**: Identify unauthorized changes to AppLocker policies.

{% code overflow="wrap" %}
```powershell
Get-AppLockerPolicy -Effective | Select-String -Pattern "Path", "Publisher", "FileHash"
```
{% endcode %}

**8.2. Monitoring Changes to Software Restriction Policies**

**Purpose**: Detect changes to software restriction policies that could allow unauthorized software execution.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
```
{% endcode %}

### 9. **Disabling Security Controls**

**9.1. Detecting Changes to Windows Security Center**

**Purpose**: Identify changes that disable or tamper with the Windows Security Center.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Security Center" -Name * | Select-Object PSChildName, *
```
{% endcode %}

**9.2. Monitoring Tampering with Security Auditing**

**Purpose**: Detect changes to auditing policies that could disable monitoring.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name AuditBaseObjects
```
{% endcode %}

### 10. **Manipulating System Logs and Auditing**

**10.1. Monitoring for Clearing of Application Logs**

**Purpose**: Detect the clearing of application logs, which may indicate an attempt to remove traces of activity.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=104} | Where-Object {$_.Message -match 'The event log was cleared'}
```
{% endcode %}

**10.2. Detecting Changes to Audit Log Settings**

**Purpose**: Identify changes to audit log settings that could indicate attempts to hide actions.

{% code overflow="wrap" %}
```powershell
Get-AuditPolicy | Where-Object {$_.Category -match 'Logon/Logoff'} | Select-Object Subcategory, Success, Failure
```
{% endcode %}
