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

# PowerShell Mitre Based Investigation

## <mark style="color:blue;">**PowerShell MITRE-Based Investigations**</mark>

PowerShell is a powerful and versatile tool deeply integrated into the Windows operating system. It is a critical component in legitimate administrative tasks and malicious activities. For this reason, it plays a significant role in **MITRE ATT\&CK-based investigations**, where adversary tactics, techniques, and procedures (TTPs) are analysed to understand and combat cyber threats.

The **MITRE ATT\&CK framework** provides a comprehensive matrix of adversary behaviours, detailing how attackers exploit tools like PowerShell to achieve objectives such as privilege escalation, lateral movement, persistence, and data exfiltration. PowerShell’s extensive capabilities, including remote execution, automation, and interaction with Windows APIs, make it a favoured tool among attackers to execute malicious scripts stealthily.

For DFIR analysts, PowerShell investigations aligned with the MITRE ATT\&CK framework help to identify and correlate specific techniques used during an attack. Examples include detecting command-line obfuscation (T1059.001), analysing script execution (T1569.002), and investigating scheduled tasks (T1053.005). By focusing on these techniques, analysts can uncover traces of attacker activity, map the kill chain, and develop a comprehensive understanding of the breach.

PowerShell’s dual nature as both an operational necessity and a security risk emphasises the importance of a structured, framework-driven approach to its investigation. Leveraging MITRE-based methodologies, DFIR professionals can systematically detect malicious use of PowerShell, implement targeted defences, and enhance an organisation’s security posture against advanced threats.

## <mark style="color:blue;">Powershell Remoting</mark>

{% code overflow="wrap" %}
```powershell
## One-To-One Remoting
$Cred = Get-Credential
Enter-PSSession -ComputerName dc01 -Credential $Cred

## One-To-Many Remoting
$Cred = Get-Credential
Invoke-Command -ComputerName dc01, sql02, web01 {Get-Service -Name W32time} -Credential $Cred
OR
Invoke-Command -ComputerName dc01, sql02, web01 {Get-Service -Name W32time} -Credential $Cred | Get-Member

## PowerShell Sessions
$Session = New-PSSession -ComputerName dc01, sql02, web01 -Credential $Cred
!
Invoke-Command -Session $Session {(Get-Service -Name W32time).Start()}
Invoke-Command -Session $Session {Get-Service -Name W32time}
!
Get-PSSession | Remove-PSSession


$UserName = "bob01"
$ComputerName = "PC01"
$Credential = Get-Credential -UserName $UserName

Enter-PSSession -ComputerName $ComputerName -Credential $Credential
```
{% endcode %}

## <mark style="color:blue;">Initial Access Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Suspicious Process Execution**</mark>

**1.1. Detect Encoded PowerShell Commands**

**Purpose**: Identify potentially malicious encoded commands executed via PowerShell.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |  Where-Object {$_.Message -like '*-enc*'} | Format-Table -Autosize -Wrap

**Detect Encoded Commands:**
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Message -like "*-EncodedCommand*" }
```
{% endcode %}

**1.2. Identify Executions of CMD or PowerShell**

**Purpose**: Detect command-line executions that might indicate malicious activities.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[5].Value -match 'cmd.exe|powershell.exe'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}

**Detect Obfuscated Scripts:**
- Look for common obfuscation patterns like concatenation, split, or char conversion.
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Message -match "(\s|\.|\+|\|)+.*-j(\s|\.|\+|\|)+" }
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**User Account Activity Monitoring**</mark>

**2.1. Identify Unusual Logon Attempts**

**Purpose**: Detect unusual logon activities that could indicate credential misuse.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |  Where-Object {$_.Properties[8].Value -notin @("Domain Admins", "Enterprise Admins")} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='LogonType';e={$_.Properties[10].Value}}
```
{% endcode %}

**2.2. Detect Enumeration of User Accounts**

**Purpose**: Identify enumeration attempts against user accounts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4648} |  Where-Object {$_.Properties[5].Value -notin @("Domain Admins", "Enterprise Admins")}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**File and Directory Monitoring**</mark>

**3.1. Detect New Executable Files**

**Purpose**: Identify new executable files created in specific directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Temp" -Recurse -Filter *.exe | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

**3.2. Identify Suspicious File Downloads**

**Purpose**: Detect suspicious file downloads, potentially indicating a dropper or payload.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=11} |  Where-Object {$_.Message -like '*File*'}

**Detect Use of DownloadString or Invoke-Expression:**
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $_.Message -like "*DownloadString*" -or $_.Message -like "*Invoke-Expression*" }
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Network Activity Analysis**</mark>

**4.1. Unusual Outbound Connections**

**Purpose**: Detect unusual outbound network connections.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection |  Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**4.2. Identify DNS Requests to Suspicious Domains**

**Purpose**: Detect DNS queries to suspicious or known malicious domains.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Where-Object {($_.Message -match 'SuspiciousDomain')}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Scheduled Tasks and Services**</mark>

**5.1. Newly Created Scheduled Tasks**

**Purpose**: Identify newly created scheduled tasks that might indicate malicious activity.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -notlike "NT AUTHORITY\*"} | Select-Object TaskName, Principal, @{n='Action';e={$_.Actions.Context}}
```
{% endcode %}

**5.2. Detect Unusual Service Installations**

**Purpose**: Identify the installation of unusual or suspicious services.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} |  Where-Object {$_.Properties[1].Value -notin @("KnownGoodServices")}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Registry Modifications**</mark>

**6.1. Registry Run Key Changes**

**Purpose**: Detect changes to registry keys commonly used for persistence.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, *
```
{% endcode %}

**6.2. Monitor AppInit\_DLLs Changes**

**Purpose**: Identify changes to AppInit\_DLLs, which may indicate DLL injection attempts.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Event Log Monitoring**</mark>

**7.1. Detection of Cleared Event Logs**

**Purpose**: Identify attempts to clear event logs, indicating possible cover-up actions.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102}
```

**7.2. Audit Policy Changes**

**Purpose**: Detect changes in audit policies that could disable logging and monitoring.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4719}
```

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Email Security Monitoring**</mark>

**8.1. Detect Phishing Emails**

**Purpose**: Identify potential phishing emails by searching for known indicators.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName Application |  Where-Object {($_.Message -like "*Subject:*") -and ($_.Message -like "*attachment*" -or $_.Message -like "*click here*")}
```
{% endcode %}

**8.2. Monitor Email Client Configuration Changes**

**Purpose**: Identify unauthorized changes to email client configurations.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\*\Outlook\Preferences" | Select-Object PSChildName, *
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Application Execution Monitoring**</mark>

**9.1. Detect Execution of Unsigned Binaries**

**Purpose**: Identify executions of unsigned binaries that could indicate untrusted applications.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[8].Value -eq '0'}  # Unsigned
```
{% endcode %}

**9.2. Exploitation Tool Detection**

**Purpose**: Detect known exploitation tools on the system.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\Temp\*" -Recurse -Filter *.exe |  Where-Object {$_.Name -in @("mimikatz.exe", "cobaltstrike.exe")}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**System and Security Configuration**</mark>

**10.1. Group Policy Object Modifications**

**Purpose**: Detect unauthorized changes to Group Policy Objects.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136}
```

**10.2. Changes to Security Settings**

**Purpose**: Identify changes to critical security settings within the registry.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name NullSessionShares
```
{% endcode %}

#### Additional Discovery Techniques

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Phishing and Spear Phishing**</mark>

**1.1. Detecting Suspicious Email Attachments**

**Purpose**: Identify emails with potentially malicious attachments.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-EventLog/Email" |  Where-Object {($_.Message -match "Attachment: ") -and ($_.Message -match "exe|zip|rar|docm|xlsm|pptm")} | Select-Object TimeCreated, @{n='Attachment';e={$_.Message -match 'Attachment: (.*)' -replace 'Attachment: '}}
```
{% endcode %}

**1.2. Monitoring for Malicious Links in Emails**

**Purpose**: Detect emails containing suspicious or malicious URLs.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-EventLog/Email" |  Where-Object {($_.Message -match "http://") -or ($_.Message -match "https://")} | Select-Object TimeCreated, @{n='URL';e={$_.Message -match 'http(s)?://[^ ]+' -replace '(http(s)?://[^ ]+)' }}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Exploiting Vulnerabilities**</mark>

**2.1. Detecting Exploit Attempts in Web Servers**

**Purpose**: Identify attempts to exploit vulnerabilities in web applications.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-IIS-Logging" |  Where-Object {($_.Message -match "exploit") -or ($_.Message -match "injection")} | Select-Object TimeCreated, @{n='Request';e={$_.Message}}
```
{% endcode %}

**2.2. Monitoring for SMB Vulnerability Exploits**

**Purpose**: Detect exploit attempts against SMB vulnerabilities.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Where-Object {$_.Message -match 'SMB'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Theft and Brute Force**</mark>

**3.1. Detecting Brute Force Attack Attempts**

**Purpose**: Identify multiple failed login attempts, indicating a brute force attack.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Where-Object {$_.Properties[19].Value -eq "0xc000006a"} | Group-Object -Property {$_.Properties[5].Value} |  Where-Object {$_.Count -gt 10} | Select-Object Name, Count
```
{% endcode %}

**3.2. Monitoring for Use of Stolen Credentials**

**Purpose**: Detect successful logins from unusual locations or devices.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {($_.Properties[8].Value -eq "%%2313") -or ($_.Properties[8].Value -eq "%%2312")} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='LogonType';e={$_.Properties[10].Value}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious Code Execution**</mark>

**4.1. Detecting Script Execution from Email Attachments**

**Purpose**: Identify scripts executed from email attachments.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'FromEmailAttachment'} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

**4.2. Monitoring Macro-Enabled Document Execution**

**Purpose**: Detect execution of macro-enabled documents (e.g., Word, Excel).

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Office-Alerts'; ID=300} | Where-Object {($_.Message -match ".docm") -or ($_.Message -match ".xlsm")} | Select-Object TimeCreated, @{n='DocumentName';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious File and Malware Deployment**</mark>

**5.1. Detecting Newly Created Executables**

**Purpose**: Identify the creation of new executable files, potentially indicating a dropper or payload.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Temp" -Recurse -Include *.exe | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

**5.2. Monitoring Suspicious File Downloads**

**Purpose**: Detect files downloaded from potentially malicious sources.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Security-Auditing'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'File Download'} | Select-Object TimeCreated, @{n='FileName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Abuse of Valid Accounts**</mark>

**6.1. Detecting Account Creation and Privilege Escalation**

**Purpose**: Identify unauthorized creation of accounts or escalation of privileges.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4724} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[0].Value}}, @{n='Action';e={$_.Message}}
```
{% endcode %}

**6.2. Monitoring for Unusual Admin Account Activity**

**Purpose**: Detect unusual activities from administrative accounts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} | Where-Object {$_.Properties[9].Value -eq "%%500"} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### 7. **Phishing Landing Pages and Fake Websites**

**7.1. Detecting Redirection to Phishing Sites**

**Purpose**: Identify redirection attempts to known phishing sites.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where-Object {$_.Message -match "phishing-site.com"} | Select-Object TimeCreated, @{n='RedirectedURL';e={$_.Message}}
```
{% endcode %}

**7.2. Monitoring Access to Fake Login Pages**

**Purpose**: Detect access to fake login pages hosted within the organization.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-IIS-Logging" | Where-Object {$_.Message -match "login.html" -and $_.Message -match "FakeLoginPage"} | Select-Object TimeCreated, @{n='URL';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Remote Services and Exploitation**</mark>

**8.1. Detecting Remote Desktop Protocol (RDP) Access**

**Purpose**: Identify unauthorized RDP access attempts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[10].Value -eq '10'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**8.2. Monitoring for Remote PowerShell Sessions**

**Purpose**: Detect unauthorized remote PowerShell sessions.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103} | Where-Object {$_.Message -match "New-PSSession"} | Select-Object TimeCreated, @{n='Command';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Abuse of Application Layer Protocols**</mark>

**9.1. Monitoring for Suspicious HTTP/S Traffic**

**Purpose**: Detect suspicious HTTP/S traffic that may indicate exploitation or command and control.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-IIS-Logging" | Where-Object {$_.Message -match "suspicious"} | Select-Object TimeCreated, @{n='Request';e={$_.Message}}
```
{% endcode %}

**9.2. Detecting Use of Anonymous FTP**

**Purpose**: Identify the use of anonymous FTP, potentially indicating unauthorized data transfer.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" | Where-Object {($_.Message -match "Anonymous") -and ($_.Message -match "FTP")} | Select-Object TimeCreated, @{n='Action';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious Use of Legitimate Tools**</mark>

**10.1. Detecting Execution of PsExec**

**Purpose**: Identify the use of PsExec, a legitimate tool that can be misused for lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'psexec'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**10.2. Monitoring for Use of WMI**

**Purpose**: Detect the use of WMI for potentially malicious purposes.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} | Where-Object {$_.Message -match "CommandLineEventConsumer"} | Select-Object TimeCreated, @{n='Command';e={$_.Message}}
```
{% endcode %}

## <mark style="color:blue;">Reconnaissance Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Network Scanning and Enumeration**</mark>

**1.1. Detect Network Scanning Activities**

**Purpose**: Identify potential network scanning activities by monitoring for unusual network connections.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection |  Where-Object {$_.State -eq 'Listen' -and $_.RemoteAddress -ne '0.0.0.0'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**1.2. Identify Unusual ARP Table Entries**

**Purpose**: Detect new or unusual ARP entries that may indicate scanning or network discovery.

{% code overflow="wrap" %}
```powershell
Get-NetNeighbor |  Where-Object {$_.State -eq 'Reachable' -and $_.AddressFamily -eq 'IPv4'} | Select-Object ifIndex, IPAddress, LinkLayerAddress
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**System Information Gathering**</mark>

**2.1. Enumeration of Installed Applications**

**Purpose**: Detect enumeration of installed applications, which may indicate software inventory reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```
{% endcode %}

**2.2. Listing Running Processes**

**Purpose**: Identify unauthorized listing of running processes, which may indicate system reconnaissance.

```powershell
Get-Process | Select-Object Id, ProcessName, StartTime
```

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**User and Account Information Discovery**</mark>

**3.1. List Local User Accounts**

**Purpose**: Detect enumeration of local user accounts.

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

**3.2. Active Directory User Enumeration**

**Purpose**: Identify enumeration of Active Directory users, which may indicate domain reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter * -Property DisplayName, Title, Department | Select-Object DisplayName, Title, Department
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Group and Permission Enumeration**</mark>

**4.1. List Local Groups and Memberships**

**Purpose**: Detect enumeration of local groups and their memberships.

{% code overflow="wrap" %}
```powershell
Get-LocalGroup | ForEach-Object {     [PSCustomObject]@{         GroupName = $_.Name         Members   = (Get-LocalGroupMember -Group $_.Name | Select-Object -ExpandProperty Name) -join ", "     } }
```
{% endcode %}

**4.2. Active Directory Group Enumeration**

**Purpose**: Identify enumeration of Active Directory groups, which may indicate privilege reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ADGroup -Filter * -Property Members | Select-Object Name, @{n='Members';e={$_.Members -join ", "}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;">**Network Configuration and Interface Enumeration**</mark>

**5.1. List Network Interfaces**

**Purpose**: Detect enumeration of network interfaces, potentially indicating network reconnaissance.

```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MACAddress
```

**5.2. Get IP Configuration Details**

**Purpose**: Identify gathering of IP configuration details.

```powershell
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength
```

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Service and Port Enumeration**</mark>

**6.1. List Listening Ports**

**Purpose**: Detect enumeration of listening ports, which may indicate open port scanning.

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort
```

**6.2. Identify Running Services**

**Purpose**: Detect enumeration of running services, potentially indicating service reconnaissance.

```powershell
Get-Service | Select-Object Name, DisplayName, Status, StartType
```

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**File and Directory Enumeration**</mark>

**7.1. List Files in Sensitive Directories**

**Purpose**: Identify enumeration of files in sensitive directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\SensitiveData\" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

**7.2. Detect Access to Administrative Shares**

**Purpose**: Detect access or enumeration of administrative shares.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Type=0" | Select-Object Name, Path
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Logon Session and Security Group Enumeration**</mark>

**8.1. List Active Logon Sessions**

**Purpose**: Detect enumeration of active logon sessions.

{% code overflow="wrap" %}
```powershell
Get-Process -IncludeUserName | Where-Object { $_.UserName } | Select-Object ProcessName, UserName, StartTime
```
{% endcode %}

**8.2. Enumerate Security Groups of Logged-on Users**

**Purpose**: Identify enumeration of security groups for logged-on users.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_ComputerSystem | Select-Object DomainRole, Name, PartOfDomain
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Registry and System Configuration Discovery**</mark>

**9.1. List Auto-Start Programs**

**Purpose**: Detect enumeration of auto-start programs.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, *
```
{% endcode %}

**9.2. Identify Registry Key Enumeration**

**Purpose**: Detect enumeration of registry keys related to system configuration.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Select-Object PSChildName, Start, Type
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Scheduled Task and Job Discovery**</mark>

**10.1. List Scheduled Tasks**

**Purpose**: Detect enumeration of scheduled tasks.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Select-Object TaskName, LastRunTime, TaskPath
```
{% endcode %}

**10.2. Enumerate Windows Jobs**

**Purpose**: Identify enumeration of Windows jobs.

```powershell
Get-WmiObject -Class Win32_ScheduledJob | Select-Object Name, JobId, JobStatus
```

**Additional Discovery Techniques**

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;">**Network Scanning and Discovery**</mark>

**1.1. Detecting Network Scanning Attempts**

**Purpose**: Identify attempts to scan the network for open ports and services.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5156} | Where-Object {($_.Properties[19].Value -match "Allowed") -and ($_.Properties[7].Value -ne "System")} | Select-Object TimeCreated, @{n='SourceIP';e={$_.Properties[18].Value}}, @{n='DestinationIP';e={$_.Properties[2].Value}}
```
{% endcode %}

**1.2. Monitoring for ARP Scanning**

**Purpose**: Detect ARP scanning attempts, which can reveal network topology.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=104} | Where-Object {$_.Message -match "ARP"} | Select-Object TimeCreated, @{n='SourceIP';e={$_.Properties[0].Value}}, @{n='DestinationIP';e={$_.Properties[1].Value}}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**DNS and Directory Service Enumeration**</mark>

**2.1. Detecting DNS Zone Transfer Attempts**

**Purpose**: Identify attempts to perform DNS zone transfers, which can reveal domain information.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Server/Audit" | Where-Object {$_.Message -match "AXFR"} | Select-Object TimeCreated, @{n='Query';e={$_.Message}}
```
{% endcode %}

**2.2. Monitoring LDAP Enumeration**

**Purpose**: Detect LDAP queries that may indicate enumeration of Active Directory objects.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} | Where-Object {$_.Message -match "LDAP"} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[5].Value}}, @{n='AccountName';e={$_.Properties[1].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**User and Account Enumeration**</mark>

**3.1. Detecting User Enumeration via SMB**

**Purpose**: Identify attempts to enumerate user accounts over SMB.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Where-Object {$_.Properties[19].Value -eq "0xc0000064"} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**3.2. Monitoring for Kerberos Enumeration**

**Purpose**: Detect enumeration of Kerberos accounts, which may reveal service accounts and SPNs.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} | Where-Object {$_.Properties[8].Value -eq "0x0"} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Service and System Discovery**</mark>

**4.1. Detecting Windows Management Instrumentation (WMI) Queries**

**Purpose**: Identify the use of WMI to query system information.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} | Where-Object {$_.Message -match "SELECT"} | Select-Object TimeCreated, @{n='Query';e={$_.Message}}
```
{% endcode %}

**4.2. Monitoring Remote System Discovery via RDP**

**Purpose**: Detect the use of RDP to explore remote systems.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[10].Value -eq '10'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**File and Directory Enumeration**</mark>

**5.1. Detecting Enumeration of File Shares**

**Purpose**: Monitor for attempts to enumerate network file shares.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5145} | Where-Object {$_.Properties[6].Value -match 'Share Enumeration'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**5.2. Monitoring Access to Sensitive Directories**

**Purpose**: Detect access attempts to sensitive directories or files.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match 'C:\SensitiveData'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Network and Firewall Configuration Enumeration**</mark>

**6.1. Detecting Attempts to Query Firewall Rules**

**Purpose**: Identify attempts to enumerate firewall rules.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4703} | Select-Object TimeCreated, @{n='RuleName';e={$_.Properties[6].Value}}
```
{% endcode %}

**6.2. Monitoring for Changes in Network Configuration**

**Purpose**: Detect changes in network configurations that may indicate reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name Interfaces
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Operating System and Application Enumeration**</mark>

**7.1. Detecting OS Version and Installed Software Enumeration**

**Purpose**: Monitor for attempts to enumerate OS versions and installed applications.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Version, BuildNumber Get-WmiObject -Class Win32_Product | Select-Object Name, Version
```
{% endcode %}

**7.2. Monitoring for Enumeration of Installed Patches**

**Purpose**: Detect enumeration of installed patches and hotfixes, which can indicate vulnerability assessment.

```powershell
Get-HotFix | Select-Object Description, HotFixID, InstalledOn
```

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Cloud and Virtual Environment Discovery**</mark>

**8.1. Detecting Enumeration of Cloud Resources**

**Purpose**: Identify attempts to enumerate cloud resources and configurations.

{% code overflow="wrap" fullWidth="false" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" | Where-Object {$_.Message -match "cloud"} | Select-Object TimeCreated, @{n='Details';e={$_.Message}}
```
{% endcode %}

**8.2. Monitoring for Enumeration of Virtual Machines**

**Purpose**: Detect enumeration of virtual machines and their configurations.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Namespace "root\virtualization\v2" -Class Msvm_ComputerSystem |  Select-Object ElementName, OperationalStatus
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Service and Process Enumeration**</mark>

**9.1. Detecting Enumeration of Running Processes**

**Purpose**: Monitor for attempts to list running processes on a system.

```powershell
Get-Process | Select-Object Id, ProcessName, StartTime
```

**9.2. Monitoring for Service Status Queries**

**Purpose**: Detect queries for the status of services running on a system.

```powerquery
Get-Service | Select-Object Name, DisplayName, Status
```

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Anomalous Network Behaviour**</mark>

**10.1. Detecting Network Traffic Anomalies**

**Purpose**: Identify unusual network traffic patterns that may indicate reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection |  Where-Object {($_.State -eq 'Established') -and ($_.RemoteAddress -notin 'KnownGoodIPs')} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**10.2. Monitoring for Use of Network Analysis Tools**

**Purpose**: Detect the use of network analysis tools like Nmap, Nessus, etc.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'nmap|nessus'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

## <mark style="color:blue;">Execution Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Monitoring Process Execution**</mark>

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

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**PowerShell Script Execution Monitoring**</mark>

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

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identifying Execution of Scripting Languages**</mark>

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

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious Use of Built-in Tools**</mark>

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

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Macro Execution and Document Exploits**</mark>

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

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Windows Management Instrumentation (WMI) Execution**</mark>

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

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;">**Execution via Services and Tasks**</mark>

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

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Dumping and Usage**</mark>

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

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Execution of Exploit Tools**</mark>

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

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Script and Binary Obfuscation**</mark>

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

**Additional Discovery Techniques**

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;">**Monitoring Script Execution**</mark>

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

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious Use of Legitimate Tools**</mark>

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

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Unauthorized Software and Tool Usage**</mark>

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

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Remote Command Execution**</mark>

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

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Execution of Scripting Languages**</mark>

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

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Executable and DLL Injection**</mark>

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

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;">**Malicious Use of System Tools**</mark>

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

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Application Whitelisting Bypass**</mark>

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

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Macro and Script Exploitation**</mark>

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

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Exploitation Tools and Post-Exploitation Frameworks**</mark>

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

## <mark style="color:blue;">Persistence Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Registry-Based Persistence**</mark>

**1.1. Registry Run Key Modifications**

**Purpose**: Detect changes to registry keys that run programs at startup.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, *
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, *
```
{% endcode %}

**1.2. AppInit\_DLLs Changes**

**Purpose**: Identify modifications to the AppInit\_DLLs registry value, often used for DLL injection.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Scheduled Tasks and Services**</mark>

**2.1. Listing Suspicious Scheduled Tasks**

**Purpose**: Detect the creation of scheduled tasks that may indicate persistence.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | Select-Object TaskName, @{n='Actions';e={$_.Actions}}
```
{% endcode %}

**2.2. Service Installation Events**

**Purpose**: Identify the installation of unusual services, which may be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} |  Where-Object {$_.Properties[1].Value -notin 'KnownGoodServices'}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;">**WMI Persistence**</mark>

**3.1. Detecting WMI Event Consumers**

**Purpose**: Identify WMI event consumers, which can be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer | Select-Object Name, CommandLineTemplate
```
{% endcode %}

**3.2. Monitoring WMI Event Filters**

**Purpose**: Detect suspicious WMI event filters.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Select-Object Name, Query
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Startup Folder Persistence**</mark>

**4.1. Listing Items in Startup Folders**

**Purpose**: Detect suspicious scripts or executables placed in startup folders.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object FullName, CreationTime
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object FullName, CreationTime
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**GPO and Logon Scripts**</mark>

**5.1. Detecting GPO Logon Scripts**

**Purpose**: Identify logon scripts configured via Group Policy Objects.

{% code overflow="wrap" %}
```powershell
Get-GPRegistryValue -All | Where-Object {$_.ValueName -like '*logon*script*'} | Select-Object PolicyName, KeyPath, ValueName, Value
```
{% endcode %}

**5.2. Enumerating Local Logon Scripts**

**Purpose**: Detect logon scripts configured locally.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\System32\GroupPolicy\User\Scripts\Logon" | Select-Object FullName, CreationTime
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Binary and Script-Based Persistence**</mark>

**6.1. Monitoring Changes in Common System Directories**

**Purpose**: Detect unauthorized binaries or scripts in common system directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\System32" -Filter "*.exe, *.dll" | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

**6.2. Detecting PowerShell Profile Changes**

**Purpose**: Identify modifications to PowerShell profiles, which can be used for persistence.

```powershell
Get-Content -Path $PROFILE
```

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious Use of Scripting Languages**</mark>

**7.1. Monitoring for Suspicious PowerShell Scripts**

**Purpose**: Detect suspicious PowerShell scripts, especially those that could establish persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'Invoke-Mimikatz|New-Object'}
```
{% endcode %}

**7.2. Detecting JScript and VBScript Persistence**

**Purpose**: Identify suspicious JScript or VBScript files that may be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\Temp" -Filter "*.js, *.vbs" | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Registry Persistence**</mark>

**8.1. Checking for Winlogon Shell Modifications**

**Purpose**: Detect modifications to the Winlogon Shell registry key, which can be used to start malware.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell
```
{% endcode %}

**8.2. Investigating Userinit Key Modifications**

**Purpose**: Identify unauthorized changes to the Userinit registry key.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Userinit
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Boot and Auto-Start Configuration**</mark>

**9.1. Checking for Boot Configuration Data (BCD) Changes**

**Purpose**: Detect unauthorized changes to the Boot Configuration Data.

```csharp
bcdedit /enum all
```

**9.2. Detecting Changes to Auto-Start Services**

**Purpose**: Identify unauthorized changes to services set to auto-start.

{% code overflow="wrap" %}
```powershell
Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | Select-Object Name, DisplayName, Status
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Persistence via Network and Remote Services**</mark>

**10.1. Monitoring Remote Desktop Protocol (RDP) Changes**

**Purpose**: Detect changes to RDP settings that could indicate persistence mechanisms.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
```
{% endcode %}

**10.2. Detecting Changes to Remote Management Settings**

**Purpose**: Identify changes to Windows Remote Management (WinRM) settings.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client" -Name AllowBasic
```
{% endcode %}

**Additional Discovery Techniques**

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Registry and Autoruns Monitoring**</mark>

**1.1. Detecting Autorun Entries in the Registry**

**Purpose**: Identify suspicious autorun entries that may indicate persistence mechanisms.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, @{n='Value';e={$_ -replace '.*\\'}}
```
{% endcode %}

**1.2. Monitoring for Changes in Startup Folders**

**Purpose**: Detect changes in startup folders that may indicate unauthorized persistence.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Service and Scheduled Task Persistence**</mark>

**2.1. Detecting Creation of New Services**

**Purpose**: Identify the creation of new services, which can be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[5].Value}}
```
{% endcode %}

**2.2. Monitoring for New or Modified Scheduled Tasks**

**Purpose**: Detect the creation or modification of scheduled tasks for persistence.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*"} | Select-Object TaskName, Principal, @{n='Actions';e={$_.Actions}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**WMI and COM Object Persistence**</mark>

**3.1. Detecting WMI Event Subscription Persistence**

**Purpose**: Identify persistent WMI event subscriptions used for persistence.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Select-Object Name, Query
```
{% endcode %}

**3.2. Monitoring for Suspicious COM Object Creation**

**Purpose**: Detect the creation of suspicious COM objects that may indicate persistence.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Classes\CLSID" -Recurse | Where-Object {$_.PSChildName -match ".*\{.*\}.*"} | Select-Object PSChildName, @{n='Value';e={$_.Property}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Startup Scripts and Logon Hooks**</mark>

**4.1. Detecting Changes in Group Policy Logon Scripts**

**Purpose**: Identify changes to logon scripts set by Group Policy for persistence.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon" | Select-Object ScriptList, GPOID
```
{% endcode %}

**4.2. Monitoring for Logon Hook Injections**

**Purpose**: Detect the injection of logon hooks for persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} | Where-Object {$_.Properties[9].Value -match "SeTcbPrivilege"} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious Use of Scheduled Jobs and Cron Jobs**</mark>

**5.1. Detecting Creation of New Scheduled Jobs**

**Purpose**: Identify new scheduled jobs that may indicate persistence mechanisms.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_ScheduledJob | Select-Object JobID, Name, Status, Command
```
{% endcode %}

**5.2. Monitoring for Changes in Existing Scheduled Jobs**

**Purpose**: Detect modifications to existing scheduled jobs for persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698} | Select-Object TimeCreated, @{n='JobName';e={$_.Properties[0].Value}}, @{n='Operation';e={$_.Properties[1].Value}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Persistence via System Services**</mark>

**6.1. Detecting Changes to System Services**

**Purpose**: Monitor changes to system services that may indicate persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7040} | Where-Object {($_.Properties[2].Value -match "start type changed")} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='Change';e={$_.Properties[2].Value}}
```
{% endcode %}

**6.2. Monitoring for New or Suspicious Service Installations**

**Purpose**: Detect the installation of new services that may be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7030} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[1].Value}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Browser Extensions and Plug-Ins**</mark>

**7.1. Detecting Malicious Browser Extensions**

**Purpose**: Identify browser extensions that may be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

**7.2. Monitoring for New or Unusual Plug-Ins**

**Purpose**: Detect the installation of new or unusual browser plug-ins.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files (x86)\Mozilla Firefox\browser\extensions" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**DLL Hijacking and Injection**</mark>

**8.1. Detecting DLL Hijacking Attempts**

**Purpose**: Monitor for attempts to hijack DLLs for persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {($_.Properties[9].Value -match "rundll32.exe") -and ($_.Properties[9].Value -match "DLL_Path")} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**8.2. Monitoring for Suspicious DLL Injections**

**Purpose**: Identify DLL injections used to maintain persistence.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {($_.Properties[9].Value -match "0x1F0FFF") -and ($_.Properties[5].Value -match "DLL_Path")} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Remote Access and Backdoors**</mark>

**9.1. Detecting Remote Access Tools (RATs)**

**Purpose**: Identify the presence of remote access tools used for persistence.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match "TeamViewer|AnyDesk|RAT_Tool"} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**9.2. Monitoring for Backdoor Installations**

**Purpose**: Detect installations of backdoors for unauthorized remote access.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7035} | Where-Object {$_.Properties[0].Value -match "backdoor_service_name"} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Persistence via System and Network Configuration**</mark>

**10.1. Detecting Changes in Network Configuration**

**Purpose**: Monitor changes in network configurations, such as proxy settings, which can be used for persistence.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer
```
{% endcode %}

**10.2. Monitoring System Boot Configuration Changes**

**Purpose**: Detect changes to system boot configurations that may indicate persistence.

```csharp
bcdedit /enum all | Select-String "path"
```

## <mark style="color:blue;">Privilege Escalation Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Monitoring Process and Service Changes**</mark>

**1.1. Detecting New Administrative Process Creation**

**Purpose**: Identify processes started with administrative privileges that may indicate privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'Administrator'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**1.2. Monitoring for New Services with Elevated Privileges**

**Purpose**: Detect the creation of new services that run with elevated privileges.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**User and Group Changes**</mark>

**2.1. Detecting New User Account Creation**

**Purpose**: Identify new user accounts that may have been created with elevated privileges.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[0].Value}}, @{n='CreatedBy';e={$_.Properties[1].Value}}
```
{% endcode %}

**2.2. Monitoring for Group Membership Changes**

**Purpose**: Detect changes in group memberships, particularly in administrative groups.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4732,4746,4756} | Select-Object TimeCreated, @{n='GroupName';e={$_.Properties[0].Value}}, @{n='MemberName';e={$_.Properties[1].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Registry and System Configuration**</mark>

**3.1. Monitoring Registry Key Changes for Escalation Paths**

**Purpose**: Identify changes to registry keys that may enable privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4657} | Where-Object {$_.Properties[6].Value -match 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'}
```
{% endcode %}

**3.2. Detecting UAC Bypass Techniques**

**Purpose**: Detect changes to registry keys or system settings that might indicate UAC bypass attempts.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Scheduled Tasks and Services**</mark>

**4.1. Detecting Changes to Scheduled Tasks**

**Purpose**: Identify changes to scheduled tasks that may allow privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "Highest"} | Select-Object TaskName, Principal, Actions
```
{% endcode %}

**4.2. Monitoring Service Configuration Changes**

**Purpose**: Detect changes to service configurations that may provide elevated access.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.StartName -eq "LocalSystem"} | Select-Object Name, DisplayName, PathName, StartMode
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Access Control and Permissions**</mark>

**5.1. Monitoring Changes to ACLs on Sensitive Files**

**Purpose**: Detect modifications to access control lists (ACLs) on sensitive system files.

{% code overflow="wrap" %}
```powershell
Get-Acl -Path "C:\Windows\System32\*" |  Where-Object {$_.Access -like '*Everyone*'} | Select-Object Path, Access
```
{% endcode %}

**5.2. Detecting Changes to Important Security Settings**

**Purpose**: Identify changes to security settings that might indicate privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name NullSessionShares
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Executable and Script Monitoring**</mark>

**6.1. Detecting Unusual Executables in System Directories**

**Purpose**: Identify executables in system directories that may be used for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\System32\*" -Filter "*.exe" | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

**6.2. Monitoring Script Execution with Elevated Privileges**

**Purpose**: Detect the execution of scripts with administrative privileges.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'RunAsAdministrator'}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Application and Service Installation**</mark>

**7.1. Detecting Installation of Potentially Malicious Software**

**Purpose**: Identify the installation of software that may be used for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=11707} | Select-Object TimeCreated, @{n='Product';e={$_.Properties[0].Value}}, @{n='InstalledBy';e={$_.Properties[1].Value}}
```
{% endcode %}

**7.2. Monitoring Changes to Auto-Start Applications**

**Purpose**: Detect changes to auto-start applications that could indicate persistence or privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, *
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Exploit Detection and Mitigation**</mark>

**8.1. Monitoring for Known Exploit Attempts**

**Purpose**: Detect attempts to exploit known vulnerabilities for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} |  Where-Object {$_.Properties[10].Value -match '0xc000006a'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='FailureReason';e={$_.Properties[9].Value}}
```
{% endcode %}

**8.2. Detecting Kernel Driver Installation**

**Purpose**: Identify the installation of kernel drivers, which may be used to escalate privileges.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7040} |  Where-Object {$_.Properties[1].Value -match 'Driver'}
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Audit Policy and Event Log Monitoring**</mark>

**9.1. Monitoring Changes to Audit Policies**

**Purpose**: Detect changes to audit policies that might indicate attempts to cover privilege escalation activities.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4719}
```

**9.2. Detecting Clearing of Event Logs**

**Purpose**: Identify attempts to clear event logs, which may indicate an attempt to hide evidence of privilege escalation.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102}
```

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Domain and Network-Level Privilege Escalation**</mark>

**10.1. Monitoring Changes to Domain Admin Group**

**Purpose**: Detect unauthorized changes to the Domain Admins group.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4728} | Where-Object {$_.Properties[2].Value -eq "Domain Admins"}
```
{% endcode %}

**10.2. Detecting Changes to Group Policy Objects (GPOs)**

**Purpose**: Identify changes to GPOs that may indicate attempts to escalate privileges.

{% code overflow="wrap" %}
```powershell
Get-GPO -All | Get-GPOReport -ReportType XML | Select-String -Pattern "Administrator"
```
{% endcode %}

**Additional Discovery Techniques**

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;">**Monitoring Account Privilege Changes**</mark>

**1.1. Detecting Changes in User Group Membership**

**Purpose**: Identify users added to high-privilege groups, such as Administrators.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4732,4728} | Select-Object TimeCreated, @{n='Group';e={$_.Properties[6].Value}}, @{n='User';e={$_.Properties[1].Value}}
```
{% endcode %}

**1.2. Monitoring User Account Control (UAC) Changes**

**Purpose**: Detect changes to UAC settings that may indicate privilege escalation attempts.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin, EnableLUA
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Service and Process Manipulation**</mark>

**2.1. Detecting Service Configuration Changes**

**Purpose**: Identify changes to service configurations that might be used for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7040} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='Change';e={$_.Properties[2].Value}}
```
{% endcode %}

**2.2. Monitoring for Abnormal Parent-Child Process Relationships**

**Purpose**: Detect unusual parent-child process relationships that might indicate process injection or manipulation.

{% code overflow="wrap" %}
```powershell
Get-CimInstance -ClassName Win32_Process |  Select-Object ProcessId, Name, ParentProcessId | Where-Object {($_.ParentProcessId -ne 0) -and ($_.Name -match "cmd.exe|powershell.exe")}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Scheduled Tasks and Cron Jobs**</mark>

**3.1. Detecting Creation of High-Privilege Scheduled Tasks**

**Purpose**: Monitor for the creation of scheduled tasks with high privileges.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*"} | Select-Object TaskName, Principal, @{n='Actions';e={$_.Actions}}
```
{% endcode %}

**3.2. Monitoring Modification of Scheduled Tasks**

**Purpose**: Identify modifications to scheduled tasks, which can be used for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698} | Select-Object TimeCreated, @{n='TaskName';e={$_.Properties[0].Value}}, @{n='Operation';e={$_.Properties[1].Value}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Exploitation of Vulnerabilities and Misconfigurations**</mark>

**4.1. Detecting Exploitation of Known Vulnerabilities**

**Purpose**: Identify attempts to exploit known vulnerabilities for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "exploit"} | Select-Object TimeCreated, @{n='Details';e={$_.Message}}
```
{% endcode %}

**4.2. Monitoring for Misconfigured File or Folder Permissions**

**Purpose**: Detect weak permissions on critical files or folders that may allow privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-Acl -Path "C:\Windows\System32" | Select-Object -ExpandProperty Access |  Where-Object {$_.FileSystemRights -match 'FullControl' -and $_.IdentityReference -ne 'BUILTIN\Administrators'}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Theft and Reuse**</mark>

**5.1. Detecting Use of Pass-the-Hash**

**Purpose**: Identify the use of NTLM hashes for authentication, bypassing standard credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[8].Value -eq 'NTLM'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='LogonType';e={$_.Properties[10].Value}}
```
{% endcode %}

**5.2. Monitoring for Token Manipulation**

**Purpose**: Detect attempts to manipulate tokens, such as by using tools like `incognito`.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4673} | Where-Object {$_.Properties[10].Value -match "SeDebugPrivilege"} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Exploit Local Privilege Escalation (LPE) Vulnerabilities**</mark>

**6.1. Detecting Execution of Exploits**

**Purpose**: Identify the execution of known exploit tools for local privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[9].Value -match "exploit"} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**6.2. Monitoring for Privilege Escalation via DLL Hijacking**

**Purpose**: Detect attempts to use DLL hijacking for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[9].Value -match "rundll32.exe"} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Abuse of Built-in Windows Tools**</mark>

**7.1. Detecting Use of WMI for Privilege Escalation**

**Purpose**: Identify the use of Windows Management Instrumentation (WMI) for privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} | Where-Object {$_.Message -match 'MethodInvocation'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Message}}
```
{% endcode %}

**7.2. Monitoring for PowerShell Privilege Escalation Attempts**

**Purpose**: Detect the use of PowerShell scripts or commands to escalate privileges.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'New-Object System.Security.Principal.WindowsPrincipal'} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Abuse of Service Control Manager**</mark>

**8.1. Detecting Service Installation by Non-Admins**

**Purpose**: Identify attempts by non-administrative users to install services.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Where-Object {($_.Properties[1].Value -ne 'SYSTEM')} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[5].Value}}
```
{% endcode %}

**8.2. Monitoring for Unauthorized Service Modifications**

**Purpose**: Detect modifications to existing services that could indicate privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7040} | Where-Object {($_.Properties[2].Value -match 'change')} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='Change';e={$_.Properties[2].Value}}
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Manipulation of Security Policies and Settings**</mark>

**9.1. Monitoring Changes to Local Security Policies**

**Purpose**: Detect changes to local security policies that may indicate attempts to weaken security.

{% code overflow="wrap" %}
```powershell
secedit /export /cfg C:\securitypolicy.cfg Get-Content C:\securitypolicy.cfg | Where-Object {$_ -match "AuditPolicyChange"}
```
{% endcode %}

**9.2. Detecting Changes to User Rights Assignments**

**Purpose**: Identify changes to user rights assignments, which can indicate privilege escalation.

{% code overflow="wrap" %}
```powershell
`Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name SeDebugPrivilege`
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Manipulation of Active Directory Objects**</mark>

**10.1. Detecting Unusual Changes to Group Policy Objects (GPOs)**

**Purpose**: Monitor for unauthorized changes to GPOs that could indicate privilege escalation.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136} | Where-Object {$_.Message -match "groupPolicyContainer"} | Select-Object TimeCreated, @{n='AttributeName';e={$_.Properties[9].Value}}
```
{% endcode %}

**10.2. Monitoring for Unusual Delegation of Privileges in AD**

**Purpose**: Identify unusual delegation of privileges within Active Directory.

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter {MemberOf -eq "Administrators"} -Property MemberOf | Select-Object Name, MemberOf
```
{% endcode %}

## <mark style="color:blue;">Defence Evasion Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Antivirus and Security Tools Interference**</mark>

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

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Log Deletion and Tampering**</mark>

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

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Obfuscation Techniques**</mark>

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

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Bypassing User Account Control (UAC)**</mark>

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

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Hiding Artifacts and File Manipulation**</mark>

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

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Code Injection and Process Manipulation**</mark>

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

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Modifying System Settings for Evasion**</mark>

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

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Application Whitelisting and Execution Control Bypass**</mark>

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

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Disabling Security Controls**</mark>

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

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Manipulating System Logs and Auditing**</mark>

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

## <mark style="color:blue;">Credential Access Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detecting Credential Dumping Attempts**</mark>

**1.1. Monitoring for LSASS Process Access**

**Purpose**: Detect attempts to access the LSASS process, which may indicate credential dumping.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {$_.Properties[9].Value -match 'lsass.exe'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='HandleID';e={$_.Properties[7].Value}}
```
{% endcode %}

**1.2. Identifying the Use of Mimikatz**

**Purpose**: Detect the execution of Mimikatz, a tool commonly used for credential dumping.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'mimikatz'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Suspicious Account Activity Monitoring**</mark>

**2.1. Tracking Account Logon Failures**

**Purpose**: Identify multiple logon failures that could indicate password guessing or brute force attacks.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='FailureReason';e={$_.Properties[9].Value}}
```
{% endcode %}

**2.2. Detecting Privileged Account Logons**

**Purpose**: Monitor logons by privileged accounts that may indicate misuse of credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[8].Value -eq '%%500'} |  # Logon with special privileges Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='LogonType';e={$_.Properties[10].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;">**Phishing and Email-based Attacks**</mark>

**3.1. Detecting Phishing Email Characteristics**

**Purpose**: Identify characteristics of phishing emails, such as unusual attachments or links.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000} | Where-Object {($_.Message -like "*Subject:*") -and ($_.Message -like "*attachment*" -or $_.Message -like "*click here*")}
```
{% endcode %}

**3.2. Monitoring for Unusual Email Client Activity**

**Purpose**: Detect unusual activity in email clients that may indicate compromised accounts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=3005} | Where-Object {$_.Message -like '*Outlook*'} | Select-Object TimeCreated, @{n='Event';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Caching and Storage**</mark>

**4.1. Detecting Stored Credentials in Browsers**

**Purpose**: Identify stored credentials in browser caches.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data" -Force | Select-Object FullName, LastWriteTime
```
{% endcode %}

**4.2. Monitoring for Cached Credentials in RDP**

**Purpose**: Detect cached credentials used in Remote Desktop Protocol (RDP) sessions.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\Documents\Default.rdp" -Force | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Keylogging and User Input Capture**</mark>

**5.1. Detecting Keylogger Installation**

**Purpose**: Identify the installation of keylogging software.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\*" -Filter "*keylogger*" -Recurse | Select-Object FullName, CreationTime
```
{% endcode %}

**5.2. Monitoring for Keylogger Activity**

**Purpose**: Detect activity indicative of keylogging, such as unusual process behaviour.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -like '*logger*'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Theft from API and Memory**</mark>

**6.1. Monitoring Access to Security Account Manager (SAM) Database**

**Purpose**: Detect unauthorized access attempts to the SAM database.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {$_.Properties[9].Value -match 'SAM'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

**6.2. Identifying Memory Dumping Attempts**

**Purpose**: Detect attempts to dump process memory for credential harvesting.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'Process Memory'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Suspicious Network and Remote Access Activity**</mark>

**7.1. Detecting Suspicious VPN Connections**

**Purpose**: Monitor for unusual VPN connections that could indicate credential misuse.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000} | Where-Object {($_.Message -match "VPN") -and ($_.Message -match "Connected")}
```
{% endcode %}

**7.2. Monitoring Remote Access Tools (RATs)**

**Purpose**: Identify remote access tools that may be used for credential theft.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -like '*RAT*'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Password and Credential Policy Changes**</mark>

**8.1. Monitoring Changes to Password Policies**

**Purpose**: Detect changes to password policies that may weaken security.

{% code overflow="wrap" %}
```powershell
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, LockoutDuration, LockoutObservationWindow, MaxPasswordAge
```
{% endcode %}

**8.2. Detecting Changes to Credential Delegation Policies**

**Purpose**: Identify changes to credential delegation settings.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin"
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Browser and Web-based Credential Theft**</mark>

**9.1. Detecting Malicious Browser Extensions**

**Purpose**: Identify browser extensions that may be used to steal credentials.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Recurse | Where-Object {($_.Name -like "*.dll") -or ($_.Name -like "*.exe")}
```
{% endcode %}

**9.2. Monitoring for Credential Harvesting Websites**

**Purpose**: Detect access to known credential-harvesting websites.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; ID=101} | Where-Object {($_.Message -match "phishing.com") -or ($_.Message -match "login-redirect")}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Advanced Credential Stealing Techniques**</mark>

**10.1. Monitoring for Kerberoasting Attempts**

**Purpose**: Identify attempts to request Kerberos service tickets to crack offline.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} | Where-Object {$_.Properties[8].Value -eq "0x12"} |  # Encryption type indicating RC4 Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[5].Value}}
```
{% endcode %}

**10.2. Detecting Pass-the-Hash Attacks**

**Purpose**: Monitor for using NTLM hashes to authenticate without knowing the plaintext password.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[8].Value -eq 'NTLM'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='LogonType';e={$_.Properties[10].Value}}
```
{% endcode %}

**Additional Discovery Techniques**

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;">**Credential Dumping**</mark>

**1.1. Monitoring LSASS Memory Access**

**Purpose**: Detect attempts to access LSASS process memory for credential dumping.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {$_.Properties[9].Value -match 'lsass.exe'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='HandleID';e={$_.Properties[7].Value}}
```
{% endcode %}

**1.2. Detecting the Use of Mimikatz**

**Purpose**: Identify execution of Mimikatz, a tool commonly used for credential dumping.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'mimikatz'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;">**Keylogging and Input Capture**</mark>

**2.1. Detecting Keylogger Installation**

**Purpose**: Identify keylogging software installation.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\*" -Filter "*keylogger*" -Recurse | Select-Object FullName, CreationTime
```
{% endcode %}

**2.2. Monitoring for Keylogger Activity**

**Purpose**: Detect processes indicative of keylogging activity.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -like '*logger*'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Brute Force and Password Guessing**</mark>

**3.1. Monitoring Account Lockout Events**

**Purpose**: Identify multiple failed login attempts indicating brute force attacks.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[0].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**3.2. Detecting Multiple Login Failures**

**Purpose**: Track multiple login failures to identify potential password-guessing attempts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Group-Object -Property {$_.Properties[5].Value} |  Where-Object {$_.Count -gt 10} | Select-Object Name, Count
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Phishing and Spear Phishing**</mark>

**4.1. Identifying Phishing Email Characteristics**

**Purpose**: Detect emails with phishing characteristics, such as suspicious links or attachments.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-EventLog/Email" |  Where-Object {($_.Message -match "http://") -or ($_.Message -match "https://") -or ($_.Message -match ".zip|.rar|.exe|.docm")} | Select-Object TimeCreated, @{n='Details';e={$_.Message}}
```
{% endcode %}

**4.2. Monitoring for Unusual Email Activity**

**Purpose**: Detect unusual email activity, such as unexpected mass emails or account use.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match 'SendEmail'} | Select-Object TimeCreated, @{n='EmailDetails';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Theft from Browsers**</mark>

**5.1. Detecting Access to Stored Browser Credentials**

**Purpose**: Identify access to browser-stored credentials.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data" -Force | Select-Object FullName, LastWriteTime
```
{% endcode %}

**5.2. Monitoring Browser Extension Activity**

**Purpose**: Detect potentially malicious browser extensions that could steal credentials.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Dumping from the Security Account Manager (SAM)**</mark>

**6.1. Monitoring SAM Database Access**

**Purpose**: Detect attempts to access the SAM database, which stores user credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {$_.Properties[9].Value -match 'SAM'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

**6.2. Detecting Use of SAMDump Tools**

**Purpose**: Identify the use of tools designed to dump SAM database contents.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'samdump|pwdump'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Exploitation of Default Credentials**</mark>

**7.1. Detecting Use of Default or Weak Credentials**

**Purpose**: Identify logins using default or weak credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {($_.Properties[5].Value -match 'admin') -or ($_.Properties[5].Value -match 'root')} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}
```
{% endcode %}

**7.2. Monitoring for Access to Critical Systems**

**Purpose**: Detect unauthorized access to critical systems using default credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {($_.Properties[8].Value -eq '0x10')} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Harvesting from Application Credentials**</mark>

**8.1. Detecting Access to Application Credentials**

**Purpose**: Identify attempts to access credentials stored within applications.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match 'credentials'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

**8.2. Monitoring Credential Harvesting via API Calls**

**Purpose**: Detect the use of API calls to harvest credentials from applications.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'Invoke-WebRequest|Invoke-RestMethod'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Pass-the-Hash and Pass-the-Ticket**</mark>

**9.1. Detecting Pass-the-Hash Attacks**

**Purpose**: Identify attempts to use NTLM hashes to authenticate without knowing the plaintext password.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[8].Value -eq 'NTLM'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**9.2. Monitoring for Pass-the-Ticket Attempts**

**Purpose**: Detect unauthorized use of Kerberos tickets.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} | Where-Object {$_.Properties[8].Value -eq '0x1'} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Access via Remote Services**</mark>

**10.1. Detecting Unauthorized RDP Access**

**Purpose**: Monitor for unauthorized Remote Desktop Protocol (RDP) access.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[10].Value -eq '10'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**10.2. Monitoring Remote Service Authentication**

**Purpose**: Identify authentication attempts via remote services like SSH, VPN, etc.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[10].Value -eq '3'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

## <mark style="color:blue;">Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;">**Network Discovery**</mark>

**1.1. Detecting Network Scanning Activities**

**Purpose**: Identify network scanning activities, which may indicate reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen' -and $_.RemoteAddress -ne '0.0.0.0'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**1.2. Identifying New ARP Entries**

**Purpose**: Detect unusual or new ARP table entries that may indicate scanning.

{% code overflow="wrap" %}
```powershell
Get-NetNeighbor | Where-Object {$_.State -eq 'Reachable'} | Select-Object InterfaceIndex, IPAddress, LinkLayerAddress, State
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**User and Account Discovery**</mark>

**2.1. Enumerating Local User Accounts**

**Purpose**: Identify attempts to list local user accounts on systems.

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

**2.2. Active Directory User Enumeration**

**Purpose**: Detect enumeration of Active Directory user accounts.

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter * -Property DisplayName, Title, Department | Select-Object DisplayName, Title, Department
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Group and Permission Discovery**</mark>

**3.1. Listing Local Group Memberships**

**Purpose**: Identify attempts to enumerate local group memberships.

{% code overflow="wrap" %}
```powershell
Get-LocalGroup | ForEach-Object {[PSCustomObject]@{GroupName = $_.Name Members = (Get-LocalGroupMember -Group $_.Name | Select-Object -ExpandProperty Name) -join ", "}}
```
{% endcode %}

**3.2. Active Directory Group Enumeration**

**Purpose**: Detect enumeration of Active Directory groups and their members.

{% code overflow="wrap" %}
```powershell
Get-ADGroup -Filter * -Property Members | Select-Object Name, @{n='Members';e={$_.Members -join ", "}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**System and Application Discovery**</mark>

**4.1. Enumerating Installed Applications**

**Purpose**: Detect attempts to list installed applications on systems.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```
{% endcode %}

**4.2. Listing Running Processes**

**Purpose**: Identify attempts to enumerate running processes.

{% code overflow="wrap" %}
```powershell
Get-Process | Select-Object Id, ProcessName, StartTime
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Network Configuration and Interface Enumeration**</mark>

**5.1. Listing Network Interfaces**

**Purpose**: Detect enumeration of network interfaces on systems.

```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MACAddress
```

**5.2. Getting IP Configuration Details**

**Purpose**: Identify gathering of IP configuration information.

```powershell
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength
```

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Service and Port Discovery**</mark>

**6.1. Listing Listening Ports**

**Purpose**: Detect attempts to list listening ports on systems.

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort
```

**6.2. Enumerating Running Services**

**Purpose**: Identify attempts to enumerate running services.

```powershell
Get-Service | Select-Object Name, DisplayName, Status, StartType
```

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**File and Directory Discovery**</mark>

**7.1. Listing Files in Specific Directories**

**Purpose**: Detect attempts to enumerate files in sensitive directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\SensitiveData\" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

**7.2. Accessing Administrative Shares**

**Purpose**: Identify attempts to access or enumerate administrative shares.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Type=0" | Select-Object Name, Path
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Security and Policy Discovery**</mark>

**8.1. Enumerating Local Security Policies**

**Purpose**: Detect attempts to enumerate local security policies.

```powershell
secedit /export /cfg C:\securitypolicy.cfg Get-Content C:\securitypolicy.cfg
```

**8.2. Checking Audit Policy Settings**

**Purpose**: Identify attempts to enumerate audit policy settings.

```powershell
Get-AuditPolicy | Select-Object Subcategory, Success, Failure
```

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;">**Scheduled Task and Job Discovery**</mark>

**9.1. Listing Scheduled Tasks**

**Purpose**: Detect attempts to enumerate scheduled tasks.

```powershell
Get-ScheduledTask | Select-Object TaskName, LastRunTime, TaskPath
```

**9.2. Enumerating Windows Scheduled Jobs**

**Purpose**: Identify attempts to enumerate Windows scheduled jobs.

```powershell
Get-WmiObject -Class Win32_ScheduledJob | Select-Object Name, JobId, JobStatus
```

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Remote System and Domain Discovery**</mark>

**10.1. Listing Domain Controllers**

**Purpose**: Detect attempts to enumerate domain controllers in the environment.

```powershell
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site
```

**10.2. Enumerating Trust Relationships**

**Purpose**: Identify attempts to enumerate domain trust relationships.

```powershell
Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection
```

## <mark style="color:blue;">Lateral Movement Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Remote Execution and Access Tools**</mark>

**1.1. Detecting Remote Desktop Protocol (RDP) Usage**

**Purpose**: Identify suspicious use of RDP, which may indicate lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |  Where-Object {$_.Properties[10].Value -eq '10'} |  Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**1.2. Monitoring for PowerShell Remoting**

**Purpose**: Detect usage of PowerShell Remoting for remote code execution.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103} |  Where-Object {$_.Message -like "*Creating Scriptblock text*"} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Pass-the-Hash and Pass-the-Ticket**</mark>

**2.1. Detecting Pass-the-Hash Attacks**

**Purpose**: Monitor for usage of NTLM hashes to authenticate without the actual password.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |  Where-Object {$_.Properties[8].Value -eq 'NTLM'} |  Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='LogonType';e={$_.Properties[10].Value}}
```
{% endcode %}

**2.2. Monitoring for Pass-the-Ticket Attempts**

**Purpose**: Identify suspicious usage of Kerberos tickets that may indicate pass-the-ticket attacks.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} |  Where-Object {$_.Properties[8].Value -eq '0x1'} |  Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Remote Services and Scheduled Tasks**</mark>

**3.1. Detecting Remote Service Creation**

**Purpose**: Identify the creation of services on remote systems, often used for lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} |  Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[5].Value}}
```
{% endcode %}

**3.2. Monitoring Scheduled Tasks on Remote Systems**

**Purpose**: Detect creation of scheduled tasks on remote systems for executing code.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*"} | Select-Object TaskName, Principal, @{n='Actions';e={$_.Actions}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**File Sharing and Remote File Copy**</mark>

**4.1. Monitoring for Use of Admin Shares**

**Purpose**: Detect the use of administrative shares (e.g., C$) for file transfers.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Name LIKE 'C$' OR Name LIKE 'ADMIN$'" | Select-Object Name, Path
```
{% endcode %}

**4.2. Detecting Remote File Copy Operations**

**Purpose**: Identify file copy operations to or from remote systems, which may indicate lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} |  Where-Object {$_.Properties[8].Value -match 'File Read|File Write'} |  Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential Harvesting and Stealing**</mark>

**5.1. Monitoring for Credential Dumping Tools**

**Purpose**: Detect the use of tools like Mimikatz for credential harvesting.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[5].Value -match 'mimikatz'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**5.2. Detecting LSASS Memory Access**

**Purpose**: Monitor for access attempts to the LSASS process, which contains credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} |  Where-Object {$_.Properties[9].Value -match 'lsass.exe'} |  Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='HandleID';e={$_.Properties[7].Value}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Use of Legitimate Admin Tools**</mark>

**6.1. Detecting PsExec Usage**

**Purpose**: Identify the use of PsExec, a legitimate tool often used for remote execution.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[5].Value -match 'psexec'} |  Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**6.2. Monitoring for WMI Remote Command Execution**

**Purpose**: Detect usage of WMI for executing commands remotely.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} |  Where-Object {$_.Message -match 'CommandLineEventConsumer'}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Domain Controller and Active Directory Access**</mark>

**7.1. Monitoring Access to Domain Controllers**

**Purpose**: Detect unauthorized access or enumeration attempts against domain controllers.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} |  Where-Object {$_.Properties[8].Value -match 'Domain Controller'} |  Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[5].Value}}
```
{% endcode %}

**7.2. Detecting Enumeration of Active Directory**

**Purpose**: Identify attempts to enumerate Active Directory objects, such as users, groups, or computers.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} |  Where-Object {$_.Properties[5].Value -match 'DS_Replication_*'} |  Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Application and Script Execution**</mark>

**8.1. Detecting Script Execution Across Network**

**Purpose**: Identify the execution of scripts on remote systems.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |  Where-Object {$_.Message -match 'Invoke-Command'} |  Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

**8.2. Monitoring for Malicious Batch Files**

**Purpose**: Detect the execution of batch files that may be used for lateral movement.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\Temp\" -Filter "*.bat" | Select-Object FullName, CreationTime
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Use of Third-Party Remote Access Tools**</mark>

**9.1. Detecting Use of VNC**

**Purpose**: Identify the use of VNC software for remote control.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_Process |  Where-Object {$_.Name -match "vnc"} | Select-Object Name, ProcessId, CommandLine
```
{% endcode %}

**9.2. Monitoring for TeamViewer Usage**

**Purpose**: Detect the presence and use of TeamViewer for remote sessions.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'TeamViewer'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

#### 10. <mark style="color:blue;">**Command and Control (C2) and Beaconing**</mark>

**10.1. Monitoring for Beaconing Activity**

**Purpose**: Detect regular interval connections that may indicate beaconing.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection |  Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Group-Object -Property RemoteAddress |  Where-Object {$_.Count -gt 10}
```
{% endcode %}

**10.2. Detecting C2 Infrastructure Usage**

**Purpose**: Identify connections to known Command and Control infrastructure.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; ID=101} |  Where-Object {($_.Message -match 'SuspiciousDomain1.com') -or ($_.Message -match 'SuspiciousDomain2.com')}
```
{% endcode %}

**Additional Discovery Techniques**

#### 1. <mark style="color:blue;">**Remote Desktop Protocol (RDP) Usage**</mark>

**1.1. Detecting Unauthorized RDP Sessions**

**Purpose**: Identify unauthorized RDP sessions, which may indicate lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[10].Value -eq '10'} |  Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**1.2. Monitoring Multiple RDP Connections from Single Account**

**Purpose**: Detect multiple RDP connections from a single account, indicating potential misuse.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[10].Value -eq '10'} | Group-Object -Property {$_.Properties[5].Value} | Where-Object {$_.Count -gt 5} | Select-Object Name, Count
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Remote Services and Command Execution**</mark>

**2.1. Detecting PsExec Usage**

**Purpose**: Identify the use of PsExec for remote command execution.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'psexec'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**2.2. Monitoring Remote PowerShell Sessions**

**Purpose**: Detect unauthorized remote PowerShell sessions.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103} | Where-Object {$_.Message -match "New-PSSession"} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Windows Management Instrumentation (WMI)**</mark>

**3.1. Detecting WMI Command Execution**

**Purpose**: Monitor for commands executed via WMI, often used for lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} | Where-Object {$_.Message -match 'CommandLineEventConsumer'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Message}}
```
{% endcode %}

**3.2. Monitoring WMI Event Subscription Persistence**

**Purpose**: Identify persistent WMI event subscriptions, which can be used for lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Select-Object Name, Query
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Service and Scheduled Task Creation**</mark>

**4.1. Detecting Creation of New Services**

**Purpose**: Identify the creation of new services, which can be used for lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[5].Value}}
```
{% endcode %}

**4.2. Monitoring Scheduled Task Creation**

**Purpose**: Detect the creation of scheduled tasks that may be used for executing commands.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*"} | Select-Object TaskName, Principal, @{n='Actions';e={$_.Actions}}
```
{% endcode %}

#### 5. <mark style="color:blue;">**File and Directory Discovery**</mark>

**5.1. Monitoring Access to Shared Folders**

**Purpose**: Detect unauthorized access to shared folders, which may indicate lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match '\\\\.*\\Share\\'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

**5.2. Detecting Access to Administrative Shares**

**Purpose**: Identify attempts to access administrative shares, often used for lateral movement.

{% code overflow="wrap" %}
```powershell
`Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Type=0" | Where-Object {($_.Name -match 'C$|ADMIN$')} | Select-Object Name, Path`
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Account and Credential Manipulation**</mark>

**6.1. Monitoring for Privilege Escalation Attempts**

**Purpose**: Detect actions that indicate attempts to escalate privileges.

{% code overflow="wrap" %}
```powershell
`Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='Privileges';e={$_.Properties[9].Value}}`
```
{% endcode %}

**6.2. Detecting Unauthorized User Account Creation**

**Purpose**: Identify the creation of unauthorized user accounts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[0].Value}}, @{n='CreatedBy';e={$_.Properties[1].Value}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;">**Pass-the-Hash and Pass-the-Ticket Attacks**</mark>

**7.1. Detecting NTLM Authentication Attempts**

**Purpose**: Monitor for NTLM authentication attempts, which may indicate pass-the-hash attacks.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[8].Value -eq 'NTLM'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**7.2. Monitoring Kerberos Ticket Requests**

**Purpose**: Identify unusual Kerberos ticket requests, which may indicate pass-the-ticket attacks.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} | Where-Object {$_.Properties[8].Value -eq "0x1"} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[5].Value}}
```
{% endcode %}

#### 8. <mark style="color:blue;">**File Transfer and Data Staging**</mark>

**8.1. Detecting File Transfers via SMB**

**Purpose**: Identify file transfers over SMB, which may indicate lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5145} | Where-Object {$_.Properties[8].Value -match 'File Read|File Write'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

**8.2. Monitoring Use of RDP Clipboard for File Transfer**

**Purpose**: Detect the use of RDP clipboard for transferring files.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RDPClient/Operational'; ID=150} | Where-Object {$_.Message -match "Clipboard"} | Select-Object TimeCreated, @{n='Details';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Network and Protocol Analysis**</mark>

**9.1. Detecting Anomalous Network Traffic**

**Purpose**: Identify unusual network traffic patterns that may indicate lateral movement.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {($_.State -eq 'Established') -and ($_.RemoteAddress -notin 'KnownGoodIPs')} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**9.2. Monitoring for Use of Lateral Movement Tools**

**Purpose**: Detect the use of tools like SMBexec, CrackMapExec, or other lateral movement tools.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[9].Value -match 'smbexec|crackmapexec'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Anomalous Behavior and Activity Monitoring**</mark>

**10.1. Detecting Anomalous Login Times**

**Purpose**: Identify logins occurring at unusual times, indicating potential lateral movement.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {($_.TimeCreated.Hour -lt 6) -or ($_.TimeCreated.Hour -gt 20)} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}
```
{% endcode %}

**10.2. Monitoring for Unusual Access Patterns**

**Purpose**: Detect unusual patterns of access to sensitive systems or data.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {($_.Properties[6].Value -match 'SensitiveData') -and ($_.Properties[18].Value -notin 'KnownIPs')} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

## <mark style="color:blue;">Collection Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;">**File and Data Collection**</mark>

**1.1. Detecting Large File Searches**

**Purpose**: Identify searches for large files, which may indicate data collection.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*" -Recurse -File |  Where-Object {$_.Length -gt 100MB} |  Select-Object FullName, Length
```
{% endcode %}

**1.2. Monitoring for File Searches by Extension**

**Purpose**: Detect searches for specific file types, such as documents or spreadsheets.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*" -Recurse -Include *.docx, *.xlsx, *.pdf |  Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Clipboard Data Collection**</mark>

**2.1. Monitoring Clipboard Access**

{% code overflow="wrap" %}
```powershell
Get-EventLog -LogName Application -Source 'ClipSp' | Select-Object TimeGenerated, EntryType, Message
```
{% endcode %}

**2.2. Detecting Clipboard Content Retrieval**

**Purpose**: Identify attempts to read clipboard contents programmatically.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'Clipboard'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Keystroke Logging**</mark>

**3.1. Detecting Keylogger Installation**

**Purpose**: Identify the presence of keylogging software.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\*" -Filter "*keylogger*" -Recurse | Select-Object FullName, CreationTime
```
{% endcode %}

**3.2. Monitoring for Keystroke Logging Activity**

**Purpose**: Detect processes indicative of keystroke logging.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -like '*logger*'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

#### 4. <mark style="color:blue;">**Screenshot and Video Capture**</mark>

**4.1. Detecting Screenshot Capture Programs**

**Purpose**: Identify tools used for capturing screenshots.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Snagit|Greenshot|SnippingTool'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**4.2. Monitoring Video Capture Software**

**Purpose**: Detect software used for video capture.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'OBS|Camtasia|Debut'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Audio Capture and Surveillance**</mark>

**5.1. Monitoring for Audio Recording Software**

**Purpose**: Identify software that may be used to record audio.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Audacity|AudioHijack|SoundRecorder'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**5.2. Detecting Use of System Microphone**

**Purpose**: Monitor for applications accessing the system's microphone.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_PnPEntity |  Where-Object {($_.Name -match "Microphone") -and ($_.Status -eq "OK")} | Select-Object Name, Status
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Credential and Authentication Data Collection**</mark>

**6.1. Monitoring for Credential Dumping Tools**

**Purpose**: Detect the use of tools like Mimikatz for extracting credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'mimikatz'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**6.2. Detecting Access to Credential Stores**

**Purpose**: Identify attempts to access stored credentials, such as password vaults.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'Credentials'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Email and Messaging Data Collection**</mark>

**7.1. Monitoring for Email Client Activity**

**Purpose**: Detect unusual activity in email clients, such as bulk exports.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=3005} | Where-Object {$_.Message -match 'Outlook'} | Select-Object TimeCreated, @{n='Event';e={$_.Message}}
```
{% endcode %}

**7.2. Detecting Access to Messaging Applications**

**Purpose**: Identify access to messaging applications like Skype, Teams, etc.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Teams|Skype|Slack'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Browser Data Collection**</mark>

**8.1. Detecting Access to Browser Data**

**Purpose**: Monitor for access to browser data, including cookies and history.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default" -Include Cookies, History -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

**8.2. Monitoring Browser Extensions for Data Collection**

**Purpose**: Detect malicious or suspicious browser extensions.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Data Staging and Compression**</mark>

**9.1. Detecting Data Compression Tools**

**Purpose**: Identify the use of tools like WinRAR or 7-Zip for compressing data.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'WinRAR|7z'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**9.2. Monitoring for Creation of Archive Files**

**Purpose**: Detect the creation of archive files that may indicate data staging.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*" -Recurse -Include *.zip, *.rar, *.7z | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Cloud and Remote Storage Access**</mark>

**10.1. Monitoring for Cloud Storage Access**

**Purpose**: Detect access to cloud storage services like Dropbox, Google Drive, etc.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Dropbox|GoogleDrive|OneDrive'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**10.2. Detecting File Uploads to Remote Servers**

**Purpose**: Identify file uploads to remote servers, indicating potential exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'File Write'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

### <mark style="color:blue;">Command & Control (C2) Discovery</mark>

#### 1. <mark style="color:blue;">**Network Connection Monitoring**</mark>

**1.1. Detecting Unusual Outbound Connections**

**Purpose**: Identify suspicious outbound connections to unfamiliar IP addresses or domains.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**1.2. Monitoring Connections to High-Entropy Domains**

**Purpose**: Detect connections to high-entropy domains, often used for C2 communication.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Where-Object {($_.Message -match "QueryName") -and ($_.Message -match "[a-zA-Z0-9]{10,}")} | Select-Object TimeCreated, @{n='DomainName';e={$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '}}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**DNS-based C2 Detection**</mark>

**2.1. Detecting DNS Tunneling**

**Purpose**: Identify potential DNS tunneling used for C2 communication.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Where-Object {($_.Message -match "TXT") -or ($_.Message -match "TXT Record")} | Select-Object TimeCreated, @{n='DomainName';e={$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '}}
```
{% endcode %}

**2.2. Frequent DNS Requests Monitoring**

**Purpose**: Identify frequent DNS requests to the same domain, indicating possible C2 activity.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Group-Object -Property {$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '} | Where-Object {$_.Count -gt 100} |  Select-Object @{n='DomainName';e={$_.Name}}, Count
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**HTTP/HTTPS C2 Detection**</mark>

**3.1. Detecting Suspicious User-Agent Strings**

**Purpose**: Identify HTTP/HTTPS requests with unusual or rare User-Agent strings.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "User-Agent: [^a-zA-Z0-9\- ]+"} | Select-Object TimeCreated, @{n='UserAgent';e={$_.Message -match 'User-Agent: (.*)' -replace 'User-Agent: '}}
```
{% endcode %}

**3.2. Monitoring Encrypted Traffic Anomalies**

**Purpose**: Identify anomalies in encrypted traffic patterns that may indicate HTTPS-based C2.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemotePort -eq 443 -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Beaconing Behavior Detection**</mark>

**4.1. Detecting Regular Interval Connections**

**Purpose**: Identify network connections occurring at regular intervals, indicative of beaconing.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Group-Object -Property RemoteAddress |  Where-Object {$_.Count -gt 10} | Select-Object @{n='RemoteAddress';e={$_.Name}}, Count
```
{% endcode %}

**4.2. Monitoring Low-Volume Periodic Traffic**

**Purpose**: Identify low-volume, periodic network traffic patterns that may suggest C2 communication.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.LocalAddress -notin 'KnownGoodIPs'} | Group-Object -Property RemoteAddress |  Where-Object {$_.Count -gt 10} | Select-Object @{n='RemoteAddress';e={$_.Name}}, Count
```
{% endcode %}

#### 5. <mark style="color:blue;">**Email-based C2 Detection**</mark>

**5.1. Detecting Suspicious Email Attachments**

**Purpose**: Identify email attachments that may contain malicious payloads or scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "Attachment"} | Select-Object TimeCreated, @{n='Attachment';e={$_.Message -match 'Attachment: (.*)' -replace 'Attachment: '}}
```
{% endcode %}

**5.2. Monitoring Unusual Email Communication Patterns**

**Purpose**: Detect unusual patterns in email communication, such as emails with suspicious subjects or senders.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "Subject: [^a-zA-Z0-9\- ]+"} | Select-Object TimeCreated, @{n='Subject';e={$_.Message -match 'Subject: (.*)' -replace 'Subject: '}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Domain Generation Algorithm (DGA) Detection**</mark>

**6.1. Detecting DGA Domain Names**

**Purpose**: Identify domain names generated by a Domain Generation Algorithm (DGA).

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Where-Object {($_.Message -match "[a-zA-Z0-9]{10,}") -and ($_.Message -match ".com|.net|.org")} | Select-Object TimeCreated, @{n='DomainName';e={$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '}}
```
{% endcode %}

**6.2. Monitoring High-Frequency Domain Resolution**

**Purpose**: Identify frequent domain resolutions, a characteristic of DGA-based C2.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Group-cObject -Property {$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '} | Where-Object {$_.Count -gt 200} |  Select-Object @{n='DomainName';e={$_.Name}}, Count
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Peer-to-Peer (P2P) C2 Detection**</mark>

**7.1. Detecting P2P Protocol Traffic**

**Purpose**: Identify traffic indicative of peer-to-peer C2 communication.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemotePort -in 6881, 6889, 6969} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**7.2. Monitoring Unusual Port Usage**

**Purpose**: Identify unusual port usage that may indicate non-standard P2P communications.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemotePort -notin (80, 443, 21, 22, 25)} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Command Execution and Data Exfiltration**</mark>

**8.1. Monitoring Command Execution via C2 Channels**

**Purpose**: Detect the execution of commands or scripts via C2 channels.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |  Where-Object {$_.Properties[9].Value -match "cmd.exe|powershell.exe"} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**8.2. Detecting Data Exfiltration Indicators**

**Purpose**: Identify potential data exfiltration activities, such as large data transfers to external IPs

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**TLS/SSL Certificate Anomalies**</mark>

**9.1. Detecting Self-Signed Certificates**

**Purpose**: Identify the use of self-signed certificates, which may indicate malicious HTTPS traffic.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "Self-Signed"} | Select-Object TimeCreated, @{n='Certificate';e={$_.Message -match 'Certificate: (.*)' -replace 'Certificate: '}}
```
{% endcode %}

**9.2. Monitoring for Short-Lived Certificates**

**Purpose**: Identify the use of short-lived TLS/SSL certificates, often used in malicious activities.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "Certificate Expiry"} | Select-Object TimeCreated, @{n='Certificate';e={$_.Message -match 'Certificate: (.*)' -replace 'Certificate: '}}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Anonymization Services and Tor Usage**</mark>

**10.1. Detecting Tor Network Usage**

**Purpose**: Identify connections to the Tor network, often used for anonymization.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -in 'TorExitNodesIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**10.2. Monitoring for VPN or Proxy Services**

**Purpose**: Detect the use of VPNs or proxy services to mask C2 communication.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -in 'KnownVPNIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**Additional Discovery Techniques**

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Network Traffic and Connection Monitoring**</mark>

**1.1. Detecting Unusual Outbound Connections**

**Purpose**: Identify connections to suspicious or unfamiliar external IP addresses.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**1.2. Monitoring Connections to High-Risk Countries**

**Purpose**: Detect connections to IP addresses in countries known for hosting C2 infrastructure.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {($_.RemoteAddress -match 'IP_Range_Country_X') -and ($_.State -eq 'Established')} | Select-Object LocalAddress, RemoteAddress
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**DNS-based C2 Detection**</mark>

**2.1. Identifying Frequent DNS Queries to Unusual Domains**

**Purpose**: Detect frequent DNS queries that may indicate domain generation algorithm (DGA) activity.

{% code overflow="wrap" %}
```powershell
`Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Group-Object -Property {$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '} | Where-Object {$_.Count -gt 50} |  Select-Object @{n='DomainName';e={$_.Name}}, Count`
```
{% endcode %}

**2.2. Monitoring DNS Requests for Suspicious TLDs**

**Purpose**: Detect DNS requests to top-level domains (TLDs) commonly associated with malicious activity.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Where-Object {($_.Message -match "\.xyz$|\.pw$|\.top$")} | Select-Object TimeCreated, @{n='DomainName';e={$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '}}
```
{% endcode %}

#### 3. <mark style="color:blue;">**HTTP/HTTPS-based C2 Detection**</mark>

**3.1. Detecting Suspicious User-Agent Strings**

**Purpose**: Identify HTTP/HTTPS requests with uncommon or suspicious User-Agent strings.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "User-Agent: [^a-zA-Z0-9\- ]+"} | Select-Object TimeCreated, @{n='UserAgent';e={$_.Message -match 'User-Agent: (.*)' -replace 'User-Agent: '}}
```
{% endcode %}

**3.2. Monitoring HTTP POST Requests**

**Purpose**: Detect HTTP POST requests to suspicious endpoints, indicating potential data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "POST") -and ($_.Message -match "http")} | Select-Object TimeCreated, @{n='URL';e={$_.Message -match 'URL: (.*)' -replace 'URL: '}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Beaconing Behavior Detection**</mark>

**4.1. Identifying Regular Interval Network Connections**

**Purpose**: Detect beaconing behavior characterized by regular interval connections to external IPs.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection |  Group-Object -Property RemoteAddress |  Where-Object {$_.Count -gt 10} |  Select-Object @{n='RemoteAddress';e={$_.Name}}, Count
```
{% endcode %}

**4.2. Monitoring Low-Volume Periodic Traffic**

**Purpose**: Identify low-volume, periodic traffic patterns indicative of beaconing.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {($_.State -eq 'Established') -and ($_.RemoteAddress -notin 'KnownGoodIPs')} | Group-Object -Property RemoteAddress |  Where-Object {$_.Count -gt 10} | Select-Object @{n='RemoteAddress';e={$_.Name}}, Count
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Malicious Code and Script Execution**</mark>

**5.1. Detecting PowerShell Command Execution**

**Purpose**: Monitor for potentially malicious PowerShell command execution.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'Invoke-WebRequest|Invoke-RestMethod'} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

**5.2. Monitoring JavaScript or VBScript Execution**

**Purpose**: Detect the execution of potentially malicious JavaScript or VBScript.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {($_.Properties[5].Value -match 'wscript.exe|cscript.exe') -and ($_.Properties[9].Value -match '\.js|\.vbs')} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**TLS/SSL Certificate Anomalies**</mark>

**6.1. Identifying Self-Signed Certificates**

**Purpose**: Detect the use of self-signed certificates, which may indicate malicious HTTPS traffic.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "Self-Signed"} | Select-Object TimeCreated, @{n='Certificate';e={$_.Message -match 'Certificate: (.*)' -replace 'Certificate: '}}
```
{% endcode %}

**6.2. Monitoring for Short-Lived Certificates**

**Purpose**: Identify the use of short-lived TLS/SSL certificates, often used in malicious activities.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "Certificate Expiry"} | Select-Object TimeCreated, @{n='Certificate';e={$_.Message -match 'Certificate: (.*)' -replace 'Certificate: '}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Email-based C2 Detection**</mark>

**7.1. Detecting Suspicious Email Communications**

**Purpose**: Identify email communications that may indicate C2 activity, such as exfiltration or command execution.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {$_.Message -match "Email Send"} | Select-Object TimeCreated, @{n='EmailDetails';e={$_.Message}}
```
{% endcode %}

**7.2. Monitoring for Unusual Email Attachments**

**Purpose**: Detect email attachments that may contain C2 tools or scripts.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-EventLog/Email" |  Where-Object {($_.Message -match "Attachment: ") -and ($_.Message -match ".exe|.bat|.ps1")} | Select-Object TimeCreated, @{n='Attachment';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Command Execution and Data Exfiltration**</mark>

**8.1. Monitoring for Command and Control via Web Shells**

**Purpose**: Identify the use of web shells for C2 activities.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-IIS-Logging" |  Where-Object {($_.Message -match "POST") -and ($_.Message -match "cmd|powershell")} | Select-Object TimeCreated, @{n='Request';e={$_.Message}}
```
{% endcode %}

**8.2. Detecting Data Exfiltration Indicators**

**Purpose**: Identify potential data exfiltration activities, such as large data transfers to external IPs.

{% code overflow="wrap" %}
```powershell
`Get-NetTCPConnection | Where-Object {($_.State -eq 'Established') -and ($_.RemoteAddress -notin 'KnownGoodIPs')} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort`
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Application Whitelisting and Execution Control Bypass**</mark>

**9.1. Detecting Execution of Non-Whitelisted Applications**

**Purpose**: Monitor the execution of applications that bypass whitelisting controls.

{% code overflow="wrap" %}
```powershell
`Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {($_.Properties[5].Value -notmatch 'whitelisted_app.exe|another_allowed_app.exe')} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}`
```
{% endcode %}

**9.2. Monitoring Dynamic Invocation of Scripts**

**Purpose**: Detect the dynamic invocation of scripts to bypass whitelisting.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'Invoke-Expression|Invoke-Command'} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Peer-to-Peer (P2P) C2 Detection**</mark>

**10.1. Identifying P2P Protocol Traffic**

**Purpose**: Detect traffic indicative of peer-to-peer C2 communication.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemotePort -in 6881, 6889, 6969} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**10.2. Monitoring Unusual Port Usage**

**Purpose**: Identify unusual port usage that may indicate non-standard P2P communications.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemotePort -notin (80, 443, 21, 22, 25)} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

## <mark style="color:blue;">Exfiltration Discovery</mark>

#### 1. <mark style="color:blue;">**Network Traffic and Connection Monitoring**</mark>

**1.1. Detecting Large Data Transfers**

**Purpose**: Identify large data transfers to external IP addresses, which may indicate data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{n='DataTransferred';e={($_.OwningProcess).ToString()}}
```
{% endcode %}

**1.2. Monitoring Unusual Outbound Connections**

**Purpose**: Detect outbound connections to suspicious or uncommon destinations.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Cloud Storage and Remote Access**</mark>

**2.1. Detecting Access to Cloud Storage Services**

**Purpose**: Monitor for access to cloud storage platforms like Dropbox, Google Drive, and OneDrive.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Dropbox|GoogleDrive|OneDrive'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**2.2. Monitoring for File Uploads to Remote Servers**

**Purpose**: Identify file uploads to remote servers, which may indicate exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'File Write'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Email-Based Exfiltration**</mark>

**3.1. Detecting Large Email Attachments**

**Purpose**: Identify large email attachments that may contain exfiltrated data.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-EventLog/Email" | Where-Object {($_.Message -match 'Attachment: ') -and ($_.Message -match '[0-9]{5,} bytes')} | Select-Object TimeCreated, @{n='Attachment';e={$_.Message -match 'Attachment: (.*)' -replace 'Attachment: '}}
```
{% endcode %}

**3.2. Monitoring Use of Personal Email Accounts**

**Purpose**: Detect the use of personal email accounts for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" | Where-Object {($_.Message -match 'Subject: ') -and ($_.Message -match '@gmail.com|@yahoo.com')} | Select-Object TimeCreated, @{n='Recipient';e={$_.Message -match 'Recipient: (.*)' -replace 'Recipient: '}}
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**USB and Removable Media**</mark>

**4.1. Detecting USB Device Insertions**

**Purpose**: Monitor the insertion of USB devices, which may be used for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=20001} | Where-Object {$_.Message -match 'USB'} | Select-Object TimeCreated, @{n='Device';e={$_.Message -match 'Device: (.*)' -replace 'Device: '}}
```
{% endcode %}

**4.2. Monitoring File Transfers to USB Drives**

**Purpose**: Detect file transfers to USB devices.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match 'E:\\'} |  # Assuming E: is the USB drive letter Select-Object TimeCreated, @{n='FileName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Compression and Encryption**</mark>

**5.1. Detecting Use of Compression Tools**

**Purpose**: Identify the use of tools like WinRAR or 7-Zip for compressing data.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'WinRAR|7z'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**5.2. Monitoring Encryption Tool Usage**

**Purpose**: Detect the use of encryption tools, indicating attempts to secure exfiltrated data.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'gpg.exe|openssl.exe'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Steganography and Data Hiding**</mark>

**6.1. Detecting Steganography Tools**

**Purpose**: Identify the use of steganography tools for hiding data in images or other files.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\*" -Recurse -Include *steg* | Select-Object FullName, LastWriteTime
```
{% endcode %}

**6.2. Monitoring for Unusual File Types in Sensitive Locations**

**Purpose**: Detect unusual file types or hidden data in sensitive directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\SensitiveData\*" -Recurse -Include *.jpg, *.png | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Network Protocol Abuse**</mark>

**7.1. Detecting ICMP Exfiltration**

**Purpose**: Monitor for data exfiltration attempts using ICMP (ping).

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 7} |  # ICMP Echo Select-Object LocalAddress, RemoteAddress, RemotePort
```
{% endcode %}

**7.2. Monitoring for DNS Data Exfiltration**

**Purpose**: Identify attempts to use DNS queries for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Where-Object {($_.Message -match "TXT") -or ($_.Message -match "TXT Record")} | Select-Object TimeCreated, @{n='DomainName';e={$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '}}
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**SFTP and FTP Transfers**</mark>

**8.1. Detecting SFTP Transfers**

**Purpose**: Identify data transfers using SFTP.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "SFTP") -and ($_.Message -match "Upload")} | Select-Object TimeCreated, @{n='RemoteAddress';e={$_.Message -match 'RemoteAddress: (.*)' -replace 'RemoteAddress: '}}
```
{% endcode %}

**8.2. Monitoring FTP Uploads**

**Purpose**: Detect data uploads via FTP.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "FTP") -and ($_.Message -match "Upload")} | Select-Object TimeCreated, @{n='RemoteAddress';e={$_.Message -match 'RemoteAddress: (.*)' -replace 'RemoteAddress: '}}
```
{% endcode %}

#### 9. <mark style="color:blue;">**Physical Media Exfiltration**</mark>

**9.1. Monitoring CD/DVD Write Events**

**Purpose**: Detect attempts to write data to CD/DVD media.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "CD") -or ($_.Message -match "DVD")} | Select-Object TimeCreated, @{n='Action';e={$_.Message -match 'Action: (.*)' -replace 'Action: '}}
```
{% endcode %}

**9.2. Detecting Data Copy to External Hard Drives**

**Purpose**: Monitor for data copies to external hard drives.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match 'F:\\'} |  # Assuming F: is the external drive letter Select-Object TimeCreated, @{n='FileName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**HTTP/S and Web-based Exfiltration**</mark>

**10.1. Detecting HTTP POST Requests**

**Purpose**: Identify HTTP POST requests that may be used for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "POST") -and ($_.Message -match "http")} | Select-Object TimeCreated, @{n='URL';e={$_.Message -match 'URL: (.*)' -replace 'URL: '}}
```
{% endcode %}

**10.2. Monitoring Web Uploads**

**Purpose**: Detect uploads via web forms or other HTTP/S methods.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "Upload") -and ($_.Message -match "http")} | Select-Object TimeCreated, @{n='URL';e={$_.Message -match 'URL: (.*)' -replace 'URL: '}}
```
{% endcode %}

### <mark style="color:blue;">Impact Discovery</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Data Destruction and Manipulation**</mark>

**1.1. Detecting Mass File Deletions**

**Purpose**: Identify mass deletions of files, which may indicate a destructive action.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'Delete'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

**1.2. Monitoring File Modifications**

**Purpose**: Detect unauthorized modifications to critical files.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'WriteData'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**System and Service Disruption**</mark>

**2.1. Detecting Service Stoppages**

**Purpose**: Identify unexpected stoppages of critical services.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7036} | Where-Object {$_.Message -match 'stopped'} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Message -match 'The (.*) service' -replace 'The | service'}}
```
{% endcode %}

**2.2. Monitoring Unexpected System Shutdowns or Restarts**

**Purpose**: Detect system shutdowns or restarts that may indicate malicious activity.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074} | Select-Object TimeCreated, @{n='Reason';e={$_.Properties[5].Value}}
```
{% endcode %}

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Ransomware and Encryption**</mark>

**3.1. Detecting File Encryption Activity**

**Purpose**: Identify signs of ransomware encrypting files.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'ReadData'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

**3.2. Monitoring for Ransomware Note Creation**

**Purpose**: Detect the creation of ransomware notes in directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\Documents\*" -Recurse -Include *.txt | Where-Object {($_.Name -match 'READ_ME') -or ($_.Name -match 'DECRYPT_INSTRUCTIONS')} | Select-Object FullName, CreationTime
```
{% endcode %}

#### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**System Integrity and Configuration Changes**</mark>

**4.1. Monitoring for Unauthorized Changes to System Files**

**Purpose**: Detect unauthorized changes to important system files.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Windows\System32" -Recurse -Include *.exe, *.dll | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
```
{% endcode %}

**4.2. Detecting Group Policy Object Modifications**

**Purpose**: Identify unauthorized modifications to Group Policy Objects (GPOs).

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136} | Where-Object {$_.Message -match 'groupPolicyContainer'} | Select-Object TimeCreated, @{n='AttributeName';e={$_.Properties[9].Value}}
```
{% endcode %}

#### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Security Tool Tampering**</mark>

**5.1. Detecting Disabling of Security Software**

**Purpose**: Identify attempts to disable antivirus or other security tools.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Where-Object {$_.Properties[0].Value -match 'Security' -or $_.Properties[0].Value -match 'AV'} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[5].Value}}
```
{% endcode %}

**5.2. Monitoring Changes to Firewall Settings**

**Purpose**: Detect unauthorized changes to firewall rules that may expose systems to attacks.

{% code overflow="wrap" %}
```powershell
Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {($_.Action -eq 'Allow') -and ($_.Enabled -eq 'True')} | Select-Object Name, Action, Enabled, Direction, LocalAddress, RemoteAddress
```
{% endcode %}

#### 6. <mark style="color:blue;">**Data Integrity and Backup Manipulation**</mark>

**6.1. Detecting Deletion of Backup Files**

**Purpose**: Identify the deletion of backup files, which may prevent recovery from an attack.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Backups\*" -Recurse -Include *.bak | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-1)}
```
{% endcode %}

**6.2. Monitoring Shadow Copy Deletions**

**Purpose**: Detect the deletion of Volume Shadow Copies, which may indicate ransomware activity.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=8224} | Where-Object {$_.Message -match 'The VSS service is shutting down'} | Select-Object TimeCreated, @{n='Message';e={$_.Message}}
```
{% endcode %}

#### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Application and Software Integrity**</mark>

**7.1. Detecting Unauthorized Software Installations**

**Purpose**: Identify the installation of unauthorized or malicious software.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=11707} | Select-Object TimeCreated, @{n='ProductName';e={$_.Properties[0].Value}}, @{n='InstalledBy';e={$_.Properties[1].Value}}
```
{% endcode %}

**7.2. Monitoring Changes to Software Configurations**

**Purpose**: Detect unauthorized changes to critical software configurations.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_Product |  Where-Object {$_.InstallDate -gt (Get-Date).AddDays(-1)} | Select-Object Name, Version, InstallDate
```
{% endcode %}

#### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Log and Audit Manipulation**</mark>

**8.1. Detecting Clearing of Event Logs**

**Purpose**: Identify attempts to clear event logs, which may indicate an effort to cover tracks.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102}
```

**8.2. Monitoring Changes to Audit Policy**

**Purpose**: Detect unauthorized changes to audit policy settings.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name MaxSize
```
{% endcode %}

#### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**System Resource Abuse**</mark>

**9.1. Detecting Cryptocurrency Mining Activity**

**Purpose**: Identify unauthorized use of system resources for cryptocurrency mining.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'xmrig|miner'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**9.2. Monitoring Unusual CPU and Memory Usage**

**Purpose**: Detect abnormal spikes in CPU and memory usage, indicating potential resource abuse.

{% code overflow="wrap" %}
```powershell
Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 5 -MaxSamples 3 | Where-Object {$_.CounterSamples.CookedValue -gt 80}
```
{% endcode %}

#### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Website Defacement and System Messaging**</mark>

**10.1. Detecting Website Defacement**

**Purpose**: Identify unauthorized changes to website content.

{% code overflow="wrap" %}
```powershell
Get-Content -Path "C:\inetpub\wwwroot\index.html" | Where-Object {$_ -match 'Hacked by|Defaced by'}
```
{% endcode %}

**10.2. Monitoring System Message Display**

**Purpose**: Detect the display of unauthorized system messages or pop-ups.

{% code overflow="wrap" %}
```powershell
Get-EventLog -LogName Application -Source "Windows Error Reporting" | Where-Object {$_.Message -match 'Ransom Note|Warning Message'} | Select-Object TimeGenerated, EntryType, Message
```
{% endcode %}
