---
hidden: true
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

# Lateral Movement Discovery

### Lateral Movement Discovery

#### 1. **Remote Execution and Access Tools**

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

#### 2. **Pass-the-Hash and Pass-the-Ticket**

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

#### 3. **Remote Services and Scheduled Tasks**

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

#### 4. **File Sharing and Remote File Copy**

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

#### 5. **Credential Harvesting and Stealing**

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

#### 6. **Use of Legitimate Admin Tools**

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

#### 7. **Domain Controller and Active Directory Access**

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

#### 8. **Application and Script Execution**

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

#### 9. **Use of Third-Party Remote Access Tools**

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

#### 10. **Command and Control (C2) and Beaconing**

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

#### 1. **Remote Desktop Protocol (RDP) Usage**

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

#### 2. **Remote Services and Command Execution**

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

#### 3. **Windows Management Instrumentation (WMI)**

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

#### 4. **Service and Scheduled Task Creation**

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

#### 5. **File and Directory Discovery**

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

#### <mark style="color:blue;">6.</mark> **Account and Credential Manipulation**

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

#### 7. **Pass-the-Hash and Pass-the-Ticket Attacks**

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

#### 8. **File Transfer and Data Staging**

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

#### 9. **Network and Protocol Analysis**

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

#### 10. **Anomalous Behaviour and Activity Monitoring**

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
