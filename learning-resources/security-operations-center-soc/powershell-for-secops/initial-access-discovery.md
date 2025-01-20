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

# Initial Access Discovery

### Initial Access Discovery

#### 1. **Suspicious Process Execution**

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

#### 2. **User Account Activity Monitoring**

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

#### 3. **File and Directory Monitoring**

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

#### 4. **Network Activity Analysis**

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

#### 5. **Scheduled Tasks and Services**

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

#### 6. **Registry Modifications**

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

#### 7. **Event Log Monitoring**

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

#### 8. **Email Security Monitoring**

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

#### 9. **Application Execution Monitoring**

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

#### 10. **System and Security Configuration**

**10.1. Group Policy Object Modifications**

**Purpose**: Detect unauthorised changes to Group Policy Objects.

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

#### 1. **Phishing and Spear Phishing**

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

#### 2. **Exploiting Vulnerabilities**

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

#### 3. **Credential Theft and Brute Force**

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

#### 4. **Malicious Code Execution**

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

#### 5. **Malicious File and Malware Deployment**

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

#### 6. **Abuse of Valid Accounts**

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

#### 8. **Remote Services and Exploitation**

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

#### 9. **Abuse of Application Layer Protocols**

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

#### 10. **Malicious Use of Legitimate Tools**

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
