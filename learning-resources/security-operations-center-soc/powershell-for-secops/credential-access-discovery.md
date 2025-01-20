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

# Credential Access Discovery

### **Introduction**

PowerShell is a powerful and flexible tool that plays a critical role in security operations (SecOps), particularly in the detection, investigation, and remediation of threats within enterprise networks. Its deep integration with Windows systems, robust scripting capabilities, and extensive library of cmdlets make it an essential asset for digital forensics and incident response (DFIR). Specifically, PowerShell is highly effective in uncovering **Credential Access Discovery** activities, which are often part of an attacker’s effort to gain unauthorised access to sensitive accounts or escalate privileges. By leveraging PowerShell, SecOps teams can efficiently identify and mitigate credential theft or misuse, a critical step in protecting enterprise environments.

***

### **Capabilities of PowerShell for Credential Access Discovery in DFIR**

**1. Detecting Credential Dumping Activities:**

PowerShell enables the identification of suspicious activities like memory dumping or unauthorised access to critical processes such as`lsass.exe`, often targeted for credential extraction. It can also detect tools and techniques used to dump password hashes or plaintext credentials, providing insights into attacker behaviour.

**2. Investigating Credential Storage Locations:**

PowerShell can analyse system components like the Security Account Manager (SAM), Active Directory database files, and registry entries to detect unauthorised access attempts or modifications. It is also capable of monitoring sensitive storage areas, such as the Windows Credential Manager, to uncover malicious activities aimed at harvesting credentials.

**3. Monitoring for Credential Harvesting:**

PowerShell can be used to identify abnormal patterns in account usage, such as unusual logins, privilege escalations, or anomalous network activity. This enables security teams to track the misuse of compromised credentials across the network and detect lateral movement or unauthorised access attempts.

**4. Hunting for Tools and Techniques:**

PowerShell can effectively detect malicious tools, obfuscated scripts, or encoded commands used in credential theft attacks. It also supports monitoring for Kerberos ticket abuse, such as Golden or Silver Ticket attacks, which adversaries often employ to maintain persistent access.

**5. Artifact Collection for Forensic Analysis:**

PowerShell automates the collection of critical forensic artifacts, such as security logs, memory dumps, and process details. These artifacts provide valuable evidence for identifying the scope of credential access activities and understanding the attacker’s methods.

***

### **Efficiency Provided by PowerShell in Credential Access Discovery**

1. **Comprehensive Visibility**: PowerShell provides unparalleled access to logs, processes, and system configurations, offering a complete view of credential access attempts and associated behaviours.
2. **Scalability**: The ability to execute scripts across multiple endpoints through PowerShell Remoting makes it ideal for investigations in large enterprise environments.
3. **Real-Time Insights**: PowerShell’s dynamic querying capabilities enable security teams to detect and analyse credential-related threats in real-time, reducing response times.
4. **Automation and Consistency**: By automating repetitive tasks, PowerShell ensures consistency in detection and analysis workflows while freeing up analysts for more complex investigations.
5. **Customisable Detection**: PowerShell scripts can be tailored to align with the **MITRE ATT\&CK framework**, ensuring the detection of specific adversarial tactics and techniques.
6. **Integration with Security Tools**: Seamless integration with platforms like Microsoft Sentinel, Defender for Endpoint, and SIEM tools enhances the efficiency and effectiveness of credential access discovery and incident response efforts.

***

By utilising PowerShell’s extensive capabilities, SecOps teams can effectively detect and investigate credential access activities, enabling timely mitigation and strengthening the overall security posture of the enterprise.

### Credential Access Discovery

### 1. **Detecting Credential Dumping Attempts**

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

### 2. **Suspicious Account Activity Monitoring**

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

### 3. **Phishing and Email-based Attacks**

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

### 4. **Credential Caching and Storage**

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

### 5. **Keylogging and User Input Capture**

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

### 6. **Credential Theft from API and Memory**

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

### 7. **Suspicious Network and Remote Access Activity**

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

### 8. **Password and Credential Policy Changes**

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

### 9. **Browser and Web-based Credential Theft**

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

### 10. **Advanced Credential Stealing Techniques**

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

### **Additional Discovery Techniques**

### 1. **Credential Dumping**

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

### 2. **Keylogging and Input Capture**

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

### 3. **Brute Force and Password Guessing**

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

### 4. **Phishing and Spear Phishing**

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

### 5. **Credential Theft from Browsers**

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

### 6. **Credential Dumping from the Security Account Manager (SAM)**

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

### 7. **Exploitation of Default Credentials**

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

### 8. **Credential Harvesting from Application Credentials**

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

### 9. **Pass-the-Hash and Pass-the-Ticket**

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

### 10. **Credential Access via Remote Services**

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
