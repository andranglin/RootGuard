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

# Privilege Escalation Discovery

### **Introduction**

PowerShell is an indispensable tool for security operations (SecOps), offering extensive capabilities for managing and securing enterprise networks. Its deep integration with Windows systems, robust scripting functionality, and comprehensive library of cmdlets make it a critical asset for conducting **Privilege Escalation Discovery** activities in digital forensics and incident response (DFIR) investigations. Privilege escalation is a tactic commonly used by attackers to gain elevated access within a network, enabling them to execute unauthorised actions and evade security measures. PowerShell empowers SecOps teams to efficiently detect and analyse privilege escalation techniques, providing actionable insights to mitigate threats and protect enterprise systems.

***

### **Capabilities of PowerShell for Privilege Escalation Discovery in DFIR**

**1. Enumerating Local and Domain Users:**

PowerShell enables analysts to query user accounts and groups on local systems and Active Directory (AD). This helps detect newly created accounts, unauthorised privilege assignments, or abnormal group memberships that could indicate privilege escalation attempts.

**2. Analysing Privilege Changes:**

With PowerShell, analysts can monitor privilege escalation events, such as changes to user rights, group policies, or role assignments. This includes tracking modifications to critical groups like Administrators, Domain Admins, or Enterprise Admins.

**3. Detecting Misconfigurations and Exploitable Settings:**

Attackers often exploit misconfigurations to elevate privileges. PowerShell allows for the inspection of file and folder permissions, service configurations, and registry keys to identify weaknesses, such as improperly set `SeTakeOwnershipPrivilege` or `SeDebugPrivilege`.

**4. Identifying Credential Exposure:**

Privilege escalation often involves harvesting credentials from compromised systems. PowerShell facilitates the detection of exposed credentials, such as plaintext passwords in scripts, memory, or configuration files, which attackers might use to gain elevated access.

**5. Monitoring Process and Service Escalation:**

PowerShell provides detailed insights into running processes and services, helping analysts identify processes with elevated privileges or services that have been modified to execute malicious binaries.

**6. Event Log Analysis:**

Privilege escalation activities often leave traces in Windows event logs. PowerShell enables querying of security logs for specific events, such as changes to user rights, process creation with elevated privileges, or attempts to exploit privileged accounts.

**7. Hunting for Privilege Escalation Tools:**

Attackers commonly use tools like Mimikatz or PsExec for privilege escalation. PowerShell allows analysts to search for the presence of these tools, as well as their execution traces in system logs or memory.

***

### **Efficiency Provided by PowerShell in Privilege Escalation Discovery**

1. **Comprehensive Visibility**: PowerShell offers access to critical system components and logs, allowing security teams to detect privilege escalation attempts across both local systems and domain environments.
2. **Real-Time Analysis**: PowerShell’s dynamic querying capabilities provide real-time insights into privilege-related activities, enabling rapid detection and response to escalation attempts.
3. **Scalability**: Using **PowerShell Remoting**, analysts can perform privilege escalation discovery across multiple endpoints simultaneously, ensuring coverage in large enterprise networks.
4. **Automation and Consistency**: PowerShell scripts automate repetitive tasks, such as querying group memberships or analysing user rights, ensuring consistent and efficient investigation workflows.
5. **Customisable Detection**: PowerShell can be tailored to detect specific privilege escalation techniques outlined in the **MITRE ATT\&CK framework**, ensuring alignment with known adversarial tactics.
6. **Integration with Security Tools**: PowerShell integrates seamlessly with platforms like Microsoft Sentinel, Defender for Endpoint, and other SIEMs, enabling enriched detection and automated remediation workflows.

***

By leveraging PowerShell’s capabilities, SecOps teams can efficiently identify and mitigate privilege escalation activities, enhancing their ability to protect enterprise networks and maintain a robust security posture.

### Privilege Escalation Discovery

### 1. **Monitoring Process and Service Changes**

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

### 2. **User and Group Changes**

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

### 3. **Registry and System Configuration**

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

### 4. **Scheduled Tasks and Services**

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

### 5. **Access Control and Permissions**

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

### 6. **Executable and Script Monitoring**

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

### 7. **Application and Service Installation**

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

### 8. **Exploit Detection and Mitigation**

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

### 9. **Audit Policy and Event Log Monitoring**

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

### 10. **Domain and Network-Level Privilege Escalation**

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

### **Additional Discovery Techniques**

### 1. **Monitoring Account Privilege Changes**

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

### 2. **Service and Process Manipulation**

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

### 3. **Scheduled Tasks and Cron Jobs**

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

### 4. **Exploitation of Vulnerabilities and Misconfigurations**

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

### 5. **Credential Theft and Reuse**

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

### 6. **Exploit Local Privilege Escalation (LPE) Vulnerabilities**

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

### 7. **Abuse of Built-in Windows Tools**

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

### 8. **Abuse of Service Control Manager**

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

### 9. **Manipulation of Security Policies and Settings**

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

### 10. **Manipulation of Active Directory Objects**

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
