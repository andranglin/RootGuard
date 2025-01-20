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

# Persistence Discovery

### Persistence Discovery

#### 1. **Registry-Based Persistence**

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

#### 2. **Scheduled Tasks and Services**

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

#### 3. **WMI Persistence**

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

#### 4. **Startup Folder Persistence**

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

#### 5. **GPO and Logon Scripts**

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

#### 6. **Binary and Script-Based Persistence**

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

#### 7. **Malicious Use of Scripting Languages**

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

#### 8. **Registry Persistence**

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

#### 9. **Boot and Auto-Start Configuration**

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

#### 10. **Persistence via Network and Remote Services**

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

#### 1. **Registry and Autoruns Monitoring**

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

#### 2. **Service and Scheduled Task Persistence**

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

#### 3. **WMI and COM Object Persistence**

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

#### 4. **Startup Scripts and Logon Hooks**

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

#### 5. **Malicious Use of Scheduled Jobs and Cron Jobs**

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

#### 6. **Persistence via System Service**<mark style="color:blue;">**s**</mark>

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

#### 7. **Browser Extensions and Plug-Ins**

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

#### 8. **DLL Hijacking and Injection**

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

#### 9. **Remote Access and Backdoors**

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

#### 10. **Persistence via System and Network Configuration**

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
