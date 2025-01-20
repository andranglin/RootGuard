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

# Impact Discovery

### Impact Discovery

#### 1. **Data Destruction and Manipulation**

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

#### 2. **System and Service Disruption**

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

#### 3. **Ransomware and Encryption**

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

#### 4. **System Integrity and Configuration Changes**

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

#### 5. **Security Tool Tampering**

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

#### 6. **Data Integrity and Backup Manipulation**

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

#### 7. **Application and Software Integrity**

**7.1. Detecting Unauthorised Software Installations**

**Purpose**: Identify the installation of unauthorised or malicious software.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=11707} | Select-Object TimeCreated, @{n='ProductName';e={$_.Properties[0].Value}}, @{n='InstalledBy';e={$_.Properties[1].Value}}
```
{% endcode %}

**7.2. Monitoring Changes to Software Configurations**

**Purpose**: Detect unauthorised changes to critical software configurations.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_Product |  Where-Object {$_.InstallDate -gt (Get-Date).AddDays(-1)} | Select-Object Name, Version, InstallDate
```
{% endcode %}

#### 8. **Log and Audit Manipulation**

**8.1. Detecting Clearing of Event Logs**

**Purpose**: Identify attempts to clear event logs, which may indicate an effort to cover tracks.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102}
```

**8.2. Monitoring Changes to Audit Policy**

**Purpose**: Detect unauthorised changes to audit policy settings.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name MaxSize
```
{% endcode %}

#### 9. **System Resource Abuse**

**9.1. Detecting Cryptocurrency Mining Activity**

**Purpose**: Identify unauthorised use of system resources for cryptocurrency mining.

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

#### 10. **Website Defacement and System Messaging**

**10.1. Detecting Website Defacement**

**Purpose**: Identify unauthorised changes to website content.

{% code overflow="wrap" %}
```powershell
Get-Content -Path "C:\inetpub\wwwroot\index.html" | Where-Object {$_ -match 'Hacked by|Defaced by'}
```
{% endcode %}

**10.2. Monitoring System Message Display**

**Purpose**: Detect the display of unauthorised system messages or pop-ups.

{% code overflow="wrap" %}
```powershell
Get-EventLog -LogName Application -Source "Windows Error Reporting" | Where-Object {$_.Message -match 'Ransom Note|Warning Message'} | Select-Object TimeGenerated, EntryType, Message
```
{% endcode %}
