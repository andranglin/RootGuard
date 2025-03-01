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

# PowerShell for Detection and Analysis

## Incident Identification

### General Indicators Of Compromise

```powershell
1. Attack Surface Vulnerability Exists
2. Corroboration From Multiple Intelligence Assets
3. Unusual Ingress/Egress Network Traffic
4. Anomalies In Privileged User Account Activity
5. Geographical Irregularities
6. Log-In Anomalies
7. Volume Increase For Database Reads
8. HTTP Response Size Anomalies
9. Large Numbers Of Requests For The Same File
10. Mismatched Port-Application Traffic
11. Suspicious Registry Or System File Changes
12. DNS Request Anomalies
13. Unexpected Patching Of Systems
14. Mobile Device Profile Changes
15. Data In The Wrong Places
16. Unusual Lateral Movement
17. Velocity Increase For Share / Mount Activity
18. Time Based Anomalies
19. Suspicious Byte Counts
20. Suspicious Domain Controller Activity
21. Subsequent Activity By Attacker Address / GEO
22. HTTP Response Code Success
23. File Hashes
```

### Internal Threat Indicators

```powershell
1. Logons To New Or Unusual Systems
2. New Or Unusual Logon Session Types
3. Unusual Time Of Day Activity
4. Unusual GEO Access or Access Attempts
5. Unlikely Velocity
6. Shared Account Usage
7. Privileged Account Usage
8. Unusual Program Execution
9. New Program Execution
10. High Volume File Access
11. Unusual File Access Patterns
12. Cloud-based File Sharing Uploads
13. New IP Address Association
14. Bad Reputation Address Association
15. Unusual DNS Queries
16. Bandwidth Usage
17. Unusual Or Suspicious Application Usage
18. Dark Outbound Network Connections
19. Known Command And Control Connections
20. Building Entry And Exits
21. High Volume Printing Activity
22. Unusual Time Period Printing
23. Endpoint Indicators Of Compromise
24. Sensitive Table Access
25. Sensitive Data Movement Combined With Other Risk Indicators
```

### Network Forensic Indicators

```powershell
1. Known Signatures
2. Reputation
3. IP Addresses
4. Domains
5. DNS Queries
6. IPS/IDS Indicators
7. Anomalous Traffic Patterns
8. Protocols
9. Inconsistent Protocols
10. Malformed Protocols
11. Masquerading Protocols
12. Prohibited Protocols
```

### Suspicious Domain Indicators

```powershell
1. Domain registered date is recent
2. Domain registrant is anonymous or non-reputable
3. Domain shares similar characteristics with prior known bad
4. Domain has a suspicious email infrastructure
5. Domain has a suspicious website infrastructure
6. Domain has a disreputable history
7. Domain has suspicious IP addresses / DNS data
```

### Azure & Office 365 Indicators

```powershell
1. Privileged account logon from foreign address
2. Creation of accounts in Azure AD
3. Traffic restrictions loosened on Virtual Network
4. Storage account accessed via stolen key from foreign address
5. Subscription Administrator added
6. Windows level intrusion of VM
7. High priority target's mailbox is accessed
```

### Important event logs

{% code overflow="wrap" %}
```powershell
Some of the common event logs that you want to collect as part of live response are given below:
- Logon events
- Logon failure events
- Time change events
- Application crashes
- Process execution
- Service control manager events
- Windows-Application-Experience/Program-Inventory events
- Task scheduler events
- Terminal services events
- User creation
- Logon using explicit credentials
- Privilege use events
- DNS – failed resolution events
- WFP events
```
{% endcode %}

## Identify Notable Processes

* **Monitor process behaviour:** Look for any unusual or suspicious activities, such as high CPU or memory usage, unexpected network traffic, or processes running from unfamiliar locations.
* **Check process file locations:** Verify the file locations of running processes. Legitimate Windows processes typically reside in specific system directories (e.g., C:\Windows\System32). If you find a process running from an unusual location, it could indicate malware.
* **Investigate process names:** Research the names of unfamiliar or suspicious processes.
* **Analyse process signatures:** Use tools like Process Explorer or Process Monitor to examine digital signatures of running processes. Legitimate processes often have valid digital signatures from reputable publishers, while unsigned or suspicious signatures can indicate potential malicious activity.
* **Monitor startup programs:** Regularly review the list of programs set to run at system startup. Use the "msconfig" utility or Task Manager's Startup tab to check for unfamiliar or suspicious entries. Malware often tries to persist by adding itself to startup programs.
* **Check for unusual network connections**: Use network monitoring tools to identify any abnormal network connections initiated by processes. Look for connections to suspicious IP addresses or domains that are known to be associated with malware or botnets.
* **Be cautious of system changes:** Be vigilant when new processes suddenly appear after installing software or visiting unknown websites. Malware may attempt to install additional processes or modify existing ones. Monitor your system for any unauthorized changes.

## System Processes

* **System** (Profile: start at boot, no parent, one instance, runs .sys and .dll executables, runs for ntoskml.exe)
* **Services** (Profile: Parent is wininit.exe, Starts at boot, path= C\Windows\System32, only one instance running)
* **lsm.exe** (Profile: Parent is wininit.exe, Starts at boot, Path= C\Windows\System32, only one instance running
* **csrss.exe** (Profile: Parent not shown (parent disappears after boot), could have multiple processes running, start after boot, Path= C\Windows\System32)
* **tashost.exe** (Profile: Parent is Services, trigger based on User or local service action, path= C\Windows\System32)
* **Winlogon.exe** (Profile: Parent not shown, path=C\Windows\System32, Children = (LogonUI.exe, winlogon.exe, and Dwm.exe))
* **Lsass.exe** (Profile: Starts at boot, Parent is wininit.exe, Path = C\Windows\System32, Only one instance, NO child processes)
* **SMSS.exe**  (Profile: Starts immediately after boot, Parent is System, Path = C\Windows\System32)
* **WININIT.exe** (Profile: Starts immediately after boot, Will not see Parent(smss.exe), Only one instance, Associated with starting: (lsm.exe, lsass.exe, services.exe))
* **SVCHOST.exe** (Profile: Parent is services.exe, multiple instances running, Used for running service DLLS, Path = C\Windows\System32)

## User Processes

* **Explorer.exe** (Profile: Parent not shown, Path=C\Windows\System32, One for each logged-on user, Running underneath it should be user programs)
* **Iexplore.exe** (Profile: Parent is explorer.exe, Path="Program files\Internet Explorer" OR Path=Program files (x86), One for each logged-on user, Running underneath it should be user programs)

***

## Accounts and Groups

### Local Groups

{% code overflow="wrap" %}
```powershell
Get-LocalGroup
Get-LocalGroup | ft Name
Get-LocalGroupMember Administrator
Get-ChildItem C:\Users | ft Name
```
{% endcode %}

### Logged in Users

{% code overflow="wrap" %}
```powershell
Write-Host $env:UserDomain\$env:UserName;
Start-Process "qwinsta" -NoNewWindow -Wait
```
{% endcode %}

### Local Users

{% code overflow="wrap" %}
```powershell
Get-LocalUser | ft Name,Enabled,LastLogon;
Get-LocalUser
Get-LocalUser | where Enabled -eq $True
```
{% endcode %}

### &#x20;Local Administrators

{% code overflow="wrap" %}
```powershell
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
{% endcode %}

### Domain Account - Users | Group | Computers

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter 'Name -Like "*"' | where Enabled -eq $True
Get-ADGroupMember Administrator | where objectClass -eq 'user'
Get-ADComputer -Filter "Name -Like '*'" -Properties * | where Enabled -eq $True | Select-Object Name, OperatingSystem, Enabled
```
{% endcode %}

### List of IPV4 Addresses Who Have Connected (RDP)

{% code overflow="wrap" %}
```powershell
Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | select -exp Properties | where {$_.Value -like '...' } | sort Value -u
```
{% endcode %}

### User Autologon Registry Items

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*"
```
{% endcode %}

### Check for executables in the Local System User Profile and Files

{% code overflow="wrap" %}
```powershell
Get-ChildItem C:\Windows\*\config\systemprofile -recurse -force -ea 0 -include *.exe, *.dll *.lnk
```
{% endcode %}

### Startup Commands for Certain Programs

```cs
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User
```

### Installed Software Directories

{% code overflow="wrap" %}
```powershell
Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime
```
{% endcode %}

### Software in Registry

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
{% endcode %}

### Connected Drives

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class Win32_Share
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"};
```
{% endcode %}

### Firewall Config

```powershell
Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait
```

### Credential Manager

```cs
start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait
```

### Scan Process Creation Logs for AppData

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4688';}| ? {$_.Message -match 'appdata'}|FL TimeCreated, Message
```
{% endcode %}

***

### T1176 Browser Extensions

#### **Chrome**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -recurse -erroraction SilentlyContinue

Get-ChildItem -path 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions' -recurse -erroraction SilentlyContinue -include manifest.json | cat`*
```
{% endcode %}

#### **Firefox**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions" -recurse -erroraction SilentlyContinue

Get-ChildItem -path "C:\Program Files\Mozilla Firefox\plugins\" -recurse -erroraction SilentlyContinue

Get-ChildItem -path registry::HKLM\SOFTWARE\Mozilla\*\extensions
```
{% endcode %}

#### **Edge**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path C:\Users\*\AppData\Local\Packages\ -recurse -erroraction SilentlyContinue
```
{% endcode %}

#### **Internet Explorer**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path "C:\Program Files\Internet Explorer\Plugins\" -recurse -erroraction SilentlyContinue
```
{% endcode %}

### T1031 Modify Existing Service

{% code overflow="wrap" %}
```powershell
Get-ItemProperty REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\\ -ea 0 | where {($.ServiceDll -ne $null)} | foreach {filehash $.ServiceDll}
```
{% endcode %}

### T1050 New Service

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class win32_service | FL Name, DisplayName, PathName, State
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | FL TimeCreated,Message
```
{% endcode %}

### T1137 Office Application Startup

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path C:\Users\\Microsoft\\STARTUP\*.dotm
Get-ChildItem -path registry::HKLM\SOFTWARE\Microsoft\Office\*\Addins\*
Get-ChildItem -path registry::HKLM\SOFTWARE\Wow6432node\Microsoft\Office\*\Addins\*
Get-ChildItem -path registry::HKLM\SOFTWARE\Wow6432node\Microsoft\Office\*\Addins\*
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Microsoft\Templates\*" -erroraction SilentlyContinue
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Microsoft\Excel\XLSTART\*" -erroraction SilentlyContinue
Get-ChildItem -path C:\ -recurse -include Startup -ea 0*`

Get-WinEvent -FilterHashtable @{ LogName='Microsoft Office Alerts'; Id='300';} | FL TimeCreated,Message
```
{% endcode %}

### T1060 Registry Run Keys / Startup Folder

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Shell-Core/Operational'; Id='9707'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Shell-Core/Operational'; Id='9708'} | FL TimeCreated,Message
```
{% endcode %}

### T1053 Scheduled Task

{% code overflow="wrap" %}
```powershell
gci -path C:\windows\system32\tasks | Select-String Command | FT Line, Filename
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)} | Select-String Command | FL Filename,Line
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)} | where {$_.CreationTime.hour -ge (get-date).hour-2}| Select-String Command | FL Line,Filename
gci -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\'
gci -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\'
```
{% endcode %}

### T1019 System Firmware

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class win32_bios
```
{% endcode %}

### T1100 Web Shell

{% code overflow="wrap" %}
```powershell
gci -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "runat" | FL
gci -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "eval" | FL
```
{% endcode %}

### T1074 Data Staging

{% code overflow="wrap" %}
```powershell
gci C:\ProgramData\ -recurse -include .* -ea 0 -force | ?{ $_.PSIsContainer }
gci C:\Windows\Temp -recurse -ea 0 -force | ?{ $_.PSIsContainer }
```
{% endcode %}

***

### Query WMI Persistence

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class __FilterToConsumerBinding -Namespace root\subscription
Get-CimInstance -Class __EventFilter -Namespace root\subscription
Get-CimInstance -Class __EventConsumer -Namespace root\subscription
```
{% endcode %}

Review Software Keys for malicious entries

{% code overflow="wrap" %}
```powershell
gci registry::HKLM\Software\*
gci registry::HKU\*\Software\*
```
{% endcode %}

**Check system directories for executables not signed as part of an operating system releas**e

{% code overflow="wrap" %}
```powershell
gci C:\windows\\.exe -File -force |get-authenticodesignature|?{$_.IsOSBinary -notmatch 'True'}
```
{% endcode %}

**Determine if the user Trusted a doc/spreadsheet, etc and ran a macro**

{% code overflow="wrap" %}
```powershell
reg query 'HKU\[SID]\Software\Microsoft\Office\[versionnumber]\Word\Security\Trusted Documents\TrustRecords';
```
{% endcode %}

***

### Check Office Security Settings

{% code overflow="wrap" %}
```powershell
gci REGISTRY::HKU\*\Software\Microsoft\Office\*\*\Security -rec
gci REGISTRY::HKCU\Software\Microsoft\Office\*\*\Security -rec
```
{% endcode %}

### Check Outlook Temporary Files

{% code overflow="wrap" %}
```powershell
gci ((gp REGISTRY::HKU\*\Software\Microsoft\Office\[VerNumber]\Outlook\Security\ -ea 0).OutlookSecureTempFolder)
gci (((gp REGISTRY::HKU\*\Software\Microsoft\Office\*\Outlook\Security\ -ea 0)|select -exp OutlookSecureTempFolder -ea 0))
```
{% endcode %}

***

### Check MS Office Logs for High-Risk File Names

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='OAlerts';} |Where { $_.Message -Match 'invoice' }| FL TimeCreated, Message
```
{% endcode %}

**Determine if a user opened a document**

```cs
gci "REGISTRY::HKU\\Software\Microsoft\Office\\Word\Reading Locations\*"
```

**Find files without extensions**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path C:\Users\[user]\AppData -Recurse -Exclude . -File -Force -ea SilentlyContinue
```
{% endcode %}

**Obtain hash for all running executables**

{% code overflow="wrap" %}
```powershell
(gps|gi -ea SilentlyContinue|filehash).hash|sort -u
```
{% endcode %}

**Obtain hash and established network connections for running executables with DNS cache**

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection -State Established | Select RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(gps -Id $.OwningProcess).Path}},@{n="Hash";e={(gps -Id $.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $.RemoteAddress -ea 0).Entry}}|sort|gu -AS|FT
```
{% endcode %}

**Obtain hash and listening network connections for running executables**

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection -State LISTEN | Select LocalAddress, LocalPort, OwningProcess, @{n="Path";e={(gps -Id $.OwningProcess).Path}},@{n="Hash";e={(gps -Id $.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT
```
{% endcode %}

**Obtain hash and possible tunnelled network connections for running executables**

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection -State ESTABLISHED |? LocalAddress -Like "::1" | Select RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress).Entry}}|sort|gu -AS|FT
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection -State Established |? LocalAddress -Like "127.0.0.1"| Select RemoteAddress, RemotePort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}},@{n="DNSCache";e={(Get-DnsClientCache -Data $_.RemoteAddress).Entry}}|sort|gu -AS|FT
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection -State LISTEN |? LocalAddress -Like "127.0.0.1" | Select LocalAddress, LocalPort, OwningProcess, @{n="Path";e={(gps -Id $_.OwningProcess).Path}},@{n="Hash";e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n="User";e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT
```
{% endcode %}

### Obtain Workstation Name for Tunnelled Authentication

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='::';} | FL TimeCreated,Message
```
{% endcode %}

### Obtain Processes Where the Binary File Version Doesn’t Match the OS Release

{% code overflow="wrap" %}
```powershell
gps -FileVersionInfo -ea 0|? {$_.ProductVersion -notmatch $([System.Environment]::OSVersion.Version|Select -exp Build)}
```
{% endcode %}

### Obtain Process Binary File External Names

{% code overflow="wrap" %}
```powershell
gps -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | FL *name,*version
```
{% endcode %}

### Baseline Processes and Services

{% code overflow="wrap" %}
```powershell
Get-Process | Export-Clixml -Path C:\Users\User\Desktop\process.xml
Get-Service | Export-Clixml -Path C:\Users\User\Desktop\service.xml
$edproc = Import-Clixml -Path C:\Users\User\Desktop\process.xml
$edproc1 = Import-Clixml -Path C:\Users\User\Desktop\process1.xml
$edservice = Import-Clixml -Path C:\Users\User\Desktop\service.xml
$edservice1 = Import-Clixml -Path C:\Users\User\Desktop\service1.xml
Compare-Object $edproc $edproc1 -Property processname
Compare-Object $edservice $edservice1 -Property servicename
```
{% endcode %}

***

## Alternate Data Streams Discovery

#### Use Alternate Data Streams to find the download location

{% code overflow="wrap" %}
```powershell
get-item * -stream *|Where-Object {$_.Stream -ine ":`$DATA"}|cat
get-item C:\Users\Username\Downloads\* -stream *|Where-Object {$_.Stream -ine ":`$DATA"}|cat
$a=(gci -rec -path C:\users\user\downloads -ea 0 | gi -s Zone.Identifier -ea 0 | ? {$_.Length -ge '27'});foreach ($b in $a){$b.FileName;$b|cat}
$a=(get-item * -stream Zone.Identifier -ea 0 | ? {$_.Length -ge '27'});foreach ($b in $a){$b.FileName;$b|cat}

gci -Recurse -Path $env:APPDATA\..\ -include *.txt -ea SilentlyContinue |gi -s *| Where-Object {$_.Stream -ine ":`$DATA"}|cat
```
{% endcode %}

**List Alternate Data Streams in text files within AppData**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Recurse -Path $env:APPDATA\..\ -include *.txt -ea SilentlyContinue|gi -s *|Select Stream -ea SilentlyContinue| Where-Object {$_.Stream -ine ":`$DATA"}
```
{% endcode %}

**Programs Accessing Windows Features such as Webcam and Microphone**

{% code overflow="wrap" %}
```powershell
$a=$(gci REGISTRY::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\ -recurse | FT -AutoSize | Out-String);$a.replace("#","\")
```
{% endcode %}

**Programs Using Webcam**

{% code overflow="wrap" %}
```powershell
$a=$(gci REGISTRY::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam -recurse | Select PSChildName | Out-String);$a.replace("#","\")
```
{% endcode %}

#### Programs Using Microphone

{% code overflow="wrap" %}
```powershell
$a=$(gci REGISTRY::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone -recurse | Select PSChildName | Out-String);$a.replace("#","\")
```
{% endcode %}

***
