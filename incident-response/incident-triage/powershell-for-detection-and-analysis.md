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

## <mark style="color:blue;">Incident Identification</mark>

### <mark style="color:blue;">General Indicators Of Compromise</mark>

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

### <mark style="color:blue;">Internal Threat Indicators</mark>

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

### <mark style="color:blue;">Network Forensic Indicators</mark>

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

### <mark style="color:blue;">Suspicious Domain Indicators</mark>

```powershell
1. Domain registered date is recent
2. Domain registrant is anonymous or non-reputable
3. Domain shares similar characteristics with prior known bad
4. Domain has a suspicious email infrastructure
5. Domain has a suspicious website infrastructure
6. Domain has a disreputable history
7. Domain has suspicious IP addresses / DNS data
```

### <mark style="color:blue;">Azure & Office 365 Indicators</mark>

```powershell
1. Privileged account logon from foreign address
2. Creation of accounts in Azure AD
3. Traffic restrictions loosened on Virtual Network
4. Storage account accessed via stolen key from foreign address
5. Subscription Administrator added
6. Windows level intrusion of VM
7. High priority target's mailbox is accessed
```

### <mark style="color:blue;">Important event logs</mark>

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

## <mark style="color:blue;">Identify Notable Processes:</mark>

* **Monitor process behaviour:** Look for any unusual or suspicious activities, such as high CPU or memory usage, unexpected network traffic, or processes running from unfamiliar locations.
* **Check process file locations:** Verify the file locations of running processes. Legitimate Windows processes typically reside in specific system directories (e.g., C:\Windows\System32). If you find a process running from an unusual location, it could indicate malware.
* **Investigate process names:** Research the names of unfamiliar or suspicious processes.
* **Analyse process signatures:** Use tools like Process Explorer or Process Monitor to examine digital signatures of running processes. Legitimate processes often have valid digital signatures from reputable publishers, while unsigned or suspicious signatures can indicate potential malicious activity.
* **Monitor startup programs:** Regularly review the list of programs set to run at system startup. Use the "msconfig" utility or Task Manager's Startup tab to check for unfamiliar or suspicious entries. Malware often tries to persist by adding itself to startup programs.
* **Check for unusual network connections**: Use network monitoring tools to identify any abnormal network connections initiated by processes. Look for connections to suspicious IP addresses or domains that are known to be associated with malware or botnets.
* **Be cautious of system changes:** Be vigilant when new processes suddenly appear after installing software or visiting unknown websites. Malware may attempt to install additional processes or modify existing ones. Monitor your system for any unauthorized changes.

## <mark style="color:blue;">System Processes</mark>

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

## <mark style="color:blue;">User Processes</mark>

* **Explorer.exe** (Profile: Parent not shown, Path=C\Windows\System32, One for each logged-on user, Running underneath it should be user programs)
* **Iexplore.exe** (Profile: Parent is explorer.exe, Path="Program files\Internet Explorer" OR Path=Program files (x86), One for each logged-on user, Running underneath it should be user programs)

## <mark style="color:blue;">Malware or Compromised Investigation</mark>

### <mark style="color:blue;">**Possible Indicators of Compromise:**</mark>

```powershell
Unusual Activities:
Unusual Outbound Network Traffic (C2 activities)
Unusual DNS Requests
Unusual Processes
Unusual Ports
Unusual Services
Rogue Accounts
Anomalies in Privileged User Account Activity
```

```powershell
Unusual Files (Executables in Download or Temp directories may be suspicious)
Autostart Locations
Log-In Red Flags
Large Numbers of Requests for the Same File
Mismatched Port-Application Traffic
Suspicious Registry or System File Changes
```

### <mark style="color:blue;">**Identify Notable Processes:**</mark>

```powershell
Spelled Correctly
Correct parent child relationship
Running from correct directory?
Are they suppose to have children?
Is it a singleton?
```

### <mark style="color:blue;">Review Running Programs</mark>

{% code overflow="wrap" %}
```powershell
Get-CimInstance -ClassName win32_Product
Get-CimInstance -ClassName win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage

Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publishe

Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | where DisplayName -Like "*Edge*" | Select-object DisplayName, DisplayVersion, InstallDate, Publisher

Note: OR use exclusion:
Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | where DisplayName -NotLike "*Edge*" | Select-object DisplayName, DisplayVersion, InstallDate, Publisher

Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher

Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where DisplayName -Like "*Microsoft*" | Select-object DisplayName, DisplayVersion, InstallDate, Publisher

Note: OR use exclusion:
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where DisplayName -NotLike "*Microsoft*" | Select-object DisplayName, DisplayVersion, InstallDate, Published
```
{% endcode %}

### <mark style="color:blue;">Review Running Processes</mark>

{% code overflow="wrap" %}
```powershell
Get-Process
Get-CimInstance -Class win32_process|select ProcessName,ParentProcessId,ProcessId,CommandLine,ExecutablePath,InstallDate
Get-CimInstance -Class win32_process | where Name -NotLike "svchost.exe" |select ProcessName,ParentProcessId,ProcessId,CommandLine,ExecutablePath,InstallDate

Note: OR use exclusion:
Get-CimInstance -Class win32_process | where Name -NotLike "svchost.exe" |select ProcessName,ParentProcessId,ProcessId,CommandLine,ExecutablePath,InstallDate

Note: Search Specific Process:
Get-CimInstance -Class win32_process -Filter "name like '%powershell.exe'" | select processId,commandline|FL
Get-CimInstance -Class win32_process | select name,processId,path,commandline|FL

Note: View Process and Owners:
Get-CimInstance -Class win32_process |FL ProcessID,ParentProcessID,CommandLine,@{e={$_.GetOwner().User}}

Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

Get-CimInstance -Class win32_process | Sort-Object -Property ProcessID | FL ProcessID,Path,CommandLine,ParentProcessID,@{n="User";e={$_.GetOwner().User}},@{n="ParentProcessPath";e={gps -Id $_.ParentProcessID|Select -exp Path}}
```
{% endcode %}

### <mark style="color:blue;">Review Installed Services</mark>

{% code overflow="wrap" %}
```powershell
Get-Service | Sort-Object Status
get-service | where-object {$_.Status -eq 'Running'}

Note: Search Specific Service:
Get-Service "WMI"

Note: OR use exclusion:
Get-Service -Name "win*" -Exclude "WinRM"

Note: Service Status
Get-Service | Where-Object {$_.Status -eq "Running"}

Get-CimInstance -Class win32_service | select Name,ProcessId,Startmode,State,Status,DisplayName| ft -Autosize

Note: Stopping, starting, suspending, and restarting services
Stop-Service -Name spooler
start-Service -Name spooler
Suspend-Service -Name spooler
Restart-Service -Name spooler

Note: Get service on remote machine
get-service -computername Server64
Invoke-Command -ComputerName Server02 -ScriptBlock { Get-Service }
```
{% endcode %}

### <mark style="color:blue;">Review Recent Execution of Programs</mark>

{% code overflow="wrap" %}
```powershell
Get-ItemProperty "REGISTRY::HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
Get-ItemProperty "REGISTRY::HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
```
{% endcode %}

**If Malicious Process is Discovered (Get Malicious Process Details)**

We identified that the malware .exe process is executing, but we need to know the complete path to identify if it’s running from the temp directory.

{% code overflow="wrap" %}
```powershell
Get-Process malware.exe| Select-Object Id, ProcessName, Path, Company, StartTime | Format-Table

Get-CimInstance -Class win32_process -Filter "name like '%malware.exe'" | select processId,commandline|FL

Get-CimInstance -Class win32_process | where Name -NotLike "malware.exe" |select ProcessName,ParentProcessId,ProcessId,CommandLine,ExecutablePath,InstallDate
```
{% endcode %}

**Only applicable for Windows PowerShell 5.1**

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_Process -Filter "name='malware.exe'" | Select-Object ProcessId, ProcessName, CommandLine`
```
{% endcode %}

**But if Get-Wmiobject is deprecated use Get-CimInstance for PowerShell 7**

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class Win32_Process | Format-Table -Property ProcessId, ProcessName, CommandLine -Autosize
```
{% endcode %}

### <mark style="color:blue;">Check for files in $env:APPDATA\GUID\\</mark>

Malware, for example, NanoCore creates a unique GUID DIR in $env:APPDATA to keep it’s copy and logs. We can Get-ChildItem cmdlet to list the directory; it’s like DIR cmd. This cmdlet can be used in file system directory, registry hive, or a certificate store. Recurse – Used to recursive list all the sub-dir Filter – You can use the parameter to filter the path, and it supports \* and ? wildcards e.g. \*.dat, _.exe_

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path $Env:APPDATA -Force -Recurse -Filter run.dat
Instead of Get-ChildItem, we can Test-Path to check if the dir or file exists or not
Test-Path -Path $Env:APPDATA\*\run.dat
```
{% endcode %}

**Test-Path & Get-ChildItem PowerShell cmdlets**

After running the above cmds you will be able to know the unique GUID directory name 0319B08F-2B65-4192-B2D2-1E2F62087064, this folder contain other artifacts as shown in below screenshot\*

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path C:\Users\admin\AppData\Roaming\0319B08F-2B65-4192-B2D2-1E2F62087064\ -Force -Recurse
```
{% endcode %}

### <mark style="color:blue;">**Gather File hashes**</mark>

Get-FileHash cmdlet can be used to get the hash using a different algorithm e.g. MD5. SHA1 , SHA256 etc. By default, the Get-FileHash cmdlet uses the SHA256 algorithm, although any hash algorithm that is supported by the target operating system can be used. **SHA256**

{% code overflow="wrap" %}
```powershell
Get-FileHash -Path 'C:\Users\admin\AppData\Roaming\0319B08F-2B65-4192-B2D2-1E2F62087064\IMAP Service\imapsv.exe'
```
{% endcode %}

### <mark style="color:blue;">**MD5**</mark>

{% code overflow="wrap" %}
```powershell
Get-FileHash -Algorithm MD5 -Path 'C:\Users\admin\AppData\Roaming\0319B08F-2B65-4192-B2D2-1E2F62087064\IMAP Service\imapsv.exe'
```
{% endcode %}

**Copy artifacts for analysis** Before removing the artifacts, we may want to copy them for further analysis if needed by other teams. Let’s use the New-Item cmdlet to create the directory and use Copy-Item to copy the files to IoCs dir

{% code overflow="wrap" %}
```powershell
New-Item -ItemType Directory -Path C:\Users\admin\IoCs
Copy-Item C:\Users\admin\AppData\Roaming\0319B08F-2B65-4192-B2D2-1E2F62087064\ -Destination C:\Users\admin\IoCs\ -Recurse
```
{% endcode %}

### <mark style="color:blue;">Check Locates for Possible  Signs of Malware</mark>

{% code overflow="wrap" %}
```powershell
gci -path C:\Users\*\AppData\Roaming\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Roaming\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Roaming\*\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Roaming\*\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\*\Data -recurse -force -ea SilentlyContinue
gci -path C:\Users\*\AppData\Local\*\*\Modules -recurse -force -ea SilentlyContinue
gci -path C:\Windows\System32\config\systemprofile\appdata\roaming -recurse -force -include *.exe
```
{% endcode %}

## <mark style="color:blue;">Accounts and Groups</mark>

### <mark style="color:blue;">Local Groups</mark>

{% code overflow="wrap" %}
```powershell
Get-LocalGroup
Get-LocalGroup | ft Name
Get-LocalGroupMember Administrator
Get-ChildItem C:\Users | ft Name
```
{% endcode %}

### <mark style="color:blue;">Logged in Users</mark>

{% code overflow="wrap" %}
```powershell
Write-Host $env:UserDomain\$env:UserName;
Start-Process "qwinsta" -NoNewWindow -Wait
```
{% endcode %}

### <mark style="color:blue;">Local Users</mark>

{% code overflow="wrap" %}
```powershell
Get-LocalUser | ft Name,Enabled,LastLogon;
Get-LocalUser
Get-LocalUser | where Enabled -eq $True
```
{% endcode %}

### &#x20;<mark style="color:blue;">Local Administrators</mark>

{% code overflow="wrap" %}
```powershell
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
{% endcode %}

### <mark style="color:blue;">Domain Account - Users | Group | Computers</mark>

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter 'Name -Like "*"' | where Enabled -eq $True
Get-ADGroupMember Administrator | where objectClass -eq 'user'
Get-ADComputer -Filter "Name -Like '*'" -Properties * | where Enabled -eq $True | Select-Object Name, OperatingSystem, Enabled
```
{% endcode %}

### <mark style="color:blue;">List of IPV4 addresses who have connected (RDP)</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | select -exp Properties | where {$_.Value -like '...' } | sort Value -u
```
{% endcode %}

### <mark style="color:blue;">User Autologon Registry Items</mark>

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

### <mark style="color:blue;">Startup Commands for Certain Programs</mark>

```cs
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User
```

### <mark style="color:blue;">Installed Software Directories</mark>

{% code overflow="wrap" %}
```powershell
Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime
```
{% endcode %}

### <mark style="color:blue;">Software in Registry</mark>

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
{% endcode %}

### <mark style="color:blue;">Connected Drives</mark>

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class Win32_Share
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"};
```
{% endcode %}

### <mark style="color:blue;">Firewall Config</mark>

```powershell
Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait
```

### <mark style="color:blue;">Credential Manager</mark>

```cs
start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait
```

### <mark style="color:blue;">Scan Process Creation Logs for ‘AppData’</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4688';}| ? {$_.Message -match 'appdata'}|FL TimeCreated, Message
```
{% endcode %}

## <mark style="color:blue;">More Detail Checks and Analysis</mark>

### <mark style="color:blue;">T1176 Browser Extensions</mark>

**Chrome**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -recurse -erroraction SilentlyContinue

Get-ChildItem -path 'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions' -recurse -erroraction SilentlyContinue -include manifest.json | cat`*
```
{% endcode %}

**Firefox**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions" -recurse -erroraction SilentlyContinue

Get-ChildItem -path "C:\Program Files\Mozilla Firefox\plugins\" -recurse -erroraction SilentlyContinue

Get-ChildItem -path registry::HKLM\SOFTWARE\Mozilla\*\extensions
```
{% endcode %}

**Edge**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path C:\Users\*\AppData\Local\Packages\ -recurse -erroraction SilentlyContinue
```
{% endcode %}

**Internet Explorer**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -path "C:\Program Files\Internet Explorer\Plugins\" -recurse -erroraction SilentlyContinue
```
{% endcode %}

### <mark style="color:blue;">T1031 Modify Existing Service</mark>

{% code overflow="wrap" %}
```powershell
Get-ItemProperty REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\\ -ea 0 | where {($.ServiceDll -ne $null)} | foreach {filehash $.ServiceDll}
```
{% endcode %}

### <mark style="color:blue;">T1050 New Service</mark>

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class win32_service | FL Name, DisplayName, PathName, State
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">T1137 Office Application Startup</mark>

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

### <mark style="color:blue;">T1060 Registry Run Keys / Startup Folder</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Shell-Core/Operational'; Id='9707'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Shell-Core/Operational'; Id='9708'} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">T1053 Scheduled Task</mark>

{% code overflow="wrap" %}
```powershell
gci -path C:\windows\system32\tasks | Select-String Command | FT Line, Filename
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)} | Select-String Command | FL Filename,Line
gci -path C:\windows\system32\tasks -recurse | where {$_.CreationTime -ge (get-date).addDays(-1)} | where {$_.CreationTime.hour -ge (get-date).hour-2}| Select-String Command | FL Line,Filename
gci -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\'
gci -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\'
```
{% endcode %}

### <mark style="color:blue;">T1019 System Firmware</mark>

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class win32_bios
```
{% endcode %}

### <mark style="color:blue;">T1100 Web Shell</mark>

{% code overflow="wrap" %}
```powershell
gci -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "runat" | FL
gci -path "C:\inetpub\wwwroot" -recurse -File -ea SilentlyContinue | Select-String -Pattern "eval" | FL
```
{% endcode %}

### <mark style="color:blue;">T1074 Data Staging</mark>

{% code overflow="wrap" %}
```powershell
gci C:\ProgramData\ -recurse -include .* -ea 0 -force | ?{ $_.PSIsContainer }
gci C:\Windows\Temp -recurse -ea 0 -force | ?{ $_.PSIsContainer }
```
{% endcode %}

### <mark style="color:blue;">Query WMI Persistence</mark>

{% code overflow="wrap" %}
```powershell
Get-CimInstance -Class __FilterToConsumerBinding -Namespace root\subscription
Get-CimInstance -Class __EventFilter -Namespace root\subscription
Get-CimInstance -Class __EventConsumer -Namespace root\subscription
```
{% endcode %}

#### Review Software Keys for malicious entries

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

**Determine if user Trusted a doc/spreadsheet etc and ran a macro**

{% code overflow="wrap" %}
```powershell
reg query 'HKU\[SID]\Software\Microsoft\Office\[versionnumber]\Word\Security\Trusted Documents\TrustRecords';
```
{% endcode %}

### <mark style="color:blue;">Check Office Security Settings</mark>

{% code overflow="wrap" %}
```powershell
gci REGISTRY::HKU\*\Software\Microsoft\Office\*\*\Security -rec
gci REGISTRY::HKCU\Software\Microsoft\Office\*\*\Security -rec
```
{% endcode %}

### <mark style="color:blue;">Check Outlook Temporary Files</mark>

{% code overflow="wrap" %}
```powershell
gci ((gp REGISTRY::HKU\*\Software\Microsoft\Office\[VerNumber]\Outlook\Security\ -ea 0).OutlookSecureTempFolder)
gci (((gp REGISTRY::HKU\*\Software\Microsoft\Office\*\Outlook\Security\ -ea 0)|select -exp OutlookSecureTempFolder -ea 0))
```
{% endcode %}

### \*Check MS Office Logs for high risk file names

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

**Obtain hash and established network connections for running executables with dns cache**

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

### <mark style="color:blue;">Obtain workstation name for tunneled authentication</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='::';} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">Obtain processes where binaries file version doesn’t match OS Release</mark>

{% code overflow="wrap" %}
```powershell
gps -FileVersionInfo -ea 0|? {$_.ProductVersion -notmatch $([System.Environment]::OSVersion.Version|Select -exp Build)}
```
{% endcode %}

### <mark style="color:blue;">Obtain process binary file external names</mark>

{% code overflow="wrap" %}
```powershell
gps -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | Select OriginalFilename,InternalName,Filename
gps -module -FileVersionInfo -ea 0 | sort -uniq | FL *name,*version
```
{% endcode %}

### <mark style="color:blue;">Baseline processes and services</mark>

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

## <mark style="color:blue;">Lateral Movement Discovery</mark>

{% code overflow="wrap" %}
```powershell
Scheduled Tasks Lateral Movement Detection (Destinations)
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4698';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4702';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4699';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4700';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4701';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='106';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='140';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='141';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='200';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='201';} | FL TimeCreated,Message*`

Get-ChildItem -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\' | Get-ItemProperty | FL Path, Actions

gci -path C:\Windows\System32\Tasks\ -recurse -File
```
{% endcode %}

### <mark style="color:blue;">PsExec Lateral Movement Detection (Destinations)</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='2'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\ADMIN$'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'; Data='PSEXESVC'} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">Services Lateral Movement Detection (Destinations)</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4697';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7034';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7035';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7036';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7040';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">Map Network Shares Lateral Movement Detection (Destinations)</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4776';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4768';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4769';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\C$'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5145';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140';} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">WMI/WMIC Lateral Movement Detection (Destinations)</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5857';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5860';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5861';} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">PowerShell Lateral Movement Detection (Destinations)</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4103';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4104';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='53504';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='400';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='403';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='91';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='168';} | FL TimeCreated,Message
```
{% endcode %}

### <mark style="color:blue;">Remote Desktop Lateral Movement Detection (Destinations)</mark>

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='10'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4778';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4779';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id='98';} | FL Message,ProcessId,TimeCreated
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id='131';} | FL Message,ProcessId,TimeCreated
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='21';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='22';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='25';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='41';} | FL TimeCreated,Message
```
{% endcode %}

## <mark style="color:blue;">Delete Malware Artifacts</mark>

### <mark style="color:blue;">Terminate Malicious Process</mark>

Stop-Process can be used to terminate processes based on process name or process ID (PID), or pass a process object.

{% code overflow="wrap" %}
```powershell
Get-Process RAVBg64 | Stop-Process
```
{% endcode %}

You may need to stop this process imapsv.exe instead of RAVBg64.exe, if the machine has already restarted as this filename is used in registry for persistence.

### <mark style="color:blue;">Remove Persistence</mark>

**Get-ItemProperty cmdlet can be used for listing registry entries as shown below:**

{% code overflow="wrap" %}
```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'IMAP Service'`*
```
{% endcode %}

**Remove-ItemProperty can be used for removing malware related persistence registry entry**

{% code overflow="wrap" %}
```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Remove-ItemProperty -Name 'IMAP Service' Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'*`
```
{% endcode %}

We have already removed the persistence mechanism, now we just need to delete the files from the infected machine using Remove-Item cmdlet. Delete the complete dir recursively

{% code overflow="wrap" fullWidth="false" %}
```powershell
Remove-Item -Path $env:APPDATA\0319B08F-2B65-4192-B2D2-1E2F62087064\ -Recurse -Force
```
{% endcode %}

#### Remove the copy of the malware

```powershell
Remove-Item -Path $env:TEMP\malware.exe -Force
```

#### Delete the initial file

```powershell
Remove-Item -Path $env:USERPROFILE\Desktop\Serial.exe
```

#### Remediate malicious files

```powershell
Remove-Item [C:\Users\Public\*.exe]
Remove-Item -Path [C:\Users\Public\malware.exe] -Force
Get-ChildItem * -Include *.exe -Recurse | Remove-Item
```

## <mark style="color:blue;">Alternate Data Streams Discovery</mark>

#### <mark style="color:blue;">Use Alternate Data Streams to find the download location</mark>

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

## <mark style="color:blue;">Native Windows Approach</mark>

### <mark style="color:blue;">Check for Unusual Accounts</mark>

Look for unusual accounts created, especially in the Administrators group:

* C:> lusrmgr.msc List users:
* C:> net user List members of the Admin group:
* C:> net localgroup administrators&#x20;

### <mark style="color:blue;">Check For Unusual Files</mark>

Look for unusually big files bigger than 5MB. This can be an indication of a system compromised for illegal content storage. Look for unusual files added recently in system folders, especially C:\WINDOWS\system32. Use WinDirStat to show disk usage statistics: [**https://windirstat.net/**](https://windirstat.net/). Look for files using the “hidden” attribute in all subfolders:

* C:> _dir_ _/S_ _/A:H_  Look for files larger than 10 MG
* FOR /R C:\ %i in (\*) do @if %\~zi gtr 10000000 echo %i %\~zi GUI on Win10: open Explorer  and in the search box enter: size:>10M

### <mark style="color:blue;">Check For Unusual Processes</mark>

Check all running processes for unusual/unknown entries, especially processes with username “SYSTEM”  and “ADMINISTRATOR”:

* C:> _taskmgr.exe_ (or tlisk, tasklist depending on Windows release)
* Use Sysinternals Process Explorer (psexplorer) if possible.

From the commandline:

* C:>  tasklist
* C:>  wmic process list full To get parent process ID info
* C:> wmic process get name, parentprocessid, processid Get commandline options and DLLs
* C:> tasklist /m /fi "pid eq \[pip]"
* C:>  wmic process where processid=\[pid] get commandline

Beware of Base64 endings $input = “StringToBeDecoded” $output = \[System.Text.Encoding]::Unicode.GetString(\[System.Convert]::FromBase64String($input)) $output

Use Base64 decoding tools online

* [https://www.base64decode.org/](https://www.base64decode.org/)

### <mark style="color:blue;">Check for Unusual Network Services</mark>

Look for unusual/unexpected network services installed and started:

* C:> _services.msc_
* C:> _net start_&#x20;
* C:> sc query | more
* C:>  tasklist /svc

### <mark style="color:blue;">Check for Unusual Network Activity</mark>

Check for file shares and verify each one is linked to a normal activity:

* C:> _net view \\_[_127.0.0.1_](http://127.0.0.1)
* Use SysInternals TCPView (tcpview) if possible.

Look at the opened sessions on the machine:

* C:> _net session_ Look at the sessions the machine has opened with other systems:
* C:> _net use_ Look for any suspicious Netbios connections:
* C:> _nbtstat –S_ Look for any suspicious activity on the system’s ports:
* C:> _netstat –na 5_ (5 makes it refresh every 5 seconds)

### <mark style="color:blue;">Check Startup Folders</mark>

Look for unusual startup programs for all users (path depends on Windows release): For GUI access: Open the WinX Menu

* Select Run to open the Run box
* Type shell:startup and hit Enter to open the Current Users Startup folder
* Type shell:common startup and hit Enter to open the All Users Startup folder.
* dir "C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
* C:> wmic startup list full

### <mark style="color:blue;">Check for Unusual Registry Entries</mark>

Look for unusual programs launched at boot time in the Windows registry:

* HKLM\Software\Microsoft\Windows\CurrentVersion\Run
* HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce
* HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx&#x20;

Inspect both HKLM and HKCU , can be analyzed with the regedit GUI The Autoruns utility can be used pulling Auto Start Entry Points(ASEs) Or, the reg command at the command line can also be used to query the values of these settings

* C:> reg query hklm\software\microsoft\windows\currentversion\run

### <mark style="color:blue;">Check for Unusual Automated Tasks</mark>

Look at the list of scheduled tasks for any unusual entries:

* C:> schtasks

#### Check for Unusual Log Entries

Use Event Viewer locally on the system: C:> _eventvwr.msc_

* Look for suspicious events:
* Event log service was stopped
* Windows File Protection is not active on this system
* The MS Telnet Service has started successfully
* Look for a large number of failed logon attempts or locked-out accounts

Via the command prompt, on some versions of Windows, an admin can inspect logs with

* C:> wevtutil qe security /f:text
* Search for events affecting the firewall, the anti-virus, the file protection, or any suspicious new service.
* Look for a huge amount of failed login attempts or locked-out accounts.

If you are using Splunk, Search for “index=<_index-of-your-Windows-Event Logs_> **XXXX**” Some Windows Event IDs to look for (depending on your OS):

* **64004** - Windows File Protection warning event.
* **4688** - New process created. Look for unusual processes or wrong names (spelling is off, lowercase drive letters, extra spaces).
* **1001** - Application crash. Look for buffer overflow as the cause.
* **64697** - Created and installed a new service.
* **4698** - Created a new scheduled task.
* **4657** - Modify registry key for service to start at boot.
* **7034, 7035, 7036, 7040** - Virus protection mechanism changes.
