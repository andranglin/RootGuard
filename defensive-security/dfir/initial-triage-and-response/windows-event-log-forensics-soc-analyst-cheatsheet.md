# Windows Event Log Forensics - SOC Analyst Cheatsheet

### Practical Guide for Event Log Analysis & Threat Hunting

***

### Quick Reference: Critical Event IDs by Investigation Type

| Investigation Type       | Critical Event IDs              | Log Source                       | What They Reveal                         |
| ------------------------ | ------------------------------- | -------------------------------- | ---------------------------------------- |
| **Account Compromise**   | 4624, 4625, 4648, 4672          | Security                         | Logon success/fail, privilege escalation |
| **Lateral Movement**     | 4624 (Type 3), 4648, 5140, 7045 | Security, System                 | Remote logons, service creation          |
| **RDP Activity**         | 4624 (Type 10), 1149, 21/24/25  | Security, RDP logs               | Remote desktop sessions                  |
| **Persistence**          | 7045, 4697, 4698, 106/140/200   | System, Security, Task Scheduler | Service/task creation                    |
| **Privilege Escalation** | 4672, 4728, 4732, 4756          | Security                         | Admin rights, group changes              |
| **Credential Dumping**   | 4688, 4656, 5140                | Security                         | Process creation, object access          |
| **PowerShell Abuse**     | 4104, 4103, 400/403             | PowerShell logs                  | Script execution                         |
| **Evidence Destruction** | 1102, 104                       | Security, System                 | Log clearing                             |

***

### Investigation Priority Matrix

| Priority     | Event ID | Log      | Description                      | Investigation Use                    |
| ------------ | -------- | -------- | -------------------------------- | ------------------------------------ |
| **CRITICAL** | 4624     | Security | Successful logon                 | Account compromise, lateral movement |
| **CRITICAL** | 4625     | Security | Failed logon                     | Brute force, reconnaissance          |
| **CRITICAL** | 4672     | Security | Admin privileges assigned        | Privilege escalation                 |
| **CRITICAL** | 7045     | System   | Service installed                | Persistence mechanism                |
| **CRITICAL** | 4688     | Security | Process creation                 | Execution timeline                   |
| **HIGH**     | 4648     | Security | Explicit credentials             | Pass-the-hash, runas                 |
| **HIGH**     | 4697     | Security | Service installed (Security log) | Persistence validation               |
| **HIGH**     | 4698     | Security | Scheduled task created           | Persistence mechanism                |
| **HIGH**     | 1102     | Security | Event log cleared                | Anti-forensics                       |

***

### Core Investigation Questions

#### Primary Questions:

1. **Who logged in?** (4624 - Account identification)
2. **From where?** (Logon Type + Source IP)
3. **What did they do?** (4688 - Process execution)
4. **How did they move laterally?** (4624 Type 3, 7045, 5140)
5. **What persistence was created?** (7045, 4697, 4698)

***

### SOC Investigation Workflows

#### Workflow 1: Account Compromise Investigation (CRITICAL)

**Scenario:** Suspected compromised user account

**Investigation Priority Order:**

**Step 1: Identify Successful Logons (4624)**

**Event ID 4624 - Successful Logon**

**Critical Fields:**

* `SubjectUserName` - Who initiated the logon
* `TargetUserName` - Account that logged in
* `LogonType` - How they logged in
* `IpAddress` / `WorkstationName` - Source location
* `LogonProcessName` - Process used for logon
* `TimeCreated` - When

**Logon Types (MEMORIZE):**

```bash
Type 2  - Interactive (Console)
Type 3  - Network (Lateral Movement, File Shares)
Type 4  - Batch (Scheduled Tasks)
Type 5  - Service
Type 7  - Unlock
Type 8  - NetworkCleartext (Plaintext passwords!)
Type 9  - NewCredentials (RunAs)
Type 10 - RemoteInteractive (RDP)
Type 11 - CachedInteractive
Type 12 - CachedRemoteInteractive (RDP with cached creds)
```

**PowerShell - Find Logons:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Parse Security.evtx for logon events
#>

param(
    [string]$EventLog = "C:\Windows\System32\winevt\Logs\Security.evtx",
    [int]$Hours = 24
)

$startTime = (Get-Date).AddHours(-$Hours)

Write-Host "[+] Searching for logon events in last $Hours hours..." -ForegroundColor Cyan

# Parse Security log for 4624 events
$logons = Get-WinEvent -Path $EventLog -FilterXPath "*[System[(EventID=4624) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($logons) {
    Write-Host "[*] Found $($logons.Count) logon events" -ForegroundColor Yellow
    
    $logons | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        [PSCustomObject]@{
            Time = $_.TimeCreated
            EventID = $_.Id
            TargetUser = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            LogonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
            SourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
            Workstation = ($eventData | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
            LogonProcess = ($eventData | Where-Object {$_.Name -eq 'LogonProcessName'}).'#text'
        }
    } | Sort-Object Time -Descending | Format-Table -AutoSize
} else {
    Write-Host "[!] No logon events found" -ForegroundColor Red
}
```
{% endcode %}

**Red Flags in 4624:**

* ✗ **Type 10 (RDP)** from unusual IP addresses
* ✗ **Type 3 (Network)** indicating lateral movement
* ✗ **Type 8 (NetworkCleartext)** - plaintext password logon
* ✗ **Logons outside business hours**
* ✗ **Logons from unusual workstations**
* ✗ **Service accounts with Type 10 (RDP)**

***

**Step 2: Check for Failed Logon Attempts (4625)**

**Event ID 4625 - Failed Logon**

**Critical Fields:**

* `TargetUserName` - Account targeted
* `FailureReason` - Why it failed
* `IpAddress` / `WorkstationName` - Attack source
* `LogonType` - Attack method

**Common Failure Reasons:**

```bash
0xC000006D - Bad username or password (most common)
0xC000006E - Account restriction
0xC0000064 - Account does not exist
0xC000006F - Logon outside allowed time
0xC0000070 - Workstation restriction
0xC0000071 - Password expired
0xC0000072 - Account disabled
0xC0000193 - Account expired
0xC0000224 - Password must be changed
0xC0000234 - Account locked out
```

**PowerShell - Detect Brute Force:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Detect brute force attempts (multiple 4625 events)
#>

param(
    [string]$EventLog = "C:\Windows\System32\winevt\Logs\Security.evtx",
    [int]$Threshold = 5,  # Failed attempts to consider suspicious
    [int]$Hours = 24
)

$startTime = (Get-Date).AddHours(-$Hours)

Write-Host "[+] Detecting brute force attempts (threshold: $Threshold failed logons)..." -ForegroundColor Cyan

$failedLogons = Get-WinEvent -Path $EventLog -FilterXPath "*[System[(EventID=4625) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($failedLogons) {
    $analysis = $failedLogons | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        [PSCustomObject]@{
            Time = $_.TimeCreated
            TargetUser = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            SourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
            LogonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
            FailureReason = ($eventData | Where-Object {$_.Name -eq 'Status'}).'#text'
        }
    }
    
    # Group by user and source
    $bruteForce = $analysis | Group-Object TargetUser, SourceIP | Where-Object {$_.Count -ge $Threshold}
    
    if ($bruteForce) {
        Write-Host "`n[!] POTENTIAL BRUTE FORCE DETECTED:" -ForegroundColor Red
        
        foreach ($attack in $bruteForce) {
            $user = $attack.Group[0].TargetUser
            $ip = $attack.Group[0].SourceIP
            Write-Host "`n  Target: $user" -ForegroundColor Yellow
            Write-Host "  Source IP: $ip" -ForegroundColor Yellow
            Write-Host "  Failed Attempts: $($attack.Count)" -ForegroundColor Red
            Write-Host "  Time Range: $($attack.Group[0].Time) to $($attack.Group[-1].Time)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[+] No brute force patterns detected" -ForegroundColor Green
    }
} else {
    Write-Host "[!] No failed logon events found" -ForegroundColor Gray
}
```
{% endcode %}

**Red Flags in 4625:**

* ✗ **Multiple failures** followed by success (brute force)
* ✗ **High volume** from single IP (>10 failures)
* ✗ **Failed admin accounts** (Administrator, admin, etc.)
* ✗ **0xC000006D** repeated (password guessing)
* ✗ **Multiple usernames** from same IP (spray attack)

***

**Step 3: Check for Privilege Escalation (4672)**

**Event ID 4672 - Special Privileges Assigned**

**Indicates:** Account logged on with administrator-level privileges

**Critical Fields:**

* `SubjectUserName` - Account that gained privileges
* `PrivilegeList` - Specific privileges granted

**Important Privileges:**

```bash
SeDebugPrivilege          - Debug programs (used by Mimikatz!)
SeBackupPrivilege         - Backup files
SeRestorePrivilege        - Restore files
SeTakeOwnershipPrivilege  - Take ownership
SeLoadDriverPrivilege     - Load kernel drivers
```

**PowerShell - Find Privilege Escalation:**

{% code overflow="wrap" %}
```powershell
# Find 4672 events for non-SYSTEM accounts
$privEvents = Get-WinEvent -Path $EventLog -FilterXPath "*[System[EventID=4672]]" -MaxEvents 100 -ErrorAction SilentlyContinue

$privEvents | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $user = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
    
    # Filter out normal SYSTEM events
    if ($user -ne "SYSTEM" -and $user -ne "$env:COMPUTERNAME$") {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = $user
            Privileges = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'PrivilegeList'}).'#text'
        }
    }
} | Format-Table -AutoSize
```
{% endcode %}

**Red Flags in 4672:**

* ✗ **Non-admin users** with 4672 events
* ✗ **SeDebugPrivilege** (credential dumping indicator)
* ✗ **Service accounts** with admin privileges
* ✗ **Shortly after 4624** (privilege escalation after logon)

***

**Step 4: Identify Explicit Credentials (4648)**

**Event ID 4648 - Logon with Explicit Credentials**

**Indicates:**

* `runas` command used
* Pass-the-hash attack
* Credential theft/reuse

**Critical Fields:**

* `SubjectUserName` - Who initiated the action
* `TargetUserName` - Credentials used
* `TargetServerName` - Target system
* `ProcessName` - Process used (often runas.exe)

**Red Flags in 4648:**

* ✗ **Different user credentials** than current session
* ✗ **Admin credentials** used by standard user
* ✗ **Multiple 4648 events** in short time (credential testing)
* ✗ **Non-runas.exe process** (potentially malicious)

***

#### EvtxECmd Usage (Zimmerman Tool) - CRITICAL

**Location:**

```bash
C:\Windows\System32\winevt\Logs\*.evtx
```

**Collection:**

```powershell
# Collect all event logs
$output = "C:\Cases\EventLogs"
Copy-Item "C:\Windows\System32\winevt\Logs\*.evtx" $output -Force
```

**Parsing with EvtxECmd:**

**Basic Directory Parse:**

```cmd
REM Parse all event logs in directory
EvtxECmd.exe -d "C:\Cases\EventLogs" --csv "C:\Cases\Output" --csvf all_events.csv
```

**Filter Specific Event IDs (RECOMMENDED):**

{% code overflow="wrap" %}
```cmd
REM Parse only critical security events
EvtxECmd.exe -d "C:\Cases\EventLogs" --csv "C:\Cases\Output" --csvf security.csv --inc 4624,4625,4648,4672,4688,4697,4698,1102

REM Parse lateral movement events
EvtxECmd.exe -d "C:\Cases\EventLogs" --csv "C:\Cases\Output" --csvf lateral_movement.csv --inc 4624,4648,5140,7045

REM Parse RDP events
EvtxECmd.exe -d "C:\Cases\EventLogs" --csv "C:\Cases\Output" --csvf rdp.csv --inc 4624,1149,21,24,25,131

REM Parse persistence events
EvtxECmd.exe -d "C:\Cases\EventLogs" --csv "C:\Cases\Output" --csvf persistence.csv --inc 7045,4697,4698,106,140,200,201
```
{% endcode %}

**Exclude Noisy Events:**

{% code overflow="wrap" %}
```cmd
REM Exclude object access events (very noisy)
EvtxECmd.exe -d "C:\Cases\EventLogs" --csv "C:\Cases\Output" --csvf events.csv --exc 4656,4658,4660,4663
```
{% endcode %}

**Parse with Maps (Normalised Output):**

```cmd
REM EvtxECmd uses built-in "maps" to normalise output
REM Events with maps get consistent, readable output
REM Events without maps are still parsed but format varies

EvtxECmd.exe -d "C:\Cases\EventLogs" --csv "C:\Cases\Output" --csvf normalized.csv
```

**Key EvtxECmd Output Columns:**

* `TimeCreated` - Event timestamp
* `Computer` - System name
* `EventId` - Event ID
* `Level` - Severity
* `Provider` - Log source
* `Channel` - Log file
* `UserId` - User SID
* `MapDescription` - Readable event description
* `PayloadData1-6` - Event-specific data

***

#### Workflow 2: Lateral Movement Detection (HIGH PRIORITY)

**Scenario:** Detect attacker moving between systems

**Key Event Correlation:**

**Lateral Movement Pattern:**

```bash
Source System:
1. 4648 - Explicit credentials used (optional)
2. 4688 - Process execution (PsExec, WMI, etc.)
3. 3 (Sysmon) - Network connection

Destination System:
4. 4624 (Type 3) - Network logon
5. 4672 - Admin privileges assigned
6. 7045 - Service installed (if using PsExec/services)
7. 5140 - Share accessed (if using file shares)
8. 4688 - Process execution on target
```

**PsExec Lateral Movement:**

**Source System Indicators:**

```bash
Event 4648 - Explicit credentials
Event 4688 - psexec.exe execution
Prefetch - PSEXEC.EXE-*.pf
```

**Destination System Indicators:**

```bash
Event 4624 (Type 3) - Network logon
Event 4672 - Admin privileges
Event 7045 - Service "PSEXESVC" created
Event 5140 - ADMIN$ share accessed
Event 4688 - PSEXESVC.EXE execution
Prefetch - PSEXESVC.EXE-*.pf
```

**PowerShell - Detect PsExec:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Detect PsExec usage via event logs
#>

Write-Host "[+] Detecting PsExec Activity..." -ForegroundColor Cyan

# Check System log for PSEXESVC service
$systemLog = "C:\Windows\System32\winevt\Logs\System.evtx"
$psexecService = Get-WinEvent -Path $systemLog -FilterXPath "*[System[EventID=7045] and EventData[Data[@Name='ServiceName']='PSEXESVC']]" -ErrorAction SilentlyContinue

if ($psexecService) {
    Write-Host "`n[!] PSEXEC SERVICE DETECTED:" -ForegroundColor Red
    
    $psexecService | ForEach-Object {
        $xml = [xml]$_.ToXml()
        Write-Host "  Time: $($_.TimeCreated)" -ForegroundColor Yellow
        Write-Host "  Service: PSEXESVC" -ForegroundColor Red
        Write-Host "  Image Path: $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImagePath'}).'#text')" -ForegroundColor Yellow
    }
}

# Check Security log for related network logons
$securityLog = "C:\Windows\System32\winevt\Logs\Security.evtx"

# Find network logons around the time of PSEXESVC service
if ($psexecService) {
    $serviceTime = $psexecService[0].TimeCreated
    $timeWindow = New-TimeSpan -Minutes 5
    
    $networkLogons = Get-WinEvent -Path $securityLog -FilterXPath "*[System[(EventID=4624) and TimeCreated[@SystemTime>='$($serviceTime.AddMinutes(-5).ToUniversalTime().ToString('o'))' and @SystemTime<='$($serviceTime.AddMinutes(5).ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue
    
    if ($networkLogons) {
        Write-Host "`n[*] Network Logons Near PsExec Execution:" -ForegroundColor Yellow
        
        $networkLogons | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $logonType = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
            
            if ($logonType -eq '3') {  # Network logon
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    User = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    SourceIP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
                    Workstation = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
                }
            }
        } | Format-Table -AutoSize
    }
}
```
{% endcode %}

***

**WMI Lateral Movement:**

**Source System Indicators:**

```bash
Event 4688 - wmic.exe execution
Event 5857 - WMI activity detected
Event 5861 - WMI subscription activity
```

**Destination System Indicators:**

```bash
Event 4624 (Type 3) - Network logon
Event 4672 - Admin privileges
Event 4688 - wmiprvse.exe execution
Event 5857/5860/5861 - WMI activity
```

***

**RDP Lateral Movement:**

**Source System Indicators:**

```bash
Event 4648 - Explicit credentials (optional)
Event 4688 - mstsc.exe execution
Prefetch - MSTSC.EXE-*.pf
Jump List - RDP connections (destinations)
```

**Destination System Indicators:**

```bash
Event 4624 (Type 10) - RDP logon
Event 1149 - RDP authentication success
Event 21 - RDP session logon
Event 131 - RDP connection established
Prefetch - rdpclip.exe, tstheme.exe
```

***

#### Workflow 3: Persistence Detection

**Scenario:** Identify persistence mechanisms

**Key Events:**

**Service Creation:**

**Event 7045 - Service Installed (System Log)**

**Critical Fields:**

* `ServiceName` - Name of service
* `ImagePath` - Executable path
* `ServiceType` - Service type
* `StartType` - Auto-start configuration
* `AccountName` - Service account

**Event 4697 - Service Installed (Security Log)**

* Same as 7045 but in Security log (requires auditing enabled)

**PowerShell - Find Suspicious Services:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Detect suspicious service creation
#>

param(
    [string]$SystemLog = "C:\Windows\System32\winevt\Logs\System.evtx",
    [int]$Days = 7
)

$startTime = (Get-Date).AddDays(-$Days)

Write-Host "[+] Searching for service creation events..." -ForegroundColor Cyan

$services = Get-WinEvent -Path $SystemLog -FilterXPath "*[System[(EventID=7045) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($services) {
    Write-Host "[*] Found $($services.Count) service creation events" -ForegroundColor Yellow
    
    $analysis = $services | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        $serviceName = ($eventData | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
        $imagePath = ($eventData | Where-Object {$_.Name -eq 'ImagePath'}).'#text'
        $serviceType = ($eventData | Where-Object {$_.Name -eq 'ServiceType'}).'#text'
        $startType = ($eventData | Where-Object {$_.Name -eq 'StartType'}).'#text'
        
        [PSCustomObject]@{
            Time = $_.TimeCreated
            ServiceName = $serviceName
            ImagePath = $imagePath
            ServiceType = $serviceType
            StartType = $startType
        }
    }
    
    # Identify suspicious patterns
    $suspicious = $analysis | Where-Object {
        $_.ImagePath -like "*\Temp\*" -or
        $_.ImagePath -like "*\AppData\*" -or
        $_.ImagePath -like "*\Users\Public\*" -or
        $_.ImagePath -match "powershell" -or
        $_.ImagePath -match "cmd.exe" -or
        $_.ServiceName -eq "PSEXESVC"
    }
    
    if ($suspicious) {
        Write-Host "`n[!] SUSPICIOUS SERVICES DETECTED:" -ForegroundColor Red
        $suspicious | Format-Table -AutoSize
    }
    
    Write-Host "`n[*] All Service Creations:" -ForegroundColor Yellow
    $analysis | Format-Table -AutoSize
}
```
{% endcode %}

**Red Flags in 7045/4697:**

* ✗ **Image path in temp directories**
* ✗ **PowerShell/cmd.exe as service**
* ✗ **Random service names**
* ✗ **PSEXESVC** (PsExec)
* ✗ **Auto-start** configuration

***

**Scheduled Task Creation:**

**Event 4698 - Scheduled Task Created (Security)** **Event 106 - Scheduled Task Created (Task Scheduler/Operational)** **Event 140 - Scheduled Task Updated (Task Scheduler/Operational)** **Event 200 - Scheduled Task Executed (Task Scheduler/Operational)**

**PowerShell - Find Scheduled Tasks:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Detect scheduled task creation
#>

param(
    [string]$SecurityLog = "C:\Windows\System32\winevt\Logs\Security.evtx",
    [int]$Days = 7
)

$startTime = (Get-Date).AddDays(-$Days)

Write-Host "[+] Searching for scheduled task creation..." -ForegroundColor Cyan

$tasks = Get-WinEvent -Path $SecurityLog -FilterXPath "*[System[(EventID=4698) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($tasks) {
    Write-Host "[*] Found $($tasks.Count) task creation events" -ForegroundColor Yellow
    
    $tasks | ForEach-Object {
        $xml = [xml]$_.ToXml()
        
        Write-Host "`n--- Task Created: $($_.TimeCreated) ---" -ForegroundColor Yellow
        Write-Host "Creator: $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text')" -ForegroundColor Cyan
        Write-Host "Task Name: $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TaskName'}).'#text')" -ForegroundColor Cyan
        
        # Parse XML task content
        $taskContent = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TaskContent'}).'#text'
        if ($taskContent) {
            Write-Host "Task Content:" -ForegroundColor Yellow
            Write-Host $taskContent -ForegroundColor Gray
        }
    }
}
```
{% endcode %}

**Red Flags in 4698/106:**

* ✗ **Executables from temp/appdata**
* ✗ **PowerShell with encoded commands**
* ✗ **Hidden tasks** (names with spaces/special chars)
* ✗ **High-frequency execution** (every minute)
* ✗ **Tasks running as SYSTEM**

***

#### Workflow 4: PowerShell Activity Investigation

**Scenario:** Detect malicious PowerShell usage

**Key Events:**

**Event 4104 - Script Block Logging** (MOST IMPORTANT)

**Shows:** Actual PowerShell commands executed

**PowerShell - Analyse Script Blocks:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Analyse PowerShell script block logs
#>

param(
    [string]$PSLog = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
    [int]$Hours = 24
)

$startTime = (Get-Date).AddHours(-$Hours)

Write-Host "[+] Analysing PowerShell Script Block Logs..." -ForegroundColor Cyan

$scripts = Get-WinEvent -Path $PSLog -FilterXPath "*[System[(EventID=4104) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($scripts) {
    Write-Host "[*] Found $($scripts.Count) script blocks" -ForegroundColor Yellow
    
    # Define suspicious keywords
    $suspiciousKeywords = @(
        "Invoke-Mimikatz", "Invoke-Expression", "IEX", "DownloadString",
        "Net.WebClient", "Invoke-Shellcode", "Invoke-WMIMethod",
        "-EncodedCommand", "-enc", "bypass", "hidden",
        "mimikatz", "procdump", "lsass", "SAM", "NTDS.dit"
    )
    
    $suspicious = $scripts | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $scriptBlock = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ScriptBlockText'}).'#text'
        
        foreach ($keyword in $suspiciousKeywords) {
            if ($scriptBlock -match $keyword) {
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    Keyword = $keyword
                    ScriptBlock = $scriptBlock.Substring(0, [Math]::Min(200, $scriptBlock.Length)) + "..."
                }
                break
            }
        }
    }
    
    if ($suspicious) {
        Write-Host "`n[!] SUSPICIOUS POWERSHELL DETECTED:" -ForegroundColor Red
        $suspicious | ForEach-Object {
            Write-Host "`n--- Detection: $($_.Time) ---" -ForegroundColor Red
            Write-Host "Keyword: $($_.Keyword)" -ForegroundColor Yellow
            Write-Host "Script: $($_.ScriptBlock)" -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] No suspicious PowerShell detected" -ForegroundColor Green
    }
}
```
{% endcode %}

**Event 4103 - Module Logging**

* Logs PowerShell module loading and pipeline execution

**Event 400 - PowerShell Engine Start**

* PowerShell session started

**Event 403 - PowerShell Engine End**

* PowerShell session ended

**Event 800 - Pipeline Execution**

* Command pipeline details

**Red Flags in PowerShell Events:**

* ✗ **Invoke-Expression (IEX)**
* ✗ **DownloadString** (download and execute)
* ✗ **-EncodedCommand** (obfuscation)
* ✗ **Bypass ExecutionPolicy**
* ✗ **Hidden window** (-WindowStyle Hidden)
* ✗ **Known attack tools** (Mimikatz, Empire, Covenant)
* ✗ **Base64 encoded commands**

***

#### Workflow 5: Credential Dumping Detection

**Scenario:** Detect credential theft attempts

**Key Indicators:**

**LSASS Access:**

**Event 4656 - Handle to Object Requested**

* Process requesting access to lsass.exe
* `ObjectName: \Device\HarddiskVolume*\Windows\System32\lsass.exe`

**Event 4688 - Process Creation**

* Look for:
  * procdump.exe
  * mimikatz.exe
  * dumpert.exe
  * comsvcs.dll (MiniDump)

**PowerShell - Detect LSASS Access:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Detect LSASS access attempts
#>

param(
    [string]$SecurityLog = "C:\Windows\System32\winevt\Logs\Security.evtx",
    [int]$Days = 7
)

$startTime = (Get-Date).AddDays(-$Days)

Write-Host "[+] Detecting LSASS access attempts..." -ForegroundColor Cyan

# Event 4656 - Object access (requires object access auditing enabled)
$lsassAccess = Get-WinEvent -Path $SecurityLog -FilterXPath "*[System[(EventID=4656) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($lsassAccess) {
    $lsassEvents = $lsassAccess | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $objectName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ObjectName'}).'#text'
        
        if ($objectName -like "*lsass.exe*") {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Process = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessName'}).'#text'
                User = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
                AccessMask = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'AccessMask'}).'#text'
            }
        }
    } | Where-Object {$_ -ne $null}
    
    if ($lsassEvents) {
        Write-Host "`n[!] LSASS ACCESS DETECTED:" -ForegroundColor Red
        $lsassEvents | Format-Table -AutoSize
    }
}

# Also check process creation for dumping tools
$processes = Get-WinEvent -Path $SecurityLog -FilterXPath "*[System[(EventID=4688) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

$dumpingTools = @("procdump", "mimikatz", "dumpert", "pwdump", "gsecdump")

$suspicious = $processes | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $process = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
    
    foreach ($tool in $dumpingTools) {
        if ($process -match $tool) {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Process = $process
                User = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
                Tool = $tool
            }
            break
        }
    }
} | Where-Object {$_ -ne $null}

if ($suspicious) {
    Write-Host "`n[!] CREDENTIAL DUMPING TOOLS DETECTED:" -ForegroundColor Red
    $suspicious | Format-Table -AutoSize
}
```
{% endcode %}

**SAM/NTDS.dit Access:**

**Event 4663 - Attempt to Access Object**

* Access to SAM/SECURITY/SYSTEM registry hives
* Access to NTDS.dit (Active Directory database)

***

#### Workflow 6: Evidence Destruction Detection

**Scenario:** Detect log clearing and anti-forensics

**Critical Events:**

**Event 1102 - Security Log Cleared** **Event 104 - System Log Cleared**

**PowerShell - Detect Log Clearing:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Detect event log clearing
#>

Write-Host "[+] Detecting event log clearing..." -ForegroundColor Cyan

# Check Security log
$securityCleared = Get-WinEvent -Path "C:\Windows\System32\winevt\Logs\Security.evtx" -FilterXPath "*[System[EventID=1102]]" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($securityCleared) {
    Write-Host "`n[!] SECURITY LOG CLEARING DETECTED:" -ForegroundColor Red
    
    $securityCleared | ForEach-Object {
        $xml = [xml]$_.ToXml()
        Write-Host "  Time: $($_.TimeCreated)" -ForegroundColor Yellow
        Write-Host "  Cleared By: $(($xml.Event.UserData.LogFileCleared.SubjectUserName))" -ForegroundColor Red
        Write-Host "  Domain: $(($xml.Event.UserData.LogFileCleared.SubjectDomainName))" -ForegroundColor Yellow
    }
}

# Check System log
$systemCleared = Get-WinEvent -Path "C:\Windows\System32\winevt\Logs\System.evtx" -FilterXPath "*[System[EventID=104]]" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($systemCleared) {
    Write-Host "`n[!] SYSTEM LOG CLEARING DETECTED:" -ForegroundColor Red
    
    $systemCleared | ForEach-Object {
        Write-Host "  Time: $($_.TimeCreated)" -ForegroundColor Yellow
    }
}

if (-not $securityCleared -and -not $systemCleared) {
    Write-Host "[+] No log clearing detected" -ForegroundColor Green
}
```
{% endcode %}

**Red Flags:**

* ✗ **Event 1102 or 104** at all (major indicator)
* ✗ **Shortly after suspicious activity**
* ✗ **Cleared by non-admin account**
* ✗ **Multiple logs cleared**

***

### Complete Investigation Script

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Comprehensive Windows Event Log Investigation
.DESCRIPTION
    Performs complete event log analysis for incident response
#>

param(
    [string]$OutputPath = "C:\Cases\EventLogAnalysis",
    [int]$DaysBack = 7
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$startTime = (Get-Date).AddDays(-$DaysBack)

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       WINDOWS EVENT LOG INVESTIGATION                     ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Analysis Period: Last $DaysBack days" -ForegroundColor Yellow
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

# Define log paths
$securityLog = "C:\Windows\System32\winevt\Logs\Security.evtx"
$systemLog = "C:\Windows\System32\winevt\Logs\System.evtx"
$psLog = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"

# ============================================================================
# 1. ACCOUNT ACTIVITY ANALYSIS
# ============================================================================
Write-Host "[1/6] Analysing Account Activity..." -ForegroundColor Yellow
$accountOutput = "$OutputPath\01_Account_Activity.txt"

"=" * 80 | Out-File $accountOutput
"ACCOUNT ACTIVITY ANALYSIS - $(Get-Date)" | Out-File $accountOutput -Append
"=" * 80 | Out-File $accountOutput -Append

# Successful logons
"`n--- SUCCESSFUL LOGONS (4624) ---" | Out-File $accountOutput -Append
$logons = Get-WinEvent -Path $securityLog -FilterXPath "*[System[(EventID=4624) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($logons) {
    "Total Logons: $($logons.Count)" | Out-File $accountOutput -Append
    
    $logonSummary = $logons | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            LogonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
            SourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        }
    }
    
    $logonSummary | Sort-Object Time -Descending | Format-Table -AutoSize | Out-File $accountOutput -Append
} else {
    "No logon events found" | Out-File $accountOutput -Append
}

# Failed logons
"`n--- FAILED LOGONS (4625) ---" | Out-File $accountOutput -Append
$failedLogons = Get-WinEvent -Path $securityLog -FilterXPath "*[System[(EventID=4625) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($failedLogons) {
    "Total Failed Attempts: $($failedLogons.Count)" | Out-File $accountOutput -Append
    
    # Brute force detection
    $bruteForce = $failedLogons | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        [PSCustomObject]@{
            User = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            SourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        }
    } | Group-Object User, SourceIP | Where-Object {$_.Count -ge 5}
    
    if ($bruteForce) {
        "`nPOTENTIAL BRUTE FORCE DETECTED:" | Out-File $accountOutput -Append
        $bruteForce | ForEach-Object {
            "  Target: $($_.Name) - Attempts: $($_.Count)" | Out-File $accountOutput -Append
        }
    }
} else {
    "No failed logon events found" | Out-File $accountOutput -Append
}

# Privilege escalation
"`n--- PRIVILEGE ESCALATION (4672) ---" | Out-File $accountOutput -Append
$privEsc = Get-WinEvent -Path $securityLog -FilterXPath "*[System[(EventID=4672) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -MaxEvents 100 -ErrorAction SilentlyContinue

if ($privEsc) {
    $nonSystem = $privEsc | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $user = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        
        if ($user -ne "SYSTEM" -and $user -ne "$env:COMPUTERNAME$") {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = $user
            }
        }
    } | Where-Object {$_ -ne $null}
    
    if ($nonSystem) {
        $nonSystem | Format-Table -AutoSize | Out-File $accountOutput -Append
    } else {
        "Only SYSTEM privileges (normal)" | Out-File $accountOutput -Append
    }
}

Write-Host "  [✓] Account activity analysis complete" -ForegroundColor Green

# ============================================================================
# 2. LATERAL MOVEMENT DETECTION
# ============================================================================
Write-Host "[2/6] Detecting Lateral Movement..." -ForegroundColor Yellow
$lateralOutput = "$OutputPath\02_Lateral_Movement.txt"

"=" * 80 | Out-File $lateralOutput
"LATERAL MOVEMENT DETECTION - $(Get-Date)" | Out-File $lateralOutput -Append
"=" * 80 | Out-File $lateralOutput -Append

# PsExec detection
"`n--- PSEXEC DETECTION ---" | Out-File $lateralOutput -Append
$psexecService = Get-WinEvent -Path $systemLog -FilterXPath "*[System[(EventID=7045) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($psexecService) {
    $psexec = $psexecService | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $serviceName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
        
        if ($serviceName -eq "PSEXESVC") {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Service = $serviceName
                ImagePath = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImagePath'}).'#text'
            }
        }
    } | Where-Object {$_ -ne $null}
    
    if ($psexec) {
        "[!] PSEXEC DETECTED:" | Out-File $lateralOutput -Append
        $psexec | Format-Table -AutoSize | Out-File $lateralOutput -Append
    } else {
        "No PsExec activity detected" | Out-File $lateralOutput -Append
    }
} else {
    "No service creation events found" | Out-File $lateralOutput -Append
}

# Network logons (Type 3)
"`n--- NETWORK LOGONS (TYPE 3) ---" | Out-File $lateralOutput -Append
$networkLogons = $logons | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $logonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
    
    if ($logonType -eq '3') {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            SourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
            Workstation = ($eventData | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
        }
    }
} | Where-Object {$_ -ne $null}

if ($networkLogons) {
    $networkLogons | Format-Table -AutoSize | Out-File $lateralOutput -Append
} else {
    "No network logons detected" | Out-File $lateralOutput -Append
}

Write-Host "  [✓] Lateral movement detection complete" -ForegroundColor Green

# ============================================================================
# 3. PERSISTENCE DETECTION
# ============================================================================
Write-Host "[3/6] Detecting Persistence Mechanisms..." -ForegroundColor Yellow
$persistenceOutput = "$OutputPath\03_Persistence.txt"

"=" * 80 | Out-File $persistenceOutput
"PERSISTENCE DETECTION - $(Get-Date)" | Out-File $persistenceOutput -Append
"=" * 80 | Out-File $persistenceOutput -Append

# Service creation
"`n--- SERVICE CREATION (7045) ---" | Out-File $persistenceOutput -Append
$services = Get-WinEvent -Path $systemLog -FilterXPath "*[System[(EventID=7045) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($services) {
    $serviceList = $services | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        
        [PSCustomObject]@{
            Time = $_.TimeCreated
            ServiceName = ($eventData | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
            ImagePath = ($eventData | Where-Object {$_.Name -eq 'ImagePath'}).'#text'
            StartType = ($eventData | Where-Object {$_.Name -eq 'StartType'}).'#text'
        }
    }
    
    # Flag suspicious services
    $suspicious = $serviceList | Where-Object {
        $_.ImagePath -like "*\Temp\*" -or
        $_.ImagePath -like "*\AppData\*" -or
        $_.ImagePath -match "powershell" -or
        $_.ImagePath -match "cmd.exe"
    }
    
    if ($suspicious) {
        "`n[!] SUSPICIOUS SERVICES:" | Out-File $persistenceOutput -Append
        $suspicious | Format-Table -AutoSize | Out-File $persistenceOutput -Append
    }
    
    "`nAll Services:" | Out-File $persistenceOutput -Append
    $serviceList | Format-Table -AutoSize | Out-File $persistenceOutput -Append
} else {
    "No service creation events found" | Out-File $persistenceOutput -Append
}

# Scheduled tasks
"`n--- SCHEDULED TASKS (4698) ---" | Out-File $persistenceOutput -Append
$tasks = Get-WinEvent -Path $securityLog -FilterXPath "*[System[(EventID=4698) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue

if ($tasks) {
    "Found $($tasks.Count) scheduled task creation events" | Out-File $persistenceOutput -Append
    
    $tasks | ForEach-Object {
        $xml = [xml]$_.ToXml()
        "`nTask: $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TaskName'}).'#text')" | Out-File $persistenceOutput -Append
        "Created: $($_.TimeCreated)" | Out-File $persistenceOutput -Append
        "By: $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text')" | Out-File $persistenceOutput -Append
    }
} else {
    "No scheduled task events found" | Out-File $persistenceOutput -Append
}

Write-Host "  [✓] Persistence detection complete" -ForegroundColor Green

# ============================================================================
# 4. POWERSHELL ACTIVITY
# ============================================================================
Write-Host "[4/6] Analysing PowerShell Activity..." -ForegroundColor Yellow
$psOutput = "$OutputPath\04_PowerShell_Activity.txt"

"=" * 80 | Out-File $psOutput
"POWERSHELL ACTIVITY ANALYSIS - $(Get-Date)" | Out-File $psOutput -Append
"=" * 80 | Out-File $psOutput -Append

if (Test-Path $psLog) {
    # Script block logging
    $scriptBlocks = Get-WinEvent -Path $psLog -FilterXPath "*[System[(EventID=4104) and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString('o'))']]]" -ErrorAction SilentlyContinue
    
    if ($scriptBlocks) {
        "Total Script Blocks: $($scriptBlocks.Count)" | Out-File $psOutput -Append
        
        # Suspicious keyword detection
        $suspiciousKeywords = @(
            "Invoke-Mimikatz", "Invoke-Expression", "IEX", "DownloadString",
            "Invoke-Shellcode", "-EncodedCommand", "bypass", "hidden"
        )
        
        "`n--- SUSPICIOUS SCRIPT BLOCKS ---" | Out-File $psOutput -Append
        
        $foundSuspicious = $false
        $scriptBlocks | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $scriptBlock = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ScriptBlockText'}).'#text'
            
            foreach ($keyword in $suspiciousKeywords) {
                if ($scriptBlock -match $keyword) {
                    $foundSuspicious = $true
                    "`n[!] DETECTION: $keyword" | Out-File $psOutput -Append
                    "Time: $($_.TimeCreated)" | Out-File $psOutput -Append
                    "Script: $($scriptBlock.Substring(0, [Math]::Min(500, $scriptBlock.Length)))" | Out-File $psOutput -Append
                    break
                }
            }
        }
        
        if (-not $foundSuspicious) {
            "No suspicious keywords detected" | Out-File $psOutput -Append
        }
    } else {
        "No PowerShell script blocks found" | Out-File $psOutput -Append
    }
} else {
    "PowerShell operational log not found" | Out-File $psOutput -Append
}

Write-Host "  [✓] PowerShell analysis complete" -ForegroundColor Green

# ============================================================================
# 5. RDP ACTIVITY
# ============================================================================
Write-Host "[5/6] Analysing RDP Activity..." -ForegroundColor Yellow
$rdpOutput = "$OutputPath\05_RDP_Activity.txt"

"=" * 80 | Out-File $rdpOutput
"RDP ACTIVITY ANALYSIS - $(Get-Date)" | Out-File $rdpOutput -Append
"=" * 80 | Out-File $rdpOutput -Append

# Type 10 logons (RDP)
"`n--- RDP LOGONS (TYPE 10) ---" | Out-File $rdpOutput -Append
$rdpLogons = $logons | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $logonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
    
    if ($logonType -eq '10') {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            SourceIP = ($eventData | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
            LogonID = ($eventData | Where-Object {$_.Name -eq 'TargetLogonId'}).'#text'
        }
    }
} | Where-Object {$_ -ne $null}

if ($rdpLogons) {
    $rdpLogons | Format-Table -AutoSize | Out-File $rdpOutput -Append
} else {
    "No RDP logons detected" | Out-File $rdpOutput -Append
}

Write-Host "  [✓] RDP analysis complete" -ForegroundColor Green

# ============================================================================
# 6. EVIDENCE DESTRUCTION
# ============================================================================
Write-Host "[6/6] Detecting Evidence Destruction..." -ForegroundColor Yellow
$destructionOutput = "$OutputPath\06_Evidence_Destruction.txt"

"=" * 80 | Out-File $destructionOutput
"EVIDENCE DESTRUCTION DETECTION - $(Get-Date)" | Out-File $destructionOutput -Append
"=" * 80 | Out-File $destructionOutput -Append

# Security log clearing
"`n--- SECURITY LOG CLEARING (1102) ---" | Out-File $destructionOutput -Append
$securityCleared = Get-WinEvent -Path $securityLog -FilterXPath "*[System[EventID=1102]]" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($securityCleared) {
    "[!] SECURITY LOG CLEARING DETECTED:" | Out-File $destructionOutput -Append
    
    $securityCleared | ForEach-Object {
        $xml = [xml]$_.ToXml()
        "Time: $($_.TimeCreated)" | Out-File $destructionOutput -Append
        "Cleared By: $(($xml.Event.UserData.LogFileCleared.SubjectUserName))" | Out-File $destructionOutput -Append
        "Domain: $(($xml.Event.UserData.LogFileCleared.SubjectDomainName))" | Out-File $destructionOutput -Append
        "" | Out-File $destructionOutput -Append
    }
} else {
    "No security log clearing detected" | Out-File $destructionOutput -Append
}

# System log clearing
"`n--- SYSTEM LOG CLEARING (104) ---" | Out-File $destructionOutput -Append
$systemCleared = Get-WinEvent -Path $systemLog -FilterXPath "*[System[EventID=104]]" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($systemCleared) {
    "[!] SYSTEM LOG CLEARING DETECTED:" | Out-File $destructionOutput -Append
    
    $systemCleared | ForEach-Object {
        "Time: $($_.TimeCreated)" | Out-File $destructionOutput -Append
    }
} else {
    "No system log clearing detected" | Out-File $destructionOutput -Append
}

Write-Host "  [✓] Evidence destruction analysis complete" -ForegroundColor Green

# ============================================================================
# GENERATE SUMMARY
# ============================================================================
$summaryOutput = "$OutputPath\00_INVESTIGATION_SUMMARY.txt"

@"
╔════════════════════════════════════════════════════════════════════════════╗
║              WINDOWS EVENT LOG INVESTIGATION SUMMARY                       ║
╚════════════════════════════════════════════════════════════════════════════╝

Investigation Date: $(Get-Date)
Computer: $env:COMPUTERNAME
Analysis Period: $(Get-Date $startTime) to $(Get-Date)
Analyst: $env:USERNAME

ANALYSIS PERFORMED:
────────────────────────────────────────────────────────────────────────────
[✓] Account Activity (Logons, Failed Attempts, Privilege Escalation)
[✓] Lateral Movement (PsExec, Network Logons, RDP)
[✓] Persistence Mechanisms (Services, Scheduled Tasks)
[✓] PowerShell Activity (Script Blocks, Suspicious Commands)
[✓] RDP Activity (Remote Desktop Sessions)
[✓] Evidence Destruction (Log Clearing)

OUTPUT FILES:
────────────────────────────────────────────────────────────────────────────
01_Account_Activity.txt      → Logon analysis and brute force detection
02_Lateral_Movement.txt      → PsExec, network logons, remote access
03_Persistence.txt           → Service and task creation
04_PowerShell_Activity.txt   → PowerShell script execution
05_RDP_Activity.txt          → Remote Desktop activity
06_Evidence_Destruction.txt  → Log clearing attempts

RECOMMENDED NEXT STEPS:
────────────────────────────────────────────────────────────────────────────
1. Review suspicious indicators in each output file

2. Collect event logs for offline analysis:
   Copy-Item "C:\Windows\System32\winevt\Logs\*.evtx" "$OutputPath\EventLogs\"

3. Parse with EvtxECmd for timeline analysis:
   EvtxECmd.exe -d "$OutputPath\EventLogs" --csv "$OutputPath\Parsed" --csvf events.csv

4. Focus on critical event IDs:
   EvtxECmd.exe -d "$OutputPath\EventLogs" --csv "$OutputPath\Parsed" --csvf critical.csv --inc 4624,4625,4648,4672,4688,7045,4697,4698,1102

5. Correlate with other artifacts:
   - Prefetch (execution evidence)
   - Registry (persistence mechanisms)
   - File system (malware, staging directories)
   - Network artifacts (connections, shares)

6. Build complete attack timeline using TimelineExplorer

KEY INDICATORS TO INVESTIGATE:
────────────────────────────────────────────────────────────────────────────
→ Failed logon attempts followed by success (brute force)
→ Type 3 network logons (lateral movement)
→ Type 10 RDP logons from unusual IPs
→ Service creation in temp/appdata directories
→ PowerShell with suspicious keywords (IEX, DownloadString, etc.)
→ Event log clearing (1102, 104)
→ 4672 events for non-SYSTEM accounts (privilege escalation)

════════════════════════════════════════════════════════════════════════════
"@ | Out-File $summaryOutput

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║            INVESTIGATION COMPLETE                          ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host "`nResults: $OutputPath" -ForegroundColor Cyan
Write-Host "Review: 00_INVESTIGATION_SUMMARY.txt`n" -ForegroundColor Yellow
```
{% endcode %}

***

### Quick Triage Commands

#### Live System Quick Checks

{% code overflow="wrap" %}
```powershell
# Last 24 hours successful logons
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated, Message -First 20

# Failed logon attempts
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated, Message -First 20

# Recent service creation
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, Message

# Log clearing detection
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5
Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 5

# PowerShell execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated, Message -First 10

# RDP logons (Type 10)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-7)} | Where-Object {$_.Properties[8].Value -eq 10} | Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
```
{% endcode %}

***

### Event Log Collection Commands

{% code overflow="wrap" %}
```batch
@echo off
set OUTPUT=C:\Cases\EventLogs
mkdir %OUTPUT%

echo [+] Collecting Event Logs...

REM Critical logs
copy C:\Windows\System32\winevt\Logs\Security.evtx %OUTPUT%
copy C:\Windows\System32\winevt\Logs\System.evtx %OUTPUT%
copy C:\Windows\System32\winevt\Logs\Application.evtx %OUTPUT%

REM PowerShell
copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%%4Operational.evtx" %OUTPUT%
copy "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx" %OUTPUT%

REM RDP
copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx" %OUTPUT%
copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx" %OUTPUT%
copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Operational.evtx" %OUTPUT%

REM Task Scheduler
copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx" %OUTPUT%

REM WMI
copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%%4Operational.evtx" %OUTPUT%

REM Sysmon (if installed)
copy "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx" %OUTPUT% 2>nul

echo [+] Collection Complete: %OUTPUT%
```
{% endcode %}

***

### Investigation Checklists

#### Account Compromise Investigation

* \[ ] Check 4624 for successful logons (unusual times/IPs)
* \[ ] Check 4625 for brute force attempts (>5 failures)
* \[ ] Correlate failures with successes (same user/IP)
* \[ ] Check 4672 for privilege escalation
* \[ ] Check 4648 for explicit credential usage
* \[ ] Review logon types (Type 10 RDP, Type 3 network)
* \[ ] Identify source IPs and workstations
* \[ ] Build user activity timeline
* \[ ] Cross-reference with file access artifacts

#### Lateral Movement Investigation

* \[ ] Check 4624 Type 3 (network logons)
* \[ ] Check 7045 for PSEXESVC service
* \[ ] Check 4648 for explicit credentials
* \[ ] Check 5140 for share access (ADMIN$, C$)
* \[ ] Check 4688 for remote execution tools
* \[ ] Review WMI activity logs (5857, 5860, 5861)
* \[ ] Check PowerShell remote execution
* \[ ] Correlate source and destination events
* \[ ] Map lateral movement paths

#### Persistence Investigation

* \[ ] Check 7045 for service creation
* \[ ] Review service image paths (temp/appdata)
* \[ ] Check 4697 (Security log service install)
* \[ ] Check 4698 for scheduled tasks
* \[ ] Review Task Scheduler operational log (106, 140, 200)
* \[ ] Check registry Run keys (correlate with registry artifacts)
* \[ ] Review WMI event subscriptions
* \[ ] Validate autostart locations

***

### Summary: Critical Event IDs (Memorise)

#### Top 10 Most Important

| EventID  | Log        | Description          | Priority |
| -------- | ---------- | -------------------- | -------- |
| **4624** | Security   | Successful logon     | CRITICAL |
| **4625** | Security   | Failed logon         | CRITICAL |
| **4672** | Security   | Admin privileges     | CRITICAL |
| **4688** | Security   | Process creation     | CRITICAL |
| **7045** | System     | Service installed    | CRITICAL |
| **1102** | Security   | Log cleared          | CRITICAL |
| **4648** | Security   | Explicit credentials | HIGH     |
| **4697** | Security   | Service installed    | HIGH     |
| **4698** | Security   | Task created         | HIGH     |
| **4104** | PowerShell | Script block         | HIGH     |

#### Key Principle

**Event logs document what happened on a Windows system. Focus on logon events (4624/4625), privilege escalation (4672), persistence (7045/4698), and evidence destruction (1102). Always correlate multiple events to build the complete attack timeline.**

***

**Remember:** Event logs survive many anti-forensics techniques. Even if malware is deleted, event logs show it executed. Always check for log clearing (1102/104) as first indicator of attacker awareness!
