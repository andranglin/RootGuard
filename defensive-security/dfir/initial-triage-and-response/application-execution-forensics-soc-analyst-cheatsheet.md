# Application Execution Forensics – SOC Analyst Cheatsheet

### Practical Guide for Execution Analysis & Incident Response

***

### Quick Reference: Execution Artifacts Matrix

| Artifact       | What Ran | When Ran    | Where From | Count | Persistence  | OS Support             |
| -------------- | -------- | ----------- | ---------- | ----- | ------------ | ---------------------- |
| **Prefetch**   | ✓        | ✓ (Last 8)  | ✓          | ✓     | \~30 days    | Win7-11 (Workstations) |
| **BAM/DAM**    | ✓        | ✓ (Last)    | ✓          | ✗     | \~7 days     | Win10 1709+            |
| **ShimCache**  | ✓        | ✗           | ✓          | ✗     | Until reboot | All Windows            |
| **Amcache**    | ✓        | ✓ (Install) | ✓          | ✗     | Persistent   | Win7+                  |
| **Jump Lists** | ✓        | ✓ (Multi)   | ✓          | ✗     | Persistent   | Win7+                  |

***

### Investigation Priority Matrix

| Priority     | Artifact   | Best For                              | Live/Dead | Volatility |
| ------------ | ---------- | ------------------------------------- | --------- | ---------- |
| **CRITICAL** | Prefetch   | Recent execution (30 days), run count | Both      | Medium     |
| **CRITICAL** | BAM/DAM    | Last 7 days execution                 | Live      | High       |
| **HIGH**     | ShimCache  | Historical presence                   | Both      | Medium     |
| **HIGH**     | Amcache    | SHA1 hashes, installed apps           | Both      | Low        |
| **MEDIUM**   | Jump Lists | User file access patterns             | Both      | Low        |

***

### Core Investigation Questions

#### The Three Critical Questions:

1. **What executables ran?** (Program identification)
2. **When did they run?** (Timeline construction)
3. **Where did they run from?** (Path analysis for anomalies)

#### Additional Context:

4. **How many times?** (Frequency analysis)
5. **What files did they touch?** (Associated files/DLLs)
6. **Who ran them?** (User attribution)

***

### SOC Investigation Workflows

#### Workflow 1: Malware Detection & Triage (CRITICAL)

**Scenario:** Suspected malware execution on endpoint

**Investigation Steps:**

**Step 1: Check Recent Execution (Last 7 Days) - BAM/DAM**

**Why first:** Most recent activity, fastest to check

```cmd
REM Query BAM for all users
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s

REM Query DAM
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" /s

REM Filter for .exe only
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s /v *.exe
```

**PowerShell - Parse BAM with Timestamps:**

```powershell
<#
.SYNOPSIS
    Parse BAM entries with readable timestamps
#>

Write-Host "[+] Parsing BAM Execution Data..." -ForegroundColor Cyan

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"

Get-ChildItem $bamPath | ForEach-Object {
    $sid = $_.PSChildName
    Write-Host "`n[*] User SID: $sid" -ForegroundColor Yellow
    
    Get-ItemProperty $_.PSPath | ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $_.Name -like "*exe*" -or $_.Name -like "*\*"
        } | ForEach-Object {
            $exePath = $_.Name
            $rawTime = $_.Value
            
            # Convert Windows FILETIME to DateTime
            if ($rawTime -and $rawTime.Length -ge 8) {
                $time = [DateTime]::FromFileTime(
                    [BitConverter]::ToInt64($rawTime, 0)
                )
                
                [PSCustomObject]@{
                    Executable = $exePath
                    LastExecuted = $time
                    SID = $sid
                }
            }
        }
    }
} | Sort-Object LastExecuted -Descending | Format-Table -AutoSize
```

**Red Flags in BAM/DAM:**

* ✗ Executables from `%TEMP%`, `%APPDATA%`, `C:\Users\Public`
* ✗ Random filename patterns (e.g., `a3f8b2c9.exe`)
* ✗ Known attacker tools (psexec, mimikatz, procdump)
* ✗ Script interpreters with suspicious arguments
* ✗ Execution from USB/removable media paths

***

**Step 2: Analyse Prefetch (Last 30 Days + Run Count)**

**Why second:** Shows execution history, frequency, file dependencies

**Quick Check - List Recent Prefetch Files:**

```cmd
REM List prefetch files sorted by date
dir C:\Windows\Prefetch\*.pf /o-d /ta

REM Search for specific executable
dir C:\Windows\Prefetch\*MIMIKATZ*.pf
dir C:\Windows\Prefetch\*PROCDUMP*.pf
dir C:\Windows\Prefetch\*PSEXEC*.pf
```

**PowerShell - Check Prefetch Status:**

{% code overflow="wrap" %}
```powershell
# Check if Prefetch is enabled
$prefetchStatus = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher

switch ($prefetchStatus.EnablePrefetcher) {
    0 { Write-Host "[!] Prefetch is DISABLED" -ForegroundColor Red }
    1 { Write-Host "[+] Application Prefetch ENABLED" -ForegroundColor Green }
    2 { Write-Host "[+] Boot Prefetch ENABLED" -ForegroundColor Green }
    3 { Write-Host "[+] Application and Boot Prefetch ENABLED" -ForegroundColor Green }
}

# List recent prefetch files
Get-ChildItem "C:\Windows\Prefetch\*.pf" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object Name, LastWriteTime -First 20 | 
    Format-Table -AutoSize
```
{% endcode %}

**Using PECmd (Zimmerman Tool) - RECOMMENDED:**

{% code overflow="wrap" %}
```cmd
REM Single file analysis
PECmd.exe -f "C:\Windows\Prefetch\MIMIKATZ.EXE-ABC12345.pf"

REM Entire directory analysis to CSV
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Cases\Output" --csvf prefetch.csv -q

REM With Volume Shadow Copy processing
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Cases\Output" --csvf prefetch.csv -q --vss

REM Highlight suspicious keywords (red in console)
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Cases\Output" --csvf prefetch.csv -q -k "temp,appdata,downloads,public,users"
```
{% endcode %}

**Key Metadata from Prefetch:**

* Executable name and path
* Run count (how many times executed)
* Last 8 execution timestamps (Win10/11)
* Files and DLLs loaded by executable
* Directories accessed

**Red Flags in Prefetch:**

* ✗ Multiple prefetch files for same executable = ran from different locations
  * Example: `CMD.EXE-123ABC.pf` AND `CMD.EXE-456DEF.pf`
* ✗ Executables from unusual paths
* ✗ Known malware/tool names
* ✗ High run count on suspicious files
* ✗ Recent execution of system tools (psexec, wmic, reg.exe)

**Special Note on Multiple Prefetch Files:**

```bash
Normal: svchost.exe will have MANY prefetch files (different command-line args)
Suspicious: cmd.exe, notepad.exe, calc.exe with multiple prefetch files
```

***

**Step 3: Check ShimCache (Historical Execution)**

**Why third:** Shows files that existed/were accessed, even if deleted

**Live System Query:**

{% code overflow="wrap" %}
```cmd
REM ShimCache is in SYSTEM registry hive
REM Extract with AppCompatCacheParser (Zimmerman Tool)

AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv "C:\Cases\Output" --csvf shimcache.csv
```
{% endcode %}

**PowerShell - Manual ShimCache Query (Limited):**

{% code overflow="wrap" %}
```powershell
# ShimCache data is binary, best parsed with AppCompatCacheParser
# This shows the key exists:
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Name AppCompatCache
```
{% endcode %}

**Using AppCompatCacheParser (REQUIRED):**

{% code overflow="wrap" %}
```cmd
REM Parse SYSTEM hive
AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv "C:\Cases\Output" --csvf shimcache.csv

REM With timeline output
AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv "C:\Cases\Output" --csvf shimcache.csv -t
```
{% endcode %}

**Key Metadata from ShimCache:**

* Executable path
* Last modification time
* File size
* Executed flag (older Windows only)

**Critical Understanding:**

```bash
Win10+ ShimCache = Proves PRESENCE, NOT execution
Entry in ShimCache = File was checked for compatibility
Does NOT prove it successfully ran
```

**Red Flags in ShimCache:**

* ✗ Executables that no longer exist on disk
* ✗ Modifications to system tools
* ✗ Tools from temp directories
* ✗ Executables from external media

***

**Step 4: Analyse Amcache (SHA1 Hashes + Installed Apps)**

**Why fourth:** SHA1 hashes allow definitive malware identification

**Location:**

```bash
C:\Windows\AppCompat\Programs\Amcache.hve
```

**Using AmcacheParser (Zimmerman Tool):**

{% code overflow="wrap" %}
```cmd
REM Parse live system
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Cases\Output" --csvf amcache.csv -i

REM With known-bad hash comparison
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" -b "C:\Cases\bad_hashes.txt" --csv "C:\Cases\Output" --csvf amcache.csv

REM Parse offline hive
AmcacheParser.exe -f "E:\Evidence\Amcache.hve" --csv "C:\Cases\Output" --csvf amcache.csv -i
```
{% endcode %}

**Key Metadata from Amcache:**

* Executable name and full path
* SHA1 hash (CRITICAL for identification)
* File size
* Compilation timestamp
* Publisher information
* Install timestamp

**Investigative Value:**

```bash
SHA1 hash allows:
- VirusTotal lookup
- OSINT research
- Definitive identification of renamed malware
- Known-good vs known-bad filtering
```

**Red Flags in Amcache:**

* ✗ Executables without valid digital signatures
* ✗ SHA1 hashes matching known malware (VirusTotal)
* ✗ Suspicious publisher names or no publisher
* ✗ Executables from temp/appdata locations
* ✗ Recent install timestamps during incident window

***

#### PowerShell Script: Comprehensive Execution Triage

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Complete execution artifact triage for malware detection
.DESCRIPTION
    Checks BAM, Prefetch status, and generates reports
#>

param(
    [string]$OutputPath = "C:\Cases\ExecutionTriage"
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Host "`n[+] Starting Execution Artifact Triage..." -ForegroundColor Cyan
Write-Host "[*] Output: $OutputPath" -ForegroundColor Yellow

# 1. BAM/DAM Analysis
Write-Host "`n[1/4] Parsing BAM/DAM..." -ForegroundColor Yellow
$bamOutput = "$OutputPath\BAM_Execution.txt"

"=" * 80 | Out-File $bamOutput
"BAM Execution Analysis - $(Get-Date)" | Out-File $bamOutput -Append
"=" * 80 | Out-File $bamOutput -Append

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object {
        $sid = $_.PSChildName
        "`nUser SID: $sid" | Out-File $bamOutput -Append
        "-" * 80 | Out-File $bamOutput -Append
        
        Get-ItemProperty $_.PSPath | ForEach-Object {
            $_.PSObject.Properties | Where-Object {
                $_.Name -like "*\*"
            } | ForEach-Object {
                $exePath = $_.Name
                $rawTime = $_.Value
                
                if ($rawTime -and $rawTime.Length -ge 8) {
                    try {
                        $time = [DateTime]::FromFileTime([BitConverter]::ToInt64($rawTime, 0))
                        "$time - $exePath" | Out-File $bamOutput -Append
                    } catch {}
                }
            }
        }
    }
    Write-Host "  [✓] BAM output saved" -ForegroundColor Green
} else {
    Write-Host "  [!] BAM not found" -ForegroundColor Red
}

# 2. Prefetch Status Check
Write-Host "`n[2/4] Checking Prefetch Status..." -ForegroundColor Yellow
$prefetchOutput = "$OutputPath\Prefetch_Status.txt"

"=" * 80 | Out-File $prefetchOutput
"Prefetch Status - $(Get-Date)" | Out-File $prefetchOutput -Append
"=" * 80 | Out-File $prefetchOutput -Append

$prefetchStatus = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher
"Prefetch Status: $($prefetchStatus.EnablePrefetcher)" | Out-File $prefetchOutput -Append

switch ($prefetchStatus.EnablePrefetcher) {
    0 { "  Status: DISABLED" | Out-File $prefetchOutput -Append }
    1 { "  Status: Application Prefetch ENABLED" | Out-File $prefetchOutput -Append }
    2 { "  Status: Boot Prefetch ENABLED" | Out-File $prefetchOutput -Append }
    3 { "  Status: Application and Boot ENABLED" | Out-File $prefetchOutput -Append }
}

"`nRecent Prefetch Files (Last 50):" | Out-File $prefetchOutput -Append
"-" * 80 | Out-File $prefetchOutput -Append

Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 50 | 
    ForEach-Object {
        "$($_.LastWriteTime) - $($_.Name)" | Out-File $prefetchOutput -Append
    }

Write-Host "  [✓] Prefetch status saved" -ForegroundColor Green

# 3. Suspicious Path Detection
Write-Host "`n[3/4] Scanning for Suspicious Execution Paths..." -ForegroundColor Yellow
$suspiciousOutput = "$OutputPath\Suspicious_Paths.txt"

"=" * 80 | Out-File $suspiciousOutput
"Suspicious Execution Path Detection - $(Get-Date)" | Out-File $suspiciousOutput -Append
"=" * 80 | Out-File $suspiciousOutput -Append

$suspiciousPaths = @(
    "*\temp\*",
    "*\appdata\local\temp\*",
    "*\users\public\*",
    "*\downloads\*",
    "*\desktop\*",
    "*\documents\*"
)

"`nScanning BAM for suspicious paths..." | Out-File $suspiciousOutput -Append
Get-ChildItem $bamPath | ForEach-Object {
    $sid = $_.PSChildName
    Get-ItemProperty $_.PSPath | ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $path = $_.Name
            $found = $false
            foreach ($pattern in $suspiciousPaths) {
                if ($path -like $pattern) {
                    $found = $true
                    break
                }
            }
            $found
        } | ForEach-Object {
            "[SUSPICIOUS] $($_.Name)" | Out-File $suspiciousOutput -Append
        }
    }
}

Write-Host "  [✓] Suspicious paths saved" -ForegroundColor Green

# 4. Summary Report
Write-Host "`n[4/4] Generating Summary..." -ForegroundColor Yellow
$summaryOutput = "$OutputPath\Execution_Summary.txt"

@"
================================================================================
EXECUTION ARTIFACT TRIAGE SUMMARY
================================================================================
Analysis Date: $(Get-Date)
Computer: $env:COMPUTERNAME
Analyst: $env:USERNAME

OUTPUT FILES:
- BAM_Execution.txt : Last 7 days of execution from BAM
- Prefetch_Status.txt : Prefetch configuration and recent files
- Suspicious_Paths.txt : Executables from unusual locations

RECOMMENDED NEXT STEPS:
1. Review suspicious paths for malware indicators
2. Run PECmd on Prefetch directory for detailed timeline
3. Run AppCompatCacheParser on SYSTEM hive for historical data
4. Run AmcacheParser for SHA1 hashes and VirusTotal lookup

TOOLS REQUIRED:
- PECmd.exe : https://ericzimmerman.github.io/
- AppCompatCacheParser.exe : https://ericzimmerman.github.io/
- AmcacheParser.exe : https://ericzimmerman.github.io/

================================================================================
"@ | Out-File $summaryOutput

Write-Host "`n[+] Triage Complete!" -ForegroundColor Green
Write-Host "[*] Results saved to: $OutputPath" -ForegroundColor Cyan
Write-Host "`n[!] Next: Run Zimmerman tools for detailed analysis" -ForegroundColor Yellow
```
{% endcode %}

***

### Workflow 2: User Activity & Timeline Reconstruction

**Scenario:** Understand what user did during incident timeframe

#### Jump List Analysis (File Access Timeline)

**Location:**

```bash
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
  ├── AutomaticDestinations\  (automatically tracked)
  └── CustomDestinations\     (pinned items)
```

**PowerShell - List Jump Lists:**

```powershell
# Automatic destinations
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object Name, LastWriteTime, Length

# Custom destinations (pinned)
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object Name, LastWriteTime, Length
```

**Using JLECmd (Zimmerman Tool):**

{% code overflow="wrap" %}
```cmd
REM Single Jump List file
JLECmd.exe -f "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms" --csv "C:\Cases\Output" -q

REM Entire directory
JLECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\Cases\Output" --csvf jumplists.csv -q

REM All users
JLECmd.exe -d "C:\Users" --csv "C:\Cases\Output" --csvf all_jumplists.csv -q
```
{% endcode %}

**Key Jump List AppIDs:**

| AppID              | Application          | Forensic Value          |
| ------------------ | -------------------- | ----------------------- |
| `1b4dd67f29cb1962` | Microsoft Word       | Documents opened        |
| `1bc392b8e104a00e` | Microsoft Excel      | Spreadsheets accessed   |
| `2d9a7c5e0f5c0ad9` | Microsoft PowerPoint | Presentations accessed  |
| `5f7b5f1e01b83767` | Windows Explorer     | Folders/files browsed   |
| `b8b2d1b5e3cd6f1e` | Google Chrome        | Recently accessed items |
| `f214ca2f1b9c2c1a` | Remote Desktop       | **RDP connections!**    |

**Jump List Forensic Value:**

* Files accessed per application
* Remote Desktop connection history (destination IPs!)
* MRU order (most recently used)
* File metadata (path, size, timestamps)
* Network share access

**Red Flags in Jump Lists:**

* ✗ Access to sensitive files (HR data, financial docs)
* ✗ Remote Desktop connections to unusual IPs
* ✗ File access from external drives
* ✗ Access to files that are now deleted

***

#### Cross-Artifact Timeline Correlation

**Scenario:** Build complete execution timeline for incident window

**Steps:**

1.  **Extract all execution artifacts**

    <pre class="language-cmd" data-overflow="wrap"><code class="lang-cmd">REM Prefetch
    PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Timeline" --csvf prefetch.csv -q --mp

    REM ShimCache
    AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv "C:\Timeline" --csvf shimcache.csv

    REM Amcache
    AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Timeline" --csvf amcache.csv -i

    REM Jump Lists
    JLECmd.exe -d "C:\Users" --csv "C:\Timeline" --csvf jumplists.csv -q
    </code></pre>
2. **Merge timelines (use TimelineExplorer or Excel)**
   * Sort by timestamp
   * Filter by incident timeframe
   * Look for correlated events
3.  **Correlation Example:**

    ```bash
    09:15:30 - Prefetch: MIMIKATZ.EXE first execution
    09:15:32 - BAM: C:\Users\Attacker\Downloads\mimikatz.exe
    09:15:45 - Jump List: lsass.dmp accessed
    09:16:00 - Prefetch: 7Z.EXE execution (compression)
    09:16:30 - Jump List: passwords.7z created
    ```

***

### Workflow 3: Lateral Movement Detection

**Scenario:** Detect remote execution and lateral movement

#### Key Indicators in Execution Artifacts

**1. PsExec Execution**

**Prefetch indicators:**

* `PSEXEC.EXE-*.pf`
* `PSEXESVC.EXE-*.pf` (PsExec service component)

**Search command:**

```cmd
dir C:\Windows\Prefetch\*PSEXEC*.pf
```

**2. Remote Desktop Activity**

**Jump List indicators:**

* Remote Desktop AppID: `f214ca2f1b9c2c1a`
* Contains destination IPs and computer names

**JLECmd analysis:**

```cmd
JLECmd.exe -d "C:\Users" --csv "C:\Cases\RDP" --csvf rdp_connections.csv -q
REM Then filter CSV for AppID: f214ca2f1b9c2c1a
```

**3. WMI Execution**

**Prefetch indicators:**

* `WMIC.EXE-*.pf`
* `WMIPRVSE.EXE-*.pf` (WMI Provider Host)

**Search command:**

```cmd
dir C:\Windows\Prefetch\*WMIC*.pf
dir C:\Windows\Prefetch\*WMI*.pf
```

**4. Remote Service Creation**

**Prefetch indicators:**

* `SC.EXE-*.pf` (service control)
* `NET.EXE-*.pf` or `NET1.EXE-*.pf`

***

### Artifact-Specific Deep Dives

#### Prefetch Deep Dive

**File Naming Convention:**

```bash
[EXECUTABLE NAME]-[8-CHAR HASH].pf

Example: CMD.EXE-8E75B5BB.pf
- Executable: CMD.EXE
- Hash: 8E75B5BB (based on executable path)
```

**Multiple Prefetch Files Scenarios:**

**NORMAL (Hosting Apps):**

```bash
SVCHOST.EXE-12345678.pf
SVCHOST.EXE-ABCD9012.pf
SVCHOST.EXE-EF345678.pf
→ Different command-line arguments, expected
```

**SUSPICIOUS (Standard Apps):**

```bash
CMD.EXE-8E75B5BB.pf        (C:\Windows\System32\cmd.exe)
CMD.EXE-A3F8B2C9.pf        (C:\Users\Public\cmd.exe)
→ Same program, different locations, INVESTIGATE!
```

**Prefetch Metadata (Win10/11):**

* Last 8 execution times (precise timeline)
* Files/DLLs loaded (dependencies)
* Directories accessed (file system activity)
* Volume information (drive serial numbers)

**Prefetch Limitations:**

```bash
✓ Proves execution
✓ Shows frequency
✓ Shows file dependencies
✗ Doesn't prove SUCCESS (broken programs create .pf too)
✗ Limited to ~1024 prefetch files (oldest deleted)
✗ Not enabled by default on Windows Server
```

**Prefetch Analysis with PECmd:**

**Output CSV Columns of Interest:**

* `SourceFile` - Prefetch filename
* `Executable` - Program that ran
* `RunCount` - Times executed
* `LastRun` - Most recent execution
* `PreviousRun0-7` - Previous 7 executions (Win10/11)
* `FilesLoaded` - DLLs and files accessed
* `DirectoriesLoaded` - Directories accessed

***

#### BAM/DAM Deep Dive

**Background Activity Moderator (BAM):**

* Windows service controlling background app activity
* Updated at boot
* Stores last execution time per user

**Desktop Activity Moderator (DAM):**

* Similar to BAM
* Desktop-focused activity

**Registry Location:**

```bash
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}
```

**Data Structure:**

```bash
Value Name: Full path to executable
Value Data: 64-bit FILETIME timestamp (last execution)
```

**Typical Retention:**

* \~7 days of data
* Cleared on system updates/reboots (inconsistent)

**BAM/DAM Advantages:**

```bash
✓ Very recent activity (last week)
✓ Per-user attribution (SID)
✓ Easy to query on live system
✓ Full executable paths
```

**BAM/DAM Limitations:**

```bash
✗ Only last execution time (not historical)
✗ No run count
✗ Short retention period
✗ May not survive reboots reliably
```

**PowerShell Parsing (Advanced):**

{% code overflow="wrap" %}
```powershell
# Convert SID to username
function Get-UsernameFromSID {
    param([string]$SID)
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {
        return $SID
    }
}

# Parse BAM with username resolution
$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
Get-ChildItem $bamPath | ForEach-Object {
    $sid = $_.PSChildName
    $username = Get-UsernameFromSID $sid
    
    Write-Host "`nUser: $username ($sid)" -ForegroundColor Cyan
    
    Get-ItemProperty $_.PSPath | ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $_.Name -like "*\*"
        } | ForEach-Object {
            $exePath = $_.Name
            $rawTime = $_.Value
            
            if ($rawTime -and $rawTime.Length -ge 8) {
                $time = [DateTime]::FromFileTime([BitConverter]::ToInt64($rawTime, 0))
                
                [PSCustomObject]@{
                    User = $username
                    Executable = $exePath
                    LastExecuted = $time
                }
            }
        }
    }
} | Sort-Object LastExecuted -Descending | Format-Table -AutoSize
```
{% endcode %}

***

#### ShimCache Deep Dive

**Application Compatibility Cache:**

* Tracks executables for compatibility shimming
* Updated continuously during runtime
* Written to registry at shutdown

**Critical Understanding:**

```bash
Windows 10+ Behaviour Change:
- Entry in ShimCache = File was CHECKED (presence)
- Does NOT prove execution
- Useful for proving file existed, even if deleted
```

**Older Windows (XP-8.1):**

* Has execution flag (more reliable)
* Can prove execution

**ShimCache Use Cases:**

```bash
✓ Prove file existed on system
✓ Last modification timestamp
✓ File path
✓ Detect deleted executables
✓ Timeline of file system changes
```

**Investigative Patterns:**

```bash
# Look for:
- Executables that no longer exist
- Modified system tools (suspicious changes)
- Tools from temp/external media
- Recent entries during incident window
```

**AppCompatCacheParser Output:**

* `LastModifiedTimeUTC` - File modification time
* `Path` - Full executable path
* `Size` - File size
* `Executed` - Execution flag (pre-Win10 only)

***

#### Amcache Deep Dive

**Amcache Unique Value:**

* **SHA1 hashes** for executables and drivers
* Definitive file identification
* Survives file rename/move

**Amcache Key Locations (Internal):**

```bash
Root\File - Executed programs
Root\Programs - Installed applications
InventoryApplication - Application inventory
InventoryDriverBinary - Driver information
```

**SHA1 Hash Investigation Workflow:**

1.  **Extract SHA1 from Amcache:**

    <pre class="language-cmd" data-overflow="wrap"><code class="lang-cmd">AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Cases" --csvf amcache.csv -i
    </code></pre>
2. **Check VirusTotal:**
   * Upload SHA1 to VirusTotal
   * Or use API for batch lookups
3. **OSINT Research:**
   * Search SHA1 in threat intel feeds
   * Check against known malware databases
   * Review MISP, AlienVault OTX, etc.

**Amcache Metadata:**

* Executable path and name
* SHA1 hash
* File size
* Compilation timestamp
* Publisher/signer information
* First installation timestamp
* Program ID

**Detection Patterns:**

```bash
# Suspicious indicators:
- No publisher information
- Self-signed or invalid certificates
- SHA1 matches known malware
- Executables from temp/appdata
- Compilation date mismatch with install date
```

***

#### Jump List Deep Dive

**Jump List Types:**

**AutomaticDestinations:**

* Automatically tracked files
* Recent items accessed via application
* MRU order maintained

**CustomDestinations:**

* User-pinned items
* Persistent across sessions

**Jump List Structure:**

```bash
AppID-based filename: [AppID].automaticDestinations-ms

Example: 1b4dd67f29cb1962.automaticDestinations-ms
         → Microsoft Word
```

**Jump List Contents:**

* LNK stream per accessed item
* Target file path
* Timestamps (accessed, modified, created)
* File size
* Network share information
* MRU position

**Critical AppIDs for SOC:**

| AppID              | Application       | Investigation Value               |
| ------------------ | ----------------- | --------------------------------- |
| `f214ca2f1b9c2c1a` | Remote Desktop    | **Lateral movement destinations** |
| `5f7b5f1e01b83767` | Windows Explorer  | File system navigation            |
| `adecfb853d77462`  | Microsoft Outlook | Email attachments                 |
| `1b4dd67f29cb1962` | Microsoft Word    | Document access                   |
| `fb3b0dbfee58fac8` | 7-Zip             | Compressed file access            |

**RDP Jump List Analysis (Critical):**

Remote Desktop Jump List contains:

* Destination IP addresses
* Computer names
* Connection timestamps
* User accounts used

**JLECmd for RDP Connections:**

```cmd
REM Parse all Jump Lists
JLECmd.exe -d "C:\Users" --csv "C:\Cases\RDP" --csvf all_jumplists.csv -q

REM Filter CSV for AppID: f214ca2f1b9c2c1a
REM Shows all RDP connection history
```

***

### Common Attack Scenarios & Detection

#### Scenario 1: Ransomware Execution

**Execution Artifact Indicators:**

**Prefetch:**

```bash
- RANSOMWARE.EXE-*.pf (actual malware)
- VSSADMIN.EXE-*.pf (shadow copy deletion)
- WBADMIN.EXE-*.pf (backup deletion)
- BCDEDIT.EXE-*.pf (boot config changes)
- CIPHER.EXE-*.pf (secure file deletion)
```

**BAM:**

```bash
Recent execution of:
- Suspicious executable from temp/downloads
- Volume shadow copy deletion tools
- File encryption utilities
```

**Timeline Pattern:**

```bash
1. Initial execution (ransomware binary)
2. Reconnaissance (directory enumeration)
3. Anti-recovery (shadow copy/backup deletion)
4. Encryption phase (file modification)
5. Ransom note delivery
```

**PowerShell Detection Script:**

{% code overflow="wrap" %}
```powershell
# Ransomware execution detection
$ransomwareTools = @(
    "*vssadmin*",
    "*wbadmin*",
    "*bcdedit*",
    "*cipher*",
    "*wevtutil*"
)

Write-Host "[+] Checking for Ransomware Tool Execution..." -ForegroundColor Yellow

foreach ($tool in $ransomwareTools) {
    $prefetchFiles = Get-ChildItem "C:\Windows\Prefetch\$tool.pf" -ErrorAction SilentlyContinue
    if ($prefetchFiles) {
        Write-Host "[!] FOUND: $($prefetchFiles.Name)" -ForegroundColor Red
        Write-Host "    Last Modified: $($prefetchFiles.LastWriteTime)" -ForegroundColor Red
    }
}
```
{% endcode %}

***

#### Scenario 2: Credential Dumping

**Execution Artifact Indicators:**

**Prefetch:**

```bash
- MIMIKATZ.EXE-*.pf
- PROCDUMP.EXE-*.pf (used to dump lsass.exe)
- SQLDUMPER.EXE-*.pf (alternative lsass dumper)
```

**Jump Lists:**

```bash
- lsass.dmp file accessed
- Memory dump files (.dmp)
- Compressed archives with credential dumps
```

**Timeline Pattern:**

```bash
1. Credential dumper execution (mimikatz, procdump)
2. LSASS memory dump
3. Dump file compression (7z.exe, rar.exe)
4. Exfiltration preparation
```

**Detection Commands:**

```bash
REM Search for credential dumping tools
dir C:\Windows\Prefetch\*MIMIKATZ*.pf
dir C:\Windows\Prefetch\*PROCDUMP*.pf
dir C:\Windows\Prefetch\*DUMP*.pf

REM Check for .dmp file access in Jump Lists
REM Use JLECmd and search output for ".dmp"
```

***

#### Scenario 3: Lateral Movement

**Execution Artifact Indicators:**

**Prefetch:**

```bash
- PSEXEC.EXE-*.pf (remote execution)
- PSEXESVC.EXE-*.pf (PsExec service)
- WMIC.EXE-*.pf (WMI lateral movement)
- SC.EXE-*.pf (service manipulation)
- NET.EXE-*.pf (network commands)
- AT.EXE-*.pf or SCHTASKS.EXE-*.pf (task scheduling)
```

**Jump Lists:**

```bash
- Remote Desktop connections to multiple systems
- Network share access (\\server\share)
- Remote tool execution artifacts
```

**Timeline Pattern:**

```bash
1. Reconnaissance (net.exe, nltest.exe)
2. Remote execution setup (sc.exe, psexec)
3. Tool deployment (copy to remote system)
4. Lateral movement execution
5. Post-exploitation (credential dumping on remote system)
```

**Detection Script:**

{% code overflow="wrap" %}
```powershell
# Lateral movement tool detection
$lateralTools = @(
    "*PSEXEC*",
    "*WMIC*",
    "*SC.EXE*",
    "*NET.EXE*",
    "*NET1.EXE*",
    "*SCHTASKS*"
)

Write-Host "[+] Checking for Lateral Movement Tools..." -ForegroundColor Yellow

foreach ($tool in $lateralTools) {
    $prefetchFiles = Get-ChildItem "C:\Windows\Prefetch\$tool*.pf" -ErrorAction SilentlyContinue
    if ($prefetchFiles) {
        foreach ($file in $prefetchFiles) {
            Write-Host "[!] FOUND: $($file.Name)" -ForegroundColor Red
            Write-Host "    Last Modified: $($file.LastWriteTime)" -ForegroundColor Yellow
            Write-Host "    Full Path: $($file.FullName)" -ForegroundColor Cyan
        }
    }
}
```
{% endcode %}

***

### SOC Quick Reference Commands

#### Rapid Triage Commands

**Check Prefetch Enabled:**

{% code overflow="wrap" %}
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher
```
{% endcode %}

**List Recent Executions (Prefetch):**

```cmd
dir C:\Windows\Prefetch\*.pf /o-d /ta | more
```

**Query BAM (Last 7 Days):**

{% code overflow="wrap" %}
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s > bam_output.txt
```
{% endcode %}

**Search Specific Tool:**

```cmd
dir C:\Windows\Prefetch\*[TOOLNAME]*.pf
```

**Amcache Location:**

```cmd
dir C:\Windows\AppCompat\Programs\Amcache.hve
```

**Jump Lists Location:**

```cmd
dir "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations"
```

***

#### Collection Commands (Live Response)

**Collect All Execution Artifacts:**

{% code overflow="wrap" %}
```bash
@echo off
set OUTPUT=C:\Cases\Execution_Collection
mkdir %OUTPUT%

echo [+] Collecting Prefetch...
xcopy C:\Windows\Prefetch\*.pf %OUTPUT%\Prefetch\ /Y /I

echo [+] Collecting SYSTEM hive...
reg save HKLM\SYSTEM %OUTPUT%\SYSTEM

echo [+] Collecting Amcache...
copy C:\Windows\AppCompat\Programs\Amcache.hve %OUTPUT%\
copy C:\Windows\AppCompat\Programs\Amcache.hve.LOG* %OUTPUT%\

echo [+] Collecting Jump Lists...
xcopy "%APPDATA%\Microsoft\Windows\Recent\*.automaticDestinations-ms" %OUTPUT%\JumpLists\ /Y /I
xcopy "%APPDATA%\Microsoft\Windows\Recent\*.customDestinations-ms" %OUTPUT%\JumpLists\ /Y /I

echo [+] Exporting BAM...
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s > %OUTPUT%\BAM_Export.txt

echo [+] Collection Complete!
```
{% endcode %}

***

#### Zimmerman Tools Batch Processing

**Parse Everything (Requires Zimmerman Tools):**

```batch
@echo off
set SOURCE=C:\Cases\Evidence
set OUTPUT=C:\Cases\Parsed

REM Prefetch
PECmd.exe -d "%SOURCE%\Prefetch" --csv "%OUTPUT%" --csvf prefetch.csv -q --mp

REM ShimCache
AppCompatCacheParser.exe -f "%SOURCE%\SYSTEM" --csv "%OUTPUT%" --csvf shimcache.csv

REM Amcache
AmcacheParser.exe -f "%SOURCE%\Amcache.hve" --csv "%OUTPUT%" --csvf amcache.csv -i

REM Jump Lists
JLECmd.exe -d "%SOURCE%\JumpLists" --csv "%OUTPUT%" --csvf jumplists.csv -q

echo [+] All artifacts parsed! Check %OUTPUT% for CSV files.
```

***

### Detection Rules & IOCs

#### High-Confidence Malware Indicators

**Prefetch Patterns:**

```bash
Executables from:
- %TEMP%
- %APPDATA%\Local\Temp
- C:\Users\Public
- C:\ProgramData (non-standard)
- Recycler / $Recycle.Bin

Suspicious names:
- Random characters (a3f8b2c9.exe)
- Single characters (a.exe, x.exe)
- Numeric only (12345.exe)
- Known tools (mimikatz, procdump, psexec)
```

**Run Count Anomalies:**

```bash
High run count from temp location = persistence
Multiple prefetch files = different execution locations
Recent creation during incident window
```

**Path-Based IOCs:**

```bash
Normal:
C:\Program Files\[Vendor]\[Application]\app.exe
C:\Windows\System32\svchost.exe

Suspicious:
C:\Users\Alice\Downloads\svchost.exe
C:\Windows\Temp\update.exe
\\RemoteShare\tools\backdoor.exe
```

***

#### Known Attack Tool Prefetch Signatures

| Tool          | Prefetch Name                          | Purpose            |
| ------------- | -------------------------------------- | ------------------ |
| Mimikatz      | `MIMIKATZ.EXE-*.pf`                    | Credential dumping |
| PsExec        | `PSEXEC.EXE-*.pf`, `PSEXESVC.EXE-*.pf` | Lateral movement   |
| ProcDump      | `PROCDUMP.EXE-*.pf`                    | LSASS dumping      |
| Cobalt Strike | `BEACON.EXE-*.pf`                      | C2 implant         |
| Netcat        | `NC.EXE-*.pf`                          | Reverse shell      |
| Meterpreter   | `METERPRETER.EXE-*.pf`                 | Post-exploitation  |
| PowerSploit   | `POWERSPLOIT*.pf`                      | PowerShell attacks |

***

### Tools Reference

#### Essential Tools (Eric Zimmerman Suite)

**Download:** https://ericzimmerman.github.io/

| Tool                     | Purpose                    | Output Format |
| ------------------------ | -------------------------- | ------------- |
| **PECmd**                | Prefetch parsing           | CSV, JSON     |
| **AppCompatCacheParser** | ShimCache parsing          | CSV           |
| **AmcacheParser**        | Amcache parsing            | CSV           |
| **JLECmd**               | Jump List parsing          | CSV           |
| **TimelineExplorer**     | Timeline viewing           | GUI           |
| **RegistryExplorer**     | Registry viewing (BAM/DAM) | GUI           |

#### Installation:

```powershell
# Download Zimmerman Tools
# Extract to C:\Tools\ZimmermanTools
# Add to PATH or use full paths
```

***

#### Alternative Tools

**NirSoft:**

* **WinPrefetchView** - Prefetch viewer (GUI)

**Commercial:**

* **X-Ways Forensics** - All artifacts
* **Magnet AXIOM** - Automated parsing
* **EnCase** - Enterprise forensics

**Open Source:**

* **RegRipper** - Registry parsing (BAM/DAM)
* **KAPE** - Artifact collection

***

### Best Practices

#### Live Response

✅ **DO:**

* Collect Prefetch directory FIRST (volatile if tools run)
* Export SYSTEM hive for offline analysis
* Document all commands executed
* Use write-protected USB for tool execution
* Hash all collected evidence

❌ **DON'T:**

* Run excessive tools (creates new prefetch files)
* Modify prefetch directory
* Run from C: drive (use external media)
* Forget to check Prefetch status first

***

#### Offline Analysis

✅ **DO:**

* Parse all artifacts to CSV for timeline correlation
* Check Volume Shadow Copies (--vss flag)
* Cross-reference multiple artifacts
* Validate timestamps with system timezone
* Document tool versions used

❌ **DON'T:**

* Rely on single artifact
* Ignore timezone offsets
* Forget to check artifact retention periods
* Skip SHA1 hash validation (Amcache)

***

#### Timeline Construction

**Best Practice Workflow:**

1. **Parse all artifacts to CSV**
   * Prefetch → prefetch.csv
   * ShimCache → shimcache.csv
   * Amcache → amcache.csv
   * Jump Lists → jumplists.csv
   * BAM → bam\_export.txt (convert to CSV)
2. **Merge timelines**
   * Use TimelineExplorer or Excel
   * Sort by timestamp
   * Filter by incident timeframe
3. **Correlate events**
   * Look for related executions
   * Identify process trees
   * Track file access patterns
4. **Visualize**
   * Create timeline diagram
   * Highlight critical events
   * Document attack chain

***

### Investigation Checklists

#### Malware Investigation

* \[ ] Check BAM for recent executions (last 7 days)
* \[ ] Parse Prefetch for execution history
* \[ ] Identify executables from suspicious paths
* \[ ] Check run counts for persistence indicators
* \[ ] Parse ShimCache for deleted executables
* \[ ] Extract SHA1 hashes from Amcache
* \[ ] Cross-reference SHA1 with VirusTotal
* \[ ] Review Jump Lists for file access patterns
* \[ ] Build execution timeline
* \[ ] Document all findings with timestamps

#### Lateral Movement Investigation

* \[ ] Search Prefetch for PsExec, WMIC, SC.EXE
* \[ ] Parse Remote Desktop Jump Lists
* \[ ] Check BAM for remote execution tools
* \[ ] Review network share access (Jump Lists)
* \[ ] Identify reconnaissance tools (net.exe, nltest.exe)
* \[ ] Document remote connection destinations
* \[ ] Cross-reference with network logs
* \[ ] Build lateral movement map

#### Credential Theft Investigation

* \[ ] Search for Mimikatz, ProcDump prefetch
* \[ ] Check Jump Lists for .dmp file access
* \[ ] Look for compression tool execution (7z, rar)
* \[ ] Review BAM for dumping tools
* \[ ] Check Amcache for attacker tool SHA1s
* \[ ] Document credential access timeline
* \[ ] Identify potential exfiltration

***

### Summary: Critical Takeaways

#### Artifact Strengths

**Prefetch:**

* Best for: Execution proof, frequency, timeline
* Limitation: \~30 days retention, not on servers

**BAM/DAM:**

* Best for: Very recent activity (7 days)
* Limitation: Only last execution, may not survive reboot

**ShimCache:**

* Best for: Deleted file evidence, historical presence
* Limitation: Doesn't prove execution (Win10+)

**Amcache:**

* Best for: SHA1 hashes, definitive identification
* Limitation: Doesn't prove execution, only presence

**Jump Lists:**

* Best for: File access patterns, RDP connections
* Limitation: User-specific, application-dependent

#### Investigation Strategy

1. **Start with BAM** (fastest, most recent)
2. **Parse Prefetch** (execution proof, timeline)
3. **Check ShimCache** (historical context)
4. **Extract Amcache** (SHA1 validation)
5. **Analyse Jump Lists** (file access, RDP)
6. **Correlate everything** (build complete picture)

#### Key Principle

**Multiple artifacts provide different views of the same event. Cross-correlation is essential for accurate investigation.**

***

**Remember:** Execution artifacts survive file deletion, anti-forensics, and log clearing. They are your most reliable evidence that a program ran on a system.
