---
description: >-
  Prefetch, Amcache.hve, ShimCache, Shell Bags, Jump Lists, Recycle Bin, Master
  File Table ($MFT), $J, $LogFile, Alternate Data Streams (ADS), and Link File -
  Shortcut (.ink)
---

# Evidence of Execution Forensics – SOCb Analyst Cheatsheet

### Comprehensive Guide for Execution Analysis & Malware Detection

***

### Quick Reference: Execution Artifacts Matrix

| Artifact       | Proves Execution | Timeline      | Run Count | File Path | SHA1 Hash | Retention    |
| -------------- | ---------------- | ------------- | --------- | --------- | --------- | ------------ |
| **Prefetch**   | ✓ YES            | Last 8 runs   | ✓ YES     | ✓         | ✗         | \~30 days    |
| **Amcache**    | ✗ Presence only  | Install time  | ✗         | ✓         | ✓ YES     | Persistent   |
| **ShimCache**  | ✗ Presence only  | Last modified | ✗         | ✓         | ✗         | Until reboot |
| **BAM/DAM**    | ✓ YES            | Last run      | ✗         | ✓         | ✗         | \~7 days     |
| **UserAssist** | ✓ YES            | Last run      | ✓ YES     | ✓         | ✗         | Persistent   |
| **Jump Lists** | ✓ YES (indirect) | Multiple      | ✗         | ✓         | ✗         | Persistent   |

***

### Investigation Priority Matrix

| Priority     | Artifact   | Best For                              | Key Value                         | Limitation                  |
| ------------ | ---------- | ------------------------------------- | --------------------------------- | --------------------------- |
| **CRITICAL** | Prefetch   | Recent execution (30 days), frequency | Last 8 runs, run count, DLLs      | \~1024 file limit           |
| **CRITICAL** | Amcache    | SHA1 hashes, malware ID               | Definitive file identification    | Doesn't prove execution     |
| **HIGH**     | ShimCache  | Historical presence                   | Files that existed (even deleted) | No execution proof (Win10+) |
| **HIGH**     | BAM/DAM    | Very recent (7 days)                  | Last execution per user           | Single timestamp only       |
| **MEDIUM**   | UserAssist | GUI execution                         | Run count, focus time             | GUI apps only               |
| **MEDIUM**   | Jump Lists | File associations                     | App-specific file access          | Application-dependent       |

***

### Critical Understanding: Execution vs. Presence

#### Proves Execution:

* ✓ **Prefetch** - Application ran
* ✓ **BAM/DAM** - Application ran (last time)
* ✓ **UserAssist** - GUI application ran
* ✓ **Event 4688** - Process creation logged

#### Indicates Presence (NOT execution):

* ✗ **Amcache** - File existed on system
* ✗ **ShimCache (Win10+)** - File was checked for compatibility
* ✗ **MFT** - File existed on disk

**This distinction is CRITICAL for court testimony and investigation accuracy!**

***

### SOC Investigation Workflows

#### Workflow 1: Malware Execution Detection (CRITICAL)

**Scenario:** Suspected malware on endpoint

**Investigation Steps (Priority Order):**

**Step 1: Check Prefetch for Recent Execution**

**Location:** `C:\Windows\Prefetch\`

**Why First:**

* Proves execution
* Shows frequency (run count)
* Last 8 execution times
* Shows loaded DLLs
* Reveals file paths

**Prefetch File Naming:** `EXECUTABLE-HASH.pf`

* Example: `MIMIKATZ.EXE-A3F8B2C9.pf`
* Hash based on executable path
* Multiple prefetch = same name, different locations

**PowerShell - Quick Prefetch Check:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Quick prefetch analysis for recent executions
#>

param(
    [int]$Days = 7
)

Write-Host "[+] Analyzing Prefetch for Recent Executions..." -ForegroundColor Cyan

$prefetchPath = "C:\Windows\Prefetch"
$cutoffDate = (Get-Date).AddDays(-$Days)

if (Test-Path $prefetchPath) {
    # Check if prefetch is enabled
    $prefetchStatus = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher
    
    Write-Host "`n[*] Prefetch Status: $($prefetchStatus.EnablePrefetcher)" -ForegroundColor Yellow
    switch ($prefetchStatus.EnablePrefetcher) {
        0 { Write-Host "    DISABLED" -ForegroundColor Red }
        1 { Write-Host "    Application Prefetch ENABLED" -ForegroundColor Green }
        2 { Write-Host "    Boot Prefetch ENABLED" -ForegroundColor Green }
        3 { Write-Host "    Application and Boot ENABLED" -ForegroundColor Green }
    }
    
    # Get recent prefetch files
    $recentPrefetch = Get-ChildItem "$prefetchPath\*.pf" | 
        Where-Object { $_.LastWriteTime -gt $cutoffDate } |
        Sort-Object LastWriteTime -Descending
    
    if ($recentPrefetch) {
        Write-Host "`n[*] Recent Prefetch Files (Last $Days days): $($recentPrefetch.Count)" -ForegroundColor Yellow
        
        # Suspicious keywords
        $suspiciousKeywords = @(
            "*MIMIKATZ*", "*PROCDUMP*", "*PSEXEC*", "*COBALT*",
            "*METERPRETER*", "*NETCAT*", "*NC64*", "*PWDUMP*",
            "*GSECDUMP*", "*WCEAUX*", "*FGDUMP*", "*CACHEDUMP*"
        )
        
        Write-Host "`n--- SUSPICIOUS EXECUTABLES ---" -ForegroundColor Red
        $foundSuspicious = $false
        
        foreach ($keyword in $suspiciousKeywords) {
            $matches = $recentPrefetch | Where-Object { $_.Name -like $keyword }
            if ($matches) {
                $foundSuspicious = $true
                foreach ($match in $matches) {
                    Write-Host "  [!] $($match.Name)" -ForegroundColor Red
                    Write-Host "      Last Modified: $($match.LastWriteTime)" -ForegroundColor Yellow
                }
            }
        }
        
        if (-not $foundSuspicious) {
            Write-Host "  No known malware tools detected" -ForegroundColor Green
        }
        
        # Check for suspicious paths
        Write-Host "`n--- EXECUTABLES FROM UNUSUAL LOCATIONS ---" -ForegroundColor Yellow
        $unusualPaths = @("*TEMP*", "*APPDATA*", "*DOWNLOADS*", "*USERS\PUBLIC*", "*RECYCLE*")
        
        # Note: Would need PECmd to parse internal path data
        Write-Host "  [!] Use PECmd for detailed path analysis" -ForegroundColor Cyan
        
        # Show all recent
        Write-Host "`n--- ALL RECENT PREFETCH FILES ---" -ForegroundColor Yellow
        $recentPrefetch | Select-Object -First 20 | ForEach-Object {
            Write-Host "  $($_.LastWriteTime) | $($_.Name)" -ForegroundColor Gray
        }
        
    } else {
        Write-Host "[!] No recent prefetch files found" -ForegroundColor Red
    }
} else {
    Write-Host "[!] Prefetch directory not found" -ForegroundColor Red
}

Write-Host "`n[!] For detailed analysis, use PECmd:" -ForegroundColor Cyan
Write-Host "    PECmd.exe -d 'C:\Windows\Prefetch' --csv 'C:\Cases\Output' --csvf prefetch.csv -q`n" -ForegroundColor White
```
{% endcode %}

**Using PECmd (Zimmerman Tool) - REQUIRED for Full Analysis:**

{% code overflow="wrap" %}
```cmd
REM Single file analysis
PECmd.exe -f "C:\Windows\Prefetch\MIMIKATZ.EXE-A3F8B2C9.pf"

REM Entire directory to CSV
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Cases\Output" --csvf prefetch.csv -q

REM Include Volume Shadow Copies
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Cases\Output" --csvf prefetch.csv -q --vss

REM Highlight suspicious keywords (shows in red)
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Cases\Output" --csvf prefetch.csv -q -k "mimikatz,procdump,psexec,temp,appdata"
```
{% endcode %}

**Critical Prefetch Metadata:**

* `Executable` - Program that ran
* `RunCount` - Times executed
* `LastRun` - Most recent execution
* `PreviousRun0-7` - Last 8 executions (Win10/11)
* `FilesLoaded` - DLLs and dependencies
* `DirectoriesLoaded` - Directories accessed
* `Volume Info` - Drive serial numbers

**Red Flags in Prefetch:**

* ✗ **Multiple prefetch files** for same executable (different locations)
  * `CMD.EXE-8E75B5BB.pf` (normal: C:\Windows\System32)
  * `CMD.EXE-A3F8B2C9.pf` (suspicious: C:\Users\Public)
* ✗ **Known attack tools** (mimikatz, procdump, psexec)
* ✗ **Recently created** during incident window
* ✗ **High run count** on suspicious files
* ✗ **Unusual paths** in FilesLoaded/DirectoriesLoaded

**IMPORTANT EXCEPTIONS:**

```bash
Normal to have multiple prefetch files:
- SVCHOST.EXE-*.pf (many instances with different args)
- DLLHOST.EXE-*.pf
- BACKGROUNDTASKHOST.EXE-*.pf
- RUNDLL32.EXE-*.pf

Hash calculated from: path + command line arguments
```

***

**Step 2: Extract SHA1 Hashes from Amcache**

**Location:** `C:\Windows\AppCompat\Programs\Amcache.hve`

**Why Second:**

* SHA1 hash = definitive file identification
* Survives file rename/deletion
* Can match against VirusTotal/threat intel
* Full path and metadata

**CRITICAL UNDERSTANDING:**

```bash
Amcache DOES NOT prove execution!
Amcache proves file EXISTENCE on system

Use for:
✓ File identification (SHA1)
✓ File metadata (size, timestamps, publisher)
✓ Proving file was present even if deleted

Do NOT use for:
✗ Proving file executed
✗ Execution timestamps
```

**Using AmcacheParser (Zimmerman Tool):**

{% code overflow="wrap" %}
```cmd
REM Live system
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Cases\Output" --csvf amcache.csv -i

REM With known-bad hash list
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" -b "C:\Cases\bad_hashes.txt" --csv "C:\Cases\Output" --csvf amcache.csv

REM Offline analysis
AmcacheParser.exe -f "E:\Evidence\Amcache.hve" --csv "C:\Cases\Output" --csvf amcache.csv -i
```
{% endcode %}

**PowerShell - Check if Amcache Exists:**

{% code overflow="wrap" %}
```powershell
$amcachePath = "C:\Windows\AppCompat\Programs\Amcache.hve"

if (Test-Path $amcachePath) {
    $file = Get-Item $amcachePath
    Write-Host "[+] Amcache found" -ForegroundColor Green
    Write-Host "    Size: $([math]::Round($file.Length / 1MB, 2)) MB" -ForegroundColor Yellow
    Write-Host "    Last Modified: $($file.LastWriteTime)" -ForegroundColor Yellow
    Write-Host "`n[!] Parse with AmcacheParser for SHA1 hashes" -ForegroundColor Cyan
} else {
    Write-Host "[!] Amcache not found" -ForegroundColor Red
}
```
{% endcode %}

**Amcache Key Metadata:**

* `SHA1` - File hash (CRITICAL for identification)
* `FullPath` - Complete file path
* `FileSize` - File size in bytes
* `FileExtension` - File type
* `LinkDate` - Compilation timestamp
* `Publisher` - Digital signature publisher
* `BinaryType` - 32-bit vs 64-bit

**Investigation Workflow with SHA1:**

```bash
1. Extract SHA1 from Amcache
2. Search SHA1 on VirusTotal
3. Check against threat intel feeds
4. Cross-reference with Prefetch
5. If malware: Find ALL instances via SHA1
```

**Example Analysis:**

```bash
Amcache shows:
- SHA1: f3b25701fe362ec84616a93a45ce9994

VirusTotal result:
- 45/70 AV vendors detect as "Mimikatz"

Conclusion:
- File present on system
- Definitively identified as Mimikatz
- Check Prefetch for execution evidence
```

***

**Step 3: Check ShimCache for Historical Presence**

**Location:** `C:\Windows\System32\config\SYSTEM` **Registry Key:** `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

**Why Third:**

* Shows files that existed on system
* Survives file deletion
* Contains files that may have been present but removed

**CRITICAL UNDERSTANDING:**

```bash
Windows 10+ Behavior:
ShimCache DOES NOT prove execution!
Entry = File was checked for compatibility

Use for:
✓ Proving file existed
✓ Last modification time
✓ Detecting deleted executables

Do NOT use for:
✗ Proving execution (Win10+)
✗ Execution timestamps
```

**Using AppCompatCacheParser (Zimmerman Tool):**

{% code overflow="wrap" %}
```cmd
REM Parse SYSTEM hive
AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv "C:\Cases\Output" --csvf shimcache.csv

REM Offline analysis
AppCompatCacheParser.exe -f "E:\Evidence\SYSTEM" --csv "C:\Cases\Output" --csvf shimcache.csv
```
{% endcode %}

**ShimCache Metadata:**

* `Path` - Full executable path
* `LastModified` - File modification time
* `FileSize` - File size
* `Executed` - Execution flag (pre-Win10 only)

**Red Flags in ShimCache:**

* ✗ **Executables that no longer exist** on disk
* ✗ **Modified system tools** (unusual modification dates)
* ✗ **Paths from temp/external media**
* ✗ **Known malware** filenames
* ✗ **Recent entries** during incident window

**Investigation Pattern:**

```bash
ShimCache shows:
- C:\Users\Public\update.exe
- Last Modified: 2024-11-29 14:23

File check:
- File no longer exists on disk
- Not in Prefetch (may have been deleted)
- Found in Amcache with suspicious SHA1

Conclusion:
- File was present on system
- Likely deleted by attacker
- Amcache SHA1 identifies as malware
```

***

**Step 4: Check BAM/DAM for Very Recent Activity**

**Location:** `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}`

**Why Fourth:**

* Very recent activity (last 7 days)
* Last execution timestamp
* Per-user attribution

**PowerShell - Parse BAM:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Parse BAM for recent execution (covered in previous document)
#>

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"

if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object {
        $sid = $_.PSChildName
        Write-Host "`n[*] User SID: $sid" -ForegroundColor Yellow
        
        Get-ItemProperty $_.PSPath | ForEach-Object {
            $_.PSObject.Properties | Where-Object {
                $_.Name -like "*\*"
            } | ForEach-Object {
                $exePath = $_.Name
                $rawTime = $_.Value
                
                if ($rawTime -and $rawTime.Length -ge 8) {
                    try {
                        $time = [DateTime]::FromFileTime([BitConverter]::ToInt64($rawTime, 0))
                        
                        [PSCustomObject]@{
                            Executable = $exePath
                            LastExecuted = $time
                            SID = $sid
                        }
                    } catch {}
                }
            }
        }
    } | Sort-Object LastExecuted -Descending | Format-Table -AutoSize
}
```
{% endcode %}

***

**Step 5: Check UserAssist for GUI Application Execution**

**Location:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

**Why Fifth:**

* Proves GUI application execution
* Run count available
* Focus time (time in foreground)

**IMPORTANT:** Values are ROT-13 encoded

**PowerShell - Decode ROT-13:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Decode UserAssist entries (ROT-13)
#>

function Decode-ROT13 {
    param([string]$Text)
    
    $result = ""
    foreach ($char in $Text.ToCharArray()) {
        if ($char -match '[A-Ma-m]') {
            $result += [char]([int]$char + 13)
        } elseif ($char -match '[N-Zn-z]') {
            $result += [char]([int]$char - 13)
        } else {
            $result += $char
        }
    }
    return $result
}

Write-Host "[+] Parsing UserAssist..." -ForegroundColor Cyan

$userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

Get-ChildItem $userAssistPath | ForEach-Object {
    $guid = $_.PSChildName
    Write-Host "`n[*] GUID: $guid" -ForegroundColor Yellow
    
    $countPath = Join-Path $_.PSPath "Count"
    if (Test-Path $countPath) {
        Get-Item $countPath | ForEach-Object {
            $_.Property | ForEach-Object {
                $encoded = $_
                $decoded = Decode-ROT13 $encoded
                
                if ($decoded -notlike "UEME_*") {
                    Write-Host "  $decoded" -ForegroundColor Cyan
                }
            }
        }
    }
}
```
{% endcode %}

**UserAssist GUIDs:**

* `CEBFF5CD` - Executable file execution
* `F4E57C4B` - Shortcut file execution

**UserAssist Metadata:**

```bash
Binary value contains:
- Last execution time
- Number of executions
- Focus count (times in foreground)
- Focus time (total time in foreground)
```

***

#### Complete Execution Analysis Script

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Comprehensive execution artifact analysis
.DESCRIPTION
    Analyzes multiple execution artifacts for malware detection
#>

param(
    [string]$OutputPath = "C:\Cases\ExecutionAnalysis",
    [int]$Days = 7
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      EXECUTION ARTIFACT ANALYSIS                          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Analysis Period: Last $Days days" -ForegroundColor Yellow
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

$cutoffDate = (Get-Date).AddDays(-$Days)

# ============================================================================
# 1. PREFETCH ANALYSIS
# ============================================================================
Write-Host "[1/6] Analyzing Prefetch..." -ForegroundColor Yellow
$prefetchOutput = "$OutputPath\01_Prefetch_Analysis.txt"

"=" * 80 | Out-File $prefetchOutput
"PREFETCH ANALYSIS - $(Get-Date)" | Out-File $prefetchOutput -Append
"=" * 80 | Out-File $prefetchOutput -Append

$prefetchPath = "C:\Windows\Prefetch"

if (Test-Path $prefetchPath) {
    # Check status
    $prefetchStatus = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher
    "`nPrefetch Status: $($prefetchStatus.EnablePrefetcher)" | Out-File $prefetchOutput -Append
    
    # Get recent files
    $recentPrefetch = Get-ChildItem "$prefetchPath\*.pf" | 
        Where-Object { $_.LastWriteTime -gt $cutoffDate } |
        Sort-Object LastWriteTime -Descending
    
    "`nRecent Prefetch Files: $($recentPrefetch.Count)" | Out-File $prefetchOutput -Append
    
    # Suspicious keywords
    $suspiciousKeywords = @(
        "*MIMIKATZ*", "*PROCDUMP*", "*PSEXEC*", "*COBALT*",
        "*METERPRETER*", "*NETCAT*", "*PWDUMP*", "*WCEAUX*"
    )
    
    "`n--- SUSPICIOUS EXECUTABLES ---" | Out-File $prefetchOutput -Append
    $foundSuspicious = $false
    
    foreach ($keyword in $suspiciousKeywords) {
        $matches = $recentPrefetch | Where-Object { $_.Name -like $keyword }
        if ($matches) {
            $foundSuspicious = $true
            foreach ($match in $matches) {
                "[!] $($match.Name) - $($match.LastWriteTime)" | Out-File $prefetchOutput -Append
            }
        }
    }
    
    if (-not $foundSuspicious) {
        "No suspicious prefetch files detected" | Out-File $prefetchOutput -Append
    }
    
    "`n--- ALL RECENT PREFETCH (Last $Days days) ---" | Out-File $prefetchOutput -Append
    $recentPrefetch | ForEach-Object {
        "$($_.LastWriteTime) | $($_.Name)" | Out-File $prefetchOutput -Append
    }
    
    Write-Host "  [✓] Prefetch analysis complete" -ForegroundColor Green
} else {
    "[!] Prefetch directory not found" | Out-File $prefetchOutput
    Write-Host "  [!] Prefetch not available" -ForegroundColor Red
}

# ============================================================================
# 2. AMCACHE CHECK
# ============================================================================
Write-Host "[2/6] Checking Amcache..." -ForegroundColor Yellow
$amcacheOutput = "$OutputPath\02_Amcache_Check.txt"

"=" * 80 | Out-File $amcacheOutput
"AMCACHE CHECK - $(Get-Date)" | Out-File $amcacheOutput -Append
"=" * 80 | Out-File $amcacheOutput -Append

$amcachePath = "C:\Windows\AppCompat\Programs\Amcache.hve"

if (Test-Path $amcachePath) {
    $file = Get-Item $amcachePath
    "`nAmcache found:" | Out-File $amcacheOutput -Append
    "  Size: $([math]::Round($file.Length / 1MB, 2)) MB" | Out-File $amcacheOutput -Append
    "  Last Modified: $($file.LastWriteTime)" | Out-File $amcacheOutput -Append
    "`n[!] Parse with AmcacheParser for SHA1 hashes:" | Out-File $amcacheOutput -Append
    "    AmcacheParser.exe -f '$amcachePath' --csv '$OutputPath' --csvf amcache.csv -i" | Out-File $amcacheOutput -Append
    
    Write-Host "  [✓] Amcache found" -ForegroundColor Green
} else {
    "[!] Amcache not found" | Out-File $amcacheOutput
    Write-Host "  [!] Amcache not found" -ForegroundColor Red
}

# ============================================================================
# 3. BAM/DAM ANALYSIS
# ============================================================================
Write-Host "[3/6] Analyzing BAM/DAM..." -ForegroundColor Yellow
$bamOutput = "$OutputPath\03_BAM_Execution.txt"

"=" * 80 | Out-File $bamOutput
"BAM/DAM EXECUTION ANALYSIS - $(Get-Date)" | Out-File $bamOutput -Append
"=" * 80 | Out-File $bamOutput -Append

$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"

if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object {
        $sid = $_.PSChildName
        "`n--- User SID: $sid ---" | Out-File $bamOutput -Append
        
        Get-ItemProperty $_.PSPath | ForEach-Object {
            $_.PSObject.Properties | Where-Object {
                $_.Name -like "*\*"
            } | ForEach-Object {
                $exePath = $_.Name
                $rawTime = $_.Value
                
                if ($rawTime -and $rawTime.Length -ge 8) {
                    try {
                        $time = [DateTime]::FromFileTime([BitConverter]::ToInt64($rawTime, 0))
                        "$time | $exePath" | Out-File $bamOutput -Append
                    } catch {}
                }
            }
        }
    }
    
    Write-Host "  [✓] BAM/DAM analysis complete" -ForegroundColor Green
} else {
    "[!] BAM not found (may not be available on this OS version)" | Out-File $bamOutput
    Write-Host "  [!] BAM not available" -ForegroundColor Gray
}

# ============================================================================
# 4. USERASSIST ANALYSIS
# ============================================================================
Write-Host "[4/6] Analyzing UserAssist..." -ForegroundColor Yellow
$userAssistOutput = "$OutputPath\04_UserAssist.txt"

"=" * 80 | Out-File $userAssistOutput
"USERASSIST ANALYSIS - $(Get-Date)" | Out-File $userAssistOutput -Append
"=" * 80 | Out-File $userAssistOutput -Append
"`n[!] Values are ROT-13 encoded" | Out-File $userAssistOutput -Append

# ROT-13 decoder
function Decode-ROT13 {
    param([string]$Text)
    $result = ""
    foreach ($char in $Text.ToCharArray()) {
        if ($char -match '[A-Ma-m]') {
            $result += [char]([int]$char + 13)
        } elseif ($char -match '[N-Zn-z]') {
            $result += [char]([int]$char - 13)
        } else {
            $result += $char
        }
    }
    return $result
}

$userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

if (Test-Path $userAssistPath) {
    Get-ChildItem $userAssistPath | ForEach-Object {
        $guid = $_.PSChildName
        "`n--- GUID: $guid ---" | Out-File $userAssistOutput -Append
        
        $countPath = Join-Path $_.PSPath "Count"
        if (Test-Path $countPath) {
            Get-Item $countPath | ForEach-Object {
                $_.Property | ForEach-Object {
                    $encoded = $_
                    $decoded = Decode-ROT13 $encoded
                    
                    if ($decoded -notlike "UEME_*") {
                        "  $decoded" | Out-File $userAssistOutput -Append
                    }
                }
            }
        }
    }
    
    Write-Host "  [✓] UserAssist analysis complete" -ForegroundColor Green
} else {
    "[!] UserAssist not found" | Out-File $userAssistOutput
    Write-Host "  [!] UserAssist not found" -ForegroundColor Red
}

# ============================================================================
# 5. JUMP LIST CHECK
# ============================================================================
Write-Host "[5/6] Checking Jump Lists..." -ForegroundColor Yellow
$jumpListOutput = "$OutputPath\05_Jump_Lists.txt"

"=" * 80 | Out-File $jumpListOutput
"JUMP LIST ANALYSIS - $(Get-Date)" | Out-File $jumpListOutput -Append
"=" * 80 | Out-File $jumpListOutput -Append

$autoDestPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
$customDestPath = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"

if (Test-Path $autoDestPath) {
    $autoJumpLists = Get-ChildItem $autoDestPath -ErrorAction SilentlyContinue
    "`nAutomatic Destinations: $($autoJumpLists.Count) files" | Out-File $jumpListOutput -Append
    
    if ($autoJumpLists) {
        "`nRecent Jump Lists:" | Out-File $jumpListOutput -Append
        $autoJumpLists | Sort-Object LastWriteTime -Descending | Select-Object -First 20 | ForEach-Object {
            "  $($_.LastWriteTime) | $($_.Name)" | Out-File $jumpListOutput -Append
        }
    }
}

if (Test-Path $customDestPath) {
    $customJumpLists = Get-ChildItem $customDestPath -ErrorAction SilentlyContinue
    "`nCustom Destinations: $($customJumpLists.Count) files" | Out-File $jumpListOutput -Append
}

"`n[!] Parse with JLECmd for detailed analysis:" | Out-File $jumpListOutput -Append
"    JLECmd.exe -d '$autoDestPath' --csv '$OutputPath' --csvf jumplists.csv -q" | Out-File $jumpListOutput -Append

Write-Host "  [✓] Jump List check complete" -ForegroundColor Green

# ============================================================================
# 6. SUSPICIOUS INDICATOR SUMMARY
# ============================================================================
Write-Host "[6/6] Generating Suspicious Indicator Summary..." -ForegroundColor Yellow
$suspiciousOutput = "$OutputPath\06_Suspicious_Indicators.txt"

"=" * 80 | Out-File $suspiciousOutput
"SUSPICIOUS INDICATOR SUMMARY - $(Get-Date)" | Out-File $suspiciousOutput -Append
"=" * 80 | Out-File $suspiciousOutput -Append

# Known attack tools
$attackTools = @(
    "mimikatz", "procdump", "psexec", "cobalt", "beacon",
    "meterpreter", "netcat", "nc64", "pwdump", "gsecdump",
    "wceaux", "fgdump", "cachedump", "metasploit", "empire"
)

"`n[*] Scanning for known attack tools..." | Out-File $suspiciousOutput -Append

$toolsFound = $false
if (Test-Path $prefetchPath) {
    $allPrefetch = Get-ChildItem "$prefetchPath\*.pf"
    
    foreach ($tool in $attackTools) {
        $matches = $allPrefetch | Where-Object { $_.Name -like "*$tool*" }
        if ($matches) {
            $toolsFound = $true
            "`n[!] FOUND: $tool" | Out-File $suspiciousOutput -Append
            foreach ($match in $matches) {
                "    $($match.Name) - $($match.LastWriteTime)" | Out-File $suspiciousOutput -Append
            }
        }
    }
}

if (-not $toolsFound) {
    "`n[+] No known attack tools detected in Prefetch" | Out-File $suspiciousOutput -Append
}

Write-Host "  [✓] Suspicious indicator summary complete" -ForegroundColor Green

# ============================================================================
# GENERATE SUMMARY
# ============================================================================
$summaryOutput = "$OutputPath\00_INVESTIGATION_SUMMARY.txt"

@"
╔════════════════════════════════════════════════════════════════════════════╗
║           EXECUTION ARTIFACT ANALYSIS SUMMARY                              ║
╚════════════════════════════════════════════════════════════════════════════╝

Investigation Date: $(Get-Date)
Computer: $env:COMPUTERNAME
Analysis Period: Last $Days days
Analyst: $env:USERNAME

ARTIFACTS ANALYZED:
────────────────────────────────────────────────────────────────────────────
[✓] Prefetch (Proves execution, run count, last 8 runs)
[✓] Amcache (SHA1 hashes, file metadata - presence only)
[✓] BAM/DAM (Last execution per user - last 7 days)
[✓] UserAssist (GUI execution, run count)
[✓] Jump Lists (Application file access)

OUTPUT FILES:
────────────────────────────────────────────────────────────────────────────
01_Prefetch_Analysis.txt      → Recent executions and suspicious tools
02_Amcache_Check.txt           → SHA1 hash availability
03_BAM_Execution.txt           → Very recent execution (7 days)
04_UserAssist.txt              → GUI application usage
05_Jump_Lists.txt              → Application file associations
06_Suspicious_Indicators.txt   → Known attack tool detection

CRITICAL NEXT STEPS:
────────────────────────────────────────────────────────────────────────────
1. Parse Prefetch with PECmd for full timeline:
   PECmd.exe -d "C:\Windows\Prefetch" --csv "$OutputPath" --csvf prefetch.csv -q -k "mimikatz,psexec,procdump,temp,appdata"

2. Parse Amcache for SHA1 hashes:
   AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "$OutputPath" --csvf amcache.csv -i

3. Parse ShimCache for historical presence:
   AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv "$OutputPath" --csvf shimcache.csv

4. Parse Jump Lists for file access:
   JLECmd.exe -d "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations" --csv "$OutputPath" --csvf jumplists.csv -q

5. Check suspicious SHA1 hashes on VirusTotal

6. Build complete execution timeline using TimelineExplorer

KEY INVESTIGATION PRINCIPLES:
────────────────────────────────────────────────────────────────────────────
PROVES EXECUTION:
✓ Prefetch (definitive proof)
✓ BAM/DAM (last execution)
✓ UserAssist (GUI apps)
✓ Event 4688 (process creation)

PROVES PRESENCE (NOT EXECUTION):
✗ Amcache (Win7+)
✗ ShimCache (Win10+)
✗ MFT

CRITICAL UNDERSTANDING:
→ Multiple prefetch files for same executable = different locations
→ Prefetch .pf creation ≠ successful execution (may have crashed)
→ Amcache SHA1 is CRITICAL for malware identification
→ ShimCache (Win10+) does NOT prove execution
→ Always correlate multiple artifacts

DETECTION PATTERNS:
────────────────────────────────────────────────────────────────────────────
→ Prefetch from temp/appdata directories
→ Known attack tools (mimikatz, procdump, psexec)
→ Multiple prefetch for standard Windows tools (cmd.exe, powershell.exe)
→ Execution during off-hours or incident window
→ SHA1 hashes matching known malware

TOOLS REQUIRED:
────────────────────────────────────────────────────────────────────────────
✓ PECmd.exe (Prefetch parser)
✓ AmcacheParser.exe (Amcache parser)
✓ AppCompatCacheParser.exe (ShimCache parser)
✓ JLECmd.exe (Jump List parser)
✓ TimelineExplorer.exe (Timeline analysis)

Download: https://ericzimmerman.github.io/

════════════════════════════════════════════════════════════════════════════
"@ | Out-File $summaryOutput

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║            ANALYSIS COMPLETE                               ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host "`nResults: $OutputPath" -ForegroundColor Cyan
Write-Host "Review: 00_INVESTIGATION_SUMMARY.txt`n" -ForegroundColor Yellow

Write-Host "[!] CRITICAL: Parse artifacts with Zimmerman Tools for full analysis" -ForegroundColor Red
Write-Host "    PECmd.exe -d 'C:\Windows\Prefetch' --csv '$OutputPath' --csvf prefetch.csv -q`n" -ForegroundColor White
```
{% endcode %}

***

### Workflow 2: Persistence Mechanism Detection

**Scenario:** Detect malware persistence mechanisms

#### AutoStart Extension Points (ASEP)

**Critical Locations:**

**Registry Run Keys:**

```bash
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

**Winlogon:**

```bash
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
```

**Startup Folder:**

```
%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

**PowerShell - Check All ASEP Locations:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Check all AutoStart Extension Points for persistence
#>

Write-Host "[+] Checking AutoStart Extension Points..." -ForegroundColor Cyan

# Run Keys
Write-Host "`n--- HKLM Run Keys ---" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | 
    Select-Object * -ExcludeProperty PS* | Format-List

Write-Host "`n--- HKCU Run Keys ---" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Select-Object * -ExcludeProperty PS* | Format-List

# Winlogon
Write-Host "`n--- Winlogon ---" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
    Select-Object Shell, Userinit | Format-List

# Startup folder
Write-Host "`n--- Startup Folder ---" -ForegroundColor Yellow
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupPath) {
    Get-ChildItem $startupPath | Select-Object Name, LastWriteTime
}

Write-Host "`n[!] For comprehensive ASEP analysis, use Autoruns or RECmd" -ForegroundColor Cyan
```
{% endcode %}

**Using Autoruns (Sysinternals):**

```bash
autorunsc64.exe -accepteula -a * -s -h -c > autoruns_output.csv

Flags:
-a * : Show all startup locations
-s : Verify digital signatures
-h : Show file hashes
-c : Output as CSV
```

***

### Workflow 3: File System Artifacts

#### Master File Table ($MFT)

**Location:** Root of NTFS volume (hidden system file)

**Forensic Value:**

* Every file/folder on NTFS volume
* Timestamps (MACB - Modified, Accessed, Changed, Born)
* File size, attributes
* Deleted file records (may persist)

**Using MFTECmd (Zimmerman Tool):**

```cmd
REM Parse MFT
MFTECmd.exe -f "C:\$MFT" --csv "C:\Cases\Output" --csvf mft.csv

REM Filter for executables
MFTECmd.exe -f "C:\$MFT" --csv "C:\Cases\Output" --csvf mft_exe.csv --de
```

#### USN Journal ($J)

**Location:** `$Extend\$UsnJrnl:$J`

**Forensic Value:**

* File system change journal
* Records create, delete, rename operations
* Timestamps for file activity
* **Shows files that were deleted**

**Using MFTECmd:**

```cmd
REM Parse USN Journal
MFTECmd.exe -f "C:\$Extend\$UsnJrnl:$J" --csv "C:\Cases\Output" --csvf usnjrnl.csv
```

#### $LogFile

**Location:** Root of NTFS volume

**Forensic Value:**

* NTFS transaction log
* File operations (create, delete, modify, rename)
* Even more detailed than USN Journal

**Using LogFileParser:**

```cmd
LogFileParser.exe -f "C:\$LogFile" --csv "C:\Cases\Output"
```

***

### Workflow 4: Alternate Data Streams (ADS)

**Description:** Hidden data streams attached to files (NTFS only)

**Malware Use Cases:**

* Hide malicious code in legitimate files
* Store hacking tools invisibly
* Evade antivirus detection

**PowerShell - Find ADS:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Detect Alternate Data Streams
#>

param(
    [string]$Path = "C:\Users",
    [string]$OutputPath = "C:\Cases\ADS_Detection.txt"
)

Write-Host "[+] Scanning for Alternate Data Streams..." -ForegroundColor Cyan

$adsFiles = Get-ChildItem $Path -Recurse -ErrorAction SilentlyContinue | 
    Get-Item -Stream * -ErrorAction SilentlyContinue | 
    Where-Object { $_.Stream -ne ':$DATA' } |
    Select-Object PSPath, Stream, Length

if ($adsFiles) {
    Write-Host "[!] Found $($adsFiles.Count) files with ADS" -ForegroundColor Red
    
    $adsFiles | Out-File $OutputPath
    $adsFiles | Format-Table -AutoSize
    
    Write-Host "`n[*] Results saved to: $OutputPath" -ForegroundColor Yellow
} else {
    Write-Host "[+] No ADS detected" -ForegroundColor Green
}
```
{% endcode %}

**Manual ADS Commands:**

```bash
REM List ADS on file
dir /r file.txt

REM View ADS content
more < file.txt:hidden_stream

REM Extract ADS
type file.txt:hidden_stream > extracted.exe

REM Delete ADS
more < nul > file.txt:hidden_stream
```

**Zone.Identifier ADS:**

```bash
Files downloaded from internet get Zone.Identifier ADS
Contains URL source and zone information

Check with:
more < file.exe:Zone.Identifier
```

***

### Investigation Checklists

#### Malware Execution Investigation

* \[ ] Check Prefetch for known malware tools
* \[ ] Look for multiple prefetch files for standard tools (cmd.exe, etc.)
* \[ ] Extract SHA1 hashes from Amcache
* \[ ] Search SHA1 on VirusTotal
* \[ ] Check ShimCache for deleted executables
* \[ ] Review BAM/DAM for recent execution
* \[ ] Parse UserAssist for GUI application usage
* \[ ] Check for executables in suspicious paths
* \[ ] Build execution timeline with all artifacts
* \[ ] Cross-reference with network/file access artifacts

#### Persistence Investigation

* \[ ] Check all Run/RunOnce keys (HKLM and HKCU)
* \[ ] Verify Winlogon Shell and Userinit values
* \[ ] Check Startup folder for suspicious items
* \[ ] Review Services for malicious entries
* \[ ] Check Scheduled Tasks
* \[ ] Look for DLL hijacking indicators
* \[ ] Scan for ADS on system files
* \[ ] Use Autoruns for comprehensive ASEP check
* \[ ] Document all persistence mechanisms found

#### Timeline Construction

* \[ ] Parse Prefetch to CSV
* \[ ] Parse Amcache to CSV
* \[ ] Parse ShimCache to CSV
* \[ ] Parse BAM/DAM to CSV
* \[ ] Parse Jump Lists to CSV
* \[ ] Merge all CSVs in TimelineExplorer
* \[ ] Sort by timestamp
* \[ ] Filter by incident window
* \[ ] Correlate execution with file/network activity
* \[ ] Document complete attack timeline

***

### Critical Detection Patterns

#### Suspicious Prefetch Patterns

```bash
RED FLAGS:
✗ MIMIKATZ.EXE-*.pf
✗ PROCDUMP.EXE-*.pf or PROCDUMP64.EXE-*.pf
✗ PSEXEC.EXE-*.pf (lateral movement)
✗ Multiple CMD.EXE-*.pf (different hashes)
✗ Multiple POWERSHELL.EXE-*.pf (different hashes)
✗ Files from C:\Users\Public, C:\Temp, %APPDATA%
```

#### Suspicious Amcache Indicators

```bash
RED FLAGS:
✗ No digital signature (unsigned executables)
✗ SHA1 matches known malware
✗ Publisher: (blank) or suspicious
✗ Executables from temp directories
✗ Recently installed during incident window
```

#### Suspicious ShimCache Indicators

```bash
RED FLAGS:
✗ Executables that no longer exist
✗ Modified system tools
✗ Files from external media
✗ Malware-named files (even if deleted)
```

***

### Real Investigation Scenario

#### Case Study: Mimikatz Execution Detection

**Evidence Chain:**

**1. Prefetch Analysis:**

```bash
Found: MIMIKATZ.EXE-A3F8B2C9.pf
Location: C:\Users\Public\mimikatz.exe (from FilesLoaded)
Run Count: 3
Last Run: 2024-11-29 14:23:45
Previous Runs: 14:15:30, 14:10:22
DLLs Loaded: cryptdll.dll, samlib.dll (credential access indicators)
```

**2. Amcache Analysis:**

```bash
Found: C:\Users\Public\mimikatz.exe
SHA1: f3b25701fe362ec84616a93a45ce9994
File Size: 1,256,960 bytes
Publisher: (none)
Compilation Date: 2024-01-15
```

**3. VirusTotal Check:**

```bash
SHA1: f3b25701fe362ec84616a93a45ce9994
Detection: 45/70 AV vendors
Name: Mimikatz credential dumper
```

**4. ShimCache Analysis:**

```bash
Found: C:\Users\Public\mimikatz.exe
Last Modified: 2024-11-29 14:10:00
Note: File no longer exists on disk (attacker deleted it)
```

**5. BAM Analysis:**

```bash
User SID: S-1-5-21-....-1001 (Bob's account)
Last Execution: 2024-11-29 14:23:45
Path: C:\Users\Public\mimikatz.exe
```

**6. Timeline:**

```bash
14:10:00 - File created (ShimCache last modified)
14:10:22 - First execution (Prefetch)
14:15:30 - Second execution (Prefetch)
14:23:45 - Third execution (Prefetch, BAM)
14:25:00 - File deleted (no longer on disk)
```

**Conclusion:**

* Mimikatz definitively executed 3 times
* Used by Bob's account
* Credential dumping activity
* Attacker attempted cleanup (file deleted)
* Evidence survived via Prefetch, Amcache, ShimCache

***

### Summary: Key Takeaways

#### Most Critical Artifacts (Top 3)

1. **Prefetch** - Proves execution, run count, timeline
2. **Amcache** - SHA1 hashes for definitive identification
3. **ShimCache** - Historical presence even if deleted

#### Execution Proof Hierarchy

**Definitive Proof:**

* ✓ Prefetch file exists
* ✓ Event 4688 logged
* ✓ UserAssist entry (GUI apps)

**Strong Indicator:**

* ⚠ BAM/DAM entry (very recent)
* ⚠ Jump List entry (application used file)

**Presence Only (NOT execution):**

* ✗ Amcache entry (Win7+)
* ✗ ShimCache entry (Win10+)
* ✗ MFT record

#### Critical Commands

{% code overflow="wrap" %}
```cmd
REM Prefetch analysis
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Output" --csvf prefetch.csv -q

REM Amcache SHA1 extraction
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Output" --csvf amcache.csv -i

REM ShimCache historical analysis
AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv "C:\Output" --csvf shimcache.csv

REM Jump List analysis
JLECmd.exe -d "C:\Users" --csv "C:\Output" --csvf jumplists.csv -q

REM ASEP comprehensive check
autorunsc64.exe -accepteula -a * -s -h -c > autoruns.csv
```
{% endcode %}

#### Key Principle

**Execution artifact analysis requires correlation of multiple sources. Prefetch proves execution, Amcache provides SHA1 for identification, ShimCache shows historical presence. Always validate findings across artifacts - a single artifact is never sufficient for conclusive determination.**

\
**Target Audience:** SOC analysts, incident responders, malware analysts\
**Tools Required:** Zimmerman Tools (PECmd, AmcacheParser, AppCompatCacheParser, JLECmd), Autoruns\
**Usage:** Malware detection, execution timeline, persistence hunting

**Remember:** Prefetch = execution proof. Amcache = SHA1 identification. ShimCache = historical presence. Multiple prefetch files for standard tools (cmd.exe, powershell.exe) = potential attacker activity. Always correlate artifacts!

{% file src="../../../.gitbook/assets/SANS DFIR Windows Artifact Analysis Evidence Of Execution.pdf" %}
