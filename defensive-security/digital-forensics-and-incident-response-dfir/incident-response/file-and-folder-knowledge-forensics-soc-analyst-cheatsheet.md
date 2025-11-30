# File & Folder Knowledge Forensics - SOC Analyst Cheatsheet

### Practical Guide for User Activity & Data Access Investigation

***

### Quick Reference: File/Folder Artifacts Matrix

| Artifact         | What Files   | When Accessed | Where From | Deleted Files | User Attribution | Retention      |
| ---------------- | ------------ | ------------- | ---------- | ------------- | ---------------- | -------------- |
| **Recent Files** | ✓            | ✓             | ✓          | ✓             | ✓ (Per-user)     | Last 150 files |
| **LNK Files**    | ✓            | ✓             | ✓          | ✓             | ✓ (Per-user)     | Persistent     |
| **Shell Bags**   | Folders only | ✓             | ✓          | ✓             | ✓ (Per-user)     | Persistent     |
| **Recycle Bin**  | ✓            | ✓ (Deletion)  | ✓          | ✓             | ✓ (Per-user)     | Until emptied  |

***

### Investigation Priority Matrix

| Priority     | Artifact     | Best For                             | Live/Dead | Key Value                 |
| ------------ | ------------ | ------------------------------------ | --------- | ------------------------- |
| **CRITICAL** | LNK Files    | File access proof, USB/network files | Both      | Survives file deletion    |
| **CRITICAL** | Recycle Bin  | Deleted file recovery                | Both      | Actual file content       |
| **HIGH**     | Recent Files | Recent user focus                    | Both      | Last 150 files            |
| **HIGH**     | Shell Bags   | Folder navigation                    | Both      | Network shares, USB paths |

***

### Core Investigation Questions

#### Primary Questions:

1. **What files did the user access?** (File identification)
2. **When were files accessed?** (Timeline construction)
3. **Where were files located?** (Local, USB, network share)

#### Secondary Questions:

4. **What files were deleted?** (Evidence destruction)
5. **What folders were browsed?** (User navigation patterns)
6. **Were external devices used?** (Data exfiltration vector)

***

### SOC Investigation Workflows

#### Workflow 1: Data Exfiltration Investigation (CRITICAL)

**Scenario:** Suspected data theft via USB or network transfer

**Investigation Priority Order:**

**Step 1: Check Recent File Access (Last 150 Files)** **Why first:** Shows what user was recently focused on

**Registry Location:**

```bash
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

**PowerShell - Parse Recent Files:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Parse RecentDocs registry key with file type breakdown
#>

Write-Host "[+] Parsing Recent Files..." -ForegroundColor Cyan

$recentDocsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# Get main RecentDocs (last 150 files overall)
Write-Host "`n[*] Last 150 Files Accessed (All Types):" -ForegroundColor Yellow
$mainDocs = Get-Item $recentDocsPath
$mainDocs.Property | Where-Object {$_ -match "^\d+$"} | ForEach-Object {
    $value = $mainDocs.GetValue($_)
    if ($value) {
        # Binary data - extract filename
        $filename = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00.*', ''
        if ($filename) {
            Write-Host "  $filename"
        }
    }
}

# Get by file extension (last 20 per type)
Write-Host "`n[*] Recent Files by Type (Last 20 Each):" -ForegroundColor Yellow
Get-ChildItem $recentDocsPath | Where-Object {$_.PSChildName -ne "Folder"} | ForEach-Object {
    $extension = $_.PSChildName
    Write-Host "`n  Extension: .$extension" -ForegroundColor Cyan
    
    $extKey = Get-Item $_.PSPath
    $extKey.Property | Where-Object {$_ -match "^\d+$"} | Select-Object -First 20 | ForEach-Object {
        $value = $extKey.GetValue($_)
        if ($value) {
            $filename = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00.*', ''
            if ($filename) {
                Write-Host "    $filename"
            }
        }
    }
}

# Get recent folders (last 30)
Write-Host "`n[*] Recent Folders Accessed (Last 30):" -ForegroundColor Yellow
$folderKey = Get-Item "$recentDocsPath\Folder" -ErrorAction SilentlyContinue
if ($folderKey) {
    $folderKey.Property | Where-Object {$_ -match "^\d+$"} | Select-Object -First 30 | ForEach-Object {
        $value = $folderKey.GetValue($_)
        if ($value) {
            $foldername = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00.*', ''
            if ($foldername) {
                Write-Host "  $foldername"
            }
        }
    }
}
```
{% endcode %}

**Red Flags in Recent Files:**

* ✗ Sensitive documents (HR, financial, confidential)
* ✗ Large number of similar files (bulk access)
* ✗ Files from restricted folders
* ✗ Database exports (.csv, .xlsx, .sql)
* ✗ Configuration files (.conf, .cfg, .ini)
* ✗ Credential files (passwords.txt, accounts.xlsx)

***

**Step 2: Analyse LNK Files (Detailed File Access)** **Why second:** Provides precise timestamps, file paths, volume info

**Location:**

```bash
C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\{username}\AppData\Roaming\Microsoft\Office\Recent\
```

**PowerShell - List Recent LNK Files:**

{% code overflow="wrap" %}
```powershell
# List LNK files by date
Write-Host "`n[+] Recent LNK Files (Last 50):" -ForegroundColor Cyan
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 50 | 
    ForEach-Object {
        Write-Host "  $($_.LastWriteTime) - $($_.Name)" -ForegroundColor Yellow
    }

# Check Office Recent
Write-Host "`n[+] Recent Office Files:" -ForegroundColor Cyan
Get-ChildItem "$env:APPDATA\Microsoft\Office\Recent\*.lnk" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    ForEach-Object {
        Write-Host "  $($_.LastWriteTime) - $($_.Name)" -ForegroundColor Yellow
    }
```
{% endcode %}

**Using LECmd (Zimmerman Tool) - RECOMMENDED:**

{% code overflow="wrap" %}
```cmd
REM Single LNK file analysis
LECmd.exe -f "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\secret_data.xlsx.lnk"

REM Entire Recent directory
LECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\Output" --csvf lnk_analysis.csv -q

REM All users on system
LECmd.exe -d "C:\Users" --csv "C:\Cases\Output" --csvf all_users_lnk.csv -q

REM Filter for USB/removable drives
LECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\Output" --csvf lnk_analysis.csv -q
REM Then filter CSV for DriveType = "Removable"
```
{% endcode %}

**Critical LNK Metadata:**

* Target file path (including USB/network paths)
* Volume serial number (links to specific USB device)
* Volume type (Fixed, Removable, Network)
* Target file timestamps (Created, Modified, Accessed)
* File size
* Network share information (\server\share)
* MAC address (network shares)

**Red Flags in LNK Files:**

* ✗ **Volume Type = "Removable"** → USB/external drive access
* ✗ **Network paths (\server\share)** → Data copied to network
* ✗ **Recently deleted files** → LNK persists after deletion
* ✗ **Large files** → Potential data exfiltration
* ✗ **Multiple similar files** → Bulk data access
* ✗ **Personal storage paths** → OneDrive, Dropbox, Google Drive

**Data Exfiltration Indicators:**

```bash
Timeline Pattern:
1. Access to sensitive documents (HR, financial)
2. Copy to USB drive (Volume Type = Removable)
3. OR copy to network share (\\personal-nas\data)
4. Original files deleted (Recycle Bin check)
5. LNK files remain as evidence
```

***

**Step 3: Check Shell Bags (Folder Navigation)** **Why third:** Shows folders browsed, including external/network locations

**Registry Location:**

```bash
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
```

**File Location:**

```bash
C:\Users\{username}\NTUSER.DAT
C:\Users\{username}\AppData\Local\Microsoft\Windows\UsrClass.dat
```

**Using SBECmd (Zimmerman Tool):**

```cmd
REM Single user analysis
SBECmd.exe -d "C:\Users\Alice" --csv "C:\Cases\Output" --csvf shellbags_alice.csv

REM All users
SBECmd.exe -d "C:\Users" --csv "C:\Cases\Output" --csvf shellbags_all.csv

REM Live system (current user)
SBECmd.exe -l --csv "C:\Cases\Output" --csvf shellbags_live.csv
```

**Shell Bags Forensic Value:**

* Folder names and full paths
* Folder interaction timestamps (last accessed)
* Network share paths (\server\share\folder)
* USB device paths (E:\SecretData)
* Zip files, ISOs, mounted containers
* Folders even if now deleted

**Red Flags in Shell Bags:**

* ✗ Access to HR/Finance/Confidential folders
* ✗ Browsing of network shares (lateral movement)
* ✗ USB drive folder navigation
* ✗ Temp/staging folders (C:\Temp\ToExfil)
* ✗ Cloud sync folders (OneDrive, Dropbox)
* ✗ Deleted folder paths (folder no longer exists)

**Data Exfiltration Pattern:**

```bash
Shell Bag Evidence:
1. Browsed: C:\Finance\Payroll\2024\
2. Browsed: E:\DataCopy\  (USB drive)
3. Browsed: \\HomeNAS\Backup\Work\
```

***

**Step 4: Examine Recycle Bin (Deleted Files)** **Why fourth:** May contain actual deleted files or evidence of deletion

**Location:**

```bash
C:\$Recycle.Bin\{User-SID}\
```

**File Structure:**

* `$I######.ext` - Metadata (original path, filename, deletion time)
* `$R######.ext` - Actual file contents

**Quick Command - Browse Recycle Bin:**

```bash
REM Navigate to Recycle Bin
cd C:\$Recycle.Bin
dir /a

REM List user folders (SIDs)
dir

REM Enter specific user folder
cd S-1-5-21-...

REM List deleted items
dir

REM View original filename/path
type $I123456.xlsx

REM Copy deleted file for analysis
copy $R123456.xlsx C:\Cases\recovered_file.xlsx
```

**PowerShell - Enumerate Recycle Bin:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Enumerate Recycle Bin contents with metadata
#>

Write-Host "`n[+] Enumerating Recycle Bin..." -ForegroundColor Cyan

$recycleBin = "C:\$Recycle.Bin"
Get-ChildItem $recycleBin -Directory -Force | ForEach-Object {
    $userSid = $_.Name
    Write-Host "`n[*] User SID: $userSid" -ForegroundColor Yellow
    
    # Try to resolve SID to username
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($userSid)
        $username = $objSID.Translate([System.Security.Principal.NTAccount]).Value
        Write-Host "    Username: $username" -ForegroundColor Green
    } catch {
        Write-Host "    Username: Unable to resolve" -ForegroundColor Red
    }
    
    # List deleted items
    $userRecycleBin = Join-Path $recycleBin $userSid
    $deletedItems = Get-ChildItem $userRecycleBin -Force | Where-Object {$_.Name -like '$I*'}
    
    if ($deletedItems) {
        Write-Host "    Deleted Items:" -ForegroundColor Cyan
        foreach ($item in $deletedItems) {
            Write-Host "      $($item.Name) - Deleted: $($item.CreationTime)"
        }
    } else {
        Write-Host "    (Empty)" -ForegroundColor Gray
    }
}
```
{% endcode %}

**Using RBCmd (Zimmerman Tool):**

{% code overflow="wrap" %}
```cmd
REM Parse single $I file
RBCmd.exe -f "C:\$Recycle.Bin\{SID}\$I123456.xlsx"

REM Parse entire user's Recycle Bin
RBCmd.exe -d "C:\$Recycle.Bin\{SID}" --csv "C:\Cases\Output" --csvf recycle_bin.csv -q

REM Parse all users
RBCmd.exe -d "C:\$Recycle.Bin" --csv "C:\Cases\Output" --csvf all_recycle_bins.csv -q
```
{% endcode %}

**Recycle Bin Metadata:**

* Original filename and path
* Deletion timestamp
* File size
* Actual file contents (in $R file)

**Red Flags in Recycle Bin:**

* ✗ Recently deleted sensitive documents
* ✗ Deletion during incident timeframe
* ✗ Large files deleted (covering tracks)
* ✗ System/log files deleted
* ✗ Evidence of bulk deletion

**Important Notes:**

```bash
Files NOT in Recycle Bin:
- Shift+Delete bypasses Recycle Bin
- Network share deletions
- Files >8GB (may bypass on some systems)
- Files deleted from command line
- Recycle Bin manually emptied
```

***

#### PowerShell Script: Comprehensive File Access Investigation

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Complete file and folder access investigation
.DESCRIPTION
    Analyses Recent Files, LNK files, Shell Bags, and Recycle Bin
.PARAMETER OutputPath
    Output directory for results
.PARAMETER Username
    Target username (optional, defaults to current user)
#>

param(
    [string]$OutputPath = "C:\Cases\FileAccessInvestigation",
    [string]$Username = $env:USERNAME
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     FILE & FOLDER ACCESS INVESTIGATION                    ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "Target User: $Username" -ForegroundColor Yellow
Write-Host "Output Path: $OutputPath`n" -ForegroundColor Yellow

# ============================================================================
# 1. RECENT FILES ANALYSIS
# ============================================================================
Write-Host "[1/4] Analysing Recent Files Registry..." -ForegroundColor Yellow
$recentOutput = "$OutputPath\01_Recent_Files.txt"

"=" * 80 | Out-File $recentOutput
"RECENT FILES ANALYSIS - $(Get-Date)" | Out-File $recentOutput -Append
"=" * 80 | Out-File $recentOutput -Append
"`nUser: $Username" | Out-File $recentOutput -Append

# Parse RecentDocs
$recentDocsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

if (Test-Path $recentDocsPath) {
    "`n--- LAST 150 FILES ACCESSED (ALL TYPES) ---" | Out-File $recentOutput -Append
    $mainDocs = Get-Item $recentDocsPath
    $count = 0
    $mainDocs.Property | Where-Object {$_ -match "^\d+$"} | ForEach-Object {
        $value = $mainDocs.GetValue($_)
        if ($value) {
            $filename = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00.*', ''
            if ($filename) {
                $count++
                "$count. $filename" | Out-File $recentOutput -Append
            }
        }
    }
    
    "`n--- RECENT FILES BY EXTENSION (LAST 20 EACH) ---" | Out-File $recentOutput -Append
    Get-ChildItem $recentDocsPath | Where-Object {$_.PSChildName -ne "Folder"} | ForEach-Object {
        $extension = $_.PSChildName
        "`nExtension: .$extension" | Out-File $recentOutput -Append
        "-" * 40 | Out-File $recentOutput -Append
        
        $extKey = Get-Item $_.PSPath
        $extKey.Property | Where-Object {$_ -match "^\d+$"} | Select-Object -First 20 | ForEach-Object {
            $value = $extKey.GetValue($_)
            if ($value) {
                $filename = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00.*', ''
                if ($filename) {
                    "  $filename" | Out-File $recentOutput -Append
                }
            }
        }
    }
    
    "`n--- RECENT FOLDERS (LAST 30) ---" | Out-File $recentOutput -Append
    $folderKey = Get-Item "$recentDocsPath\Folder" -ErrorAction SilentlyContinue
    if ($folderKey) {
        $folderKey.Property | Where-Object {$_ -match "^\d+$"} | Select-Object -First 30 | ForEach-Object {
            $value = $folderKey.GetValue($_)
            if ($value) {
                $foldername = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00.*', ''
                if ($foldername) {
                    "  $foldername" | Out-File $recentOutput -Append
                }
            }
        }
    }
    
    Write-Host "  [✓] Recent Files analysis complete" -ForegroundColor Green
} else {
    Write-Host "  [!] RecentDocs not found" -ForegroundColor Red
}

# ============================================================================
# 2. LNK FILES ANALYSIS
# ============================================================================
Write-Host "[2/4] Enumerating LNK Files..." -ForegroundColor Yellow
$lnkOutput = "$OutputPath\02_LNK_Files.txt"

"=" * 80 | Out-File $lnkOutput
"LNK FILES ENUMERATION - $(Get-Date)" | Out-File $lnkOutput -Append
"=" * 80 | Out-File $lnkOutput -Append

# Recent folder
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) {
    "`n--- RECENT FOLDER LNK FILES ---" | Out-File $lnkOutput -Append
    $lnkFiles = Get-ChildItem "$recentPath\*.lnk" | Sort-Object LastWriteTime -Descending
    
    if ($lnkFiles) {
        "Total LNK Files: $($lnkFiles.Count)" | Out-File $lnkOutput -Append
        "`nMost Recent 50:" | Out-File $lnkOutput -Append
        "-" * 80 | Out-File $lnkOutput -Append
        
        $lnkFiles | Select-Object -First 50 | ForEach-Object {
            "$($_.LastWriteTime) | $($_.Name)" | Out-File $lnkOutput -Append
        }
    } else {
        "(No LNK files found)" | Out-File $lnkOutput -Append
    }
}

# Office Recent
$officeRecentPath = "$env:APPDATA\Microsoft\Office\Recent"
if (Test-Path $officeRecentPath) {
    "`n--- OFFICE RECENT LNK FILES ---" | Out-File $lnkOutput -Append
    $officeLnk = Get-ChildItem "$officeRecentPath\*.lnk" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    
    if ($officeLnk) {
        "Total Office LNK Files: $($officeLnk.Count)" | Out-File $lnkOutput -Append
        "`nRecent Office Files:" | Out-File $lnkOutput -Append
        "-" * 80 | Out-File $lnkOutput -Append
        
        $officeLnk | ForEach-Object {
            "$($_.LastWriteTime) | $($_.Name)" | Out-File $lnkOutput -Append
        }
    } else {
        "(No Office LNK files found)" | Out-File $lnkOutput -Append
    }
}

Write-Host "  [✓] LNK Files enumeration complete" -ForegroundColor Green
Write-Host "  [!] Use LECmd.exe for detailed LNK parsing" -ForegroundColor Cyan

# ============================================================================
# 3. RECYCLE BIN ANALYSIS
# ============================================================================
Write-Host "[3/4] Analysing Recycle Bin..." -ForegroundColor Yellow
$recycleOutput = "$OutputPath\03_Recycle_Bin.txt"

"=" * 80 | Out-File $recycleOutput
"RECYCLE BIN ANALYSIS - $(Get-Date)" | Out-File $recycleOutput -Append
"=" * 80 | Out-File $recycleOutput -Append

$recycleBin = "C:\$Recycle.Bin"
if (Test-Path $recycleBin) {
    Get-ChildItem $recycleBin -Directory -Force | ForEach-Object {
        $userSid = $_.Name
        "`n--- USER SID: $userSid ---" | Out-File $recycleOutput -Append
        
        # Try to resolve SID
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($userSid)
            $resolvedUser = $objSID.Translate([System.Security.Principal.NTAccount]).Value
            "Username: $resolvedUser" | Out-File $recycleOutput -Append
        } catch {
            "Username: (Unable to resolve)" | Out-File $recycleOutput -Append
        }
        
        # List deleted items
        $userRecycleBin = Join-Path $recycleBin $userSid
        $deletedItems = Get-ChildItem $userRecycleBin -Force | Where-Object {$_.Name -like '$I*'}
        
        if ($deletedItems) {
            "`nDeleted Items: $($deletedItems.Count)" | Out-File $recycleOutput -Append
            "-" * 60 | Out-File $recycleOutput -Append
            
            foreach ($item in $deletedItems) {
                "$($item.CreationTime) | $($item.Name) | Size: $($item.Length) bytes" | Out-File $recycleOutput -Append
            }
        } else {
            "`nRecycle Bin: (Empty)" | Out-File $recycleOutput -Append
        }
    }
    
    Write-Host "  [✓] Recycle Bin analysis complete" -ForegroundColor Green
    Write-Host "  [!] Use RBCmd.exe for detailed Recycle Bin parsing" -ForegroundColor Cyan
} else {
    Write-Host "  [!] Recycle Bin not accessible" -ForegroundColor Red
}

# ============================================================================
# 4. SUSPICIOUS INDICATORS DETECTION
# ============================================================================
Write-Host "[4/4] Detecting Suspicious Indicators..." -ForegroundColor Yellow
$suspiciousOutput = "$OutputPath\04_Suspicious_Indicators.txt"

"=" * 80 | Out-File $suspiciousOutput
"SUSPICIOUS INDICATOR DETECTION - $(Get-Date)" | Out-File $suspiciousOutput -Append
"=" * 80 | Out-File $suspiciousOutput -Append

$suspiciousKeywords = @(
    "*confidential*",
    "*secret*",
    "*password*",
    "*credential*",
    "*payroll*",
    "*salary*",
    "*financial*",
    "*budget*"
)

"`n--- SUSPICIOUS FILENAME PATTERNS ---" | Out-File $suspiciousOutput -Append
"-" * 80 | Out-File $suspiciousOutput -Append

# Check RecentDocs
if (Test-Path $recentDocsPath) {
    $mainDocs = Get-Item $recentDocsPath
    $mainDocs.Property | Where-Object {$_ -match "^\d+$"} | ForEach-Object {
        $value = $mainDocs.GetValue($_)
        if ($value) {
            $filename = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00.*', ''
            if ($filename) {
                foreach ($keyword in $suspiciousKeywords) {
                    if ($filename -like $keyword) {
                        "[SUSPICIOUS] $filename" | Out-File $suspiciousOutput -Append
                        break
                    }
                }
            }
        }
    }
}

# Check LNK files
if (Test-Path $recentPath) {
    "`n--- SUSPICIOUS LNK FILES ---" | Out-File $suspiciousOutput -Append
    "-" * 80 | Out-File $suspiciousOutput -Append
    
    $lnkFiles = Get-ChildItem "$recentPath\*.lnk"
    foreach ($lnk in $lnkFiles) {
        foreach ($keyword in $suspiciousKeywords) {
            if ($lnk.Name -like $keyword) {
                "[SUSPICIOUS LNK] $($lnk.LastWriteTime) | $($lnk.Name)" | Out-File $suspiciousOutput -Append
                break
            }
        }
    }
}

Write-Host "  [✓] Suspicious indicator detection complete" -ForegroundColor Green

# ============================================================================
# 5. GENERATE SUMMARY
# ============================================================================
$summaryOutput = "$OutputPath\00_INVESTIGATION_SUMMARY.txt"

@"
╔════════════════════════════════════════════════════════════════════════════╗
║                   FILE ACCESS INVESTIGATION SUMMARY                        ║
╚════════════════════════════════════════════════════════════════════════════╝

Investigation Date: $(Get-Date)
Target User: $Username
Computer: $env:COMPUTERNAME
Analyst: $env:USERNAME

ARTIFACTS ANALYZED:
─────────────────────────────────────────────────────────────────────────────
[✓] Recent Files Registry (Last 150 files)
[✓] LNK Files (Recent folder and Office)
[✓] Recycle Bin (Deleted items)
[✓] Suspicious Indicator Detection

OUTPUT FILES:
─────────────────────────────────────────────────────────────────────────────
01_Recent_Files.txt          → Recent file access history
02_LNK_Files.txt             → LNK file enumeration
03_Recycle_Bin.txt           → Deleted items analysis
04_Suspicious_Indicators.txt → Potential IOCs detected

RECOMMENDED NEXT STEPS:
─────────────────────────────────────────────────────────────────────────────
1. Run LECmd on LNK files for detailed metadata:
   LECmd.exe -d "$recentPath" --csv "$OutputPath" --csvf lnk_detailed.csv -q

2. Run RBCmd on Recycle Bin for full analysis:
   RBCmd.exe -d "C:\$Recycle.Bin" --csv "$OutputPath" --csvf recycle_detailed.csv -q

3. Run SBECmd for Shell Bags analysis:
   SBECmd.exe -d "C:\Users\$Username" --csv "$OutputPath" --csvf shellbags.csv

4. Review suspicious indicators in 04_Suspicious_Indicators.txt

5. Build timeline correlating all artifacts

6. Cross-reference with:
   - USB device history (USBSTOR registry)
   - Network share access (MountPoints2)
   - Browser downloads
   - Email attachments

TOOLS REQUIRED:
─────────────────────────────────────────────────────────────────────────────
✓ LECmd.exe (LNK parser)
✓ RBCmd.exe (Recycle Bin parser)
✓ SBECmd.exe (Shell Bags parser)

Download: https://ericzimmerman.github.io/

INVESTIGATION FOCUS AREAS:
─────────────────────────────────────────────────────────────────────────────
→ Files accessed from USB drives (check LNK Volume Type)
→ Network share access (check LNK network paths)
→ Recently deleted sensitive files (Recycle Bin)
→ Bulk file access patterns (Recent Files)
→ Personal cloud storage usage (OneDrive, Dropbox paths)

════════════════════════════════════════════════════════════════════════════
"@ | Out-File $summaryOutput

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║            INVESTIGATION COMPLETE                          ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
Write-Host "Review: 00_INVESTIGATION_SUMMARY.txt for next steps`n" -ForegroundColor Yellow
```
{% endcode %}

***

### Workflow 2: Insider Threat Investigation

**Scenario:** Employee suspected of stealing company data before resignation

#### Investigation Checklist:

**Timeline Window:** Focus on 30 days before resignation date

**Phase 1: Document Access Pattern**

```bash
□ Recent Files - Last 150 accessed (what interested them)
□ LNK Files - Detailed access timeline
□ Office Recent - Specific document types
□ Filter for: HR, Finance, Customer, IP documents
```

**Phase 2: External Device Usage**

```bash
□ LNK files with Volume Type = "Removable"
□ Shell Bags with E:, F:, G: drive paths
□ USB device registry (USBSTOR)
□ Correlate USB serial number with LNK volume serial
```

**Phase 3: Network Activity**

```bash
□ LNK files with UNC paths (\\server\share)
□ Shell Bags with network locations
□ MountPoints2 registry for shares
□ Identify personal/external storage
```

**Phase 4: Evidence Destruction**

```bash
□ Recycle Bin for recently deleted files
□ Check for bulk deletions
□ Timing: Deletions before last day?
□ CCleaner/BleachBit execution (Prefetch)
```

**Suspicious Timeline Pattern:**

```bash
Week -4: Normal work activity
Week -3: Increased document access (Recent Files spike)
Week -2: USB device connected (LNK Volume Type = Removable)
Week -2: Large files copied to USB (LNK shows copies)
Week -1: Mass file deletions (Recycle Bin)
Week -1: Recycle Bin emptied
Last Day: Resignation submitted
```

***

### Workflow 3: Malware File Analysis

**Scenario:** Malware downloaded and executed, need to trace file origin

#### Investigation Steps:

**Step 1: Identify Malware File Access**

```bash
- Recent Files: Was malware file accessed?
- LNK Files: Malware download path (Downloads folder?)
- Timestamps: When was it first accessed?
```

**Step 2: Trace File Origin**

```bash
LNK Metadata reveals:
- Download location (C:\Users\Alice\Downloads\)
- Browser used (check Jump Lists for browser activity)
- Original filename before rename
- Network source (if downloaded from share)
```

**Step 3: Related File Activity**

```bash
- Recent Files: Other files accessed around same time
- LNK Files: Additional downloads
- Shell Bags: Folders browsed (staging location?)
```

**Step 4: Post-Infection Activity**

```bash
- Recent Files: What files did malware access?
- LNK Files: Files opened by malware process
- Recycle Bin: Files deleted by malware
```

***

### Cross-Artifact Correlation Techniques

#### Technique 1: USB Data Exfiltration Timeline

**Combine:**

1. **USBSTOR Registry** → Device connected
2. **Shell Bags** → Browsed USB folders
3. **LNK Files** → Files copied to/from USB (Volume Serial Number match)
4. **Recent Files** → What files were accessed before USB use

**Example Timeline:**

```bash
10:15 - USB device E: connected (USBSTOR)
10:16 - Browsed E:\DataCopy\ (Shell Bags)
10:17 - Accessed Confidential.xlsx (Recent Files)
10:18 - Confidential.xlsx copied to E:\ (LNK with Volume Type = Removable)
10:19 - Original file deleted (Recycle Bin)
10:20 - USB device disconnected
```

***

#### Technique 2: Network Share Data Theft

**Combine:**

1. **Shell Bags** → Network share browsed
2. **LNK Files** → Files copied to network share
3. **MountPoints2 Registry** → Share connection details
4. **Recent Files** → Files accessed before copy

**Example Timeline:**

```bash
14:30 - Mapped \\PersonalNAS\Backup (MountPoints2)
14:31 - Browsed \\PersonalNAS\Backup\Work\ (Shell Bags)
14:32 - Accessed sensitive files (Recent Files)
14:35 - Files copied to network share (LNK with UNC path)
```

***

#### Technique 3: File Deletion Investigation

**Combine:**

1. **Recycle Bin** → Deleted files list
2. **LNK Files** → Proof file existed (LNK survives deletion)
3. **Recent Files** → File was recently accessed
4. **$R file in Recycle Bin** → Actual file content (if not emptied)

**Investigation Value:**

```bash
Scenario: File deleted, Recycle Bin emptied
Evidence remaining:
✓ LNK file shows file existed, path, timestamps
✓ Recent Files shows it was accessed
✓ Shell Bags shows folder was browsed
✓ Volume Serial Number identifies source drive
```

***

### Zimmerman Tools Command Reference

#### LECmd (LNK File Parser)

**Single File:**

```cmd
LECmd.exe -f "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\secret.xlsx.lnk"
```

**Directory:**

{% code overflow="wrap" %}
```cmd
LECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\Output" --csvf lnk.csv -q
```
{% endcode %}

**All Users:**

```cmd
LECmd.exe -d "C:\Users" --csv "C:\Cases\Output" --csvf all_lnk.csv -q
```

**With File Content Display:**

{% code overflow="wrap" %}
```cmd
LECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\Output" --csvf lnk.csv
```
{% endcode %}

**Key CSV Output Columns:**

* `SourceFile` - LNK filename
* `TargetPath` - Original file location
* `VolumeSerialNumber` - Drive/USB serial
* `DriveType` - Fixed, Removable, Network
* `VolumeLabel` - Drive name
* `TargetCreated` - File creation time
* `TargetModified` - File modification time
* `TargetAccessed` - File access time
* `FileSize` - Target file size
* `MachineName` - Computer name
* `NetworkPath` - UNC path (if network)

***

#### RBCmd (Recycle Bin Parser)

**Single $I File:**

```cmd
RBCmd.exe -f "C:\$Recycle.Bin\{SID}\$I123456.xlsx"
```

**User's Recycle Bin:**

```cmd
RBCmd.exe -d "C:\$Recycle.Bin\{SID}" --csv "C:\Cases\Output" --csvf recycle.csv -q
```

**All Users:**

```cmd
RBCmd.exe -d "C:\$Recycle.Bin" --csv "C:\Cases\Output" --csvf all_recycle.csv -q
```

**Key CSV Output Columns:**

* `FileName` - Original filename
* `FileSize` - Size in bytes
* `DeletedOn` - Deletion timestamp
* `OriginalPath` - Full original path
* `$IFile` - Metadata file
* `$RFile` - Content file

***

#### SBECmd (Shell Bags Parser)

**Single User:**

```cmd
SBECmd.exe -d "C:\Users\Alice" --csv "C:\Cases\Output" --csvf shellbags_alice.csv
```

**All Users:**

```cmd
SBECmd.exe -d "C:\Users" --csv "C:\Cases\Output" --csvf shellbags_all.csv
```

**Live System (Current User):**

```cmd
SBECmd.exe -l --csv "C:\Cases\Output" --csvf shellbags_live.csv
```

**Key CSV Output Columns:**

* `Path` - Full folder path
* `FirstInteracted` - First access time
* `LastInteracted` - Last access time
* `ShellType` - Folder, Zip, Network, etc.
* `MRUPosition` - Most recently used order

***

### Detection Patterns & Red Flags

#### Data Exfiltration Indicators

**Pattern 1: USB Data Theft**

```bash
RED FLAGS:
✗ LNK files with DriveType = "Removable"
✗ Large file access followed by USB copy
✗ Multiple similar files (bulk copy)
✗ Sensitive file types (.xlsx, .docx, .pdf, .sql)
✗ USB connected outside normal hours
```

**Pattern 2: Network Share Transfer**

```bash
RED FLAGS:
✗ LNK files with UNC paths to non-corporate shares
✗ Shell Bags showing personal NAS browsing
✗ Large file transfers
✗ Access during off-hours
✗ Shares to personal domains (HomeNAS, etc.)
```

**Pattern 3: Cloud Storage Exfiltration**

```bash
RED FLAGS:
✗ Shell Bags: OneDrive, Dropbox, Google Drive folders
✗ LNK files: Copies to cloud sync folders
✗ Recent Files: Bulk document access
✗ Personal cloud accounts (not corporate)
```

**Pattern 4: Evidence Destruction**

```bash
RED FLAGS:
✗ Mass deletions in Recycle Bin
✗ Recycle Bin emptied after file access
✗ LNK files remain for deleted files
✗ CCleaner/BleachBit execution
✗ Timing: Deletions before resignation/incident
```

***

#### File Type Risk Assessment

| File Type             | Risk Level | Typical Use                         | Exfiltration Value |
| --------------------- | ---------- | ----------------------------------- | ------------------ |
| `.xlsx`, `.csv`       | HIGH       | Financial, customer data            | Very High          |
| `.docx`, `.pdf`       | HIGH       | Intellectual property, reports      | High               |
| `.sql`, `.bak`        | CRITICAL   | Database dumps                      | Critical           |
| `.pst`, `.ost`        | HIGH       | Email archives                      | High               |
| `.txt`, `.cfg`        | MEDIUM     | Configurations, credentials         | Medium-High        |
| `.zip`, `.7z`, `.rar` | HIGH       | Compressed archives (bulk theft)    | Very High          |
| `.jpg`, `.png`        | LOW-MEDIUM | Images (may contain sensitive info) | Low-Medium         |

***

### Common Investigation Scenarios

#### Scenario 1: Employee Downloaded Sensitive Data

**Evidence Chain:**

```bash
1. Recent Files shows access to HR/Finance documents
2. LNK files show copies made to Downloads folder
3. Shell Bags shows browsing of staging directory
4. LNK files show USB device connection
5. Files copied to USB (DriveType = Removable)
6. Original files deleted (Recycle Bin)
7. USB device disconnected
```

**Key Artifacts:**

* Recent Files: HR\_Salaries\_2024.xlsx, Customer\_List.xlsx
* LNK Files: Copies to C:\Users\Alice\Downloads\ToTake\\
* Shell Bags: Browsed E:\CompanyData\\
* Recycle Bin: Original files deleted
* USBSTOR: USB device serial number

***

#### Scenario 2: Malware Downloaded and Executed

**Evidence Chain:**

```bash
1. Browser download (check browser artifacts)
2. LNK file created for downloaded executable
3. Recent Files shows malware file access
4. Execution (check Prefetch/BAM)
5. Post-infection file access
6. Malware file deleted (Recycle Bin)
```

**Key Artifacts:**

* LNK File: C:\Users\Alice\Downloads\invoice.exe.lnk
* Recent Files: invoice.exe accessed
* Prefetch: INVOICE.EXE-\*.pf execution
* Recent Files: Malware accessed system files
* Recycle Bin: Malware file deleted

***

#### Scenario 3: Lateral Movement File Access

**Evidence Chain:**

```bash
1. Remote share mounted
2. Shell Bags shows network share browsing
3. LNK files show files accessed from network
4. Files copied locally or executed remotely
```

**Key Artifacts:**

* Shell Bags: \VICTIM-PC\C$\Windows\Temp\\
* LNK Files: \VICTIM-PC\C$\Windows\Temp\tools.exe
* Recent Files: Remote executable accessed
* MountPoints2: \VICTIM-PC\C$ connection

***

### SOC Quick Reference Commands

#### Rapid Triage

**List Recent LNK Files:**

{% code overflow="wrap" %}
```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" | Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name, LastWriteTime
```
{% endcode %}

**Check Recycle Bin:**

```bash
dir C:\$Recycle.Bin /a /s
```

**Export Recent Files Registry:**

{% code overflow="wrap" %}
```cmd
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" C:\Cases\RecentDocs.reg
```
{% endcode %}

**Quick Suspicious File Check:**

{% code overflow="wrap" %}
```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" | Where-Object {$_.Name -like "*password*" -or $_.Name -like "*confidential*"}
```
{% endcode %}

***

#### Collection Script (Batch)

{% code overflow="wrap" %}
```batch
@echo off
set USER=%USERNAME%
set OUTPUT=C:\Cases\FileAccess_%USER%
mkdir %OUTPUT%

echo [+] Collecting File Access Artifacts...

REM Export RecentDocs registry
echo [*] Exporting RecentDocs registry...
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" "%OUTPUT%\RecentDocs.reg"

REM Copy LNK files
echo [*] Copying LNK files...
xcopy "%APPDATA%\Microsoft\Windows\Recent\*.lnk" "%OUTPUT%\LNK_Recent\" /Y /I
xcopy "%APPDATA%\Microsoft\Office\Recent\*.lnk" "%OUTPUT%\LNK_Office\" /Y /I

REM Copy NTUSER.DAT and USRCLASS.DAT (for Shell Bags)
echo [*] Copying registry hives...
copy "%USERPROFILE%\NTUSER.DAT" "%OUTPUT%\" /Y
copy "%USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat" "%OUTPUT%\" /Y

REM Export Recycle Bin info
echo [*] Listing Recycle Bin contents...
dir C:\$Recycle.Bin /a /s > "%OUTPUT%\RecycleBin_Listing.txt"

echo [+] Collection Complete!
echo [+] Output: %OUTPUT%
pause
```
{% endcode %}

***

### Investigation Best Practices

#### Live Response

✅ **DO:**

* Collect LNK files immediately (minimal footprint)
* Export registry keys before analysis
* Document collection timestamp
* Hash all collected artifacts
* Use write-protected USB for tools

❌ **DON'T:**

* Open files in Recent folder (updates access time)
* Delete items from Recycle Bin
* Browse folders (updates Shell Bags)
* Run excessive tools (creates new LNK files)

***

#### Offline Analysis

✅ **DO:**

* Parse all artifacts to CSV for correlation
* Build comprehensive timeline
* Cross-reference multiple artifacts
* Check file existence (LNK target may be deleted)
* Validate volume serial numbers

❌ **DON'T:**

* Rely on single artifact
* Ignore timezone offsets
* Skip deleted file recovery attempts
* Forget to check Office Recent folder

***

#### Timeline Construction

**Best Practice:**

1. Parse all artifacts to CSV
2. Merge timelines in Excel/TimelineExplorer
3. Add columns: Artifact Source, Action Type
4. Sort by timestamp
5. Filter by incident window
6. Identify correlated events
7. Build narrative

**Example Timeline Entries:**

```bash
2024-11-30 14:23:15 | Recent Files | Accessed: Payroll_2024.xlsx
2024-11-30 14:23:45 | LNK File | Copied to: E:\Data\ (USB)
2024-11-30 14:24:10 | Shell Bags | Browsed: E:\Data\
2024-11-30 14:25:00 | Recycle Bin | Deleted: Payroll_2024.xlsx
```

***

### Investigation Checklists

#### Data Exfiltration Investigation

* \[ ] Parse Recent Files for sensitive document access
* \[ ] Analyse LNK files for USB/network transfers
* \[ ] Check Shell Bags for external device browsing
* \[ ] Review Recycle Bin for evidence destruction
* \[ ] Correlate USB device serial numbers
* \[ ] Build timeline of file access → copy → deletion
* \[ ] Document external storage paths
* \[ ] Cross-reference with network logs
* \[ ] Check cloud storage folder access

#### Insider Threat Investigation

* \[ ] Identify resignation/termination date
* \[ ] Focus on 30 days before exit
* \[ ] Analyse Recent Files for bulk access
* \[ ] Check LNK files for USB usage
* \[ ] Review network share access
* \[ ] Examine Recycle Bin for deletions
* \[ ] Look for anti-forensic tool usage
* \[ ] Document access patterns over time
* \[ ] Correlate with HR records

#### Malware File Analysis

* \[ ] Identify malware file in Recent Files
* \[ ] Check LNK file for download path
* \[ ] Review browser download artifacts
* \[ ] Analyse post-infection file access
* \[ ] Check for file deletion attempts
* \[ ] Cross-reference with execution artifacts
* \[ ] Document file origin and timestamps
* \[ ] Look for related malicious files

***

### Tools & Resources

#### Essential Tools

**Zimmerman Tools (Free):**

* LECmd - LNK file parser
* RBCmd - Recycle Bin parser
* SBECmd - Shell Bags parser
* TimelineExplorer - Timeline viewer
* RegistryExplorer - Registry viewer

**Download:** https://ericzimmerman.github.io/

**Alternative Tools:**

* NirSoft LnkParser - LNK viewer
* FTK Imager - Evidence collection
* X-Ways Forensics - Commercial suite
* Magnet AXIOM - Commercial suite

***

### Summary: Critical Takeaways

#### Artifact Strengths

**LNK Files:**

* ✓ Survives file deletion
* ✓ Precise timestamps
* ✓ Volume serial numbers (USB tracking)
* ✓ Network path information
* ✓ File size and attributes

**Recent Files:**

* ✓ Shows user focus/interest
* ✓ Last 150 files accessed
* ✓ Organised by file type
* ✓ Recent folders list

**Shell Bags:**

* ✓ Folder navigation history
* ✓ Network share access
* ✓ USB device paths
* ✓ Survives folder deletion

**Recycle Bin:**

* ✓ Actual file content (if not emptied)
* ✓ Deletion timestamp
* ✓ Original file path
* ✓ Per-user attribution

#### Investigation Strategy

1. **Start with Recent Files** (what was user interested in)
2. **Analyse LNK Files** (detailed access, USB/network)
3. **Check Shell Bags** (folder navigation)
4. **Examine Recycle Bin** (deletions, recovery)
5. **Correlate all artifacts** (build timeline)
6. **Cross-reference with execution/USB artifacts**

#### Key Principle

**File access artifacts persist after file deletion and provide crucial evidence of user knowledge, intent, and data handling—essential for data exfiltration and insider threat investigations.**

***

**Remember:** LNK files are your best friend—they survive file deletion and prove the file existed, was accessed, and can link to specific USB devices or network shares through volume serial numbers.

***

