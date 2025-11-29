# File and Folder Access Investigation Guide

### Complete DFIR Workflow & Cheatsheet

***

### 📚 Table of Contents

1. [Artifact Priority Matrix](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#artifact-priority-matrix)
2. [Investigation Framework](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-framework)
3. [MRU Artifacts Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#mru-artifacts-analysis)
4. [Recent Files Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#recent-files-analysis)
5. [LNK Files Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#lnk-files-analysis)
6. [Office Artifacts Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#office-artifacts-analysis)
7. [Deleted Items Investigation](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#deleted-items-investigation)
8. [Search and Navigation History](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#search-and-navigation-history)
9. [Investigation Playbooks](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-playbooks)
10. [Tool Reference](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#tool-reference)

***

### 🎯 Artifact Priority Matrix

#### Quick Decision Guide: What to Check First?

| Investigation Goal           | Primary Artifacts               | Secondary Artifacts         | Timeframe |
| ---------------------------- | ------------------------------- | --------------------------- | --------- |
| **Recent Document Access**   | RecentDocs, LNK Files           | OpenSaveMRU, Office MRU     | 5-15 min  |
| **Deleted Files**            | Recycle Bin ($I/$R), Thumbcache | Windows Search, IE History  | 15-30 min |
| **User File Focus**          | Recent Folder, Jump Lists       | LastVisitedMRU              | 10-20 min |
| **Office Document Activity** | Office File MRU, Trust Records  | Reading Locations, OAlerts  | 15-30 min |
| **Data Exfiltration**        | RecentDocs, LNK Files           | OpenSaveMRU, LastVisitedMRU | 30-45 min |
| **Insider Threat**           | Office MRU, Recent Files        | Trust Records, Search Terms | 30-60 min |
| **Malicious Documents**      | Office Trust Records            | Office MRU, LNK Files       | 15-30 min |
| **User Search Behavior**     | WordWheelQuery, TypedPaths      | Recent Files                | 10-15 min |
| **Network Share Access**     | LNK Files, IE History           | LastVisitedMRU              | 20-30 min |

***

### 🔍 Investigation Framework

#### Phase 1: Quick Triage (First 15 Minutes)

**Determine Investigation Scope:**

```bash
□ What the alert/incident type?
  - Data theft
  - Insider threat
  - Malware execution via document
  - Account compromise
  - Policy violation

□ Who is the user of interest?
□ What is the timeframe?
□ What file types are relevant?
□ Are we looking for deleted files?
```

**Quick Wins - Check These Immediately:**

{% code overflow="wrap" %}
```powershell
# 1. Recent documents (last 150 files)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# 2. Recent folders
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\Folder"

# 3. Run commands
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

# 4. Search terms
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"

# 5. Check for macro-enabled documents
reg query "HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords"
reg query "HKCU\Software\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords"
```
{% endcode %}

***

#### Phase 2: Artifact Collection (Live System)

**Critical Files to Collect:**

{% code overflow="wrap" %}
```powershell
# Create collection directory
New-Item -Path "C:\DFIR_Collection\FileAccess" -ItemType Directory -Force

# User profile path
$User = "username"
$UserProfile = "C:\Users\$User"

# 1. Registry Hives
reg save HKCU "$Env:TEMP\NTUSER.DAT" /y
Copy-Item "$Env:TEMP\NTUSER.DAT" -Destination "C:\DFIR_Collection\FileAccess\"

# Or for offline user
Copy-Item "$UserProfile\NTUSER.DAT" -Destination "C:\DFIR_Collection\FileAccess\"

# 2. LNK Files
Copy-Item "$UserProfile\AppData\Roaming\Microsoft\Windows\Recent\*" -Destination "C:\DFIR_Collection\FileAccess\LNK_Recent\" -Recurse
Copy-Item "$UserProfile\AppData\Roaming\Microsoft\Office\Recent\*" -Destination "C:\DFIR_Collection\FileAccess\LNK_Office\" -Recurse -ErrorAction SilentlyContinue

# 3. Thumbcache
Copy-Item "$UserProfile\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" -Destination "C:\DFIR_Collection\FileAccess\Thumbcache\"

# 4. Windows Search Database
Copy-Item "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" -Destination "C:\DFIR_Collection\FileAccess\"
Copy-Item "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\*" -Destination "C:\DFIR_Collection\FileAccess\GatherLogs\" -Recurse

# 5. Recycle Bin (for specific user)
# Need to identify user SID first
$UserSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object {$_.Name -eq $User}).SID
Copy-Item "C:\`$Recycle.Bin\$UserSID\*" -Destination "C:\DFIR_Collection\FileAccess\RecycleBin\" -Recurse -ErrorAction SilentlyContinue

# 6. WebCache (IE/Edge history)
Copy-Item "$UserProfile\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat" -Destination "C:\DFIR_Collection\FileAccess\"

# 7. Office OAlerts
Copy-Item "C:\Windows\System32\winevt\Logs\OAlerts.evtx" -Destination "C:\DFIR_Collection\FileAccess\" -ErrorAction SilentlyContinue
```
{% endcode %}

***

### 📋 MRU Artifacts Analysis

#### 1. OpenSaveMRU

**Overview:**

* **Purpose**: Track files opened/saved via Windows Open/Save dialogs
* **Location**: NTUSER.DAT
* **Coverage**: Office apps, browsers, chat clients, most GUI applications
* **Retention**: Last 20 files per extension

**Registry Locations:**

```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```

**Structure:**

```bash
OpenSavePidlMRU\
├── * (all file types - most recent 20)
├── exe (executables)
├── txt (text files)
├── docx (Word documents)
├── xlsx (Excel files)
├── pdf (PDF files)
└── [any extension]
```

**Key Features:**

* Each extension tracks last 20 files
* `*` key = most recent files regardless of extension
* `MRUListEx` = ordered list (most recent first)
* Stores full path (as PIDL + filename)

**Collection & Analysis:**

**Using Registry Explorer:**

{% code overflow="wrap" %}
```bash
1. Load NTUSER.DAT
2. Navigate: Software → Microsoft → Windows → CurrentVersion → Explorer → ComDlg32 → OpenSavePidlMRU
3. Expand subkeys (* and specific extensions)
4. Review MRUListEx for order (first value = most recent)
5. Export to CSV
```
{% endcode %}

**Manual Registry Query:**

{% code overflow="wrap" %}
```bash
# Query OpenSaveMRU
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s

# Query specific extension
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\pdf" /s
```
{% endcode %}

**Using RegRipper:**

```powershell
# Extract OpenSaveMRU
.\rr.exe -r "C:\Evidence\NTUSER.DAT" -p opensavemru > opensavemru.txt
```

**PowerShell Parsing:**

{% code overflow="wrap" %}
```powershell
# Get all OpenSaveMRU extensions
$OpenSavePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"

Get-ChildItem $OpenSavePath | ForEach-Object {
    $Extension = $_.PSChildName
    
    # Get MRUListEx (order of access)
    $MRUList = Get-ItemProperty -Path $_.PSPath -Name "MRUListEx" -ErrorAction SilentlyContinue
    
    [PSCustomObject]@{
        Extension = $Extension
        LastWriteTime = $_.LastWriteTime
        EntryCount = ($_.Property | Where-Object {$_ -notlike "MRU*"}).Count
    }
} | Sort-Object LastWriteTime -Descending | Format-Table
```
{% endcode %}

**Investigation Tips:**

**1. Recent File Access by Type:**

```bash
Check specific extensions relevant to investigation:
- .docx, .xlsx, .pptx = Office documents
- .pdf = PDF files
- .ps1, .bat, .vbs = Scripts
- .exe = Executables
- .zip, .rar = Archives
```

**2. Timeline Construction:**

```bash
MRUListEx order + Registry LastWriteTime:
- Position 0 in MRUListEx = most recent
- Key LastWriteTime = when most recent file was accessed
- Build timeline of file access per extension
```

**3. Red Flags:**

```bash
🚩 Suspicious file extensions:
   - .ps1, .bat, .vbs in non-admin user context
   - .exe from Downloads or Temp directories
   
🚩 Sensitive document access:
   - Files with "confidential", "password", "secret" in paths
   
🚩 External drives:
   - Files from E:, F:, etc. (data exfiltration)
   
🚩 Network paths:
   - UNC paths (\\server\share) - lateral movement
```

***

#### 2. LastVisitedMRU

**Overview:**

* **Purpose**: Track applications and last folder they accessed
* **Forensic Value**: Shows which app accessed which folder
* **Location**: NTUSER.DAT

**Registry Location:**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```
{% endcode %}

**Key Information:**

* Application executable name
* Last folder path accessed by that application
* Order of access (MRUListEx)

**Collection & Analysis:**

{% code overflow="wrap" %}
```powershell
# Query LastVisitedMRU
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /s
```
{% endcode %}

**Using RegRipper:**

```powershell
.\rr.exe -r "NTUSER.DAT" -p comdlg32 > comdlg32.txt
```

**Investigation Tips:**

**What to Look For:**

```bash
1. Unusual applications accessing sensitive folders
   Example: notepad.exe accessing C:\Windows\System32\config

2. Office applications accessing unusual folders
   Example: WINWORD.EXE accessing C:\Users\Public\Downloads

3. Known attack tools
   Example: powershell.exe accessing C:\Temp

4. Hidden or system folders
   Example: cmd.exe accessing C:\$Recycle.Bin
```

**Cross-Reference Strategy:**

```bash
LastVisitedMRU shows: Application + Folder
         ↓
OpenSaveMRU shows: Specific files in that folder
         ↓
LNK Files show: Exact file opened + timestamps
         ↓
Complete picture of file access
```

***

### 📁 Recent Files Analysis

#### 1. RecentDocs Registry Key

**Overview:**

* **Purpose**: Track last 150 files/folders opened
* **Location**: NTUSER.DAT per user
* **Organisation**: By file extension + rollup key
* **Forensic Gold**: Survives file deletion!

**Registry Location:**

```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

**Structure:**

```bash
RecentDocs\
├── [Root - Last 150 files/folders opened]
├── Folder [Last 30 folders]
├── .docx [Last 20 .docx files]
├── .xlsx [Last 20 .xlsx files]
├── .pdf [Last 20 .pdf files]
└── [Any extension - Last 20 files each]
```

**Key Features:**

| Component             | Description    | Retention    | Timestamp                       |
| --------------------- | -------------- | ------------ | ------------------------------- |
| **Root Key**          | All file types | Last 150     | Key LastWriteTime = most recent |
| **Folder Subkey**     | Folders only   | Last 30      | Key LastWriteTime               |
| **Extension Subkeys** | Per file type  | Last 20 each | Key LastWriteTime               |
| **MRUListEx**         | Access order   | N/A          | Ordered list                    |

**Collection & Analysis:**

**Manual Registry Query:**

{% code overflow="wrap" %}
```powershell
# Query all RecentDocs
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /s

# Query specific extension
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf" /s

# Query folders
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\Folder" /s
```
{% endcode %}

**Using Registry Explorer:**

```bash
1. Load NTUSER.DAT
2. Navigate: Software → Microsoft → Windows → CurrentVersion → Explorer → RecentDocs
3. View root key for all files
4. Check "Folder" subkey for folder access
5. Check extension subkeys for specific file types
6. Review MRUListEx for chronological order
7. Export to CSV
```

**Using RegRipper:**

```powershell
# Parse RecentDocs
.\rr.exe -r "NTUSER.DAT" -p recentdocs > recentdocs.txt
```

**PowerShell Parsing:**

{% code overflow="wrap" %}
```powershell
# Parse RecentDocs with file names
function Parse-RecentDocs {
    param([string]$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
    
    Get-ChildItem $RegistryPath | ForEach-Object {
        $Subkey = $_
        $Extension = $Subkey.PSChildName
        
        # Get MRU order
        $MRUList = Get-ItemProperty -Path $Subkey.PSPath -Name "MRUListEx" -ErrorAction SilentlyContinue
        
        # Get all value names (file entries)
        $Values = $Subkey.Property | Where-Object {$_ -notlike "MRU*"}
        
        foreach ($Value in $Values) {
            $Data = Get-ItemProperty -Path $Subkey.PSPath -Name $Value -ErrorAction SilentlyContinue
            
            [PSCustomObject]@{
                Extension = if ($Extension -eq "Folder") {"Folder"} else {$Extension}
                ValueName = $Value
                LastModified = $Subkey.LastWriteTime
                RawData = $Data.$Value
            }
        }
    }
}

Parse-RecentDocs | Export-Csv C:\Analysis\RecentDocs.csv -NoTypeInformation
```
{% endcode %}

**Investigation Workflows:**

**1. Recent File Timeline:**

```bash
Goal: Build chronological list of file access

Steps:
1. Check root RecentDocs key LastWriteTime (most recent file)
2. Parse MRUListEx for order
3. Check each extension subkey LastWriteTime
4. Correlate with LNK files for precise timestamps
```

**2. Deleted File Detection:**

```bash
RecentDocs persists after file deletion!

Check:
1. File paths in RecentDocs
2. Verify if files still exist on disk
3. If missing → File was deleted
4. Check Recycle Bin for recovery
```

**3. Sensitive Document Access:**

```powershell
# Search for sensitive keywords in file names
.\rr.exe -r "NTUSER.DAT" -p recentdocs | 
    Select-String -Pattern "password|confidential|secret|salary|ssn|credit"
```

**4. External Drive Usage:**

```bash
Check RecentDocs for paths like:
- E:\, F:\, G:\ (removable drives)
- \\USB_DRIVE\
- Volume serial numbers indicate specific USB device
```

**Red Flags:**

```bash
🚩 Unusual file types for user role:
   - Financial files accessed by IT admin
   - HR documents by non-HR user
   
🚩 After-hours access:
   - Cross-reference timestamps with logon times
   
🚩 Mass file access:
   - Many files in short timeframe
   - Different file types (reconnaissance)
   
🚩 Deleted files:
   - Files in RecentDocs but not on disk
   - Potential evidence destruction
   
🚩 External drives:
   - Files accessed from E:, F:, etc.
   - Possible data exfiltration
```

***

#### 2. Recent Folder (LNK Files Location)

**Overview:**

* **Physical Location**: `C:\Users\{Username}\AppData\Roaming\Microsoft\Windows\Recent`
* **Contains**: LNK shortcut files for recently accessed files
* **Forensic Value**: Rich metadata + survives file deletion

**What's Stored:**

* LNK files (Windows shortcuts)
* Automatically created on file access
* Persists after target file deletion
* Contains target file metadata

**Note**: See detailed LNK Files section below for analysis

***

### 🔗 LNK Files Analysis

#### Overview

**What are LNK Files?**

* Windows shortcut files
* Automatically created when user opens file
* Rich forensic metadata
* Persist after target deletion

**Locations:**

```bash
Primary:
C:\Users\{Username}\AppData\Roaming\Microsoft\Windows\Recent\

Office Specific:
C:\Users\{Username}\AppData\Roaming\Microsoft\Office\Recent\

Others:
- Desktop
- Start Menu
- Taskbar (pinned items)
```

**Key Forensic Information:**

| Data Point               | Description                         | Source            |
| ------------------------ | ----------------------------------- | ----------------- |
| **LNK Creation Time**    | First time file of that name opened | LNK file metadata |
| **LNK Modified Time**    | Last time file of that name opened  | LNK file metadata |
| **Target Created Time**  | When target file was created        | Embedded in LNK   |
| **Target Modified Time** | When target was last modified       | Embedded in LNK   |
| **Target Accessed Time** | When target was last accessed       | Embedded in LNK   |
| **Target Path**          | Original location of file           | Embedded in LNK   |
| **Target Size**          | Size of target file                 | Embedded in LNK   |
| **Volume Info**          | Drive name, type, serial number     | Embedded in LNK   |
| **Network Share**        | UNC path if on network              | Embedded in LNK   |
| **Machine ID**           | NetBIOS name of system              | Embedded in LNK   |

#### Important Behaviors

**1. LNK Overwriting (Pre-Windows 10):**

```bash
Problem: Same filename = overwrite
Example:
  - User opens C:\Temp\report.docx → Creates report.docx.lnk
  - User opens C:\Users\John\Documents\report.docx → Overwrites report.docx.lnk
  
Result: Only latest location preserved
```

**2. LNK with Extension (Windows 10+):**

```bash
Fix: Extension added to LNK filename
Example:
  - report.docx → report.docx.lnk
  - report.txt → report.txt.lnk
  
Result: Both preserved (different extensions)
```

**3. LNK Persistence:**

```bash
✅ LNK file remains even after target file is deleted
✅ Timestamps preserved in LNK
✅ Can prove file existed and was accessed
✅ Can recover original path/location
```

#### Collection & Analysis

**Collection:**

{% code overflow="wrap" %}
```powershell
# Collect LNK files
$User = "username"
$LNKPath = "C:\Users\$User\AppData\Roaming\Microsoft\Windows\Recent"
Copy-Item "$LNKPath\*" -Destination "C:\Analysis\LNK\" -Recurse

# Office-specific LNK files
$OfficeLNK = "C:\Users\$User\AppData\Roaming\Microsoft\Office\Recent"
Copy-Item "$OfficeLNK\*" -Destination "C:\Analysis\LNK_Office\" -Recurse -ErrorAction SilentlyContinue
```
{% endcode %}

**Quick Analysis (Command Line):**

{% code overflow="wrap" %}
```bash
:: Display LNK modification time (last time file opened)
dir /a filename.xlsx.lnk

:: Display LNK creation time (first time file opened)
dir /tc filename.xlsx.lnk
```
{% endcode %}

**Using ExifTool:**

```bash
# Extract all metadata
exiftool report.docx.lnk

# Extract specific fields
exiftool -TargetFileSize -LocalBasePath -VolumeLabel report.docx.lnk

# Batch process all LNK files
exiftool -csv -r C:\Analysis\LNK\ > lnk_metadata.csv
```

**Using LECmd (Link Explorer Command Line):**

{% code overflow="wrap" %}
```powershell
# Single file analysis
.\LECmd.exe -f "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\report.docx.lnk"

# With CSV output
.\LECmd.exe -f "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\report.docx.lnk" --csv "C:\Analysis" --csvf report_lnk.csv

# Directory of LNK files
.\LECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Analysis" --csvf all_lnk.csv -q

# Include all metadata
.\LECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent" --all --csv "C:\Analysis" --csvf detailed_lnk.csv
```
{% endcode %}

**LECmd Output Analysis:**

```bash
Key CSV Columns:
- SourceFile: LNK file path
- SourceCreated: First time file of that name opened
- SourceModified: Last time file opened  
- TargetCreated: Target file creation time
- TargetModified: Target file modification time
- TargetAccessed: Target file access time
- LocalPath: Original path of target
- FileSize: Target file size
- VolumeLabel: Drive name
- VolumeSerialNumber: Drive serial (unique per drive)
- MachineName: NetBIOS name
- NetworkPath: UNC path if on network
```

#### Investigation Workflows

**1. File Access Timeline:**

```bash
Reconstruct when user accessed specific file:

Step 1: Find LNK file for target
Step 2: LNK Creation = First access
Step 3: LNK Modified = Last access
Step 4: Compare with target file timestamps
```

**2. Deleted File Recovery:**

```bash
LNK persists after file deletion!

Evidence available:
✓ Original file path
✓ File size
✓ Access times
✓ Drive it was on (volume serial)
✓ Machine it was accessed from

Actions:
1. Check Recycle Bin for file
2. Check Volume Shadow Copies
3. Check file carving
4. Check network shares (if UNC path)
```

**3. Network Share Access (Lateral Movement):**

{% code overflow="wrap" %}
```powershell
# Find LNK files with network paths
.\LECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Analysis" --csvf lnk.csv

# Import and filter
$LNKData = Import-Csv C:\Analysis\lnk.csv

# Network shares
$LNKData | Where-Object {
    $_.NetworkPath -ne "" -or $_.LocalPath -match "^\\\\"
} | Select-Object SourceModified, LocalPath, NetworkPath, MachineName

# Admin shares (lateral movement indicator)
$LNKData | Where-Object {
    $_.LocalPath -match "\\\\.*\\[A-Z]\$" -or 
    $_.LocalPath -match "\\\\.*\\ADMIN\$"
}
```
{% endcode %}

**4. USB Drive Tracking:**

{% code overflow="wrap" %}
```powershell
# Find files accessed from external drives
$LNKData = Import-Csv C:\Analysis\lnk.csv

# Filter by drive letter (E:, F:, etc.)
$LNKData | Where-Object {
    $_.LocalPath -match "^[E-Z]:\\"
} | Select-Object SourceModified, LocalPath, VolumeLabel, VolumeSerialNumber

# Group by volume serial (track specific USB device)
$LNKData | Where-Object {$_.LocalPath -match "^[E-Z]:\\"} |
    Group-Object VolumeSerialNumber |
    ForEach-Object {
        [PSCustomObject]@{
            VolumeSerial = $_.Name
            VolumeLabel = $_.Group[0].VolumeLabel
            FileCount = $_.Count
            FirstAccess = ($_.Group | Sort-Object SourceCreated | Select-Object -First 1).SourceCreated
            LastAccess = ($_.Group | Sort-Object SourceModified -Descending | Select-Object -First 1).SourceModified
            Files = ($_.Group.LocalPath | Select-Object -Unique)
        }
    }
```
{% endcode %}

**5. Cross-Machine Activity:**

```powershell
# Find files accessed from different machines
$LNKData | Where-Object {
    $_.MachineName -ne $env:COMPUTERNAME -and $_.MachineName -ne ""
} | Select-Object SourceModified, MachineName, LocalPath, NetworkPath
```

#### Red Flags

```bash
🚩 Access to sensitive documents:
   - HR files, financial data, credentials
   - Files with "confidential", "password" in name
   
🚩 Network share access:
   - \\SERVER\C$ (admin share)
   - \\WORKSTATION\ADMIN$ 
   - Unusual servers for user's role
   
🚩 USB drive usage:
   - Large files to external drives
   - Multiple different USB devices
   - After-hours USB usage
   
🚩 Deleted file evidence:
   - LNK exists but target missing
   - Sensitive file deletion
   - Mass deletion patterns
   
🚩 Cross-machine access:
   - Files accessed from different machines
   - Machine names don't match user's assigned systems
   
🚩 Unusual file locations:
   - System directories (C:\Windows\System32\)
   - Hidden directories
   - Temp folders
```

#### Pro Tips

✅ **Timeline Reconstruction**: Combine LNK timestamps with file timestamps for complete picture

✅ **USB Device Tracking**: Volume serial number uniquely identifies USB device

✅ **Network Mapping**: LNK files show lateral movement paths

✅ **Deleted Evidence**: LNK survives deletion - crucial for proving file existed

⚠️ **Filename Limitation**: Pre-Win10 systems overwrite LNK for same filename

⚠️ **Hidden Extensions**: .lnk extension never shown in Windows Explorer

***

### 📄 Office Artifacts Analysis

#### 1. Office File MRU

**Overview:**

* **Purpose**: Track recent files per Office application
* **Advantage over RecentDocs**: Includes full path + last opened time
* **Location**: NTUSER.DAT per user
* **Office Versions**:
  * 16.0 = Office 2016/2019/Microsoft 365
  * 15.0 = Office 2013
  * 14.0 = Office 2010

**Registry Locations:**

**Standard Office:**

```bash
NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\File MRU

Examples:
NTUSER.DAT\Software\Microsoft\Office\16.0\Word\File MRU
NTUSER.DAT\Software\Microsoft\Office\16.0\Excel\File MRU
NTUSER.DAT\Software\Microsoft\Office\16.0\PowerPoint\File MRU
```

**Microsoft 365 (Personal Account):**

```bash
NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\User MRU\LiveId_####\File MRU
```

**Microsoft 365 (Azure AD):**

```bash
NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\User MRU\AD_####\File MRU
```

**Collection & Analysis:**

**Manual Query:**

```powershell
# Word MRU
reg query "HKCU\Software\Microsoft\Office\16.0\Word\File MRU" /s

# Excel MRU
reg query "HKCU\Software\Microsoft\Office\16.0\Excel\File MRU" /s

# PowerPoint MRU
reg query "HKCU\Software\Microsoft\Office\16.0\PowerPoint\File MRU" /s

# Check all Office versions
reg query "HKCU\Software\Microsoft\Office" /s /f "File MRU"
```

**Using Registry Explorer:**

```bash
1. Load NTUSER.DAT
2. Navigate: Software → Microsoft → Office → 16.0 → Word → File MRU
3. Review "Item #" values (Item 1 = most recent)
4. Check User MRU subkeys for M365 accounts
5. Export to CSV
```

**PowerShell Parsing:**

{% code overflow="wrap" %}
```powershell
# Parse Office MRU for all apps
function Get-OfficeMRU {
    param([string]$OfficeVersion = "16.0")
    
    $Apps = @("Word", "Excel", "PowerPoint", "Access")
    $Results = @()
    
    foreach ($App in $Apps) {
        $MRUPath = "HKCU:\Software\Microsoft\Office\$OfficeVersion\$App\File MRU"
        
        if (Test-Path $MRUPath) {
            $MRUData = Get-ItemProperty -Path $MRUPath -ErrorAction SilentlyContinue
            
            # Parse Item values
            $MRUData.PSObject.Properties | Where-Object {$_.Name -like "Item *"} | ForEach-Object {
                # Value format: [F00000000][T01D8...][O00000000]*C:\path\to\file.docx
                $Value = $_.Value
                
                if ($Value -match '\*(.*)$') {
                    $FilePath = $Matches[1]
                    
                    $Results += [PSCustomObject]@{
                        Application = $App
                        Position = $_.Name
                        FilePath = $FilePath
                        LastAccessed = (Get-Item $MRUPath).LastWriteTime
                    }
                }
            }
        }
    }
    
    return $Results
}

Get-OfficeMRU | Export-Csv C:\Analysis\Office_MRU.csv -NoTypeInformation
```
{% endcode %}

**Investigation Workflows:**

**1. Recent Document Activity:**

```bash
Goal: Identify what documents user recently opened

Steps:
1. Check File MRU for each Office app
2. Item 1 = most recent (descending order)
3. Extract file paths and names
4. Cross-reference with file existence
```

**2. Sensitive Document Access:**

```powershell
# Search for sensitive file names
Get-OfficeMRU | Where-Object {
    $_.FilePath -match "password|confidential|secret|salary|budget|financial"
}
```

**3. Network Share Document Access:**

```powershell
# Documents accessed from network shares
Get-OfficeMRU | Where-Object {
    $_.FilePath -match "^\\\\"
} | Select-Object Application, FilePath, LastAccessed
```

**4. External Drive Documents:**

```powershell
# Documents on USB drives
Get-OfficeMRU | Where-Object {
    $_.FilePath -match "^[E-Z]:\\"
}
```

**5. Deleted Document Evidence:**

```powershell
# Documents in MRU but not on disk
Get-OfficeMRU | ForEach-Object {
    if (-not (Test-Path $_.FilePath)) {
        [PSCustomObject]@{
            Application = $_.Application
            MissingFile = $_.FilePath
            LastKnownAccess = $_.LastAccessed
            Status = "DELETED or MOVED"
        }
    }
}
```

***

#### 2. MS Word Reading Locations

**Overview:**

* **Feature**: Word 2013+ tracks user's position in document
* **Forensic Value**: Proves document was opened + how long user spent in it
* **Location**: NTUSER.DAT

**Registry Location:**

```bash
NTUSER.DAT\Software\Microsoft\Office\<Version>\Word\Reading Locations
```

**Key Information:**

* Document path
* Last cursor position in document
* Last closed time
* Duration of reading session (with File MRU data)

**Collection & Analysis:**

```powershell
# Query Reading Locations
reg query "HKCU\Software\Microsoft\Office\16.0\Word\Reading Locations" /s
```

**Using Registry Explorer:**

```bash
1. Load NTUSER.DAT
2. Navigate: Software → Microsoft → Office → 16.0 → Word → Reading Locations
3. Each subkey = document hash
4. Values show: Position, DateTime
5. Export to CSV
```

**Investigation Use:**

```bash
Proves user actually read/edited document:
✓ Document was opened
✓ User scrolled to specific position
✓ Time document was closed
✓ Duration of session (when combined with File MRU open time)

Example Timeline:
File MRU shows: Document opened at 10:00 AM
Reading Location shows: Document closed at 10:45 AM, position at page 15
Conclusion: User spent 45 minutes reading to page 15
```

***

#### 3. Office Trust Records

**Overview:**

* **Purpose**: Track documents where user enabled macros/editing
* **Security Significance**: Macro-enabled documents = common malware vector
* **Location**: NTUSER.DAT per Office app

**Registry Locations:**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\Security\Trusted Documents\TrustRecords

Examples:
HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords
HKCU\Software\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords
HKCU\Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords
```
{% endcode %}

**Key Information:**

* Document path (local or network)
* Time document was trusted
* Permissions granted (macros enabled, editing enabled)
* **Critical**: Value ending in `FF FF FF 7F` = Macros enabled!

**Collection & Analysis:**

**Manual Query:**

{% code overflow="wrap" %}
```powershell
# Check Word trust records
reg query "HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords" /s

# Check Excel trust records  
reg query "HKCU\Software\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords" /s

# Check PowerPoint trust records
reg query "HKCU\Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords" /s
```
{% endcode %}

**PowerShell - Find Macro-Enabled Documents:**

{% code overflow="wrap" %}
```powershell
# Search for documents with macros enabled
function Get-MacroEnabledDocs {
    $OfficeApps = @("Word", "Excel", "PowerPoint")
    $Results = @()
    
    foreach ($App in $OfficeApps) {
        $TrustPath = "HKCU:\Software\Microsoft\Office\16.0\$App\Security\Trusted Documents\TrustRecords"
        
        if (Test-Path $TrustPath) {
            $TrustRecords = Get-ItemProperty -Path $TrustPath -ErrorAction SilentlyContinue
            
            $TrustRecords.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} | ForEach-Object {
                $ValueName = $_.Name
                $ValueData = $_.Value
                
                # Check last 4 bytes for FF FF FF 7F (macros enabled)
                if ($ValueData.Length -ge 4) {
                    $LastBytes = $ValueData[-4..-1]
                    if ($LastBytes[0] -eq 0xFF -and $LastBytes[1] -eq 0xFF -and 
                        $LastBytes[2] -eq 0xFF -and $LastBytes[3] -eq 0x7F) {
                        
                        # Decode file path from value name
                        $FilePath = [System.Text.Encoding]::Unicode.GetString(
                            [System.Convert]::FromBase64String($ValueName)
                        )
                        
                        $Results += [PSCustomObject]@{
                            Application = $App
                            FilePath = $ValueName  # Base64 encoded path
                            DecodedPath = $FilePath
                            MacrosEnabled = "YES"
                            LastModified = (Get-Item $TrustPath).LastWriteTime
                        }
                    }
                }
            }
        }
    }
    
    return $Results
}

Get-MacroEnabledDocs | Export-Csv C:\Analysis\Macro_Enabled_Docs.csv -NoTypeInformation
```
{% endcode %}

**Investigation Workflows:**

**1. Malicious Document Detection:**

```bash
Goal: Find potentially malicious macro-enabled documents

Steps:
1. Extract all Trust Records
2. Filter for FF FF FF 7F (macros enabled)
3. Decode file paths
4. Check if files still exist
5. Check file locations (suspicious if from Downloads, Temp, Email attachments)
6. Cross-reference with:
   - Antivirus alerts
   - Email attachments
   - Web downloads
   - Process execution (4688) around same time
```

**2. Timeline Correlation:**

```bash
Trust Record timestamp = When user clicked "Enable Content"
         ↓
Check process execution (4688) shortly after
         ↓
If malicious process started = macro executed malware
```

**3. Document Source Analysis:**

{% code overflow="wrap" %}
```powershell
# Categorize trusted documents by location
Get-MacroEnabledDocs | ForEach-Object {
    $Location = switch -Regex ($_.DecodedPath) {
        "^\\\\.*" { "Network Share" }
        "Downloads" { "Downloads Folder" }
        "Temp" { "Temp Folder" }
        "AppData" { "AppData" }
        "Users\\.*\\Documents" { "Documents Folder" }
        "Users\\.*\\Desktop" { "Desktop" }
        default { "Other" }
    }
    
    [PSCustomObject]@{
        FilePath = $_.DecodedPath
        Application = $_.Application
        Location = $Location
        Risk = if ($Location -in @("Network Share", "Downloads Folder", "Temp Folder")) {"HIGH"} else {"MEDIUM"}
    }
} | Group-Object Location | Sort-Object Count -Descending
```
{% endcode %}

**Red Flags:**

```bash
🚩🚩🚩 CRITICAL - Macro-Enabled Documents:
   - From Downloads folder
   - From email attachments  
   - From Temp directories
   - From network shares (phishing campaigns)
   - With suspicious names (invoice.xls, payment.doc)
   
🚩 Documents trusted during compromise window
🚩 Multiple macro documents trusted in short time
🚩 Macros enabled by non-technical users
🚩 Documents from external sources
```

**Malware Investigation:**

```bash
If macro-enabled document found:
1. Collect document for analysis
2. Check document hash (VirusTotal)
3. Extract macros (olevba)
4. Check process execution after trust time
5. Check network connections
6. Check file modifications ($J)
7. Check for lateral movement
```

***

#### 4. Office OAlerts

**Overview:**

* **Purpose**: Log Office application alerts/prompts
* **Location**: OAlerts.evtx
* **Event ID**: 300 (all Office apps)
* **Forensic Value**: User interactions with Office

**Location:**

```bash
C:\Windows\System32\winevt\Logs\OAlerts.evtx
```

**Key Information:**

* Office application name
* Alert dialog message
* User response
* Timestamp

**Collection:**

```powershell
# Copy OAlerts log
Copy-Item "C:\Windows\System32\winevt\Logs\OAlerts.evtx" -Destination "C:\Analysis\"
```

**Analysis:**

**Using EvtxECmd:**

{% code overflow="wrap" %}
```powershell
# Parse OAlerts
.\EvtxECmd.exe -f "C:\Analysis\OAlerts.evtx" --csv "C:\Analysis" --csvf oalerts.csv

# Filter for Event ID 300
.\EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\OAlerts.evtx" --csv "C:\Analysis" --csvf oalerts.csv --inc 300
```
{% endcode %}

**PowerShell Query:**

```powershell
# Query OAlerts events
Get-WinEvent -Path "C:\Analysis\OAlerts.evtx" -FilterXPath "*[System[EventID=300]]" |
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Application = $_.Properties[0].Value
            Message = $_.Message
        }
    } | Export-Csv C:\Analysis\OAlerts_Parsed.csv -NoTypeInformation
```

**Investigation Use:**

```
Examples of what's logged:
- "Do you want to save changes?"
- "Enable editing?"
- "Enable content?"
- "File already exists, overwrite?"

Forensic Value:
✓ Proves user interaction with document
✓ Shows user decisions
✓ Timeline of Office activity
✓ Can correlate with Trust Records
```

***

### 🗑️ Deleted Items Investigation

#### 1. Recycle Bin Analysis

**Overview:**

* **Windows 7+**: Uses $I and $R files per deleted item
* **Location**: C:$Recycle.Bin{User-SID}\\
* **Forensic Value**: Deleted file recovery + deletion timeline

**Structure:**

```bash
C:\$Recycle.Bin\
├── S-1-5-21-XXX-XXX-XXX-1001\  (User SID)
│   ├── $I6A3B9D.docx  (Metadata: original path, size, deletion time)
│   ├── $R6A3B9D.docx  (Content: actual deleted file - can be recovered)
│   ├── $IFDE892.xlsx
│   └── $RFDE892.xlsx
└── S-1-5-21-XXX-XXX-XXX-1002\  (Another user)
```

**File Types:**

* **$I files**: Metadata (original filename, path, deletion time, size)
* **$R files**: Actual deleted file content (recoverable)
* **6-character identifier**: Links $I and $R files together

**Key Information:**

| Data Point            | Description                   | Source  |
| --------------------- | ----------------------------- | ------- |
| **Original Filename** | Full original name            | $I file |
| **Original Path**     | Complete path before deletion | $I file |
| **File Size**         | Size of deleted file          | $I file |
| **Deletion Time**     | When file was deleted         | $I file |
| **File Content**      | Actual file data              | $R file |

**Collection & Analysis:**

**Collection:**

{% code overflow="wrap" %}
```powershell
# Identify user SID
$Username = "john"
$UserSID = (Get-WmiObject -Class Win32_UserAccount | Where-Object {$_.Name -eq $Username}).SID

# Copy Recycle Bin contents for specific user
Copy-Item "C:\`$Recycle.Bin\$UserSID\*" -Destination "C:\Analysis\RecycleBin\" -Recurse -Force

# Or collect for all users
Copy-Item "C:\`$Recycle.Bin\*" -Destination "C:\Analysis\RecycleBin\" -Recurse -Force
```
{% endcode %}

**Using RBCmd (Recycle Bin Command Line):**

{% code overflow="wrap" %}
```powershell
# Parse single $I file
.\RBCmd.exe -f "C:\`$Recycle.Bin\S-1-5-21-XXX\`$I6A3B9D.docx"

# Parse all for specific user
.\RBCmd.exe -d "C:\`$Recycle.Bin\S-1-5-21-XXX\" --csv "C:\Analysis" --csvf recyclebin.csv -q

# Parse entire Recycle Bin
.\RBCmd.exe -d "C:\`$Recycle.Bin\" -q --csv "C:\Analysis" --csvf recyclebin_all.csv
```
{% endcode %}

**PowerShell Parsing:**

{% code overflow="wrap" %}
```powershell
# List deleted items
function Get-RecycleBinItems {
    param([string]$UserSID)
    
    $RecyclePath = "C:\`$Recycle.Bin\$UserSID"
    
    Get-ChildItem $RecyclePath -Filter "`$I*" | ForEach-Object {
        $IFile = $_
        $RFile = $IFile.FullName -replace '^\$I', '$R'
        
        [PSCustomObject]@{
            MetadataFile = $IFile.Name
            ContentFile = (Split-Path $RFile -Leaf)
            ContentExists = (Test-Path $RFile)
            DeletedTime = $IFile.LastWriteTime
            Size = $IFile.Length
        }
    }
}

# Get user SID and parse
$SID = (Get-WmiObject Win32_UserAccount | Where-Object {$_.Name -eq "john"}).SID
Get-RecycleBinItems -UserSID $SID | Export-Csv C:\Analysis\DeletedItems.csv -NoTypeInformation
```
{% endcode %}

**Investigation Workflows:**

**1. Deleted File Timeline:**

```bash
Goal: Build timeline of file deletions

Steps:
1. Parse all $I files
2. Extract deletion times
3. Sort chronologically
4. Identify patterns (mass deletions, cleanup activity)
```

**2. Sensitive File Deletion:**

```powershell
# Search for sensitive files in Recycle Bin
.\RBCmd.exe -d "C:\`$Recycle.Bin\" --csv "C:\Analysis"

$Deleted = Import-Csv C:\Analysis\*.csv

$Deleted | Where-Object {
    $_.OriginalPath -match "confidential|password|secret|financial|ssn"
} | Select-Object DeletedTime, OriginalPath, FileSize
```

**3. Mass Deletion Detection:**

```powershell
# Find bulk deletions (possible evidence destruction)
$Deleted = Import-Csv C:\Analysis\recyclebin_all.csv

# Group by time windows
$Deleted | ForEach-Object {
    $_.DeletedTime = [DateTime]$_.DeletedTime
    $_
} | Group-Object {$_.DeletedTime.ToString("yyyy-MM-dd HH")} |
    Where-Object {$_.Count -gt 10} |
    Sort-Object Name |
    ForEach-Object {
        [PSCustomObject]@{
            TimeWindow = $_.Name
            ItemsDeleted = $_.Count
            Files = $_.Group.OriginalPath
        }
    }
```

**4. File Recovery:**

```powershell
# Recover deleted files
$RFiles = Get-ChildItem "C:\`$Recycle.Bin\*\`$R*" -Recurse

foreach ($RFile in $RFiles) {
    # Find corresponding $I file for original name
    $IFile = $RFile.FullName -replace '^\$R', '$I'
    
    if (Test-Path $IFile) {
        # Parse $I to get original filename (would need proper parser)
        # For demo: copy with R filename
        Copy-Item $RFile.FullName -Destination "C:\Recovery\$($RFile.Name)"
    }
}
```

**Red Flags:**

```bash
🚩 Mass deletions:
   - Many files deleted in short time window
   - All files from specific folder
   - Deletion during/after suspicious activity
   
🚩 Sensitive file deletion:
   - Financial documents
   - HR files
   - Password files
   - Company confidential data
   
🚩 Evidence destruction:
   - Log files deleted
   - Security tool logs deleted
   - Recycle Bin emptied after suspicious activity
   
🚩 Cleanup activity:
   - Attacker tools deleted
   - Temporary files deleted
   - Downloaded malware deleted
```

**Pro Tips:**

✅ **Recovery Possible**: $R files are intact until overwritten

✅ **Timeline Evidence**: Deletion time preserved in $I files

✅ **User Attribution**: SID folder identifies who deleted files

⚠️ **Bypass**: Files deleted via command line with /F switch bypass Recycle Bin

⚠️ **Size Limit**: Very large files may bypass Recycle Bin

***

#### 2. Thumbcache Analysis

**Overview:**

* **Purpose**: Store thumbnail images of pictures, videos, documents
* **Location**: Per-user Explorer folder
* **Forensic Value**: Thumbnails survive file deletion!
* **Available**: Windows Vista+

**Location:**

```bash
C:\Users\{Username}\AppData\Local\Microsoft\Windows\Explorer\
```

**Files:**

```bash
thumbcache_16.db     (16x16 thumbnails - icons)
thumbcache_32.db     (32x32 thumbnails)
thumbcache_48.db     (48x48 thumbnails)
thumbcache_96.db     (96x96 thumbnails)
thumbcache_256.db    (256x256 thumbnails)
thumbcache_1024.db   (1024x1024 thumbnails)
thumbcache_1280.db   (1280x1280 thumbnails)
thumbcache_1600.db   (1600x1600 thumbnails - HD)
thumbcache_2560.db   (2560x2560 thumbnails - extra large)
thumbcache_sr.db     (Stream thumbnails)
thumbcache_idx.db    (Index file)
```

**Key Information:**

* Thumbnail image (visual)
* Thumbnail Cache ID
* File hash
* Image can be extracted even if original deleted

**Collection:**

{% code overflow="wrap" %}
```powershell
# Collect thumbcache databases
$User = "username"
Copy-Item "C:\Users\$User\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" -Destination "C:\Analysis\Thumbcache\"
```
{% endcode %}

**Analysis:**

**Using thumbcache\_viewer.exe:**

```bash
1. Run thumbcache_viewer.exe
2. Load thumbcache database (e.g., thumbcache_256.db)
3. View thumbnail images
4. Export thumbnails
5. Note Cache Entry IDs for cross-reference
```

**Using thumbs\_viewer.exe:**

```bash
Similar GUI tool:
1. Load database
2. Browse thumbnails
3. Export images
4. Save metadata
```

**Investigation Workflows:**

**1. Deleted Image Recovery:**

```bash
Goal: Recover images of deleted files

Process:
1. Extract thumbnails from thumbcache
2. Visually review images
3. Identify relevant images
4. Cross-reference with Windows Search Database using Cache ID
5. Determine original filename and path
```

**2. Content Verification:**

```bash
Use cases:
- Verify file contents before deletion
- Identify inappropriate images
- Confirm data exfiltration
- Prove file existence
```

**3. Timeline Construction:**

```bash
Thumbcache + Windows Search + MFT:
1. Thumbcache shows image existed
2. Cache ID → Windows Search → Filename
3. Filename → MFT → Timestamps
4. Complete timeline of image activity
```

**Cross-Reference Strategy:**

```bash
thumbcache_256.db → Extract thumbnail → Get Cache ID
         ↓
Windows.edb (Search Database) → Match Cache ID → Get filename, path
         ↓
$MFT → Match filename → Get full timestamps
         ↓
Complete picture: Image + Name + Path + Timestamps
```

***

#### 3. Windows Search Database

**Overview:**

* **Purpose**: Index files for fast searching
* **Format**: ESE database (Extensible Storage Engine)
* **Location**: System-wide (not per-user)
* **Forensic Value**: File metadata + partial content + survives deletion

**Location:**

```bash
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb

Gather Logs (candidate files for indexing):
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex\
```

**Key Information:**

* File paths
* File metadata (size, dates, properties)
* Partial file content (indexed text)
* Email metadata
* Document properties
* Over 900 file types indexed

**Collection:**

{% code overflow="wrap" %}
```powershell
# Copy Windows.edb (may be locked - use forensic tools)
# Using Volume Shadow Copy
$VSS = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
$Shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $VSS.ShadowID}
$ShadowPath = $Shadow.DevicePath + "\ProgramData\Microsoft\Search\Data\Applications\Windows\"

Copy-Item "$ShadowPath\Windows.edb" -Destination "C:\Analysis\"
$Shadow.Delete()

# Or use RawCopy
RawCopy.exe /FileNamePath:"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /OutputPath:"C:\Analysis"
```
{% endcode %}

**Analysis:**

**Using ESEDatabaseView (NirSoft):**

```bash
1. Run ESEDatabaseView
2. Open Windows.edb
3. Browse tables
4. Search for keywords
5. Export results
```

**Using KAPE:**

```powershell
.\kape.exe --target WindowsSearchDatabase --tdest C:\Analysis
```

**Investigation Workflows:**

**1. Deleted File Search:**

```bash
Windows Search may contain metadata of deleted files:
- Original path
- File size
- Creation/modification dates
- File properties
- Partial content
```

**2. Keyword Search:**

```bash
Search database for:
- Sensitive keywords
- Filenames
- Document content
- Email content
```

**3. Email Investigation:**

```bash
Outlook emails indexed:
- Sender/recipient
- Subject lines
- Body content (partial)
- Attachments
```

***

#### 4. Thumbs.db (Legacy - Windows XP)

**Overview:**

* **Purpose**: Store thumbnails per folder
* **Available**: Windows XP (can appear on modern systems via UNC)
* **Location**: Each folder with images
* **Forensic Value**: Thumbnails + filenames (XP only)

**Key Information (XP):**

* Thumbnail image
* Original filename
* Last modification time

**Modern Systems:**

* Thumbs.db may be created when viewing folders via UNC paths
* Limited metadata compared to XP

**Collection:**

```powershell
# Find all Thumbs.db files
Get-ChildItem C:\ -Recurse -Filter "Thumbs.db" -Force -ErrorAction SilentlyContinue |
    Copy-Item -Destination "C:\Analysis\ThumbsDB\" -Force
```

***

#### 5. Internet Explorer File Access History

**Overview:**

* **Purpose**: IE history contains local file access via file:/// protocol
* **Forensic Value**: Tracks file opening even if not opened in browser
* **Location**: WebCache database
* **Persists**: Even on Windows 11 without IE!

**Location:**

```bash
C:\Users\{Username}\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat
```

**Key Information:**

* Local file paths
* Access times
* File:/// protocol entries
* Network share (UNC) access

**Format:**

```bash
file:///C:/Users/John/Documents/report.docx
file:///C:/Temp/malware.exe
file:///\\SERVER\Share\confidential.xlsx
```

**Collection:**

{% code overflow="wrap" %}
```powershell
# Copy WebCache database
$User = "username"
Copy-Item "C:\Users\$User\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat" -Destination "C:\Analysis\"
```
{% endcode %}

**Analysis:**

**Using Nirsoft BrowsingHistoryView:**

```bash
1. Run BrowsingHistoryView
2. Advanced Options → Load history from specific profile
3. Filter for "file:///" entries
4. Export to CSV
```

**Using ESEDatabaseView:**

```bash
1. Open WebCacheV01.dat
2. Browse Container_# tables
3. Search for "file:///" URLs
4. Export results
```

**Investigation Use:**

```bash
File access logged even when:
✓ File double-clicked in Explorer
✓ File opened from network share
✓ Not actually opened in browser

Important for:
- File access timeline
- Network share access
- Deleted file evidence (path preserved)
```

***

### 🔍 Search and Navigation History

#### 1. WordWheelQuery

**Overview:**

* **Purpose**: Store Windows Search keywords from File Explorer
* **Location**: NTUSER.DAT per user
* **Forensic Value**: Shows what user searched for

**Registry Location:**

```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```

**Key Information:**

* Search keywords (Unicode)
* Temporal order (MRUListEx)
* Last search (registry LastWriteTime)

**Collection & Analysis:**

```powershell
# Query WordWheelQuery
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /s
```

**Using Registry Explorer:**

{% code overflow="wrap" %}
```bash
1. Load NTUSER.DAT
2. Navigate: Software → Microsoft → Windows → CurrentVersion → Explorer → WordWheelQuery
3. Review numbered values (MRU order)
4. Last value in MRUListEx = most recent search
5. Export to CSV
```
{% endcode %}

**Using RegRipper:**

```powershell
.\rr.exe -r "NTUSER.DAT" -p wordwheelquery > wordwheelquery.txt
```

**Investigation Workflows:**

**1. Keyword Analysis:**

```bash
What was user searching for?
- Filenames
- Document content
- Sensitive keywords
- Tool names
```

**2. Incident Investigation:**

{% code overflow="wrap" %}
```powershell
# Search for incident-related keywords
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /s |
    Select-String -Pattern "password|confidential|payroll|credential"
```
{% endcode %}

**Red Flags:**

```bash
🚩 Suspicious searches:
   - "password", "credential", "confidential"
   - Company secrets
   - Tools (mimikatz, procdump)
   - How to delete evidence
   - Data exfiltration methods
   
🚩 Timeline correlation:
   - Searches during compromise window
   - Searches before file access
   - Searches before data theft
```

***

#### 2. TypedPaths

**Overview:**

* **Purpose**: Track paths typed directly into File Explorer address bar
* **Location**: NTUSER.DAT
* **Forensic Value**: Shows user knowledge of specific locations

**Registry Location:**

```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

**Key Information:**

* Paths manually typed by user
* Order of entry (url1, url2, etc.)
* Indicates intentional navigation

**Collection & Analysis:**

```powershell
# Query TypedPaths
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /s
```

**Using Registry Explorer:**

```bash
1. Load NTUSER.DAT
2. Navigate: Software → Microsoft → Windows → CurrentVersion → Explorer → TypedPaths
3. Review url1, url2, url3... values
4. Export to CSV
```

**Investigation Workflows:**

**1. Hidden Location Detection:**

```bash
TypedPaths shows user knew specific path:
- Hidden folders
- System directories
- Network shares
- External drives
```

**2. Intentional Access:**

```bash
Difference between:
- Browsing to folder (not in TypedPaths)
- Typing path directly (in TypedPaths) ← More suspicious
```

**Red Flags:**

```bash
🚩 Suspicious paths:
   - C:\Windows\System32\config (registry hives)
   - C:\$Recycle.Bin (deleted files)
   - \\SERVER\C$ (admin shares)
   - Hidden directories
   - Temp folders with specific malware paths
   
🚩 External shares:
   - \\WORKSTATION\C$ (lateral movement)
   - \\SERVER\ADMIN$
   
🚩 Knowledge indicator:
   - User shouldn't know these paths
   - Typed complex paths from memory
   - System/hidden folders
```

***

### 📚 Investigation Playbooks

#### Playbook 1: Data Exfiltration Investigation

**Objective**: Detect and quantify data theft

**Phase 1: Document Access (30 min)**

```bash
□ Check RecentDocs for recently accessed files
□ Identify file types and sensitivity
□ Check Office MRU for document access
□ Review LNK files for exact access times
□ Cross-reference with user's normal behavior
```

**Phase 2: External Media (30 min)**

```bash
□ Check LNK files for E:, F:, G: drive letters
□ Extract volume serial numbers (USB device tracking)
□ Check RecentDocs for external drive paths
□ Review Jump Lists for USB file access
□ Correlate with logon/logoff times
```

**Phase 3: Network Shares (30 min)**

```bash
□ Check LNK files for UNC paths (\\SERVER\)
□ Review LastVisitedMRU for network locations
□ Check IE file history for file:// network access
□ Identify destination servers
□ Correlate with authentication logs
```

**Phase 4: Timeline Construction (45 min)**

```bash
□ Build timeline using:
  - RecentDocs LastWriteTime
  - LNK file timestamps (creation = first access, modified = last access)
  - Office MRU access times
  - Event logs (4624 logons)
□ Identify exfiltration windows
□ Correlate with USB insertion events
```

**Phase 5: Quantification (30 min)**

```bash
□ List all accessed documents
□ Check file sizes (from LNK or MFT)
□ Calculate total data volume
□ Identify most sensitive documents
□ Determine exfiltration method (USB, network, email)
```

***

#### Playbook 2: Malicious Document Investigation

**Objective**: Investigate macro-enabled document compromise

**Phase 1: Trust Record Analysis (15 min)**

```bash
□ Check Office Trust Records for macro-enabled docs
□ Extract documents with FF FF FF 7F signature
□ Note trust timestamps
□ Identify document locations (Downloads? Email?)
```

**Phase 2: Document Source (20 min)**

```bash
□ Check Office MRU for document open time
□ Review LNK files for document access
□ Check RecentDocs for document path
□ Determine source:
  - Email attachment?
  - Web download?
  - Network share?
  - USB drive?
```

**Phase 3: Execution Timeline (30 min)**

```bash
□ Trust Record time = When macros enabled
□ Check process execution (Event 4688) after trust time
□ Look for:
  - PowerShell execution
  - cmd.exe spawning
  - Unusual processes
  - Network connections
□ Window: 0-5 minutes after macro enablement
```

**Phase 4: Impact Assessment (45 min)**

```bash
□ Check if malicious processes executed
□ Review network activity (SRUM)
□ Check file modifications ($J)
□ Look for lateral movement
□ Check for persistence (Run keys, services, tasks)
□ Review Prefetch for malware execution
```

**Phase 5: IOC Extraction (30 min)**

```bash
□ Document hash (if file still exists)
□ Document metadata
□ Macro code (if available)
□ Process tree
□ Network indicators
□ File modifications
```

***

#### Playbook 3: Insider Threat - Document Access

**Objective**: Investigate unauthorized document access

**Phase 1: Scope Definition (15 min)**

```bash
□ Identify suspected insider
□ Determine timeframe
□ List sensitive documents/folders
□ Define normal access patterns for user
```

**Phase 2: Recent Activity (30 min)**

```bash
□ Check RecentDocs for accessed files
□ Review Office MRU (Word, Excel, PowerPoint)
□ Check OpenSaveMRU for document types
□ Analyze Reading Locations (time spent in documents)
□ Review LNK files for detailed timeline
```

**Phase 3: Anomaly Detection (45 min)**

```bash
□ Compare recent activity vs. baseline:
  - File types accessed
  - Folders accessed
  - Time of day
  - Frequency
  
□ Red flags:
  - Access to files outside normal scope
  - After-hours access
  - Mass document opening
  - Access to HR/Finance/IP documents
```

**Phase 4: Search Behaviour (20 min)**

```bash
□ Check WordWheelQuery for searches
□ Review TypedPaths for deliberate navigation
□ Correlate searches with file access
□ Look for sensitive keyword searches
```

**Phase 5: Exfiltration Check (45 min)**

```bash
□ Check for USB device usage (LNK files)
□ Review network share access
□ Check email activity (if available)
□ Review file copying patterns
□ Check Recycle Bin for evidence destruction
```

***

#### Playbook 4: Deleted File Recovery

**Objective**: Recover and analyze deleted files

**Phase 1: Recycle Bin (20 min)**

```bash
□ Parse Recycle Bin with RBCmd
□ Extract $I files (metadata)
□ Identify $R files (recoverable content)
□ Build deletion timeline
□ Identify sensitive deleted files
```

**Phase 2: Artifact Persistence (30 min)**

```bash
Deleted files may still appear in:
□ RecentDocs registry
□ LNK files (Recent folder)
□ Office MRU
□ Jump Lists
□ IE file history
□ Windows Search database

Extract:
- Original filenames
- Original paths
- Access times
- File sizes
```

**Phase 3: Visual Evidence (30 min)**

```bash
□ Extract thumbcache databases
□ Recover thumbnail images
□ Identify deleted images visually
□ Cross-reference Cache IDs with Windows Search
□ Determine original filenames
```

**Phase 4: File System Analysis (60 min)**

```bash
□ Check $J (UsnJrnl) for deletion records
□ Review $MFT for file records (may still exist)
□ Check $LogFile for recent operations
□ Use file carving tools if necessary
□ Check Volume Shadow Copies
```

**Phase 5: Timeline Construction (30 min)**

```bash
□ When files were created (MFT, LNK)
□ When files were last accessed (LNK, RecentDocs)
□ When files were deleted (Recycle Bin $I)
□ User who deleted (Recycle Bin SID folder)
□ Context around deletion (Event logs)
```

***

### 🛠️ Tool Reference

#### Registry Analysis Tools

**Registry Explorer (GUI)** - Eric Zimmerman

```bash
Download: https://ericzimmerman.github.io/
Usage: Load NTUSER.DAT, SOFTWARE, SAM hives
Features: Bookmarks, search, export, live system loading
```

**RegRipper (CLI)** - H. Carvey

```bash
Download: https://github.com/keydet89/RegRipper3.0
Usage: .\rr.exe -r NTUSER.DAT -p [plugin] > output.txt

Common plugins:
- recentdocs
- opensavemru
- comdlg32
- wordwheelquery
- runmru
- userassist
```

**RECmd (CLI)** - Eric Zimmerman

```bash
Download: https://ericzimmerman.github.io/
Usage: .\RECmd.exe -f NTUSER.DAT --csv C:\Output

Features: Batch processing, CSV output, live system support
```

***

#### LNK File Analysis Tools

**LECmd (CLI)** - Eric Zimmerman

{% code overflow="wrap" %}
```bash
Download: https://ericzimmerman.github.io/

Single file:
.\LECmd.exe -f file.lnk --csv C:\Output

Directory:
.\LECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Output -q

All metadata:
.\LECmd.exe -d Recent --all --csv C:\Output
```
{% endcode %}

**ExifTool (CLI)**

```bash
Download: https://exiftool.org/

Extract metadata:
exiftool file.lnk

Batch CSV:
exiftool -csv -r C:\LNK\ > output.csv
```

***

#### Recycle Bin Tools

**RBCmd (CLI)** - Eric Zimmerman

```bash
Download: https://ericzimmerman.github.io/

Single file:
.\RBCmd.exe -f $I6A3B9D.docx

Directory:
.\RBCmd.exe -d "C:\$Recycle.Bin\S-1-5-21-XXX" --csv C:\Output -q

All users:
.\RBCmd.exe -d "C:\$Recycle.Bin" --csv C:\Output
```

**Rifiuti2 (CLI)**

```bash
Download: https://github.com/abelcheung/rifiuti2

Usage: rifiuti-vista.exe -x -o output.xml "C:\$Recycle.Bin\S-1-5-21-XXX"
```

***

#### Thumbcache Tools

**thumbcache\_viewer.exe** - Thumbsviewer Project

```bash
Download: https://thumbsviewer.github.io/
Usage: GUI - Load database, export thumbnails
```

**thumbs\_viewer.exe** - Vinetto Project

```bash
Usage: Extract and view thumbnails from thumbcache
```

***

#### Event Log Tools

**EvtxECmd (CLI)** - Eric Zimmerman

```bash
Download: https://ericzimmerman.github.io/

Parse OAlerts:
.\EvtxECmd.exe -f OAlerts.evtx --csv C:\Output --inc 300
```

***

#### Database Tools

**ESEDatabaseView** - NirSoft

```bash
Download: https://www.nirsoft.net/utils/ese_database_view.html
Usage: Open Windows.edb, WebCacheV01.dat
```

**DB Browser for SQLite**

```bash
Download: https://sqlitebrowser.org/
Usage: Open SQLite databases
```

***

#### Collection Tools

**KAPE** - Kroll Artifact Parser and Extractor

```bash
Download: https://www.kroll.com/kape

Collect MRU artifacts:
.\kape.exe --target RecentFileCache,LNKFiles,RegistryHives --tdest C:\Collection

Full file access artifacts:
.\kape.exe --target FileExplorerArtifacts --tdest C:\Collection
```

**FTK Imager**

```bash
Download: https://www.exterro.com/ftk-imager
Usage: Mount images, collect locked files
```

***

### 📊 Quick Reference Cards

#### Artifact Comparison Matrix

| Artifact           | File Path   | Deleted Files  | Timestamps    | User Attribution | File Size | Network Shares |
| ------------------ | ----------- | -------------- | ------------- | ---------------- | --------- | -------------- |
| **RecentDocs**     | ✅ Yes       | ✅ Survives     | ⚠️ Key time   | ✅ Per user       | ❌ No      | ✅ UNC paths    |
| **OpenSaveMRU**    | ✅ Yes       | ✅ Survives     | ⚠️ Key time   | ✅ Per user       | ❌ No      | ✅ UNC paths    |
| **LastVisitedMRU** | ⚠️ Folder   | ✅ Survives     | ⚠️ Key time   | ✅ Per user       | ❌ No      | ✅ UNC paths    |
| **LNK Files**      | ✅ Yes       | ✅ Survives     | ✅ Multiple    | ✅ Per user       | ✅ Yes     | ✅ Full UNC     |
| **Office MRU**     | ✅ Full path | ✅ Survives     | ✅ Last open   | ✅ Per user       | ❌ No      | ✅ UNC paths    |
| **Trust Records**  | ✅ Yes       | ✅ Survives     | ✅ Trust time  | ✅ Per user       | ❌ No      | ✅ UNC paths    |
| **Recycle Bin**    | ✅ Original  | ✅ **Content!** | ✅ Delete time | ✅ SID folder     | ✅ Yes     | ❌ No           |
| **Thumbcache**     | ⚠️ Via ID   | ✅ Thumbnails   | ❌ No          | ✅ Per user       | ❌ No      | ❌ No           |
| **IE History**     | ✅ file:///  | ✅ Survives     | ✅ Access      | ✅ Per user       | ❌ No      | ✅ file://      |

#### Collection Priority (Live System)

**First 5 Minutes:**

```bash
1. Recycle Bin (evidence destruction risk)
2. RecentDocs registry query (quick overview)
3. Office Trust Records (macro-enabled docs)
4. Running process list
5. Active network connections
```

**Next 15 Minutes:**

```bash
6. LNK files (Recent folder)
7. NTUSER.DAT (all MRU data)
8. Thumbcache databases
9. Office MRU registry keys
10. WordWheelQuery (searches)
```

**Next 30 Minutes:**

```bash
11. Windows.edb (Search database)
12. WebCache (IE history)
13. Office OAlerts.evtx
14. Event logs (4688, 4624)
15. $MFT, $J (file system)
```

#### Investigation Time Estimates

| Task                                  | Estimated Time |
| ------------------------------------- | -------------- |
| Quick triage (RecentDocs, searches)   | 10-15 min      |
| LNK file analysis (50-100 files)      | 20-30 min      |
| Office artifact analysis              | 30-45 min      |
| Recycle Bin analysis                  | 15-30 min      |
| Thumbcache extraction                 | 30-60 min      |
| Complete file access timeline         | 2-3 hours      |
| Data exfiltration investigation       | 3-4 hours      |
| Insider threat comprehensive analysis | 4-6 hours      |

***

### 🎓 Pro Tips

#### Cross-Referencing Strategy

```bash
Always cross-reference multiple artifacts:

RecentDocs → Shows file was accessed
     ↓
LNK Files → Provides exact timestamps + original path
     ↓
Office MRU → Confirms application used + open time
     ↓
Reading Locations → Proves document was actually read
     ↓
Trust Records → Shows if macros were enabled
     ↓
Event 4688 → Shows processes executed after
     ↓
Complete attack chain
```

#### Timeline Construction

```bash
Build comprehensive timeline:

1. Logon time (Event 4624)
2. File searched (WordWheelQuery)
3. Folder navigated (TypedPaths)
4. File accessed (LNK creation time)
5. File opened (RecentDocs, Office MRU)
6. Macros enabled (Trust Records)
7. Process executed (Event 4688)
8. File deleted (Recycle Bin)
9. Logoff (Event 4634)

Result: Complete picture of user activity
```

#### Common Pitfalls

```bash
❌ Only checking RecentDocs (missing LNK details)
❌ Ignoring deleted files (artifacts persist!)
❌ Not checking Office-specific MRU
❌ Missing Trust Records (macro investigation)
❌ Forgetting network share access (IE history)
❌ Not cross-referencing timestamps
❌ Ignoring thumbnail evidence
❌ Missing search terms (intent evidence)
```

#### Red Flag Summary

```bash
🚩🚩🚩 CRITICAL INDICATORS:

1. Macro-enabled documents from Downloads/Email
2. Mass file deletion in short time window
3. Sensitive files accessed by unauthorised user
4. Files accessed from USB drives
5. Network admin share access (\\C$)
6. Searches for "password", "confidential", "delete"
7. After-hours document access
8. File paths typed manually (TypedPaths)
9. Recycle Bin emptied after suspicious activity
10. Documents accessed then immediately deleted
```

***

_Use this guide for comprehensive file and folder access investigations. Remember: Artifacts persist after deletion - always check multiple sources!_
