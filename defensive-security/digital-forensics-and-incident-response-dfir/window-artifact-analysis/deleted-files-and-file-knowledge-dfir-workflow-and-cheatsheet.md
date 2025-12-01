---
cover: ../../../../.gitbook/assets/Screenshot 2025-01-05 105840 (1).png
coverY: 0
---

# Deleted Files & File Knowledge—DFIR Workflow & Cheatsheet

## Quick Reference: Investigation Priority Matrix

| Priority   | Artifact          | Key Questions Answered                  | Data Retention | OS Version |
| ---------- | ----------------- | --------------------------------------- | -------------- | ---------- |
| **HIGH**   | Recycle Bin       | What deleted? When? By whom?            | Until emptied  | All        |
| **HIGH**   | Windows Search DB | What files existed? Content? Metadata?  | Persistent     | Vista+     |
| **HIGH**   | Recent Docs MRU   | What files accessed? By what app?       | Medium         | All        |
| **MEDIUM** | Thumbcache        | What images/docs viewed? (even deleted) | High           | Vista+     |
| **MEDIUM** | IE File History   | What files opened (local/network)?      | Medium         | All        |
| **MEDIUM** | WordWheelQuery    | What did user search for?               | Medium         | All        |
| **LOW**    | TypedPaths        | What paths manually typed?              | Low            | All        |
| **LOW**    | Thumbs.db         | What images in folder? (legacy)         | High           | XP/Legacy  |

***

## Investigation Workflow

## Phase 1: Deleted File Recovery (Critical Priority)

**Goal:** Recover deleted files and establish deletion timeline

### **1.1 Recycle Bin Analysis**

**What it tells you:** Deleted files, original location, deletion time, file size

**Location:**

```bash
C:\$Recycle.Bin\<USER-SID>\
```

**File Structure (Windows 7+):**

* **$I files** - Metadata (original filename, path, deletion date/time, size)
* **$R files** - Actual deleted file content (renamed copy)
* **$I and $R share same 6-character identifier**

**Quick Investigation Commands:**

```batch
REM Navigate to Recycle Bin
cd C:\$Recycle.Bin
dir /a

REM List contents of specific user's recycle bin
cd <USER-SID>
dir /a

REM View original filename and path
type $I<6-chars>.ext

REM Copy deleted file for analysis
copy $R<6-chars>.ext C:\Cases\Evidence\recovered_file.ext
```

**PowerShell Collection:**

```powershell
# List all deleted items with metadata
Get-ChildItem "C:\$Recycle.Bin" -Recurse -Force | 
    Where-Object {$_.Name -like '$I*'} | 
    Select-Object FullName, Length, CreationTime

# Copy all Recycle Bin contents for analysis
Copy-Item "C:\$Recycle.Bin\*" -Destination "C:\Cases\RecycleBin" -Recurse -Force
```

**Using Eric Zimmerman's RBCmd:**

{% code overflow="wrap" %}
```batch
REM Parse single $I file
RBCmd.exe -f "C:\$Recycle.Bin\<SID>\$I<chars>.ext"

REM Process entire Recycle Bin directory to CSV
RBCmd.exe -d "C:\$Recycle.Bin" -q --csv "C:\Cases\Output" --csvf RecycleBin_Analysis.csv

REM Process specific user's recycle bin
RBCmd.exe -d "C:\$Recycle.Bin\<USER-SID>" --csv "C:\Cases\Output" --csvf User_RecycleBin.csv
```
{% endcode %}

**Key Investigation Points:**

* ✓ Map SID to username via Registry (see SID Mapping section)
* ✓ $I file contains: Original path, filename, size, deletion timestamp
* ✓ $R file IS the actual deleted file (can be opened/analysed)
* ✓ Files persist until Recycle Bin is emptied
* ✓ Check file size - large files may not go to Recycle Bin
* ✓ Network deletions bypass Recycle Bin
* ✓ Shift+Delete bypasses Recycle Bin

**Forensic Value:**

```bash
✓ Proof of deletion (intent to conceal?)
✓ Original file location (reveals user knowledge)
✓ Exact deletion timestamp
✓ File content recovery (if not overwritten)
✓ Attribution to specific user account
```

***

## Phase 2: File Existence & Metadata (High Priority)

**Goal:** Prove files existed, even if deleted and not in Recycle Bin

### **2.1 Windows Search Database (ESE Database)**

**What it tells you:** Indexed file metadata, partial content, extensive file properties

**Location:**

```bash
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex
```

**Database Format:** Extensible Storage Engine (ESE) - same as Active Directory

**Key Investigation Points:**

* ✓ **Indexes 900+ file types** (documents, emails, media, etc.)
* ✓ Stores extensive metadata: filename, path, size, dates, author, title
* ✓ May contain **partial file content** for text searching
* ✓ **GatherLogs** folder contains candidate files for indexing (24-hour cycles)
* ✓ Data persists even after file deletion
* ✓ Can prove file existed on system
* ✓ Timestamps: Created, Modified, Accessed

**Required Tools:**

```bash
ESEDatabaseView (NirSoft) - View ESE databases
Windows Search Index Examiner - Parse Windows.edb
libesedb - Open-source ESE parser
KAPE - Has Windows Search targets
```

**Analysis Workflow:**

```bash
1. Copy Windows.edb to analysis workstation
2. Use ESEDatabaseView or specialized parser
3. Search for keywords related to investigation
4. Extract metadata for files of interest
5. Cross-reference with Thumbcache using Thumbnail Cache ID
6. Document file existence and metadata
```

**Forensic Value:**

```bash
✓ Proves file existed on system
✓ Shows file paths (including network shares, USB drives)
✓ Author/creator information from metadata
✓ Last modified dates (even for deleted files)
✓ Partial content may reveal sensitive data
✓ Email metadata (sender, recipient, subject)
```

**Critical Notes:**

* ⚠️ Indexing must be enabled (usually default)
* ⚠️ Some file types may not be indexed
* ⚠️ External drives only indexed if specifically configured
* ⚠️ Large database - focus on targeted searches

***

### **2.2 Internet Explorer File History**

**What it tells you:** Local and network file access via file:/// protocol

**Location:**

```bash
IE 10-11 and Windows 10+:
%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat
```

**Key Investigation Points:**

* ✓ Tracks file access even on Windows 11 (no IE installed)
* ✓ Format: `file:///C:/directory/filename.ext`
* ✓ **Does NOT mean file was opened in browser**
* ✓ Tracks both local and UNC path access
* ✓ ESE database format (use ESEDatabaseView)
* ✓ Includes access timestamps

**Common Scenarios Tracked:**

```bash
file:///C:/Users/Alice/Documents/classified.docx
file:///D:/USB_Drive/evidence.xlsx
file:////FileServer/Share/confidential.pdf
```

**Forensic Value:**

```bash
✓ File access via File Explorer
✓ Network share access (reveals external knowledge)
✓ USB drive file access
✓ Timeline of file interactions
✓ May reveal files not in other artifacts
```

**Analysis Commands:**

{% code overflow="wrap" %}
```powershell
# Copy WebCache database
Copy-Item "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\*.dat" -Destination "C:\Cases\WebCache\"

# Use ESEDatabaseView or:
# BrowsingHistoryView (NirSoft) - includes file:/// entries
```
{% endcode %}

***

## Phase 3: File Access & User Knowledge (Medium Priority)

**Goal:** Understand what files user accessed and how they knew about them

### **3.1 Recent Documents MRU (Most Recently Used)**

**What it tells you:** Recent files accessed per application

**Primary Locations:**

**RecentDocs (Overall):**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

Registry Hive: NTUSER.DAT per user
Live Path: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```
{% endcode %}

**LastVisitedPidlMRU (Application-specific):**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU

Live Path: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```
{% endcode %}

**OpenSavePidlMRU (Files opened/saved):**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

Live Path: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```
{% endcode %}

**RunMRU (Commands executed via Run dialog):**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

Live Path: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
{% endcode %}

**Key Investigation Points:**

* ✓ **RecentDocs** shows files accessed across all applications
* ✓ **LastVisitedPidlMRU** links applications to last folder accessed
* ✓ Shows executable + last file system location it touched
* ✓ **OpenSavePidlMRU** organized by file extension
* ✓ Reveals hidden and unusual directories
* ✓ MRU = Most Recently Used (temporal order)
* ✓ Last Write Time = Most recent activity in that key

**Analysis Tools:**

```bash
RegRipper (rr.exe) - Automated MRU extraction
RegistryExplorer.exe - Manual registry browsing
RECmd.exe (Eric Zimmerman) - Advanced registry parsing
```

**RegRipper Commands:**

```batch
REM Extract all MRU data from NTUSER.DAT
rr.exe -r "C:\Users\Alice\NTUSER.DAT" -p recentdocs

REM Run all plugins against NTUSER.DAT
rr.exe -r "C:\Users\Alice\NTUSER.DAT" -a
```

**Forensic Value:**

```bash
✓ Applications executed by user
✓ Files accessed by specific applications
✓ Knowledge of file system locations
✓ Hidden/external/network paths accessed
✓ Temporal access patterns (MRU order)
✓ Commands run via Windows Run dialog
```

**Investigation Tips:**

* ✓ Check for suspicious directories (hidden folders, temp locations)
* ✓ Look for USB drive paths (E:, F:, etc.)
* ✓ Network share paths reveal lateral movement
* ✓ Uncommon applications accessing sensitive locations
* ✓ Cross-reference with LNK files and Jump Lists

***

### **3.2 WordWheelQuery (File Explorer Searches)**

**What it tells you:** Keywords searched in Windows Explorer search bar

**Location:**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery

Live Path: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```
{% endcode %}

**Key Investigation Points:**

* ✓ **Unicode** formatted search terms
* ✓ **MRU list** (temporal order - most recent first)
* ✓ Last Write Time = Last search conducted
* ✓ Shows user's search intent and knowledge
* ✓ Reveals what user was looking for

**Analysis Workflow:**

```bash
1. Load NTUSER.DAT in RegistryExplorer
2. Navigate to WordWheelQuery key
3. Note Last Write Time (last search timestamp)
4. List all MRU entries in order
5. Document suspicious keywords
```

**Example Search Terms (Indicators):**

```bash
Suspicious: "password", "confidential", "payroll", "delete", "encrypt"
USB Related: "usb", "removable", "E:", "external"
Anti-Forensics: "ccleaner", "bleach", "shred", "secure delete"
```

**Forensic Value:**

```bash
✓ User's search intent
✓ Knowledge of specific files/data
✓ Attempted data location
✓ Consciousness of guilt (searching for cleanup tools)
✓ Timeline of search activity
```

***

### **3.3 TypedPaths (Manually Entered Paths)**

**What it tells you:** Paths typed directly into Explorer address bar

**Location:**

{% code overflow="wrap" %}
```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

Live Path: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```
{% endcode %}

**Key Investigation Points:**

* ✓ User manually typed path instead of browsing
* ✓ **Indicates knowledge** of specific location
* ✓ Reveals hidden, network, or external drive paths
* ✓ Shows familiarity with file system structure
* ✓ Limited number of entries stored

**Common Typed Paths:**

```bash
C:\ProgramData\Hidden\SecretFolder
\\FileServer\Share\Confidential
E:\ExternalDrive\StolenData
C:\Users\Bob\AppData\Local\Temp
```

**Forensic Value:**

```bash
✓ Proof of knowledge of specific locations
✓ Access to hidden folders (not discovered by browsing)
✓ Network share access
✓ External drive familiarity
✓ Deliberate navigation to specific path
```

**Analysis:**

```bash
RegRipper: rr.exe -r NTUSER.DAT -p typedpaths
Manual: RegistryExplorer → Browse to TypedPaths key
```

***

## Phase 4: Visual Evidence (Medium Priority)

**Goal:** Recover thumbnail images as visual proof

### **4.1 Thumbcache (Windows Vista+)**

**What it tells you:** Thumbnail previews of images, documents, folders

**Location:**

```bash
%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\

Files:
thumbcache_32.db, thumbcache_96.db, thumbcache_256.db, thumbcache_1024.db
thumbcache_idx.db, thumbcache_sr.db, iconcache_*.db
```

**Database Files by Size:**

```bash
thumbcache_32.db    - 32x32 px thumbnails (small icons)
thumbcache_96.db    - 96x96 px thumbnails (medium icons)
thumbcache_256.db   - 256x256 px thumbnails (large icons)
thumbcache_1024.db  - 1024x1024 px thumbnails (extra large)
thumbcache_idx.db   - Index database
thumbcache_sr.db    - System Resources
iconcache_*.db      - Application icon cache
```

**Key Investigation Points:**

* ✓ **Persists after file deletion** - visual evidence remains
* ✓ Created when folder viewed in thumbnail view
* ✓ Each size stored in separate database
* ✓ **Thumbnail Cache ID** cross-references to Windows Search DB
* ✓ Can extract actual thumbnail images
* ✓ Proves user viewed file/folder graphically

**Cross-Reference Capability:**

```bash
Thumbcache → Thumbnail Cache ID → Windows Search DB → Full file metadata
```

**Analysis Tools:**

```bash
thumbcache_viewer.exe - Extract and view thumbnails
Thumbs Viewer (Sanderson Forensics) - Commercial tool
ThumbsExtract (NirSoft) - Extract thumbnails
```

**Workflow:**

```bash
1. Copy all thumbcache_*.db files to analysis system
2. Use thumbcache_viewer.exe to open databases
3. Extract thumbnails of interest
4. Note Thumbnail Cache IDs
5. Cross-reference IDs with Windows Search DB
6. Document visual evidence with full file paths
```

**Forensic Value:**

```bash
✓ Visual proof of images/documents on system
✓ Thumbnails persist after file deletion
✓ Can identify illicit content (CSAM, IP theft, etc.)
✓ Shows user viewed content graphically
✓ Metadata extraction when combined with Windows Search
```

**Investigation Tips:**

* ✓ Check ALL size databases (different views = different DBs)
* ✓ Thumbnails can exist for deleted files
* ✓ PDF, Office docs, videos also have thumbnails
* ✓ Folder thumbnails may show contained file previews

***

### **4.2 Thumbs.db (Legacy - Windows XP)**

**What it tells you:** Thumbnail cache for images in specific folder

**Location:**

```bash
Each folder with images viewed in thumbnail view contains its own Thumbs.db file
Hidden file attribute
```

**Key Investigation Points:**

* ✓ **Windows XP primary usage** (hidden by default)
* ✓ Can be created on Win7+ when accessing UNC network paths
* ✓ Per-folder database (not centralized like Thumbcache)
* ✓ **Persists after original file deletion**
* ✓ Contains: Thumbnail image, Last Modification Time (XP), Original Filename (XP)

**Analysis Tools:**

```bash
thumbs_viewer.exe - View and extract Thumbs.db contents
Thumbs.db Viewer (Sanderson Forensics)
ThumbsExtract (NirSoft)
```

**Modern Relevance:**

```bash
⚠️ Primarily XP-era artifact
✓ Still created when accessing network shares via UNC on newer OS
✓ Check network share folders for Thumbs.db files
✓ May exist on USB drives formatted/used on XP systems
```

**Forensic Value:**

```bash
✓ Visual evidence of deleted images
✓ Filename and modification metadata (XP)
✓ Proves images existed in specific folder
✓ Network share access evidence (modern OS)
```

***

## Advanced Investigation Techniques

### SID to Username Mapping

**Method 1: Registry (SOFTWARE Hive)**

```bash
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList

Each subkey is a SID - check ProfileImagePath value for username
```

**Method 2: Command Line**

```batch
REM On live system
wmic useraccount get name,sid

REM Via PowerShell
Get-LocalUser | Select-Object Name, SID

REM From account name
wmic useraccount where name="Alice" get sid
```

**Method 3: Offline Registry**

```bash
1. Load SOFTWARE hive into RegistryExplorer
2. Navigate to ProfileList
3. Match SID to ProfileImagePath (shows username)
```

***

### Timeline Correlation Strategy

**Build Master Timeline:**

```bash
1. Recycle Bin deletion times
2. Windows Search index timestamps
3. RecentDocs Last Write Times
4. WordWheelQuery Last Write Time (last search)
5. Thumbcache entry dates
6. IE File History access times
7. MFT timestamps from filesystem
8. LNK file timestamps
9. Prefetch execution times
```

**Use Plaso/Log2Timeline:**

```bash
log2timeline.py --storage-file timeline.plaso C:\Evidence\

psort.py -o l2tcsv -w timeline.csv timeline.plaso
```

***

### Anti-Forensics Detection

**Check for Cleaning Tools:**

```bash
Applications: CCleaner, BleachBit, Eraser, Cipher.exe
WordWheelQuery: Search terms like "secure delete", "wipe", "shred"
Recent Programs: Execution of cleaning utilities
Browser History: Downloads of anti-forensic tools
```

**Indicators of Data Destruction:**

```bash
✓ Empty Recycle Bin with recent LNK files
✓ Gaps in Windows Search index
✓ Missing expected Thumbcache entries
✓ Truncated or corrupted ESE databases
✓ Volume Shadow Copies deleted
✓ Event log clearing (Security, System)
```

***

### Network Share & USB Evidence

**TypedPaths Indicators:**

```bash
\\FileServer\Share\*
\\192.168.1.100\C$\*
E:\*, F:\*, G:\* (external drives)
```

**Windows Search Database:**

```bash
Search for paths containing:
- UNC paths (\\server\share)
- Drive letters beyond C: (USB drives)
- External device names
```

**IE File History:**

```bash
file:///\\server\share\filename.ext
file:///E:/USBDrive/data.xlsx
```

***

## Investigation Checklists

#### Quick Triage Checklist

* \[ ] Identify all user accounts (via ProfileList)
* \[ ] Map SIDs to usernames
* \[ ] Check Recycle Bin for all users
* \[ ] Copy NTUSER.DAT for each user
* \[ ] Copy Windows Search Database (Windows.edb)
* \[ ] Copy Thumbcache databases for each user
* \[ ] Copy IE File History (WebCacheV\*.dat)
* \[ ] Document current date/time and timezone

#### Deleted File Investigation

* \[ ] Parse Recycle Bin with RBCmd
* \[ ] Extract file metadata from $I files
* \[ ] Recover file contents from $R files
* \[ ] Map deletion times to incident timeline
* \[ ] Check for files too large for Recycle Bin
* \[ ] Review for Shift+Delete evidence
* \[ ] Cross-reference with MFT entries

#### File Knowledge Investigation

* \[ ] Parse Windows Search Database
* \[ ] Extract RecentDocs MRU
* \[ ] Review LastVisitedPidlMRU (app to folder)
* \[ ] Analyze WordWheelQuery searches
* \[ ] Check TypedPaths for manual navigation
* \[ ] Extract IE File History entries
* \[ ] Correlate all artifacts to timeline

#### Visual Evidence Recovery

* \[ ] Extract all Thumbcache databases
* \[ ] Use thumbcache\_viewer to recover thumbnails
* \[ ] Cross-reference Cache IDs with Windows Search
* \[ ] Check for legacy Thumbs.db files
* \[ ] Document visual evidence with metadata
* \[ ] Preserve thumbnail images as exhibits

#### Network & External Access

* \[ ] Search TypedPaths for UNC paths
* \[ ] Check Windows Search for network shares
* \[ ] Review IE File History for file:/// UNC entries
* \[ ] Identify USB drive letters in artifacts
* \[ ] Correlate with USB device history
* \[ ] Map network share access timeline

***

## Essential DFIR Tools

#### Registry Analysis

```bash
✓ RegRipper (rr.exe) - Automated plugin-based parsing
✓ RegistryExplorer (Eric Zimmerman) - GUI registry viewer
✓ RECmd (Eric Zimmerman) - Command-line registry parser
✓ Registry Viewer (AccessData) - Commercial option
```

#### Recycle Bin

```bash
✓ RBCmd (Eric Zimmerman) - Recycle Bin parser
✓ Manual inspection via command line
✓ IEF (Internet Evidence Finder) - Recycle Bin module
```

#### Windows Search Database

```bash
✓ ESEDatabaseView (NirSoft) - ESE database viewer
✓ Windows Search Index Examiner
✓ libesedb - Open-source ESE library
✓ KAPE - Windows Search targets included
```

#### Thumbnails

```bash
✓ thumbcache_viewer.exe - Free thumbcache extractor
✓ thumbs_viewer.exe - Legacy Thumbs.db viewer
✓ ThumbsExtract (NirSoft) - Extract thumbnails
✓ Thumbcache Viewer (Sanderson) - Commercial
```

#### Comprehensive Suites

```bash
✓ Autopsy - Open-source with registry modules
✓ X-Ways Forensics - Professional forensic suite
✓ Magnet AXIOM - Commercial full-spectrum tool
✓ FTK (Forensic Toolkit) - Enterprise solution
✓ KAPE - Triage collection and processing
```

#### Timeline Analysis

```bash
✓ Plaso/Log2Timeline - Super timeline creation
✓ TimelineExplorer (Eric Zimmerman) - Timeline viewer
✓ DCode - Timestamp converter
```

***

## Quick Command Reference

#### PowerShell Collection Script

```powershell
# Set variables
$case = "CASE-2024-001"
$user = "Alice"
$dest = "C:\Cases\$case\Artifacts"

# Create directory structure
New-Item -ItemType Directory -Path "$dest\RecycleBin" -Force
New-Item -ItemType Directory -Path "$dest\Registry" -Force
New-Item -ItemType Directory -Path "$dest\Thumbcache" -Force
New-Item -ItemType Directory -Path "$dest\WindowsSearch" -Force
New-Item -ItemType Directory -Path "$dest\WebCache" -Force

# Collect Recycle Bin
Copy-Item "C:\$Recycle.Bin\*" -Destination "$dest\RecycleBin" -Recurse -Force

# Collect Registry Hives
Copy-Item "C:\Users\$user\NTUSER.DAT" -Destination "$dest\Registry\" -Force
Copy-Item "C:\Windows\System32\config\SOFTWARE" -Destination "$dest\Registry\" -Force

# Collect Thumbcache
Copy-Item "C:\Users\$user\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" `
    -Destination "$dest\Thumbcache\" -Force

# Collect Windows Search Database
Copy-Item "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" `
    -Destination "$dest\WindowsSearch\" -Force

# Collect IE File History
Copy-Item "C:\Users\$user\AppData\Local\Microsoft\Windows\WebCache\*.dat" `
    -Destination "$dest\WebCache\" -Force

# Generate collection report
Get-ChildItem $dest -Recurse | 
    Select-Object FullName, Length, CreationTime, LastWriteTime |
    Export-Csv "$dest\Collection_Report.csv" -NoTypeInformation

Write-Host "Collection complete: $dest" -ForegroundColor Green
```

#### Batch Forensic Parsing

```batch
REM Parse Recycle Bin
RBCmd.exe -d "C:\$Recycle.Bin" --csv "C:\Cases\Output" --csvf RecycleBin.csv

REM Parse Registry MRUs
rr.exe -r "C:\Cases\Registry\NTUSER.DAT" -p recentdocs > RecentDocs.txt
rr.exe -r "C:\Cases\Registry\NTUSER.DAT" -p wordwheelquery > Searches.txt
rr.exe -r "C:\Cases\Registry\NTUSER.DAT" -p typedpaths > TypedPaths.txt

REM Process all artifacts
RECmd.exe -d "C:\Cases\Registry" --csv "C:\Cases\Output" --csvf Registry_Analysis.csv
```

#### SID Enumeration

{% code overflow="wrap" %}
```powershell
# Live system - all users
Get-WmiObject Win32_UserAccount | 
    Select-Object Name, SID, Domain | 
    Format-Table -AutoSize

# Export to CSV
Get-WmiObject Win32_UserAccount | 
    Select-Object Name, SID, Domain | 
    Export-Csv "C:\Cases\SID_Mapping.csv" -NoTypeInformation

# Match SID to Recycle Bin folders
Get-ChildItem "C:\$Recycle.Bin" -Directory | 
    ForEach-Object {
        $sid = $_.Name
        $user = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount])
        [PSCustomObject]@{
            SID = $sid
            Username = $user.Value
            Path = $_.FullName
        }
    } | Format-Table -AutoSize
```
{% endcode %}

***

### File Path Variables

```bash
%USERPROFILE% = C:\Users\<username>
%LOCALAPPDATA% = C:\Users\<username>\AppData\Local
%APPDATA% = C:\Users\<username>\AppData\Roaming
%PROGRAMDATA% = C:\ProgramData
```

***

## Common Forensic Scenarios

#### Scenario 1: Prove File Existed (Deleted, Not in Recycle Bin)

```bash
1. Check Windows Search Database (Windows.edb)
   - Search by filename/keyword
   - Extract full metadata

2. Check Thumbcache
   - May have thumbnail even if file deleted
   - Cross-reference Cache ID to Windows Search

3. Check IE File History
   - file:/// entries show access

4. Check RecentDocs MRU
   - File may appear in recent documents

5. Check LNK files and Jump Lists
   - Application shortcuts may reference file

6. Filesystem analysis
   - MFT entry may still exist
   - Unallocated space carving
```

#### Scenario 2: User Searched for Sensitive Terms

```bash
1. WordWheelQuery registry key
   - Shows File Explorer searches

2. Browser history (separate artifact)
   - Web search terms

3. Windows Search Database
   - May log search queries

4. Recently opened files
   - RecentDocs may show files matching search

5. Correlation
   - Timeline: When searched → What accessed
```

#### Scenario 3: USB Drive File Access

```bash
1. TypedPaths
   - Manually typed E:\, F:\, etc.

2. Windows Search Database
   - Indexes external drives (if configured)
   - Search for drive letters E:, F:, G:

3. IE File History
   - file:///E:/ entries

4. RecentDocs MRU
   - Files accessed from external drives

5. LNK files
   - May contain volume serial number of USB

6. Cross-reference with USB device history
```

#### Scenario 4: Network Share Access

```bash
1. TypedPaths
   - \\server\share paths manually entered

2. IE File History
   - file:///\\server\share\ entries

3. Windows Search Database
   - UNC paths if indexed

4. RecentDocs MRU
   - Files from network locations

5. Thumbs.db on network share
   - Shows user accessed share

6. Shell Bags
   - Network folder access history
```

***

## Investigation Gotchas & Notes

#### Recycle Bin

```bash
✓ Files >8GB may bypass Recycle Bin (varies by OS)
⚠️ Shift+Delete bypasses Recycle Bin entirely
⚠️ Network deletions bypass Recycle Bin
⚠️ Some applications bypass Recycle Bin
✓ Each user has separate SID folder
✓ Files persist until emptied (high forensic value)
```

#### Windows Search Database

```bash
✓ Only indexes if Windows Search enabled (default on)
⚠️ External drives not indexed by default
⚠️ Some folders excluded (e.g., Windows, Program Files)
✓ Database can be very large (GBs)
✓ Use targeted keyword searches
✓ ESE database format requires specialized tools
```

#### Thumbcache

```bash
✓ Only created when thumbnails viewed
⚠️ Different sizes in different databases
✓ Persists after file deletion (high value!)
✓ Requires cross-reference with Windows Search for metadata
⚠️ Not all file types generate thumbnails
```

#### MRU Lists

```bash
✓ Limited number of entries (typically 10-20)
✓ Older entries pushed out by newer
✓ Last Write Time = Most recent activity
⚠️ Application closure may update MRU
✓ MRU data in binary format (use tools)
```

#### IE File History

```bash
✓ Tracks local file:/// access
✓ ESE database format (WebCacheV*.dat)
⚠️ Database can be locked on live system
✓ Persists even on Windows 11 without IE
✓ Includes network share access
```

***

## Best Practices

#### Evidence Preservation

```bash
1. Use write-blocking when possible
2. Hash all source files before analysis
3. Work on copies, never originals
4. Document collection date/time/timezone
5. Maintain chain of custody
6. Use forensically sound tools
```

#### Analysis Methodology

```bash
1. Start with highest priority artifacts
2. Build comprehensive timeline
3. Cross-reference multiple artifacts
4. Document correlations and conflicts
5. Validate findings with multiple sources
6. Consider anti-forensics indicators
```

#### Reporting

```bash
1. Clear attribution (SID to username)
2. Precise timestamps with timezone
3. Visual evidence when available
4. Cross-referenced artifact support
5. Explain technical terms for non-technical audience
6. Include tool versions used
```

***

**Critical Notes:**

* Always verify artifact locations per OS version
* Use multiple artifacts to corroborate findings
* Consider timestamp precision and timezone
* Account for user anti-forensics actions
* Map SIDs to usernames early in investigation

**Key Principle:** Files leave traces even after deletion - use multiple artifacts to build comprehensive proof of file existence, access, and user knowledge.
