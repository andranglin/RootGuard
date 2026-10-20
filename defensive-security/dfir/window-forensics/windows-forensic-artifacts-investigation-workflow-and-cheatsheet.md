# Windows Forensic Artifacts – Investigation Workflow & Cheatsheet

Investigate Windows artefacts through a scoped, evidence-led workflow. Interpret each artefact alongside independent data and record acquisition limitations.

## Investigation workflow

### Phase 1: Evidence Identification & Scoping

```bash
1. Define Investigation Parameters
   ├─ Incident type (malware, data theft, insider threat, etc.)
   ├─ Timeline of interest
   ├─ Systems and users involved
   └─ Initial indicators of compromise (IOCs)

2. Determine Artifact Priority
   ├─ Volatile artifacts (Prefetch, memory)
   ├─ Execution evidence
   ├─ User activity evidence
   ├─ Persistence mechanisms
   └─ File system artifacts
```

### Phase 2: Systematic Artifact Collection

#### **Collection Order (by Volatility & Importance)**

```bash
Priority 1: VOLATILE DATA
├─ Prefetch files (overwritten at 1024 limit)
└─ Live registry (if live response)

Priority 2: EXECUTION EVIDENCE
├─ Amcache.hve
├─ ShimCache (SYSTEM hive)
├─ UserAssist (NTUSER.DAT)
├─ Jump Lists
└─ LNK Files

Priority 3: USER ACTIVITY
├─ ShellBags (USRCLASS.DAT, NTUSER.DAT)
├─ Recent Documents (RecentDocs registry)
├─ Last Visited MRU
└─ Recycle Bin

Priority 4: FILE SYSTEM ARTIFACTS
├─ $MFT
├─ $J (USN Journal)
├─ $LogFile
└─ Alternate Data Streams

Priority 5: PERSISTENCE
└─ AutoStart Extension Points (ASEPs)
```

### Phase 3: Artifact Analysis Framework

***

### 📂 1. EXECUTION EVIDENCE ARTIFACTS

### 🔹 Prefetch Analysis

**Purpose:** Prove program execution, identify execution patterns

{% code overflow="wrap" %}
```bash
INVESTIGATION STEPS:
1. Extract Prefetch directory
   └─ C:\Windows\Prefetch

2. Check if Prefetch is enabled
   └─ HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
   └─ Value 0=Disabled, 3=Enabled

3. Parse all .pf files
   ├─ Tool: PECmd.exe
   └─ Output: CSV for timeline analysis

4. Analyze for:
   ├─ First execution time (creation - 10 seconds)
   ├─ Last execution time (modification - 10 seconds)
   ├─ Last 8 execution times (Win10/11)
   ├─ Total run count
   ├─ Files and directories referenced
   └─ Volume information

5. Look for RED FLAGS:
   ├─ Multiple prefetch files for same executable name
   ├─ Execution from unusual locations
   ├─ Known malicious tool names
   └─ Execution from removable media paths
```
{% endcode %}

**Commands:**

{% code overflow="wrap" %}
```bash
 Single file analysis
.\PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf

# Directory analysis with CSV output
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Output --csvf prefetch.csv

# Include VSS and highlight keywords
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Output --csvf prefetch.csv --vss --mp -k "system32, downloads, fonts"
```
{% endcode %}

**Key Metadata:**

* Executable name
* 8-character hash of executable path
* Creation/modification/access timestamps
* Run count (number of executions)
* Last 8 run times
* Files and directories referenced
* Volume information

### 🔹 Amcache Analysis

**Purpose:** Identify program presence, validate with SHA1 hashes

{% code overflow="wrap" %}
```bash
INVESTIGATION STEPS:
1. Extract Amcache.hve
   └─ C:\Windows\AppCompat\Programs\Amcache.hve
   └─ Include .LOG1 and .LOG2 files

2. Parse with AmcacheParser
   ├─ Output to CSV
   └─ Use -i flag for includes

3. Extract key information:
   ├─ Full file paths
   ├─ File sizes
   ├─ File modification times
   ├─ Compilation times
   ├─ Publisher metadata
   └─ SHA1 hashes (KEY VALUE!)

4. Cross-reference SHA1 hashes:
   ├─ Known good (Microsoft files)
   ├─ Known bad (malware databases)
   └─ Unknown (requires further investigation)

5. Correlate with other execution artifacts
   └─ Amcache presence + Prefetch = High confidence execution
```
{% endcode %}

**Commands:**

{% code overflow="wrap" %}
````bash
# Live system analysis
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" -i --csv C:\Output

# Forensic image analysis
.\AmcacheParser.exe -f "C:\User\username\Desktop\amcache\Amcache.hve" -i --csv C:\Output

# With blacklist filtering
.\AmcacheParser.exe -f c:\Windows\AppCompat\Programs\Amcache.hve -b G:\Blacklist.txt --csv G:\Output
```

**⚠️ Important Note:** Amcache indicates PRESENCE, not proven EXECUTION
````
{% endcode %}

### 🔹 ShimCache (AppCompatCache) Analysis

**Purpose:** Historical program presence on system

```bash
INVESTIGATION STEPS:
1. Extract SYSTEM registry hive
   └─ C:\Windows\System32\config\SYSTEM

2. Determine current ControlSet
   └─ SYSTEM\Select\Current

3. Parse AppCompatCache
   └─ HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

4. Extract information:
   ├─ Full executable paths
   ├─ Last modification times
   ├─ File sizes
   └─ Execution flag (Win7/8 only)

5. Analyze patterns:
   ├─ Up to 1,024 entries
   ├─ Most recent on top
   ├─ Written only on shutdown
   └─ Deleted files may still appear

6. Investigation use cases:
   ├─ Identify deleted malware
   ├─ Track tool presence
   └─ Build historical timeline
```

**Commands:**

````bash
# Parse SYSTEM hive
.\AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv G:\Output

# Live system
.\AppCompatCacheParser.exe --csv C:\Output --csvf shimcache.csv
```

**⚠️ Critical Note:** Win10+ ShimCache does NOT prove execution, only presence!
````

### 🔹 UserAssist Analysis

**Purpose:** Track GUI-based program launches

```bash
INVESTIGATION STEPS:
1. Extract NTUSER.DAT hive
   └─ C:\Users\[Username]\NTUSER.DAT

2. Navigate to UserAssist keys
   └─ Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

3. Identify GUID subkeys:
   ├─ CEBFF5CD = Executable File Execution
   └─ F4E57C4B = Shortcut File Execution

4. Decode ROT-13 values
   ├─ Use Registry Explorer (auto-decodes)
   └─ Or manually decode with CyberChef

5. Extract metadata:
   ├─ Application path
   ├─ Last run time
   ├─ Run count
   ├─ Focus time (time application had focus)
   └─ Focus count

6. Analyze for:
   ├─ Unusual application launches
   ├─ Portable applications
   └─ Tools run from removable media
```

**Commands:**

{% code overflow="wrap" %}
```bash
# Use Registry Explorer (Zimmerman Tools)
RegistryExplorer.exe
# File > Live System > NTUSER.DAT
# Navigate: ROOT > Software > Microsoft > Windows > CurrentVersion > Explorer > UserAssist

# Alternative: RegRipper
rr.exe -r NTUSER.DAT -p userassist
```
{% endcode %}

**Key Value:** Tracks GUI program execution with timestamps and frequency

## 📂 2. USER ACTIVITY ARTIFACTS

### 🔹 Jump Lists Analysis

**Purpose:** Identify applications used and files accessed

{% code overflow="wrap" %}
```bash
INVESTIGATION STEPS:
1. Locate Jump List files
   ├─ AutomaticDestinations: C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
   └─ CustomDestinations: C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations

2. Identify application by AppID
   └─ Reference: https://dfir.to/EZJumpList

3. Parse Jump List files
   ├─ AutomaticDestinations = OLE format
   └─ CustomDestinations = MS-SHLLINK format

4. Extract metadata:
   ├─ Files opened by application
   ├─ File paths and locations
   ├─ Access timestamps
   ├─ Creation time = First item added
   └─ Modification time = Last item added

5. Analyze for:
   ├─ Recent document access
   ├─ Network share connections
   ├─ Removable media usage
   └─ Suspicious file locations
```
{% endcode %}

**Commands:**

{% code overflow="wrap" %}
```bash
# Single file analysis
JLECmd.exe -f C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\<file>.automaticDestinations-ms --csv G:\Output -q

# All automatic destinations
JLECmd.exe -d C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations --csv G:\Output -q

# All custom destinations
JLECmd.exe -d C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations --csv G:\Output -q
```
{% endcode %}

### 🔹 LNK (Shortcut) Files Analysis

**Purpose:** Track file and folder access by users

```bash
INVESTIGATION STEPS:
1. Locate LNK files
   ├─ Recent: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
   └─ Office Recent: %USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\

2. Parse LNK files
   └─ Tool: LECmd.exe

3. Extract metadata:
   ├─ Target file path and size
   ├─ Target file timestamps (MAC times)
   ├─ LNK creation time = First opened
   ├─ LNK modification time = Last opened
   ├─ Volume information (name, type, serial)
   ├─ Network share information
   ├─ System name
   └─ Sometimes MAC address

4. Analyze for:
   ├─ Files opened from USB devices
   ├─ Network share access
   ├─ Files that no longer exist
   └─ Recently accessed documents

5. Note behaviors:
   ├─ LNK persists even if target deleted
   ├─ Win10+ includes file extensions
   └─ Only latest open recorded per filename
```

**Commands:**

{% code overflow="wrap" %}
```bash
# Single file
LECmd.exe -f C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\file.lnk

# Directory analysis
LECmd.exe -d C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent --csv G:\Output --html G:\Output -q

# All subdirectories
LECmd.exe -d C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent --all --csv G:\Output

# View with command line
dir filename.xxx.lnk
dir /tc filename.xxx.lnk  # Show creation time
```
{% endcode %}

### 🔹 ShellBags Analysis

**Purpose:** Track folder access and view settings

```bash
INVESTIGATION STEPS:
1. Locate ShellBags registry keys
   Primary:
   ├─ USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
   └─ USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
   
   Residual:
   ├─ NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
   └─ NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags

2. Parse ShellBags
   └─ Tools: SBECmd.exe, ShellBagsExplorer.exe

3. Extract information:
   ├─ Folders accessed by user
   ├─ Folder view settings
   ├─ First interaction time
   ├─ Last interaction time
   ├─ Folder timestamps (archived)
   └─ Exotic items (mobile devices, control panel, ZIP archives)

4. Investigate for:
   ├─ Local folder navigation
   ├─ Removable device access
   ├─ Network share browsing
   ├─ Deleted folder evidence
   └─ Hidden directory access
```

**Commands:**

{% code overflow="wrap" %}
```bash
# ShellBags Explorer (GUI)
ShellBagsExplorer.exe

# SBECmd (Command line)
SBECmd.exe -d C:\Users\<user> --csv G:\Output

# Live system
SBECmd.exe -l --csv G:\Output
```
{% endcode %}

**Forensic Value:** Proves user navigated to specific folders, even if deleted

### 🔹 Recycle Bin Analysis

**Purpose:** Identify deleted files and deletion timeline

```bash
INVESTIGATION STEPS:
1. Navigate to Recycle Bin
   └─ C:\$Recycle.Bin

2. Identify user SID folders
   └─ Each user has separate SID subfolder
   └─ Map SID to username via Registry

3. Understand file naming:
   ├─ $I###### = Metadata (original name, deletion time)
   └─ $R###### = Actual deleted file contents

4. Extract information:
   ├─ Original filename
   ├─ Original path
   ├─ File size
   ├─ Deletion date/time
   └─ File contents (from $R file)

5. Manual examination:
   └─ Use command line to view hidden files

6. Parse with tools for bulk analysis
```

**Commands:**

```bash
# Manual browsing
dir /a
cd $Recycle.Bin
dir /a
cd [SID-of-interest]
dir
type $I******.png  # View metadata
copy $R******.png C:\Users\username\Desktop\recovered.png

# Parse with RBCmd
RBCmd.exe -f C:\$Recycle.Bin\[SID]\$I[file].png

# Parse entire Recycle Bin
RBCmd.exe -d C:\$Recycle.Bin\ -q --csv C:\Output --csvf recycle-bin.csv
```

### 🔹 Last Visited MRU Analysis

**Purpose:** Track applications and last file locations accessed

{% code overflow="wrap" %}
```bash
INVESTIGATION STEPS:
1. Locate MRU registry keys
   ├─ LastVisitedPidlMRU: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
   ├─ RecentDocs: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
   ├─ OpenSavePidlMRU: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
   └─ RunMRU: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

2. Parse registry hives
   └─ Use Registry Explorer or Regedit

3. Extract information:
   ├─ Applications executed
   ├─ Last directory accessed by application
   ├─ Files opened via Open/Save dialogs
   └─ Commands run via Windows Run utility

4. Analyze for:
   ├─ Unusual directory access
   ├─ Hidden folder interactions
   └─ Application usage patterns
```
{% endcode %}

**Commands:**

{% code overflow="wrap" %}
```bash
# Use Registry Explorer
RegistryExplorer.exe
# Navigate to keys listed above

# Or use regedit on live system
regedit.exe
# Navigate: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
```
{% endcode %}

## 📂 3. FILE SYSTEM ARTIFACTS

### 🔹 Master File Table ($MFT) Analysis

**Purpose:** Comprehensive file system timeline and metadata

```bash
INVESTIGATION STEPS:
1. Extract $MFT
   └─ Located at root of NTFS volume
   └─ Use FTK Imager or similar

2. Parse $MFT
   └─ Tool: MFTECmd.exe

3. Extract metadata for each file:
   ├─ File name and path
   ├─ File type and size
   ├─ Created timestamp (Birth)
   ├─ Modified timestamp
   ├─ Accessed timestamp
   ├─ MFT Record Modified timestamp
   ├─ File attributes
   └─ Parent directory references

4. Use for:
   ├─ Complete file system timeline
   ├─ Deleted file recovery
   ├─ File existence verification
   └─ Timestamp analysis
```

**Commands:**

```bash
# Parse MFT with CSV output
MFTECmd.exe -f "C:\Temp\$MFT" --csv "C:\Output" --csvf mft.csv

# Parse with JSON output
MFTECmd.exe -f "C:\Temp\$MFT" --json "C:\Output"

# Body file format (for timeline)
MFTECmd.exe -f "C:\Temp\$MFT" --body "C:\Output" --bdl c
```

### 🔹 USN Journal ($J) Analysis

**Purpose:** Track file system changes and operations

```bash
INVESTIGATION STEPS:
1. Extract $J data stream
   └─ NTFS\$Extend\$UsnJrnl\$J

2. Parse USN Journal
   └─ Tool: MFTECmd.exe or USN Journal Parser

3. Extract change records:
   ├─ Date/time of change
   ├─ Reason for change (create, delete, rename, modify)
   ├─ MFT entry number
   ├─ MFT parent entry
   ├─ File name
   └─ Sequence of operations

4. Investigate for:
   ├─ File creation events
   ├─ File deletion events
   ├─ File rename operations
   ├─ Anti-forensic activity
   └─ Attacker movement patterns
```

**Commands:**

```bash
# Parse USN Journal
MFTECmd.exe -f "C:\Temp\$J" --csv "C:\Output" --csvf usnjrnl.csv

# Decode specific entries
MFTECmd.exe -f "C:\Temp\$J" --de 5-5
```

**Key Value:** Shows file operations even after files are deleted

### 🔹 $LogFile Analysis

**Purpose:** NTFS transaction log for all metadata operations

```bash
INVESTIGATION STEPS:
1. Extract $LogFile
   └─ Located at NTFS root, MFT entry #2

2. Parse $LogFile
   └─ Tools: NTFS_Log_Tracker.exe, LogFileParser.exe

3. Extract transaction records:
   ├─ File creation
   ├─ File deletion
   ├─ File renaming
   ├─ File copying
   └─ Metadata modifications

4. Use for:
   ├─ Recent file activity (short retention)
   ├─ Redo/undo operations analysis
   └─ Correlation with other artifacts
```

**Commands:**

```bash
# Parse with NTFS Log Tracker
NTFS_Log_Tracker.exe -f C:\Temp\$LogFile -o C:\Output

# Parse with LogFileParser
LogFileParser.exe -f C:\Temp\$LogFile -o C:\Output
```

### 🔹 Alternate Data Streams (ADS) Analysis

**Purpose:** Detect hidden data within files

```bash
INVESTIGATION STEPS:
1. Scan for ADS
   └─ NTFS attribute, no specific path

2. Use detection tools:
   ├─ streams.exe (Sysinternals)
   ├─ AlternateStreamView.exe
   ├─ PowerShell Get-Item
   └─ cmd.exe dir /R

3. Investigate suspicious streams:
   ├─ Zone.Identifier (normal - tracks download source)
   ├─ Custom streams (potential hiding)
   └─ Executable streams (malware)

4. Extract and analyze contents:
   └─ Use notepad, PowerShell, or hex editor

5. Look for:
   ├─ Hidden executables
   ├─ Hacking toolkits
   ├─ Concealed documents
   └─ Malicious scripts
```

**Commands:**

```bash
# Sysinternals Streams
streams.exe -s C:\path\to\directory

# PowerShell
Get-Item C:\path\to\file -Stream *
Get-Content C:\path\to\file -Stream [stream-name]

# Command Prompt
dir /R C:\path\to\directory

# AlternateStreamView (GUI)
AlternateStreamView.exe
```

## 📂 4. PERSISTENCE MECHANISMS

### 🔹 AutoStart Extension Points (ASEP) Analysis

**Purpose:** Identify malware persistence locations

```bash
INVESTIGATION STEPS:
1. Understand persistence
   └─ Malware ability to survive reboots

2. Check primary AutoStart locations:
   Registry Keys:
   ├─ HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   ├─ HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
   ├─ HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   ├─ HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
   ├─ HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
   └─ HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
   
   File System:
   └─ %AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

3. Check additional persistence methods:
   ├─ Scheduled Tasks
   ├─ Windows Services
   ├─ Service Creation/Replacement
   ├─ DLL Search Order Hijacking
   ├─ Trojaned System Libraries
   ├─ WMI Event Subscriptions
   ├─ Local Group Policy
   └─ MS Office Add-Ins

4. Parse with tools for comprehensive coverage

5. Compare across systems (stacking)
   └─ Identify unique/suspicious entries
```

**Commands:**

{% code overflow="wrap" %}
```bash
// Some code# KAPE collection
.\kape.exe --tsource C: --tdest C:\Output\ASEP-tout --tflush --target RegistryHives --mdest C:\Output\ASEP-mout --mflush --module RECmd_RegistryASEPs

# Autoruns (Sysinternals)
.\autorunsc64.exe -accepteula -a * -s -h -c > autoruns-output.csv
# Flags: -a * (all locations), -s (verify signatures), -h (hashes), -c (CSV)

# RECmd (Registry Explorer)
RECmd.exe --bn BatchExamples\RegistryASEPs.reb -d D:\Triage --nl --csv D:\Output

# Analyze with Timeline Explorer
TimelineExplorer.exe autoruns-output.csv
```
{% endcode %}

**Investigation Focus:**

* Services with suspicious image paths (not in System32)
* Unsigned executables in autostart locations
* Recent registry LastWrite times during attack window
* Base64 encoded commands in registry values
* Scripts in startup folders

## 🔍 CROSS-ARTIFACT ANALYSIS MATRIX

#### Evidence Correlation Table

| **Investigation Question**             | **Primary Artifacts**                                                    | **Secondary Artifacts**                                                                     | **Validation Method**                                                                               | **Confidence Level** |
| -------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------- |
| Was program executed?                  | <p>• Prefetch<br>• UserAssist (GUI only)</p>                             | <p>• Jump Lists<br>• Amcache<br>• LNK files</p>                                             | <p>Prefetch shows run count + last 8 times<br>UserAssist shows GUI launches</p>                     | HIGH ✅               |
| When was program first run?            | <p>• Prefetch creation time (-10s)<br>• UserAssist first run</p>         | <p>• Amcache compilation time<br>• ShimCache first appearance<br>• $MFT file creation</p>   | <p>Cross-reference timestamps across artifacts<br>VSS for historical validation</p>                 | HIGH ✅               |
| When was program last run?             | <p>• Prefetch modified time (-10s)<br>• UserAssist last run time</p>     | <p>• Jump Lists modification<br>• LNK file modification<br>• $J recent operations</p>       | <p>Compare last execution timestamps<br>Check for temporal consistency</p>                          | HIGH ✅               |
| How many times was program executed?   | <p>• Prefetch run count<br>• UserAssist run count</p>                    | <p>• Jump Lists entry count<br>• Multiple LNK files</p>                                     | <p>Run counts should correlate<br>Note: GUI vs CLI differences</p>                                  | HIGH ✅               |
| What files did program access?         | <p>• Prefetch file list<br>• Jump Lists (by AppID)</p>                   | <p>• LNK files<br>• RecentDocs registry<br>• $J file operations</p>                         | <p>Map files to applications<br>Timeline correlation</p>                                            | MEDIUM-HIGH ✓        |
| What folders did program access?       | • Prefetch directory list                                                | <p>• ShellBags<br>• LNK files<br>• OpenSavePidlMRU</p>                                      | <p>Cross-reference paths<br>Check for hidden directories</p>                                        | MEDIUM ✓             |
| What is program's SHA1 hash?           | • Amcache (ONLY SOURCE)                                                  | None (unique to Amcache)                                                                    | <p>Extract from Amcache<br>Verify against VirusTotal<br>Compare to known malware</p>                | HIGH ✅               |
| Did program exist on system?           | <p>• ShimCache<br>• Amcache</p>                                          | <p>• $MFT<br>• Prefetch<br>• $J</p>                                                         | <p>ShimCache proves presence<br>$MFT shows file existence<br>Note: Win10+ ShimCache limitations</p> | MEDIUM-HIGH ✓        |
| Was file deleted?                      | <p>• Recycle Bin (I/I/ I/R files)<br>• $J USN records</p>                | <p>• $MFT (deleted entry flag)<br>• $LogFile<br>• ShimCache (may persist)</p>               | <p>$I file shows deletion time<br>$J shows delete operation<br>$MFT shows deleted flag</p>          | HIGH ✅               |
| When was file deleted?                 | <p>• Recycle Bin $I metadata<br>• $J delete timestamp</p>                | <p>• $LogFile transaction<br>• $MFT timestamp analysis</p>                                  | <p>Parse $I file for deletion time<br>Correlate with $J entries</p>                                 | HIGH ✅               |
| Was file renamed or moved?             | <p>• $J rename operations<br>• $LogFile transactions</p>                 | <p>• $MFT parent directory changes<br>• ShellBags path history</p>                          | <p>$J shows old and new names<br>Sequence of operations in $LogFile</p>                             | MEDIUM-HIGH ✓        |
| What folders did user browse?          | • ShellBags                                                              | <p>• LNK files<br>• Jump Lists<br>• LastVisitedPidlMRU</p>                                  | <p>ShellBags proves navigation<br>LNK files show file access<br>MRU shows application paths</p>     | HIGH ✅               |
| Was USB device connected?              | <p>• ShellBags (device paths)<br>• LNK files (volume info)</p>           | <p>• Registry USBSTOR keys<br>• Prefetch (volume data)<br>• Jump Lists</p>                  | <p>Volume serial numbers match<br>Drive letter assignments<br>Timestamps correlate</p>              | HIGH ✅               |
| When was USB first connected?          | <p>• Registry USBSTOR key creation<br>• ShellBags first access</p>       | <p>• LNK file with volume serial<br>• Prefetch with volume info</p>                         | <p>Registry key timestamp<br>First ShellBag entry for device</p>                                    | HIGH ✅               |
| When was USB last connected?           | <p>• ShellBags last access<br>• LNK file timestamps</p>                  | <p>• Registry USBSTOR last write<br>• Prefetch last run (if program executed)</p>           | <p>Most recent timestamp for volume serial<br>Last file access from device</p>                      | HIGH ✅               |
| What files were accessed from USB?     | <p>• LNK files (volume serial match)<br>• Jump Lists</p>                 | <p>• Prefetch (if executables run)<br>• RecentDocs<br>• ShellBags</p>                       | <p>Filter artifacts by volume serial<br>Match drive letters to volume info</p>                      | HIGH ✅               |
| Were programs executed from USB?       | <p>• Prefetch (volume information)<br>• UserAssist</p>                   | <p>• Jump Lists<br>• LNK files</p>                                                          | <p>Prefetch shows source volume<br>Cross-reference with USB timeline</p>                            | HIGH ✅               |
| What files were opened by user?        | <p>• Jump Lists (by application)<br>• LNK files</p>                      | <p>• RecentDocs registry<br>• LastVisitedPidlMRU<br>• Office Recent files</p>               | <p>Application-specific tracking<br>Timeline of document access</p>                                 | HIGH ✅               |
| What applications did user run?        | <p>• Prefetch<br>• UserAssist</p>                                        | <p>• Jump Lists<br>• Amcache<br>• ShimCache</p>                                             | <p>Multiple sources confirm usage<br>Frequency and timing data</p>                                  | HIGH ✅               |
| Is malware persistent?                 | <p>• ASEP registry keys<br>• Startup folder contents</p>                 | <p>• Scheduled Tasks<br>• Windows Services<br>• WMI subscriptions</p>                       | <p>Check all autostart locations<br>Verify signatures<br>Compare across systems (stacking)</p>      | HIGH ✅               |
| When was persistence established?      | <p>• Registry key LastWrite times<br>• Scheduled Task creation time</p>  | <p>• File creation time (startup folder)<br>• Service creation time<br>• $MFT timestamp</p> | <p>LastWrite time of Run keys<br>Task file creation timestamp</p>                                   | HIGH ✅               |
| What persistence mechanisms exist?     | <p>• Autoruns comprehensive scan<br>• ASEP registry analysis</p>         | <p>• Manual service review<br>• WMI subscription query<br>• DLL hijacking check</p>         | <p>Enumerate all autostart points<br>Identify unsigned/unusual entries</p>                          | HIGH ✅               |
| Is data hidden in files?               | <p>• ADS scan (streams.exe)<br>• AlternateStreamView</p>                 | <p>• PowerShell Get-Item<br>• dir /R command</p>                                            | <p>Scan for non-Zone.Identifier streams<br>Examine suspicious streams</p>                           | HIGH ✅               |
| Were files archived/compressed?        | <p>• Prefetch (7zip, WinRAR, WinZip)<br>• Jump Lists (archive tools)</p> | <p>• $J (.zip, .rar, .7z creation)<br>• UserAssist<br>• $MFT</p>                            | <p>Archive tool execution evidence<br>Archive file creation events</p>                              | HIGH ✅               |
| Were files uploaded/exfiltrated?       | <p>• Prefetch (FTP, cloud tools)<br>• Jump Lists (upload apps)</p>       | <p>• Browser artifacts<br>• Network share access<br>• $J file operations</p>                | <p>Upload tool execution<br>Large file movements<br>Network connections</p>                         | MEDIUM-HIGH ✓        |
| Were files staged for exfiltration?    | <p>• ShellBags (new directories)<br>• $J (directory creation)</p>        | <p>• $MFT (staging folder)<br>• Jump Lists (mass file access)<br>• LNK files</p>            | <p>New directory creation<br>Mass file copy operations<br>Temporal clustering</p>                   | MEDIUM-HIGH ✓        |
| What network shares were accessed?     | <p>• ShellBags (UNC paths)<br>• LNK files (network info)</p>             | <p>• Jump Lists<br>• LastVisitedPidlMRU<br>• RecentDocs</p>                                 | <p>UNC path evidence<br>Network share information<br>Remote file access</p>                         | HIGH ✅               |
| Were system files modified?            | <p>• $LogFile transactions<br>• $J operations</p>                        | <p>• $MFT timestamps<br>• ShimCache updates<br>• Prefetch for system tools</p>              | <p>System file modification events<br>Suspicious system tool execution</p>                          | HIGH ✅               |
| Were logs cleared?                     | <p>• Prefetch (wevtutil.exe)<br>• $J (log file deletions)</p>            | <p>• Event log timestamps<br>• UserAssist<br>• ShimCache</p>                                | <p>Log clearing tool execution<br>Event log file operations<br>Suspicious gaps in logs</p>          | HIGH ✅               |
| Were anti-forensic tools used?         | <p>• Prefetch (CCleaner, BleachBit, etc.)<br>• UserAssist</p>            | <p>• Jump Lists<br>• Amcache SHA1<br>• ShimCache</p>                                        | <p>Tool execution evidence<br>Timeline of cleaning activity<br>Hash matching</p>                    | HIGH ✅               |
| Was remote access tool used?           | <p>• Prefetch (RDP, VNC, TeamViewer)<br>• Amcache</p>                    | <p>• ASEP (persistence check)<br>• Services<br>• Network artifacts</p>                      | <p>Remote tool execution<br>Persistence mechanisms<br>Connection timestamps</p>                     | HIGH ✅               |
| Were credentials dumped?               | <p>• Prefetch (mimikatz, pwdump)<br>• Amcache SHA1</p>                   | <p>• $J (SAM/SYSTEM access)<br>• Jump Lists<br>• File access to credential stores</p>       | <p>Credential dumping tool execution<br>Access to credential files<br>Hash identification</p>       | HIGH ✅               |
| Was lateral movement performed?        | <p>• Prefetch (psexec, wmic)<br>• UserAssist</p>                         | <p>• Scheduled Tasks (remote)<br>• Services (remote creation)<br>• Network artifacts</p>    | <p>Lateral movement tool execution<br>Remote task/service creation<br>Timeline correlation</p>      | HIGH ✅               |
| Were reconnaissance commands run?      | <p>• Prefetch (cmd, powershell, wmic)<br>• UserAssist</p>                | <p>• Jump Lists<br>• RecentDocs<br>• ShimCache</p>                                          | <p>System enumeration tools<br>Command line execution<br>Unusual tool combinations</p>              | MEDIUM-HIGH ✓        |
| Was malware downloaded?                | <p>• Browser artifacts<br>• Prefetch (download locations)</p>            | <p>• $J (file creation in Downloads)<br>• Zone.Identifier ADS<br>• LNK files</p>            | <p>Download timestamp<br>Zone.Identifier shows source<br>File creation in Downloads</p>             | HIGH ✅               |
| Was file opened from email attachment? | <p>• Jump Lists (email client)<br>• LNK files</p>                        | <p>• Zone.Identifier ADS<br>• Outlook artifacts<br>• Temp folder activity</p>               | <p>Email client file access<br>Temp folder execution<br>Zone information</p>                        | MEDIUM-HIGH ✓        |
| Did program crash or fail?             | <p>• Prefetch (may exist without success)<br>• Event logs</p>            | <p>• $LogFile errors<br>• Application crash dumps<br>• Windows Error Reporting</p>          | <p>Prefetch created ≠ successful execution<br>Error events correlate</p>                            | MEDIUM ⚠️            |
| What was timeline of attack?           | • ALL ARTIFACTS COMBINED                                                 | <p>• Super timeline creation<br>• VSS for historical depth</p>                              | <p>Build comprehensive timeline<br>Correlate all timestamps<br>Identify phases of attack</p>        | HIGH ✅               |

### 🎯 Artifact Combination Strategies

### Maximum Confidence Combinations

**Execution Proof (Highest Confidence):**

```bash
Prefetch (run count + times) 
+ Amcache (SHA1 hash match) 
+ UserAssist (GUI execution) 
+ Jump Lists (files accessed)
= 95%+ confidence of execution
```

**File Access Proof:**

```bash
LNK files (target path + volume info)
+ Jump Lists (application association)
+ ShellBags (folder navigation)
+ RecentDocs (document tracking)
= 90%+ confidence of access
```

**USB Device Usage:**

```bash
ShellBags (device path + timestamps)
+ LNK files (volume serial number)
+ Registry USBSTOR (device info)
+ Prefetch (program execution from device)
= 95%+ confidence of usage
```

**Persistence Confirmation:**

```bash
ASEP registry keys (autostart entries)
+ Scheduled Tasks (task files)
+ Services (service registry)
+ Autoruns (comprehensive scan)
= 90%+ confidence of persistence
```

**Data Exfiltration:**

```bash
Prefetch (archive/upload tools)
+ Jump Lists (files archived)
+ $J (file operations)
+ ShellBags (staging directories)
+ LNK files (USB or network paths)
= 85%+ confidence of exfiltration
```

## 🚨 INVESTIGATION RED FLAGS MASTER LIST

### Execution-Based Indicators

````bash
❌ Suspicious Executable Names
├─ One or two-letter names (a.exe, ab.exe)
├─ Random character strings (asdfjkl.exe)
├─ Misspelled system files (svch0st.exe, exp1orer.exe)
└─ Known malware names (mimikatz, pwdump, psexec)

❌ Unusual Execution Locations
├─ C:\$Recycle.Bin
├─ C:\ProgramData
├─ %TEMP% or %TMP%
├─ %APPDATA%
├─ User profile root (C:\Users\username\)
├─ Downloads folder
├─ Public folders
└─ System Volume Information

❌ Multiple Prefetch Files Same Name
└─ Indicates execution from different paths
└─ Exception: svchost, dllhost, rundll32 (expected)

❌ Living Off The Land Binaries (LOLBins)
├─ cmd.exe (from non-System32)
├─ powershell.exe (unusual parameters)
├─ wmic.exe
├─ psexec.exe
├─ reg.exe
├─ schtasks.exe
├─ net.exe / net1.exe
├─ wscript.exe / cscript.exe
├─ mshta.exe
├─ regsvr32.exe
├─ rundll32.exe (unusual parameters)
└─ certutil.exe (download operations)
```

### Temporal Red Flags
```
❌ Off-Hours Activity
├─ Executions at 2-5 AM
├─ Weekend activity in corporate environment
└─ Holiday activity

❌ Rapid Sequential Execution
├─ Reconnaissance tools run in quick succession
├─ Multiple system tools within minutes
└─ Mass file access patterns

❌ Execution Immediately After
├─ USB device connection
├─ Network share access
├─ Email receipt timestamp
└─ User login
```

### Persistence Red Flags
```
❌ Suspicious AutoStart Entries
├─ Unsigned executables in Run keys
├─ Base64 encoded commands
├─ Scripts in Startup folder
├─ Services with unusual paths
└─ Recent registry modifications

❌ Scheduled Task Indicators
├─ Tasks running as SYSTEM
├─ Tasks with unusual triggers
├─ Tasks pointing to temp directories
└─ Recently created tasks during incident window
```

### User Activity Red Flags
```
❌ Unusual File Access
├─ Access to sensitive directories (SAM, SYSTEM)
├─ Mass document opening
├─ Network share enumeration
└─ System file browsing

❌ Data Exfiltration Indicators
├─ Large file copies to USB
├─ Archive creation (zip, rar)
├─ Upload to cloud services
└─ Files moved to staging directories
````

***

### 🛠️ TOOL COMMAND REFERENCE LIBRARY

#### Zimmerman Tools Suite

**PECmd (Prefetch)**

{% code overflow="wrap" %}
```bash
# Single file
.\PECmd.exe -f C:\Windows\Prefetch\[file].pf

# Single file with CSV
.\PECmd.exe -f C:\Windows\Prefetch\[file].pf --csv "C:\Output" --csvf prefetch.csv

# Directory
.\PECmd.exe -d C:\Windows\Prefetch

# Directory with VSS and keywords
.\PECmd.exe -d C:\Windows\Prefetch -q --csv C:\Output --csvf prefetch.csv --vss --mp -k "system32, downloads, temp"
```
{% endcode %}

**AmcacheParser**

```bash
# Live system
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" -i --csv C:\Output

# Forensic image
.\AmcacheParser.exe -f "[path]\Amcache.hve" -i --csv C:\Output

# With blacklist
.\AmcacheParser.exe -f "[path]\Amcache.hve" -b C:\blacklist.txt --csv C:\Output
```

**AppCompatCacheParser (ShimCache)**

```bash
# From SYSTEM hive
.\AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv C:\Output

# Live system
.\AppCompatCacheParser.exe --csv C:\Output --csvf shimcache.csv
```

**JLECmd (Jump Lists)**

{% code overflow="wrap" %}
```bash
# Single file
JLECmd.exe -f "[path]\[file].automaticDestinations-ms" --csv C:\Output -q

# Directory (Automatic)
JLECmd.exe -d "C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\Output -q

# Directory (Custom)
JLECmd.exe -d "C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" --csv C:\Output -q
```
{% endcode %}

**LECmd (LNK Files)**

{% code overflow="wrap" %}
```bash
# Single file
LECmd.exe -f "[path]\[file].lnk"

# Single file with outputs
LECmd.exe -f "[path]\[file].lnk" --json C:\Output --pretty

# Directory
LECmd.exe -d "C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Output --html C:\Output -q

# All subdirectories
LECmd.exe -d "[path]" --all --csv C:\Output
```
{% endcode %}

**SBECmd (ShellBags)**

```bash
# Specific user directory
SBECmd.exe -d C:\Users\[user] --csv C:\Output

# Live system
SBECmd.exe -l --csv C:\Output
```

**RBCmd (Recycle Bin)**

```bash
# Single file
RBCmd.exe -f "C:\$Recycle.Bin\[SID]\$I[file]"

# Entire Recycle Bin
RBCmd.exe -d C:\$Recycle.Bin\ -q --csv C:\Output --csvf recycle-bin.csv
```

**MFTECmd (MFT, $J, etc.)**

```bash
# Parse MFT
MFTECmd.exe -f "[path]\$MFT" --csv "C:\Output" --csvf mft.csv

# Parse with JSON
MFTECmd.exe -f "[path]\$MFT" --json "C:\Output"

# Parse USN Journal
MFTECmd.exe -f "[path]\$J" --csv "C:\Output" --csvf usnjrnl.csv

# Body file format
MFTECmd.exe -f "[path]\$MFT" --body "C:\Output" --bdl c

# Decode specific entry
MFTECmd.exe -f "[path]\$MFT" --de 5-5
```

**Registry Explorer**

```bash
# GUI tool - launch and navigate
RegistryExplorer.exe

# Load live system
# File > Live System > [select hive]

# Load offline hive
# File > Load Hive > [select file]
```

**RECmd (Registry Explorer CLI)**

```bash
# Parse ASEP registry keys
RECmd.exe --bn BatchExamples\RegistryASEPs.reb -d [path] --nl --csv C:\Output

# Custom registry parsing
RECmd.exe -f "[path]\NTUSER.DAT" --csv C:\Output
```

***

#### KAPE (Kroll Artifact Parser and Extractor)

{% code overflow="wrap" %}
```bash
# Collect Registry Hives
.\kape.exe --tsource C: --tdest C:\Output\tout --tflush --target RegistryHives

# Collect and parse ASEP
.\kape.exe --tsource C: --tdest C:\Output\tout --tflush --target RegistryHives --mdest C:\Output\mout --mflush --module RECmd_RegistryASEPs

# Comprehensive collection
.\kape.exe --tsource C: --tdest C:\Output\tout --target !SANS_Triage --mdest C:\Output\mout --module !EZParser
```
{% endcode %}

***

#### Sysinternals Tools

**Autoruns**

```bash
# Full scan with signatures and hashes
.\autorunsc64.exe -accepteula -a * -s -h -c > autoruns-output.csv

# Flags explanation:
# -accepteula = Accept EULA automatically
# -a * = Show all autostart locations
# -s = Verify digital signatures
# -h = Show file hashes
# -c = Output as CSV
```

**Streams (ADS)**

```bash
# Scan directory for ADS
streams.exe -s C:\path\to\directory

# Scan file
streams.exe C:\path\to\file

# Delete specific stream
streams.exe -d [stream-name] C:\path\to\file
```

***

#### FTK Imager

{% code overflow="wrap" %}
```bash
# CLI mode - create image
ftkimager.exe [source] [destination] --e01 --compress 6 --case-number [case] --evidence-number [num]

# GUI operations:
# File > Add Evidence Item > [select source]
# Browse to artifact location
# Right-click > Export Files
```
{% endcode %}

***

#### PowerShell Commands

**Alternate Data Streams**

```powershell
# List all streams
Get-Item C:\path\to\file -Stream *

# Read stream content
Get-Content C:\path\to\file -Stream [stream-name]

# Create stream
Set-Content C:\path\to\file -Stream [stream-name] -Value "content"

# Remove stream
Remove-Item C:\path\to\file -Stream [stream-name]
```

**Registry Access**

{% code overflow="wrap" %}
```powershell
# Read registry key
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count"

# Export registry key
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" C:\Output\shimcache.reg
```
{% endcode %}

***

#### Command Prompt Commands

**Recycle Bin Manual Examination**

```bash
# Show hidden files
dir /a

# Navigate to Recycle Bin
cd C:\$Recycle.Bin
dir /a

# Navigate to user SID
cd [SID]
dir

# View metadata file
type $I[identifier]

# Copy deleted file
copy $R[identifier] C:\Output\recovered-file.ext
```

**Alternate Data Streams**

````cmd
# List files with streams
dir /R C:\path\to\directory

# View stream
more < C:\path\to\file:[stream-name]

# Execute from stream
wscript.exe C:\path\to\file:[stream-name]
```

---

## 📋 INVESTIGATION TEMPLATES

### Template 1: Malware Execution Investigation
```
OBJECTIVE: Determine if suspicious executable was run and when

ARTIFACTS TO COLLECT:
☐ Prefetch files
☐ Amcache.hve
☐ SYSTEM hive (ShimCache)
☐ NTUSER.DAT (UserAssist)

ANALYSIS WORKFLOW:
1. Search Prefetch for executable name
   ├─ If found: Extract last 8 run times and run count
   └─ If not found: Check if Prefetch is enabled

2. Search Amcache for executable
   ├─ Extract SHA1 hash
   ├─ Check VirusTotal / malware databases
   └─ Note full path and timestamps

3. Search ShimCache for executable path
   └─ Confirms presence even if deleted

4. Check UserAssist for GUI execution
   └─ Provides run count and last run time

5. Cross-reference timestamps across artifacts

QUESTIONS TO ANSWER:
- Was program executed? (Prefetch = yes, others = maybe)
- When was first execution?
- When was last execution?
- How many times was it run?
- What is the SHA1 hash?
- What files did it access?
- Has it been deleted?

DELIVERABLE:
Timeline of execution events with supporting evidence
```

---

### Template 2: USB Device Usage Investigation
```
OBJECTIVE: Determine what USB devices were connected and what files were accessed

ARTIFACTS TO COLLECT:
☐ ShellBags (USRCLASS.DAT, NTUSER.DAT)
☐ LNK files from Recent folder
☐ Jump Lists
☐ SYSTEM hive (USB device registry keys)
☐ Prefetch files

ANALYSIS WORKFLOW:
1. Parse ShellBags for removable device paths
   └─ Look for drive letters and volume names

2. Examine LNK files
   ├─ Filter for removable media paths
   ├─ Extract volume serial numbers
   └─ Note timestamps of file access

3. Review Jump Lists for files opened from USB
   └─ Check document applications (Office, PDF readers)

4. Check Registry for USB device history
   └─ HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR

5. Search Prefetch for executables run from USB
   └─ Volume information in .pf files

QUESTIONS TO ANSWER:
- What USB devices were connected?
- When were they first connected?
- When were they last connected?
- What files were accessed from USB?
- Were any programs executed from USB?
- Were files copied to/from USB?

DELIVERABLE:
USB device timeline with file access activity
```

---

### Template 3: Data Exfiltration Investigation
```
OBJECTIVE: Identify potential data theft and exfiltration methods

ARTIFACTS TO COLLECT:
☐ Jump Lists (archive tools, upload applications)
☐ LNK files (file access in sensitive directories)
☐ ShellBags (folder browsing activity)
☐ Prefetch (archiving tools, FTP clients, cloud sync)
☐ $J and $MFT (file operations, mass copies)
☐ RecentDocs and MRU keys
☐ Browser artifacts (separate investigation)

ANALYSIS WORKFLOW:
1. Identify staging directories
   ├─ Check ShellBags for new folder creation
   └─ Review $J for directory operations

2. Search for archive creation
   ├─ Prefetch: 7zip, WinRAR, WinZip execution
   ├─ Jump Lists: Files added to archives
   └─ $J: .zip, .rar, .7z file creation

3. Check for upload tools
   ├─ Prefetch: FTP clients, cloud sync tools
   ├─ Jump Lists: Files opened by upload apps
   └─ UserAssist: Cloud storage application use

4. Review sensitive document access
   ├─ LNK files: Office documents, PDFs
   ├─ Jump Lists: Multiple file opens
   └─ ShellBags: Sensitive directory browsing

5. Identify file copies to removable media
   ├─ ShellBags: USB drive access
   ├─ $J: Large file copy operations
   └─ LNK files: Files accessed from USB

6. Timeline correlation
   └─ Align file access, archiving, and transfer timestamps

QUESTIONS TO ANSWER:
- What files were accessed?
- Were files archived?
- What archiving tools were used?
- Were files copied to USB or network?
- Were cloud upload tools used?
- What was the timeline of activity?
- What was the volume of data?

DELIVERABLE:
Comprehensive timeline of data access and exfiltration with volume estimates
```

---

### Template 4: Persistence Mechanism Investigation
```
OBJECTIVE: Identify how malware maintains persistence on system

ARTIFACTS TO COLLECT:
☐ Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT)
☐ Startup folder contents
☐ Scheduled tasks
☐ Windows Services
☐ WMI subscriptions

ANALYSIS WORKFLOW:
1. Run Autoruns comprehensive scan
   └─ Export results to CSV

2. Check primary AutoStart registry keys
   ├─ HKCU and HKLM Run keys
   ├─ RunOnce keys
   └─ Winlogon entries

3. Examine Startup folders
   └─ %AppData%\Microsoft\Windows\Start Menu\Programs\Startup

4. Review Scheduled Tasks
   ├─ C:\Windows\System32\Tasks\
   └─ Check task triggers and actions

5. Investigate Windows Services
   ├─ New services created
   ├─ Services with unusual paths
   └─ Service DLL hijacking

6. Check for DLL search order hijacking
   └─ DLLs in application directories

7. Review WMI event subscriptions
   └─ wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter GET /FORMAT:LIST

8. Correlate LastWrite times with attack timeline

QUESTIONS TO ANSWER:
- What persistence mechanisms are present?
- When were they created?
- What executables are involved?
- Are they signed/verified?
- Are they in unusual locations?
- Do they survive reboots?

DELIVERABLE:
List of all persistence mechanisms with risk assessment and removal instructions
```

---

## 🎓 ANALYST BEST PRACTICES

### Collection Best Practices
```
1. Volatile First
   └─ Collect Prefetch before running analysis tools
   └─ Live response tools create new prefetch files

2. Preserve Originals
   └─ Work on copies, never original evidence
   └─ Maintain chain of custody

3. Document Everything
   └─ Commands run
   └─ Tools used and versions
   └─ Analysis notes
   └─ Findings

4. Use VSS
   └─ Volume Shadow Copies provide historical data
   └─ Critical for timeline depth

5. Hash Verification
   └─ Hash evidence before and after
   └─ Use Amcache SHA1 for executables
```

### Analysis Best Practices
```
1. Start Broad, Then Narrow
   └─ Begin with high-level timeline
   └─ Focus on suspicious time periods
   └─ Deep dive on specific artifacts

2. Cross-Reference Multiple Artifacts
   └─ Single artifact = low confidence
   └─ Multiple artifacts = high confidence
   └─ Build evidence matrix

3. Understand Limitations
   └─ Prefetch: May not prove execution on Win10+
   └─ Amcache: Presence, not execution
   └─ ShimCache: Definitely not execution on Win10+
   └─ UserAssist: GUI only

4. Use Timeline Analysis
   └─ Build super timeline with all artifacts
   └─ Look for temporal patterns
   └─ Identify anomalies

5. Consider Context
   └─ Corporate vs. personal use
   └─ User role and responsibilities
   └─ Normal behavior baseline
```

### Reporting Best Practices
```
1. Executive Summary
   └─ Non-technical overview
   └─ Impact assessment
   └─ Key findings

2. Technical Details
   └─ Artifact analysis results
   └─ Timeline of events
   └─ Evidence correlation

3. Visual Aids
   └─ Timelines
   └─ Process trees
   └─ Network diagrams

4. Indicators of Compromise (IOCs)
   └─ File hashes
   └─ File paths
   └─ Registry keys
   └─ IP addresses / domains

5. Recommendations
   └─ Remediation steps
   └─ Prevention measures
   └─ Security improvements
````

***

### 📊 ARTIFACT RELIABILITY MATRIX

| Artifact   | Execution Proof                              | Timing Accuracy                        | Historical Depth                       | Data Richness                        | Forensic Value |
| ---------- | -------------------------------------------- | -------------------------------------- | -------------------------------------- | ------------------------------------ | -------------- |
| Prefetch   | <p>✅ High (Win7-8)<br>⚠️ Medium (Win10+)</p> | <p>✅ Excellent<br>(±10 sec)</p>        | <p>⚠️ Limited<br>(Last 8 times)</p>    | <p>✅ High<br>(Files accessed)</p>    | ⭐⭐⭐⭐⭐          |
| Amcache    | <p>❌ Low<br>(Presence only)</p>              | <p>✅ Good<br>(Multiple timestamps)</p> | <p>✅ Excellent<br>(Historical)</p>     | <p>⭐ Very High<br>(SHA1 hashes!)</p> | ⭐⭐⭐⭐⭐          |
| ShimCache  | <p>❌ None (Win10+)<br>⚠️ Low (Win7-8)</p>    | <p>⚠️ Limited<br>(Mod time only)</p>   | <p>✅ Excellent<br>(1024 entries)</p>   | <p>⚠️ Medium<br>(Paths only)</p>     | ⭐⭐⭐            |
| UserAssist | <p>✅ High<br>(GUI only)</p>                  | ✅ Good                                 | <p>⚠️ Limited<br>(Per application)</p> | <p>✅ High<br>(Focus time)</p>        | ⭐⭐⭐⭐           |
| Jump Lists | <p>✅ High<br>(Indirect)</p>                  | ✅ Excellent                            | <p>⚠️ Limited<br>(Recent items)</p>    | <p>✅ High<br>(File associations)</p> | ⭐⭐⭐⭐           |
| LNK Files  | <p>⚠️ Medium<br>(File access)</p>            | ✅ Excellent                            | <p>⚠️ Limited<br>(Latest only)</p>     | <p>✅ Very High<br>(Device info)</p>  | ⭐⭐⭐⭐           |
| ShellBags  | <p>⚠️ Medium<br>(Folder access)</p>          | ✅ Good                                 | ✅ Excellent                            | <p>✅ Very High<br>(Exotic items)</p> | ⭐⭐⭐⭐           |
| $MFT       | ❌ None                                       | ✅ Excellent                            | ✅ Excellent                            | ✅ Very High                          | ⭐⭐⭐⭐⭐          |
| $J         | ❌ None                                       | ✅ Excellent                            | <p>⚠️ Medium<br>(Circular log)</p>     | <p>⭐ Very High<br>(Operations)</p>   | ⭐⭐⭐⭐⭐          |
| $LogFile   | ❌ None                                       | ✅ Excellent                            | <p>❌ Low<br>(Very recent)</p>          | <p>⭐ Very High<br>(Transactions)</p> | ⭐⭐⭐            |

***

### 🔑 KEY TAKEAWAYS

#### Critical Rules to Remember

1. **Prefetch Priority**
   * Collect FIRST - it's volatile
   * Proves execution (with caveats on Win10+)
   * Contains last 8 execution times
2. **Amcache is Unique**
   * ONLY native source of SHA1 hashes
   * Does NOT prove execution
   * Excellent for malware identification
3. **ShimCache on Win10+**
   * Does NOT prove execution
   * Only proves file existed
   * Useful for historical presence
4. **Cross-Reference Everything**
   * Single artifact = low confidence
   * Multiple artifacts = high confidence
   * Build correlation matrix
5. **Understand Windows Versions**
   * Win7/8 vs Win10/11 behavior differs
   * Prefetch compression on Win10/11
   * ShimCache reliability decreased
6. **Timeline is King**
   * Build comprehensive super timeline
   * Correlate across all artifacts
   * Look for temporal patterns
7. **SHA1 Hashes Matter**
   * Use Amcache for executable identification
   * Cross-reference with VirusTotal
   * Identify known good vs. known bad
8. **Persistence Hunting**
   * Check all ASEP locations
   * Review Scheduled Tasks
   * Examine Windows Services
   * Stack results across systems

***

### 📞 QUICK REFERENCE CARD

#### Top 5 Evidence of Execution Artifacts

1. **Prefetch** - Proves execution, timing, run count
2. **Amcache** - SHA1 hashes, metadata
3. **UserAssist** - GUI program tracking
4. **Jump Lists** - Application file access
5. **ShimCache** - Historical presence (Win10+ caveat)

#### Top 5 User Activity Artifacts

1. **LNK Files** - File/folder access, device info
2. **ShellBags** - Folder navigation
3. **Jump Lists** - Recent documents
4. **RecentDocs/MRU** - Application usage
5. **Recycle Bin** - Deleted files

#### Top 5 File System Artifacts

1. **$MFT** - Complete file metadata
2. **$J** - Change journal (creates, deletes, renames)
3. **$LogFile** - NTFS transactions
4. **ADS** - Hidden data streams
5. **Volume Shadow Copies** - Historical snapshots

#### Top 5 Zimmerman Tools

1. **PECmd** - Prefetch parsing
2. **MFTECmd** - File system analysis
3. **JLECmd** - Jump List parsing
4. **LECmd** - LNK file parsing
5. **Registry Explorer** - Registry analysis

#### Top Investigation Commands

{% code overflow="wrap" %}
```bash
# Quick triage set
.\PECmd.exe -d C:\Windows\Prefetch --csv C:\Output -q
.\AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\Output
.\AppCompatCacheParser.exe --csv C:\Output
JLECmd.exe -d %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations --csv C:\Output -q
LECmd.exe -d %APPDATA%\Microsoft\Windows\Recent --csv C:\Output -q
```
{% endcode %}

***

_For DFIR Practitioner_
