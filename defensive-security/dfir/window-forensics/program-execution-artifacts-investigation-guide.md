# Program Execution Artifacts Investigation Guide

### baComplete DFIR Workflow & Cheatsheet

***

### 📚 Table of Contents

1. [Artifact Priority Matrix](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#artifact-priority-matrix)
2. [Investigation Workflow](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-workflow)
3. [Prefetch Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#prefetch-analysis)
4. [BAM/DAM Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#bamdam-analysis)
5. [ShimCache Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#shimcache-analysis)
6. [Amcache Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#amcache-analysis)
7. [Jump Lists Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#jump-lists-analysis)
8. [UserAssist Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#userassist-analysis)
9. [Windows Timeline Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#windows-timeline-analysis)
10. [SRUM Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#srum-analysis)
11. [MRU Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#mru-analysis)
12. [PowerShell History](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#powershell-history)
13. [NTFS Artifacts](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#ntfs-artifacts)
14. [Investigation Playbooks](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-playbooks)
15. [Tool Reference](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#tool-reference)

***

### 🎯 Artifact Priority Matrix

#### Quick Decision Guide: Which Artifact to Check First?

| Investigation Goal      | Primary Artifacts                | Secondary Artifacts | Timeframe |
| ----------------------- | -------------------------------- | ------------------- | --------- |
| **Prove Execution**     | Prefetch, BAM/DAM                | Amcache, SRUM       | Minutes   |
| **Execution Timeline**  | Prefetch (last 8 times), BAM/DAM | ShimCache, Timeline | Minutes   |
| **User Activity**       | UserAssist, Jump Lists           | Timeline, MRU       | 15-30 min |
| **Malware Presence**    | Prefetch, ShimCache, Amcache     | BAM/DAM             | 15-30 min |
| **File Access History** | Jump Lists, MRU                  | Timeline, SRUM      | 30-45 min |
| **Network Activity**    | SRUM                             | Timeline            | 30 min    |
| **Deleted Files**       | $J, $LogFile                     | MFT, ShimCache      | 45-60 min |
| **PowerShell Activity** | ConsoleHost\_history.txt         | Event Logs          | 15 min    |
| **Hidden Data**         | ADS                              | MFT                 | 30 min    |

***

### 🔍 Investigation Workflow

#### Phase 1: Quick Triage (First 15 Minutes)

**Step 1: Determine Investigation Scope**

```bash
□ What's the alert/indicator?
□ Do we have a specific executable name?
□ Do we have a timeframe?
□ Is this live system or forensic image?
□ What's the suspected malware/activity?
```

**Step 2: Collect Core Artifacts (Live System)**

{% code overflow="wrap" %}
```powershell
# Create collection directory
New-Item -Path "C:\DFIR_Collection" -ItemType Directory -Force

# Collect Prefetch
Copy-Item "C:\Windows\Prefetch\*" -Destination "C:\DFIR_Collection\Prefetch\" -Recurse

# Export registry hives
reg save HKLM\SYSTEM "C:\DFIR_Collection\SYSTEM" /y
reg save HKLM\SOFTWARE "C:\DFIR_Collection\SOFTWARE" /y
reg save HKLM\SAM "C:\DFIR_Collection\SAM" /y

# Copy user profiles (for specific user)
$User = "username"
Copy-Item "C:\Users\$User\NTUSER.DAT" -Destination "C:\DFIR_Collection\"
Copy-Item "C:\Users\$User\AppData\Local\Microsoft\Windows\UsrClass.dat" -Destination "C:\DFIR_Collection\"

# Collect Amcache
Copy-Item "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination "C:\DFIR_Collection\"

# Collect PowerShell history
Copy-Item "C:\Users\$User\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Destination "C:\DFIR_Collection\"

# Collect SRUM
Copy-Item "C:\Windows\System32\sru\SRUDB.dat" -Destination "C:\DFIR_Collection\"

# Collect Timeline
Copy-Item "C:\Users\$User\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db" -Destination "C:\DFIR_Collection\" -Recurse
```
{% endcode %}

**Step 3: Quick Wins - Check These First**

{% code overflow="wrap" %}
```powershell
# 1. Check Prefetch for executable
Get-ChildItem C:\Windows\Prefetch\MALWARE*.pf -ErrorAction SilentlyContinue

# 2. Check BAM/DAM for recent execution
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s | findstr /i "malware"

# 3. Check PowerShell history
Get-Content "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# 4. Check running processes
Get-Process | Where-Object {$_.Name -like "*suspicious*"}
```
{% endcode %}

***

#### Phase 2: Detailed Analysis (30-60 Minutes)

**Step 1: Execution Timeline Construction**

```bash
Use these artifacts in order:
1. Prefetch (last 8 execution times + run count)
2. BAM/DAM (last execution time, up to 1 week)
3. Timeline (30 days of activity)
4. ShimCache (presence, not execution proof)
5. Amcache (presence, metadata, SHA1 hash)
```

**Step 2: User Activity Analysis**

```bash
1. UserAssist (GUI program launches)
2. Jump Lists (files accessed by applications)
3. MRU (recent documents, commands)
4. Timeline (comprehensive activity log)
```

**Step 3: Persistence & IOC Extraction**

```bash
1. Run Keys (registry persistence)
2. ShimCache (check unusual paths)
3. Amcache (get SHA1 hashes)
4. ADS (hidden files)
```

***

### 💾 Prefetch Analysis

#### Overview

* **Purpose**: Evidence of program execution with timestamps
* **Location**: `C:\Windows\Prefetch`
* **Format**: `(exename)-(hash).pf`
* **Retention**: Up to 1,024 files (128 on Server 2016+)
* **Enabled**: Workstations by default, NOT on servers

#### Key Information Available

| Data Point            | Description                      | Forensic Value                            |
| --------------------- | -------------------------------- | ----------------------------------------- |
| **Execution Count**   | Total times executed             | Distinguish single vs. repeated execution |
| **Last 8 Run Times**  | Win10/11 store last 8 timestamps | Timeline of activity                      |
| **File Path**         | Original execution location      | Identify unusual paths                    |
| **Files Referenced**  | DLLs, resources loaded           | Understand program behavior               |
| **Volumes**           | Drives accessed                  | Removable media usage                     |
| **Creation Time**     | First execution time (-10 sec)   | Initial compromise time                   |
| **Modification Time** | Last execution time (-10 sec)    | Most recent activity                      |

#### Registry Configuration Check

**Check if Prefetch is Enabled:**

{% code overflow="wrap" %}
```powershell
# Check registry value
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher

# Values:
# 0 = Disabled
# 1 = Application Prefetching Only
# 2 = Boot Prefetching Only  
# 3 = Both Enabled (default on workstations)
```
{% endcode %}

#### Collection & Analysis

**Using PECmd (Prefetch Explorer Command Line):**

{% code overflow="wrap" %}
```powershell
# Single file analysis
.\PECmd.exe -f "C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf"

# Single file with CSV output
.\PECmd.exe -f "C:\Windows\Prefetch\MALWARE.EXE-1234ABCD.pf" --csv "C:\Analysis" --csvf malware_prefetch.csv

# Entire directory analysis
.\PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Analysis" --csvf all_prefetch.csv

# With quiet mode (less console output)
.\PECmd.exe -d "C:\Windows\Prefetch" -q --csv "C:\Analysis" --csvf all_prefetch.csv

# Include Volume Shadow Copies
.\PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Analysis" --csvf prefetch_with_vss.csv --vss

# Highlight suspicious keywords
.\PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Analysis" --csvf prefetch.csv -k "temp,downloads,appdata,public"

# High precision timestamps
.\PECmd.exe -d "C:\Windows\Prefetch" -q --csv "C:\Analysis" --csvf prefetch.csv --mp
```
{% endcode %}

**Using WinPrefetchView:**

```bash
1. Download from NirSoft
2. Run WinPrefetchView.exe
3. File → Select Folder → Choose C:\Windows\Prefetch
4. File → Export → CSV
```

#### Analysis Tips

**🔴 Red Flags to Look For:**

1.  **Multiple Prefetch Files for Same Executable**

    ```bash
    CMD.EXE-0BD30981.pf  (Normal: C:\Windows\System32\cmd.exe)
    CMD.EXE-8A7E2C91.pf  (Suspicious: C:\Users\Public\cmd.exe)
    ```

    * Different hash = different path or command line
    * Indicates executable run from non-standard location
2.  **Executables from Suspicious Paths**

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"># Search Prefetch for suspicious paths
    .\PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Analysis" --csvf prefetch.csv -k "temp,appdata,downloads,public,recycle"
    </code></pre>

    * `C:\Users\*\Downloads\`
    * `C:\Users\*\AppData\Local\Temp\`
    * `C:\Users\Public\`
    * `C:\$Recycle.Bin\`
    * `C:\ProgramData\`
3.  **Known Malware Names**

    ```bash
    MIMIKATZ.EXE-*.pf
    PSEXEC.EXE-*.pf (on non-admin workstation)
    PROCDUMP.EXE-*.pf
    PWDUMP.EXE-*.pf
    ```
4.  **Hosting Applications with Multiple Hashes**

    ```bash
    Normal:
    - RUNDLL32.EXE (multiple hashes normal - based on DLL loaded)
    - SVCHOST.EXE (multiple hashes normal - different services)
    - DLLHOST.EXE
    - BACKGROUNDTASKHOST.EXE

    Investigation needed if count is excessive (>20)
    ```
5. **Low Run Count with Recent Execution**
   * Run count = 1 or 2
   * Recent modification time
   * Possibly newly introduced malware

**Prefetch Timeline Analysis:**

```powershell
# Parse all Prefetch and create timeline
.\PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\Analysis" --csvf timeline.csv --mp

# Import into Excel/Timeline Explorer and sort by:
# - Last Run Time (column: LastRun)
# - Review "Previous Run Times" for pattern
# - Check "Run Count" for frequency
# - Examine "Files Loaded" for suspicious DLLs
```

**Pro Tips:**

⚠️ **CRITICAL**: Running forensic tools creates Prefetch files!

* Prioritize Prefetch collection FIRST
* Oldest files deleted when limit reached (1,024)
* Use forensic imaging to preserve evidence

✅ **Win10/11 Compression**: Files are compressed - use PECmd to decompress automatically

✅ **Execution != Success**: Prefetch created even if program crashes/fails

✅ **Network Execution**: Programs run from network shares create Prefetch on local system

***

### ⚡ BAM/DAM Analysis

#### Overview

* **BAM**: Background Activity Moderator
* **DAM**: Desktop Activity Moderator
* **Purpose**: Control background app activity
* **Available**: Windows 10 1709+ / Server 2016+
* **Retention**: \~7 days

#### Key Information Available

| Data Point              | Description                     |
| ----------------------- | ------------------------------- |
| **Full Path**           | Complete path to executable     |
| **Last Execution Time** | Most recent execution timestamp |
| **User SID**            | Which user executed the program |

#### Location

```bash
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}
```

#### Collection & Analysis

**Manual Registry Query:**

{% code overflow="wrap" %}
```powershell
# Query BAM for all users
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s

# Query DAM for all users
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" /s

# Search for specific executable
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s | findstr /i "malware.exe"

# Query for specific user SID
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-XXX" /s
```
{% endcode %}

**PowerShell Parsing:**

{% code overflow="wrap" %}
```powershell
# Parse BAM entries
$BAMPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
Get-ChildItem $BAMPath | ForEach-Object {
    $UserSID = $_.PSChildName
    $Props = Get-ItemProperty $_.PSPath
    
    $Props.PSObject.Properties | Where-Object {$_.Name -like "*\*"} | ForEach-Object {
        $ExecutablePath = $_.Name
        $RawTimestamp = $_.Value
        
        # Convert timestamp (stored as filetime)
        if ($RawTimestamp -is [byte[]]) {
            $Timestamp = [DateTime]::FromFileTime([BitConverter]::ToInt64($RawTimestamp, 0))
        }
        
        [PSCustomObject]@{
            UserSID = $UserSID
            ExecutablePath = $ExecutablePath
            LastExecutionTime = $Timestamp
        }
    }
} | Export-Csv C:\Analysis\BAM_Parsed.csv -NoTypeInformation
```
{% endcode %}

**Using RegistryExplorer:**

```bash
1. Load SYSTEM hive
2. Navigate to: CurrentControlSet\Services\bam\State\UserSettings
3. Expand each SID subkey
4. Review values (executable paths with timestamps)
5. Export to CSV
```

**Using BamParser.py:**

```bash
# Parse exported SYSTEM hive
python BamParser.py -f SYSTEM -o bam_output.csv
```

#### Analysis Tips

**Investigation Workflow:**

```bash
1. Identify User → Match SID to username using:
   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
   
2. Review Execution Paths → Look for:
   - Temp directories
   - Downloads folders
   - Removable media (E:, F:)
   - Suspicious locations
   
3. Correlate with Other Artifacts → Cross-reference with:
   - Prefetch (confirm execution + get more details)
   - Event Logs (logon sessions)
   - Timeline (broader activity context)
```

**Red Flags:**

```bash
✓ Service accounts executing interactive programs
✓ Executables from external drives
✓ Programs in temp/download folders
✓ Execution outside business hours
✓ Known attack tools (mimikatz, psexec, procdump)
```

**Limitations:**

⚠️ Shows LAST execution only (not historical) ⚠️ \~7 day retention ⚠️ Doesn't prove execution success ⚠️ Can be cleared on reboot (not persistent)

***

### 📋 ShimCache Analysis

#### Overview

* **Official Name**: Application Compatibility Cache
* **Purpose**: Track compatibility settings for programs
* **Key Feature**: Tracks executables even if NOT executed
* **Location**: SYSTEM registry hive
* **Retention**: 1,024 entries (Win7+)

#### CRITICAL Understanding

```bash
⚠️ IMPORTANT: ShimCache in Win10+ does NOT prove execution
   - Proves: File existed/was present on system
   - Does NOT prove: File was actually executed
   - Use for: Malware presence, timeline, deleted file evidence
```

#### Key Information Available

| Data Point             | Description                        | Forensic Value                     |
| ---------------------- | ---------------------------------- | ---------------------------------- |
| **Full Path**          | Complete path to executable        | Identify malware location          |
| **File Size**          | Size of executable                 | Cross-reference with known malware |
| **Last Modified Time** | File's last modification timestamp | Timeline analysis                  |
| **Existence**          | Proof file was present             | Evidence even if deleted           |

#### Location

```bash
Live System:
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

File:
C:\Windows\System32\config\SYSTEM

Determine Current ControlSet:
HKLM\SYSTEM\Select\Current
```

#### Collection & Analysis

**Using AppCompatCacheParser:**

{% code overflow="wrap" %}
```powershell
# Parse live system
.\AppCompatCacheParser.exe -t --csv "C:\Analysis" --csvf shimcache.csv

# Parse exported SYSTEM hive
.\AppCompatCacheParser.exe -f "C:\Evidence\SYSTEM" --csv "C:\Analysis" --csvf shimcache.csv

# Include all control sets
.\AppCompatCacheParser.exe -f "C:\Evidence\SYSTEM" --csv "C:\Analysis" --csvf shimcache_all.csv -t
```
{% endcode %}

**Manual Registry Export:**

{% code overflow="wrap" %}
```powershell
# Export ShimCache key
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" C:\Analysis\shimcache.reg
```
{% endcode %}

#### Analysis Tips

**Understanding the Output:**

```bash
Key Columns in CSV:
- CacheEntryPosition: Position in cache (0 = most recent)
- Path: Full path to executable
- LastModifiedTimeUTC: File's modification time
- Executed: (Win7/8 only - not reliable in Win10+)
```

**Investigation Workflow:**

1. **Sort by CacheEntryPosition** (most recent = position 0)
   * Recent activity appears first
   * Useful for timeline
2.  **Search for Suspicious Patterns:**

    ```powershell
    # Import CSV and filter
    $ShimCache = Import-Csv C:\Analysis\shimcache.csv

    # Suspicious paths
    $ShimCache | Where-Object {
        $_.Path -match "temp|tmp|downloads|public|appdata\\local\\temp|recycle"
    }

    # Known malware names
    $ShimCache | Where-Object {
        $_.Path -match "mimikatz|psexec|procdump|pwdump|cobalt"
    }

    # Single/two letter executables
    $ShimCache | Where-Object {
        $_.Path -match "\\[a-z]{1,2}\.exe$"
    }
    ```
3.  **Cross-Reference with Prefetch:**

    ```bash
    ShimCache shows presence → Prefetch proves execution

    If in ShimCache but NOT in Prefetch:
    - May not have been executed
    - May have been deleted
    - May have been blocked
    ```

**Red Flags:**

```bash
🚩 Executables from:
   - C:\Users\Public\
   - C:\Windows\Temp\
   - C:\$Recycle.Bin\
   - System Volume Information
   - Removable media roots (E:\, F:\)

🚩 Unusual system tool locations:
   - cmd.exe NOT in System32
   - powershell.exe in Downloads
   - net.exe in Temp

🚩 LOLBins in suspicious contexts:
   - regsvr32.exe with DLLs from temp
   - rundll32.exe from appdata
   - mshta.exe from downloads
```

**Timeline Analysis:**

```bash
ShimCache updates on shutdown/reboot only!

Entries added to cache when:
1. File is first accessed
2. File metadata is checked
3. Compatibility check performed

Last Modified Time = File's timestamp, NOT when added to cache
```

**Pro Tips:**

✅ **Deleted File Recovery**: ShimCache may be only evidence of deleted malware

✅ **Pre-Execution Evidence**: Files scanned by AV/security tools appear in ShimCache

✅ **Network Drive Execution**: UNC paths captured if executed

⚠️ **False Positives**: Installers, Windows Updates create many entries

***

### 🗂️ Amcache Analysis

#### Overview

* **Location**: `C:\Windows\AppCompat\Programs\Amcache.hve`
* **Purpose**: Track installed applications and executed programs
* **Key Feature**: Contains SHA1 hashes of executables!
* **Retention**: Long-term (not time-limited)

#### Key Information Available

| Data Point             | Description                 | Forensic Value         |
| ---------------------- | --------------------------- | ---------------------- |
| **Full Path**          | Complete path to executable | Malware location       |
| **SHA1 Hash**          | File hash                   | Malware identification |
| **File Size**          | Size of file                | Cross-reference        |
| **Compilation Time**   | PE header timestamp         | Build date             |
| **Publisher**          | Code signing certificate    | Legitimacy check       |
| **File Version**       | Version info                | Specific variant       |
| **Language**           | Program language            | Target analysis        |
| **File Modified Time** | Last modification           | Timeline               |

#### CRITICAL Understanding

```bash
⚠️ Amcache shows PRESENCE, not necessarily EXECUTION
   - Entries created during: Installation, file discovery, program execution
   - Use as: Evidence of file existence, hash extraction, metadata collection
   - Don't use as: Definitive proof of execution (use Prefetch for that)
```

#### Collection & Analysis

**Collection (Live System):**

```powershell
# Copy Amcache files
Copy-Item "C:\Windows\AppCompat\Programs\Amcache.hve" -Destination "C:\Analysis\"
Copy-Item "C:\Windows\AppCompat\Programs\Amcache.hve.LOG1" -Destination "C:\Analysis\"
Copy-Item "C:\Windows\AppCompat\Programs\Amcache.hve.LOG2" -Destination "C:\Analysis\"
```

**Collection (FTK Imager):**

```bash
1. File → Add Evidence Item → Physical Drive
2. Navigate: [Windows]\AppCompat\Programs\
3. Select: Amcache.hve, Amcache.hve.LOG1, Amcache.hve.LOG2
4. Right-click → Export Files
```

**Using AmcacheParser:**

{% code overflow="wrap" %}
```powershell
# Parse Amcache (live system)
.\AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Analysis" --csvf amcache.csv

# Parse Amcache (exported file)
.\AmcacheParser.exe -f "C:\Evidence\Amcache.hve" --csv "C:\Analysis" --csvf amcache.csv

# Include unassociated file entries
.\AmcacheParser.exe -f "C:\Evidence\Amcache.hve" -i --csv "C:\Analysis" --csvf amcache_full.csv

# With whitelist (filter known goods)
.\AmcacheParser.exe -f "C:\Evidence\Amcache.hve" -w "C:\whitelists\microsoft.txt" --csv "C:\Analysis"
```
{% endcode %}

**Using Registry Explorer:**

```bash
1. Run RegistryExplorer.exe as Administrator
2. File → Load Hive → Select Amcache.hve
3. Navigate: ROOT → InventoryApplicationFile (programs executed)
4. Navigate: ROOT → InventoryDriverBinary (drivers loaded)
5. Review entries, export to CSV
```

#### Analysis Tips

**Key Tables in Amcache:**

```bash
InventoryApplicationFile: Executables that ran or were installed
InventoryDriverBinary: Driver files loaded
Programs: Installed applications (MSI, setup)
```

**Investigation Workflow:**

1.  **Extract SHA1 Hashes:**

    ```powershell
    # Parse and extract hashes
    .\AmcacheParser.exe -f Amcache.hve --csv C:\Analysis

    # Open output CSV: Amcache_UnassociatedFileEntries.csv
    # Column: SHA1
    ```
2.  **Check Hashes Against Threat Intelligence:**

    ```powershell
    # Extract unique SHA1s
    $Hashes = Import-Csv C:\Analysis\Amcache_UnassociatedFileEntries.csv | 
        Select-Object -ExpandProperty SHA1 -Unique

    # Check against VirusTotal (API required)
    # Check against internal malware database
    ```
3.  **Identify Suspicious Paths:**

    ```powershell
    $Amcache = Import-Csv C:\Analysis\Amcache_UnassociatedFileEntries.csv

    $Amcache | Where-Object {
        $_.FullPath -match "temp|downloads|public|appdata\\local\\temp"
    } | Select-Object FullPath, SHA1, FileSize, Created, Modified
    ```
4.  **Check Unsigned/Unknown Publishers:**

    ```powershell
    $Amcache | Where-Object {
        $_.Publisher -eq "" -or $_.Publisher -eq $null
    } | Select-Object FullPath, SHA1, FileSize
    ```
5.  **Analyze Compilation Times:**

    ```powershell
    # Executables compiled recently (possible custom malware)
    $Amcache | Where-Object {
        $_.CompileTime -gt (Get-Date).AddDays(-30)
    }
    ```

**Red Flags:**

```bash
🚩 No publisher information (unsigned)
🚩 Recent compilation time (custom-built malware)
🚩 Small file size (<100KB for .exe)
🚩 Suspicious paths (temp, downloads, appdata)
🚩 SHA1 hash matches known malware
🚩 Mismatched file names (e.g., "svchost.exe" in Downloads)
```

**Cross-Reference Strategy:**

```bash
Amcache → Get SHA1 → Check VirusTotal
         ↓
    Get Path → Check Prefetch (was it executed?)
         ↓
    Get Timestamp → Build timeline
```

**Pro Tips:**

✅ **Hash Database**: Build whitelist of known-good Microsoft hashes

✅ **Driver Analysis**: InventoryDriverBinary tracks drivers (rootkit detection)

✅ **Portable Apps**: External USB executables tracked

⚠️ **Compilation Time**: Can be forged by attacker

***

### 🔗 Jump Lists Analysis

#### Overview

* **Purpose**: Track recently/frequently accessed files per application
* **Location**: `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\`
* **Types**:
  * AutomaticDestinations (automatic)
  * CustomDestinations (pinned to taskbar)
* **Retention**: \~2,000 items per application

#### Key Information Available

| Data Point       | Description       | Forensic Value       |
| ---------------- | ----------------- | -------------------- |
| **Target Path**  | File accessed     | Document analysis    |
| **Timestamps**   | Access times      | Timeline             |
| **File Size**    | Size of target    | Verification         |
| **Volume Info**  | Local/Network/USB | Data exfil detection |
| **Network Path** | UNC paths         | Lateral movement     |
| **MRU Order**    | Access frequency  | User behavior        |

#### Location Details

```bash
AutomaticDestinations:
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\

CustomDestinations:
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\

Naming Format:
{AppID}.automaticDestinations-ms
{AppID}.customDestinations-ms

Example:
f01b4d95cf55d32a.automaticDestinations-ms = Microsoft Word
```

#### Common Application IDs

| AppID            | Application          |
| ---------------- | -------------------- |
| f01b4d95cf55d32a | Microsoft Word       |
| 23646679aaccfae0 | Microsoft Excel      |
| 1b72d5ec7c8ef7f6 | Microsoft PowerPoint |
| 5d696d521de238c3 | Notepad              |
| 9b9cdc69c1c24e2b | File Explorer        |
| fb3b0dbfee58fac8 | Remote Desktop       |
| 7cfdf86b2e3d65ef | Paint                |
| 1ac14e77410f4e4b | Chrome               |
| bc3e45ec13a6059e | Edge                 |

**Full List**: https://dfir.to/EZJumpList

#### Collection & Analysis

**Collection:**

{% code overflow="wrap" %}
```powershell
# Copy all jump lists for user
$User = "username"
Copy-Item "C:\Users\$User\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*" -Destination "C:\Analysis\JumpLists\Auto\"
Copy-Item "C:\Users\$User\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*" -Destination "C:\Analysis\JumpLists\Custom\"
```
{% endcode %}

**Using JLECmd (JumpList Explorer Command Line):**

{% code overflow="wrap" %}
```powershell
# Single file
.\JLECmd.exe -f "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms" --csv "C:\Analysis" -q

# All jump lists for user
.\JLECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\Analysis" -q

# Both Auto and Custom
.\JLECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\Analysis" --csvf auto.csv -q
.\JLECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" --csv "C:\Analysis" --csvf custom.csv -q
```
{% endcode %}

**Using JumpListExplorer (GUI):**

```bash
1. Run JumpListExplorer.exe
2. File → Load Jump List Directory
3. Select AutomaticDestinations folder
4. Review entries by application
5. Export → CSV
```

#### Analysis Tips

**Investigation Workflows:**

**1. Recent Document Access:**

{% code overflow="wrap" %}
```powershell
# Parse all jump lists
.\JLECmd.exe -d "C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\Analysis"

# Import and filter
$JumpLists = Import-Csv C:\Analysis\*.csv

# Documents accessed in last 7 days
$JumpLists | Where-Object {
    [datetime]$_.LastModified -gt (Get-Date).AddDays(-7)
} | Select-Object AppId, TargetPath, LastModified, FileSize
```
{% endcode %}

**2. Network Share Access (Lateral Movement):**

```powershell
# Find UNC paths
$JumpLists | Where-Object {
    $_.TargetPath -match "^\\\\"
} | Select-Object AppId, TargetPath, LastModified

# Group by server
$JumpLists | Where-Object {$_.TargetPath -match "^\\\\"} | 
    Group-Object @{Expression={($_.TargetPath -split '\\')[2]}}
```

**3. External Drive Usage:**

```powershell
# USB/External drives (E:, F:, etc.)
$JumpLists | Where-Object {
    $_.TargetPath -match "^[E-Z]:\\"
} | Select-Object AppId, TargetPath, VolumeLabel, VolumeSerialNumber
```

**4. Sensitive File Access:**

```powershell
# Look for sensitive documents
$JumpLists | Where-Object {
    $_.TargetPath -match "password|confidential|secret|ssn|credential|private"
} | Select-Object AppId, TargetPath, LastModified
```

**5. RDP Connection History:**

```powershell
# Remote Desktop jump lists (AppID: fb3b0dbfee58fac8)
$RDP = $JumpLists | Where-Object {$_.AppId -eq "fb3b0dbfee58fac8"}

# Extract destination IPs/hostnames
$RDP | Select-Object TargetPath, LastModified | Format-Table
```

**Red Flags:**

```bash
🚩 Access to \\C$ or \\ADMIN$ shares (lateral movement)
🚩 Documents from external drives (data exfiltration)
🚩 Access to unusual file types (.ps1, .exe, .dll via Office)
🚩 RDP connections to suspicious IPs
🚩 Recent access to sensitive documents during off-hours
🚩 Access to files on systems user shouldn't reach
```

**Investigation Scenarios:**

**Scenario 1: Data Exfiltration**

```bash
Check Jump Lists for:
1. External drive letters (E:, F:, G:)
2. Files copied to USB
3. Volume serial numbers (track specific USB devices)
4. Timestamp correlation with logon/logoff
```

**Scenario 2: Lateral Movement**

```bash
Check Jump Lists for:
1. UNC paths (\\SERVER\Share\)
2. Access to admin shares (\\HOST\C$)
3. RDP connection history
4. Timeline of access across multiple systems
```

**Scenario 3: Document Activity**

```bash
Check Jump Lists for:
1. Recently accessed files
2. Deleted documents (Jump List persists after deletion)
3. Access patterns (frequency)
4. Shared documents
```

**Pro Tips:**

✅ **Persistence**: Jump Lists survive file deletion (evidence of deleted files)

✅ **MRU Order**: Most recently used = position 0

✅ **Link Files**: Each entry is essentially a .lnk file with rich metadata

⚠️ **Privacy Mode**: Private browsing doesn't create jump list entries

***

### 🖱️ UserAssist Analysis

#### Overview

* **Purpose**: Track GUI-based program launches
* **Location**: NTUSER.DAT registry hive per user
* **Encoding**: ROT13 (rotate 13 characters)
* **Retention**: Persistent (doesn't age out)

#### Key Information Available

| Data Point        | Description                | Forensic Value     |
| ----------------- | -------------------------- | ------------------ |
| **Program Path**  | Full path to executable    | Malware location   |
| **Last Run Time** | Most recent execution      | Timeline           |
| **Run Count**     | Number of times executed   | Frequency analysis |
| **Focus Time**    | Time application had focus | Usage duration     |
| **Focus Count**   | Times app received focus   | User interaction   |

#### Location

```bash
Registry Path:
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count

File Location:
C:\Users\{Username}\NTUSER.DAT

GUIDs:
{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} = Executable File Execution
{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F} = Shortcut File Execution
```

#### Collection & Analysis

**Manual Registry Query (requires decoding):**

{% code overflow="wrap" %}
```powershell
# View raw (ROT13 encoded) entries
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
```
{% endcode %}

**Using Registry Explorer (Recommended):**

{% code overflow="wrap" %}
```bash
1. Run RegistryExplorer.exe as Administrator
2. File → Live System (or load NTUSER.DAT)
3. Navigate: ROOT → Software → Microsoft → Windows → CurrentVersion → Explorer → UserAssist
4. Expand CEBFF5CD (Executables) and F4E57C4B (Shortcuts)
5. Review decoded values
6. Export to CSV
```
{% endcode %}

**Using RegRipper:**

```powershell
# Extract and parse NTUSER.DAT
.\rr.exe -r "C:\Users\john\NTUSER.DAT" -p userassist > userassist_output.txt
```

**PowerShell Parsing with ROT13 Decode:**

{% code overflow="wrap" %}
```powershell
function Decode-ROT13 {
    param([string]$EncodedString)
    $decoded = ""
    foreach ($char in $EncodedString.ToCharArray()) {
        if ($char -match '[A-Za-z]') {
            $base = if ($char -match '[A-Z]') { 65 } else { 97 }
            $decoded += [char](((([int]$char - $base + 13) % 26) + $base))
        } else {
            $decoded += $char
        }
    }
    return $decoded
}

# Parse UserAssist
$UserAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"

Get-ItemProperty -Path $UserAssistPath | 
    Select-Object * -ExcludeProperty PS* | 
    ForEach-Object {
        $_.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} | ForEach-Object {
            $EncodedPath = $_.Name
            $DecodedPath = Decode-ROT13 $EncodedPath
            $Value = $_.Value
            
            # Parse value (binary data containing timestamps and counts)
            [PSCustomObject]@{
                DecodedPath = $DecodedPath
                RawValue = $Value
            }
        }
    } | Export-Csv C:\Analysis\UserAssist_Decoded.csv -NoTypeInformation
```
{% endcode %}

#### Analysis Tips

**Investigation Workflow:**

1. **Load and Decode:**
   * Use Registry Explorer (automatic decoding)
   * Or manually decode ROT13 values
2.  **Sort by Last Run Time:**

    ```
    Recent = Potential compromise timeframe
    ```
3.  **Filter Suspicious Executables:**

    ```powershell
    # Look for executables from suspicious paths
    # Temp directories, Downloads, Public folders
    ```
4.  **Check Run Counts:**

    ```
    Run Count = 1: Recently introduced program (possible malware)
    High Count: Frequently used (legitimate or persistent malware)
    ```

**Red Flags:**

```bash
🚩 Executables from:
   - C:\Users\*\Downloads\
   - C:\Users\*\AppData\Local\Temp\
   - C:\Users\Public\
   - External drives

🚩 Known attack tools:
   - mimikatz.exe
   - procdump.exe
   - psexec.exe
   - nc.exe (netcat)

🚩 Suspicious patterns:
   - Random executable names
   - Single-letter executables (a.exe, x.exe)
   - Missing descriptions
```

**Example Analysis:**

```bash
Decoded Entry: C:\Users\John\Downloads\updater.exe
Last Run Time: 2025-11-29 02:34:12
Run Count: 1
Focus Time: 2 seconds

Analysis:
- Run from Downloads (suspicious)
- Executed once (recently introduced)
- Very short focus time (automated/non-GUI?)
- Generic name (suspicious)
→ HIGH PRIORITY for investigation
```

**Pro Tips:**

✅ **GUI Only**: Only tracks programs with GUI (not console applications)

✅ **Persistence**: Survives file deletion

✅ **Focus Time**: Helps distinguish user interaction vs. automated execution

⚠️ **Encoding**: ROT13 is obfuscation, not encryption

***

### 📅 Windows Timeline Analysis

#### Overview

* **Feature**: Windows 10 Timeline (deprecated in late Win10/Win11)
* **Database**: SQLite (ActivitiesCache.db)
* **Location**: Per-user profile
* **Retention**: 30 days
* **Status**: Feature deprecated but database still populated

#### Key Information Available

| Data Point          | Description      | Forensic Value          |
| ------------------- | ---------------- | ----------------------- |
| **Application**     | Program executed | Activity identification |
| **Start Time**      | Activity start   | Timeline                |
| **End Time**        | Activity end     | Duration calculation    |
| **Duration**        | How long active  | Usage analysis          |
| **Files/URLs**      | Items opened     | Content accessed        |
| **Expiration Time** | Record expiry    | Data retention          |

#### Location

{% code overflow="wrap" %}
```bash
C:\Users\{Username}\AppData\Local\ConnectedDevicesPlatform\{Profile-ID}\ActivitiesCache.db

Multiple profile IDs possible (one per Microsoft account/local account)
```
{% endcode %}

#### Collection & Analysis

**Collection:**

{% code overflow="wrap" %}
```powershell
# Find and copy all Timeline databases
$User = "username"
Get-ChildItem "C:\Users\$User\AppData\Local\ConnectedDevicesPlatform\" -Recurse -Filter "ActivitiesCache.db" | 
    Copy-Item -Destination "C:\Analysis\Timeline\" -Force
```
{% endcode %}

**Using WxTCmd (Windows Timeline Parser):**

{% code overflow="wrap" %}
```powershell
# Parse Timeline database
.\WxTCmd.exe -f "C:\Users\john\AppData\Local\ConnectedDevicesPlatform\L.john\ActivitiesCache.db" --csv "C:\Analysis" --csvf timeline.csv

# Parse all for user
Get-ChildItem "C:\Users\john\AppData\Local\ConnectedDevicesPlatform\" -Recurse -Filter "ActivitiesCache.db" | 
    ForEach-Object {
        .\WxTCmd.exe -f $_.FullName --csv "C:\Analysis" --csvf "timeline_$($_.Directory.Name).csv"
    }
```
{% endcode %}

**Using DB Browser for SQLite:**

```bash
1. Download DB Browser for SQLite
2. Open Database → Select ActivitiesCache.db
3. Browse Data tab → Select tables:
   - Activity (main activity records)
   - Activity_PackageId (application info)
   - ActivityOperation (changes)
4. Execute SQL queries or export tables
```

**Useful SQL Queries:**

```sql
-- All activities in last 7 days
SELECT 
    Id,
    AppId,
    PackageIdHash,
    AppActivityId,
    ActivityType,
    datetime(StartTime, 'unixepoch') as StartTime,
    datetime(EndTime, 'unixepoch') as EndTime,
    datetime(LastModifiedTime, 'unixepoch') as LastModified,
    OriginalPayload
FROM Activity
WHERE StartTime > strftime('%s', 'now', '-7 days')
ORDER BY StartTime DESC;

-- Application usage summary
SELECT 
    AppId,
    COUNT(*) as ActivityCount,
    SUM(EndTime - StartTime) as TotalDuration
FROM Activity
GROUP BY AppId
ORDER BY ActivityCount DESC;

-- Activities with URLs/files
SELECT 
    datetime(StartTime, 'unixepoch') as StartTime,
    AppId,
    json_extract(OriginalPayload, '$.displayText') as DisplayText,
    json_extract(OriginalPayload, '$.contentUri') as ContentUri
FROM Activity
WHERE ContentUri IS NOT NULL
ORDER BY StartTime DESC;
```

#### Analysis Tips

**Investigation Workflows:**

**1. Timeline Reconstruction:**

```bash
Use Timeline to understand:
- What applications were used
- When they were used
- For how long
- What files/URLs were accessed
```

**2. Document Access Analysis:**

```sql
-- Find specific document access
SELECT 
    datetime(StartTime, 'unixepoch') as AccessTime,
    AppId,
    json_extract(OriginalPayload, '$.displayText') as FileName
FROM Activity
WHERE OriginalPayload LIKE '%confidential%'
ORDER BY StartTime DESC;
```

**3. Web Browsing History:**

```sql
-- Extract URLs visited
SELECT 
    datetime(StartTime, 'unixepoch') as VisitTime,
    json_extract(OriginalPayload, '$.contentUri') as URL,
    json_extract(OriginalPayload, '$.displayText') as PageTitle
FROM Activity
WHERE AppId LIKE '%browser%'
ORDER BY StartTime DESC;
```

**4. Application Usage Patterns:**

```
- Peak usage hours
- Weekend vs. weekday activity
- After-hours usage
- Anomalous application usage
```

**Red Flags:**

```
🚩 Off-hours activity (nights, weekends)
🚩 Access to sensitive documents
🚩 Unusual applications
🚩 High activity during account compromise window
🚩 Access to external URLs/cloud storage
```

**Pro Tips:**

✅ **JSON Payloads**: OriginalPayload column contains rich JSON data

✅ **Cross-Platform**: Can sync across devices (Microsoft account)

✅ **Persistence**: Survives after feature deprecation

⚠️ **Privacy**: Users can disable/clear timeline

***

### 📊 SRUM Analysis

#### Overview

* **Name**: System Resource Usage Monitor
* **Purpose**: Track application resource usage, network activity
* **Location**: `C:\Windows\System32\sru\SRUDB.dat`
* **Format**: ESE database
* **Retention**: 30-60 days

#### Key Information Available

| Data Point               | Description                 | Forensic Value         |
| ------------------------ | --------------------------- | ---------------------- |
| **Network Usage**        | Bytes sent/received per app | Data exfiltration      |
| **Application Resource** | CPU, memory usage           | Resource analysis      |
| **Application Timeline** | When apps ran               | Execution timeline     |
| **Network Connectivity** | Connected networks          | Connection history     |
| **Energy Usage**         | Battery/power usage         | Mobile device analysis |
| **User Activity**        | Per-user stats              | User behavior          |

#### Important Tables

```bash
{973F5D5C-1D90-4944-BE8E-24B94231A174} = Network Data Usage
{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} = Application Resource Usage  
{DD6636C4-8929-4683-974E-22C046A43763} = Network Connectivity Usage
{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477} = Energy Usage (Win8+)
{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37} = Energy Usage (Win10+)
```

#### Collection & Analysis

**Collection (Requires Both Files):**

```powershell
# Copy SRUM database
Copy-Item "C:\Windows\System32\sru\SRUDB.dat" -Destination "C:\Analysis\"

# CRITICAL: Also copy SOFTWARE hive (needed for mapping)
Copy-Item "C:\Windows\System32\config\SOFTWARE" -Destination "C:\Analysis\"
Copy-Item "C:\Windows\System32\config\SOFTWARE.LOG1" -Destination "C:\Analysis\"
Copy-Item "C:\Windows\System32\config\SOFTWARE.LOG2" -Destination "C:\Analysis\"
```

**Using SrumECmd:**

```powershell
# Parse SRUM (requires both SRUDB.dat and SOFTWARE hive in same directory)
.\SrumECmd.exe -d "C:\Analysis" --csv "C:\Analysis\SRUM_Output"

# Output files created:
# - SRUM_TEMPLATE_NETWORK_DATA_USAGE.csv
# - SRUM_TEMPLATE_APPLICATION_RESOURCE_USAGE.csv
# - SRUM_TEMPLATE_NETWORK_CONNECTIVITY.csv
# - And others...
```

**Using FTK Imager to Extract:**

```bash
1. File → Add Evidence Item → Physical Drive
2. Navigate: [Windows]\System32\sru\
3. Export: SRUDB.dat
4. Navigate: [Windows]\System32\config\
5. Export: SOFTWARE, SOFTWARE.LOG1, SOFTWARE.LOG2
```

#### Analysis Tips

**Investigation Workflows:**

**1. Network Data Usage Analysis:**

{% code overflow="wrap" %}
```powershell
# Import network usage data
$NetworkData = Import-Csv "C:\Analysis\SRUM_Output\SRUM_TEMPLATE_NETWORK_DATA_USAGE.csv"

# Find applications with high data transfer
$NetworkData | 
    Group-Object Application | 
    ForEach-Object {
        [PSCustomObject]@{
            Application = $_.Name
            TotalBytesSent = ($_.Group | Measure-Object BytesSent -Sum).Sum
            TotalBytesReceived = ($_.Group | Measure-Object BytesReceived -Sum).Sum
            TotalBytes = ($_.Group | Measure-Object BytesSent -Sum).Sum + ($_.Group | Measure-Object BytesReceived -Sum).Sum
        }
    } | Sort-Object TotalBytes -Descending | Select-Object -First 20

# Suspicious data transfer
$NetworkData | Where-Object {
    $_.BytesSent -gt 100MB  # Large uploads (potential exfil)
} | Select-Object Timestamp, Application, BytesSent, BytesReceived, User
```
{% endcode %}

**2. Application Resource Usage:**

{% code overflow="wrap" %}
```powershell
# Import resource usage
$ResourceData = Import-Csv "C:\Analysis\SRUM_Output\SRUM_TEMPLATE_APPLICATION_RESOURCE_USAGE.csv"

# Most CPU-intensive applications
$ResourceData | 
    Group-Object Application | 
    ForEach-Object {
        [PSCustomObject]@{
            Application = $_.Name
            TotalCPUTime = ($_.Group | Measure-Object ForegroundCycleTime -Sum).Sum
            ExecutionCount = $_.Count
        }
    } | Sort-Object TotalCPUTime -Descending | Select-Object -First 20
```
{% endcode %}

**3. Timeline of Network Activity:**

```powershell
# Network activity timeline
$NetworkData | 
    Select-Object Timestamp, Application, BytesSent, BytesReceived, User | 
    Sort-Object Timestamp | 
    Where-Object {[datetime]$_.Timestamp -gt (Get-Date).AddDays(-7)} |
    Export-Csv C:\Analysis\Network_Timeline.csv -NoTypeInformation
```

**4. Data Exfiltration Detection:**

```powershell
# Find unusual upload patterns
$NetworkData | 
    Where-Object {
        $BytesSent = [int64]$_.BytesSent
        $BytesReceived = [int64]$_.BytesReceived
        
        # High upload:download ratio
        $BytesSent -gt 0 -and $BytesReceived -gt 0 -and
        ($BytesSent / $BytesReceived) -gt 10
    } | Select-Object Timestamp, Application, BytesSent, BytesReceived, User |
    Export-Csv C:\Analysis\Potential_Exfiltration.csv -NoTypeInformation
```

**5. Per-User Activity:**

```powershell
# Activity by user
$NetworkData | 
    Group-Object User | 
    ForEach-Object {
        [PSCustomObject]@{
            User = $_.Name
            TotalBytes = ($_.Group | Measure-Object BytesSent,BytesReceived -Sum).Sum
            Applications = ($_.Group.Application | Select-Object -Unique).Count
        }
    } | Sort-Object TotalBytes -Descending
```

**Red Flags:**

```bash
🚩 High data transfer by suspicious applications
🚩 Upload significantly exceeds download (exfiltration)
🚩 Network activity during off-hours
🚩 Unknown/unsigned applications with network usage
🚩 PowerShell/cmd.exe with network activity
🚩 Activity during suspected compromise window
```

**Investigation Scenarios:**

**Scenario: Data Exfiltration**

```bash
1. Check Network Data Usage table
2. Identify applications with high BytesSent
3. Correlate timestamps with authentication logs
4. Check application legitimacy (Amcache, Prefetch)
5. Identify destination (if available in logs)
```

**Scenario: Resource Abuse**

```bash
1. Check Application Resource Usage
2. Identify CPU/memory intensive apps
3. Check for cryptominers, malware
4. Correlate with process execution (Event 4688)
```

**Pro Tips:**

✅ **Hourly Granularity**: Data recorded per hour

✅ **User Context**: Tracks which user ran what

✅ **Network Interfaces**: Can identify VPN, WiFi, Ethernet usage

⚠️ **SOFTWARE Hive Required**: App GUIDs mapped to names via registry

***

### 📝 MRU Analysis

#### Overview

* **MRU**: Most Recently Used
* **Purpose**: Track recent file/folder access per application
* **Location**: NTUSER.DAT (per user)
* **Retention**: Varies by MRU type (typically 10-20 items)

#### Key MRU Locations

| Registry Path                   | Description                                |
| ------------------------------- | ------------------------------------------ |
| **RecentDocs**                  | Recently opened documents (all file types) |
| **ComDlg32\LastVisitedPidlMRU** | Last folders accessed by applications      |
| **ComDlg32\OpenSavePidlMRU**    | Files accessed via Open/Save dialogs       |
| **RunMRU**                      | Commands typed in Run dialog               |
| **TypedPaths**                  | Paths typed in Explorer address bar        |
| **WordWheelQuery**              | Windows search terms                       |
| **Office MRU**                  | Recent documents per Office app            |

#### Detailed Locations

{% code overflow="wrap" %}
```bash
Recent Documents:
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

Last Visited (folders accessed by apps):
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU

Open/Save Dialog:
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

Run Commands:
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

Typed Paths:
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

Search Terms:
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```
{% endcode %}

#### Collection & Analysis

**Using Registry Explorer:**

```bash
1. Load NTUSER.DAT for target user
2. Navigate to each MRU location
3. Review entries (most recent = higher in list)
4. Export to CSV
```

**Using RegRipper:**

```powershell
# Parse all MRU entries
.\rr.exe -r "C:\Users\john\NTUSER.DAT" -p recentdocs > recentdocs.txt
.\rr.exe -r "C:\Users\john\NTUSER.DAT" -p comdlg32 > comdlg32.txt
.\rr.exe -r "C:\Users\john\NTUSER.DAT" -p runmru > runmru.txt
```

**Manual Registry Query (Live System):**

```powershell
# Recent documents
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# Run commands
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

# Typed paths
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"

# Search terms
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
```

#### Analysis Tips

**Investigation Workflows:**

**1. Recent Document Analysis:**

```bash
Check RecentDocs for:
- Recently accessed files
- File types accessed
- Deleted documents (MRU persists)
- External drive files
```

**2. Application File Access:**

```bash
Check LastVisitedPidlMRU:
- Which apps accessed which folders
- Unusual folder access
- Temporal patterns
```

**3. Command Execution History:**

```bash
Check RunMRU:
- Commands typed in Run dialog
- PowerShell launches
- Suspicious executables
- Network paths
```

**4. Search Terms:**

```bash
Check WordWheelQuery:
- What user searched for
- File names searched
- Potential indicators of compromise
```

**Red Flags:**

```bash
🚩 RunMRU entries for:
   - cmd.exe with suspicious parameters
   - powershell.exe -enc (encoded commands)
   - Network paths (\\server\share\)
   - Known attack tools

🚩 LastVisitedPidlMRU entries for:
   - Temp directories
   - Unusual system paths
   - External drives

🚩 RecentDocs entries for:
   - Suspicious file extensions (.ps1, .bat, .vbs)
   - Files from temp/downloads
   - Deleted files

🚩 WordWheelQuery entries for:
   - "password", "credential", "confidential"
   - Malware names
   - Company secrets
```

**Pro Tips:**

✅ **MRU Order**: List maintained in chronological order (most recent first)

✅ **Persistence**: Survives file/folder deletion

✅ **Per-User**: Each user has separate MRU data

⚠️ **Privacy**: Some applications clear their MRU

***

### 💻 PowerShell History

#### Overview

* **Feature**: PSReadLine console history
* **Location**: Per-user AppData
* **Format**: Plain text file
* **Retention**: Last 4,096 commands
* **Available**: PowerShell v5+ (Win10/Server 2016+)

#### Location

{% code overflow="wrap" %}
```bash
C:\Users\{Username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
{% endcode %}

#### Key Information Available

| Data Point     | Description             | Forensic Value           |
| -------------- | ----------------------- | ------------------------ |
| **Commands**   | Exact commands typed    | Attack reconstruction    |
| **Parameters** | Full command syntax     | Technique identification |
| **Order**      | Chronological sequence  | Timeline                 |
| **Scripts**    | Inline scripts executed | Malware analysis         |

#### CRITICAL Understanding

```bash
✅ Logs: PowerShell console commands
✅ Logs: Commands typed interactively
❌ Does NOT log: PowerShell ISE commands
❌ Does NOT log: Scripts executed without typing
❌ Does NOT log: If PSReadLine disabled/removed
```

#### Collection & Analysis

**Collection:**

{% code overflow="wrap" %}
```powershell
# Collect for all users
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" | 
    ForEach-Object {
        Copy-Item $_.FullName -Destination "C:\Analysis\PSHistory_$($_.Directory.Parent.Parent.Parent.Parent.Name).txt"
    }
```
{% endcode %}

**Analysis:**

{% code overflow="wrap" %}
```powershell
# Read and analyse history
$History = Get-Content "C:\Users\john\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# Count commands
$History.Count

# Find suspicious patterns
$SuspiciousKeywords = @(
    "invoke-expression", "iex", "downloadstring", "downloadfile",
    "invoke-webrequest", "invoke-restmethod", "net.webclient",
    "-enc", "-encodedcommand", "frombase64string",
    "invoke-mimikatz", "invoke-bloodhound", "invoke-kerberoast",
    "invoke-command", "enter-pssession", "new-pssession",
    "bypass", "unrestricted", "hidden", "windowstyle hidden"
)

$History | Where-Object {
    $Command = $_
    $SuspiciousKeywords | Where-Object {$Command -match $_}
} | Format-List

# Export suspicious commands
$History | Where-Object {
    $Command = $_
    $SuspiciousKeywords | Where-Object {$Command -match $_}
} | Out-File C:\Analysis\Suspicious_PS_Commands.txt
```
{% endcode %}

**Timeline Analysis:**

{% code overflow="wrap" %}
```powershell
# Commands are in chronological order
# First command = oldest
# Last command = most recent

# View last 50 commands
Get-Content ConsoleHost_history.txt | Select-Object -Last 50

# Find commands in timeframe (requires correlation with file timestamp)
$HistoryFile = Get-Item "C:\Users\john\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$LastModified = $HistoryFile.LastWriteTime
Write-Host "Last command executed: $LastModified"
```
{% endcode %}

#### Analysis Tips

**Investigation Workflows:**

**1. Command Reconstruction:**

```bash
Read history bottom-to-top for most recent activity
Build timeline of attacker actions
Understand attack progression
```

**2. Credential Access:**

```powershell
# Look for credential dumping
$History | Where-Object {
    $_ -match "mimikatz|sekurlsa|lsadump|sam|credential|password"
}
```

**3. Lateral Movement:**

```powershell
# Remote execution commands
$History | Where-Object {
    $_ -match "invoke-command|enter-pssession|new-pssession|wsman"
}
```

**4. Download Cradle:**

```powershell
# File downloads
$History | Where-Object {
    $_ -match "downloadstring|downloadfile|iex.*http|invoke-webrequest.*http"
}
```

**5. Obfuscation:**

```powershell
# Encoded/obfuscated commands
$History | Where-Object {
    $_ -match "-enc|-e |-encodedcommand|frombase64|char\[\]"
}
```

**Red Flags:**

```bash
🚩 Base64 encoded commands
🚩 Download cradles (IEX + DownloadString)
🚩 Invoke-Mimikatz or credential dumping tools
🚩 Execution policy bypass
🚩 Hidden window style
🚩 Remote session establishment
🚩 Port scanning or reconnaissance commands
🚩 Attempts to disable security features
```

**Evasion Detection:**

```powershell
# Attackers may try to:

# 1. Disable PSReadLine
$History | Where-Object {$_ -match "Set-PSReadLineOption.*SaveNothing"}

# 2. Remove PSReadLine module
$History | Where-Object {$_ -match "Remove-Module.*PSReadLine"}

# 3. Clear history file
# Check file for: Clear-Content ConsoleHost_history.txt

# 4. Modify history file
# Check file timestamps vs. last logon time
```

**Pro Tips:**

✅ **Plain Text**: Easy to read and analyze

✅ **Persistent**: Not cleared automatically

✅ **Comprehensive**: Captures full command syntax

⚠️ **Limitations**: Console only (not ISE, not script files)

⚠️ **Timestamps**: File modification time = last command time (not per-command timestamps)

***

### 🗄️ NTFS Artifacts

#### Master File Table ($MFT)

**Overview:**

* **Purpose**: Database of all files/folders on NTFS volume
* **Location**: NTFS root (hidden system file)
* **Contains**: Metadata for every file/directory

**Key Information:**

* File name
* File size
* Timestamps (MACB - Modified, Accessed, Changed, Born)
* MFT entry number
* Parent MFT entry
* Attributes (resident/non-resident data)

**Collection:**

```powershell
# Using FTK Imager (GUI)
# Navigate to root, export $MFT

# Using RawCopy (live system)
RawCopy.exe /FileNamePath:C:\$MFT /OutputPath:C:\Analysis

# Using KAPE
.\kape.exe --target MFT --tdest C:\Analysis
```

**Analysis:**

```powershell
# Using MFTECmd
.\MFTECmd.exe -f "C:\Analysis\$MFT" --csv "C:\Analysis" --csvf mft.csv

# With body file output (for timeline)
.\MFTECmd.exe -f "C:\Analysis\$MFT" --csv "C:\Analysis" --body "C:\Analysis" --bdl C
```

**Using MFTExplorer (GUI):**

```bash
1. Load $MFT file
2. Browse file system structure
3. View file metadata
4. Export to CSV
```

**Investigation Use Cases:**

```bash
✓ Timeline analysis (file creation, modification, access)
✓ Deleted file recovery (entries persist)
✓ File system structure reconstruction
✓ Anti-forensics detection (timestamp manipulation)
✓ Alternative Data Stream enumeration
```

***

#### UsnJrnl ($J)

**Overview:**

* **Purpose**: Change journal for NTFS volume
* **Location**: `NTFS\$Extend\$RmMetadata\$UsnJrnl\$J`
* **Contains**: Records of file system changes

**Key Information:**

* File name
* Reason for change (create, delete, rename, modify)
* Timestamp of change
* MFT entry and parent entry
* Change sequence number (USN)

**Collection:**

```powershell
# Using FTK Imager
# Navigate: [Root]\$Extend\$RmMetadata\$UsnJrnl:$J
# Export stream

# Using RawCopy
RawCopy.exe /FileNamePath:C:\$Extend\$UsnJrnl:$J /OutputPath:C:\Analysis

# Using KAPE
.\kape.exe --target J --tdest C:\Analysis
```

**Analysis:**

```powershell
# Using MFTECmd (can parse $J)
.\MFTECmd.exe -f "C:\Analysis\$J" --csv "C:\Analysis" --csvf usnjrnl.csv
```

**Investigation Use Cases:**

```bash
✓ Detect file deletion
✓ Track file rename operations
✓ Identify attacker cleanup activities
✓ Detect file encryption (ransomware)
✓ Timeline reconstruction
```

**Red Flags:**

```bash
🚩 Mass file renaming (ransomware)
🚩 Large-scale deletions
🚩 File system tunneling (timestamp manipulation)
🚩 Cleanup activities post-compromise
```

***

#### $LogFile

**Overview:**

* **Purpose**: Transaction log for NTFS metadata operations
* **Location**: NTFS root
* **Contains**: Redo/undo information for transactions

**Key Information:**

* File operations (create, delete, rename, modify)
* Timestamps
* MFT entry references
* Operation details

**Collection:**

```powershell
# Using FTK Imager
# Navigate to root, export $LogFile

# Using RawCopy
RawCopy.exe /FileNamePath:C:\$LogFile /OutputPath:C:\Analysis
```

**Analysis:**

```powershell
# Using NTFS_Log_Tracker
.\NTFS_Log_Tracker.exe -f "C:\Analysis\$LogFile" -o "C:\Analysis\logfile_output.csv"

# Using LogFileParser
.\LogFileParser.exe -f "C:\Analysis\$LogFile" > logfile_parsed.txt
```

**Investigation Use Cases:**

```bash
✓ Recent file operations
✓ Deleted file evidence
✓ File rename detection
✓ Anti-forensics detection
```

***

#### Alternate Data Streams (ADS)

**Overview:**

* **Purpose**: Store multiple data streams in single file
* **Feature**: Hidden from normal directory listings
* **Risk**: Can hide malware

**Common ADS:**

```bash
Zone.Identifier - Marks files downloaded from Internet
  - Zone 0: Local machine
  - Zone 1: Local intranet
  - Zone 2: Trusted sites
  - Zone 3: Internet
  - Zone 4: Restricted sites
```

**Detection:**

```powershell
# PowerShell - list ADS
Get-Item C:\suspect.txt -Stream *

# Specific file
Get-Content C:\suspect.txt -Stream Hidden

# Recursively scan directory
Get-ChildItem C:\Temp -Recurse | ForEach-Object {
    Get-Item $_.FullName -Stream * | 
        Where-Object {$_.Stream -ne ':$DATA'} |
        Select-Object @{N='File';E={$_.FileName}}, Stream, Length
}

# Using dir command
dir /R C:\Temp

# Using Streams.exe (Sysinternals)
.\streams.exe -s C:\Temp

# Using AlternateStreamView (NirSoft)
AlternateStreamView.exe /scomma C:\Analysis\ads.csv
```

**Analysis:**

```powershell
# Find files with suspicious ADS
Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $Streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
        $Streams | Where-Object {
            $_.Stream -notin @(':$DATA', 'Zone.Identifier') -and $_.Length -gt 0
        } | ForEach-Object {
            [PSCustomObject]@{
                File = $_.FileName
                Stream = $_.Stream
                Size = $_.Length
            }
        }
    }
```

**Red Flags:**

```bash
🚩 Executables hidden in ADS
🚩 Large ADS attached to innocuous files
🚩 Scripts in ADS
🚩 Data exfiltrated via ADS
```

**Execution from ADS:**

```powershell
# Attackers can execute from ADS:
wscript C:\innocuous.txt:malicious.vbs
powershell Get-Content C:\file.txt -Stream evil.ps1 | iex

# Detection in Event Logs:
# Process creation (4688) may show stream execution
```

***

### 📚 Investigation Playbooks

#### Playbook 1: Malware Execution Investigation

**Objective**: Confirm malware execution and build timeline

**Phase 1: Initial Identification (15 min)**

```bash
□ Identify suspected malware name/path from alert
□ Check if process still running (Get-Process)
□ Document MD5/SHA1/SHA256 hash
□ Check VirusTotal/threat intelligence
```

**Phase 2: Execution Proof (30 min)**

```bash
□ Check Prefetch for executable
  - Confirm execution
  - Get run count
  - Get last 8 execution times
  
□ Check BAM/DAM
  - Confirm last execution time
  - Identify user (SID)
  
□ Check Amcache
  - Get SHA1 hash
  - Get file metadata
  - Check digital signature
  
□ Check ShimCache
  - Confirm file presence
  - Get file modification time
```

**Phase 3: User Activity (30 min)**

```bash
□ Check UserAssist
  - Confirm GUI execution
  - Get run count
  - Get focus time
  
□ Check Jump Lists
  - Files accessed by malware
  - Network locations accessed
  
□ Check PowerShell history
  - Commands executed
  - Download cradles
  - Obfuscation
```

**Phase 4: Timeline Construction (45 min)**

```bash
□ Compile timeline using:
  - Prefetch last 8 times
  - BAM/DAM timestamp
  - Timeline database
  - Event logs (4688, 4624)
  - MFT timestamps
  
□ Identify:
  - First execution time
  - Last execution time
  - Frequency of execution
  - User context
```

**Phase 5: Persistence Check (30 min)**

```bash
□ Check registry Run keys
□ Check services (7045, 4697)
□ Check scheduled tasks (4698, 106)
□ Check WMI event consumers (5861)
□ Check startup folders
```

**Phase 6: Impact Assessment (45 min)**

```bash
□ Check SRUM for network activity
  - Data exfiltration
  - Command & control
  
□ Check Jump Lists for file access
  - Sensitive documents
  - Lateral movement
  
□ Check $J for file modifications
  - Encryption (ransomware)
  - Deletion
  
□ Check ADS for hidden files
```

**Phase 7: Reporting (30 min)**

```bash
□ Document execution proof
□ Create timeline
□ Extract IOCs (hashes, paths, registry keys)
□ Assess scope
□ Recommend remediation
```

***

#### Playbook 2: Data Exfiltration Investigation

**Objective**: Detect and quantify data exfiltration

**Phase 1: Indicators (15 min)**

```bash
□ Review alert/indicator
□ Identify suspected timeframe
□ Identify affected user
□ Check for large file transfers (logs)
```

**Phase 2: Network Activity Analysis (45 min)**

```bash
□ Check SRUM Network Data Usage
  - Applications with high BytesSent
  - Upload vs. download ratio
  - External destinations
  - Timeframe correlation
  
□ Check Timeline
  - Cloud storage activity
  - USB drive usage
  - Network share access
```

**Phase 3: File Access Analysis (45 min)**

```bash
□ Check Jump Lists
  - Recently accessed files
  - External drive paths
  - Network share paths
  - Volume serial numbers
  
□ Check MRU (RecentDocs)
  - Document types accessed
  - Sensitive file access
  
□ Check Office MRU
  - Specific documents opened
```

**Phase 4: USB/External Media (30 min)**

```bash
□ Check Jump Lists for drive letters (E:, F:, etc.)
□ Check MFT for external volume GUIDs
□ Check Event Logs for USB insertion
□ Check volume serial numbers
```

**Phase 5: Staging Detection (30 min)**

```bash
□ Check for staging directories
  - C:\Users\Public\
  - C:\Windows\Temp\
  - User temp folders
  
□ Check $J for mass file copies
□ Check Timeline for file access patterns
```

**Phase 6: Cloud/Email Exfil (30 min)**

```bash
□ Check SRUM for browser activity
□ Check Jump Lists for cloud storage
□ Check browser history (if available)
□ Check email client activity
```

**Phase 7: Quantification (30 min)**

```bash
□ Calculate total data sent (SRUM)
□ Identify files accessed (Jump Lists, MRU)
□ Estimate data volume
□ Identify external destinations
```

***

#### Playbook 3: Attacker Tool Usage

**Objective**: Identify what tools attacker used

**Phase 1: Known Tool Detection (30 min)**

```bash
□ Check Prefetch for known tools:
  - PSEXEC.EXE
  - MIMIKATZ.EXE
  - PROCDUMP.EXE
  - PWDUMP.EXE
  - NC.EXE (NetCat)
  - NMAP.EXE
  
□ Check Amcache for SHA1 hashes
  - Match against known tool hashes
  
□ Check ShimCache for tool paths
```

**Phase 2: PowerShell Analysis (45 min)**

```bash
□ Check ConsoleHost_history.txt
  - Credential dumping commands
  - Lateral movement commands
  - Download cradles
  - Encoded commands
  
□ Check Event ID 4104 (script blocks)
  - Invoke-Mimikatz
  - Invoke-BloodHound
  - Invoke-Kerberoast
```

**Phase 3: Execution Context (30 min)**

```bash
□ Check UserAssist
  - GUI tools executed
  
□ Check BAM/DAM
  - Recent tool execution
  
□ Check Timeline
  - Tool usage patterns
```

**Phase 4: Tool Downloaded (30 min)**

```bash
□ Check Jump Lists for Downloads folder
□ Check browser downloads (if available)
□ Check ADS Zone.Identifier
□ Check PowerShell download commands
```

**Phase 5: Tool Persistence (30 min)**

```bash
□ Check if tools installed as services
□ Check scheduled tasks
□ Check registry Run keys
□ Check startup folders
```

***

### 🛠️ Tool Reference

#### Eric Zimmerman Tools

**Download**: https://ericzimmerman.github.io/

```bash
PECmd.exe - Prefetch parser
AppCompatCacheParser.exe - ShimCache parser
AmcacheParser.exe - Amcache parser
JLECmd.exe - Jump List parser
MFTECmd.exe - MFT/$J parser
RegistryExplorer.exe - Registry viewer/parser
SrumECmd.exe - SRUM parser
WxTCmd.exe - Windows Timeline parser
RECmd.exe - Registry command line tool
```

**Installation:**

```powershell
# Download ZIP from GitHub releases
# Extract to C:\Tools\ZimmermanTools\
# Add to PATH
```

***

#### NirSoft Tools

**Download**: https://www.nirsoft.net/

```bash
WinPrefetchView.exe - Prefetch viewer
AlternateStreamView.exe - ADS scanner
```

***

#### Sysinternals Tools

**Download**: https://live.sysinternals.com/

```bash
streams.exe - ADS detection
strings.exe - String extraction
```

***

#### KAPE

**Download**: https://www.kroll.com/kape

{% code overflow="wrap" %}
```powershell
# Collect all program execution artifacts
.\kape.exe --target ProgramExecution --tdest C:\Collection

# Specific artifacts
.\kape.exe --target Prefetch,Amcache,JumpLists --tdest C:\Collection

# With processing
.\kape.exe --target ProgramExecution --tdest C:\Collection --module PECmd,AmcacheParser --mdest C:\Analysis
```
{% endcode %}

***

#### FTK Imager

**Download**: https://www.exterro.com/ftk-imager

**Use for:**

* Collecting locked files (SRUM, Amcache)
* Extracting $MFT, $J, $LogFile
* Forensic image mounting

***

#### DB Browser for SQLite

**Download**: https://sqlitebrowser.org/

**Use for:**

* Windows Timeline analysis
* Other SQLite databases

***

### 🎓 Quick Reference Cards

#### Artifact Comparison Matrix

| Artifact       | Proves Execution | Last Run Time | Run Count | Historical Times   | File Hash | Retention     |
| -------------- | ---------------- | ------------- | --------- | ------------------ | --------- | ------------- |
| **Prefetch**   | ✅ Yes            | ✅ Yes         | ✅ Yes     | ✅ 8 times (Win10+) | ❌ No      | 1,024 files   |
| **BAM/DAM**    | ⚠️ Likely        | ✅ Yes         | ❌ No      | ❌ No               | ❌ No      | \~7 days      |
| **ShimCache**  | ❌ No (Win10+)    | ❌ No          | ❌ No      | ❌ No               | ❌ No      | 1,024 entries |
| **Amcache**    | ⚠️ Presence      | ⚠️ Modified   | ❌ No      | ❌ No               | ✅ SHA1    | Long-term     |
| **UserAssist** | ✅ GUI only       | ✅ Yes         | ✅ Yes     | ❌ No               | ❌ No      | Persistent    |
| **Jump Lists** | ⚠️ Indirect      | ✅ Yes         | ❌ No      | ❌ No               | ❌ No      | \~2,000/app   |
| **Timeline**   | ⚠️ Activity      | ✅ Yes         | ❌ No      | ✅ Yes              | ❌ No      | 30 days       |
| **SRUM**       | ⚠️ Resource      | ✅ Yes         | ❌ No      | ✅ Hourly           | ❌ No      | 30-60 days    |

***

#### Collection Priority Checklist

**Live System - First 15 Minutes:**

```bash
□ Prefetch directory (FIRST - tools create prefetch!)
□ BAM/DAM registry export
□ PowerShell console history
□ Running process list
□ Network connections
```

**Live System - Next 30 Minutes:**

```bash
□ SYSTEM registry hive (ShimCache)
□ SOFTWARE registry hive (SRUM mapping)
□ Amcache.hve
□ SRUDB.dat
□ User NTUSER.DAT files
```

**Live System - Next 30 Minutes:**

```bash
□ Jump Lists (all users)
□ Timeline databases (all users)
□ MRU registry keys
□ Event logs
```

**Forensic Image - Priority Order:**

```bash
1. $MFT (timeline, file listing)
2. Prefetch
3. Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT)
4. Amcache
5. SRUM
6. Jump Lists
7. Timeline
8. $J (change journal)
9. $LogFile
10. ADS enumeration
```

***

_Use this guide as your go-to reference for program execution investigations. Combine multiple artifacts for the strongest evidence._
