---
description: 'Target Audience: DFIR Analysts (Junior to Advanced)'
---

# Windows DFIR Artifact Analysis Guide

**Author:** DFIR Community\
**Target Audience:** Junior to Advanced DFIR Analysts\
**Scope:** Windows 7/8/10/11 | Server 2012-2022

***

### Table of Contents

1. [Document Overview](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#document-overview)
2. [Execution Evidence Hierarchy](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#execution-evidence-hierarchy)
3. [Core Artifacts](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#core-artifacts)
   * [Prefetch](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#1-prefetch)
   * [Amcache](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#2-amcache)
   * [ShimCache](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#3-shimcache)
   * [BAM/DAM](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#4-bamdam)
   * [ShellBags](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#5-shellbags)
   * [Jump Lists](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#6-jump-lists)
   * [Recycle Bin](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#7-recycle-bin)
   * [Master File Table (MFT)](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#8-master-file-table-mft)
   * [USN Journal](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#9-usn-journal-j)
   * [LNK Files](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#10-lnk-files-shortcut-files)
   * [UserAssist](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#11-userassist)
   * [Recent/MRU](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#12-recent-mru)
   * [AutoStart Extension Points (ASEP)](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#13-autostart-extension-points-asep)
   * [Alternate Data Streams](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#14-alternate-data-streams-ads)
   * [LogFile](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#15-logfile)
4. [Artifact Correlation Framework](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#artifact-correlation-framework)
5. [Investigation Workflows](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#investigation-workflows)
6. [Anti-Forensics Detection](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#anti-forensics-detection)
7. [Troubleshooting Guide](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#troubleshooting-guide)
8. [Case Studies](https://claude.ai/chat/9edaf1b8-5725-43aa-9c79-5b0231800090#case-studies)

***

### Document Overview

This guide provides comprehensive coverage of Windows forensic artifacts for digital forensics and incident response investigations. It includes artifact descriptions, collection methods, analysis techniques, correlation strategies, and real-world case studies.

#### How to Use This Guide

**Quick Reference Mode:**

* Jump directly to specific artifacts for locations and tools
* Use tool command examples for immediate analysis

**Investigation Mode:**

* Follow correlation frameworks for comprehensive analysis
* Use investigation workflows for common scenarios
* Apply anti-forensics detection techniques

**Learning Mode:**

* Read case studies for real-world context
* Study artifact relationships and correlation
* Practice with troubleshooting scenarios

#### Key Improvements in Version 2.0

* ✅ Added BAM/DAM (critical Win10/11 execution artifact)
* ✅ Artifact correlation matrix and frameworks
* ✅ Investigation workflows for common scenarios
* ✅ Anti-forensics detection techniques
* ✅ Troubleshooting section for tool issues
* ✅ Real-world case studies with timelines
* ✅ Windows version-specific behaviors
* ✅ Cross-artifact verification methods

***

### Execution Evidence Hierarchy

#### Reliability Matrix

Understanding which artifacts prove execution vs. mere presence is critical for accurate analysis.

| Artifact       | Execution Proof                          | Win Version         | Reliability | Notes                                     |
| -------------- | ---------------------------------------- | ------------------- | ----------- | ----------------------------------------- |
| **Prefetch**   | ✅ Yes                                    | 7-11 (Workstations) | High\*      | \*Creation ≠ success; disabled on servers |
| **BAM/DAM**    | ✅ Yes                                    | 10-11 (1709+)       | Very High   | Most reliable on modern Windows           |
| **UserAssist** | ✅ Yes                                    | 7-11                | High        | GUI applications only                     |
| **Jump Lists** | ✅ Yes                                    | 7-11                | High        | User interaction required                 |
| **Amcache**    | ❌ Presence Only                          | 7-11                | Medium      | Valuable for SHA1 hashes                  |
| **ShimCache**  | <p>❌ Win7-8: Maybe<br>❌ Win10-11: No</p> | 7-11                | Low-Medium  | Presence indicator only (Win10+)          |
| **Event Logs** | ✅ Yes                                    | All                 | High        | EID 4688 with command line                |
| **Sysmon**     | ✅ Yes                                    | All (if installed)  | Very High   | EID 1 (process creation)                  |

#### Critical Understanding

**Proof of Execution:**

* Prefetch + BAM/DAM = strongest evidence
* UserAssist (GUI apps) + Jump Lists = user interaction proof
* Event Logs (4688) = execution with user context
* Sysmon (EID 1) = detailed execution with hashes

**Presence Only (NOT Execution):**

* ShimCache (Win10/11) = file existed on system
* Amcache = file installed/discovered
* MFT = file existed at some point

**Investigation Strategy:** Always correlate multiple artifacts. Single artifact = weak evidence. Multiple artifacts = strong timeline.

***

## Core Artifacts

### 1. Prefetch

#### **Overview**

**Description:** Performance optimization mechanism that provides strong evidence of application execution on Windows workstations.

**Key Facts:**

* NOT enabled by default on Windows Servers
* Windows 10/11: Compressed format, stores last 8 execution times
* Maximum 1,024 files (Win8+)
* Files created \~10 seconds after execution begins
* Hash calculated from executable path and sometimes command-line arguments

**Location**

```
Primary: C:\Windows\Prefetch
Format: (EXENAME)-(8-CHAR-HASH).pf

Registry Status Check:
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
EnablePrefetcher Values:
- 0 = Disabled
- 1 = Application Prefetching Enabled
- 2 = Boot Prefetching Enabled  
- 3 = Both Enabled (default on workstations)
```

**Available Metadata**

```
```

**Tools for Analysis**

**PECmd (Eric Zimmerman) - Recommended:**

powershell

````powershell
# Single file analysis
PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf

# Single file with CSV output
PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf --csv "G:\Output" --csvf cmd_analysis.csv

# Directory analysis
PECmd.exe -d "C:\Windows\Prefetch"

# Directory with CSV output and quiet mode
PECmd.exe -d C:\Windows\Prefetch -q --csv G:\Output --csvf prefetch.csv

# Include Volume Shadow Copies with high-precision timestamps
PECmd.exe -d C:\Windows\Prefetch -q --csv G:\Output --csvf prefetch.csv --vss --mp

# Highlight suspicious keywords (red text output)
PECmd.exe -d C:\Windows\Prefetch -q --csv G:\Output --csvf prefetch.csv -k "temp,download,appdata,recycle"

# VSS-only processing
PECmd.exe -d C:\Windows\Prefetch --vss --csv G:\Output --csvf prefetch_vss.csv
```

**Alternative Tools:**
- WinPrefetchView.exe (NirSoft) - GUI tool for quick viewing
- FTK Imager - For extraction

#### Interpretation Guide

**Timestamps:**

| Source | Meaning | Accuracy |
|--------|---------|----------|
| .pf file creation | First execution | ±10 seconds |
| .pf file modification | Last execution | ±10 seconds |
| Embedded last run | Last execution | Precise |
| Embedded previous runs | Historical executions | Precise (up to 7) |

**Multiple Prefetch Files (Same Executable):**
```
Example:
CMD.EXE-8E75B5BB.pf
CMD.EXE-A4D6D9A0.pf

Interpretation: cmd.exe executed from DIFFERENT locations

Normal:     C:\Windows\System32\cmd.exe → CMD.EXE-8E75B5BB.pf
Suspicious: C:\Users\Bob\Downloads\cmd.exe → CMD.EXE-A4D6D9A0.pf
```

**Exceptions (Normal Multiple Files):**
These Windows hosting applications legitimately have multiple prefetch files:
- svchost.exe (different services)
- dllhost.exe (different COM objects)
- backgroundtaskhost.exe (different background tasks)
- rundll32.exe (different DLLs and entry points)

Hash includes command-line arguments, creating unique files for each variant.

#### Investigator Notes

**⚠️ Critical Reminders:**

1. **Collection Priority:** 
   - Prefetch should be collected FIRST in live response
   - Running forensic tools creates NEW prefetch files
   - 1,024-file limit means oldest files get deleted
   - Prioritize collection to preserve evidence

2. **Creation ≠ Successful Execution:**
   - Prefetch file created even if program crashes immediately
   - Verify execution success with:
     - Event logs (application errors)
     - Other execution artifacts
     - Expected output/results

3. **Server Considerations:**
   - Prefetch DISABLED by default on Windows Servers
   - Must check registry to confirm status
   - If disabled, rely on other artifacts (ShimCache, BAM/DAM, Event Logs)

#### Suspicious Patterns to Investigate

**File Names:**
```
High-Value Indicators:
- psexec.exe, psexesvc.exe (lateral movement)
- mimikatz.exe, pwdump.exe (credential theft)
- procdump.exe (memory dumping)
- tcpdump.exe, wireshark.exe (network sniffing)
- nc.exe, netcat.exe (backdoors)
- 7z.exe, winrar.exe (data staging)

Red Flags:
- Single/two-letter names: a.exe, x.exe, 1.exe
- Misspelled system tools: scvhost.exe, lsass.exe
- Common names in wrong locations
```

**Execution Paths:**
```
Suspicious Locations:
- C:\Users\*\Downloads\
- C:\Users\*\AppData\Local\Temp\
- C:\Windows\Temp\
- C:\$Recycle.Bin\
- C:\PerfLogs\
- C:\Intel\ (on non-Intel systems)
- System Volume Information\
- C:\Users\Public\
```

**Timing Patterns:**
```
After-Hours Execution:
- Late night (10 PM - 6 AM)
- Weekends
- Holidays

Context matters:
- IT Admin: May be legitimate
- Regular user: Highly suspicious
```

#### Anti-Forensics Detection

**Technique 1: Prefetch Deletion**
```
Detection:
- Empty or suspiciously small Prefetch folder on active system
- Check registry: EnablePrefetcher value changed to 0
- VSS analysis: Previous prefetch files exist
- Prefetch for deletion tools: CCleaner, BleachBit

Recovery:
- Volume Shadow Copies
- Carve deleted .pf files from unallocated space
- Check ShimCache, Amcache for corroboration
```

**Technique 2: Timestomping**
```
Detection:
- Compare .pf file timestamps with embedded execution times
- Discrepancies indicate manipulation
- Cross-reference with:
  * BAM/DAM execution times
  * Event logs (EID 4688)
  * Amcache compilation times

Example:
.pf Creation: 2020-01-01 00:00:00 (suspicious - too old/round)
Embedded Last Run: 2024-03-15 14:32:45 (actual)
→ File system timestamp modified, embedded data reliable
```

#### Correlation Strategy

**Prefetch Tells You:**
- ✅ Program executed (high confidence)
- ✅ Execution count
- ✅ Last 8 execution times (Win10/11)
- ✅ Files/DLLs accessed (behavior)
- ✅ Execution path

**Verify With:**
- **BAM/DAM:** Exact timestamp, user SID
- **Event Logs:** User context, parent process
- **Amcache:** SHA1 hash, publisher verification
- **Sysmon:** Network connections, loaded modules

**Example Correlation:**
```
Prefetch: MALWARE.EXE-A1B2C3D4.pf
- Run Count: 3
- Last Run: 2024-03-15 14:30:22
- Path: C:\Users\Bob\Downloads\malware.exe

Cross-Check:
✓ BAM/DAM: Confirms 14:30:22, User SID = Bob
✓ Amcache: SHA1 = known malware (VirusTotal)
✓ Event 4688: Process created at 14:30:22 by Bob
✓ Sysmon EID 1: Network connection to C2 server

Conclusion: Strong execution evidence, malware confirmed
```

#### Forensic Value Summary

**Strengths:**
- ✅ Reliable execution proof (workstations)
- ✅ Run count tracking
- ✅ Last 8 execution times (Win10/11)
- ✅ Behavioral analysis (files accessed)
- ✅ Historical timeline

**Limitations:**
- ❌ Disabled on servers by default
- ❌ Creation doesn't guarantee successful execution
- ❌ No user attribution (use BAM/DAM)
- ❌ Limited to 1,024 entries
- ❌ Can be cleared by attacker/tools

**Best Used For:**
- Proving application execution on workstations
- Building execution timelines
- Identifying program behavior
- Detecting unusual execution locations
- Frequency analysis (run counts)

---

### 2. Amcache

#### Overview

**Description:** Registry hive that tracks application execution, driver loading, and program installation. Unique among artifacts for storing **SHA1 hashes** of executables and drivers.

**Key Facts:**
- Execution evidence is WEAK (presence indicator)
- SHA1 hashes enable malware identification
- Tracks full path, file size, publisher metadata, compilation time
- Automatically populated during installation and execution
- More reliable for "file existed" than "file executed"

#### Location
```
Primary: C:\Windows\AppCompat\Programs\Amcache.hve

Associated Files:
- Amcache.hve (main hive)
- Amcache.hve.LOG1 (transaction log)
- Amcache.hve.LOG2 (transaction log)

Extract all three files together for complete analysis
```

#### Registry Structure
```
Root
├── File (Win7/8)
│   └── {Volume GUID}
│       └── File entries
├── DriverPackages
├── DeviceContainers  
├── InventoryApplication (Win10+)
├── InventoryApplicationFile (Win10+)
└── InventoryDriverBinary (Win10+)

Windows 10/11: More structured data in Inventory* keys
Windows 7/8: Less structured data in File key
````

**Available Metadata**

```
```

**Tools for Analysis**

**AmcacheParser (Eric Zimmerman) - Recommended:**

powershell

````powershell
# Basic parsing
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "G:\Output"

# Include additional data (-i flag)
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" -i --csv "G:\Output"

# Blacklist filtering (flag known malware hashes)
AmcacheParser.exe -f Amcache.hve -b "G:\IOCs\malware_sha1.txt" --csv "G:\Output"

# Whitelist filtering (exclude known-good Microsoft files)
AmcacheParser.exe -f Amcache.hve -w "G:\Baselines\microsoft_whitelist.txt" --csv "G:\Output"

# Live system analysis
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" -i --csv "C:\Cases\Output"
```

**Registry Explorer (Eric Zimmerman) - GUI:**
```
1. Run as Administrator
2. File > Load Hive > Select Amcache.hve
3. Navigate keys:
   - InventoryApplicationFile (Win10+)
   - Root\File\{Volume GUID} (Win7/8)
4. Right-click entries > Export for detailed view
```

**Extraction with FTK Imager:**
```
1. File > Add Evidence Item > Physical Drive
2. Select target drive > Finish
3. Navigate: [OS Partition] > Windows > AppCompat > Programs
4. Select ALL THREE files:
   - Amcache.hve
   - Amcache.hve.LOG1
   - Amcache.hve.LOG2
5. Right-click > Export Files
```

#### Interpretation Guide

**SHA1 Hash - The Key Feature:**
```
Example Entry:
Path: C:\Users\Bob\Downloads\update.exe
SHA1: 3395856ce81f2b7382dee72602f798b642f14140
Size: 847,360 bytes
Publisher: "Microsoft Corporation"
Compilation: 2024-03-14 10:22:33

Investigation Steps:
1. Extract SHA1 hash
2. Query VirusTotal API
3. Check threat intelligence feeds
4. Search internal IOC database

Results:
✓ VirusTotal: 45/70 detections → Confirmed malware
✓ File deleted from system but SHA1 proves it existed
✓ Publisher "Microsoft" is SPOOFED
```

**⚠️ Critical: Presence vs. Execution**

Amcache entries can be created by:
- Application installation (Setup.exe, MSI)
- Windows automatic file discovery/indexing
- Windows Defender scanning
- Opening certain file types
- First-time execution

**DO NOT use Amcache alone to prove execution**

#### Investigator Notes

**Fake Publisher Detection:**
```
Red Flags:
✗ Publisher: "Microsoft Corporation" but file in Downloads
✗ Publisher: "Adobe Systems" but unsigned executable
✗ Compilation time in future
✗ Compilation time = 1970-01-01 (Unix epoch - modified)
✗ Mismatched version strings
✗ No digital signature despite claiming major vendor

Verification:
1. Check digital signature validity
2. Compare compilation time with file modification
3. Verify publisher certificate chain
4. Cross-reference with known-good samples
```

**Compilation Time Analysis:**
```
Suspicious Patterns:
❌ Future timestamps
❌ Epoch timestamps (1970-01-01, 1601-01-01)
❌ Compilation >> File modification (impossible)
❌ All zeros (0000-00-00)

Example:
File Modified: 2024-03-15 14:30:00
Compilation: 2023-01-15 08:22:13
Analysis: Normal - compiled before deployment

File Modified: 2024-03-15 14:30:00
Compilation: 2025-06-30 00:00:00
Analysis: Suspicious - future compilation impossible
```

**High-Value Investigation Paths:**
```
Priority Locations:
C:\Users\*\Downloads\*.exe
C:\Users\*\AppData\Local\Temp\*.exe
C:\Windows\Temp\*.exe
C:\$Recycle.Bin\*\*.exe
C:\ProgramData\*\*.exe
C:\Users\Public\*.exe

Priority File Types:
- Unsigned executables
- Executables with no publisher
- Executables claiming major vendor but in temp folders
- Recently compiled files (compilation time within days)
```

#### Anti-Forensics Detection

**Technique: Amcache Deletion**
```
Detection:
- Amcache.hve file missing or empty
- Recent creation timestamp (system reinstalled behavior)
- VSS contains older, populated Amcache

Recovery:
1. Check Volume Shadow Copies
2. Extract historical Amcache.hve
3. Parse with AmcacheParser
4. Compare current vs. historical entries
5. Identify deleted/missing entries
```

**Technique: PE Header Manipulation**
```
Detection:
- Compilation time modified in PE header
- Amcache records the MODIFIED compilation time
- Cannot detect this from Amcache alone

Mitigation:
- Cross-reference with other artifacts:
  * Prefetch (execution time)
  * Event Logs (process creation time)
  * MFT (file creation time)
  * USN Journal (file operations timeline)
```

#### Correlation Strategy

**Amcache Tells You:**
- ✅ File existed on system
- ✅ SHA1 hash (malware identification)
- ✅ Publisher/version metadata
- ✅ Compilation time
- ✅ File size and path

**Verify With:**
- **Prefetch:** Prove actual execution, get run count
- **BAM/DAM:** Get precise execution timestamp
- **ShimCache:** Confirm file presence, modification time
- **Event Logs:** User context, process creation
- **VirusTotal:** Malware identification via SHA1

**Example Correlation:**
```
Scenario: Unknown executable found

Amcache Entry:
Path: C:\Windows\Temp\svchost.exe
SHA1: a3f4e2d1c5b8a9f6e3d2c1b0a9f8e7d6c5b4a3f2
Publisher: "" (empty)
Compilation: 2024-03-15 08:23:45
Size: 425,984 bytes

Analysis Steps:
1. SHA1 → VirusTotal: Known ransomware variant
2. Path analysis: Windows\Temp (suspicious for svchost.exe)
3. Publisher empty: No digital signature (red flag)
4. Check Prefetch: SVCHOST.EXE-A1B2C3D4.pf
   - Run count: 1
   - Execution: 2024-03-15 08:24:00
   - Files accessed: Multiple network DLLs
5. Check Event 4688: Process created by user "victim"
6. Check network logs: Connections to C2 server

Conclusion:
- Malware confirmed (SHA1 match)
- Executed once (Prefetch)
- Impersonating system process (svchost in wrong location)
- Active at time of encryption
```

#### Forensic Value Summary

**Strengths:**
- ✅ SHA1 hashes (unique identification)
- ✅ Publisher/version metadata
- ✅ Compilation time analysis
- ✅ Survives file deletion
- ✅ Tracks drivers (rootkit detection)

**Limitations:**
- ❌ NOT proof of execution
- ❌ No execution timestamp (unreliable)
- ❌ No run count
- ❌ No user attribution
- ❌ Entries may be from scanning/indexing

**Best Used For:**
- Malware identification via SHA1
- Verifying file presence on system
- Publisher/signature verification
- Compilation time analysis
- Correlation with execution artifacts

---

### 3. ShimCache (Application Compatibility Cache)

#### Overview

**Description:** Windows compatibility tracking system that records executables checked for compatibility shimming. **On Windows 10/11, this is a PRESENCE indicator only, NOT proof of execution.**

**⚠️ Critical Distinction:**
- **Windows 7/8:** May indicate execution (execution flag present but unreliable)
- **Windows 10/11:** Presence only (no execution flag)

**Key Facts:**
- Serialized to registry on system shutdown/restart
- Maintained in kernel memory during operation
- Up to 1,024 entries (Win7+)
- Most recent entries at top of cache
- Executables added even if shimming not needed

#### Location
```
File Source:
C:\Windows\System32\config\SYSTEM

Registry (Live):
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache

Determining Current ControlSet:
HKLM\SYSTEM\Select\Current
Value indicates which ControlSet is active (usually ControlSet001)
````

**Available Metadata**

```
```

**Tools for Analysis**

**AppCompatCacheParser (Eric Zimmerman) - Recommended:**

powershell

````powershell
# Parse from extracted SYSTEM hive
AppCompatCacheParser.exe -f "D:\Evidence\SYSTEM" --csv "G:\Output" --csvf shimcache.csv

# Parse from live system (requires admin)
AppCompatCacheParser.exe --csv "C:\Cases\Output" --csvf shimcache_live.csv

# Quiet mode (suppress informational messages)
AppCompatCacheParser.exe -f "SYSTEM" --csv "G:\Output" --csvf shimcache.csv -q

# Include all ControlSets
AppCompatCacheParser.exe -f "SYSTEM" --csv "G:\Output" -c
```

**Alternative Tools:**
- ShimCacheParser.py (Mandiant) - Python-based parser
- Registry Explorer - Manual hive inspection

**Extraction with FTK Imager:**
```
Live System:
1. File > Obtain Protected Files
2. Select source drive
3. Choose destination folder
4. SYSTEM hive will be copied

Forensic Image:
1. Navigate to: [OS Partition]\Windows\System32\config\
2. Export file: SYSTEM
```

#### Interpretation Guide

**Entry Order:**
```
Most Recent → Entry 0
             Entry 1
             Entry 2
             ...
Oldest    → Entry 1023

Order reflects file system checks, NOT necessarily execution
New entries added on:
- File execution
- Windows Explorer browsing
- File property viewing
- Windows Defender scanning
- Application installation
```

**Timestamps:**
```
ShimCache records: Last MODIFICATION time of executable
Does NOT record: When file was accessed/executed by ShimCache

Example:
Entry: C:\Users\Bob\Downloads\malware.exe
Modified: 2024-03-10 14:30:00

This means:
✓ File was last modified on March 10
✗ Does NOT mean file was executed on March 10
✗ Does NOT mean file was added to cache on March 10
```

**Windows 10/11 Behavior:**
```
CRITICAL: No execution flag in Win10/11

Files added to cache by:
✓ Browsing folder in Windows Explorer
✓ Viewing file properties
✓ Antivirus scanning
✓ Windows Search indexing
✓ Application execution (but can't prove it)

Cannot Distinguish:
❌ Executed vs. merely present
❌ User interaction vs. system scanning
❌ Actual use vs. background discovery
```

#### Investigator Notes

**Best Use Cases:**
```
1. Proof of File Existence
   "This malware.exe file WAS on the system at some point"
   
2. Timeline Reconstruction
   Last modification time provides context
   
3. Deleted File Discovery
   File removed but ShimCache entry persists
   
4. Correlation with Other Artifacts
   Cross-reference with Prefetch for execution proof
```

**Reliability by Windows Version:**

| Version | Execution Evidence | Recommended Use |
|---------|-------------------|-----------------|
| **Win 10/11** | ❌ None | Presence only, correlation |
| **Win 7/8** | ⚠️ Low | Presence, weak execution hint |
| **Win XP/2003** | ⚠️ Medium | Historical interest only |

**⚠️ Common Misunderstanding:**
```
WRONG: "File is in ShimCache, therefore it executed"
RIGHT: "File is in ShimCache, therefore it existed on system"

For Execution Proof, Use:
✓ Prefetch (workstations)
✓ BAM/DAM (Win10/11)
✓ Event Logs (EID 4688)
✓ UserAssist (GUI apps)
✓ Jump Lists (user interaction)
```

#### Investigation Patterns

**Pattern 1: Deleted File Discovery**
```
Scenario: Attacker removed tools after use

ShimCache Evidence:
Entry: C:\Users\Bob\Downloads\mimikatz.exe
Modified: 2024-03-15 14:23:45
Status: File no longer exists on disk

Corroboration:
✓ Prefetch: MIMIKATZ.EXE-A1B2C3D4.pf (proves execution)
✓ Amcache: SHA1 hash (identifies malware)
✓ MFT: File deletion timestamp (USN Journal)
✓ Event 4688: Process creation by "Bob" at 14:24:00

Conclusion: ShimCache proves file existed despite deletion
```

**Pattern 2: Living Off The Land Detection**
```
Built-In Tools to Hunt For:
- psexec.exe (lateral movement)
- wmic.exe (remote execution)
- reg.exe (registry modification)
- schtasks.exe (persistence)
- vssadmin.exe (shadow copy deletion)
- cipher.exe (secure deletion)
- powershell.exe (from unusual paths)

Filter ShimCache CSV in Timeline Explorer:
1. Search for tool names
2. Filter for unusual execution paths
3. Compare with baseline "normal" locations
```

**Pattern 3: Unusual Execution Paths**
```
Red Flag Paths:
C:\Windows\Temp\
C:\$Recycle.Bin\
C:\Users\*\AppData\Local\Temp\
C:\PerfLogs\
System Volume Information\
C:\Users\Public\

Example:
Entry: C:\Windows\Temp\cmd.exe
Modified: 2024-03-15 03:15:22

Analysis:
✗ cmd.exe should be in C:\Windows\System32\
✗ Temp folder location is suspicious
✓ Check Prefetch for execution proof
✓ Check Amcache for SHA1 (renamed malware?)
```

#### Server Environment Considerations

**Critical for Server Investigations:**
```
Prefetch: Disabled by default on Windows Server
ShimCache: STILL ACTIVE on servers

Therefore: ShimCache becomes MORE valuable on servers

Server Investigation Strategy:
1. ShimCache: Identify suspicious executables
2. Event Logs: Prove execution (EID 4688 with command line)
3. Amcache: Get SHA1 hashes
4. BAM/DAM: Execution timestamps (if Win Server 2016+)

Example Server Artifacts:
- psexec.exe in ShimCache (lateral movement)
- procdump64.exe (credential dumping)
- mimikatz.exe (credential theft)
```

#### Anti-Forensics Detection

**Technique: File Timestomping**
```
Detection:
ShimCache records executable's MODIFICATION time
If attacker timestomps executable, ShimCache shows fake time

Cross-Verification:
1. MFT: Compare $SI vs. $FN timestamps
2. USN Journal: Check BASIC_INFO_CHANGE entries
3. Amcache: Compilation time vs. modification time
4. Prefetch: Execution time vs. ShimCache time

Example:
ShimCache: malware.exe Modified = 2020-01-01 (suspicious)
MFT FN: Created = 2024-03-15 (actual)
Prefetch: Executed = 2024-03-15 (actual)
→ Timestomping detected
```

**Technique: Cache Overflow**
```
Attack Method:
Execute 1,024+ different files to push old entries out of cache

Detection:
- Unusually high number of unique executables
- Many executables from same source folder
- Sequential or pattern-based names

Mitigation:
- Collect ShimCache EARLY in investigation
- Check Volume Shadow Copies for historical cache
- Cross-reference with Prefetch (has different retention)
```

#### Correlation Strategy

**ShimCache Tells You:**
- ✅ File existed on system
- ✅ Last modification time (file metadata)
- ✅ Full file path
- ✅ File size

**Does NOT Tell You:**
- ❌ Whether file executed (Win10/11)
- ❌ When file was accessed
- ❌ How many times executed
- ❌ Who executed it

**Verify With:**
- **Prefetch:** PROVES execution, adds run count
- **BAM/DAM:** Precise execution timestamp + user
- **Amcache:** SHA1 hash for identification
- **Event Logs:** User context, command line
- **MFT/USN Journal:** File creation/deletion timeline

**Example Correlation:**
```
Scenario: Unknown executable investigation

ShimCache Entry:
Path: C:\Users\Bob\Desktop\update.exe
Modified: 2024-03-15 10:30:00
Size: 2,457,600 bytes

Question: Did this execute?

Answer: ShimCache CANNOT tell us (Win10/11)

Verification:
1. Prefetch: UPDATE.EXE-A1B2C3D4.pf
   → YES, it executed
   → Run count: 3 times
   → Last run: 2024-03-15 10:31:15

2. BAM/DAM: Confirms 10:31:15, User = Bob

3. Amcache: SHA1 → VirusTotal: Trojan detected

4. Event 4688: Process created by Bob at 10:31:15
   Command line: update.exe /silent /install

Conclusion:
- ShimCache proved file existed
- Prefetch proved execution
- Amcache identified malware
- Event logs provided user context
- COMBINED = strong evidence chain
```

#### Forensic Value Summary

**Strengths:**
- ✅ Proves file presence on system
- ✅ Survives file deletion
- ✅ Up to 1,024 entries
- ✅ Available on servers (where Prefetch disabled)
- ✅ Full path information

**Limitations:**
- ❌ NO execution proof (Win10/11)
- ❌ No execution timestamp
- ❌ No run count
- ❌ No user attribution
- ❌ Can be filled/overwritten

**Best Used For:**
- Server investigations (Prefetch disabled)
- Proving file existed despite deletion
- Correlation with execution artifacts
- Timeline reconstruction (via file modification)
- Living Off The Land detection

---

### 4. BAM/DAM

#### Overview

**Description:** Background Activity Monitor (BAM) and Desktop Activity Moderator (DAM) track application execution with precise timestamps on Windows 10 (1709+) and Windows 11. **Among the most reliable execution artifacts on modern Windows.**

**Key Facts:**
- Introduced in Windows 10 Fall Creators Update (1709)
- Records execution with exact timestamp
- Includes user SID (identifies who executed)
- Survives file deletion
- Works even when Prefetch disabled
- More reliable than ShimCache for execution proof

#### Location
```
File Source:
C:\Windows\System32\config\SYSTEM

Registry (Live):
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{User-SID}
HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{User-SID}

Each user has separate subkey identified by their Security Identifier (SID)
````

**Available Metadata**

```
```

**Tools for Analysis**

**RECmd (Eric Zimmerman) - Recommended:**

powershell

````powershell
# Parse SYSTEM hive
RECmd.exe -f "C:\Windows\System32\config\SYSTEM" --bn BatchExamples\bam.reb --csv "G:\Output"

# Alternative: Use predefined batch file
RECmd.exe -f "SYSTEM" --bn bam.reb --csv "G:\Output"
```

**Registry Explorer (Eric Zimmerman) - GUI:**
```
1. Run as Administrator
2. File > Load Hive > Select SYSTEM
3. Navigate to:
   ROOT\CurrentControlSet\Services\bam\State\UserSettings
   ROOT\CurrentControlSet\Services\dam\State\UserSettings
4. Expand user SID folders
5. View execution entries with timestamps
````

**RegRipper:**

powershell

```powershell
# Parse BAM/DAM with RegRipper
rip.exe -r SYSTEM -p bam
rip.exe -r SYSTEM -p dam
```

**PowerShell (Live System):**

powershell

````powershell
# Enumerate BAM entries
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*" | 
  Select-Object PSChildName, * | 
  Where-Object {$_.PSChildName -ne "Background Activity Monitor"}

# Convert FileTime to readable format
$fileTime = [long]"132945678901234567"
[DateTime]::FromFileTime($fileTime)
```

#### Interpretation Guide

**Timestamp Format:**
```
Registry stores: 64-bit FILETIME (100-nanosecond intervals since 1601-01-01)

Example:
Raw Value: 132945678901234567
Converted: 2024-03-15 14:32:45.123 UTC

Tools automatically convert FILETIME to human-readable format
````

**User SID Mapping:**

powershell

````powershell
# Live system - Map SID to username
wmic useraccount get name,sid

# Offline analysis - Registry (SAM hive)
Load SAM hive in Registry Explorer
Navigate: SAM\Domains\Account\Users\Names
Map SID to username

Common SIDs:
S-1-5-18 = SYSTEM
S-1-5-19 = LOCAL SERVICE
S-1-5-20 = NETWORK SERVICE
S-1-5-21-...-500 = Administrator
S-1-5-21-...-1001+ = Regular users
```

**Execution Entry Structure:**
```
Example Entry:
Path: C:\Users\Bob\Downloads\malware.exe
SID: S-1-5-21-123456789-123456789-123456789-1105
Timestamp: 2024-03-15 14:32:45 UTC

Interpretation:
- User "Bob" (SID ending in -1105)
- Executed malware.exe from Downloads folder
- At 14:32:45 on March 15, 2024
```

#### Investigator Notes

**⚠️ Critical Strengths:**
```
1. Execution Proof
   Unlike ShimCache, BAM/DAM definitively proves execution

2. User Attribution
   SID directly identifies which user executed program

3. Precise Timestamp
   Exact execution time (not approximate like Prefetch)

4. Survives File Deletion
   Entry persists even after executable removed

5. Works Without Prefetch
   Valuable on servers or if Prefetch disabled

6. Minimal Anti-Forensics
   Difficult for attackers to clear without detection
```

**BAM vs. DAM:**
```
BAM (Background Activity Monitor):
- Tracks all applications
- More commonly populated
- Focus investigation here first

DAM (Desktop Activity Moderator):
- Tracks desktop applications  
- Less commonly populated
- Check if BAM lacks entries
```

**Comparison with Other Execution Artifacts:**

| Artifact | Execution Proof | User SID | Precise Time | Survives Deletion |
|----------|----------------|----------|--------------|-------------------|
| **BAM/DAM** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Prefetch | ✅ Yes | ❌ No | ⚠️ ±10s | ✅ Yes |
| ShimCache | ❌ No (Win10) | ❌ No | ❌ No | ✅ Yes |
| Amcache | ❌ No | ❌ No | ❌ No | ✅ Yes |

#### Investigation Patterns

**Pattern 1: Lateral Movement Detection**
```
Scenario: Detecting PsExec usage across network

BAM Entry:
Path: C:\Windows\psexec.exe
SID: S-1-5-21-...-1105 (Domain Admin)
Timestamp: 2024-03-15 03:15:22

Path: C:\Windows\Temp\procdump.exe
SID: S-1-5-21-...-1105 (Same user)
Timestamp: 2024-03-15 03:16:45

Path: C:\Windows\Temp\mimikatz.exe
SID: S-1-5-21-...-1105 (Same user)
Timestamp: 2024-03-15 03:18:12

Analysis:
- Domain Admin account used
- Attack tools executed sequentially
- Precise timeline established
- User attribution confirmed
```

**Pattern 2: After-Hours Execution**
```
Filter BAM/DAM for:
- Execution times: 10 PM - 6 AM
- Weekends/Holidays
- Outside user's normal working hours

Example:
User: Bob (normally works 9-5, Mon-Fri)
BAM Entry:
  Path: C:\Users\Bob\Desktop\sensitive_export.exe
  Timestamp: 2024-03-16 02:30:15 (Saturday, 2:30 AM)
  
Red Flag: Highly unusual timing for regular user
```

**Pattern 3: Execution from Unusual Locations**
```
High-Value Paths to Monitor:
- C:\Users\*\Downloads\
- C:\Users\*\AppData\Local\Temp\
- C:\Windows\Temp\
- C:\$Recycle.Bin\
- C:\PerfLogs\

Example:
BAM Entry:
  Path: C:\Users\Public\update.exe
  SID: S-1-5-21-...-1001
  Timestamp: 2024-03-15 14:32:22

Analysis:
✗ C:\Users\Public\ is unusual for executables
✗ "update.exe" is generic name (possible malware)
✓ Check Amcache for SHA1 → VirusTotal
✓ Check Prefetch for file behavior analysis
```

#### Anti-Forensics Detection

**Technique: BAM/DAM Clearing**
```
Attack Method:
1. Delete registry subkeys
2. Modify SYSTEM hive directly
3. Requires admin/SYSTEM privileges

Detection:
- Empty or sparse BAM/DAM for active user
- Recently created registry keys (unusual)
- Check Volume Shadow Copies for historical data
- Event logs may show registry modification (if auditing enabled)

Recovery:
1. Extract SYSTEM hive from VSS
2. Parse with RECmd
3. Compare current vs. historical entries
4. Identify deleted executions
```

**Technique: Execution via Scheduled Tasks**
```
Some execution methods may not populate BAM/DAM reliably:
- Scheduled tasks (depending on configuration)
- Services
- Kernel-mode drivers

Mitigation:
- Check Scheduled Task artifacts
- Review Services registry keys
- Correlate with Event Logs (EID 4688, Sysmon EID 1)
```

#### Correlation Strategy

**BAM/DAM Tells You:**
- ✅ Program executed (definitive)
- ✅ Exact execution timestamp
- ✅ User who executed (via SID)
- ✅ Full execution path

**Does NOT Tell You:**
- ❌ Execution count (how many times)
- ❌ Files accessed by program
- ❌ Parent process
- ❌ Command-line arguments

**Verify With:**
- **Prefetch:** Run count, last 8 execution times, file behavior
- **Event Logs:** Parent process, command-line arguments
- **Amcache:** SHA1 hash, publisher verification
- **Sysmon:** Network connections, DLL loads, process tree

**Example Correlation:**
```
Scenario: Suspected credential dumping

BAM Entry:
Path: C:\Windows\Temp\procdump64.exe
SID: S-1-5-21-...-1105 (maps to "admin_bob")
Timestamp: 2024-03-15 03:15:45

Cross-Verification:

1. Prefetch: PROCDUMP64.EXE-A1B2C3D4.pf
   - Run count: 1
   - Last run: 2024-03-15 03:15:45 (matches BAM)
   - Files accessed: lsass.exe memory

2. Event 4688 (Process Creation):
   - Time: 2024-03-15 03:15:45 (matches)
   - User: DOMAIN\admin_bob (confirmed)
   - Command line: procdump64.exe -ma lsass.exe lsass.dmp

3. Amcache:
   - SHA1: Matches legitimate Sysinternals ProcDump
   - Publisher: Microsoft Corporation (verified)

4. File System:
   - C:\Windows\Temp\lsass.dmp (52 MB, created 03:15:47)
   - Confirms credential dumping occurred

Conclusion:
- BAM provided initial detection with user and time
- Prefetch confirmed execution and target (lsass)
- Event logs revealed command-line (dumping memory)
- File system showed output (lsass.dmp created)
- STRONG evidence chain for credential theft
```

#### Windows Version Considerations

**Windows 10 (Version 1709+):**
```
✓ BAM fully functional
✓ DAM may be present
✓ Most reliable execution artifact

Registry Path:
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\
```

**Windows 11:**
```
✓ BAM fully functional
✓ Improved reliability over Win10
✓ Primary execution artifact recommended

Same registry path as Win10
```

**Earlier Windows Versions:**
```
❌ BAM/DAM not available (pre-1709)
Alternative Artifacts:
- Prefetch (if workstation)
- UserAssist (GUI applications)
- Event Logs (EID 4688)
- Amcache (presence only)
```

**Windows Server 2016+:**
```
✓ BAM available (if patched to 1709+ equivalent)
✓ Especially valuable since Prefetch disabled by default

Server Investigation Priority:
1. BAM/DAM (execution with user/time)
2. Event Logs (command-line auditing)
3. ShimCache (presence indicator)
4. Amcache (SHA1 hashes)
```

#### Forensic Value Summary

**Strengths:**
- ✅ **Definitive execution proof** (not just presence)
- ✅ **Precise timestamp** (exact execution time)
- ✅ **User attribution** (SID identifies user)
- ✅ **Survives file deletion**
- ✅ **Works when Prefetch disabled**
- ✅ **Difficult to manipulate** without detection

**Limitations:**
- ❌ No execution count
- ❌ No file behavior analysis
- ❌ Only last execution (not historical like Prefetch)
- ❌ Requires Windows 10 1709+ or Win11
- ❌ Can be cleared by skilled attacker with admin rights

**Best Used For:**
- **Primary execution artifact on Win10/11**
- User attribution for executed programs
- Precise execution timeline
- Server investigations (Prefetch alternative)
- After-hours activity detection
- Lateral movement tracking

**Investigation Priority:**
```
Windows 10/11 Execution Analysis Order:
1. BAM/DAM (proves execution + user + time)
2. Prefetch (run count + behavior + historical)
3. Event Logs (command line + parent process)
4. Amcache/ShimCache (verification + hashes)

This combination provides strongest evidence chain
```

---

### 5. ShellBags

#### Overview

**Description:** Registry artifact tracking folder access and view preferences in Windows Explorer. Records folder interactions even after folder deletion, including removable devices and network shares.

**Key Facts:**
- Tracks user folder navigation
- Records view settings (size, position, sorting)
- Persists after folder deletion
- Identifies removable media access
- Shows network share connections
- Can prove folders that never existed locally

#### Location

**Primary Data (Most Comprehensive):**
```
File: C:\Users\[Username]\AppData\Local\Microsoft\Windows\UsrClass.dat

Registry Paths:
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
```

**Residual Data (Desktop Items & Network Shares):**
```
File: C:\Users\[Username]\NTUSER.DAT

Registry Paths:
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
```

#### Available Metadata

| Metadata | Description | Forensic Value |
|----------|-------------|----------------|
| Full folder path | Local, network, removable | Navigation history |
| First interaction | When user first opened folder | Initial access |
| Last interaction | When user last opened folder | Recent activity |
| Folder timestamps | Creation, modification times | Timeline correlation |
| Window position | Screen coordinates | User behavior |
| View mode | Icons, list, details, tiles | Preferences |
| Sort preferences | Sort order | User habits |
| Volume information | Serial number, label | Removable media ID |
| Network paths | UNC paths | Share access |

#### Tools for Analysis

**ShellBagsExplorer (Eric Zimmerman) - GUI:**
```
1. Launch ShellBagsExplorer.exe
2. File > Load Offline Hive > Select UsrClass.dat
3. View folder access timeline
4. Right-click folders > Properties for details
5. Export > CSV for timeline analysis

Features:
- Visual folder tree structure
- Timeline view
- Detailed metadata inspection
- Export capabilities
````

**SBECmd (Eric Zimmerman) - Command Line:**

powershell

````powershell
# Parse UsrClass.dat
SBECmd.exe -f "C:\Users\Bob\AppData\Local\Microsoft\Windows\UsrClass.dat" --csv "G:\Output"

# Parse NTUSER.DAT
SBECmd.exe -f "C:\Users\Bob\NTUSER.DAT" --csv "G:\Output"

# Parse entire user directory (both hives)
SBECmd.exe -d "C:\Users\Bob" --csv "G:\Output"

# Quiet mode (suppress console output)
SBECmd.exe -d "C:\Users\Bob" --csv "G:\Output" -q

# Live system (current user)
SBECmd.exe -l --csv "C:\Cases\Output"
```

**Extraction with FTK Imager:**
```
UsrClass.dat Location:
C:\Users\[Username]\AppData\Local\Microsoft\Windows\

Files to Export:
- UsrClass.dat
- UsrClass.dat.LOG1
- UsrClass.dat.LOG2

NTUSER.DAT Location:
C:\Users\[Username]\

Files to Export:
- NTUSER.DAT
- NTUSER.DAT.LOG1
- NTUSER.DAT.LOG2

Extract all associated .LOG files for complete analysis
```

#### Interpretation Guide

**Folder Access Timeline:**
```
Example Entry:
Folder: C:\Users\Bob\Documents\Confidential
First Interacted: 2024-03-10 08:30:15
Last Interacted: 2024-03-20 16:45:22

Interpretation:
- User first opened this folder on March 10
- User last accessed folder on March 20
- Active folder usage over 10-day period
- Indicates sustained interest in contents
```

**Deleted Folder Evidence:**
```
ShellBag Entry: C:\Users\Bob\Documents\Secret_Project
Current Status: Folder does NOT exist

Forensic Value:
✓ Proves folder existed despite deletion
✓ Shows when user accessed it
✓ Timeline of user interest

Investigation Steps:
1. Check Recycle Bin for folder recovery
2. Check MFT for folder deletion timestamp
3. Search $UsnJrnl for file operations
4. Check VSS for folder/file recovery
5. Correlate with LNK files for specific file access
```

**What Triggers ShellBag Creation:**
```
User Actions:
✓ Opening folder in Windows Explorer
✓ Changing folder view settings (icons, details, etc.)
✓ Sorting folder contents
✓ Accessing removable media
✓ Navigating network shares
✓ Creating new folders

NOT Triggered By:
✗ Command-line directory access (cd, dir)
✗ Application file access (without Explorer)
✗ Background system operations
```

#### Investigation Patterns

**Pattern 1: Removable Media Tracking**
```
ShellBag Entry Example:
Path: E:\Backup\Company_Data
Volume Label: "KINGSTON_USB"
Volume Serial: 1A2B-3C4D
First Interaction: 2024-03-15 14:20:00
Last Interaction: 2024-03-15 14:35:18

Analysis:
✓ USB drive "KINGSTON_USB" connected
✓ User navigated to Backup\Company_Data folder
✓ 15-minute interaction window
✓ Potential data exfiltration timeframe

Cross-Reference:
- USB connection logs (SYSTEM\MountedDevices)
- LNK files pointing to E:\ drive
- Jump Lists for applications used
- Event logs for user logon session
```

**Pattern 2: Network Share Access**
```
ShellBag Entry Example:
Path: \\fileserver\Finance\Payroll_2024
First Interaction: 2024-03-18 20:15:42
Last Interaction: 2024-03-18 20:47:55

Red Flags:
✗ Access to sensitive folder (Payroll)
✗ After-hours access (8:15 PM)
✗ Extended session (32 minutes)

Investigation:
1. Verify user authorization for Finance share
2. Check network logon events (EID 4624 Type 3)
3. Review file server access logs
4. Check for file downloads/copies
5. Correlate with LNK files (specific files accessed)
6. Check for email/cloud uploads (exfiltration)
```

**Pattern 3: Data Staging Detection**
```
ShellBag Timeline:
2024-03-10 08:00 | C:\Users\Bob\Desktop\ToBackup [CREATED]
2024-03-10 08:15 | \\fileserver\Shared\Projects
2024-03-10 08:30 | C:\Users\Bob\Desktop\ToBackup [ACCESSED]
2024-03-12 14:00 | E:\Backup (USB drive)
2024-03-12 14:15 | C:\Users\Bob\Desktop\ToBackup [ACCESSED]
2024-03-13 09:00 | C:\Users\Bob\Desktop\ToBackup [DELETED]

Pattern Analysis:
1. Created staging folder "ToBackup"
2. Accessed network Projects share
3. Returned to staging folder (likely copying files)
4. Connected USB drive
5. Accessed staging folder again (copying to USB)
6. Deleted staging folder (cleanup)

Conclusion: Systematic data exfiltration via USB
```

#### Investigator Notes

**High-Value Folder Locations:**
```
Sensitive Data Folders:
\\*\Finance\*
\\*\HR\*
\\*\Legal\*
\\*\Executive\*
\\*\Payroll\*
\\*\Confidential\*

Suspicious Local Folders:
C:\Users\*\Desktop\Backup
C:\Users\*\Documents\ToDelete
C:\Users\*\Desktop\Temp
C:\ProgramData\*
C:\Users\Public\*

Cloud Storage Folders:
C:\Users\*\Dropbox\
C:\Users\*\Google Drive\
C:\Users\*\OneDrive\
C:\Users\*\Box\
```

**Insider Threat Indicators:**
```
Red Flags:
1. Access to folders outside normal job scope
2. After-hours/weekend folder navigation
3. Rapid folder navigation (automated copying)
4. New personal "Backup" folders created
5. Access to HR/Finance folders by non-authorized users
6. Removable media access during sensitive periods
7. Network share access from unusual workstations
```

**Exotic Items Tracked:**
```
Beyond Normal Folders:
✓ Control Panel applets
✓ Zip archive internal structure (folders inside .zip)
✓ Mobile device folders (MTP protocol)
✓ FTP server navigation
✓ Compressed folders (Explorer integration)
✓ Virtual machine shared folders
✓ Cloud storage sync folders
```

#### Anti-Forensics Detection

**Technique 1: Registry Hive Deletion**
```
Attack Method:
- Delete UsrClass.dat, NTUSER.DAT
- Clear registry keys manually

Detection:
1. Check for missing/recently created hives
2. Compare with user's last logon time
3. Check VSS for previous versions
4. Look for evidence of registry manipulation

Recovery:
- Extract hives from Volume Shadow Copies
- Parse historical ShellBags data
- Compare current vs. VSS to identify deleted entries
```

**Technique 2: Selective Key Deletion**
```
Attack Method:
- Delete specific ShellBag registry keys
- Target only incriminating folders

Detection:
1. Registry transaction logs (NTUSER.DAT.LOG1, .LOG2)
2. VSS comparison (current vs. historical)
3. Look for gaps in MRU sequences
4. Unusual registry modification timestamps

Analysis:
- Parse transaction logs with Registry Explorer
- Compare VSS ShellBags with current
- Identify "missing" folder entries
```

**Technique 3: CCleaner/Privacy Tools**
```
Tools Used:
- CCleaner
- BleachBit
- PrivaZer

Detection:
1. Prefetch: CCLEANER.EXE-*.pf
2. Amcache: Privacy tool SHA1 hashes
3. VSS: Historical ShellBags before cleaning
4. Browser history: Privacy tool downloads

Mitigation:
- VSS analysis provides pre-cleaning data
- Execution of cleaning tool itself is evidence
- May indicate consciousness of guilt
```

#### Correlation Strategy

**ShellBags Tell You:**
- ✅ Folders user navigated to
- ✅ First/last access times
- ✅ Removable media connections
- ✅ Network share access
- ✅ Deleted folder evidence

**Does NOT Tell You:**
- ❌ Specific files accessed (use LNK files)
- ❌ File contents viewed
- ❌ Applications used
- ❌ Data copied/modified

**Verify With:**
- **LNK Files:** File-level access within folders
- **Jump Lists:** Recent documents in applications
- **Prefetch:** Applications executed from folders
- **USB Artifacts:** Device connection timeline
- **MFT/$UsnJrnl:** Folder/file creation and deletion
- **Event Logs:** Network logons, file share access

**Example Correlation:**
```
Scenario: Suspected data theft via USB

Evidence Chain:

1. ShellBags:
   - E:\Backup (USB "SANDISK_64GB")
     First: 2024-03-10 | Last: 2024-03-15
   - C:\Users\employee\Documents\Company_Files
     Accessed: 2024-03-10-15
   - C:\Users\employee\Desktop\ToBackup
     Created: 2024-03-09 | Deleted: 2024-03-16

2. USB Logs (Registry):
   - Device: SANDISK_64GB, Serial: 12AB34CD56EF
   - Connections: 12 times (Mar 10-15)
   - User: DOMAIN\employee

3. LNK Files:
   - customer_database.xlsx.lnk (accessed Mar 10)
   - financial_report.docx.lnk (accessed Mar 12)
   - Both from Company_Files folder

4. Prefetch:
   - XCOPY.EXE-*.pf (executed Mar 10-15)
   - 7Z.EXE-*.pf (executed Mar 15)

5. Recycle Bin (VSS):
   - ToBackup folder contents (50+ files)
   - Deleted Mar 16 after USB activity

6. MFT/USN Journal:
   - ToBackup folder: Created Mar 9
   - Files copied into ToBackup: Mar 10-15
   - ToBackup deleted: Mar 16

Timeline:
Mar 9: Created staging folder
Mar 10-15: Copied company files to staging, then to USB
Mar 16: Deleted staging folder (cleanup)

Conclusion:
ShellBags provided folder navigation timeline proving:
- Access to sensitive company folders
- USB drive usage
- Staging folder creation and deletion
- Systematic data exfiltration pattern
```

#### Forensic Value Summary

**Strengths:**
- ✅ Folder navigation history
- ✅ First/last interaction timestamps
- ✅ Deleted folder evidence
- ✅ Removable media identification
- ✅ Network share access
- ✅ Survives folder deletion
- ✅ Window preferences (investigator profiling)

**Limitations:**
- ❌ No file-level access (only folders)
- ❌ No file contents
- ❌ Command-line not tracked
- ❌ Can be cleared by tools/attacker

**Best Used For:**
- User folder navigation timeline
- Data exfiltration investigations
- Removable media usage
- Network share access patterns
- Insider threat detection
- Deleted folder evidence
- User behavior profiling

---

### 6. Jump Lists

#### Overview

**Description:** Windows feature allowing quick access to recent/frequent items via taskbar. Provides rich metadata about user interactions with applications and files since Windows 7.

**Key Facts:**
- Two types: Automatic (system-generated) and Custom (user-pinned)
- Named by Application ID (AppID)
- Hidden by default
- Contains embedded LNK stream data
- Identifies deleted files
- Shows network and removable media access

#### Location

**Automatic Jump Lists:**
```
C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations

Format: [16-digit-hex-AppID].automaticDestinations-ms

Structure: Microsoft Compound File Binary (CFB/OLE)
Contains:
- DestList stream (metadata)
- Numbered SHLLINK streams (file references)
```

**Custom Jump Lists:**
```
C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations

Format: [16-digit-hex-AppID].customDestinations-ms

Structure: Sequential MS-SHLLINK binary format
Contains:
- User-pinned items
- Taskbar pins
````

**Access Methods:**

* Enter full path in Windows Explorer address bar
* Use forensic tools (files are hidden)
* Command-line navigation

**Common Application IDs**

```
```

**Full List:** [https://dfir.to/EZJumpList](https://dfir.to/EZJumpList)

**Available Metadata**

**From DestList Stream:**

* Application AppID
* File path (local/network/removable)
* File creation, modification, access times
* Last used timestamp
* Interaction count
* Entry number
* Volume information (serial, label)
* File size
* File attributes

**From SHLLINK Streams:**

* Target file path
* Working directory
* Command-line arguments
* Drive type (fixed, removable, network)
* Volume serial number
* MAC address (sometimes)
* Machine ID/hostname

**Tools for Analysis**

**JLECmd (Eric Zimmerman) - Command Line:**

powershell

````powershell
# Single Jump List file
JLECmd.exe -f "C:\Users\Bob\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms" --csv "G:\Output" -q

# All AutomaticDestinations for user
JLECmd.exe -d "C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "G:\Output" -q

# All users, all Jump Lists
JLECmd.exe -d "C:\Users\" --csv "G:\Output" -q --all

# Include CustomDestinations
JLECmd.exe -d "C:\Users\Bob\AppData\Roaming\Microsoft\Windows\Recent\" --csv "G:\Output" -q

# JSON output (single file, detailed)
JLECmd.exe -f "jumplist.automaticDestinations-ms" --json "G:\Output" --pretty

# Live system (current user)
JLECmd.exe --ld --csv "C:\Cases\Output" -q
```

**JumpListExplorer (Eric Zimmerman) - GUI:**
```
1. Launch JumpListExplorer.exe
2. File > Load Jump List
3. Select .automaticDestinations-ms or .customDestinations-ms
4. View DestList and individual entries
5. Inspect LNK stream data
6. Export to CSV
```

**Extraction with FTK Imager:**
```
Navigate to:
C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Recent

Export Folders:
- AutomaticDestinations (entire folder)
- CustomDestinations (entire folder)

These folders are HIDDEN - ensure hidden files visible in FTK Imager
```

#### Interpretation Guide

**Automatic Jump List Timestamps:**
```
Entry Example:
Application: Microsoft Word (5f7b5f1e01b83767)
File: C:\Users\Bob\Documents\Confidential_Report.docx
Creation Time: 2024-03-10 09:15:30
Modification Time: 2024-03-20 16:42:18
Last Used Time: 2024-03-20 16:42:18
Interaction Count: 15

Interpretation:
- First opened in Word: March 10, 9:15 AM
- Last opened in Word: March 20, 4:42 PM
- Opened 15 times total
- Heavy user interaction with document
- Active editing over 10-day period
```

**Jump List Creation vs. Modification:**
```
Jump List File Timestamps:
Creation: First time item added to jump list = First file access
Modification: Last time item added/updated = Last file access

Example:
5f7b5f1e01b83767.automaticDestinations-ms
Created: 2024-01-15 (first time user opened any Word doc)
Modified: 2024-03-20 (last time user opened Word doc)

Individual entries have their own timestamps within the jump list
```

#### Investigation Patterns

**Pattern 1: Deleted File Evidence**
```
Jump List Entry Exists BUT File Does Not:

Entry:
Path: C:\Users\Bob\Downloads\confidential_data.xlsx
Status: File deleted from system
Last Used: 2024-03-15 18:30:00
Interaction Count: 8

Forensic Value:
✓ Proves file existed on system
✓ User accessed file 8 times
✓ Last access was March 15, 6:30 PM
✓ File path known for carving attempts

Investigation Steps:
1. Check Recycle Bin for recovery
2. Check MFT for file metadata
3. Search $UsnJrnl for deletion timestamp
4. VSS for file recovery
5. Browser history for download source
6. Email for attachment source
```

**Pattern 2: Network Share Access**
```
Jump List Entry:
Path: \\fileserver\HR\Salaries\2024_Compensation.xlsx
AppID: 5f7b5f1e01b83767 (Microsoft Excel)
First Access: 2024-03-15 20:35:12
Last Access: 2024-03-20 22:15:45
Interaction Count: 12

Red Flags:
✗ HR salary data access
✗ After-hours access (8:35 PM, 10:15 PM)
✗ Multiple interactions over 5 days
✗ Possible unauthorized access

Cross-Reference:
1. User authorization check (is user HR staff?)
2. Network logon events (EID 4624 Type 3)
3. File server access logs
4. DLP alerts
5. Data exfiltration indicators (email, USB, cloud)
```

**Pattern 3: Removable Media File Access**
```
Jump List Entry:
Path: E:\Backup\customer_database.db
Drive Type: Removable
Volume Label: "KINGSTON"
Volume Serial: 1A2B-3C4D
Last Access: 2024-03-18 14:22:45
Interaction Count: 3

Analysis:
✓ User accessed database file on USB drive
✓ Drive name "KINGSTON" (USB flash drive)
✓ Path suggests backup/exfiltration
✓ 3 separate access sessions

Investigation:
1. Check ShellBags for E:\ folder navigation
2. USB connection logs (SYSTEM\MountedDevices)
3. File timeline (when was DB file created?)
4. Prefetch for database applications
5. Network activity (upload attempts?)
```

**Pattern 4: Cross-Application Correlation**
```
Same File in Multiple Jump Lists:

File: C:\Users\Bob\secret_project.docx

Found in:
1. Word (5f7b5f1e01b83767) - Edited 20 times
2. Notepad++ (custom AppID) - Opened 5 times
3. 7-Zip (23646679aaccfae0) - Compressed 1 time

Timeline:
Mar 10-20: Heavy Word editing (20 opens)
Mar 20: Opened in Notepad++ (possible text extraction)
Mar 20: Compressed with 7-Zip (prep for transfer?)

Analysis:
- Normal editing in Word
- Notepad++ suggests text-only extraction
- Compression indicates preparation for exfiltration
- Pattern shows intentional data handling
```

#### Investigator Notes

**Application Usage Patterns:**
```
Normal Interaction Counts:
- Working documents: 5-20 accesses
- Reference documents: 1-5 accesses
- Active projects: 15-50 accesses

Suspicious Counts:
- 50+ accesses in short time: Automated access?
- 1-2 accesses to sensitive files: Quick grab?
- Unusual application pairings: Data manipulation?

Unusual Applications:
✗ Remote Desktop: Lateral movement investigation
✗ Archive Tools (7-Zip, WinRAR): Data staging
✗ FTP Clients: Potential exfiltration
✗ Database Tools: Data extraction
✗ Hex Editors: Malware analysis/modification
```

**Temporal Analysis:**
```
After-Hours Access:
- Weekends
- Late night (10 PM - 6 AM)
- Holidays
- Outside user's normal hours

Context Matters:
✓ IT Admin working overnight: May be legitimate
✗ Finance user accessing files at 2 AM: Suspicious
✗ Sales employee on payroll server: Unauthorized

Rapid Sequential Access:
Multiple files opened in seconds: Automated script?
Pattern: open-close-open-close: Data harvesting?
```

**File Type Priorities:**
```
High-Value File Types:
- .xlsx, .xls: Financial data, databases
- .docx, .doc: Contracts, reports
- .pdf: Documents, forms, scans
- .pst, .ost: Email archives
- .db, .sqlite, .mdb: Databases
- .zip, .rar, .7z: Archives
- .kdbx: Password databases (KeePass)
- .rdp: Remote Desktop configs
- .config, .xml: Configuration files
```

#### Anti-Forensics Detection

**Technique 1: Jump List Deletion**
```
Attack Methods:
- Delete .automaticDestinations-ms files
- Delete specific entries within jump lists
- Use privacy tools (CCleaner, etc.)

Detection:
1. Empty or recent Jump List files (suspicious)
2. Check VSS for historical jump lists
3. Prefetch for deletion tools
4. Recent folder may have residual LNK files

Recovery:
- Extract jump lists from VSS
- Compare current vs. historical
- Identify deleted entries
- Parse recent folder for additional LNK files
```

**Technique 2: OLE Compound File Manipulation**
```
Attack Method:
- Modify jump list internal structure
- Remove incriminating DestList entries
- Requires specialized tools

Detection:
1. Compare file modification time with last entry time
2. Check for malformed jump list structure
3. Parse with multiple tools (verify consistency)
4. VSS comparison

Red Flags:
- Jump list modified but no new file access
- Structural inconsistencies
- Missing expected entries
```

#### Correlation Strategy

**Jump Lists Tell You:**
- ✅ Application usage (by AppID)
- ✅ Files accessed by application
- ✅ First and last access times
- ✅ Interaction counts
- ✅ Deleted file evidence
- ✅ Network share access
- ✅ Removable media usage

**Does NOT Tell You:**
- ❌ User attribution (inferred from profile)
- ❌ File contents
- ❌ Success/failure of access
- ❌ Application execution (only file access)

**Verify With:**
- **LNK Files:** Corroborate recent file access
- **Prefetch:** Prove application execution
- **ShellBags:** Folder navigation context
- **Amcache:** File hash verification
- **Event Logs:** User logon sessions, process creation
- **Browser History:** Download sources

**Example Correlation:**
```
Scenario: Credential theft investigation

Jump Lists Findings:

1. Remote Desktop (74d7f43c1561fc1e):
   - \\DC01 (Domain Controller) - 2024-03-15 03:22:15
   - \\FILESERVER01 - 2024-03-15 03:35:42
   - \\EXCHANGE01 - 2024-03-15 03:48:19
   Analysis: Lateral movement to critical servers

2. 7-Zip (23646679aaccfae0):
   - C:\Users\Bob\AppData\Local\Temp\lsass.dmp - 03:15:08
   - C:\Windows\Temp\creds.zip - 03:16:45
   Analysis: LSASS dump compressed

3. Chrome (4efdf69aa7f1ce62):
   - transfer.sh/creds.zip - 03:20:33
   Analysis: File uploaded to file-sharing service

Supporting Evidence:

Prefetch:
- PROCDUMP.EXE-*.pf (Last Run: 03:14:50) → LSASS dumping
- 7Z.EXE-*.pf (Last Run: 03:16:40) → Compression
- CHROME.EXE-*.pf (Last Run: 03:20:15) → Upload

Event Logs:
- EID 4688: procdump.exe executed by Bob at 03:14:50
- EID 4624: Network logons to DC01, FS01, EXCHANGE01

Network Logs:
- HTTPS POST to transfer.sh (03:20:33, 2.5 MB upload)

Timeline:
03:14 - LSASS memory dumped
03:16 - Credentials compressed
03:20 - File uploaded to transfer.sh
03:22 - Lateral movement begins (RDP sessions)

Conclusion:
Jump Lists provided critical timeline evidence:
- Credential theft workflow
- Data exfiltration method
- Lateral movement targets
- Complete attack reconstruction
```

#### Forensic Value Summary

**Strengths:**
- ✅ Application-specific file access
- ✅ Interaction counts (frequency)
- ✅ First/last access timestamps
- ✅ Deleted file evidence
- ✅ Network/removable media tracking
- ✅ Rich metadata (volume info, paths)

**Limitations:**
- ❌ No user attribution (profile-based inference)
- ❌ Hidden files (harder to access)
- ❌ Limited to supported applications
- ❌ Can be cleared/manipulated

**Best Used For:**
- Document access timeline
- Application usage patterns
- Deleted file discovery
- Network share access
- Lateral movement (RDP jump lists)
- Data exfiltration (archive tool usage)
- Cross-application correlation

---

### 7. Recycle Bin

#### Overview

**Description:** Temporary storage for deleted files. Windows creates two artifacts per deleted file: $I (metadata) and $R (file contents), enabling file recovery and deletion timeline analysis.

**Key Facts:**
- Each user has separate SID-based subfolder
- $I files contain original path and deletion timestamp
- $R files contain actual deleted file data
- Hidden system folder
- Persists until emptied or storage limit exceeded
- Available since Windows Vista (replaced INFO2)

#### Location
```
C:\$Recycle.Bin\[User-SID]\

Example Structure:
C:\$Recycle.Bin\
├── S-1-5-21-123...-1001\ (User 1)
│   ├── $IA1B2C3.xlsx (metadata)
│   ├── $RA1B2C3.xlsx (file content)
│   ├── $I4D5E6F.docx
│   └── $R4D5E6F.docx
└── S-1-5-21-123...-1002\ (User 2)
    ├── $I7G8H9I.pdf
    └── $R7G8H9I.pdf
```

#### File Naming Convention
```
Format: $[I or R][6-character-random-ID][.ext]

$I = Metadata file (information)
$R = Renamed copy of deleted file (recovery)

Both use same 6-character identifier:

Example:
$RA1B2C3.xlsx = Deleted Excel file (recoverable data)
$IA1B2C3.xlsx = Metadata about that Excel file

The extension matches the original file type
```

#### $I File Metadata Structure
```
Offset 0x00: Version (8 bytes) - Always 2 on Vista+
Offset 0x08: Original file size (8 bytes)
Offset 0x10: Deletion timestamp (8 bytes, FILETIME format)
Offset 0x18: Original file path (variable length, Unicode)

Example:
Version: 2
Size: 1,048,576 bytes (1 MB)
Deleted: 2024-03-15 14:32:18 UTC
Original Path: C:\Users\Bob\Documents\Financial_Records\2024_Budget.xlsx
````

**Tools for Analysis**

**RBCmd (Eric Zimmerman) - Command Line:**

powershell

```powershell
# Single $I file analysis
RBCmd.exe -f "C:\$Recycle.Bin\S-1-5-21-...\$IA1B2C3.xlsx"

# Entire user's Recycle Bin
RBCmd.exe -d "C:\$Recycle.Bin\S-1-5-21-123...-1001" -q --csv "G:\Output" --csvf recycle_user1.csv

# All users' Recycle Bins
RBCmd.exe -d "C:\$Recycle.Bin\" -q --csv "G:\Output" --csvf all_recycle_bins.csv

# With full metadata extraction
RBCmd.exe -d "C:\$Recycle.Bin\" --csv "G:\Output" --csvf recycle.csv -q
```

**Command Line (Manual Analysis):**

cmd

```cmd
:: View Recycle Bin structure (show hidden/system files)
dir /a C:\$Recycle.Bin

:: Navigate to specific user SID
cd C:\$Recycle.Bin\S-1-5-21-123456789-123456789-123456789-1001

:: List all deleted files
dir /a

:: View metadata (hex dump - not human-readable)
type $IA1B2C3.xlsx

:: Recover file by copying $R file
copy $RA1B2C3.xlsx C:\Cases\Evidence\recovered_budget.xlsx
```

**PowerShell (Live Analysis):**

powershell

```powershell
# View all Recycle Bin contents
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force

# Find all $I metadata files
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -Filter '$I*'

# Count deleted items per user
Get-ChildItem 'C:\$Recycle.Bin' -Directory -Force | 
  ForEach-Object {
    $sid = $_.Name
    $count = (Get-ChildItem $_.FullName -Filter '$I*' -Force | Measure-Object).Count
    [PSCustomObject]@{
      UserSID = $sid
      DeletedItems = $count
    }
  }

# Find large deleted files (>10MB)
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -Filter '$R*' | 
  Where-Object {$_.Length -gt 10MB} |
  Select-Object Name, Length, LastWriteTime
```

**Rifiuti2 (Open Source):**

bash

```bash
# Windows
rifiuti-vista.exe -o output.csv "C:\$Recycle.Bin\S-1-5-21-...\$I*"

# Linux (forensic images)
rifiuti-vista -x -o output.xml /path/to/$Recycle.Bin/S-1-5-21-.../
```

**Interpretation Guide**

**SID to Username Mapping:**

powershell

````powershell
# Live system
wmic useraccount get name,sid

Output Example:
Name             SID
Administrator    S-1-5-21-123...-500
Bob              S-1-5-21-123...-1001
Alice            S-1-5-21-123...-1002

# Offline (Registry - SAM hive)
1. Load SAM hive in Registry Explorer
2. Navigate: SAM\Domains\Account\Users\Names
3. Map username to RID
4. Construct full SID: S-1-5-21-{domain-id}-{RID}
```

**What Gets Recycled:**
```
✅ Files deleted via Windows Explorer
✅ Files deleted via right-click > Delete
✅ Files deleted via Delete key
✅ Files moved to Recycle Bin programmatically (some apps)

❌ Files deleted with Shift+Delete (bypass bin)
❌ Files deleted from command line (del, rm)
❌ Files on network shares (not recycled)
❌ Files on removable media (usually not recycled)
❌ Files deleted by applications directly
❌ Files exceeding Recycle Bin size limit
```

**Size Limits:**
```
Default: ~5-10% of drive capacity per user
Configurable: Group Policy, local settings

Example:
500 GB Drive → ~25-50 GB Recycle Bin capacity
When limit exceeded: Oldest items permanently deleted (FIFO)

Check Limit:
Right-click Recycle Bin > Properties
```

#### Investigation Patterns

**Pattern 1: Mass Deletion (Cleanup)**
```
Timeline Example:
14:30:15 - evidence.txt deleted
14:30:18 - passwords.txt deleted
14:30:22 - screenshots.png deleted
14:30:25 - toolkit.zip deleted
14:30:28 - confidential.docx deleted
[... 50+ files in 5 minutes ...]

Analysis:
✗ Multiple files deleted rapidly
✗ Same file types or from same folder
✗ Systematic cleanup pattern
✗ Possible evidence destruction

Investigation:
1. Identify common folder source
2. Check what's still in Recycle Bin
3. VSS for files before deletion
4. USN Journal for complete deletion timeline
5. Prefetch for cleaning tools or scripts
```

**Pattern 2: Selective Deletion**
```
Timeline Example:
Mar 10 - Normal file deletion (work files)
Mar 11 - Normal file deletion
Mar 12 - Normal file deletion
Mar 15 18:30 - customer_database.xlsx deleted
Mar 15 18:32 - financial_records.zip deleted
Mar 15 18:35 - passwords.txt deleted
Mar 16 - Normal file deletion resumes

Analysis:
✓ Specific sensitive files targeted
✓ Long gaps between sensitive deletions
✓ Strategic removal suggests intent
✓ Different pattern from normal behavior

Investigation:
1. Identify why these specific files
2. Check for prior access (LNK, Jump Lists)
3. Timeline correlation with other events
4. Check for exfiltration before deletion
```

#### Investigator Notes

**File Recovery Priority:**
```
High-Value Files to Recover:

Data Files:
- .pst, .ost (Email archives)
- .kdbx, .kdb (Password databases)
- .xlsx, .xls (Financial data)
- .docx, .doc (Contracts, reports)
- .db, .sqlite, .mdb (Databases)

Evidence Files:
- .txt, .log (Text logs)
- .jpg, .png (Screenshots, images)
- .pcap (Network captures)
- .dmp (Memory dumps)

Staging Files:
- .zip, .rar, .7z (Archived data)
- backup.*, *.bak (Backups)
- ToDelete folders

Recovery Process:
1. Identify $R file of interest
2. Copy to analysis workstation
3. Rename with proper extension
4. Verify file integrity (hash, magic bytes)
5. Analyze contents
```

**Timeline Correlation:**
```
Recycle Bin + MFT:
- MFT: When file originally created
- Recycle Bin: When file deleted
- Gap: How long file existed

Recycle Bin + USN Journal:
- USN: Complete file operation history
- Recycle Bin: Deletion endpoint
- Combined: Full file lifecycle

Recycle Bin + Event Logs:
- Event: User logon sessions
- Recycle Bin: Deletion during session
- Analysis: Who deleted what when
```

#### Anti-Forensics Detection

**Technique 1: Recycle Bin Emptying**
```
Attack Method:
- Right-click Recycle Bin > Empty
- Automated scripts
- Privacy tools (CCleaner)

Detection:
1. Empty Recycle Bin on active system (suspicious)
2. Check VSS for previous Recycle Bin state
3. Prefetch for privacy tools
4. Event logs (if auditing configured)
5. USN Journal deletion entries

Recovery:
- Mount Volume Shadow Copies
- Extract historical $Recycle.Bin contents
- Parse with RBCmd
- Identify what was deleted then emptied
```

**Technique 2: Shift+Delete (Bypass Bin)**
```
Attack Method:
- Shift+Delete bypasses Recycle Bin
- File immediately "deleted" (MFT marked)

Detection:
1. File absent from Recycle Bin but MFT shows deletion
2. USN Journal: FILE_DELETE without Recycle Bin
3. No $I/$R files for known deleted item

Evidence:
- MFT: File metadata preserved
- USN Journal: Deletion timestamp
- File carving: Possible data recovery

Red Flag:
User pattern changes from normal deletion to Shift+Delete
```

**Technique 3: Command-Line Deletion**
```
Commands:
del /f /q filename.txt
rm -rf /path/to/folder
PowerShell: Remove-Item -Force

Detection:
1. Prefetch: CMD.EXE-*.pf, POWERSHELL.EXE-*.pf
2. Event 4688: Process creation with command line
3. PowerShell logs: Script block logging
4. USN Journal: Deletion without Recycle Bin entries

Analysis:
- Command line shows intentional bypass
- Prefetch shows execution timing
- Pattern indicates technical sophistication
```

**Technique 4: Secure Deletion Tools**
```
Tools:
- SDelete (Sysinternals)
- Eraser
- Cipher /w

Detection:
1. Prefetch: SDELETE.EXE-*.pf, ERASER.EXE-*.pf
2. USN Journal: Multiple overwrite operations
3. File carving: Random data (unrecoverable)
4. Browser history: Secure deletion tool downloads

Impact:
- File data UNRECOVERABLE (multiple overwrites)
- File names preserved in MFT, USN Journal
- Tool execution is evidence of intent

Example:
$I file shows: secret_document.docx deleted Mar 15
$R file: Unrecoverable (overwritten)
Prefetch: SDELETE64.EXE-*.pf executed Mar 15
→ File name proves sensitive data, even if contents gone
```

#### Volume Shadow Copy Analysis

**High-Value VSS Investigation:**
```
Process:
1. List available shadow copies:
   vssadmin list shadows

2. Mount shadow copy:
   mklink /d C:\VSS \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\

3. Parse historical Recycle Bin:
   RBCmd.exe -d "C:\VSS\$Recycle.Bin" --csv "G:\VSS_Output" --csvf vss_recycle.csv

4. Compare current vs. historical:
   - Identify files in VSS but not current (emptied)
   - Timeline: When files were deleted, when bin emptied
   - Recovery: Extract $R files from VSS

Value:
✓ Recover deleted evidence even after bin emptied
✓ Timeline of anti-forensic activity
✓ Identify systematic cleanup patterns
```

#### Correlation Strategy

**Recycle Bin Tells You:**
- ✅ Original file name and path
- ✅ Deletion timestamp (precise)
- ✅ File size
- ✅ User who deleted (via SID)
- ✅ File contents (recoverable via $R)

**Does NOT Tell You:**
- ❌ Why file was deleted
- ❌ Application that deleted file
- ❌ Files deleted via Shift+Delete
- ❌ Command-line deletions

**Verify With:**
- **MFT:** File creation, original location, attributes
- **USN Journal:** Complete file operation history
- **ShellBags:** Folder navigation before deletion
- **LNK Files:** Recent file access before deletion
- **Prefetch:** Application execution (cleaners, scripts)
- **Event Logs:** User logon sessions

**Example Correlation:**
```
Scenario: Employee data theft before resignation

Recycle Bin Analysis (Current): EMPTY

VSS Analysis (Shadow Copy from 2 days ago):

$I Entries Found:
1. $IA1B2C3.xlsx
   Original: C:\Users\employee\Documents\CustomerDB_Export.csv
   Deleted: 2024-03-18 16:45:33
   Size: 15,728,640 bytes (15 MB)

2. $I4D5E6F.zip
   Original: C:\Users\employee\Documents\DB_Backup_2024.zip
   Deleted: 2024-03-18 16:46:02
   Size: 52,428,800 bytes (50 MB)

3. $I7G8H9I.xlsx
   Original: C:\Users\employee\Desktop\contacts.xlsx
   Deleted: 2024-03-18 16:47:15
   Size: 2,097,152 bytes (2 MB)

Cross-Reference:

ShellBags:
- E:\ (USB "SANDISK_64GB") accessed 16:30-16:40

USB Logs:
- SANDISK_64GB connected 16:30, disconnected 16:50

Timeline:
16:30 - USB connected
16:40 - Files copied to USB (ShellBags shows E:\ access)
16:45-47 - Files deleted to Recycle Bin (staging cleanup)
17:00 - Recycle Bin emptied (anti-forensics)
17:15 - USB disconnected

Recovery:
1. Carved $R files from VSS
2. Recovered CustomerDB_Export.csv (complete customer list)
3. Recovered DB_Backup_2024.zip (database credentials inside)
4. Recovered contacts.xlsx (client information)

Conclusion:
- Recycle Bin (via VSS) proved data theft
- Timeline: Copy to USB → Delete originals → Empty bin
- Anti-forensics: Attempted evidence destruction
- Recovery successful: Files retrieved from VSS
````

**Forensic Value Summary**

**Strengths:**

* ✅ Original file name and full path
* ✅ Precise deletion timestamp
* ✅ File size information
* ✅ User attribution (via SID)
* ✅ File contents recoverable (via $R)
* ✅ Timeline reconstruction
* ✅ VSS recovery possible

**Limitations:**

* ❌ Shift+Delete bypasses bin
* ❌ Command-line deletions bypass bin
* ❌ Network shares not recycled
* ❌ Can be emptie

<br>
