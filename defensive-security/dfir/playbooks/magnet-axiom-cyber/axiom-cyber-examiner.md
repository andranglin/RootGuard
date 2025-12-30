# Axiom Cyber Examiner

### Comprehensive Windows DFIR Analysis Guide

_**For Digital Forensics and Incident Response Professionals**_

_**Note**: Aligned with MITRE ATT\&CK Framework and NIST SP 800-86_

## 1. Introduction and Case Setup

Magnet AXIOM Examine is an industry-leading digital forensics platform that enables investigators to analyse evidence from computers, mobile devices, cloud services, and vehicles within a unified case file. This guide provides DFIR analysts with comprehensive procedures for Windows-based investigations, from initial case setup through advanced analysis techniques.

### 1.1 Opening and Configuring a Case

Before beginning analysis, ensure your case is properly configured for optimal investigation efficiency:

* **Load Case:** Open your processed .mfdb file via File > Open Case
* **Verify Evidence Sources:** Confirm all evidence items appear in the Evidence Sources panel
* **Configure Time Zone:** Set the appropriate time zone (Tools > Options > Time Zone) to match the source system or use UTC for multi-timezone investigations
* **Enable Hash Verification:** Validate evidence integrity against known good hash databases (NSRL, HashKeeper)
* **Review Dashboard:** Check artifact categories to scope the investigation: Windows Artefacts, PowerShell, Event Logs, Operating System, and Web Related

### 1.2 Key Interface Views

<table data-header-hidden><thead><tr><th width="190" valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>View</strong></td><td valign="top"><strong>Purpose and Usage</strong></td></tr><tr><td valign="top">Artifact Explorer</td><td valign="top">Primary analysis view displaying parsed artifacts organized by category (Registry, Prefetch, Event Logs, etc.). Use for structured artifact review.</td></tr><tr><td valign="top">File System Explorer</td><td valign="top">Raw file system access including deleted files, unallocated space, and system directories. Essential for manual examination and recovery of non-parsed data.</td></tr><tr><td valign="top">Timeline</td><td valign="top">Chronological visualization of all timestamped events. Critical for establishing sequences of activities and identifying anomalies.</td></tr><tr><td valign="top">Connections</td><td valign="top">Entity relationship mapping showing links between users, devices, files, and activities. Use for visual correlation of evidence.</td></tr><tr><td valign="top">Registry Explorer</td><td valign="top">Direct registry hive examination with search and export capabilities. Access via Artifact Explorer > Windows > Registry.</td></tr></tbody></table>

## 2. Windows Artifact Deep Dive

Windows forensic artefacts provide critical evidence for reconstructing user activities, detecting malicious behaviour, and establishing event timelines. The following sections detail each major artefact category, with analysis guidance aligned with common investigation scenarios.

### 2.1 Windows Registry Analysis

The Windows Registry serves as a centralised database storing configuration settings, user preferences, and system metadata. It is one of the most valuable forensic resources because it records extensive information about system and application configurations, user activities, and potentially malicious modifications.

#### Registry Hive Locations and Forensic Value

<table data-header-hidden><thead><tr><th width="159" valign="top"></th><th valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Hive</strong></td><td valign="top"><strong>Location</strong></td><td valign="top"><strong>Forensic Value</strong></td></tr><tr><td valign="top">SAM</td><td valign="top">C:\Windows\System32\config\SAM</td><td valign="top">Local user accounts, password hashes, account creation dates, last login times</td></tr><tr><td valign="top">SYSTEM</td><td valign="top">C:\Windows\System32\config\SYSTEM</td><td valign="top">USB device history, computer name, time zone, services configuration, Shimcache</td></tr><tr><td valign="top">SOFTWARE</td><td valign="top">C:\Windows\System32\config\SOFTWARE</td><td valign="top">Installed software, OS version, NetworkList (WiFi history), Amcache</td></tr><tr><td valign="top">SECURITY</td><td valign="top">C:\Windows\System32\config\SECURITY</td><td valign="top">Security policies, LSA secrets, cached credentials</td></tr><tr><td valign="top">NTUSER.DAT</td><td valign="top">C:\Users\&#x3C;username>\NTUSER.DAT</td><td valign="top">User-specific settings, RecentDocs, TypedPaths, RunMRU, UserAssist</td></tr><tr><td valign="top">UsrClass.dat</td><td valign="top">C:\Users\&#x3C;username>\AppData\Local\Microsoft\Windows\UsrClass.dat</td><td valign="top">ShellBags (folder access history), file type associations</td></tr><tr><td valign="top">Amcache.hve</td><td valign="top">C:\Windows\AppCompat\Programs\Amcache.hve</td><td valign="top">Program execution with SHA1 hashes, first execution timestamps, file paths</td></tr></tbody></table>

#### Critical Registry Keys for DFIR

**Program Execution Evidence:**

* **UserAssist:** NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist - ROT13 encoded program execution with run counts and timestamps
* **MUICache:** NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MUICache - Executed programs with friendly names
* **AppCompatCache (Shimcache):** SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache - Program execution history (note: execution not guaranteed on all Windows versions)

**Persistence Mechanisms (MITRE ATT\&CK T1547.001):**

* **Run Keys:** HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run, RunOnce, RunOnceEx
* **Services:** HKLM\SYSTEM\CurrentControlSet\Services - Check for suspicious ImagePath values
* **Winlogon:** HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, Userinit
* **Scheduled Tasks:** HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache

**USB Device History:**

* **USBSTOR:** SYSTEM\CurrentControlSet\Enum\USBSTOR - Device vendor, product, serial number, first/last connection
* **MountedDevices:** SYSTEM\MountedDevices - Maps device signatures to drive letters
* **MountPoints2:** NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 - User-specific mount points

### 2.2 Windows Event Log Analysis

Windows Event Logs provide a chronological record of system, security, and application events. They are essential for detecting unauthorised access, tracking user activities, identifying malicious behaviour, and reconstructing incident timelines. Event logs are stored as .evtx files in C:\Windows\System32\winevt\Logs\\.

#### Critical Security Event IDs

<table data-header-hidden><thead><tr><th width="114" valign="top"></th><th width="224" valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Event ID</strong></td><td valign="top"><strong>Event Name</strong></td><td valign="top"><strong>Forensic Significance</strong></td></tr><tr><td valign="top">4624</td><td valign="top">Successful Logon</td><td valign="top">User authentication success. Check Logon Type: 2=Interactive, 3=Network, 7=Unlock, 10=RemoteInteractive (RDP)</td></tr><tr><td valign="top">4625</td><td valign="top">Failed Logon</td><td valign="top">Authentication failure. High volume may indicate brute force or password spraying attacks</td></tr><tr><td valign="top">4648</td><td valign="top">Explicit Credential Logon</td><td valign="top">Logon using explicit credentials (RunAs). Often seen in lateral movement or credential abuse</td></tr><tr><td valign="top">4672</td><td valign="top">Special Privileges Assigned</td><td valign="top">Administrative logon. Critical for tracking privilege escalation and admin activities</td></tr><tr><td valign="top">4688</td><td valign="top">Process Creation</td><td valign="top">New process started (requires audit policy). Shows parent process, command line if enabled</td></tr><tr><td valign="top">4697</td><td valign="top">Service Installed</td><td valign="top">New service installation. Common persistence mechanism (MITRE T1543.003)</td></tr><tr><td valign="top">4698</td><td valign="top">Scheduled Task Created</td><td valign="top">New scheduled task. Common persistence technique used by threat actors</td></tr><tr><td valign="top">4720</td><td valign="top">User Account Created</td><td valign="top">New local account creation. May indicate attacker persistence via account creation</td></tr><tr><td valign="top">4732</td><td valign="top">Member Added to Group</td><td valign="top">User added to security group. Watch for additions to Administrators, RDP Users</td></tr><tr><td valign="top">4776</td><td valign="top">Credential Validation</td><td valign="top">NTLM credential validation attempt. Useful for detecting pass-the-hash attacks</td></tr><tr><td valign="top">7045</td><td valign="top">Service Installed (System)</td><td valign="top">System log service installation. Check ServiceFileName for suspicious paths</td></tr><tr><td valign="top">1102</td><td valign="top">Audit Log Cleared</td><td valign="top">Security log was cleared. Strong indicator of anti-forensic activity</td></tr></tbody></table>

#### Additional Critical Event Logs

**PowerShell Logging (Microsoft-Windows-PowerShell/Operational):**

* **Event ID 4103:** Module logging - captures pipeline execution details
* **Event ID 4104:** Script Block logging - captures full PowerShell scripts executed (critical for malware analysis)

**Remote Desktop Services:**

* **Event ID 1149 (RemoteConnectionManager):** Successful RDP authentication
* **Event ID 21 (LocalSessionManager):** Session logon succeeded
* **Event ID 24 (LocalSessionManager):** Session disconnected
* **Event ID 25 (LocalSessionManager):** Session reconnected

**Windows Defender (Microsoft-Windows-Windows Defender/Operational):**

* **Event ID 1116:** Malware detected
* **Event ID 1117:** Action taken on malware
* **Event ID 5001:** Real-time protection disabled

### 2.3 Program Execution Artifacts

Understanding program execution is fundamental to DFIR investigations. Multiple artifacts collectively provide evidence of what programs ran, when they executed, and their associated files.

#### Prefetch Files

**Location:** C:\Windows\Prefetch\\\*.pf&#x20;

**Forensic Value:** Provides program execution evidence including executable name, execution count (up to 8 timestamps on Windows 8+), files and directories accessed during execution, and volume information.

**Analysis Tips:**

* Filename format: EXECUTABLE.EXE-XXXXXXXX.pf (hash based on path and command line)
* Same executable from different paths creates separate prefetch files
* Check for suspicious locations: TEMP, APPDATA, RECYCLE.BIN, public shares
* Correlate with Amcache for SHA1 hash verification

#### Amcache.hve

**Location**: C:\Windows\AppCompat\Programs\Amcache.hve&#x20;

**Forensic Value:** Tracks executed applications with SHA1 hash, full file path, file size, compilation timestamp (PE TimeDateStamp), publisher information, and first execution time.

**Critical Fields in AXIOM:**

* **SHA1 Hash:** Cross-reference with VirusTotal, threat intelligence feeds
* **Key Last Write Time:** Indicates first program execution
* **File Path:** Identify execution from suspicious directories

#### Shimcache (AppCompatCache)

**Location**: SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache&#x20;

**Forensic Value:** Records executables that Windows checked for compatibility. Provides file path, file size, last modification time, and execution flag (Windows XP/2003 only).&#x20;

On modern Windows, presence indicates the file existed but not necessarily executed.

**Important**: Shimcache entries are written to the registry only upon system shutdown or reboot. Recent entries may only exist in memory until then.

#### SRUM (System Resource Usage Monitor)

**Location**: C:\Windows\System32\sru\SRUDB.dat&#x20;

**Forensic Value:** Windows 8+ artifact tracking application resource usage over 30-60 days: CPU time, network bytes sent/received, foreground/background time, and battery usage per application.

**Investigation Uses:**

* Identify data exfiltration (high network bytes sent by unusual applications)
* Detect cryptomining (sustained high CPU usage)
* Correlate network activity with specific applications

### 2.4 File and Folder Access Artifacts

#### LNK Files (Shortcut Files)

**Location**: C:\Users\\\<user>\AppData\Roaming\Microsoft\Windows\Recent\\&#x20;

**Forensic Value:** Created when users open files. Contains target file path, timestamps (creation, modification, access of target), file size, volume information (serial number, label), MAC address of host (if target on network), and working directory.

**Analysis Tips:**

* LNK files persist even after target files are deleted
* Network share access creates LNK files with embedded MAC addresses
* Check both the Recent folder and application-specific Recent folders

#### Jump Lists

**Location**: C:\Users\\\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ and CustomDestinations\\&#x20;

**Forensic Value:** Application-specific lists of recently accessed files. AutomaticDestinations are system-maintained; CustomDestinations are application-specific. Contains up to 15+ entries per application with full path and timestamps.

**Common AppID Values:**

* 5f7b5f1e01b83767 - Windows Explorer
* 1b4dd67f29cb1962 - Windows Explorer (pinned)
* a7bd71699cd38d1c - Notepad
* 9b9cdc69c1c24e2b - Notepad++

#### ShellBags

**Location**: NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU and Bags\\; UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\\&#x20;

**Forensic Value:** Records folder viewing preferences including folder paths accessed (even deleted folders), first and last access timestamps, folder view settings, and network/removable media paths.

**Critical for:**

* Proving user knowledge of folder contents
* Tracking access to removable media and network shares
* Recovering evidence of deleted folder access

#### $MFT (Master File Table)

**Location**: Root of NTFS volume (File System Explorer > $MFT)&#x20;

**Forensic Value:** Contains metadata for every file and folder on NTFS volume: filename, parent directory reference, $STANDARD\_INFORMATION timestamps (easily modified), $FILE\_NAME timestamps (harder to modify), file size, and $DATA attribute (resident data for small files).

**Timestamp Analysis:**

* **$STANDARD\_INFORMATION:** User-modifiable MACE timestamps (easily timestomped)
* **$FILE\_NAME:** System-controlled timestamps (compare to detect timestomping)
* $FN timestamp older than $SI timestamp = likely timestomping

### 2.5 Network and External Device Artifacts

#### USB Device Analysis

USB device forensics requires correlation across multiple registry keys and log sources to establish device identification, connection times, user association, and drive letter mapping.

<table data-header-hidden><thead><tr><th width="171" valign="top"></th><th valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Artifact</strong></td><td valign="top"><strong>Registry Location</strong></td><td valign="top"><strong>Information Provided</strong></td></tr><tr><td valign="top">USBSTOR</td><td valign="top">SYSTEM\CurrentControlSet\Enum\USBSTOR</td><td valign="top">Device vendor, product, version, serial number, first/last connection timestamps</td></tr><tr><td valign="top">USB (VID/PID)</td><td valign="top">SYSTEM\CurrentControlSet\Enum\USB</td><td valign="top">Vendor ID (VID) and Product ID (PID) for device identification</td></tr><tr><td valign="top">MountedDevices</td><td valign="top">SYSTEM\MountedDevices</td><td valign="top">Maps device signatures to drive letters and volume GUIDs</td></tr><tr><td valign="top">MountPoints2</td><td valign="top">NTUSER.DAT\...\Explorer\MountPoints2</td><td valign="top">User-specific mount point access (associates user with device)</td></tr><tr><td valign="top">DeviceClasses</td><td valign="top">SYSTEM\CurrentControlSet\Control\DeviceClasses</td><td valign="top">Additional device timestamps and identifiers</td></tr><tr><td valign="top">setupapi.dev.log</td><td valign="top">C:\Windows\INF\setupapi.dev.log</td><td valign="top">Device installation timestamps (first connection)</td></tr></tbody></table>

#### Network Connections and WiFi History

**Network Profile History:**

* **Location:** SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
* **Value:** SSID/network name, first and last connection dates, network type (public/private/domain)

**WLAN Event Logs:**

* **Event ID 8001:** Successfully connected to wireless network
* **Event ID 8002:** Failed to connect to wireless network
* **Event ID 8003:** Successfully disconnected from wireless network

#### BITS (Background Intelligent Transfer Service)

**Location**: C:\ProgramData\Microsoft\Network\Downloader\qmgr.db&#x20;

**Forensic Value:** BITS is commonly abused by malware for stealthy file downloads. Records contain source URL, destination path, job state, creation/modification times, and bytes transferred.

**Red Flag:** BITS jobs downloading from suspicious URLs (especially those downloading to TEMP, APPDATA, or non-standard locations) warrant immediate investigation.

## 3. Systematic Analysis Workflow

**Effective DFIR analysis requires a structured methodology.**&#x20;

The following workflow ensures comprehensive evidence collection while maintaining investigative efficiency.

### 3.1 Investigation Preparation

1. **Define Investigation Objectives:** Document specific questions to answer (e.g., "Did user X exfiltrate file Y via USB between dates A and B?")
2. **Identify Key Timeframe:** Establish the time window of interest based on incident reports or initial findings
3. **List Relevant Artifacts:** Based on objectives, identify which artifacts will provide relevant evidence
4. **Prepare Search Terms:** Compile keywords, file names, user accounts, IP addresses, and other identifiers

### 3.2 Initial Triage

* Review Dashboard artifact counts to prioritise analysis areas
* Check for anti-forensic indicators: cleared event logs (Event ID 1102), timestomping (MFT analysis), deleted prefetch files
* Identify user accounts and their SIDs from SAM and Security logs
* Establish system installation date and last boot time

### 3.3 Timeline Construction

AXIOM's Timeline view enables chronological analysis of all parsed artifacts. Effective timeline analysis requires:

* **Filter by Date Range:** Use the time filter to focus on the relevant period
* **Select Artifact Types:** Include Event Logs, Prefetch, LNK, USB artifacts, and file system events
* **Identify Pivot Points:** Look for the first evidence of compromise, lateral movement, or data access
* **Correlate Events:** Cross-reference timestamps across multiple artifact types

### 3.4 Correlation Using Connections

The Connections view enables visual mapping of relationships between entities:

* **Create Profiles:** Tag users, devices, and IP addresses as Profiles for entity tracking
* **Map Relationships:** Visualise links between users, files, USB devices, and network connections
* **Identify Clusters:** Look for unexpected connections that may indicate malicious activity

## 4. Advanced Analysis Techniques

### 4.1 Keyword and Pattern Searching

AXIOM supports both simple keyword searches and regular expressions for pattern matching:

* **Filename Patterns:** Search for specific files (e.g., "Q1Report\*", "\*.zip")
* **IP Addresses:** Use regex \b\d{1,3}\\.\d{1,3}\\.\d{1,3}\\.\d{1,3}\b
* **Base64 Encoded:** Search for potential encoded commands in PowerShell logs
* **USB Serials:** Use regex for serial number formats specific to device vendors

### 4.2 Anti-Forensic Detection

**Indicators of Anti-Forensic Activity:**

<table data-header-hidden><thead><tr><th width="191" valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Technique</strong></td><td valign="top"><strong>Detection Method in AXIOM</strong></td></tr><tr><td valign="top">Log Clearing</td><td valign="top">Event ID 1102 (Security Log Cleared); Check for gaps in sequential Event Record IDs; Unusual timestamps</td></tr><tr><td valign="top">Timestomping</td><td valign="top">Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps in MFT; $FN timestamp older than $SI indicates tampering</td></tr><tr><td valign="top">File Deletion</td><td valign="top">Check $MFT for orphaned entries; Search unallocated space; Review $Recycle.Bin; Analyze $I and $R files</td></tr><tr><td valign="top">Prefetch Deletion</td><td valign="top">MFT shows deleted .pf files; Cross-reference with Amcache/Shimcache for execution evidence</td></tr><tr><td valign="top">USN Journal Deletion</td><td valign="top">Abnormally small $UsnJrnl:$J; Gaps in USN sequence numbers</td></tr><tr><td valign="top">Registry Key Deletion</td><td valign="top">Examine transaction logs (.LOG1, .LOG2) for recently deleted keys</td></tr></tbody></table>

### 4.3 Memory Analysis Integration

When memory captures are available, analyse them alongside disk artifacts for comprehensive investigation:

* **Process List:** Compare running processes with Prefetch/Amcache to identify injected or hidden processes
* **Network Connections:** Active connections may reveal C2 communications not present in logs
* **Registry Hives:** In-memory registry may contain entries not yet written to disk (especially Shimcache)
* **Credential Extraction:** Memory may contain cleartext credentials or hashes

**Recommended External Tools:** Volatility3, MemProcFS for detailed memory analysis

### 4.4 Custom Artifact Development

AXIOM supports custom artifact definitions for parsing non-standard evidence sources:

* **Artifact Exchange:** Download community-contributed artifacts from Magnet's customer portal
* **Custom Parsers:** Create XML or Python-based artifacts for proprietary applications
* **SQLite Analysis:** Use SQLite Browser within AXIOM for manual database examination

## 5. Common Investigation Scenarios

### 5.1 Data Exfiltration Investigation

**Objective**: Determine if the user copied sensitive files to unauthorised media

**Evidence Collection Path:**

1. **User Authentication:** Security Event ID 4624 confirms user login with a timestamp
2. **File Access:** LNK files and Jump Lists show the file was opened/accessed
3. **Application Execution:** Prefetch for compression tools (WinRAR, 7zip) with timestamps
4. **USB Connection:** USBSTOR shows device serial and connection time
5. **User Association:** MountPoints2 links a specific user to USB device access
6. **File Transfer:** ShellBags shows the user navigated to the USB drive; SRUM shows the application data transfer

### 5.2 Malware Infection Analysis

**Objective**: Identify infection vector, persistence mechanisms, and scope of compromise

**Evidence Collection Path:**

1. **Initial Access:** Browser history, email attachments, download locations
2. **Execution Evidence:** Prefetch, Amcache with SHA1 hashes; cross-reference with threat intelligence
3. **Persistence:** Registry Run keys, Services (Event ID 7045), Scheduled Tasks (Event ID 4698)
4. **C2 Communication:** PowerShell logs (Event ID 4104), BITS jobs, network connections
5. **Lateral Movement:** Event ID 4648 (explicit credentials), RDP events, admin share access
6. **Privilege Escalation:** Event ID 4672 (special privileges), new service installations

### 5.3 Unauthorised Access Investigation

**Objective**: Identify unauthorised logons and attacker activities

**Key Analysis Areas:**

* **Failed Logons:** Event ID 4625 clusters indicating brute force attempts
* **Successful Logons:** Event ID 4624 from unexpected sources (check Logon Type, source IP)
* **Account Creation:** Event ID 4720 for new accounts created by the attacker
* **Group Modifications:** Event ID 4732 for accounts added to privileged groups
* **RDP Activity:** Event IDs 1149, 21, 24, 25 from TerminalServices logs
* **Pass-the-Hash:** Event ID 4776 with unusual source systems; correlate with 4624 Logon Type 3

## 6. Documentation and Reporting

### 6.1 Evidence Tagging Best Practices

* **Consistent Nomenclature:** Use standardised tag names (e.g., "EXFIL-USB", "MALWARE-PERSIST", "UNAUTH-ACCESS")
* **Document Reasoning:** Add comments explaining the significance of tagged evidence
* **Tag by Category:** Create tags for each phase of attack (Initial Access, Persistence, Exfiltration)
* **Include Negatives:** Tag evidence that disproves hypotheses for completeness

### 6.2 Report Generation

**AXIOM Report Contents:**

* **Case Information:** Case number, examiner, evidence sources, processing details
* **Executive Summary:** High-level findings for non-technical stakeholders
* **Detailed Findings:** Artefact-by-artefact analysis with screenshots and raw data
* **Timeline Visualisation:** Export Timeline view as PNG for visual representation
* **Supporting Data:** Export raw logs (Event Logs as EVTX, Registry hives) for verification

### 6.3 Portable Case for Collaboration

Create Portable Cases (.mfc files) to share evidence with stakeholders who don't have AXIOM licenses. Include all relevant tagged evidence and export as a self-contained package that recipients can review using the free AXIOM Examine viewer.

## 7. External Tool Integration

While AXIOM provides comprehensive analysis capabilities, some investigations benefit from specialised external tools:

<table data-header-hidden><thead><tr><th width="175" valign="top"></th><th width="211" valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Tool</strong></td><td valign="top"><strong>Purpose</strong></td><td valign="top"><strong>Integration with AXIOM</strong></td></tr><tr><td valign="top">Volatility3</td><td valign="top">Memory forensics</td><td valign="top">Export memory dumps from AXIOM; analyze process trees, network connections, registry hives in memory</td></tr><tr><td valign="top">RegRipper</td><td valign="top">Registry parsing</td><td valign="top">Export registry hives from File System Explorer; parse for additional context not parsed by AXIOM</td></tr><tr><td valign="top">Eric Zimmerman Tools</td><td valign="top">Specialized parsers</td><td valign="top">Use MFTECmd, PECmd, EvtxECmd for detailed parsing of specific artifacts; compare results with AXIOM</td></tr><tr><td valign="top">Plaso/Log2Timeline</td><td valign="top">Super timeline creation</td><td valign="top">Create comprehensive timelines from raw evidence for alternative timeline analysis</td></tr><tr><td valign="top">Timeline Explorer</td><td valign="top">CSV timeline analysis</td><td valign="top">Export AXIOM Timeline to CSV; analyze in Timeline Explorer for filtering and grouping</td></tr><tr><td valign="top">YARA</td><td valign="top">Malware detection</td><td valign="top">Run YARA rules against exported files to identify malware families</td></tr><tr><td valign="top">VirusTotal</td><td valign="top">Hash reputation</td><td valign="top">Export SHA1/MD5 hashes from Amcache; bulk query against VT for known malware</td></tr></tbody></table>

## 8. Quick Reference Tables

### 8.1 Logon Type Reference

<table data-header-hidden><thead><tr><th width="86" valign="top"></th><th width="166" valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Type</strong></td><td valign="top"><strong>Name</strong></td><td valign="top"><strong>Description</strong></td></tr><tr><td valign="top">2</td><td valign="top">Interactive</td><td valign="top">Local console logon (keyboard)</td></tr><tr><td valign="top">3</td><td valign="top">Network</td><td valign="top">Network logon (SMB, mapped drives); common in lateral movement</td></tr><tr><td valign="top">4</td><td valign="top">Batch</td><td valign="top">Scheduled task execution</td></tr><tr><td valign="top">5</td><td valign="top">Service</td><td valign="top">Service started by Service Control Manager</td></tr><tr><td valign="top">7</td><td valign="top">Unlock</td><td valign="top">Workstation unlock</td></tr><tr><td valign="top">8</td><td valign="top">NetworkCleartext</td><td valign="top">Network logon with cleartext credentials (IIS Basic Auth)</td></tr><tr><td valign="top">9</td><td valign="top">NewCredentials</td><td valign="top">RunAs with /netonly flag</td></tr><tr><td valign="top">10</td><td valign="top">RemoteInteractive</td><td valign="top">RDP/Terminal Services logon</td></tr><tr><td valign="top">11</td><td valign="top">CachedInteractive</td><td valign="top">Logon with cached credentials (domain controller unavailable)</td></tr><tr><td valign="top">12</td><td valign="top">CachedRemote</td><td valign="top">Remote interactive with cached credentials</td></tr><tr><td valign="top">13</td><td valign="top">CachedUnlock</td><td valign="top">Unlock with cached credentials</td></tr></tbody></table>

### 8.2 MITRE ATT\&CK Persistence Techniques Reference

<table data-header-hidden><thead><tr><th width="161" valign="top"></th><th valign="top"></th><th valign="top"></th></tr></thead><tbody><tr><td valign="top"><strong>Technique ID</strong></td><td valign="top"><strong>Technique Name</strong></td><td valign="top"><strong>Key Artifacts</strong></td></tr><tr><td valign="top">T1547.001</td><td valign="top">Registry Run Keys / Startup Folder</td><td valign="top">Registry Run keys, Startup folder LNK files</td></tr><tr><td valign="top">T1053.005</td><td valign="top">Scheduled Task</td><td valign="top">Event ID 4698, TaskCache registry, Task XML files</td></tr><tr><td valign="top">T1543.003</td><td valign="top">Windows Service</td><td valign="top">Event ID 7045, Services registry key</td></tr><tr><td valign="top">T1546.003</td><td valign="top">WMI Event Subscription</td><td valign="top">WMI repository, Event ID 5861</td></tr><tr><td valign="top">T1136.001</td><td valign="top">Local Account Creation</td><td valign="top">Event ID 4720, SAM hive</td></tr><tr><td valign="top">T1078</td><td valign="top">Valid Accounts</td><td valign="top">Event IDs 4624/4625, credential access artifacts</td></tr><tr><td valign="top">T1547.004</td><td valign="top">Winlogon Helper DLL</td><td valign="top">Winlogon registry keys</td></tr><tr><td valign="top">T1197</td><td valign="top">BITS Jobs</td><td valign="top">BITS database, Event ID 59/60</td></tr></tbody></table>

