# Cerberus-Triage Toolkit User Guide

**Cerberus-Triage (DFIR Toolkit):** [https://github.com/andranglin/Cerberus-Triage](https://github.com/andranglin/Cerberus-Triage)

***

### 1. Executive Summary

The RootGuard DFIR Toolkit is a PowerShell-based orchestration platform designed to streamline Digital Forensics and Incident Response (DFIR) workflows. It serves as a centralised orchestration console that unifies industry-standard forensic binaries—including KAPE, DumpIt, Volatility 3, and Eric Zimmerman’s EZ Tools—into a single, automated interface.

#### Core Value Proposition

* Speed: Reduces triage time from hours to minutes.
* Privilege Management: Auto-checks for Administrator rights to ensure access to protected raw disk sectors (MFT/RAM).
* Flexibility: Supports surgical scripted collection, heavy forensic imaging, and volatile live response.
* Scale: Integrated remote deployment engine for network-wide investigations via WinRM.

***

### 2. System Requirements & Architecture

#### Prerequisites

* Operating System: Windows 10/11 or Windows Server 2016+.
* Privileges: Local Administrator rights are required (for MFT parsing, Registry hive access, and RAM capture).
* Dependencies:
  * PowerShell 5.1+ (Pre-installed on all modern Windows OS).
  * Python 3.x (Required on the analyst workstation if using Volatility 3 source code).
  * WinRM (Required on target endpoints for Remote Acquisition modes).

#### Directory Structure

The toolkit relies on fixed relative paths. Do not rename the script files.

```bash
C:\RootGuard-DFIR\
├── WinAnalysis_Console.ps1       <-- [CONTROLLER] Main Launch Script
├── Invoke-WinArtifacts.ps1       <-- [MODULE] Standard Collector
├── Invoke-KapeCollection.ps1     <-- [MODULE] KAPE Wrapper
├── Invoke-MemoryCapture.ps1      <-- [MODULE] Memory Wrapper
├── Invoke-Vol3Analysis.ps1       <-- [MODULE] Volatility 3 Wrapper
├── Invoke-LiveResponse.ps1       <-- [MODULE] Live Response
├── Invoke-RemoteForensics.ps1    <-- [MODULE] Remote Engine
├── Analyze-Results.ps1           <-- [MODULE] Report Generator
└── Tools\                        <-- [BINARIES - POPULATE MANUALLY]
    ├── DumpIt.exe (or winpmem.exe)
    ├── hindsight.exe
    ├── KAPE\
    ├── Volatility3\
    └── EZTools\ (MFTECmd, RECmd, PECmd, etc.)
```

***

### 3. Launch Instructions (Critical)

Because forensic tools access protected system areas (like physical memory and the Master File Table), standard Windows security policies often block these scripts. You must launch the toolkit using specific flags.

#### Method 1: The "One-Liner" (Recommended)

Open PowerShell or Command Prompt as Administrator and run:

{% code overflow="wrap" %}
```bash
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Maximized -File "C:\RootGuard-DFIR\WinAnalysis_Console.ps1"
```
{% endcode %}

Breakdown of Flags:

* `-ExecutionPolicy Bypass`: Temporarily ignores the system's script restriction policy (e.g., Restricted) for this session only.
* `-NoProfile`: Prevents loading user profile scripts, ensuring a clean environment.
* `-File`: Executes the toolkit wrapper.

#### Method 2: Permanent Desktop Shortcut

For rapid access during an incident:

1. Right-click Desktop -> New -> Shortcut.
2.  Paste the following into the location box:

    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\RootGuard-DFIR\WinAnalysis\_Console.ps1"
3. Name it "RootGuard Toolkit".
4. Important: Right-click the new shortcut -> Properties -> Advanced -> Check Run as Administrator.

Now, double-clicking the icon will launch the toolkit with full forensic privileges.

***

### 4. Operational Workflows

#### Scenario A: Standard Triage (The "Slow PC")

Context: Suspicion of basic malware or unauthorised usage. You need quick answers about file execution and web history.

1. Launch the toolkit.
2. Select Option \[1] Standard Triage.
   * _Action:_ Executes Hindsight (Browser), PECmd (Prefetch), and RECmd (Registry).
3. Result: Open `C:\Temp\RootGuard_Cases\Case-[ID]`.
   * Check `Browser_[User]\analysis.xlsx` (URLs visited).
   * Check `Prefetch.csv` (Did a suspicious EXE run?).

#### Scenario B: Live Response & Memory (The "Active Breach")

Context: A machine is communicating with a C2 server _right now_. You cannot shut it down yet.

1. Select Option \[3] Live Response.
   * _Action:_ Instantly captures volatile data without writing heavy files to disk.
   * _Review:_ `Network_Connections.csv` (Look for "ESTABLISHED" to unknown IPs).
2. Select Option \[4] Memory Ops -> \[1] Capture RAM.
   * _Action:_ Dumps physical RAM to `Memory.raw`.
3. Select Option \[4] Memory Ops -> \[2] Analyse Dump.
   * _Action:_ Uses Volatility 3 to find malware hidden in RAM (psscan/malfind).

#### Scenario C: Remote Acquisition (The "Remote User")

**Context:** User is off-site on VPN. You need to collect evidence discreetly without disrupting them.

1. Select Option \[5] Remote Acquisition.
2. Enter the Hostname/IP and Admin Credentials.
3. Select Mode \[1] Standard Collection.
   * Push: Toolkit stages itself to `C:\Windows\Temp` on the target via WinRM.
   * Execute: Runs the collection silently in the background.
   * Retrieve: Zips and pulls evidence back to your machine.
   * Clean: Performs a secure cleanup of the target staging directory.

***

### 5. Artifact Reference & Tool Mapping

<table data-header-hidden><thead><tr><th width="173.5455322265625"></th><th width="177"></th><th></th></tr></thead><tbody><tr><td><strong>Forensic Artifact</strong></td><td><strong>Tool Used</strong></td><td><strong>Question Answered</strong></td></tr><tr><td>Filesystem ($MFT)</td><td>MFTECmd</td><td>"What files were created, deleted, or modified?"</td></tr><tr><td>Execution</td><td>PECmd (Prefetch)</td><td>"Did malware.exe run? How many times?"</td></tr><tr><td>User Activity</td><td>RECmd (UserAssist)</td><td>"Did the user double-click Payload.pdf?"</td></tr><tr><td>Browser History</td><td>Hindsight</td><td>"Did they visit phishing-site.com?"</td></tr><tr><td>Volatile Network</td><td>Live Response</td><td>"Is there an active connection to a C2 IP?"</td></tr><tr><td>Rootkits</td><td>Volatility 3</td><td>"Are there hidden processes running in RAM?"</td></tr><tr><td>Physical Memory</td><td>WinPMEM / DumpIt</td><td>"Can we recover passwords or keys from RAM?"</td></tr></tbody></table>
