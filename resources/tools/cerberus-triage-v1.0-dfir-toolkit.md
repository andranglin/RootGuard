---
hidden: true
---

# Cerberus Triage v1.0 (DFIR Toolkit)

## User Guide

### 1. Executive Summary

The RootGuard DFIR Toolkit is a PowerShell-based orchestration platform designed to streamline Digital Forensics and Incident Response (DFIR) workflows. It serves as a centralised "Command and Control" interface that unifies industry-standard forensic binaries—including KAPE, WinPMEM, Volatility 3, and Eric Zimmerman’s EZ Tools—into a single, easy-to-use console.

Core Value Proposition:

* Speed: Reduces triage time from hours to minutes.
* Privilege Management: Auto-checks for Administrator rights to ensure access to raw disk sectors (MFT/RAM).
* Flexibility: Supports surgical scripted collection, heavy forensic imaging, and volatile live response.
* Scale: Integrated remote deployment engine for network-wide investigations.

***

### 2. System Requirements & Architecture

#### Prerequisites

1. Operating System: Windows 10/11 or Windows Server 2016+.
2. Privileges: Local Administrator rights are mandatory. (Required for MFT parsing, Registry hive access, and RAM capture).
3. Dependencies:
   * PowerShell 5.1+ (Pre-installed on Windows 10+).
   * Python 3.x (Required on the _analyst workstation_ for Volatility 3).
   * WinRM (Required on _target endpoints_ for Remote Acquisition).

#### Directory Structure

The toolkit _must_ maintain this specific folder hierarchy to function. Do not rename files.

Plaintext

```bash
C:\RootGuard-DFIR\
├── WinAnalysis_Console.ps1       <-- [CONTROLLER] Main Launch Script
├── Invoke-WinArtifacts.ps1       <-- [MODULE] Standard Collector
├── Invoke-KapeCollection.ps1     <-- [MODULE] KAPE Wrapper
├── Invoke-MemoryCapture.ps1      <-- [MODULE] WinPMEM Wrapper
├── Invoke-Vol3Analysis.ps1       <-- [MODULE] Volatility 3 Wrapper
├── Invoke-LiveResponse.ps1       <-- [MODULE] Live Response
├── Invoke-RemoteForensics.ps1    <-- [MODULE] Remote Engine
├── Analyze-Results.ps1           <-- [MODULE] Report Generator
└── Tools\                        <-- [BINARIES]
    ├── winpmem.exe
    ├── hindsight.exe
    ├── kape\                     <-- KAPE Folder
    ├── volatility3\              <-- Volatility 3 Source
    └── ... (EZ Tools: MFTECmd, RECmd, PECmd, etc.)
```

***

### 3. Launch Instructions (Critical)

Because forensic tools access protected system areas (like physical memory and the MFT), standard security policies often block these scripts. You must launch the toolkit using specific flags.

#### Method 1: The "One-Liner" (Recommended)

Open PowerShell or Command Prompt as Administrator and run:

PowerShell

{% code overflow="wrap" %}
```ps1
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Maximized -File "C:\RootGuard-DFIR\WinAnalysis_Console.ps1"
```
{% endcode %}

Breakdown of Flags:

* `-ExecutionPolicy Bypass`: Temporarily ignores the system's script restriction policy (e.g., Restricted/RemoteSigned) for _this specific session only_. This is required to run the unsigned `.ps1` modules.
* `-NoProfile`: Prevents loading user profile scripts (like `$PROFILE`), ensuring a clean environment and faster startup.
* `-File`: Tells PowerShell to execute the toolkit wrapper.

#### Method 2: Creating a Permanent Desktop Shortcut

For rapid access in an emergency, create a shortcut that auto-elevates to Admin.

1. Right-click on your Desktop -> New -> Shortcut.
2.  Paste the following into the location box:

    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\RootGuard-DFIR\WinAnalysis\_Console.ps1"
3. Click Next, name it "RootGuard Toolkit", and click Finish.
4. Important: Right-click the new shortcut -> Properties -> Advanced... -> Check Run as Administrator.
5. Click OK -> OK.

_Now, simply double-clicking the icon will launch the toolkit with full forensic privileges._

***

### 4. User Guide: Operational Workflows

#### Scenario A: Standard Triage (The "Slow PC")

_Context: Suspicion of basic malware or unauthorised usage. Need quick answers._

1. Launch the toolkit.
2. Select Option \[1] Standard Triage.
3. The tool executes Hindsight (browser history), PECmd (Prefetch), and RECmd (Registry).
4. Result: Open `C:\Temp\RootGuard_Cases\Case-001`.
   * Check: `Browser_[User]\analysis.xlsx` (URLs visited).
   * Check: `Prefetch.csv` (Did a suspicious EXE run?).

#### Scenario B: Live Response & Memory (The "Active Breach")

_Context: A machine is communicating with a C2 server right now. You cannot shut it down yet._

1. Select Option \[3] Live Response.
   * Instantly captures volatile data without writing heavy files to disk.
   * Review: `Network_Connections.csv` (Look for "ESTABLISHED" to unknown IPs) and `Processes.csv` (Look for odd parent-child relationships).
2. Select Option \[4] Memory Ops -> \[1] Capture RAM.
   * Dumps physical RAM to `Memory.raw`.
3. Select Option \[4] Memory Ops -> \[2] Analyse Dump.
   * Uses Volatility 3 to find the malware hidden in RAM that isn't on the disk (`psscan`/`malfind`).

#### Scenario C: Remote Acquisition (The "Work from Home" User)

_Context: User is off-site on VPN. You need to collect evidence discreetly._

1. Select Option \[5] Remote Acquisition.
2. Enter the Hostname or IP and Admin Credentials.
3. Select Mode \[1] Standard Collection.
4. Process:
   * Toolkit pushes itself to `C:\Windows\Temp` on the target via WinRM.
   * Executes collection silently.
   * Zips and pulls evidence back to your machine.
   * Wipes traces from the target.

***

### 5. Artifact Reference & Tool Mapping

| **Forensic Artifact** | **Tool Used**        | **Question Answered**                                   |
| --------------------- | -------------------- | ------------------------------------------------------- |
| Filesystem ($MFT)     | `MFTECmd`            | "What files were created, deleted, or modified?"        |
| Execution             | `PECmd` (Prefetch)   | "Did `malware.exe` run? How many times?"                |
| User Activity         | `RECmd` (UserAssist) | "Did the user double-click `Payload.pdf`?"              |
| Browser History       | `Hindsight`          | "Did they visit `phishing-site.com`?"                   |
| Volatile Network      | `Live Response`      | "Is there an active connection to a C2 IP?"             |
| Rootkits              | `Volatility 3`       | "Are there hidden processes running in RAM?"            |
| Physical Memory       | `WinPMEM`            | "Can we recover passwords or encryption keys from RAM?" |

***

### 6. Benefits for the DFIR Professional

1. Defensible Process: By wrapping standard tools in a script, you ensure repeatability. Every case is collected exactly the same way, which is crucial for legal defensibility.
2. Tool Agnostic: The toolkit is a "Wrapper." If a better version of KAPE or Volatility is released, you replace the file in the `Tools` folder. The workflow remains unchanged.
3. Safety Rails: The `-ExecutionPolicy Bypass` and admin checks prevent junior analysts from failing to collect data due to permission errors.
4. Zero Footprint (Live Response): The Live Response module uses _only_ native PowerShell commands (WMI/CIM). It does not drop binaries, making it stealthy and less likely to trigger AV/EDR during an active investigation.
