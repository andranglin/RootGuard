# Cerberus: PowerShell DFIR Investigation Toolkit

**Cerberus-Triage (DFIR Toolkit):** [https://github.com/andranglin/Cerberus](https://github.com/andranglin/Cerberus)

### Introduction

**Cerberus** is a **modular, agentless PowerShell-based Digital Forensics and Incident Response (DFIR) toolkit** designed for rapid evidence collection, live analysis, and remote forensic acquisition on Windows systems.

It integrates leading industry-standard forensic tools (such as KAPE, E**ric Zimmerman's EZTools**, **Hindsight, Volatility 3,** and memory capture utilities) into a unified automation framework. Cerberus uses a "Zip & Ship" architecture over **WinRM** to deploy and execute tools remotely without installing persistent agents.

**Repository**: [https://github.com/andranglin/Cerberus](https://github.com/andranglin/Cerberus)\
**Author:** andranglin (part of the RootGuard ecosystem)\
**License:** MIT License\
**Primary Language:** PowerShell \
**Initial Release:** January, 2026\
**Important Note:** This tool is for **authorised forensic investigations only**. Ensure proper legal authorisation before use.

**Disclaimer:** Provided "as is" without warranty. The author is not responsible for misuse, damage, or legal consequences.

### Key Features

* Agentless Remote Acquisition — Executes collections via WinRM on remote Windows endpoints.
* Flexible Collection Modes — From quick live response to full forensic acquisition, including memory capture.
* Integrated Tools:
  * KAPE for targeted artifact collection.
  * EZTools for parsing Registry, Amcache, etc.
  * Hindsight for browser history analysis (Chrome/Edge).
  * Volatility 3 for immediate memory forensics.
  * Smart memory capture (Magnet RAM Capture for Secure Boot systems; DumpIt otherwise).
* Live Response — Rapid HTML reports of processes, network connections, and logged-on users.
* Unified Reporting — Generates interactive HTML triage reports linking all evidence.

### Prerequisites and Dependencies

Cerberus requires several external third-party tools (not included in the repo—download the latest versions manually):

* KAPE
* EZTools (Eric Zimmerman's toolkit)
* Hindsight
* Volatility 3
* Magnet RAM Capture (or DumpIt)

Place these in the Tools/ subdirectory as specified.

WinRM must be enabled on target systems for remote operations.

### Installation

1.  Clone the repository:

    ```bash
    powershell
    git clone https://github.com/andranglin/Cerberus.git
    cd Cerberus
    ```
2.  Run the initialisation script to create directories:

    ```powershell
    powershell
    .\Initialize-Cerberus.ps1
    ```
3. Download and populate the Tools/ folder:
   * Tools\EZTools\\
   * Tools\kape\\
   * Tools\hindsight\\
   * Tools\volatility3\\
   * Tools\MagnetRAMCapture\\
   * Tools\dumpit\\
4.  (Optional) Unblock scripts if needed:

    ```powershell
    powershell
    Get-ChildItem -Recurse *.ps1 | Unblock-File
    ```

### Usage

#### Interactive Console (Recommended)

Launch the menu-driven interface:

```bash
powershell
.\Cerberus_Console.ps1
```

Follow on-screen prompts to select targets and modes.

#### Remote Forensics

Perform collection on a remote host:

{% code overflow="wrap" %}
```powershell
powershell
$Creds = Get-Credential
.\Modules\Invoke-RemoteForensics.ps1 -TargetComputer "TARGET-HOST" -Credential $Creds -Mode 3
```
{% endcode %}

#### Collection Modes:

* Mode 1 (Triage): Standard artifacts + Browser History
* Mode 2 (Deep): Triage + Deep Registry + Amcache
* Mode 3 (Full): Everything + Memory Capture
* Mode 4 (Live): Quick live response only (processes, network, users)

#### Local Execution

Run individual modules directly on the analyst or suspect machine:

*   Artifact collection:

    ```powershell
    powershell
    .\Modules\Invoke-WinArtifacts.ps1 -OutputDir "C:\Evidence"
    ```
*   Memory capture:

    ```powershell
    powershell
    .\Modules\Invoke-MemoryCapture.ps1 -OutputDir "C:\Evidence"
    ```

Other modules include Invoke-KapeCollection.ps1, Invoke-LiveResponse.ps1, Invoke-Vol3Analysis.ps1, etc.

#### Directory Structure

```
Cerberus/
├── Cerberus_Console.ps1          # Interactive launcher
├── Initialize-Cerberus.ps1       # Setup script
├── Config/                       # Configuration files
├── Modules/                      # Core functionality
│   ├── Analyze-Results.ps1
│   ├── Invoke-KapeCollection.ps1
│   ├── Invoke-LiveResponse.ps1
│   ├── Invoke-MemoryCapture.ps1
│   ├── Invoke-RemoteForensics.ps1
│   ├── Invoke-Vol3Analysis.ps1
│   └── Invoke-WinArtifacts.ps1
└── Tools/                        # External binaries (user-populated)
```

#### Warnings and Best Practices

* Legal Authorisation Required: Only use on systems you are explicitly permitted to investigate.
* Verify compatibility of external tools with target OS (especially Secure Boot for memory capture).
* Evidence is collected in a forensically sound manner where possible, but always validate the chain of custody.
* The toolkit is newly released (January 2026) and may evolve rapidly.

For related tools and DFIR methodologies, see the Chimera (cross-platform triage) and RootGuard repositories.

This document serves as a starting guide for using Cerberus in authorised Windows DFIR engagements.
