# Chimera: PowerShell Incident Response Toolkit

### Introduction

Chimera is a modular, agent-less forensic triage framework designed specifically for Incident Response (IR) and Digital Forensics and Incident Response (DFIR) teams. It bridges the gap between rapid "Live Response" techniques and in-depth forensic analysis by orchestrating industry-standard tools through PowerShell and SSH.

The tool supports forensic acquisitions on both Windows and Linux endpoints without requiring persistent agents. It integrates popular open-source forensic tools to collect artifacts, capture memory, and perform triage efficiently.

**Repository:** [https://github.com/andranglin/Chimera](https://github.com/andranglin/Chimera)\
**License:** MIT License\
**Primary Language:** PowerShell \
**Important Note:** This tool is intended only for authorised forensic acquisition. Always ensure proper legal authorisation before use.

**Disclaimer**: The software is provided "as is" without warranty. The author is not responsible for any damage or legal issues arising from its use.

Chimera is part of the RootGuard ecosystem and links to additional DFIR resources in the [RootGuard GitBook documentation](https://rootguard.gitbook.io/cyberops).

### Key Features

#### Windows Forensics

* Shadow Copy (VSS) Access — Bypasses file locks to access and parse Registry hives, Event Logs, and filesystem artifacts.
* Eric Zimmerman Tools (EZTools) Integration — Natively executes tools for Amcache, Shimcache, Registry parsing, with direct CSV output.
* Browser Forensics — Automated parsing of Chrome, Edge, and Brave browser history and profiles using Hindsight.

#### Linux Forensics

* Zero-Footprint Triage — Deploys a static payload over SSH, executes in memory or /tmp, and self-cleans to minimise traces.
* "The Goat" Engine — Hybrid collection script combining RCSIRT and Cat-Scale methodologies for hunting webshells, rootkits, user history, Docker artifacts, databases, and more.
* Memory Acquisition — Remote RAM capture using Microsoft's AVML tool with on-the-fly compression for faster transfers.

#### Prerequisites and Dependencies

Chimera relies on several external third-party tools (not bundled in the repository to ensure you use the latest verified versions):

* EZTools (Eric Zimmerman's tools) — For Windows artifact parsing.
* AVML (Microsoft's memory acquisition tool) — For Linux RAM captures.
* Hindsight — For browser history analysis.

Detailed download links and setup instructions are provided in the repository's INSTALL.md file.

#### Installation

1.  Clone or download the repository from GitHub:

    ```bash
    git clone https://github.com/andranglin/Chimera.git
    ```
2. Follow the instructions in INSTALL.md to download and configure the required external tools (EZTools, AVML, Hindsight).
3. Place the external tools in the appropriate directories or configure paths as needed (refer to repository config).
4. Open PowerShell as Administrator.
5.  Unblock the PowerShell scripts (required only on first use):

    ```powershell
    powershell
    Get-ChildItem -Recurse | Unblock-File
    ```

#### Usage

Chimera is launched via its main PowerShell script.

#### Basic Launch

Navigate to the repository directory and run:

```bash
powershell
.\Chimera.ps1
```

This starts the launcher, which loads modules and provides an interface for selecting and executing triage tasks based on the target operating system.&#x20;

#### Core Modules&#x20;

The toolkit includes several key modules (invoked automatically or manually depending on configuration):

* Invoke-WinArtifacts — Collects Windows artifacts via VSS (Registry, Event Logs, ShimCache, etc.).
* Invoke-BrowserArtifacts — Parses browser data from supported browsers.
* Invoke-LinuxLiveResponse — Executes zero-footprint triage on Linux systems (system info, network, persistence mechanisms, webshells, etc.).
* Invoke-LinuxMemCapture — Captures and compresses RAM from Linux hosts over SSH.

Configuration files in the Config/ directory allow customisation of targets, modules, and output paths.&#x20;

#### Directory Structure Overview

* Chimera.ps1 — Main launcher script.
* Initialize-Chimera.ps1 — Environment setup and dependency checks.
* Modules/ — Individual PowerShell modules for specific tasks.
* Config/ — Configuration files for modules and targets.
* Tools/ — Wrappers or interfaces for external dependencies.
* INSTALL.md — Detailed dependency installation guide.

#### Warnings and Best Practices

* Use only on systems where you have explicit authorisation.
* The tool is in early stages (initial release: January 7, 2026).
* Verify external tool versions for compatibility and integrity.
* Review the RootGuard knowledge base for DFIR methodologies and artifact analysis playbooks.

For more advanced usage, methodologies, and updates, refer to the linked RootGuard documentation: https://rootguard.gitbook.io/cyberops.&#x20;

This document provides a comprehensive starting point for using Chimaera in authorised incident response scenarios.
