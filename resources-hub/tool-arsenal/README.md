---
cover: ../../.gitbook/assets/RootGuardToolsLandingPage.png
coverY: 0
layout:
  width: default
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Tool Arsenal

## Operational Tooling for the Modern Defender

**Automate. Hunt. Eradicate.**

Manual forensics doesn't scale. RootGuard Operational Tooling bridges the gap between detection and remediation, providing battle-tested tools to accelerate triage, automate evidence collection, and execute deep-dive investigations.

This is not a script dump. This is a curated armoury of frameworks designed to function in hostile environments without deployment friction.

***

### The Arsenal

#### 🛡️ Custodian-HT

Comprehensive Threat Hunting & DFIR Suite

The flagship framework for high-intensity incident response. Custodian-HT is a modular ecosystem that automates the entire lifecycle of a hunt—from artifact collection to analysis and reporting.

* Capabilities:
  * Unified Analysis: Integrates KAPE, Hayabusa, Chainsaw, and YARA into a single workflow.
  * Remote Warfare: Execute hunts across Windows (WinRM/PSExec) and Linux (SSH) fleets.
  * Automated Intelligence: Built-in OSINT lookups (VirusTotal, AbuseIPDB) and Patch Tuesday vulnerability analysis.
  * Loki-RS Scanner: Rapid IOC scanning across distributed endpoints.

[View Repository](https://github.com/andranglin/Custodian-HT)

***

#### 🦁 Chimera

Rapid Triage & Acquisition Framework

Speed is the only metric that matters during a breakout. Chimera is a lightweight, agent-less triage engine designed to deploy, acquire, and vanish.

* Capabilities:
  * Agentless Architecture: "Zip & Ship" deployment via PowerShell and SSH. Zero footprint left behind.
  * Hybrid Targeting: Native support for both Windows (VSS, EZTools) and Linux ("The Goat" engine).
  * Precision Forensics: Targeted extraction of ShimCache, AmCache, and browser history (Chrome/Edge/Brave).
  * Volatile Data: Streamlined RAM capture using AVML with on-the-fly compression.

[View Repository](https://github.com/andranglin/Chimera)

***

#### 🐕 Cerberus

Deep-Dive Investigation Toolkit

When the alert is confirmed, Cerberus goes deep. This toolkit focuses on "Live Response" forensics, reconstructing the adversary's actions with granular precision.

* Capabilities:
  * Smart Memory Capture: Auto-detection of Secure Boot to select the correct acquisition method (Magnet vs. DumpIt).
  * Live Response Mode: Generates instant HTML reports on active processes, network connections, and user sessions.
  * Browser Forensics: Automated parsing of web history using Hindsight.
  * Volatility Integration: Built-in support for immediate memory analysis without leaving the framework.

[View Repository](https://github.com/andranglin/Cerberus)

***

### Which Tool Do You Need?

<table data-header-hidden><thead><tr><th></th><th width="215.3636474609375"></th><th></th></tr></thead><tbody><tr><td><strong>Scenario</strong></td><td><strong>Recommended Weapon</strong></td><td><strong>Why?</strong></td></tr><tr><td>"I need to hunt for a specific threat across the entire network."</td><td>Custodian-HT</td><td>Built for scale, integrated analysis, and heavy-duty hunting (Hayabusa/Chainsaw).</td></tr><tr><td>"I need to grab artifacts from a suspect endpoint immediately."</td><td>Chimera</td><td>Lightweight, fast, and requires no agent installation. Perfect for initial triage.</td></tr><tr><td>"I need to analyse a compromised host and get a memory dump."</td><td>Cerberus</td><td>Specialized for deep investigation, live response reporting, and memory forensics.</td></tr></tbody></table>

***

### Deployment & Safety

All tools in the RootGuard Arsenal are designed for authorised defensive use only.

* Open Source: Auditable code transparently hosted on GitHub.
* Modular: Use only what you need.
* Operational Security: Scripts are designed to minimise noise and clean up after execution.

_Always adhere to your organisation's legal and operational guidelines._
