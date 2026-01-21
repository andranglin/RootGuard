---
cover: ../../.gitbook/assets/image.jpg
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

# Tools How-To

## Operational Tooling Guides

#### Master the Instruments of Cyber Warfare

**Theory is useless without execution.**

This section is the technical field manual for the tools that define the battlefield. Whether you are hunting persistence in memory, mapping an adversary's perimeter, or living off the land, proficiency with these binaries is non-negotiable.

We do not provide "man page" summaries. We provide operational syntax—the exact flags, chains, and logic required to achieve effects in real-world environments.

***

[Select Your Weapon →](https://rootguard.gitbook.io/cyberops/resources-hub/tool-arsenal)

***

### The Philosophy of Tooling

In the hands of a novice, `nmap` is a noise generator. In the hands of an operator, it is a surgical scalpel. RootGuard "How-To" guides are structured to bridge the gap between basic usage and advanced tradecraft.

* **Dual-Use Reality:** Every tool listed here is a weapon for the Red Team and a sensor for the Blue Team. You must understand both perspectives to defend effectively.
* **Syntax Over Semantics:** We prioritise "copy-paste" operational one-liners that work under fire.

***

### Operational Modules

#### 🔬 Forensics & Artifact Analysis

Deep-dive inspection of compromised systems.

* [Volatility v3 Memory Forensics](https://rootguard.gitbook.io/cyberops/knowledge-base/tools-how-to/volatility-v3-memory-forensics)
  * Extract encryption keys, process handles, and network connections from RAM.
  * _Key Skills:_ Plugin selection, memory profile identification, malware extraction.

#### ⚔️ Offensive & Reconnaissance

Mapping the attack surface and validating vulnerabilities.

* [Nmap Scanning](https://rootguard.gitbook.io/cyberops/knowledge-base/tools-how-to/nmap-scanning)
  * Beyond `-sS`. Evasion techniques, NSE scripting, and service versioning.
* [SQLMap](https://rootguard.gitbook.io/cyberops/knowledge-base/tools-how-to/sqlmap)
  * Automating the detection and takeover of database clusters via injection.

#### 🛠️ Living off the Land (LOLBins)

Native binaries used for persistence, exfiltration, and evasion.

* [Linux Find Commands](https://rootguard.gitbook.io/cyberops/knowledge-base/tools-how-to/linux-find-commands)
  * The most underrated tool in Linux. Time-based hunting, SUID detection, and perm-bit analysis.
* [Netcat: Attack & Detection](https://rootguard.gitbook.io/cyberops/knowledge-base/tools-how-to/netcat-attack-and-detection-techniques)
  * The "Swiss Army Knife." Reverse shells, data exfiltration, and port scanning.
* [PowerShell Tradecraft](https://rootguard.gitbook.io/cyberops/knowledge-base/tools-how-to/powershell-attack-and-detection-techniques)
  * Execution policies, download cradles, and obfuscation detection.

***

### Why These Specific Tools?

We focus on the Universal Baselines. These are the tools that are:

1. **Ubiquitous**: Likely to be found pre-installed or easily deployed.
2. **Versatile**: Capable of multiple functions (scanning, exploiting, analysing).
3. **High-Impact**: Mastery of these few tools yields exponential operational capability.

***

"A tool is only as dangerous as the operator behind the keyboard."

_Authorised defensive and educational use only._
