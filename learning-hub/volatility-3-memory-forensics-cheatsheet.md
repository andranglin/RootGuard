# Volatility 3 Memory Forensics Cheatsheet

### verview

Volatility 3 is an open-source memory forensics framework for analysing RAM dumps from Windows, Linux, and macOS systems. It extracts digital artifacts including running processes, network connections, loaded modules, registry data, and evidence of malicious activity.

***

### Core Syntax

```bash
vol -f <memory_image> <plugin> [options]
python3 vol.py -f <memory_image> <plugin> [options]
```

**Note:** Volatility 3 auto-detects the OS profile—no manual profile selection required (unlike Volatility 2).

***

### Learning Workflow

**Phase 1: Orientation** — Image info, process listing, basic triage\
**Phase 2: Process Analysis** — Deep dive into process artifacts\
**Phase 3: Memory Extraction** — Dump processes, DLLs, and memory regions\
**Phase 4: Artifact Hunting** — Registry, network, malware indicators\
**Phase 5: Advanced Analysis** — Rootkit detection, timeline, and correlation

***

### Installation & Setup

#### Installation

```bash
# Clone repository
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3

# Install dependencies
pip3 install -r requirements.txt

# Install as package (optional)
pip3 install -e .

# Verify installation
python3 vol.py -h
```

#### Symbol Tables

Volatility 3 requires symbol tables for accurate analysis. Download from:

* Windows: https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
* Linux: https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
* macOS: https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip

```bash
# Extract to volatility3/symbols/ directory
mkdir -p volatility3/symbols
unzip windows.zip -d volatility3/symbols/
unzip linux.zip -d volatility3/symbols/
```

#### Memory Acquisition Tools

| Tool       | Platform | Notes                        |
| ---------- | -------- | ---------------------------- |
| WinPMEM    | Windows  | Free, reliable               |
| FTK Imager | Windows  | GUI-based                    |
| DumpIt     | Windows  | Single executable            |
| LiME       | Linux    | Loadable kernel module       |
| AVML       | Linux    | Microsoft's acquisition tool |
| OSXPmem    | macOS    | Mac memory acquisition       |

***

### Phase 1: Orientation & Triage

#### Image Information

```bash
# Basic image info and OS detection
vol -f memory.dmp windows.info
vol -f memory.dmp linux.info
vol -f memory.dmp mac.info

# Verify image integrity
vol -f memory.dmp isfinfo
```

#### List Available Plugins

```bash
# Show all plugins
vol -f memory.dmp --help

# Filter by OS
vol --help | grep windows
vol --help | grep linux
```

#### Initial Process Listing

```bash
# Windows - basic process list
vol -f memory.dmp windows.pslist

# Windows - process tree (parent/child relationships)
vol -f memory.dmp windows.pstree

# Windows - scan for hidden/unlinked processes
vol -f memory.dmp windows.psscan

# Linux - process list
vol -f memory.lime linux.pslist

# Linux - process tree
vol -f memory.lime linux.pstree

# macOS - process list
vol -f memory.raw mac.pslist
```

#### Quick Triage Commands

```bash
# Network connections
vol -f memory.dmp windows.netstat
vol -f memory.dmp windows.netscan

# Command line arguments
vol -f memory.dmp windows.cmdline

# Environment variables
vol -f memory.dmp windows.envars

# Loaded DLLs
vol -f memory.dmp windows.dlllist
```

***

### Phase 2: Process Analysis

#### Process Listing Plugins

| Plugin            | Purpose                                     |
| ----------------- | ------------------------------------------- |
| `windows.pslist`  | List processes from EPROCESS linked list    |
| `windows.pstree`  | Display process parent/child hierarchy      |
| `windows.psscan`  | Scan for EPROCESS structures (finds hidden) |
| `windows.psxview` | Cross-reference multiple process sources    |

```bash
# Compare outputs to find hidden processes
vol -f memory.dmp windows.pslist > pslist.txt
vol -f memory.dmp windows.psscan > psscan.txt

# Processes in psscan but not pslist may be hidden/terminated
```

#### Process Details

```bash
# Command line arguments for all processes
vol -f memory.dmp windows.cmdline

# Command line for specific PID
vol -f memory.dmp windows.cmdline --pid 1234

# Environment variables
vol -f memory.dmp windows.envars
vol -f memory.dmp windows.envars --pid 1234

# Process privileges
vol -f memory.dmp windows.privileges
vol -f memory.dmp windows.privileges --pid 1234

# Security tokens
vol -f memory.dmp windows.getsids
```

#### DLL Analysis

```bash
# List loaded DLLs
vol -f memory.dmp windows.dlllist
vol -f memory.dmp windows.dlllist --pid 1234

# Scan for DLLs (finds unlinked)
vol -f memory.dmp windows.ldrmodules

# Detect DLL injection (unmapped DLLs)
vol -f memory.dmp windows.malfind
```

#### Handle Analysis

```bash
# List handles (files, registry, mutexes, etc.)
vol -f memory.dmp windows.handles
vol -f memory.dmp windows.handles --pid 1234

# Filter by handle type
vol -f memory.dmp windows.handles --pid 1234 | grep -i file
vol -f memory.dmp windows.handles --pid 1234 | grep -i key
vol -f memory.dmp windows.handles --pid 1234 | grep -i mutant
```

***

### Phase 3: Memory Extraction

#### Process Memory Dumps

```bash
# Dump process executable
vol -f memory.dmp windows.pslist --dump --pid 1234

# Dump all processes
vol -f memory.dmp windows.pslist --dump

# Dump specific process memory
vol -f memory.dmp windows.memmap --dump --pid 1234
```

#### DLL Extraction

```bash
# Dump DLLs from a process
vol -f memory.dmp windows.dlllist --dump --pid 1234

# Dump all DLLs
vol -f memory.dmp windows.dlllist --dump
```

#### Driver Extraction

```bash
# List kernel modules/drivers
vol -f memory.dmp windows.modules

# Dump driver files
vol -f memory.dmp windows.moddump
vol -f memory.dmp windows.moddump --base 0xfffff800xxxxx
```

#### Memory Regions

```bash
# Virtual address descriptors (memory map)
vol -f memory.dmp windows.vadinfo --pid 1234

# Walk VAD tree
vol -f memory.dmp windows.vadwalk --pid 1234

# Dump VAD regions
vol -f memory.dmp windows.vadyarascan --pid 1234

# Memory maps
vol -f memory.dmp windows.memmap --pid 1234
```

#### File Extraction

```bash
# Scan for file objects
vol -f memory.dmp windows.filescan

# Dump files by offset
vol -f memory.dmp windows.dumpfiles --virtaddr 0xXXXX
vol -f memory.dmp windows.dumpfiles --physaddr 0xXXXX

# Dump cached files
vol -f memory.dmp windows.dumpfiles
```

***

### Phase 4: Artifact Hunting

#### Network Analysis

```bash
# Active connections (Windows)
vol -f memory.dmp windows.netstat

# Network connection scan (includes closed)
vol -f memory.dmp windows.netscan

# Linux network connections
vol -f memory.lime linux.sockstat
```

**Network Output Fields**

| Field       | Description                 |
| ----------- | --------------------------- |
| Offset      | Memory address of structure |
| Proto       | Protocol (TCP/UDP)          |
| LocalAddr   | Local IP:Port               |
| ForeignAddr | Remote IP:Port              |
| State       | Connection state            |
| PID         | Associated process ID       |
| Owner       | Process name                |

#### Registry Analysis

{% code overflow="wrap" %}
```bash
# List registry hives
vol -f memory.dmp windows.registry.hivelist

# Print registry key
vol -f memory.dmp windows.registry.printkey
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Dump registry hive
vol -f memory.dmp windows.registry.hivescan

# User assist (program execution evidence)
vol -f memory.dmp windows.registry.userassist

# Get certificates
vol -f memory.dmp windows.registry.certificates
```
{% endcode %}

**Key Registry Locations**

{% code overflow="wrap" %}
```bash
# Persistence - Run keys
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\RunOnce"

# Services
vol -f memory.dmp windows.registry.printkey --key "SYSTEM\CurrentControlSet\Services"

# Recent documents
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# Typed URLs
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Internet Explorer\TypedURLs"
```
{% endcode %}

#### Service Analysis

```bash
# List Windows services
vol -f memory.dmp windows.svcscan

# Look for suspicious services
vol -f memory.dmp windows.svcscan | grep -i "unknown\|temp\|appdata"
```

#### Scheduled Tasks

```bash
# Scan for scheduled tasks
vol -f memory.dmp windows.scheduled_tasks
```

#### User Information

```bash
# Dump password hashes
vol -f memory.dmp windows.hashdump

# LSA secrets
vol -f memory.dmp windows.lsadump

# Cached domain credentials
vol -f memory.dmp windows.cachedump

# Get SIDs
vol -f memory.dmp windows.getsids
```

***

### Phase 5: Advanced Analysis

#### Malware Detection

{% code overflow="wrap" %}
```bash
# Detect code injection (PAGE_EXECUTE_READWRITE regions)
vol -f memory.dmp windows.malfind
vol -f memory.dmp windows.malfind --pid 1234

# Dump injected code
vol -f memory.dmp windows.malfind --dump

# YARA scanning
vol -f memory.dmp windows.yarascan --yara-rules "rule_file.yar"
vol -f memory.dmp yarascan.YaraScan --yara-rules "rule_file.yar"

# Scan for specific string
vol -f memory.dmp windows.yarascan --yara-rules "rule test { strings: \$a = \"malware\" condition: \$a }"
```
{% endcode %}

#### Rootkit Detection

```bash
# Compare process lists (hidden process detection)
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.psscan

# Driver scan (find hidden drivers)
vol -f memory.dmp windows.modules
vol -f memory.dmp windows.modscan

# SSDT hooks
vol -f memory.dmp windows.ssdt

# Callbacks
vol -f memory.dmp windows.callbacks

# Check for IDT hooks
vol -f memory.dmp windows.idt
```

#### Timeline Analysis

```bash
# Create timeline from multiple sources
vol -f memory.dmp timeliner.Timeliner

# Output in bodyfile format
vol -f memory.dmp timeliner.Timeliner --create-bodyfile
```

#### String Analysis

{% code overflow="wrap" %}
```bash
# Extract strings from process memory
vol -f memory.dmp windows.strings --pid 1234

# Search for specific strings
vol -f memory.dmp windows.yarascan --yara-rules "rule find { strings: \$s = \"password\" nocase condition: \$s }"

# Strings with physical offset
strings -a -t d memory.dmp > strings.txt
vol -f memory.dmp windows.strings --strings-file strings.txt
```
{% endcode %}

***

### Windows-Specific Plugins

#### Core Plugins

| Plugin               | Description                 |
| -------------------- | --------------------------- |
| `windows.info`       | OS and kernel information   |
| `windows.pslist`     | Process list (active)       |
| `windows.pstree`     | Process tree hierarchy      |
| `windows.psscan`     | Scan for processes (hidden) |
| `windows.cmdline`    | Process command lines       |
| `windows.envars`     | Environment variables       |
| `windows.dlllist`    | Loaded DLLs                 |
| `windows.handles`    | Open handles                |
| `windows.modules`    | Loaded kernel modules       |
| `windows.driverscan` | Scan for drivers            |

#### Memory & Extraction

| Plugin              | Description           |
| ------------------- | --------------------- |
| `windows.memmap`    | Process memory map    |
| `windows.vadinfo`   | VAD information       |
| `windows.vadwalk`   | Walk VAD tree         |
| `windows.dumpfiles` | Extract cached files  |
| `windows.filescan`  | Scan for file objects |
| `windows.moddump`   | Dump kernel modules   |

#### Registry & Credentials

| Plugin                        | Description          |
| ----------------------------- | -------------------- |
| `windows.registry.hivelist`   | List registry hives  |
| `windows.registry.printkey`   | Print registry key   |
| `windows.registry.userassist` | UserAssist data      |
| `windows.hashdump`            | Dump password hashes |
| `windows.lsadump`             | LSA secrets          |
| `windows.cachedump`           | Cached credentials   |

#### Network & Services

| Plugin                    | Description              |
| ------------------------- | ------------------------ |
| `windows.netstat`         | Active connections       |
| `windows.netscan`         | Scan network connections |
| `windows.svcscan`         | Windows services         |
| `windows.scheduled_tasks` | Scheduled tasks          |

#### Malware Analysis

| Plugin               | Description        |
| -------------------- | ------------------ |
| `windows.malfind`    | Find injected code |
| `windows.yarascan`   | YARA rule scanning |
| `windows.ssdt`       | SSDT hooks         |
| `windows.callbacks`  | Kernel callbacks   |
| `windows.ldrmodules` | DLL load analysis  |

***

### Linux-Specific Plugins

| Plugin                     | Description              |
| -------------------------- | ------------------------ |
| `linux.info`               | System information       |
| `linux.pslist`             | Process listing          |
| `linux.pstree`             | Process tree             |
| `linux.bash`               | Bash history             |
| `linux.check_afinfo`       | Network protocol hooks   |
| `linux.check_creds`        | Process credentials      |
| `linux.check_idt`          | IDT hooks                |
| `linux.check_modules`      | Module verification      |
| `linux.check_syscall`      | System call hooks        |
| `linux.elfs`               | ELF binaries in memory   |
| `linux.keyboard_notifiers` | Keyboard hooks           |
| `linux.lsmod`              | Loaded modules           |
| `linux.lsof`               | Open files               |
| `linux.malfind`            | Malicious memory regions |
| `linux.proc.maps`          | Process memory maps      |
| `linux.psaux`              | Process with arguments   |
| `linux.sockstat`           | Network connections      |
| `linux.tty_check`          | TTY hooks                |

#### Linux Workflow

```bash
# System info
vol -f memory.lime linux.info

# Process listing
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree

# Bash history
vol -f memory.lime linux.bash

# Network connections
vol -f memory.lime linux.sockstat

# Loaded kernel modules
vol -f memory.lime linux.lsmod

# Open files by process
vol -f memory.lime linux.lsof

# Check for rootkits
vol -f memory.lime linux.check_syscall
vol -f memory.lime linux.check_modules
vol -f memory.lime linux.check_idt
```

***

### macOS-Specific Plugins

| Plugin                 | Description         |
| ---------------------- | ------------------- |
| `mac.info`             | System information  |
| `mac.pslist`           | Process listing     |
| `mac.pstree`           | Process tree        |
| `mac.bash`             | Bash history        |
| `mac.check_syscall`    | System call hooks   |
| `mac.check_sysctl`     | Sysctl hooks        |
| `mac.check_trap_table` | Trap table hooks    |
| `mac.ifconfig`         | Network interfaces  |
| `mac.kauth_listeners`  | Kauth listeners     |
| `mac.kevents`          | Kevents             |
| `mac.lsmod`            | Loaded modules      |
| `mac.lsof`             | Open files          |
| `mac.malfind`          | Injected code       |
| `mac.mount`            | Mounted filesystems |
| `mac.netstat`          | Network connections |
| `mac.proc_maps`        | Process memory maps |
| `mac.psaux`            | Process arguments   |
| `mac.socket_filters`   | Socket filters      |
| `mac.timers`           | Kernel timers       |
| `mac.trustedbsd`       | TrustedBSD hooks    |

***

### Investigation Workflows

#### Malware Triage Workflow

{% code overflow="wrap" %}
```bash
# 1. Get system info
vol -f memory.dmp windows.info

# 2. List processes (look for anomalies)
vol -f memory.dmp windows.pstree

# 3. Check for hidden processes
vol -f memory.dmp windows.psscan

# 4. Check command lines
vol -f memory.dmp windows.cmdline

# 5. Network connections
vol -f memory.dmp windows.netscan

# 6. Detect injected code
vol -f memory.dmp windows.malfind --dump

# 7. Scan with YARA rules
vol -f memory.dmp windows.yarascan --yara-rules malware.yar

# 8. Check persistence
vol -f memory.dmp windows.svcscan
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```
{% endcode %}

#### Process Investigation Workflow

```bash
# Target: Suspicious process PID 1234

# 1. Basic info
vol -f memory.dmp windows.pslist --pid 1234

# 2. Parent/child relationships
vol -f memory.dmp windows.pstree

# 3. Command line
vol -f memory.dmp windows.cmdline --pid 1234

# 4. Environment variables
vol -f memory.dmp windows.envars --pid 1234

# 5. Loaded DLLs
vol -f memory.dmp windows.dlllist --pid 1234

# 6. Open handles
vol -f memory.dmp windows.handles --pid 1234

# 7. Network connections for this process
vol -f memory.dmp windows.netscan | grep 1234

# 8. Check for injection
vol -f memory.dmp windows.malfind --pid 1234

# 9. Dump executable
vol -f memory.dmp windows.pslist --dump --pid 1234
```

#### Credential Extraction Workflow

```bash
# 1. Dump SAM hashes
vol -f memory.dmp windows.hashdump

# 2. LSA secrets
vol -f memory.dmp windows.lsadump

# 3. Cached domain credentials
vol -f memory.dmp windows.cachedump

# 4. Look for mimikatz artifacts
vol -f memory.dmp windows.yarascan --yara-rules mimikatz.yar

# 5. Check for LSASS access
vol -f memory.dmp windows.handles | grep -i lsass
```

#### Rootkit Detection Workflow

```bash
# 1. Compare process lists
vol -f memory.dmp windows.pslist > pslist.txt
vol -f memory.dmp windows.psscan > psscan.txt
diff pslist.txt psscan.txt

# 2. Compare module lists
vol -f memory.dmp windows.modules > modules.txt
vol -f memory.dmp windows.modscan > modscan.txt
diff modules.txt modscan.txt

# 3. Check SSDT for hooks
vol -f memory.dmp windows.ssdt

# 4. Check kernel callbacks
vol -f memory.dmp windows.callbacks

# 5. Check drivers
vol -f memory.dmp windows.driverscan
```

#### Lateral Movement Investigation

```bash
# 1. Network connections to internal hosts
vol -f memory.dmp windows.netscan | grep -E "10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\."

# 2. Check for RDP artifacts
vol -f memory.dmp windows.pslist | grep -i "mstsc\|rdp"

# 3. Check for PsExec/remote execution
vol -f memory.dmp windows.pslist | grep -i "psexe\|wmiprvse"

# 4. SMB connections (port 445)
vol -f memory.dmp windows.netscan | grep ":445"

# 5. Check for WinRM
vol -f memory.dmp windows.pslist | grep -i "wsmprovhost"

# 6. Named pipes
vol -f memory.dmp windows.handles | grep -i "pipe"
```

#### Data Exfiltration Investigation

```bash
# 1. External network connections
vol -f memory.dmp windows.netscan | grep -v "10\.\|192\.168\.\|172\."

# 2. Browser processes
vol -f memory.dmp windows.pslist | grep -iE "chrome|firefox|edge|iexplore"

# 3. File handles in sensitive locations
vol -f memory.dmp windows.handles | grep -iE "documents|desktop|downloads"

# 4. Check for archive utilities
vol -f memory.dmp windows.pslist | grep -iE "7z|rar|zip|tar"

# 5. DNS queries (if available)
vol -f memory.dmp windows.netscan | grep ":53"

# 6. Cloud storage
vol -f memory.dmp windows.pslist | grep -iE "dropbox|onedrive|gdrive"
```

***

### Output Options

```bash
# Output to file
vol -f memory.dmp windows.pslist > output.txt

# Render as JSON
vol -f memory.dmp -r json windows.pslist > output.json

# Render as CSV
vol -f memory.dmp -r csv windows.pslist > output.csv

# Pretty print JSON
vol -f memory.dmp -r pretty windows.pslist

# Specify output directory for dumps
vol -f memory.dmp -o /output/dir windows.malfind --dump

# Quiet mode (less verbose)
vol -f memory.dmp -q windows.pslist

# Verbose/debug mode
vol -f memory.dmp -vvv windows.pslist
```

***

### YARA Integration

#### Basic YARA Scanning

{% code overflow="wrap" %}
```bash
# Scan with rule file
vol -f memory.dmp windows.yarascan --yara-rules rules.yar

# Scan specific process
vol -f memory.dmp windows.yarascan --yara-rules rules.yar --pid 1234

# Inline rule
vol -f memory.dmp windows.yarascan --yara-rules "rule test { strings: \$a = \"malicious\" condition: \$a }"
```
{% endcode %}

#### Useful YARA Rules Sources

* https://github.com/Yara-Rules/rules
* https://github.com/Neo23x0/signature-base
* https://github.com/reversinglabs/reversinglabs-yara-rules

***

### Quick Reference Card

<table><thead><tr><th width="237">Task</th><th>Command</th></tr></thead><tbody><tr><td>System info</td><td><code>vol -f mem.dmp windows.info</code></td></tr><tr><td>Process list</td><td><code>vol -f mem.dmp windows.pslist</code></td></tr><tr><td>Process tree</td><td><code>vol -f mem.dmp windows.pstree</code></td></tr><tr><td>Hidden processes</td><td><code>vol -f mem.dmp windows.psscan</code></td></tr><tr><td>Command lines</td><td><code>vol -f mem.dmp windows.cmdline</code></td></tr><tr><td>DLL list</td><td><code>vol -f mem.dmp windows.dlllist</code></td></tr><tr><td>Network connections</td><td><code>vol -f mem.dmp windows.netscan</code></td></tr><tr><td>Open handles</td><td><code>vol -f mem.dmp windows.handles</code></td></tr><tr><td>Services</td><td><code>vol -f mem.dmp windows.svcscan</code></td></tr><tr><td>Registry hives</td><td><code>vol -f mem.dmp windows.registry.hivelist</code></td></tr><tr><td>Registry key</td><td><code>vol -f mem.dmp windows.registry.printkey --key "path"</code></td></tr><tr><td>Password hashes</td><td><code>vol -f mem.dmp windows.hashdump</code></td></tr><tr><td>Injected code</td><td><code>vol -f mem.dmp windows.malfind</code></td></tr><tr><td>YARA scan</td><td><code>vol -f mem.dmp windows.yarascan --yara-rules file.yar</code></td></tr><tr><td>Kernel modules</td><td><code>vol -f mem.dmp windows.modules</code></td></tr><tr><td>File scan</td><td><code>vol -f mem.dmp windows.filescan</code></td></tr><tr><td>Dump files</td><td><code>vol -f mem.dmp windows.dumpfiles</code></td></tr><tr><td>Dump process</td><td><code>vol -f mem.dmp windows.pslist --dump --pid 1234</code></td></tr><tr><td>JSON output</td><td><code>vol -f mem.dmp -r json windows.pslist</code></td></tr></tbody></table>

***

### Common Issues & Fixes

<table><thead><tr><th width="245">Issue</th><th>Solution</th></tr></thead><tbody><tr><td>No suitable symbol table</td><td>Download symbols from Volatility Foundation</td></tr><tr><td>Unsupported layer type</td><td>Ensure memory image isn't corrupted</td></tr><tr><td>Plugin not found</td><td>Check plugin name spelling; use <code>--help</code></td></tr><tr><td>Slow analysis</td><td>Use SSD, increase RAM, or analyze specific PIDs</td></tr><tr><td>Missing processes</td><td>Try <code>psscan</code> instead of <code>pslist</code></td></tr><tr><td>Incomplete results</td><td>Memory may be corrupted; try different plugins</td></tr><tr><td>Python errors</td><td>Ensure Python 3.7+ and all dependencies installed</td></tr></tbody></table>

***

### Volatility 2 vs 3 Command Mapping

| Volatility 2 | Volatility 3                |
| ------------ | --------------------------- |
| `imageinfo`  | `windows.info`              |
| `pslist`     | `windows.pslist`            |
| `pstree`     | `windows.pstree`            |
| `psscan`     | `windows.psscan`            |
| `dlllist`    | `windows.dlllist`           |
| `handles`    | `windows.handles`           |
| `netscan`    | `windows.netscan`           |
| `hivelist`   | `windows.registry.hivelist` |
| `printkey`   | `windows.registry.printkey` |
| `hashdump`   | `windows.hashdump`          |
| `malfind`    | `windows.malfind`           |
| `svcscan`    | `windows.svcscan`           |
| `modules`    | `windows.modules`           |
| `modscan`    | `windows.modscan`           |
| `filescan`   | `windows.filescan`          |
| `dumpfiles`  | `windows.dumpfiles`         |

**Key Differences:**

* Vol3: No manual profile selection (auto-detection)
* Vol3: Plugin names prefixed with OS (windows., linux., mac.)
* Vol3: Python 3 only
* Vol3: Symbol tables instead of profiles
