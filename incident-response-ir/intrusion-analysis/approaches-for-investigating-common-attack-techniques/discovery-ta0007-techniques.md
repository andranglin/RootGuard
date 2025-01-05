---
icon: laptop-code
---

# Discovery (TA0007) Techniques

### <mark style="color:blue;">Introduction</mark>

Forensically investigating discovery techniques on workstations and server systems involves identifying how an attacker or malicious entity gathered information about your systems and network. Discovery is a tactic in the MITRE ATT\&CK framework that encompasses various techniques used by adversaries to gain knowledge about the system, network, and environment they have compromised.

#### Understanding Common Discovery Techniques

* **System and Network Discovery:** Identifying system configurations, network resources, and devices.
* **Account Discovery:** Gathering information about user accounts.
* **File and Directory Discovery:** Searching for files and directories of interest.
* **Software Discovery:** Identifying installed applications and software.
* **Command and Control Discovery:** Detecting communication with C\&C servers.

#### Data Collection and Preservation

* **Forensic Imaging:** Use tools like EnCase, AXIOM Cyber, FTK Imager or dd to create images of affected systems.
* **Memory Capture**: Employ tools like Magnet RAM Capture or WinPmem to capture volatile memory.
* **Log Collection:** Collect security logs, system logs, application logs, and command execution logs.

#### Log Analysis

* **Security and System Logs:** Look for signs of reconnaissance activities, such as frequent access to system information utilities or scripts.
* **Authentication Logs:** Check for unusual login attempts or user enumeration activities.
* **Network Logs:** Review logs for signs of network scanning or mapping activities.

#### File and Directory Analysis

* **File Access Logs:** Investigate logs for access to specific files or directories containing sensitive information.
* **File System Forensics:** Analyse file systems for tools or scripts that could be used in the discovery process.

#### Command History Analysis

* **Command Line Logs:** Windows systems log command line activity, including PowerShell, in Event Logs. Look for commands related to system reconnaissance (like netstat, ipconfig, whoami, and net commands).
* **Bash History (Unix/Linux):** Review .bash\_history or equivalent files for executed commands that could be used for discovery.

#### Network Traffic Analysis

* **Network Monitoring Tools:** Use tools like Wireshark or Tcpdump to analyse captured network traffic for reconnaissance patterns.
* **DNS Query Logs:** Review DNS logs for domain lookups that may indicate reconnaissance or mapping of internal resources.

#### Artifact Analysis

* **Prefetch Files (Windows):** Analyse Prefetch files to determine if any tools commonly used for discovery were executed.
* **Registry Analysis (Windows):** Check registry keys for traces of commands or tools execution.

#### Use of Specialised Forensic Tools

* **Forensic Suites:** Tools like EnCase, Autopsy, or X-Ways for comprehensive system analysis.
* **Sysinternals Suite (Windows):** Use tools like Process Monitor and Process Explorer for real-time system monitoring.

#### Documentation and Reporting

* **Detailed Documentation:** Record all findings, methodologies, and evidence paths.
* **Forensic Report:** Compile a comprehensive report detailing the investigation, findings, and potential impact.

#### Post-Investigation Actions

* **Mitigation and Remediation:** Implement necessary security measures to counter the identified discovery techniques.
* **Recovery:** Restore systems and data from backups where necessary.
* **Enhancing Defenses:** Update security policies and tools based on the findings.

#### Key Considerations

* Chain of Custody: Maintain a clear chain of custody for all evidence.
* Legal Compliance: Ensure the investigation is compliant with legal and organisational policies.
* Data Confidentiality: Handle all data securely, maintaining its confidentiality and integrity.

Each case of discovery by an attacker can be unique, requiring a tailored approach based on the specifics of the incident and the environment.

### <mark style="color:blue;">Using KQL to Investigate Discovery Activities in an Environment Using Defender/Sentinel</mark>

Discovery techniques involve adversaries trying to gather information about the system and network they have compromised. This information is often used to facilitate further attacks or lateral movement.

### <mark style="color:blue;">**1. T1012 - Query Registry**</mark>

**Objective**: Detect attempts to query the Windows Registry to gather information about the system, users, and software.&#x20;

1. **Detect Registry Queries for Installed Software**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to query registry keys related to installed software.

2. **Monitor for Queries of Autostart Locations**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to query autostart locations in the registry.

3. **Identify Queries for Network Configuration**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for queries related to network configuration settings.

4. **Detect Access to User Account Information in the Registry**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\SAM\\SAM\\Domains\\Account\\Users" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to query user account information from the registry.

5. **Monitor for Registry Queries Related to Security Settings**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\System\\CurrentControlSet\\Control\\Lsa", "HKLM\\Software\\Policies\\Microsoft\\Windows Defender") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect queries related to security settings in the registry.

6. **Identify Queries for Installed Patches**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for registry queries related to installed patches and updates.

### <mark style="color:blue;">**2. T1082 - System Information Discovery**</mark>

**Objective**: Detect attempts to gather detailed information about the system, including OS version, hardware, and configuration.&#x20;

1. **Detect Use of `systeminfo` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "systeminfo" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of the `systeminfo` command to gather system information.

2. **Monitor for Execution of `hostname` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "hostname" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to determine the system's hostname.

3. **Identify Use of `wmic` to Gather System Information**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("wmic os", "wmic computersystem", "wmic cpu") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for use of `wmic` to query system information.

4. **Detect PowerShell Commands for System Information Gathering**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-ComputerInfo", "Get-WmiObject", "Get-HotFix") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands used to gather system information.

5. **Monitor for Use of `dxdiag`**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "dxdiag" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect use of the `dxdiag` tool to gather detailed system information.

6. **Identify Use of `msinfo32`**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "msinfo32" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of `msinfo32` to gather system information.

### <mark style="color:blue;">**3. T1016 - System Network Configuration Discovery**</mark>

**Objective**: Detect attempts to gather information about network configuration, including interfaces, routing, and DNS settings.&#x20;

1. **Detect Use of `ipconfig` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ipconfig" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of the `ipconfig` command to gather network configuration information.

2. **Monitor for Execution of `route` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "route" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to view or modify the system's routing table.

3. **Identify Use of `netsh` for Network Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "netsh" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of `netsh` to discover network configuration.

4. **Detect PowerShell Commands for Network Configuration Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-NetIPConfiguration", "Get-NetAdapter", "Get-DnsClient") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands used to discover network configuration.

5. **Monitor for Use of `nbtstat`**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "nbtstat" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

{% code overflow="wrap" %}
```
_Purpose_: Detect use of the `nbtstat` command to gather information about NetBIOS over TCP/IP.
```
{% endcode %}

6\. **Identify Use of `netstat`**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "netstat" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of `netstat` to view active network connections and listening ports.

### **4. T1049 - System Network Connections Discovery**

**Objective**: Detect attempts to discover active network connections, including listening ports and established sessions.&#x20;

1. **Detect Use of `netstat` to View Network Connections**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "netstat" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of `netstat` to view active network connections.

2. **Monitor for PowerShell Commands to Discover Network Connections**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-NetTCPConnection", "Get-NetUDPEndpoint") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell commands used to discover TCP/UDP connections.

3. **Identify Use of `ss` Command (for Linux or WSL environments)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ss" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of the `ss` command to view network connections.

4. **Detect Use of `lsof` Command (for Linux or WSL environments)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "lsof -i" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of the `lsof` command to list open files and network connections.

5. **Monitor for Execution of `net use` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "net use" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to view or connect to shared network resources using the `net use` command.

6. **Identify Use of `arp` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "arp" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of the `arp` command to view or manipulate the ARP table.

### <mark style="color:blue;">**5. T1083 - File and Directory Discovery**</mark>

**Objective**: Detect attempts to discover files and directories on the system, especially those containing sensitive information.&#x20;

1. **Detect Use of `dir` or `ls` Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("dir", "ls") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to list files and directories.

2. **Monitor for Recursive Directory Listings**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("/s", "-R") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect recursive directory listings that may indicate an attempt to discover sensitive files.

3. **Identify Use of `tree` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "tree" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of the `tree` command to display directory structures.

4. **Detect PowerShell Commands for File Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-ChildItem", "Get-Item") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands used for discovering files and directories.

5. **Monitor for Searches for Specific File Types**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any (".doc", ".pdf", ".xls", ".txt") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect searches for specific file types that may contain sensitive information.

6. **Identify Use of `find` Command (for Linux or WSL environments)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "find" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of the `find` command to search for files and directories.

### <mark style="color:blue;">**6. T1033 - System Owner/User Discovery**</mark>

**Objective**: Detect attempts to gather information about the system owner or users, including usernames and account details.&#x20;

1. **Detect Use of `whoami` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "whoami" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of the `whoami` command to determine the current logged-in user.

2. **Monitor for Execution of `query user` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "query user" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to query currently logged-on users.

3. **Identify Use of `net user` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "net user" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for attempts to query user accounts using the `net user` command.

4. **Detect PowerShell Commands for User Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-LocalUser", "Get-ADUser") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands used to discover local or domain users.

5. **Monitor for Execution of `who` Command (for Linux or WSL environments)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "who" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect use of the `who` command to list logged-in users on Linux or WSL.

6. **Identify Use of `id` Command (for Linux or WSL environments)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "id" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of the `id` command to display user ID and group information.

### <mark style="color:blue;">**7. T1018 - Remote System Discovery**</mark>

**Objective**: Detect attempts to discover remote systems within the network, often as a precursor to lateral movement.&#x20;

1. **Detect Use of `net view` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "net view" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to discover remote systems using the `net view` command.

2. **Monitor for Execution of `ping` to Discover Remote Systems**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ping" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect use of the `ping` command to identify remote systems.

3. **Identify Use of `arp` to Discover Remote Systems**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "arp -a" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for use of the `arp` command to discover remote systems via ARP tables.

4. **Detect PowerShell Commands for Remote System Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Test-Connection", "Get-NetNeighbor") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands used to discover remote systems on the network.

5. **Monitor for Use of `nbtstat` to Discover Remote Systems**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "nbtstat -A" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect use of `nbtstat` to discover remote systems and their NetBIOS names.

6. **Identify Use of `Get-ADComputer` for Remote System Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has "Get-ADComputer" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of `Get-ADComputer` to list computers in Active Directory.

### <mark style="color:blue;">**8. T1057 - Process Discovery**</mark>

**Objective**: Detect attempts to enumerate running processes on the system to identify security software, active applications, or potential targets for privilege escalation.&#x20;

1. **Detect Use of `tasklist` Command**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "tasklist" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of the `tasklist` command to enumerate running processes.

2. **Monitor for Execution of `ps` Command (for Linux or WSL environments)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ps" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect use of the `ps` command to list processes on Linux or WSL.

3. **Identify Use of PowerShell for Process Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-Process", "gwmi win32_process") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for PowerShell commands used to list running processes.

4. **Detect Use of `wmic` for Process Discovery**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic process" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify use of `wmic` to query running processes.

5. **Monitor for Use of `taskmgr.exe`**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "taskmgr.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to open Task Manager to view running processes.

6. **Identify Use of `top` Command (for Linux or WSL environments)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "top" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of the `top` command to display running processes on Linux or WSL.
