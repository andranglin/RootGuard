# Hunting APT TTPs and LOLBAS Operations - Playbook

### Overview

This playbook is designed for cyber investigators using Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL) to hunt for tactics, techniques, and procedures (TTPs) associated with APT groups (e.g., APT41) and Living Off the Land Binaries and Scripts (LOLBAS). It draws from MITRE ATT\&CK research and observed behaviours involving discovery, lateral movement, credential access, and data collection.

### **The Playbook Focuses On:**

* **Detection Queries:** KQL queries for MDE to identify suspicious activities.
* **Investigation Steps:** Contextual guidance on interpreting results and pivoting.
* **Response Actions:** Recommendations for containment and remediation.&#x20;
* **Data Sources:** Primarily DeviceProcessEvents, DeviceFileEvents, and DeviceNetworkEvents in MDE.

Assume administrative access to MDE for running advanced hunting queries. Run queries over a relevant time frame (e.g., last 30 days) and correlate with MITRE ATT\&CK IDs (e.g., T1016 for Network Service Discovery).

### Prerequisites

* Enable advanced logging in Windows Event Viewer (e.g., ESENT for NTDS.dit events).
* Configure SACLs on sensitive files, such as ntds, dit, for access auditing.
* Monitor for anomalous processes via Sysmon or MDE.

### Playbook Structure

Organised by key tools/commands observed in APT operations.&#x20;

For each:

* **Description**: TTP context and MITRE IDs.
* **KQL Queries:** Adapted from provided MDE examples.
* **Investigation Tips:** How to analyse results.
* **Mitigation:** Preventive measures.

### 1. Initial Access & Execution: File Downloads

**Certutil**

**Tactic:** Execution (TA0002) / Ingress Tool Transfer (TA0011) **Description**: Used for downloading payloads (e.g., Cobalt Strike BEACON) via URL cache. MITRE: T1105 (Ingress Tool Transfer), T1016 (System Network Configuration Discovery).&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\certutil.exe' or ProcessVersionInfoOriginalFileName =~ @'certutil.exe') and ProcessCommandLine contains @"-urlcache -split -f"
| project Timestamp, DeviceName, FolderPath, ProcessCommandLine, AccountName
```
{% endcode %}

OR

{% code overflow="wrap" %}
```kql
DeviceNetworkEvents
| where  TimeGenerated > ago(30d)
| where InitiatingProcessFileName =~ "certutil.exe"
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80, 443, 135, 445) // Common ports for file transfer
| where RemoteUrl startswith "http"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemotePort, InitiatingProcessParentFileName, InitiatingProcessAccountName
| sort by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**: `Certutil` Initiating External Network Connections.&#x20;

Looks for `certutil` being used to make outbound connections, indicating a potential file download or data staging.

* Check DestinationPort in network events (e.g., 80, 443).
* Pivot to IP addresses like 91.208.184.78.
* Correlate with file downloads (e.g., 2.exe MD5: 3e856162c36b532925c8226b4ed3481c).&#x20;
* **Mitigation**: Block certutil outbound connections via AppLocker; monitor for anomalous network initiations.

### 2. Discovery & Enumeration

**Dnscmd**

**Description**: Enumerates DNS records and zones for environment discovery. MITRE: T1016 (System Network Configuration Discovery), T1069.002 (Permission Groups Discovery). Enumerates network topology **\[T1016]** and Active Directory structure **\[T1069.002]** via commands like `/enumrecords` and `/enumzones`.&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\dnscmd.exe' or ProcessVersionInfoOriginalFileName =~ @'dnscmd.exe') and (ProcessCommandLine contains @'/enumrecords' or ProcessCommandLine contains @'/enumzones')
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFolderPath
```
{% endcode %}

OR

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessCommandLine has_any (
    // Network/Host
    "ipconfig /all", "arp -a", "netstat -ano", "route print", "systeminfo", "tasklist /v",
    "wmic volume list brief", "wmic service brief", "wmic product list brief",
    // Domain/Account
    "dnscmd . /enum", "nltest /dclist", "nltest /domain_trusts",
    "net group /dom", "net localgroup administrators", "ldifde.exe -f",
    // Log/Config
    "wevtutil qe security", "reg query hklm\\software"
)
| summarize count() by DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
| order by count_ desc
```
{% endcode %}

**Investigation Tips**: Broad Reconnaissance Command Execution&#x20;

This query targets a wide array of discovery commands, including those used to identify network settings, system details, and domain structure.

* To detect outliers, look for commands targeting redacted zones.
* Use stats to detect outliers in process counts.&#x20;
* **Mitigation**: Restrict dnscmd execution to admins; audit DNS queries.

### 3. Ldifde

**Description**: Exports AD data for enumeration. MITRE: T1069.001 (Local Groups), T1082 (System Information Discovery).&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where  TimeGenerated > ago(30d)
| where (FolderPath endswith @'\ldifde.exe' or ProcessVersionInfoOriginalFileName =~ @'ldifde.exe') and ProcessCommandLine contains @'-f c:\windows\temp\.txt -p subtree'
| project TimeGenerated, DeviceName, ProcessCommandLine
```
{% endcode %}

**Investigation Tips**:

* Scan for exported files in C:\Windows\Temp.
* Correlate with net group commands. **Mitigation**:&#x20;
* Monitor file creations in Temp directories.

### 4. Net User/Group/Use

**Description**: Enumerates local and domain groups/admins.&#x20;

MITRE: T1069.002 (Permission Groups Discovery).&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessCommandLine contains @"net localgroup administrators" or ProcessCommandLine contains @"net group /dom" or ProcessCommandLine contains @"net group “Domain Admins” /dom"
| project TimeGenerated, DeviceName, ProcessCommandLine, AccountName
```
{% endcode %}

OR

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessCommandLine has_any (@"net localgroup", @"net group")
| where ProcessCommandLine has_any (@"net localgroup administrators", @"net group /dom") or ProcessCommandLine contains_cs @"net group ""Domain Admins"" /dom"
| project TimeGenerated, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessCommandLine, ProcessRemoteSessionDeviceName, ReportId
| summarize arg_max(TimeGenerated, *) by DeviceName, ProcessCommandLine, AccountName
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Identify unusual user contexts (e.g., non-admin).
* Pivot to lateral movement indicators.&#x20;
* **Mitigation**: Audit net.exe usage; restrict to privileged accounts.

### 5. Netsh

**Description**: Shows firewall configs and sets up port proxies for forwarding. MITRE: T1090 (Proxy), T1016 (System Network Configuration Discovery).&#x20;

**KQL Queries**:

* Firewall Enumeration:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\netsh.exe' or FileName =~ 'netsh.exe') and ProcessCommandLine has_any (@'show', @'dump')
| where ProcessCommandLine has_all ('show', 'firewall')
    or ProcessCommandLine has_all ('show', 'portproxy')
    or ProcessCommandLine has_all ('show', 'state')
    or ProcessCommandLine contains 'dump' 
| extend DiscoveryTarget = case(
    ProcessCommandLine contains 'firewall', 'Firewall Rules',
    ProcessCommandLine contains 'portproxy', 'Port Proxy/Redirection',
    ProcessCommandLine contains 'dump', 'Full Configuration Dump',
    'General Network State'
)
| project TimeGenerated, DeviceName, AccountName, DiscoveryTarget, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionIP, SHA256
| order by TimeGenerated desc
```
{% endcode %}

* Port Proxy Addition:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\netsh.exe' or FileName =~ 'netsh.exe')
    and ProcessCommandLine has_any (@"add", @"set")
    and ProcessCommandLine has_all (@"interface", @"portproxy")
    and ProcessCommandLine has_all (@"listenport", @"connectport")
| where ProcessCommandLine has_any (@"listenport=50100", @"connectport=1433")
| extend ActionType = case(
    ProcessCommandLine contains @"delete", "Rule Deletion",
    ProcessCommandLine contains @"add", "Rule Addition (Suspicious)",
    ProcessCommandLine contains @"set", "Rule Modification (Suspicious)",
    "Port Proxy Activity"
)
| project TimeGenerated, DeviceName, ActionType, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, InitiatingProcessRemoteSessionIP, SHA256
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Check registry: HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp.
* Review firewall logs for unauthorised rules.&#x20;
* **Mitigation**: Audit registry changes; limit portproxy usage.

### 6. Nltest

**Description**: Queries domain trusts and DCs. MITRE: T1482 (Domain Trust Discovery).&#x20;

**KQL Queries**:

* Basic Execution:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\nltest.exe' or FileName =~ 'nltest.exe' or ProcessVersionInfoOriginalFileName =~ @'nltestrk.exe')
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
```
{% endcode %}

* Recon Commands:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\nltest.exe' or FileName =~ 'nltest.exe' or ProcessVersionInfoOriginalFileName =~ @'nltestrk.exe')
    and ProcessCommandLine has_any (@'/dclist:', @'/domain_trusts', @'/trusted_domains')
| extend DiscoveryTarget = case(
    ProcessCommandLine contains @'/dclist:', "Domain Controller List Enumeration",
    ProcessCommandLine contains @'/domain_trusts', "Domain Trust Relationships Mapping",
    ProcessCommandLine contains @'/trusted_domains', "Trusted Domains List Enumeration",
    "General AD Reconnaissance"
)
| project TimeGenerated, DeviceName, DiscoveryTarget, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Look for /server:/query patterns.
* Correlate with domain admin queries.&#x20;
* **Mitigation**: Restrict nltest to domain admins.

### 7. PowerShell

**Description**: Queries event logs for logons. MITRE: T1059.001 (PowerShell), T1033 (System Owner/User Discovery).&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\powershell.exe' or FileName =~ 'powershell.exe' or FolderPath endswith @'\pwsh.exe' or FileName =~ 'pwsh.exe')
| where ProcessCommandLine has_any (@'Get-EventLog', @'Get-WinEvent')
| where ProcessCommandLine has_any (@'security', @'4624', @'4625', @'4634', @'4740')
| extend EventCheckFocus = case(
    ProcessCommandLine contains '4624', 'Successful Logon Check (4624)',
    ProcessCommandLine contains '4625', 'Failed Logon Check (4625)',
    ProcessCommandLine contains '4634', 'Logoff Check (4634)',
    ProcessCommandLine contains '4740', 'Account Lockout Check (4740)',
    'General Security Event Log Access'
)
| project TimeGenerated, DeviceName, AccountName, EventCheckFocus, ProcessCommandLine, InitiatingProcessCommandLine, FileName
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Check for failed logons (Event ID 4625), followed by successful logons.
* Look for time-and-distance anomalies in logons.&#x20;
* **Mitigation**: Constrain PowerShell via AppLocker; enable script block logging.

### 8. Reg Query/Save

**Description**: Dumps registry hives for credentials. MITRE: T1003 (OS Credential Dumping), T1555 (Credentials from Password Stores).&#x20;

**KQL Queries**:

* Save Hives:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\reg.exe' or FileName =~ 'reg.exe')
| where ProcessCommandLine has_all (@"save", @"hklm\")
    and ProcessCommandLine has_any (@"sam", @"system", @"security", @"software", @"default") 
| extend RegActionType = case(
    ProcessCommandLine contains @"sam" and ProcessCommandLine contains @"system", 'Critical Credential Dump (SAM + SYSTEM)',
    ProcessCommandLine contains @"sam", 'SAM Hive Dump (Credential Theft)',
    ProcessCommandLine contains @"system", 'SYSTEM Hive Dump (Decryption Key)',
    ProcessCommandLine contains @"security", 'SECURITY Hive Dump (Local Policy)',
    ProcessCommandLine contains @"software", 'SOFTWARE Hive Dump',
    'General Sensitive Hive Save'
)
| project TimeGenerated, DeviceName, RegActionType, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

* Query Software:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\reg.exe' or FileName =~ 'reg.exe')
| where ProcessCommandLine has_all (@"query", @"hklm\") or ProcessCommandLine has_all (@"query", @"hkcu\")
| where ProcessCommandLine has_any (
    @"software\OpenSSH", @"software\putty", @"software\ssh", @"software\SecureCRT", 
    @"software\Microsoft\Terminal Server Client",
    @"software\Google\Chrome\User Data",
    @"software\mozilla\firefox\profiles"
)
| extend ReconTarget = case(
    ProcessCommandLine contains @"software\OpenSSH", 'OpenSSH Configuration Check',
    ProcessCommandLine contains @"software\putty", 'PuTTY Configuration Check',
    ProcessCommandLine contains @"Terminal Server Client", 'RDP History/Config Check',
    ProcessCommandLine contains @"User Data" or ProcessCommandLine contains @"profiles", 'Browser Profile/Secret Check',
    'General Configuration Reconnaissance'
)
| project TimeGenerated, DeviceName, ReconTarget, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Scan for saved files like ss.dat, sy.dat.
* Pivot to tools like Mimikatz.&#x20;
* **Mitigation**: Audit registry access; use LSA protection.

### 9. Systeminfo, Tasklist, Wevtutil

**Description**: Gathers system info, processes, and event logs. MITRE: T1082 (System Information Discovery).&#x20;

**KQL Query (Combined Enumeration)**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessCommandLine has_any (
    @"systeminfo", // System configuration
    @"tasklist", // Running processes
    @"wevtutil", // Event log queries
    @"whoami", // User/group identity
    @"ipconfig", // Network configuration
    @"netstat" // Network connections
)
| where (ProcessCommandLine has_all (@"tasklist", @"/v")) 
    or (ProcessCommandLine has_all (@"wevtutil", @"security")) 
    or ProcessCommandLine contains @"systeminfo"
    or ProcessCommandLine contains @"whoami"
    or (ProcessCommandLine has_any (@"ipconfig", @"netstat"))
| extend DiscoveryFocus = case(
    ProcessCommandLine contains @"systeminfo", 'System Configuration Discovery',
    ProcessCommandLine has_all (@"tasklist", @"/v"), 'Detailed Process Listing',
    ProcessCommandLine has_all (@"wevtutil", @"security"), 'Security Event Log Query',
    ProcessCommandLine contains @"whoami", 'User/Privilege Discovery',
    ProcessCommandLine has_any (@"ipconfig", @"netstat"), 'Network Configuration Discovery',
    'General System Discovery'
)
| project TimeGenerated, DeviceName, DiscoveryFocus, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, InitiatingProcessRemoteSessionIP
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Correlate with other recon commands.&#x20;
* **Mitigation**: Monitor for batch executions.

### 10. WMI/WMIC

**Description**: Queries logical disks; executes remote commands. MITRE: T1047 (Windows Management Instrumentation), T1082.&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\wmic.exe' or FileName =~ 'wmic.exe')
| where ProcessCommandLine has_any (
    @"win32_logicaldisk get",     // Disk/Volume discovery (Original Query)
    @"win32_computersystem get",  // System/Domain/Model discovery
    @"win32_product get",         // Installed software/applications discovery
    @"win32_process get",         // Process discovery
    @"win32_service get",         // Service discovery
    @"win32_startupcommand get",  // Persistence discovery
    @"qfe get"                    // Installed patches/hotfixes discovery
)
| extend ReconTarget = case(
    ProcessCommandLine contains @"win32_logicaldisk get", 'Disk & Volume Discovery',
    ProcessCommandLine contains @"win32_computersystem get", 'System & Domain Discovery',
    ProcessCommandLine contains @"win32_product get", 'Installed Software Discovery',
    ProcessCommandLine contains @"win32_process get", 'Running Process Discovery',
    ProcessCommandLine contains @"win32_service get", 'System Service Discovery',
    ProcessCommandLine contains @"win32_startupcommand get", 'Startup Persistence Check',
    ProcessCommandLine contains @"qfe get", 'Installed Patch/Hotfix Discovery',
    'General WMI Reconnaissance'
)
| project TimeGenerated, DeviceName, ReconTarget, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Enable WMI tracing for user attribution.&#x20;
* **Mitigation**: Restrict WMI via GPO.

### 11. Ntdsutil

**Description**: Dumps NTDS.dit for AD credentials. MITRE: T1003.003 (NTDS).&#x20;

**KQL Queries**:

* Shadow Copy Creation:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\vssadmin.exe' or FileName =~ 'vssadmin.exe')
    or (FolderPath endswith @'\wmic.exe' or FileName =~ 'wmic.exe' and ProcessCommandLine contains @"shadow")
    or (FolderPath endswith @'\powershell.exe' or FileName =~ 'powershell.exe' and ProcessCommandLine has_any (@"Remove-Vss", @"New-Vss"))
| where ProcessCommandLine has_any (@"create shadow", @"delete shadows", @"resize", @"Remove-Vss", @"New-Vss")
| extend VssAction = case(
    ProcessCommandLine has_any (@"delete shadows", @"Remove-Vss"), 'Shadow Copy Deletion (HIGH SEVERITY)',
    ProcessCommandLine has_any (@"create shadow", @"New-Vss"), 'Shadow Copy Creation (Suspicious)',
    ProcessCommandLine contains @"resize", 'Shadow Copy Storage Modification',
    'General VSS Activity'
)
| project TimeGenerated, DeviceName, VssAction, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

* NTDS Dump:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessCommandLine has_any (@"ntds.dit", @"ntdsutil", @"esentutl", @"vssadmin")
| where (
        ProcessCommandLine has_all (@"ntdsutil", @"ac i ntds", @"create full")
        or ProcessCommandLine has_all (@"esentutl", @"ntds.dit")
        or (ProcessCommandLine contains @"ntds.dit" and ProcessCommandLine contains @"volume" and ProcessCommandLine contains @"shadow")
    )
| extend AttackMethod = case(
    ProcessCommandLine has_all (@"ntdsutil", @"create full"), 'NTDSUTIL Snapshot Creation (Highly Suspect)',
    ProcessCommandLine has_all (@"esentutl", @"ntds.dit"), 'ESENTUTL Database Manipulation',
    ProcessCommandLine contains @"ntds.dit" and ProcessCommandLine contains @"shadow", 'Copying NTDS.DIT from Shadow Copy',
    'General NTDS/Database Activity'
)
| project TimeGenerated, DeviceName, AttackMethod, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath, SHA256
| order by TimeGenerated desc
```
{% endcode %}

* File Events:

{% code overflow="wrap" %}
```kql
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where FileName =~ 'ntds.dit' and FolderPath contains @'\ntds\'
| where InitiatingProcessFolderPath has_any (@'\Temp\', @'\Public\', @'\Users\Default\', @'\ProgramData\', @'\Windows\Tasks\')
| where InitiatingProcessFileName !in~ ('ntdsutil.exe', 'wbadmin.exe', 'rsync.exe', 'BackupExec.exe')
| extend StagingLocation = case(
    InitiatingProcessFolderPath contains @'\Temp\', 'User/System Temp Folder',
    InitiatingProcessFolderPath contains @'\Public\', 'Public Share Folder',
    InitiatingProcessFolderPath contains @'\ProgramData\', 'ProgramData Folder (Common Malware Location)',
    'Other Suspicious Staging Location'
)
| project TimeGenerated, DeviceName, StagingLocation, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessRemoteSessionDeviceName, SHA256, DestinationFileLocation=FolderPath
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Check ESENT events (IDs 216, 325-327) for ntds.dit references.
* Look for folders like \Active Directory, \registry.
* If dumped, assume domain compromise; follow eviction guidance.&#x20;
* **Mitigation**: Harden DCs; audit ntdsutil.exe; block tools like Secretsdump.py.

### 12. Impacket

**Description**: Executes commands via WMI, outputs to ADMIN$ with timestamps. MITRE: T1047.&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\cmd.exe' or FileName =~ 'cmd.exe')
    and ProcessCommandLine has_all (@"cmd.exe", @"/c", @"2>&1")
| where ProcessCommandLine has_any (@"\\127.0.0.1\ADMIN$", @"\\127.0.0.1\C$", @"\\localhost\ADMIN$", @"\\localhost\C$", @"\ADMIN$\__", @"\C$\__")
| extend ExecutionMethod = case(
    ProcessCommandLine contains @"127.0.0.1\ADMIN$", 'Local ADMIN$ Command Execution (PSEXEC-style)',
    ProcessCommandLine contains @"localhost\ADMIN$", 'Localhost ADMIN$ Command Execution',
    ProcessCommandLine contains @"\ADMIN$\__", 'Remote ADMIN$ Command Execution Template',
    ProcessCommandLine contains @"\C$\__", 'Remote C$ Command Execution Template',
    'General Suspicious Remote Execution Pattern'
)
| project TimeGenerated, DeviceName, ExecutionMethod, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, InitiatingProcessRemoteSessionDeviceName
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Parse timestamps (e.g., \_\_1684956600.123456) for execution time.
* Check Security Event ID 5145 for ADMIN$ access.&#x20;
* **Mitigation**: Block Impacket indicators; monitor WMI exec.

### 13. General Enumeration Commands

**Description**: Broad recon across the network, AD, and system. MITRE: T1016, T1069, T1082.&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where ProcessCommandLine has_any (
    @"ipconfig /all", @"arp -a", @"net group /dom", @"curl", @"dnscmd", @"ldifde",
    @"netsh interface", @"netstat -ano", @"systeminfo", @"tasklist /v", @"wmic", @"wevtutil qe security"
)
| where FileName !in~ ("svchost.exe", "explorer.exe", "msiexec.exe")
| extend DiscoveryCategory = case(
    ProcessCommandLine has_any (@"ipconfig /all", @"arp -a", @"netstat -ano", @"netsh interface"), 'Network Configuration Discovery (T1016)',
    ProcessCommandLine has_any (@"systeminfo", @"wmic volume list", @"tasklist /v"), 'System & Process Discovery (T1082/T1057)',
    ProcessCommandLine has_any (@"net group /dom", @"dnscmd", @"ldifde"), 'Active Directory/Account Discovery (T1482/T1087)',
    ProcessCommandLine has_any (@"curl www.ip-api.com", @"curl ifconfig.me"), 'External IP Geolocation Check (T1071)',
    ProcessCommandLine contains @"wevtutil qe security", 'Event Log Audit Check (T1562.002)',
    'Other Reconnaissance'
)
| project TimeGenerated, DeviceName, DiscoveryCategory, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, InitiatingProcessRemoteSessionDeviceName
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Use eventstats for outlier process counts.
* Correlate with user agents like "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101 Firefox/68.0".&#x20;
* **Mitigation**: Implement network segmentation.

### 14. Credential Theft

**Description**: Targets SSH keys, Firefox profiles, and the registry for VNC/PuTTY. MITRE: T1555, T1003. **KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName in~ ('cmd.exe', 'powershell.exe', 'reg.exe', 'dir.exe', 'Get-ChildItem', 'gci', 'ls')
| where ProcessCommandLine has_any (
    @"known_hosts", 
    @"hklm\sam", @"hklm\system",
    @"software\OpenSSH", @"software\putty", 
    @"appdata\roaming\Mozilla\firefox", 
    @"appdata\local\Google\Chrome\User Data", 
    @"secretsdump", @"lazagne", 
    @"passwordstore" 
)
| extend DiscoveryTarget = case(
    ProcessCommandLine contains @"sam" or ProcessCommandLine contains @"known_hosts" or ProcessCommandLine has_any (@"secretsdump", @"lazagne"), 'Credential/Secrets Discovery (HIGH SEVERITY)',
    ProcessCommandLine contains @"firefox" or ProcessCommandLine contains @"chrome", 'Browser Data Reconnaissance',
    ProcessCommandLine contains @"software\OpenSSH" or ProcessCommandLine contains @"software\putty", 'SSH Client Configuration Check',
    'General Sensitive File/Reg Query'
)
| project TimeGenerated, DeviceName, DiscoveryTarget, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Scan for Mimikatz indicators.&#x20;
* **Mitigation**: Use Credential Guard; encrypt sensitive stores.

### 15. Additional Commands (7z, RAR, etc.)

**Description**: Compresses data for exfil. MITRE: T1560 (Archive Collected Data).&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName has_any ('7z.exe', 'rar.exe', 'winrar.exe', 'zip.exe', 'tar.exe', 'powershell.exe')
    and ProcessCommandLine has_any (@" a -p", @" c -p", @"-sdel", @"-hp", @"-p ", @"compress-archive", @"new-ziparchive")
| where ProcessCommandLine has_any (@"c:\windows\temp\", @"c:\users\public\", @"c:\programdata\", @"c:\temp\", @"$env:temp", @"$env:public")
| extend ArchiveAction = case(
    ProcessCommandLine has_any (@" -p", @"-hp"), 'Password-Protected Archiving',
    ProcessCommandLine has_any (@" -sdel", @"/sdel"), 'Archive and Delete Source (Cover Tracks)',
    ProcessCommandLine has_any (@"compress-archive", @"new-ziparchive"), 'PowerShell Compression (Commonly Passworded)',
    'General Suspicious Archiving'
)
| project TimeGenerated, DeviceName, ArchiveAction, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Look for hidden PowerShell starts.&#x20;
* **Mitigation**: Block archiving in Temp.

### 16. RUNDLL32

**Description**: Proxy for malicious payloads, LSASS dumps. MITRE: T1218.011 (Signed Binary Proxy Execution), T1003.001 (LSASS Memory).&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\rundll32.exe' or FileName =~ 'rundll32.exe')
    or (FolderPath endswith @'\taskmgr.exe' or FileName =~ 'taskmgr.exe')
    or (ProcessCommandLine has_any (@'out-file', @'debug', @'dump') and ProcessCommandLine contains 'lsass.exe')
| where ProcessCommandLine has_any (
    @"comsvcs.dll, MiniDump",
    @"MiniDump", @"lsass.exe",
    @"procdump", @"dumpert"
)
| extend DumpAction = case(
    ProcessCommandLine contains @"comsvcs.dll, MiniDump", 'RUNDLL32 LSASS Dump (High Severity)',
    ProcessCommandLine contains @"lsass.exe", 'LSASS Process Target (General Dump)',
    ProcessCommandLine contains @"taskmgr.exe", 'Task Manager Dump Action',
    'Other Process Memory Dump'
)
| project TimeGenerated, DeviceName, DumpAction, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Check for injections into explorer.exe.&#x20;
* **Mitigation**: Monitor DLL loads.

### 17. Schtasks

**Description**: Creates tasks for persistence/recon. MITRE: T1053.005 (Scheduled Task).&#x20;

**KQL Query**:

{% code overflow="wrap" %}
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where (FolderPath endswith @'\schtasks.exe' or FileName =~ 'schtasks.exe')
| where ProcessCommandLine has_any (@'/create', @'/change', @'/delete')
| where AccountName !startswith @"NT AUTHORIT"
    and AccountName !contains @"SERVICE$"
    and AccountName !contains @"LocalSystem"
| extend PersistenceAction = case(
    ProcessCommandLine contains @'/create', 'Task Creation (Persistence)',
    ProcessCommandLine contains @'/change', 'Task Modification (Evasion)',
    ProcessCommandLine contains @'/delete', 'Task Deletion (Cover Tracks)',
    'General Scheduled Task Activity'
)
| project TimeGenerated, DeviceName, PersistenceAction, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName, SHA256
| order by TimeGenerated desc
```
{% endcode %}

**Investigation Tips**:

* Filter for LOLBAS in tasks (e.g., calc.exe).&#x20;
* **Mitigation**: Audit task creations; restrict via GPO.

### IOCs

* **File Hashes (SHA256)**:
  * f4dd44bc19c19056794d29151a5b1bb76afd502388622e24c863a8494af147dd
  * ef09b8ff86c276e9b475a6ae6b54f08ed77e09e169f7fc0872eb1d427ee27d31
  * (Full list in content; use for alerts)
* **File Names**: cisco\_up.exe, cl64.exe, vm3dservice.exe, etc.
* **Paths**: C:\Users\Public\Appfile, C:\Perflogs, C:\Windows\Temp.
* **User Agent**: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101 Firefox/68.0
* **C2 Ports**: 80880, 8443, 8043, 800, 10443.

### Response Actions

1. **Isolate Affected Hosts**: Use MDE isolation.
2. **Credential Reset**: If NTDS dumped, reset all domain creds.
3. **Eviction**: Follow CISA guidance for actor removal.
4. **Enhance Monitoring**: Add Sigma rules to SIEM; use D3FEND for visualisation.

### Data Sources and Analytics

* **Command Execution**: DeviceProcessEvents | where EventId in (4688, 1, 800).
* **File Access**: DeviceFileEvents | where AccessList contains "%%4416" (read) or "%%4417" (write).
* **Analytic Example (Suspicious NTDS Access)**:

{% code overflow="wrap" %}
```kql
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where FileName =~ 'ntds.dit' and FolderPath contains @'\NTDS\'
| where InitiatingProcessFileName !in~ ('lsass.exe', 'vssvc.exe', 'esedbcli.exe', 'esentutl.exe', 'ntdsutil.exe')
| summarize
    Count = count(),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    InitiatingProcesses = make_set(InitiatingProcessFileName),
    AccountNames = make_set(InitiatingProcessAccountName)
    by DeviceName
| where Count > 1
| extend TimeDifference = LastAccess - FirstAccess
| project DeviceName, Count, FirstAccess, LastAccess, TimeDifference, InitiatingProcesses, AccountNames
| order by Count desc
```
{% endcode %}
