# Lateral Movement Investigation Runbook

## SOC & DFIR Operations Guide

**Environment:** Windows AD | Microsoft 365 | Defender XDR | Sentinel | Entra ID | Palo Alto Prisma Access

***

## Overview & Scope

This runbook provides standardised procedures for investigating lateral movement attacks across the hybrid enterprise environment. Lateral movement is a critical phase in the attack lifecycle where adversaries move through a network in search of key assets and data. Detecting and disrupting lateral movement is essential to preventing major breaches.

### Lateral Movement Definition

Lateral movement refers to techniques adversaries use to enter and control remote systems on a network after gaining initial access.&#x20;

The primary goals are:

* **Access additional systems** to find valuable targets
* **Maintain persistence** across multiple systems
* **Escalate privileges** by compromising higher-value accounts
* **Position for data exfiltration** or objective execution
* **Evade detection** by blending with normal network traffic

### Lateral Movement Categories

#### By Authentication Method

<table><thead><tr><th width="178">Category</th><th>Description</th><th>Risk Level</th></tr></thead><tbody><tr><td><strong>Credential-Based</strong></td><td>Using stolen credentials to authenticate</td><td>High</td></tr><tr><td><strong>Token-Based</strong></td><td>Reusing authentication tokens/tickets</td><td>High</td></tr><tr><td><strong>Session-Based</strong></td><td>Hijacking existing sessions</td><td>High</td></tr><tr><td><strong>Key-Based</strong></td><td>Using stolen SSH keys or certificates</td><td>High</td></tr><tr><td><strong>Trust-Based</strong></td><td>Exploiting trust relationships</td><td>Critical</td></tr></tbody></table>

#### By Protocol/Technique

<table><thead><tr><th width="248">Technique</th><th width="213">Protocol/Method</th><th>Common Tools</th></tr></thead><tbody><tr><td><strong>Remote Desktop</strong></td><td>RDP (3389)</td><td>mstsc, SharpRDP</td></tr><tr><td><strong>Windows Admin Shares</strong></td><td>SMB (445)</td><td>PsExec, net use</td></tr><tr><td><strong>Windows Remote Management</strong></td><td>WinRM (5985/5986)</td><td>PowerShell Remoting, Evil-WinRM</td></tr><tr><td><strong>WMI Execution</strong></td><td>DCOM/WMI (135+)</td><td>wmic, Invoke-WmiMethod</td></tr><tr><td><strong>SSH</strong></td><td>SSH (22)</td><td>OpenSSH, PuTTY</td></tr><tr><td><strong>Remote Services</strong></td><td>Various</td><td>RPC, DCOM, MMC</td></tr><tr><td><strong>Pass-the-Hash</strong></td><td>NTLM</td><td>Mimikatz, Impacket</td></tr><tr><td><strong>Pass-the-Ticket</strong></td><td>Kerberos</td><td>Mimikatz, Rubeus</td></tr><tr><td><strong>Overpass-the-Hash</strong></td><td>Kerberos</td><td>Mimikatz, Rubeus</td></tr><tr><td><strong>Pass-the-Certificate</strong></td><td>Kerberos PKINIT</td><td>Certify, Rubeus</td></tr><tr><td><strong>Distributed Component Object Model</strong></td><td>DCOM</td><td>Various</td></tr><tr><td><strong>Remote Registry</strong></td><td>SMB</td><td>reg.exe</td></tr><tr><td><strong>Scheduled Tasks</strong></td><td>RPC/SMB</td><td>schtasks, at</td></tr><tr><td><strong>Service Execution</strong></td><td>RPC/SMB</td><td>sc.exe, PsExec</td></tr></tbody></table>

### Common Lateral Movement Attack Chains

#### Chain 1: Credential Theft → Pass-the-Hash → SMB Lateral Movement

```bash
Initial Access → Credential Dumping (Mimikatz) → NTLM Hash Extracted →
Pass-the-Hash → SMB Connection to Target → PsExec/Service Execution →
SYSTEM Shell on Target
```

#### Chain 2: Kerberoasting → Service Account Compromise → Lateral Movement

```bash
Initial Access → Kerberoasting → Service Account Password Cracked →
Authenticate as Service Account → Access Service Account Resources →
Pivot to Additional Systems
```

#### Chain 3: RDP Hijacking → Session Takeover

```bash
Initial Access → Privilege Escalation → Identify Disconnected RDP Sessions →
RDP Session Hijacking → Access as Hijacked User → Access User's Resources
```

#### Chain 4: WinRM PowerShell Remoting

```bash
Initial Access → Credential Access → Enable-PSRemoting →
Enter-PSSession to Remote Host → Execute Commands →
Establish Persistence → Move to Next Target
```

***

## Detection Sources & Data Mapping

### Log Sources Matrix

<table><thead><tr><th width="223">Platform</th><th width="216">Log Table</th><th>Lateral Movement Data</th></tr></thead><tbody><tr><td>Defender for Endpoint</td><td><code>DeviceLogonEvents</code></td><td>All logon types, source/dest IPs</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceNetworkEvents</code></td><td>SMB, RDP, WinRM connections</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceProcessEvents</code></td><td>PsExec, WMIC, remote execution</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceEvents</code></td><td>Named pipes, remote service creation</td></tr><tr><td>Defender for Identity</td><td><code>IdentityLogonEvents</code></td><td>Authentication anomalies</td></tr><tr><td>Defender for Identity</td><td><code>IdentityDirectoryEvents</code></td><td>Pass-the-Hash, Pass-the-Ticket</td></tr><tr><td>On-Prem AD</td><td><code>SecurityEvent</code></td><td>4624, 4648, 4768, 4769, 4776</td></tr><tr><td>Sentinel</td><td><code>Syslog</code></td><td>Linux SSH, authentication</td></tr><tr><td>Prisma Access</td><td><code>PaloAltoPrismaAccess</code></td><td>East-west traffic, segmentation violations</td></tr><tr><td>Azure/Entra</td><td><code>SigninLogs</code></td><td>Cloud resource access</td></tr></tbody></table>

### Critical Windows Event IDs

#### Network Logon Events

<table><thead><tr><th width="164">Event ID</th><th>Description</th><th>Lateral Movement Relevance</th></tr></thead><tbody><tr><td><strong>4624 (Type 3)</strong></td><td>Network logon</td><td>Primary lateral movement indicator</td></tr><tr><td><strong>4624 (Type 10)</strong></td><td>Remote Interactive (RDP)</td><td>RDP-based lateral movement</td></tr><tr><td><strong>4624 (Type 7)</strong></td><td>Unlock</td><td>Session resume</td></tr><tr><td><strong>4648</strong></td><td>Explicit credential logon</td><td>RunAs, credential reuse</td></tr><tr><td><strong>4625</strong></td><td>Failed logon</td><td>Lateral movement attempts</td></tr><tr><td><strong>4647</strong></td><td>User initiated logoff</td><td>Session end tracking</td></tr></tbody></table>

#### Kerberos Events

<table><thead><tr><th width="186">Event ID</th><th>Description</th><th>Lateral Movement Relevance</th></tr></thead><tbody><tr><td><strong>4768</strong></td><td>TGT requested</td><td>Initial authentication</td></tr><tr><td><strong>4769</strong></td><td>TGS requested</td><td>Service access, Kerberoasting</td></tr><tr><td><strong>4770</strong></td><td>TGT renewed</td><td>Extended session</td></tr><tr><td><strong>4771</strong></td><td>Kerberos pre-auth failed</td><td>Failed lateral movement</td></tr></tbody></table>

#### NTLM Events

<table><thead><tr><th width="200">Event ID</th><th>Description</th><th>Lateral Movement Relevance</th></tr></thead><tbody><tr><td><strong>4776</strong></td><td>NTLM authentication</td><td>Pass-the-Hash detection</td></tr><tr><td><strong>8004</strong></td><td>NTLM authentication (DC)</td><td>NTLM relay, PTH</td></tr></tbody></table>

#### Process & Service Events

<table><thead><tr><th width="166">Event ID</th><th>Description</th><th>Lateral Movement Relevance</th></tr></thead><tbody><tr><td><strong>4688</strong></td><td>Process creation</td><td>Remote command execution</td></tr><tr><td><strong>4697</strong></td><td>Service installed</td><td>PsExec, remote service</td></tr><tr><td><strong>4698</strong></td><td>Scheduled task created</td><td>Remote task execution</td></tr><tr><td><strong>5140</strong></td><td>Network share accessed</td><td>SMB lateral movement</td></tr><tr><td><strong>5145</strong></td><td>Share object access checked</td><td>Admin share access</td></tr></tbody></table>

#### Remote Access Events

<table><thead><tr><th width="170">Event ID</th><th>Description</th><th>Lateral Movement Relevance</th></tr></thead><tbody><tr><td><strong>1149</strong></td><td>RDP authentication succeeded</td><td>RDP lateral movement</td></tr><tr><td><strong>21</strong></td><td>RDP session logon</td><td>RDP session start</td></tr><tr><td><strong>24</strong></td><td>RDP session disconnect</td><td>Session tracking</td></tr><tr><td><strong>25</strong></td><td>RDP session reconnect</td><td>Session hijacking</td></tr><tr><td><strong>4778</strong></td><td>Session reconnected</td><td>Session hijacking</td></tr><tr><td><strong>4779</strong></td><td>Session disconnected</td><td>Session tracking</td></tr></tbody></table>

### Logon Type Reference

<table><thead><tr><th width="148">Logon Type</th><th width="170">Name</th><th>Description</th><th>Lateral Movement Risk</th></tr></thead><tbody><tr><td><strong>2</strong></td><td>Interactive</td><td>Local console logon</td><td>Low (requires physical)</td></tr><tr><td><strong>3</strong></td><td>Network</td><td>SMB, WinRM, remote access</td><td>High</td></tr><tr><td><strong>4</strong></td><td>Batch</td><td>Scheduled task execution</td><td>Medium</td></tr><tr><td><strong>5</strong></td><td>Service</td><td>Service account logon</td><td>Medium</td></tr><tr><td><strong>7</strong></td><td>Unlock</td><td>Workstation unlock</td><td>Low</td></tr><tr><td><strong>8</strong></td><td>NetworkCleartext</td><td>IIS Basic Auth</td><td>Medium</td></tr><tr><td><strong>9</strong></td><td>NewCredentials</td><td>RunAs /netonly</td><td>High</td></tr><tr><td><strong>10</strong></td><td>RemoteInteractive</td><td>RDP</td><td>High</td></tr><tr><td><strong>11</strong></td><td>CachedInteractive</td><td>Cached credentials</td><td>Medium</td></tr></tbody></table>

***

## Investigation Workflows

### General Lateral Movement Investigation

**Objective:** Identify, scope, and contain lateral movement activity across the environment.

#### Step 1: Initial Alert Triage

1. Review alert source and detection logic
2. Identify source and destination systems
3. Determine account(s) involved
4. Check timestamp and establish baseline timeline
5. Assess if source system was already compromised

#### Step 2: Authentication Pattern Analysis

1. Query all logon events for the account (7-30 days)
2. Establish normal access patterns (systems, times, methods)
3. Identify anomalous destination systems
4. Check for unusual logon types
5. Look for authentication method changes (Kerberos vs. NTLM)

#### Step 3: Source System Investigation

1. Determine how attacker gained access to source
2. Check for credential theft indicators
3. Review process execution history
4. Identify lateral movement tools/techniques used
5. Check for persistence mechanisms

#### Step 4: Destination System Investigation

1. Document all activity on destination system
2. Check for secondary lateral movement (pivot)
3. Review data access and exfiltration indicators
4. Identify any persistence established
5. Check for privilege escalation attempts

#### Step 5: Scope Determination

1. Query for same account across all systems
2. Search for same source IP across all authentications
3. Look for similar techniques from other accounts
4. Map all compromised systems
5. Identify potential data exposure

#### Step 6: Timeline Construction

1. Create chronological timeline of all events
2. Map initial access → lateral movement chain
3. Document each hop with timestamps
4. Identify dwell time per system
5. Correlate with known threat actor TTPs

***

### RDP Lateral Movement Investigation

**Objective:** Investigate Remote Desktop-based lateral movement.

#### Detection Indicators

* Logon Type 10 from unusual sources
* RDP connections during non-business hours
* RDP from servers to workstations (unusual direction)
* RDP session hijacking (tscon.exe usage)
* Multiple failed RDP attempts followed by success
* RDP connections from recently compromised systems

#### Investigation Steps

1. **Identify RDP Sessions**
   * Query DeviceLogonEvents for LogonType "RemoteInteractive"
   * Review Event ID 1149, 21, 24, 25 on target
   * Check TerminalServices-LocalSessionManager logs
2. **Analyse Source System**
   * Verify source system is authorised for RDP
   * Check if source system shows compromise indicators
   * Review outbound RDP connections from source
   * Check for RDP-related tools (mstsc spawning from unusual parents)
3. **Session Hijacking Detection**
   * Search for tscon.exe execution
   * Check for query session / quser commands
   * Look for session ID manipulation
   * Review SYSTEM-level RDP access
4. **Map RDP Chain**
   * Track all RDP hops from initial system
   * Document credentials used at each hop
   * Identify final destination/objective
   * Check for data accessed via RDP sessions

***

### SMB/Admin Share Lateral Movement Investigation

**Objective:** Investigate lateral movement via Windows Admin Shares and SMB.

#### Detection Indicators

* Access to C$, ADMIN$, IPC$ shares from non-admin workstations
* SMB connections to unusual systems
* PsExec service installation (PSEXESVC)
* High volume of SMB connections from single source
* SMB authentication failures followed by success
* Use of explicit credentials for SMB access

#### Investigation Steps

1. **Identify SMB Activity**
   * Query Event ID 5140, 5145 for share access
   * Review DeviceNetworkEvents for port 445 connections
   * Check for admin share ($) access patterns
   * Identify source IPs and accounts
2. **PsExec/Remote Service Detection**
   * Search for PSEXESVC service creation
   * Look for services with unusual names
   * Check for service binary paths to ADMIN$
   * Review service account usage
3. **File Transfer Analysis**
   * Check for executable files copied to shares
   * Review files dropped in ADMIN$, C$
   * Look for staging directories
   * Identify malicious payloads transferred
4. **Credential Analysis**
   * Determine if PTH was used (NTLM only)
   * Check for explicit credential usage (4648)
   * Review account privilege level
   * Identify source of compromised credentials

***

### WinRM/PowerShell Remoting Investigation

**Objective:** Investigate lateral movement via Windows Remote Management.

#### Detection Indicators

* WinRM connections (port 5985/5986) from unusual sources
* PowerShell remoting from non-admin systems
* Enter-PSSession / Invoke-Command usage
* WinRM service enabled on unusual systems
* Encoded PowerShell commands in remote sessions
* Evil-WinRM or similar tool signatures

#### Investigation Steps

1. **Identify WinRM Sessions**
   * Query DeviceNetworkEvents for ports 5985/5986
   * Review Windows Remote Management operational logs
   * Check for WSMan connections
   * Identify source and destination pairs
2. **PowerShell Analysis**
   * Review PowerShell script block logging
   * Check for encoded commands in remote sessions
   * Analyse Invoke-Command patterns
   * Look for New-PSSession creations
3. **Credential Usage**
   * Check if CredSSP was used (credential delegation)
   * Review explicit credential specifications
   * Look for Enter-PSSession with -Credential
   * Check for PSCredential object creation
4. **Command Execution**
   * Review commands executed via remoting
   * Check for reconnaissance commands
   * Look for credential access commands
   * Identify persistence establishment

***

### WMI Lateral Movement Investigation

**Objective:** Investigate lateral movement via Windows Management Instrumentation.

#### Detection Indicators

* WMIC process creation events
* WMI remote connections (DCOM)
* WmiPrvSE.exe spawning unusual processes
* Process creation via Win32\_Process
* WMI subscriptions created remotely
* Event ID 5857, 5858, 5859, 5861 (WMI Activity)

#### Investigation Steps

1. **Identify WMI Activity**
   * Query for WMIC.exe process execution
   * Review WmiPrvSE.exe child processes
   * Check WMI-Activity operational logs
   * Look for Win32\_Process Create method calls
2. **Remote WMI Detection**
   * Check for /node: parameter in WMIC
   * Review DCOM connections (port 135+)
   * Look for WMI authentication events
   * Identify source systems for remote WMI
3. **Command Execution Analysis**
   * Review process command lines
   * Check for encoded commands
   * Look for script downloads/execution
   * Identify persistence attempts

***

### Pass-the-Hash/Ticket Investigation

**Objective:** Investigate credential reuse attacks for lateral movement.

#### Pass-the-Hash Indicators

* NTLM authentication where Kerberos expected
* Network logons without corresponding interactive logon
* Event 4776 success without 4624 Type 2
* NTLM from systems with Kerberos capability
* Multiple hosts accessed with same NTLM hash
* Impacket/Mimikatz tool indicators

#### Pass-the-Ticket Indicators

* Kerberos tickets used from unexpected hosts
* TGS without corresponding TGT request
* Ticket encryption anomalies
* Forwardable tickets from non-domain systems
* Service access without prior TGT

#### Investigation Steps

1. **Identify Authentication Anomalies**
   * Correlate NTLM vs Kerberos usage
   * Check for missing authentication chain events
   * Review MDI alerts for PTH/PTT
   * Analyse authentication source vs. account home
2. **Timeline Reconstruction**
   * Map all authentications for affected account
   * Identify patient zero for credential theft
   * Track all systems accessed post-compromise
   * Correlate with credential dumping activity
3. **Ticket Analysis (PTT)**
   * Review Kerberos ticket properties
   * Check for anomalous encryption types
   * Look for ticket lifetime anomalies
   * Identify service tickets without TGT

***

## KQL Query Cheat Sheet

### Network Logon Analysis

#### All Network Logons (Type 3)

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize 
    LogonCount = count(),
    UniqueTargets = dcount(DeviceName),
    Targets = make_set(DeviceName, 20),
    UniqueAccounts = dcount(AccountName)
    by RemoteIP, bin(Timestamp, 1h)
| where UniqueTargets > 5
| sort by UniqueTargets desc
```

#### Unusual Network Logon Sources

```kusto
let baseline = DeviceLogonEvents
| where Timestamp between (ago(30d) .. ago(1d))
| where LogonType == "Network"
| summarize by AccountName, RemoteIP;
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| join kind=leftanti baseline on AccountName, RemoteIP
| summarize 
    FirstSeen = min(Timestamp),
    LogonCount = count(),
    TargetDevices = make_set(DeviceName, 10)
    by AccountName, RemoteIP
| sort by LogonCount desc
```

#### Lateral Movement Velocity Detection

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| summarize 
    TargetCount = dcount(DeviceName),
    Targets = make_set(DeviceName, 50),
    MinTime = min(Timestamp),
    MaxTime = max(Timestamp)
    by AccountName, bin(Timestamp, 1h)
| extend VelocityPerHour = TargetCount
| where VelocityPerHour > 5
| sort by VelocityPerHour desc
```

***

### RDP Lateral Movement

#### RDP Connections Analysis

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| summarize 
    RDPCount = count(),
    UniqueTargets = dcount(DeviceName),
    Targets = make_set(DeviceName, 10)
    by AccountName, RemoteIP
| sort by UniqueTargets desc
```

#### RDP from Server to Workstation (Unusual Direction)

{% code overflow="wrap" %}
```kusto
let servers = DeviceInfo 
| where DeviceType == "Server" 
| summarize by DeviceName;
let workstations = DeviceInfo 
| where DeviceType == "Workstation" 
| summarize by DeviceName;
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| join kind=inner servers on $left.RemoteDeviceName == $right.DeviceName
| join kind=inner workstations on $left.DeviceName == $right.DeviceName
| project Timestamp, AccountName, SourceServer = RemoteDeviceName, TargetWorkstation = DeviceName
| sort by Timestamp desc
```
{% endcode %}

#### RDP Session Hijacking Detection

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "tscon.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp desc
```
{% endcode %}

#### RDP Brute Force Followed by Success

{% code overflow="wrap" %}
```kusto
let rdpFailures = DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonFailed"
| summarize FailCount = count() by RemoteIP, TargetDevice = DeviceName, bin(Timestamp, 1h);
let rdpSuccess = DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project SuccessTime = Timestamp, RemoteIP, TargetDevice = DeviceName, AccountName;
rdpFailures
| join kind=inner rdpSuccess on RemoteIP, TargetDevice
| where FailCount > 5
| project RemoteIP, TargetDevice, FailCount, SuccessTime, AccountName
| sort by FailCount desc
```
{% endcode %}

***

### SMB/Admin Share Activity

#### Admin Share Access Detection

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any ("C$", "ADMIN$", "IPC$")
| summarize 
    ConnectionCount = count(),
    UniqueTargets = dcount(RemoteIP),
    Targets = make_set(RemoteIP, 10)
    by DeviceName, InitiatingProcessFileName, RemoteUrl
| sort by UniqueTargets desc
```

#### PsExec Service Detection

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| extend ServicePath = tostring(parse_json(AdditionalFields).ServiceStartType)
| where ServiceName matches regex @"(?i)(psexe|paexe|csexe|smbexec|remcom)"
    or ServiceName matches regex @"^[a-zA-Z]{8}$"  // Random 8-char service names
| project Timestamp, DeviceName, ServiceName, InitiatingProcessFileName, InitiatingProcessAccountName
```
{% endcode %}

#### SMB Lateral Movement Pattern

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| summarize 
    SMBConnections = count(),
    UniqueTargets = dcount(RemoteIP),
    Targets = make_set(RemoteIP, 50)
    by DeviceName, bin(Timestamp, 15m)
| where UniqueTargets > 10
| sort by UniqueTargets desc
```

#### File Copy to Admin Shares

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath matches regex @"\\\\[^\\]+\\(C\$|ADMIN\$)"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| sort by Timestamp desc
```
{% endcode %}

***

### WinRM/PowerShell Remoting

#### WinRM Connections

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (5985, 5986)
| where ActionType == "ConnectionSuccess"
| summarize 
    Connections = count(),
    UniqueTargets = dcount(RemoteIP),
    Targets = make_set(RemoteIP, 20)
    by DeviceName, InitiatingProcessFileName
| where UniqueTargets > 3
| sort by UniqueTargets desc
```

#### PowerShell Remoting Commands

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any (
    "Enter-PSSession",
    "Invoke-Command",
    "New-PSSession",
    "-ComputerName",
    "Enable-PSRemoting",
    "-Session")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```

#### Remote PowerShell Session Creation

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("New-PSSession", "Enter-PSSession", "Invoke-Command")
| extend Command = tostring(parse_json(AdditionalFields).Command)
| project Timestamp, DeviceName, AccountName, Command
```
{% endcode %}

***

### WMI Lateral Movement

#### Remote WMI Execution

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "/node:"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```

#### WMI Process Creation

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName !in~ ("wmiprvse.exe", "wbem", "mofcomp.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp desc
```
{% endcode %}

#### DCOM Lateral Movement

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 135 or RemotePort between (49152 .. 65535)
| where InitiatingProcessFileName in~ ("mmc.exe", "excel.exe", "outlook.exe", "powershell.exe")
| summarize 
    Connections = count(),
    UniqueTargets = dcount(RemoteIP)
    by DeviceName, InitiatingProcessFileName, RemotePort
| where UniqueTargets > 3
```
{% endcode %}

***

### Pass-the-Hash / Pass-the-Ticket

#### NTLM Authentication Anomalies

{% code overflow="wrap" %}
```kusto
// NTLM where Kerberos expected
IdentityLogonEvents
| where Timestamp > ago(24h)
| where Protocol == "NTLM"
| where LogonType == "Network"
| where TargetDeviceName !has "exchange" and TargetDeviceName !has "sql"  // Exclude known NTLM users
| summarize 
    NTLMCount = count(),
    UniqueTargets = dcount(TargetDeviceName),
    Targets = make_set(TargetDeviceName, 20)
    by AccountUpn, DeviceName
| where UniqueTargets > 3
| sort by UniqueTargets desc
```
{% endcode %}

#### Pass-the-Hash Detection (MDI)

```kusto
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Application == "Active Directory"
| where Protocol == "NTLM"
| where LogonType == "Network"
| join kind=leftanti (
    IdentityLogonEvents
    | where Timestamp > ago(7d)
    | where LogonType == "Interactive"
    | project AccountUpn, InteractiveDevice = DeviceName, InteractiveTime = Timestamp
) on AccountUpn
| summarize 
    PotentialPTH = count(),
    Targets = make_set(TargetDeviceName, 20),
    SourceDevices = make_set(DeviceName, 10)
    by AccountUpn
| where PotentialPTH > 5
```

#### Kerberos Ticket Anomalies

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| where TicketEncryptionType in ("0x17", "0x18")  // RC4 or AES
| summarize 
    TicketRequests = count(),
    UniqueServices = dcount(ServiceName),
    EncryptionTypes = make_set(TicketEncryptionType)
    by TargetUserName, IpAddress
| where TicketRequests > 20 or UniqueServices > 10
```

***

### Scheduled Task & Service Lateral Movement

#### Remote Scheduled Task Creation

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has_any ("/s ", "/S ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```

#### Remote Service Creation

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any ("create", "config", "start") 
    and ProcessCommandLine matches regex @"\\\\[^\\]+\\"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```

***

### Cross-Platform Queries

#### Unified Lateral Movement Detection

{% code overflow="wrap" %}
```kusto
let networkLogons = DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, SourceDevice = RemoteDeviceName, TargetDevice = DeviceName, Method = "Logon";
let smbConnections = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project Timestamp, AccountName = InitiatingProcessAccountName, SourceDevice = DeviceName, TargetDevice = RemoteIP, Method = "SMB";
let winrmConnections = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (5985, 5986)
| where ActionType == "ConnectionSuccess"
| project Timestamp, AccountName = InitiatingProcessAccountName, SourceDevice = DeviceName, TargetDevice = RemoteIP, Method = "WinRM";
union networkLogons, smbConnections, winrmConnections
| summarize 
    Connections = count(),
    Methods = make_set(Method),
    UniqueTargets = dcount(TargetDevice),
    Targets = make_set(TargetDevice, 20)
    by AccountName, SourceDevice, bin(Timestamp, 1h)
| where UniqueTargets > 5
| sort by UniqueTargets desc
```
{% endcode %}

#### Lateral Movement Chain Reconstruction

{% code overflow="wrap" %}
```kusto
let timeframe = 24h;
let seedDevice = "COMPROMISED-WKS01";  // Starting point
DeviceLogonEvents
| where Timestamp > ago(timeframe)
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| where RemoteDeviceName == seedDevice or DeviceName == seedDevice
| project Timestamp, AccountName, Source = RemoteDeviceName, Target = DeviceName, LogonType
| sort by Timestamp asc
```
{% endcode %}

***

### Prisma Access Network Detection

#### East-West Traffic Anomalies

```kusto
PaloAltoPrismaAccess
| where TimeGenerated > ago(24h)
| where DestinationZone != "internet" and SourceZone != "internet"
| where Action == "allow"
| summarize 
    Connections = count(),
    BytesTotal = sum(BytesTotal),
    UniqueDestinations = dcount(DestinationIP)
    by SourceIP, SourceUser
| where UniqueDestinations > 20
| sort by UniqueDestinations desc
```

#### Unusual Internal RDP Traffic

```kusto
PaloAltoPrismaAccess
| where TimeGenerated > ago(24h)
| where DestinationPort == 3389
| where Action == "allow"
| summarize 
    RDPConnections = count(),
    UniqueDestinations = dcount(DestinationIP),
    Destinations = make_set(DestinationIP, 20)
    by SourceIP, SourceUser
| where UniqueDestinations > 5
| sort by UniqueDestinations desc
```

***

## Response Actions & Remediation

### Immediate Containment Actions

| Scenario                         | Action                                        | Method                   |
| -------------------------------- | --------------------------------------------- | ------------------------ |
| **Active Lateral Movement**      | Isolate source and destination systems        | MDE Device Isolation     |
| **Compromised Account**          | Disable account, revoke sessions              | AD + Entra ID            |
| **Credential Theft Confirmed**   | Reset all potentially compromised credentials | AD + Entra ID            |
| **RDP-based Movement**           | Block RDP at network level                    | Prisma Access / Firewall |
| **SMB-based Movement**           | Block SMB between segments                    | Prisma Access / Firewall |
| **PTH/PTT Detected**             | Reset affected account passwords              | AD                       |
| **Multiple Systems Compromised** | Network segment isolation                     | Firewall / VLAN changes  |

### Containment Commands

#### MDE Device Isolation

```powershell
# Via Microsoft Graph API
$deviceId = "device-id-here"
$isolationType = "Full"  # or "Selective"

$body = @{
    Comment = "Lateral movement investigation - IR ticket #12345"
    IsolationType = $isolationType
} | ConvertTo-Json

Invoke-MgGraphRequest -Method POST `
    -Uri "https://api.securitycenter.microsoft.com/api/machines/$deviceId/isolate" `
    -Body $body
```

#### Block Lateral Movement at Network Level

```
# Prisma Access - Create emergency security rule
Rule Name: EMERGENCY-Block-Lateral-Movement
Source Zone: trust
Destination Zone: trust  
Source Address: [compromised-subnet]
Destination Address: any
Application: any
Service: application-default
Action: Deny
Log: Yes
```

#### Disable Compromised Account

```powershell
# On-premises AD
Disable-ADAccount -Identity "compromised_user"

# Entra ID
Update-MgUser -UserId "user@domain.com" -AccountEnabled:$false

# Revoke all sessions
Revoke-MgUserSignInSession -UserId "user@domain.com"
```

### Post-Incident Remediation

#### For Each Compromised System

1. **Evidence Collection**
   * Memory dump if possible
   * Event logs export
   * File system timeline
   * Network connection logs
2. **Malware/Tool Removal**
   * Remove attacker tools
   * Delete persistence mechanisms
   * Clear credential caches
   * Remove unauthorised accounts
3. **Credential Reset**
   * Reset local admin passwords
   * Reset cached domain credentials
   * Consider LAPS redeployment
4. **System Hardening**
   * Apply missing patches
   * Enable advanced audit logging
   * Implement host firewall rules
   * Deploy/verify EDR agent

#### Network-Level Hardening

| Action                    | Description                         | Implementation         |
| ------------------------- | ----------------------------------- | ---------------------- |
| **Segment Networks**      | Limit lateral movement paths        | VLAN / Firewall rules  |
| **Restrict Admin Shares** | Disable C$, ADMIN$ where not needed | GPO / Registry         |
| **Limit RDP Access**      | Restrict RDP to jump servers        | Firewall / NLA         |
| **Disable WinRM**         | Disable where not required          | GPO                    |
| **Implement LAPS**        | Randomize local admin passwords     | LAPS deployment        |
| **Deploy PAWs**           | Privileged Access Workstations      | Tiered admin model     |
| **Block NTLM**            | Enforce Kerberos authentication     | GPO / Network policies |

***

## Quick Reference Cards

### Lateral Movement Tool Signatures

<table><thead><tr><th width="178">Tool</th><th>Process Indicators</th><th>Network Indicators</th></tr></thead><tbody><tr><td><strong>PsExec</strong></td><td>PSEXESVC service, psexec.exe</td><td>SMB (445) to ADMIN$</td></tr><tr><td><strong>Impacket</strong></td><td>Random service names, atexec.py</td><td>SMB (445), WMI (135)</td></tr><tr><td><strong>CrackMapExec</strong></td><td>Multiple SMB connections</td><td>SMB (445) spray pattern</td></tr><tr><td><strong>Evil-WinRM</strong></td><td>winrm connections, ruby signatures</td><td>WinRM (5985/5986)</td></tr><tr><td><strong>Mimikatz</strong></td><td>sekurlsa, lsadump commands</td><td>PTH/PTT artifacts</td></tr><tr><td><strong>Cobalt Strike</strong></td><td>Named pipes, beacons</td><td>HTTP/HTTPS beaconing</td></tr><tr><td><strong>WMIExec</strong></td><td>wmiprvse.exe children</td><td>DCOM (135+)</td></tr><tr><td><strong>SharpRDP</strong></td><td>mstsc activity, unusual parents</td><td>RDP (3389)</td></tr><tr><td><strong>Rubeus</strong></td><td>Kerberos ticket manipulation</td><td>4768, 4769 anomalies</td></tr></tbody></table>

### Lateral Movement Detection Checklist

| Check                              | Data Source         | Query Focus             |
| ---------------------------------- | ------------------- | ----------------------- |
| Network logons to multiple systems | DeviceLogonEvents   | Type 3, unique targets  |
| RDP connections from servers       | DeviceLogonEvents   | Type 10, server sources |
| Admin share access                 | DeviceNetworkEvents | Port 445, C$, ADMIN$    |
| Service installation               | DeviceEvents        | ServiceInstalled        |
| Scheduled task creation            | DeviceEvents        | ScheduledTaskCreated    |
| WinRM connections                  | DeviceNetworkEvents | Port 5985/5986          |
| WMI remote execution               | DeviceProcessEvents | wmic /node              |
| NTLM without Kerberos              | IdentityLogonEvents | Protocol analysis       |
| Pass-the-Hash                      | MDI alerts          | PTH detection           |
| Pass-the-Ticket                    | MDI alerts          | PTT detection           |

### Common Lateral Movement Ports

| Port            | Protocol    | Usage                | Risk     |
| --------------- | ----------- | -------------------- | -------- |
| **22**          | SSH         | Linux remote access  | High     |
| **135**         | RPC/DCOM    | WMI, DCOM            | High     |
| **139**         | NetBIOS     | Legacy file sharing  | Medium   |
| **445**         | SMB         | File sharing, PsExec | Critical |
| **3389**        | RDP         | Remote Desktop       | High     |
| **5985**        | WinRM HTTP  | PowerShell Remoting  | High     |
| **5986**        | WinRM HTTPS | Secure PS Remoting   | High     |
| **49152-65535** | Dynamic RPC | DCOM, WMI callbacks  | High     |

***

## Escalation Matrix

### Severity Classification

<table><thead><tr><th width="125">Severity</th><th width="427">Criteria</th><th>Response Time</th></tr></thead><tbody><tr><td>🔴 <strong>Critical</strong></td><td>Domain controller accessed, mass lateral movement (>10 systems), privileged account compromise</td><td>Immediate - 15 min</td></tr><tr><td>🟠 <strong>High</strong></td><td>Multiple systems compromised (3-10), active C2 with lateral movement, data server access</td><td>30 min - 1 hour</td></tr><tr><td>🟡 <strong>Medium</strong></td><td>Single system pivot, limited lateral movement, contained to workstation tier</td><td>4 hours</td></tr><tr><td>🟢 <strong>Low</strong></td><td>Failed lateral movement attempts, reconnaissance only</td><td>Next business day</td></tr></tbody></table>

### Escalation Triggers

| Condition                          | Escalation Level            |
| ---------------------------------- | --------------------------- |
| Domain Controller lateral movement | DFIR + Identity Team + CISO |
| >5 systems confirmed compromised   | DFIR Team + SOC Manager     |
| Pass-the-Hash/Ticket confirmed     | Tier 2 SOC + Identity Team  |
| Database/file server accessed      | Tier 2 SOC + Data Owner     |
| Active command and control         | DFIR + Network Team         |
| Lateral movement chain >3 hops     | Tier 2 SOC                  |
| Unknown tools/techniques           | DFIR for analysis           |

### Communication Flow

```bash
Detection → Tier 1 Triage → Severity Assessment →
├── Low/Medium → Tier 1 Investigation → Document & Monitor
├── High → Tier 2 + Containment → DFIR if needed
└── Critical → Immediate DFIR → Leadership Notification → IR Activation
```

***

## MITRE ATT\&CK Mapping

### Lateral Movement (TA0008)

<table><thead><tr><th width="253">Technique</th><th>ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Remote Services: RDP</td><td>T1021.001</td><td>Remote Desktop Protocol</td><td>DeviceLogonEvents (Type 10)</td></tr><tr><td>Remote Services: SMB/Admin Shares</td><td>T1021.002</td><td>Windows Admin Shares</td><td>Event 5140, 5145</td></tr><tr><td>Remote Services: DCOM</td><td>T1021.003</td><td>Distributed COM</td><td>DeviceNetworkEvents (135)</td></tr><tr><td>Remote Services: SSH</td><td>T1021.004</td><td>Secure Shell</td><td>Syslog, network logs</td></tr><tr><td>Remote Services: WinRM</td><td>T1021.006</td><td>Windows Remote Management</td><td>DeviceNetworkEvents (5985/5986)</td></tr><tr><td>Remote Service Session Hijacking: RDP</td><td>T1563.002</td><td>RDP Session Hijacking</td><td>tscon.exe, Event 4778</td></tr><tr><td>Use Alternate Authentication Material: PTH</td><td>T1550.002</td><td>Pass the Hash</td><td>Event 4776, MDI</td></tr><tr><td>Use Alternate Authentication Material: PTT</td><td>T1550.003</td><td>Pass the Ticket</td><td>Event 4768/4769, MDI</td></tr><tr><td>Exploitation of Remote Services</td><td>T1210</td><td>Exploit vulnerabilities</td><td>MDE alerts</td></tr><tr><td>Internal Spearphishing</td><td>T1534</td><td>Phish internal users</td><td>EmailEvents</td></tr><tr><td>Lateral Tool Transfer</td><td>T1570</td><td>Copy tools between systems</td><td>DeviceFileEvents</td></tr><tr><td>Software Deployment Tools</td><td>T1072</td><td>Abuse deployment tools</td><td>Varies by tool</td></tr><tr><td>Taint Shared Content</td><td>T1080</td><td>Modify shared resources</td><td>DeviceFileEvents</td></tr></tbody></table>

### Related Techniques

<table><thead><tr><th width="157">Tactic</th><th width="217">Technique</th><th width="72">ID</th><th>Relevance</th></tr></thead><tbody><tr><td>Discovery</td><td>Network Share Discovery</td><td>T1135</td><td>Pre-lateral movement recon</td></tr><tr><td>Discovery</td><td>Remote System Discovery</td><td>T1018</td><td>Target identification</td></tr><tr><td>Credential Access</td><td>OS Credential Dumping</td><td>T1003</td><td>Enables credential-based movement</td></tr><tr><td>Execution</td><td>Windows Management Instrumentation</td><td>T1047</td><td>WMI lateral execution</td></tr><tr><td>Execution</td><td>Scheduled Task/Job</td><td>T1053</td><td>Remote task execution</td></tr><tr><td>Execution</td><td>Service Execution</td><td>T1569</td><td>PsExec-style execution</td></tr></tbody></table>

***

## Appendix: Investigation Commands

### Network Connection Analysis

```powershell
# Get active network connections with process info
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
        ProcessName = $proc.Name
        ProcessPath = $proc.Path
        ProcessId = $_.OwningProcess
    }
} | Where-Object {$_.RemotePort -in @(445, 3389, 5985, 5986, 135, 22)}

# Check for RDP connections
qwinsta /server:localhost

# List established SMB sessions
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens

# Check WinRM connectivity
Test-WSMan -ComputerName targetserver -ErrorAction SilentlyContinue
```

### Authentication Event Analysis

```powershell
# Get recent network logons
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 100 | Where-Object {
    $_.Properties[8].Value -eq 3  # Logon Type 3 (Network)
} | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = $_.Properties[5].Value
        Domain = $_.Properties[6].Value
        SourceIP = $_.Properties[18].Value
        LogonType = $_.Properties[8].Value
    }
}

# Get explicit credential usage (4648)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4648
} -MaxEvents 50 | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        SubjectUser = $_.Properties[1].Value
        TargetUser = $_.Properties[5].Value
        TargetServer = $_.Properties[9].Value
        ProcessName = $_.Properties[11].Value
    }
}

# Get NTLM authentications
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4776
} -MaxEvents 100 | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = $_.Properties[1].Value
        Workstation = $_.Properties[2].Value
        Status = $_.Properties[4].Value
    }
}
```

### Service & Task Analysis

```powershell
# Get recently created services
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID = 7045
} -MaxEvents 20 | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        ServiceName = $_.Properties[0].Value
        ImagePath = $_.Properties[1].Value
        ServiceType = $_.Properties[2].Value
        StartType = $_.Properties[3].Value
        Account = $_.Properties[4].Value
    }
}

# Get scheduled tasks created recently
Get-ScheduledTask | Where-Object {
    $_.Date -gt (Get-Date).AddDays(-7)
} | Select-Object TaskName, TaskPath, Author, Date, State

# Check for PsExec service
Get-Service | Where-Object {$_.Name -match "psexe|paexe|remcom|csexe"}
```

### Remote Execution Detection

```powershell
# Check for recent PowerShell remoting
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    ID = 4103, 4104
} -MaxEvents 100 | Where-Object {
    $_.Message -match "Invoke-Command|Enter-PSSession|New-PSSession"
}

# Check WMI activity
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    ID = 5857, 5858, 5859, 5861
} -MaxEvents 50

# Check for remote registry access
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
} -MaxEvents 100 | Where-Object {
    $_.Properties[6].Value -match "Registry"
}
```

### Lateral Movement Tool Detection

{% code overflow="wrap" %}
```powershell
# Search for common lateral movement tools
$toolPatterns = @(
    "mimikatz",
    "psexec",
    "paexec", 
    "wmiexec",
    "smbexec",
    "atexec",
    "crackmapexec",
    "evil-winrm",
    "rubeus",
    "sharphound",
    "bloodhound"
)

Get-ChildItem -Path C:\Users, C:\Windows\Temp, C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object {
        $file = $_
        $toolPatterns | Where-Object {$file.Name -match $_}
    } | Select-Object FullName, CreationTime, LastWriteTime

# Check running processes for tool signatures
Get-Process | Where-Object {
    $proc = $_
    $toolPatterns | Where-Object {$proc.Name -match $_ -or $proc.Path -match $_}
}
```
{% endcode %}

### Evidence Collection Script

{% code overflow="wrap" %}
```powershell
# Lateral Movement Evidence Collection
$outputPath = "C:\IR_LateralMovement_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputPath -Force

# System info
systeminfo > "$outputPath\systeminfo.txt"

# Network connections
Get-NetTCPConnection | Export-Csv "$outputPath\network_connections.csv" -NoTypeInformation

# SMB Sessions
Get-SmbSession | Export-Csv "$outputPath\smb_sessions.csv" -NoTypeInformation

# Recent logons (Security log)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625,4648,4776} -MaxEvents 1000 |
    Export-Csv "$outputPath\logon_events.csv" -NoTypeInformation

# Services
Get-WmiObject Win32_Service | Export-Csv "$outputPath\services.csv" -NoTypeInformation

# Scheduled Tasks
Get-ScheduledTask | Export-Csv "$outputPath\scheduled_tasks.csv" -NoTypeInformation

# RDP Sessions
qwinsta > "$outputPath\rdp_sessions.txt"

# PowerShell history (all users)
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $user = $_.FullName.Split('\')[2]
        Copy-Item $_.FullName "$outputPath\ps_history_$user.txt"
    }

# Compress
Compress-Archive -Path $outputPath -DestinationPath "$outputPath.zip" -Force

Write-Host "Evidence collected to: $outputPath.zip"
```
{% endcode %}

***

> ⚠️ **Critical Investigation Note:** Lateral movement rarely occurs in isolation.&#x20;
>
> Always investigate: (1) How did the attacker gain initial access? (2) What credential theft occurred before movement? (3) What is the attacker's objective? (4) Has data exfiltration occurred?&#x20;
>
> Treat any confirmed lateral movement as a potential full environment compromise until proven otherwise.
