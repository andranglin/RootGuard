---
description: DFIR Cheatsheet
---

# Windows AD Attack Investigation – Velociraptor Cheatsheet

Table of Contents

1. Investigation Workflow
2. Initial Triage
3. Credential Attacks
4. Kerberos Attacks
5. Privilege Escalation
6. Lateral Movement
7. Persistence Mechanisms
8. Domain Controller Attacks
9. Golden/Silver Ticket Detection
10. Data Exfiltration

***

### Investigation Workflow

#### Phase 1: Scope Definition

1. Identify compromised accounts/systems
2. Determine attack timeline
3. Define investigation scope (hosts, domain controllers, time range)

#### Phase 2: Data Collection

1. Deploy Velociraptor agents to target systems
2. Execute targeted artifact collection
3. Preserve evidence integrity

#### Phase 3: Analysis

1. Analyse collected artifacts
2. Correlate events across systems
3. Build attack timeline

#### Phase 4: Containment & Remediation

1. Document findings
2. Implement containment measures
3. Provide remediation recommendations

***

### Initial Triage

#### Check System Status and Connections

{% code overflow="wrap" %}
```sql
-- Query active network connections
SELECT * FROM netstat()
WHERE Status = 'ESTABLISHED'

-- Check for suspicious processes
SELECT Name, Pid, Ppid, CommandLine, Username, 
       Authenticode.Trusted, Hash.SHA256
FROM pslist()
WHERE NOT Authenticode.Trusted OR CommandLine =~ "powershell|cmd|wmic|mimikatz|procdump"
```
{% endcode %}

#### Collect Windows Event Logs

```sql
-- Security Event Log (Authentication Events)
SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(
  EvtxGlob='C:/Windows/System32/winevt/Logs/Security.evtx',
  IocRegex='4624|4625|4648|4768|4769|4771|4776|4672'
)

-- System Event Log
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
WHERE EventID IN (7045, 7036, 7040)
```

#### Rapid Host Survey

```sql
-- Collect system information
SELECT * FROM Artifact.Windows.System.SurveyHostInfo()

-- Check logged-in users
SELECT * FROM Artifact.Windows.System.Users()
```

***

### Credential Attacks

#### Detect LSASS Access (Credential Dumping)

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter`
* `Windows.Detection.ProcessCreation`
* `Windows.Memory.Acquisition`
* `Windows.System.Handles`

**What to Look For:**

* **Process Access to LSASS** - Event ID 4656 showing processes opening handles to lsass.exe
* **Known Tool Names** - Mimikatz, procdump, dumpert, pypykatz, comsvcs.dll
* **Suspicious Parent Processes** - cmd.exe, powershell.exe spawning memory dump tools
* **Living-off-the-land** - rundll32.exe calling comsvcs.dll (native Windows DLL for dumps)
* **Handle Count Anomalies** - Unusual processes with handles to lsass.exe

**Analysis Steps:**

1. Check Security.evtx for Event ID 4656 targeting lsass.exe
2. Correlate with Event ID 4688 (process creation) to identify the attacking process
3. Look for crash dump files in unusual locations (not C:\Windows\Minidump)
4. Check for base64 encoded commands in PowerShell logs
5. Examine process command lines for `-ma lsass.exe` or similar dump flags
6. Verify legitimacy - Some admin tools legitimately access LSASS (backup software, AV)

**Red Flags:**

* Multiple failed LSASS access attempts followed by success
* LSASS access from user workstations (rare in normal operations)
* Process spawned from Office applications accessing LSASS
* Recent file modifications in Temp folders with .dmp extension
* Remote process creation followed immediately by LSASS access

{% code overflow="wrap" %}
```sql
-- Check for LSASS process access
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4656 AND EventData.ObjectName =~ "lsass.exe"

-- Hunt for credential dumping tools
SELECT * FROM Artifact.Windows.Detection.ProcessCreation(
  ProcessRegex='mimikatz|procdump|dumpert|nanodump|pypykatz|lazagne|comsvcs'
)

-- Check for suspicious LSASS handles
SELECT Pid, Name, Handles
FROM handles()
WHERE Name =~ "lsass.exe"
```
{% endcode %}

#### Detect DCSync Attacks

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter` (on Domain Controllers)
* `Windows.EventLogs.AlternateLogon`
* `Windows.System.Users`
* `Windows.Forensics.Timeline`

**What to Look For:**

* **Event ID 4662** - Directory Service Access with specific GUID properties
  * `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` - DS-Replication-Get-Changes
  * `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` - DS-Replication-Get-Changes-All
  * `89e95b76-444d-4c62-991a-0facbeda640c` - DS-Replication-Get-Changes-In-Filtered-Set
* **Non-DC Sources** - Replication requests from workstations/member servers
* **Tool Artifacts** - Mimikatz DCSync module, Invoke-Mimikatz, secretsdump.py
* **Unusual User Accounts** - Service accounts or standard users performing replication

**Analysis Steps:**

1. **Check Source Host** - Is it a legitimate Domain Controller? Query DC list from AD
2. **Review User Context** - Does this account normally perform replication operations?
3. **Check Timing** - Multiple replication requests in short timeframe = bulk dumping
4. **Correlate with Network** - Look for large data transfers to external IPs after replication
5. **Review Account Privileges** - Verify if account has "Replicating Directory Changes" permission
6. **Check for Tool Execution** - Look for PowerShell scripts, Python processes on the source

**Red Flags:**

* Workstation hostname in SubjectMachineName field
* Service account triggering replication outside maintenance windows
* Replication requests for krbtgt account specifically
* Multiple object types replicated in succession (users, computers, groups)
* Replication followed by logoff and network disconnect
* User account that shouldn't have replication rights performing DCSync

**Legitimate vs Malicious:**

* **Legitimate**: DC-to-DC replication, scheduled backups, Azure AD Connect
* **Malicious**: Single workstation, manual user context, after-hours, high volume

```sql
-- Event ID 4662 - Directory Service Access
SELECT EventData.SubjectUserName as Username,
       EventData.ObjectName as ObjectAccessed,
       EventData.Properties as Properties,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4662 
  AND (Properties =~ "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR
       Properties =~ "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" OR
       Properties =~ "89e95b76-444d-4c62-991a-0facbeda640c")

-- Replication activity from non-DC
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4662 AND EventData.AccessMask = "0x100"
```

#### Password Spraying Detection

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter`
* `Windows.EventLogs.FailedLogons`
* `Custom.Windows.EventLogs.PasswordSpray` (create custom artifact)
* `Windows.Network.NetstatEnriched`

**What to Look For:**

* **Event ID 4625** - Failed logon attempts
* **Low Volume per Account** - 1-3 attempts per username (staying below lockout threshold)
* **High Account Count** - Many different usernames from same source IP
* **Time Clustering** - Failed attempts within short time windows (5-30 minutes)
* **Common Passwords** - Sequential testing of weak passwords (Password123!, Summer2024!)
* **Source Patterns** - Single IP or small IP range targeting many accounts

**Analysis Steps:**

1. **Aggregate by Source IP** - Count unique usernames per source IP
2. **Check Failure Rate** - Look for 1-3 failures per account (below lockout threshold)
3. **Examine Time Distribution** - Spray attacks often occur in waves
4. **Review Targeted Accounts** - Random user accounts vs. privileged accounts
5. **Check Logon Types** - Type 3 (network) or Type 8 (NetworkClearText) common for sprays
6. **Correlate Success** - Did any accounts succeed? (Event ID 4624)
7. **Review Source Location** - Internal IP, external VPN, cloud services?

**Red Flags:**

* 50+ unique usernames from single IP within 1 hour
* Failed attempts for disabled accounts (attacker doesn't know account status)
* Alphabetical username pattern (attacker enumerated user list)
* Failed attempts during off-hours (2 AM - 5 AM)
* Source IP with no successful authentications ever
* Attempts against service accounts that shouldn't authenticate interactively

**Legitimate vs Malicious:**

* **Legitimate**: Help desk password resets, user typos (usually same user repeatedly)
* **Malicious**: Many users, few attempts each, regular timing patterns

**Thresholds to Set:**

* **Low Confidence**: 10+ accounts, 1-2 failures each, within 1 hour
* **Medium Confidence**: 30+ accounts, 1-3 failures each, within 30 minutes
* **High Confidence**: 50+ accounts, consistent timing, includes disabled accounts

```sql
-- Multiple failed logins across accounts
SELECT EventData.TargetUserName as Username,
       EventData.IpAddress as SourceIP,
       count(*) as FailureCount,
       min(System.TimeCreated.SystemTime) as FirstAttempt,
       max(System.TimeCreated.SystemTime) as LastAttempt
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4625
GROUP BY SourceIP, Username
HAVING FailureCount > 5
```

#### AS-REP Roasting Detection

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter` (on Domain Controllers)
* `Windows.EventLogs.Kerberos`
* `Windows.System.Users` (check for accounts with pre-auth disabled)
* `Windows.Detection.ProcessCreation`

**What to Look For:**

* **Event ID 4768** - Kerberos TGT request with PreAuthType = 0 (no pre-authentication)
* **RC4 Encryption** - TicketEncryptionType = 0x17 (weak encryption, easier to crack)
* **Account Enumeration Pattern** - Sequential requests for multiple user accounts
* **Tool Signatures** - Rubeus.exe, GetNPUsers.py (Impacket), PowerView commands
* **Unusual Source IPs** - Non-standard workstations requesting TGTs

**Analysis Steps:**

1. **BehaviourIdentify Vulnerable Accounts** - Which accounts have "Do not require Kerberos preauthentication" set?
2. **Baseline Normal Behaviour** - Do these accounts normally authenticate? From where?
3. **Check Request Volume** - Single account or bulk enumeration?
4. **Review Encryption Type** - RC4 (0x17) indicates potential offline cracking target
5. **Correlate with Process Creation** - Look for Rubeus, PowerShell scripts on source host
6. **Check Timing** - After-hours requests more suspicious
7. **Follow-up Activity** - Did successful authentication occur later? (compromised password)

**Red Flags:**

* Multiple user accounts queried in short timeframe (enumeration)
* Requests from workstation that shouldn't perform authentication operations
* PreAuthType = 0 for accounts that normally use pre-authentication
* RC4 encryption requested when AES should be default
* Requests followed by unusual authentication patterns days/weeks later
* Service accounts with pre-auth disabled being targeted

**Legitimate vs Malicious:**

* **Legitimate**: Some legacy applications require pre-auth disabled (rare)
* **Malicious**: Bulk account queries, tools like Rubeus in command line, off-hours

**Account Configuration Check:**

powershell

```powershell
# Check which accounts have pre-auth disabled (run on DC)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

**Post-Exploitation Indicators:**

* Look for password changes on targeted accounts (attacker succeeded in cracking)
* Unusual authentication patterns from targeted accounts after AS-REP roasting
* New service principal names (SPNs) added to roasted accounts

```sql
-- Event ID 4768 with RC4 encryption and no pre-auth
SELECT EventData.TargetUserName as Username,
       EventData.IpAddress as SourceIP,
       EventData.TicketEncryptionType as EncryptionType,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4768 
  AND EventData.PreAuthType = "0"
  AND EventData.TicketEncryptionType = "0x17"
```

***

### Kerberos Attacks

#### Kerberoasting Detection

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter` (on Domain Controllers)
* `Windows.EventLogs.Kerberos`
* `Windows.Detection.ProcessCreation`
* `Windows.Forensics.Timeline`

**What to Look For:**

* **Event ID 4769** - Service ticket (TGS) requests with RC4 encryption (0x17)
* **High Volume Requests** - Single user requesting tickets for many SPNs
* **Service Name Patterns** - Non-standard services, SQL, HTTP, MSSQL SPNs
* **Tool Artifacts** - Rubeus.exe, Invoke-Kerberoast, GetUserSPNs.py commands
* **Ticket Options** - Look for 0x40810000 (forwardable, renewable flags)
* **Encryption Downgrade** - RC4 when AES should be standard

**Analysis Steps:**

1. **Identify Service Accounts** - Which accounts have SPNs registered?
2. **Baseline Ticket Requests** - Normal users don't request tickets for many services
3. **Check Request Pattern** - 10+ service tickets in short timeframe = enumeration
4. **Review Encryption Type** - RC4 (0x17) makes offline cracking easier
5. **Correlate with Account Activity** - Check for subsequent authentication with cracked password
6. **Examine Source Workstation** - Look for offensive security tools
7. **Timeline Analysis** - Map service ticket requests to later suspicious activity

**Red Flags:**

* Single user account requesting 10+ different service tickets within minutes
* Service tickets requested for accounts that user doesn't normally access
* RC4 encryption when domain policy requires AES
* Ticket requests from developer/contractor accounts (common targets)
* Requests for high-value SPNs (SQL servers, web services, admin accounts)
* PowerShell process with Base64 commands around same timeframe
* Service tickets requested but services never actually accessed

**Legitimate vs Malicious:**

* **Legitimate**: Users accessing services they use (1-3 tickets), AES encryption
* **Malicious**: Bulk requests, RC4 encryption, no actual service connection after

**High-Value SPN Targets:**

* SQL Server accounts (MSSQL/hostname)
* IIS web services (HTTP/hostname)
* Exchange servers
* Custom application service accounts
* Accounts with AdminSDHolder protection

**Post-Kerberoasting Indicators:**

* Password changes on service accounts shortly after roasting
* Unusual authentication patterns from previously roasted accounts
* New SPNs registered (attacker maintaining access)
* Service account used for lateral movement

```sql
-- Event ID 4769 - Service ticket requests with RC4
SELECT EventData.ServiceName as ServiceName,
       EventData.TargetUserName as RequestingUser,
       EventData.IpAddress as SourceIP,
       EventData.TicketEncryptionType as EncryptionType,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4769 
  AND EventData.TicketEncryptionType = "0x17"
  AND EventData.ServiceName NOT IN ("krbtgt", "$")
  AND EventData.ServiceName =~ "^[^$]"

-- Multiple service ticket requests (enumeration)
SELECT ServiceName, RequestingUser, count(*) as RequestCount
FROM (
  SELECT EventData.ServiceName as ServiceName,
         EventData.TargetUserName as RequestingUser
  FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
  WHERE EventID = 4769
)
GROUP BY RequestingUser
HAVING RequestCount > 10
```

#### Golden Ticket Detection

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter` (on Domain Controllers)
* `Windows.EventLogs.Kerberos`
* `Windows.Forensics.Timeline`
* `Windows.Registry.NTUser` (check for cached tickets)

**What to Look For:**

* **Event ID 4768** - TGT requests with unusual characteristics
* **Anomalous Ticket Lifetime** - Tickets valid for 10+ years (max allowed)
* **Encryption Downgrade** - RC4 when AES is domain standard
* **Missing User Context** - TGS (4769) without corresponding TGT (4768)
* **Impossible Timestamps** - Ticket start dates in the past or far future
* **Privileged Account Activity** - Domain Admin accounts authenticating from unusual locations
* **Ticket Renewal Patterns** - Tickets that never expire or renew abnormally

**Analysis Steps:**

1. **Check krbtgt Password History** - When was it last changed? Golden tickets persist until password changed twice
2. **Analyse TGT Characteristics** - Look for tickets with 10-year lifetime (common Mimikatz default)
3. **Review Ticket Timeline** - Correlate TGT (4768) with TGS (4769) - should be sequential
4. **Examine Encryption Type** - Golden tickets often use RC4 for compatibility
5. **Check Account Status** - Is the authenticating account disabled? Golden ticket still works
6. **Source IP Analysis** - Does source IP match user's typical location?
7. **Privilege Level** - Are standard users suddenly accessing Domain Admin resources?

**Red Flags:**

* TGT with StartTime before domain creation date
* Ticket lifetime > 10 hours (default is 10 hours)
* Event ID 4769 (service ticket) without prior Event ID 4768 (TGT)
* Disabled account successfully authenticating
* Account authenticating from multiple IPs simultaneously (ticket reuse)
* TGT with TicketEncryptionType = 0x17 when domain uses AES
* Administrator account from workstation IP (not typical admin workstation)
* Authentication outside normal business hours for typically 9-5 accounts

**Legitimate vs Malicious:**

* **Legitimate**: Standard ticket lifetime, AES encryption, normal user behaviour
* **Malicious**: Extended lifetime, RC4 encryption, disabled accounts authenticating

**Critical Checks:**

1. **krbtgt Account Status** - Check last password change

powershell

```powershell
Get-ADUser krbtgt -Properties PasswordLastSet
```

2. **Ticket Characteristics** - Look for tickets with these anomalies:
   * TicketLifetime > 10 hours
   * RC4 encryption (0x17)
   * StartTime inconsistencies

**Detection Strategies:**

* **Orphaned TGS**: Service tickets without TGT requests
* **Temporal Anomalies**: Tickets used before they were issued
* **Account Anomalies**: Disabled/deleted accounts still authenticating
* **Encryption Mismatches**: Domain requires AES but ticket uses RC4

**Post-Detection Actions:**

1. Reset krbtgt password twice (requires 2 resets to invalidate all tickets)
2. Review all administrative account activity during suspected timeframe
3. Force password resets for compromised accounts
4. Audit Domain Admin group membership changes

```sql
-- Anomalous TGT characteristics
SELECT EventData.TargetUserName as Username,
       EventData.TicketEncryptionType as EncryptionType,
       EventData.IpAddress as SourceIP,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4768
  AND (
    EventData.TicketEncryptionType NOT IN ("0x12", "0x11") OR
    EventData.TargetUserName = "Administrator" OR
    System.TimeCreated.SystemTime < "2000-01-01"
  )

-- TGS without prior TGT
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4769
  AND NOT EXISTS(
    SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
    WHERE EventID = 4768
  )
```

#### Silver Ticket Detection

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter`
* `Windows.EventLogs.Kerberos`
* `Windows.System.Services`
* `Windows.Network.NetstatEnriched`

**What to Look For:**

* **Event ID 4769** - Service ticket requests with anomalous characteristics
* **Missing TGT Request** - Service ticket without corresponding TGT (Event ID 4768)
* **Encryption Downgrade** - RC4 (0x17) for service tickets
* **Ticket Options** - Look for 0x40810000 or 0x40810010 flags
* **Service Account Compromise** - Tickets for specific services (CIFS, HTTP, MSSQL, LDAP)
* **Direct Service Access** - Access to resources without going through normal authentication flow

**Analysis Steps:**

1. **Identify Target Service** - Which service is being accessed? (CIFS for file shares, HTTP for web)
2. **Check TGT Existence** - Was there a TGT request before this service ticket?
3. **Review Service Account** - Does the service account hash appear compromised?
4. **Analyse Access Pattern** - Is this user's normal behaviour for accessing this service?
5. **Check Ticket Lifetime** - Silver tickets may have extended lifetimes
6. **Correlate Network Activity** - Is actual service traffic matching the ticket requests?
7. **Examine Source Location** - Does source IP match user's typical location?

**Red Flags:**

* Event ID 4769 without prior Event ID 4768 from same user/IP
* Service ticket encryption type RC4 when service supports AES
* Service ticket requested but no actual service connection logged
* Multiple different services accessed with silver tickets (indicates multiple service account compromises)
* Service tickets for accounts that shouldn't access those services
* Tickets with TicketOptions = 0x40810000 (forwardable + renewable)
* Access to administrative shares (CIFS/server$) from non-admin accounts

**Legitimate vs Malicious:**

* **Legitimate**: Normal ticket flow (TGT → TGS), AES encryption, expected service access
* **Malicious**: TGS without TGT, RC4 encryption, unusual service access patterns

**Service-Specific Indicators:**

**CIFS (File Share Access):**

* Look for Event ID 5140 (share access) matching ticket requests
* Check if accessed shares align with user's job function

**HTTP (Web Services):**

* Review IIS logs for actual web requests
* Correlate with ticket request timing

**MSSQL (Database):**

* Check SQL Server logs for authentication
* Verify if user typically accesses this database

**LDAP (Directory Services):**

* Review for unusual LDAP queries
* Check for directory enumeration activity

**Detection Strategies:**

1. **Orphaned Service Tickets** - Service tickets without TGT
2. **Service Account Monitoring** - Track all service account password changes
3. **Encryption Baseline** - Identify services using RC4 vs AES
4. **Access Patterns** - Baseline normal service access per user

**Post-Detection Actions:**

1. Reset password for compromised service account
2. Review all authentication using that service account
3. Check for lateral movement from systems accessed via silver ticket
4. Audit service account permissions (principle of least privilege)

```sql
-- Service ticket encryption downgrade
SELECT EventData.ServiceName,
       EventData.TargetUserName,
       EventData.TicketEncryptionType,
       System.TimeCreated.SystemTime
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4769
  AND EventData.TicketEncryptionType = "0x17"
  AND EventData.TicketOptions = "0x40810000"
```

***

### Privilege Escalation

#### Token Manipulation Detection

```sql
-- Event ID 4672 - Special privileges assigned
SELECT EventData.SubjectUserName as Username,
       EventData.PrivilegeList as Privileges,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4672
  AND Privileges =~ "SeDebugPrivilege|SeImpersonatePrivilege|SeTcbPrivilege"

-- Process creation with suspicious privileges
SELECT * FROM Artifact.Windows.EventLogs.ProcessCreation()
WHERE NewProcessName =~ "cmd.exe|powershell.exe|wmic.exe"
  AND ParentProcessName =~ "winlogon.exe|services.exe|lsass.exe"
```

#### Detect Exploitation Frameworks

```sql
-- Hunt for Cobalt Strike beacons
SELECT Name, Pid, CommandLine, Hash.SHA256
FROM pslist()
WHERE CommandLine =~ "rundll32.*,StartW|regsvr32 /s /n /u /i:http"
   OR Exe =~ "\\\\pipe\\\\[0-9a-f]{8}"

-- Metasploit artifacts
SELECT * FROM Artifact.Windows.Detection.Webshells()

-- Empire/PowerShell Empire
SELECT * FROM Artifact.Windows.EventLogs.PowershellScriptblock()
WHERE ScriptBlockText =~ "System.Net.WebClient|IEX|Invoke-Expression|FromBase64String"
```

***

### Lateral Movement

#### Pass-the-Hash Detection

**Artifacts to Use:**

* `Windows.EventLogs.EvtxHunter`
* `Windows.EventLogs.RDPAuth`
* `Windows.EventLogs.AlternateLogon`
* `Windows.System.Users`
* `Windows.Network.NetstatEnriched`

**What to Look For:**

* **Event ID 4624 Type 3** - Network logon using NTLM authentication
* **NTLM Authentication** - AuthenticationPackageName = "NTLM" (not Kerberos)
* **Privileged Accounts** - Local Administrator or Domain Admin accounts
* **Logon from Unusual Sources** - IPs/hostnames not typically used by that account
* **Lateral Movement Pattern** - Sequential logins across multiple systems
* **Workstation Name Anomalies** - Hostname doesn't match user's assigned system

**Analysis Steps:**

1. **Identify Logon Type** - Type 3 = Network logon (SMB, WMI, etc.)
2. **Check Authentication Package** - NTLM indicates hash-based authentication
3. **Review Account Type** - Built-in Administrator or domain privileged accounts
4. **Analyse Source IP** - Cross-reference with DHCP/asset inventory
5. **Check Logon Frequency** - Multiple systems in short timeframe = lateral movement
6. **Correlate with Process Creation** - Look for remote execution tools (psexec, wmic)
7. **Review Destination Systems** - What systems are being targeted?

**Red Flags:**

* Local Administrator account authenticating via network (Type 3) with NTLM
* Same account authenticating to 5+ systems within 30 minutes
* Account authenticating from IP it has never used before
* LogonType = 3 with NTLM from non-Domain Controller
* Computer account (ending in $) authenticating to other workstations
* Authentication pattern: Workstation A → Workstation B → Workstation C (pivoting)
* Built-in RID 500 Administrator account (should be disabled)

**Legitimate vs Malicious:**

* **Legitimate**: Service accounts using NTLM, scheduled tasks, administrative scripts with Kerberos
* **Malicious**: Interactive admin accounts using NTLM Type 3, rapid multi-host authentication

**Key Fields to Analyse:**

* **TargetUserName**: Which account is being used?
* **WorkstationName**: Source hostname
* **IpAddress**: Source IP (often shows as "-" for local subnet)
* **LogonType**: Type 3 = network, Type 9 = NewCredentials, Type 10 = RemoteInteractive
* **AuthenticationPackageName**: NTLM (suspicious) vs Kerberos (normal)
* **LogonProcessName**: Should be "NtLmSsp" for Pass-the-Hash

**Detection Patterns:**

**Rapid Lateral Spread:**

```kql
10:15:02 - User: admin, Source: 192.168.1.50, Target: SERVER01
10:15:34 - User: admin, Source: 192.168.1.50, Target: SERVER02
10:16:12 - User: admin, Source: 192.168.1.50, Target: SERVER03
```

**Privilege Escalation:**

* Standard user account suddenly authenticating as local admin
* Domain user becoming local admin on multiple systems

**Correlate with Other Artifacts:**

* **Event ID 4672** - Special privileges assigned (admin rights)
* **Event ID 4688** - Process creation (psexec, wmic, powershell)
* **Event ID 5140** - Network share accessed (ADMIN,C, C ,C, IPC$)
* **Event ID 5145** - Detailed file share access

**Tools Commonly Using Pass-the-Hash:**

* Mimikatz (sekurlsa::pth)
* Impacket (psexec.py, wmiexec.py, smbexec.py)
* CrackMapExec
* Metasploit (psexec module)
* PowerShell Empire
* Cobalt Strike

```sql
-- Event ID 4624 Type 3 with NTLM
SELECT EventData.TargetUserName as Username,
       EventData.WorkstationName as SourceHost,
       EventData.IpAddress as SourceIP,
       EventData.LogonType as LogonType,
       EventData.AuthenticationPackageName as AuthPackage,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4624
  AND EventData.LogonType = "3"
  AND EventData.AuthenticationPackageName = "NTLM"
  AND EventData.TargetUserName NOT LIKE "%$"
```

#### Pass-the-Ticket Detection

```sql
-- Event ID 4648 - Explicit credential usage
SELECT EventData.SubjectUserName as SourceUser,
       EventData.TargetUserName as TargetUser,
       EventData.TargetServerName as TargetServer,
       EventData.IpAddress as SourceIP,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4648
  AND SourceUser != TargetUser
```

#### Remote Execution Detection

{% code overflow="wrap" %}
```sql
-- PsExec activity
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
WHERE EventID = 7045 AND EventData.ServiceName =~ "PSEXESVC"

-- WMI remote execution
SELECT * FROM Artifact.Windows.EventLogs.RDPAuth()

-- WinRM activity
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-WinRM%4Operational.evtx')
WHERE EventID IN (6, 8, 15, 16, 33)

-- Remote scheduled task creation
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx')
WHERE EventID = 106 AND EventData.TaskName NOT LIKE "\\Microsoft\\%"
```
{% endcode %}

#### SMB Lateral Movement

```sql
-- Event ID 5140/5145 - Network share access
SELECT EventData.SubjectUserName as Username,
       EventData.ShareName as ShareName,
       EventData.IpAddress as SourceIP,
       EventData.AccessMask as AccessMask,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID IN (5140, 5145)
  AND ShareName =~ "ADMIN$|C$|IPC$"
```

***

### Persistence Mechanisms

#### Scheduled Tasks

{% code overflow="wrap" %}
```sql
-- Suspicious scheduled tasks
SELECT Name, Path, Actions, Triggers, Author, 
       Created, LastRunTime, NextRunTime
FROM Artifact.Windows.System.TaskScheduler()
WHERE Author NOT LIKE "%Microsoft%"
   OR Actions =~ "powershell|cmd|wscript|cscript|mshta"
   OR Path NOT LIKE "\\Microsoft\\%"

-- Task creation events
SELECT EventData.TaskName, EventData.UserName,
       System.TimeCreated.SystemTime
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx')
WHERE EventID = 106
```
{% endcode %}

#### Service Creation

```sql
-- Event ID 7045 - New service installed
SELECT EventData.ServiceName,
       EventData.ImagePath,
       EventData.ServiceType,
       EventData.AccountName,
       System.TimeCreated.SystemTime
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
WHERE EventID = 7045
  AND (ImagePath =~ "powershell|cmd|wscript|rundll32" OR
       ServiceName NOT LIKE "%Microsoft%")

-- Enumerate suspicious services
SELECT Name, DisplayName, PathName, StartMode, State, StartName
FROM services()
WHERE PathName =~ "\\\\Temp\\\\|\\\\Users\\\\|powershell|cmd"
   OR NOT Authenticode.Trusted
```

#### Registry Persistence

{% code overflow="wrap" %}
```sql
-- Common autorun locations
SELECT Key, Name, Type, Data.value as Value
FROM glob(globs='HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*')

-- Enumerate all autorun entries
SELECT * FROM Artifact.Windows.System.StartupItems()

-- Registry modification events
SELECT * FROM Artifact.Windows.Registry.Sysinternals.Autoruns()
```
{% endcode %}

#### WMI Persistence

{% code overflow="wrap" %}
```sql
-- WMI Event Subscriptions
SELECT Name, Query, 
       SELECT * FROM __EventFilter
FROM wmi(query='SELECT * FROM __EventFilter', namespace='root\\subscription')

-- WMI Event Consumers
SELECT Name, CommandLineTemplate
FROM wmi(query='SELECT * FROM CommandLineEventConsumer', namespace='root\\subscription')

-- WMI Bindings
SELECT * FROM wmi(query='SELECT * FROM __FilterToConsumerBinding', namespace='root\\subscription')
```
{% endcode %}

#### Account Manipulation

```sql
-- Event ID 4720 - User account created
SELECT EventData.TargetUserName as CreatedUser,
       EventData.SubjectUserName as CreatedBy,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4720

-- Event ID 4732 - User added to privileged group
SELECT EventData.MemberName as AddedUser,
       EventData.TargetUserName as GroupName,
       EventData.SubjectUserName as AddedBy,
       System.TimeCreated.SystemTime as Timestamp
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4732
  AND GroupName =~ "Administrators|Domain Admins|Enterprise Admins|Schema Admins"
```

***

### Domain Controller Attacks

#### NTDS.dit Extraction Detection

```sql
-- VSS Shadow Copy creation
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
WHERE EventID = 7036 AND EventData.ServiceName = "VSS"

-- NTDS.dit file access
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4663
  AND EventData.ObjectName =~ "ntds.dit"
  AND EventData.AccessMask =~ "ReadData"

-- Check for NTDS extraction tools
SELECT Name, Pid, CommandLine, ParentProcessName
FROM pslist()
WHERE CommandLine =~ "ntdsutil|vssadmin|diskshadow|esentutl|ntds.dit"
```

#### DCShadow Detection

{% code overflow="wrap" %}
```sql
-- Unexpected DC registration
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Directory Service.evtx')
WHERE EventID IN (1946, 2042)

-- Suspicious SPN modifications
SELECT EventData.ObjectDN,
       EventData.AttributeLDAPDisplayName,
       EventData.AttributeValue,
       System.TimeCreated.SystemTime
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 5136
  AND EventData.AttributeLDAPDisplayName IN ("servicePrincipalName", "dNSHostName")
```
{% endcode %}

#### Skeleton Key Detection

```sql
-- LSASS code injection
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')
WHERE EventID = 7045 AND EventData.ServiceName =~ "mimikatz|skeleton"

-- Unusual LSASS modules
SELECT ProcessName, ModulePath, Description, Company
FROM modules()
WHERE ProcessName = "lsass.exe"
  AND (ModulePath NOT LIKE "C:\\Windows\\%"
       OR NOT Authenticode.Trusted)
```

***

### Golden/Silver Ticket Detection

#### Comprehensive Ticket Analysis

```sql
-- Anomalous ticket lifetimes
SELECT EventData.TargetUserName,
       EventData.TicketEncryptionType,
       EventData.TicketOptions,
       parse_windows_time(string=EventData.StartTime) as TicketStart,
       parse_windows_time(string=EventData.EndTime) as TicketEnd,
       (parse_windows_time(string=EventData.EndTime).Unix - 
        parse_windows_time(string=EventData.StartTime).Unix) / 3600 as LifetimeHours
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4769
  AND LifetimeHours > 10

-- Tickets with unusual encryption
SELECT * FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID IN (4768, 4769)
  AND EventData.TicketEncryptionType NOT IN ("0x12", "0x11", "0x18")
```

#### Cross-Reference Ticket Activity

```sql
-- Correlate TGT and TGS requests
LET tgt_requests = SELECT 
  EventData.TargetUserName as Username,
  EventData.IpAddress as SourceIP,
  System.TimeCreated.SystemTime as TGTTime
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4768

LET tgs_requests = SELECT
  EventData.TargetUserName as Username,
  EventData.ServiceName as Service,
  System.TimeCreated.SystemTime as TGSTime
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4769

SELECT tgs.Username, tgs.Service, tgs.TGSTime, tgt.TGTTime
FROM tgs_requests as tgs
LEFT JOIN tgt_requests as tgt
ON tgs.Username = tgt.Username
WHERE tgt.TGTTime IS NULL OR tgs.TGSTime < tgt.TGTTime
```

***

### Data Exfiltration

#### Large Data Transfers

```sql
-- Monitor network connections for data transfer
SELECT Laddr.IP as LocalIP,
       Laddr.Port as LocalPort,
       Raddr.IP as RemoteIP,
       Raddr.Port as RemotePort,
       Status,
       Pid,
       Name
FROM netstat()
WHERE Status = 'ESTABLISHED'
  AND Raddr.IP NOT IN ('127.0.0.1', '::1')
  AND RemotePort IN (21, 22, 80, 443, 445, 3389)

-- Detect file staging
SELECT Name, FullPath, Size, ModTime, Created
FROM glob(globs='C:/Users/*/AppData/Local/Temp/**/*.{zip,rar,7z,tar,gz}')
WHERE Size > 10000000
```

#### DNS Tunnelling Detection

```sql
-- Unusual DNS queries
SELECT * FROM Artifact.Windows.EventLogs.DNSQueries()
WHERE QueryName =~ "^[a-z0-9]{20,}\\."
   OR LEN(QueryName) > 50

-- DNS query volume analysis
SELECT QueryName, count(*) as QueryCount
FROM Artifact.Windows.EventLogs.DNSQueries()
GROUP BY QueryName
HAVING QueryCount > 100
```

#### Cloud Service Uploads

```sql
-- Browser history for cloud services
SELECT * FROM Artifact.Windows.Forensics.BrowserHistory()
WHERE URL =~ "dropbox|onedrive|drive\\.google|mega\\.nz|wetransfer"

-- Process connections to cloud services
SELECT Name, Pid, CommandLine, Raddr.IP as RemoteIP
FROM netstat()
WHERE Name =~ "chrome|firefox|edge|onedrive|dropbox"
  AND Status = 'ESTABLISHED'
```

***

### Hunt Queries

#### Generic Threat Hunting

{% code overflow="wrap" %}
```sql
-- Baseline rare processes
SELECT Name, count(*) as ExecutionCount, 
       collect(array=CommandLine) as CommandLines
FROM Artifact.Windows.EventLogs.ProcessCreation()
GROUP BY Name
HAVING ExecutionCount < 5

-- Unsigned binary execution
SELECT Name, FullPath, Hash.SHA256, CommandLine
FROM pslist()
WHERE NOT Authenticode.Trusted
  AND FullPath NOT LIKE "C:\\Windows\\%"

-- Processes with suspicious parent-child relationships
SELECT Name, Pid, Ppid, ParentProcessName, CommandLine
FROM pslist()
WHERE (Name =~ "cmd.exe|powershell.exe" AND ParentProcessName =~ "winword.exe|excel.exe|outlook.exe")
   OR (Name =~ "net.exe|net1.exe" AND ParentProcessName =~ "cmd.exe|powershell.exe")
```
{% endcode %}

#### Timeline Analysis

```sql
-- Create unified timeline
SELECT "Process" as EventType,
       System.TimeCreated.SystemTime as Timestamp,
       EventData.NewProcessName as Details
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4688

UNION

SELECT "Login" as EventType,
       System.TimeCreated.SystemTime as Timestamp,
       EventData.TargetUserName || " from " || EventData.IpAddress as Details
FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')
WHERE EventID = 4624

ORDER BY Timestamp DESC
```

***

### Response Actions

#### Isolation and Containment

```sql
-- Disable network adapter (use with caution)
-- This requires executing system commands

-- Kill suspicious process
SELECT * FROM execve(argv=['taskkill', '/PID', str(str=Pid), '/F'])
FROM pslist()
WHERE Name = 'malicious.exe'

-- Disable user account (requires appropriate permissions)
SELECT * FROM execve(argv=['net', 'user', 'compromised_user', '/active:no'])
```

#### Evidence Collection

```sql
-- Collect memory dump of specific process
SELECT * FROM Artifact.Windows.Memory.Acquisition(
  ProcessId=1234,
  DumpPath='C:/forensics/dumps/'
)

-- Collect prefetch files
SELECT * FROM glob(globs='C:/Windows/Prefetch/**')

-- Collect recent files
SELECT * FROM Artifact.Windows.Forensics.RecentApps()
```

#### Hunt Deployment Strategies

```bash
# Velociraptor Hunt Examples (CLI)

# Deploy credential dumping detection across all endpoints
velociraptor --config server.config.yaml hunts create \
  --name "Credential Dumping Hunt" \
  --artifact "Custom.CredentialDumping.Detection"

# Collect specific event logs from Domain Controllers
velociraptor --config server.config.yaml hunts create \
  --name "DC Event Log Collection" \
  --label "role:domain_controller" \
  --artifact "Windows.EventLogs.EvtxHunter" \
  --parameter "EvtxGlob=C:/Windows/System32/winevt/Logs/Security.evtx"

# Emergency triage collection
velociraptor --config server.config.yaml hunts create \
  --name "Emergency Triage" \
  --artifact "Windows.Triage.Collection"
```

***

### Key Event IDs Reference

#### Authentication Events

* **4624** - Successful logon
* **4625** - Failed logon
* **4634** - Logoff
* **4647** - User initiated logoff
* **4648** - Logon with explicit credentials
* **4672** - Special privileges assigned
* **4768** - Kerberos TGT requested
* **4769** - Kerberos service ticket requested
* **4771** - Kerberos pre-authentication failed
* **4776** - Domain controller authentication attempt

#### Account Management

* **4720** - User account created
* **4722** - User account enabled
* **4724** - Password reset attempt
* **4732** - Member added to security-enabled local group
* **4733** - Member removed from security-enabled local group
* **4756** - Member added to security-enabled universal group

#### Object Access

* **4656** - Handle to object requested
* **4663** - Attempt to access object
* **4662** - Operation performed on Active Directory object

#### System Events

* **7045** - New service installed
* **7036** - Service state change
* **7040** - Service startup type changed

***

### Tips and Best Practices

#### Investigation Tips

1. **Always establish a timeline** - Use multiple event sources
2. **Correlate across systems** - Single host view may miss lateral movement
3. **Check Domain Controllers first** - They hold the most critical evidence
4. **Look for cleanup activities** - Attackers often try to cover tracks
5. **Document everything** - Chain of custody is critical

#### VQL Optimization

* Use `WHERE` clauses early to filter data
* Limit time ranges when possible
* Use `LIMIT` for initial testing
* Index frequently queried fields
* Cache results of expensive queries using `LET`

#### Common Mistakes to Avoid

* Don't rely solely on single indicators
* Don't ignore false positives without investigation
* Don't forget to check for persistence mechanisms
* Don't overlook legitimate admin activity
* Don't modify evidence without proper documentation

#### Performance Considerations

```sql
-- Use time bounds to limit data processing
SELECT * FROM parse_evtx(filename='Security.evtx')
WHERE System.TimeCreated.SystemTime > now() - 86400

-- Use EXISTS for better performance
SELECT * FROM table1
WHERE EXISTS(SELECT * FROM table2 WHERE table1.id = table2.id)

-- Limit results during testing
SELECT * FROM pslist() LIMIT 100
```

***

### Additional Resources

#### Velociraptor Built-in Artifacts

* `Windows.EventLogs.EvtxHunter` - Hunt for specific event IDs
* `Windows.Detection.Yara.Process` - YARA scanning
* `Windows.Forensics.Timeline` - Comprehensive timeline
* `Windows.System.Amcache` - Execution history
* `Windows.Forensics.Usn` - USN Journal analysis
* `Windows.Registry.NTUser` - User registry analysis

#### Log Locations

{% code overflow="wrap" %}
```sql
Security: C:\Windows\System32\winevt\Logs\Security.evtx
System: C:\Windows\System32\winevt\Logs\System.evtx
PowerShell: C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
Task Scheduler: C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx
WinRM: C:\Windows\System32\winevt\Logs\Microsoft-Windows-WinRM%4Operational.evtx
Sysmon: C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```
{% endcode %}

***

**Note:** Always test queries in a non-production environment first. Adjust time ranges, filters, and thresholds based on your specific environment and baseline.
