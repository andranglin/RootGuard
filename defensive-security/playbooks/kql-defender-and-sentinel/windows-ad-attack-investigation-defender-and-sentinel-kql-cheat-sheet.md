---
description: DFIR Workflow
---

# Windows AD Attack Investigation – Defender & Sentinel KQL Cheat Sheet

### Table of Contents

1. Investigation Workflow
2. Data Sources & Tables
3. Initial Triage
4. Credential Attacks
5. Kerberos Attacks
6. Privilege Escalation
7. Lateral Movement
8. Persistence Mechanisms
9. Domain Controller Attacks
10. Golden/Silver Ticket Detection
11. Data Exfiltration
12. Threat Hunting Queries

***

### Investigation Workflow

#### Phase 1: Scope Definition

1. Identify compromised accounts/systems
2. Determine attack timeline
3. Query relevant log sources (Defender, Sentinel, Azure AD)

#### Phase 2: Data Collection

1. Use KQL to query across multiple data sources
2. Correlate events using joins and unions
3. Build a comprehensive timeline

#### Phase 3: Analysis

1. Pivot on indicators (usernames, IPs, processes)
2. Use summarise for pattern detection
3. Apply threat intelligence enrichment

#### Phase 4: Containment & Remediation

1. Document findings
2. Create detection rules
3. Implement response playbooks

***

### Data Sources & Tables

#### Microsoft Defender for Endpoint (MDE)

* **DeviceProcessEvents** - Process creation, command lines
* **DeviceNetworkEvents** - Network connections
* **DeviceFileEvents** - File operations
* **DeviceRegistryEvents** - Registry modifications
* **DeviceLogonEvents** - Logon activities
* **DeviceEvents** - General device events
* **DeviceImageLoadEvents** - DLL loading

#### Microsoft Sentinel

* **SecurityEvent** - Windows Security Event logs
* **Event** - Windows System/Application logs
* **IdentityLogonEvents** - Identity-related logons
* **IdentityQueryEvents** - LDAP queries, AD enumeration
* **IdentityDirectoryEvents** - AD object changes
* **AADSignInLogs** - Azure AD sign-ins
* **AADUserRiskEvents** - Identity Protection alerts

#### Microsoft Defender for Identity (MDI)

* **IdentityLogonEvents** - Authentication events
* **IdentityQueryEvents** - Directory service queries
* **IdentityDirectoryEvents** - AD modifications

#### Office 365

* **OfficeActivity** - SharePoint, Exchange, Teams activity
* **CloudAppEvents** - Cloud app interactions

***

### Initial Triage

#### Quick System Survey

**Artifacts to Use:**

* `DeviceInfo`
* `DeviceProcessEvents`
* `DeviceLogonEvents`
* `SecurityEvent`

**What to Look For:**

* Recent logon activity across affected systems
* Unusual process executions
* Network connections to suspicious IPs
* Timeline of initial compromise

**Analysis Steps:**

1. Identify all systems where a suspicious account authenticated
2. Map network connections to identify C2 infrastructure
3. Build a process tree to understand the execution chain
4. Correlate with threat intelligence

{% code overflow="wrap" %}
```kql
// Get overview of device activity for specific device
DeviceInfo
| where DeviceName == "WORKSTATION01"
| project Timestamp, DeviceName, OSPlatform, OSVersion, LoggedOnUsers, PublicIP

// Check recent process executions
DeviceProcessEvents
| where DeviceName == "WORKSTATION01"
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("mimikatz", "procdump", "lsass", "sekurlsa")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName

// Review logon activity
DeviceLogonEvents
| where DeviceName == "WORKSTATION01"
| where Timestamp > ago(7d)
| summarize LogonCount = count() by AccountName, LogonType, RemoteIP
| order by LogonCount desc
```
{% endcode %}

#### Windows Security Event Quick Check

```kql
// Failed and successful logon patterns
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4625)
| summarize SuccessCount = countif(EventID == 4624), 
            FailureCount = countif(EventID == 4625) 
    by Account, IpAddress, Computer
| where FailureCount > 5 or SuccessCount > 20
| order by FailureCount desc
```

***

### Credential Attacks

#### Detect LSASS Access (Credential Dumping)

**Artifacts to Use:**

* `DeviceProcessEvents`
* `DeviceEvents`
* `SecurityEvent` (Event ID 4656, 4663)
* `DeviceFileEvents`

**What to Look For:**

* **Process Access to LSASS** - Processes opening handles to lsass.exe
* **Known Tools** - Mimikatz, procdump, dumpert, comsvcs.dll, pypykatz
* **Suspicious Parent Processes** - Office apps, browsers, spawning dump tools
* **Memory Dump Files** - .dmp files created in unusual locations
* **Living-off-the-land** - rundll32.exe calling comsvcs.dll
* **MiniDumpWriteDump API** - Direct memory dumping

**Analysis Steps:**

1. **Query Process Access to LSASS:**
   * Look for DeviceEvents with ActionType "OpenProcessApiCall" targeting lsass.exe
   * Check for non-standard processes accessing LSASS
   * Review process command lines for dump flags
2. **Identify Credential Dumping Tools:**
   * Search for known tool names in process executions
   * Look for Base64 encoded PowerShell commands
   * Check for comsvcs.dll usage via rundll32
3. **Check for Memory Dump Files:**
   * Query DeviceFileEvents for .dmp file creation
   * Focus on Temp directories and user profiles
   * Check file sizes (LSASS dumps typically 50-200MB)
4. **Correlate with Logon Events:**
   * Did unusual authentication occur after LSASS access?
   * Check for lateral movement within 24 hours
5. **Review Parent Process Chain:**
   * Office applications (winword.exe, excel.exe) spawning dump tools = phishing
   * cmd.exe or powershell.exe from remote session = manual attacker activity

**Red Flags:**

* LSASS access from user workstations (not typical)
* Multiple failed access attempts followed by success
* Process spawned from Office documents accessing LSASS
* Dump files created in C:\Users\*\AppData\Local\Temp
* rundll32.exe with comsvcs.dll and "MiniDump" parameters
* ProcDump with "-ma lsass.exe" or PID of lsass
* PowerShell downloading and executing memory dumping scripts

**Legitimate vs Malicious:**

* **Legitimate**: Antivirus software, backup solutions, monitoring tools (known processes)
* **Malicious**: Unknown processes, user-initiated dumps, Office parent processes

{% code overflow="wrap" %}
```kql
// Detect processes accessing LSASS
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass.exe"
| where InitiatingProcessFileName !in ("MsSense.exe", "PRTG", "BackupAgent.exe") // Exclude known legitimate tools
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, 
          AccountName, InitiatingProcessParentFileName
| order by Timestamp desc

// Hunt for credential dumping tools
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("mimikatz.exe", "procdump.exe", "procdump64.exe", "dumpert.exe", 
                      "nanodump.exe", "lazagne.exe", "pypykatz.exe")
   or ProcessCommandLine has_any ("sekurlsa", "lsass", "procdump -ma", "comsvcs.dll MiniDump")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, FolderPath
| order by Timestamp desc

// Detect comsvcs.dll MiniDump technique (living-off-the-land)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_all ("comsvcs", "MiniDump")
   or ProcessCommandLine matches regex @"comsvcs\.dll[,\s]+#?\d+\s+\S+\.dmp"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine

// Check for suspicious .dmp file creation
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".dmp"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Users\\Public\\")
| where FileSize > 10000000 // Files larger than 10MB
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, 
          InitiatingProcessFileName, InitiatingProcessCommandLine

// Correlate LSASS access with subsequent suspicious activity
let LsassAccess = DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass.exe"
| distinct DeviceName, AccountName, Timestamp;
LsassAccess
| join kind=inner (
    DeviceLogonEvents
    | where Timestamp > ago(24h)
    | where LogonType in ("Network", "RemoteInteractive")
) on DeviceName, AccountName
| where Timestamp1 > Timestamp // Logon after LSASS access
| project LsassAccessTime=Timestamp, LogonTime=Timestamp1, DeviceName, AccountName, 
          RemoteIP, LogonType

// Defender for Endpoint Alert correlation
AlertEvidence
| where Timestamp > ago(30d)
| where EntityType == "Process"
| where Title has_any ("LSASS", "Credential", "Mimikatz", "Dumping")
| join kind=inner (AlertInfo) on AlertId
| project Timestamp, DeviceName, Title, Severity, ProcessCommandLine, AccountName
```
{% endcode %}

**Post-Detection Actions:**

1. Isolate affected systems
2. Reset passwords for all accounts that logged into the compromised system
3. Review Defender for Identity alerts for credential replay
4. Check for lateral movement using compromised credentials
5. Enable Credential Guard on critical systems

***

#### Detect DCSync Attacks

**Artifacts to Use:**

* `IdentityDirectoryEvents`
* `IdentityQueryEvents`
* `SecurityEvent` (Event ID 4662)
* `AlertInfo` / `AlertEvidence`

**What to Look For:**

* **Event ID 4662** - Directory Service Access with replication GUIDs
* **Replication from Non-DCs** - Workstations performing AD replication
* **Tool Artifacts** - Mimikatz DCSync module, secretsdump.py, Invoke-Mimikatz
* **DRSR Protocol Usage** - Directory Replication Service Remote Protocol
* **Unusual Accounts** - Service accounts or standard users with replication rights
* **High Volume Queries** - Multiple objects replicated in a short timeframe

**Analysis Steps:**

1. **Identify Replication Requests:**
   * Query IdentityDirectoryEvents for replication operations
   * Filter for DS-Replication-Get-Changes GUIDs
   * Check source device - is it a Domain Controller?
2. **Validate Source Device:**
   * Cross-reference the source hostname with the known DC list
   * Check if the device has a DC role in DeviceInfo
   * Workstation hostname = suspicious
3. **Review Account Context:**
   * Does the account typically perform replication?
   * Check Azure AD Identity Protection risk scores
   * Review account privileges and group memberships
4. **Check Timing and Volume:**
   * Single request vs. bulk dumping (multiple objects)
   * Time of day - during maintenance windows or after-hours?
   * Frequency - one-time event or repeated attempts?
5. **Correlate with Network Activity:**
   * Look for large data transfers after replication
   * Check for connections to external IPs
   * Review for data staging and compression
6. **Tool Detection:**
   * Search for Mimikatz, PowerShell Empire, Impacket
   * Check process command lines for "lsadump::dcsync"
   * Look for Python processes (secretsdump.py)

**Red Flags:**

* Replication request from workstation (non-DC hostname pattern: WS\*, LAPTOP\*, DESKTOP\*)
* Service account triggering replication outside maintenance windows
* Event ID 4662 with Properties containing:
  * `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes)
  * `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)
  * `89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set)
* Replication of the krbtgt account specifically
* Multiple object types replicated rapidly (users, computers, groups)
* User account with "Replicating Directory Changes All" permission that shouldn't have it

**Legitimate vs Malicious:**

* **Legitimate**: DC-to-DC replication, scheduled backups, Azure AD Connect (from known sync server)
* **Malicious**: Workstation source, manual user context, high volume, after-hours, targeting krbtgt

**Account Permissions to Review:**

```cmd
Replicating Directory Changes (Base replication)
Replicating Directory Changes All (Includes password hashes)
Replicating Directory Changes In Filtered Set (For read-only DCs)
```

{% code overflow="wrap" %}
```kql
// Detect DCSync using Defender for Identity
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType == "Directory Service Replication"
| where AdditionalFields contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" // DS-Replication-Get-Changes
   or AdditionalFields contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" // DS-Replication-Get-Changes-All
   or AdditionalFields contains "89e95b76-444d-4c62-991a-0facbeda640c" // Filtered Set
| where DeviceName !has "DC" and DeviceName !has "AZUREADCONNECT" // Exclude known DCs and sync servers
| project Timestamp, DeviceName, AccountName, AccountDomain, TargetAccountDisplayName, 
          Protocol, AdditionalFields
| order by Timestamp desc

// DCSync detection via SecurityEvent (for Sentinel)
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4662
| where AccessMask == "0x100" // Control Access
| extend Properties = tostring(parse_json(EventData).Properties)
| where Properties has_any ("1131f6aa", "1131f6ad", "89e95b76")
| extend SubjectUserName = tostring(parse_json(EventData).SubjectUserName)
| extend SubjectLogonId = tostring(parse_json(EventData).SubjectLogonId)
| extend ObjectName = tostring(parse_json(EventData).ObjectName)
| where Computer !has "DC" // Exclude Domain Controllers
| project TimeGenerated, Computer, SubjectUserName, ObjectName, Properties, SubjectLogonId
| order by TimeGenerated desc

// Count replication events by account (detect bulk dumping)
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Service Replication"
| summarize ReplicationCount = count(), 
            TargetAccounts = make_set(TargetAccountDisplayName),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
    by AccountName, DeviceName
| where ReplicationCount > 10 // Multiple objects replicated
| order by ReplicationCount desc

// Correlate DCSync with subsequent lateral movement
let DCSyncEvents = IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Service Replication"
| where DeviceName !has "DC"
| distinct DeviceName, AccountName, Timestamp;
DCSyncEvents
| join kind=inner (
    DeviceLogonEvents
    | where Timestamp > ago(7d)
    | where LogonType == "Network"
) on DeviceName, AccountName
| where Timestamp1 > Timestamp // Logon after DCSync
| project DCSyncTime=Timestamp, LogonTime=Timestamp1, DeviceName, AccountName, 
          RemoteDeviceName, RemoteIP

// Check for Mimikatz DCSync command in process logs
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("lsadump::dcsync", "dcsync", "secretsdump.py", 
                                     "Invoke-Mimikatz", "DCSync")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName

// Defender for Identity DCSync alerts
AlertInfo
| where Timestamp > ago(30d)
| where Title has "DCSync"
   or Title has "Directory Service Replication"
   or Title has "Replication request"
| join kind=inner (AlertEvidence) on AlertId
| project Timestamp, Title, Severity, DeviceName, AccountName, 
          AdditionalFields, RemoteUrl
```
{% endcode %}

**Post-Detection Actions:**

1. **Immediate**: Isolate the source device
2. Reset krbtgt password twice (wait for replication between resets)
3. Reset passwords for all accounts with elevated privileges
4. Review "Replicating Directory Changes" permissions - remove unnecessary grants
5. Check for Golden Ticket usage (see Golden Ticket section)
6. Audit all Domain Admin and Enterprise Admin activity
7. Enable Advanced Audit Policy for Directory Service Access
8. Review Azure AD Connect sync account permissions

***

#### Password Spraying Detection

**Artifacts to Use:**

* `AADSignInLogs`
* `IdentityLogonEvents`
* `SecurityEvent` (Event ID 4625, 4648)
* `DeviceLogonEvents`
* `AADUserRiskEvents`

**What to Look For:**

* **Event ID 4625** - Multiple failed logon attempts
* **Low Volume per Account** - 1-3 attempts per username (below lockout threshold)
* **High Account Count** - Many different usernames from the same source IP
* **Time Clustering** - Failed attempts within 5-30 minute windows
* **Common Passwords** - Testing weak passwords (Password123!, Summer2024!)
* **Source Patterns** - Single IP or small IP range, VPN endpoints, cloud IPs

**Analysis Steps:**

1. **Aggregate by Source IP:**
   * Count unique usernames attempted from each source IP
   * Look for IPs trying 10+ different accounts
   * Check IP reputation and geolocation
2. **Check Failure Rate per Account:**
   * 1-3 failures per account indicates spray (staying below lockout)
   * Compare to the normal failed logon baseline
   * Look for alphabetical username patterns (enumerated list)
3. **Examine Time Distribution:**
   * Spray attacks occur in waves/rounds
   * Look for consistent time intervals (e.g., every 30 minutes)
   * Plot failures on the timeline to identify patterns
4. **Review Targeted Accounts:**
   * Are they random users or privileged accounts?
   * Check if disabled accounts are being tested (attacker doesn't know status)
   * Look for service accounts that shouldn't authenticate interactively
5. **Check Logon Types:**
   * Type 3 (Network) or Type 8 (NetworkClearText) is common for sprays
   * Azure AD sign-ins from unusual locations
   * VPN authentication attempts
6. **Correlate Success Events:**
   * Did any accounts succeed? (Event ID 4624, AAD successful sign-in)
   * Check for account lockouts following spray (Event ID 4740)
   * Review subsequent activity from successfully compromised accounts
7. **Source Location Analysis:**
   * Internal IP vs. external
   * Cloud service IPs (AWS, Azure, GCP)
   * TOR exit nodes or proxy services
   * Geographic location vs. the user's typical location

**Red Flags:**

* 50+ unique usernames from a single IP within 1 hour
* Failed attempts for disabled accounts (EventID 4625, FailureReason "disabled")
* Alphabetical or sequential username patterns
* Failed attempts during off-hours (2 AM - 5 AM)
* Source IP with zero successful historical authentications
* Attempts against service accounts (SVC-_, SQL_, ADMIN\*)
* Same password hash across multiple accounts (rare in legitimate scenarios)
* High failure count, but only 1-2 per account

**Legitimate vs Malicious:**

* **Legitimate**: Help desk password resets (same user, multiple attempts), user typos, expired passwords
* **Malicious**: Many users, few attempts each, regular timing, includes disabled accounts

**Thresholds:**

* **Low Confidence**: 10+ accounts, 1-2 failures each, within 1 hour
* **Medium Confidence**: 30+ accounts, 1-3 failures each, within 30 minutes, includes disabled accounts
* **High Confidence**: 50+ accounts, consistent timing, external IP, followed by successful logon

{% code overflow="wrap" %}
```kql
// Password spray detection - Multiple accounts from a single IP
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625 // Failed logon
| extend FailureReason = tostring(parse_json(EventData).FailureReason)
| extend IpAddress = tostring(parse_json(EventData).IpAddress)
| extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
| where TargetUserName !endswith "$" // Exclude computer accounts
| summarize FailedAccounts = dcount(TargetUserName),
            AccountList = make_set(TargetUserName),
            FailureCount = count(),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
    by IpAddress, Computer
| where FailedAccounts >= 10 // 10 or more different accounts
| extend Duration = datetime_diff('minute', LastAttempt, FirstAttempt)
| project IpAddress, Computer, FailedAccounts, FailureCount, 
          Duration, FirstAttempt, LastAttempt, AccountList
| order by FailedAccounts desc

// Azure AD password spray detection
AADSignInLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0 // Failed sign-ins
| where ResultType in ("50126", "50053") // Invalid username/password, Account disabled
| summarize FailedAccounts = dcount(UserPrincipalName),
            AttemptCount = count(),
            AccountList = make_set(UserPrincipalName),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
    by IPAddress, AppDisplayName
| where FailedAccounts >= 10
| extend Duration = datetime_diff('minute', LastAttempt, FirstAttempt)
| project IPAddress, AppDisplayName, FailedAccounts, AttemptCount, 
          Duration, FirstAttempt, LastAttempt
| order by FailedAccounts desc

// Detect spray pattern - Low attempts per user
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| extend IpAddress = tostring(parse_json(EventData).IpAddress)
| extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
| summarize AttemptsPerUser = count() by TargetUserName, IpAddress
| where AttemptsPerUser <= 3 // 3 or fewer attempts per account
| summarize UniqueAccounts = dcount(TargetUserName), 
            TotalAttempts = sum(AttemptsPerUser)
    by IpAddress
| where UniqueAccounts >= 20 // But many different accounts
| order by UniqueAccounts desc

// Check for successful logon after spray attempt
let FailedLogons = SecurityEvent
| where TimeGenerated > ago(2h)
| where EventID == 4625
| extend IpAddress = tostring(parse_json(EventData).IpAddress)
| extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
| summarize FailureCount = count() by TargetUserName, IpAddress
| where FailureCount <= 3;
FailedLogons
| join kind=inner (
    SecurityEvent
    | where TimeGenerated > ago(2h)
    | where EventID == 4624 // Successful logon
    | extend IpAddress = tostring(parse_json(EventData).IpAddress)
    | extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
) on TargetUserName, IpAddress
| project TimeGenerated, TargetUserName, IpAddress, Computer, 
          FailureCount, LogonType = parse_json(EventData).LogonType
| order by TimeGenerated desc

// Defender for Identity password spray alerts
IdentityLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonFailed"
| summarize FailedUsers = dcount(AccountName),
            AttemptCount = count(),
            UserList = make_set(AccountName)
    by IPAddress, DeviceName
| where FailedUsers >= 10
| order by FailedUsers desc

// Account lockout correlation (spray victim identification)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4740 // Account locked out
| extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
| extend CallerComputerName = tostring(parse_json(EventData).CallerComputerName)
| summarize LockoutCount = count(), 
            FirstLockout = min(TimeGenerated),
            LastLockout = max(TimeGenerated)
    by TargetUserName
| where LockoutCount >= 1
| join kind=inner (
    SecurityEvent
    | where TimeGenerated > ago(24h)
    | where EventID == 4625
    | extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
    | summarize FailureCount = count() by TargetUserName
) on TargetUserName
| project TargetUserName, LockoutCount, FailureCount, FirstLockout, LastLockout

// Detect spraying against disabled accounts (strong indicator)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| extend FailureReason = tostring(parse_json(EventData).SubStatus)
| where FailureReason == "0xc0000072" // Account disabled
| extend IpAddress = tostring(parse_json(EventData).IpAddress)
| extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
| summarize DisabledAccountAttempts = dcount(TargetUserName),
            AccountList = make_set(TargetUserName)
    by IpAddress
| where DisabledAccountAttempts >= 5
```
{% endcode %}

**Post-Detection Actions:**

1. **Immediate**: Block source IP at firewall/WAF
2. Enable MFA for all user accounts if not already enabled
3. Reset passwords for any accounts that showed successful logon after the spray
4. Review Azure AD Conditional Access policies
5. Enable Azure AD Identity Protection
6. Implement account lockout policies (balance security vs. DoS)
7. Deploy Smart Lockout for Azure AD
8. Alert on password changes following spray attempts
9. Review VPN access logs for unusual patterns
10. Consider implementing CAPTCHA for authentication endpoints

***

#### AS-REP Roasting Detection

**Artifacts to Use:**

* `IdentityLogonEvents`
* `IdentityQueryEvents`
* `SecurityEvent` (Event ID 4768)
* `DeviceProcessEvents`
* `AADUserRiskEvents`

**What to Look For:**

* **Event ID 4768** - Kerberos TGT request with PreAuthType = 0
* **RC4 Encryption** - TicketEncryptionType = 0x17 (weak, easier to crack)
* **Account Enumeration** - Sequential TGT requests for multiple users
* **Tool Signatures** - Rubeus.exe, GetNPUsers.py (Impacket), PowerView
* **Unusual Source IPs** - Workstations requesting TGTs for accounts they don't belong to
* **Accounts with Pre-Auth Disabled** - Configuration vulnerability

**Analysis Steps:**

1. **Identify Vulnerable Accounts:**
   * Query IdentityDirectoryEvents for accounts with "Do not require Kerberos preauthentication" attribute
   * Cross-reference with privileged group memberships
   * Check if these accounts should have pre-auth disabled (usually not needed)
2. **Baseline Normal Behaviour:**
   * Do these accounts normally authenticate?
   * From what locations/devices?
   * What is a typical authentication pattern?
3. **Check Request Volume:**
   * Single account targeted or bulk enumeration?
   * Time clustering - multiple accounts within a short timeframe
   * Source pattern - same device/IP requesting multiple TGTs
4. **Review Encryption Type:**
   * RC4 (0x17) indicates an offline cracking target
   * AES (0x11, 0x12) is standard - RC4 is suspicious
   * Encryption downgrade attempts
5. **Correlate with Tool Execution:**
   * Search for Rubeus in process logs
   * PowerShell scripts with "Get-DomainUser -PreauthNotRequired"
   * Python processes (GetNPUsers.py from Impacket)
   * Look for Base64 encoded commands
6. **Check Timing:**
   * After-hours requests are more suspicious
   * Correlation with initial access (phishing, VPN compromise)
   * Pattern: Enumeration → AS-REP roasting → Password spray/credential stuffing
7. **Monitor Follow-up Activity:**
   * Did successful authentication occur days/weeks later?
   * Password changes on targeted accounts
   * New service principal names (SPNs) added
   * Unusual authentication patterns from roasted accounts

**Red Flags:**

* Multiple user accounts queried for TGTs in a short timeframe (5-10 minutes)
* TGT requests from the workstation for accounts not assigned to that system
* PreAuthType = 0 for accounts that typically require pre-authentication
* RC4 encryption when the domain policy mandates AES
* Requests followed by unusual authentication 1-7 days later
* Service accounts with pre-auth disabled are being targeted
* Pattern: Failed logon → AS-REP request → Successful logon (cracked password)
* Tool names in process: Rubeus, GetNPUsers, Invoke-ASREPRoast

**Legitimate vs Malicious:**

* **Legitimate**: Some legacy applications require pre-auth disabled (very rare, should be remediated)
* **Malicious**: Bulk queries, offensive tools in the command line, off-hours, no legitimate service usage

**Account Configuration Vulnerability:**

```
UserAccountControl attribute bit: DONT_REQ_PREAUTH (4194304)
Allows AS-REP without pre-authentication
Makes account vulnerable to offline password cracking
```

**Post-Roasting Indicators:**

* Password changes on targeted accounts within 24-72 hours
* Unusual authentication patterns from previously roasted accounts
* New SPNs registered on user accounts
* Lateral movement using compromised accounts

{% code overflow="wrap" %}
```kql
// Detect AS-REP Roasting via Defender for Identity
IdentityLogonEvents
| where Timestamp > ago(30d)
| where ActionType == "LogonFailed"
| where Protocol == "Kerberos"
| where AdditionalFields contains '"PreAuthType":"0"' // No pre-authentication
| extend EncryptionType = tostring(parse_json(AdditionalFields).TicketEncryptionType)
| where EncryptionType == "0x17" // RC4
| summarize RequestCount = count(),
            FirstRequest = min(Timestamp),
            LastRequest = max(Timestamp),
            TargetAccounts = make_set(AccountName)
    by IPAddress, DeviceName
| where RequestCount >= 5
| order by RequestCount desc

// AS-REP Roasting via SecurityEvent (Sentinel)
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4768 // TGT request
| extend PreAuthType = tostring(parse_json(EventData).PreAuthType)
| extend TicketEncryptionType = tostring(parse_json(EventData).TicketEncryptionType)
| extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
| extend IpAddress = tostring(parse_json(EventData).IpAddress)
| where PreAuthType == "0" // No pre-authentication required
| where TicketEncryptionType == "0x17" // RC4 encryption
| summarize RequestCount = count(),
            TargetAccounts = make_set(TargetUserName),
            FirstRequest = min(TimeGenerated),
            LastRequest = max(TimeGenerated)
    by IpAddress, Computer
| where RequestCount >= 5 or array_length(TargetAccounts) >= 5
| order by RequestCount desc

// Detect Rubeus AS-REP Roasting tool
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "Rubeus.exe"
   or ProcessCommandLine has_any ("asreproast", "Rubeus", "/user:", "/format:hashcat")
   or ProcessCommandLine matches regex @"Rubeus\.exe\s+asreproast"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// Detect PowerShell AS-REP enumeration
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Get-DomainUser", "PreauthNotRequired", 
                                     "DONT_REQ_PREAUTH", "Invoke-ASREPRoast")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName

// Detect GetNPUsers.py (Impacket)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "python.exe" or FileName =~ "python3.exe"
| where ProcessCommandLine has "GetNPUsers.py"
   or ProcessCommandLine has "getnpusers"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Find accounts with pre-auth disabled (configuration check)
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Account modified"
| where AdditionalFields contains "DONT_REQ_PREAUTH"
| project Timestamp, TargetAccountDisplayName, AccountName, 
          DeviceName, AdditionalFields

// Correlate AS-REP requests with later successful authentication
let ASREPTargets = IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonFailed"
| where AdditionalFields contains '"PreAuthType":"0"'
| distinct AccountName, IPAddress, Timestamp;
ASREPTargets
| join kind=inner (
    IdentityLogonEvents
    | where Timestamp > ago(7d)
    | where ActionType == "LogonSuccess"
) on AccountName
| where Timestamp1 > Timestamp and Timestamp1 < Timestamp + 7d // Success within 7 days
| project ASREPTime=Timestamp, SuccessTime=Timestamp1, AccountName, 
          ASREPSource=IPAddress, SuccessSource=IPAddress1, DeviceName

// Account password changes after AS-REP roasting (compromised indicator)
let RoastedAccounts = IdentityLogonEvents
| where Timestamp > ago(30d)
| where AdditionalFields contains '"PreAuthType":"0"'
| distinct AccountName, Timestamp;
RoastedAccounts
| join kind=inner (
    IdentityDirectoryEvents
    | where Timestamp > ago(30d)
    | where ActionType == "Account Password changed"
) on AccountName
| where Timestamp1 > Timestamp and Timestamp1 < Timestamp + 3d // Password change within 3 days
| project RoastTime=Timestamp, PasswordChangeTime=Timestamp1, 
          AccountName, TargetAccountDisplayName
```
{% endcode %}

**Post-Detection Actions:**

1. **Immediate**: Identify all accounts with pre-auth disabled
2. Enable pre-authentication for all accounts (remediate vulnerability)
3. Reset passwords for accounts targeted in AS-REP roasting
4. Review Azure AD Identity Protection risk detections
5. Check for follow-up attacks using compromised credentials
6. Audit account configurations - no accounts should have DONT\_REQ\_PREAUTH unless necessary
7. Enable Advanced Audit Policy for Kerberos Authentication
8. Deploy detection rules for Rubeus and Impacket tools

***

### Kerberos Attacks

#### Kerberoasting Detection

**Artifacts to Use:**

* `IdentityLogonEvents`
* `IdentityQueryEvents`
* `SecurityEvent` (Event ID 4769)
* `DeviceProcessEvents`
* `AlertInfo` / `AlertEvidence`

**What to Look For:**

* **Event ID 4769** - Service ticket (TGS) requests with RC4 encryption
* **High Volume Requests** - Single user requesting tickets for many SPNs
* **Service Name Patterns** - SQL, HTTP, MSSQL, custom service accounts
* **Tool Artifacts** - Rubeus.exe, Invoke-Kerberoast, GetUserSPNs.py
* **Ticket Options** - Forwardable and renewable flags (0x40810000)
* **Encryption Downgrade** - RC4 when AES should be standard

**Analysis Steps:**

1. **Identify Service Accounts with SPNs:**
   * Query IdentityDirectoryEvents for accounts with ServicePrincipalNames
   * Focus on accounts with weak passwords or old password ages
   * Check the privilege levels of SPN accounts
2. **Baseline Ticket Requests:**
   * Normal users don't request tickets for many different services
   * Legitimate service access is predictable and consistent
   * Establish baseline: users typically access 1-3 services
3. **Check Request Pattern:**
   * 10+ service tickets in a short timeframe = enumeration
   * Sequential requests suggest an automated tool
   * Time clustering - all requests within 5-10 minutes
4. **Review Encryption Type:**
   * RC4 (0x17) makes offline cracking much easier
   * Domain policy should enforce AES (0x11, 0x12)
   * RC4 downgrade is a major red flag
5. **Correlate with Account Activity:**
   * Check for subsequent authentication with a cracked password
   * Look for unusual logons from service accounts
   * Service account accessing resources it normally doesn't
6. **Examine Source Workstation:**
   * Search for offensive security tools
   * Check process command lines for Kerberoasting keywords
   * Look for PowerShell with Base64 encoded commands
7. **Timeline Analysis:**
   * Map service ticket requests to later suspicious activity
   * Pattern: Enumeration → Kerberoasting → Credential validation → Lateral movement

**Red Flags:**

* Single user requesting 10+ different service tickets within 5-10 minutes
* Service tickets for accounts that the user doesn't typically access
* RC4 encryption when the domain requires AES (encryption downgrade)
* Tickets requested from developer/contractor accounts (easy targets for compromise)
* High-value SPN targets: SQL servers, web services, privileged service accounts
* PowerShell with Base64 commands around the same timeframe
* Service tickets requested, but no actual service connection/usage afterwards
* Requests outside business hours
* Pattern: SPN enumeration → bulk TGS requests → no service usage

**Legitimate vs Malicious:**

* **Legitimate**: Users accessing services they regularly use (1-3 tickets), AES encryption, actual service usage
* **Malicious**: Bulk requests (10+), RC4 encryption, no service connection after ticket request, tool signatures

**High-Value SPN Targets to Monitor:**

* SQL Server service accounts (MSSQLSvc/hostname)
* IIS web application pools (HTTP/hostname)
* Exchange servers
* Custom application service accounts
* Accounts with AdminSDHolder protection
* Service accounts with Domain Admin rights (should never exist)

**Post-Kerberoasting Indicators:**

* Password changes on service accounts within 24-72 hours of roasting
* Service account authentication from unusual locations
* New SPNs registered (attacker maintaining access)
* Service account used for lateral movement
* Privileged actions performed by the service account outside the normal pattern

**Tool Signatures:**

* **Rubeus**: `Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt`
* **Invoke-Kerberoast**: PowerShell cmdlet, often Base64 encoded
* **GetUserSPNs.py**: Impacket suite, Python-based
* **Mimikatz**: `kerberos::ask` command

{% code overflow="wrap" %}
```kql
// Detect Kerberoasting via service ticket requests with RC4
IdentityLogonEvents
| where Timestamp > ago(30d)
| where ActionType == "Kerberos service ticket requested"
| extend EncryptionType = tostring(parse_json(AdditionalFields).TicketEncryptionType)
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| where EncryptionType == "0x17" // RC4 encryption
| where ServiceName !has "$" // Exclude computer accounts
| where ServiceName !in ("krbtgt") // Exclude TGT service
| summarize TicketCount = count(),
            Services = make_set(ServiceName),
            FirstRequest = min(Timestamp),
            LastRequest = max(Timestamp)
    by AccountName, DeviceName
| where TicketCount >= 10 // Multiple service tickets
| extend Duration = datetime_diff('minute', LastRequest, FirstRequest)
| order by TicketCount desc

// Kerberoasting via SecurityEvent (Sentinel)
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4769 // Service ticket requested
| extend ServiceName = tostring(parse_json(EventData).ServiceName)
| extend TicketEncryptionType = tostring(parse_json(EventData).TicketEncryptionType)
| extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
| extend IpAddress = tostring(parse_json(EventData).IpAddress)
| where TicketEncryptionType == "0x17" // RC4
| where ServiceName !has "$" and ServiceName !in ("krbtgt")
| summarize TicketCount = count(),
            ServiceList = make_set(ServiceName),
            FirstRequest = min(TimeGenerated),
            LastRequest = max(TimeGenerated)
    by TargetUserName, IpAddress, Computer
| where TicketCount >= 10
| extend Duration = datetime_diff('minute', LastRequest, FirstRequest)
| project Computer, TargetUserName, IpAddress, TicketCount, Duration, 
          FirstRequest, LastRequest, ServiceList
| order by TicketCount desc

// Detect Rubeus Kerberoasting tool
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "Rubeus.exe"
   or ProcessCommandLine has_any ("kerberoast", "Rubeus", "/spn:", "/format:hashcat")
   or ProcessCommandLine matches regex @"Rubeus\.exe\s+kerberoast"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, FolderPath
| order by Timestamp desc

// Detect PowerShell Kerberoasting (Invoke-Kerberoast)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Invoke-Kerberoast", "Get-DomainUser", 
                                     "Get-NetUser", "ServicePrincipalName",
                                     "Request-SPNTicket")
   or ProcessCommandLine matches regex @"-enc\s+[A-Za-z0-9+/=]{100,}" // Base64 encoded
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName

// Detect GetUserSPNs.py (Impacket)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("python.exe", "python3.exe")
| where ProcessCommandLine has_any ("GetUserSPNs.py", "getuserspns", "impacket")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Identify accounts being Kerberoasted (high-value targets)
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4769
| extend ServiceName = tostring(parse_json(EventData).ServiceName)
| extend TicketEncryptionType = tostring(parse_json(EventData).TicketEncryptionType)
| where TicketEncryptionType == "0x17"
| where ServiceName !has "$"
| summarize RequestCount = count(),
            RequestingUsers = make_set(tostring(parse_json(EventData).TargetUserName))
    by ServiceName
| where RequestCount >= 5
| order by RequestCount desc

// Correlate Kerberoasting with password changes (compromised indicator)
let KerberoastedAccounts = SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4769
| extend ServiceName = tostring(parse_json(EventData).ServiceName)
| extend TicketEncryptionType = tostring(parse_json(EventData).TicketEncryptionType)
| where TicketEncryptionType == "0x17"
| where ServiceName !has "$"
| distinct ServiceName, TimeGenerated;
KerberoastedAccounts
| join kind=inner (
    SecurityEvent
    | where TimeGenerated > ago(30d)
    | where EventID == 4724 // Password reset
    | extend TargetUserName = tostring(parse_json(EventData).TargetUserName)
) on $left.ServiceName == $right.TargetUserName
| where TimeGenerated1 > TimeGenerated and TimeGenerated1 < TimeGenerated + 3d
| project KerberoastTime=TimeGenerated, PasswordResetTime=TimeGenerated1,
          ServiceAccount=ServiceName, Computer

// Detect encryption downgrade attempts
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4769
| extend TicketEncryptionType = tostring(parse_json(EventData).TicketEncryptionType)
| extend TicketOptions = tostring(parse_json(EventData).TicketOptions)
| extend ServiceName = tostring(parse_json(EventData).ServiceName)
| where TicketEncryptionType == "0x17" // RC4
| where TicketOptions == "0x40810000" // Forwardable + Renewable
| where ServiceName !has "$"
| project TimeGenerated, Computer, ServiceName, TicketEncryptionType, 
          TicketOptions, TargetUserName = tostring(parse_json(EventData).TargetUserName)

// Defender for Identity Kerberoasting alerts
AlertInfo
| where Timestamp > ago(30d)
| where Title has_any ("Kerberoasting", "Service ticket", "Encryption downgrade")
| join kind=inner (AlertEvidence) on AlertId
| project Timestamp, Title, Severity, DeviceName, AccountName,
          ServiceName = tostring(parse_json(AdditionalFields).ServiceName),
          RemoteUrl

// Service accounts with recent authentication anomalies
IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountName has "svc" or AccountName has "sql" or AccountName has "service"
| where LogonType == "Interactive" // Service accounts shouldn't logon interactively
| project Timestamp, AccountName, DeviceName, LogonType, IPAddress, Protocol
| order by Timestamp desc
```
{% endcode %}

**Post-Detection Actions:**

1. **Immediate**: Identify all Kerberoasted service accounts
2. Reset passwords for all affected service accounts (use 25+ character complex passwords)
3. Remove SPNs from user accounts where possible - use Group Managed Service Accounts (gMSA)
4. Audit all service account permissions - implement least privilege
5. Enable AES encryption for Kerberos (disable RC4)
6. Monitor service accounts for unusual authentication patterns
7. Implement Service Account Password Rotation policy
8. Review adminSDHolder protected accounts
9. Deploy gMSA where possible to eliminate static passwords
10. Check for lateral movement using compromised service accounts
