# Unauthorised Access & Privilege Escalation Investigation Runbook

## SOC & DFIR Operations Guide

**Environment:** Windows AD | Microsoft 365 | Defender XDR | Sentinel | Entra ID | Palo Alto Prisma Access

***

## Overview & Scope

This runbook provides standardised procedures for investigating unauthorised access attempts and privilege escalation attacks across the hybrid enterprise environment. It covers detection, investigation, containment, and remediation workflows for both on-premises Active Directory and cloud identity platforms.

### Attack Categories

#### Unauthorised Access Types

<table><thead><tr><th width="210">Type</th><th width="249">Description</th><th>Examples</th></tr></thead><tbody><tr><td><strong>Credential-Based</strong></td><td>Using stolen/compromised credentials</td><td>Phishing, credential stuffing, password spray</td></tr><tr><td><strong>Session Hijacking</strong></td><td>Taking over active sessions</td><td>Token theft, cookie hijacking, session replay</td></tr><tr><td><strong>Authentication Bypass</strong></td><td>Circumventing authentication controls</td><td>MFA bypass, legacy protocol abuse, CA policy gaps</td></tr><tr><td><strong>Access Control Abuse</strong></td><td>Exploiting misconfigurations</td><td>Overprivileged accounts, broken access control</td></tr><tr><td><strong>Insider Threat</strong></td><td>Authorized users exceeding permissions</td><td>Data theft, unauthorized system access</td></tr></tbody></table>

#### Privilege Escalation Types

| Type                            | Description                       | Target                 |
| ------------------------------- | --------------------------------- | ---------------------- |
| **Local Privilege Escalation**  | User → Admin on single system     | Endpoints, servers     |
| **Domain Privilege Escalation** | User → Domain Admin               | Active Directory       |
| **Cloud Privilege Escalation**  | User → Global Admin               | Entra ID, M365         |
| **Horizontal Escalation**       | Access to peer accounts/resources | Lateral movement       |
| **Vertical Escalation**         | Lower → Higher privilege level    | Elevation of privilege |

### Common Attack Techniques

#### On-Premises AD Privilege Escalation

<table><thead><tr><th width="216">Technique</th><th width="405">Description</th><th>Risk Level</th></tr></thead><tbody><tr><td><strong>Kerberoasting</strong></td><td>Crack service account passwords via TGS</td><td>High</td></tr><tr><td><strong>AS-REP Roasting</strong></td><td>Crack passwords for accounts without pre-auth</td><td>High</td></tr><tr><td><strong>DCSync</strong></td><td>Replicate password hashes from DC</td><td>Critical</td></tr><tr><td><strong>Golden Ticket</strong></td><td>Forge TGT with KRBTGT hash</td><td>Critical</td></tr><tr><td><strong>Silver Ticket</strong></td><td>Forge TGS for specific services</td><td>High</td></tr><tr><td><strong>AdminSDHolder Abuse</strong></td><td>Modify protected groups ACLs</td><td>Critical</td></tr><tr><td><strong>GPO Abuse</strong></td><td>Modify Group Policy for persistence/escalation</td><td>Critical</td></tr><tr><td><strong>DACL/ACL Abuse</strong></td><td>Exploit misconfigured object permissions</td><td>High</td></tr><tr><td><strong>Unconstrained Delegation</strong></td><td>Capture TGTs from connecting users</td><td>Critical</td></tr><tr><td><strong>Constrained Delegation Abuse</strong></td><td>Impersonate users to specific services</td><td>High</td></tr><tr><td><strong>Resource-Based Constrained Delegation</strong></td><td>Modify delegation settings</td><td>High</td></tr><tr><td><strong>Print Spooler Abuse</strong></td><td>PrintNightmare, SpoolSample</td><td>High</td></tr><tr><td><strong>Certificate Template Abuse</strong></td><td>AD CS misconfigurations</td><td>Critical</td></tr><tr><td><strong>Shadow Credentials</strong></td><td>Add key credentials to user objects</td><td>High</td></tr><tr><td><strong>LAPS Abuse</strong></td><td>Access local admin passwords</td><td>High</td></tr></tbody></table>

#### Cloud Privilege Escalation

<table><thead><tr><th>Technique</th><th width="296">Description</th><th>Risk Level</th></tr></thead><tbody><tr><td><strong>Entra ID Role Assignment</strong></td><td>Add user to privileged roles</td><td>Critical</td></tr><tr><td><strong>PIM Abuse</strong></td><td>Activate/exploit privileged roles</td><td>Critical</td></tr><tr><td><strong>OAuth Consent Grant</strong></td><td>Gain app permissions via consent</td><td>High</td></tr><tr><td><strong>Application Impersonation</strong></td><td>Use app permissions to access data</td><td>High</td></tr><tr><td><strong>Service Principal Abuse</strong></td><td>Exploit app registration permissions</td><td>High</td></tr><tr><td><strong>Conditional Access Bypass</strong></td><td>Circumvent CA policies</td><td>High</td></tr><tr><td><strong>Cross-Tenant Access</strong></td><td>Abuse B2B/B2C configurations</td><td>High</td></tr><tr><td><strong>Administrative Unit Abuse</strong></td><td>Escape AU restrictions</td><td>Medium</td></tr></tbody></table>

#### Local Privilege Escalation

<table><thead><tr><th>Technique</th><th width="343">Description</th><th>Risk Level</th></tr></thead><tbody><tr><td><strong>Token Manipulation</strong></td><td>Impersonate privileged tokens</td><td>High</td></tr><tr><td><strong>UAC Bypass</strong></td><td>Circumvent User Account Control</td><td>Medium</td></tr><tr><td><strong>DLL Hijacking</strong></td><td>Load malicious DLLs in privileged context</td><td>High</td></tr><tr><td><strong>Service Exploitation</strong></td><td>Abuse misconfigured services</td><td>High</td></tr><tr><td><strong>Scheduled Task Abuse</strong></td><td>Create/modify tasks for elevation</td><td>Medium</td></tr><tr><td><strong>Unquoted Service Paths</strong></td><td>Exploit path parsing vulnerabilities</td><td>Medium</td></tr><tr><td><strong>AlwaysInstallElevated</strong></td><td>MSI installation with SYSTEM privileges</td><td>High</td></tr><tr><td><strong>Kernel Exploits</strong></td><td>Exploit OS vulnerabilities</td><td>Critical</td></tr><tr><td><strong>Named Pipe Impersonation</strong></td><td>Impersonate connecting clients</td><td>High</td></tr></tbody></table>

***

## Detection Sources & Data Mapping

### Log Sources Matrix

<table><thead><tr><th width="189">Platform</th><th width="222">Log Table</th><th>Key Data</th></tr></thead><tbody><tr><td>On-Prem AD</td><td><code>SecurityEvent</code></td><td>Privileged logons, group changes, ACL modifications</td></tr><tr><td>Defender for Identity</td><td><code>IdentityDirectoryEvents</code></td><td>AD object changes, reconnaissance</td></tr><tr><td>Defender for Identity</td><td><code>IdentityLogonEvents</code></td><td>Authentication events, anomalies</td></tr><tr><td>Defender for Identity</td><td><code>IdentityQueryEvents</code></td><td>LDAP queries, enumeration</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceEvents</code></td><td>Token manipulation, UAC bypass</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceProcessEvents</code></td><td>Privilege escalation tools</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceLogonEvents</code></td><td>Local/remote logons</td></tr><tr><td>Entra ID</td><td><code>AuditLogs</code></td><td>Role assignments, PIM activations</td></tr><tr><td>Entra ID</td><td><code>SigninLogs</code></td><td>Privileged account access</td></tr><tr><td>Cloud Apps</td><td><code>CloudAppEvents</code></td><td>OAuth grants, app permissions</td></tr><tr><td>Sentinel</td><td><code>AzureActivity</code></td><td>Azure RBAC changes</td></tr><tr><td>Sentinel</td><td><code>SecurityAlert</code></td><td>Correlated privilege alerts</td></tr></tbody></table>

### Critical Windows Event IDs

#### Authentication & Access

<table><thead><tr><th width="103">Event ID</th><th width="230">Description</th><th>Investigation Relevance</th></tr></thead><tbody><tr><td><strong>4624</strong></td><td>Successful logon</td><td>Track privileged access patterns</td></tr><tr><td><strong>4625</strong></td><td>Failed logon</td><td>Brute force, unauthorized access attempts</td></tr><tr><td><strong>4648</strong></td><td>Explicit credential logon</td><td>Credential usage, lateral movement</td></tr><tr><td><strong>4672</strong></td><td>Special privileges assigned</td><td>Admin/privileged logon detection</td></tr><tr><td><strong>4768</strong></td><td>Kerberos TGT requested</td><td>Initial authentication, AS-REP roasting</td></tr><tr><td><strong>4769</strong></td><td>Kerberos TGS requested</td><td>Kerberoasting, service access</td></tr><tr><td><strong>4771</strong></td><td>Kerberos pre-auth failed</td><td>Password attacks</td></tr><tr><td><strong>4776</strong></td><td>NTLM authentication</td><td>Legacy auth, Pass-the-Hash</td></tr></tbody></table>

#### Privilege Changes

<table><thead><tr><th width="128">Event ID</th><th>Description</th><th>Investigation Relevance</th></tr></thead><tbody><tr><td><strong>4728</strong></td><td>Member added to security group</td><td>Privilege escalation</td></tr><tr><td><strong>4729</strong></td><td>Member removed from security group</td><td>Access revocation, cover-up</td></tr><tr><td><strong>4732</strong></td><td>Member added to local group</td><td>Local privilege escalation</td></tr><tr><td><strong>4733</strong></td><td>Member removed from local group</td><td>Access changes</td></tr><tr><td><strong>4756</strong></td><td>Member added to universal group</td><td>Enterprise-wide access</td></tr><tr><td><strong>4757</strong></td><td>Member removed from universal group</td><td>Access changes</td></tr></tbody></table>

#### Object & Policy Changes

<table><thead><tr><th width="129">Event ID</th><th>Description</th><th>Investigation Relevance</th></tr></thead><tbody><tr><td><strong>4662</strong></td><td>Object access operation</td><td>DCSync detection, AD object access</td></tr><tr><td><strong>4663</strong></td><td>Object access attempted</td><td>File/folder access</td></tr><tr><td><strong>4670</strong></td><td>Permissions changed on object</td><td>ACL modification</td></tr><tr><td><strong>4713</strong></td><td>Kerberos policy changed</td><td>Security policy tampering</td></tr><tr><td><strong>4719</strong></td><td>System audit policy changed</td><td>Audit evasion</td></tr><tr><td><strong>4739</strong></td><td>Domain policy changed</td><td>Domain-wide changes</td></tr><tr><td><strong>4780</strong></td><td>ACL set on admin accounts</td><td>AdminSDHolder modification</td></tr><tr><td><strong>5136</strong></td><td>Directory object modified</td><td>AD attribute changes</td></tr><tr><td><strong>5137</strong></td><td>Directory object created</td><td>New AD objects</td></tr><tr><td><strong>5141</strong></td><td>Directory object deleted</td><td>AD object removal</td></tr></tbody></table>

#### Service & Scheduled Task

<table><thead><tr><th width="139">Event ID</th><th>Description</th><th>Investigation Relevance</th></tr></thead><tbody><tr><td><strong>4697</strong></td><td>Service installed</td><td>Persistence, privilege escalation</td></tr><tr><td><strong>4698</strong></td><td>Scheduled task created</td><td>Persistence mechanism</td></tr><tr><td><strong>4699</strong></td><td>Scheduled task deleted</td><td>Cover-up activity</td></tr><tr><td><strong>4700</strong></td><td>Scheduled task enabled</td><td>Activation of persistence</td></tr><tr><td><strong>4702</strong></td><td>Scheduled task updated</td><td>Modification of tasks</td></tr></tbody></table>

***

## Investigation Workflows

### Unauthorised Access Investigation

**Objective:** Determine if access was unauthorised, identify the access method, assess impact, and remediate.

#### Step 1: Initial Triage

1. Review the alert source and detection logic
2. Identify the account and resource accessed
3. Verify if access was expected/authorised
4. Check account type: user, service, admin, guest
5. Determine time of access vs. normal working hours

#### Step 2: Access Pattern Analysis

1. Query SigninLogs/SecurityEvent for account history
2. Compare current access to baseline behaviour
3. Check source IP, location, and device
4. Review authentication method used
5. Identify any Conditional Access policy bypasses

#### Step 3: Session Analysis

1. Determine session duration and activity
2. Query all resources accessed during session
3. Check for data access, downloads, or modifications
4. Review email activity if applicable
5. Examine file access patterns

#### Step 4: Authorisation Verification

1. Confirm account's authorised access level
2. Check group memberships and role assignments
3. Verify if access was within scope of permissions
4. Review any recent permission changes
5. Contact account owner if needed for verification

#### Step 5: Impact Assessment

1. Document all resources accessed
2. Identify sensitive data exposure
3. Check for data exfiltration indicators
4. Assess potential for lateral movement
5. Determine business impact

***

### Domain Privilege Escalation Investigation

**Objective:** Detect and investigate attempts to gain elevated privileges within Active Directory.

#### Step 1: Identify Escalation Vector

1. Review MDI alerts for known attack patterns
2. Check for Kerberoasting/AS-REP Roasting indicators
3. Look for DCSync or replication anomalies
4. Review sensitive group membership changes
5. Check for delegation abuse

#### Step 2: Sensitive Group Monitoring

**Critical Groups to Monitor:**

| Group                       | Risk     | Detection Focus            |
| --------------------------- | -------- | -------------------------- |
| Domain Admins               | Critical | Any membership change      |
| Enterprise Admins           | Critical | Any membership change      |
| Schema Admins               | Critical | Any membership change      |
| Administrators              | Critical | Non-standard additions     |
| Account Operators           | High     | Can create/modify accounts |
| Backup Operators            | High     | Can access any file        |
| Server Operators            | High     | Can logon to DCs           |
| Print Operators             | High     | Can load drivers on DCs    |
| DnsAdmins                   | High     | Can execute code on DCs    |
| Group Policy Creator Owners | High     | Can create GPOs            |

#### Step 3: DCSync Detection

1. Query for Directory Replication Service Access
2. Check 4662 events for replication GUIDs
3. Verify source is a legitimate domain controller
4. Review MDI alerts for DCSync detection
5. Check for DRSUAPI calls from non-DCs

#### Step 4: Kerberos Attack Detection

1. Review 4769 events for RC4 encryption (0x17)
2. Check for bulk TGS requests from single user
3. Look for AS-REQ without pre-auth (4768)
4. Monitor for ticket anomalies via MDI
5. Check for golden/silver ticket indicators

#### Step 5: GPO Abuse Detection

1. Query for GPO creation/modification events
2. Check for GPO links to sensitive OUs
3. Review script deployment via GPO
4. Look for scheduled task deployment
5. Monitor for software installation changes

***

### Cloud Privilege Escalation Investigation

**Objective:** Detect and investigate privilege escalation within Entra ID and Microsoft 365.

#### Step 1: Role Assignment Analysis

1. Query AuditLogs for role assignment events
2. Identify who assigned the role and when
3. Verify the assignment was authorised
4. Check if proper approval workflow was followed
5. Review the user's other role assignments

#### Step 2: PIM Activity Review

1. Query for PIM role activations
2. Check justification provided for activation
3. Verify approval if required
4. Review activation duration
5. Analyse activity during activation period

#### Step 3: Application Consent Analysis

1. Query for OAuth consent grant events
2. Identify permissions granted
3. Check if admin consent was required/given
4. Review the application's reputation
5. Assess risk of granted permissions

#### Step 4: Service Principal Investigation

1. Review service principal permission changes
2. Check for credential/secret additions
3. Identify API permissions granted
4. Review owner assignments
5. Check for federation configurations

#### Step 5: Conditional Access Bypass

1. Review sign-ins that bypassed CA policies
2. Identify policy gaps or exclusions
3. Check for legacy authentication usage
4. Review named locations and trusted IPs
5. Assess device compliance bypasses

***

### Local Privilege Escalation Investigation

**Objective:** Detect and investigate attempts to gain SYSTEM or admin privileges on endpoints.

#### Step 1: Process Analysis

1. Review DeviceProcessEvents for suspicious activity
2. Check for known escalation tools (mimikatz, etc.)
3. Analyse parent-child process relationships
4. Look for unusual SYSTEM process creation
5. Check for token manipulation indicators

#### Step 2: Service Exploitation Detection

1. Review service creation/modification events
2. Check for unquoted service paths
3. Look for writable service binaries
4. Review service account permissions
5. Check for DLL hijacking opportunities

#### Step 3: Scheduled Task Analysis

1. Query for task creation by non-admin users
2. Check for SYSTEM-level task execution
3. Review task actions and triggers
4. Look for suspicious task paths
5. Check for legacy AT jobs

#### Step 4: Exploit Indicators

1. Review MDE alerts for exploit detection
2. Check for kernel exploit indicators
3. Look for UAC bypass patterns
4. Review memory injection alerts
5. Check for driver loading anomalies

***

## KQL Query Cheat Sheet

### Privileged Account Monitoring

#### Privileged Logon Activity

{% code overflow="wrap" %}
```kusto
// Monitor privileged account logons
let PrivilegedAccounts = dynamic(["admin", "administrator", "domain admin"]);
IdentityLogonEvents
| where Timestamp > ago(24h)
| where AccountUpn has_any (PrivilegedAccounts) or AccountName has_any (PrivilegedAccounts)
| summarize 
    LogonCount = count(),
    UniqueDevices = dcount(TargetDeviceName),
    Devices = make_set(TargetDeviceName, 10),
    LogonTypes = make_set(LogonType)
    by AccountUpn, AccountName
| sort by LogonCount desc
```
{% endcode %}

#### Special Privileges Assigned (4672)

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4672
| where SubjectUserName !endswith "$"  // Exclude computer accounts
| summarize 
    PrivilegedLogons = count(),
    UniqueWorkstations = dcount(WorkstationName),
    Workstations = make_set(WorkstationName, 10)
    by SubjectUserName, SubjectDomainName
| sort by PrivilegedLogons desc
```

#### First-Time Privileged Access

{% code overflow="wrap" %}
```kusto
let lookback = 30d;
let timeframe = 1d;
let baseline = SecurityEvent
| where TimeGenerated between (ago(lookback) .. ago(timeframe))
| where EventID == 4672
| summarize by SubjectUserName, SubjectDomainName;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4672
| where SubjectUserName !endswith "$"
| join kind=leftanti baseline on SubjectUserName, SubjectDomainName
| project TimeGenerated, SubjectUserName, SubjectDomainName, WorkstationName, LogonType
```
{% endcode %}

***

### Sensitive Group Changes

#### Domain Admin Group Modifications

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4729, 4732, 4733, 4756, 4757)
| where TargetUserName in~ (
    "Domain Admins", 
    "Enterprise Admins", 
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators")
| project 
    TimeGenerated,
    EventID,
    Action = case(
        EventID in (4728, 4732, 4756), "Member Added",
        EventID in (4729, 4733, 4757), "Member Removed",
        "Unknown"),
    TargetGroup = TargetUserName,
    MemberAdded = MemberName,
    ChangedBy = SubjectUserName,
    ChangedFrom = Computer
| sort by TimeGenerated desc
```

#### Entra ID Role Assignments

{% code overflow="wrap" %}
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Add scoped member to role")
| extend 
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    RoleName = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue),
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where RoleName has_any ("Global Administrator", "Privileged Role Administrator", "Security Administrator", "Exchange Administrator", "SharePoint Administrator")
| project TimeGenerated, OperationName, TargetUser, RoleName, InitiatedBy, Result
```
{% endcode %}

#### PIM Role Activations

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role completed (PIM activation)"
| extend 
    ActivatedBy = tostring(InitiatedBy.user.userPrincipalName),
    RoleName = tostring(TargetResources[0].displayName),
    Justification = tostring(AdditionalDetails[3].value)
| project TimeGenerated, ActivatedBy, RoleName, Justification, Result
| sort by TimeGenerated desc
```

***

### Kerberos Attack Detection

#### Kerberoasting Detection

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| where ServiceName !endswith "$"  // Exclude computer accounts
| where TicketEncryptionType == "0x17"  // RC4 encryption
| summarize 
    RequestCount = count(),
    UniqueServices = dcount(ServiceName),
    Services = make_set(ServiceName, 20)
    by TargetUserName, IpAddress
| where RequestCount > 5 or UniqueServices > 3
| sort by RequestCount desc
```

#### AS-REP Roasting Detection

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4768
| where PreAuthType == "0"  // No pre-authentication
| where TargetUserName !endswith "$"
| project TimeGenerated, TargetUserName, IpAddress, ServiceName, TicketEncryptionType
| sort by TimeGenerated desc
```

#### Golden Ticket Indicators

{% code overflow="wrap" %}
```kusto
// TGT requests with anomalies
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4768
| where TicketOptions has_any ("0x40810010", "0x60810010")  // Renewable, forwardable
| where TargetUserName !endswith "$"
| extend TicketLifetime = datetime_diff('hour', TicketExpiryTime, TimeGenerated)
| where TicketLifetime > 10  // Abnormally long lifetime
| project TimeGenerated, TargetUserName, IpAddress, ServiceName, TicketLifetime, TicketOptions
```
{% endcode %}

#### Silver Ticket / Service Ticket Anomalies

{% code overflow="wrap" %}
```kusto
// TGS requests without corresponding TGT
let TGTRequests = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4768
| project TGTTime = TimeGenerated, TGTUser = TargetUserName, TGTClient = IpAddress;
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| join kind=leftanti TGTRequests on $left.TargetUserName == $right.TGTUser, $left.IpAddress == $right.TGTClient
| where ServiceName !endswith "$"
| project TimeGenerated, TargetUserName, ServiceName, IpAddress, TicketEncryptionType
```
{% endcode %}

***

### DCSync & Replication Attacks

#### DCSync Detection

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4662
| where ObjectType contains "domainDNS"
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c")  // DS-Replication-Get-Changes-In-Filtered-Set
| where SubjectUserName !endswith "$"
| project TimeGenerated, SubjectUserName, SubjectDomainName, ObjectName, Properties, Computer
| sort by TimeGenerated desc
```
{% endcode %}

#### Defender for Identity - DCSync

{% code overflow="wrap" %}
```kusto
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Service Replication"
| where DestinationDeviceName !contains "DC"
| project Timestamp, AccountDisplayName, DestinationDeviceName, TargetDeviceName, Application
```
{% endcode %}

***

### ACL & Permission Abuse

#### AdminSDHolder Modification

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4780
| project TimeGenerated, SubjectUserName, SubjectDomainName, TargetUserName, Computer
| sort by TimeGenerated desc
```

#### Object Permission Changes

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4670
| where ObjectType has_any ("user", "group", "computer")
| project 
    TimeGenerated,
    SubjectUserName,
    ObjectName,
    ObjectType,
    OldSd,
    NewSd,
    Computer
| sort by TimeGenerated desc
```

#### Delegation Configuration Changes

```kusto
// Detect changes to delegation settings
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Attribute modified"
| where AdditionalFields has_any (
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "userAccountControl")
| project Timestamp, AccountDisplayName, TargetAccountDisplayName, AdditionalFields
```

***

### Local Privilege Escalation

#### Token Manipulation Detection

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType in (
    "CreateRemoteThreadApiCall",
    "OpenProcessApiCall",
    "DuplicateTokenApiCall",
    "ImpersonateLoggedOnUserApiCall")
| where InitiatingProcessFileName !in~ ("services.exe", "lsass.exe", "svchost.exe", "csrss.exe")
| project Timestamp, DeviceName, ActionType, 
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    FileName, ProcessCommandLine
```
{% endcode %}

#### Suspicious Service Installation

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| extend ServicePath = tostring(parse_json(AdditionalFields).ServicePath)
| extend ServiceAccount = tostring(parse_json(AdditionalFields).ServiceAccount)
| where ServicePath !startswith "C:\\Windows\\System32"
    or ServiceAccount == "LocalSystem"
| project Timestamp, DeviceName, ServiceName, ServicePath, ServiceAccount, InitiatingProcessFileName
```
{% endcode %}

#### UAC Bypass Detection

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (
    // Fodhelper bypass
    (FileName =~ "fodhelper.exe" and InitiatingProcessFileName !~ "explorer.exe")
    // Eventvwr bypass
    or (FileName =~ "eventvwr.exe" and InitiatingProcessFileName !~ "explorer.exe")
    // Computerdefaults bypass
    or (FileName =~ "computerdefaults.exe" and InitiatingProcessFileName !~ "explorer.exe")
    // CMSTP bypass
    or (FileName =~ "cmstp.exe" and ProcessCommandLine has "/au")
    // WSReset bypass
    or (FileName =~ "wsreset.exe" and InitiatingProcessFileName !~ "explorer.exe")
)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
{% endcode %}

#### Scheduled Task Privilege Escalation

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "ScheduledTaskCreated"
| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)
| extend TaskContent = tostring(parse_json(AdditionalFields).TaskContent)
| where TaskContent has_any ("SYSTEM", "S-1-5-18", "NT AUTHORITY")
| where InitiatingProcessAccountSid !startswith "S-1-5-18"  // Not created by SYSTEM
| project Timestamp, DeviceName, TaskName, InitiatingProcessAccountName, InitiatingProcessFileName
```
{% endcode %}

***

### OAuth & Application Abuse

#### Suspicious OAuth Consent Grants

{% code overflow="wrap" %}
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties[4].newValue)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All")
| project TimeGenerated, AppName, Permissions, ConsentedBy, Result
```
{% endcode %}

#### Application Permission Changes

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any (
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add application")
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, TargetApp, ModifiedBy, Result
| sort by TimeGenerated desc
```

#### Service Principal Credential Addition

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any (
    "Add service principal credentials",
    "Update application – Certificates and secrets management")
| extend AppName = tostring(TargetResources[0].displayName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, AppName, ModifiedBy, Result
```

***

### Conditional Access & Access Policy

#### Conditional Access Policy Changes

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any (
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy")
| extend PolicyName = tostring(TargetResources[0].displayName)
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, PolicyName, ModifiedBy, Result
```

#### Sign-ins Bypassing Conditional Access

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful
| where ConditionalAccessStatus == "notApplied"
| where UserPrincipalName !has "#EXT#"  // Exclude guest accounts
| summarize 
    BypassCount = count(),
    UniqueApps = dcount(AppDisplayName),
    Apps = make_set(AppDisplayName, 10)
    by UserPrincipalName, IPAddress, Location
| where BypassCount > 5
| sort by BypassCount desc
```

#### Legacy Authentication Usage

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Other clients")
| summarize 
    LegacyAuthCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20)
    by ClientAppUsed, IPAddress
| sort by LegacyAuthCount desc
```
{% endcode %}

***

### Lateral Movement Detection

#### Unusual Lateral Movement Patterns

```kusto
IdentityLogonEvents
| where Timestamp > ago(24h)
| where LogonType in ("RemoteInteractive", "Network")
| summarize 
    TargetDevices = dcount(TargetDeviceName),
    DeviceList = make_set(TargetDeviceName, 50),
    LogonCount = count()
    by AccountUpn, bin(Timestamp, 1h)
| where TargetDevices > 5
| sort by TargetDevices desc
```

#### Pass-the-Hash / Pass-the-Ticket

```kusto
IdentityLogonEvents
| where Timestamp > ago(24h)
| where LogonType == "Network"
| where Protocol in ("NTLM", "Kerberos")
| where isnotempty(FailureReason)
| summarize 
    FailedAttempts = count(),
    TargetDevices = dcount(TargetDeviceName),
    Reasons = make_set(FailureReason)
    by AccountUpn, Protocol
| where FailedAttempts > 10
```

***

## Response Actions & Remediation

### Immediate Containment Actions

| Scenario                           | Action                           | Method                   |
| ---------------------------------- | -------------------------------- | ------------------------ |
| **Compromised Privileged Account** | Disable account                  | AD + Entra ID disable    |
| **Active Privilege Escalation**    | Isolate affected systems         | MDE device isolation     |
| **DCSync Detected**                | Block source IP, disable account | Firewall + AD disable    |
| **Rogue Admin Account**            | Disable and remove from groups   | AD + Entra ID            |
| **Malicious OAuth App**            | Revoke consent, disable app      | Entra ID Enterprise Apps |
| **Golden Ticket Suspected**        | Reset KRBTGT (twice)             | AD KRBTGT reset script   |
| **Unauthorized Role Assignment**   | Remove role assignment           | Entra ID / PIM           |

### Privileged Account Remediation

#### Active Directory

{% code overflow="wrap" %}
```powershell
# Disable compromised account
Disable-ADAccount -Identity "compromised_user"

# Remove from all privileged groups
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach ($group in $privilegedGroups) {
    Remove-ADGroupMember -Identity $group -Members "compromised_user" -Confirm:$false
}

# Reset password
Set-ADAccountPassword -Identity "compromised_user" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempP@ssw0rd!" -Force)

# Force password change at next logon
Set-ADUser -Identity "compromised_user" -ChangePasswordAtLogon $true

# Check and remove any delegations
Get-ADUser "compromised_user" -Properties msDS-AllowedToDelegateTo | 
    Set-ADUser -Clear "msDS-AllowedToDelegateTo"
```
{% endcode %}

#### Entra ID

{% code overflow="wrap" %}
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Block sign-in
Update-MgUser -UserId "user@domain.com" -AccountEnabled:$false

# Revoke all sessions
Revoke-MgUserSignInSession -UserId "user@domain.com"

# Remove from privileged roles
$userId = (Get-MgUser -UserId "user@domain.com").Id
$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$userId'"
foreach ($assignment in $roleAssignments) {
    Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $assignment.Id
}

# Remove from PIM eligible roles
$eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$userId'"
# Review and remove as needed
```
{% endcode %}

### KRBTGT Reset Procedure

> ⚠️ **Warning:** KRBTGT reset affects all Kerberos tickets in the domain. Plan carefully and reset twice with appropriate interval.

```powershell
# Download and use the official Microsoft KRBTGT reset script
# https://github.com/microsoft/New-KrbtgtKeys.ps1

# First reset
.\New-KrbtgtKeys.ps1 -Mode 2

# Wait for replication (minimum 10 hours recommended, or 2x maximum ticket lifetime)
# Monitor for authentication issues

# Second reset (invalidates all tickets including any forged ones)
.\New-KrbtgtKeys.ps1 -Mode 2
```

### OAuth Application Remediation

{% code overflow="wrap" %}
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Revoke OAuth consent for specific app
$servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Malicious App'"
$grants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $servicePrincipal.Id
foreach ($grant in $grants) {
    Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id
}

# Disable the application
Update-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id -AccountEnabled:$false

# Remove app role assignments
$appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id
foreach ($assignment in $appRoleAssignments) {
    Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipal.Id -AppRoleAssignmentId $assignment.Id
}
```
{% endcode %}

***

## Quick Reference Cards

### Privilege Escalation Attack Identification

<table><thead><tr><th width="158">Attack</th><th width="435">Key Indicators</th><th>Primary Detection</th></tr></thead><tbody><tr><td><strong>Kerberoasting</strong></td><td>RC4 TGS requests, bulk service ticket requests</td><td>Event 4769, MDI</td></tr><tr><td><strong>AS-REP Roasting</strong></td><td>4768 without pre-auth, accounts with DONT_REQ_PREAUTH</td><td>Event 4768, MDI</td></tr><tr><td><strong>DCSync</strong></td><td>Replication from non-DC, 4662 with replication GUIDs</td><td>Event 4662, MDI</td></tr><tr><td><strong>Golden Ticket</strong></td><td>TGT anomalies, long lifetime, forged PAC</td><td>MDI, Event 4768</td></tr><tr><td><strong>Silver Ticket</strong></td><td>TGS without TGT, service ticket anomalies</td><td>MDI, Event 4769</td></tr><tr><td><strong>Pass-the-Hash</strong></td><td>NTLM from unusual source, network logon type</td><td>Event 4776, MDI</td></tr><tr><td><strong>Pass-the-Ticket</strong></td><td>Kerberos reuse across systems</td><td>MDI, correlation</td></tr><tr><td><strong>GPO Abuse</strong></td><td>GPO modification, link changes</td><td>Event 5136, 5137</td></tr><tr><td><strong>AdminSDHolder</strong></td><td>ACL modification on protected objects</td><td>Event 4780</td></tr><tr><td><strong>Delegation Abuse</strong></td><td>msDS-AllowedToDelegateTo changes</td><td>Event 5136, MDI</td></tr></tbody></table>

### Critical AD Object GUIDs for Detection

<table><thead><tr><th width="334">GUID</th><th width="273">Object/Permission</th><th>Risk</th></tr></thead><tbody><tr><td><code>1131f6aa-9c07-11d1-f79f-00c04fc2dcd2</code></td><td>DS-Replication-Get-Changes</td><td>DCSync</td></tr><tr><td><code>1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</code></td><td>DS-Replication-Get-Changes-All</td><td>DCSync</td></tr><tr><td><code>89e95b76-444d-4c62-991a-0facbeda640c</code></td><td>DS-Replication-Get-Changes-In-Filtered-Set</td><td>DCSync</td></tr><tr><td><code>00000000-0000-0000-0000-000000000000</code></td><td>All extended rights</td><td>Full control</td></tr><tr><td><code>00299570-246d-11d0-a768-00aa006e0529</code></td><td>User-Force-Change-Password</td><td>Password reset</td></tr></tbody></table>

### Entra ID Critical Roles

<table><thead><tr><th width="319">Role</th><th>Risk Level</th><th>Monitor For</th></tr></thead><tbody><tr><td>Global Administrator</td><td>Critical</td><td>Any assignment</td></tr><tr><td>Privileged Role Administrator</td><td>Critical</td><td>Any assignment</td></tr><tr><td>Security Administrator</td><td>High</td><td>Unusual assignment</td></tr><tr><td>Exchange Administrator</td><td>High</td><td>Mailbox access abuse</td></tr><tr><td>SharePoint Administrator</td><td>High</td><td>Data access abuse</td></tr><tr><td>Application Administrator</td><td>High</td><td>App permission abuse</td></tr><tr><td>Cloud Application Administrator</td><td>High</td><td>App permission abuse</td></tr><tr><td>Authentication Administrator</td><td>High</td><td>MFA/password bypass</td></tr><tr><td>User Administrator</td><td>Medium</td><td>Account creation</td></tr></tbody></table>

***

## Escalation Matrix

### Severity Classification

<table><thead><tr><th width="125">Severity</th><th width="449">Criteria</th><th>Response Time</th></tr></thead><tbody><tr><td>🔴 <strong>Critical</strong></td><td>Domain Admin compromise, DCSync confirmed, Golden Ticket, Global Admin compromise</td><td>Immediate - 15 min</td></tr><tr><td>🟠 <strong>High</strong></td><td>Privileged account compromise, sensitive group changes, Kerberoasting success</td><td>30 min - 1 hour</td></tr><tr><td>🟡 <strong>Medium</strong></td><td>Privilege escalation attempt blocked, suspicious privilege usage</td><td>4 hours</td></tr><tr><td>🟢 <strong>Low</strong></td><td>Failed privilege escalation, reconnaissance activity</td><td>Next business day</td></tr></tbody></table>

### Escalation Triggers

| Condition                             | Escalation Level            |
| ------------------------------------- | --------------------------- |
| Domain Admin/Global Admin compromised | DFIR + Identity Team + CISO |
| DCSync/Golden Ticket detected         | DFIR + Identity Team        |
| Multiple privileged accounts affected | Tier 2 SOC + DFIR           |
| Kerberoasting with successful cracks  | Tier 2 SOC                  |
| Sensitive group membership change     | Tier 2 SOC                  |
| Unauthorized PIM activation           | Tier 2 SOC                  |
| OAuth admin consent abuse             | Tier 2 SOC + App Owner      |

### Notification Requirements

<table><thead><tr><th width="153">Severity</th><th>Internal Notification</th><th>External Notification</th></tr></thead><tbody><tr><td>Critical</td><td>CISO, CIO, Legal (1 hour)</td><td>Consider regulatory (24-72 hours)</td></tr><tr><td>High</td><td>Security Leadership (4 hours)</td><td>As required</td></tr><tr><td>Medium</td><td>SOC Manager (next shift)</td><td>N/A</td></tr><tr><td>Low</td><td>Standard reporting</td><td>N/A</td></tr></tbody></table>

***

## MITRE ATT\&CK Mapping

### Privilege Escalation (TA0004)

<table><thead><tr><th>Technique</th><th width="103">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Abuse Elevation Control Mechanism</td><td>T1548</td><td>UAC bypass, sudo abuse</td><td>DeviceProcessEvents</td></tr><tr><td>Access Token Manipulation</td><td>T1134</td><td>Token theft/impersonation</td><td>DeviceEvents</td></tr><tr><td>Boot or Logon Autostart</td><td>T1547</td><td>Persistence for priv code</td><td>DeviceRegistryEvents</td></tr><tr><td>Create or Modify System Process</td><td>T1543</td><td>Service/daemon creation</td><td>DeviceEvents</td></tr><tr><td>Domain Policy Modification</td><td>T1484</td><td>GPO modification</td><td>SecurityEvent 5136</td></tr><tr><td>Event Triggered Execution</td><td>T1546</td><td>WMI, accessibility features</td><td>DeviceEvents</td></tr><tr><td>Exploitation for Privilege Escalation</td><td>T1068</td><td>Kernel/software exploits</td><td>MDE Alerts</td></tr><tr><td>Hijack Execution Flow</td><td>T1574</td><td>DLL hijacking, path interception</td><td>DeviceProcessEvents</td></tr><tr><td>Process Injection</td><td>T1055</td><td>Code injection techniques</td><td>DeviceEvents</td></tr><tr><td>Scheduled Task/Job</td><td>T1053</td><td>Elevated task creation</td><td>DeviceEvents</td></tr><tr><td>Valid Accounts</td><td>T1078</td><td>Privileged account abuse</td><td>SigninLogs, IdentityLogonEvents</td></tr></tbody></table>

### Credential Access (Related)

<table><thead><tr><th>Technique</th><th width="91">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>OS Credential Dumping</td><td>T1003</td><td>LSASS, SAM, DCSync</td><td>DeviceEvents, SecurityEvent 4662</td></tr><tr><td>Steal or Forge Kerberos Tickets</td><td>T1558</td><td>Golden/Silver ticket, Kerberoasting</td><td>SecurityEvent 4768/4769, MDI</td></tr><tr><td>Unsecured Credentials</td><td>T1552</td><td>Credentials in files/registry</td><td>DeviceFileEvents</td></tr></tbody></table>

### Persistence (Related)

<table><thead><tr><th width="190">Technique</th><th width="94">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Account Manipulation</td><td>T1098</td><td>Add credentials, SSH keys</td><td>AuditLogs, SecurityEvent</td></tr><tr><td>Create Account</td><td>T1136</td><td>Local/domain/cloud accounts</td><td>SecurityEvent 4720, AuditLogs</td></tr></tbody></table>

***

## Appendix: Investigation Commands

### Active Directory Enumeration

{% code overflow="wrap" %}
```powershell
# Find users with SPN (Kerberoasting targets)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
    Select-Object Name, SamAccountName, ServicePrincipalName

# Find users without pre-auth (AS-REP Roasting targets)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
    Select-Object Name, SamAccountName, DoesNotRequirePreAuth

# Get members of privileged groups
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Select-Object Name, SamAccountName

# Check for unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select-Object Name, DNSHostName, TrustedForDelegation

# Check for constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo |
    Select-Object Name, SamAccountName, msDS-AllowedToDelegateTo

# Find AdminSDHolder protected objects
Get-ADObject -Filter {AdminCount -eq 1} -Properties AdminCount | Select-Object Name, ObjectClass

# Check recent privileged group changes
Get-ADGroup -Identity "Domain Admins" -Properties whenChanged | Select-Object Name, whenChanged
```
{% endcode %}

### ACL Analysis

{% code overflow="wrap" %}
```powershell
# Get ACL for sensitive objects
Import-Module ActiveDirectory
$domain = (Get-ADDomain).DistinguishedName

# Domain object permissions
(Get-Acl "AD:\$domain").Access | Where-Object {$_.ActiveDirectoryRights -match "ExtendedRight"} |
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType

# AdminSDHolder permissions
$adminSDHolder = "CN=AdminSDHolder,CN=System,$domain"
(Get-Acl "AD:\$adminSDHolder").Access | Select-Object IdentityReference, ActiveDirectoryRights

# Check GPO permissions
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $permissions = Get-GPPermission -Guid $gpo.Id -All
    $permissions | Select-Object @{N='GPO';E={$gpo.DisplayName}}, Trustee, Permission
}
```
{% endcode %}

### Entra ID Investigation

{% code overflow="wrap" %}
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All", "AuditLog.Read.All", "RoleManagement.Read.All"

# Get all Global Administrators
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | ForEach-Object {
    Get-MgUser -UserId $_.Id | Select-Object DisplayName, UserPrincipalName
}

# Get recent role assignments
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add member to role'" -Top 50 |
    Select-Object ActivityDateTime, InitiatedBy, TargetResources

# Get service principals with high privileges
$appRoles = Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
    foreach ($assignment in $assignments) {
        [PSCustomObject]@{
            AppDisplayName = $sp.DisplayName
            AppRoleId = $assignment.AppRoleId
            PrincipalType = $assignment.PrincipalType
        }
    }
}

# Check OAuth consent grants
Get-MgOauth2PermissionGrant -All | Where-Object {$_.ConsentType -eq "AllPrincipals"} |
    Select-Object ClientId, Scope, ConsentType
```
{% endcode %}

### Local Privilege Escalation Checks

{% code overflow="wrap" %}
```powershell
# Check for unquoted service paths
Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -notlike '"*' -and 
    $_.PathName -like '* *' -and 
    $_.PathName -notlike 'C:\Windows\*'
} | Select-Object Name, PathName, StartMode

# Check AlwaysInstallElevated
$hklm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$hkcu = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
    Write-Warning "AlwaysInstallElevated is enabled - privilege escalation possible!"
}

# Check for writable service binaries
$services = Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -ne $null}
foreach ($service in $services) {
    $path = ($service.PathName -split '"')[1]
    if ($path -and (Test-Path $path)) {
        $acl = Get-Acl $path
        $writable = $acl.Access | Where-Object {
            $_.FileSystemRights -match "Write|FullControl" -and
            $_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller"
        }
        if ($writable) {
            Write-Warning "Writable service binary: $path"
        }
    }
}

# Check scheduled tasks running as SYSTEM
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"} |
    Select-Object TaskName, TaskPath, @{N='Actions';E={$_.Actions.Execute}}
```
{% endcode %}

***

> ⚠️ **Critical Reminder:** Privilege escalation investigations often uncover broader compromise. Always assume lateral movement has occurred and expand investigation scope accordingly. When Domain Admin or Global Admin compromise is suspected, engage DFIR immediately and consider the entire environment potentially compromised.
