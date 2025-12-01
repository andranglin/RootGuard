# Identity Attack Investigation Runbook

## SOC & DFIR Operations Guide

**Environment:** Windows AD | Microsoft 365 | Defender XDR | Sentinel | Entra ID | Palo Alto Prisma Access

***

## Overview & Scope

This runbook provides standardised procedures for investigating identity-based attacks across the hybrid enterprise environment. It covers detection, investigation, containment, and remediation workflows for both on-premises Active Directory and cloud identity platforms.

### Identity Attack Categories

<table><thead><tr><th width="211">Category</th><th>Techniques</th></tr></thead><tbody><tr><td><strong>Credential Theft</strong></td><td>Password spraying, brute force, credential stuffing, phishing</td></tr><tr><td><strong>Token/Session Attacks</strong></td><td>Pass-the-Hash, Pass-the-Ticket, Golden/Silver Ticket, Token theft</td></tr><tr><td><strong>Privilege Escalation</strong></td><td>Kerberoasting, AS-REP Roasting, DCSync, AdminSDHolder abuse</td></tr><tr><td><strong>Lateral Movement</strong></td><td>RDP hijacking, SMB relay, DCOM/WMI abuse</td></tr><tr><td><strong>Persistence</strong></td><td>Skeleton Key, DCShadow, Federation trust abuse, App consent grants</td></tr><tr><td><strong>Cloud Identity Attacks</strong></td><td>OAuth abuse, consent phishing, MFA fatigue, device code phishing</td></tr></tbody></table>

***

## Detection Sources & Data Mapping

### Log Sources Matrix

<table><thead><tr><th width="181">Platform</th><th>Log Table</th><th>Key Events</th></tr></thead><tbody><tr><td>On-Prem AD</td><td><code>SecurityEvent</code></td><td>4624/4625, 4768/4769, 4672, 4720-4738</td></tr><tr><td>Entra ID</td><td><code>SigninLogs</code>, <code>AADNonInteractiveUserSignInLogs</code></td><td>Sign-ins, MFA, CA policies, risk events</td></tr><tr><td>Entra ID</td><td><code>AuditLogs</code></td><td>User/group changes, app registrations, PIM</td></tr><tr><td>Defender for Identity</td><td><code>IdentityDirectoryEvents</code>, <code>IdentityLogonEvents</code></td><td>LDAP queries, Kerberos activity, recon</td></tr><tr><td>Defender XDR</td><td><code>AlertEvidence</code>, <code>IdentityInfo</code></td><td>Correlated alerts, entity context</td></tr><tr><td>Cloud Apps</td><td><code>CloudAppEvents</code></td><td>SaaS activity, OAuth grants, file access</td></tr><tr><td>Prisma Access</td><td><code>PaloAltoPrismaAccess</code></td><td>VPN connections, GlobalProtect, ZTNA</td></tr></tbody></table>

### Critical Windows Event IDs

<table><thead><tr><th width="110">Event ID</th><th width="272">Description</th><th>Investigation Relevance</th></tr></thead><tbody><tr><td><strong>4624</strong></td><td>Successful logon</td><td>Baseline normal access, identify anomalies</td></tr><tr><td><strong>4625</strong></td><td>Failed logon</td><td>Brute force, password spray detection</td></tr><tr><td><strong>4648</strong></td><td>Explicit credential logon</td><td>RunAs usage, lateral movement</td></tr><tr><td><strong>4672</strong></td><td>Special privileges assigned</td><td>Privileged access tracking</td></tr><tr><td><strong>4768</strong></td><td>Kerberos TGT requested</td><td>AS-REP roasting, initial auth</td></tr><tr><td><strong>4769</strong></td><td>Kerberos service ticket</td><td>Kerberoasting, service access</td></tr><tr><td><strong>4776</strong></td><td>NTLM authentication</td><td>Pass-the-Hash, legacy auth</td></tr><tr><td><strong>4720</strong></td><td>User account created</td><td>Persistence, rogue accounts</td></tr><tr><td><strong>4732</strong></td><td>Member added to group</td><td>Privilege escalation</td></tr><tr><td><strong>4662</strong></td><td>Directory object accessed</td><td>DCSync detection</td></tr></tbody></table>

***

## Investigation Workflows

### Compromised Account Investigation

**Objective:** Determine scope of compromise, identify threat actor activity, and contain the account.

#### Step 1: Initial Triage

1. Document the alert source, timestamp, and affected account(s)
2. Check Defender XDR for correlated incidents and alerts
3. Verify account type: standard user, service account, admin, or privileged
4. Assess business criticality and data access level

#### Step 2: Sign-In Analysis

1. Query Entra ID SigninLogs for last 30 days of activity
2. Identify anomalous locations, devices, or IP addresses
3. Check for impossible travel scenarios
4. Review MFA challenge results and authentication methods
5. Examine Conditional Access policy evaluations

#### Step 3: Activity Timeline

1. Build timeline from first suspicious activity
2. Query AuditLogs for configuration changes
3. Check CloudAppEvents for M365 and SaaS activity
4. Review EmailEvents for mailbox rules and forwarding
5. Examine OfficeActivity for file access and sharing

#### Step 4: Lateral Movement Check

1. Query IdentityLogonEvents for on-prem authentication
2. Check DeviceLogonEvents for endpoint access
3. Review SecurityEvent for network logons (Type 3, 10)
4. Identify accessed systems and potential pivot points

#### Step 5: Containment Actions

1. Revoke all refresh tokens via Entra ID
2. Disable account if active threat confirmed
3. Reset password and require MFA re-registration
4. Review and revoke OAuth app consents
5. Remove any suspicious mailbox rules

***

### Credential Attack Investigation

**Objective:** Identify credential-based attacks including password spray, brute force, and credential stuffing.

#### Detection Indicators

* High volume of failed authentications from single/multiple IPs
* Multiple accounts targeted with same password
* Authentication attempts during unusual hours
* Legacy protocol usage (POP3, IMAP, SMTP AUTH)
* TOR exit node or VPN/proxy IP addresses

#### Investigation Steps

1. Aggregate failed sign-ins by IP, user, and error code
2. Calculate authentication failure rates and patterns
3. Correlate with successful authentications post-failure
4. Check IP reputation via threat intelligence
5. Identify affected accounts requiring password reset
6. Review Conditional Access to block attack vectors

***

### Kerberos Attack Investigation

**Objective:** Detect and investigate Kerberoasting, AS-REP Roasting, Pass-the-Ticket, and Golden/Silver Ticket attacks.

#### Kerberoasting Indicators

* Event 4769 with RC4 encryption (0x17) for service tickets
* High volume of service ticket requests from single user
* Requests for SPNs associated with service accounts
* MDI alerts for Kerberos encryption downgrade

#### Golden/Silver Ticket Indicators

* TGT with abnormally long lifetime
* Missing or inconsistent PAC data
* TGT used without corresponding AS-REQ
* Service ticket without prior TGT request

***

## KQL Query Cheat Sheet

### Entra ID Sign-In Analysis

#### User Sign-In Summary (Last 7 Days)

```kusto
let targetUser = "user@domain.com";
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ targetUser
| summarize 
    TotalSignIns = count(),
    SuccessCount = countif(ResultType == 0),
    FailureCount = countif(ResultType != 0),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location),
    UniqueApps = dcount(AppDisplayName)
    by UserPrincipalName
| extend SuccessRate = round(100.0 * SuccessCount / TotalSignIns, 2)
```

#### Failed Sign-Ins with Error Details

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize 
    FailCount = count(),
    Accounts = make_set(UserPrincipalName, 100)
    by ResultType, ResultDescription, IPAddress
| where FailCount > 10
| sort by FailCount desc
```

#### Impossible Travel Detection

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, Location, IPAddress
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevLocation = prev(Location), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser and Location != PrevLocation
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes < 60
```
{% endcode %}

***

### Password Spray Detection

#### Password Spray Pattern Detection

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50126", "50053", "50055")
| summarize 
    AttemptCount = count(),
    DistinctAccounts = dcount(UserPrincipalName),
    Accounts = make_set(UserPrincipalName, 100)
    by IPAddress, bin(TimeGenerated, 10m)
| where DistinctAccounts > 10 and AttemptCount > 20
| sort by AttemptCount desc
```

#### Successful Auth After Spray

```kusto
let SprayIPs = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailCount = count() by IPAddress
| where FailCount > 50
| project IPAddress;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| where IPAddress in (SprayIPs)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location
```

***

### Defender for Identity Queries

#### Kerberoasting Detection

```kusto
IdentityQueryEvents
| where Timestamp > ago(24h)
| where ActionType == "SAMR query"
    or QueryType == "ServicePrincipalName"
| summarize 
    QueryCount = count(),
    TargetAccounts = make_set(TargetAccountDisplayName, 50)
    by AccountDisplayName, DeviceName
| where QueryCount > 20
```

#### DCSync Detection

```kusto
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Services replication"
| where DestinationDeviceName !contains "DC"
| project Timestamp, AccountDisplayName, DestinationDeviceName, TargetDeviceName
```

***

### On-Premises AD Queries

#### NTLM Authentication Analysis

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4776
| extend Status = case(
    Status == "0x0", "Success",
    Status == "0xC000006A", "Bad Password",
    Status == "0xC0000064", "User Not Found",
    "Other")
| summarize Count = count() by TargetAccount, Workstation, Status
| where Count > 50
```

#### Suspicious Service Ticket Requests (Kerberoasting)

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| where ServiceName !endswith "$"
| where TicketEncryptionType == "0x17"
| summarize 
    RequestCount = count(),
    UniqueServices = dcount(ServiceName)
    by AccountName, IpAddress
| where RequestCount > 10 or UniqueServices > 5
```

#### Privileged Group Membership Changes

```kusto
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)
| where TargetUserName in~ (
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators")
| project TimeGenerated, EventID, SubjectAccount, MemberName, TargetUserName
```

***

### Prisma Access Queries

#### VPN Authentication Anomalies

```kusto
PaloAltoPrismaAccess
| where TimeGenerated > ago(24h)
| where EventType == "GlobalProtect"
| where Action in ("login-success", "login-fail")
| summarize 
    SuccessCount = countif(Action == "login-success"),
    FailCount = countif(Action == "login-fail")
    by User, SourceIP, Location
| where FailCount > 5
```

#### Concurrent Session Detection

```kusto
PaloAltoPrismaAccess
| where TimeGenerated > ago(1h)
| where EventType == "GlobalProtect" and Action == "login-success"
| summarize 
    SessionCount = count(),
    UniqueIPs = dcount(SourceIP),
    Locations = make_set(Location)
    by User, bin(TimeGenerated, 5m)
| where UniqueIPs > 1
```

***

## Response Actions & Remediation

### Immediate Containment Actions

| Scenario                      | Action                | Command/Location                         |
| ----------------------------- | --------------------- | ---------------------------------------- |
| **Compromised Cloud Account** | Revoke sessions       | Entra ID → Users → Revoke Sessions       |
| **Active Attack**             | Disable account       | `Set-AzureADUser -AccountEnabled $false` |
| **Token Theft**               | Revoke refresh tokens | `Revoke-AzureADUserAllRefreshToken`      |
| **On-Prem Account**           | Disable AD account    | `Disable-ADAccount -Identity <user>`     |
| **Malicious OAuth App**       | Remove app consent    | `Remove-AzureADOAuth2PermissionGrant`    |
| **Golden Ticket**             | Reset KRBTGT (2x)     | `Reset-KrbtgtKeyInteractive.ps1`         |

### Post-Incident Hardening

| Action                 | Details                                                           |
| ---------------------- | ----------------------------------------------------------------- |
| **Enable MFA**         | Enforce phishing-resistant MFA (FIDO2, Windows Hello)             |
| **Conditional Access** | Block legacy authentication, require compliant devices            |
| **Password Policy**    | Implement Azure AD Password Protection, banned password list      |
| **Privileged Access**  | Implement PIM for just-in-time admin access                       |
| **Service Accounts**   | Migrate to gMSA, implement credential rotation                    |
| **Monitoring**         | Enable Sign-in Risk and User Risk policies in Identity Protection |

***

## Quick Reference Cards

### Attack Type Quick Identification

| Attack Type          | Key Indicators                                      | Primary Data Source            |
| -------------------- | --------------------------------------------------- | ------------------------------ |
| **Password Spray**   | Many accounts, few attempts each, same time window  | SigninLogs (50126)             |
| **Brute Force**      | Single account, many attempts, sequential           | SigninLogs, SecurityEvent 4625 |
| **MFA Fatigue**      | Multiple MFA prompts, user finally approves         | SigninLogs (MFA required)      |
| **Kerberoasting**    | Bulk TGS requests, RC4 encryption, service SPNs     | SecurityEvent 4769, MDI        |
| **Pass-the-Hash**    | NTLM auth from unusual source, no interactive logon | SecurityEvent 4776, MDI        |
| **DCSync**           | DS replication from non-DC, GetNCChanges            | SecurityEvent 4662, MDI        |
| **Consent Phishing** | OAuth grant to unknown app, excessive permissions   | AuditLogs, CloudAppEvents      |

### Entra ID Error Code Reference

| Error Code | Description                    | Investigation Notes                    |
| ---------- | ------------------------------ | -------------------------------------- |
| **50126**  | Invalid username or password   | Common in spray attacks                |
| **50053**  | Account locked                 | Result of brute force                  |
| **50074**  | MFA required                   | Check if followed by success           |
| **50076**  | MFA denied                     | User rejected - may indicate awareness |
| **53003**  | Blocked by CA policy           | CA working correctly                   |
| **50158**  | External security challenge    | Third-party MFA in use                 |
| **50140**  | Keep me signed in interrupt    | Normal behavior                        |
| **50097**  | Device authentication required | Device compliance check                |

***

## Escalation Matrix

### Severity Classification

| Severity        | Criteria                                                         | Response Time               |
| --------------- | ---------------------------------------------------------------- | --------------------------- |
| 🔴 **Critical** | Domain Admin compromise, Golden Ticket, active data exfiltration | Immediate - 15 min response |
| 🟠 **High**     | Privileged account compromise, lateral movement detected         | 30 min - 1 hour response    |
| 🟡 **Medium**   | Standard user compromise, ongoing password spray                 | 4 hour response             |
| 🟢 **Low**      | Failed attack attempts, reconnaissance activity                  | Next business day           |

### Escalation Path

| Tier                         | Responsibility                                              |
| ---------------------------- | ----------------------------------------------------------- |
| **Tier 1 SOC**               | Initial triage, alert validation, basic containment         |
| **Tier 2 SOC**               | Deep investigation, advanced hunting, incident coordination |
| **DFIR Team**                | Forensic analysis, malware analysis, evidence preservation  |
| **Identity Team**            | AD/Entra configuration changes, KRBTGT reset                |
| **CISO/Security Leadership** | Critical severity incidents, breach notification decisions  |

### Documentation Requirements

All identity incidents must include:

1. Initial detection timestamp and alert source
2. Affected account(s) and account type(s)
3. Attack vector and techniques (MITRE ATT\&CK mapping)
4. Timeline of attacker activity
5. Systems accessed and potential data exposure
6. Containment actions taken with timestamps
7. Evidence preserved (logs, screenshots, exports)
8. Remediation actions and hardening recommendations

***

## MITRE ATT\&CK Mapping

| Tactic                | Technique                     | ID        | Detection        |
| --------------------- | ----------------------------- | --------- | ---------------- |
| **Initial Access**    | Valid Accounts                | T1078     | SigninLogs       |
| **Credential Access** | Brute Force                   | T1110     | 4625, SigninLogs |
| **Credential Access** | Kerberoasting                 | T1558.003 | 4769, MDI        |
| **Credential Access** | DCSync                        | T1003.006 | 4662, MDI        |
| **Lateral Movement**  | Pass the Hash                 | T1550.002 | 4776, MDI        |
| **Lateral Movement**  | Pass the Ticket               | T1550.003 | 4768/4769, MDI   |
| **Persistence**       | Golden Ticket                 | T1558.001 | 4768, MDI        |
| **Persistence**       | Application Access Token      | T1550.001 | AuditLogs        |
| **Defense Evasion**   | Modify Authentication Process | T1556     | AuditLogs, 4657  |

***

## Appendix: PowerShell Commands

### Entra ID / Azure AD (Microsoft Graph)

{% code overflow="wrap" %}
```powershell
# Get user sign-in activity
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'user@domain.com'" -Top 100

# Revoke all sessions
Revoke-MgUserSignInSession -UserId "user@domain.com"

# Get user's OAuth consent grants
Get-MgUserOauth2PermissionGrant -UserId "user@domain.com"

# Remove OAuth grant
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<grant-id>"

# Check user risk state
Get-MgRiskyUser -Filter "userPrincipalName eq 'user@domain.com'"

# Get user's authentication methods
Get-MgUserAuthenticationMethod -UserId "user@domain.com"

# Force password change on next login
Update-MgUser -UserId "user@domain.com" -PasswordProfile @{ForceChangePasswordNextSignIn = $true}
```
{% endcode %}

### On-Premises Active Directory

{% code overflow="wrap" %}
```powershell
# Get account lockout status
Get-ADUser -Identity username -Properties LockedOut, LastBadPasswordAttempt, BadPwdCount

# Unlock account
Unlock-ADAccount -Identity username

# Check group membership
Get-ADPrincipalGroupMembership -Identity username | Select Name

# Get recent logon events
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 100

# Find service accounts with SPNs (Kerberoasting targets)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Get users with Kerberos pre-auth disabled (AS-REP Roasting targets)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Find recently created accounts
Get-ADUser -Filter {Created -gt $((Get-Date).AddDays(-7))} -Properties Created | Select Name, Created

# Check AdminSDHolder protected accounts
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf
```
{% endcode %}

### Microsoft Graph API (REST)

{% code overflow="wrap" %}
```http
# Get sign-ins for a user
GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userPrincipalName eq 'user@domain.com'

# Get risky sign-ins
GET https://graph.microsoft.com/v1.0/identityProtection/riskyUsers

# Revoke sign-in sessions
POST https://graph.microsoft.com/v1.0/users/{id}/revokeSignInSessions

# Get audit logs
GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=initiatedBy/user/userPrincipalName eq 'user@domain.com'

# Get OAuth2 permission grants
GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=principalId eq '{user-id}'
```
{% endcode %}

***

> **Note:** This runbook should be reviewed and updated regularly or after significant incidents to incorporate lessons learned and emerging attack techniques.
