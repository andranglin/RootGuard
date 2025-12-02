# Ransomware Investigation & Response Runbook

## SOC & DFIR Operations Guide

**Environment:** Windows AD | Microsoft 365 | Defender XDR | Sentinel | Entra ID | Palo Alto Prisma Access

***

## Overview & Scope

This runbook provides standardised procedures for investigating and responding to ransomware attacks across the hybrid enterprise environment. Ransomware incidents require rapid, coordinated response to minimise damage, preserve evidence, and enable recovery. Time is critical—every minute of delay can result in additional encrypted systems and data loss.

### What is Ransomware?

Ransomware is malicious software that encrypts files and systems, rendering them inaccessible until a ransom is paid. Modern ransomware operations (often called "Big Game Hunting") typically involve:

* **Data exfiltration before encryption** (double extortion)
* **Threat to publish stolen data** if ransom not paid
* **Targeting of backups** to prevent recovery
* **Domain-wide encryption** via compromised credentials
* **Ransomware-as-a-Service (RaaS)** affiliate models

**Key Statistics:**

* Average downtime: 21+ days
* Average ransom demand: $200,000 - $5,000,000+
* Recovery costs often exceed ransom amount
* 80% of victims who pay are attacked again
* Data exfiltration occurs in 70%+ of cases

### Environment Architecture

<table><thead><tr><th width="326">Component</th><th>Role in Ransomware Response</th></tr></thead><tbody><tr><td><strong>Microsoft Defender for Endpoint (MDE)</strong></td><td>Ransomware detection, device isolation, live response</td></tr><tr><td><strong>Microsoft Defender for Identity (MDI)</strong></td><td>Lateral movement detection, credential compromise</td></tr><tr><td><strong>Microsoft Sentinel</strong></td><td>Correlation, automated response, hunting</td></tr><tr><td><strong>Active Directory</strong></td><td>Credential reset, KRBTGT rotation, GPO recovery</td></tr><tr><td><strong>Microsoft Entra ID</strong></td><td>Cloud identity protection, session revocation</td></tr><tr><td><strong>Backup Systems</strong></td><td>Recovery source validation, integrity verification</td></tr><tr><td><strong>Palo Alto Prisma Access</strong></td><td>Network isolation, C2 blocking</td></tr></tbody></table>

### Ransomware Attack Lifecycle

```bash
1. Initial Access (Days to Weeks Before)
   ├── Phishing email with malicious attachment/link
   ├── Exploitation of public-facing application
   ├── Compromised credentials (RDP, VPN)
   └── Supply chain compromise

2. Execution & Persistence
   ├── Malware deployment
   ├── Backdoor installation
   └── Scheduled tasks/services created

3. Credential Access
   ├── Mimikatz/credential dumping
   ├── Kerberoasting
   └── DCSync attack

4. Discovery & Lateral Movement
   ├── Network enumeration
   ├── Active Directory reconnaissance
   ├── Move to high-value targets
   └── Compromise Domain Controllers

5. Collection & Exfiltration (Double Extortion)
   ├── Identify sensitive data
   ├── Stage for exfiltration
   └── Exfiltrate to attacker infrastructure

6. Impact - Ransomware Deployment
   ├── Disable security tools
   ├── Delete shadow copies/backups
   ├── Deploy ransomware domain-wide
   └── Encrypt files and systems
```

### Ransomware Families Reference

#### Prevalent Ransomware Groups (2024-2025)

<table><thead><tr><th width="185">Group/Ransomware</th><th>Characteristics</th><th>TTPs</th></tr></thead><tbody><tr><td><strong>LockBit 3.0</strong></td><td>RaaS, fast encryption, data leak site</td><td>GPO deployment, PsExec</td></tr><tr><td><strong>BlackCat/ALPHV</strong></td><td>Rust-based, cross-platform, triple extortion</td><td>Cobalt Strike, ExMatter</td></tr><tr><td><strong>Cl0p</strong></td><td>Targets file transfer appliances (MOVEit, GoAnywhere)</td><td>Zero-day exploitation</td></tr><tr><td><strong>Royal/BlackSuit</strong></td><td>Rebranded Conti members, partial encryption</td><td>Callback phishing, BatLoader</td></tr><tr><td><strong>Play</strong></td><td>Intermittent encryption, no RaaS</td><td>AdFind, SystemBC</td></tr><tr><td><strong>Akira</strong></td><td>Targets VPNs, Linux/VMware variants</td><td>Cisco VPN exploitation</td></tr><tr><td><strong>Black Basta</strong></td><td>Conti successor, QakBot delivery</td><td>QakBot, Cobalt Strike</td></tr><tr><td><strong>Rhysida</strong></td><td>Healthcare/education targeting</td><td>Phishing, Cobalt Strike</td></tr><tr><td><strong>Medusa</strong></td><td>Data leak blog, negotiation portal</td><td>RDP brute force</td></tr><tr><td><strong>8Base</strong></td><td>SMB targeting, Phobos variant</td><td>Phishing, SmokeLoader</td></tr></tbody></table>

#### Ransomware File Extensions

<table><thead><tr><th width="267">Extension</th><th>Ransomware Family</th></tr></thead><tbody><tr><td><code>.lockbit</code>, <code>.lockbit3</code></td><td>LockBit</td></tr><tr><td><code>.alphv</code>, <code>.ALPHV</code></td><td>BlackCat</td></tr><tr><td><code>.clop</code>, <code>.Cl0p</code></td><td>Cl0p</td></tr><tr><td><code>.royal</code></td><td>Royal</td></tr><tr><td><code>.play</code></td><td>Play</td></tr><tr><td><code>.akira</code></td><td>Akira</td></tr><tr><td><code>.basta</code></td><td>Black Basta</td></tr><tr><td><code>.rhysida</code></td><td>Rhysida</td></tr><tr><td><code>.medusa</code></td><td>Medusa</td></tr><tr><td><code>.8base</code></td><td>8Base</td></tr></tbody></table>

***

## Detection Sources & Indicators

### Log Sources Matrix

<table><thead><tr><th width="194">Platform</th><th width="226">Log Table</th><th>Ransomware Detection Data</th></tr></thead><tbody><tr><td>Defender for Endpoint</td><td><code>DeviceAlertEvents</code></td><td>Ransomware behavior alerts</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceFileEvents</code></td><td>Mass file modifications</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceProcessEvents</code></td><td>Encryption processes, deletion tools</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceEvents</code></td><td>Shadow copy deletion, service tampering</td></tr><tr><td>Defender for Identity</td><td><code>IdentityLogonEvents</code></td><td>Mass lateral movement</td></tr><tr><td>Defender for Identity</td><td><code>IdentityDirectoryEvents</code></td><td>DCSync, credential access</td></tr><tr><td>Sentinel</td><td><code>SecurityAlert</code></td><td>Correlated ransomware alerts</td></tr><tr><td>Windows Events</td><td><code>SecurityEvent</code></td><td>Logon events, service installation</td></tr><tr><td>Windows Events</td><td><code>Event</code> (System)</td><td>Service creation, VSS events</td></tr><tr><td>Prisma Access</td><td><code>PaloAltoPrismaAccess</code></td><td>C2 communication, exfiltration</td></tr></tbody></table>

### Pre-Encryption Indicators (Warning Signs)

#### Days/Weeks Before Encryption

<table><thead><tr><th width="218">Indicator</th><th width="296">Description</th><th>Detection Source</th></tr></thead><tbody><tr><td><strong>Cobalt Strike beacons</strong></td><td>C2 framework activity</td><td>MDE alerts, network</td></tr><tr><td><strong>Mimikatz execution</strong></td><td>Credential dumping</td><td>MDE process events</td></tr><tr><td><strong>DCSync attacks</strong></td><td>Domain replication from non-DC</td><td>MDI alerts, Event 4662</td></tr><tr><td><strong>Mass reconnaissance</strong></td><td>AdFind, BloodHound, network scans</td><td>MDE process events</td></tr><tr><td><strong>Lateral movement spikes</strong></td><td>RDP, SMB, WinRM to many systems</td><td>MDI, MDE logon events</td></tr><tr><td><strong>New admin accounts</strong></td><td>Unauthorized privileged accounts</td><td>AD audit logs</td></tr><tr><td><strong>Disabled security tools</strong></td><td>AV/EDR tampering</td><td>MDE health alerts</td></tr><tr><td><strong>Backup access/deletion</strong></td><td>Targeting backup systems</td><td>Backup system logs</td></tr></tbody></table>

#### Hours Before Encryption

<table><thead><tr><th>Indicator</th><th width="261">Description</th><th>Detection Source</th></tr></thead><tbody><tr><td><strong>Shadow copy deletion</strong></td><td>vssadmin, wmic commands</td><td>MDE process events</td></tr><tr><td><strong>GPO creation/modification</strong></td><td>Ransomware deployment prep</td><td>AD audit logs</td></tr><tr><td><strong>PsExec deployment</strong></td><td>Mass tool deployment</td><td>MDE, Event 7045</td></tr><tr><td><strong>Security tool uninstall</strong></td><td>Removing defenses</td><td>MDE events</td></tr><tr><td><strong>bcdedit modifications</strong></td><td>Disabling recovery options</td><td>MDE process events</td></tr><tr><td><strong>Service account usage spike</strong></td><td>Automation of deployment</td><td>Logon events</td></tr><tr><td><strong>Scheduled tasks creation</strong></td><td>Timed ransomware execution</td><td>Event 4698</td></tr></tbody></table>

### Active Encryption Indicators

<table><thead><tr><th width="222">Indicator</th><th width="299">Description</th><th>Detection Source</th></tr></thead><tbody><tr><td><strong>Mass file modifications</strong></td><td>Thousands of files changed/renamed</td><td>MDE DeviceFileEvents</td></tr><tr><td><strong>Ransom note creation</strong></td><td>README, DECRYPT, RECOVER files</td><td>MDE DeviceFileEvents</td></tr><tr><td><strong>Known ransomware processes</strong></td><td>Identified encryption binaries</td><td>MDE alerts</td></tr><tr><td><strong>High CPU/disk usage</strong></td><td>Encryption activity</td><td>Performance monitoring</td></tr><tr><td><strong>File extension changes</strong></td><td>Mass extension modifications</td><td>MDE DeviceFileEvents</td></tr><tr><td><strong>User complaints</strong></td><td>Unable to access files</td><td>Service desk</td></tr><tr><td><strong>Application failures</strong></td><td>Systems becoming unavailable</td><td>Monitoring systems</td></tr></tbody></table>

### Critical Detection Rules

#### MDE Alert Categories for Ransomware

<table><thead><tr><th width="289">Alert Category</th><th width="189">Severity</th><th>Action</th></tr></thead><tbody><tr><td><code>Ransomware</code></td><td>High/Critical</td><td>Immediate response</td></tr><tr><td><code>Suspicious credential access</code></td><td>High</td><td>Investigate immediately</td></tr><tr><td><code>Tampering with security</code></td><td>High</td><td>Investigate immediately</td></tr><tr><td><code>Suspicious process activity</code></td><td>Medium-High</td><td>Investigate within 1 hour</td></tr><tr><td><code>Lateral movement</code></td><td>Medium-High</td><td>Investigate within 1 hour</td></tr><tr><td><code>Data exfiltration</code></td><td>High</td><td>Investigate immediately</td></tr></tbody></table>

***

## Investigation Workflows

### Ransomware Incident Response Phases

```bash
┌─────────────────────────────────────────────────────────────────────┐
│                    RANSOMWARE RESPONSE PHASES                       │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 1: DETECTION & INITIAL RESPONSE (0-15 minutes)               │
│  → Validate alert, assess scope, activate IR team                   │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 2: CONTAINMENT (15-60 minutes)                               │
│  → Isolate systems, block C2, preserve evidence                     │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 3: INVESTIGATION (Ongoing)                                   │
│  → Determine scope, identify patient zero, map impact               │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 4: ERADICATION (After containment)                           │
│  → Remove malware, reset credentials, validate clean                │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 5: RECOVERY (After eradication)                              │
│  → Restore from backup, rebuild systems, validate integrity         │
├─────────────────────────────────────────────────────────────────────┤
│  Phase 6: POST-INCIDENT (After recovery)                            │
│  → Lessons learned, hardening, documentation                        │
└─────────────────────────────────────────────────────────────────────┘
```

***

### Phase 1: Detection & Initial Response

**Timeline:** 0-15 minutes **Objective:** Validate the ransomware incident and mobilise response.

#### Step 1.1: Alert Validation

1. Confirm alert is ransomware (not false positive)
2. Identify alerting source and detection logic
3. Determine affected system(s) from initial alert
4. Check for ransomware indicators:
   * Known ransomware file extensions
   * Ransom notes present
   * Mass file modification alerts
   * Shadow copy deletion

#### Step 1.2: Initial Scope Assessment

1. Query for related alerts in last 24-72 hours
2. Identify potentially related systems
3. Check for Domain Controller involvement
4. Assess criticality of affected systems
5. Determine if encryption is active or complete

#### Step 1.3: Incident Declaration

<table><thead><tr><th width="337">Condition</th><th>Declaration</th></tr></thead><tbody><tr><td>Single workstation, contained</td><td>Security Incident - Medium</td></tr><tr><td>Multiple workstations affected</td><td>Security Incident - High</td></tr><tr><td>Server infrastructure affected</td><td>Major Incident</td></tr><tr><td>Domain Controllers affected</td><td>Critical Incident / Disaster</td></tr><tr><td>Active encryption spreading</td><td>Critical Incident / Disaster</td></tr></tbody></table>

#### Step 1.4: Activate Incident Response

1. **Notify IR Team Lead** immediately
2. **Establish communication channel** (out-of-band if needed)
3. **Begin incident documentation**
4. **Alert leadership** per escalation matrix
5. **Engage external IR support** if needed (Critical/Major)

#### Initial Response Checklist

```bash
□ Alert validated as ransomware incident
□ Initial affected systems identified
□ Incident severity declared
□ IR team activated
□ Communication channel established
□ Initial timeline documented
□ Evidence preservation initiated
□ External IR on standby (if needed)
```

***

### Phase 2: Containment

**Timeline:** 15-60 minutes&#x20;

**copies/backupsObjective:** Stop the spread of ransomware and preserve evidence.

> ⚠️ **Critical Decision:** Containment must be fast but measured. Premature actions may tip off attackers or destroy evidence. However, delay costs encrypted systems.

#### Step 2.1: Network Containment

**Immediate Network Actions**

<table><thead><tr><th width="101">Priority</th><th>Action</th><th>Method</th><th>Risk</th></tr></thead><tbody><tr><td><strong>1</strong></td><td>Isolate confirmed infected systems</td><td>MDE Device Isolation</td><td>Low</td></tr><tr><td><strong>2</strong></td><td>Block known C2 infrastructure</td><td>Prisma Access / Firewall</td><td>Low</td></tr><tr><td><strong>3</strong></td><td>Isolate suspected systems</td><td>MDE Device Isolation</td><td>Medium</td></tr><tr><td><strong>4</strong></td><td>Segment affected network zones</td><td>Firewall rules</td><td>Medium</td></tr><tr><td><strong>5</strong></td><td>Block lateral movement ports</td><td>Emergency firewall rules</td><td>High (business impact)</td></tr><tr><td><strong>6</strong></td><td>Disable external access</td><td>VPN/RDP shutdown</td><td>High (business impact)</td></tr></tbody></table>

**Network Isolation Decision Tree**

```bash
Is encryption actively spreading?
├── YES → Aggressive network isolation immediately
│         Consider domain-wide segmentation
│         Accept business disruption
│
└── NO (encryption stopped/contained)
    ├── How many systems affected?
    │   ├── <10 → Isolate individual systems
    │   ├── 10-50 → Isolate network segment
    │   └── >50 → Consider broader isolation
    │
    └── Are Domain Controllers compromised?
        ├── YES → Isolate DC network
        │         Prepare for KRBTGT reset
        └── NO → Continue targeted isolation
```

#### Step 2.2: Endpoint Containment

{% code overflow="wrap" %}
```powershell
# MDE Device Isolation via Security Center or API
# Isolates device from network but maintains MDE connectivity

# Via Microsoft Graph Security API
$deviceId = "device-id-here"
$body = @{
    Comment = "Ransomware containment - IR-2024-XXX"
    IsolationType = "Full"
} | ConvertTo-Json

Invoke-MgGraphRequest -Method POST `
    -Uri "https://api.securitycenter.microsoft.com/api/machines/$deviceId/isolate" `
    -Body $body
```
{% endcode %}

#### Step 2.3: Identity Containment

**Immediate Identity Actions**

<table><thead><tr><th width="261">Action</th><th>When</th><th>Method</th></tr></thead><tbody><tr><td>Disable compromised accounts</td><td>Confirmed compromise</td><td>AD + Entra ID</td></tr><tr><td>Reset compromised passwords</td><td>Confirmed compromise</td><td>AD + Entra ID</td></tr><tr><td>Revoke active sessions</td><td>All suspicious accounts</td><td>Entra ID</td></tr><tr><td>Disable service accounts</td><td>If used in attack</td><td>AD (with caution)</td></tr><tr><td>Block suspicious IPs</td><td>Attacker infrastructure</td><td>Conditional Access</td></tr></tbody></table>

**Account Containment Commands**

{% code overflow="wrap" %}
```powershell
# Disable potentially compromised accounts
$compromisedUsers = @("user1", "user2", "admin1")

foreach ($user in $compromisedUsers) {
    # Disable AD account
    Disable-ADAccount -Identity $user
    
    # Disable Entra ID account
    Update-MgUser -UserId "$user@domain.com" -AccountEnabled:$false
    
    # Revoke sessions
    Revoke-MgUserSignInSession -UserId "$user@domain.com"
    
    Write-Host "Contained account: $user"
}
```
{% endcode %}

#### Step 2.4: Preserve Evidence

> ⚠️ **Critical:** Do not wipe or reimage systems until evidence is preserved!

<table><thead><tr><th>Evidence Type</th><th width="301">Collection Method</th><th>Priority</th></tr></thead><tbody><tr><td>Memory dumps</td><td>MDE Live Response, WinPmem</td><td>High</td></tr><tr><td>Ransomware samples</td><td>MDE quarantine, manual collection</td><td>High</td></tr><tr><td>Ransom notes</td><td>Copy to evidence storage</td><td>High</td></tr><tr><td>Event logs</td><td>Export before rotation</td><td>High</td></tr><tr><td>MFT/filesystem metadata</td><td>Forensic tools</td><td>Medium</td></tr><tr><td>Network captures</td><td>PCAP from network devices</td><td>Medium</td></tr></tbody></table>

#### Step 2.5: Protect Backups

<table><thead><tr><th width="321">Action</th><th>Purpose</th></tr></thead><tbody><tr><td>Verify backup isolation</td><td>Ensure backups not accessible to attackers</td></tr><tr><td>Disable backup network access</td><td>Prevent backup encryption/deletion</td></tr><tr><td>Validate backup integrity</td><td>Confirm backups are usable</td></tr><tr><td>Create backup of backups</td><td>Protect recovery capability</td></tr><tr><td>Document backup status</td><td>Record what's available for recovery</td></tr></tbody></table>

#### Containment Checklist

```bash
□ Infected systems isolated (network)
□ C2 infrastructure blocked
□ Affected network segments isolated
□ Compromised accounts disabled
□ Sessions revoked for affected users
□ Evidence collection initiated
□ Backups verified and protected
□ Encryption spread stopped
□ Containment documented with timestamps
```

***

### Phase 3: Investigation

**Timeline:** Ongoing (parallel to containment/eradication) **Objective:** Determine full scope, identify root cause, and map impact.

#### Step 3.1: Identify Patient Zero

1. Query for earliest ransomware indicators
2. Trace back from encrypted systems
3. Identify initial access vector
4. Document initial compromise timeline
5. Determine attacker dwell time

#### Step 3.2: Map Lateral Movement

1. Query all lateral movement for compromised accounts
2. Identify all systems accessed
3. Map credential usage patterns
4. Document administrative access points
5. Identify Domain Controller access

#### Step 3.3: Determine Full Scope

| Question                     | Investigation Method         |
| ---------------------------- | ---------------------------- |
| How many systems encrypted?  | MDE query, file share scan   |
| Which systems were accessed? | Logon event analysis         |
| What accounts compromised?   | Authentication analysis      |
| Was data exfiltrated?        | Network analysis, cloud logs |
| Are backups affected?        | Backup system verification   |
| Are DCs compromised?         | DC forensic analysis         |

#### Step 3.4: Assess Data Exfiltration

1. Review network traffic for large outbound transfers
2. Check cloud storage activity
3. Review known exfiltration tools
4. Analyse pre-encryption timeline
5. Document potential data exposure

#### Step 3.5: Identify Ransomware Variant

1. Collect ransom notes
2. Analyse encrypted file extensions
3. Check ransomware identification services
4. Research variant-specific TTPs
5. Check for available decryptors

#### Investigation Documentation Template

```bash
RANSOMWARE INVESTIGATION SUMMARY
================================
Incident ID: IR-2024-XXX
Date Detected: YYYY-MM-DD HH:MM
Ransomware Variant: [Name/Family]
Ransom Amount: $XXX,XXX

TIMELINE:
---------
Initial Access: YYYY-MM-DD (estimated)
First Lateral Movement: YYYY-MM-DD
Data Exfiltration: YYYY-MM-DD (if confirmed)
Encryption Started: YYYY-MM-DD HH:MM
Encryption Detected: YYYY-MM-DD HH:MM

SCOPE:
------
Total Systems Affected: XXX
Servers Encrypted: XXX
Workstations Encrypted: XXX
Domain Controllers: [Affected/Clean]
Backups Status: [Intact/Compromised/Unknown]

ACCOUNTS COMPROMISED:
--------------------
- [List accounts]

DATA EXFILTRATION:
-----------------
Status: [Confirmed/Suspected/No Evidence]
Data Types: [If known]
Volume: [If known]

ROOT CAUSE:
-----------
Initial Access Vector: [Phishing/RDP/VPN/Other]
Exploited Vulnerability: [If applicable]
```

***

### Phase 4: Eradication

**Timeline:** After containment confirmed&#x20;

**Objective:** Remove all attacker presence from the environment.

> ⚠️ **Warning:** Do not begin eradication until containment is complete. Partial eradication may alert attackers and trigger destructive actions.

#### Step 4.1: Credential Reset Strategy

**Tiered Credential Reset**

<table><thead><tr><th width="93">Tier</th><th>Accounts</th><th>When</th><th>Method</th></tr></thead><tbody><tr><td><strong>Tier 0</strong></td><td>KRBTGT, Domain Admin, Enterprise Admin</td><td>Immediately if DC compromised</td><td>Scripted reset</td></tr><tr><td><strong>Tier 1</strong></td><td>All privileged accounts</td><td>After Tier 0</td><td>Scripted reset</td></tr><tr><td><strong>Tier 2</strong></td><td>Service accounts</td><td>After Tier 1</td><td>Coordinated reset</td></tr><tr><td><strong>Tier 3</strong></td><td>All user accounts</td><td>After Tier 1-2</td><td>Forced reset at logon</td></tr></tbody></table>

**KRBTGT Reset Procedure**

> ⚠️ **Critical:** KRBTGT reset affects all Kerberos authentication. Plan carefully.

```bash
# KRBTGT Reset Procedure
# Must be done TWICE with appropriate interval

# Pre-requisites:
# - Verify all DCs are replicating
# - Plan for authentication disruption
# - Have rollback plan ready

# Download official Microsoft script
# https://github.com/microsoft/New-KrbtgtKeys.ps1

# Step 1: First Reset
.\New-KrbtgtKeys.ps1 -Mode 2  # Mode 2 = Reset

# Step 2: Wait for replication
# Minimum wait: Maximum TGT lifetime (default 10 hours)
# Recommended: 24 hours if possible

# Step 3: Monitor for issues
# - Authentication failures
# - Application issues
# - Service account problems

# Step 4: Second Reset (invalidates any attacker tickets)
.\New-KrbtgtKeys.ps1 -Mode 2

# Step 5: Monitor for 24-48 hours
```

**Domain Admin Reset**

{% code overflow="wrap" %}
```powershell
# Reset all Domain Admin passwords
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object {$_.objectClass -eq "user"}

foreach ($admin in $domainAdmins) {
    # Generate secure random password
    $newPassword = -join ((65..90) + (97..122) + (48..57) + (33..47) | 
        Get-Random -Count 20 | ForEach-Object {[char]$_})
    
    # Reset password
    Set-ADAccountPassword -Identity $admin.SamAccountName `
        -Reset -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force)
    
    # Log securely (store password securely for distribution)
    Write-Host "Reset password for: $($admin.SamAccountName)"
}

# Force password change at next logon for all users
Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true
```
{% endcode %}

#### Step 4.2: Malware Removal

**Per-System Eradication**

<table><thead><tr><th width="85">Step</th><th>Action</th><th>Verification</th></tr></thead><tbody><tr><td>1</td><td>Run full AV scan</td><td>MDE full scan</td></tr><tr><td>2</td><td>Remove persistence mechanisms</td><td>Registry, services, tasks</td></tr><tr><td>3</td><td>Remove malware files</td><td>All identified binaries</td></tr><tr><td>4</td><td>Remove attacker tools</td><td>Cobalt Strike, Mimikatz, etc.</td></tr><tr><td>5</td><td>Verify removal</td><td>Second scan, manual check</td></tr></tbody></table>

**Persistence Mechanism Removal**

```powershell
# Check and remove common persistence mechanisms

# Scheduled Tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -notmatch "Microsoft"} |
    Select-Object TaskName, TaskPath, State

# Services
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch "Windows|Microsoft|Program Files" -and
    $_.State -eq "Running"
} | Select-Object Name, PathName, StartMode

# Run Keys
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
        Select-Object PSPath, *
}

# WMI Subscriptions
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter
Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding
```

#### Step 4.3: GPO Cleanup

```powershell
# Check for suspicious GPOs
Get-GPO -All | Where-Object {
    $_.ModificationTime -gt (Get-Date).AddDays(-30)
} | Select-Object DisplayName, ModificationTime, GpoStatus

# Review GPO contents
Get-GPO -All | ForEach-Object {
    $report = Get-GPOReport -Guid $_.Id -ReportType XML
    # Analyse for suspicious settings
}

# Remove malicious GPOs
Remove-GPO -Name "Suspicious GPO Name" -Confirm
```

#### Step 4.4: Validate Eradication

| Validation Check        | Method                     | Pass Criteria        |
| ----------------------- | -------------------------- | -------------------- |
| Full endpoint scan      | MDE scan all systems       | No detections        |
| Persistence check       | Manual/script verification | No persistence found |
| Network monitoring      | 24-48 hour monitoring      | No C2 callbacks      |
| Credential verification | Test authentication        | Clean authentication |
| IOC search              | Hunt for known IOCs        | No matches           |

#### Eradication Checklist

```bash
□ KRBTGT reset completed (twice)
□ All Domain Admin passwords reset
□ All privileged account passwords reset
□ Service account passwords reset
□ Malware removed from all systems
□ Persistence mechanisms removed
□ Malicious GPOs removed
□ Attacker tools removed
□ Full scan completed on all systems
□ 24-48 hour monitoring shows no reinfection
□ Eradication validated and documented
```

***

### Phase 5: Recovery

**Timeline:** After eradication validated&#x20;

**Objective:** Restore systems and data from clean backups.

#### Step 5.1: Recovery Prioritisation

<table><thead><tr><th width="108">Priority</th><th>Systems</th><th width="236">Recovery Method</th><th>Timeline Target</th></tr></thead><tbody><tr><td><strong>P1</strong></td><td>Domain Controllers</td><td>Rebuild or verified backup</td><td>Immediate</td></tr><tr><td><strong>P2</strong></td><td>Authentication infrastructure</td><td>Rebuild or verified backup</td><td>Immediate</td></tr><tr><td><strong>P3</strong></td><td>Critical business applications</td><td>Backup restore</td><td>24-48 hours</td></tr><tr><td><strong>P4</strong></td><td>File servers</td><td>Backup restore</td><td>48-72 hours</td></tr><tr><td><strong>P5</strong></td><td>User workstations</td><td>Reimage + backup data</td><td>As capacity allows</td></tr></tbody></table>

#### Step 5.2: Backup Validation

> ⚠️ **Critical:** Validate backups are clean before restoration!

| Validation Step   | Method                 | Purpose              |
| ----------------- | ---------------------- | -------------------- |
| Isolate backup    | Air-gapped restoration | Prevent infection    |
| Scan backup       | AV/EDR scan            | Detect malware       |
| Test restore      | Restore to isolated VM | Verify integrity     |
| Date verification | Confirm backup date    | Ensure pre-infection |
| Application test  | Test functionality     | Verify usability     |

#### Step 5.3: Domain Controller Recovery

**If DCs Are Compromised**

| Option                  | When to Use                        | Complexity |
| ----------------------- | ---------------------------------- | ---------- |
| **Restore from backup** | Clean backup available, <24hrs old | Medium     |
| **Rebuild DC**          | No clean backup, or backup old     | High       |
| **Forest recovery**     | Multiple/all DCs compromised       | Very High  |

**DC Rebuild Procedure (Summary)**

1. Build new DC on clean hardware/VM
2. Promote to Domain Controller
3. Wait for replication
4. Seize FSMO roles if needed
5. Demote compromised DCs
6. Remove compromised DC metadata
7. Validate AD functionality

#### Step 5.4: System Recovery Procedures

**Server Recovery**

```bash
1. Validate backup integrity (isolated restore test)
2. Prepare clean hardware/VM
3. Restore from backup
4. Apply security updates before network connection
5. Harden configuration
6. Deploy EDR agent
7. Validate functionality
8. Connect to network (monitored segment initially)
9. Monitor for 24-48 hours
10. Move to production
```

**Workstation Recovery**

```bash
1. Reimage with clean OS image
2. Apply security updates
3. Install required applications
4. Deploy EDR agent
5. Restore user data from backup (scan first)
6. Enforce password change at first logon
7. Monitor for anomalies
```

#### Step 5.5: Data Recovery

| Data Type        | Recovery Method              | Validation              |
| ---------------- | ---------------------------- | ----------------------- |
| File shares      | Restore from backup          | Spot check + AV scan    |
| Databases        | Restore from backup          | Integrity check + test  |
| Email            | PST restore or O365 recovery | Verify mailbox function |
| Cloud data       | Point-in-time recovery       | Verify access           |
| Application data | Application-specific restore | Application testing     |

#### Recovery Checklist

```bash
□ Recovery priorities established
□ Backup integrity validated
□ Domain Controllers recovered/rebuilt
□ KRBTGT reset completed (if not done)
□ Authentication services functional
□ Critical applications restored
□ File servers restored
□ User workstations reimaged
□ User data restored
□ All systems scanned post-recovery
□ Recovery validated and documented
□ Users notified of recovery status
```

***

### Phase 6: Post-Incident Activities

**Timeline:** After recovery complete&#x20;

**Objective:** Learn from the incident and improve defences.

#### Step 6.1: Post-Incident Review (PIR)

<table><thead><tr><th width="189">Topic</th><th>Questions to Address</th></tr></thead><tbody><tr><td><strong>Detection</strong></td><td>How was the incident detected? How long was dwell time?</td></tr><tr><td><strong>Response</strong></td><td>What worked well? What could be improved?</td></tr><tr><td><strong>Containment</strong></td><td>Was containment fast enough? What slowed it down?</td></tr><tr><td><strong>Eradication</strong></td><td>Was eradication complete? Any reinfection?</td></tr><tr><td><strong>Recovery</strong></td><td>How long did recovery take? Were backups adequate?</td></tr><tr><td><strong>Communication</strong></td><td>Was communication effective? Any gaps?</td></tr></tbody></table>

#### Step 6.2: Documentation Requirements

<table><thead><tr><th width="196">Document</th><th width="326">Contents</th><th>Audience</th></tr></thead><tbody><tr><td>Technical Report</td><td>Full technical details, IOCs, timeline</td><td>Security team</td></tr><tr><td>Executive Summary</td><td>Business impact, costs, key decisions</td><td>Leadership</td></tr><tr><td>Legal Report</td><td>Evidence, timeline for litigation</td><td>Legal counsel</td></tr><tr><td>Regulatory Report</td><td>Data breach details if applicable</td><td>Regulators</td></tr><tr><td>Insurance Claim</td><td>Costs, timeline, evidence</td><td>Cyber insurance</td></tr></tbody></table>

#### Step 6.3: Hardening Recommendations

<table><thead><tr><th width="159">Category</th><th>Common Improvements</th></tr></thead><tbody><tr><td><strong>Identity</strong></td><td>MFA everywhere, privileged access management, reduced admin accounts</td></tr><tr><td><strong>Endpoint</strong></td><td>EDR coverage, application control, attack surface reduction</td></tr><tr><td><strong>Network</strong></td><td>Segmentation, east-west traffic monitoring, zero trust</td></tr><tr><td><strong>Backup</strong></td><td>Air-gapped backups, immutable storage, tested restoration</td></tr><tr><td><strong>Detection</strong></td><td>Improved alerting, UEBA, deception technology</td></tr><tr><td><strong>Response</strong></td><td>Updated runbooks, tabletop exercises, IR retainer</td></tr></tbody></table>

#### Step 6.4: Regulatory Notifications

<table><thead><tr><th width="172">Regulation</th><th width="300">Notification Requirement</th><th>Timeline</th></tr></thead><tbody><tr><td>GDPR</td><td>Data Protection Authority if EU data</td><td>72 hours</td></tr><tr><td>HIPAA</td><td>HHS if PHI involved</td><td>60 days</td></tr><tr><td>State Breach Laws</td><td>State AG, affected individuals</td><td>Varies (typically 30-60 days)</td></tr><tr><td>SEC</td><td>Material cybersecurity incidents</td><td>4 business days</td></tr><tr><td>PCI-DSS</td><td>Card brands, acquirer</td><td>Immediately</td></tr><tr><td>CISA</td><td>Critical infrastructure</td><td>72 hours</td></tr></tbody></table>

***

## KQL Query Cheat Sheet

### Ransomware Detection Queries

#### Mass File Modification Detection

```kusto
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| summarize 
    ModifiedFiles = count(),
    UniqueExtensions = dcount(tostring(split(FileName, ".")[-1])),
    Extensions = make_set(tostring(split(FileName, ".")[-1]), 20)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where ModifiedFiles > 100
| sort by ModifiedFiles desc
```

#### Known Ransomware Extensions

{% code overflow="wrap" %}
```kusto
let ransomwareExtensions = dynamic([
    ".lockbit", ".lockbit3", ".alphv", ".ALPHV", ".clop", ".Cl0p",
    ".royal", ".play", ".akira", ".basta", ".rhysida", ".medusa",
    ".8base", ".encrypted", ".enc", ".locked", ".crypted"
]);
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName has_any (ransomwareExtensions)
| summarize Count = count(), Files = make_set(FileName, 20) by DeviceName, InitiatingProcessFileName
| sort by Count desc
```
{% endcode %}

#### Ransom Note Detection

{% code overflow="wrap" %}
```kusto
let ransomNotePatterns = dynamic([
    "readme", "DECRYPT", "RECOVER", "RESTORE", "HOW_TO", "HELP_ME",
    "READ_ME", "ATTENTION", "_HELP_", "RANSOM", "ENCRYPTED"
]);
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FileName has_any (ransomNotePatterns)
| where FileName endswith ".txt" or FileName endswith ".html" or FileName endswith ".hta"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp desc
```
{% endcode %}

#### Shadow Copy Deletion

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete", "shadows", "resize"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("shadowcopy", "delete"))
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "no", "ignoreallfailures"))
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Get-WmiObject", "Win32_ShadowCopy", "Delete"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
```
{% endcode %}

#### Security Tool Tampering

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "DisableAntiSpyware",
    "DisableRealtimeMonitoring",
    "Set-MpPreference",
    "Stop-Service",
    "sc stop",
    "net stop",
    "taskkill /F /IM"
)
| where ProcessCommandLine has_any (
    "defender", "antivirus", "malware", "security", "protect",
    "msmpeng", "mssense", "sense", "windefend"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp desc
```

***

### Pre-Encryption Activity Detection

#### Credential Dumping Tools

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("mimikatz.exe", "procdump.exe", "procdump64.exe", "comsvcs.dll")
    or ProcessCommandLine has_any (
        "sekurlsa", "lsadump", "kerberos::", "privilege::debug",
        "-ma lsass", "MiniDump", "comsvcs.dll,MiniDump"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```
{% endcode %}

#### Reconnaissance Tools

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AdFind.exe", "adfind.exe", "bloodhound.exe", "sharphound.exe")
    or ProcessCommandLine has_any (
        "AdFind", "-f objectcategory=computer",
        "Get-ADComputer", "Get-ADUser", "Get-ADGroup",
        "net group", "net user", "net localgroup",
        "nltest /dclist", "dsquery"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

#### PsExec and Remote Execution

{% code overflow="wrap" %}
```kusto
union
(DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe", "psexec64.exe", "paexec.exe")
| project Timestamp, DeviceName, AccountName, Tool = FileName, CommandLine = ProcessCommandLine),
(DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| where ServiceName matches regex @"(?i)(psexe|paexe|remcom|csexe)"
| project Timestamp, DeviceName, AccountName, Tool = "Service", CommandLine = ServiceName)
| sort by Timestamp desc
```
{% endcode %}

#### Lateral Movement Velocity

```kusto
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| summarize 
    TargetCount = dcount(DeviceName),
    Targets = make_set(DeviceName, 50),
    SourceIPs = make_set(RemoteIP, 10)
    by AccountName, bin(Timestamp, 15m)
| where TargetCount > 10
| sort by TargetCount desc
```

***

### Active Encryption Detection

#### Real-Time File Encryption Alert

```kusto
DeviceFileEvents
| where Timestamp > ago(15m)
| where ActionType in ("FileModified", "FileRenamed")
| summarize 
    FileCount = count(),
    UniqueDirectories = dcount(FolderPath)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1m)
| where FileCount > 50
| sort by Timestamp desc, FileCount desc
```

#### Encryption Process Identification

{% code overflow="wrap" %}
```kusto
// Find processes modifying many files
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| summarize FileCount = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessId
| where FileCount > 500
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(1h)
) on DeviceName, $left.InitiatingProcessFileName == $right.FileName
| project DeviceName, ProcessName = InitiatingProcessFileName, FileCount, ProcessCommandLine, ProcessCreationTime = Timestamp
| sort by FileCount desc
```
{% endcode %}

#### Affected Systems Dashboard

```kusto
DeviceFileEvents
| where Timestamp > ago(4h)
| where ActionType in ("FileModified", "FileRenamed")
| extend FileExtension = tostring(split(FileName, ".")[-1])
| summarize 
    TotalFiles = count(),
    UniqueExtensions = dcount(FileExtension),
    Extensions = make_set(FileExtension, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| where TotalFiles > 100
| sort by TotalFiles desc
```

***

### Post-Compromise Investigation

#### Timeline for Affected Device

{% code overflow="wrap" %}
```kusto
let targetDevice = "INFECTED-PC01";
let timeframe = 7d;
union
(DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where DeviceName == targetDevice
| project Timestamp, EventType = "Process", Details = strcat(FileName, " - ", ProcessCommandLine)),
(DeviceLogonEvents
| where Timestamp > ago(timeframe)
| where DeviceName == targetDevice
| project Timestamp, EventType = "Logon", Details = strcat(AccountName, " from ", RemoteIP, " (", LogonType, ")")),
(DeviceNetworkEvents
| where Timestamp > ago(timeframe)
| where DeviceName == targetDevice
| where RemoteIPType == "Public"
| project Timestamp, EventType = "Network", Details = strcat(InitiatingProcessFileName, " -> ", RemoteIP, ":", RemotePort)),
(DeviceFileEvents
| where Timestamp > ago(timeframe)
| where DeviceName == targetDevice
| where ActionType in ("FileCreated", "FileModified") and FileName endswith ".exe"
| project Timestamp, EventType = "FileEvent", Details = strcat(ActionType, ": ", FileName))
| sort by Timestamp asc
```
{% endcode %}

#### Account Activity Analysis

{% code overflow="wrap" %}
```kusto
let compromisedAccount = "DOMAIN\\username";
let timeframe = 7d;
IdentityLogonEvents
| where Timestamp > ago(timeframe)
| where AccountUpn contains compromisedAccount or AccountName contains compromisedAccount
| summarize 
    LogonCount = count(),
    UniqueTargets = dcount(TargetDeviceName),
    Targets = make_set(TargetDeviceName, 50),
    LogonTypes = make_set(LogonType),
    Protocols = make_set(Protocol)
    by bin(Timestamp, 1h)
| sort by Timestamp asc
```
{% endcode %}

#### C2 Communication Detection

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize 
    Connections = count(),
    BytesSent = sum(SentBytes),
    BytesReceived = sum(ReceivedBytes),
    Processes = make_set(InitiatingProcessFileName, 10)
    by DeviceName, RemoteIP, RemotePort
| where Connections > 100 or BytesSent > 100000000
| sort by Connections desc
```

***

### Backup and Recovery Queries

#### Backup System Access

```kusto
DeviceLogonEvents
| where Timestamp > ago(30d)
| where DeviceName has_any ("backup", "veeam", "commvault", "veritas", "cohesity")
| summarize 
    LogonCount = count(),
    UniqueAccounts = dcount(AccountName),
    Accounts = make_set(AccountName, 20)
    by DeviceName, LogonType, bin(Timestamp, 1d)
| sort by Timestamp desc
```

#### VSS Activity Monitoring

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("vssadmin.exe", "wmic.exe", "diskshadow.exe")
| where ProcessCommandLine has_any ("shadow", "delete", "create", "resize", "list")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

***

## Response Actions & Commands

### Immediate Response Actions

#### MDE Device Isolation

{% code overflow="wrap" %}
```powershell
# Isolate device via MDE
# Full isolation - device can only communicate with MDE

$deviceId = "device-machine-id"
$comment = "Ransomware containment - IR-2024-XXX"

# Via Microsoft Graph
$body = @{
    Comment = $comment
    IsolationType = "Full"
} | ConvertTo-Json

Invoke-MgGraphRequest -Method POST `
    -Uri "https://api.securitycenter.microsoft.com/api/machines/$deviceId/isolate" `
    -Body $body

# Bulk isolation
$deviceIds = @("device1-id", "device2-id", "device3-id")
foreach ($id in $deviceIds) {
    Invoke-MgGraphRequest -Method POST `
        -Uri "https://api.securitycenter.microsoft.com/api/machines/$id/isolate" `
        -Body $body
    Write-Host "Isolated: $id"
}
```
{% endcode %}

#### Network Containment via Prisma Access

```bash
# Emergency Security Policy - Block Ransomware Spread

Rule 1: Block SMB Lateral Movement
- Source: Any internal
- Destination: Any internal  
- Service: microsoft-ds (445), netbios-ssn (139)
- Action: Deny
- Log: Yes

Rule 2: Block RDP Lateral Movement
- Source: Any internal (except jump servers)
- Destination: Any internal
- Service: ms-rdp (3389)
- Action: Deny
- Log: Yes

Rule 3: Block Known C2
- Source: Any
- Destination: [IOC IP list]
- Service: Any
- Action: Deny
- Log: Yes
```

#### Mass Account Disable

```powershell
# Disable compromised accounts in bulk
$compromisedAccounts = @(
    "user1@domain.com",
    "user2@domain.com",
    "admin1@domain.com"
)

# Entra ID
Connect-MgGraph -Scopes "User.ReadWrite.All"
foreach ($user in $compromisedAccounts) {
    Update-MgUser -UserId $user -AccountEnabled:$false
    Revoke-MgUserSignInSession -UserId $user
    Write-Host "Disabled and revoked sessions: $user"
}

# On-premises AD
foreach ($user in $compromisedAccounts) {
    $samAccount = ($user -split "@")[0]
    Disable-ADAccount -Identity $samAccount
    Write-Host "Disabled AD account: $samAccount"
}
```

### Evidence Collection

#### Collect Ransomware Artifacts

{% code overflow="wrap" %}
```powershell
# Collect artifacts from affected system (run via MDE Live Response or locally)

$evidencePath = "C:\IR_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidencePath -Force

# Collect ransom notes
Get-ChildItem -Path C:\ -Recurse -Include "*readme*","*decrypt*","*recover*","*help*" -File -ErrorAction SilentlyContinue |
    Where-Object {$_.Extension -in ".txt",".html",".hta"} |
    Copy-Item -Destination $evidencePath

# Collect encrypted file samples
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {$_.Extension -match "\.(lockbit|encrypted|enc|locked)"} |
    Select-Object -First 5 |
    Copy-Item -Destination $evidencePath

# Export event logs
$logs = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational")
foreach ($log in $logs) {
    wevtutil epl $log "$evidencePath\$($log -replace '/','-').evtx"
}

# Collect running processes
Get-Process | Export-Csv "$evidencePath\processes.csv" -NoTypeInformation

# Collect network connections
Get-NetTCPConnection | Export-Csv "$evidencePath\connections.csv" -NoTypeInformation

# Collect scheduled tasks
Get-ScheduledTask | Export-Csv "$evidencePath\scheduledtasks.csv" -NoTypeInformation

# Collect services
Get-Service | Export-Csv "$evidencePath\services.csv" -NoTypeInformation

# Compress evidence
Compress-Archive -Path $evidencePath -DestinationPath "$evidencePath.zip" -Force

Write-Host "Evidence collected to: $evidencePath.zip"
```
{% endcode %}

#### Memory Acquisition

```powershell
# Using WinPmem (must be deployed to system)
# Run via MDE Live Response

# Upload WinPmem to device first
# Then execute:
.\winpmem_mini_x64.exe memdump.raw

# Alternative: Using MDE Live Response built-in
# (limited memory collection capability)
```

***

## Quick Reference Cards

### Ransomware Response Checklist

#### Immediate Actions (First 15 Minutes)

```bash
□ Validate ransomware alert
□ Identify initial affected systems
□ Declare incident severity
□ Activate IR team
□ Establish secure communication
□ Begin isolating confirmed infected systems
□ Alert leadership
□ Start incident documentation
```

#### Containment Actions (15-60 Minutes)

```bash
□ Isolate all confirmed infected systems
□ Block C2 infrastructure
□ Isolate network segments if spreading
□ Disable compromised accounts
□ Protect backup systems
□ Preserve evidence (don't wipe!)
□ Verify containment effectiveness
□ Document containment actions
```

#### Investigation Actions (Ongoing)

```bash
□ Identify patient zero
□ Determine initial access vector
□ Map lateral movement
□ Identify all compromised accounts
□ Assess data exfiltration
□ Determine encryption scope
□ Identify ransomware variant
□ Check for available decryptors
```

#### Eradication Actions (After Containment)

```bash
□ Plan credential reset strategy
□ Execute KRBTGT reset (if DC compromised)
□ Reset all privileged passwords
□ Reset all user passwords
□ Remove malware and persistence
□ Remove attacker tools
□ Clean up GPOs
□ Validate eradication complete
```

#### Recovery Actions (After Eradication)

```bash
□ Validate backup integrity
□ Prioritise system recovery
□ Recover/rebuild Domain Controllers
□ Restore critical applications
□ Restore file servers
□ Reimage workstations
□ Restore user data
□ Validate recovery complete
```

### Ransomware Variant Quick Reference

<table><thead><tr><th width="324">If You See...</th><th>Likely Ransomware</th><th>Known For</th></tr></thead><tbody><tr><td><code>.lockbit3</code> extension, red wallpaper</td><td>LockBit 3.0</td><td>Fast encryption, RaaS</td></tr><tr><td><code>.ALPHV</code> extension, rust-based</td><td>BlackCat/ALPHV</td><td>Cross-platform</td></tr><tr><td>Targets MOVEit/GoAnywhere</td><td>Cl0p</td><td>Zero-day exploitation</td></tr><tr><td><code>.royal</code> extension</td><td>Royal/BlackSuit</td><td>Partial encryption</td></tr><tr><td><code>.play</code> extension</td><td>Play</td><td>No RaaS, stealth</td></tr><tr><td><code>.akira</code> extension, retro theme</td><td>Akira</td><td>VPN targeting</td></tr><tr><td><code>.basta</code> extension</td><td>Black Basta</td><td>QakBot delivery</td></tr></tbody></table>

### Critical Contacts Template

| Role              | Name | Phone | Email |
| ----------------- | ---- | ----- | ----- |
| IR Team Lead      |      |       |       |
| CISO              |      |       |       |
| Legal Counsel     |      |       |       |
| External IR Firm  |      |       |       |
| Cyber Insurance   |      |       |       |
| FBI Field Office  |      |       |       |
| PR/Communications |      |       |       |

***

## Escalation Matrix

### Severity Classification

<table><thead><tr><th width="122">Severity</th><th width="398">Criteria</th><th>Response</th></tr></thead><tbody><tr><td>🔴 <strong>Critical</strong></td><td>Active encryption spreading, DCs affected, >50 systems</td><td>All hands, external IR</td></tr><tr><td>🟠 <strong>High</strong></td><td>Encryption contained, multiple servers affected</td><td>Full IR team</td></tr><tr><td>🟡 <strong>Medium</strong></td><td>Single server or multiple workstations</td><td>Tier 2 + Tier 1</td></tr><tr><td>🟢 <strong>Low</strong></td><td>Single workstation, rapidly contained</td><td>Tier 1 with Tier 2 backup</td></tr></tbody></table>

### Escalation Timeline

<table><thead><tr><th width="196">Time</th><th>Actions</th></tr></thead><tbody><tr><td><strong>0-15 min</strong></td><td>IR team lead notified, incident declared</td></tr><tr><td><strong>15-30 min</strong></td><td>CISO notified, containment in progress</td></tr><tr><td><strong>30-60 min</strong></td><td>Executive leadership briefed</td></tr><tr><td><strong>1-4 hours</strong></td><td>External IR engaged (if needed), Legal notified</td></tr><tr><td><strong>4-24 hours</strong></td><td>Board notification (if critical), insurance notified</td></tr><tr><td><strong>24-72 hours</strong></td><td>Regulatory notification assessment</td></tr></tbody></table>

### Communication Templates

#### Initial Executive Notification

```bash
Subject: SECURITY INCIDENT - Ransomware Detected

Priority: CRITICAL

Summary:
At [TIME], our security systems detected ransomware activity affecting 
[NUMBER] systems. The incident response team has been activated.

Current Status:
- Containment actions in progress
- Affected systems are being isolated
- Investigation underway

Impact Assessment:
- Systems affected: [NUMBER/LIST]
- Business services impacted: [LIST]
- Data at risk: [ASSESSMENT]

Next Update: [TIME]

Actions Required:
- [Any executive decisions needed]

Contact: [IR Lead] - [Phone]
```

#### Status Update Template

```bash
Subject: SECURITY INCIDENT UPDATE #[X] - Ransomware Response

Time: [TIMESTAMP]
Status: [Containment/Investigation/Eradication/Recovery]

Progress Since Last Update:
- [Bullet points of progress]

Current Actions:
- [What's happening now]

Challenges/Blockers:
- [Any issues]

Next Steps:
- [Planned actions]

Metrics:
- Systems Contained: X/Y
- Systems Clean: X/Y
- Estimated Recovery: [TIME]

Next Update: [TIME]
```

***

## MITRE ATT\&CK Mapping

### Pre-Ransomware Techniques

<table><thead><tr><th>Tactic</th><th width="236">Technique</th><th>ID</th><th>Detection</th></tr></thead><tbody><tr><td>Initial Access</td><td>Phishing</td><td>T1566</td><td>MDO alerts</td></tr><tr><td>Initial Access</td><td>External Remote Services</td><td>T1133</td><td>VPN/RDP logs</td></tr><tr><td>Initial Access</td><td>Valid Accounts</td><td>T1078</td><td>SigninLogs anomalies</td></tr><tr><td>Execution</td><td>PowerShell</td><td>T1059.001</td><td>Script block logging</td></tr><tr><td>Execution</td><td>Command Interpreter</td><td>T1059.003</td><td>Process command lines</td></tr><tr><td>Persistence</td><td>Scheduled Task</td><td>T1053.005</td><td>Event 4698</td></tr><tr><td>Persistence</td><td>Registry Run Keys</td><td>T1547.001</td><td>Registry monitoring</td></tr><tr><td>Privilege Escalation</td><td>Valid Accounts</td><td>T1078</td><td>Privileged logons</td></tr><tr><td>Defense Evasion</td><td>Disable Security Tools</td><td>T1562.001</td><td>MDE health alerts</td></tr><tr><td>Credential Access</td><td>OS Credential Dumping</td><td>T1003</td><td>MDE alerts, process events</td></tr><tr><td>Credential Access</td><td>Kerberoasting</td><td>T1558.003</td><td>Event 4769</td></tr><tr><td>Discovery</td><td>Domain Trust Discovery</td><td>T1482</td><td>Nltest, AD queries</td></tr><tr><td>Discovery</td><td>Network Share Discovery</td><td>T1135</td><td>Net view commands</td></tr><tr><td>Lateral Movement</td><td>Remote Services</td><td>T1021</td><td>Logon events</td></tr><tr><td>Lateral Movement</td><td>SMB/Admin Shares</td><td>T1021.002</td><td>Event 5140</td></tr><tr><td>Collection</td><td>Data from Local System</td><td>T1005</td><td>File access</td></tr><tr><td>Exfiltration</td><td>Exfil Over Web Service</td><td>T1567</td><td>Network traffic</td></tr></tbody></table>

### Ransomware Execution Techniques

<table><thead><tr><th width="119">Tactic</th><th width="240">Technique</th><th>ID</th><th>Detection</th></tr></thead><tbody><tr><td>Impact</td><td>Data Encrypted for Impact</td><td>T1486</td><td>Mass file modification</td></tr><tr><td>Impact</td><td>Inhibit System Recovery</td><td>T1490</td><td>VSS deletion, bcdedit</td></tr><tr><td>Impact</td><td>Service Stop</td><td>T1489</td><td>Service control events</td></tr><tr><td>Impact</td><td>System Shutdown/Reboot</td><td>T1529</td><td>System events</td></tr></tbody></table>

***

## Appendix: Additional Resources

### Ransomware Identification Resources

<table><thead><tr><th width="221">Resource</th><th width="308">URL</th><th>Purpose</th></tr></thead><tbody><tr><td>ID Ransomware</td><td>https://id-ransomware.malwarehunterteam.com</td><td>Identify variant by sample</td></tr><tr><td>No More Ransom</td><td>https://www.nomoreransom.org</td><td>Free decryptors</td></tr><tr><td>Ransomwhere</td><td>https://ransomwhe.re</td><td>Ransom payment tracking</td></tr><tr><td>CISA Ransomware Guide</td><td>https://www.cisa.gov/stopransomware</td><td>Official guidance</td></tr></tbody></table>

### Decryptor Resources

<table><thead><tr><th width="239">Source</th><th>URL</th></tr></thead><tbody><tr><td>No More Ransom Project</td><td>https://www.nomoreransom.org/en/decryption-tools.html</td></tr><tr><td>Emsisoft Decryptors</td><td>https://www.emsisoft.com/ransomware-decryption-tools/</td></tr><tr><td>Kaspersky No Ransom</td><td>https://noransom.kaspersky.com</td></tr><tr><td>Avast Decryptors</td><td>https://www.avast.com/ransomware-decryption-tools</td></tr></tbody></table>

### Legal and Regulatory Resources

<table><thead><tr><th width="188">Topic</th><th>Resource</th></tr></thead><tbody><tr><td>FBI IC3</td><td>https://www.ic3.gov (report ransomware)</td></tr><tr><td>CISA</td><td>https://www.cisa.gov/stopransomware</td></tr><tr><td>OFAC Sanctions</td><td>Check before any ransom consideration</td></tr><tr><td>State Breach Laws</td><td>Varies by state</td></tr></tbody></table>

### Ransom Payment Considerations

> ⚠️ **Important Legal Note:** This section is for awareness only. Ransom payment decisions require legal, executive, and potentially law enforcement consultation.

<table><thead><tr><th width="243">Factor</th><th>Consideration</th></tr></thead><tbody><tr><td><strong>OFAC Sanctions</strong></td><td>Payment to sanctioned entities is illegal</td></tr><tr><td><strong>No Guarantee</strong></td><td>Payment doesn't guarantee decryption</td></tr><tr><td><strong>Repeat Targeting</strong></td><td>Paying may invite future attacks</td></tr><tr><td><strong>Data Already Leaked</strong></td><td>Payment won't prevent data publication</td></tr><tr><td><strong>Decryptor Availability</strong></td><td>Free decryptors may exist</td></tr><tr><td><strong>Backup Recovery</strong></td><td>Recovery without payment may be possible</td></tr><tr><td><strong>Insurance Coverage</strong></td><td>Policy may have payment restrictions</td></tr><tr><td><strong>Legal Liability</strong></td><td>Consider all legal implications</td></tr></tbody></table>

**Recommendation:** Exhaust all recovery options before considering payment. Always involve legal counsel and potentially law enforcement.

***

> 🚨 **CRITICAL REMINDER:** Ransomware incidents are time-critical. Every minute of delay can result in additional encrypted systems. However, hasty actions can destroy evidence or alert attackers. Balance speed with precision. When in doubt, isolate first, investigate second. NEVER pay ransom without exhausting all other options and consulting legal counsel. Most importantly—test your backups regularly; they are your primary recovery mechanism.
