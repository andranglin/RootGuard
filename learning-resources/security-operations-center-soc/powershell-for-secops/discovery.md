---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Discovery

### Discovery

#### 1. **Network Discovery**

**1.1. Detecting Network Scanning Activities**

**Purpose**: Identify network scanning activities, which may indicate reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen' -and $_.RemoteAddress -ne '0.0.0.0'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**1.2. Identifying New ARP Entries**

**Purpose**: Detect unusual or new ARP table entries that may indicate scanning.

{% code overflow="wrap" %}
```powershell
Get-NetNeighbor | Where-Object {$_.State -eq 'Reachable'} | Select-Object InterfaceIndex, IPAddress, LinkLayerAddress, State
```
{% endcode %}

#### 2. **User and Account Discovery**

**2.1. Enumerating Local User Accounts**

**Purpose**: Identify attempts to list local user accounts on systems.

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

**2.2. Active Directory User Enumeration**

**Purpose**: Detect enumeration of Active Directory user accounts.

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter * -Property DisplayName, Title, Department | Select-Object DisplayName, Title, Department
```
{% endcode %}

#### 3. **Group and Permission Discovery**

**3.1. Listing Local Group Memberships**

**Purpose**: Identify attempts to enumerate local group memberships.

{% code overflow="wrap" %}
```powershell
Get-LocalGroup | ForEach-Object {[PSCustomObject]@{GroupName = $_.Name Members = (Get-LocalGroupMember -Group $_.Name | Select-Object -ExpandProperty Name) -join ", "}}
```
{% endcode %}

**3.2. Active Directory Group Enumeration**

**Purpose**: Detect enumeration of Active Directory groups and their members.

{% code overflow="wrap" %}
```powershell
Get-ADGroup -Filter * -Property Members | Select-Object Name, @{n='Members';e={$_.Members -join ", "}}
```
{% endcode %}

#### 4. **System and Application Discovery**

**4.1. Enumerating Installed Applications**

**Purpose**: Detect attempts to list installed applications on systems.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```
{% endcode %}

**4.2. Listing Running Processes**

**Purpose**: Identify attempts to enumerate running processes.

{% code overflow="wrap" %}
```powershell
Get-Process | Select-Object Id, ProcessName, StartTime
```
{% endcode %}

#### 5. **Network Configuration and Interface Enumeration**

**5.1. Listing Network Interfaces**

**Purpose**: Detect enumeration of network interfaces on systems.

```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MACAddress
```

**5.2. Getting IP Configuration Details**

**Purpose**: Identify gathering of IP configuration information.

```powershell
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength
```

#### 6. **Service and Port Discovery**

**6.1. Listing Listening Ports**

**Purpose**: Detect attempts to list listening ports on systems.

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort
```

**6.2. Enumerating Running Services**

**Purpose**: Identify attempts to enumerate running services.

```powershell
Get-Service | Select-Object Name, DisplayName, Status, StartType
```

#### 7. **File and Directory Discovery**

**7.1. Listing Files in Specific Directories**

**Purpose**: Detect attempts to enumerate files in sensitive directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\SensitiveData\" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

**7.2. Accessing Administrative Shares**

**Purpose**: Identify attempts to access or enumerate administrative shares.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Type=0" | Select-Object Name, Path
```
{% endcode %}

#### 8. **Security and Policy Discovery**

**8.1. Enumerating Local Security Policies**

**Purpose**: Detect attempts to enumerate local security policies.

```powershell
secedit /export /cfg C:\securitypolicy.cfg Get-Content C:\securitypolicy.cfg
```

**8.2. Checking Audit Policy Settings**

**Purpose**: Identify attempts to enumerate audit policy settings.

```powershell
Get-AuditPolicy | Select-Object Subcategory, Success, Failure
```

#### 9. **Scheduled Task and Job Discovery**

**9.1. Listing Scheduled Tasks**

**Purpose**: Detect attempts to enumerate scheduled tasks.

```powershell
Get-ScheduledTask | Select-Object TaskName, LastRunTime, TaskPath
```

**9.2. Enumerating Windows Scheduled Jobs**

**Purpose**: Identify attempts to enumerate Windows scheduled jobs.

```powershell
Get-WmiObject -Class Win32_ScheduledJob | Select-Object Name, JobId, JobStatus
```

#### 10. **Remote System and Domain Discovery**

**10.1. Listing Domain Controllers**

**Purpose**: Detect attempts to enumerate domain controllers in the environment.

```powershell
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site
```

**10.2. Enumerating Trust Relationships**

**Purpose**: Identify attempts to enumerate domain trust relationships.

```powershell
Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection
```
