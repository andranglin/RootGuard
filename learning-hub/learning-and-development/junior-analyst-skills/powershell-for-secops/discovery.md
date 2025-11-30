# Discovery

### **Introduction**

PowerShell is an essential tool for security operations (SecOps), offering a powerful platform for managing systems, automating tasks, and conducting threat investigations. Its deep integration with Windows and robust scripting capabilities make it invaluable for **Digital Forensics and Incident Response (DFIR)** investigations, particularly in uncovering **Discovery activities**. Discovery activities are actions taken by attackers to gain information about the environment, such as network configurations, user accounts, and active processes, to facilitate their attack objectives. PowerShell provides a comprehensive and efficient means to detect and analyse these activities, empowering SecOps teams to identify threats, mitigate risks, and safeguard enterprise networks.

***

### **Capabilities of PowerShell for Discovery Activities in DFIR**

**1. Detecting Host Reconnaissance:**

PowerShell enables analysts to monitor and analyse commands related to host discovery, such as the enumeration of running processes, services, and system information. This includes detecting queries that reveal system architecture, operating system versions, or installed software, which are commonly used by attackers during initial reconnaissance.

**2. Monitoring for Network Discovery:**

PowerShell provides the ability to detect attempts at network scanning and enumeration. This includes commands used to identify live hosts, open ports, and network shares, as well as activities aimed at mapping network topologies and configurations.

**3. Investigating Account and Credential Enumeration:**

Attackers often attempt to enumerate user accounts, groups, and Active Directory (AD) objects to identify privileged accounts or potential targets. PowerShell can track these activities by analysing queries related to AD, group memberships, and credential storage locations.

**4. Detecting File and Directory Enumeration:**

PowerShell can monitor activities involving the enumeration of files, directories, or shares, which attackers may use to locate sensitive information or valuable data. This includes identifying abnormal access patterns to critical directories or shared resources.

**5. Identifying Command-Line Discovery Techniques:**

PowerShell can capture and analyse suspicious or encoded command-line arguments indicative of discovery activities. This includes detecting the use of obfuscated commands or scripts aimed at bypassing security tools during reconnaissance.

**6. Event Log Analysis for Discovery Patterns:**

PowerShell facilitates querying event logs for patterns indicative of discovery activities. This includes looking for specific event IDs related to process creation, access attempts, or network activity that align with known discovery techniques.

**7. Hunting for Discovery Tools:**

Attackers may use third-party tools for discovery purposes, such as port scanners or AD enumeration tools. PowerShell can identify the execution of these tools and track their usage across the network.

***

### **Efficiency Provided by PowerShell in Discovery Activities**

1. **Comprehensive Visibility**: PowerShell provides detailed access to system logs, processes, and configurations, enabling analysts to uncover discovery activities across endpoints and networks.
2. **Real-Time Detection**: PowerShell’s dynamic querying capabilities allow SecOps teams to monitor system activities in real-time, providing immediate insights into discovery attempts.
3. **Scalability**: With **PowerShell Remoting**, analysts can execute detection scripts across multiple systems simultaneously, ensuring efficient coverage in enterprise environments.
4. **Automation of Analysis**: PowerShell scripts can automate the detection of specific discovery activities, such as tracking commands that query system information or network configurations, ensuring consistent and repeatable workflows.
5. **Tailored Detection**: PowerShell’s flexibility allows for customising detection rules to align with organisational baselines and threat models, including the **MITRE ATT\&CK framework**.
6. **Integration with Security Tools**: PowerShell integrates seamlessly with tools like Microsoft Sentinel, Defender for Endpoint, and SIEM platforms, enabling automated responses and enriched threat analysis.

***

By leveraging PowerShell’s extensive capabilities, SecOps teams can effectively uncover and analyse discovery activities during DFIR investigations, allowing for rapid containment and mitigation of threats while enhancing the organisation’s security posture.

### Discovery Actions

### 1. **Network Discovery**

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

### 2. **User and Account Discovery**

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

### 3. **Group and Permission Discovery**

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

### 4. **System and Application Discovery**

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

### 5. **Network Configuration and Interface Enumeration**

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

### 6. **Service and Port Discovery**

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

### 7. **File and Directory Discovery**

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

### 8. **Security and Policy Discovery**

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

### 9. **Scheduled Task and Job Discovery**

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

### 10. **Remote System and Domain Discovery**

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
