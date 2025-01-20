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

# Reconnaissance Discovery

### **Introduction**

PowerShell is a versatile and powerful scripting language and automation tool widely used in security operations (SecOps) to manage and secure enterprise networks. Its deep integration with the Windows operating system and expansive library of cmdlets make it indispensable for conducting reconnaissance, discovery, digital forensics, and incident response (DFIR) activities. With its ability to query, analyse, and automate tasks at scale, PowerShell is an essential tool for SecOps teams tasked with protecting enterprise environments from evolving cyber threats.

***

### **Capabilities of PowerShell for Reconnaissance Discovery**

**1. Reconnaissance in Enterprise Networks:**

* **Network Mapping**: PowerShell cmdlets like `Test-Connection`, `Resolve-DnsName`, and `Get-NetRoute` help enumerate hosts, identify active devices, and map network topology.
* **Service Enumeration**: With tools like `Get-Service` and `Get-NetTCPConnection`, PowerShell enables analysts to identify running services and open ports, providing insights into potential attack surfaces.
* **User and Group Recon**: Commands such as `Get-ADUser` and `Get-ADGroup` allow enumeration of Active Directory objects, helping security teams understand account structures and privileges.

**2. Discovery of Threats and Anomalies:**

* **File and Process Analysis**: Use `Get-Process` and `Get-Item` to identify suspicious processes, files, or directories, focusing on anomalies like unsigned executables or hidden files.
* **Network Activity Monitoring**: PowerShell scripts can analyse live network traffic, connections, and listening ports using cmdlets like `Get-NetTCPConnection` and custom parsing of logs.
* **System Event Logs**: Cmdlets such as `Get-WinEvent` and `Get-EventLog` enable comprehensive log analysis for detecting indicators of compromise (IOCs) or anomalous behaviour.

**3. Digital Forensics and Incident Response (DFIR):**

* **Memory Forensics**: PowerShell facilitates memory dumps using `Get-Process` and tools like `Procdump`, providing forensic data for malware or threat analysis.
* **Artifact Collection**: PowerShell can automate the collection of forensic artifacts, such as registry hives, logs, and file metadata, with commands like `Export-Csv` and `Copy-Item`.
* **Persistence Analysis**: Scripts can analyse autorun locations (e.g., registry keys, scheduled tasks) to uncover persistence mechanisms used by attackers.
* **Lateral Movement Detection**: Using `Get-WinEvent` and network-related cmdlets, PowerShell helps detect evidence of lateral movement, such as suspicious logons or credential use.

***

### **Efficiency Provided by PowerShell in SecOps**

1. **Scalability**: PowerShell’s ability to execute commands across multiple systems simultaneously using **PowerShell Remoting** or scripting reduces the time required for reconnaissance, discovery, and remediation tasks.
2. **Automation**: With its robust scripting capabilities, PowerShell enables the automation of repetitive DFIR activities, such as log collection, IOC searches, and artifact analysis, freeing up SecOps resources for more strategic tasks.
3. **Real-Time Insights**: PowerShell provides near-instant access to system and network data, enabling faster detection and response to threats in dynamic environments.
4. **Customisation**: The flexibility of PowerShell allows analysts to write custom scripts tailored to specific enterprise environments and threat scenarios, improving detection and investigation accuracy.
5. **Integration with Security Tools**: PowerShell integrates seamlessly with tools like Microsoft Defender, Azure Sentinel, and SIEM platforms, allowing security teams to orchestrate responses and analyse data in a unified manner.

***

By leveraging PowerShell’s capabilities, SecOps teams can perform effective reconnaissance, threat discovery, and incident response activities across enterprise networks with unmatched precision and efficiency, significantly improving their ability to detect, analyse, and mitigate security incidents.

### Reconnaissance Discovery

### 1. **Network Scanning and Enumeration**

**1.1. Detect Network Scanning Activities**

**Purpose**: Identify potential network scanning activities by monitoring for unusual network connections.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection |  Where-Object {$_.State -eq 'Listen' -and $_.RemoteAddress -ne '0.0.0.0'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**1.2. Identify Unusual ARP Table Entries**

**Purpose**: Detect new or unusual ARP entries that may indicate scanning or network discovery.

{% code overflow="wrap" %}
```powershell
Get-NetNeighbor |  Where-Object {$_.State -eq 'Reachable' -and $_.AddressFamily -eq 'IPv4'} | Select-Object ifIndex, IPAddress, LinkLayerAddress
```
{% endcode %}

### 2. **System Information Gathering**

**2.1. Enumeration of Installed Applications**

**Purpose**: Detect enumeration of installed applications, which may indicate software inventory reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```
{% endcode %}

**2.2. Listing Running Processes**

**Purpose**: Identify unauthorised listing of running processes, which may indicate system reconnaissance.

```powershell
Get-Process | Select-Object Id, ProcessName, StartTime
```

### 3. **User and Account Information Discovery**

**3.1. List Local User Accounts**

**Purpose**: Detect enumeration of local user accounts.

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

**3.2. Active Directory User Enumeration**

**Purpose**: Identify enumeration of Active Directory users, which may indicate domain reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter * -Property DisplayName, Title, Department | Select-Object DisplayName, Title, Department
```
{% endcode %}

### 4. **Group and Permission Enumeration**

**4.1. List Local Groups and Memberships**

**Purpose**: Detect enumeration of local groups and their memberships.

{% code overflow="wrap" %}
```powershell
Get-LocalGroup | ForEach-Object {     [PSCustomObject]@{         GroupName = $_.Name         Members   = (Get-LocalGroupMember -Group $_.Name | Select-Object -ExpandProperty Name) -join ", "     } }
```
{% endcode %}

**4.2. Active Directory Group Enumeration**

**Purpose**: Identify enumeration of Active Directory groups, which may indicate privilege reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ADGroup -Filter * -Property Members | Select-Object Name, @{n='Members';e={$_.Members -join ", "}}
```
{% endcode %}

### 5. **Network Configuration and Interface Enumeration**

**5.1. List Network Interfaces**

**Purpose**: Detect enumeration of network interfaces, potentially indicating network reconnaissance.

```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MACAddress
```

**5.2. Get IP Configuration Details**

**Purpose**: Identify gathering of IP configuration details.

```powershell
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength
```

### 6. **Service and Port Enumeration**

**6.1. List Listening Ports**

**Purpose**: Detect enumeration of listening ports, which may indicate open port scanning.

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort
```

**6.2. Identify Running Services**

**Purpose**: Detect enumeration of running services, potentially indicating service reconnaissance.

```powershell
Get-Service | Select-Object Name, DisplayName, Status, StartType
```

### 7. **File and Directory Enumeration**

**7.1. List Files in Sensitive Directories**

**Purpose**: Identify enumeration of files in sensitive directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\SensitiveData\" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

**7.2. Detect Access to Administrative Shares**

**Purpose**: Detect access or enumeration of administrative shares.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Type=0" | Select-Object Name, Path
```
{% endcode %}

### 8. **Logon Session and Security Group Enumeration**

**8.1. List Active Logon Sessions**

**Purpose**: Detect enumeration of active logon sessions.

{% code overflow="wrap" %}
```powershell
Get-Process -IncludeUserName | Where-Object { $_.UserName } | Select-Object ProcessName, UserName, StartTime
```
{% endcode %}

**8.2. Enumerate Security Groups of Logged-on Users**

**Purpose**: Identify enumeration of security groups for logged-on users.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_ComputerSystem | Select-Object DomainRole, Name, PartOfDomain
```
{% endcode %}

### 9. **Registry and System Configuration Discovery**

**9.1. List Auto-Start Programs**

**Purpose**: Detect enumeration of auto-start programs.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object PSChildName, *
```
{% endcode %}

**9.2. Identify Registry Key Enumeration**

**Purpose**: Detect enumeration of registry keys related to system configuration.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Select-Object PSChildName, Start, Type
```
{% endcode %}

### 10. **Scheduled Task and Job Discovery**

**10.1. List Scheduled Tasks**

**Purpose**: Detect enumeration of scheduled tasks.

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Select-Object TaskName, LastRunTime, TaskPath
```
{% endcode %}

**10.2. Enumerate Windows Jobs**

**Purpose**: Identify enumeration of Windows jobs.

```powershell
Get-WmiObject -Class Win32_ScheduledJob | Select-Object Name, JobId, JobStatus
```

### **Additional Discovery Techniques**

### 1. **Network Scanning and Discovery**

**1.1. Detecting Network Scanning Attempts**

**Purpose**: Identify attempts to scan the network for open ports and services.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5156} | Where-Object {($_.Properties[19].Value -match "Allowed") -and ($_.Properties[7].Value -ne "System")} | Select-Object TimeCreated, @{n='SourceIP';e={$_.Properties[18].Value}}, @{n='DestinationIP';e={$_.Properties[2].Value}}
```
{% endcode %}

**1.2. Monitoring for ARP Scanning**

**Purpose**: Detect ARP scanning attempts, which can reveal network topology.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=104} | Where-Object {$_.Message -match "ARP"} | Select-Object TimeCreated, @{n='SourceIP';e={$_.Properties[0].Value}}, @{n='DestinationIP';e={$_.Properties[1].Value}}
```
{% endcode %}

### 2. **DNS and Directory Service Enumeration**

**2.1. Detecting DNS Zone Transfer Attempts**

**Purpose**: Identify attempts to perform DNS zone transfers, which can reveal domain information.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Server/Audit" | Where-Object {$_.Message -match "AXFR"} | Select-Object TimeCreated, @{n='Query';e={$_.Message}}
```
{% endcode %}

**2.2. Monitoring LDAP Enumeration**

**Purpose**: Detect LDAP queries that may indicate enumeration of Active Directory objects.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} | Where-Object {$_.Message -match "LDAP"} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[5].Value}}, @{n='AccountName';e={$_.Properties[1].Value}}
```
{% endcode %}

### 3. **User and Account Enumeration**

**3.1. Detecting User Enumeration via SMB**

**Purpose**: Identify attempts to enumerate user accounts over SMB.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Where-Object {$_.Properties[19].Value -eq "0xc0000064"} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**3.2. Monitoring for Kerberos Enumeration**

**Purpose**: Detect enumeration of Kerberos accounts, which may reveal service accounts and SPNs.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} | Where-Object {$_.Properties[8].Value -eq "0x0"} | Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[5].Value}}
```
{% endcode %}

### 4. **Service and System Discovery**

**4.1. Detecting Windows Management Instrumentation (WMI) Queries**

**Purpose**: Identify the use of WMI to query system information.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=5857} | Where-Object {$_.Message -match "SELECT"} | Select-Object TimeCreated, @{n='Query';e={$_.Message}}
```
{% endcode %}

**4.2. Monitoring Remote System Discovery via RDP**

**Purpose**: Detect the use of RDP to explore remote systems.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[10].Value -eq '10'} | Select-Object TimeCreated, @{n='AccountName';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

### 5. **File and Directory Enumeration**

**5.1. Detecting Enumeration of File Shares**

**Purpose**: Monitor for attempts to enumerate network file shares.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5145} | Where-Object {$_.Properties[6].Value -match 'Share Enumeration'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}
```
{% endcode %}

**5.2. Monitoring Access to Sensitive Directories**

**Purpose**: Detect access attempts to sensitive directories or files.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match 'C:\SensitiveData'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

### 6. **Network and Firewall Configuration Enumeration**

**6.1. Detecting Attempts to Query Firewall Rules**

**Purpose**: Identify attempts to enumerate firewall rules.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4703} | Select-Object TimeCreated, @{n='RuleName';e={$_.Properties[6].Value}}
```
{% endcode %}

**6.2. Monitoring for Changes in Network Configuration**

**Purpose**: Detect changes in network configurations that may indicate reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name Interfaces
```
{% endcode %}

### 7. **Operating System and Application Enumeration**

**7.1. Detecting OS Version and Installed Software Enumeration**

**Purpose**: Monitor for attempts to enumerate OS versions and installed applications.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Version, BuildNumber Get-WmiObject -Class Win32_Product | Select-Object Name, Version
```
{% endcode %}

**7.2. Monitoring for Enumeration of Installed Patches**

**Purpose**: Detect enumeration of installed patches and hotfixes, which can indicate vulnerability assessment.

```powershell
Get-HotFix | Select-Object Description, HotFixID, InstalledOn
```

### 8. **Cloud and Virtual Environment Discovery**

**8.1. Detecting Enumeration of Cloud Resources**

**Purpose**: Identify attempts to enumerate cloud resources and configurations.

{% code overflow="wrap" fullWidth="false" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" | Where-Object {$_.Message -match "cloud"} | Select-Object TimeCreated, @{n='Details';e={$_.Message}}
```
{% endcode %}

**8.2. Monitoring for Enumeration of Virtual Machines**

**Purpose**: Detect enumeration of virtual machines and their configurations.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Namespace "root\virtualization\v2" -Class Msvm_ComputerSystem |  Select-Object ElementName, OperationalStatus
```
{% endcode %}

### 9. **Service and Process Enumeration**

**9.1. Detecting Enumeration of Running Processes**

**Purpose**: Monitor for attempts to list running processes on a system.

```powershell
Get-Process | Select-Object Id, ProcessName, StartTime
```

**9.2. Monitoring for Service Status Queries**

**Purpose**: Detect queries for the status of services running on a system.

```powerquery
Get-Service | Select-Object Name, DisplayName, Status
```

### 10. **Anomalous Network Behaviour**

**10.1. Detecting Network Traffic Anomalies**

**Purpose**: Identify unusual network traffic patterns that may indicate reconnaissance.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection |  Where-Object {($_.State -eq 'Established') -and ($_.RemoteAddress -notin 'KnownGoodIPs')} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

**10.2. Monitoring for Use of Network Analysis Tools**

**Purpose**: Detect the use of network analysis tools like Nmap, Nessus, etc.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'nmap|nessus'} | Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}
