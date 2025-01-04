---
icon: laptop-code
---

# Reconnaissance (TA0043) Techniques

Reconnaissance is the tactic used by adversaries to gather information about a target network, system, or organisation before launching an attack.

### <mark style="color:blue;">**1. T1595 - Active Scanning**</mark>

**Objective**: Detect network scanning activities indicative of reconnaissance.&#x20;

1. **Detect IP Block Scanning**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP != "127.0.0.1" | summarize count() by RemoteIP, LocalIP, LocalPort | where count() > 50
```
{% endcode %}

**Purpose**: Identify scanning of multiple IP blocks from a single IP address.

2. **Monitor for Multiple Port Scans**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | summarize port_count=count() by RemoteIP, LocalPort | where port_count > 20
```
{% endcode %}

**Purpose**: Detect scanning of multiple ports by a single IP address.

3. **Detect SYN Scans**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "ConnectionInitiated" and Protocol == "TCP" and TcpFlags == "SYN" | summarize count() by RemoteIP, LocalIP | where count() > 100
```
{% endcode %}

**Purpose**: Identify SYN scanning activity.

4. **Identify ICMP Ping Sweeps**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol == "ICMP" and ICMPType == 8 | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Detect ICMP echo requests (pings) across multiple IP addresses.

5. **Detect Scanning on Common Service Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where LocalPort in (22, 23, 80, 443, 3389) | summarize count() by RemoteIP, LocalPort | where count() > 10
```
{% endcode %}

**Purpose**: Identify scans targeting common service ports.

6. **Monitor for Unusual Network Traffic Patterns**

```cs
DeviceNetworkEvents | summarize count() by RemoteIP, LocalIP | where count() > 200
```

**Purpose**: Detect unusual traffic patterns that may indicate active scanning.

7. **Identify Excessive DNS Queries**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 | summarize count() by RemoteIP, LocalIP | where count() > 100
```
{% endcode %}

**Purpose**: Monitor for excessive DNS queries that may indicate domain reconnaissance.

8. **Detect Network Scanning Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("nmap", "masscan", "zmap") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify known network scanning tools in use.

9. **Monitor for Unusual HTTP Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where HttpMethod == "GET" and URL has_any ("/admin", "/login", "/.git") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

**Purpose**: Detect reconnaissance through unusual HTTP GET requests.

10. **Detect Suspicious Network Connection Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "ConnectionFailed" | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Identify repeated connection failures that may indicate scanning.

### <mark style="color:blue;">**2. T1590 - Gather Victim Network Information**</mark>

**Objective**: Detect activities aimed at collecting information about the target network, such as IP ranges, domain names, and network topology.&#x20;

1. **Monitor for ARP Scans**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol == "ARP" and ActionType == "Request" | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Detect ARP scanning activity used to map network topology.

2. **Identify DNS Zone Transfer Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 and ProcessCommandLine has "axfr" | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor for DNS zone transfer requests that may indicate network reconnaissance.

3. **Detect SMB Enumeration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and ActionType == "Query" | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

**Purpose**: Identify attempts to enumerate SMB shares on the network.

4. **Monitor for LDAP Enumeration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 389 and ActionType == "Query" | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

**Purpose**: Detect LDAP queries that may indicate attempts to gather network information.

5. **Identify Use of Network Mapping Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("net view", "netstat", "route print") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor for the use of network mapping tools.

6. **Detect ICMP Traceroute Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol == "ICMP" and ICMPType == 8 and TTL < 5 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Identify traceroute attempts using ICMP.

7. **Monitor for DNS Query Flooding**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 and ActionType == "Query" | summarize count() by RemoteIP | where count() > 200
```
{% endcode %}

**Purpose**: Detect excessive DNS queries aimed at gathering network information.

8. **Detect TCP/IP Fingerprinting Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol == "TCP" and ActionType == "ConnectionInitiated" | where TcpFlags == "SYN" and TTL > 100 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Identify attempts to fingerprint the network using TCP/IP.

9. **Identify HTTP Enumeration Activity**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("/admin", "/login", "/config") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

**Purpose**: Monitor for HTTP requests that may indicate enumeration of network resources.

10. **Monitor for SNMP Queries**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 161 and ActionType == "Query" | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Detect SNMP queries that may be used to gather network information.

### <mark style="color:blue;">**3. T1592 - Gather Victim Host Information**</mark>

**Objective**: Detect attempts to collect information about victim hosts, including operating system details, hardware configuration, and installed software.&#x20;

1. **Detect Host Fingerprinting Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("systeminfo", "hostname", "ipconfig", "wmic") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify host information gathering commands.

2. **Monitor for Enumeration of Installed Software**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic product get" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect enumeration of installed software on victim hosts.

3. **Detect Querying of System Configuration**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "msinfo32" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Identify attempts to query system configuration.

4. **Identify Registry Enumeration**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where ActionType == "RegistryQuery" | project Timestamp, DeviceName, RegistryKey, RegistryValueName
```
{% endcode %}

**Purpose**: Monitor for enumeration of the Windows registry.

5. **Monitor for OS Version Enumeration**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ver" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect attempts to gather OS version information.

6. **Detect Running Process Enumeration**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "tasklist" or ProcessCommandLine has "pslist" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify enumeration of running processes on victim hosts.

7. **Monitor for PowerShell Reconnaissance Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Get-WmiObject" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect the use of PowerShell commands to gather host information.

8. **Identify Enumeration of Active Network Connections**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "netstat" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Monitor for enumeration of active network connections.

9. **Detect Attempts to Query BIOS Information**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic bios" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify attempts to gather BIOS information.

10. **Monitor for Enumeration of User Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "net user" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect enumeration of user accounts on the host.

### <mark style="color:blue;">**4. T1591 - Gather Victim Identity Information**</mark>

**Objective**: Detect activities aimed at collecting information about user identities, such as account credentials, email addresses, and group memberships.&#x20;

1. **Detect Enumeration of Active Directory Users**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "dsquery user" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify enumeration of Active Directory users.

2. **Monitor for Group Membership Queries**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "net group" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect attempts to enumerate group memberships.

3. **Identify LDAP Queries for User Information**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 389 and ProcessCommandLine has "(&(objectCategory=person)(objectClass=user))" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Monitor for LDAP queries aimed at gathering user information.

4. **Monitor for Attempts to Access Credential Stores**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "rundll32.exe keymgr.dll,KRShowKeyMgr" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect attempts to access stored credentials.

5. **Detect Enumeration of Domain Admin Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "dsquery group -name \"Domain Admins\"" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify attempts to enumerate domain admin accounts.

6. **Monitor for Access to Password Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has_any ("password", "credentials") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

_Purpose_: Detect access to files that may contain passwords.

7. **Detect Enumeration of Service Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "dsquery user -name svc*" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify enumeration of service accounts.

8. **Monitor for Attempts to Query Email Addresses**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "dsquery user -email" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect attempts to gather email addresses from Active Directory.

9. **Identify Enumeration of Privileged Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("net localgroup administrators", "net localgroup Remote Desktop Users") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Monitor for enumeration of privileged accounts.

10. **Detect Attempts to Query Group Policy Information**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "gpresult /R" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify attempts to query group policy information.

### <mark style="color:blue;">**5. T1596 - Search Open Websites/Domains**</mark>

**Objective**: Detect attempts to gather information about the target organization from public websites, domains, and other online resources.&#x20;

1. **Monitor for Access to Public Web Resources**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("linkedin.com", "github.com", "pastebin.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to public websites that may be used for reconnaissance.

2. **Detect Searches for Company Information**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("company.com", "aboutus", "contactus") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for searches related to the target company.

3. **Identify Access to Domain Registration Information**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "whois.domaintools.com" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect attempts to gather domain registration information.

4. **Monitor for Public Code Repository Access**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("github.com", "gitlab.com", "bitbucket.org") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to public code repositories that may contain company information.

5. **Detect Access to Online Forums and Paste Sites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("reddit.com", "pastebin.com", "stackexchange.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor access to online forums and paste sites that may be used to gather information.

6. **Identify Use of Search Engines for Reconnaissance**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("google.com", "bing.com", "duckduckgo.com") and QueryString has_any ("site:", "intitle:", "inurl:") | project Timestamp, DeviceName, URL, QueryString
```
{% endcode %}

_Purpose_: Detect search engine queries that may indicate reconnaissance.

7. **Monitor for Access to Social Media Profiles**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("linkedin.com", "twitter.com", "facebook.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to social media profiles that may be used for gathering information about employees.

8. **Detect Access to Online Employee Directories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "people.company.com" or URL has "employees.company.com" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for access to online employee directories.

9. **Identify Access to Government Websites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any (".gov", ".mil") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect access to government websites that may indicate reconnaissance on publicly available information.

10. **Monitor for Access to Industry-Specific Websites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("financial.com", "healthcare.com", "energy.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to industry-specific websites that may be used for reconnaissance.

### <mark style="color:blue;">**6. T1593 - Search Open Technical Databases**</mark>

**Objective**: Detect attempts to gather information about the target organization from public technical databases, such as vulnerability databases, code repositories, or security forums.&#x20;

1. **Monitor for Access to Vulnerability Databases**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("nvd.nist.gov", "cvedetails.com", "exploit-db.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to vulnerability databases.

2. **Detect Searches for Specific CVEs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where QueryString has "CVE-" and URL has_any ("nvd.nist.gov", "cvedetails.com") | project Timestamp, DeviceName, URL, QueryString
```
{% endcode %}

_Purpose_: Monitor for searches related to specific CVEs.

3. **Identify Access to Public Code Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("github.com", "gitlab.com", "bitbucket.org") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect access to public code repositories that may contain exploitable code.

4. **Monitor for Access to Security Forums**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("forum.exploit-db.com", "community.rapid7.com", "security.stackexchange.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to security forums that may be used for reconnaissance.

5. **Detect Access to Online Penetration Testing Resources**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("offensive-security.com", "metasploit.com", "tools.kali.org") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for access to online resources used for penetration testing.

6. **Identify Use of Search Engines for Technical Information**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("google.com", "bing.com", "duckduckgo.com") and QueryString has_any ("vulnerability", "exploit", "POC") | project Timestamp, DeviceName, URL, QueryString
```
{% endcode %}

_Purpose_: Detect search engine queries related to technical information.

7. **Monitor for Access to Security Research Blogs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("research.securiteam.com", "blogs.akamai.com", "blog.malwarebytes.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to security research blogs.

8. **Detect Access to Public Malware Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("malshare.com", "virusshare.com", "kernelmode.info") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for access to public malware repositories.

9. **Identify Access to Bug Bounty Platforms**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("hackerone.com", "bugcrowd.com", "intigriti.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect access to bug bounty platforms.

10. **Monitor for Access to Open Vulnerability Scanners**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("nessus.org", "openvas.org", "nmap.org") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to open-source vulnerability scanners.

### <mark style="color:blue;">**7. T1594 - Search Open Source Code Repositories**</mark>

**Objective**: Detect attempts to gather information about the target organization from public source code repositories, such as GitHub, GitLab, or Bitbucket.&#x20;

1. **Monitor for Access to Public Code Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("github.com", "gitlab.com", "bitbucket.org") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to public code repositories.

2. **Detect Searches for Company-Related Code**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where QueryString has_any ("companyname", "internalrepo", "secrets") | project Timestamp, DeviceName, URL, QueryString
```
{% endcode %}

_Purpose_: Monitor for searches related to the target company.

3. **Identify Access to Forked Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "forks" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect access to forked repositories that may contain sensitive information.

4. **Monitor for Cloning of Public Repositories**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "git clone" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify attempts to clone public repositories.

5. **Detect Access to Private Code Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "private" and URL has_any ("github.com", "gitlab.com", "bitbucket.org") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for access to private code repositories.

6. **Identify Use of Search Engines to Locate Code Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where QueryString has "repo" and URL has_any ("google.com", "bing.com", "duckduckgo.com") | project Timestamp, DeviceName, URL, QueryString
```
{% endcode %}

_Purpose_: Detect search engine queries aimed at locating code repositories.

7. **Monitor for Access to Public Code Snippets**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "gist.github.com" or URL has "pastebin.com" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to public code snippets that may contain sensitive information.

8. **Detect Access to Publicly Shared Secrets**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("github.com", "gitlab.com") and QueryString has_any ("secret", "key", "password") | project Timestamp, DeviceName, URL, QueryString`
```
{% endcode %}

_Purpose_: Monitor for searches related to secrets in public repositories.

9. **Identify Unauthorized Downloads of Source Code**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "download.zip" or URL has "download.tar.gz" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect unauthorized downloads of source code from public repositories.

10. **Monitor for Access to Deprecated Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "archive" or URL has "deprecated" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to deprecated repositories that may still contain valuable information.

### <mark style="color:blue;">**8. T1597 - Search Closed Sources**</mark>

**Objective**: Detect attempts to gather information from closed sources, such as internal documentation, proprietary software, or private forums.&#x20;

1. **Monitor for Access to Internal Documentation Sites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("wiki.company.com", "confluence.company.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to internal documentation that may contain sensitive information.

2. **Detect Attempts to Access Proprietary Software**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".exe" or FileName endswith ".dll" | where FilePath has_any ("C:\\Program Files\\CompanySoftware", "C:\\Users\\Public\\CompanySoftware") | project Timestamp, DeviceName, FileName, FilePath
```
{% endcode %}

_Purpose_: Monitor for attempts to access proprietary software.

3. **Identify Access to Private Forums or Discussion Boards**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("forum.company.com", "discussions.company.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect access to private forums or discussion boards.

4. **Monitor for Searches in Internal Knowledge Bases**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "knowledgebase.company.com" | project Timestamp, DeviceName, URL, QueryString
```
{% endcode %}

_Purpose_: Identify searches in internal knowledge bases that may indicate reconnaissance.

5. **Detect Unauthorized Access to Internal Git Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "git.company.com" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for unauthorized access to internal Git repositories.

6. **Identify Access to Internal Training Materials**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("training.company.com", "learning.company.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect access to internal training materials that may contain sensitive information.

7. **Monitor for Attempts to Access Internal APIs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has "api.company.com" | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify attempts to access internal APIs.

8. **Detect Access to Internal Bug Tracking Systems**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("jira.company.com", "bugzilla.company.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for access to internal bug tracking systems.

9. **Identify Unauthorized Access to HR Systems**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("hr.company.com", "payroll.company.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect unauthorized access to HR systems.

10. **Monitor for Access to Internal Email Systems**

{% code overflow="wrap" %}
```cs
    DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("mail.company.com", "exchange.company.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify access to internal email systems.

### <mark style="color:blue;">**9. T1598 - Phishing for Information**</mark>

**Objective**: Detect phishing attempts aimed at gathering information from users, such as credentials, financial information, or sensitive documents.&#x20;

1. **Monitor for Emails Containing Suspicious Links**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailBody contains "http://" or EmailBody contains "https://" | project Timestamp, EmailSenderAddress, EmailSubject, EmailBody
```
{% endcode %}

_Purpose_: Identify emails with links that could lead to phishing websites.

2. **Detect Emails Containing Suspicious Attachments**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailAttachmentFileName endswith ".exe" or EmailAttachmentFileName endswith ".js" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}

_Purpose_: Monitor for emails with suspicious attachments.

3. **Identify Emails with Urgent Requests**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "Urgent" or EmailBody contains "immediately" | project Timestamp, EmailSenderAddress, EmailSubject, EmailBody
```
{% endcode %}

_Purpose_: Detect phishing emails using urgency to deceive users.

4. **Monitor for Emails Spoofing Internal Addresses**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where SenderDomain == "internal.company.com" and SenderAddress not in ("trusted_email_list") | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

_Purpose_: Identify emails spoofing internal addresses.

5. **Detect Phishing Emails Targeting Executives**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "CEO" or EmailSubject contains "CFO" | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

_Purpose_: Monitor for phishing emails targeting executives.

6. **Identify Emails Requesting Sensitive Information**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailBody contains "password" or EmailBody contains "account number" | project Timestamp, EmailSenderAddress, EmailSubject, EmailBody
```
{% endcode %}

_Purpose_: Detect emails requesting sensitive information.

7. **Monitor for Emails with Suspicious Reply-To Addresses**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailHeader contains "Reply-To" and EmailHeader contains "external_domain" | project Timestamp, EmailSenderAddress, EmailSubject, EmailHeader
```
{% endcode %}

_Purpose_: Identify emails with suspicious reply-to addresses.

8. **Detect Phishing Emails with Suspicious Macros**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailAttachmentFileName endswith ".docm" or EmailAttachmentFileName endswith ".xlsm" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}

_Purpose_: Monitor for phishing emails with attachments containing macros.

9. **Identify Emails Containing Suspicious Content**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailBody contains "<script>" or EmailBody contains "base64" | project Timestamp, EmailSenderAddress, EmailSubject, EmailBody
```
{% endcode %}

_Purpose_: Detect phishing emails with suspicious content.

10. **Monitor for Suspicious Email Activity Following a Phishing Attempt**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" | summarize count() by TargetUserName, DeviceName, LogonTime | where count() > 5
```
{% endcode %}

_Purpose_: Identify suspicious login activity following a phishing attempt.

### <mark style="color:blue;">**10. T1599 - Social Engineering**</mark>

**Objective**: Detect attempts to manipulate or deceive users to gain information or access, such as through phone calls, messages, or in-person interactions.&#x20;

1. **Monitor for Unusual Outbound Communication**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("slack.com", "discord.com", "telegram.org") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify unusual outbound communication that may indicate social engineering.

2. **Detect Unusual Volume of Emails Sent by a Single User**

```cs
DeviceEmailEvents | summarize count() by SenderAddress | where count() > 100
```

_Purpose_: Monitor for users sending an unusually high volume of emails, possibly as part of a phishing campaign.

3. **Identify Access to Social Media Sites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("linkedin.com", "facebook.com", "twitter.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for access to social media sites that may be used for social engineering.

4. **Monitor for Unauthorized External Phone Calls**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 5060 or RemotePort == 5061 | project Timestamp, DeviceName, RemoteIP, LocalPort
```
{% endcode %}

_Purpose_: Detect unauthorized phone calls made using VoIP.

5. **Detect Unusual Text Messaging Activity**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and URL has_any ("twilio.com", "messagebird.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Identify unusual text messaging activity that may indicate social engineering.

6. **Monitor for Users Accessing Personal Email Accounts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("gmail.com", "yahoo.com", "outlook.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Detect users accessing personal email accounts that may be targeted for social engineering.

7. **Identify Attempts to Access HR Systems**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where URL has_any ("hr.company.com", "payroll.company.com") | project Timestamp, DeviceName, URL, RemoteIP
```
{% endcode %}

_Purpose_: Monitor for unauthorized attempts to access HR systems.

8. **Detect Unauthorized Remote Access Attempts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Identify unauthorized remote access attempts that may indicate social engineering.

9. **Monitor for Unusual Requests for Assistance**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "help" or EmailBody contains "assistance" | project Timestamp, EmailSenderAddress, EmailSubject, EmailBody
```
{% endcode %}

_Purpose_: Detect unusual requests for assistance that may be social engineering attempts.

10. **Identify Attempts to Bypass Security Controls**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("disable", "bypass", "stop") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Monitor for attempts to disable or bypass security controls, which may be related to social engineering.
