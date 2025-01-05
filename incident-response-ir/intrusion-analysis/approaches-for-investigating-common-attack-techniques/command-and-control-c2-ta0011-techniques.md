---
icon: laptop-code
---

# Command and Control (C2) (TA0011) Techniques

### <mark style="color:blue;">Introduction</mark>

Forensically investigating Command and Control (C\&C) techniques on workstations and server systems involves identifying how an attacker communicates with compromised systems to control them remotely and potentially exfiltrate data. This process is critical for understanding the scope of an attack and mitigating further risks.

#### 1. Understanding Common C\&C Techniques

* **Direct Connections:** Using tools like remote desktop, SSH, or VNC.
* **HTTP/HTTPS-Based Communication:** Often disguised as normal web traffic.
* **DNS-Based Communication:** Using DNS queries to send commands or exfiltrate data.
* **Use of Proxy Servers:** To route and obfuscate the traffic.
* **Social Media and Cloud Services:** Utilising popular platforms to disguise communication.

#### 2. Data Collection and Preservation

* **Forensic Imaging:** Create exact images of affected systems using tools like FTK Imager or dd.
* **Memory Capture:** Use tools like Magnet RAM Capture or WinPmem for capturing volatile memory, which may contain remnants of C\&C communication.
* **Log Collection:** Gather network logs, firewall logs, DNS logs, system logs, and web proxy logs.

#### 3. Network Traffic Analysis

* **Traffic Capture and Analysis:** Use tools like Wireshark or Tcpdump to analyse network traffic for unusual patterns, especially outbound connections to unknown IPs or domains.
* **Protocol Analysis:** Look for anomalies in standard protocols (HTTP, DNS, etc.) that could indicate C\&C activities.
* **Decryption of Traffic:** Where possible, decrypt encrypted network traffic to inspect the contents for command and control communication.

#### 4. DNS Query Analysis

* **Logs Review:** Examine DNS query logs for frequent or irregular requests to uncommon domains, which could be indicative of DNS tunnelling.

#### 5. Firewall and Proxy Logs Analysis

* **Outbound Traffic:** Check for any rules or logs that show unusual outbound traffic, especially traffic bypassing standard network egress points.

#### 6. Endpoint Analysis

* **Running Processes:** Analyse running processes and their network activity for signs of C\&C communications.
* **Startup Items and Scheduled Tasks:** Check for persistence mechanisms that may initiate C\&C communication upon system restart.
* **Host-based Intrusion Detection Systems:** Review alerts and logs for signs of C\&C behaviour.

#### 7. Malware Analysis (if applicable)

* **Static and Dynamic Analysis:** If malware is identified, perform static and dynamic analysis to understand its communication mechanisms.
* **Reverse Engineering:** Reverse-engineering malware may reveal built-in C\&C domains or IP addresses.

#### 8. Use of Specialised Forensic Tools

* **Forensic Suites:** Tools like EnCase, Autopsy, or X-Ways for comprehensive system analysis.
* **Network Analysis Tools:** Wireshark, Tcpdump, NetWitness, NetworkMiner for network traffic analysis.

#### 9. Documentation and Reporting

* **Detailed Documentation:** Record all methodologies, findings, and tools used.
* **Forensic Report:** Compile a comprehensive report detailing the C\&C investigation, findings, and implications.

#### 10. Post-Investigation Actions

* **Mitigation and Remediation:** Implement measures to disrupt the C\&C channels and prevent further unauthorised access.
* **Recovery and Notifications:** Restore systems and notify relevant stakeholders as per organisational and legal requirements.

#### Tools to Consider

* **Forensic Imaging:** EnCase, AXIOM Cyber, FTK Imager, dd
* **Memory Capture:** Magnet RAM Capture, WinPmem
* **Network Analysis:** Wireshark, Tcpdump, NetWitness, NetworkMiner
* **Forensic Suites:** EnCase, AXIOM Cyber, Binalyze-Air, Autopsy

#### Key Considerations

* **Legal Compliance:** Ensure the investigation complies with relevant laws and regulations, especially when decrypting traffic.
* **Chain of Custody:** Maintain an accurate chain of custody for all forensic evidence.
* **Data Confidentiality:** Handle all data securely, maintaining its confidentiality and integrity.

C\&C investigation requires a multi-faceted approach, combining network analysis, endpoint inspection, and potentially malware analysis to fully understand the attacker's methods and impact. Tailoring the investigation to the specifics of the incident and the environment is crucial.

### <mark style="color:blue;">Using KQL to Investigate Command and Control (C2) Activities in an Environment Using Defender/Sentinel</mark>

Command and Control (C2) techniques involve adversaries communicating with compromised systems to control them, exfiltrate data, or execute commands remotely.

### <mark style="color:blue;">**1. T1071.001 - Application Layer Protocol: Web Protocols**</mark>

**Objective**: Detect and investigate the use of web protocols (HTTP/HTTPS) for Command and Control communication.

1. **Detect Unusual HTTP/HTTPS Traffic**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol in ("HTTP", "HTTPS") | summarize count() by RemoteIP, RemoteUrl, DeviceName, InitiatingProcessAccountName | where count_ > 100 // adjust based on network baseline | project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify unusual HTTP/HTTPS traffic patterns that may indicate C2 communication.

2. **Monitor for Suspicious User-Agent Strings**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where UserAgent contains_any ("curl", "wget", "python", "powershell") | project Timestamp, DeviceName, RemoteIP, RemoteUrl, UserAgent, InitiatingProcessAccountName`
```
{% endcode %}

_Purpose_: Detect suspicious or uncommon User-Agent strings used by C2 tools.

3. **Identify HTTP/HTTPS Traffic to Uncommon Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol in ("HTTP", "HTTPS") and RemotePort not in (80, 443) | project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for web traffic over non-standard ports that may indicate C2 communication.

4. **Detect HTTP POST Requests with Large Payloads**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "HTTP" and RequestMethod == "POST" and RequestSize > 100000 | project Timestamp, DeviceName, RemoteIP, RemoteUrl, RequestSize, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify large HTTP POST requests that could be exfiltrating data.

5. **Monitor for HTTP Traffic with Suspicious Headers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "HTTP" and (RequestHeaders has "X-Forwarded-For" or RequestHeaders has "X-Custom-Header") | project Timestamp, DeviceName, RemoteIP, RemoteUrl, RequestHeaders, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect HTTP requests with unusual or suspicious headers that may be used in C2 communication.

6. **Identify HTTP/HTTPS Traffic to Known Malicious Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("malicious.com", "badactor.org") // replace with known malicious domains | project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for HTTP/HTTPS traffic to domains associated with C2 infrastructure.

### <mark style="color:blue;">**2. T1071.004 - Application Layer Protocol: DNS**</mark>

**Objective**: Detect and investigate the use of DNS for Command and Control communication.&#x20;

1. **Detect DNS Queries to Suspicious Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl endswith_any (".xyz", ".top", ".gq") // Example TLDs used by attackers | project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify DNS queries to suspicious top-level domains often used by attackers.

2. **Monitor for High-Frequency DNS Queries**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 | summarize QueryCount = count() by RemoteUrl, DeviceName, InitiatingProcessAccountName | where QueryCount > 100 // adjust based on environment | project Timestamp, DeviceName, RemoteUrl, QueryCount, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect high-frequency DNS queries that may indicate DNS tunneling.

3. **Identify DNS Queries for Uncommon Record Types**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 and DNSQueryType not in ("A", "AAAA", "CNAME") | project Timestamp, DeviceName, RemoteIP, RemoteUrl, DNSQueryType, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DNS queries with uncommon record types that could be used for C2.

4. **Detect DNS Queries with Long or Suspicious Subdomains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 and strlen(RemoteUrl) > 50 | project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify DNS queries with unusually long subdomains that may indicate DNS tunnelling.

5. **Monitor for DNS Queries to Dynamic DNS Providers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("no-ip.com", "dynu.com", "duckdns.org") | project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect DNS queries to dynamic DNS providers, which are often used for C2.

6. **Identify DNS Queries to Known Malicious C2 Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("malicious-dns.com", "attacker-dns.org") // replace with known malicious domains | project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DNS queries to domains associated with C2 infrastructure.

### <mark style="color:blue;">**3. T1095 - Non-Standard Port**</mark>

**Objective**: Detect and investigate the use of non-standard ports for Command and Control communication.&#x20;

1. **Detect Network Traffic on Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort not in (80, 443, 53, 21, 22, 3389) // common ports | project Timestamp, DeviceName, RemoteIP, RemotePort, NetworkProtocol, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify network traffic on uncommon ports that may be used for C2.

2. **Monitor for SSH Traffic on Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "TCP" and RemotePort != 22 and ProcessCommandLine has "ssh" | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect SSH connections on ports other than 22, which may indicate C2 communication.

3. **Identify RDP Traffic on Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "TCP" and RemotePort != 3389 and ProcessCommandLine has "mstsc" | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for RDP connections on ports other than 3389, which may be used for stealthy C2.

4. **Detect Web Traffic on Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol in ("HTTP", "HTTPS") and RemotePort not in (80, 443) | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify HTTP/HTTPS traffic on non-standard ports, which may indicate C2 communication.

5. **Monitor for FTP Traffic on Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "TCP" and RemotePort != 21 and ProcessCommandLine has "ftp" | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect FTP connections on ports other than 21, which may be used for data exfiltration or C2.

6. **Identify Non-Standard Port Usage by Known Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("ncat", "socat", "netcat") and RemotePort not in (80, 443, 53) | project Timestamp, DeviceName, ProcessCommandLine, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of common network tools on non-standard ports.

### <mark style="color:blue;">**4. T1219 - Remote Access Software**</mark>

**Objective**: Detect and investigate the use of remote access software that may be used for C2.&#x20;

1. **Detect Execution of Common Remote Access Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("teamviewer.exe", "anydesk.exe", "vncviewer.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the execution of common remote access tools.

2. **Monitor for Installation of Remote Access Software**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("Software\\TeamViewer", "Software\\AnyDesk", "Software\\RealVNC") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect registry entries related to the installation of remote access software.

3. **Identify Remote Access Traffic Patterns**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("teamviewer", "anydesk", "vnc") | project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for network traffic patterns associated with remote access software.

4. **Detect Use of Remote Access Software Over Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("teamviewer", "anydesk", "vnc") and RemotePort not in (80, 443) | project Timestamp, DeviceName, RemoteUrl, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of remote access software over non-standard ports.

5. **Monitor for PowerShell Commands Installing Remote Access Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Install-TeamViewer", "Install-AnyDesk", "Install-VNC") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell commands used to install remote access tools.

6. **Identify Persistence Mechanisms for Remote Access Software**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") and RegistryValueData has_any ("teamviewer", "anydesk", "vnc") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for persistence mechanisms used by remote access software.

### <mark style="color:blue;">**5. T1105 - Ingress Tool Transfer**</mark>

**Objective**: Detect and investigate the transfer of tools or files into a compromised environment, often used to establish C2 channels.&#x20;

1. **Detect File Downloads from Suspicious Sources**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RequestMethod == "GET" and RemoteUrl contains_any (".exe", ".bat", ".ps1") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify file downloads from potentially malicious sources.

2. **Monitor for Use of PowerShell to Download Files**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell commands used to download files from the internet.

3. **Identify Use of `certutil` for File Download**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "certutil" and ProcessCommandLine has "urlcache" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of `certutil` to download files, often used in fileless attacks.

4. **Detect Use of FTP to Transfer Files**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "ftp" and ProcessCommandLine has_any ("-s:", "ftp.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of FTP commands to transfer files into the environment.

5. **Monitor for Execution of Downloaded Files**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessFileName endswith_any (".exe", ".bat", ".ps1") and FolderPath startswith "C:\\Users\\Public\\Downloads" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the execution of files downloaded to the default Downloads directory.

6. **Identify Files Transferred Over SMB**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "\\\\" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for files transferred over SMB shares, which may be used to introduce C2 tools.

### <mark style="color:blue;">**6. T1213.002 - Data from Information Repositories: Confluence**</mark>

**Objective**: Detect and investigate the use of Confluence (or similar information repositories) for C2 communication or data exfiltration.&#x20;

1. **Detect Access to Confluence Pages**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "confluence" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to Confluence pages, which could be used for data exfiltration or C2 communication.

2. **Monitor for Downloads from Confluence**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "confluence" and RequestMethod == "GET" | summarize DownloadCount = count() by InitiatingProcessAccountName, DeviceName | where DownloadCount > 10 | project Timestamp, InitiatingProcessAccountName, DeviceName, DownloadCoun
```
{% endcode %}

_Purpose_: Detect bulk downloads from Confluence that may indicate data collection or exfiltration.

3. **Identify Confluence API Access for Data Extraction**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "confluence" and RemoteUrl contains "api" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of Confluence APIs to extract data.

4. **Detect Use of PowerShell for Confluence Data Access**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-ConfluencePage", "Export-ConfluencePage", "Connect-ConfluenceService") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands that access or extract data from Confluence.

5. **Monitor for Unusual Access Patterns in Confluence**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "confluence" and TimeGenerated between (startofday(ago(1d))) .. (endofday(ago(1d))) | summarize AccessCount = count() by InitiatingProcessAccountName, RemoteIP | where AccessCount > 50 | project Timestamp, InitiatingProcessAccountName, RemoteIP, AccessCount
```
{% endcode %}

_Purpose_: Detect unusual access patterns to Confluence that may indicate C2 or exfiltration activities.

6. **Identify Large Data Transfers from Confluence**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "confluence" and NetworkProtocol == "HTTP" and TotalBytes > 5000000 | project Timestamp, DeviceName, RemoteUrl, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for large data transfers from Confluence, which could indicate significant data exfiltration.

### <mark style="color:blue;">**7. T1102.001 - Web Service: Dead Drop Resolver**</mark>

**Objective**: Detect and investigate the use of dead drop resolvers (e.g., pastebin or GitHub) for C2 communication.

1. **Detect Access to Known Dead Drop Sites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("pastebin.com", "gist.github.com", "paste.ee") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to dead drop sites commonly used for C2 communication.

2. **Monitor for Suspicious Pastebin or GitHub Gist Access**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("pastebin.com", "gist.github.com") | project Timestamp, DeviceName, RemoteUrl, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect suspicious GET or POST requests to pastebin or GitHub Gists that may be used for C2.

3. **Identify Access to Newly Created Pastes or Gists**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "pastebin.com/raw" or RemoteUrl contains "gist.github.com/raw" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for access to newly created pastes or gists, which could be used as dead drops.

4. **Detect Unusual Traffic to Dead Drop Sites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("pastebin.com", "gist.github.com") | summarize AccessCount = count() by InitiatingProcessAccountName, RemoteIP | where AccessCount > 10 | project Timestamp, InitiatingProcessAccountName, RemoteIP, AccessCount
```
{% endcode %}

_Purpose_: Identify repeated or unusual access to dead drop sites that may indicate C2 activity.

5. **Monitor for Use of PowerShell to Access Dead Drop Sites**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Invoke-WebRequest", "Invoke-RestMethod") and ProcessCommandLine has_any ("pastebin", "github") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell scripts accessing dead drop sites for C2 communication.

6. **Identify Download of C2 Instructions from Dead Drop Sites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("pastebin.com/raw", "gist.github.com/raw") and RequestMethod == "GET" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for downloads of C2 instructions from dead drop sites.

### <mark style="color:blue;">**8. T1210 - Exploitation of Remote Services**</mark>

**Objective**: Detect and investigate the exploitation of remote services to establish C2 channels.&#x20;

1. **Detect Exploitation Attempts via RDP**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Failed" | project Timestamp, DeviceName, AccountName, LogonResult, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify failed RDP logon attempts that may indicate exploitation attempts.

2. **Monitor for Exploitation of SSH**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 22 and ActionType == "NetworkSessionDenied" | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect SSH connection attempts that are denied, which may indicate exploitation attempts.

3. **Identify Suspicious SMB Activity**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and (ActionType == "FileShareAccessDenied" or ActionType == "AccessDenied") | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for suspicious SMB activity, such as repeated access denied events.

4. **Detect Exploitation of Web Services**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "HTTP" and RemotePort == 80 and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify web exploitation attempts using HTTP POST requests.

5. **Monitor for Vulnerability Scanning Activity**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort in (80, 443, 22, 3389) and RequestMethod == "OPTIONS" | project Timestamp, DeviceName, RemoteIP, RemotePort, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect vulnerability scanning activity that may precede exploitation attempts.

6. **Identify Exploitation of Remote Services via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Invoke-Command", "New-PSSession", "Enter-PSSession") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for PowerShell commands attempting to exploit remote services.
