---
icon: laptop-code
---

# Exfiltration (TA0010) Techniques

### <mark style="color:blue;">Introduction</mark>

Investigating data exfiltration forensically on workstations and server systems involves identifying and analysing how sensitive data was transferred from the network. This process is critical in understanding the scope of a security breach. Exfiltration can occur in various ways, including unauthorised email transmissions, external storage devices, cloud storage uploads, and covert channels.

#### Understanding Common Exfiltration Techniques

* **Email Transmission:** Unauthorised sending of sensitive data via email.
* **Removable Media:** Copying data to USB drives or other removable media.
* **Network Transfer:** Utilising FTP, HTTP, or other protocols to transfer data to external servers.
* **Cloud Storage:** Uploading data to cloud storage services.
* **Encrypted Channels:** Using VPNs, SSH tunnels, or other encrypted methods to hide data transmission.

#### Data Collection and Preservation

* **Forensic Imaging:** Create exact images of the hard drives of affected systems using tools like FTK Imager or dd.
* **Memory Capture:** Use tools like Magnet RAM Capture or WinPmem to capture volatile memory.
* **Log Collection:** Gather network logs, firewall logs, system logs, and application logs.

#### Email Analysis

* **Email Server Logs:** Review logs for signs of large email transmissions or emails sent to unusual external addresses.
* **Email Client Analysis:** Examine the email clients on affected systems for sent items, drafts, or deleted emails.

#### Removable Media Analysis

* **USB Device History:** Windows stores a history of connected USB devices in the registry. Examine this for evidence of any unknown devices.
* **File System Analysis:** Check for recently accessed files or file copies that coincide with the connection times of external media.

#### Network Traffic Analysis

* **Network Monitoring Tools:** Use tools like Wireshark or Tcpdump to analyse captured network traffic for data transfers to unusual external IP addresses.
* **Firewall and Proxy Logs:** Review logs for large data transfers or connections to known file-sharing or cloud storage sites.

#### Cloud Storage and Web Uploads

* **Browser History and Cookies:** Examine web browser history and cookies for access to cloud storage websites.
* **Web Proxy Logs:** Analyse web proxy logs for uploads to cloud services.

#### Analysing Encrypted Traffic

* **Decrypting Traffic:** Where possible and legal, decrypt encrypted network traffic to inspect the contents.
* **TLS/SSL Certificate Analysis:** Review certificates for any unrecognised or self-signed certificates that may have been used in exfiltration.

#### File Access and Movement Analysis

* **File Access Logs:** Review logs for files being accessed that contain sensitive information.
* **Recent Documents and File Timestamps:** Examine recent documents and file timestamps for evidence of copying or accessing large volumes of data.

#### Use of Specialised Forensic Tools

* **Forensic Suites:** Tools like EnCase, Autopsy, or AXIOM Cyber for comprehensive analysis.
* **Network Analysis Tools:** Wireshark, Tcpdump, NetWitness for network traffic analysis.

#### Documentation and Reporting

* **Detailed Documentation:** Keep a detailed record of all findings, tools used, and investigative processes.
* **Forensic Report:** Prepare a comprehensive report detailing the exfiltration methods identified, data compromised, and impact assessment.

#### Post-Investigation Actions

* **Mitigation and Remediation:** Implement necessary security measures to prevent future incidents.
* **Recovery and Notifications:** Follow organisational and legal protocols for data breach response, including notifying affected parties if necessary.

#### Key Considerations

* **Legal Compliance:** Ensure the investigation complies with legal and regulatory requirements, especially when dealing with encrypted traffic and privacy-sensitive data.
* **Data Confidentiality:** Maintain strict confidentiality and integrity of data throughout the investigation process.
* **Chain of Custody:** Maintain a clear chain of custody for all evidence collected.

Forensic investigations of data exfiltration require careful analysis of various data sources and the application of appropriate forensic techniques. Tailoring the investigation to the specifics of the incident and the nature of the data involved is crucial.

### <mark style="color:blue;">Using KQL to Investigate Data Exfiltration Activities in an Environment Using Defender/Sentinel</mark>

Exfiltration techniques involve adversaries stealing data from a compromised network or system and transferring it to an external location under their control.

### <mark style="color:blue;">**1. T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol**</mark>

**Objective**: Detect attempts to exfiltrate data using unencrypted or obfuscated protocols that are not typically used for Command and Control.&#x20;

1. **Detect Data Exfiltration Over FTP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 21 and RequestMethod == "PUT" | project Timestamp, DeviceName, RemoteIP, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify FTP PUT requests used to upload files to an external FTP server.

2. **Monitor for Exfiltration Over HTTP Using Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "HTTP" and RemotePort not in (80, 443) and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteIP, RemotePort, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect HTTP POST requests on non-standard ports that may be used for exfiltration.

3. **Identify Large Data Transfers Over FTP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 21 and TotalBytes > 10000000 | project Timestamp, DeviceName, RemoteIP, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for large file uploads over FTP, indicating potential data exfiltration.

4. **Detect Exfiltration Over SMTP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 25 and RequestMethod == "DATA" | project Timestamp, DeviceName, RemoteIP, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify SMTP DATA commands that could be used to send sensitive data via email.

5. **Monitor for DNS-Based Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 and DNSQueryType not in ("A", "AAAA", "CNAME") | project Timestamp, DeviceName, RemoteIP, DNSQueryType, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect DNS queries with uncommon record types, which could indicate DNS tunneling for data exfiltration.

6. **Identify Exfiltration Over ICMP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "ICMP" and TotalBytes > 1000 | project Timestamp, DeviceName, RemoteIP, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for large ICMP packets, which may be used to exfiltrate data.

### <mark style="color:blue;">**2. T1052.001 - Exfiltration Over Physical Medium: USB Drive**</mark>

**Objective**: Detect attempts to exfiltrate data via physical media, such as USB drives.

1. **Detect USB Drive Insertion**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "RemovableMediaInserted" | project Timestamp, DeviceName, RemovableMediaName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify when a USB drive is inserted into a system, which could be used for data exfiltration.

2. **Monitor for File Transfers to USB Drives**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "E:\\" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, FileOperation, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect files being copied to a USB drive, which could indicate data exfiltration.

3. **Identify Execution of Files from USB Drives**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FolderPath startswith "E:\\" and ProcessCommandLine has ".exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the execution of files directly from a USB drive.

4. **Detect Unusual Activity on USB Drives**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "E:\\" and FileOperation == "Delete" | project Timestamp, DeviceName, FileName, FolderPath, FileOperation, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify file deletions on USB drives, which may be an attempt to cover tracks after data exfiltration.

5. **Monitor for Large Data Transfers to USB Drives**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath startswith "E:\\" and FileSize > 10000000 | project Timestamp, DeviceName, FileName, FolderPath, FileSize, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect large files being transferred to a USB drive, indicating potential exfiltration.

6. **Identify Suspicious USB Drive Activity by Non-Admin Users**

{% code overflow="wrap" %}
```cs
DeviceEvents | where ActionType == "RemovableMediaInserted" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, RemovableMediaName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for USB drive usage by non-admin users, which may be unusual in a secured environment.

### <mark style="color:blue;">**3. T1041 - Exfiltration Over C2 Channel**</mark>

**Objective**: Detect attempts to exfiltrate data over established Command and Control (C2) channels.&#x20;

1. **Detect Data Sent to Known C2 Servers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("malicious.com", "c2server.net") // replace with known C2 domains | project Timestamp, DeviceName, RemoteIP, RemoteUrl, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify data exfiltration attempts to known C2 servers.

2. **Monitor for Large POST Requests to External IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RequestMethod == "POST" and TotalBytes > 100000 and RemoteIP != "192.168.1.1" // replace with internal IP range | project Timestamp, DeviceName, RemoteIP, TotalBytes, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect large POST requests to external IPs that could be used for data exfiltration.

3. **Identify Unusual C2 Channel Activity After Hours**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where TimeGenerated between (startofday(ago(1d))) .. (endofday(ago(1d))) and RemoteUrl contains_any ("c2server.net", "malicious.com") | project Timestamp, DeviceName, RemoteUrl, RemoteIP, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for C2 channel activity outside of normal business hours, which could indicate exfiltration.

4. **Detect C2 Channels Using Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort not in (80, 443) and RemoteUrl contains_any ("c2server.net", "malicious.com") | project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify C2 channels that are exfiltrating data using non-standard ports.

5. **Monitor for Encrypted Traffic to Untrusted IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where NetworkProtocol == "HTTPS" and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | project Timestamp, DeviceName, RemoteIP, RemotePort, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect encrypted traffic to external IP addresses that could be exfiltrating data.

6. **Identify Suspicious DNS Tunneling Activity**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where DNSQueryType not in ("A", "AAAA", "CNAME") and TotalBytes > 1000 | project Timestamp, DeviceName, RemoteIP, DNSQueryType, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DNS tunneling activity that could be used for data exfiltration.

### <mark style="color:blue;">**4. T1020 - Automated Exfiltration**</mark>

**Objective**: Detect and investigate automated processes that continuously exfiltrate data from the environment.&#x20;

1. **Detect Scheduled Tasks for Data Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks" and ProcessCommandLine has_any ("export", "copy", "move") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify scheduled tasks configured to automate data exfiltration.

2. **Monitor for Automated File Transfers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RequestMethod == "PUT" and RemoteUrl contains_any (".ftp", ".sftp", ".http") | project Timestamp, DeviceName, RemoteIP, RequestMethod, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect automated file transfers to external servers.

3. **Identify Use of PowerShell for Automated Data Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Start-Job", "Invoke-WebRequest", "Export-CSV") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for PowerShell scripts that automate data exfiltration tasks.

4. **Detect Use of Automated Exfiltration Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("rsync", "curl", "wget") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of tools that automate data transfers to external servers.

5. **Monitor for Continuous Network Activity to External IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | summarize ContinuousConnection = count() by RemoteIP, DeviceName, InitiatingProcessAccountName | where ContinuousConnection > 100 | project Timestamp, DeviceName, RemoteIP, ContinuousConnection, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect continuous or persistent network connections to external IPs that could indicate automated exfiltration.

6. **Identify Repeated Attempts to Exfiltrate Data**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | summarize RepeatAttempts = count() by RemoteIP, DeviceName, InitiatingProcessAccountName | where RepeatAttempts > 10 | project Timestamp, DeviceName, RemoteIP, RepeatAttempts, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for repeated exfiltration attempts to external IPs.

### <mark style="color:blue;">**5. T1030 - Data Transfer Size Limits**</mark>

**Objective**: Detect and investigate attempts to exfiltrate data while staying under network or data transfer size limits to avoid detection.&#x20;

1. **Detect Multiple Small Data Transfers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where TotalBytes < 50000 and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | summarize TransferCount = count() by RemoteIP, DeviceName, InitiatingProcessAccountName | where TransferCount > 20 | project Timestamp, DeviceName, RemoteIP, TransferCount, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify multiple small data transfers that could be an attempt to avoid detection.

2. **Monitor for Continuous Data Transfers Staying Below Size Limits**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where TotalBytes between (10000 .. 50000) and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | project Timestamp, DeviceName, RemoteIP, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect continuous data transfers that stay below common detection thresholds.

3. **Identify Repeated Small Exfiltration Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where TotalBytes < 50000 and RequestMethod == "POST" | summarize RepeatAttempts = count() by RemoteIP, DeviceName, InitiatingProcessAccountName | where RepeatAttempts > 10 | project Timestamp, DeviceName, RemoteIP, RepeatAttempts, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for repeated small exfiltration attempts via POST requests.

4. **Detect Stealthy Exfiltration Using Non-Standard Ports**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where TotalBytes < 50000 and RemotePort not in (80, 443) | project Timestamp, DeviceName, RemoteIP, RemotePort, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify data exfiltration attempts using non-standard ports while keeping transfer sizes small.

5. **Monitor for Exfiltration Via Chunked Transfer Encoding**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RequestHeaders has "Transfer-Encoding: chunked" | project Timestamp, DeviceName, RemoteIP, RequestMethod, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect exfiltration attempts using chunked transfer encoding to bypass size limits.

6. **Identify Exfiltration Attempts to Unusual IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | project Timestamp, DeviceName, RemoteIP, RemotePort, TotalBytes, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for exfiltration attempts to unusual or unrecognized external IP addresses.
