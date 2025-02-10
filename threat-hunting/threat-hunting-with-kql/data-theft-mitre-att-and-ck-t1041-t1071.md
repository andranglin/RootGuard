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

# Data Theft (MITRE ATT\&CK: T1041, T1071)

**Note: Sometimes, you may have to customise the queries to your environment. Also, queries will only work if the data is available.**

### **Data Theft (MITRE ATT\&CK: T1041, T1071)**

**Overview:**

Data theft involves the exfiltration of sensitive information from compromised systems. Attackers often use network-based techniques or built-in tools to exfiltrate data to external servers.

**25 Example Queries for Data Theft Detection:**

1. **Monitor Data Exfiltration via FTP (Port 21)**\
   &#xNAN;_&#x46;TP is commonly used for data exfiltration to external servers._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 21 and ActionType == "ConnectionSuccess" | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

2. **Detect HTTP POST Requests to External Servers**\
   &#xNAN;_&#x44;ata exfiltration often occurs via HTTP POST requests._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where HttpMethod == "POST" and RemoteIP not in (expected_ips) | summarize count() by DeviceName, RemoteIP, HttpMethod
```
{% endcode %}

3. **Track Unusual Data Transfers Over SMB (File Copying)**\
   &#xNAN;_&#x44;ata may be exfiltrated over SMB by copying sensitive files._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and ActionType == "FileCopy" | summarize count() by DeviceName, RemoteIP, FileShare
```
{% endcode %}

4. **Monitor Use of Cloud Storage Services for Data Exfiltration**\
   &#xNAN;_&#x41;ttackers may use cloud services (e.g., Dropbox, Google Drive) to exfiltrate data._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "dropbox.com" or RemoteUrl contains "drive.google.com" | summarize count() by DeviceName, RemoteUrl
```
{% endcode %}

5. **Detect Use of PowerShell for File Uploads (Invoke-WebRequest)**\
   &#xNAN;_&#x50;owerShell scripts may use Invoke-WebRequest to exfiltrate data._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Invoke-WebRequest" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

6. **Track Data Exfiltration Attempts Over DNS (DNS Tunneling)**\
   &#xNAN;_&#x44;NS tunneling is used to exfiltrate data over DNS queries._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where DnsQueryType == "TXT" and RemoteIP not in (expected_ips) | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

7. **Monitor Outbound Traffic to Suspicious IPs (External C2)**\
   &#xNAN;_&#x4F;utbound traffic to suspicious or external IP addresses may indicate data exfiltration._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP not in (expected_ips) and ActionType == "ConnectionSuccess" | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

8. **Detect Large Data Transfers Over Non-Standard Ports**\
   &#xNAN;_&#x55;nusually large data transfers over non-standard ports may indicate exfiltration._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where BytesSent > 1000000 and RemotePort between (1024 .. 65535) | summarize count() by DeviceName, RemoteIP, BytesSent
```
{% endcode %}

9. **Monitor Use of File Transfer Protocols (SFTP, SCP) for Data Exfiltration**\
   &#xNAN;_&#x53;FTP and SCP are commonly used for secure file transfers and may be abused for data exfiltration._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort in (22, 443) and ActionType == "FileTransfer" | summarize count() by DeviceName, RemoteIP, RemotePort
```
{% endcode %}

10. **Track Data Exfiltration via Email (Suspicious Attachments)**\
    &#xNAN;_&#x44;ata may be exfiltrated by sending sensitive files as email attachments._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "outlook.exe" and ProcessCommandLine has "attachment" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

11. **Detect Data Transfers via HTTP PUT Requests**\
    &#xNAN;_&#x48;TTP PUT requests may be used to upload data to external servers._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where HttpMethod == "PUT" and RemoteIP not in (expected_ips) | summarize count() by DeviceName, RemoteIP, HttpMethod
```
{% endcode %}

12. **Monitor Large Data Transfers Over RDP (Clipboard Sharing)**\
    &#xNAN;_&#x52;DP clipboard sharing may be used to exfiltrate data during remote sessions._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and ClipboardDataSize > 500000 | summarize count() by AccountName, DeviceName, RemoteIP, ClipboardDataSize
```
{% endcode %}

13. **Track Use of USB Storage Devices for Data Exfiltration**\
    &#xNAN;_&#x55;SB storage devices may be used to copy sensitive data for exfiltration._

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where ActionType == "FileCopy" and DeviceType == "USB" | summarize count() by DeviceName, FileName, FolderPath
```
{% endcode %}

14. **Detect Use of Encrypted Channels for Data Exfiltration (TLS/SSL)**\
    &#xNAN;_&#x45;ncrypted communication channels may be used to hide data exfiltration._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and BytesSent > 1000000 | summarize count() by DeviceName, RemoteIP, BytesSent
```
{% endcode %}

15. **Monitor File Transfers to External FTP Servers**\
    &#xNAN;_&#x46;TP servers may be used to store exfiltrated data._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 21 and ActionType == "FileTransfer" | summarize count() by DeviceName, RemoteIP, BytesSent
```
{% endcode %}

16. **Detect Use of OneDrive for Data Exfiltration**\
    &#xNAN;_&#x4F;neDrive may be used to store sensitive files outside of the corporate network._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "onedrive.live.com" | summarize count() by DeviceName, RemoteUrl, BytesSent
```
{% endcode %}

17. **Track Use of Unapproved Cloud Storage Providers (e.g., Box)**\
    &#xNAN;_&#x44;ata may be exfiltrated to unapproved cloud storage services like Box._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "box.com" | summarize count() by DeviceName, RemoteUrl, BytesSent
```
{% endcode %}

18. **Monitor Data Exfiltration via VPN Services**\
    &#xNAN;_&#x56;PN services may be used to hide data exfiltration activities._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 1194 or RemotePort == 443 and RemoteIP not in (expected_ips) | summarize count() by DeviceName, RemoteIP, RemotePort
```
{% endcode %}

19. **Detect Large Data Transfers Over ICMP (Ping Flooding)**\
    &#xNAN;_&#x49;CMP packets can be used to exfiltrate data in a covert manner._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol == "ICMP" and BytesSent > 100000 | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

20. **Track the Use of Data Compression Tools (e.g., 7-Zip) for Exfiltration**\
    &#xNAN;_&#x41;ttackers may compress files before exfiltrating them to reduce detection._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "7z.exe" or ProcessCommandLine has "compress" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

21. **Monitor Use of Secure Shell (SSH) for Data Exfiltration**\
    &#xNAN;_&#x53;SH connections may be used to exfiltrate data in a secure manner._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 22 and BytesSent > 100000 | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

22. **Detect Use of WebDAV for Data Exfiltration**\
    &#xNAN;_&#x57;ebDAV is a protocol that may be used for file transfer and data exfiltration._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "webdav" and BytesSent > 100000 | summarize count() by DeviceName, RemoteUrl, BytesSent
```
{% endcode %}

23. **Track Use of File Transfer Applications (e.g., FileZilla)**\
    &#xNAN;_&#x46;ile transfer applications may be used to exfiltrate data._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "filezilla.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

24. **Monitor for Unusual Data Exfiltration via Secure File Transfer (HTTPS)**\
    &#xNAN;_&#x48;TTPS may be used to hide data exfiltration in encrypted traffic._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and BytesSent > 1000000 | summarize count() by DeviceName, RemoteIP, BytesSent
```
{% endcode %}

25. **Detect Use of Unapproved Email Clients for Data Exfiltration**\
    &#xNAN;_&#x55;napproved email clients may be used to send sensitive data externally._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("thunderbird.exe", "eudora.exe") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}
