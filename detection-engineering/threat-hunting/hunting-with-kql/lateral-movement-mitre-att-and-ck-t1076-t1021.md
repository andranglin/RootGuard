# Lateral Movement (MITRE ATT\&CK: T1076, T1021)

**Note: Sometimes, you may have to customise the queries to your environment. Also, queries will only work if the data is available.**

### **Lateral Movement (MITRE ATT\&CK: T1076, T1021)**

**Overview:**

Lateral movement involves attackers gaining access to additional systems within the network after an initial compromise. Techniques include using RDP, SMB, or administrative tools like PsExec to move between hosts.

**25 Eample Queries for Lateral Movement Detection:**

1. **Track RDP Logins (RemoteInteractive Logon Type)**\
   &#xNAN;_&#x52;DP logons can be used for lateral movement to access remote systems._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

2. **Detect PsExec Use for Remote Command Execution**\
   &#xNAN;_&#x50;sExec is a popular tool for executing commands on remote systems._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "psexec.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

3. **Monitor SMB Traffic for Lateral Movement**\
   &#xNAN;_&#x53;MB (Port 445) can be used for file transfer and lateral movement between systems._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and ActionType == "ConnectionSuccess" | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

4. **Detect Remote PowerShell Sessions for Lateral Movement**\
   &#xNAN;_&#x50;owerShell remoting is often used for lateral movement within a Windows environment._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "New-PSSession" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

5. **Track Use of WMI for Remote Code Execution**\
   &#xNAN;_&#x57;MI can be used to execute commands remotely on other systems._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wmic.exe" and ProcessCommandLine has_any ("process call", "os get") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

6. **Monitor Remote Service Creation (SC.exe)**\
   &#xNAN;_&#x53;C.exe is used to create or modify services on remote systems for lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "sc.exe" and ProcessCommandLine has "create" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

7. **Detect New Scheduled Tasks for Lateral Movement**\
   &#xNAN;_&#x53;cheduled tasks may be created on remote systems to maintain persistence or execute code._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "schtasks.exe" and ProcessCommandLine has "create" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

8. **Track Lateral Movement via Administrative Shares (e.g., ADMIN$)**\
   &#xNAN;_&#x41;ttackers may use administrative shares for lateral movement._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and FileShare == "ADMIN$" | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

9. **Monitor Use of Net Use for Remote Drive Mapping**\
   &#xNAN;_&#x4E;et use can be used to map network drives and facilitate lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "net.exe" and ProcessCommandLine has "use" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

10. **Detect RDP Logon Attempts from Unusual IPs**\
    &#xNAN;_&#x55;nusual RDP logon attempts may indicate unauthorized lateral movement._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and RemoteIP not in (expected_ips) | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

11. **Track Use of WinRM for Remote Command Execution**\
    &#xNAN;_&#x57;inRM is commonly used for remote administration and lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "winrm.cmd" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

12. **Monitor Use of Remote Desktop for Unusual Sessions**\
    &#xNAN;_&#x52;DP may be used to move laterally and establish persistence._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mstsc.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

13. **Detect Unusual Administrative Logon Activity (Event ID 4672)**\
    &#xNAN;_&#x54;racking privileged logons can help detect lateral movement via administrative accounts._

{% code overflow="wrap" %}
```cs
DeviceEvents | where EventID == 4672 | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

14. **Track SMB Logons via Pass-the-Hash Techniques**\
    &#xNAN;_&#x50;ass-the-Hash can be used for lateral movement by leveraging NTLM hashes._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "NTLM" and LogonType == "Network" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

15. **Monitor Remote Access via Non-Standard Ports (RDP)**\
    &#xNAN;_&#x52;DP access via non-standard ports may indicate lateral movement._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort != 3389 and RemotePort between (1024 .. 65535) | summarize count() by DeviceName, RemoteIP, RemotePort
```
{% endcode %}

16. **Detect Lateral Movement via Hidden Network Shares**\
    &#xNAN;_&#x48;idden network shares (e.g., C$, ADMIN$) may be used for lateral movement._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where FileShare in ("C$", "ADMIN$") | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

17. **Monitor PowerShell Remoting Commands for Lateral Movement**\
    &#xNAN;_&#x50;owerShell remoting commands such as Enter-PSSession may be used for lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Enter-PSSession" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

18. **Track SMB Traffic for Remote File Access (Port 445)**\
    &#xNAN;_&#x53;MB traffic to shared folders may indicate lateral movement activities._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and ActionType == "ConnectionSuccess" | summarize count() by DeviceName, RemoteIP, FileShare
```
{% endcode %}

19. **Detect Remote File Transfers via SMB (Net Use Commands)**\
    &#xNAN;_&#x4E;et use commands may be used to transfer files over SMB for lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "net.exe" and ProcessCommandLine has "use" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

20. **Monitor Network Scanning Tools Used for Lateral Movement (e.g., Nmap)**\
    &#xNAN;_&#x4E;etwork scanning tools like Nmap may be used to identify targets for lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("nmap.exe", "masscan.exe") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

21. **Track Access to Hidden Administrative Shares (IPC$)**\
    &#xNAN;_&#x41;ccess to IPC$ shares may be indicative of lateral movement or reconnaissance._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where FileShare == "IPC$" | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

22. **Detect Use of WMI for Remote Service Creation**\
    &#xNAN;_&#x57;MI may be used to create services on remote systems for lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wmic.exe" and ProcessCommandLine has "create" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

23. **Monitor Remote Desktop Sessions from Unusual Geographic Locations**\
    &#xNAN;_&#x52;DP sessions from unexpected locations may indicate lateral movement or unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and GeoLocation != "expected_geo" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

24. **Track Use of Administrative Tools for Remote Access (e.g., WinSCP)**\
    &#xNAN;_&#x54;ools like WinSCP may be used for remote access and file transfer during lateral movement._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "winscp.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

25. **Monitor Use of RDP for Unusual Logon Times (Off-Hours Access)**\
    &#xNAN;_&#x52;DP logons during unusual hours may indicate unauthorized lateral movement._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and todatetime(Timestamp) between (datetime(00:00) and datetime(06:00)) | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}
