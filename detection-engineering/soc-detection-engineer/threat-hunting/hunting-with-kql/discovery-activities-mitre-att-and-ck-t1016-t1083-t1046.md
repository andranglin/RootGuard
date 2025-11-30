# Discovery Activities (MITRE ATT\&CK: T1016, T1083, T1046)

**Note: Sometimes, you may have to customise the queries to your environment. Also, queries will only work if the data is available.**

### **Discovery Activities (MITRE ATT\&CK: T1016, T1083, T1046)**

**Overview:**

Discovery tactics involve gathering information about the network, system, and security settings. Adversaries often use built-in tools to map out the environment and plan further attacks, such as lateral movement.

**25 Example Queries for Actor Discovery Detection:**

1. **Detect Network Enumeration via Netstat**\
   &#xNAN;_&#x4E;etstat reveals active connections, open ports, and listening services._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "netstat.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

2. **Monitor the Use of Ipconfig for Network Discovery**\
   &#xNAN;_&#x49;pconfig provides detailed information about network interfaces._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "ipconfig.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

3. **Track Nslookup for DNS Reconnaissance**\
   &#xNAN;_&#x4E;slookup is used to query DNS records, revealing internal services._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "nslookup.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

4. **Detect ARP Scans for Network Mapping**\
   &#xNAN;_&#x41;rp scans are used to discover devices on the same network segment._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "arp.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

5. **Monitor the Use of Nbtstat for Network Resource Enumeration**\
   &#xNAN;_&#x4E;btstat queries NetBIOS over TCP/IP to reveal network resources._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "nbtstat.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

6. **Track Use of Whoami for Privilege Discovery**\
   &#xNAN;_&#x57;hoami is often used to check the current user’s privileges._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "whoami.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

7. **Detect PowerShell Use for Active Directory Enumeration**\
   &#xNAN;_&#x41;ttackers may use PowerShell to enumerate AD objects and user groups._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has_any ("Get-ADUser", "Get-ADGroup") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

8. **Monitor the Use of Net View for Listing Network Shares**\
   &#xNAN;_&#x4E;et view lists available shares on the network, often used by attackers._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "net.exe" and ProcessCommandLine has "view" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

9. **Track Execution of Tasklist for Process Enumeration**\
   &#xNAN;_&#x54;asklist is used to list all running processes on a system._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "tasklist.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

10. **Detect Execution of Systeminfo for System Information Discovery**\
    &#xNAN;_&#x53;ysteminfo provides information about the operating system and hardware._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "systeminfo.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

11. **Monitor Execution of Net Use for Drive Mapping**\
    &#xNAN;_&#x4E;et use can be used to connect to network drives and shares._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "net.exe" and ProcessCommandLine has "use" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

12. **Track WMIC Commands for System Discovery**\
    &#xNAN;_&#x57;MIC can retrieve information about operating systems, processes, and services._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wmic.exe" and ProcessCommandLine has_any ("os get", "process call create") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

13. **Detect Use of Ping for Host Discovery**\
    &#xNAN;_&#x50;ing is often used to test connectivity and discover active hosts._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "ping.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

14. **Monitor Execution of Route for Network Route Discovery**\
    &#xNAN;_&#x52;oute.exe can display or modify the IP routing table._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "route.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

15. **Detect Use of Getmac for MAC Address Discovery**\
    &#xNAN;_&#x47;etmac retrieves the MAC addresses of network adapters._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "getmac.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

16. **Monitor Unusual SMB Traffic for Network Enumeration**\
    &#xNAN;_&#x53;MB traffic may be indicative of network reconnaissance activities._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and ActionType == "ConnectionSuccess" | summarize count() by DeviceName, RemoteIP, AccountName
```
{% endcode %}

17. **Track Execution of Reg.exe for Registry Enumeration**\
    &#xNAN;_&#x52;eg.exe is used to query or modify Windows registry entries._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "reg.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

18. **Detect Use of NetSh for Network Configuration Changes**\
    &#xNAN;_&#x4E;etSh can be used to query or modify network configurations._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "netsh.exe" and ProcessCommandLine has_any ("firewall", "interface") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

19. **Monitor Execution of PowerShell Network Discovery Scripts**\
    &#xNAN;_&#x50;owerShell scripts can perform various network discovery tasks._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has_any ("Test-Connection", "Get-NetIPAddress") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

20. **Detect Use of Network Sniffing Tools (Tcpdump, Wireshark)**\
    &#xNAN;_&#x4E;etwork sniffing tools can be used for passive network reconnaissance._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("tcpdump.exe", "wireshark.exe") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

21. **Monitor the Use of PsExec for Remote Execution**\
    &#xNAN;_&#x50;sExec is often used to execute commands remotely across the network._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "psexec.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

22. **Track Use of PowerShell Remoting Commands**\
    &#xNAN;_&#x50;owerShell remoting commands such as New-PSSession may indicate lateral movement attempts._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "New-PSSession" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

23. **Monitor Netstat for Port and Connection Enumeration**\
    &#xNAN;_&#x4E;etstat is used to view active network connections and ports._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "netstat.exe" and ProcessCommandLine has "an" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

24. **Detect DNS Query Tools for Domain Discovery (Nslookup, Dig)**\
    &#xNAN;_&#x44;NS query tools like nslookup and dig are used for DNS reconnaissance._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("nslookup.exe", "dig.exe") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

25. **Track Use of GPResult for Group Policy Enumeration**\
    &#xNAN;_&#x47;PResult provides details about applied Group Policy settings._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "gpresult.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}
