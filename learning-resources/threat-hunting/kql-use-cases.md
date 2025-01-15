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

# KQL Use Cases

## **1. Detecting Malware Infection (MITRE ATT\&CK: T1566, T1059)**

#### **Overview:**

Malware infection often involves scripts, executables, and payloads designed to compromise systems, execute commands, or maintain persistence. These infections can lead to lateral movement, data theft, or further compromises within the network.

**Below 25 Example Queries for Malware Infection Detection:**

1. **Detect Suspicious PowerShell Commands (Encoded Commands)**\
   &#xNAN;_&#x50;owerShell encoded commands often indicate obfuscation used in malware payloads._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "encodedCommand" | where InitiatingProcessAccountName !="network service" and InitiatingProcessAccountName !="system"| summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

2. **Identify Execution of Suspicious EXEs from Temp Directories**\
   &#xNAN;_&#x4D;alware often resides in temp directories before execution._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName endswith ".exe" and FolderPath contains "Temp" | where InitiatingProcessAccountName !="network service" and InitiatingProcessAccountName !="system" | summarize count() by DeviceName, InitiatingProcessAccountName, FileName
```
{% endcode %}

3. **Track Use of MSHTA for Malicious Script Execution**\
   &#xNAN;_&#x4D;SHTA is frequently abused to execute malicious scripts._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mshta.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

4. **Detect Rundll32 Execution of Malicious DLLs**\
   &#xNAN;_&#x52;undll32 is often used to execute malicious DLLs, a common malware technique._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "rundll32.exe" and ProcessCommandLine has ".dll" | where InitiatingProcessAccountName !="network service" and InitiatingProcessAccountName !="system" and InitiatingProcessAccountName !="local service" and InitiatingProcessAccountName !="lokaler dienst" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

5. **Monitor Execution of Suspicious Scripting Engines**\
   &#xNAN;_&#x4D;alicious scripts may be executed via WScript or CScript._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("wscript.exe", "cscript.exe") | where InitiatingProcessAccountName !="network service" and InitiatingProcessAccountName !="system" and InitiatingProcessAccountName !="local service" and InitiatingProcessAccountName !="lokaler dienst" and InitiatingProcessAccountName !startswith "sys"  | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

6. **Track EXE File Downloads and Execution via CertUtil**\
   &#xNAN;_&#x43;ertUtil is often abused to download malware payloads._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "certutil.exe" and ProcessCommandLine has "URL" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

7. **Identify Use of LOLBins (Living Off the Land Binaries)**\
   &#xNAN;_&#x43;ommon system binaries like bitsadmin and msiexec are often used in attacks._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("bitsadmin.exe", "msiexec.exe") | where InitiatingProcessAccountName !="network service" and InitiatingProcessAccountName !="system" and InitiatingProcessAccountName !="local service" and InitiatingProcessAccountName !="lokaler dienst" and InitiatingProcessAccountName !startswith "sys" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

8. **Detect Creation of Suspicious Scheduled Tasks**\
   &#xNAN;_&#x4D;alware often uses scheduled tasks for persistence._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "schtasks.exe" and ProcessCommandLine has "create" | where InitiatingProcessAccountName !="system" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

9. **Monitor PowerShell Script Downloads via Invoke-WebRequest**\
   &#xNAN;_&#x49;nvoke-WebRequest is used to download malicious scripts from the internet._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Invoke-WebRequest" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

10. **Track Suspicious Use of Bitsadmin for File Transfers**\
    &#xNAN;_&#x42;itsadmin is sometimes leveraged to download or upload malicious files._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "bitsadmin.exe" and ProcessCommandLine has "transfer" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

11. **Detect New EXE Files in User Directories**\
    &#xNAN;_&#x4E;ew EXE files appearing in user directories may indicate malware delivery._

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".exe" and FolderPath contains "Users" | where InitiatingProcessAccountName != "system" | summarize count() by DeviceName, InitiatingProcessAccountName, FileName, FolderPath
```
{% endcode %}

12. **Monitor Process Spawning from Office Applications**\
    &#xNAN;_&#x4D;alicious macros in Office documents may spawn child processes._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where InitiatingProcessFileName in ("winword.exe", "excel.exe", "powerpnt.exe") | summarize count() by DeviceName, InitiatingProcessAccountName, FileName, FolderPath
```
{% endcode %}

13. **Detect the Use of Task Scheduler to Maintain Persistence**\
    &#xNAN;_&#x53;cheduled tasks can be created by malware to ensure persistence._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "schtasks.exe" and ProcessCommandLine has_any ("create", "add") | where InitiatingProcessAccountName != "system" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

14. **Identify Script Execution via CMD (Batch Scripts)**\
    &#xNAN;_&#x43;MD can be used to execute batch scripts in malware infections._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "cmd.exe" and ProcessCommandLine has_any (".bat", "start") | where InitiatingProcessAccountName != "system" and InitiatingProcessAccountName !startswith "svc-wc" and InitiatingProcessAccountName !startswith "sys_" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

15. **Track PowerShell Use of Bypass Execution Policies**\
    &#xNAN;_&#x4D;alicious PowerShell scripts often bypass execution policies._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "-ExecutionPolicy Bypass" | where InitiatingProcessAccountName != "system" and InitiatingProcessAccountName !startswith "sys_" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine, FolderPath
```
{% endcode %}

16. **Detect DLL Side-Loading or Injection**\
    &#xNAN;_&#x44;LL injection or side-loading is used to execute malicious code within trusted processes._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "rundll32.exe" and ProcessCommandLine has ".dll" | where InitiatingProcessAccountName !="system" and InitiatingProcessAccountName != "lokaler dienst" and InitiatingProcessAccountName != "local service" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

17. **Monitor Unusual Use of MSBuild for Malware Execution**\
    &#xNAN;_&#x4D;SBuild is sometimes leveraged to execute code or load malware._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "MSBuild.exe" | where InitiatingProcessAccountName !startswith "sys_" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

18. **Detect Use of Hidden Windows for Malware Persistence (explorer.exe)**\
    &#xNAN;_&#x4D;alware can use hidden windows to hide its execution from the user._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "explorer.exe" and ProcessCommandLine has "hidden" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

19. **Monitor Suspicious Use of CMD for File Deletion**\
    &#xNAN;_&#x4D;alware may delete files to cover its tracks using the "del" command._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "cmd.exe" and ProcessCommandLine has "del" | where InitiatingProcessAccountName != "system"| summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

20. **Track Use of Remote Desktop Protocol for Malicious Access**\
    &#xNAN;_&#x52;DP is often used to access compromised systems remotely._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess" | where AccountName !startswith "sys_" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

21. **Detect Powershell Execution Using Uncommon Flags**\
    &#xNAN;_&#x4D;alicious scripts may use uncommon flags to bypass detection (e.g., -windowstyle hidden)._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "-windowstyle hidden" | where InitiatingProcessAccountName != "system" and InitiatingProcessAccountName != "network service" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

22. **Monitor the Use of VSSAdmin for Shadow Copy Deletion**\
    &#xNAN;_&#x4D;alware (such as ransomware) may delete volume shadow copies to prevent recovery._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "vssadmin.exe" and ProcessCommandLine has "delete shadows" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

23. **Identify Unusual Network Traffic from Newly Executed Binaries**\
    &#xNAN;_&#x4D;alware often communicates with external C2 servers after execution._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where InitiatingProcessFileName endswith ".exe" and RemoteUrl != "" | where InitiatingProcessAccountName != "system" and InitiatingProcessAccountName != "network service" and InitiatingProcessAccountName != "lokaler dienst" and InitiatingProcessAccountName != "netzwerkdienst" | summarize count() by DeviceName, InitiatingProcessAccountName, RemoteUrl
```
{% endcode %}

24. **Detect Execution of Signed Binaries Used by Attackers**\
    &#xNAN;_&#x41;ttackers may abuse trusted signed binaries for malicious purposes (e.g., regsvr32, msiexec)._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("regsvr32.exe", "msiexec.exe") | where InitiatingProcessAccountName != "system"| summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

25. **Monitor the Use of Certutil for Decoding Malicious Payloads**\
    &#xNAN;_&#x43;ertutil can be used to decode base64-encoded malicious payloads._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "certutil.exe" and ProcessCommandLine has "decode" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

### **2. Discovery Activities (MITRE ATT\&CK: T1016, T1083, T1046)**

**Overview:**

Discovery tactics involve gathering information about the network, system, and security settings. Adversaries often use built-in tools to map out the environment and plan further attacks such as lateral movement.

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

### **3. Credential Theft (MITRE ATT\&CK: T1003, T1078)**

#### **Overview:**

Credential theft involves attackers trying to steal valid user credentials through various means such as credential dumping, brute force, and network sniffing. Once credentials are obtained, adversaries use them for lateral movement or privilege escalation.

**25 Example Queries for Credential Theft Detection:**

1. **Detect LSASS Memory Access (Mimikatz)**\
   &#xNAN;_&#x4D;imikatz is a well-known tool used to extract credentials from LSASS memory._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mimikatz.exe" or ProcessCommandLine has "lsass" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

2. **Monitor Execution of Credential Dumping Tools (e.g., ProcDump)**\
   &#xNAN;_&#x50;rocDump can be used to dump LSASS for credential extraction._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "procdump.exe" and ProcessCommandLine has "lsass" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

3. **Detect Use of DCSync for Credential Replication**\
   &#xNAN;_&#x41;ttackers may use DCSync to impersonate a domain controller and request password hashes._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mimikatz.exe" and ProcessCommandLine has "lsadump::dcsync" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

4. **Track Unusual Access to SAM and SYSTEM Registry Hives**\
   &#xNAN;_&#x43;redential information is stored in the SAM and SYSTEM registry hives._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "reg.exe" and ProcessCommandLine has_any ("save SAM", "save SYSTEM") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

5. **Detect Use of NTDSUtil for Credential Extraction**\
   &#xNAN;_&#x4E;TDSUtil is used to interact with Active Directory databases and can be abused to dump credentials._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "ntdsutil.exe" and ProcessCommandLine has "IFM" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

6. **Monitor PowerShell Credential Dumping Scripts**\
   &#xNAN;_&#x50;owerShell scripts such as Invoke-Mimikatz are used to dump credentials._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Invoke-Mimikatz" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

7. **Track Unauthorized Access to Cached Credentials (VaultCmd)**\
   &#xNAN;_&#x56;aultCmd can be used to list and extract cached credentials._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "vaultcmd.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

8. **Detect Attempts to Dump Password Hashes via SAMR Protocol**\
   &#xNAN;_&#x41;ttackers may use the SAMR protocol to enumerate user accounts and dump password hashes._

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 and ActionType == "ConnectionSuccess" and ProcessCommandLine has "samr" | summarize count() by DeviceName, RemoteIP, AccountName
```
{% endcode %}

9. **Monitor the Use of Tools Like LaZagne for Credential Extraction**\
   &#xNAN;_&#x4C;aZagne is a popular tool used to extract stored credentials._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "lazagne.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

10. **Detect Use of Windows Credential Editor (WCE)**\
    &#xNAN;_&#x57;indows Credential Editor is used to extract password hashes from memory._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wce.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

11. **Track Unusual LSASS Process Access via Task Manager**\
    &#xNAN;_&#x44;irect access to the LSASS process by unauthorized tools may indicate credential dumping._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "taskmgr.exe" and ProcessCommandLine has "lsass" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

12. **Monitor the Use of Net Commands for Account Enumeration**\
    &#xNAN;_&#x4E;et user and net group commands are often used for account and group enumeration._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "net.exe" and ProcessCommandLine has_any ("user", "group") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

13. **Detect Brute Force Attacks by Tracking Multiple Failed Logons**\
    &#xNAN;_&#x4D;ultiple failed logon attempts in a short time may indicate a brute force attack._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where ActionType == "LogonFailed" | summarize count() by AccountName, DeviceName, RemoteIP | where count_ > 5
```
{% endcode %}

14. **Monitor the Use of KERBROAST for Ticket Extraction**\
    &#xNAN;_&#x4B;ERBROAST is used to extract and crack Kerberos ticket hashes._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "Invoke-Kerberoast.ps1" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

15. **Detect Unusual Access to LSA Secrets via Registry Access**\
    &#xNAN;_&#x4C;SA secrets stored in the registry can be accessed to extract credentials._

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey contains "LSA" and ProcessCommandLine has_any ("save", "export") | summarize count() by DeviceName, InitiatingProcessAccountName, RegistryKey
```
{% endcode %}

16. **Monitor the Use of Pass-the-Hash Techniques via NTLM**\
    &#xNAN;_&#x50;ass-the-hash attacks leverage stolen NTLM hashes to authenticate without knowing the password._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "NTLM" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

17. **Detect Attempts to Access LSASS Memory (Handles, Threads)**\
    &#xNAN;_&#x41;ttackers may attempt to access LSASS memory directly using various tools._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("procdump.exe", "taskmgr.exe", "mimikatz.exe") and ProcessCommandLine has "lsass" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

18. **Monitor the Use of CrackMapExec for Credential Attacks**\
    &#xNAN;_&#x43;rackMapExec is a post-exploitation tool that can perform credential-related attacks._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "crackmapexec.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

19. **Track Use of BloodHound for Active Directory Credential Enumeration**\
    &#xNAN;_&#x42;loodHound is a tool used to map AD objects and identify paths for privilege escalation._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "bloodhound.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

20. **Detect Use of Windows Password Recovery Tools (e.g., Cain & Abel)**\
    &#xNAN;_&#x50;assword recovery tools may be used to extract stored credentials._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "cain.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

21. **Monitor the Use of Remote Credential Guard Techniques**\
    &#xNAN;_&#x52;emote Credential Guard is designed to protect against credential theft over RDP sessions._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mstsc.exe" and ProcessCommandLine has "RemoteCredentialGuard" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

22. **Track Usage of Keyloggers for Credential Capture**\
    &#xNAN;_&#x4B;eyloggers may be used to capture credentials as they are typed._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("keylogger.exe", "capture.exe") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

23. **Monitor Tools Like Responder for LLMNR/NBT-NS Poisoning**\
    &#xNAN;_&#x52;esponder is used to capture credentials by poisoning LLMNR and NBT-NS requests._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "responder.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

24. **Detect Enumeration of Windows Credential Guard Status**\
    &#xNAN;_&#x57;indows Credential Guard can be enumerated to determine if it is enabled._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "Get-WinEvent" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

25. **Track Attempts to Exploit Credential Guard Vulnerabilities**\
    &#xNAN;_&#x45;xploitation attempts may target Credential Guard to steal credentials._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "exploit.exe" and ProcessCommandLine has "CredentialGuard" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

### **4. Lateral Movement (MITRE ATT\&CK: T1076, T1021)**

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

### **5. Data Theft (MITRE ATT\&CK: T1041, T1071)**

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

### **6. Execution of Actor Tools and Command-line Activities (MITRE ATT\&CK: T1059)**

**Overview:**

Command-line interfaces (CLI) are often abused by adversaries to execute malicious tools and commands. Monitoring these activities is crucial for detecting malicious behaviour.

**25 Example Queries for Execution of Actor Tools and Command-line Detection:**

1. **Detect PowerShell Execution with Encoded Commands**\
   &#xNAN;_&#x45;ncoded PowerShell commands often indicate obfuscation used in attacks._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "encodedCommand" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

2. **Monitor Execution of Scripts via CMD (Batch Files)**\
   &#xNAN;_&#x42;atch files may be used to automate malicious commands._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "cmd.exe" and ProcessCommandLine has ".bat" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

3. **Track Execution of Python Scripts for Malicious Activities**\
   &#xNAN;_&#x50;ython scripts may be used to execute malicious code._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "python.exe" or ProcessCommandLine has ".py" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

4. **Detect Execution of System Binaries Used by Attackers (LOLBins)**\
   &#xNAN;_&#x41;ttackers often abuse legitimate system binaries (LOLBins) like msiexec, certutil, etc._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("msiexec.exe", "certutil.exe", "rundll32.exe") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

5. **Monitor Execution of VBS Scripts for Malicious Activity**\
   &#xNAN;_&#x56;BS scripts can be used to execute malicious code, download payloads, etc._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wscript.exe" and ProcessCommandLine has ".vbs" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

6. **Detect Use of PowerShell to Bypass Execution Policies**\
   &#xNAN;_&#x4D;alicious PowerShell scripts often bypass execution policies._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has "-ExecutionPolicy Bypass" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

7. **Monitor Use of CertUtil for Malicious File Downloads**\
   &#xNAN;_&#x43;ertUtil is often abused to download and decode malicious payloads._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "certutil.exe" and ProcessCommandLine has "download" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

8. **Track Use of MSHTA for Script Execution (Malicious Activity)**\
   &#xNAN;_&#x4D;SHTA is commonly abused to execute malicious HTML applications._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mshta.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

9. **Detect Use of CMD for Remote Command Execution**\
   &#xNAN;_&#x43;MD may be used to execute commands on remote systems using tools like PsExec._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "cmd.exe" and ProcessCommandLine has_any ("psexec", "wmic", "mstsc") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

10. **Monitor Use of PowerShell for Downloading and Executing Scripts**\
    &#xNAN;_&#x50;owerShell can be used to download and execute malicious scripts._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has_any ("download", "Invoke-WebRequest") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

11. **Track Execution of Python Tools Used by Attackers (e.g., Empire)**\
    &#xNAN;_&#x50;ython-based post-exploitation tools like Empire are often used by attackers._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "python.exe" and ProcessCommandLine has_any ("empire", "exploit") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

12. **Detect Use of PowerShell for Process Injection Techniques**\
    &#xNAN;_&#x50;owerShell scripts may be used to inject malicious code into legitimate processes._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine has_any ("Invoke-ReflectivePEInjection", "Invoke-Mimikatz") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

13. **Monitor the Use of VSSAdmin for Shadow Copy Deletion**\
    &#xNAN;_&#x56;SSAdmin may be used to delete shadow copies, typically seen in ransomware attacks._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "vssadmin.exe" and ProcessCommandLine has "delete shadows" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

14. **Track Use of 7-Zip or WinRAR for Data Compression Before Exfiltration**\
    &#xNAN;_&#x41;ttackers may compress data before exfiltration to minimize detection._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName in ("7z.exe", "winrar.exe") and ProcessCommandLine has "compress" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

15. **Detect Use of Bitsadmin for File Downloads**\
    &#xNAN;_&#x42;itsadmin is often abused to download or transfer malicious files._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "bitsadmin.exe" and ProcessCommandLine has "transfer" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

16. **Monitor the Use of Command-line Tools for User Enumeration**\
    &#xNAN;_&#x43;ommands like net user and net localgroup may be used to enumerate accounts._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "net.exe" and ProcessCommandLine has_any ("user", "localgroup") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

17. **Track Use of Network Scanning Tools (e.g., Nmap)**\
    &#xNAN;_&#x4E;etwork scanning tools may be used by attackers to discover systems and services._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "nmap.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

18. **Detect Use of WMI for Remote Code Execution**\
    &#xNAN;_&#x57;MI is often used to execute commands on remote systems._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wmic.exe" and ProcessCommandLine has_any ("process call create", "os get") | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

19. **Monitor Use of Netstat for Network Discovery**\
    &#xNAN;_&#x4E;etstat is used to list active network connections, which can be abused for discovery._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "netstat.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

20. **Track Execution of SQL Tools for Database Discovery (e.g., SQLCMD)**\
    &#xNAN;_&#x53;QL tools may be used by attackers to query databases and extract information._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "sqlcmd.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

21. **Detect Use of Regsvr32 for Malicious DLL Execution**\
    &#xNAN;_&#x52;egsvr32 can be used to execute DLLs and load malicious code._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "regsvr32.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

22. **Monitor Execution of VBScript Files for Malicious Activity**\
    &#xNAN;_&#x56;BScript files may be used to download, execute, or perform malicious actions._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wscript.exe" and ProcessCommandLine has ".vbs" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

23. **Track Use of Network Monitoring Tools for Reconnaissance (e.g., Wireshark)**\
    &#xNAN;_&#x4E;etwork monitoring tools may be used to capture and analyze network traffic for reconnaissance._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "wireshark.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

24. **Detect Use of Task Scheduler for Remote Command Execution (Schtasks.exe)**\
    &#xNAN;_&#x53;chtasks may be used to schedule and execute tasks on remote systems._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "schtasks.exe" and ProcessCommandLine has "create" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

25. **Monitor Use of Remote Desktop Services for Command Execution**\
    &#xNAN;_&#x52;emote Desktop Services (mstsc.exe) may be used for lateral movement and command execution._

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "mstsc.exe" | summarize count() by DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```
{% endcode %}

### **7. Windows Security Logs (Identity and Logon Activities)**

**Overview:**

Windows Security Logs contain rich information about identity and logon activities. These logs are crucial for detecting unauthorized logons, privilege escalation, and lateral movement.

**25 Example Queries for Identity and Logon Activities:**

1. **Track Successful Logon Events (Event ID 4624)**\
   &#xNAN;_&#x45;vent ID 4624 records successful logon events, which can be analyzed for suspicious activity._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where ActionType == "LogonSuccess" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

2. **Monitor Failed Logon Attempts (Event ID 4625)**\
   &#xNAN;_&#x4D;ultiple failed logon attempts may indicate a brute force attack._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where ActionType == "LogonFailed" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

3. **Track Interactive Logons (LogonType 2, Event ID 4624)**\
   &#xNAN;_&#x49;nteractive logons are physical or RDP logons to a system._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "Interactive" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

4. **Detect Use of Service Accounts for Logon (LogonType 5)**\
   &#xNAN;_&#x53;ervice accounts may be used to maintain persistence within the network._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "Service" | summarize count() by AccountName, DeviceName
```
{% endcode %}

5. **Monitor Privileged Logons (Event ID 4672)**\
   &#xNAN;_&#x50;rivileged accounts logon events can be tracked for signs of abuse._

```cs
DeviceEvents | where EventID == 4672 | summarize count() by AccountName, DeviceName
```

6. **Detect Kerberos Logon Failures (Event ID 4771)**\
   &#xNAN;_&#x46;ailed Kerberos logon attempts may indicate credential theft or brute force attacks._

{% code overflow="wrap" %}
```cs
DeviceEvents | where EventID == 4771 | summarize count() by AccountName, DeviceName, FailureReason
```
{% endcode %}

7. **Track NTLM Logon Events (Event ID 4624)**\
   &#xNAN;_&#x4E;TLM logons can be used for lateral movement through pass-the-hash attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "NTLM" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

8. **Monitor Account Lockout Events (Event ID 4740)**\
   &#xNAN;_&#x41;ccount lockouts may indicate attempted brute force attacks or credential theft._

{% code overflow="wrap" %}
```cs
DeviceEvents | where EventID == 4740 | summarize count() by AccountName, DeviceName, TargetAccountName
```
{% endcode %}

9. **Detect Logon Events During Unusual Hours**\
   &#xNAN;_&#x55;nusual logon times may indicate unauthorized access outside of business hours._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where todatetime(Timestamp) between (datetime(01:00) .. datetime(05:00)) | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

10. **Track Interactive Logon Failures (LogonType 2)**\
    &#xNAN;_&#x46;ailed interactive logons may indicate unauthorized attempts to access a system._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "Interactive" and ActionType == "LogonFailed" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

11. **Detect Unusual Logon Locations for Users (GeoLocation Analysis)**\
    &#xNAN;_&#x55;sers logging in from unusual locations may indicate credential compromise._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | summarize count() by AccountName, DeviceName, GeoLocation | where GeoLocation != "expected_location"
```
{% endcode %}

12. **Monitor Remote Logons Using RDP (Event ID 4624, LogonType 10)**\
    &#xNAN;_&#x52;emote logons using RDP may be an indication of lateral movement or remote access attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

13. **Detect Unsuccessful Logon Attempts for Privileged Accounts**\
    &#xNAN;_&#x46;ailed logon attempts for admin accounts may indicate credential guessing or brute force attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName contains "admin" and ActionType == "LogonFailed" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

14. **Track Use of Temporary or Guest Accounts for Logon**\
    &#xNAN;_&#x54;emporary or guest accounts being used for logon may indicate unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName contains "guest" or AccountName contains "temp" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

15. **Monitor Use of Smartcards for Logon (Event ID 4776)**\
    &#xNAN;_&#x4C;ogons using smartcards can be tracked to ensure they are legitimate._

{% code overflow="wrap" %}
```cs
DeviceEvents | where EventID == 4776 | summarize count() by AccountName, DeviceName
```
{% endcode %}

16. **Detect Logon Attempts Using Stale Credentials (Expired Passwords)**\
    &#xNAN;_&#x52;epeated attempts to logon with expired credentials may indicate an attacker is using stolen credentials._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where Status == "ExpiredPassword" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

17. **Track Failed Logon Attempts Due to Bad Passwords**\
    &#xNAN;_&#x42;ad password failures may indicate a brute force or credential stuffing attack._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where Status == "BadPassword" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

18. **Monitor Use of Shadow Credentials for Logon Attempts**\
    &#xNAN;_&#x53;hadow credentials (e.g., certificate-based) may be used for unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "Certificate" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

19. **Track Successful Logons Using Unusual Account Types (Service, System)**\
    &#xNAN;_&#x55;nusual logon types may indicate an attacker is using system or service accounts._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType in ("Service", "System") | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

20. **Detect Multiple Logon Attempts from a Single IP Address (Credential Stuffing)**\
    &#xNAN;_&#x4D;ultiple logon attempts from the same IP may indicate credential stuffing attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | summarize count() by RemoteIP, AccountName | where count_ > 10
```
{% endcode %}

21. **Monitor Use of Administrative Accounts for Interactive Logons**\
    &#xNAN;_&#x49;nteractive logons using administrative accounts can be tracked for unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName contains "admin" and LogonType == "Interactive" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

22. **Track Unusual Authentication Attempts Using NTLM (Event ID 4624)**\
    &#xNAN;_&#x4E;TLM authentication may be used for lateral movement or unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "NTLM" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

23. **Detect Logons Using Expired or Disabled Accounts**\
    &#xNAN;_&#x4C;ogon attempts using disabled or expired accounts may indicate account compromise._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where Status in ("ExpiredAccount", "DisabledAccount") | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

24. **Monitor Logon Attempts Using Compromised Accounts (Known Breaches)**\
    &#xNAN;_&#x4B;nown compromised accounts from breaches can be monitored for logon attempts._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName in (list_of_compromised_accounts) | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

25. **Track Use of Anonymous Logon Accounts (Event ID 4624, Account: ANONYMOUS)**\
    &#xNAN;_&#x41;nonymous logon attempts may indicate unauthorized access attempts._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName == "ANONYMOUS LOGON" | summarize count() by DeviceName, RemoteIP
```
{% endcode %}

## **Conclusion**

This guide provides SOC analysts with a structured approach to threat hunting in a Windows enterprise environment, leveraging **Microsoft Defender XDR** and focusing on key areas of the **MITRE ATT\&CK Framework**. It covers:

* **Malware infection detection**
* **Discovery activities**
* **Credential theft attempts**
* **Lateral movement detection**
* **Data theft**
* **Command-line activities**
* **Windows Security Log analysis for identity and logon activities**

By regularly performing these searches, SOC teams can proactively detect and respond to emerging threats, mitigating potential damage before attackers escalate their activities.
