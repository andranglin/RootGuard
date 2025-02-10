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

# Credential Theft (MITRE ATT\&CK: T1003, T1078)

**Note: Sometimes, you may have to customise the queries to your environment. Also, queries will only work if the data is available.**

### **Credential Theft (MITRE ATT\&CK: T1003, T1078)**

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
