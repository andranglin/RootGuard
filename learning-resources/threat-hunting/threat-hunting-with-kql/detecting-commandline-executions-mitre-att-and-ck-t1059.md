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

# Detecting CommandLine Executions (MITRE ATT\&CK: T1059)

**Note: Sometimes, you may have to customise the queries to your environment. Also, queries will only work if the data is available.**

### **Execution of Actor Tools and Command-line Activities (MITRE ATT\&CK: T1059)**

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
