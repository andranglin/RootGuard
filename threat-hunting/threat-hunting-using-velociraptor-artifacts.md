---
icon: laptop-code
---

# Threat Hunting Using Velociraptor Artifacts

## Hunting for Ransomware Activities

Ransomware remains one of the most pervasive and damaging cyber threats organisations face today. It involves malicious software designed to encrypt data and demand ransom payments for its release. Hunting for ransomware activities is a proactive approach to detect and mitigate ransomware before it can execute its payload. This process leverages threat intelligence, behavioural analytics, and advanced tools like Velociraptor to uncover the early signs of ransomware infection. Velociraptor, an open-source endpoint monitoring and forensic platform, excels at detecting indicators such as unusual file access patterns, lateral movement, and unauthorised data exfiltration. By integrating Velociraptor into their ransomware hunting practices, organisations can significantly reduce their exposure to this growing threat and enhance their overall cybersecurity posture.

### 1. **Detecting Malware Infection**

**Description:** Malware infection detection involves identifying signs of compromise through executable files, persistence mechanisms, and suspicious behaviour. This section focuses on detecting malware that could be infecting systems through various techniques.

**25 Example Velociraptor Artifacts:**

1. **Artifact Name:** `Windows.System.Pslist`&#x20;
   * **Description:** Lists running processes to identify suspicious or malicious executables, such as those frequently associated with malware infections.
2. **Artifact Name:** `Windows.System.Autoruns`&#x20;
   * **Description:** Identifies autorun entries, which may be exploited by malware for persistence.
3. **Artifact Name:** `Windows.Registry.PersistKeys`&#x20;
   * **Description:** Detects registry keys commonly used by malware to establish persistence.
4. **Artifact Name:** `Windows.Services.Config`&#x20;
   * **Description:** Monitors Windows services that could be abused or created by malware to maintain persistence.
5. **Artifact Name:** `Windows.FileSystem.TempFiles`&#x20;
   * **Description:** Searches for suspicious executable files in temporary directories like `C:\Windows\Temp` and `C:\Users\Public`.
6. **Artifact Name:** `Windows.ScheduledTasks`&#x20;
   * **Description:** Detects non-default scheduled tasks that could be created by malware for recurring execution.
7. **Artifact Name:** `Windows.Prefetch.List`&#x20;
   * **Description:** Analyzes prefetch files to identify malware that has been executed on the system.
8. **Artifact Name:** `Windows.System.StartupItems`&#x20;
   * **Description:** Gathers information about items configured to start with Windows, which may be exploited by malware.
9. **Artifact Name:** `Windows.Network.Connections`&#x20;
   * **Description:** Identifies active network connections that may indicate malware communicating with a command-and-control (C2) server.
10. **Artifact Name:** `Windows.FileSystem.MalwareFiles`&#x20;
    * **Description:** Searches for known malware file hashes in common directories.

### 2. **Actor Discovery Activities**

**Description:** Discovery activities involve attackers attempting to gather information about the environment, including systems, users, and network shares. Monitoring these activities can provide early indicators of compromise.

**25 Example Velociraptor Artifacts:**

11. **Artifact Name:** `Windows.Network.Connections`&#x20;
    * **Description:** Lists current network connections to detect port scanning or enumeration tools like `nmap`.
12. **Artifact Name:** `Windows.System.PowerShellHistory`&#x20;
    * **Description:** Reviews PowerShell command history to detect discovery commands such as `Get-Process` or `Get-ADUser`.
13. **Artifact Name:** `Windows.SMBClientShares`&#x20;
    * **Description:** Identifies remote SMB shares that have been accessed, potentially indicating reconnaissance activities.
14. **Artifact Name:** `Windows.System.Netstat`&#x20;
    * **Description:** Tracks network statistics to detect anomalous connections or network discovery activities.
15. **Artifact Name:** `Windows.WMI.Event`&#x20;
    * **Description:** Monitors for suspicious use of Windows Management Instrumentation (WMI) for discovery purposes.
16. **Artifact Name:** `Windows.System.EnvironmentVariables`&#x20;
    * **Description:** Checks for environment variable manipulations, often used to discover system information or misconfigurations.
17. **Artifact Name:** `Windows.System.Sysinfo`&#x20;
    * **Description:** Provides system information that attackers often query during the discovery phase (e.g., `systeminfo.exe`).
18. **Artifact Name:** `Windows.Security.LocalAccounts`&#x20;
    * **Description:** Lists local user accounts, which could indicate attackers querying for users or groups.
19. **Artifact Name:** `Windows.Network.ListAdapters`&#x20;
    * **Description:** Monitors network adapter information for changes or signs of network discovery.
20. **Artifact Name:** `Windows.Audit.AccountLogonEvents`&#x20;
    * **Description:** Captures events related to user logon activities, which attackers often target during discovery.

### 3. **Credential Theft Attempts**

**Description:** Credential theft enables attackers to escalate privileges or move laterally across systems. These artifacts focus on detecting malicious attempts to dump or steal credentials from memory, registries, or credential stores.

**25 Example Velociraptor Artifacts:**

21. **Artifact Name:** `Windows.Registry.SAM`&#x20;
    * **Description:** Collects information from the Security Account Manager (SAM) database, often targeted in credential dumping attacks.
22. **Artifact Name:** `Windows.Handles.LSASS`&#x20;
    * **Description:** Monitors for processes attempting to access LSASS (Local Security Authority Subsystem Service) memory, a common target for credential theft.
23. **Artifact Name:** `Windows.System.CredentialGuard`&#x20;
    * **Description:** Examines Credential Guard settings to check if credentials are protected against theft.
24. **Artifact Name:** `Windows.Registry.DPAPI`&#x20;
    * **Description:** Monitors for decryption attempts on Data Protection API (DPAPI) credentials.
25. **Artifact Name:** `Windows.EventLog.Security_4625`
    * **Description:** Gathers failed logon attempt events (Event ID 4625), which could indicate brute force or password guessing attacks.
26. **Artifact Name:** `Windows.System.KeyLogger`&#x20;
    * **Description:** Detects keylogging software used to steal credentials.
27. **Artifact Name:** `Windows.LSASS.Dump`&#x20;
    * **Description:** Looks for memory dumps of LSASS, a technique used by attackers to steal credentials.
28. **Artifact Name:** `Windows.CachedLogonTokens`&#x20;
    * **Description:** Searches for cached logon tokens that could be used by attackers to authenticate as another user.
29. **Artifact Name:** `Windows.Registry.SAMHiveDump`&#x20;
    * **Description:** Detects attempts to dump the SAM hive, which stores hashed passwords for local accounts.
30. **Artifact Name:** `Windows.Kerberos.TicketGrants`&#x20;
    * **Description:** Monitors for unusual Kerberos ticket-granting-ticket (TGT) requests, which could indicate credential theft.

### 4. **Lateral Movement Evidence**

**Description:** Lateral movement allows attackers to expand access across a network, using tools and techniques like remote services, file sharing, and administrative accounts. These artifacts help detect such activities.

**25 Example Velociraptor Artifacts:**

31. **Artifact Name:** `Windows.Sysinternals.PsExec`&#x20;
    * **Description:** Monitors the use of Sysinternals PsExec, a common tool for remote execution and lateral movement.
32. **Artifact Name:** `Windows.EventLog.Security_4624`&#x20;
    * **Description:** Captures successful logon events (Event ID 4624) to identify lateral movement across accounts and machines.
33. **Artifact Name:** `Windows.EventLog.Security_4648`&#x20;
    * **Description:** Tracks explicit credential use during logons (Event ID 4648), often associated with lateral movement attempts.
34. **Artifact Name:** `Windows.RDP.Connections`&#x20;
    * **Description:** Identifies new or unusual Remote Desktop Protocol (RDP) connections, which could indicate lateral movement.
35. **Artifact Name:** `Windows.SMB.Sessions`&#x20;
    * **Description:** Tracks active SMB sessions to detect potential lateral movement via file shares.
36. **Artifact Name:** `Windows.WinRM.Access`&#x20;
    * **Description:** Monitors for usage of Windows Remote Management (WinRM) for remote execution, which may be exploited in lateral movement.
37. **Artifact Name:** `Windows.Powershell.RemoteExecution`&#x20;
    * **Description:** Detects remote execution of PowerShell commands using `New-PSSession`, which attackers use for lateral movement.
38. **Artifact Name:** `Windows.EventLog.Security_4769`&#x20;
    * **Description:** Detects Kerberos service ticket request events (Event ID 4769), which may indicate lateral movement attempts via pass-the-ticket.
39. **Artifact Name:** `Windows.AdminShares.Access`&#x20;
    * **Description:** Identifies unauthorized access to administrative shares (e.g., `C$`), often used during lateral movement.
40. **Artifact Name:** `Windows.System.WMIEvents`&#x20;
    * **Description:** Monitors for WMI-based remote execution, commonly used in lateral movement scenarios.

### 5. **Data Theft Attempts**

**Description:** Data exfiltration involves stealing sensitive data, often using file transfer methods or network connections to external locations. These artifacts help detect signs of data theft.

**25 Example Velociraptor Artifacts:**

41. **Artifact Name:** `Windows.FileSystem.LargeFiles`&#x20;
    * **Description:** Identifies large files that could be compressed or moved as part of data exfiltration.
42. **Artifact Name:** `Windows.Network.FTPConnections`&#x20;
    * **Description:** Monitors for FTP connections, a common method for transferring stolen data.
43. **Artifact Name:** `Windows.Network.DNSQueries`&#x20;
    * **Description:** Tracks DNS queries to identify connections to external domains used for data exfiltration.
44. **Artifact Name:** `Windows.FileSystem.USBDevices`&#x20;
    * **Description:** Detects USB devices that may be used for data theft via physical storage.
45. **Artifact Name:** `Windows.Cloud.StorageAccess`&#x20;
    * **Description:** Monitors for connections to cloud storage services (e.g., Google Drive, Dropbox), often used in data exfiltration.
46. **Artifact Name:** `Windows.Network.HighBandwidthTransfers`&#x20;
    * **Description:** Tracks high-volume outbound traffic, which could indicate data theft over the network.
47. **Artifact Name:** `Windows.EventLog.Security_4663`&#x20;
    * **Description:** Captures file access events (Event ID 4663) to detect unauthorized access to sensitive files.
48. **Artifact Name:** `Windows.System.RDPFileCopy`&#x20;
    * **Description:** Detects file copy actions over RDP sessions, often used to exfiltrate data.
49. **Artifact Name:** `Windows.FileSystem.EncryptedFiles`&#x20;
    * **Description:** Identifies files encrypted before exfiltration, a common technique used by ransomware actors.
50. **Artifact Name:** `Windows.FileSystem.FileShares`&#x20;
    * **Description:** Monitors file shares for unusual activity or access, which could indicate attempts to steal data.

### 6. **Execution of Actor Tools & Command-Line Activities**

**Description:** Attackers use a variety of tools and command-line utilities to execute their malicious actions. These artifacts help detect the use of attacker tools and suspicious command-line executions

**25 Example Velociraptor Artifacts**

51. **Artifact Name:** `Windows.Processes.Cmdline`&#x20;
    * **Description:** Gathers command-line execution details to detect malicious use of administrative or attacker tools.
52. **Artifact Name:** `Windows.System.PowerShellExecution`&#x20;
    * **Description:** Monitors PowerShell executions, especially those bypassing execution policies or running encoded commands.
53. **Artifact Name:** `Windows.CobaltStrike.Beacons`&#x20;
    * **Description:** Detects execution of `Cobalt Strike` beacons, a tool used by many advanced threat actors.
54. **Artifact Name:** `Windows.System.NetcatUsage`&#x20;
    * **Description:** Tracks the use of `Netcat`, a tool often used for remote connections and data exfiltration.
55. **Artifact Name:** `Windows.System.CmdExec`&#x20;
    * **Description:** Identifies suspicious use of `cmd.exe`, often used for script execution or administrative tasks.
56. **Artifact Name:** `Windows.Metasploit.Execution`&#x20;
    * **Description:** Detects usage of Metasploit, a common framework for exploitation and pivoting.
57. **Artifact Name:** `Windows.System.ScheduledTaskCreation`&#x20;
    * **Description:** Monitors for the creation of scheduled tasks that may be used to run attacker tools periodically.
58. **Artifact Name:** `Windows.System.WScriptExecution`&#x20;
    * **Description:** Tracks executions of Windows Script Host (`wscript.exe`), which attackers frequently abuse to execute scripts.
59. **Artifact Name:** `Windows.EventLog.Security_4688`&#x20;
    * **Description:** Captures process creation events (Event ID 4688) to monitor for suspicious command-line executions.
60. **Artifact Name:** `Windows.System.EncodedScriptExecution`&#x20;
    * **Description:** Detects execution of encoded or obfuscated scripts, often used to hide malicious actions.

### 7. **Identity & Logon Activities Using Windows Security Logs**

**Description:** Monitoring user logon activities can help identify compromised accounts, unusual logon times, and suspicious access patterns.

**25 Example Velociraptor Artifacts:**

61. **Artifact Name:** `Windows.EventLog.Security_4624`&#x20;
    * **Description:** Gathers successful logon events to detect unauthorized access or suspicious logon activities.
62. **Artifact Name:** `Windows.EventLog.Security_4625`&#x20;
    * **Description:** Collects failed logon attempts, which could indicate brute force or account enumeration attempts.
63. **Artifact Name:** `Windows.EventLog.Security_4648`&#x20;
    * **Description:** Monitors for explicit logons where credentials are provided manually, often indicating lateral movement.
64. **Artifact Name:** `Windows.EventLog.Security_4672`&#x20;
    * **Description:** Tracks privileged logon events, which could signal unauthorized use of administrative accounts.
65. **Artifact Name:** `Windows.EventLog.Security_4769`&#x20;
    * **Description:** Detects Kerberos service ticket requests, which could indicate lateral movement via pass-the-ticket.
66. **Artifact Name:** `Windows.EventLog.Security_4771`&#x20;
    * **Description:** Captures failed Kerberos pre-authentication attempts, potentially indicating password brute-force attempts.
67. **Artifact Name:** `Windows.EventLog.Security_4776`&#x20;
    * **Description:** Monitors NTLM authentication events, useful for identifying pass-the-hash or relay attacks.
68. **Artifact Name:** `Windows.EventLog.Security_4647`&#x20;
    * **Description:** Detects user logoff events to track anomalous session terminations.
69. **Artifact Name:** `Windows.EventLog.Security_4634`&#x20;
    * **Description:** Gathers logoff events to correlate with other suspicious user activity.
70. **Artifact Name:** `Windows.Security.LocalAccountCreation`&#x20;
    * **Description:** Monitors for new user accounts created locally, which could indicate the creation of backdoor accounts.

## Threat-Hunting Guide Using Velociraptor Artifacts: With Example VQL

### **1. Malware Infection Detection**

**Description:** Malware infections involve malicious code or files being installed or executed on the system. Attackers often use these infections to establish persistence and gain control over the system.

**Example Velociraptor Artifact: `Windows.System.Pslist`**

* **Artifact Description:** Lists all running processes, helping identify suspicious or malicious executables running on the system.

**5 Example VQL Queries for Malware Detection:**

1. **Query:** Detect execution of suspicious PowerShell scripts used in malware infections.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%powershell%' AND cmdline LIKE '%Invoke%'
```

**Description:** Detects malicious PowerShell scripts often used for downloading or executing malware payloads.

2. **Query:** Search for unsigned or suspicious executables in the `C:\Windows\Temp` directory.

{% code overflow="wrap" %}
```cs
SELECT * FROM fileinfo() WHERE filename LIKE 'C:\\Windows\\Temp\\%' AND signed = false
```
{% endcode %}

**Description:** Detects unsigned files, often used by malware during execution.

3. **Query:** Identify persistent malware by checking for new services.

```cs
SELECT * FROM services() WHERE start_type = 'auto' AND path LIKE '%.exe%'
```

**Description:** Detects new services created by malware to ensure persistence across reboots.

4. **Query:** Detect executable files running from unusual directories (e.g., user folders).

```cs
SELECT * FROM pslist() WHERE path LIKE 'C:\\Users\\%'
```

**Description:** Identifies executables launched from non-standard directories often used by malware.

5. **Query:** Detect the presence of malware-related prefetch files.

```cs
SELECT * FROM prefetch() WHERE filename LIKE '%malware%'
```

**Description:** Detects execution of malware based on prefetch file entries.

### **2. Actor Discovery Activities**

**Description:** Discovery activities are used by attackers to learn more about the environment, such as gathering information about the network, users, and systems.

**Example Velociraptor Artifact: `Windows.Network.Connections`**

* **Artifact Description:** Lists active network connections, which can help identify scanning and reconnaissance activities.

**5 Example VQL Queries for Actor Discovery:**

1. **Query:** Detect network scanning tools like `nmap` or `masscan`.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%nmap%' OR cmdline LIKE '%masscan%'
```

**Description:** Detects popular network scanning tools used for reconnaissance.

2. **Query:** Detect network discovery commands like `netstat` or `arp`.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%netstat%' OR cmdline LIKE '%arp -a%'
```

**Description:** Detects common network enumeration tools used by attackers.

3. **Query:** Search for SMB share enumeration activity.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%net view%' OR cmdline LIKE '%net share%'
```

**Description:** Detects attempts to enumerate SMB shares in the network.

4. **Query:** Monitor for ARP scanning activities.

```cs
SELECT * FROM network() WHERE protocol = 'ARP'
```

**Description:** Identifies ARP scans used by attackers to map out IP addresses in the local network.

5. **Query:** Detect WMI-based system discovery attempts.

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%wmic%' AND cmdline LIKE '%computersystem%'
```
{% endcode %}

**Description:** Detects WMI commands used by attackers to gather system information.

### **3. Credential Theft Attempts**

**Description:** Credential theft attempts involve attackers trying to extract user credentials from memory, files, or the registry. These credentials are then used to escalate privileges or move laterally within the network.

**Example Velociraptor Artifact: `Windows.Registry.SAM`**

* **Artifact Description:** Examines the SAM registry hive for credential dumping activities.

**5 Example VQL Queries for Credential Theft:**

1. **Query:** Detect attempts to access LSASS memory for credential dumping.

```cs
SELECT * FROM handles() WHERE process_name = 'lsass.exe' AND access LIKE '%READ%'
```

**Description:** Identifies attempts to dump credentials from LSASS memory.

2. **Query:** Search for known credential dumping tools like `Mimikatz`.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%mimikatz%'
```

**Description:** Detects the use of `Mimikatz`, a popular tool for stealing credentials.

3. **Query:** Monitor access to the SAM registry hive, which stores hashed user credentials.

```cs
SELECT * FROM registry() WHERE key_path LIKE 'HKLM\\SAM\\%'
```

**Description:** Detects unauthorized access to the SAM registry hive.

4. **Query:** Detect suspicious access to the Windows credential manager.

{% code overflow="wrap" %}
```cs
SELECT * FROM fileinfo() WHERE path LIKE 'C:\\Windows\\System32\\config\\CredentialManager'
```
{% endcode %}

**Description:** Monitors attempts to access the credential manager, where sensitive user credentials may be stored.

5. **Query:** Detect Kerberos ticket-granting-ticket (TGT) extraction attempts.

```cs
SELECT * FROM windows_event_log() WHERE event_id = 4768
```

**Description:** Tracks unusual Kerberos TGT requests that may be used in ticket-based attacks.

### **4. Evidence of Lateral Movement**

**Description:** Lateral movement refers to an attacker’s ability to move through a network by exploiting remote services, shared credentials, or other vectors. Detecting these movements is crucial for containing an attacker’s spread.

**Example Velociraptor Artifact: `Windows.Sysinternals.PsExec`**

* **Artifact Description:** Detects the use of PsExec, a common tool used by attackers to remotely execute commands on another machine.

**5 Example VQL Queries for Lateral Movement:**

1. **Query:** Detect usage of Sysinternals PsExec for remote command execution.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%psexec%'
```

**Description:** Detects PsExec usage, which is commonly used for lateral movement.

2. **Query:** Monitor for PowerShell remoting sessions.

{% code overflow="wrap" %}
```cs
SELECT * FROM windows_event_log() WHERE event_id = 4104 AND script_block_text LIKE '%New-PSSession%'
```
{% endcode %}

**Description:** Detects the creation of new remote PowerShell sessions used by attackers for lateral movement.

3. **Query:** Detect usage of Remote Desktop Protocol (RDP) for lateral movement.

```cs
SELECT * FROM rdp_sessions() WHERE event_type = 'connect'
```

**Description:** Identifies RDP connections that could indicate lateral movement between machines.

4. **Query:** Monitor access to administrative shares (e.g., C$).

```cs
SELECT * FROM smb_sessions() WHERE share_name = 'C$'`
```

**Description:** Tracks access to administrative shares, which can be used in lateral movement.

5. **Query:** Detect remote command execution using WinRM.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%winrm%' AND cmdline LIKE '%RemoteShell%'`
```

**Description:** Detects the use of Windows Remote Management (WinRM) for executing commands on remote systems.

### **5. Data Theft Attempts**

**Description:** Data theft attempts involve stealing sensitive information, often by exfiltrating files over the network or copying data to external storage devices.

**Example Velociraptor Artifact: `Windows.FileSystem.USBDevices`**

* **Artifact Description:** Monitors connected USB devices, which could be used to exfiltrate data.

**5 Example VQL Queries for Data Theft:**

1. **Query:** Detect high-volume outbound network traffic that could indicate data exfiltration.

```cs
SELECT * FROM network() WHERE bytes_out > 10000000
```

**Description:** Tracks large outbound data transfers, which could indicate data theft.

2. **Query:** Detect the use of file compression tools like `WinRAR` or `7-Zip`.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%winrar%' OR cmdline LIKE '%7z%'
```

**Description:** Detects the use of compression tools, often used to prepare data for exfiltration.

3. **Query:** Monitor for suspicious FTP connections used to exfiltrate data.

```cs
SELECT * FROM network() WHERE remote_port = 21 AND protocol = 'tcp'
```

**Description:** Identifies FTP connections, a common method for transferring stolen data.

4. **Query:** Detect file uploads to cloud storage services like Dropbox or Google Drive.

{% code overflow="wrap" %}
```cs
SELECT * FROM network() WHERE remote_address LIKE '%dropbox%' OR remote_address LIKE '%google%'
```
{% endcode %}

**Description:** Tracks file transfers to cloud storage services often used by attackers to exfiltrate data.

5. **Query:** Monitor for USB devices connected during suspicious file transfers.

```cs
SELECT * FROM usb_devices() WHERE event_type = 'connect'`
```

**Description:** Detects when USB storage devices are connected to the system, which could be used for data theft.

### **6. Execution of Actor Tools & Command-Line Activities**

**Description:** Attackers use a variety of tools and scripts to achieve their objectives. Monitoring the execution of these tools and their associated command-line activity can help detect compromise.

* **Artifact Description:** Collects command-line execution data from processes to identify the use of attacker tools or malicious commands.

**5 Example VQL Queries for Execution of Actor Tools:**

1. **Query:** Detect execution of `Cobalt Strike` beacons.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%cobaltstrike%'
```

**Description:** Tracks the execution of `Cobalt Strike`, a commonly used post-exploitation framework.

2. **Query:** Detect suspicious PowerShell commands bypassing execution policies.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%powershell%' AND cmdline LIKE '%bypass%'
```

**Description:** Identifies PowerShell commands attempting to bypass execution policies, commonly used in attacks.

3. **Query:** Monitor for encoded or obfuscated scripts executed via PowerShell.

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%powershell%' AND cmdline LIKE '%-encodedcommand%'
```
{% endcode %}

**Description:** Detects encoded scripts executed in PowerShell, often used to hide malicious activities.

4. **Query:** Detect Metasploit payloads being executed.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%metasploit%'
```

**Description:** Tracks the execution of Metasploit, a popular penetration testing tool used by attackers.

5. **Query:** Monitor suspicious `cmd.exe` activity.

```cs
SELECT * FROM pslist() WHERE cmdline LIKE '%cmd.exe%' AND cmdline LIKE '%/c%'
```

**Description:** Detects suspicious command-line execution using `cmd.exe`, often used in post-exploitation.

### **7. Identity & Logon Activity Monitoring**

**Description:** Monitoring logon events can reveal compromised accounts, brute force attempts, and unusual authentication patterns, which may indicate an ongoing attack.

**Example Velociraptor Artifact: `Windows.EventLogs.Security`**

* **Artifact Description:** Collects Windows security logs related to user logon and authentication activities.

**5 Example VQL Queries for Identity & Logon Monitoring:**

1. **Query:** Detect failed logon attempts (Event ID 4625).

```cs
    SELECT * FROM windows_event_log() WHERE event_id = 4625
```

**Description:** Tracks failed logon attempts that may indicate brute force or password guessing attacks.

2. **Query:** Detect suspicious logon activities from foreign IP addresses.

{% code overflow="wrap" %}
```cs
SELECT * FROM windows_event_log() WHERE event_id = 4624 AND ip_address LIKE '%foreign%'
```
{% endcode %}

**Description:** Monitors for successful logons from unexpected or foreign IP addresses.

3. **Query:** Monitor logons using administrative accounts (Event ID 4672).

```cs
SELECT * FROM windows_event_log() WHERE event_id = 4672
```

**Description:** Tracks the use of privileged accounts, which may indicate abuse or compromise of admin credentials.

4. **Query:** Detect abnormal logon types, such as network logons (Event ID 4624).

```cs
SELECT * FROM windows_event_log() WHERE event_id = 4624 AND logon_type = 3
```

**Description:** Monitors network logons, often used in lateral movement and remote access.

5. **Query:** Detect Kerberos ticket-granting-service (TGS) requests (Event ID 4769).

```cs
SELECT * FROM windows_event_log() WHERE event_id = 4769
```

**Description:** Tracks Kerberos TGS requests, often used in pass-the-ticket attacks.
