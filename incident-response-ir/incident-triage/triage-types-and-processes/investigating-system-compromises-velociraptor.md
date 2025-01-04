---
icon: laptop-code
---

# Investigating System Compromises - Velociraptor

## <mark style="color:blue;">1. Initial Access</mark>

**1.1. Phishing: Spearphishing Attachment (T1566.001)**

**Hunt Name:** Detect\_Malicious\_Email\_Attachments **Query 1: Identify Malicious Executables in INetCache**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\%.exe'
```
{% endcode %}

**Hunt Name:** Find\_Recent\_Executables\_In\_User\_Directories **Query 2: Search for Recently Created Executables in User Directories**

{% code overflow="wrap" %}
```cs
SELECT FullPath, CreationTime, Size FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\*.exe' AND CreationTime > now() - 86400
```
{% endcode %}

**Hunt Name:** Identify\_Dangerous\_File\_Extensions **Query 3: Detect Suspicious Attachments with Dangerous Extensions**

{% code overflow="wrap" %}
```cs
SELECT FullPath FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\%.exe'
```
{% endcode %}

**Hunt Name:** Monitor\_Temp\_Directory\_For\_PDFs **Query 4: Search for PDF Files in Temp Directory**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%.pdf'
```
{% endcode %}

**Hunt Name:** Check\_Temp\_Folder\_For\_Office\_Docs **Query 5: Detect Office Documents in Temp Folders**

{% code overflow="wrap" %}
```cs
SELECT FullPath, CreationTime, Size FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%.docx'
```
{% endcode %}

## <mark style="color:blue;">2. Execution</mark>

**2.1. Command and Scripting Interpreter: PowerShell (T1059.001)**

**Hunt Name:** Detect\_PowerShell\_Execution **Query 6: Identify PowerShell Executions**

```cs
SELECT * FROM pslist()  WHERE name = 'powershell.exe' OR name = 'pwsh.exe'
```

**Hunt Name:** Find\_Encoded\_PowerShell\_Commands **Query 7: Detect PowerShell Commands with Encoded Scripts**

```cs
SELECT * FROM pslist()  WHERE name = 'powershell.exe' AND command_line LIKE '%-enc%'
```

**Hunt Name:** Monitor\_PowerShell\_Scripts\_In\_Temp **Query 8: Monitor PowerShell Scripts in Temp Directory**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%.ps1
```
{% endcode %}

**Hunt Name:** Search\_For\_Suspicious\_PowerShell\_Modules **Query 9: Search for Suspicious PowerShell Modules**

{% code overflow="wrap" %}
```cs
SELECT * FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\WindowsPowerShell\\Modules\\%'
```
{% endcode %}

**Hunt Name:** Detect\_Recent\_PowerShell\_Executions **Query 10: Identify Recent PowerShell Executions**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE name = 'powershell.exe' AND CreationTime > now() - 86400
```
{% endcode %}

## <mark style="color:blue;">3. Persistence</mark>

**3.1. Registry Run Keys / Startup Folder (T1547.001)**

**Hunt Name:** Enumerate\_Registry\_Run\_Keys **Query 11: Enumerate Run Keys in Registry**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Key LIKE 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%'
```
{% endcode %}

**Hunt Name:** Detect\_Suspicious\_Startup\_Items **Query 12: Detect Startup Items in User Profiles**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%'
```
{% endcode %}

**Hunt Name:** Search\_For\_Unusual\_RunOnce\_Keys **Query 13: Search for Unusual RunOnce Keys**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Key LIKE 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce%'
```
{% endcode %}

**Hunt Name:** Monitor\_Run\_Key\_Modifications **Query 14: Monitor Run Key Modifications**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Key LIKE 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%'
```
{% endcode %}

**Hunt Name:** Identify\_Suspicious\_Startup\_Folder\_Entries **Query 15: Identify Suspicious Startup Folder Entries**

{% code overflow="wrap" %}
```cs
SELECT FullPath FROM FileSystem  WHERE FullPath LIKE 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%'
```
{% endcode %}

## <mark style="color:blue;">4. Privilege Escalation</mark>

**4.1. Process Injection (T1055)**

**Hunt Name:** Detect\_Remote\_Thread\_Creation **Query 16: Detect Remote Thread Creation**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Handles()  WHERE Type = 'Thread' AND GrantedAccess = 'CREATE_THREAD'
```
{% endcode %}

**Hunt Name:** Identify\_Processes\_With\_Injected\_Code **Query 17: Identify Processes with Injected Code**

```cs
SELECT * FROM Windows.Processes()  WHERE Injected = true
```

**Hunt Name:** Monitor\_Suspicious\_Memory\_Regions **Query 18: Monitor Processes with Suspicious Memory Regions**

```cs
SELECT * FROM Windows.MemoryMap()  WHERE PrivateMemory = true AND Writable = true
```

**Hunt Name:** Detect\_DLL\_Injection\_In\_Processes **Query 19: Search for Processes with DLL Injections**

```cs
SELECT * FROM Windows.Processes()  WHERE DllInjected = true
```

**Hunt Name:** `Monitor_Process_Handle_Operations` **Query 20: Identify Suspicious Process Handle Operations**

{% code overflow="wrap" %}
```
 SELECT * FROM Windows.Handles()  WHERE Type = 'Process' AND GrantedAccess = 'ALL_ACCESS'
```
{% endcode %}

## <mark style="color:blue;">5. Defence Evasion</mark>

**5.1. Obfuscated Files or Information (T1027)**

**Hunt Name:** Detect\_Base64\_Encoded\_PowerShell **Query 21: Detect Base64 Encoded PowerShell Commands**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE name = 'powershell.exe' AND command_line LIKE '%-encodedcommand%'
```
{% endcode %}

**Hunt Name:** Identify\_Obfuscated\_Scripts\_In\_Temp **Query 22: Identify Suspicious Scripts in Temp Directory**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%.vbs'
```
{% endcode %}

**Hunt Name:** Search\_For\_Encrypted\_Scripts **Query 23: Search for Encrypted Scripts**

```cs
SELECT FullPath FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%.vbe'
```

**Hunt Name:** Monitor\_Batch\_Files\_In\_Temp **Query 24: Monitor Obfuscated Batch Files**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%.bat'
```
{% endcode %}

**Hunt Name:** Identify\_XOR\_Encrypted\_Files **Query 25: Identify XOR Encrypted Files**

```cs
SELECT FullPath FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%.xor'
```

## <mark style="color:blue;">6. Credential Access</mark>

**6.1. Credential Dumping: LSASS Memory (T1003.001)**

**Hunt Name:** Search\_For\_LSASS\_Memory\_Dumps **Query 26: Search for LSASS Memory Dumps**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.Application  WHERE ProviderName = 'Sysmon' AND EventID = 10 AND Image = 'lsass.exe'
```
{% endcode %}

**Hunt Name:** Monitor\_LSASS\_Process\_Access **Query 27: Monitor Access to LSASS Process**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Handles()  WHERE ProcessName = 'lsass.exe' AND GrantedAccess = 'ALL_ACCESS'
```
{% endcode %}

**Hunt Name:** Identify\_LSASS\_Handle\_Operations **Query 28: Identify Processes with LSASS Handles**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Processes()  WHERE name = 'lsass.exe' AND HasInjectedCode = true
```
{% endcode %}

**Hunt Name:** Detect\_Tools\_For\_LSASS\_Dumps **Query 29: Detect Tools Known for LSASS Dumps**

```cs
SELECT * FROM pslist()  WHERE name LIKE 'procdump%' OR name LIKE 'taskmanager%'
```

**Hunt Name:** Monitor\_LSASS\_Memory\_Reads **Query 30: Monitor Memory Reads from LSASS**

{% code overflow="wrap" %}
```cs
  SELECT * FROM Windows.MemoryMap()  WHERE ProcessName = 'lsass.exe' AND Readable = true
```
{% endcode %}

## <mark style="color:blue;">7. Discovery</mark>

**7.1. System Information Discovery (T1082)**

**Hunt Name:** Identify\_System\_Info\_Commands **Query 31: Search for System Information Enumeration**

```cs
SELECT * FROM pslist()  WHERE name = 'systeminfo.exe' OR name = 'hostname.exe'
```

**Hunt Name:** Monitor\_Host\_Information\_Commands **Query 32: Monitor Commands Gathering Host Information**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%hostname%' OR command_line LIKE '%whoami%'
```
{% endcode %}

**Hunt Name:** Identify\_WMI\_System\_Info\_Queries **Query 33: Identify System Information Queries via WMI**

```cs
SELECT * FROM Windows.WMI.Query  WHERE QueryText LIKE '%Win32_ComputerSystem%'
```

**Hunt Name:** Detect\_AD\_Enumeration **Query 34: Detect Active Directory Enumeration**

```cs
SELECT * FROM pslist()  WHERE name = 'dsquery.exe' OR name = 'net.exe'
```

**Hunt Name:** Monitor\_WMIC\_System\_Commands **Query 35: Monitor WMIC Commands for System Information**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE name = 'wmic.exe' AND command_line LIKE '%computersystem%'
```
{% endcode %}

## <mark style="color:blue;">8. Lateral Movement</mark>

**8.1. Remote Services: Remote Desktop Protocol (RDP) (T1021.001)**

**Hunt Name:** Monitor\_RDP\_Logons **Query 36: Monitor RDP Logons**

```cs
SELECT * FROM Windows.EventLogs.Security  WHERE EventID = 4624 AND LogonType = 10
```

**Hunt Name:** Identify\_RDP\_Network\_Sessions **Query 37: Identify RDP Sessions Established via Network**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Network.Connection  WHERE RemotePort = 3389 AND State = 'ESTABLISHED'
```
{% endcode %}

**Hunt Name:** Search\_For\_RDP\_Config\_Changes **Query 38: Search for RDP Configuration Changes**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Key LIKE 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\%'
```
{% endcode %}

**Hunt Name:** Detect\_RDP\_Client\_Use **Query 39: Detect Use of RDP Client**

```cs
SELECT * FROM pslist()  WHERE name = 'mstsc.exe'
```

**Hunt Name:** Monitor\_Suspicious\_RDP\_File\_Transfers **Query 40: Monitor Suspicious RDP File Transfers**

```cs
SELECT * FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\RDP\\%'
```

## <mark style="color:blue;">9. Collection</mark>

**9.1. Data from Local System (T1005)**

**Hunt Name:** Identify\_Access\_To\_Sensitive\_Files **Query 41: Identify Access to Sensitive Files**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, LastAccessTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%' AND LastAccessTime > now() - 86400
```
{% endcode %}

**Hunt Name:** Monitor\_Copy\_Operations\_Of\_Sensitive\_Files **Query 42: Monitor Copy Operations of Sensitive Files**

{% code overflow="wrap" %}
```cs
SELECT * FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%' AND Operation = 'COPY'
```
{% endcode %}

**Hunt Name:** Detect\_Archive\_Files\_With\_Sensitive\_Data **Query 43: Detect Archive Files Containing Sensitive Data**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%.zip'
```
{% endcode %}

**Hunt Name:** Search\_For\_Encrypted\_Archives **Query 44: Search for Encrypted Archives**

```cs
SELECT FullPath FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%.7z'
```

**Hunt Name:** Identify\_Unauthorized\_Data\_Access **Query 45: Identify Unauthorized Data Access Attempts**

{% code overflow="wrap" %}
```cs
SELECT FullPath FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%' AND PermissionDenied = true
```
{% endcode %}

## <mark style="color:blue;">10. Command and Control</mark>

**10.1. Command and Control: Web Protocols (T1071.001)**

**Hunt Name:** Monitor\_DNS\_Queries\_For\_C2\_Domains **Query 46: Monitor DNS Queries for Known Malicious Domains**

{% code overflow="wrap" %}
```cs
SELECT QueryName, QueryType FROM Windows.DNS.Queries  WHERE QueryName LIKE '%maliciousdomain.com%'
```
{% endcode %}

**Hunt Name:** Search\_For\_HTTP\_S\_Connections\_To\_C2 **Query 47: Search for HTTP/S Connections to C2 Servers**

```cs
SELECT * FROM Windows.Network.Connection  WHERE RemotePort = 80 OR RemotePort = 443
```

**Hunt Name:** Detect\_Suspicious\_HTTP\_POST\_Requests **Query 48: Identify Suspicious HTTP POST Requests**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Network.Connection  WHERE RemotePort = 80 AND Protocol = 'HTTP' AND Method = 'POST'
```
{% endcode %}

**Hunt Name:** Identify\_Non\_Standard\_HTTP\_Methods **Query 49: Detect Non-Standard HTTP Methods**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Network.Connection  WHERE RemotePort = 80 AND Method NOT IN ('GET', 'POST')
```
{% endcode %}

**Hunt Name:** Monitor\_DNS\_For\_Known\_C2\_Patterns **Query 50: Monitor DNS Traffic for Known C2 Patterns**

```cs
SELECT QueryName, QueryType FROM Windows.DNS.Queries  WHERE QueryName LIKE '%cnc%'
```

## <mark style="color:blue;">11. Exfiltration</mark>

**11.1. Exfiltration Over C2 Channel (T1041)**

**Hunt Name:** Monitor\_Large\_Data\_Transfers\_To\_External\_IPs **Query 51: Monitor Large Data Transfers to External IPs**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Network.Connection  WHERE BytesSent > 10485760 AND RemoteAddress NOT LIKE '192.168.%'
```
{% endcode %}

**Hunt Name:** Search\_For\_Encrypted\_Data\_Exfiltration **Query 52: Search for Encrypted Data Exfiltration**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Network.Connection  WHERE Protocol = 'HTTPS' AND BytesSent > 10485760
```
{% endcode %}

**Hunt Name:** Detect\_FTP\_Uploads\_To\_External\_Servers **Query 53: Detect FTP Uploads to External Servers**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Network.Connection  WHERE RemotePort = 21 AND State = 'ESTABLISHED'
```
{% endcode %}

**Hunt Name:** Identify\_ICMP\_Tunneling\_Attempts **Query 54: Identify ICMP Tunneling Attempts**

```cs
SELECT * FROM Windows.Network.Icmp  WHERE MessageType = 8 AND MessageCode = 0
```

**Hunt Name:** Monitor\_SFTP\_Transfers\_To\_Untrusted\_Servers **Query 55: Monitor SFTP Transfers to Untrusted Servers**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Network.Connection  WHERE RemotePort = 22 AND State = 'ESTABLISHED'
```
{% endcode %}

## <mark style="color:blue;">12. Impact</mark>

**12.1. Inhibit System Recovery: Disable or Modify Tools (T1490)**

**Hunt Name:** Monitor\_Volume\_Shadow\_Copy\_Deletion **Query 56: Monitor Volume Shadow Copy Deletion**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.Application  WHERE ProviderName = 'VSS' AND EventID = 8194
```
{% endcode %}

**Hunt Name:** Search\_For\_Commands\_Disabling\_Recovery **Query 57: Search for Commands Disabling System Recovery**

```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%vssadmin delete shadows%'
```

**Hunt Name:** Detect\_System\_Restore\_Point\_Deletion **Query 58: Detect System Restore Point Deletion**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.System  WHERE EventID = 103 AND SourceName = 'System Restore'
```
{% endcode %}

**Hunt Name:** Monitor\_Registry\_Changes\_Disabling\_Backups **Query 59: Monitor Registry Changes Disabling Backup Features**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Key LIKE 'HKLM\\System\\CurrentControlSet\\Services\\VSS\\Start'
```
{% endcode %}

**Hunt Name:** Search\_For\_Disabled\_Windows\_Recovery **Query 60: Search for Disabling Windows Recovery Options**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Registry.KeyValue  WHERE KeyPath = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute'  AND Data != 'autocheck autochk *'
```
{% endcode %}

## <mark style="color:blue;">13. Execution (Continued)</mark>

**13.1. User Execution: Malicious File (T1204.002)**

**Hunt Name:** Identify\_Unsigned\_Executable\_Execution **Query 61: Identify Execution of Unsigned Executables**

```cs
SELECT * FROM pslist()  WHERE name LIKE '%.exe' AND Signed = false
```

**Hunt Name:** Search\_For\_Execution\_Of\_Recent\_Downloads **Query 62: Search for Execution of Recently Downloaded Files**

```cs
SELECT * FROM pslist()  WHERE name LIKE '%.exe' AND CreationTime > now() - 86400
```

**Hunt Name:** Monitor\_Script\_Execution\_From\_User\_Folders **Query 63: Monitor Execution of Scripts from User Folders**

```cs
SELECT * FROM pslist()  WHERE name LIKE '%.vbs' OR name LIKE '%.js'
```

**Hunt Name:** Detect\_Execution\_Of\_Suspicious\_Extensions **Query 64: Detect Execution of Files with Suspicious Extensions**

```cs
SELECT * FROM pslist()  WHERE name LIKE '%.scr' OR name LIKE '%.cpl'
```

**Hunt Name:** Identify\_Execution\_From\_Temp\_Directories **Query 65: Identify Execution of Files from Temp Directories**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE command_line LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%'
```
{% endcode %}

## <mark style="color:blue;">14. Persistence (Continued)</mark>

**14.1. Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)**

**Hunt Name:** Identify\_Registry\_Autostart\_Entries **Query 66: Identify Autostart Entries in Registry**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Key LIKE 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%'
```
{% endcode %}

**Hunt Name:** Monitor\_RunOnce\_Key\_Changes **Query 67: Monitor Changes to RunOnce Keys**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Key LIKE 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce%'
```
{% endcode %}

**Hunt Name:** Detect\_New\_Startup\_Registry\_Entries **Query 68: Detect New Startup Items in Registry**

{% code overflow="wrap" %}
```cs
SELECT * FROM registry()  WHERE Key LIKE 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%'  AND Value NOT IN (SELECT Value FROM registry_previous)
```
{% endcode %}

**Hunt Name:** Search\_For\_Persistence\_Via\_Winlogon\_Keys **Query 69: Search for Persistence via Winlogon Keys**

{% code overflow="wrap" %}
```cs
SELECT * FROM registry()  WHERE Key LIKE 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\%'
```
{% endcode %}

**Hunt Name:** Monitor\_Registry\_Entries\_For\_Suspicious\_Executables **Query 70: Monitor Registry Entries for Suspicious Executables**

{% code overflow="wrap" %}
```cs
SELECT Key, Value, Data FROM registry()  WHERE Data LIKE '%.exe' AND (Key LIKE 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%'  OR Key LIKE 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%')
```
{% endcode %}

## <mark style="color:blue;">15. Defence Evasion (Continued)</mark>

**15.1. Process Injection: Process Hollowing (T1055.012)**

**Hunt Name:** Detect\_Process\_Hollowing\_Indicators **Query 71: Monitor for Suspicious Process Hollowing Indicators**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Processes()  WHERE CommandLine LIKE '%svchost.exe%' AND ParentProcessName != 'services.exe'`
```
{% endcode %}

**Hunt Name:** Search\_For\_Inconsistencies\_In\_Memory\_Allocation **Query 72: Search for Inconsistencies in Memory Allocation**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.MemoryMap()  WHERE ProcessName = 'svchost.exe' AND (MemoryMapped = false OR Writable = true)
```
{% endcode %}

**Hunt Name:** Detect\_Unusual\_Parent\_Child\_Process\_Relationships **Query 73: Detect Unusual Parent-Child Process Relationships**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Processes()  WHERE ParentProcessName NOT IN ('explorer.exe', 'services.exe')  AND ProcessName LIKE '%svchost.exe%'
```
{% endcode %}

**Hunt Name:** Monitor\_Process\_Creation\_With\_Suspicious\_Flags **Query 74: Monitor for Process Creation with Suspicious Flags**

```cs
SELECT * FROM Windows.Processes()  WHERE CreationFlags & 0x00000004 != 0
```

**Hunt Name:** Search\_For\_Hollowed\_Process\_Memory\_Regions **Query 75: Search for Processes with Hollowed Memory Regions**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.MemoryMap()  WHERE PrivateMemory = true AND Writable = true AND Executable = true
```
{% endcode %}

## <mark style="color:blue;">16. Credential Access (Continued)</mark>

**16.1. OS Credential Dumping: NTDS (T1003.003)**

**Hunt Name:** Search\_For\_NTDS\_dit\_Access\_Attempts **Query 76: Search for NTDS.dit Access Attempts**

```cs
SELECT * FROM FileSystem  WHERE FullPath LIKE 'C:\\Windows\\NTDS\\ntds.dit'
```

**Hunt Name:** Monitor\_NTDS\_dit\_Copy\_Operations **Query 77: Monitor for NTDS.dit Copy Operations**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.Security  WHERE EventID = 4663 AND ObjectName LIKE 'C:\\Windows\\NTDS\\ntds.dit'
```
{% endcode %}

**Hunt Name:** Detect\_NTDS\_dit\_Access\_Via\_VSSAdmin **Query 78: Detect NTDS.dit Access via VSSAdmin**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE name = 'vssadmin.exe' AND command_line LIKE '%create shadow%'
```
{% endcode %}

**Hunt Name:** Search\_For\_NTDS\_dit\_In\_VSS\_Snapshots **Query 79: Search for NTDS.dit in VSS Snapshots**

{% code overflow="wrap" %}
```cs
SELECT * FROM FileSystem  WHERE FullPath LIKE 'C:\\Windows\\NTDS\\ntds.dit' AND IsInShadowCopy = true
```
{% endcode %}

**Hunt Name:** Monitor\_NTDS\_dit\_Access\_By\_Non\_System\_Processes **Query 80: Monitor NTDS.dit Access by Non-System Processes**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.Processes()  WHERE name = 'ntds.dit' AND ParentProcessName NOT IN ('lsass.exe', 'services.exe')
```
{% endcode %}

## <mark style="color:blue;">17. Discovery (Continued)</mark>

**17.1. File and Directory Discovery (T1083)**

**Hunt Name:** Identify\_File\_And\_Directory\_Enumeration\_Commands **Query 81: Identify Commands Enumerating Files or Directories**

```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%dir%' OR command_line LIKE '%ls%'
```

**Hunt Name:** Monitor\_File\_Listings\_In\_User\_Folders **Query 82: Monitor File Listing Commands in User Folders**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%dir%' AND command_line LIKE 'C:\\Users\\%'
```
{% endcode %}

**Hunt Name:** Search\_For\_Commands\_Accessing\_Hidden\_Directories **Query 83: Search for Commands Accessing Hidden Directories**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%dir%' AND command_line LIKE '%/A:H%'
```
{% endcode %}

**Hunt Name:** Detect\_Listing\_Of\_System\_Files **Query 84: Detect Listing of System Files**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%dir%' AND command_line LIKE 'C:\\Windows\\%'
```
{% endcode %}

**Hunt Name:** Monitor\_Recursive\_File\_Listings **Query 85: Monitor Recursive File Listings**

```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%dir /S%'
```

## <mark style="color:blue;">18. Lateral Movement (Continued)</mark>

**18.1. Pass the Hash (T1550.002)**

**Hunt Name:** Monitor\_LSASS\_For\_Credential\_Extraction **Query 86: Monitor LSASS for Credential Extraction**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE name = 'mimikatz.exe' OR command_line LIKE '%sekurlsa::pth%'
```
{% endcode %}

**Hunt Name:** Search\_For\_Suspicious\_Logon\_Attempts\_Using\_Hashes **Query 87: Search for Suspicious Logon Attempts Using Hashes**

```cs
 SELECT * FROM Windows.EventLogs.Security  WHERE EventID = 4624 AND LogonType = 9
```

**Hunt Name:** Detect\_Abnormal\_SMB\_Logon\_Attempts **Query 88: Detect Abnormal SMB Logon Attempts**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.Security  WHERE EventID = 4624 AND LogonType = 3 AND AccountName NOT IN (SELECT AccountName FROM UserAccounts)
```
{% endcode %}

**Hunt Name:** Search\_For\_Lateral\_Movement\_Using\_Cached\_Credentials **Query 89: Search for Lateral Movement Using Cached Credentials**

```cs
SELECT * FROM Windows.EventLogs.Security  WHERE EventID = 4624 AND LogonType = 5
```

**Hunt Name:** Monitor\_Logon\_Sessions\_From\_Unusual\_Sources **Query 90: Monitor Logon Sessions Originating from Unusual Sources**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.Security  WHERE EventID = 4624 AND LogonType = 2 AND SourceAddress NOT LIKE '192.168.%'
```
{% endcode %}

## <mark style="color:blue;">19. Collection (Continued)</mark>

**19.1. Screen Capture (T1113)**

**Hunt Name:** Search\_For\_Screen\_Capture\_Tools **Query 91: Search for Screen Capture Tools**

```cs
SELECT * FROM pslist()  WHERE name LIKE '%snippingtool%' OR name LIKE '%screenshot%'
```

**Hunt Name:** Monitor\_Output\_Files\_From\_Screen\_Capture\_Tools **Query 92: Monitor Output Files from Screen Capture Tools**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Pictures\\Screenshots\\%'
```
{% endcode %}

**Hunt Name:** Detect\_Use\_Of\_Built\_In\_Screenshot\_Tools **Query 93: Detect Use of Built-in Screenshot Tools**

```cs
SELECT * FROM pslist()  WHERE name LIKE '%Snip%'
```

**Hunt Name:** Identify\_Screen\_Capture\_Commands **Query 94: Identify Screen Capture Commands**

{% code overflow="wrap" %}
```cs
SELECT * FROM pslist()  WHERE command_line LIKE '%screencapture%' OR command_line LIKE '%scrot%'
```
{% endcode %}

**Hunt Name:** Monitor\_Image\_Files\_Created\_In\_Temp\_Folders **Query 95: Monitor Creation of Image Files in Temp Folders**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%.png'  OR FullPath LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%.jpg'
```
{% endcode %}

## <mark style="color:blue;">20. Impact (Continued)</mark>

**20.1. Data Encrypted for Impact (T1486)**

**Hunt Name:** Monitor\_Unusual\_File\_Modifications **Query 96: Monitor Unusual File Modifications Indicating Encryption**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, LastWriteTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\%' AND Extension IN ('.encrypted', '.locked')
```
{% endcode %}

**Hunt Name:** Search\_For\_Known\_Ransomware\_Signatures **Query 97: Search for Known Ransomware Signatures**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.Application  WHERE ProviderName = 'Symantec' AND Message LIKE '%Ransomware%'
```
{% endcode %}

**Hunt Name:** Detect\_Sudden\_Increase\_In\_File\_Modifications **Query 98: Detect Sudden Increase in File Modifications**

{% code overflow="wrap" %}
```cs
SELECT * FROM Windows.EventLogs.Security  WHERE EventID = 4663 AND ObjectName LIKE 'C:\\Users\\%\\Documents\\%'  AND ObjectType = 'File' AND AccessMask = 'WRITE'
```
{% endcode %}

**Hunt Name:** Monitor\_Creation\_Of\_Ransom\_Notes **Query 99: Monitor Creation of Ransom Notes**

{% code overflow="wrap" %}
```cs
SELECT FullPath, Size, CreationTime FROM FileSystem  WHERE FullPath LIKE 'C:\\Users\\%\\Documents\\RansomwareNote.txt'
```
{% endcode %}

**Hunt Name:** Identify\_Ransomware\_Processes **Query 100: Identify Ransomware Processes**

```cs
SELECT * FROM pslist()  WHERE name LIKE 'ransomware%'
```
