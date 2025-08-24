# Windows Event Logs

#### Description&#x20;

Windows Event Logs are separated into different log roles and record a wide range of events on the Windows host.

There are many Event Logs in the evtx folder, some aimed at system-wide events like Security.evtx, System.evtx, and Application.evtx. Others may contain more specific events. All Event Logs are stored in the same format, but the actual data elements collected vary. This variation of data elements makes the correlation of Event Logs a challenge. This is where EvtxECmd shines. All events are normalised across all event types and all Event Logs file types!&#x20;

The EvtxECmd parser has custom maps and locked file support. EvtxECmd has a unique feature, “Maps,” that allows for consistent output. Event Log Location: Event Logs for Windows Vista or later are found in %systemroot%\System32\winevt\logs. Parsing all events could end in millions of results. Using EvtxCMD's maps can help target specific artefacts.

#### Location

```
C:\Windows\System32\winevt\Logs
```

#### Caveats&#x20;

Some Windows hosts may have different logging options&#x20;

#### Forensic Analysis Tools&#x20;

* EvtxECmd (Zimmerman tool)

#### Basic Usage&#x20;

Recursively parsing a directory of event logs is probably the most efficient way to use EvtxECmd. To parse a directory, copy Event Logs to a temporary directory and use the -d option. Additionally, use the --inc option to only include specific EventIDs in the processing.&#x20;

You have extracted the Event Log to a folder named e:\evtx\logs, and now you want to process all those logs in a single command.&#x20;

```powerquery
EvtxECmd.exe -d E:\evtx\logs --csv G:\evtx\out --csvf evtxecmd_out.csv 
```

Process all event logs and only include event\_id specifi ed by the --inc option&#x20;

{% code overflow="wrap" %}
```powerquery
EvtxECmd.exe -d E:\evtx\logs --csv G:\evtx\out --csvf evtxecmd_out.csv --inc 4624,4625,4634,4647,4672
```
{% endcode %}

&#x20;Exclude specific event\_id’s by using the -exc option&#x20;

{% code overflow="wrap" %}
```powerquery
EvtxECmd.exe -d E:\evtx\logs --csv G:\evtx\out --csvf evtxecmd_out.csv --exc 4656,4660,4663
```
{% endcode %}

#### &#x20;Key Data Returned

Events without maps are still processed, but output format will vary. The normalized Event Log output makes it possible to analyze many different types of Event Logs in a single view. Timeline Explorer is perfect for this analysis.

#### Output Fields

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 135508.png" alt=""><figcaption></figcaption></figure>

***

### Interesting Log Sources <a href="#interesting-log-sources" id="interesting-log-sources"></a>

| Log sources                                                                  | Context                                        |
| ---------------------------------------------------------------------------- | ---------------------------------------------- |
| Security.evtx                                                                | Security-related events                        |
| System.evtx                                                                  | Tracks system component events                 |
| Application.evtx                                                             | Logs application-specific events               |
| Microsoft-Windows-Sysmon/Operational.evtx                                    | Enhanced process, network, and file monitoring |
| Microsoft-Windows-PowerShell/4Operational.evtx                               | Records PowerShell activity                    |
| Microsoft-Windows-Windows Defender/Operational.evtx                          | Logs Windows Defender events                   |
| Microsoft-Windows-WMI-Activity/4Operational.evtx                             | Logs WMI events                                |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx | Logs RDP session events                        |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx      | Logs RDP session events                        |
| Microsoft-Windows-TaskScheduler/Operational.evtx                             | Logs Task Scheduler events                     |
| Microsoft-Windows-DNS-Server%4Operational.evtx                               | Active Directory Server Logs                   |
| Directory Service.evtx                                                       | Active Directory Server Logs                   |
| File Replication Service.evtx                                                | Active Directory Server Logs                   |
| %SystemDrive%\inetpub\logs\LogFiles                                          | IIS log                                        |
| %SystemRoot%\System32\LogFiles\HTTPERR                                       | IIS log                                        |
| %ProgramFiles%\Microsoft\Exchange Server\V15\Logging                         | Exchange log                                   |
| Panther\*.log                                                                | Windows setup details                          |
| RPC Client Access\*.log                                                      | Exchange Server, if applicable                 |
| Third party antivirus log                                                    | AV logs                                        |

***

### User Account Access

<table><thead><tr><th width="108">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>4624</td><td>An account was successfully logged on</td><td>This event can identify a user logon time and the method that they logged on. The “Logon Type” field is critical to determining the logon method</td></tr><tr><td>4625</td><td>An account failed to logon</td><td>This may indicate brute-force attempts to access the account or mistakes made by a threat actor when attempting to logon as a legitimate user</td></tr><tr><td>4648</td><td>A logon was attempted using explicit credentials</td><td>This can highlight the usage of the “runas” command and may indicate compromised accounts. Other logs must be correlated to provide context to these events</td></tr><tr><td>4672</td><td>Special privileges assigned to a new logon</td><td>These events should be correlated against accounts that have high-level and administrator-level permissions. It is normal for SYSTEM to generate a high-volume of these events</td></tr></tbody></table>

***

### User Account Management

<table><thead><tr><th width="113">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>4720</td><td>A user account was created</td><td>The creation of new users on a host can be an indicator of a threat actor trying to blend in with normal activity</td></tr><tr><td>4722</td><td>A user account was enabled</td><td>A threat actor may utilise dormant accounts with access to privileged groups. Unexpected enablement or re-enablement of accounts should be investigated</td></tr><tr><td>4724</td><td>An attempt was made to reset an accounts password</td><td>Resetting an account password by a TA can provide a persistence mechanism and potentially lock out a legitimate user</td></tr><tr><td>4728, 4732, 4756</td><td>Group membership changes</td><td>A threat actor may attempt to add their compromised user account to other domain groups in order to access other areas of the network</td></tr></tbody></table>

***

### Remote Desktop Activity

<table><thead><tr><th width="118">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>46241 (Type 10)</td><td>An account was successfully logged on</td><td>A Type 10 4624 event indicates that a user performed a logon via the Remote Desktop Protocol (RDP)</td></tr><tr><td>1149</td><td>User authentication succeeded</td><td>This event shows that a connection was made over RDP. However, it is not indicative of a logon event. The username and IP address of the source host may be available within this event</td></tr><tr><td>21</td><td>Remote Desktop Services: Session logon succeeded</td><td>Indicates a successful logon via RDP if the source network address is not "LOCAL.". The username and source IP address may be available within this event</td></tr><tr><td>24</td><td>Remote Desktop Services: Session has been disconnected</td><td>The user has disconnected from an RDP session</td></tr><tr><td>25</td><td>Remote Desktop Services: Session reconnection succeeded</td><td>The user has reconnected to an RDP session</td></tr></tbody></table>

***

### Hunting Persistence

<table><thead><tr><th width="98">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>7045</td><td>New Service Creation</td><td>This is recorded in the system log when a new service is installed</td></tr><tr><td>4697</td><td>A service was installed in the system</td><td>Security log entry for new service creation</td></tr><tr><td>4698</td><td>A scheduled task was created</td><td>Similar to service creation, security log track the creation of scheduled tasks</td></tr></tbody></table>

***

### PowerShell Activity

<table><thead><tr><th width="188">EventID &#x26; Channel</th><th>Description</th><th></th></tr></thead><tbody><tr><td>4104</td><td>PowerShell ScriptBlock Logging</td><td>When enabled, this event will record the PowerShell script that has been executed</td></tr><tr><td></td><td></td><td></td></tr><tr><td></td><td></td><td></td></tr></tbody></table>

***

### File sharing <a href="#id-2-file-sharing" id="id-2-file-sharing"></a>

#### Windows Admin share (net use) <a href="#windows-admin-share-net-use" id="windows-admin-share-net-use"></a>

Commonly for transferring their tools and malware. Or it can be abused to exfiltrate data.

| Event Log          | Event ID                                 | Computer    |
| ------------------ | ---------------------------------------- | ----------- |
| Security           | 4648                                     | Source      |
| SMBClient-Security | 31001                                    | Source      |
| Security           | 4624, 4672, 4776, 4768, 4769, 5140, 5145 | Destination |

| Filesystem          | Location                                                                             | Computer |
| ------------------- | ------------------------------------------------------------------------------------ | -------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\net.EXE-RANDOM.pf` and `C:\Windows\Prefetch\net1.EXE-RANDOM.pf` | Source   |
| Jumplist            | `C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`  | Source   |
| USNJ or MFT         | Created file                                                                         | Source   |

| Registry                  | Findings                                                                 | Computer |
| ------------------------- | ------------------------------------------------------------------------ | -------- |
| User Profile (NTUSER.DAT) | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Source   |
| USRCLASS.dat              | Shellbags (Remote folders accessed)                                      | Source   |
| Shimcache (SYSTEM)        | `net.exe` and `net1.exe`                                                 | Source   |
| BAM/DAM (SYSTEM)          | Last time executed `net.exe` and `net1.exe`                              | Source   |
| Amcache.hve               | First Execution time of `net.exe` and `net1.exe`                         | Source   |

***

### Remote login <a href="#id-3-remote-login" id="id-3-remote-login"></a>

An attacker might utilise the remote login feature such as RDP, VNC, external software or SSH to login remotely

### RDP <a href="#rdp" id="rdp"></a>

| Event Log                            | Event ID                               | Computer    |
| ------------------------------------ | -------------------------------------- | ----------- |
| Security                             | 4648                                   | Source      |
| RDPClient Operational                | 1024, 1025, 1026, 1102                 | Source      |
| Security                             | 4624 (logon type 10 or 12), 4778, 4779 | Destination |
| RDPCoreTS Operational                | 131, 98, 99                            | Destination |
| RemoteConnection Manager Operational | 1149                                   | Destination |
| RemoteConnection Manager Admin       | 1158                                   | Destination |
| LocalSession Manager Operational     | 21, 23, 24, 25, 41                     | Destination |

| Filesystem          | Location                                                                                                                   | Computer    |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\MSTSC.EXE-RANDOM.pf`                                                                                  | Source      |
| Jumplist            | `C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` (MSTSC-APPID-automaticDestinations-ms) | Source      |
| Bitmap Cache        | `C:\Users\USERNAME\AppData\Local\Microsoft\Terminal Server Client\Cache\*`                                                 | Source      |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\rdpclip.exe-RANDOM.pf` and `C:\Windows\Prefetch\tstheme.exe-RANDOM.pf`                                | Destination |

| Registry                  | Findings                                                   | Computer    |
| ------------------------- | ---------------------------------------------------------- | ----------- |
| User Profile (NTUSER.DAT) | `NTUSER\SOFTWARE\Microsoft\Terminal Server Client\Servers` | Source      |
| Shimcache (SYSTEM)        | `mstsc.exe`                                                | Source      |
| BAM/DAM (SYSTEM)          | Last Execution time of `mstsc.exe`                         | Source      |
| Amcache.hve               | First Execution time of `mstsc.exe`                        | Source      |
| UserAssist (NTUSER.dat)   | Last Execution time and Numbers of Times of `mstsc.exe`    | Source      |
| RecentApps (NTUSER.DAT)   | Last Execution time and Numbers of Times of `mstsc.exe`    | Source      |
| ShimCache (SYSTEM)        | `rdpclip.exe` and `tstheme.exe`                            | Destination |
| AmCache.hve               | `rdpclip.exe` and `tstheme.exe`                            | Destination |

***

### SSH <a href="#ssh" id="ssh"></a>

| Event Log | Event ID             | Computer    |
| --------- | -------------------- | ----------- |
| Security  | 4624,4625,4688, 5154 | Destination |
| System    | 10016                | Destination |

| Filesystem          | Location                                             | Computer    |
| ------------------- | ---------------------------------------------------- | ----------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[SSH executable].exe-RANDOM.pf` | Destination |

| Registry                  | Findings                                 | Computer    |
| ------------------------- | ---------------------------------------- | ----------- |
| User Profile (NTUSER.DAT) | `Software\SimonTatham\PuTTY\SshHostKeys` | Destination |

***

### Remote Execution <a href="#remote-execution" id="remote-execution"></a>

### Pass-The-Hash-Ticket (WCE) <a href="#pass-the-hash-ticket-wce" id="pass-the-hash-ticket-wce"></a>

| Event Log | Event ID                | Computer    |
| --------- | ----------------------- | ----------- |
| System    | 7045, 7036 (WCESERVICE) | Source      |
| Security  | 4624, 4634              | Destination |
| Security  | 4776, 4771, 5156        | DC          |

| Filesystem          | Location                                        | Computer |
| ------------------- | ----------------------------------------------- | -------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[Tool name].exe-RANDOM.pf` | Source   |
| USNJ                | wceaux.dll\`                                    | Source   |

***

### Pass-The-Hash-Ticket (Mimikatz) <a href="#pass-the-hash-ticket-mimikatz" id="pass-the-hash-ticket-mimikatz"></a>

| Event Log | Event ID               | Computer    |
| --------- | ---------------------- | ----------- |
| Security  | 4624, 4672, 4634       | Destination |
| Security  | 4776, 4771, 5156, 4769 | DC          |

| Filesystem          | Location                                        | Computer |
| ------------------- | ----------------------------------------------- | -------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[Tool name].exe-RANDOM.pf` | Source   |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\WMIC.EXE-[RANDOM].pf`      | Source   |

***

### PsExec <a href="#psexec" id="psexec"></a>

| Event Log | Event ID                             | Computer    |
| --------- | ------------------------------------ | ----------- |
| Security  | 4648                                 | Source      |
| Security  | 4624 (Logon type 3 or 2), 4672, 5140 | Destination |
| System    | 7045, 7036                           | Destination |

| Filesystem          | Location                                                         | Computer    |
| ------------------- | ---------------------------------------------------------------- | ----------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[Executable File Name of Tool]-[RANDOM].pf` | Source      |
| MFT, USNJ           | psexec.exe executable                                            | Source      |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\PSEXESVC.EXE-RANDOM.pf`                     | Destination |
| C:\Windows          | `psexesvc.exe` or renamed executable                             | Destination |

| Registry                  | Findings                                           | Computer    |
| ------------------------- | -------------------------------------------------- | ----------- |
| User Profile (NTUSER.DAT) | `NTUSER\SOFTWARE\Sysinternals\PsExec\EulaAccepted` | Source      |
| Shimcache (SYSTEM)        | `psexec.exe`                                       | Source      |
| BAM/DAM (SYSTEM)          | Last execution time of`psexec.exe`                 | Source      |
| Amcache.hve               | First Execution time of `psexec.exe`               | Source      |
| SYSTEM                    | `SYSTEM\CurrentControlSet\Services\PSEXESVC`       | Destination |
| Shimcache (SYSTEM)        | `psexecsvc.exe`                                    | Destination |
| Amcache.hve               | First Execution time of `psexecsvc.exe`            | Destination |

***

### Remote Services <a href="#remote-services" id="remote-services"></a>

| Event Log | Event ID                     | Computer    |
| --------- | ---------------------------- | ----------- |
| Security  | 4624 (Logon type 3), 4697    | Destination |
| System    | 7034, 7035, 7036, 7040, 7045 | Destination |

| Filesystem          | Location                                 | Computer    |
| ------------------- | ---------------------------------------- | ----------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\sc.exe-RANDOM.pf`   | Source      |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.exe-RANDOM.pf` | Destination |
| File disk           | Creation of evil.exe or dll              | Destination |

| Registry           | Findings                           | Computer    |
| ------------------ | ---------------------------------- | ----------- |
| BAM/DAM (SYSTEM)   | `sc.exe`                           | Source      |
| Shimcache (SYSTEM) | `sc.exe`                           | Source      |
| Amcache.hve        | First Execution time of `sc.exe`   | Source      |
| SYSTEM             | `\CurrentControlSet\Services\`     | Destination |
| Shimcache (SYSTEM) | `evil.exe`                         | Destination |
| Amcache.hve        | First Execution time of `evil.exe` | Destination |

***

### Scheduled Task <a href="#scheduled-task" id="scheduled-task"></a>

| Event Log                  | Event ID                                 | Computer    |
| -------------------------- | ---------------------------------------- | ----------- |
| Security                   | 4648                                     | Source      |
| Security                   | 4672, 4624, 4698, 4702, 4699, 4700, 4701 | Destination |
| Task scheduler Operational | 106, 140, 141, 200, 201                  | Destination |

| Filesystem          | Location                                       | Computer    |
| ------------------- | ---------------------------------------------- | ----------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\SCHTASKS.EXE-[RANDOM].pf` | Source      |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\at.EXE-[RANDOM].pf`       | Source      |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\TASKENG.EXE-[RANDOM].pf`  | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.EXE-[RANDOM].pf`     | Destination |
| Job files           | `C:\Windows\Tasks`                             | Destination |
| Task files          | `C:\Wmdows\System32\Tasks`                     | Destination |

| Registry           | Findings                                                                               | Computer    |
| ------------------ | -------------------------------------------------------------------------------------- | ----------- |
| BAM/DAM (SYSTEM)   | `at.exe` and `schtasks.exe`                                                            | Source      |
| Shimcache (SYSTEM) | `at.exe` and `schtasks.exe`                                                            | Source      |
| Amcache.hve        | `at.exe` and `schtasks.exe`                                                            | Source      |
| Shimcache (SYSTEM) | `evil.exe`                                                                             | Destination |
| Amcache.hve        | First Execution time of `evil.exe`                                                     | Destination |
| SYSTEM             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\*` | Destination |

***

#### WMIC <a href="#wmic" id="wmic"></a>

| Event Log                | Event ID       | Computer    |
| ------------------------ | -------------- | ----------- |
| Security                 | 4648           | Source      |
| Security                 | 4624, 4672     | Destination |
| WMI Activity Operational | 5857,5860,5861 | Destination |

| Filesystem          | Location                                       | Computer    |
| ------------------- | ---------------------------------------------- | ----------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\WMIC.EXE-[RANDOM].pf`     | Source      |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.exe-[RANDOM].pf`     | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\scrcons.exe-[RANDOM].pf`  | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\mofcomp.exe-[RANDOM].pf`  | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\wmiprvse.exe-[RANDOM].pf` | Destination |
| WMI repository      | `C:\Windows\System32\wbem\Repository`          | Destination |
| File creation       | `evil.exe` or `evil.mof`                       | Destination |

| Registry           | Findings                                                 | Computer    |
| ------------------ | -------------------------------------------------------- | ----------- |
| Shimcache (SYSTEM) | `Wmic.exe`                                               | Source      |
| BAM/DAM (SYSTEM)   | `Wmic.exe`                                               | Source      |
| Amcache.hve        | First Execution time of `Wmic.exe`                       | Source      |
| ShimCache (SYSTEM) | `scrcons.exe`, `mofcomp.exe`, `wmiprvse.exe`, `evil.exe` | Destination |
| AmCache.hve        | `scrcons.exe`, `mofcomp.exe`, `wmiprvse.exe`, `evil.exe` | Destination |

***

### WinRM and Powershell <a href="#winrm-and-powershell" id="winrm-and-powershell"></a>

| Event Log              | Event ID                       | Computer    |
| ---------------------- | ------------------------------ | ----------- |
| Security               | 4648                           | Source      |
| WinRM Operational      | 6,8,15,16,33                   | Source      |
| Powershell Operational | 40691, 40692, 8193, 8194, 8197 | Source      |
| Security               | 4624, 4672                     | Destination |
| Powershell Operational | 4103, 4104, 53504              | Destination |
| Powershell             | 400, 403, 800                  | Destination |
| WinRM                  | 91, 168                        | Destination |

| Filesystem          | Location                                                                                            | Computer    |
| ------------------- | --------------------------------------------------------------------------------------------------- | ----------- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\powershell.exe-RANDOM.pf`                                                      | Source      |
| Conmand history     | `C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` | Source      |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.exe-RANDOM.pf`                                                            | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\wsmprovhost.exe-RANDOM.pf`                                                     | Destination |

| Registry           | Findings                                                               | Computer    |
| ------------------ | ---------------------------------------------------------------------- | ----------- |
| Shimcache (SYSTEM) | `Powershell.exe`                                                       | Source      |
| BAM/DAM (SYSTEM)   | `Powershell.exe`                                                       | Source      |
| Amcache.hve        | First Execution time of `Powershell.exe`                               | Source      |
| ShimCache (SYSTEM) | `wsmprovhost.exe` and `evil.exe`                                       | Destination |
| SOFTWARE           | `Microsoft\PowerShell\1\ShellIds\Microsoft.Powershell\ExecutionPolicy` | Destination |
| AmCache.hve        | `wsmprovhost.exe` and `evil.exe`                                       | Destination |

***

### SMB <a href="#smb" id="smb"></a>

| Event Log              | Event ID                                | Computer |
| ---------------------- | --------------------------------------- | -------- |
| Security               | 4688,4624,4656,5140,5142,5143,5144,5145 | Source   |
| SMB Server Operational | 4100,4103,4104,800,4104,40961,40962     | Source   |

***

#### DCOM <a href="#dcom" id="dcom"></a>

| Event Log | Event ID                          | Computer    |
| --------- | --------------------------------- | ----------- |
| Security  | 4624,4662, 4688, 4697, 4698, 4702 | Destination |

***

### File Transfer <a href="#file-transfer" id="file-transfer"></a>

| Event Log                                 | Event ID   | Computer    |
| ----------------------------------------- | ---------- | ----------- |
| Security                                  | 4688       | Destination |
| Microsoft-Windows-PowerShell/ Operational | 4103, 4104 | Destination |

***

### Important Security Event IDs <a href="#important-security-event-ids" id="important-security-event-ids"></a>

| IDs            | Event log     | Context                                                                               |
| -------------- | ------------- | ------------------------------------------------------------------------------------- |
| 4624           | Security      | Successful Login                                                                      |
| 4625           | Security      | Failed Login                                                                          |
| 4634/4647      | Security      | User Initiated Logoff/An Account was Logged Off                                       |
| 4648           | Security      | A Logon was Attempted Using Explicit Credentials                                      |
| 4662           | Security      | An Operation was Performed on an Object                                               |
| 4663           | Security      | An Attempt was Made to Access an Object                                               |
| 4672           | Security      | Special Logon                                                                         |
| 4688           | Security      | Process Creation                                                                      |
| 4689           | Security      | Process Termination                                                                   |
| 4697           | Security      | Service Installed                                                                     |
| 4698/4702/4700 | Security      | Scheduled Task Created or Updated                                                     |
| 4699           | Security      | Scheduled Task Deleted                                                                |
| 4701           | Security      | Scheduled Task Enabled                                                                |
| 4702           | Security      | Service Removed                                                                       |
| 4720           | Security      | A User Account was Created                                                            |
| 4722           | Security      | A User Account was Enabled                                                            |
| 4723           | Security      | An Attempt was Made to Change an Account’s Password                                   |
| 4724           | Security      | An Attempt was Made to Reset an Account’s Password                                    |
| 4725           | Security      | A User Account was Disabled                                                           |
| 4726           | Security      | A User Account was Deleted                                                            |
| 4728           | Security      | A Member was Added to a Security-Enabled Global Group                                 |
| 4729           | Security      | A Member was Removed from a Security-Enabled Global Group                             |
| 4732           | Security      | A Security-Enabled Local Group was Created                                            |
| 4733           | Security      | A Security-Enabled Local Group was Changed                                            |
| 4734           | Security      | A Security-Enabled Local Group was Deleted                                            |
| 4741           | Security      | A Computer Account was Created                                                        |
| 4742           | Security      | A Computer Account was Changed                                                        |
| 4768           | Security (DC) | Kerberos TGT request                                                                  |
| 4769           | Security (DC) | Kerberos Service Ticket request                                                       |
| 4771           | Security      | Locked Out Account                                                                    |
| 4776           | Security      | NTLM authentication                                                                   |
| 4778           | Security      | Session Reconnected                                                                   |
| 4779           | Security      | Session Disconnected by User                                                          |
| 4794           | Security      | An Attempt was Made to Set the Directory Services Restore Mode Administrator Password |
| 5136           | Security      | Directory Service Changes                                                             |
| 5140           | Security      | A Network Share Object was Accessed                                                   |
| 5141           | Security      | A Directory Service Object was Deleted                                                |
| 5145           | Security      | Network Share Object was Checked                                                      |
| 5376           | Security      | Credential Manager Credentials Submitted                                              |
| 5377           | Security      | Credential Manager Credentials Auto-Logon                                             |
| 1102           | Security      | Event Log Cleared                                                                     |
| 1100           | Security      | Event Log Service Shutdown                                                            |

***

### Logon type corresponding to successful (4624) or Failed logins (4625) <a href="#logon-type-corresponding-to-succesfull-4624-or-failed-logins-4625" id="logon-type-corresponding-to-succesfull-4624-or-failed-logins-4625"></a>

| Logon Type | Explanation                                                                   |
| ---------- | ----------------------------------------------------------------------------- |
| 2          | Logon via console                                                             |
| 3          | Network Logon. A user or computer logged on to this computer from the network |
| 4          | Batch Logon (Task scheduler and AT)                                           |
| 5          | Windows Service logon                                                         |
| 7          | Credentials used to unlock screen                                             |
| 8          | Network logon sending credentials (cleartext)                                 |
| 9          | Different credentials used than logon user                                    |
| 10         | Remote Interactive logon (RDP)                                                |
| 11         | Cached credentials used to logon                                              |
| 12         | Cached remote interactive (RDP)                                               |
| 13         | Cached Unlock (Similar to logon type 7)                                       |

***

### Other’s log important Event IDs <a href="#others-log-important-event-ids" id="others-log-important-event-ids"></a>

| IDs   | Event log                                                               | Context                                                   |
| ----- | ----------------------------------------------------------------------- | --------------------------------------------------------- |
| 7045  | System                                                                  | Service installed                                         |
| 7034  | System                                                                  | The service terminated unexpectedly                       |
| 7035  | System                                                                  | Service Control Manager                                   |
| 7036  | System                                                                  | Service State Change                                      |
| 7040  | System                                                                  | Service was changed from disabled to auto start.          |
| 7001  | System                                                                  | Service Start Failed                                      |
| 1001  | System                                                                  | BSOD                                                      |
| 6005  | System                                                                  | Start-up time of the machine                              |
| 6006  | System                                                                  | Shutdown time of the machine                              |
| 104   | System                                                                  | Log cleared                                               |
| 59    | MicrosoftWindows Bits Client/operational                                | Bits Jobs                                                 |
| 2004  | Microsoft-Windows-Windows Firewall with Advanced Security               | Rule has been added to the Window Firewall exception list |
| 2006  | Microsoft-Windows-Windows Firewall with Advanced Security               | Deleted firewall rule                                     |
| 1116  | Microsoft Windows Windows Defender/Operational                          | Defender Antivirus has detected malware                   |
| 1117  | Microsoft Windows Windows Defender/Operational                          | Action taken                                              |
| 1006  | Microsoft Windows Windows Defender/Operational                          | Scan result                                               |
| 4103  | Microsoft Windows PowerShell/Operational                                | Module logging                                            |
| 4104  | Microsoft Windows PowerShell/Operational                                | Script Block Logging                                      |
| 4105  | Microsoft Windows PowerShell/Operational                                | Transcription Logging                                     |
| 4688  | Microsoft Windows PowerShell/Operational                                | Process Creation (including PowerShell processes)         |
| 400   | Windows PowerShell                                                      | Start of a PowerShell activity, whether local or remote.  |
| 403   | Windows PowerShell                                                      | Completion of a PowerShell activity                       |
| 800   | Windows PowerShell                                                      | Pipeline execution                                        |
| 1000  | Application                                                             | Application Error/crash                                   |
| 1001  | Application                                                             | Application Error reporting                               |
| 1002  | Application                                                             | Application Hang                                          |
| 1024  | Application                                                             | Software Installation                                     |
| 1040  | Application                                                             | User Initiated Software Installation                      |
| 1033  | Application                                                             | Software installed                                        |
| 1034  | Application                                                             | Windows Installer removed the product                     |
| 11707 | Application                                                             | Installation operation completed successfully             |
| 11708 | Application                                                             | Installation failed                                       |
| 11724 | Application                                                             | Installation completed successfully                       |
| 1     | Microsoft-Windows-Sysmon/Operational                                    | Process Creation                                          |
| 2     | Microsoft-Windows-Sysmon/Operational                                    | A process changed a file creation time                    |
| 3     | Microsoft-Windows-Sysmon/Operational                                    | Network connection detected                               |
| 6     | Microsoft-Windows-Sysmon/Operational                                    | Driver Loaded                                             |
| 7     | Microsoft-Windows-Sysmon/Operational                                    | Image Loaded                                              |
| 8     | Microsoft-Windows-Sysmon/Operational                                    | CreateRemoteThread                                        |
| 10    | Microsoft-Windows-Sysmon/Operational                                    | ProcessAccess                                             |
| 11    | Microsoft-Windows-Sysmon/Operational                                    | FileCreate                                                |
| 12    | Microsoft-Windows-Sysmon/Operational                                    | RegistryEvent (Object create and delete)                  |
| 1149  | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP User authentication succeeded                         |
| 21    | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP Session logon succeeded                               |
| 24    | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP Session has been disconnected                         |
| 25    | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP Session reconnection succeeded                        |
| 131   | RDPCoreTS                                                               | RDP connection is first established                       |
| 106   | Task Scheduler                                                          | New scheduled task is created                             |
| 140   | Task Scheduler                                                          | New scheduled task is created                             |
| 141   | Task Scheduler                                                          | User deleted Task Scheduler task                          |
| 200   | Task Scheduler                                                          | Task executed                                             |
| 201   | Task Scheduler                                                          | Task scheduler successfully completed the task            |
| 5857  | WMI-Activity Operational                                                | WMI activity is detected                                  |
| 5858  | WMI-Activity Operational                                                | WMI error                                                 |
| 5859  | WMI-Activity Operational                                                | Subscription-based activity                               |
| 5860  | WMI-Activity Operational                                                | Detailed subscription-based activity                      |
| 5861  | WMI-Activity Operational                                                | Permanent subscription activity                           |
