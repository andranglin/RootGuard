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

# Windows Event Logs

#### Description&#x20;

Windows Event Logs are separated into different log roles and record a wide range of events that occur on the Windows host.

There are many Event Logs in the evtx folder, some aimed at system-wide events like Security.evtx, System.evtx, and Application.evtx. Others may contain more specific events. All Event Logs are stored in the same format, but the actual data elements collected varies. It is this variation of data elements that makes the correlation of Event Logs a challenge. This is where EvtxECmd shines. All events are normalized across all event types and across all Event Logs file types!&#x20;

The EvtxECmd parser has custom maps and locked file support. EvtxECmd has a unique feature, “Maps,” that allows for consistent output. Event Log Location: Event Logs for Windows Vista or later are found in %systemroot%\System32\winevt\logs Parsing all events could end in millions of results. Using EvtxCMD's maps can help target specifi c artifacts.

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

```
EvtxECmd.exe -d E:\evtx\logs --csv G:\evtx\out --csvf evtxecmd_out.csv 
```

Process all event logs and only include event\_id specifi ed by the --inc option&#x20;

{% code overflow="wrap" %}
```powershell
EvtxECmd.exe -d E:\evtx\logs --csv G:\evtx\out --csvf evtxecmd_out.csv --inc 4624,4625,4634,4647,4672
```
{% endcode %}

&#x20;Exclude specific event\_id’s by using the -exc option&#x20;

{% code overflow="wrap" %}
```
EvtxECmd.exe -d E:\evtx\logs --csv G:\evtx\out --csvf evtxecmd_out.csv --exc 4656,4660,4663
```
{% endcode %}

#### &#x20;Key Data Returned

Events without maps are still processed, but output format will vary. The normalized Event Log output makes it possible to analyze many different types of Event Logs in a single view. Timeline Explorer is perfect for this analysis

#### Output Fields

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 135508.png" alt=""><figcaption></figcaption></figure>

#### Notable EventIDs—User Account Access

<table><thead><tr><th width="108">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>4624</td><td>An account was successfully logged on</td><td>This event can identify a user logon time and the method that they logged on. The “Logon Type” field is critical to determining the logon method</td></tr><tr><td>4625</td><td>An account failed to logon</td><td>This may indicate brute-force attempts to access the account or mistakes made by a threat actor when attempting to logon as a legitimate user</td></tr><tr><td>4648</td><td>A logon was attempted using explicit credentials</td><td>This can highlight the usage of the “runas” command and may indicate compromised accounts. Other logs must be correlated to provide context to these events</td></tr><tr><td>4672</td><td>Special privileges assigned to a new logon</td><td>These events should be correlated against accounts that have high-level and administrator-level permissions. It is normal for SYSTEM to generate a high-volume of these events</td></tr></tbody></table>

#### Notable EventIDs—User Account Management

<table><thead><tr><th width="113">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>4720</td><td>A user account was created</td><td>The creation of new users on a host can be an indicator of a threat actor trying to blend in with normal activity</td></tr><tr><td>4722</td><td>A user account was enabled</td><td>A threat actor may utilise dormant accounts with access to privileged groups. Unexpected enablement or re-enablement of accounts should be investigated</td></tr><tr><td>4724</td><td>An attempt was made to reset an accounts password</td><td>Resetting an account password by a TA can provide a persistence mechanism and potentially lock out a legitimate user</td></tr><tr><td>4728, 4732, 4756</td><td>Group membership changes</td><td>A threat actor may attempt to add their compromised user account to other domain groups in order to access other areas of the network</td></tr></tbody></table>

#### Notable Event IDs—Remote Desktop Activity

<table><thead><tr><th width="118">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>46241 (Type 10)</td><td>An account was successfully logged on</td><td>A Type 10 4624 event indicates that a user performed a logon via the Remote Desktop Protocol (RDP)</td></tr><tr><td>1149</td><td>User authentication succeeded</td><td>This event shows that a connection was made over RDP. However, it is not indicative of a logon event. The username and IP address of the source host may be available within this event</td></tr><tr><td>21</td><td>Remote Desktop Services: Session logon succeeded</td><td>Indicates a successful logon via RDP if the source network address is not "LOCAL.". The username and source IP address may be available within this event</td></tr><tr><td>24</td><td>Remote Desktop Services: Session has been disconnected</td><td>The user has disconnected from an RDP session</td></tr><tr><td>25</td><td>Remote Desktop Services: Session reconnection succeeded</td><td>The user has reconnected to an RDP session</td></tr></tbody></table>

#### Notable EventIDs—Hunting Persistence

<table><thead><tr><th width="98">EventID</th><th>Description</th><th>Forensic Analysis</th></tr></thead><tbody><tr><td>7045</td><td>New Service Creation</td><td>This is recorded in the system log when a new service is installed</td></tr><tr><td>4697</td><td>A service was installed in the system</td><td>Security log entry for new service creation</td></tr><tr><td>4698</td><td>A scheduled task was created</td><td>Similar to service creation, security log track the creation of scheduled tasks</td></tr></tbody></table>

#### Notable EventIDs—PowerShell Activity

<table><thead><tr><th width="188">EventID &#x26; Channel</th><th>Description</th><th></th></tr></thead><tbody><tr><td>4104</td><td>PowerShell ScriptBlock Logging</td><td>When enabled, this event will record the PowerShell script that has been executed</td></tr><tr><td></td><td></td><td></td></tr><tr><td></td><td></td><td></td></tr></tbody></table>

