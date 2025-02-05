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

# Detect Execution of PSEXESVC via Remote Systems

### Description of the Query:

This KQL query is designed to detect the execution of **`PSEXESVC`** via a remote system. `PSEXESVC` is the service associated with **PsExec,** a legitimate tool from Sysinternals used for remote process executio&#x6E;**.** While administrators commonly use **PsExec** for legitimate purposes, attackers often abuse it for lateral movement, privilege escalation, or executing malicious payloads on remote systems.

The query focuses on identifying process creation events (`ProcessCreate`) where `PSEXESVC.exe` is executed on a target system by a remote system. It analyses the parent process and command line to determine if the execution originated from a remote source. By correlating this information, security teams can identify potential misuse of PsExec for malicious activities.

### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect Execution of PSEXESVC via a Remote System
DeviceProcessEvents
| where Timestamp > ago(1d) // Limit results to the last 24 hours
| where ActionType == "ProcessCreate" // Focus on process creation events
| where InitiatingProcessFileName contains "PSEXESVC.exe" // Filter for PSEXESVC execution
| extend ParentProcessName = InitiatingProcessFileName // Extract the parent process name
| extend ParentCommandLine = InitiatingProcessCommandLine // Extract the parent process command line
| extend UserName = tostring(split(InitiatingProcessAccountName, @"\")[1]) // Extract username for context
| extend IsRemoteExecution = iff(ParentCommandLine contains @"\\" or ParentCommandLine contains "remotetools", true, false)
| where IsRemoteExecution == true // Focus on events involving remote execution
| project
    Timestamp,
    DeviceName,
    UserName,
    InitiatingProcessAccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    ParentCommandLine,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

#### Explanation of the Query:

1. **Filtering Process Creation Events** :
   * The query starts by filtering for `ProcessCreate` events (`ActionType == "ProcessCreate"`) within the last 24 hours (`Timestamp > ago(1d)`).
2. **Identifying PSEXESVC Execution** :
   * It specifically looks for processes named `PSEXESVC.exe` (`ProcessName contains "PSEXESVC.exe"`), which is the service associated with PsExec.
3. **Analysing Parent Process** :
   * The `ParentProcessName` and `ParentCommandLine` are extracted to analyse the process that initiated `PSEXESVC.exe`.
   * The `InitiatingProcessAccountName` is used to extract the `UserName` for additional context about the user account under which the activity occurred.
4. **Detecting Remote Execution** :
   * The query checks if the `ParentCommandLine` contains indicators of remote execution:
     * `@\\`: A common pattern in PsExec commands when specifying a remote system.
     * `"remotetools"`: A keyword that may appear in PsExec-related activity.
   * The `IsRemoteExecution` flag is set to `true` if the parent process command line matches these criteria.
5. **Projecting Relevant Columns** :
   * The query projects relevant fields such as:
     * `Timestamp`: When the event occurred.
     * `DeviceName`: The name of the device where `PSEXESVC.exe` was executed.
     * `UserName`: The user account associated with the activity.
     * `ProcessName`: The name of the process (`PSEXESVC.exe`).
     * `ProcessCommandLine`: The command line used to launch the process.
     * `ParentProcessName`: The name of the parent process that initiated `PSEXESVC.exe`.
     * `ParentCommandLine`: The command line of the parent process.
     * `InitiatingProcessAccountName`: The account name of the initiating process.
     * `ActionType`: The type of action (e.g., `ProcessCreate`).
6. **Sorting Results** :
   * The results are sorted by `Timestamp` in descending order to show the most recent events first.

### Use Case:

This query is particularly useful for detecting:

* **Lateral Movement**: Attackers using PsExec to execute commands or payloads on remote systems as part of lateral movement.
* **Privilege Escalation**: Misuse of PsExec to escalate privileges or execute high-privilege commands.
* **Malware Deployment**: Attackers leveraging PsExec to deploy malware across multiple systems.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious PsExec activity and investigate potential threats.

### Notes:

* **False Positives**: Legitimate administrative tasks may also use PsExec for remote management. Analysts should review the results to differentiate between benign and malicious activity.
* **Customisation**: The query can be customised to filter for specific devices, users, or time ranges based on the organisation's environment and known attack vectors.
* **Performance**: To optimise performance, consider narrowing the time range or filtering by specific devices/users if needed.
