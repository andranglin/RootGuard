# Identify Processes Launched by PowerShell Remoting (WSMProvHost.exe)

### Description of the Query:

This KQL query is designed to detect processes launched by **PowerShell Remoting**, specifically those initiated by `WSMProvHost.exe`. PowerShell Remoting is a legitimate feature of PowerShell that allows administrators to execute commands on remote systems. However, attackers can abuse this functionality to execute malicious commands or scripts on remote machines without directly interacting with the target system.

The query focuses on identifying processes spawned by `WSMProvHost.exe`, which is the host process for PowerShell Remoting sessions. By analysing process creation events (`ProcessCreate`), the query detects when `WSMProvHost.exe` launches child processes. This helps security teams identify potential misuse of PowerShell Remoting for lateral movement, persistence, or other malicious activities.

### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect Processes Launched by PowerShell Remoting (WSMProvHost.exe)
DeviceProcessEvents
| where Timestamp > ago(1d) // Limit results to the last 24 hours
| where ActionType == "ProcessCreate" // Focus on process creation events
| where InitiatingProcessFileName contains "WSMProvHost.exe" // Filter for processes initiated by WSMProvHost.exe
| extend UserName = tostring(split(InitiatingProcessAccountName, @"\")[1]) // Extract username for context
| project
    Timestamp,
    DeviceName,
    UserName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

### Explanation of the Query:

1. **Filtering Process Creation Events** :
   * The query starts by filtering for `ProcessCreate` events (`ActionType == "ProcessCreate"`) within the last 24 hours (`Timestamp > ago(1d)`).
2. **Identifying PowerShell Remoting** :
   * It specifically looks for processes initiated by `WSMProvHost.exe` (`InitiatingProcessName contains "WSMProvHost.exe"`). This process is responsible for hosting PowerShell Remoting sessions and executing commands remotely.
3. **Extracting Contextual Information** :
   * The `UserName` is extracted from the `InitiatingProcessAccountName` to provide additional context about the user account under which the PowerShell Remoting session was initiated.
   * The `InitiatingProcessCommandLine` provides details about the command executed by `WSMProvHost.exe`.
4. **Projecting Relevant Columns** :
   * The query projects relevant fields such as:
     * `Timestamp`: When the event occurred.
     * `DeviceName`: The name of the device where the process was launched.
     * `UserName`: The user account associated with the PowerShell Remoting session.
     * `ProcessName`: The name of the process launched by `WSMProvHost.exe`.
     * `ProcessCommandLine`: The command line used to launch the process.
     * `InitiatingProcessName`: The name of the initiating process (`WSMProvHost.exe`).
     * `InitiatingProcessCommandLine`: The command line of the initiating process.
     * `InitiatingProcessAccountName`: The account name of the initiating process.
     * `ActionType`: The type of action (e.g., `ProcessCreate`).
5. **Sorting Results** :
   * The results are sorted by `Timestamp` in descending order to show the most recent events first.

### Use Case:

This query is handy for detecting:

* **Lateral Movement**: Attackers using PowerShell Remoting to execute commands on remote systems as part of lateral movement.
* **Persistence**: Malicious actors leveraging PowerShell Remoting to maintain access to compromised systems.
* **Command Execution**: Identifying suspicious commands or scripts executed via PowerShell Remoting.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious PowerShell Remoting activity and investigate potential threats.

### Notes:

* **False Positives**: Legitimate administrative tasks may also use PowerShell Remoting. Analysts should review the results to differentiate between benign and malicious activity.
* **Customisation**: The query can be customised to filter for specific devices, users, or time ranges based on the organisation's environment and known attack vectors.
* **Performance**: To optimise performance, consider narrowing the time range or filtering by specific devices/users if needed.
