# Detecting Command Line Interpreters Launched via Scheduled Tasks

### KQL Queries:&#x20;

{% tabs %}
{% tab title="Option 1" %}
KQL query to discover command line interpreters launched via scheduled tasks:

{% code overflow="wrap" %}
```kusto
// Define patterns to identify command line interpreters
let CommandLineInterpreters = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "mshta.exe", "cscript.exe", "wscript.exe"]);
// Query DeviceProcessEvents table
DeviceProcessEvents
| where ((InitiatingProcessFileName =~ "taskeng.exe") // For anything pre-Windows 10 version 1511
    or (InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has "Schedule")) // For anything post Windows 10 version 1511
| where FileName in~ (CommandLineInterpreters) // Match command line interpreters
| summarize
    Devices = make_set(DeviceName),
    NumberOfDevices = dcount(DeviceName),
    UniqueUsers = dcount(AccountName),
    TotalEvents = count()
    by ProcessCommandLine, FileName, FolderPath, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| order by TotalEvents desc
| project TimeGenerated, ProcessCommandLine, FileName, FolderPath, InitiatingProcessFileName, Devices, NumberOfDevices, UniqueUsers, TotalEvents

```
{% endcode %}

#### Explanation:

1. **Pattern Matching**: The `CommandLineInterpreters` dynamic array contains common command line interpreters.
2. **Filtering**: The `where` clauses filter the `DeviceProcessEvents` table to retain only events where command line interpreters were launched via scheduled tasks.
3. **Summarisation**: The `summarise` statement aggregates the data to count the number of devices and list the devices for each command line.
4. **Ordering**: The results are ordered by the number of devices in descending order.
5. **Projection**: The `project` statement selects the relevant columns for the final output.
{% endtab %}

{% tab title="Option 2" %}
KQL (Kusto Query Language) query to discover command-line interpreters (e.g., `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `bash.exe`) launched via scheduled tasks:

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)  // Adjust time range as needed
| where InitiatingProcessFileName has "schtasks.exe" or InitiatingProcessCommandLine has "Task Scheduler"
| where FileName in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "bash.exe")
| extend ScheduledTaskName = extract(@"\s*/TN\s*(\S+)", 1, InitiatingProcessCommandLine)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ScheduledTaskName
| summarize Count = count() by DeviceName, AccountName, FileName, ScheduledTaskName
| order by Count desc
```
{% endcode %}

#### Explanation:

1. **Filter by Time Range**:
   * The query examines events from the last 7 days (adjustable).
2. **Scheduled Task Detection**:
   * Matches processes where the parent process is `schtasks.exe` or has "Task Scheduler" in its command line.
3. **Target Command-Line Interpreters**:
   * Filters child processes to include common command-line interpreters (`cmd.exe`, `powershell.exe`, etc.).
4. **Scheduled Task Extraction**:
   * Uses a regex (`/TN`) to extract the name of the scheduled task from the initiating process’s command line.
5. **Projection**:
   * Displays relevant details such as the device, account, command line, and scheduled task name.
6. **Aggregation**:
   * Groups results by `DeviceName`, `AccountName`, `FileName`, and `ScheduledTaskName`, with a count of occurrences.
7. **Sorting**:
   * Sorts by the number of occurrences (`Count`) to highlight the most frequent events.

#### Example Use Cases:

* **Threat Hunting**: Detect unauthorised or malicious use of scheduled tasks to launch command-line interpreters.
* **Anomaly Detection**: Identify unusual behaviour where interpreters are invoked via scheduled tasks.
* **Forensic Analysis**: Investigate post-compromise activities involving scheduled tasks.
{% endtab %}
{% endtabs %}

### Splunk Queries:

{% tabs %}
{% tab title="Option 1" %}
To detect **Command Line Interpreters launched via Scheduled Tasks** in Splunk using the `sysmon` index, you can use the following  SPL (Search Processing Language) query. It leverages Sysmon Event IDs, processes commonly associated with command-line interpreters, and their execution context.

{% code overflow="wrap" %}
```kusto
index=sysmon EventCode=1 
| eval is_scheduled_task=if((ParentImage="*\\taskeng.exe" OR ParentImage="*\\svchost.exe" OR CommandLine="schtasks*"), "true", "false")
| search is_scheduled_task="true"
| eval is_interpreter=if((Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\pwsh.exe" OR Image="*\\bash.exe"), "true", "false")
| search is_interpreter="true"
| table _time ComputerName User Image ParentImage CommandLine
| rename Image as "Interpreter", ParentImage as "Parent Process"
| sort - _time
```
{% endcode %}

#### Explanation of the Query:

1. **Index and Event Filtering:**
   * `index=sysmon` filters to only events within the `sysmon` index.
   * `EventCode=1`focuses on process creation events.
2. **Parent Process Check (Scheduled Tasks):**
   * `ParentImage="*\\taskeng.exe"` or `ParentImage="*\\svchost.exe"` indicates the process is potentially related to Scheduled Tasks.
   * `CommandLine="schtasks*"`captures executions directly involving `schtasks`.
3. **Command-Line Interpreter Filtering:**
   * Filters for commonly abused command-line interpreters, including `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `pwsh.exe`, and `bash.exe`.
4. **Conditional Evaluation and Final Filtering:**
   * Uses `eval` to tag events based on parent process or interpreter usage.
   * Filters only events where `is_scheduled_task` and `is_interpreter` are both true.
5. **Tabular Results:**
   * Displays relevant fields: `Interpreter`, `Parent Process`, `CommandLine`, `User`, `ComputerName`, and `_time`.
6. **Sorting:**
   * Sort results by timestamp for analysis.
{% endtab %}

{% tab title="Option 2" %}
The following Splunk query will search for command line interpreters launched via scheduled tasks using the `sysmon` index:

{% code overflow="wrap" %}
```kusto
index=sysmon
sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=1
| eval CommandLineInterpreters=mvappend("cmd.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "mshta.exe", "cscript.exe", "wscript.exe")
| eval IsInterpreter=if(match(CommandLine, mvjoin(CommandLineInterpreters, "|")), 1, 0)
| where IsInterpreter=1
| eval IsScheduledTask=if(match(ParentCommandLine, "schtasks.exe") OR match(ParentCommandLine, "taskeng.exe"), 1, 0)
| where IsScheduledTask=1
| stats count as TotalEvents, dc(host) as UniqueDevices, dc(user) as UniqueUsers by CommandLine, ParentCommandLine, Image, ParentImage
| sort - TotalEvents
| table _time, CommandLine, ParentCommandLine, Image, ParentImage, TotalEvents, UniqueDevices, UniqueUsers
```
{% endcode %}

#### Explanation:

1. **Index and Sourcetype**: The query filters the `sysmon` index and `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` sourcetype for process creation events (EventCode=1).
2. **Pattern Matching**: The `CommandLineInterpreters` array contains common command line interpreters.
3. **Evaluation**: The `eval` statements create flags (`IsInterpreter` and `IsScheduledTask`) to identify command lines containing interpreters and those launched via scheduled tasks.
4. **Filtering**: The `where` clauses filter the events to retain only those with command line interpreters launched via scheduled tasks.
5. **Aggregation**: The `stats`command aggregates the data to count the total number of events, unique devices, and unique users for each command line, parent command line, image, and parent image.
6. **Sorting and Display**: The results are sorted by the total number of events in descending order and displayed in a table format.
{% endtab %}
{% endtabs %}
