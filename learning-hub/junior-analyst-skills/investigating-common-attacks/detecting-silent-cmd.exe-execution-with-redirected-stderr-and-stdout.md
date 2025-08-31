# Detecting Silent cmd.exe Execution With Redirected STDERR & STDOUT

This query helps identify instances where `cmd.exe` is executed silently with output redirection, which can be indicative of malicious activity or attempts to hide command execution.

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where FileName =~ "cmd.exe" // Filter events where the process name is cmd.exe
| where ProcessCommandLine has_all ("/Q", "/C") // Filter events where the command line contains /Q and /C
| where ProcessCommandLine has_any ("&1", "2>&1") // Filter events where the command line contains &1 or 2>&1
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ProcessCommandLine // Project relevant columns for the final output
| order by Timestamp desc // Order the results by Timestamp in descending order
```
{% endcode %}

Below is an extended version of the query:

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where FileName =~ "cmd.exe" // Filter events where the process name is cmd.exe
| where ProcessCommandLine has_all ("/Q", "/C") // Filter events where the command line contains /Q and /C
| where ProcessCommandLine has_any ("&1", "2>&1") // Filter events where the command line contains &1 or 2>&1
| extend ProcessDuration = datetime_diff('second', now(), ProcessCreationTime) // Calculate the duration of each process
| summarize EventCount = count(), TotalProcessDuration = sum(ProcessDuration) by TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ProcessCommandLine // Summarize the events by relevant fields
| where EventCount > 5 // Filter results where the event count is greater than 5
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ProcessCommandLine, EventCount, TotalProcessDuration // Project relevant columns for the final output
| order by TimeGenerated desc // Order the results by Timestamp in descending order
```
{% endcode %}
