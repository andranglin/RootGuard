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

# Identify Execution of Script From User's Downloads Folder

### Introduction

The query filters for common scripting interpreters, such as `powershell.exe`, `cscript.exe`, `wscript.exe`, and others, and checks if the parent process or command line references the `C:\Users\<username>\Downloads\` path. This helps identify potential threats where an attacker may have dropped a malicious script in the Downloads folder and attempted to execute it.

#### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect Script Execution From User's Downloads Folder
// Detect Script Execution From User's Downloads Folder
DeviceProcessEvents
| where Timestamp > ago(1d) // Limit results to the last 24 hours
| where ActionType == "ProcessCreate" // Focus on process creation events
| where ProcessCommandLine has_any ("powershell.exe", "cscript.exe", "wscript.exe", "cmd.exe", "mshta.exe", "rundll32.exe")
    or InitiatingProcessCommandLine has_any ("powershell.exe", "cscript.exe", "wscript.exe", "cmd.exe", "mshta.exe", "rundll32.exe")
| where (ProcessCommandLine contains @"C:\Users\" and ProcessCommandLine contains @"\Downloads\")
    or (InitiatingProcessCommandLine contains @"C:\Users\" and InitiatingProcessCommandLine contains @"\Downloads\")
| extend UserName = tostring(split(ProcessCommandLine, @"C:\Users\")[1]) // Extract username for context
| extend UserName = iff(isnotempty(UserName), split(UserName, "\\")[0], "") // Extract the username before the first backslash
| extend ScriptPath = iff(ProcessCommandLine contains @"\Downloads\", ProcessCommandLine, InitiatingProcessCommandLine)
| project
    Timestamp,
    DeviceName,
    UserName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ScriptPath,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

### Explanation of the Query:

1. **Filtering Process Creation Events** :
   * The query starts by filtering for `ProcessCreate` events (`ActionType == "ProcessCreate"`) within the last 24 hours (`Timestamp > ago(1d)`).
2. **Identifying Scripting Interpreters** :
   * It looks for processes commonly used to execute scripts, such as `powershell.exe`, `cscript.exe`, `wscript.exe`, `cmd.exe`, `mshta.exe`, and `rundll32.exe`. These are checked in both the `ProcessCommandLine` and `InitiatingProcessCommandLine`.
3. **Checking for Downloads Folder Path** :
   * The query checks if the `ProcessCommandLine` or `InitiatingProcessCommandLine` contains the string `C:\Users\<username>\Downloads\`. This ensures that the script execution originates from the Downloads folder.
4. **Extracting Contextual Information** :
   * The `UserName` is extracted from the `ProcessCommandLine` to provide additional context about the affected user.
   * The `ScriptPath` is identified as either the `ProcessCommandLine` or `InitiatingProcessCommandLine` that contains the Downloads folder path.
5. **Projecting Relevant Columns** :
   * The query projects relevant fields, such as `Timestamp`, `DeviceName`, `UserName`, `ProcessName`, `ProcessCommandLine`, `InitiatingProcessCommandLine`, and `ScriptPath` for easier analysis.
6. **Sorting Results** :
   * The results are sorted by `Timestamp` in descending order to show the most recent events first.

### Use Case:

This query is particularly useful for detecting post-exploitation activities, such as an attacker downloading a malicious script and executing it from the Downloads folder. Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for such behaviour and respond promptly to potential threats.

### Notes:

* **False Positives** : Legitimate scripts may also be executed from the Downloads folder. Analysts should review the results to differentiate between benign and malicious activity.
* **Customisation** : The list of scripting interpreters can be expanded based on the organisation's environment and known attack vectors.
* **Performance** : To optimise performance, consider narrowing the time range or filtering by specific devices/users if needed.
