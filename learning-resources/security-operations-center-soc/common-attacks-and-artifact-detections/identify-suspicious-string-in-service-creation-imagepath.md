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

# Identify Suspicious String in Service Creation ImagePath

### Description of the Query:

This KQL query is designed to detect suspicious strings in the **`ImagePath` f**ield during service creation events. Services are a common target for attackers because they run with elevated privileges and can persist across reboots. Attackers often create malicious services or modify legitimate ones by embedding suspicious commands, scripts, or binaries in the `ImagePath` field.

The query focuses on identifying service creation events (`ServiceCreate`) where the `ImagePath` contains suspicious patterns such as:

* Known malicious commands (e.g., `cmd.exe`, `powershell.exe`, `mshta.exe`).
* Scripting keywords (e.g., `-EncodedCommand`, `-ExecutionPolicy`).
* Non-standard paths (e.g., temporary directories like `C:\Users\<username>\AppData\Local\Temp`).

By analysing these patterns, security teams can identify potential misuse of services for malicious purposes, such as executing payloads, maintaining persistence, or escalating privileges.

#### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect Suspicious String in Service Creation ImagePath
DeviceEvents
| where Timestamp > ago(1d) // Limit results to the last 24 hours
| where ActionType == "ServiceCreate" // Focus on service creation events
| extend ImagePath = tostring(parse_json(AdditionalFields).ImagePath) // Extract ImagePath from AdditionalFields
| extend UserName = tostring(split(InitiatingProcessAccountName, @"\")[1]) // Extract username for context
| where ImagePath has_any (
    "cmd.exe", 
    "powershell.exe", 
    "mshta.exe", 
    "cscript.exe", 
    "wscript.exe", 
    "-EncodedCommand", 
    "-ExecutionPolicy", 
    "C:\\Users\\", 
    "C:\\Windows\\Temp", 
    "C:\\ProgramData"
    "ADMIN$"
    "C$"
    "127.0.0.1"
) // Filter for suspicious strings in ImagePath
| project
    Timestamp,
    DeviceName,
    UserName,
    ServiceName = tostring(parse_json(AdditionalFields).ServiceName), // Extract service name
    ImagePath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

#### Explanation of the Query:

1. **Filtering Service Creation Events** :
   * The query starts by filtering for `ServiceCreate` events (`ActionType == "ServiceCreate"`) within the last 24 hours (`Timestamp > ago(1d)`).
2. **Extracting ImagePath** :
   * The `ImagePath` field is extracted from the `AdditionalFields` JSON object using `parse_json`. This field specifies the executable or command that the service will run.
3. **Extracting Contextual Information** :
   * The `UserName` is extracted from the `InitiatingProcessAccountName` to provide additional context about the user account under which the service was created.
   * The `ServiceName` is also extracted from the `AdditionalFields` JSON object for reference.
4. **Detecting Suspicious Strings** :
   * The query checks if the `ImagePath` contains suspicious patterns, including:
     * Commonly abused executables: `cmd.exe`, `powershell.exe`, `mshta.exe`, `cscript.exe`, `wscript.exe`.
     * Scripting keywords: `-EncodedCommand`, `-ExecutionPolicy`.
     * Non-standard paths: Temporary directories (`C:\Users\`, `C:\Windows\Temp`, `C:\ProgramData`), which are often used to store malicious payloads.
5. **Projecting Relevant Columns** :
   * The query projects relevant fields such as:
     * `Timestamp`: When the event occurred.
     * `DeviceName`: The name of the device where the service was created.
     * `UserName`: The user account associated with the activity.
     * `ServiceName`: The name of the service being created.
     * `ImagePath`: The path or command specified in the `ImagePath` field.
     * `InitiatingProcessName`: The name of the process that initiated the service creation.
     * `InitiatingProcessCommandLine`: The command line of the initiating process.
     * `InitiatingProcessAccountName`: The account name of the initiating process.
     * `ActionType`: The type of action (e.g., `ServiceCreate`).
6. **Sorting Results** :
   * The results are sorted by `Timestamp` in descending order to show the most recent events first.

### Use Case:

This query is particularly useful for detecting:

* **Malware Persistence**: Attackers create services with malicious payloads to ensure persistence across reboots.
* **Privilege Escalation**: Misuse of services to execute high-privilege commands or scripts.
* **Lateral Movement**: Attackers leveraging services to execute commands on remote systems.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious service creation activity and investigate potential threats.

### Notes:

* **False Positives**: Legitimate administrative tasks may also create services with unusual `ImagePath` values. Analysts should review the results to differentiate between benign and malicious activity.
* **Customisation**: The list of suspicious strings can be expanded based on the organisation's environment and known attack vectors.
* **Performance**: To optimise performance, consider narrowing the time range or filtering by specific devices/users if needed.
