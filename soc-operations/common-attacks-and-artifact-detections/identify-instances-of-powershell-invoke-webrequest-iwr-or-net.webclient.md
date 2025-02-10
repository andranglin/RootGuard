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

# Identify Instances of PowerShell Invoke-WebRequest, IWR or Net.WebClient

### Description of the Query:

This KQL query is designed to detect the use of PowerShell commands that leverage `Invoke-WebRequest` (`IWR`) or `Net.WebClient` for downloading files or interacting with web resources. Attackers commonly use these commands to download malicious payloads, exfiltrate data, or communicate with command-and-control (C2) servers.

The query focuses on identifying suspicious PowerShell activity by analysing process creation events (`ProcessCreate`) and filtering for specific keywords, such as `Invoke-WebRequest`, `IWR`, `Net.WebClient`, or their aliases. It also extracts relevant details like the URL being accessed, the process command line, and the user context to help security analysts investigate potential malicious behaviour.

### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect PowerShell Invoke-WebRequest, IWR, or Net.WebClient Activity
DeviceProcessEvents
| where Timestamp > ago(10d) // Limit results to the last 24 hours
| where ActionType == "ProcessCreate" // Focus on process creation events
| where InitiatingProcessFileName contains "powershell.exe" // Filter for PowerShell processes
| where ProcessCommandLine has_any ("Invoke-WebRequest", "iwr", "Net.WebClient", "DownloadFile", "DownloadString")
| extend ParsedCommandLine = parse_command_line(ProcessCommandLine, "windows") // Parse command line using the Windows parser
| extend DownloadURL = extract(@"((http|https):\/\/[^\s]+)", 0, ProcessCommandLine) // Extract URLs from the command line
| extend UserName = tostring(split(ParsedCommandLine.User, @"\")[1]) // Extract username for context
| project
    Timestamp,
    DeviceName,
    UserName,
    InitiatingProcessFileName,
    ProcessCommandLine,
    DownloadURL,
    InitiatingProcessCommandLine,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

### Explanation of the Query:

1. **Filtering Process Creation Events** :
   * The query starts by filtering for `ProcessCreate` events (`ActionType == "ProcessCreate"`) within the last 24 hours (`Timestamp > ago(1d)`).
2. **Focusing on PowerShell** :
   * It specifically looks for processes named `powershell.exe` (`ProcessName contains "powershell.exe"`), as these commands are executed within PowerShell.
3. **Identifying Suspicious Keywords** :
   * The query checks for common PowerShell commands and methods used for web requests:
     * `Invoke-WebRequest`: A cmdlet used to send HTTP/HTTPS requests.
     * `iwr`: An alias for `Invoke-WebRequest`.
     * `Net.WebClient`: A .NET class is often used to download files or strings.
     * `DownloadFile` and `DownloadString`: Methods of `Net.WebClient` used to retrieve files or content from URLs.
4. **Extracting URLs** :
   * The `extract` function is used to identify and extract URLs from the `ProcessCommandLine`. This helps pinpoint the specific web resource being accessed.
5. **Parsing Command Line for Context** :
   * The `parse_command_line` function is used to break down the command line into structured components, making it easier to analyse.
   * The `UserName` is extracted from the parsed command line to provide additional context about the user executing the command.
6. **Projecting Relevant Columns** :
   * The query projects relevant fields, such as `Timestamp`, `DeviceName`, `UserName`, `ProcessName`, `ProcessCommandLine`, `DownloadURL`, `InitiatingProcessCommandLine`, and `ActionType` for easier analysis.
7. **Sorting Results** :
   * The results are sorted by `Timestamp` in descending order to show the most recent events first.

### Use Case:

This query is particularly useful for detecting:

* **Malware Downloads**: Attackers using PowerShell to download malicious payloads from remote servers.
* **Data Exfiltration**: PowerShell scripts send sensitive data to external servers.
* **Command-and-Control (C2)**: PowerShell communicating with C2 servers for further instructions.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious PowerShell activity and investigate potential threats.

### Notes:

* **False Positives**: Legitimate administrative tasks may also use `Invoke-WebRequest` or `Net.WebClient`. Analysts should review the results to differentiate between benign and malicious activity.
* **Customisation**: The list of keywords can be expanded based on the organisation's environment and known attack vectors.
* **Performance**: To optimise performance, consider narrowing the time range or filtering by specific devices/users if needed.
