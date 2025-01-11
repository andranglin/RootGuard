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

# Detect Potential Cleartext Credentials in Command Line

### <mark style="color:blue;">KQL Queries</mark>

{% tabs %}
{% tab title="DeviceProcessEvents" %}
KQL (Kusto Query Language) query to identify potential cleartext credentials in command lines, leveraging Microsoft Defender for Endpoint or other platforms like Azure Monitor Logs:

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)  // Adjust the time frame as needed
| where ProcessCommandLine has_any ("password", "pwd", "pass", "secret", "key", "credential", "login")
| extend SuspiciousWords = extract_all(@"(?i)(password\s*[:=]\s*\S+|pwd\s*[:=]\s*\S+|pass\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|key\s*[:=]\s*\S+|credential\s*[:=]\s*\S+|login\s*[:=]\s*\S+)", ProcessCommandLine)
| where array_length(SuspiciousWords) > 0
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SuspiciousWords
| extend AccountDomain = tostring(split(AccountName, "\\", 0)), Username = tostring(split(AccountName, "\\", 1))
| summarize Count = count(), Commands = make_set(ProcessCommandLine) by Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Count desc
```
{% endcode %}

#### Key Features of the Query:

1. **Filters Suspicious Command Lines**:
   * Targets command lines with keywords commonly associated with credentials like `password`, `pwd`, `secret`, etc.
2. **Extracts Potential Credentials**:
   * Uses regex to extract possible key-value pairs (e.g., `password=1234`).
3. **Aggregation for Context**:
   * Groups occurrences by `DeviceName`, `AccountDomain`, and `Username` to provide context.
4. **Summarization and Ordering**:
   * Highlights accounts and devices with the highest occurrences of potential issues.

#### How It Works:

* **Extract\_all Function**: This regex extracts any matching patterns from the command line that indicate potential cleartext credentials.
* **Dynamic Analysis**: Produces a dynamic array of potential matches, ensuring flexibility in parsing varying formats.
* **Adjustable Time Frame**: Allows tuning for recent or historical analysis.

#### Use Case Scenarios:

* Detect accidental or intentional exposure of credentials in scripts or commands.
* Investigate potential misuse by attackers or internal personnel.
{% endtab %}

{% tab title="DeviceProcessEvents" %}
KQL query will detect potential cleartext credentials in command lines. This query will look for process execution events that may contain credentials in their command line arguments:

{% code overflow="wrap" %}
```kusto
// Excluding known false positive processes
let ExcludedProcesses = dynamic(["WerFault.exe", "WerFaultSecure.exe", "SenseNDR.exe"]);
// Define patterns to identify potential user and password command line arguments
let PossibleUserCLI = dynamic(["/U", "/User", "/username", "-u", "-user", "--user", "--username"]);
let PossiblePasswordCLI = dynamic(["/P", "/password", "/pass", "-p", "-password", "-pw", "-pass", "--pass", "--password"]);
// Query DeviceProcessEvents table
DeviceProcessEvents
| where not (FileName in~ ExcludedProcesses) // Exclude known false positive processes
| where ProcessCommandLine has_any (PossibleUserCLI) // Match potential user command line arguments
| where ProcessCommandLine has_any (PossiblePasswordCLI) // Match potential password command line arguments
| summarize
    TotalEvents = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(AccountName)
    by ProcessCommandLine, FileName, FolderPath, bin(TimeGenerated, 1h)
| order by TotalEvents desc
| project TimeGenerated, ProcessCommandLine, FileName, FolderPath, TotalEvents, UniqueDevices, UniqueUsers
```
{% endcode %}

#### Explanation:

1. **Pattern Matching**: The `PossibleUserCLI` and `PossiblePasswordCLI` dynamic arrays contain common command line arguments for user and password.
2. **Filtering**: The `where` clauses filter the `DeviceProcessEvents` table to exclude known false positive processes and retain only events matching the specified patterns.
3. **Summarisation**: The `summarise` statement aggregates the data to count the total number of events, unique devices, and unique users for each command line, file name, and folder path.
4. **Ordering**: The results are ordered by the total number of events in descending order.
5. **Projection**: The `project` statement selects the relevant columns for the final output.
{% endtab %}

{% tab title="CloudAppEvents" %}
KQL query to discover potential cleartext credentials in command lines without using Instead, we'll use the `CloudAppEvents` table:

{% code overflow="wrap" %}
```kusto
// Define patterns to identify potential user and password command line arguments
let PossibleUserCLI = dynamic(["/U", "/User", "/username", "-u", "-user", "--user", "--username"]);
let PossiblePasswordCLI = dynamic(["/P", "/password", "/pass", "-p", "-password", "-pw", "-pass", "--pass", "--password"]);
// Query CloudAppEvents table
CloudAppEvents
| where EventType == "ProcessCreation" // Filter for process creation events
| where CommandLine has_any (PossibleUserCLI) // Match potential user command line arguments
| where CommandLine has_any (PossiblePasswordCLI) // Match potential password command line arguments
| summarize
    TotalEvents = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(AccountName)
    by CommandLine, AppName, FolderPath, bin(TimeGenerated, 1h)
| order by TotalEvents desc
| project TimeGenerated, CommandLine, AppName, FolderPath, TotalEvents, UniqueDevices, UniqueUsers
```
{% endcode %}

#### Explanation:

1. **Pattern Matching**: The `PossibleUserCLI` and `PossiblePasswordCLI` dynamic arrays contain common command line arguments for user and password.
2. **Filtering**: The `where` clauses filter the `CloudAppEvents` table to retain only process creation events matching the specified patterns.
3. **Summarisation**: The `summarise` statement aggregates the data to count the total number of events, unique devices, and unique users for each command line, app name, and folder path.
4. **Ordering**: The results are ordered by the total number of events in descending order.
5. **Projection**: The `project` statement selects the relevant columns for the final output.
{% endtab %}

{% tab title="DeviceFileEvents" %}
KQL query to discover potential cleartext credentials in command lines using the `DeviceFileEvents` table:

{% code overflow="wrap" %}
```kusto
// Define patterns to identify potential user and password command line arguments
let PossibleUserCLI = dynamic(["/U", "/User", "/username", "-u", "-user", "--user", "--username"]);
let PossiblePasswordCLI = dynamic(["/P", "/password", "/pass", "-p", "-password", "-pw", "-pass", "--pass", "--password"]);
// Query DeviceFileEvents table
DeviceFileEvents
| where ActionType == "FileCreated" or ActionType == "FileModified" // Filter for file creation or modification events
| where FileName endswith ".log" or FileName endswith ".txt" // Filter for log or text files
| where FilePath has_any (PossibleUserCLI) // Match potential user command line arguments
| where FilePath has_any (PossiblePasswordCLI) // Match potential password command line arguments
| summarize
    TotalEvents = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(AccountName)
    by FilePath, FileName, FolderPath, bin(TimeGenerated, 1h)
| order by TotalEvents desc
| project TimeGenerated, FilePath, FileName, FolderPath, TotalEvents, UniqueDevices, UniqueUsers
```
{% endcode %}

#### Explanation:

1. **Pattern Matching**: The `PossibleUserCLI` and `PossiblePasswordCLI` dynamic arrays contain common command line arguments for user and password.
2. **Filtering**: The `where` clauses filter the `DeviceFileEvents` table to retain only file creation or modification events for log or text files matching the specified patterns.
3. **Summarisation**: The `summarise` statement aggregates the data to count the total number of events, unique devices, and unique users for each file path, file name, and folder path.
4. **Ordering**: The results are ordered by the total number of events in descending order.
5. **Projection**: The `project` statement selects the relevant columns for the final output.

This query should help you identify potential cleartext credentials in command lines within an environment.
{% endtab %}
{% endtabs %}

