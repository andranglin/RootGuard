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

# Detecting Low Prevalence DLL Loaded From Process In User Downloads Directory

Query designed to detect low prevalence DLLs loaded from processes in the user's Downloads folder:

{% code overflow="wrap" %}
```kusto
// Define a set of DLLs loaded from the user's Downloads folder
let LoadedDLLs = (
    DeviceImageLoadEvents
    | where InitiatingProcessFolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
    | where FolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
    | where FileName endswith ".dll"
    | distinct SHA1
    // The FileProfile() function has a limit of 1000 lookups per query
    | invoke FileProfile("SHA1", 1000)
);
DeviceImageLoadEvents
| where InitiatingProcessFolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
| where FolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
| where FileName endswith ".dll"
| join kind=inner (LoadedDLLs) on SHA1
// Optionally, you can add a filter on the GlobalPrevalence column to reduce the number of results
// | where GlobalPrevalence < 500
// | order by GlobalPrevalence asc
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA1, GlobalPrevalence
| order by Timestamp desc
```
{% endcode %}

Below is a more extended version of the above query:

{% code overflow="wrap" %}
```kusto
// Define a set of DLLs loaded from the user's Downloads folder
let LoadedDLLs = (
    DeviceImageLoadEvents
    | where InitiatingProcessFolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
    | where FolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
    | where FileName endswith ".dll"
    | distinct SHA1
    // The FileProfile() function has a limit of 1000 lookups per query
    | invoke FileProfile("SHA1", 1000)
);
DeviceImageLoadEvents
| where InitiatingProcessFolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
| where FolderPath matches regex @"(?i)\\Users\\[^\\] +\\Downloads\\(.*)?"
| where FileName endswith ".dll"
| join kind=inner (LoadedDLLs) on SHA1
| extend FileSize = tolong(FileSize) // Convert FileSize to a long integer for further calculations
| summarize EventCount = count(), TotalFileSize = sum(FileSize), GlobalPrevalence = min(GlobalPrevalence) by Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA1 // Summarize the events by relevant fields
| where EventCount > 1 and GlobalPrevalence < 500 // Filter results where the event count is greater than 1 and global prevalence is less than 500
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA1, EventCount, TotalFileSize, GlobalPrevalence // Project relevant columns for the final output
| order by Timestamp desc // Order the results by Timestamp in descending order

```
{% endcode %}

As usual, tweak it further based on your specific needs!
