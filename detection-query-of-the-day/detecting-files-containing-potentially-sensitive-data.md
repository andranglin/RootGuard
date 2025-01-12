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

# Detecting Files Containing Potentially Sensitive Data

The following query is designed to detect files potentially holding sensitive information like credentials, secrets, or API tokens. The query also looks for file events involving files with specific strings in their names and certain file extensions:

{% code overflow="wrap" fullWidth="false" %}
```kusto
// Define a list of strings that might indicate sensitive information
let FileNameStrings = dynamic([
    "pass",
    "password",
    "passwords",
    "cred",
    "creds",
    "credential",
    "credentials",
    "secret",
    "secrets",
    "keys"
]);
// Define a list of file extensions to look for
let FileExtensions = dynamic([
    "txt",
    "doc",
    "docx",
    "bat",
    "cmd",
    "ps1",
    "rtf",
    "png",
    "jpg",
    "jpeg"
]);
DeviceFileEvents
| where TimeGenerated > ago(30d) // Filter events that occurred in the last 30 days
| where FileName has_any(FileNameStrings) // Filter file events where the file name contains any of the strings in FileNameStrings
| extend FileExtension = split(FileName, ".")[-1] // Extract the file extension from the file name
| where FileExtension in~(FileExtensions) // Filter file events where the file extension matches any of the extensions in FileExtensions
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName // Project relevant columns for the final output
| order by Timestamp desc // Order the results by Timestamp in descending order

```
{% endcode %}

The query below looks for file events involving files with specific strings in their names and certain file extensions. The following query is an extended version of the above.

{% code overflow="wrap" %}
```kusto
// Define a list of strings that might indicate sensitive information
let FileNameStrings = dynamic([
    "pass",
    "password",
    "passwords",
    "cred",
    "creds",
    "credential",
    "credentials",
    "secret",
    "secrets",
    "keys",
    "token",
    "api",
    "key",
    "private",
    "confidential",
    "sensitive",
    "secure",
    "auth",
    "authentication"
]);
// Define a list of file extensions to look for
let FileExtensions = dynamic([
    "txt",
    "doc",
    "docx",
    "bat",
    "cmd",
    "ps1",
    "rtf",
    "png",
    "jpg",
    "jpeg",
    "xls",
    "xlsx",
    "pdf",
    "csv",
    "json",
    "xml",
    "yml",
    "yaml",
    "ini",
    "config"
]);
DeviceFileEvents
| where TimeGenerated > ago(30d) // Filter events that occurred in the last 30 days
| where FileName has_any(FileNameStrings) // Filter file events where the file name contains any of the strings in FileNameStrings
| extend FileExtension = split(FileName, ".")[-1] // Extract the file extension from the file name
| where FileExtension in~(FileExtensions) // Filter file events where the file extension matches any of the extensions in FileExtensions
| extend FileSize = tolong(FileSize) // Convert FileSize to a long integer for further calculations
| summarize eventCount = count(), TotalFileSize = sum(FileSize) by bin(TimeGenerated, 1h), DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName // Summarize the event count and total file size by relevant fields, grouped into 1-hour bins
| where eventCount > 10 // Filter results where the event count is greater than 10
| project TimeGenerated, DeviceName, FileName, FolderPath, eventCount, TotalFileSize, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName // Project relevant columns for the final output
| order by TimeGenerated desc // Order the results by TimeGenerated in descending order
```
{% endcode %}
