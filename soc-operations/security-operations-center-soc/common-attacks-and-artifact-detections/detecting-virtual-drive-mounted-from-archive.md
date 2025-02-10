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

# Detecting Virtual Drive Mounted From Archive

This query is designed to detect virtual drives mounted from archives. It helps identify instances where virtual drives are mounted from archives, which can indicate suspicious or malicious activity.

{% code overflow="wrap" %}
```kusto
let DiskImageFileExtensions = dynamic(["iso", "img", "vhd", "vhdx", "wim"]);
DeviceFileEvents
| where FolderPath matches regex @"(?i)\\Users\\[^\\] +\\AppData\\Local\\Temp\\(.*)?"
| where FolderPath has_any("7zo", "Rar$", ".zip", "Temp1_")
| extend FileExtension = split(FileName, ".")[-1]
| where FileExtension in~(DiskImageFileExtensions)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, FileExtension
| order by Timestamp desc
```
{% endcode %}

Below is an extended version, including additional extensions.

{% code overflow="wrap" %}
```kusto
let DiskImageFileExtensions = dynamic([
    "iso",
    "img",
    "vhd",
    "vhdx",
    "wim",
    "dmg",
    "vmdk",
    "bin",
    "cue",
    "nrg",
    "udf"
]);
DeviceFileEvents
| where FolderPath matches regex @"(?i)\\Users\\[^\\] +\\AppData\\Local\\Temp\\(.*)?"
| where FolderPath has_any("7zo", "Rar$", ".zip", "Temp1_")
| extend FileExtension = split(FileName, ".")[-1]
| where FileExtension in~(DiskImageFileExtensions)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ProcessCommandLine, FolderPath, FileName, FileExtension
| order by Timestamp desc
```
{% endcode %}
