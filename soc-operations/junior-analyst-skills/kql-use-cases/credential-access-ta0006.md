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

# Credential Access (TA0006)

### **Sub-technique: T1003.001 - LSASS Memory**

**Objective**: Detect attempts to dump credentials from LSASS memory.&#x20;

1. **Monitor for Suspicious LSASS Access**

<pre class="language-cs" data-overflow="wrap"><code class="lang-cs"><strong>//Basic Search
</strong>DeviceProcessEvents
| where FileName == "lsass.exe" and ProcessCommandLine has "dump"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advance Search
<strong>DeviceProcessEvents
</strong>| where FileName == "lsass.exe" and ProcessCommandLine has "dump"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "lsass.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
</code></pre>

\*\*Purpose: Detect suspicious access to LSASS memory.

2. **Detect Credential Dumping Tools**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("mimikatz", "procdump", "secretsdump")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advance Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("mimikatz", "procdump", "secretsdump")
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("mimikatz", "procdump", "secretsdump")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify known credential dumping tools.

3. **Monitor LSASS for Suspicious Memory Reads**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where FileName == "lsass.exe" and ActionType == "ReadMemory"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advance Search
DeviceProcessEvents
| where FileName == "lsass.exe" and ActionType == "ReadMemory"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "lsass.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect suspicious memory reads from LSASS.

4. **Detect LSASS Process Termination Attempts**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where FileName == "lsass.exe" and ActionType == "TerminateProcess"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advanced Search
DeviceProcessEvents
| where FileName == "lsass.exe" and ActionType == "TerminateProcess"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "lsass.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor for attempts to terminate LSASS.

5. **Suspicious DLL Injections into LSASS**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceImageLoadEvents
| where InitiatingProcessFileName == "lsass.exe" and FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName

//Advanced Search
DeviceImageLoadEvents
| where InitiatingProcessFileName == "lsass.exe" and FileName endswith ".dll"
| extend InitiatingProcessAccountDomain = tostring(split(InitiatingProcessAccountName, "\\")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "lsass.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect DLL injections into LSASS.

6. **Unauthorized LSASS Access by Non-System Accounts**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where FileName == "lsass.exe" and InitiatingProcessAccountName != "SYSTEM"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advanced Search
DeviceProcessEvents
| where FileName == "lsass.exe" and InitiatingProcessAccountName != "SYSTEM"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "lsass.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify unauthorized LSASS access by non-system accounts.

7. **Detect Procdump Used Against LSASS**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where ProcessCommandLine has "procdump" and ProcessCommandLine has "lsass.exe"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advanced Search
DeviceProcessEvents
| where ProcessCommandLine has "procdump" and ProcessCommandLine has "lsass.exe"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "procdump.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor for Procdump usage to dump LSASS.

8. **Monitor for LSASS Process Duplicates**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where FileName == "lsass.exe" and ActionType == "CreateProcess"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advanced Search
DeviceProcessEvents
| where FileName == "lsass.exe" and ActionType == "CreateProcess"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "lsass.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect the creation of duplicate LSASS processes.

9. **Identify LSASS Access Using Handle Duplication**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where ProcessCommandLine has "DuplicateHandle" and FileName == "lsass.exe"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advanced Search
DeviceProcessEvents
| where ProcessCommandLine has "DuplicateHandle" and FileName == "lsass.exe"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName == "lsass.exe"
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, NetworkEventCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor for handle duplication used to access LSASS.

10. **Detect LSASS Credential Dumping via Task Scheduler**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("schtasks", "taskschd.msc") and ProcessCommandLine has "lsass.exe"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName

//Advanced Search
DeviceProcessEvents
| where ProcessCommandLine has_any ("schtasks", "taskschd.msc") and ProcessCommandLine has "lsass.exe"
| extend InitiatingProcessFileName = tostring(split(ProcessCommandLine, " ")[0])
| join kind=leftouter (
    DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("schtasks", "taskschd.msc")
    | summarize NetworkEventCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, Initiating
```
{% endcode %}

**Purpose**: Identify attempts to schedule tasks that dump LSASS credentials.
