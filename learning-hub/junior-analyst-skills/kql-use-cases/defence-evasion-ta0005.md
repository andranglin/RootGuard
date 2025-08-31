# Defence Evasion (TA0005)

### **Sub-technique: T1070.001 - Clear Windows Event Logs**

**Objective**: Detect attempts to clear event logs to evade detection.&#x20;

1. **Detect Security Log Cleared Events**

{% code overflow="wrap" %}
```cs
DeviceEvents
| where ActionType == "SecurityLogCleared"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCreationTime, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Identify when security logs are cleared.

2. **Detect System Log Cleared Events**

{% code overflow="wrap" %}
```cs
DeviceEvents
| where ActionType == "SystemLogCleared"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCreationTime, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Monitor for system log clearing.

3. **Detect Application Log Cleared Events**

{% code overflow="wrap" %}
```cs
DeviceEvents
| where ActionType == "ApplicationLogCleared"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCreationTime, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Identify when application logs are cleared.

4. **Monitor for Log Deletion Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "wevtutil cl"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Detect usage of log clearing commands.

5. **Identify Unauthorized Log Clearing Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("clear", "delete") and InitiatingProcessAccountName != "Administrator"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Detect log clearing attempts by non-administrative users.

6. **Monitor for Event Log Service Restarts**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents 
| where ServiceName == "EventLog" and ActionType == "StartService" 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Identify restarts of the Event Log service.

7. **Detect Cleared Logs via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "Clear-EventLog"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessFolderPath
```
{% endcode %}

**Purpose**: Monitor PowerShell commands used to clear event logs.

8. **Suspicious Access to Event Log Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FolderPath has "System32\\winevt\\Logs"
| summarize event_count = count() by FileName, DeviceName
| where event_count > 1
```
{% endcode %}

**Purpose**: Identify suspicious access to log files.

9. **Detect Log Clearing via Script**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any (".bat", ".cmd") and ProcessCommandLine has "wevtutil"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Detect scripts used to clear event logs.

10. **Monitor Changes to Audit Policy**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents
| where RegistryKey has "HKLM\\System\\CurrentControlSet\\Services\\EventLog\\Security"
| project Timestamp, DeviceName, RegistryKey, ActionType
```
{% endcode %}

**Purpose**: Monitor changes to audit policies that could impact logging.
