# Lateral Movement (TA0008)

### **Sub-technique: T1021.001 - Remote Desktop Protocol (RDP)**

**Objective**: Detect lateral movement using RDP.&#x20;

1. **Monitor RDP Connections from Unusual IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents
| where RemotePort == 3389
| summarize ConnectionCount = count() by RemoteIP, LocalIP
| where ConnectionCount > 5
| project RemoteIP, LocalIP, ConnectionCount
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Detect RDP connections from unknown IP addresses.

2. **Identify Multiple Failed RDP Login Attempts**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ActionType == "LogonFailed"
| summarize FailedLogonCount = count() by AccountName, DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project AccountName, DeviceName, FailedLogonCount, ConnectionCount
| order by FailedLogonCount desc
```
{% endcode %}

**Purpose**: Monitor failed RDP login attempts.

3. **Detect RDP Connections During Off-Hours**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and (Timestamp between (datetime(2025-01-12T00:00:00Z) .. datetime(2025-01-12T06:00:00Z)) or Timestamp between (datetime(2025-01-12T18:00:00Z) .. datetime(2025-01-13T00:00:00Z)))
| summarize FailedLogonCount = count() by AccountName, DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project AccountName, DeviceName, FailedLogonCount, ConnectionCount
| order by FailedLogonCount desc
```
{% endcode %}

**Purpose**: Identify RDP sessions initiated during unusual hours.

4. **Monitor for Suspicious RDP Session Creation**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| summarize LogonCount = count() by AccountName, DeviceName
| where LogonCount > 1
| project AccountName, DeviceName, LogonCount
| order by LogonCount desc
```
{% endcode %}

**Purpose**: Detect multiple RDP sessions created by the same user.

5. **Detect RDP Session Disconnections**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ActionType == "Logoff"
| summarize LogoffCount = count() by AccountName, DeviceName
| project AccountName, DeviceName, LogoffCount
| order by LogoffCount desc
```
{% endcode %}

**Purpose**: Monitor for frequent disconnections of RDP sessions.

6. **Monitor RDP Access to Administrative Shares**

{% code overflow="wrap" %}
```cs
//Basic Search
DeviceNetworkEvents
| where RemotePort == 3389 and LocalPort == 445
| summarize ConnectionCount = count() by RemoteIP, LocalIP
| project RemoteIP, LocalIP, ConnectionCount
| order by ConnectionCount desc

// A more detailed search
DeviceNetworkEvents
| where RemotePort == 3389 and LocalPort == 445
| summarize ConnectionCount = count() by RemoteIP, DeviceName
| where ConnectionCount > 5
| join kind=leftouter (
    DeviceLogonEvents
    | summarize FailedLogonCount = countif(ActionType == "LogonFailed"), SuccessfulLogonCount = countif(ActionType == "LogonSuccess") by RemoteIP, DeviceName
) on RemoteIP, DeviceName
| join kind=leftouter (
    DeviceFileEvents
    | where FolderPath has "C:\\Program Files"
    | summarize FileAccessCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ConnectionCount, FailedLogonCount, SuccessfulLogonCount, FileAccessCount
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Detect RDP sessions accessing administrative shares.

7. **Detect RDP Connections from Multiple Locations**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| summarize locations = make_set(RemoteIP) by AccountName, DeviceName
| where array_length(locations) > 1
| project AccountName, DeviceName, locations
| order by array_length(locations) desc
```
{% endcode %}

**Purpose**: Identify users connecting via RDP from multiple locations.

8. **Monitor for RDP Session Hijacking**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ActionType == "SessionReconnected"
| summarize ReconnectionCount = count() by AccountName, DeviceName
| project AccountName, DeviceName, ReconnectionCount
| order by ReconnectionCount desc

//A More Detailed Search
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ActionType == "SessionReconnected"
| summarize ReconnectionCount = count() by AccountName, DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceFileEvents
    | where FolderPath has "C:\\Program Files"
    | summarize FileAccessCount = count() by DeviceName
) on DeviceName
| project AccountName, DeviceName, ReconnectionCount, ConnectionCount, FileAccessCount
| order by ReconnectionCount desc
```
{% endcode %}

**Purpose**: Detect hijacking of active RDP sessions.

9. **Detect RDP Brute Force Attempts**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ActionType == "LogonFailed"
| summarize FailedLogonCount = count() by AccountName, DeviceName
| where FailedLogonCount > 10
| project AccountName, DeviceName, FailedLogonCount
| order by FailedLogonCount desc

//Advanced Search
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ActionType == "LogonFailed"
| summarize FailedLogonCount = count() by AccountName, DeviceName
| where FailedLogonCount > 10
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceFileEvents
    | where FolderPath has "C:\\Program Files"
    | summarize FileAccessCount = count() by DeviceName
) on DeviceName
| project AccountName, DeviceName, FailedLogonCount, ConnectionCount, FileAccessCount
| order by FailedLogonCount desc
```
{% endcode %}

**Purpose**: Identify brute force attempts targeting RDP.

10. **Monitor RDP Connection with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ElevationType == "Full"
| summarize ElevatedLogonCount = count() by AccountName, DeviceName
| project AccountName, DeviceName, ElevatedLogonCount
| order by ElevatedLogonCount desc

//More Detailed Search
DeviceLogonEvents
| where LogonType == "RemoteInteractive" and ElevationStatus == "Full"
| summarize ElevatedLogonCount = count() by AccountName, DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 3389
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceFileEvents
    | where FolderPath has "C:\\Program Files"
    | summarize FileAccessCount = count() by DeviceName
) on DeviceName
| project AccountName, DeviceName, ElevatedLogonCount, ConnectionCount, FileAccessCount
| order by ElevatedLogonCount desc
```
{% endcode %}

**Purpose**: Detect RDP sessions initiated with elevated privileges.
