# Reconnaissance (TA0043)

### **Sub-technique: T1595.001 - Scanning IP Blocks**

**Objective**: Detect network scanning activities indicative of reconnaissance.&#x20;

1. **Detect Multiple Ports Scanned from a Single IP**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize port_count = count() by RemoteIP, LocalPort, bin(TimeGenerated, 1h)
| where port_count > 20
| project TimeGenerated, RemoteIP, LocalPort, port_count
| order by port_count desc
```
{% endcode %}

**Purpose**: Identify IP addresses scanning multiple ports.

2. **Identify Rapid Scanning Behaviour**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize time_diff = min(TimeGenerated), event_count = count() by RemoteIP, LocalPort, LocalIP
| where event_count > 50
| project time_diff, RemoteIP, LocalPort,LocalIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect scanning activity that occurs in a short time span.

3. **Suspicious Network Scanning Patterns**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where LocalPort in (22, 23, 80, 443, 3389)
| summarize event_count = count() by RemoteIP, LocalIP
| where event_count > 10
| project RemoteIP, LocalIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect scanning on commonly targeted ports.

4. **Identify Outbound Port Scanning**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where InitiatingProcessFileName == "nmap.exe"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| project TimeGenerated, DeviceName, RemoteIP, LocalPort, InitiatingProcessFileName
| order by TimeGenerated desc
```
{% endcode %}

**Purpose**: Detect known scanning tools like Nmap.

5. **Multiple Failed Connection Attempts**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize event_count = count() by RemoteIP, LocalIP
| where event_count > 100
| project RemoteIP, LocalIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Identify failed connections that could indicate scanning.

6. **Identify ICMP Echo Requests (Ping Sweeps)**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where Protocol == "ICMP"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize event_count = count() by RemoteIP, LocalIP
| where event_count > 50
| project RemoteIP, LocalIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect ICMP ping sweeps across multiple IP addresses.

7. **Scan for SMB Shares**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where LocalPort == 445
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize event_count = count() by RemoteIP, LocalIP
| where event_count > 10
| project RemoteIP, LocalIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Identify scanning activity targeting SMB shares.

8. **HTTP GET Request Flooding**

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where LocalPort == 80 and ActionType == "ConnectionSuccess"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize event_count = count() by RemoteIP, LocalIP
| where event_count > 100
| project RemoteIP, LocalIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect flooding of HTTP GET requests from a single IP.

9. **Identify DNS Query Flooding**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents
| where RemotePort == 53 and ActionType == "Query"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize event_count = count() by RemoteIP
| where event_count > 200
| project RemoteIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect excessive DNS queries that may indicate scanning.

10. **Detecting high Numbers of SYN Packets**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents
| where ActionType == "SYN"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172.16."
| summarize event_count = count() by RemoteIP
| where event_count > 500
| project RemoteIP, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect a high volume of SYN packets, which could indicate a SYN flood or scanning.
