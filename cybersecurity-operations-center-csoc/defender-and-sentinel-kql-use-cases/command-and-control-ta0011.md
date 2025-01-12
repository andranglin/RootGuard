# Command and Control (TA0011)

### **Sub-technique: T1071.001 - Web Protocols**

**Objective**: Detect command and control (C2) communications using web protocols.&#x20;

1. **Detect Suspicious Web Traffic**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents 
| where RemotePort == 80 or RemotePort == 443 
| summarize count() by RemoteIP, LocalIP 
| where count() > 50

//Extended Search
DeviceNetworkEvents
| where RemotePort == 80 or RemotePort == 443
| summarize ConnectionCount = count() by RemoteIP, DeviceName
| where ConnectionCount > 50
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("curl", "wget", "POST")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ConnectionCount, ArchiveFileCount, ProcessCount
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Identify unusual web traffic patterns.

2. **Monitor for Web Protocols Used by Malware**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where InitiatingProcessCommandLine  has_any ("curl", "wget") | project Timestamp, DeviceName, RemoteIP, InitiatingProcessCommandLine

//Extended Search
DeviceNetworkEvents
| where RemotePort == 80 or RemotePort == 443
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("curl", "wget")
    | summarize ProcessCount = count() by DeviceName, ProcessCommandLine
) on DeviceName
| summarize ConnectionCount = count() by RemoteIP, DeviceName, ProcessCommandLine
| where ConnectionCount > 50
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".pcap" or FileName endswith ".cap"
    | summarize FileCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ProcessCommandLine, ConnectionCount, FileCount
| order by ConnectionCount desc

//Another Option for Search
DeviceNetworkEvents
| where RemotePort == 80 or RemotePort == 443
| join kind=leftouter (
    DeviceProcessEvents
    | where InitiatingProcessCommandLine has_any ("curl", "wget")
    | summarize ProcessCount = count() by DeviceName, InitiatingProcessCommandLine
) on DeviceName
| summarize ConnectionCount = count() by RemoteIP, DeviceName, InitiatingProcessCommandLine
| where ConnectionCount > 50
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".pcap" or FileName endswith ".cap"
    | summarize FileCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, InitiatingProcessCommandLine, ConnectionCount, FileCount
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Detect web protocols commonly used by malware.

3. **Identify Outbound HTTP POST Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents 
| where RemotePort == 80 or RemotePort == 443 and ProcessCommandLine has "POST" 
| project Timestamp, DeviceName, RemoteIP, ProcessCommandLine

//Extended Search
DeviceNetworkEvents
| where RemotePort == 80 or RemotePort == 443
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has "POST" or ProcessCommandLine has_any ("curl", "wget")
    | summarize ProcessCount = count() by DeviceName, ProcessCommandLine
) on DeviceName
| summarize ConnectionCount = count() by RemoteIP, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName
| where ConnectionCount > 50
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".pcap" or FileName endswith ".cap"
    | summarize FileCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ProcessCommandLine, ConnectionCount, FileCount, InitiatingProcessAccountName, InitiatingProcessFileName
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Monitor for outbound HTTP POST requests used for C2.

4. **Detect Long-Lived HTTP Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents
| where RemotePort == 80 or RemotePort == 443
| extend DurationSeconds = toint(Timestamp - InitiatingProcessCreationTime) / 1000
| summarize avg_DurationSeconds = avg(DurationSeconds) by RemoteIP, DeviceName
| where avg_DurationSeconds > 600
| project RemoteIP, DeviceName, avg_DurationSeconds
| order by avg_DurationSeconds desc
```
{% endcode %}

**Purpose**: Identify long-lived HTTP connections that could indicate C2.

5. **Monitor for Unusual DNS Queries**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents 
| where RemotePort == 53 and ActionType == "Query" 
| summarize count() by RemoteIP 
| where count() > 200

//Extended Search
DeviceNetworkEvents
| where RemotePort == 53 and ActionType == "Query"
| summarize QueryCount = count() by RemoteIP, DeviceName
| where QueryCount > 200
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("dns", "query", "lookup")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, QueryCount, ArchiveFileCount, ProcessCount
| order by QueryCount desc
```
{% endcode %}

**Purpose**: Detect excessive DNS queries.

6. **Detect Use of Web Shells**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FileName endswith ".aspx" or FileName endswith ".php"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc

//Extended Search
DeviceFileEvents
| where FileName endswith ".aspx" or FileName endswith ".php"
| summarize FileAccessCount = count() by DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("powershell", "cmd", "bash")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 80 or RemotePort == 443
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, FileAccessCount, ProcessCount, ConnectionCount
| order by FileAccessCount desc
```
{% endcode %}

**Purpose**: Monitor for the presence of web shells on servers.

7. **Identify HTTPS Traffic to Unusual Domains**

<pre class="language-cs" data-overflow="wrap"><code class="lang-cs">DeviceNetworkEvents 
| where RemotePort == 443 and RemoteIP !in ("known_good_ips") 
| summarize count() by RemoteIP, LocalIP 
| where count() > 20

//Extended Search
```kusto
DeviceNetworkEvents
| where RemotePort == 443 and RemoteIP !in ("known_good_ips")
<strong>| summarize ConnectionCount = count() by RemoteIP, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
</strong>| where ConnectionCount > 20
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("curl", "wget", "POST")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ConnectionCount, ArchiveFileCount, ProcessCount, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by ConnectionCount desc
</code></pre>

**Purpose**: Detect HTTPS traffic to unusual or unknown domains.

8. **Monitor for Suspicious User-Agents**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents 
| where RemotePort == 80 or RemotePort == 443 
| where ProcessCommandLine has_any ("User-Agent: Mozilla", "User-Agent: curl") 
| project Timestamp, DeviceName, RemoteIP, ProcessCommandLine

//Extended Search
DeviceNetworkEvents
| where RemotePort == 80 or RemotePort == 443
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("User-Agent: Mozilla", "User-Agent: curl")
    | summarize ProcessCount = count() by DeviceName, ProcessCommandLine
) on DeviceName
| summarize ConnectionCount = count() by RemoteIP, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where ConnectionCount > 50
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".pcap" or FileName endswith ".cap"
    | summarize FileCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ProcessCommandLine, ConnectionCount, FileCount, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Detect unusual or spoofed user-agents in web traffic.

9. **Detect Traffic to Known Malicious Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("known_malicious_ips") | summarize count() by RemoteIP, LocalIP, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine

//Extended Search
DeviceNetworkEvents
| where RemoteIP in ("known_malicious_ips")
| summarize ConnectionCount = count() by RemoteIP, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("curl", "wget", "POST")
    | summarize ProcessCount = count() by DeviceName
) on DeviceName
| project RemoteIP, DeviceName, ConnectionCount, ArchiveFileCount, ProcessCount, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by ConnectionCount desc
```
{% endcode %}

**Purpose**: Identify traffic to known malicious IP addresses.

10. **Identify Suspicious WebSocket Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents
| where RemotePort == 443
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has "websocket"
    | summarize ProcessCount = count() by DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
) on DeviceName
| project Timestamp, DeviceName, RemoteIP, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

//Extended Search
DeviceNetworkEvents
| where RemotePort == 443
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessCommandLine has "websocket"
    | summarize ProcessCount = count() by DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
) on DeviceName
| join kind=leftouter (
    DeviceFileEvents
    | where FileName endswith ".zip" or FileName endswith ".rar"
    | summarize ArchiveFileCount = count() by DeviceName
) on DeviceName
| join kind=leftouter (
    DeviceNetworkEvents
    | where RemotePort == 80 or RemotePort == 443
    | summarize ConnectionCount = count() by DeviceName
) on DeviceName
| project Timestamp, DeviceName, RemoteIP, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ArchiveFileCount, ConnectionCount
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor for WebSocket connections used for C2.
