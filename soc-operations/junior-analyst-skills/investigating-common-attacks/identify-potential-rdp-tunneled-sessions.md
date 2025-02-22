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

# Identify Potential RDP Tunneled Sessions

### Description:

This KQL query is designed to detect **Potential Tunneled RDP Sessions**, which can indicate attackers using Remote Desktop Protocol (RDP) as a tunnel for malicious activities. Attackers often abuse RDP by routing traffic through it to bypass network restrictions or exfiltrate data. For example, they may use tools like `rdp2tcp` or other tunneling techniques to create covert channels over RDP.

The query focuses on identifying unusual patterns in RDP sessions, such as:

1. **High Data Transfer**: Abnormally large amounts of data being sent or received during an RDP session.
2. **Unusual Ports**: RDP connections that involve non-standard ports (e.g., not port 3389).
3. **Multiple Connections**: A high number of concurrent RDP sessions from a single source.
4. **Geolocation Anomalies**: Connections originating from unexpected geographic locations.

By correlating these indicators, the query helps security teams identify suspicious RDP activity that could indicate tunneled traffic or other malicious behaviour.

### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect Potential Tunneled RDP Sessions
DeviceNetworkEvents
| where Timestamp > ago(7d) // Limit results to the last 7 days
| where RemotePort == 3389 or LocalPort == 3389 // Focus on RDP traffic (default port 3389)
| extend IsNonStandardPort = RemotePort != 3389 and LocalPort != 3389 // Simplify non-standard port check
| summarize
    UniqueRemoteIPs = dcount(RemoteIP),
    SessionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort, IsNonStandardPort, InitiatingProcessAccountName
| where SessionCount > 10 // High number of concurrent sessions
    or IsNonStandardPort // Non-standard RDP ports
| where InitiatingProcessAccountName != ""
| where  InitiatingProcessAccountName !in~ ("local service", "system", "network service")
| extend GeoInfo = geo_info_from_ip_address(RemoteIP) // Geolocation enrichment
| extend Country = GeoInfo.country_name, City = GeoInfo.city
| project
    Timestamp = LastSeen,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    IsNonStandardPort,
    UniqueRemoteIPs,
    SessionCount,
    Country,
    City,
    FirstSeen,
    LastSeen
| sort by SessionCount desc
```
{% endcode %}

#### Explanation of the Query:

1. **Filtering RDP Traffic** :
   * The query starts by filtering for network events (`DeviceNetworkEvents`) involving RDP traffic, specifically focusing on the default RDP port (`3389`). It also identifies connections using non-standard ports.
2. **Summarizing Key Metrics** :
   * The query aggregates key metrics for each device and remote IP address:
     * `TotalBytesSent`: Total bytes sent during the session.
     * `TotalBytesReceived`: Total bytes received during the session.
     * `UniqueRemoteIPs`: Number of unique remote IPs connected to the device.
     * `SessionCount`: Number of RDP sessions initiated.
     * `FirstSeen` and `LastSeen`: Timestamps for the first and last observed activity.
3. **Detecting Suspicious Patterns** :
   * The query flags sessions with the following:
     * **High Data Transfer**: More than 500MB sent or received, which is unusual for typical RDP usage.
     * **Non-Standard Ports**: Connections using ports other than 3389.
     * **High Session Count**: More than 10 concurrent sessions from a single source.
4. **Geolocation Enrichment** :
   * The `geo_info_from_ip_address` function enriches the data with geolocation details (country and city) for the remote IP address. This helps identify connections from unexpected or suspicious locations.
5. **Projecting Relevant Columns** :
   * The query projects relevant fields, such as `DeviceName`, `InitiatingProcessCommandLine`, `RemoteIP`, `RemotePort`, `IsNonStandardPort`, `TotalBytesSent`, `TotalBytesReceived`, `Country`, `City`, and timestamps for a more straightforward analysis.
6. **Sorting Results** :
   * The results are sorted by `TotalBytesSent` and `TotalBytesReceived` in descending order to prioritize sessions with the highest data transfer.

### Use Case:

This query is particularly useful for detecting potential misuse of RDP sessions, such as:

* **Data Exfiltration**: Attackers use RDP tunnels to exfiltrate large amounts of data.
* **Command-and-Control (C2)**: Attackers routing C2 traffic through RDP to evade detection.
* **Unauthorized Access**: Identifying unauthorized or anomalous RDP connections.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious RDP activity and investigate potential threats.

***

### Notes:

* **False Positives**: Legitimate RDP sessions with high data transfer (e.g., file transfers) may trigger this query. Analysts should review the results to differentiate between benign and malicious activity.
* **Customization**: The thresholds for data transfer (`500MB`) and session count (`10`) can be adjusted based on the organization's typical RDP usage patterns.
* **Performance**: To optimize performance, consider narrowing the time range or filtering by specific devices/users if needed.
