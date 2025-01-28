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

# Playbook: Investigating Malicious Network Behaviour Using KQL

### Table of Contents

1. Initial Detection of Malicious Network Behaviour
   * Identify Abnormal Network Traffic Patterns
   * Detect Communication with Known Malicious IPs
   * Monitor Suspicious DNS Queries
2. Command and Control (C2) Indicators
   * Detect Long-Lived Connections
   * Identify Beaconing Activity
   * Monitor HTTP/HTTPS Traffic for Suspicious Patterns
3. Data Exfiltration Indicators
   * Large Outbound Data Transfers
   * Detect Anomalous Cloud Storage Access
   * Monitor Unusual Protocol Usage
4. Threat Persistence Indicators
   * Monitor Backdoor Communication
   * Detect Persistent Network Tunnels
   * Identify Abnormal Service Connections
5. Incident Response and Containment
   * Isolate Compromised Systems
   * Correlate Indicators of Compromise (IoCs)
   * Timeline Reconstruction
6. Conclusion

***

This playbook provides KQL queries and techniques to detect, analyse, and respond to malicious network behaviour using Microsoft Defender and Sentinel. Each section offers multiple query options with detailed descriptions and expected results.

### 1. **Initial Detection of Malicious Network Behaviour**

#### Query Option 1: Identify Abnormal Network Traffic Patterns

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and BytesSent > 5000000
| summarize TotalBytesSent = sum(BytesSent) by DeviceName, RemoteIPAddress
| where TotalBytesSent > 10000000
| project DeviceName, RemoteIPAddress, TotalBytesSent
```

**Description:** Detects devices sending large volumes of data to public IPs. Results highlight potential data exfiltration.

#### Query Option 2: Detect Communication with Known Malicious IPs

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPAddress in ("<malicious_ip_list>")
| project Timestamp, DeviceName, RemoteIPAddress, Protocol
```

**Description:** Identifies communication with known malicious IP addresses. Results display devices and protocols involved.

#### Query Option 3: Monitor Suspicious DNS Queries

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where Protocol == "DNS" and strlen(RemoteDnsDomain) > 50
| summarize QueryCount = count() by RemoteDnsDomain
| where QueryCount > 100
| project RemoteDnsDomain, QueryCount
```

**Description:** Flags DNS queries with unusually long domain names, often used in DNS tunneling. Results display domains and query counts.

***

### 2. **Command and Control (C2) Indicators**

#### Query Option 1: Detect Long-Lived Connections

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ConnectionDuration > 3600
| project Timestamp, DeviceName, RemoteIPAddress, ConnectionDuration
```

**Description:** Identifies network connections lasting longer than one hour, potentially indicating a C2 session. Results include devices and IP addresses.

#### Query Option 2: Identify Beaconing Activity

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| summarize Interval = min(Timestamp) by DeviceName, RemoteIPAddress
| where Interval < 10s
| project DeviceName, RemoteIPAddress, Interval
```

**Description:** Detects repeated communication with a consistent interval, characteristic of beaconing activity. Results include devices and IPs.

#### Query Option 3: Monitor HTTP/HTTPS Traffic for Suspicious Patterns

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where Protocol in ("HTTP", "HTTPS") and Url contains_any ("/login", "/auth")
| project Timestamp, DeviceName, RemoteIPAddress, Url
```

**Description:** Tracks suspicious HTTP/HTTPS traffic patterns, often used in C2 communications. Results display URLs and associated devices.

***

### 3. **Data Exfiltration Indicators**

#### Query Option 1: Large Outbound Data Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where BytesSent > 10000000
| project Timestamp, DeviceName, RemoteIPAddress, BytesSent
```

**Description:** Flags significant outbound data transfers. Results highlight devices and destination IPs.

#### Query Option 2: Detect Anomalous Cloud Storage Access

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteDnsDomain endswith_any ("amazonaws.com", "googleapis.com", "blob.core.windows.net")
| summarize TotalDataTransferred = sum(BytesSent) by DeviceName, RemoteDnsDomain
| where TotalDataTransferred > 5000000
| project DeviceName, RemoteDnsDomain, TotalDataTransferred
```
{% endcode %}

**Description:** Tracks data uploads to cloud storage services. Results include devices, domains, and upload volumes.

#### Query Option 3: Monitor Unusual Protocol Usage

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where Protocol not in ("HTTP", "HTTPS", "DNS", "SMB")
| summarize ProtocolCount = count() by Protocol, DeviceName
| project DeviceName, Protocol, ProtocolCount
```

**Description:** Flags uncommon protocols used for data transfers. Results highlight protocols and associated devices.

***

### 4. **Threat Persistence Indicators**

#### Query Option 1: Monitor Backdoor Communication

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPAddress in ("<backdoor_ip_list>")
| project Timestamp, DeviceName, RemoteIPAddress, Protocol
```

**Description:** Detects communication with backdoor IPs. Results display devices, IPs, and protocols involved.

#### Query Option 2: Detect Persistent Network Tunnels

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ConnectionDuration > 1800 and RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIPAddress, ConnectionDuration
```

**Description:** Identifies long-lived network tunnels, often used for persistent connections. Results highlight devices and remote IPs.

#### Query Option 3: Identify Abnormal Service Connections

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in ("22", "3389") and Direction == "Inbound"
| project Timestamp, DeviceName, RemoteIPAddress, RemotePort
```

**Description:** Flags unusual connections to critical services like SSH and RDP. Results display devices, remote IPs, and ports.

***

### 5. **Incident Response and Containment**

#### Query Option 1: Isolate Compromised Systems

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPAddress in ("<compromised_ip_list>")
| project Timestamp, DeviceName, RemoteIPAddress
```

**Description:** Tracks communication with compromised IPs, assisting in system isolation. Results display affected devices.

#### Query Option 2: Correlate Indicators of Compromise (IoCs)

```kusto
union DeviceProcessEvents, DeviceNetworkEvents
| where SHA256 in ("<IoC_hashes>")
| project Timestamp, EventType = $table, DeviceName, FileName, SHA256
```

**Description:** Correlates IoCs with device and network activities. Results highlight compromised systems and artifacts.

#### Query Option 3: Timeline Reconstruction

{% code overflow="wrap" %}
```kusto
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(30d)
| project Timestamp, EventType = $table, DeviceName, RemoteIPAddress, ProcessCommandLine
| order by Timestamp asc
```
{% endcode %}

**Description:** Creates a timeline of malicious network activities to support incident response. Results display event sequences and associated data.

***

### 6. **Conclusion**

The playbook offers a good approach to detecting and analysing compromises in an environment. However, its usefulness depends on the environment and tools at your disposal. For an environment where KQL is an option, the queries may require some adaptation to specific data sources and infrastructure setup.
