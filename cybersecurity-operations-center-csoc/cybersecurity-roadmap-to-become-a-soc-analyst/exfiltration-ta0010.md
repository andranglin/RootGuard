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

# Exfiltration (TA0010)

### **Sub-technique: T1041 - Exfiltration Over C2 Channel**

**Objective**: Detect data exfiltration over command and control channels.&#x20;

1. **Detect Large Data Transfers to Unknown IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where BytesSent > 1000000 | summarize count() by RemoteIP, LocalIP | where count() > 10

//Extended search
DeviceNetworkEvents
| where InitiatingProcessFileSize > 1000000
| summarize EventCount = count() by RemoteIP, LocalIP, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFileSize
| where EventCount > 10
```
{% endcode %}

**Purpose**: Identify large data transfers to unknown IP addresses.

2. **Monitor for DNS-Based Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 53 | summarize count() by RemoteIP, LocalIP | where count() > 100
```
{% endcode %}

**Purpose**: Detect DNS-based exfiltration.

3. **Detect HTTP POST Requests Used for Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has "POST" | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Monitor for HTTP POST requests used to exfiltrate data.

4. **Monitor for Data Exfiltration via Cloud Storage**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("cloud_storage_ip_list") | summarize count() by RemoteIP, LocalIP | where count() > 50
```
{% endcode %}

**Purpose**: Identify data uploads to cloud storage services.

5. **Detect Exfiltration via FTP**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 21 | where BytesSent > 1000000 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Detect large data transfers over FTP.

6. **Monitor for Email-Based Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 25 or RemotePort == 587 | where BytesSent > 100000 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Identify data exfiltration attempts via email.

7. **Detect Use of Encrypted Channels for Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 or RemotePort == 22 | where BytesSent > 500000 | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

**Purpose**: Monitor for data exfiltration over encrypted channels.

8. **Identify Data Exfiltration via WebSocket**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and ProcessCommandLine has "websocket" | project Timestamp, DeviceName, RemoteIP, ProcessCommandLine
```
{% endcode %}

**Purpose**: Detect WebSocket connections used for exfiltration.

9. **Monitor for Data Exfiltration via Network Shares**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 445 | summarize count() by RemoteIP, LocalIP | where count() > 20
```
{% endcode %}

**Purpose**: Identify data exfiltration via network shares.

10. **Detect Use of Unknown Protocols for Exfiltration**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where Protocol not in ("TCP", "UDP", "ICMP") | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

**Purpose**: Monitor for exfiltration over unknown or unusual protocols.
