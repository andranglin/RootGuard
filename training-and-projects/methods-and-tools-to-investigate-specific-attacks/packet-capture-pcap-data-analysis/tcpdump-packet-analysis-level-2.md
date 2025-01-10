---
cover: ../../../.gitbook/assets/Screenshot 2025-01-05 133615 (2).png
coverY: 0
---

# Tcpdump Packet Analysis (Level 2)

### <mark style="color:blue;">The Importance of Having Access to PCAP Data in an Investigation</mark>

Packet Capture (PCAP) data is a critical resource in network security investigations, providing a detailed, timestamped record of all network traffic. By preserving the raw packets exchanged across a network, PCAP data allows investigators to analyse every communication byte for forensic purposes. Its importance can be summarised as follows:

1. **Comprehensive Visibility**:
   * PCAP data captures every network interaction, enabling analysts to reconstruct events accurately. It provides insights into application-level protocols (HTTP, DNS, SMB), network-layer details (IP addresses, ports), and transport-layer interactions (TCP/UDP flags).
2. **Incident Reconstruction**:
   * In the aftermath of a security incident, PCAP data helps recreate the sequence of events, such as how an attacker gained access, what they did, and whether data was exfiltrated. This level of detail is invaluable for understanding the scope and impact of an attack.
3. **Threat Hunting**:
   * PCAP allows for the detection of hidden or subtle malicious activities, such as command-and-control communications, data exfiltration, lateral movement, or abnormal traffic patterns that log-based tools might miss.
4. **Evidence Collection**:
   * In legal or compliance scenarios, PCAP data serves as concrete evidence of malicious activities or policy violations. It ensures integrity and supports attribution efforts in cases requiring accountability.
5. **Validation of Security Controls**:
   * PCAP data can be used to assess the effectiveness of firewalls, intrusion detection/prevention systems (IDS/IPS), and other security controls by identifying what traffic was allowed or blocked during an incident.
6. **Anomaly Detection**:
   * Detailed packet analysis enables the identification of unusual behaviours, such as large file transfers, DNS tunnelling, or encrypted traffic to unknown external IPs—often indicative of advanced threats like ransomware or data theft.
7. **Training and Research**:
   * Forensic analysts can use PCAP files for simulations, training, or developing new detection mechanisms. It provides real-world traffic data to refine defensive strategies.

Access to PCAP data allows investigators to perform deep-dive analysis, validate hypotheses, and extract actionable intelligence, making it a cornerstone of modern cybersecurity and network forensics.

The following Tcpdump queries are designed to identify malicious activities. They focus on abnormal behaviours, specific protocols, and known malicious indicators.

***

### <mark style="color:blue;">1.</mark> <mark style="color:blue;">**Detect Suspicious SMB Traffic**</mark>

```bash
tcpdump -r sample.pcap port 445
```

* **Explanation**: Monitors SMB traffic, often used in ransomware attacks for lateral movement or encrypting shared files. Look for unusual file operations or an increase in SMB requests.

***

### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identify Large Outbound Traffic (Potential Data Exfiltration)**</mark>

{% code overflow="wrap" %}
```bash
tcpdump -r sample.pcap src net 192.168.1.0/24 and dst net not 192.168.1.0/24 and greater 1500
```
{% endcode %}

* **Explanation**: Detects large packets originating from the internal network (`192.168.1.0/24`) to external networks. Ransomware may exfiltrate data before encryption.

***

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Command-and-Control (C2) Communication**</mark>

*   **Over HTTPS (Port 443)**:

    {% code overflow="wrap" %}
    ```bash
    tcpdump -r sample.pcap port 443 and src net 192.168.1.0/24 and dst net not 192.168.1.0/24
    ```
    {% endcode %}
*   **DNS Tunneling (Port 53)**:

    {% code overflow="wrap" %}
    ```bash
    tcpdump -r sample.pcap port 53 and src net 192.168.1.0/24 and dst net not 192.168.1.0/24 and greater 300
    ```
    {% endcode %}
* **Explanation**: Identifies external communication to untrusted destinations, which may indicate ransomware contacting its C2 server for encryption keys or instructions.

***

### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Find Encrypted Traffic with Unusual Destinations**</mark>

```bash
tcpdump -r sample.pcap port 443 and not dst net 8.8.8.0/24
```

* **Explanation**: Extracts encrypted traffic to uncommon or suspicious IP ranges, which may indicate ransomware communication.

***

### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Abnormal File Transfers (FTP/SMB)**</mark>

*   **FTP (Port 21)**:

    ```bash
    tcpdump -r sample.pcap port 21 and src net 192.168.1.0/24
    ```
*   **SMB**:

    ```bash
    tcpdump -r file.pcap port 445 and tcp[tcpflags] & tcp-push != 0
    ```
* **Explanation**: Filters FTP and SMB traffic, focusing on unusual file transfers or commands that could signal data staging or ransomware encrypting files.

***

### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Look for Brute Force or Credential Theft**</mark>

```bash
tcpdump -r sample.pcap port 3389 or port 22
```

* **Explanation**: Monitors RDP (`3389`) and SSH (`22`) traffic for potential brute force attempts or unauthorised access, which are common precursors to ransomware deployment.

***

### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Port Scanning or Lateral Movement**</mark>

```bash
tcpdump -r sample.pcap 'tcp[tcpflags] & tcp-syn != 0'
```

* **Explanation**: Detects SYN packets, often used during port scans to identify vulnerable systems for lateral movement.

***

### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identify Ransomware Network Beaconing**</mark>

```bash
tcpdump -r sample.pcap 'udp[8:2] = 0x5353 or udp[8:2] = 0x5354'
```

* **Explanation**: Look for suspicious UDP beacons often used in ransomware to communicate with C2 servers.

***

### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Monitor for Abnormal DNS Queries**</mark>

```bash
tcpdump -r sample.pcap port 53 and 'udp[10] & 0x80 = 0'
```

* **Explanation**: Captures DNS queries, excluding responses. Look for unusually long domains, random subdomains, or queries resolving to known malicious IPs.

***

### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Rapidly Generated Outbound Connections**</mark>

{% code overflow="wrap" %}
```bash
tcpdump -r sample.pcap src net 192.168.1.0/24 and dst net not 192.168.1.0/24 and tcp[tcpflags] & tcp-syn != 0
```
{% endcode %}

* **Explanation**: Identifies a large number of SYN packets from internal hosts to external networks, which could indicate malware attempting to spread or communicate with multiple servers.

***

### <mark style="color:blue;">11.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Monitor for Tor Traffic**</mark>

```bash
tcpdump -r sample.pcap dst port 9001 or dst port 9030
```

* **Explanation**: Captures traffic to Tor entry nodes, often used by ransomware for anonymous communication.

***

### <mark style="color:blue;">12.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Capture Malicious HTTP Requests**</mark>

{% code overflow="wrap" %}
```bash
tcpdump -r sample.pcap port 80 and 'tcp[32:4] = 0x47455420 or tcp[32:4] = 0x504f5354'
```
{% endcode %}

* **Explanation**: Filters HTTP traffic containing `GET` or `POST` requests, which could be used for C2 communication or exfiltration.

***

### <mark style="color:blue;">13.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Suspicious Use of ICMP (Ping Tunnels)**</mark>

```bash
tcpdump -r sample.pcap icmp and greater 100
```

* **Explanation**: Extracts ICMP packets larger than normal (e.g., over 100 bytes), which could indicate covert data exfiltration or tunnelling.

***

### <mark style="color:blue;">14.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identify Outbound Traffic to Known Malicious IPs**</mark>

```bash
tcpdump -r sample.pcap dst net 198.51.100.0/24
```

* **Explanation**: Filters traffic to a known malicious network (replace `198.51.100.0/24` with specific indicators of compromise). Useful for threat hunting.

***

### <mark style="color:blue;">15.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Track Ransomware Encryption Activity**</mark>

```bash
tcpdump -r sample.pcap port 445 and 'tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-push) != 0'
```

* **Explanation**: Focuses on SMB traffic with specific flags, which may indicate file encryption attempts over the network.

***

### <mark style="color:blue;">16.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Packets with Suspicious Payload Sizes**</mark>

```bash
tcpdump -r sample.pcap 'greater 1200'
```

* **Explanation**: Captures large packets that could indicate file transfers or data exfiltration before ransomware encryption.

***

### <mark style="color:blue;">17.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Traffic to Unusual Regions**</mark>

```bash
tcpdump -r sample.pcap dst net not 192.168.0.0/16 and dst net not 10.0.0.0/8
```

* **Explanation**: Identifies traffic leaving the local network to unknown or external IPs, which may suggest ransomware communication or exfiltration.

***

These`tcpdump` queries are tailored to identify malicious activities and behaviours to look out for during investigations. To enhance detection, cross-reference the results with threat intelligence feeds and known IoCs (Indicators of Compromise).