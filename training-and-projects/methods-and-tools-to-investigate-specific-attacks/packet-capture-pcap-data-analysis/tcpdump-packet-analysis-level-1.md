---
cover: ../../../.gitbook/assets/Screenshot 2025-01-10 081339.png
coverY: 0
layout:
  cover:
    visible: true
    size: hero
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

# Tcpdump Packet Analysis (Level 1)

### <mark style="color:blue;">**Importance of Having Access to PCAP Data in an Investigation**</mark>

PCAP (Packet Capture) data is a critical resource in cybersecurity investigations, providing a complete, raw record of network traffic at the packet level. Having access to PCAP data allows investigators to analyse both the content and behaviour of network communications, enabling the following key capabilities:

1. **Comprehensive Visibility:**
   * PCAP data offers an unfiltered view of network activity, capturing every packet exchanged between hosts. This is invaluable for identifying anomalous behaviour, malicious communications, and policy violations.
2. **Attack Reconstruction:**
   * Investigators can use PCAP data to recreate the sequence of events during an attack, such as lateral movement, command-and-control (C2) communication, or data exfiltration. This helps determine the scope and timeline of the incident.
3. **Payload Inspection:**
   * Unlike log files, PCAP captures the full content of network packets. This allows for deep payload inspection, helping detect malware delivery, ransomware encryption protocols, or exfiltrated sensitive data.
4. **Detection of Anomalies and IoCs:**
   * By analyzing PCAP data, investigators can identify Indicators of Compromise (IoCs), such as suspicious IPs, domains, or unusual traffic patterns and correlate these with known attack vectors.
5. **Validation and Proof:**
   * PCAP data is a reliable and detailed record that validates findings, supports forensic conclusions, and provides evidence in legal or compliance investigations.
6. **Threat Intelligence Correlation:**
   * PCAP data can be cross-referenced with threat intelligence feeds to detect known malware signatures, malicious domains, or rogue IP addresses.
7. **Proactive Security Improvements:**
   * Post-incident analysis of PCAP data provides insights into vulnerabilities exploited during the attack, guiding the implementation of preventive measures to improve network defences.

In summary, PCAP data is essential for effective and accurate network forensic investigations, offering unparalleled detail and insight into the network-level activities underpinning modern cyberattacks.

### <mark style="color:blue;">Basic Tcpdump Queries</mark>

The following are basic Tcpdump queries tailored for network forensics investigations involving a `.pcap` file. These queries are structured to extract critical information; however, they are basic queries intended for those with limited experience analysing pcap data.

***

### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**View Basic Packet Information**</mark>

```bash
tcpdump -r sample.pcap
```

* **Explanation**: Reads the packets from the `.pcap` file and displays a summary of each packet. Useful as an initial step to get a high-level overview of the captured traffic.

***

### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter by IP Address**</mark>

```bash
tcpdump -r sample.pcap host 192.168.1.10
```

* **Explanation**: Displays all packets involving a specific IP address (`192.168.1.10`). Helps identify activity related to a specific host.

***

### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Packets for a Specific Protocol**</mark>

*   **TCP**:

    ```bash
    tcpdump -r sample.pcap tcp
    ```
*   **UDP**:

    ```bash
    tcpdump -r sample.pcap udp
    ```
*   **ICMP**:

    ```bash
    tcpdump -r sample.pcap icmp
    ```
* **Explanation**: This filtering function filters packets by protocol. It is useful for analysing specific protocol activities such as TCP connections, UDP communication, or ICMP pings.

***

### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter by Port**</mark>

*   **Example: HTTP (Port 80)**:

    ```bash
    tcpdump -r sample.pcap port 80
    ```
* **Explanation**: Extracts packets involving traffic on a specific port (e.g., HTTP). Replace `80` with other port numbers (e.g., `443` for HTTPS, `53` for DNS).

***

### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identify Suspicious DNS Queries**</mark>

```bash
tcpdump -r sample.pcap port 53
```

* **Explanation**: This technique focuses on DNS traffic to detect abnormal or suspicious domain lookups, such as those resolving to external IPs or unusual subdomains.

***

### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter Traffic Between Two Specific IPs**</mark>

```bash
tcpdump -r sample.pcap src 192.168.1.10 and dst 8.8.8.8
```

* **Explanation**: Displays packets where the source is `192.168.1.10` and the destination is `8.8.8.8`. Helps in isolating communication between specific endpoints.

***

### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Capture Only HTTP GET or POST Requests**</mark>

```bash
tcpdump -r sample.pcap -A -s 0 port 80 | grep "GET\|POST"
```

* **Explanation**: Extracts and displays HTTP GET and POST requests in ASCII format, making identifying potential data exfiltration or suspicious web requests easier.

***

### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Traffic by Time Range**</mark>

```bash
tcpdump -r sample.pcap -ttt
```

* **Explanation**: Displays relative timestamps for packets, allowing forensic analysts to correlate events by time.

***

### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Credentials or Sensitive Data**</mark>

```bash
tcpdump -r sample.pcap -A -s 0 port 21
```

* **Explanation**: Reads FTP traffic to identify potential plaintext credentials. Replace `21` with other ports like `110` (POP3) or `143` (IMAP) for email credentials.

***

### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Export Specific Packets to a New PCAP**</mark>

```bash
tcpdump -r sample.pcap -w filtered.pcap host 192.168.1.10 and port 80
```

* **Explanation**: Saves filtered packets into a new `.pcap` file for further analysis with tools like Wireshark.

***

### <mark style="color:blue;">11.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Potential Malware Communication**</mark>

```bash
tcpdump -r sample.pcap port 443 and dst net 185.0.0.0/8
```

* **Explanation**: Focuses on HTTPS traffic directed to a specific suspicious network range (e.g., external or untrusted subnets). Replace `185.0.0.0/8` with known malicious ranges.

***

### <mark style="color:blue;">12.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Analyze Large Packet Flows (Possible Data Exfiltration)**</mark>

```bash
tcpdump -r sample.pcap greater 1000
```

* **Explanation**: Displays packets larger than 1000 bytes. This can help identify file transfers or data exfiltration attempts.

***

### <mark style="color:blue;">13.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter for SYN or SYN-ACK Packets (Port Scanning)**</mark>

```bash
tcpdump -r sample.pcap 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'
```

* **Explanation**: Identifies SYN or SYN-ACK packets to detect port scanning activities or abnormal connection attempts.

***

### <mark style="color:blue;">14.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Potential ARP Spoofing**</mark>

```bash
tcpdump -r sample.pcap arp
```

* **Explanation**: Analyses ARP traffic to detect unusual patterns such as multiple ARP replies from a single IP or mismatched MAC addresses.

***

### <mark style="color:blue;">15.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Analyze Suspicious Command-and-Control (C2) Activity**</mark>

```bash
tcpdump -r sample.pcap dst port 443 or dst port 80
```

* **Explanation**: Isolates traffic destined for web-based ports to look for anomalies or patterns indicative of communication with a C2 server.

***

These `tcpdump` commands provide a starting point for investigating `.pcap` files in network forensics. They can be adapted based on the specific incident, suspected threat, or network environment under analysis.
