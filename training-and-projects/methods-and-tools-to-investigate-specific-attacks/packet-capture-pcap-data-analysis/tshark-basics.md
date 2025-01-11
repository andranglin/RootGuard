---
cover: ../../../.gitbook/assets/Screenshot 2025-01-10 081659.png
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

# Tshark Basics

### <mark style="color:blue;">Using TShark for PCAP Data Analysis in an Investigation</mark>

**TShark**, the command-line counterpart to Wireshark, is a powerful tool for analysing PCAP data when doing network forensic investigations. It provides detailed insights into network traffic, enabling analysts to uncover malicious activities and understand the scope of security incidents.&#x20;

Key benefits of using TShark include:

1. **Efficiency in Large-Scale Analysis**:
   * TShark can process large PCAP files quickly and efficiently, making it ideal for investigating high-volume network traffic without requiring a graphical interface.
2. **Granular Filtering and Queries**:
   * With its robust filtering options, TShark allows analysts to isolate specific traffic types, such as HTTP, DNS, or SMB, or focus on particular indicators like IP addresses, ports, or protocol flags.
3. **Customizable Output**:
   * Analysts can extract specific fields (e.g., timestamps, source/destination IPs, packet lengths) and export the data in formats like JSON, CSV, or plain text for further analysis or reporting.
4. **Protocol-Specific Insights**:
   * TShark decodes and interprets hundreds of protocols, making it easier to analyse the contents of application-layer protocols like HTTP, FTP, DNS, and TLS.
5. **Integration with Automation**:
   * Its command-line nature allows TShark to be integrated into scripts for automated analysis, such as detecting IoCs, extracting credentials, or monitoring traffic patterns.
6. **Forensic Applications**:
   * TShark can be used to reconstruct events, such as identifying command-and-control communication, detecting large file transfers (data exfiltration), or analysing malicious payloads.
7. **Reproducibility and Reporting**:
   * The ability to generate logs and export specific packets makes TShark a reliable tool for creating reproducible evidence and detailed investigative reports.

By leveraging TShark, investigators gain a precise, scalable, and scriptable tool for deep-diving into network traffic, identifying threats, and gathering actionable intelligence during cybersecurity investigations

Below is a set of **TShark** queries designed for forensic analysis of`.pcap` files, each accompanied by an explanation of its purpose. **TShark**, the command-line version of Wireshark, allows you to efficiently analyse network traffic for investigations.

***

### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**View Basic Packet Information**</mark>

```bash
tshark -r sample.pcap
```

* **Explanation**: Displays a summary of all packets in the pcap file. Use this as a starting point to get an overview of the traffic.

***

### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract HTTP GET and POST Requests**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "http.request" -T fields -e http.host -e http.request.method -e http.request.uri
```
{% endcode %}

* **Explanation**: Extracts HTTP request methods (`GET`, `POST`), the hostnames, and URIs. This is useful for identifying malicious web requests or data exfiltration.

***

### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter Traffic by IP Address**</mark>

```bash
tshark -r sample.pcap -Y "ip.addr == 192.168.1.10"
```

* **Explanation**: Displays all packets involving a specific IP address (`192.168.1.10`). This isolates traffic related to a potentially compromised host.

***

### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter DNS Queries**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "dns.qry.name" -T fields -e frame.time -e dns.qry.name
```
{% endcode %}

* **Explanation**: Extracts DNS queries with timestamps. Helps identify unusual or suspicious domain lookups, such as those related to malware or ransomware C2 servers.

***

### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter by Protocol**</mark>

*   **HTTP**:

    ```bash
    tshark -r sample.pcap -Y "http"
    ```
*   **TCP**:

    ```bash
    tshark -r sample.pcap -Y "tcp"
    ```
*   **UDP**:

    ```bash
    tshark -r sample.pcap -Y "udp"
    ```
* **Explanation**: Filters traffic by protocol type to focus on specific types of communication.

***

### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identify Large Packets (Possible Data Exfiltration)**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "frame.len > 1000" -T fields -e frame.time -e ip.src -e ip.dst -e frame.len
```
{% endcode %}

* **Explanation**: Filters packets larger than 1000 bytes, often associated with file transfers or data exfiltration attempts.

***

### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect SMB Activity**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "smb" -T fields -e frame.time -e ip.src -e ip.dst -e smb.command
```
{% endcode %}

* **Explanation**: Extracts SMB traffic to identify suspicious file operations or lateral movement attempts.

***

### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Credentials from FTP or HTTP Traffic**</mark>

*   **FTP**:

    {% code overflow="wrap" %}
    ```bash
    tshark -r sample.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS" -T fields -e ftp.request.command -e ftp.request.arg
    ```
    {% endcode %}
*   **HTTP Basic Auth**:

    ```bash
    bashCopy codetshark -r file.pcap -Y "http.authbasic" -T fields -e http.authbasic
    ```
* **Explanation**: Detects plaintext credentials in FTP or HTTP traffic.

***

### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Analyse Command-and-Control (C2) Activity**</mark>

*   **HTTP-Based C2**:

    ```bash
    tshark -r sample.pcap -Y "http.request and ip.dst == 198.51.100.1"
    ```
*   **DNS Tunneling**:

    {% code overflow="wrap" %}
    ```bash
    tshark -r sample.pcap -Y "dns.qry.name and frame.len > 300" -T fields -e dns.qry.name -e frame.len
    ```
    {% endcode %}
* **Explanation**: Filters packets for C2 activity over HTTP or DNS. Replace the IP or payload length as needed.

***

### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Port Scanning Activity**</mark>

```bash
tshark -r sample.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0"
```

* **Explanation**: Identifies SYN packets without ACK responses, which are indicative of port scanning attempts.

***

### <mark style="color:blue;">11.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Specific Fields for Analysis**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
```
{% endcode %}

* **Explanation**: Extracts key fields like timestamp, source/destination IPs, and ports for deeper analysis or reporting.

***

### <mark style="color:blue;">12.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect ICMP Tunneling**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "icmp" -T fields -e frame.time -e ip.src -e ip.dst -e icmp.type -e frame.len
```
{% endcode %}

* **Explanation**: Analyses ICMP traffic for unusually large packet sizes or frequent activity, which may indicate data tunnelling.

***

### <mark style="color:blue;">13.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter TLS Traffic**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "ssl" -T fields -e frame.time -e ip.src -e ip.dst -e ssl.handshake.ciphersuite
```
{% endcode %}

* **Explanation**: Displays TLS/SSL traffic, including cipher suites, which may help detect anomalous encrypted communication.

***

### <mark style="color:blue;">14.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identify Unusual DNS Responses**</mark>

```bash
tshark -r sample.pcap -Y "dns.flags.response == 1 and dns.a"
```

* **Explanation**: Focuses on DNS responses, highlighting resolved IP addresses that may link to malicious domains.

***

### <mark style="color:blue;">15.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Export Traffic to a New PCAP File**</mark>

```bash
tshark -r sample.pcap -Y "ip.addr == 192.168.1.10" -w filtered.pcap
```

* **Explanation**: Filters traffic for a specific condition (e.g., an IP address) and writes it to a new `.pcap` file for focused analysis.

***

### <mark style="color:blue;">16.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Reassemble HTTP Objects**</mark>

```bash
tshark -r sample.pcap --export-objects http,output_directory/
```

* **Explanation**: Extracts files transferred via HTTP. Useful for recovering potentially malicious payloads or identifying stolen data.

***

### <mark style="color:blue;">17.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Unencrypted Credentials in Telnet**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "telnet" -T fields -e frame.time -e ip.src -e ip.dst -e telnet.data
```
{% endcode %}

* **Explanation**: Captures Telnet traffic to identify unencrypted credentials or commands transmitted.

***

### <mark style="color:blue;">18.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Monitor RDP Traffic**</mark>

```bash
tshark -r sample.pcap -Y "tcp.port == 3389"
```

* **Explanation**: Analyses Remote Desktop Protocol (RDP) traffic, often targeted by attackers for brute force attempts or lateral movement.

***

### <mark style="color:blue;">19.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Malicious Traffic Using IoCs**</mark>

{% code overflow="wrap" %}
```bash
tshark -r sample.pcap -Y "ip.addr == 203.0.113.5 or dns.qry.name contains 'malicious.com'"
```
{% endcode %}

* **Explanation**: Filters traffic based on known Indicators of Compromise (IoCs), such as malicious IPs or domains.

***

### <mark style="color:blue;">20.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Identify Traffic to Tor Nodes**</mark>

```bash
tshark -r sample.pcap -Y "tcp.port == 9001 or tcp.port == 9030"
```

* **Explanation**: Filters traffic to ports commonly associated with Tor entry or relay nodes, potentially indicating anonymised communication by ransomware.

***

### <mark style="color:blue;">21.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Suspicious Packet Rates**</mark>

```bash
tshark -r sample.pcap -qz io,stat,1
```

* **Explanation**: Summarises packet counts per second. Spikes may indicate scanning, DDoS, or other anomalies.

***

#### <mark style="color:blue;">Notes:</mark>

* Replace placeholders (e.g., `192.168.1.10`, `203.0.113.5`, `malicious.com`) with investigation-specific details.
* Use threat intelligence feeds to refine filters with known IoCs.

These TShark queries provide a toolkit for performing network forensics on pcap files, helping uncover malicious activities or other suspicious behaviours.
