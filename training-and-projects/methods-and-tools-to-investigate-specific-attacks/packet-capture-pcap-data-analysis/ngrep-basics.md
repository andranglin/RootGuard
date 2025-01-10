---
cover: ../../../.gitbook/assets/Screenshot 2025-01-05 133615 (2).png
coverY: 0
---

# Ngrep Basics

### <mark style="color:blue;">Using Ngrep for PCAP Data Analysis in an Investigation</mark>

**Ngrep** (Network Grep) is a versatile tool for searching network traffic within PCAP files, offering regex-based filtering and a human-readable output. Its simplicity and focus on payload data make it a valuable resource for quick and targeted forensic investigations.&#x20;

#### Key advantages include:

1. **Payload-Focused Analysis**:
   * Unlike many tools that emphasise protocol metadata, Ngrep highlights the content of packet payloads, making it ideal for detecting keywords, patterns, or sensitive information like credentials in network traffic.
2. **Regex-Based Filtering**:
   * Ngrep's powerful regex capabilities allow investigators to define complex search patterns, such as specific URLs, authentication attempts, or indicators of compromise (IoCs).
3. **Protocol Flexibility**:
   * Ngrep supports various protocols, including HTTP, FTP, DNS, and SMB, enabling analysts to filter traffic by protocol type or port.
4. **Rapid Identification**:
   * Its straightforward syntax and immediate output make it a quick and effective tool for identifying malicious activity, such as data exfiltration, command-and-control communication, or malware payloads.
5. **Readable Output**:
   * Ngrep presents packets in a human-readable format, simplifying the process of reviewing traffic and interpreting results.
6. **Complementary Tool**:
   * While not as feature-rich as Wireshark or TShark, Ngrep excels in targeted searches, making it a complementary tool for specific forensic tasks.
7. **Export Capability**:
   * Ngrep can filter and save matching traffic into new PCAP files, which can then be analysed further with other tools.

By focusing on payload visibility and providing regex-based filtering, Ngrep is an invaluable tool for forensic investigators seeking to uncover specific evidence within large PCAP datasets quickly. Its lightweight and targeted approach complements broader network analysis workflows.

Below are some **`ngrep`** queries for network forensics investigations along with an explanation of each query.

***

### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**View All Packets in a PCAP**</mark>

```bash
ngrep -I sample.pcap
```

* **Explanation**: Displays all packets in the `.pcap` file. This provides an initial overview of the captured traffic.

***

### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter by IP Address**</mark>

```bash
ngrep -I sample.pcap host 192.168.1.10
```

* **Explanation**: Filters traffic to or from a specific IP address (`192.168.1.10`). Useful for isolating traffic related to a potentially compromised host.

***

### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Search for Specific Strings**</mark>

*   **HTTP**:

    ```bash
    ngrep -I sample.pcap -q "GET|POST" tcp port 80
    ```
*   **Sensitive Keywords**:

    ```bash
    ngrep -I sample.pcap "password|admin" any
    ```
* **Explanation**: Searches for specific strings (e.g., `GET`, `POST`, `password`, or `admin`) in the payloads of network traffic. Helps detect sensitive data leaks or malicious activity.

***

### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Inspect DNS Traffic**</mark>

```bash
ngrep -I sample.pcap -q "example.com" udp port 53
```

* **Explanation**: Filters DNS traffic for queries or responses containing a specific domain (`example.com`). Use this to detect suspicious or malicious domain lookups.

***

### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Capture HTTP Traffic**</mark>

```bash
ngrep -I sample.pcap -W byline tcp port 80
```

* **Explanation**: Captures HTTP traffic and formats the output line-by-line. Useful for analyzing web requests and responses.

***

### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Monitor FTP Traffic**</mark>

```bash
ngrep -I sample.pcap "USER|PASS" tcp port 21
```

* **Explanation**: Monitors FTP traffic for `USER` and `PASS` commands to detect plaintext credentials.

***

### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect ICMP Tunneling**</mark>

```bash
ngrep -I sample.pcap "data" icmp
```

* **Explanation**: Searches for ICMP packets with specific payloads (e.g., containing "data"). Helps detect potential tunneling activities.

***

### <mark style="color:blue;">8.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Search for Malicious Payloads**</mark>

```bash
ngrep -I sample.pcap -q "malicious_string" any
```

* **Explanation**: Searches for known malicious payloads (e.g., signatures or specific strings) in any protocol.

***

### <mark style="color:blue;">9.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter HTTPS Traffic**</mark>

```bash
ngrep -I sample.pcap "" tcp port 443
```

* **Explanation**: Captures HTTPS traffic. Since payloads are encrypted, focus on metadata like IPs and packet patterns to detect anomalies.

***

### <mark style="color:blue;">10.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Inspect SMB Traffic**</mark>

```bash
ngrep -I sample.pcap -W byline tcp port 445
```

* **Explanation**: Captures SMB traffic, potentially showing file operations or suspicious activity like ransomware encrypting files over SMB.

***

### 11. **Detect Command-and-Control (C2) Traffic**

*   **HTTP-Based C2**:

    ```bash
    ngrep -I sample.pcap -q "GET|POST" tcp port 80
    ```
*   **DNS-Based C2**:

    ```bash
    ngrep -I sample.pcap -q "malicious.domain" udp port 53
    ```
* **Explanation**: Focuses on potential C2 communication over HTTP or DNS, searching for specific patterns or domains associated with malware.

***

### <mark style="color:blue;">12.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Filter by Port**</mark>

*   **HTTP**:

    ```bash
    ngrep -I sample.pcap "" tcp port 80
    ```
*   **FTP**:

    ```bash
    ngrep -I sample.pcap "" tcp port 21
    ```
* **Explanation**: Captures all traffic on a specific port, allowing protocol-specific analysis.

***

### <mark style="color:blue;">13.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Large File Transfers**</mark>

```bash
ngrep -I sample.pcap "" tcp and greater 1500
```

* **Explanation**: Captures large packets, which may indicate file transfers or potential data exfiltration.

***

### <mark style="color:blue;">14.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Search for Base64-Encoded Payloads**</mark>

```bash
ngrep -I sample.pcap "[A-Za-z0-9+/=]{40,}" any
```

* **Explanation**: Identifies base64-encoded strings, often used in exfiltration or malware communication.

***

### <mark style="color:blue;">15.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Track Ransomware Activity**</mark>

*   **SMB-Based**:

    ```bash
    ngrep -I sample.pcap -q "smb2" tcp port 445
    ```
*   **DNS-Based**:

    ```bash
    ngrep -I sample.pcap "ransomnote.domain" udp port 53
    ```
* **Explanation**: Monitors specific behaviours (e.g., SMB or DNS activity) associated with ransomware operations.

***

### <mark style="color:blue;">16.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Extract Email Communication**</mark>

```bash
ngrep -I sample.pcap -W byline tcp port 25
```

* **Explanation**: Captures SMTP traffic to detect potentially malicious emails or data exfiltration via email.

***

### <mark style="color:blue;">17.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Analsze Tor Traffic**</mark>

```bash
ngrep -I sample.pcap "" tcp port 9001
```

* **Explanation**: Captures traffic to Tor entry nodes, which may indicate anonymised communication by malware or ransomware.

***

### <mark style="color:blue;">18.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Export Specific Packets to a New PCAP**</mark>

```bash
ngrep -O filtered.pcap "example.com" udp port 53
```

* **Explanation**: Saves packets matching a query (e.g., DNS requests for `example.com`) to a new `.pcap` file for further analysis.

***

### <mark style="color:blue;">19.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Detect Unusual Login Attempts**</mark>

```bash
ngrep -I sample.pcap "login|auth|failed" tcp port 22
```

* **Explanation**: Searches for keywords like `login`, `auth`, or `failed` in SSH traffic to detect brute-force attempts or suspicious logins.

***

### <mark style="color:blue;">20.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Track Abnormal Traffic Patterns**</mark>

```bash
ngrep -I sample.pcap "" udp and portrange 1000-2000
```

* **Explanation**: Monitors traffic on a specific port range to identify unusual patterns or suspicious activities.

***

#### <mark style="color:blue;">Notes:</mark>

* Replace placeholders like `"example.com"` or `"malicious_string"` with investigation-specific keywords or IoCs.
* Combine with regex for advanced pattern matching.
* Use `-W byline` for easier readability in multi-line traffic payloads.

**`ngrep`** is a lightweight and effective tool for quick, targeted network traffic searches, complementing more comprehensive tools like Wireshark or TShark in forensic investigations.