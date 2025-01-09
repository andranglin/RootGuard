# Ngrep Basics

**`ngrep`** is a powerful command-line tool for searching network traffic, providing human-readable packet captures with regex-based filtering. Below are **`ngrep`** queries designed for network forensics investigations using `.pcap` files, along with their explanations.

***

#### 1. **View All Packets in a PCAP**

```bash
bashCopy codengrep -I file.pcap
```

* **Explanation**: Displays all packets in the `.pcap` file. This provides an initial overview of the captured traffic.

***

#### 2. **Filter by IP Address**

```bash
bashCopy codengrep -I file.pcap host 192.168.1.10
```

* **Explanation**: Filters traffic to or from a specific IP address (`192.168.1.10`). Useful for isolating traffic related to a potentially compromised host.

***

#### 3. **Search for Specific Strings**

*   **HTTP**:

    ```bash
    bashCopy codengrep -I file.pcap -q "GET|POST" tcp port 80
    ```
*   **Sensitive Keywords**:

    ```bash
    bashCopy codengrep -I file.pcap "password|admin" any
    ```
* **Explanation**: Searches for specific strings (e.g., `GET`, `POST`, `password`, or `admin`) in the payloads of network traffic. Helps detect sensitive data leaks or malicious activity.

***

#### 4. **Inspect DNS Traffic**

```bash
bashCopy codengrep -I file.pcap -q "example.com" udp port 53
```

* **Explanation**: Filters DNS traffic for queries or responses containing a specific domain (`example.com`). Use this to detect suspicious or malicious domain lookups.

***

#### 5. **Capture HTTP Traffic**

```bash
bashCopy codengrep -I file.pcap -W byline tcp port 80
```

* **Explanation**: Captures HTTP traffic and formats the output line-by-line. Useful for analyzing web requests and responses.

***

#### 6. **Monitor FTP Traffic**

```bash
bashCopy codengrep -I file.pcap "USER|PASS" tcp port 21
```

* **Explanation**: Monitors FTP traffic for `USER` and `PASS` commands to detect plaintext credentials.

***

#### 7. **Detect ICMP Tunneling**

```bash
bashCopy codengrep -I file.pcap "data" icmp
```

* **Explanation**: Searches for ICMP packets with specific payloads (e.g., containing "data"). Helps detect potential tunneling activities.

***

#### 8. **Search for Malicious Payloads**

```bash
bashCopy codengrep -I file.pcap -q "malicious_string" any
```

* **Explanation**: Searches for known malicious payloads (e.g., signatures or specific strings) in any protocol.

***

#### 9. **Filter HTTPS Traffic**

```bash
bashCopy codengrep -I file.pcap "" tcp port 443
```

* **Explanation**: Captures HTTPS traffic. Since payloads are encrypted, focus on metadata like IPs and packet patterns to detect anomalies.

***

#### 10. **Inspect SMB Traffic**

```bash
bashCopy codengrep -I file.pcap -W byline tcp port 445
```

* **Explanation**: Captures SMB traffic, potentially showing file operations or suspicious activity like ransomware encrypting files over SMB.

***

#### 11. **Detect Command-and-Control (C2) Traffic**

*   **HTTP-Based C2**:

    ```bash
    bashCopy codengrep -I file.pcap -q "GET|POST" tcp port 80
    ```
*   **DNS-Based C2**:

    ```bash
    bashCopy codengrep -I file.pcap -q "malicious.domain" udp port 53
    ```
* **Explanation**: Focuses on potential C2 communication over HTTP or DNS, searching for specific patterns or domains associated with malware.

***

#### 12. **Filter by Port**

*   **HTTP**:

    ```bash
    bashCopy codengrep -I file.pcap "" tcp port 80
    ```
*   **FTP**:

    ```bash
    bashCopy codengrep -I file.pcap "" tcp port 21
    ```
* **Explanation**: Captures all traffic on a specific port, allowing protocol-specific analysis.

***

#### 13. **Detect Large File Transfers**

```bash
bashCopy codengrep -I file.pcap "" tcp and greater 1500
```

* **Explanation**: Captures large packets, which may indicate file transfers or potential data exfiltration.

***

#### 14. **Search for Base64-Encoded Payloads**

```bash
bashCopy codengrep -I file.pcap "[A-Za-z0-9+/=]{40,}" any
```

* **Explanation**: Identifies base64-encoded strings, often used in exfiltration or malware communication.

***

#### 15. **Track Ransomware Activity**

*   **SMB-Based**:

    ```bash
    bashCopy codengrep -I file.pcap -q "smb2" tcp port 445
    ```
*   **DNS-Based**:

    ```bash
    bashCopy codengrep -I file.pcap "ransomnote.domain" udp port 53
    ```
* **Explanation**: Monitors specific behaviors (e.g., SMB or DNS activity) associated with ransomware operations.

***

#### 16. **Extract Email Communication**

```bash
bashCopy codengrep -I file.pcap -W byline tcp port 25
```

* **Explanation**: Captures SMTP traffic to detect potentially malicious emails or data exfiltration via email.

***

#### 17. **Analyze Tor Traffic**

```bash
bashCopy codengrep -I file.pcap "" tcp port 9001
```

* **Explanation**: Captures traffic to Tor entry nodes, which may indicate anonymized communication by malware or ransomware.

***

#### 18. **Export Specific Packets to a New PCAP**

```bash
bashCopy codengrep -O filtered.pcap "example.com" udp port 53
```

* **Explanation**: Saves packets matching a query (e.g., DNS requests for `example.com`) to a new `.pcap` file for further analysis.

***

#### 19. **Detect Unusual Login Attempts**

```bash
bashCopy codengrep -I file.pcap "login|auth|failed" tcp port 22
```

* **Explanation**: Searches for keywords like `login`, `auth`, or `failed` in SSH traffic to detect brute-force attempts or suspicious logins.

***

#### 20. **Track Abnormal Traffic Patterns**

```bash
bashCopy codengrep -I file.pcap "" udp and portrange 1000-2000
```

* **Explanation**: Monitors traffic on a specific port range to identify unusual patterns or suspicious activities.

***

#### Notes:

* Replace placeholders like `"example.com"` or `"malicious_string"` with investigation-specific keywords or IoCs.
* Combine with regex for advanced pattern matching.
* Use `-W byline` for easier readability in multi-line traffic payloads.

**`ngrep`** is a lightweight and effective tool for quick, targeted network traffic searches, complementing more comprehensive tools like Wireshark or TShark in forensic investigations.
