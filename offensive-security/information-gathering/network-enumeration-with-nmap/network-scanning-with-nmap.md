# Network Scanning With Nmap

## Efficient Network Exploration

Nmap (Network Mapper) is a powerful tool for network discovery, port scanning, and security auditing. This cheat sheet provides key Nmap commands for scanning networks, discovering hosts, analysing firewalls, and optimising performance. Explanations and tips accompany each command to help you effectively use Nmap for reconnaissance, ensuring you have permission to scan the target network. Use this guide as a quick reference for network exploration and security assessments.

***

### Basic Nmap Scans

These commands cover common scanning scenarios, from host discovery to full port scans and script execution.

#### Host Discovery (Ping Scan)

```bash
nmap -sn $ip
```

* **Purpose**: Disables port scanning to perform host discovery only, checking if hosts are up.
* **Use Case**: Quickly identify live hosts in a network without scanning ports.
* **Tip**: Ideal for initial reconnaissance or when port scanning is unnecessary.

#### SYN Ping Scan

```bash
nmap -sn -PS $ip
```

* **Purpose**: Sends TCP SYN packets to check if hosts respond, bypassing ICMP blocks.
* **Use Case**: Detect hosts behind firewalls that block ICMP echo requests.
* **Tip**: Specify ports `-PS22,80` to target standard services (e.g., SSH, HTTP).

#### TCP ACK Ping Scan

```bash
nmap -sn -PA $ip
```

* **Purpose**: Sends TCP ACK packets to detect hosts, helpful for firewalled environments.
* **Use Case**: Identify live hosts when SYN or ICMP pings are blocked.
* **Tip**: Combine with -PA22,80 to probe specific ports for better accuracy.

#### Full SYN Scan with Aggressive Timing

```bash
nmap -T4 -sS -p- $ip
```

* **Purpose**: Performs a TCP SYN scan on all 65,535 ports with aggressive timing (T4).
* **Use Case**: Comprehensive port scan for identifying all open ports on a target.
* **Tip**: Use `-T4` for faster scans on reliable networks; avoid `-T5` to prevent inaccurate results.

#### Script Scan with Version Detection

```bash
nmap -sC -sV --script={name_of_script} -p- -T4 $ip
```

* **Purpose**: Runs a specific Nmap script, detects service versions, and scans all ports.
* **Use Case**: Enumerate services and vulnerabilities (e.g., `--script=http-vuln*` for web vulnerabilities).
* **Tip**: Replace `{name_of_script}` with specific scripts like `smb-vuln*` or `http-enum`.

#### ACK Scan for Firewall Analysis

```bash
nmap -Pn -sA -p- $ip
```

* **Purpose**: Performs a TCP ACK scan to determine which ports are filtered or unfiltered by firewalls.
* **Use Case**: Map firewall rules without attempting to connect to services.
* **Tip**: Use when analysing firewall configurations; results show `filtered` or `unfiltered` ports.

#### Decoy Scan with Packet Padding

```bash
nmap -Pn -sS -sV -p- --data-length 200 -D $gatewayip,$gatewayip $ip
```

* **Purpose**: Uses decoy IPs and adds random data (200 bytes) to obscure the scanner’s identity.
* **Use Case**: Evade detection by blending scan traffic with decoy IPs.
* **Tip**: Replace `$gatewayip` with valid IP addresses; ensure decoys are active to avoid suspicion.

***

### Flags for Better Results

These flags enhance scan accuracy, stealth, and output usability.

#### Scan Types

* `-sA`: **TCP ACK Scan** – Maps firewall rules by sending ACK packets; identifies filtered/unfiltered ports.
* `-sS`: **TCP SYN Scan** – Default stealth scan; sends SYN packets without completing TCP handshake.
* `-sT`: **TCP Connect Scan** – Completes TCP handshake; noisier but reliable when SYN scans are blocked.

**Tip**: Use `-sS` for stealth and speed; fallback to `-sT` if SYN scans fail due to restrictions.

#### Host & Network Discovery

* `-PE`: **ICMP Echo Ping** – Uses ICMP echo requests for host discovery (classic ping).
* `--disable-arp-ping`: Disables ARP ping for local networks, forcing other discovery methods.

**Tip**: Use `-PE` for standard ping scans; combine with `-PS` or `-PA` for firewalled networks.

#### Packet Handling & Output

* `--packet-trace`: Shows all packets sent and received for debugging scan issues.
* `--reason`: Displays why ports are marked as open, closed, or filtered.

**Tip**: Use `--packet-trace` for troubleshooting failed scans; `--reason` clarifies port states.

#### Port Scanning

* `--top-ports=10`: Scans the 10 most common ports (e.g., 80, 443, 22).
* `-p22`: Scans a specific port (e.g., SSH on port 22).
* `-F`: Scans the top 100 ports for quick results.

**Tip**: Use `-F` for fast scans; `-p-` for comprehensive scans when time permits.

#### Spoofing & Stealth Techniques

* `-D RND:5`: Generates 5 random decoy IPs to mask the scanner’s identity.
* `-S <IP>`: Spoofs the source IP address (requires root and network support).
* `-e tun0`: Sends packets through a specific interface (e.g., VPN interface tun0).
* `--source-port 53`: Uses a specific source port (e.g., 53 for DNS) to bypass firewalls.

**Tip**: Test spoofing (`-S`, `-D`) in controlled environments; ensure decoy IPs are live to avoid detection.

***

### Optimising Nmap Scans

Balancing speed, stealth, and accuracy is key to effective scanning. Faster scans may trigger intrusion detection systems (IDS), while slower scans improve stealth.

#### 🕒 Timing & Performance Tweaks

* `--host-timeout 5s`: Limits scan time per host (e.g., 5 seconds) to avoid hangs.
* `--scan-delay 5s`: Adds a delay between scan probes (e.g., 5 seconds) for stealth.
* `--initial-rtt-timeout 50ms`: Sets initial round-trip time timeout for probes.
* `--max-rtt-timeout 100ms`: Sets maximum RTT timeout to adjust for network latency.

**Tips**:

* Use `--host-timeout` for unresponsive hosts; adjust based on network reliability.
* Increase `--scan-delay` (e.g., 5s or higher) to evade IDS in sensitive environments.
* Fine-tune RTT timeouts for congested or high-latency networks.

***

### Nmap Output Formats

Save scan results for analysis, reporting, or integration with tools like Metasploit.

* `-oN <filename>`: Saves output in normal text format (.nmap).
* `-oX <filename>`: Saves output in XML format for parsing.
* `-oS <filename>`: Saves output in script-kiddie format (less common).
* `-oA <basename>`: Saves in all formats (.nmap, .xml, .gnmap) with a common basename.

**Tips**:

* Use -oA for flexibility; XML (`-oX`) is ideal for tools like Metasploit or custom scripts.
* Combine with `--append-output` to add to existing files without overwriting.

***

### Best Practices

1. **Obtain Permission**: Always secure explicit authorisation before scanning networks you don’t own.
2. **Start with Host Discovery**: Use `-sn` to identify live hosts before deep scans.
3. **Use Stealth for Sensitive Networks**: Combine `-sS`, `--scan-delay`, and `-D` for low-profile scans.
4. **Combine Flags**: Pair `-sV` and `-sC` with port scans for detailed service and vulnerability info.
5. **Optimise Timing**: Use `-T4` for reliable networks; `-T2` or lower for stealth in monitored environments.
6. **Save and Analyse Output**: Use `-oA` to store results and parse with tools like `grep`, `xsltproc`, or `nmaptocsv`.

***

### Output Analysis Tips

* **Open Ports**: Prioritise services like HTTP, SSH, or SMB for further enumeration.
* **Filtered Ports**: Indicate firewalls; use `-sA` or evasion techniques (`-f`, `-D`) to probe further.
* **Service Versions**: Use -sV to identify software versions for vulnerability research.
* **Use** `--reason`: Clarifies why ports are open, closed, or filtered.
* **Parse Outputs**: Filter `-oG` results with `grep open` or use `-oX` with tools for detailed analysis.
