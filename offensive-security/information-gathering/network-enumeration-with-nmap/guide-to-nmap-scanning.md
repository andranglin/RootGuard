# Guide to Nmap Scanning

Nmap (Network Mapper) is a powerful open-source tool for network exploration, security auditing, and reconnaissance. It allows users to discover hosts, services, operating systems, and vulnerabilities on a network. This cheat sheet organises Nmap’s key commands and flags into categories, with explanations and practical tips to help you use them effectively. Use this guide for quick reference during network scanning tasks, whether you're performing host discovery, port scanning, or advanced vulnerability assessments.

***

### Host Discovery

Host discovery identifies live hosts on a network before performing detailed scans. These flags help determine which hosts are active without necessarily scanning ports.

{% code overflow="wrap" %}
```bash
-sL    nmap 192.168.1.1-3 -sL                       # Lists targets without scanning (useful for planning)
-sn    nmap 192.168.1.1/24 -sn                      # Ping scan, disables port scanning (quick host check)
-Pn    nmap 192.168.1.1-5 -Pn                       # Skips host discovery, assumes hosts are up (use for firewalled networks)
-PS    nmap 192.168.1.1-5 -PS22-25,80               # TCP SYN discovery on specified ports (e.g., 22, 23, 24, 25, 80)
-PA    nmap 192.168.1.1-5 -PA22-25,80               # TCP ACK discovery (bypasses some firewalls)
-PU    nmap 192.168.1.1-5 -PU53                     # UDP discovery on port 53 (common for DNS servers)
-PR    nmap 192.168.1.0/24 -PR                      # ARP discovery for local networks (fast and reliable)
-n     nmap 192.168.1.1 -n                          # Disables DNS resolution (speeds up scans)
```
{% endcode %}

**Tips**:

* Use `-sn` for quick reconnaissance to identify live hosts.
* `-Pn` is ideal when hosts block ping requests (e.g., firewalled environments).
* Combine `-PR` with local network scans for faster results, as ARP is more reliable than ICMP.

***

### Target Specification

Define which hosts or networks to scan. Nmap supports various input formats for flexibility.

{% code overflow="wrap" %}
```bash
nmap 192.168.1.1                         # Scans a single IP
nmap 192.168.1.1 192.168.2.1             # Scans multiple specific IPs
nmap 192.168.1.1-254                     # Scans a range of IPs
nmap scanme.nmap.org                     # Scans a domain (resolves to IP)
nmap 192.168.1.0/24                      # Scans a subnet using CIDR notation
-iL    nmap -iL targets.txt              # Scans IPs listed in a file
-iR    nmap -iR 100                      # Scans 100 random hosts (useful for research)
--exclude nmap --exclude 192.168.1.1     # Excludes specific hosts from scan
```
{% endcode %}

**Tips**:

* Use `-iL` for large-scale scans with a pre-prepared list of targets.
* `--exclude` is useful to avoid sensitive systems (e.g., critical servers).
* CIDR notation (`/24`) is efficient for scanning entire subnets.

***

### Scan Techniques

Choose the type of scan based on your goals, network conditions, and stealth requirements.

{% code overflow="wrap" %}
```bash
-sS    nmap 192.168.1.1 -sS           # TCP SYN scan (default, stealthy, fast)
-sT    nmap 192.168.1.1 -sT           # TCP connect scan (reliable, but noisier)
-sU    nmap 192.168.1.1 -sU           # UDP scan (slower, for UDP services like DNS)
-sA    nmap 192.168.1.1 -sA           # TCP ACK scan (maps firewall rules)
-sW    nmap 192.168.1.1 -sW           # TCP Window scan (detects filtered ports)
-sM    nmap 192.168.1.1 -sM           # TCP Maimon scan (rare, for specific firewalls)
```
{% endcode %}

**Tips**:

* `-sS` is the go-to for most scans due to its speed and stealth (doesn’t complete TCP handshake).
* Use `-sU` for services like DNS, SNMP, or DHCP, but expect slower scans.
* Combine `-sA` or `-sW` to understand firewall behaviour.

***

### Port Specification

Control which ports to scan, from specific ports to all 65,535 ports.

{% code overflow="wrap" %}
```bash
-p     nmap 192.168.1.1 -p 21                     # Scans specific port (e.g., FTP)
-p     nmap 192.168.1.1 -p 21-100                 # Scans a port range
-p     nmap 192.168.1.1 -p U:53,T:21-25,80        # Scans TCP and UDP ports (e.g., UDP 53, TCP 21-25, 80)
-p-    nmap 192.168.1.1 -p-                       # Scans all 65,535 ports (comprehensive but slow)
-p     nmap 192.168.1.1 -p http,https             # Scans by service name (e.g., ports 80, 443)
-F     nmap 192.168.1.1 -F                        # Fast scan of 100 common ports
--top-ports nmap 192.168.1.1 --top-ports 200     # Scans top 2000 most common ports
```
{% endcode %}

**Tips**:

* Use `-F` for quick scans when time is limited.
* `-p-` is thorough but time-consuming; use it for critical systems.
* Specify service names (`http,https`) for readability and flexibility.

***

### Timing and Performance

Adjust scan speed and behaviour to balance accuracy, stealth, and performance.

{% code overflow="wrap" %}
```bash
-T0    nmap -T0 <target>              # Paranoid (very slow, for IDS evasion)
-T1    nmap -T1 <target>              # Sneaky (slow, stealthy)
-T2    nmap -T2 <target>              # Polite (conserves bandwidth)
-T3    nmap -T3 <target>              # Normal (default, balanced)
-T4    nmap -T4 <target>              # Aggressive (faster, for reliable networks)
-T5    nmap -T5 <target>              # Insane (fastest, may miss results)
--host-timeout <time>                 # Max time per host (e.g., 30m, 1h)
--min-rtt-timeout <time>              # Min probe timeout (e.g., 100ms)
--max-rtt-timeout <time>              # Max probe timeout (e.g., 500ms)
--min-hostgroup <size>                # Min hosts scanned in parallel
--max-hostgroup <size>                # Max hosts scanned in parallel
--min-parallelism <num>               # Min probes sent in parallel
--max-parallelism <num>               # Max probes sent in parallel
--scan-delay <time>                   # Delay between probes (e.g., 1s)
--max-scan-delay <time>               # Max delay between probes
--max-retries <tries>                 # Max retransmissions per port
--min-rate <number>                   # Min packets per second
--max-rate <number>                   # Max packets per second
```
{% endcode %}



**Tips**:

* Use `-T4` for LANs or trusted networks; `-T5` risks inaccurate results.
* `--host-timeout` prevents scans from hanging on unresponsive hosts.
* Fine-tune `--min-rate` and `--max-rate` for congested networks to avoid packet loss.

***

### Service and Version Detection

Identify services and their versions running on open ports.

{% code overflow="wrap" %}
```bash
-sV                                # Detects service versions (e.g., Apache 2.4.7)
--version-intensity <0-9>          # Sets detection intensity (0=light, 9=aggressive)
--version-light                    # Fast version scan (intensity 2)
--version-all                      # Thorough version scan (intensity 9)
-A                                 # Enables OS detection, version detection, scripts, and traceroute
```
{% endcode %}

**Tips**:

* `-sV` is essential for identifying vulnerable software versions.
* Use `--version-light` for speed, `--version-all` for thoroughness.
* `-A` is a comprehensive option for detailed reconnaissance.

***

### OS Detection

Identify the operating system and its version on target hosts.

```bash
-O                                 # Enables OS detection
--osscan-limit                     # Skips OS scan if conditions aren’t ideal
--osscan-guess                     # Makes aggressive OS guesses
--max-os-tries <x>                 # Sets max OS detection attempts
```

**Tips**:

* Combine `-O` with `-sV` for a complete system profile.
* `--osscan-guess` is useful when OS detection is uncertain but may produce less accurate results.

***

### Firewall / IDS Evasion and Spoofing

Bypass firewalls and intrusion detection systems (IDS) with these techniques.

```bash
-f                                # Fragments packets to evade detection
--mtu <val>                       # Sets custom MTU for fragmentation
-D                                # Uses decoy IPs to mask scan origin
-S                                # Spoofs source IP address
-g                                # Sets source port (e.g., -g 53 for DNS)
--proxies                         # Routes scan through proxies
--data-length <bytes>             # Appends random data to packets
```

**Tips**:

* Use `-f` or `--mtu` to fragment packets and bypass simple firewalls.
* `-D` (decoy scan) floods the target with fake scans to obscure your IP.
* Test spoofing (`-S, -g`) in controlled environments, as it may require specific permissions.

***

### NSE (Nmap Scripting Engine) Scripts

Leverage Nmap’s scripting engine for advanced tasks like vulnerability scanning and enumeration.

{% code overflow="wrap" %}
```bash
-sC                                # Runs default scripts (safe and common)
--script default                   # Same as -sC
--script=banner                    # Runs specific script (e.g., grabs service banners)
--script=http*                     # Runs all scripts matching pattern (e.g., HTTP-related)
--script=http,banner               # Runs multiple specific scripts
--script "not intrusive"           # Excludes intrusive scripts for safety
--script-args                      # Passes arguments to scripts (e.g., credentials)
```
{% endcode %}

**Example NSE Scripts**:

{% code overflow="wrap" %}
```bash
nmap -Pn --script=http-sitemap-generator scanme.nmap.org                  # Maps website structure
nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000     # Grabs banners and titles
nmap -Pn --script=dns-brute domain.com                                    # Brute-forces DNS subdomains
nmap -n -Pn -vv -O -sV --script smb-* 192.168.1.1                         # Enumerates SMB services
nmap --script whois* domain.com                                            # Performs WHOIS lookups
nmap -p80 --script http-unsafe-output-escaping scanme.nmap.org             # Checks for XSS vulnerabilities
nmap -p80 --script http-sql-injection scanme.nmap.org                      # Tests for SQL injection
```
{% endcode %}

**Web App-Specific NSE Scripts**:

{% code overflow="wrap" %}
```bash
nmap -p80 --script http-methods --script-args http-methods.test-all http://target
nmap -p80 --script http-headers http://target
nmap -p80 --script http-auth,http-auth-finder,http-auth-guess http://target
nmap -p80 --script http-enum http://target
nmap -p80 --script http-config-backup http://target
nmap -p80 --script http-userdir-enum http://target
nmap -p80 --script http-vhosts,http-iis-short-name-brute http://target
nmap -p80 --script http-dombased-xss,http-xssed,http-stored-xss,http-csrf 192.168.1.1
```
{% endcode %}

**Advanced NSE Script Usage**:

{% code overflow="wrap" %}
```bash
nmap --script-args "userdb=users.txt,passdb=passlist.txt" -p21 ftp.target.com --script ftp-brute
nmap -p445 --script smb-enum-users,smb-enum-shares --script-args smbuser=admin,smbpass=password 192.168.1.100
nmap -p80 --script http-form-brute --script-args http-form-brute.hostname=target.com,http-form-brute.path=/login,http-form-brute.uservar=username,http-form-brute.passvar=password,http-form-brute.failmsg="invalid login" 192.168.1.1
```
{% endcode %}

**Vulnerability Scanning Scripts**:

```bash
nmap --script vuln 192.168.1.1
nmap -sV --script vulners 192.168.1.1
nmap -p80 --script http-vuln-cve2015-1635 192.168.1.1
nmap -p80 --script http-vuln-cve2017-5638 192.168.1.1
nmap -p80 --script http-vuln-cve2017-1001000 192.168.1.1
```

**Tips**:

* Use `-sC` for safe, default scripts during initial scans.
* `--script vuln` is great for identifying known vulnerabilities but requires `-sV` for best results.
* Be cautious with intrusive scripts (e.g., brute-forcing) to avoid disrupting services.

***

### Output Options

Save scan results in various formats for analysis or reporting.

```bash
-oN <file>                           # Saves in normal text format
-oX <file>                           # Saves in XML format (ideal for parsing)
-oG <file>                           # Saves in grepable format
-oA <prefix>                         # Saves in all formats (normal, XML, grepable)
--append-output                      # Appends to existing files
-oG -                                # Outputs to screen (also -oN -, -oX -)
```

**Tips**:

* Use `-oA` to save in multiple formats for flexibility.
* XML output (`-oX`) is ideal for integration with tools like Metasploit or custom scripts.
* Use `--append-output` to avoid overwriting previous scans.

***

### Scan Output Analysis & Tips

Maximise the value of your scan results with these strategies:

* **Focus on Open Ports**: Prioritise services like HTTP, SMB, or FTP for further enumeration.
* **Understand Port States**:
  * _Open_: Service is running and accepting connections.
  * _Closed_: Port responds, but no service is running.
  * _Filtered_: Likely firewalled, no response received.
* **Use `-sV` and `-A`**: Combine for detailed service and OS information.
* **Enable `--reason`**: Shows why ports are marked open, closed, or filtered.
* **Save Everything:** Use -oA to store results for later analysis with tools like `grep, xsltproc`, or `nmaptocsv`.
* **Filter Results:** Run g`rep open <file>` on grepable output to quickly identify active services.

***

### Best Practices

1. **Start Simple**: Use `-sn` or `-F` for quick scans before diving into detailed scans.
2. **Stay Legal**: Always obtain permission before scanning networks you don’t own.
3. **Combine Flags**: Use `-sS -sV -O` for a balanced scan with port, service, and OS detection.
4. **Optimise Principled**: Avoid intrusive scripts unless you have explicit permission.
5. **Optimise Performance**: Adjust timing (`-T`) and parallelism based on network conditions.
6. **Review Output**: Regularly analyse results to identify next steps (e.g., manual testing of vulnerabilities).

For additional cheatsheets and Nmap guides, visit [StationX Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)
