# Nmap Network Scanning Cheatsheet

### Overview

Nmap (Network Mapper) is an open-source tool for network discovery, port scanning, service enumeration, and security auditing. It identifies hosts, open ports, running services, operating systems, and vulnerabilities across networks.

***

### Core Syntax

```bash
nmap [scan_type] [options] <target>
```

***

### Learning Workflow

**Phase 1: Discovery** — Host detection and basic port scanning\
**Phase 2: Enumeration** — Service versions and OS detection\
**Phase 3: Scripting** — NSE scripts for vulnerability detection\
**Phase 4: Evasion** — Firewall bypass and stealth techniques\
**Phase 5: Advanced** — Performance tuning, output formats, automation

***

### Target Specification

#### Single Targets

```bash
# Single IP
nmap 192.168.1.1

# Hostname
nmap target.example.com

# Multiple IPs
nmap 192.168.1.1 192.168.1.5 192.168.1.10
```

#### IP Ranges

```bash
# CIDR notation
nmap 192.168.1.0/24

# Range
nmap 192.168.1.1-254

# Octet range
nmap 192.168.1-5.1-254

# Wildcard
nmap 192.168.1.*
```

#### From Files

```bash
# Read targets from file (one per line)
nmap -iL targets.txt

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.5

# Exclude from file
nmap 192.168.1.0/24 --excludefile exclude.txt
```

#### Random Targets

```bash
# Scan random hosts (research/statistics)
nmap -iR 100
```

***

### Phase 1: Host Discovery

#### Discovery Techniques

| Option | Technique        | Description                       |
| ------ | ---------------- | --------------------------------- |
| `-sn`  | Ping scan        | Host discovery only, no port scan |
| `-Pn`  | No ping          | Skip discovery, assume host is up |
| `-PS`  | TCP SYN ping     | SYN to specified ports            |
| `-PA`  | TCP ACK ping     | ACK to specified ports            |
| `-PU`  | UDP ping         | UDP to specified ports            |
| `-PE`  | ICMP echo        | Standard ping                     |
| `-PP`  | ICMP timestamp   | Timestamp request                 |
| `-PM`  | ICMP netmask     | Address mask request              |
| `-PO`  | IP protocol ping | Protocol-specific probes          |
| `-PR`  | ARP ping         | Local network only                |

#### Host Discovery Commands

```bash
# Ping sweep (no port scan)
nmap -sn 192.168.1.0/24

# Skip ping (scan even if host appears down)
nmap -Pn 192.168.1.1

# TCP SYN ping on specific ports
nmap -PS22,80,443 192.168.1.0/24

# TCP ACK ping
nmap -PA80,443 192.168.1.0/24

# UDP ping
nmap -PU53,161 192.168.1.0/24

# ICMP echo request
nmap -PE 192.168.1.0/24

# ARP discovery (local network)
nmap -PR 192.168.1.0/24

# Combined discovery
nmap -PE -PS22,80,443 -PA80,443 -PU53 192.168.1.0/24
```

#### List Scan (No Packets Sent)

```bash
# DNS resolution only, no scanning
nmap -sL 192.168.1.0/24

# Disable DNS resolution
nmap -n 192.168.1.0/24

# Force DNS resolution
nmap -R 192.168.1.0/24

# Specify DNS servers
nmap --dns-servers 8.8.8.8,8.8.4.4 192.168.1.0/24
```

***

### Phase 1: Port Scanning

#### Scan Types

<table><thead><tr><th width="161">Option</th><th width="164">Name</th><th>Description</th></tr></thead><tbody><tr><td><code>-sS</code></td><td>SYN scan</td><td>Stealth scan, half-open (default w/root)</td></tr><tr><td><code>-sT</code></td><td>Connect scan</td><td>Full TCP connection (default w/o root)</td></tr><tr><td><code>-sU</code></td><td>UDP scan</td><td>UDP port scan</td></tr><tr><td><code>-sA</code></td><td>ACK scan</td><td>Map firewall rules</td></tr><tr><td><code>-sW</code></td><td>Window scan</td><td>ACK variant, detects open via window size</td></tr><tr><td><code>-sM</code></td><td>Maimon scan</td><td>FIN/ACK, works on some BSD systems</td></tr><tr><td><code>-sN</code></td><td>Null scan</td><td>No flags set</td></tr><tr><td><code>-sF</code></td><td>FIN scan</td><td>FIN flag only</td></tr><tr><td><code>-sX</code></td><td>Xmas scan</td><td>FIN, PSH, URG flags</td></tr><tr><td><code>-sI</code></td><td>Idle scan</td><td>Zombie host scan (very stealthy)</td></tr><tr><td><code>-sO</code></td><td>Protocol scan</td><td>IP protocol scan</td></tr><tr><td><code>-b</code></td><td>FTP bounce</td><td>FTP bounce scan</td></tr></tbody></table>

#### Basic Port Scans

```bash
# SYN scan (stealth, requires root)
sudo nmap -sS 192.168.1.1

# TCP connect scan (no root required)
nmap -sT 192.168.1.1

# UDP scan (slow, requires root)
sudo nmap -sU 192.168.1.1

# Combined TCP and UDP
sudo nmap -sS -sU 192.168.1.1

# ACK scan (firewall mapping)
sudo nmap -sA 192.168.1.1
```

#### Port Specification

```bash
# Specific ports
nmap -p 22,80,443 192.168.1.1

# Port range
nmap -p 1-1000 192.168.1.1

# All 65535 ports
nmap -p- 192.168.1.1

# Top ports
nmap --top-ports 100 192.168.1.1

# Service name
nmap -p http,https,ssh 192.168.1.1

# UDP specific ports
nmap -sU -p U:53,161 192.168.1.1

# TCP and UDP specific
nmap -p T:80,443,U:53,161 192.168.1.1

# Exclude ports
nmap -p 1-1000 --exclude-ports 22,80 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1
```

#### Port States

<table><thead><tr><th width="299">State</th><th>Meaning</th></tr></thead><tbody><tr><td><code>open</code></td><td>Service accepting connections</td></tr><tr><td><code>closed</code></td><td>Accessible but no service listening</td></tr><tr><td><code>filtered</code></td><td>Firewall blocking, can't determine state</td></tr><tr><td><code>unfiltered</code></td><td>Accessible but can't determine open/closed</td></tr><tr><td>`open</td><td>filtered`</td></tr><tr><td>`closed</td><td>filtered`</td></tr></tbody></table>

***

### Phase 2: Service & Version Detection

#### Version Detection

```bash
# Service version detection
nmap -sV 192.168.1.1

# Version intensity (0-9, default 7)
nmap -sV --version-intensity 9 192.168.1.1

# Light version detection (intensity 2)
nmap -sV --version-light 192.168.1.1

# Try all probes (intensity 9)
nmap -sV --version-all 192.168.1.1

# Show version scan activity
nmap -sV --version-trace 192.168.1.1
```

#### OS Detection

```bash
# OS detection
nmap -O 192.168.1.1

# Aggressive OS detection
nmap -O --osscan-guess 192.168.1.1

# Limit OS detection to promising targets
nmap -O --osscan-limit 192.168.1.0/24

# OS detection requires at least one open and one closed port
nmap -O --max-os-tries 2 192.168.1.1
```

#### Aggressive Scan

```bash
# Enable OS detection, version detection, script scanning, traceroute
nmap -A 192.168.1.1

# Equivalent to:
nmap -O -sV -sC --traceroute 192.168.1.1
```

#### Combined Enumeration

```bash
# Full enumeration scan
nmap -sS -sV -O -p- 192.168.1.1

# Quick comprehensive scan
nmap -sS -sV -O --top-ports 1000 192.168.1.1

# Version + default scripts
nmap -sV -sC 192.168.1.1
```

***

### Phase 3: Nmap Scripting Engine (NSE)

#### Script Categories

| Category    | Description                          |
| ----------- | ------------------------------------ |
| `auth`      | Authentication and credential checks |
| `broadcast` | Network broadcast discovery          |
| `brute`     | Brute force attacks                  |
| `default`   | Safe, useful scripts (-sC)           |
| `discovery` | Service and host discovery           |
| `dos`       | Denial of service (use carefully)    |
| `exploit`   | Active exploitation                  |
| `external`  | Third-party service queries          |
| `fuzzer`    | Fuzz testing                         |
| `intrusive` | May crash services                   |
| `malware`   | Malware detection                    |
| `safe`      | Won't crash services                 |
| `version`   | Version detection enhancement        |
| `vuln`      | Vulnerability detection              |

#### Running Scripts

```bash
# Default scripts
nmap -sC 192.168.1.1
nmap --script=default 192.168.1.1

# Single script
nmap --script=http-title 192.168.1.1

# Multiple scripts
nmap --script=http-title,http-headers 192.168.1.1

# Script category
nmap --script=vuln 192.168.1.1

# Multiple categories
nmap --script="vuln,safe" 192.168.1.1

# Wildcard
nmap --script="http-*" 192.168.1.1

# Exclude scripts
nmap --script="vuln and not dos" 192.168.1.1

# Boolean combinations
nmap --script="(http-* or ssl-*) and not intrusive" 192.168.1.1
```

#### Script Arguments

```bash
# Pass arguments to scripts
nmap --script=http-brute --script-args http-brute.path=/admin 192.168.1.1

# Multiple arguments
nmap --script=http-brute --script-args="userdb=users.txt,passdb=pass.txt" 192.168.1.1

# Arguments from file
nmap --script-args-file=args.txt 192.168.1.1
```

#### Common Reconnaissance Scripts

```bash
# HTTP enumeration
nmap --script=http-enum 192.168.1.1
nmap --script=http-title 192.168.1.1
nmap --script=http-headers 192.168.1.1
nmap --script=http-methods 192.168.1.1
nmap --script=http-robots.txt 192.168.1.1
nmap --script=http-sitemap-generator 192.168.1.1

# SSL/TLS analysis
nmap --script=ssl-enum-ciphers -p 443 192.168.1.1
nmap --script=ssl-cert -p 443 192.168.1.1
nmap --script=ssl-heartbleed -p 443 192.168.1.1

# SMB enumeration
nmap --script=smb-enum-shares 192.168.1.1
nmap --script=smb-enum-users 192.168.1.1
nmap --script=smb-os-discovery 192.168.1.1
nmap --script=smb-protocols 192.168.1.1

# DNS enumeration
nmap --script=dns-brute target.com
nmap --script=dns-zone-transfer -p 53 ns.target.com

# SNMP enumeration
nmap --script=snmp-info -sU -p 161 192.168.1.1
nmap --script=snmp-brute -sU -p 161 192.168.1.1
```

#### Vulnerability Detection Scripts

```bash
# General vulnerability scan
nmap --script=vuln 192.168.1.1

# Specific vulnerabilities
nmap --script=smb-vuln-ms17-010 192.168.1.1
nmap --script=smb-vuln-ms08-067 192.168.1.1
nmap --script=http-vuln-cve2017-5638 192.168.1.1
nmap --script=ssl-poodle -p 443 192.168.1.1
nmap --script=ssl-dh-params -p 443 192.168.1.1

# All SMB vulnerabilities
nmap --script="smb-vuln-*" 192.168.1.1

# Safe vulnerability checks
nmap --script="vuln and safe" 192.168.1.1
```

#### Brute Force Scripts

```bash
# SSH brute force
nmap --script=ssh-brute -p 22 192.168.1.1

# FTP brute force
nmap --script=ftp-brute -p 21 192.168.1.1

# HTTP basic auth brute force
nmap --script=http-brute -p 80 192.168.1.1

# MySQL brute force
nmap --script=mysql-brute -p 3306 192.168.1.1

# SMB brute force
nmap --script=smb-brute 192.168.1.1

# With custom wordlists
nmap --script=ssh-brute --script-args="userdb=users.txt,passdb=pass.txt" -p 22 192.168.1.1
```

#### Script Information

```bash
# List all scripts
ls /usr/share/nmap/scripts/

# Script help
nmap --script-help=http-enum

# Update script database
nmap --script-updatedb

# Show script trace
nmap --script=http-enum --script-trace 192.168.1.1
```

***

### Phase 4: Evasion & Stealth

#### Timing Templates

<table><thead><tr><th>Option</th><th width="195">Name</th><th>Description</th></tr></thead><tbody><tr><td><code>-T0</code></td><td>Paranoid</td><td>Very slow, IDS evasion</td></tr><tr><td><code>-T1</code></td><td>Sneaky</td><td>Slow, IDS evasion</td></tr><tr><td><code>-T2</code></td><td>Polite</td><td>Slowed down, less bandwidth</td></tr><tr><td><code>-T3</code></td><td>Normal</td><td>Default</td></tr><tr><td><code>-T4</code></td><td>Aggressive</td><td>Fast, reliable network</td></tr><tr><td><code>-T5</code></td><td>Insane</td><td>Very fast, may miss ports</td></tr></tbody></table>

```bash
# Slow scan for IDS evasion
nmap -T1 192.168.1.1

# Aggressive scan for fast results
nmap -T4 192.168.1.1
```

#### Firewall/IDS Evasion

```bash
# Fragment packets
nmap -f 192.168.1.1

# Specify MTU (must be multiple of 8)
nmap --mtu 24 192.168.1.1

# Use decoys
nmap -D decoy1,decoy2,ME,decoy3 192.168.1.1
nmap -D RND:10 192.168.1.1  # 10 random decoys

# Spoof source IP (requires specific conditions)
nmap -S 192.168.1.100 192.168.1.1

# Spoof source port
nmap --source-port 53 192.168.1.1
nmap -g 53 192.168.1.1

# Append random data to packets
nmap --data-length 50 192.168.1.1

# Randomize target order
nmap --randomize-hosts 192.168.1.0/24

# Spoof MAC address
nmap --spoof-mac 0 192.168.1.1           # Random MAC
nmap --spoof-mac Dell 192.168.1.1        # Vendor MAC
nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1  # Specific MAC

# Bad checksum (test firewall)
nmap --badsum 192.168.1.1
```

#### Idle/Zombie Scan

```bash
# Find zombie candidate
nmap --script=ipidseq 192.168.1.0/24

# Perform idle scan
nmap -sI zombie_host:port target_host
nmap -sI 192.168.1.5:80 192.168.1.1
```

#### Timing Controls

```bash
# Host timeout
nmap --host-timeout 30m 192.168.1.0/24

# Scan delay (between probes)
nmap --scan-delay 1s 192.168.1.1
nmap --max-scan-delay 5s 192.168.1.1

# Rate limiting
nmap --min-rate 100 192.168.1.1
nmap --max-rate 50 192.168.1.1

# Parallel host scanning
nmap --min-hostgroup 50 192.168.1.0/24
nmap --max-hostgroup 100 192.168.1.0/24

# Parallel probes
nmap --min-parallelism 10 192.168.1.1
nmap --max-parallelism 50 192.168.1.1

# RTT timeouts
nmap --initial-rtt-timeout 500ms 192.168.1.1
nmap --max-rtt-timeout 3s 192.168.1.1

# Retry attempts
nmap --max-retries 3 192.168.1.1
```

***

### Phase 5: Output & Automation

#### Output Formats

```bash
# Normal output
nmap -oN scan.txt 192.168.1.1

# XML output
nmap -oX scan.xml 192.168.1.1

# Grepable output
nmap -oG scan.gnmap 192.168.1.1

# All formats
nmap -oA scan_results 192.168.1.1

# Script kiddie format (for fun)
nmap -oS scan.txt 192.168.1.1
```

#### Output Options

```bash
# Verbose output
nmap -v 192.168.1.1
nmap -vv 192.168.1.1   # More verbose
nmap -vvv 192.168.1.1  # Even more

# Debug output
nmap -d 192.168.1.1
nmap -dd 192.168.1.1

# Show only open ports
nmap --open 192.168.1.1

# Show reason for port state
nmap --reason 192.168.1.1

# Show all packets sent/received
nmap --packet-trace 192.168.1.1

# Append to output file
nmap --append-output -oN scan.txt 192.168.1.1

# Resume aborted scan
nmap --resume scan.gnmap
```

#### Performance Tuning

```bash
# Fast comprehensive scan
nmap -T4 -A -p- 192.168.1.1

# Quick network sweep
nmap -sn -T4 192.168.1.0/24

# Fast port discovery
nmap -T4 --top-ports 1000 192.168.1.0/24

# Optimize for slow/unreliable network
nmap -T2 --max-retries 5 --host-timeout 60m 192.168.1.0/24

# High-speed scan (fast network)
nmap -T4 --min-rate 1000 --max-retries 1 192.168.1.0/24
```

#### IPv6 Scanning

```bash
# IPv6 scan
nmap -6 fe80::1

# IPv6 ping sweep
nmap -6 -sn fe80::1-ff
```

***

### Common Scan Profiles

#### Quick Network Discovery

```bash
# Fast ping sweep
nmap -sn -T4 192.168.1.0/24

# Quick port scan
nmap -T4 -F 192.168.1.0/24

# List live hosts with open ports
nmap -sn 192.168.1.0/24 -oG - | grep "Up" | cut -d" " -f2
```

#### Standard Vulnerability Assessment

```bash
# Comprehensive port scan with versions
sudo nmap -sS -sV -O -p- -T4 192.168.1.1

# With vulnerability scripts
sudo nmap -sS -sV --script=vuln -T4 192.168.1.1

# Full assessment
sudo nmap -sS -sV -O -A --script="default,vuln" -p- -T4 -oA full_scan 192.168.1.1
```

#### Stealth Scan

```bash
# IDS evasion scan
sudo nmap -sS -T1 -f --data-length 50 --source-port 53 192.168.1.1

# With decoys
sudo nmap -sS -T2 -D RND:5,ME --randomize-hosts 192.168.1.0/24
```

#### Web Server Enumeration

```bash
# HTTP/HTTPS enumeration
nmap -sV -p 80,443,8080,8443 --script="http-*" 192.168.1.1

# Comprehensive web scan
nmap -sV -p 80,443 --script="http-enum,http-vuln-*,ssl-*" 192.168.1.1
```

#### SMB/Windows Enumeration

```bash
# SMB enumeration
nmap -p 139,445 --script="smb-*" 192.168.1.1

# Windows comprehensive
nmap -p 135,139,445,3389 --script="smb-*,rdp-*" -sV 192.168.1.1
```

#### Database Enumeration

```bash
# Common database ports
nmap -sV -p 1433,1521,3306,5432,27017 192.168.1.1

# With scripts
nmap -sV -p 1433,1521,3306,5432 --script="mysql-*,ms-sql-*,oracle-*,pgsql-*" 192.168.1.1
```

***

### Investigation Workflows

#### External Reconnaissance

```bash
# Step 1: DNS reconnaissance
nmap --script=dns-brute target.com
nmap --script=dns-zone-transfer -p 53 ns.target.com

# Step 2: Identify live hosts
nmap -sn -PS22,80,443 -PA80,443 -T4 target.com/24

# Step 3: Quick port scan
nmap -sS -T4 --top-ports 1000 -oA external_quick target.com

# Step 4: Full port scan on interesting hosts
nmap -sS -sV -p- -T4 -oA external_full target.com

# Step 5: Vulnerability assessment
nmap -sV --script=vuln -oA external_vuln target.com
```

#### Internal Network Assessment

```bash
# Step 1: Network discovery
nmap -sn -PR 192.168.1.0/24 -oA discovery

# Step 2: Quick port sweep
nmap -sS -T4 -F 192.168.1.0/24 -oA quick_sweep

# Step 3: Identify critical services
nmap -sS -sV -p 22,23,25,53,80,110,139,143,443,445,3389 192.168.1.0/24 -oA services

# Step 4: Detailed scan of high-value targets
nmap -sS -sV -O -A -p- -T4 192.168.1.10 -oA detailed_server

# Step 5: Vulnerability scan
nmap -sV --script="vuln and safe" 192.168.1.0/24 -oA vulns
```

#### Incident Response - Lateral Movement Detection

```bash
# Identify hosts with SMB open
nmap -sS -p 445 192.168.1.0/24 --open -oG smb_hosts.gnmap

# Check for RDP
nmap -sS -p 3389 192.168.1.0/24 --open -oG rdp_hosts.gnmap

# Check for WinRM
nmap -sS -p 5985,5986 192.168.1.0/24 --open -oG winrm_hosts.gnmap

# PSExec ports
nmap -sS -p 135,139,445 192.168.1.0/24 --open -oG psexec_hosts.gnmap

# SSH
nmap -sS -p 22 192.168.1.0/24 --open -oG ssh_hosts.gnmap
```

#### Incident Response - Service Identification

```bash
# Quickly identify what's running
nmap -sS -sV --version-intensity 5 -T4 --top-ports 100 192.168.1.50

# Check for suspicious ports
nmap -sS -p 4444,5555,6666,7777,8888,9999,31337 192.168.1.0/24 --open

# Full port scan for compromised host
nmap -sS -sV -O -p- -T4 192.168.1.50 -oA compromised_host
```

#### Firewall Rule Mapping

```bash
# ACK scan to map filtered ports
sudo nmap -sA -T4 192.168.1.1

# Compare with SYN scan
sudo nmap -sS -T4 192.168.1.1

# Window scan for more detail
sudo nmap -sW -T4 192.168.1.1

# Use common source ports
sudo nmap -sS -g 53 -T4 192.168.1.1
sudo nmap -sS -g 80 -T4 192.168.1.1
```

***

### Service-Specific Scans

#### SSH

```bash
nmap -sV -p 22 --script="ssh-*" 192.168.1.1
nmap -p 22 --script=ssh-auth-methods 192.168.1.1
nmap -p 22 --script=ssh-hostkey 192.168.1.1
```

#### FTP

```bash
nmap -sV -p 21 --script="ftp-*" 192.168.1.1
nmap -p 21 --script=ftp-anon 192.168.1.1
```

#### SMTP

```bash
nmap -sV -p 25,465,587 --script="smtp-*" 192.168.1.1
nmap -p 25 --script=smtp-enum-users 192.168.1.1
nmap -p 25 --script=smtp-open-relay 192.168.1.1
```

#### DNS

{% code overflow="wrap" %}
```bash
nmap -sU -sV -p 53 --script="dns-*" 192.168.1.1
nmap -p 53 --script=dns-zone-transfer --script-args dns-zone-transfer.domain=target.com 192.168.1.1
```
{% endcode %}

#### LDAP

```bash
nmap -sV -p 389,636 --script="ldap-*" 192.168.1.1
nmap -p 389 --script=ldap-rootdse 192.168.1.1
```

#### SNMP

```bash
nmap -sU -sV -p 161 --script="snmp-*" 192.168.1.1
nmap -sU -p 161 --script=snmp-brute 192.168.1.1
```

#### RDP

```bash
nmap -sV -p 3389 --script="rdp-*" 192.168.1.1
nmap -p 3389 --script=rdp-ntlm-info 192.168.1.1
nmap -p 3389 --script=rdp-enum-encryption 192.168.1.1
```

#### VNC

```bash
nmap -sV -p 5900-5910 --script="vnc-*" 192.168.1.1
nmap -p 5900 --script=vnc-info 192.168.1.1
```

#### MySQL

{% code overflow="wrap" %}
```bash
nmap -sV -p 3306 --script="mysql-*" 192.168.1.1
nmap -p 3306 --script=mysql-info 192.168.1.1
nmap -p 3306 --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''" 192.168.1.1
```
{% endcode %}

#### MSSQL

```bash
nmap -sV -p 1433 --script="ms-sql-*" 192.168.1.1
nmap -p 1433 --script=ms-sql-info 192.168.1.1
nmap -sU -p 1434 --script=ms-sql-info 192.168.1.1  # Browser service
```

#### Oracle

```bash
nmap -sV -p 1521 --script="oracle-*" 192.168.1.1
nmap -p 1521 --script=oracle-sid-brute 192.168.1.1
```

***

### Parsing Nmap Output

#### Grep Commands

```bash
# Extract live hosts from grepable output
grep "Up" scan.gnmap | cut -d" " -f2

# Extract open ports
grep "open" scan.gnmap

# Extract hosts with specific port open
grep "80/open" scan.gnmap | cut -d" " -f2

# Count open ports per host
grep -oP '\d+/open' scan.gnmap | wc -l
```

#### XML Processing

```bash
# Convert XML to HTML report
xsltproc scan.xml -o report.html

# Parse with xmllint
xmllint --xpath "//port[@state='open']" scan.xml

# Use nmap's built-in stylesheet
xsltproc /usr/share/nmap/nmap.xsl scan.xml -o report.html
```

#### Tools for Output Parsing

```bash
# nmaptocsv
python nmaptocsv.py -i scan.xml -o scan.csv

# nmap-parse-output
nmap-parse-output scan.xml hosts

# grep-friendly one-liner
nmap -oG - 192.168.1.1 | grep open
```

***

### Quick Reference Card

| Task              | Command                             |
| ----------------- | ----------------------------------- |
| Ping sweep        | `nmap -sn 192.168.1.0/24`           |
| Quick scan        | `nmap -T4 -F 192.168.1.1`           |
| Full port scan    | `nmap -p- 192.168.1.1`              |
| SYN scan          | `sudo nmap -sS 192.168.1.1`         |
| UDP scan          | `sudo nmap -sU 192.168.1.1`         |
| Version detection | `nmap -sV 192.168.1.1`              |
| OS detection      | `sudo nmap -O 192.168.1.1`          |
| Aggressive scan   | `nmap -A 192.168.1.1`               |
| Default scripts   | `nmap -sC 192.168.1.1`              |
| Vuln scan         | `nmap --script=vuln 192.168.1.1`    |
| Skip ping         | `nmap -Pn 192.168.1.1`              |
| Top 1000 ports    | `nmap --top-ports 1000 192.168.1.1` |
| Save all formats  | `nmap -oA results 192.168.1.1`      |
| Show open only    | `nmap --open 192.168.1.1`           |
| Stealth scan      | `sudo nmap -sS -T1 -f 192.168.1.1`  |
| Fast aggressive   | `nmap -T4 -A -v 192.168.1.1`        |

***

### Common Issues & Fixes

| Issue                        | Solution                                |
| ---------------------------- | --------------------------------------- |
| "requires root privileges"   | Use `sudo` for SYN, UDP, OS scans       |
| Host appears down            | Use `-Pn` to skip ping                  |
| Scan too slow                | Increase timing `-T4` or `-T5`          |
| Missing services             | Increase `--version-intensity`          |
| Firewall blocking            | Try `-f`, `--source-port 53`, or `-sA`  |
| Too many false positives     | Lower timing, increase `--max-retries`  |
| Connection refused           | Target may have port open but rejecting |
| Script errors                | Update scripts with `--script-updatedb` |
| Memory issues on large scans | Reduce `--max-hostgroup`                |
| Incomplete results           | Check `--host-timeout` settings         |

***

### Legal & Ethical Reminders

* Only scan networks you own or have written authorisation to test
* Scanning without permission may violate computer crime laws
* ISPs may terminate service for unauthorised scanning
* Some scan types (brute force, exploit) are more invasive
* Document all testing authorisation before scanning
* Be aware of scope limitations in penetration test agreements
