# Network Enumeration

### Phase 1: Host Discovery (Finding Live Targets)

**Strategy:** Identify live hosts without triggering alerts. Start with methods that are less likely to be logged, like ARP on a local network, before moving to ICMP or TCP/UDP-based discovery.

* **LAN Discovery (Fast & Reliable):**
  * _Use Case:_ You are on the local network. This is the most effective method.
  * **Tools:**

```bash
# Nmap (Recommended)
# -PR: ARP Scan | -sn: "Ping Scan" (disables port scan)
sudo nmap -sn -PR 192.168.1.0/24 -oA discovery_arp
        
# arp-scan (Very Fast)
sudo arp-scan -l
```

* **Standard Network Discovery:**
  * _Use Case:_ Scanning external networks or internal subnets where ARP is not possible.
  * **Tools:**

```bash
# Nmap (Recommended for flexibility)
# -PS: TCP SYN to common ports | -PA: TCP ACK | -PU: UDP
# This combination bypasses many simple firewall rules that block only ICMP.
sudo nmap -sn -PS80,443 -PA22 -PU53 10.10.10.0/24 -oA discovery_standard
```

* **Assume All Hosts Are Up (When Blocked):**
  * _Use Case:_ A restrictive firewall is dropping your discovery probes. This is slow but necessary.
  * **Method:**

```bash
# -Pn: Skips host discovery entirely and attempts to port scan every IP.
# This is an Nmap flag, not a standalone tool.
# Combine this with the scanning techniques in Phase 2.
```

### Phase 2: Port Scanning (Mapping the Attack Surface)

**Strategy:** Employ a multi-step approach. Use ultra-fast scanners like `masscan` to find open ports, then feed those results into `nmap` for deep analysis. This is far more efficient than running a full `nmap` scan from the start.

* **Step 1: Fast Initial Port Scan:**
  * _Purpose:_ Quickly identify open ports across large IP ranges.
  * **Tools:**

{% code overflow="wrap" %}
```bash
# Masscan (Fastest)
# Finds open ports and saves them to a list.
masscan -p1-6553d5 --rate=100000 -iL targets.txt --output-format list -oG masscan.grep
        
# Nmap (Fast Mode)
sudo nmap -sS --top-ports 1000 -T4 --min-rate 1000 -iL targets.txt -oA scan_fast
```
{% endcode %}

* **Step 2: Detailed Service & Script Scan (On Discovered Ports):**
  * _Purpose:_ This is the main enumeration scan. It runs version detection, default scripts, and OS detection on the specific ports you found open.
  * **Tool:**

```bash
# Nmap is the best tool for this job.
# Use the port list from Masscan or the fast Nmap scan.
# --open: Only scan ports reported as open.
sudo nmap -sV -sC -O -p<PORTS> --open <target> -oA scan_detailed
```

* **Step 3: UDP Scan (As Needed):**
  * _Purpose:_ UDP is slow to scan. Only run this if you suspect key UDP services are in use (e.g., DNS, SNMP, Kerberos).
  * **Tool:**

```bash
# Nmap is the standard for UDP scanning.
sudo nmap -sU -sV --top-ports 50 <target> -oA scan_udp
```

### Phase 3: Service-Specific Enumeration (Deep Dive)

**Strategy:** Now that you have a list of open ports and versions, attack each service with specialised tools and scripts. Always check for anonymous/guest access and known misconfigurations first.

#### **Authentication & Directory Services**

* **LDAP (389, 636):**
  * **Tools:** `nmap`, `ldapsearch`

```bash
# Nmap (Safe enumeration)
sudo nmap -p 389,636 --script "ldap* and not brute" <target>
# ldapsearch (Manual query)
ldapsearch -x -h <target> -s base namingcontexts
```

* **Kerberos (88):**
  * **Tools:** `nmap`, `kerbrute`, `impacket-GetNPUsers`

{% code overflow="wrap" %}
```bash
# Nmap (Username enumeration)
sudo nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <target>
# Kerbrute (Faster username enumeration)
kerbrute userenum --dc <target> -d DOMAIN users.txt
```
{% endcode %}

* **SMB (139, 445):**
  * **Tools:** `crackmapexec`, `enum4linux-ng`, `smbclient`, `smbmap`

```bash
# 1. Initial check for null sessions and shares (fast)
crackmapexec smb <target> -u '' -p '' --shares
# 2. Deep enumeration (slower, more comprehensive)
enum4linux-ng -A <target>
# 3. Nmap vulnerability scan
sudo nmap -p 139,445 --script="smb-enum-*,smb-vuln*" <target>
```

#### **Remote Access & Management**

* **SSH (22):**
  * **Tools:** `nmap`, `ssh-audit`

```bash
# Nmap (Get host key, auth methods, algorithms)
sudo nmap -p 22 --script=ssh-hostkey,ssh-auth-methods,ssh2-enum-algos <target>
# ssh-audit (Check for weak crypto)
ssh-audit <target>
```

* **RDP (3389):**
  * **Tools:** `nmap`, `xfreerdp`

{% code overflow="wrap" %}
```bash
# Nmap (Check for vulnerabilities and encryption)
sudo nmap -p 3389 --script=rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 <target>
# xfreerdp (Attempt to connect)
xfreerdp /v:<target>   
## WinRM (5985, 5986):
## Tools: `nmap`, `evil-winrm`
sudo nmap -p 5985,5986 --script=http-winrm-info,wsman-info <target>
evil-winrm -i <target> -u <user> -p <pass>
```
{% endcode %}

* **VNC (5900):**
  * **Tools:** `nmap`

```bash
# Check for weak authentication and gather screen information
nmap -p 5900 --script=vnc-info,vnc-title <target>
```

#### **File Transfer & Sharing**

* **FTP (21):**
  * **Tools:** `nmap`, `ftp` (client)

```bash
# Nmap (Check for anon login and backdoors)
sudo nmap -p 21 --script "ftp* and not brute" <target>
# Manual connection test
ftp <target> # User: anonymous, Pass: anonymous
```

* **NFS (2049):**
  * **Tools:** `nmap`, `showmount`

```bash
# Nmap (List shares)
sudo nmap -p 2049 --script=nfs-showmount,nfs-ls <target>
# showmount (Native tool)
showmount -e <target>
```

* **RSync (873):**
  * **Tools:** `nmap`, `rsync`

```bash
# Nmap (Check for unauthenticated modules)
sudo nmap -p 873 --script=rsync-list-modules <target>
# rsync (Attempt to list a module)
rsync rsync://<target>/
```

#### **Web & Application Services (Expanded)**

**Strategy:** Web enumeration is a deep discipline. Start with fingerprinting to understand the technology stack. Then, aggressively search for hidden content. Finally, scan for common vulnerabilities based on your findings.

* **Step 1: Initial Recon & Fingerprinting:**
  * _Purpose:_ Identify web server software, frameworks, and technologies. Manually inspect headers and source code.
  * **Tools:**

{% code overflow="wrap" %}
```bash
# whatweb (Best for identifying technologies)
whatweb http://<target>
        
# curl (Inspect headers)
curl -I -s http://<target>
        
# Nmap (Get title, headers, and run basic scripts)
sudo nmap -p 80,443 --script=http-title,http-server-header,http-sitemap-generator <target>
        
# Netcat (Grab a simple banner)
nc <target> 80
# > GET / HTTP/1.1
# > Host: <target>
```
{% endcode %}

* **Step 2: Content Discovery (Directory & Subdomain Fuzzing):**
  * _Purpose:_ Find hidden pages, directories, API endpoints, and virtual hosts.
  * **Tools:**

{% code overflow="wrap" %}
```bash
# ffuf (Fastest for directory/subdomain fuzzing)
sudo ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<target>/FUZZ -fc 404
        
# gobuster (Popular alternative for directories)
sudo gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
        
# wfuzz (Highly versatile fuzzer for parameters, etc.)
sudo wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hc 404 http://<target>/FUZZ
```
{% endcode %}

* **Step 3: CMS & Framework Specific Scanning:**
  * _Purpose:_ Use specialised tools if a specific CMS like WordPress is identified.
  * **Tools:**

```bash
# wpscan (WordPress scanner)
# --enumerate u (users), ap (all plugins), at (all themes)
wpscan --url http://<target> --enumerate u,ap,at --api-token <YOUR_API_TOKEN>
```

* **Step 4: Automated Vulnerability Scanning:**
  * _Purpose:_ Scan for common vulnerabilities like SQLi, XSS, and misconfigurations.
  * **Tools:**

```bash
# Nuclei (Modern, fast, template-based scanner)
sudo nuclei -u http://<target>
        
# Nikto (Classic web server misconfiguration scanner)
nikto -h http://<target>
        
# sqlmap (The go-to tool for detecting and exploiting SQL injection)
# Crawl the site and test all forms
sqlmap -u "http://<target>" --crawl=1 --forms --batch
        
# Nmap (Web vulnerability scripts)
sudo nmap -p 80,443 --script http-vuln* <target>
```

* **Step 5: Manual Interaction & Data Transfer:**
  * _Purpose:_ Download files for offline analysis or interact with the server manually.
  * **Tools:**

```bash
# wget (Recursive download of a website)
wget --recursive --no-parent http://<target>/
        
# curl (Download a specific file)
curl -o output.html http://<target>/index.html
```

#### **Databases**

* **MySQL (3306), MSSQL (1433), PostgreSQL (5432):**
  * **Tools:** `nmap`, native clients (`mysql`, `sqlcmd`, `psql`)

```bash
# Nmap (Safe info gathering)
sudo nmap -p 3306 --script "mysql* and not brute" <target>
sudo nmap -p 1433 --script "ms-sql* and not brute" <target>
sudo nmap -p 5432 --script "pgsql* and not brute" <target>
```

* **Redis (6379) & Elasticsearch (9200):**
  * **Tools:** `nmap`

```bash
# Check for unauthenticated access and grab server info
sudo nmap -p 6379 --script=redis-info <target>
sudo nmap -p 9200 --script=http-elasticsearch-info <target>
```

#### **Core Network Services**

* **DNS (53):**
  * **Tools:** `nmap`, `dig`, `dnsrecon`

{% code overflow="wrap" %}
```bash
# Nmap (Check for zone transfers, recursion)by fingerprinting the technology stack to understand it
sudo nmap -p 53 --script dns-zone-transfer,dns-recursion,dns-nsid <target>
# Dig (Manual zone transfer attempt)
dig axfr @<target> <domain>
```
{% endcode %}

* **SNMP (UDP 161):**
  * **Tools:** `nmap`, `snmpwalk`, `snmp-check`

```bash
# Nmap (Enumerate with 'public' community string)
sudo nmap -sU -p 161 --script "snmp* and not brute" <target>
# snmp-check (Comprehensive enumeration)
snmp-check -t 8 <target>
```

* **SMTP (25, 465, 587):**
  * **Tools:** `nmap`, `netcat`

{% code overflow="wrap" %}
```bash
# Nmap (Enumerate users and check for open relay)
sudo nmap -p 25,465,587 --script=smtp-commands,smtp-enum-users,smtp-open-relay <target>
```
{% endcode %}

### Phase 4: Strategic Scans & Workflows

**Strategy:** Combine the phases into repeatable workflows for different scenarios.

* **External Pentest Workflow (Stealthy -> Detailed):**

```bash
1. sudo nmap -sn -PS80,443 -PA22 <target_range> -oA external_hosts
2. masscan -p1-65535 --rate=5000 -iL external_hosts.nmap -oG masscan.grep
3. Extract IPs and ports from `masscan.grep`
4. sudo nmap -sV -sC -O -p<PORTS> -iL <targets_with_open_ports> -oA external_detailed
5. Begin deep enumeration from Phase 3 on discovered services
```

* **Internal Pentest Workflow (Fast & Comprehensive):**

{% code overflow="wrap" %}
```bash
1. sudo nmap -sn -PR <target_range> -oA internal_hosts
2. sudo nmap -sS --top-ports 1000 -T4 --min-rate 1000 -iL internal_hosts.nmap -oA internal_fast_scan
3. sudo nmap -sV -sC -O --script="smb-enum-*,smb-vuln*,vuln" -iL internal_hosts.nmap -oA internal_full_enum
4. Use tools like `crackmapexec` and `enum4linux-ng` on discovered Windows hosts.
```
{% endcode %}
