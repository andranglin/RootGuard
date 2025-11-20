# Initial Enumeration

### Introduction

This cheat sheet provides a streamlined reference for network scanning and enumeration using Nmap and related tools. It covers host discovery, port scanning, service enumeration, and vulnerability detection for standard protocols and services. Each command is accompanied by explanations, use cases, and tips to maximise effectiveness. Use this guide for security assessments, penetration testing, or network administration, ensuring you have explicit permission to scan target networks.

### Scanning with Nmap

These Nmap commands perform various types of scans, from quick host discovery to comprehensive port and service enumeration.

#### Nmap TCP Quick Scan

```bash
sudo nmap -Pn -v -sS -sV -sC -oN tcp-quick.nmap <IP>
```

* **Purpose**: Performs a stealthy TCP SYN scan (`-sS`) with version detection (`-sV`) and default scripts (`-sC`), skipping host discovery (`-Pn`) for speed.
* **Use Case**: Quick reconnaissance to identify open ports, services, and vulnerabilities on a single host.
* **Tips**:
  * `-v` increases verbosity for real-time feedback.
  * Use on reliable networks; combine with `-T4` for faster scans if needed.
  * Save output (`-oN`) for later analysis.

#### Nmap TCP Full Scan

{% code overflow="wrap" %}
```bash
nmap -Pn -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oN tcp-full.nmap -sV <IP>
```
{% endcode %}

* **Purpose**: Comprehensive TCP SYN scan of all 65,535 ports with version detection, optimised for speed (`-T4`) and reliability.
* **Use Case**: Detailed enumeration of all TCP ports and services on a target, ideal for thorough assessments.
* **Tips**:
  * `--stats-every 3m` provides progress updates every 3 minutes.
  * `--max-retries 1` and `--defeat-rst-ratelimit` reduce scan time but may miss some ports.
  * Use on stable networks to avoid packet loss.

#### Nmap TCP - Extra Ports

```bash
nmap -Pn -v -sS -A -oN tcp-extra.nmap -p <PORTS> <IP>
```

* **Purpose**: Targeted TCP SYN scan with aggressive options (`-A`: OS detection, version detection, scripts, traceroute) on specific ports.
* **Use Case**: Follow-up scan when additional open ports are discovered, focusing on detailed enumeration.
* **Tips**:
  * Replace `<PORTS>` with specific ports (e.g., `80`,`443`).
  * `-A` is resource-intensive; use selectively.
  * Save output for documentation.

#### Nmap UDP Quick Scan

```bash
nmap -Pn -v -sU -sV --top-ports=30 -oN udp-quick.nmap <IP>
```

* **Purpose**: Scans the top 30 UDP ports with version detection, skipping host discovery.
* **Use Case**: Quick identification of common UDP services (e.g., DNS, SNMP) on a target.
* **Tips**:
  * UDP scans (`-sU`) are slower; `--top-ports=30` limits scope for speed.
  * Use -v for verbose output to monitor progress.
  * UDP services often require specific NSE scripts for enumeration.

#### Nmap UDP 1000 Scan

{% code overflow="wrap" %}
```bash
nmap -Pn --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T4 -oN udp-1000.nmap <IP>
```
{% endcode %}

* **Purpose**: Scans the top 1,000 UDP ports with aggressive timing, providing progress updates.
* **Use Case**: Broader UDP enumeration for less common services.
* **Tips**:
  * `--max-retries 1` speeds up scans but may miss unresponsive ports.
  * Use on reliable networks to minimise false negatives.
  * Save output (`-oN`) for analysis.

#### Nmap UDP - Extra Ports

```bash
sudo nmap -Pn -sU -A -oN udp-extra.nmap -p <PORTS> <IP>
```

* **Purpose**: Targeted UDP scan with aggressive options on specific ports.
* **Use Case**: Follow-up scan for newly discovered UDP ports, focusing on detailed enumeration.
* **Tips**:
  * Replace `<PORTS>` with specific ports (e.g., `161`,`123`).
  * `-A` includes OS detection and scripts; use selectively due to resource intensity.

#### ICMP Sweep

```bash
fping -a -g 10.10.10.0/24 2>/dev/null
```

* **Purpose**: Performs an ICMP ping sweep to identify live hosts in a subnet.
* **Use Case**: Quick host discovery across a network range.
* **Tips**:
  * `-a` shows only live hosts; `-g` specifies the subnet.
  * Redirect errors (`2>/dev/null`) for clean output.
  * Use when ICMP is not blocked by firewalls.

#### ARP Scan (Local Network)

```bash
arp-scan -l
```

* **Purpose**: Performs an ARP scan to discover hosts on the local network.
* **Use Case**: Fast and reliable host discovery on LANs, bypassing ICMP blocks.
* **Tips**:
  * Requires root privileges (`sudo`).
  * More effective than ICMP on local networks due to ARP’s reliability.

***

### Enumeration by Protocol/Service

These commands and checks focus on enumerating specific services and protocols, identifying configurations, vulnerabilities, and access controls.

#### FTP - Port 21

* **Checks**:
  * Identify FTP version vulnerabilities.
  * Test for anonymous login (`ftp-anon`).
  * Check for read/write access to directories (e.g., web root, system files).
* **Commands**:

{% code overflow="wrap" %}
```bash
nmap -sV --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie -p21 <IP>
```
{% endcode %}

* **Context**: Enumerates FTP services for misconfigurations or vulnerabilities.
* **Tips**:
  * Use `ftp-anon` to test anonymous access (common misconfiguration).
  * Check for known backdoors (e.g., vsftpd, ProFTPD).
  * Test write access carefully to avoid unintended changes.

#### SSH - Port 22

* **Checks**:
  * Identify SSH version vulnerabilities.
  * Enumerate users if permitted.
  * Verify if host keys are reused across systems.
  * Check if password authentication is enabled.
* **Commands**:

<pre class="language-bash"><code class="lang-bash"><strong>nmap -sV --script=ssh-hostkey,ssh-auth-methods,sshv1,ssh2-enum-algos -p22 &#x3C;IP>
</strong></code></pre>

* &#x20;Optionally, brute-force with tools like `hydra`, `patator`, or `msfconsole` if permitted.
* **Context**: Enumerates SSH configurations and potential weaknesses.
* **Tips**:
  * Use `ssh-auth-methods` to check for password-based logins.
  * Avoid brute-forcing (`ssh-brute`) unless authorised, as it may trigger defences like `fail2ban`.
  * Check `sshv1` for outdated, insecure protocol versions.

#### Telnet - Port 23

* **Checks**:
  * Connect to verify service presence and version.
* **Commands**:

```bash
telnet <IP> 23
nmap -sV --script=telnet-encryption,telnet-ntlm-info -p23 <IP>
```

* **Context**: Identifies legacy Telnet services, which are inherently insecure.
* **Tips**:
  * Presence of Telnet indicates outdated systems; prioritise further investigation.
  * Use telnet-ntlm-info for Windows environments.

#### SMTP - Port 25

* **Checks**:
  * Identify SMTP version vulnerabilities.
  * Test server response with HELO or EHLO commands.
* **Commands**:

```bash
telnet <IP> 25
# Send: HELO <domain> or EHLO <domain>
nmap -sV --script=smtp-commands,smtp-enum-users,smtp-open-relay -p25 <IP>
```

* **Context**: Enumerates mail server configurations and open relay risks.
* **Tips**:
  * Check for open relays (`smtp-open-relay`) to prevent spam abuse.
  * Use `smtp-enum-users` cautiously to avoid account lockouts.

#### POP3 - Port 110

* **Checks**:
  * Connect via Telnet to test credentials and list/retrieve emails.
* **Commands**:

```bash
telnet <IP> 110
# Commands: user <username>, pass <password>, LIST, RETR <email_number>
nmap -sV --script=pop3-capabilities,pop3-brute -p110 <IP>
```

* **Context**: Enumerates POP3 email services for configurations and credentials.
* **Tips**:
  * Avoid `pop3-brute` unless permitted.
  * Check for SSL/TLS on port 995 for secure POP3.

#### DNS - Port 53

* **Checks**:
  * Indicates a potential domain controller (Windows).
  * Test for zone transfers to reveal domain records.
* **Commands**:

```bash
nmap -sV --script=dns-zone-transfer,dns-recursion -p53 <IP>
dig axfr @<IP> <domain>
```

* **Context**: Enumerates DNS configurations and potential misconfigurations.
* **Tips**:
  * Successful zone transfers (`dns-zone-transfer`) indicate serious misconfigurations.
  * Use `-sU` for UDP-based DNS scans.

#### Kerberos - Port 88

* **Checks**:
  * Indicates a domain controller (DC) in Windows environments.
* **Commands**:

```bash
kerbrute userenum --dc <IP> -d <DOMAIN> users.txt
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass
```

* **Context**: Enumerates Kerberos users and checks for accounts vulnerable to ASREPRoast attacks.
* **Tips**:
  * Requires a valid domain name (e.g., `domain.local`).
  * Use valid user lists to avoid detection.

#### NetBIOS - Ports 137, 139

* **Checks**:
  * Enumerate NetBIOS names and SMB shares on older systems.
* **Commands**:

```bash
nmblookup -A <IP>
nbtscan <IP>
smbclient --option='client min protocol=LANMAN1' -L \\<IP>\ -N
```

* **Context**: Identifies NetBIOS and SMB services on legacy Windows systems.
* **Tips**:
  * Modify `/etc/samba/smb.conf` or use `--option` for older protocols like LANMAN1.
  * Check for null sessions (`-N`) to access shares anonymously.

#### RPC - Port 135

* **Commands**:

```bash
sudo nmap -sS -Pn -sV --script=rpcinfo.nse -p135 <IP>
rpcinfo <IP>
rpcclient -U "" -N <IP>
```

* **Context**: Enumerates Remote Procedure Call (RPC) services, often used in Windows environments.
* **Tips**:
  * Use rpcclient to query user or group information.
  * Combine with `-sV` to detect RPC service versions.

#### LDAP - Ports 389, 636, 3268, 3269

* **Commands**:

```bash
sudo nmap -sS -Pn -sV --script=ldap* -p389,636,3268,3269 <IP>
```

* **Context**: Enumerates LDAP directory services, often linked to Active Directory.
* **Tips**:
  * Use `--script=ldap-rootdse` for server metadata.
  * Avoid `ldap-brute` unless permitted to prevent account lockouts.

#### SNMP - Port 161 (UDP)

* **Commands**:

```bash
snmpwalk -v2c -c public <IP>
snmp-check <IP>
onesixtyone -c community.txt <IP>
sudo nmap -sU -sV -p161 --script=snmp* <IP>
snmpenum -t <IP> -c public
```

* **Context**: Enumerates SNMP configurations, often revealing device details.
* **Tips**:
  * Test default community strings (e.g., `public`, `private`).
  * Requires `-sU` for UDP-based scans.
  * Use `snmp-brute` cautiously to avoid detection.

#### Oracle - Port 1521

* **Commands**

```bash
tnscmd10g version -h <IP>
nmap -sV --script=oracle-tns-version,oracle-sid-brute -p1521 <IP>
odat tnscmd -s <IP> --ping
odat all -s <IP> -p 1521
odat sidguesser -s <IP>
```

* **Context**: Enumerates Oracle database configurations and SIDs.
* **Tips**:
  * `oracle-sid-brute` guesses database SIDs; use with permission.
  * Check for default credentials with `odat`.

#### MySQL - Port 3306

* **Commands**:

```bash
mysql -h <IP> -u root -p
nmap -sV --script=mysql* -p3306 <IP>
hydra -L users.txt -P passwords.txt mysql://<IP>
mysql -h <IP> -u root
```

* **Context**: Enumerates MySQL database configurations and credentials.
* **Tips**:
  * Test for empty passwords (`mysql -u root`).
  * Avoid `mysql-brute` unless permitted to prevent lockouts.

#### Web - Ports 80, 443

* **Nmap Web Scan**:

```bash
sudo nmap -Pn -sC -p80,443 <IP>
```

* **Checks**:
  * Browse the web application to identify functionality.
  * Search for usernames, keywords, or hidden pages in source code.
  * Check for web server vulnerabilities (e.g., Apache, Nginx).
  * Test for CGI vulnerabilities (e.g., Shellshock).
  * Verify SSL/TLS certificates for hostname mismatches.
  * Check `robots.txt` and `sitemap.xml` for hidden paths.
  * Test default credentials for known software.
  * Probe for SQL injection, LFI, RFI, or command execution vulnerabilities.
* **Directory Enumeration**:

{% code overflow="wrap" %}
```bash
dirb <IP>
dirb <IP> -X .php,.asp,.txt,.jsp
dirb <IP> -a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
gobuster dir --url <IP> --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt
gobuster dir --url <IP> --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt -k -a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
nikto -host <IP>
whatweb http://<IP>
wappalyzer http://<IP>
wpscan --url http://<IP> --enumerate u
```
{% endcode %}

* **Context**: Enumerates web servers, applications, and vulnerabilities.
* **Tips**:
  * Use `nikto` and `whatweb` to identify web technologies.
  * Customize `dirb` or `gobuster` with extensions based on server type (e.g., `.php`, `.asp`).
  * `wpscan` is specific to WordPress; use for CMS enumeration.

#### SMB - Ports 139, 445

* **Nmap Vulnerability Scans**

{% code overflow="wrap" %}
```bash
sudo nmap -Pn --script=smb-proto*,smb-os-discovery,smb-enum*,smb-vuln* -p139,445 <IP>
nmap -p445 -vv --script=smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010 <IP>
crackmapexec smb <IP> -u '' -p '' --shares
```
{% endcode %}

* **Null Session Checks**

```bash
/nmap --script smb-enum-shares -p139,445 <IP>
smbclient -L \\<IP>\ -N
smbclient -m=SMB2 -L \\<Hostname>\ -N
```

* **Connect to Share (Null Session)**:

```bash
smbclient \\<IP>\\$Admin -N
smbmap -H <IP>
smbmap -u DoesNotExists -H <IP>
enum4linux -a <IP>
```

* **Impacket Tools**:

```bash
impacket-smbclient -no-pass <IP>
impacket-lookupsid domain/username:password@<IP>
```

* **Check Share Permissions**

```bash
smb: \> showacls
smb: \> dir
```

* **Mount Share Locally**:

```bash
sudo mount -t cifs //<IP>/<SHARENAME> ~/path/to/mount_directory
```

* **List Shares with Credentials**:

```bash
smbmap -u <USERNAME> -p <PASSWORD> -d <DOMAIN.TLD> -H <IP>
```

* **Recursively List Files**:

```bash
smbmap -R -H <IP>
smbmap -R Replication -H <IP>
```

* **Download/Upload Files**:

```bash
smbclient \\<IP>\Replication
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
smbmap -H <IP> --download 'Replication\active.htb\'
smbmap -H <IP> --upload test.txt <SHARENAME>/test.txt
```

* **Context**: Enumerates SMB shares, users, and vulnerabilities, common in Windows environments.
* **Tips**:
  * Check for null sessions (`-N`) and vulnerabilities like MS17-010 (EternalBlue).
  * Use `crackmapexec` for quick share enumeration.
  * Test share permissions carefully to avoid unintended modifications.

#### NFS - Port 2049

* **Commands**:

```bash
/showmount -e <IP>
mount -t nfs -o vers=3 <IP>:/home/ ~/home
mount -t nfs4 -o proto=tcp,port=2049 <IP>:/srv/Share <mountpoint>
```

* **Context**: Enumerates NFS shares and mounts them for access.
* **Tips**:
  * `showmount -e` reveals exportable shares; check for world-readable shares.
  * Ensure mount commands match NFS version (e.g., `vers=3` or `nfs4`).

#### TFTP - Port 69 (UDP)

* **Commands**:

```bash
tftp <IP>
atftp <IP>
nmap -sU --script=tftp-enum -p69 <IP>
```

* **Context**: Enumerates TFTP services, often used for configuration file transfers.
* **Tips**:
  * Use `atftp` for a more robust client.
  * Check for sensitive files (e.g., MSSQL password files).

***

### Automation Tools

These tools streamline scanning and enumeration processes.

#### AutoRecon

```bash
autorecon <IP>
```

* **Purpose**: Automates Nmap scans and service enumeration.
* **Use Case**: Comprehensive reconnaissance with minimal manual effort.
* **Tip**: Ideal for large networks; review output for accuracy.

#### NmapAutomator

```bash
./NmapAutomator.sh <IP> All
```

* **Purpose**: Runs a series of Nmap scans and related tools automatically.
* **Use Case**: Quick, all-in-one enumeration for single targets.
* **Tip**: Ensure dependencies are installed for full functionality.

***

### Finding Exploits

* **Checks**:
  * Search Exploit-DB (`searchsploit`) and CVE databases for vulnerabilities.
  * Google service banners for known exploits (e.g., `searchsploit apache 2.4.49`).
  * Check for RCE, LFI, RFI, or SQL injection issues in service documentation.
* **Commands**:

```bash
searchsploit apache 2.4.49
searchsploit -x path/to/exploit
```

* **Context**: Identifies exploitable vulnerabilities based on enumerated services.
* **Tips**:
  * Cross-reference CVEs with service versions from `-sV`.
  * Test exploits in controlled environments to avoid disruption.

***

### Best Practices

1. **Obtain Permission**: Always secure explicit authorisation before scanning or enumerating networks.
2. **Start with Safe Scans**: Use quick scans (`-F`, `--top-ports`) before full scans (`-p-`).
3. **Use Stealth Techniques**: Combine `-sS`, `-Pn`, and `--scan-delay` for low-profile scans.
4. **Prioritise Services**: Focus on high-value services (e.g., HTTP, SMB) for enumeration.
5. **Avoid Intrusive Actions**: Use brute-forcing or vulnerability scripts only with permission.
6. **Save Outputs**: Use `-oA` to store results in multiple formats for analysis.
7. **Verify Findings**: Cross-check results with manual tools (e.g., `telnet`, `smbclient`) to reduce false positives.

***

### Output Analysis Tips

* **Open Ports**: Prioritise services like HTTP, SMB, or SSH for deeper enumeration.
* **Filtered Ports**: Indicate firewalls; use `-sA` or evasion techniques (`-f`, `-D`) to probe further.
* **Service Versions**: Use `-sV` to identify software for vulnerability research.
* **Parse Outputs**: Filter `-oG` results with grep open or use `-oX` with tools like `xsltproc`.
* **Document Findings**: Save all outputs (`-oA`) and note potential vulnerabilities for follow-up.
