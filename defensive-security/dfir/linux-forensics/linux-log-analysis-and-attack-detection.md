# Linux Log Analysis & Attack Detection

### Overview

This guide covers practical techniques for detecting, analysing, and defending against real-world attacks on Linux systems through log analysis. Each section provides log locations, detection patterns, investigation commands, and defensive recommendations.

***

### Learning Workflow

**Phase 1: Foundations** — Log architecture, locations, and parsing basics\
**Phase 2: Authentication Attacks** — SSH brute-force, credential theft, lateral movement\
**Phase 3: Application Attacks** — Web server, database, and service exploitation\
**Phase 4: Malware & Cryptominers** — Detection of malicious software and resource abuse\
**Phase 5: Privilege Escalation** — Sudo abuse, SUID exploitation, kernel vulnerabilities\
**Phase 6: Persistence & Evasion** — Rootkits, backdoors, log tampering\
**Phase 7: Network & Exfiltration** — Data theft, C2 communication, lateral movement\
**Phase 8: Container & Cloud** — Escape attempts, misconfigurations, supply chain attacks

***

## Phase 1: Linux Log Foundations

### Critical Log Locations

#### Authentication & Access Logs

<table><thead><tr><th width="191">Log File</th><th width="199">Distribution</th><th>Content</th></tr></thead><tbody><tr><td><code>/var/log/auth.log</code></td><td>Debian/Ubuntu</td><td>Authentication events, sudo, SSH</td></tr><tr><td><code>/var/log/secure</code></td><td>RHEL/CentOS/Fedora</td><td>Authentication events, sudo, SSH</td></tr><tr><td><code>/var/log/faillog</code></td><td>All</td><td>Failed login attempts</td></tr><tr><td><code>/var/log/lastlog</code></td><td>All</td><td>Last login info per user</td></tr><tr><td><code>/var/log/btmp</code></td><td>All</td><td>Failed login attempts (binary)</td></tr><tr><td><code>/var/log/wtmp</code></td><td>All</td><td>Login/logout history (binary)</td></tr><tr><td><code>/var/run/utmp</code></td><td>All</td><td>Current logged-in users (binary)</td></tr></tbody></table>

#### System Logs

<table><thead><tr><th width="273">Log File</th><th>Content</th></tr></thead><tbody><tr><td><code>/var/log/syslog</code></td><td>General system messages (Debian)</td></tr><tr><td><code>/var/log/messages</code></td><td>General system messages (RHEL)</td></tr><tr><td><code>/var/log/kern.log</code></td><td>Kernel messages</td></tr><tr><td><code>/var/log/dmesg</code></td><td>Boot and kernel ring buffer</td></tr><tr><td><code>/var/log/boot.log</code></td><td>Boot process logs</td></tr><tr><td><code>/var/log/cron</code></td><td>Cron job execution</td></tr></tbody></table>

#### Application Logs

<table><thead><tr><th width="277">Log File</th><th>Content</th></tr></thead><tbody><tr><td><code>/var/log/apache2/</code></td><td>Apache web server</td></tr><tr><td><code>/var/log/nginx/</code></td><td>Nginx web server</td></tr><tr><td><code>/var/log/mysql/</code></td><td>MySQL database</td></tr><tr><td><code>/var/log/postgresql/</code></td><td>PostgreSQL database</td></tr><tr><td><code>/var/log/mail.log</code></td><td>Mail server</td></tr><tr><td><code>/var/log/cups/</code></td><td>Print services</td></tr></tbody></table>

#### Security & Audit Logs

| Log File                   | Content                           |
| -------------------------- | --------------------------------- |
| `/var/log/audit/audit.log` | Auditd events (SELinux, syscalls) |
| `/var/log/fail2ban.log`    | Fail2ban actions                  |
| `/var/log/ufw.log`         | UFW firewall                      |
| `/var/log/firewalld`       | Firewalld logs                    |
| `/var/log/snort/`          | Snort IDS                         |
| `/var/log/suricata/`       | Suricata IDS                      |

#### Container & Cloud Logs

| Log File                           | Content                       |
| ---------------------------------- | ----------------------------- |
| `/var/log/docker.log`              | Docker daemon                 |
| `/var/lib/docker/containers/<id>/` | Container-specific logs       |
| `/var/log/containers/`             | Kubernetes container logs     |
| `/var/log/pods/`                   | Kubernetes pod logs           |
| `/var/log/cloud-init.log`          | Cloud instance initialization |
| `/var/log/amazon/`                 | AWS-specific logs             |

### Essential Log Analysis Commands

#### Basic Parsing

```bash
# Real-time monitoring
tail -f /var/log/auth.log
tail -f /var/log/syslog | grep -i error

# Multi-file monitoring
tail -f /var/log/auth.log /var/log/syslog

# View compressed logs
zcat /var/log/auth.log.2.gz | grep "Failed"
zgrep "Failed" /var/log/auth.log.*.gz

# Last N lines
tail -n 1000 /var/log/auth.log

# Date range (GNU date)
awk '/^Jan 15/,/^Jan 16/' /var/log/auth.log
sed -n '/Jan 15 08:00/,/Jan 15 12:00/p' /var/log/auth.log
```

#### Journalctl (systemd)

```bash
# View all logs
journalctl

# Follow mode
journalctl -f

# Since boot
journalctl -b

# Specific unit
journalctl -u sshd
journalctl -u nginx

# Time range
journalctl --since "2024-01-15 08:00:00" --until "2024-01-15 12:00:00"
journalctl --since "1 hour ago"
journalctl --since yesterday

# Priority levels
journalctl -p err      # Errors and above
journalctl -p warning  # Warnings and above

# Kernel messages
journalctl -k

# By user
journalctl _UID=1000

# Output formats
journalctl -o json
journalctl -o json-pretty
journalctl -o verbose

# Disk usage
journalctl --disk-usage
```

#### Binary Log Analysis

```bash
# wtmp - login history
last -f /var/log/wtmp
last -n 50
last -x  # Include shutdown/runlevel changes

# btmp - failed logins
lastb -f /var/log/btmp
lastb -n 50

# lastlog - last login per user
lastlog

# utmp - current sessions
who
w
```

#### Auditd Analysis

```bash
# Search audit logs
ausearch -m USER_LOGIN
ausearch -m EXECVE
ausearch -ua root
ausearch -ts today
ausearch -ts recent  # Last 10 minutes
ausearch -k <audit_key>

# Generate reports
aureport --summary
aureport --login
aureport --failed
aureport --auth
aureport --executable
aureport --file

# Specific time range
ausearch -ts 01/15/2024 08:00:00 -te 01/15/2024 12:00:00
```

***

## Phase 2: SSH Brute-Force Detection

### Attack Overview

SSH brute-force attacks involve automated attempts to guess valid username/password combinations. Variants include:

* **Traditional brute-force**: Many passwords against one user
* **Password spraying**: One password against many users
* **Credential stuffing**: Known credential pairs from breaches
* **Dictionary attacks**: Common passwords/usernames

### Log Indicators

#### Failed Authentication Patterns

```bash
# Log locations
/var/log/auth.log    # Debian/Ubuntu
/var/log/secure      # RHEL/CentOS

# Key phrases to search
"Failed password"
"authentication failure"
"Invalid user"
"Connection closed by authenticating user"
"maximum authentication attempts exceeded"
"Disconnecting: Too many authentication failures"
"PAM: Authentication failure"
"pam_unix(sshd:auth): authentication failure"
"error: PAM: Authentication failure"
"Did not receive identification string"
"Bad protocol version identification"
```

#### Successful Attack Indicators

```bash
# Successful login after many failures
"Accepted password"
"Accepted publickey"
"session opened for user"

# Suspicious patterns
"Accepted password for root"  # Root login (should be disabled)
"Accepted password" + unusual source IP
"Accepted password" + unusual time
```

### Detection Commands

#### Basic Brute-Force Detection

{% code overflow="wrap" %}
```bash
# Count failed password attempts
grep "Failed password" /var/log/auth.log | wc -l

# Failed attempts by IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Failed attempts by username
grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -rn | head -20

# Invalid users (enumeration attempts)
grep "Invalid user" /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -rn | head -20

# Failed attempts per hour
grep "Failed password" /var/log/auth.log | awk '{print $1, $2, substr($3,1,2)":00"}' | sort | uniq -c | sort -rn

# Timeline of attacks from specific IP
grep "Failed password" /var/log/auth.log | grep "192.168.1.100" | awk '{print $1, $2, $3}'
```
{% endcode %}

#### Successful Login Analysis

```bash
# All successful logins
grep "Accepted" /var/log/auth.log

# Successful logins by user
grep "Accepted" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -rn

# Successful logins by IP
grep "Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Successful logins after failures (potential compromise)
# Find IPs with failures then check for success
for ip in $(grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort -u); do
    if grep -q "Accepted.*$ip" /var/log/auth.log; then
        echo "ALERT: $ip had failures AND success"
        grep "$ip" /var/log/auth.log | grep -E "(Failed|Accepted)"
    fi
done

# Root logins (should rarely happen)
grep "Accepted.*for root" /var/log/auth.log
```

#### Advanced Detection

{% code overflow="wrap" %}
```bash
# Rapid-fire attempts (more than 10 attempts in 1 minute from same IP)
grep "Failed password" /var/log/auth.log | awk '{print $1, $2, substr($3,1,5), $(NF-3)}' | sort | uniq -c | awk '$1 > 10 {print}'

# Distributed attacks (same username from multiple IPs)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-5), $(NF-3)}' | sort | uniq | awk '{print $1}' | sort | uniq -c | sort -rn | awk '$1 > 5 {print}'

# Password spraying detection (many users, few attempts each)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | awk '$1 > 5 && $1 < 20' | sort -rn

# Connection without authentication (port scanners)
grep "Did not receive identification string" /var/log/auth.log
grep "Connection closed by" /var/log/auth.log | grep "preauth"

# SSH key-based failures
grep "Connection closed by authenticating user" /var/log/auth.log
```
{% endcode %}

#### Geolocation & Enrichment

{% code overflow="wrap" %}
```bash
# Extract unique attacker IPs for geolocation
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort -u > attacker_ips.txt

# GeoIP lookup (requires geoiplookup)
while read ip; do
    echo -n "$ip: "
    geoiplookup $ip
done < attacker_ips.txt

# Check IPs against threat intel (example with abuse.ch)
while read ip; do
    curl -s "https://threatfox-api.abuse.ch/api/v1/" -d '{"query":"search_ioc","search_term":"'"$ip"'"}'
done < attacker_ips.txt
```
{% endcode %}

### Investigation Workflow

{% code overflow="wrap" %}
```bash
# 1. Identify attack scope
echo "=== Attack Summary ==="
echo "Total failed attempts: $(grep -c 'Failed password' /var/log/auth.log)"
echo "Unique attacker IPs: $(grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort -u | wc -l)"
echo "Unique usernames tried: $(grep 'Failed password' /var/log/auth.log | awk '{print $(NF-5)}' | sort -u | wc -l)"

# 2. Check for successful compromises
echo -e "\n=== Successful Logins During Attack Period ==="
grep "Accepted" /var/log/auth.log | tail -20

# 3. Check for suspicious session activity
echo -e "\n=== Session Activity ==="
grep "session opened" /var/log/auth.log | tail -20

# 4. Check current logged-in users
echo -e "\n=== Current Sessions ==="
w
who

# 5. Check for persistence (new users, authorized_keys changes)
echo -e "\n=== Recent User Additions ==="
grep -E "useradd|adduser|usermod" /var/log/auth.log

# 6. Check SSH authorized_keys modifications
echo -e "\n=== Authorized Keys Files ==="
find /home -name "authorized_keys" -exec ls -la {} \; -exec cat {} \;
ls -la /root/.ssh/authorized_keys 2>/dev/null
```
{% endcode %}

### Real-Time Detection Script

```bash
#!/bin/bash
# SSH Brute-Force Monitor

THRESHOLD=10  # Failed attempts before alert
LOG="/var/log/auth.log"
ALERT_LOG="/var/log/ssh_attacks.log"

tail -Fn0 "$LOG" | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        IP=$(echo "$line" | awk '{print $(NF-3)}')
        COUNT=$(grep "Failed password" "$LOG" | grep "$IP" | wc -l)
        
        if [ $COUNT -gt $THRESHOLD ]; then
            TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
            echo "[$TIMESTAMP] ALERT: $IP has $COUNT failed attempts" | tee -a "$ALERT_LOG"
            
            # Optional: Auto-block with iptables
            # iptables -A INPUT -s $IP -j DROP
            
            # Optional: Add to hosts.deny
            # echo "sshd: $IP" >> /etc/hosts.deny
        fi
    fi
done
```

### Defensive Recommendations

{% code overflow="wrap" %}
```bash
# 1. Disable root login
# /etc/ssh/sshd_config
PermitRootLogin no

# 2. Use key-based authentication only
PasswordAuthentication no
PubkeyAuthentication yes

# 3. Limit users
AllowUsers admin deploy
AllowGroups sshusers

# 4. Change default port
Port 2222

# 5. Rate limiting with iptables
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# 6. Install and configure fail2ban
apt install fail2ban
# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

# 7. Enable auditd for SSH
auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config
auditctl -w /root/.ssh -p wa -k root_ssh

# 8. Configure TCP wrappers
# /etc/hosts.allow
sshd: 10.0.0.0/8

# /etc/hosts.deny
sshd: ALL
```
{% endcode %}

***

## Phase 3: Web Server Attack Detection

### Attack Types

<table><thead><tr><th width="245">Category</th><th>Examples</th></tr></thead><tbody><tr><td><strong>Injection</strong></td><td>SQL injection, command injection, LDAP injection</td></tr><tr><td><strong>XSS</strong></td><td>Reflected, stored, DOM-based cross-site scripting</td></tr><tr><td><strong>Path Traversal</strong></td><td>Directory traversal, LFI, RFI</td></tr><tr><td><strong>Brute-Force</strong></td><td>Login attacks, directory enumeration</td></tr><tr><td><strong>Exploitation</strong></td><td>Known CVEs, web shells, RCE</td></tr><tr><td><strong>DoS</strong></td><td>Slowloris, request flooding</td></tr><tr><td><strong>Scanning</strong></td><td>Vulnerability scanners, bots</td></tr></tbody></table>

### Log Locations

```bash
# Apache
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log       # RHEL/CentOS
/var/log/httpd/error_log

# Nginx
/var/log/nginx/access.log
/var/log/nginx/error.log

# Application logs
/var/log/php-fpm/error.log
/var/log/tomcat*/catalina.out
/var/log/application/*.log
```

### Detection Patterns

#### SQL Injection

{% code overflow="wrap" %}
```bash
# Common SQLi patterns
grep -iE "(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set)" /var/log/apache2/access.log
grep -iE "('|\"|\;|\-\-|#|/\*)" /var/log/apache2/access.log
grep -iE "(or|and)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+" /var/log/apache2/access.log
grep -iE "(benchmark|sleep|waitfor|delay)" /var/log/apache2/access.log
grep -iE "(@@version|information_schema|sys\.)" /var/log/apache2/access.log

# URL-encoded SQLi
grep -iE "(%27|%22|%3B|%2D%2D|%23|%2F%2A)" /var/log/apache2/access.log

# UNION-based SQLi
grep -iE "(union\+select|union%20select|union/\*\*/select)" /var/log/apache2/access.log
```
{% endcode %}

#### Cross-Site Scripting (XSS)

```bash
# Script injection attempts
grep -iE "(<script|javascript:|onerror=|onload=|onclick=)" /var/log/apache2/access.log
grep -iE "(%3Cscript|%3C/script)" /var/log/apache2/access.log
grep -iE "(alert\(|confirm\(|prompt\(|document\.cookie)" /var/log/apache2/access.log
grep -iE "(eval\(|expression\(|fromCharCode)" /var/log/apache2/access.log
```

#### Path Traversal & LFI/RFI

{% code overflow="wrap" %}
```bash
# Directory traversal
grep -iE "(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e/|..%2f)" /var/log/apache2/access.log

# Local File Inclusion
grep -iE "(/etc/passwd|/etc/shadow|/proc/self|/var/log)" /var/log/apache2/access.log
grep -iE "(\.htaccess|\.htpasswd|web\.config|\.git|\.svn)" /var/log/apache2/access.log
grep -iE "(\?file=|\?page=|\?include=|\?path=)" /var/log/apache2/access.log

# Remote File Inclusion
grep -iE "(http://|https://|ftp://)" /var/log/apache2/access.log | grep -iE "(\?file=|\?page=|\?url=)"
grep -iE "(data://|php://|file://|expect://|input://)" /var/log/apache2/access.log
```
{% endcode %}

#### Command Injection

```bash
# Shell commands
grep -iE "(\||;|&|\`|\$\(|\${)" /var/log/apache2/access.log
grep -iE "(wget|curl|nc|netcat|bash|sh|perl|python|ruby)" /var/log/apache2/access.log
grep -iE "(/bin/sh|/bin/bash|/bin/nc|/dev/tcp)" /var/log/apache2/access.log
grep -iE "(cat\+/etc|id;|whoami|uname)" /var/log/apache2/access.log

# Encoded command injection
grep -iE "(%7C|%3B|%26|%60)" /var/log/apache2/access.log
```

#### Web Shell Detection

{% code overflow="wrap" %}
```bash
# Known web shell indicators
grep -iE "(c99|r57|b374k|wso|china\+chopper)" /var/log/apache2/access.log
grep -iE "(cmd=|command=|exec=|shell=|execute=)" /var/log/apache2/access.log
grep -iE "(eval\(|base64_decode|system\(|passthru\(|shell_exec\()" /var/log/apache2/access.log

# Suspicious file uploads
grep -iE "(\.php|\.phtml|\.php5|\.phar|\.asp|\.aspx|\.jsp|\.jspx)" /var/log/apache2/access.log | grep -i "POST"

# Unusual file extensions accessed
grep -iE "\.(php|asp|jsp)[0-9]" /var/log/apache2/access.log
```
{% endcode %}

#### Scanner & Bot Detection

{% code overflow="wrap" %}
```bash
# Common scanner signatures
grep -iE "(nikto|nmap|nessus|openvas|acunetix|w3af|sqlmap|burp|zap)" /var/log/apache2/access.log
grep -iE "(dirbuster|gobuster|dirb|ffuf|wfuzz|feroxbuster)" /var/log/apache2/access.log

# Suspicious user agents
grep -iE "(python-requests|python-urllib|curl|wget|libwww|perl)" /var/log/apache2/access.log
grep -iE "(bot|crawler|spider|scan)" /var/log/apache2/access.log

# Blank or missing user agents
awk -F'"' '$6 == "" || $6 == "-"' /var/log/apache2/access.log

# Directory brute-forcing (many 404s from same IP)
awk '{print $1, $9}' /var/log/apache2/access.log | grep " 404" | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
```
{% endcode %}

#### Response Code Analysis

{% code overflow="wrap" %}
```bash
# Error distribution
awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn

# 4xx/5xx errors by IP
awk '$9 ~ /^[45]/' /var/log/apache2/access.log | awk '{print $1, $9}' | sort | uniq -c | sort -rn | head -30

# Successful attacks (200 response to suspicious requests)
grep -iE "(union.*select|<script|\.\.\/)" /var/log/apache2/access.log | awk '$9 == 200'
```
{% endcode %}

#### Comprehensive Analysis Commands

{% code overflow="wrap" %}
```bash
# Top source IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Top requested URLs
awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Top user agents
awk -F'"' '{print $6}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Requests per hour
awk '{print $4}' /var/log/apache2/access.log | cut -d: -f1-2 | sort | uniq -c

# Large response sizes (potential data exfil)
awk '$10 > 1000000 {print $1, $7, $10}' /var/log/apache2/access.log | sort -t' ' -k3 -rn | head -20

# POST requests (often used in attacks)
grep '"POST' /var/log/apache2/access.log

# Requests to admin pages
grep -iE "(admin|wp-admin|administrator|phpmyadmin|manager)" /var/log/apache2/access.log
```
{% endcode %}

### Investigation Workflow

```bash
#!/bin/bash
# Web Attack Investigation Script

LOG="${1:-/var/log/apache2/access.log}"
echo "=== Web Server Attack Analysis ==="
echo "Log file: $LOG"
echo ""

echo "=== Request Summary ==="
echo "Total requests: $(wc -l < "$LOG")"
echo "Unique IPs: $(awk '{print $1}' "$LOG" | sort -u | wc -l)"

echo -e "\n=== Response Code Distribution ==="
awk '{print $9}' "$LOG" | sort | uniq -c | sort -rn

echo -e "\n=== Top 10 Source IPs ==="
awk '{print $1}' "$LOG" | sort | uniq -c | sort -rn | head -10

echo -e "\n=== SQL Injection Attempts ==="
grep -ciE "(union.*select|'|\"|;|--)" "$LOG"

echo -e "\n=== XSS Attempts ==="
grep -ciE "(<script|javascript:|onerror)" "$LOG"

echo -e "\n=== Path Traversal Attempts ==="
grep -ciE "(\.\.\/|%2e%2e)" "$LOG"

echo -e "\n=== Command Injection Attempts ==="
grep -ciE "(\||;|&|wget|curl|nc)" "$LOG"

echo -e "\n=== Scanner Activity ==="
grep -ciE "(nikto|nmap|sqlmap|burp)" "$LOG"

echo -e "\n=== Suspicious POST Requests ==="
grep '"POST' "$LOG" | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -10

echo -e "\n=== Large Responses (>1MB) ==="
awk '$10 > 1000000 {print $1, $7, $10}' "$LOG" | head -10
```

### Modsecurity/WAF Log Analysis

```bash
# Modsecurity audit log location
/var/log/modsec_audit.log
/var/log/apache2/modsec_audit.log

# Parse Modsecurity alerts
grep -E "^Message:" /var/log/modsec_audit.log

# Find blocked requests
grep -E "Action: Intercepted" /var/log/modsec_audit.log

# Top triggered rules
grep -oP 'id "\K[^"]+' /var/log/modsec_audit.log | sort | uniq -c | sort -rn | head -20
```

### Defensive Recommendations

{% code overflow="wrap" %}
```bash
# 1. Enable detailed logging
# Apache - LogFormat with additional fields
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{X-Forwarded-For}i %D" detailed

# 2. Install ModSecurity WAF
apt install libapache2-mod-security2
a2enmod security2

# 3. Rate limiting (Apache)
# mod_evasive or mod_ratelimit

# 4. Nginx rate limiting
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
limit_req zone=one burst=20 nodelay;

# 5. Fail2ban for web
# /etc/fail2ban/jail.local
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3

# 6. File integrity monitoring for web directories
auditctl -w /var/www/html -p wa -k webroot_changes
```
{% endcode %}

***

## Phase 4: Cryptocurrency Miner Detection

### Attack Overview

Cryptominers consume CPU/GPU resources to mine cryptocurrency. They may be:

* Deployed through exploited vulnerabilities
* Installed via malicious packages
* Running as unauthorized containers
* Embedded in compromised applications

### Detection Indicators

#### Process-Based Detection

{% code overflow="wrap" %}
```bash
# High CPU processes
ps aux --sort=-%cpu | head -20

# Common miner process names
ps aux | grep -iE "(xmrig|minerd|cpuminer|cgminer|bfgminer|ccminer|ethminer|nbminer|t-rex|phoenix)"
ps aux | grep -iE "(stratum|pool|miner|nicehash|cryptonight|randomx)"

# Suspicious process names (random strings)
ps aux | awk '{print $11}' | grep -E "^(\./|/tmp/|/var/tmp/|/dev/shm/)"

# Processes in unusual locations
ls -la /tmp/ /var/tmp/ /dev/shm/ | grep -x

# Hidden processes (names starting with .)
ps aux | awk '$11 ~ /^\./'
```
{% endcode %}

#### Network-Based Detection

{% code overflow="wrap" %}
```bash
# Common mining pool ports
ss -tunapl | grep -E ":(3333|4444|5555|7777|8888|9999|14433|14444|45700)"

# Stratum protocol connections
ss -tunapl | grep -i stratum

# High-volume outbound connections
ss -tunapl | grep -E "ESTABLISHED" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# DNS queries for mining pools
grep -iE "(pool\.|mining\.|xmr\.|monero\.|nicehash|nanopool|2miners|f2pool|sparkpool)" /var/log/syslog

# Netstat with process info
netstat -tunapl | grep -E ":(3333|4444|5555)"
```
{% endcode %}

#### System Log Detection

{% code overflow="wrap" %}
```bash
# CPU-related kernel messages
dmesg | grep -iE "(temperature|thermal|cpu|throttl)"
grep -iE "(temperature|thermal|cpu)" /var/log/syslog

# Cron-based miners
grep -r "xmrig\|miner\|stratum" /var/spool/cron/
cat /etc/crontab | grep -iE "(wget|curl|bash|sh)" 
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/

# Systemd service miners
find /etc/systemd/ /lib/systemd/ -type f -exec grep -l -iE "(miner|xmrig|stratum)" {} \;

# Recently modified executables
find /usr/bin /usr/local/bin /tmp -type f -executable -mtime -7

# User-installed miners
find /home -name "*miner*" -o -name "*xmrig*" -o -name "*.json" -exec grep -l "pool" {} \; 2>/dev/null
```
{% endcode %}

#### File System Analysis

{% code overflow="wrap" %}
```bash
# Find miner binaries
find / -type f \( -name "*xmrig*" -o -name "*miner*" -o -name "*minerd*" \) 2>/dev/null

# Find miner configs
find / -type f -name "*.json" -exec grep -l -iE "(pool|stratum|wallet|miner)" {} \; 2>/dev/null

# Find by file hash (example XMRig hash)
find / -type f -executable -exec md5sum {} \; 2>/dev/null | grep -f known_miner_hashes.txt

# Recently created executables
find / -type f -executable -ctime -7 2>/dev/null

# Files in tmp directories
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null

# Hidden files
find / -name ".*" -type f -executable 2>/dev/null
```
{% endcode %}

#### Container-Based Mining

```bash
# High-CPU containers
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}" | sort -k2 -rn

# Check container processes
docker top <container_id>

# Check container networking
docker inspect <container_id> | jq '.[].NetworkSettings'

# Known miner images
docker images | grep -iE "(miner|xmrig|monero|crypto)"

# Scan all container processes
for container in $(docker ps -q); do
    echo "=== Container: $container ==="
    docker exec $container ps aux 2>/dev/null | grep -iE "(miner|xmrig|stratum)"
done
```

### Comprehensive Detection Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Cryptominer Detection Script

echo "=== Cryptominer Detection ==="
echo "Timestamp: $(date)"
echo ""

# CPU Check
echo "=== High CPU Processes ==="
ps aux --sort=-%cpu | head -10

# Known miner processes
echo -e "\n=== Known Miner Processes ==="
ps aux | grep -iE "(xmrig|minerd|cpuminer|cgminer|nicehash)" | grep -v grep

# Suspicious network connections
echo -e "\n=== Mining Pool Connections ==="
ss -tunapl | grep -E ":(3333|4444|5555|7777|8888|9999|14433|14444|45700)"

# Stratum connections
echo -e "\n=== Stratum Protocol ==="
ss -tunapl | grep -i stratum

# Tmp directory executables
echo -e "\n=== Executables in Temp Directories ==="
find /tmp /var/tmp /dev/shm -type f -executable -ls 2>/dev/null

# Cron jobs
echo -e "\n=== Suspicious Cron Entries ==="
grep -rE "(wget|curl|bash|\.sh)" /var/spool/cron/ /etc/cron.* 2>/dev/null

# Recent executables
echo -e "\n=== Recently Modified Executables ==="
find /usr/bin /usr/local/bin -type f -executable -mtime -7 -ls 2>/dev/null

# Miner configs
echo -e "\n=== Potential Miner Configs ==="
find / -name "*.json" -size +1k -size -100k -exec grep -l -E "(pool|stratum|wallet)" {} \; 2>/dev/null | head -10

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

### Known Mining Pool Indicators

<table><thead><tr><th width="188">Pool Type</th><th>Domains/IPs</th></tr></thead><tbody><tr><td>Monero (XMR)</td><td><code>pool.minexmr.com</code>, <code>xmr.pool.minergate.com</code></td></tr><tr><td>Nanopool</td><td><code>*.nanopool.org</code></td></tr><tr><td>F2Pool</td><td><code>*.f2pool.com</code></td></tr><tr><td>NiceHash</td><td><code>*.nicehash.com</code></td></tr><tr><td>Generic</td><td>Connections to ports 3333, 4444, 5555, 14433</td></tr></tbody></table>

### Defensive Recommendations

```bash
# 1. Monitor CPU usage
# Set up alerts for sustained high CPU (>80%)

# 2. Block mining pools at firewall
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -p tcp --dport 5555 -j DROP

# 3. DNS blocking for mining pools
# Add to /etc/hosts or DNS sinkhole
0.0.0.0 pool.minexmr.com
0.0.0.0 xmr.pool.minergate.com

# 4. Auditd rules for miner detection
auditctl -w /tmp -p x -k tmp_exec
auditctl -w /var/tmp -p x -k vartmp_exec
auditctl -w /dev/shm -p x -k devshm_exec

# 5. Container policies
# Use resource limits in Docker/Kubernetes
# Scan images for known miners

# 6. File integrity monitoring
aide --init
aide --check
```

***

## Phase 5: Privilege Escalation Detection

### Attack Categories

<table><thead><tr><th width="254">Category</th><th>Examples</th></tr></thead><tbody><tr><td><strong>Sudo Abuse</strong></td><td>Sudo misconfig, sudo caching, sudoers modification</td></tr><tr><td><strong>SUID/SGID</strong></td><td>SUID binary exploitation, capability abuse</td></tr><tr><td><strong>Kernel Exploits</strong></td><td>Dirty COW, Dirty Pipe, kernel module loading</td></tr><tr><td><strong>Cron/Service</strong></td><td>Writable cron jobs, service hijacking</td></tr><tr><td><strong>Path Hijacking</strong></td><td>PATH manipulation, library preloading</td></tr><tr><td><strong>Credentials</strong></td><td>Password files, SSH keys, environment variables</td></tr></tbody></table>

### Log Locations

```bash
/var/log/auth.log          # sudo commands, su usage
/var/log/secure            # RHEL equivalent
/var/log/audit/audit.log   # Auditd events
/var/log/syslog            # System events
/var/log/kern.log          # Kernel messages
```

### Sudo Abuse Detection

{% code overflow="wrap" %}
```bash
# All sudo usage
grep "sudo:" /var/log/auth.log

# Sudo failures
grep "sudo:" /var/log/auth.log | grep -i "incorrect\|failed\|not allowed"

# Sudo successes
grep "sudo:" /var/log/auth.log | grep "COMMAND="

# Commands run as root
grep "sudo:" /var/log/auth.log | grep "COMMAND=" | awk -F'COMMAND=' '{print $2}' | sort | uniq -c | sort -rn

# Sudo by user
grep "sudo:" /var/log/auth.log | awk '{print $6}' | sort | uniq -c | sort -rn

# Suspicious sudo commands
grep "sudo:" /var/log/auth.log | grep -iE "(passwd|shadow|sudoers|visudo|chmod|chown|useradd|usermod)"

# Sudoers modifications
grep -iE "(visudo|sudoers)" /var/log/auth.log
ausearch -k sudoers 2>/dev/null

# Sudo password bypass attempts
grep "sudo:" /var/log/auth.log | grep -i "NOPASSWD"
```
{% endcode %}

### SUID/SGID Detection

{% code overflow="wrap" %}
```bash
# Find all SUID files
find / -perm -4000 -type f 2>/dev/null

# Find all SGID files
find / -perm -2000 -type f 2>/dev/null

# Recently modified SUID files
find / -perm -4000 -type f -mtime -7 2>/dev/null

# SUID files not in standard locations
find / -perm -4000 -type f 2>/dev/null | grep -vE "^(/usr/bin|/bin|/sbin|/usr/sbin|/usr/lib)"

# Compare SUID files to baseline
find / -perm -4000 -type f 2>/dev/null | sort > current_suid.txt
diff baseline_suid.txt current_suid.txt

# Files with capabilities
getcap -r / 2>/dev/null

# Dangerous capabilities
getcap -r / 2>/dev/null | grep -E "(cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin)"
```
{% endcode %}

### Kernel Exploit Detection

```bash
# Kernel messages
dmesg | tail -100
dmesg | grep -iE "(exploit|overflow|corruption|panic|oops)"

# Kernel module loading
dmesg | grep -i "module"
lsmod | grep -v "^Module"

# Recently loaded modules
journalctl -k | grep -i "module"

# Suspicious kernel activity
grep -iE "(kernel|kmod)" /var/log/syslog | grep -iE "(load|insmod|modprobe)"

# Known exploit indicators
dmesg | grep -iE "(dirty.*cow|dirty.*pipe|overlayfs|bpf)"

# Audit kernel module loads
ausearch -m KMOD_LOAD
```

### User/Group Modification Detection

```bash
# User additions
grep -iE "(useradd|adduser)" /var/log/auth.log
ausearch -m ADD_USER

# User modifications
grep -iE "(usermod|passwd)" /var/log/auth.log
ausearch -m USER_MGMT

# Group modifications
grep -iE "(groupadd|gpasswd|usermod.*-aG)" /var/log/auth.log
ausearch -m ADD_GROUP

# Password changes
grep "password changed" /var/log/auth.log

# UID 0 users (besides root)
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd

# Check for new privileged users
grep ":0:" /etc/passwd
grep "sudo\|wheel\|admin" /etc/group
```

### File Permission Changes

```bash
# Chmod commands in logs
grep "chmod" /var/log/auth.log
ausearch -m CHMOD

# Chown commands
grep "chown" /var/log/auth.log
ausearch -m CHOWN

# World-writable files
find / -perm -002 -type f 2>/dev/null | grep -vE "^(/proc|/sys|/dev)"

# Recently modified sensitive files
find /etc -type f -mtime -7 2>/dev/null

# Sensitive file changes
ls -la /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/
```

### Cron/Service Hijacking

```bash
# Cron modifications
ls -la /etc/cron* /var/spool/cron/
grep -r "." /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/

# New cron jobs
find /etc/cron* /var/spool/cron -mtime -7 2>/dev/null

# Writable cron files
find /etc/cron* -perm -002 2>/dev/null

# Systemd service changes
find /etc/systemd /lib/systemd -mtime -7 2>/dev/null

# New/modified services
systemctl list-unit-files --type=service | grep enabled
journalctl -u <suspicious_service>

# Service configuration
find /etc/systemd/system /lib/systemd/system -name "*.service" -mtime -7
```

### Environment Hijacking

{% code overflow="wrap" %}
```bash
# PATH in environment
env | grep PATH

# Writable directories in PATH
for dir in $(echo $PATH | tr ':' '\n'); do
    if [ -w "$dir" ]; then
        echo "Writable PATH directory: $dir"
    fi
done

# LD_PRELOAD abuse
grep -rE "LD_PRELOAD|LD_LIBRARY_PATH" /etc/profile* /etc/environment /home/*/.bashrc /home/*/.profile 2>/dev/null

# Shared library modifications
find /lib /lib64 /usr/lib /usr/lib64 -type f -mtime -7 2>/dev/null

# Preload configuration
cat /etc/ld.so.preload 2>/dev/null
ls -la /etc/ld.so.conf.d/
```
{% endcode %}

### Auditd Rules for Privilege Escalation

{% code overflow="wrap" %}
```bash
# Monitor privilege escalation vectors
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /etc/sudoers -p wa -k sudoers_changes
auditctl -w /etc/sudoers.d/ -p wa -k sudoers_d_changes
auditctl -w /etc/group -p wa -k group_changes
auditctl -w /etc/gshadow -p wa -k gshadow_changes

# Monitor SUID changes
auditctl -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Monitor user/group commands
auditctl -w /usr/sbin/useradd -p x -k user_add
auditctl -w /usr/sbin/usermod -p x -k user_mod
auditctl -w /usr/sbin/userdel -p x -k user_del
auditctl -w /usr/sbin/groupadd -p x -k group_add

# Monitor sudo configuration
auditctl -w /usr/bin/sudo -p x -k sudo_usage
auditctl -w /usr/bin/su -p x -k su_usage

# Query audit logs
ausearch -k passwd_changes
ausearch -k sudoers_changes
aureport --mods
```
{% endcode %}

### Privilege Escalation Investigation Workflow

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Privilege Escalation Detection Script

echo "=== Privilege Escalation Detection ==="
echo "Timestamp: $(date)"
echo ""

echo "=== Recent Sudo Activity ==="
grep "sudo:" /var/log/auth.log | tail -20

echo -e "\n=== Sudo Failures ==="
grep "sudo:" /var/log/auth.log | grep -i "incorrect\|failed" | tail -10

echo -e "\n=== User Modifications ==="
grep -iE "(useradd|usermod|passwd)" /var/log/auth.log | tail -10

echo -e "\n=== New SUID Files (last 7 days) ==="
find / -perm -4000 -type f -mtime -7 2>/dev/null

echo -e "\n=== SUID in Unusual Locations ==="
find / -perm -4000 -type f 2>/dev/null | grep -vE "^(/usr/bin|/bin|/sbin|/usr/sbin|/usr/lib)"

echo -e "\n=== Files with Dangerous Capabilities ==="
getcap -r / 2>/dev/null | grep -E "(cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin)"

echo -e "\n=== UID 0 Users (non-root) ==="
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd

echo -e "\n=== World-Writable Files ==="
find /etc /usr -perm -002 -type f 2>/dev/null | head -20

echo -e "\n=== Recent Cron Changes ==="
find /etc/cron* /var/spool/cron -mtime -7 -ls 2>/dev/null

echo -e "\n=== Kernel Module Activity ==="
dmesg | grep -i "module" | tail -10

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

***

## Phase 6: Rootkit & Kernel Attack Detection

### Attack Types

<table><thead><tr><th width="273">Type</th><th>Description</th></tr></thead><tbody><tr><td><strong>User-space Rootkits</strong></td><td>LD_PRELOAD, modified binaries, library replacement</td></tr><tr><td><strong>Kernel Rootkits</strong></td><td>LKM rootkits, modified syscalls, hidden processes</td></tr><tr><td><strong>Bootkit</strong></td><td>Modified bootloader, initramfs</td></tr><tr><td><strong>Memory-only</strong></td><td>Fileless, inject into running processes</td></tr></tbody></table>

### Detection Techniques

#### Process Hiding Detection

```bash
# Compare ps to /proc
ps aux | wc -l
ls -d /proc/[0-9]* | wc -l

# Find hidden processes
ps_pids=$(ps -eo pid --no-headers | sort -n)
proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | cut -d/ -f3 | sort -n)
diff <(echo "$ps_pids") <(echo "$proc_pids")

# Detect process hiding with unhide
unhide proc
unhide sys
unhide brute

# Check for deleted executables
ls -la /proc/*/exe 2>/dev/null | grep deleted
find /proc -name exe -exec ls -la {} \; 2>/dev/null | grep deleted
```

#### File Hiding Detection

```bash
# Compare find to ls
find_count=$(find /path -type f 2>/dev/null | wc -l)
ls_count=$(ls -la /path 2>/dev/null | wc -l)

# Look for hidden files using inodes
find / -inum <suspicious_inode> 2>/dev/null

# Files with suspicious timestamps
find / -type f -mtime -1 -mmin +60 2>/dev/null  # Modified but not recent

# Stat check for hidden attributes
lsattr /path/to/suspicious

# Compare file listing methods
stat -c "%n" /path/* 2>/dev/null > stat_files.txt
ls /path/ 2>/dev/null > ls_files.txt
diff stat_files.txt ls_files.txt
```

#### Kernel Module Detection

```bash
# List loaded modules
lsmod
cat /proc/modules

# Compare to known-good baseline
lsmod | awk '{print $1}' | sort > current_modules.txt
diff baseline_modules.txt current_modules.txt

# Hidden modules (not in lsmod but in memory)
# Use specialized tools like rkhunter or chkrootkit

# Suspicious module characteristics
modinfo <module_name>

# Recently loaded modules
dmesg | grep -i "module"
journalctl -k | grep -i "loaded module"

# Unsigned modules (if secure boot)
for mod in $(lsmod | awk 'NR>1 {print $1}'); do
    modinfo $mod 2>/dev/null | grep -q "signature" || echo "Unsigned: $mod"
done

# Module in unexpected location
find /lib/modules -name "*.ko" -mtime -7 2>/dev/null
```

#### Syscall Hooking Detection

```bash
# Check syscall table (requires root and specific tools)
# Using kprobes or SystemTap

# Detect inline hooks
dmesg | grep -iE "(hook|detour|inline)"

# Kernel integrity
# Compare /proc/kallsyms to known-good

# Interrupt descriptor table
cat /proc/interrupts

# System call trace
strace -f -e trace=all <suspicious_command>
```

#### Library Preload Detection

{% code overflow="wrap" %}
```bash
# Check LD_PRELOAD
env | grep LD_PRELOAD
cat /etc/ld.so.preload

# Check for preload in profiles
grep -rE "LD_PRELOAD" /etc/profile* /etc/environment /home/*/.* 2>/dev/null

# Verify library integrity
for lib in $(ldd /bin/ls | awk '{print $3}' | grep -v "^$"); do
    if [ -f "$lib" ]; then
        rpm -Vf "$lib" 2>/dev/null || dpkg -V $(dpkg -S "$lib" 2>/dev/null | cut -d: -f1) 2>/dev/null
    fi
done

# Compare loaded libraries
ldd /bin/ls
ldd /bin/ps
```
{% endcode %}

#### Binary Integrity Verification

```bash
# Verify package integrity (Debian)
dpkg -V
debsums -s  # Only changed files

# Verify package integrity (RHEL)
rpm -Va

# Check specific binaries
dpkg -V coreutils
rpm -Vf /bin/ls

# Compare hashes to known-good
md5sum /bin/ls /bin/ps /bin/netstat
sha256sum /bin/ls /bin/ps /bin/netstat

# Find replaced binaries
find /bin /sbin /usr/bin /usr/sbin -mtime -7 -type f 2>/dev/null
```

#### Network Hiding Detection

```bash
# Compare netstat to ss
netstat -tunapl 2>/dev/null | wc -l
ss -tunapl | wc -l

# Compare to /proc/net
cat /proc/net/tcp | wc -l
netstat -tn | wc -l

# Look for hidden connections
ss -tunapl | grep -v "$(cat /proc/net/tcp | awk 'NR>1 {print $3}')"

# Packet capture for hidden traffic
tcpdump -i any -c 1000 -w capture.pcap
```

#### Rootkit Scanning Tools

```bash
# rkhunter
rkhunter --check --skip-keypress
rkhunter --propupd  # Update baseline

# chkrootkit
chkrootkit

# Lynis (security auditing)
lynis audit system

# OSSEC rootcheck
/var/ossec/bin/rootcheck
```

#### Memory Analysis

```bash
# Dump memory for analysis
# Using AVML (Microsoft's Linux memory acquisition)
avml memory.raw

# Using LiME
insmod lime.ko "path=/tmp/memory.lime format=lime"

# Analyze with Volatility 3
vol -f memory.raw linux.pslist
vol -f memory.raw linux.lsmod
vol -f memory.raw linux.check_syscall
vol -f memory.raw linux.check_modules
```

### Rootkit Detection Workflow

```bash
#!/bin/bash
# Rootkit Detection Script

echo "=== Rootkit Detection Analysis ==="
echo "Timestamp: $(date)"
echo ""

# Process comparison
echo "=== Process Hiding Check ==="
ps_count=$(ps aux | wc -l)
proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
echo "Processes (ps): $ps_count"
echo "Processes (/proc): $proc_count"
[ $ps_count -ne $proc_count ] && echo "WARNING: Process count mismatch!"

# Deleted executables
echo -e "\n=== Deleted Executables ==="
find /proc -name exe -exec ls -la {} \; 2>/dev/null | grep deleted

# LD_PRELOAD check
echo -e "\n=== LD_PRELOAD Check ==="
env | grep LD_PRELOAD && echo "WARNING: LD_PRELOAD is set!"
cat /etc/ld.so.preload 2>/dev/null && echo "WARNING: /etc/ld.so.preload exists!"

# Kernel module check
echo -e "\n=== Recent Kernel Modules ==="
dmesg | grep -i "module" | tail -10

# Binary integrity
echo -e "\n=== Binary Integrity Check ==="
rpm -Va 2>/dev/null | grep -E "^..5" | head -20
dpkg -V 2>/dev/null | grep -E "^..5" | head -20

# Hidden files check
echo -e "\n=== Hidden Attribute Files ==="
lsattr -R /etc /bin /sbin /usr 2>/dev/null | grep -E "^\-+i|^\-+a"

# Network hiding
echo -e "\n=== Network Connection Comparison ==="
netstat_count=$(netstat -tunapl 2>/dev/null | grep ESTABLISHED | wc -l)
ss_count=$(ss -tunapl | grep ESTAB | wc -l)
echo "Netstat: $netstat_count connections"
echo "ss: $ss_count connections"

# SUID check
echo -e "\n=== Unusual SUID Files ==="
find / -perm -4000 2>/dev/null | grep -vE "^(/usr/bin|/bin|/sbin|/usr/sbin|/usr/lib)"

echo -e "\n=== Detection Complete ==="
```

***

## Phase 7: Data Exfiltration Detection

### Exfiltration Methods

| Method                 | Description                       |
| ---------------------- | --------------------------------- |
| **Network**            | Direct TCP/UDP, DNS, ICMP, HTTP/S |
| **Cloud**              | S3, Azure Blob, GDrive, Dropbox   |
| **Email**              | SMTP, webmail                     |
| **USB**                | External storage devices          |
| **Encrypted Channels** | VPN, Tor, stunnel                 |
| **Steganography**      | Hidden data in images             |

### Network-Based Exfiltration

#### Outbound Traffic Analysis

```bash
# Large outbound transfers
iftop -i eth0 -f "outbound"
vnstat -l -i eth0

# Connections to unusual ports
ss -tunapl | grep -vE ":(22|80|443|53) "

# Long-running connections
ss -tunapl | grep ESTAB | awk '{print $5}' | sort | uniq -c | sort -rn

# High-volume connections (netflow if available)
conntrack -L | awk '{print $4, $5}' | sort | uniq -c | sort -rn | head -20

# Unusual destination IPs
ss -tunapl | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort -u | while read ip; do
    whois $ip 2>/dev/null | grep -iE "(country|orgname)"
done
```

#### DNS Exfiltration

```bash
# Unusually long DNS queries
tcpdump -i any -n port 53 2>/dev/null | awk '{print length, $0}' | sort -rn | head -20

# DNS queries to unusual TLDs
grep -E "\.(xyz|top|club|online|site|info)" /var/log/syslog

# High-frequency DNS queries
grep "query" /var/log/syslog | awk '{print $NF}' | sort | uniq -c | sort -rn | head -30

# DNS TXT record queries (common exfil method)
tcpdump -i any -n "port 53" 2>/dev/null | grep TXT

# Check DNS cache
cat /etc/resolv.conf
rndc dumpdb -cache 2>/dev/null
```

#### HTTP/HTTPS Exfiltration

{% code overflow="wrap" %}
```bash
# Large POST requests (from web server logs)
awk '$6 == "\"POST" && $10 > 100000 {print $1, $7, $10}' /var/log/apache2/access.log

# Long URLs (data in GET parameters)
awk 'length($7) > 500 {print $1, length($7), $7}' /var/log/apache2/access.log

# Unusual user agents
awk -F'"' '{print $6}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Cloud storage domains
grep -iE "(dropbox|drive\.google|onedrive|s3\.amazonaws|blob\.core)" /var/log/squid/access.log
grep -iE "(mega\.nz|mediafire|wetransfer|sendspace)" /var/log/squid/access.log
```
{% endcode %}

#### Encrypted Channel Detection

```bash
# Tor connections
ss -tunapl | grep -E ":9050|:9001|:9030"
grep -iE "tor" /var/log/syslog

# VPN connections
ss -tunapl | grep -E ":1194|:443|:500|:4500"
ip tunnel show
ip xfrm state

# SSH tunneling
ss -tunapl | grep ssh | grep -v ":22$"
ps aux | grep "ssh.*-[DLR]"

# Long-established SSL connections
ss -tunapl | grep ":443" | grep ESTAB
```

### File System Exfiltration

#### Sensitive File Access

```bash
# Access to sensitive files
ausearch -f /etc/passwd
ausearch -f /etc/shadow
ausearch -k sensitive_files

# Large file reads
lsof | grep -E "(\.sql|\.csv|\.xlsx|\.pdf|\.zip|\.tar)"

# Archive creation
grep -iE "(tar|zip|rar|7z|gzip)" /var/log/auth.log
ausearch -m EXECVE | grep -iE "(tar|zip|rar)"

# Recent large file creation
find / -type f -size +100M -mtime -1 2>/dev/null
```

#### USB/Removable Media

```bash
# USB device connections
dmesg | grep -i usb
journalctl | grep -iE "(usb|removable|storage)"

# Block device mounts
grep -i "mount\|usb" /var/log/syslog
mount | grep -iE "(media|mnt)"

# USB audit rules
auditctl -w /media -p rwxa -k usb_media
auditctl -w /mnt -p rwxa -k mnt_activity
ausearch -k usb_media
```

### Email Exfiltration

```bash
# Large email attachments
grep -iE "(attachment|multipart)" /var/log/mail.log
postqueue -p | head -50

# Unusual recipients
awk '/to=</ {print}' /var/log/mail.log | grep -vE "(company\.com|internal\.domain)"

# Email to external domains
grep "relay=" /var/log/mail.log | grep -v "relay=127\|relay=local" | head -50
```

### Exfiltration Investigation Workflow

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Data Exfiltration Detection Script

echo "=== Data Exfiltration Detection ==="
echo "Timestamp: $(date)"
echo ""

# Large outbound connections
echo "=== High-Volume Outbound Connections ==="
ss -tunapl | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

# Unusual ports
echo -e "\n=== Connections on Unusual Ports ==="
ss -tunapl | grep -vE ":(22|80|443|53|25|993|995) " | grep ESTAB | head -20

# Cloud storage
echo -e "\n=== Cloud Storage Connections ==="
ss -tunapl | grep -iE "dropbox|google|amazonaws|azure"

# DNS queries
echo -e "\n=== High-Frequency DNS Queries ==="
grep "query" /var/log/syslog 2>/dev/null | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10

# Large file creation
echo -e "\n=== Large Files Created Recently ==="
find / -type f -size +100M -mtime -1 2>/dev/null | head -20

# Archive creation
echo -e "\n=== Recent Archive Activity ==="
find / -type f \( -name "*.zip" -o -name "*.tar*" -o -name "*.7z" \) -mtime -1 2>/dev/null | head -20

# USB activity
echo -e "\n=== USB Device Activity ==="
dmesg | grep -i "usb" | tail -10

# Sensitive file access
echo -e "\n=== Sensitive File Access (if auditd) ==="
ausearch -k sensitive_files 2>/dev/null | tail -20

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

***

## Phase 8: Network Attack & Firewall Detection

### Attack Types

| Attack               | Description                               |
| -------------------- | ----------------------------------------- |
| **Port Scanning**    | Service discovery, nmap, masscan          |
| **DDoS**             | Volume-based, protocol, application layer |
| **MITM**             | ARP spoofing, DNS spoofing                |
| **Lateral Movement** | Internal pivoting, SSH tunnels            |
| **Firewall Bypass**  | Port hopping, tunneling                   |

### Log Locations

```bash
# Firewall logs
/var/log/ufw.log                    # UFW
/var/log/firewalld                  # Firewalld
/var/log/iptables.log              # iptables (custom)
/var/log/kern.log                   # Kernel/netfilter

# IDS/IPS logs
/var/log/snort/alert               # Snort
/var/log/suricata/fast.log         # Suricata
/var/log/suricata/eve.json         # Suricata EVE

# Network logs
/var/log/syslog                    # General
/var/log/daemon.log                # Network daemons
```

### Port Scanning Detection

{% code overflow="wrap" %}
```bash
# High number of connection attempts
grep "DPT=" /var/log/kern.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# SYN flood indicators
netstat -s | grep -i "syn"
ss -s

# Connection attempts from single IP
grep "SRC=" /var/log/kern.log | awk -F'SRC=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# UFW blocks
grep "UFW BLOCK" /var/log/ufw.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -30

# Firewalld drops
journalctl -u firewalld | grep -i "drop\|reject"

# Connection rate by port
grep "DPT=" /var/log/kern.log | awk -F'DPT=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn
```
{% endcode %}

### Firewall Log Analysis

#### UFW

{% code overflow="wrap" %}
```bash
# All blocked traffic
grep "UFW BLOCK" /var/log/ufw.log

# Blocked by source IP
grep "UFW BLOCK" /var/log/ufw.log | awk -F'SRC=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn

# Blocked by destination port
grep "UFW BLOCK" /var/log/ufw.log | awk -F'DPT=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn

# Allowed traffic
grep "UFW ALLOW" /var/log/ufw.log

# Block timeline
grep "UFW BLOCK" /var/log/ufw.log | awk '{print $1, $2, substr($3,1,2)":00"}' | sort | uniq -c
```
{% endcode %}

#### iptables Logging

{% code overflow="wrap" %}
```bash
# Enable iptables logging
iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4
iptables -A OUTPUT -j LOG --log-prefix "IPTABLES-OUT: " --log-level 4

# Analyze logs
grep "IPTABLES-DROP" /var/log/kern.log | tail -100
grep "IPTABLES-DROP" /var/log/kern.log | awk -F'SRC=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn
```
{% endcode %}

#### Netfilter Connection Tracking

{% code overflow="wrap" %}
```bash
# Current connections
conntrack -L
conntrack -L | wc -l

# Connection states
conntrack -L | awk '{print $4}' | sort | uniq -c

# Top sources
conntrack -L | awk -F'src=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Monitor in real-time
conntrack -E
```
{% endcode %}

### DDoS Detection

{% code overflow="wrap" %}
```bash
# Connection count per IP
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# SYN_RECV state (SYN flood indicator)
netstat -n | grep SYN_RECV | wc -l
ss -n state syn-recv | wc -l

# Connection states
netstat -n | awk '{print $6}' | sort | uniq -c | sort -rn

# Packet rate
cat /proc/net/dev | grep eth0
sar -n DEV 1 5

# Interface statistics
ip -s link show eth0

# Check for amplification attacks
tcpdump -i any -c 100 -n port 53 or port 123 or port 161
```
{% endcode %}

### ARP/MITM Detection

```bash
# ARP table
arp -a
ip neigh show

# Duplicate MAC addresses (ARP spoofing)
arp -a | awk '{print $4}' | sort | uniq -c | sort -rn | awk '$1 > 1'

# ARP changes
grep -i "arp" /var/log/syslog
journalctl | grep -i "arp"

# Detect ARP spoofing
arpwatch -i eth0
tail -f /var/log/arpwatch.log

# IP conflicts
grep -i "duplicate\|conflict" /var/log/syslog
```

### Lateral Movement Detection

{% code overflow="wrap" %}
```bash
# Internal SSH connections
grep "sshd" /var/log/auth.log | grep "Accepted" | awk '{print $11}' | grep -E "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"

# RPC/SMB connections (if applicable)
ss -tunapl | grep -E ":(135|139|445)"

# New outbound connections to internal hosts
ss -tunapl | grep ESTAB | awk '{print $5}' | grep -E "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"

# SSH tunneling
ps aux | grep ssh | grep -E "\-[DLR]"
```
{% endcode %}

### Network Attack Investigation

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Network Attack Detection Script

echo "=== Network Attack Detection ==="
echo "Timestamp: $(date)"
echo ""

# Connection summary
echo "=== Connection Summary ==="
ss -s

# Top connecting IPs
echo -e "\n=== Top Source IPs ==="
ss -tunapl | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -15

# SYN flood check
echo -e "\n=== SYN_RECV Connections ==="
echo "Count: $(ss -n state syn-recv | wc -l)"

# Port scan indicators
echo -e "\n=== Firewall Blocks (Recent) ==="
grep "UFW BLOCK\|DROP\|REJECT" /var/log/kern.log /var/log/ufw.log 2>/dev/null | tail -20

# ARP anomalies
echo -e "\n=== ARP Table ==="
arp -a | head -20

echo -e "\n=== Duplicate MACs ==="
arp -a | awk '{print $4}' | sort | uniq -c | sort -rn | awk '$1 > 1'

# Internal connections
echo -e "\n=== Internal Network Connections ==="
ss -tunapl | grep ESTAB | awk '{print $5}' | grep -E "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" | head -20

# Interface statistics
echo -e "\n=== Interface Statistics ==="
ip -s link show | head -30

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

***

## Phase 9: Container Escape Detection

### Attack Vectors

| Vector                    | Description                |
| ------------------------- | -------------------------- |
| **Privileged Containers** | Full host access           |
| **Sensitive Mounts**      | /etc, /var/run/docker.sock |
| **Kernel Exploits**       | Container breakout CVEs    |
| **Capability Abuse**      | CAP\_SYS\_ADMIN, etc.      |
| **Misconfigured Seccomp** | Allowed dangerous syscalls |

### Log Locations

```bash
# Docker logs
/var/log/docker.log
/var/lib/docker/containers/<id>/<id>-json.log
journalctl -u docker

# Kubernetes logs
/var/log/containers/
/var/log/pods/
journalctl -u kubelet

# Audit logs
/var/log/audit/audit.log
```

### Container Security Analysis

#### Privileged Container Detection

{% code overflow="wrap" %}
```bash
# Find privileged containers
docker ps -q | xargs docker inspect --format '{{.Name}} Privileged: {{.HostConfig.Privileged}}' | grep "true"

# Check capabilities
docker ps -q | xargs docker inspect --format '{{.Name}} Caps: {{.HostConfig.CapAdd}}'

# Check for dangerous capabilities
docker ps -q | xargs docker inspect --format '{{.Name}}: {{.HostConfig.CapAdd}}' | grep -iE "(SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)"

# Check security options
docker ps -q | xargs docker inspect --format '{{.Name}}: Seccomp={{.HostConfig.SecurityOpt}}'
```
{% endcode %}

#### Sensitive Mount Detection

{% code overflow="wrap" %}
```bash
# Check bind mounts
docker ps -q | xargs docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}'

# Dangerous mounts
docker ps -q | xargs docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}} {{end}}' | grep -iE "(/etc|/root|/var/run/docker|/proc|/sys)"

# Docker socket mounts (container escape risk)
docker ps -q | xargs docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}} {{end}}' | grep "docker.sock"
```
{% endcode %}

#### Container Process Monitoring

```bash
# Processes in containers
for container in $(docker ps -q); do
    echo "=== Container: $(docker inspect --format '{{.Name}}' $container) ==="
    docker top $container
done

# High-privilege processes in containers
for container in $(docker ps -q); do
    docker exec $container ps aux 2>/dev/null | grep -E "^root"
done

# Detect escape attempts
ausearch -m CONTAINER_CONFIG_CHANGE
ausearch -m CONTAINER_OP
```

#### Kubernetes Security

{% code overflow="wrap" %}
```bash
# Privileged pods
kubectl get pods -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# Host namespace pods
kubectl get pods -o json | jq '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) | .metadata.name'

# Service account tokens
kubectl get pods -o json | jq '.items[] | {name: .metadata.name, sa: .spec.serviceAccountName}'

# Pod security context
kubectl get pods -o json | jq '.items[] | {name: .metadata.name, securityContext: .spec.securityContext}'
```
{% endcode %}

#### Container Escape Indicators

{% code overflow="wrap" %}
```bash
# Host file access from container
ausearch -m PATH | grep -iE "(/etc/passwd|/etc/shadow|/root)"

# Container breakout syscalls
ausearch -m SYSCALL | grep -iE "(unshare|setns|clone)"

# Suspicious container activity
docker events --since 1h | grep -iE "(die|kill|oom|exec)"

# Check for modified container images
docker images --digests | head -20

# Running as root
docker ps -q | xargs docker inspect --format '{{.Name}}: User={{.Config.User}}' | grep -E "User=$|User=root|User=0"
```
{% endcode %}

#### Runtime Security Logs

```bash
# Falco alerts (if installed)
cat /var/log/falco/falco.log
journalctl -u falco

# Sysdig logs
cat /var/log/sysdig/sysdig.log

# Docker audit events
ausearch -m CONTAINER_CONFIG_CHANGE
ausearch -m CONTAINER_OP
```

### Container Security Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Container Escape Detection Script

echo "=== Container Security Analysis ==="
echo "Timestamp: $(date)"
echo ""

# Privileged containers
echo "=== Privileged Containers ==="
docker ps -q | xargs docker inspect --format '{{.Name}} Privileged: {{.HostConfig.Privileged}}' 2>/dev/null | grep "true"

# Dangerous capabilities
echo -e "\n=== Dangerous Capabilities ==="
docker ps -q | xargs docker inspect --format '{{.Name}}: {{.HostConfig.CapAdd}}' 2>/dev/null | grep -iE "(SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|ALL)"

# Docker socket mounts
echo -e "\n=== Docker Socket Mounts ==="
docker ps -q | xargs docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep "docker.sock"

# Host path mounts
echo -e "\n=== Sensitive Host Mounts ==="
docker ps -q | xargs docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' 2>/dev/null | grep -iE "(/etc|/root|/proc|/sys)"

# Running as root
echo -e "\n=== Containers Running as Root ==="
docker ps -q | xargs docker inspect --format '{{.Name}}: User={{.Config.User}}' 2>/dev/null | grep -E "User=$|User=root|User=0"

# Recent container events
echo -e "\n=== Recent Container Events ==="
docker events --since 1h --until now 2>/dev/null | tail -20

echo -e "\n=== Analysis Complete ==="
```
{% endcode %}

***

## Phase 10: Supply Chain Attack Detection

### Attack Vectors

| Vector                    | Description                       |
| ------------------------- | --------------------------------- |
| **Package Managers**      | Malicious npm, pip, gem packages  |
| **Repository Compromise** | Tainted mirrors, hijacked repos   |
| **Build Pipeline**        | CI/CD poisoning                   |
| **Dependency Confusion**  | Internal vs public package naming |
| **Typosquatting**         | Similar package names             |

### Detection Techniques

#### Package Manager Monitoring

```bash
# Recently installed packages (Debian/Ubuntu)
grep " install " /var/log/dpkg.log | tail -50
grep " install " /var/log/apt/history.log

# Recently installed packages (RHEL/CentOS)
rpm -qa --last | head -50
grep "Installed:" /var/log/yum.log

# Unusual package sources
cat /etc/apt/sources.list /etc/apt/sources.list.d/*
yum repolist

# Package verification
dpkg -V
rpm -Va

# Find packages not from official repos
apt list --installed 2>/dev/null | grep -v "ubuntu\|debian"
rpm -qa --qf '%{NAME} %{VENDOR}\n' | grep -v "Red Hat\|CentOS"
```

#### Python/Pip Monitoring

```bash
# Recently installed pip packages
pip list --format=freeze > current_packages.txt
diff baseline_packages.txt current_packages.txt

# Pip install logs
grep -rE "pip install" /var/log/ ~/.bash_history

# Check for typosquatting
pip list | awk '{print $1}' | while read pkg; do
    # Compare to known-good packages
    echo "Checking: $pkg"
done

# Unusual pip sources
pip config list
cat ~/.pip/pip.conf /etc/pip.conf 2>/dev/null

# Package locations
pip show <package> | grep Location
```

#### Node.js/NPM Monitoring

{% code overflow="wrap" %}
```bash
# Global packages
npm list -g --depth=0

# Local packages
find / -name "package.json" -exec dirname {} \; 2>/dev/null

# NPM install logs
grep -rE "npm install" /var/log/ ~/.bash_history

# Check for suspicious scripts
find /node_modules -name "package.json" -exec grep -l "preinstall\|postinstall" {} \; 2>/dev/null

# Review postinstall scripts
find / -path "*/node_modules/*/package.json" -exec sh -c 'grep -q "postinstall" "$1" && echo "$1"' _ {} \; 2>/dev/null
```
{% endcode %}

#### Build Pipeline Security

{% code overflow="wrap" %}
```bash
# CI/CD configuration changes
find / -name ".gitlab-ci.yml" -o -name "Jenkinsfile" -o -name ".github" -type d 2>/dev/null

# Recently modified build files
find / \( -name "Makefile" -o -name "CMakeLists.txt" -o -name "build.gradle" -o -name "pom.xml" \) -mtime -7 2>/dev/null

# Suspicious build scripts
grep -rE "(curl|wget|bash|sh)" /path/to/project/Makefile /path/to/project/build* 2>/dev/null
```
{% endcode %}

#### Container Image Verification

```bash
# Image digests
docker images --digests

# Image history (layer inspection)
docker history <image>

# Scan for vulnerabilities
trivy image <image>
grype <image>

# Compare to known-good
docker image inspect <image> | jq '.[].RepoDigests'
```

#### Integrity Monitoring

```bash
# AIDE (Advanced Intrusion Detection Environment)
aide --init
aide --check

# Tripwire
tripwire --check

# OSSEC
/var/ossec/bin/syscheck_control -l

# Manual integrity check
find /usr/bin /usr/sbin /bin /sbin -type f -exec md5sum {} \; > current_hashes.txt
diff baseline_hashes.txt current_hashes.txt
```

### Supply Chain Attack Script

```bash
#!/bin/bash
# Supply Chain Attack Detection

echo "=== Supply Chain Attack Detection ==="
echo "Timestamp: $(date)"
echo ""

# Recent package installations
echo "=== Recent Package Installations ==="
if [ -f /var/log/dpkg.log ]; then
    grep " install " /var/log/dpkg.log | tail -20
elif [ -f /var/log/yum.log ]; then
    grep "Installed:" /var/log/yum.log | tail -20
fi

# Package integrity
echo -e "\n=== Package Integrity Issues ==="
dpkg -V 2>/dev/null | head -20 || rpm -Va 2>/dev/null | head -20

# Pip packages
echo -e "\n=== Recent Pip Activity ==="
grep -h "pip install" ~/.bash_history /var/log/auth.log 2>/dev/null | tail -10

# NPM packages
echo -e "\n=== Global NPM Packages ==="
npm list -g --depth=0 2>/dev/null | head -20

# Binary modifications
echo -e "\n=== Recently Modified Binaries ==="
find /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null | head -20

# Unusual repositories
echo -e "\n=== Package Repositories ==="
cat /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | grep -v "^#"
cat /etc/yum.repos.d/* 2>/dev/null | grep -E "^\[|baseurl"

echo -e "\n=== Detection Complete ==="
```

***

## Additional Attack Detection

### Backdoor Detection

```bash
# Unusual SUID binaries
find / -perm -4000 -type f 2>/dev/null | xargs ls -la

# Unusual services
systemctl list-units --type=service --state=running

# Listening on unusual ports
ss -tunapl | grep LISTEN | grep -vE ":(22|80|443|25|53)"

# Netcat listeners
ps aux | grep -E "(nc|netcat|ncat)" | grep -v grep

# Reverse shells
ps aux | grep -E "(bash.*-i|/dev/tcp|python.*socket)" | grep -v grep

# Cron persistence
cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null

# Systemd persistence
find /etc/systemd/system /lib/systemd/system -name "*.service" -mtime -7 2>/dev/null

# Init.d persistence
ls -la /etc/init.d/ | grep -vE "^total|^d"
```

### Webshell Detection

{% code overflow="wrap" %}
```bash
# Common webshell patterns
find /var/www -name "*.php" -exec grep -l -E "(eval|base64_decode|system|exec|shell_exec|passthru|popen)" {} \; 2>/dev/null

# Recently modified PHP files
find /var/www -name "*.php" -mtime -7 2>/dev/null

# Suspicious file names
find /var/www -name "*.php" | grep -iE "(shell|cmd|backdoor|c99|r57|wso)"

# Files with suspicious permissions
find /var/www -perm -002 -type f 2>/dev/null

# Encoded content
find /var/www -name "*.php" -exec grep -l "base64_decode\|gzinflate\|str_rot13\|eval" {} \; 2>/dev/null
```
{% endcode %}

### Log Tampering Detection

{% code overflow="wrap" %}
```bash
# Log file gaps
for log in /var/log/auth.log /var/log/syslog /var/log/messages; do
    if [ -f "$log" ]; then
        echo "=== $log gaps ==="
        awk '{print $1, $2, $3}' "$log" | uniq -c | awk '$1 > 100 {print "Gap after:", $2, $3, $4}'
    fi
done

# Truncated logs
find /var/log -type f -size 0 2>/dev/null

# Modified log timestamps
ls -la /var/log/*.log | awk '{print $6, $7, $8, $9}'
stat /var/log/auth.log

# wtmp/btmp integrity
last -f /var/log/wtmp | tail -20
lastb -f /var/log/btmp 2>/dev/null | tail -20

# Log rotation anomalies
ls -la /var/log/*.gz | head -20
```
{% endcode %}

***

## Quick Reference Card

### Essential Commands

<table><thead><tr><th width="236">Task</th><th>Command</th></tr></thead><tbody><tr><td>Failed SSH logins</td><td><code>grep "Failed password" /var/log/auth.log</code></td></tr><tr><td>Successful SSH logins</td><td><code>grep "Accepted" /var/log/auth.log</code></td></tr><tr><td>Sudo commands</td><td><code>grep "sudo:" /var/log/auth.log | grep "COMMAND="</code></td></tr><tr><td>User additions</td><td><code>grep -E "useradd|adduser" /var/log/auth.log</code></td></tr><tr><td>High CPU processes</td><td><code>ps aux --sort=-%cpu | head</code></td></tr><tr><td>Network connections</td><td><code>ss -tunapl</code></td></tr><tr><td>Firewall blocks</td><td><code>grep "UFW BLOCK" /var/log/ufw.log</code></td></tr><tr><td>SUID files</td><td><code>find / -perm -4000 -type f</code></td></tr><tr><td>Recent file changes</td><td><code>find / -mtime -1 -type f</code></td></tr><tr><td>Kernel modules</td><td><code>lsmod</code></td></tr><tr><td>Docker containers</td><td><code>docker ps -a</code></td></tr><tr><td>Package integrity</td><td><code>dpkg -V</code> or <code>rpm -Va</code></td></tr><tr><td>Audit search</td><td><code>ausearch -m &#x3C;message_type></code></td></tr><tr><td>Journal logs</td><td><code>journalctl -u &#x3C;service></code></td></tr><tr><td>Real-time logs</td><td><code>tail -f /var/log/syslog</code></td></tr></tbody></table>

### Log Locations Summary

| Category | Debian/Ubuntu              | RHEL/CentOS                |
| -------- | -------------------------- | -------------------------- |
| Auth     | `/var/log/auth.log`        | `/var/log/secure`          |
| System   | `/var/log/syslog`          | `/var/log/messages`        |
| Kernel   | `/var/log/kern.log`        | `/var/log/messages`        |
| Audit    | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |
| Boot     | `/var/log/boot.log`        | `/var/log/boot.log`        |
| Cron     | `/var/log/cron.log`        | `/var/log/cron`            |
| Apache   | `/var/log/apache2/`        | `/var/log/httpd/`          |
| Nginx    | `/var/log/nginx/`          | `/var/log/nginx/`          |

### Critical Detection Patterns

| Attack               | Key Indicator                               |
| -------------------- | ------------------------------------------- |
| SSH Brute-Force      | Multiple "Failed password" from same IP     |
| Privilege Escalation | Unusual sudo, SUID changes, kernel exploits |
| Webshell             | eval/system/exec in web files               |
| Cryptominer          | High CPU, connections to pool ports         |
| Rootkit              | Process/file hiding, binary modifications   |
| Data Exfil           | Large outbound transfers, DNS tunneling     |
| Container Escape     | Privileged containers, host mounts          |
| Supply Chain         | Unauthorized packages, modified binaries    |

***

### Defensive Baseline

```bash
# 1. Enable comprehensive logging
# /etc/rsyslog.conf or rsyslog.d/
*.* /var/log/all.log

# 2. Enable auditd
apt install auditd
systemctl enable auditd

# 3. Basic audit rules
auditctl -w /etc/passwd -p wa -k passwd
auditctl -w /etc/shadow -p wa -k shadow
auditctl -w /etc/sudoers -p wa -k sudoers
auditctl -w /var/log -p wa -k log_changes

# 4. Install fail2ban
apt install fail2ban
systemctl enable fail2ban

# 5. Configure log rotation
# /etc/logrotate.d/custom
/var/log/*.log {
    weekly
    rotate 52
    compress
    missingok
}

# 6. File integrity monitoring
apt install aide
aide --init

# 7. Rootkit detection
apt install rkhunter chkrootkit
rkhunter --propupd
```
