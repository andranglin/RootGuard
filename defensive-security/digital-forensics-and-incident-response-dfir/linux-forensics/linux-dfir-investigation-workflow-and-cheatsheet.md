# Linux DFIR Investigation Workflow & Cheatsheet

**Purpose:** Systematic approach to investigating Linux system compromises \
**Scope:** Detection through Root Cause Analysis

***

### Investigation Phases Overview

```bash
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   DETECTION &   │──▶│   EVIDENCE     │───▶│  LIVE SYSTEM    │
│  INITIAL TRIAGE │    │   COLLECTION    │    │    ANALYSIS     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                                            │
         ▼                                            ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FILESYSTEM   │◀───│  LOG ANALYSIS  │◀───│     MEMORY     │
│    ANALYSIS     │    │                 │    │   FORENSICS     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                                            │
         ▼                                            ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PERSISTENCE  │───▶│    TIMELINE     │───▶│   ROOT CAUSE   │
│   MECHANISMS    │    │    ANALYSIS     │    │    ANALYSIS     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

***

### Phase 1: Incident Detection & Initial Triage

#### 1.1 Detection Sources

**What triggered the investigation?**

<table><thead><tr><th width="183">Source</th><th width="354">Indicators</th><th>Priority</th></tr></thead><tbody><tr><td>EDR/XDR Alerts</td><td>Process anomalies, suspicious executions</td><td>High</td></tr><tr><td>SIEM Alerts</td><td>Log-based detections, correlation rules</td><td>High</td></tr><tr><td>Network IDS/IPS</td><td>C2 traffic, lateral movement</td><td>High</td></tr><tr><td>User Reports</td><td>Unusual system behavior</td><td>Medium</td></tr><tr><td>Threat Intelligence</td><td>IOC matches</td><td>Medium</td></tr><tr><td>Scheduled Scans</td><td>Malware detection, rootkit detection</td><td>Medium</td></tr></tbody></table>

#### 1.2 Initial Triage Questions

```bash
□ What is the scope? (Single host vs. multiple systems)
□ Is the system still actively compromised?
□ What is the business criticality of the affected system?
□ What data/services does this system host?
□ Network segment and exposure level?
□ When was the anomaly first detected?
□ Has containment been initiated?
```

#### 1.3 Rapid Triage Commands

**System Identity & Context**

```bash
# Hostname and system info
hostname && uname -a
cat /etc/os-release
hostnamectl

# System uptime and last reboot
uptime
last reboot | head -5
who -b
```

**Active User Sessions**

```bash
# Currently logged-in users
w
who -a
last -20

# Failed login attempts
lastb | head -20
grep "Failed password" /var/log/auth.log | tail -20
```

**Network Quick Check**

```bash
# Active connections
ss -tulpn
netstat -anp 2>/dev/null || ss -anp

# Established connections with process info
ss -tp state established

# Listening services
ss -tlnp
```

**Process Quick Check**

```bash
# Running processes
ps auxf
ps -eo pid,ppid,user,cmd --forest

# High CPU/Memory consumers
ps aux --sort=-%cpu | head -10
ps aux --sort=-%mem | head -10
```

#### 1.4 Triage Decision Matrix

<table><thead><tr><th>Finding</th><th width="166">Risk Level</th><th>Immediate Action</th></tr></thead><tbody><tr><td>Active C2 connection</td><td>Critical</td><td>Isolate network, preserve state</td></tr><tr><td>Cryptominer running</td><td>High</td><td>Document, consider isolation</td></tr><tr><td>Unauthorized SSH sessions</td><td>Critical</td><td>Identify source, isolate</td></tr><tr><td>Modified system binaries</td><td>Critical</td><td>Isolate, full forensic capture</td></tr><tr><td>Suspicious cron jobs</td><td>High</td><td>Document, continue investigation</td></tr><tr><td>Unknown listening ports</td><td>Medium</td><td>Identify process, assess risk</td></tr></tbody></table>

***

### Phase 2: Evidence Collection & Preservation

#### 2.1 Order of Volatility

Collect evidence in this order (most volatile first):

```bash
1. CPU registers, cache          (Seconds)
2. Memory (RAM)                  (Seconds-Minutes)
3. Network state                 (Seconds-Minutes)
4. Running processes             (Minutes)
5. Disk (filesystem)             (Hours-Days)
6. Remote logging/backups        (Days-Months)
```

#### 2.2 Live Evidence Collection Script

```bash
#!/bin/bash
# Linux DFIR Live Collection Script
# Run as root

CASE_ID="${1:-CASE_$(date +%Y%m%d_%H%M%S)}"
OUTDIR="/tmp/dfir_${CASE_ID}"
mkdir -p "$OUTDIR"

echo "[*] Starting collection for $CASE_ID at $(date)"
echo "[*] Output directory: $OUTDIR"

# System Information
echo "[+] Collecting system information..."
{
    echo "=== HOSTNAME ===" && hostname
    echo "=== UNAME ===" && uname -a
    echo "=== OS RELEASE ===" && cat /etc/os-release
    echo "=== UPTIME ===" && uptime
    echo "=== DATE/TIME ===" && date && timedatectl
} > "$OUTDIR/system_info.txt"

# User Information
echo "[+] Collecting user information..."
{
    echo "=== CURRENT USERS ===" && w
    echo "=== WHO -a ===" && who -a
    echo "=== LAST LOGINS ===" && last -100
    echo "=== LAST FAILED ===" && lastb 2>/dev/null | head -100
    echo "=== PASSWD FILE ===" && cat /etc/passwd
    echo "=== SHADOW PERMISSIONS ===" && ls -la /etc/shadow
    echo "=== GROUP FILE ===" && cat /etc/group
    echo "=== SUDOERS ===" && cat /etc/sudoers 2>/dev/null
    echo "=== SUDOERS.D ===" && ls -la /etc/sudoers.d/ 2>/dev/null
} > "$OUTDIR/user_info.txt"

# Process Information
echo "[+] Collecting process information..."
{
    echo "=== PS AUXF ===" && ps auxf
    echo "=== PS TREE ===" && ps -eo pid,ppid,user,uid,gid,tty,stat,start,time,cmd --forest
    echo "=== PSTREE ===" && pstree -p 2>/dev/null
} > "$OUTDIR/process_info.txt"

# Network Information
echo "[+] Collecting network information..."
{
    echo "=== NETSTAT/SS LISTENING ===" && ss -tulpn
    echo "=== NETSTAT/SS ALL ===" && ss -anp
    echo "=== ESTABLISHED CONNECTIONS ===" && ss -tp state established
    echo "=== ROUTING TABLE ===" && ip route
    echo "=== ARP CACHE ===" && ip neigh
    echo "=== INTERFACES ===" && ip addr
    echo "=== IPTABLES ===" && iptables -L -n -v 2>/dev/null
    echo "=== NFTABLES ===" && nft list ruleset 2>/dev/null
} > "$OUTDIR/network_info.txt"

# Open Files and Handles
echo "[+] Collecting open files..."
{
    echo "=== LSOF NETWORK ===" && lsof -i -n -P 2>/dev/null
    echo "=== LSOF ALL ===" && lsof 2>/dev/null | head -5000
} > "$OUTDIR/open_files.txt"

# Scheduled Tasks
echo "[+] Collecting scheduled tasks..."
{
    echo "=== SYSTEM CRONTAB ===" && cat /etc/crontab
    echo "=== CRON.D ===" && ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null
    echo "=== CRON.DAILY ===" && ls -la /etc/cron.daily/
    echo "=== CRON.HOURLY ===" && ls -la /etc/cron.hourly/
    echo "=== CRON.WEEKLY ===" && ls -la /etc/cron.weekly/
    echo "=== CRON.MONTHLY ===" && ls -la /etc/cron.monthly/
    echo "=== USER CRONTABS ===" 
    for user in $(cut -f1 -d: /etc/passwd); do
        echo "--- Crontab for $user ---"
        crontab -u $user -l 2>/dev/null
    done
    echo "=== SYSTEMD TIMERS ===" && systemctl list-timers --all
    echo "=== AT JOBS ===" && atq 2>/dev/null
} > "$OUTDIR/scheduled_tasks.txt"

# Services and Startup
echo "[+] Collecting service information..."
{
    echo "=== SYSTEMD SERVICES ===" && systemctl list-units --type=service --all
    echo "=== ENABLED SERVICES ===" && systemctl list-unit-files --type=service
    echo "=== RUNNING SERVICES ===" && systemctl list-units --type=service --state=running
    echo "=== INIT.D ===" && ls -la /etc/init.d/
    echo "=== RC.LOCAL ===" && cat /etc/rc.local 2>/dev/null
} > "$OUTDIR/services_info.txt"

# Kernel and Modules
echo "[+] Collecting kernel information..."
{
    echo "=== LOADED MODULES ===" && lsmod
    echo "=== KERNEL PARAMETERS ===" && sysctl -a 2>/dev/null
    echo "=== DMESG TAIL ===" && dmesg | tail -200
} > "$OUTDIR/kernel_info.txt"

# File System Information
echo "[+] Collecting filesystem information..."
{
    echo "=== MOUNTED FILESYSTEMS ===" && mount
    echo "=== FSTAB ===" && cat /etc/fstab
    echo "=== DISK USAGE ===" && df -h
    echo "=== BLOCK DEVICES ===" && lsblk
} > "$OUTDIR/filesystem_info.txt"

# Environment and Shell
echo "[+] Collecting environment information..."
{
    echo "=== ENVIRONMENT ===" && env
    echo "=== BASH HISTORY LOCATIONS ===" 
    find /home /root -name ".*history" -o -name ".*_history" 2>/dev/null
} > "$OUTDIR/environment_info.txt"

# Copy critical logs
echo "[+] Copying log files..."
mkdir -p "$OUTDIR/logs"
cp -r /var/log/auth.log* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/secure* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/syslog* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/messages* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/kern.log* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/cron* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/audit/* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/btmp* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/wtmp* "$OUTDIR/logs/" 2>/dev/null
cp -r /var/log/lastlog "$OUTDIR/logs/" 2>/dev/null

# SSH artifacts
echo "[+] Collecting SSH artifacts..."
mkdir -p "$OUTDIR/ssh"
cp -r /etc/ssh/* "$OUTDIR/ssh/" 2>/dev/null
find /home /root -name "authorized_keys" -exec cp {} "$OUTDIR/ssh/" \; 2>/dev/null
find /home /root -name "known_hosts" -exec cp {} "$OUTDIR/ssh/" \; 2>/dev/null

# Package integrity (if available)
echo "[+] Checking package integrity..."
{
    echo "=== RPM VERIFY ===" && rpm -Va 2>/dev/null | head -500
    echo "=== DPKG VERIFY ===" && dpkg --verify 2>/dev/null | head -500
    echo "=== DEBSUMS ===" && debsums -c 2>/dev/null | head -500
} > "$OUTDIR/package_integrity.txt"

# Create hashes
echo "[+] Creating file hashes..."
find "$OUTDIR" -type f -exec sha256sum {} \; > "$OUTDIR/collection_hashes.txt"

# Archive collection
echo "[+] Creating archive..."
tar -czf "/tmp/dfir_${CASE_ID}.tar.gz" -C /tmp "dfir_${CASE_ID}"

echo "[*] Collection complete: /tmp/dfir_${CASE_ID}.tar.gz"
echo "[*] SHA256: $(sha256sum /tmp/dfir_${CASE_ID}.tar.gz)"
```

#### 2.3 Memory Acquisition

**Using LiME (Linux Memory Extractor)**

```bash
# Install LiME
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src && make

# Acquire memory
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Alternative: AVML (Microsoft)
./avml /evidence/memory.lime
```

**Using /proc/kcore (Less Reliable)**

```bash
# Copy kernel memory (requires root)
dd if=/proc/kcore of=/evidence/kcore.img bs=1M
```

#### 2.4 Disk Imaging

**Full Disk Image**

```bash
# Using dd
dd if=/dev/sda of=/evidence/disk.img bs=64K conv=noerror,sync status=progress

# Using dc3dd (better for forensics)
dc3dd if=/dev/sda of=/evidence/disk.img hash=sha256 log=/evidence/disk.log

# Using ewfacquire (E01 format)
ewfacquire /dev/sda -t /evidence/disk -f encase6 -c best -S 4G
```

**Verify Image Integrity**

```bash
# Generate hash of source
sha256sum /dev/sda

# Generate hash of image
sha256sum /evidence/disk.img

# Compare hashes
```

***

### Phase 3: Live System Analysis

#### 3.1 Process Investigation

**Identify Suspicious Processes**

```bash
# Full process listing with hierarchy
ps auxf --width 300

# Process tree with PIDs
pstree -p -a

# Look for processes with deleted binaries
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Find processes running from /tmp, /dev/shm, or unusual locations
ls -la /proc/*/exe 2>/dev/null | grep -E "/(tmp|dev/shm|var/tmp)"

# Processes with no associated binary
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    if [ -z "$exe" ]; then
        echo "PID $pid has no exe link"
        cat /proc/$pid/comm 2>/dev/null
    fi
done
```

**Process Deep Dive**

```bash
# For a specific PID
PID=<suspicious_pid>

# Process details
cat /proc/$PID/status
cat /proc/$PID/cmdline | tr '\0' ' '; echo
cat /proc/$PID/environ | tr '\0' '\n'

# Executable path
ls -la /proc/$PID/exe

# Current working directory
ls -la /proc/$PID/cwd

# Open file descriptors
ls -la /proc/$PID/fd/

# Memory maps
cat /proc/$PID/maps

# Network connections for process
ls -la /proc/$PID/fd/ | grep socket
cat /proc/$PID/net/tcp
cat /proc/$PID/net/tcp6

# Process start time
stat /proc/$PID

# Dump process memory
gcore -o /evidence/process_$PID $PID
```

**What to Look For - Processes**

```bash
□ Processes running from /tmp, /dev/shm, /var/tmp
□ Processes with deleted executables
□ Unusual parent-child relationships
□ Processes running as root that shouldn't be
□ Encoded/obfuscated command lines
□ Processes with unusual network connections
□ High resource consumption anomalies
□ Processes mimicking legitimate names (e.g., "sshd " with trailing space)
□ Multiple instances of typically single processes
□ Processes started recently (correlate with incident timeline)
```

#### 3.2 Network Investigation

**Active Connections Analysis**

```bash
# All connections with process info
ss -anp | column -t

# TCP connections only
ss -tnp

# UDP connections
ss -unp

# Listening ports
ss -tlnp

# Connections to external IPs
ss -tnp | grep -v "127.0.0.1\|::1"

# Find connections by state
ss -t state established
ss -t state time-wait
ss -t state close-wait
```

**Network Configuration**

```bash
# DNS configuration
cat /etc/resolv.conf
cat /etc/hosts

# Network interfaces
ip addr
ip link

# Routing table
ip route
netstat -rn

# ARP cache
ip neigh
arp -a

# Firewall rules
iptables -L -n -v --line-numbers
iptables -t nat -L -n -v
nft list ruleset 2>/dev/null
```

**What to Look For - Network**

```bash
□ Connections to known malicious IPs/domains
□ Connections on unusual ports (especially high ports)
□ Large data transfers (potential exfiltration)
□ Beaconing patterns (regular interval connections)
□ Connections from unexpected processes
□ DNS over HTTPS/TLS or non-standard DNS
□ Tor or proxy connections
□ Reverse shells (check for established connections from high ports)
□ Modified /etc/hosts (for C2 or DNS hijacking)
□ Unauthorised VPN or tunnel configurations
```

#### 3.3 User Account Investigation

**User Account Analysis**

```bash
# List all users
cat /etc/passwd | column -t -s:

# Find users with UID 0 (root equivalent)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Find users with login shells
grep -v "nologin\|false" /etc/passwd

# Recently modified password entries
ls -la /etc/passwd /etc/shadow /etc/group

# Find empty password accounts
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow

# Sudoers configuration
cat /etc/sudoers
cat /etc/sudoers.d/*

# User groups
cat /etc/group | grep -E "sudo|wheel|admin"
```

**SSH Key Investigation**

```bash
# Find all authorized_keys files
find / -name "authorized_keys" -type f 2>/dev/null

# Check each user's SSH directory
for home in /home/* /root; do
    echo "=== $home ==="
    ls -la $home/.ssh/ 2>/dev/null
    cat $home/.ssh/authorized_keys 2>/dev/null
    cat $home/.ssh/known_hosts 2>/dev/null
done

# Look for unusual SSH configurations
cat /etc/ssh/sshd_config | grep -v "^#\|^$"

# Check for SSH keys in unusual locations
find /tmp /var/tmp /dev/shm -name "*.pub" -o -name "id_rsa*" 2>/dev/null
```

**What to Look For - Users**

```bash
□ New user accounts (compare with baseline)
□ Users with UID 0 besides root
□ Users added to sudo/wheel groups
□ Unauthorised SSH keys in authorized_keys
□ Modified /etc/passwd or /etc/shadow
□ Shell history deletions or modifications
□ .bashrc/.profile modifications for persistence
□ User accounts with no password
□ Service accounts with login shells
□ Recently changed passwords
```

***

### Phase 4: Filesystem Analysis

#### 4.1 File Timeline Analysis

**Recently Modified Files**

```bash
# Files modified in last 24 hours
find / -mtime -1 -type f 2>/dev/null | grep -v proc

# Files modified in last hour
find / -mmin -60 -type f 2>/dev/null | grep -v proc

# Files accessed recently
find / -atime -1 -type f 2>/dev/null | grep -v proc

# Files with recent metadata changes
find / -ctime -1 -type f 2>/dev/null | grep -v proc

# Combine with specific directories
find /tmp /var/tmp /dev/shm /home /root /etc -mtime -7 -type f 2>/dev/null
```

**SUID/SGID File Analysis**

```bash
# Find all SUID files
find / -perm -4000 -type f 2>/dev/null

# Find all SGID files
find / -perm -2000 -type f 2>/dev/null

# Find world-writable SUID/SGID files
find / -perm -4000 -o -perm -2000 -type f -perm -o+w 2>/dev/null

# Compare against known good baseline
# Baseline creation (on clean system)
find / -perm -4000 -type f 2>/dev/null > /baseline/suid_baseline.txt

# Comparison
diff <(find / -perm -4000 -type f 2>/dev/null | sort) \
     <(sort /baseline/suid_baseline.txt)
```

#### 4.2 Suspicious File Locations

```bash
# World-writable directories (common malware staging)
find / -type d -perm -0002 2>/dev/null

# Check typical malware locations
for dir in /tmp /var/tmp /dev/shm /run/shm; do
    echo "=== $dir ==="
    ls -la $dir
    find $dir -type f -exec file {} \;
done

# Hidden files in web directories
find /var/www -name ".*" -type f 2>/dev/null

# Files with spaces or dots in names (hiding technique)
find / -name ".* *" -o -name ".. " -o -name ". " 2>/dev/null

# Executable files in /tmp
find /tmp -type f -executable 2>/dev/null

# Files owned by nobody or nogroup
find / -nouser -o -nogroup 2>/dev/null
```

#### 4.3 Binary Analysis

**Quick Binary Triage**

{% code overflow="wrap" %}
```bash
# File type
file /path/to/suspicious

# Strings extraction
strings /path/to/suspicious | head -100
strings -el /path/to/suspicious | head -100  # Little-endian

# Look for specific indicators in strings
strings /path/to/suspicious | grep -iE "http|https|ftp|ssh|password|shell|exec|socket|connect"

# Hash the file
sha256sum /path/to/suspicious
md5sum /path/to/suspicious

# Check VirusTotal (manual or API)
# https://www.virustotal.com/gui/search/<hash>

# ELF analysis
readelf -h /path/to/suspicious
readelf -S /path/to/suspicious
objdump -d /path/to/suspicious | head -100
```
{% endcode %}

**Package Integrity Verification**

```bash
# Debian/Ubuntu
debsums -c  # Check all packages
debsums -s  # Silent, only errors
dpkg --verify

# RHEL/CentOS
rpm -Va  # Verify all packages
rpm -Vf /path/to/file  # Verify specific file

# Interpretation of rpm -Va output:
# S - Size differs
# M - Mode differs
# 5 - MD5 sum differs
# D - Device major/minor number mismatch
# L - readLink path mismatch
# U - User ownership differs
# G - Group ownership differs
# T - mTime differs
```

#### 4.4 Web Shell Detection

{% code overflow="wrap" %}
```bash
# Search for common web shell indicators
find /var/www -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" \) \
    -exec grep -l -E "(eval|base64_decode|system|exec|shell_exec|passthru|assert|preg_replace.*\/e)" {} \; 2>/dev/null

# Recently modified web files
find /var/www -type f -mtime -7 2>/dev/null

# PHP files with suspicious functions
grep -r --include="*.php" -E "(eval\s*\(|base64_decode|gzinflate|str_rot13|shell_exec|system\s*\(|passthru|assert\s*\()" /var/www/ 2>/dev/null

# Look for files with many obfuscated variables
find /var/www -name "*.php" -exec grep -l '\$[a-zA-Z]\{1\}\[' {} \; 2>/dev/null

# Check web server access logs for suspicious activity
grep -E "(cmd=|passthru|shell|system\(|wget|curl|chmod|eval)" /var/log/apache2/access.log 2>/dev/null
grep -E "(cmd=|passthru|shell|system\(|wget|curl|chmod|eval)" /var/log/nginx/access.log 2>/dev/null
```
{% endcode %}

#### 4.5 What to Look For - Filesystem

```bash
□ New/modified files in system directories
□ Executables in /tmp, /var/tmp, /dev/shm
□ Hidden files (especially ..files or files starting with space)
□ Modified SUID/SGID binaries
□ New SUID/SGID files
□ Package integrity failures
□ Web shells in web directories
□ Modified system binaries (ls, ps, netstat, etc.)
□ Unusual file permissions
□ Timestamp anomalies (MAC times)
□ Files with misleading extensions
□ Large files in unexpected locations
□ Encrypted/encoded files
□ Files named to mimic legitimate system files
```

***

### Phase 5: Log Analysis

#### 5.1 Key Log Locations

| Log File                   | Content                        | Distribution     |
| -------------------------- | ------------------------------ | ---------------- |
| `/var/log/auth.log`        | Authentication events          | Debian/Ubuntu    |
| `/var/log/secure`          | Authentication events          | RHEL/CentOS      |
| `/var/log/syslog`          | General system messages        | Debian/Ubuntu    |
| `/var/log/messages`        | General system messages        | RHEL/CentOS      |
| `/var/log/kern.log`        | Kernel messages                | All              |
| `/var/log/audit/audit.log` | Auditd events                  | All (if enabled) |
| `/var/log/cron`            | Cron job execution             | All              |
| `/var/log/wtmp`            | Login records (binary)         | All              |
| `/var/log/btmp`            | Failed login attempts (binary) | All              |
| `/var/log/lastlog`         | Last login info (binary)       | All              |
| `/var/log/faillog`         | Failed login attempts          | All              |
| `~/.bash_history`          | User command history           | All              |

#### 5.2 Authentication Log Analysis

**SSH Authentication Events**

{% code overflow="wrap" %}
```bash
# Successful SSH logins
grep "Accepted" /var/log/auth.log
grep "Accepted" /var/log/secure

# Failed SSH logins
grep "Failed password" /var/log/auth.log
grep "Failed password" /var/log/secure

# SSH key authentication
grep "Accepted publickey" /var/log/auth.log

# Invalid users
grep "Invalid user" /var/log/auth.log

# SSH session events
grep -E "session opened|session closed" /var/log/auth.log

# Connection attempts by IP
grep "sshd" /var/log/auth.log | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -rn | head -20
```
{% endcode %}

**Sudo/Privilege Escalation Events**

```bash
# Sudo commands executed
grep "sudo:" /var/log/auth.log

# Successful sudo
grep "sudo:.*COMMAND" /var/log/auth.log

# Failed sudo attempts
grep "sudo:.*authentication failure" /var/log/auth.log
grep "sudo:.*NOT in sudoers" /var/log/auth.log

# Su command usage
grep "su\[" /var/log/auth.log
grep "su:" /var/log/secure
```

**User Account Changes**

```bash
# User additions
grep -E "useradd|adduser" /var/log/auth.log

# Password changes
grep "passwd" /var/log/auth.log

# User modifications
grep "usermod" /var/log/auth.log

# Group changes
grep -E "groupadd|gpasswd" /var/log/auth.log
```

#### 5.3 System Log Analysis

**System Events**

```bash
# Service start/stop
grep -E "systemd.*Started|systemd.*Stopped" /var/log/syslog

# Cron job executions
grep "CRON" /var/log/syslog
cat /var/log/cron

# Kernel messages
grep -E "segfault|oom-killer|kernel:" /var/log/kern.log

# System boot times
grep "Linux version" /var/log/kern.log
journalctl --list-boots
```

**Audit Log Analysis (auditd)**

```bash
# Search audit logs
ausearch -i -k <key>
ausearch -m USER_LOGIN
ausearch -m EXECVE
ausearch -ua root
ausearch -f /etc/passwd

# Generate report
aureport --summary
aureport --login
aureport --auth
aureport --file
aureport --executable
aureport --anomaly

# Failed events
aureport --failed

# Specific time range
ausearch --start today --end now
ausearch --start "12/01/2024 00:00:00" --end "12/31/2024 23:59:59"
```

#### 5.4 Binary Log Analysis

**wtmp/btmp Analysis**

```bash
# Login history
last -f /var/log/wtmp
last -f /var/log/wtmp -20

# Failed logins
lastb -f /var/log/btmp
lastb -f /var/log/btmp -20

# Last login per user
lastlog

# Extended last output
last -aix
```

#### 5.5 Shell History Analysis

{% code overflow="wrap" %}
```bash
# Find all history files
find /home /root -name ".*_history" -o -name ".*history" 2>/dev/null

# Analyze bash history
for hist in /home/*/.bash_history /root/.bash_history; do
    echo "=== $hist ==="
    if [ -f "$hist" ]; then
        cat "$hist" | grep -E "wget|curl|nc|ncat|python|perl|ruby|base64|chmod|chown|>/dev/null|2>&1"
    fi
done

# Look for history clearing
grep -r "history -c\|HISTSIZE=0\|unset HISTFILE\|export HISTFILE=/dev/null" /home /root 2>/dev/null
```
{% endcode %}

#### 5.6 Journald Analysis

```bash
# Recent entries
journalctl -n 100

# Entries since boot
journalctl -b

# Specific time range
journalctl --since "2024-12-01" --until "2024-12-31"
journalctl --since "1 hour ago"

# Specific unit
journalctl -u sshd
journalctl -u cron

# Kernel messages
journalctl -k

# By priority
journalctl -p err  # Error and above
journalctl -p warning

# Specific PID
journalctl _PID=<pid>

# Follow live
journalctl -f

# Output formats
journalctl -o json-pretty
journalctl -o verbose
```

#### 5.7 What to Look For - Logs

```bash
□ Authentication anomalies (unusual times, IPs, users)
□ Brute force patterns (multiple failed attempts)
□ Privilege escalation events
□ New user creation
□ Service modifications
□ Cron job changes
□ Log gaps or deletions (signs of tampering)
□ Unusual command execution
□ History file modifications
□ Kernel errors or anomalies
□ Time skew events
□ Failed audit events
□ Unauthorised SSH key usage
□ Lateral movement indicators
```

***

### Phase 6: Memory Forensics

#### 6.1 Memory Acquisition

**LiME Method**

```bash
# Build LiME for current kernel
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make

# Acquire memory
sudo insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Or raw format
sudo insmod lime-$(uname -r).ko "path=/evidence/memory.raw format=raw"
```

**AVML Method**

```bash
# Microsoft's AVML tool
./avml /evidence/memory.lime

# With compression
./avml --compress /evidence/memory.lime.zst
```

#### 6.2 Memory Analysis with Volatility 3

**Setup and Profile**

```bash
# Install Volatility 3
pip3 install volatility3

# Run with auto-detection
vol -f /evidence/memory.lime <plugin>

# Specify OS
vol -f /evidence/memory.lime linux.<plugin>
```

**Process Analysis**

```bash
# List processes
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree
vol -f memory.lime linux.psaux

# Hidden processes
vol -f memory.lime linux.psscan

# Process environment variables
vol -f memory.lime linux.envars --pid <pid>

# Process maps
vol -f memory.lime linux.proc.maps --pid <pid>
```

**Network Analysis**

```bash
# Network connections
vol -f memory.lime linux.netstat
vol -f memory.lime linux.sockstat
```

**Module Analysis**

```bash
# Loaded kernel modules
vol -f memory.lime linux.lsmod

# Hidden modules
vol -f memory.lime linux.check_modules
```

**File Analysis**

```bash
# Open files
vol -f memory.lime linux.lsof

# File cache
vol -f memory.lime linux.files

# Bash history from memory
vol -f memory.lime linux.bash
```

**Rootkit Detection**

```bash
# Check syscall table
vol -f memory.lime linux.check_syscall

# Check IDT
vol -f memory.lime linux.check_idt

# Check kernel functions
vol -f memory.lime linux.check_modules
```

#### 6.3 What to Look For - Memory

```bash
□ Processes not visible in live system (hidden)
□ Injected code in legitimate processes
□ Network connections not in netstat
□ Hidden kernel modules
□ Hooked system calls
□ Credential artifacts
□ Encryption keys
□ Command history not on disk
□ Malicious scripts in memory
□ Process hollowing indicators
□ Deleted file contents
```

***

### Phase 7: Persistence Mechanism Analysis

#### 7.1 Cron-Based Persistence

{% code overflow="wrap" %}
```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*

# Periodic cron directories
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# User crontabs
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u $user 2>/dev/null && echo "^^^ $user ^^^"
done

# Crontab spool
ls -la /var/spool/cron/crontabs/
cat /var/spool/cron/crontabs/* 2>/dev/null

# Anacron
cat /etc/anacrontab
ls -la /var/spool/anacron/

# Check for malicious cron syntax
grep -rE "(wget|curl|nc|python|perl|ruby|sh -c|bash -c)" /etc/cron* /var/spool/cron 2>/dev/null
```
{% endcode %}

#### 7.2 Systemd Persistence

{% code overflow="wrap" %}
```bash
# System services
ls -la /etc/systemd/system/
ls -la /lib/systemd/system/
ls -la /usr/lib/systemd/system/

# User services
ls -la /home/*/.config/systemd/user/ 2>/dev/null
ls -la /root/.config/systemd/user/ 2>/dev/null

# Enabled services
systemctl list-unit-files --type=service | grep enabled

# Recently modified unit files
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -mtime -30 2>/dev/null

# Systemd timers
systemctl list-timers --all
ls -la /etc/systemd/system/*.timer

# Generator scripts
ls -la /etc/systemd/system-generators/
ls -la /usr/lib/systemd/system-generators/

# Check for suspicious service content
grep -rE "(ExecStart|ExecStartPre|ExecStartPost).*(/tmp|/var/tmp|/dev/shm|wget|curl|nc|python|perl)" /etc/systemd/ /lib/systemd/ 2>/dev/null
```
{% endcode %}

#### 7.3 Init Script Persistence

```bash
# SysV init scripts
ls -la /etc/init.d/
ls -la /etc/rc.d/init.d/ 2>/dev/null

# Runlevel links
ls -la /etc/rc*.d/

# rc.local
cat /etc/rc.local
cat /etc/rc.d/rc.local 2>/dev/null

# Init configuration
cat /etc/inittab 2>/dev/null
```

#### 7.4 Shell Configuration Persistence

{% code overflow="wrap" %}
```bash
# System-wide profiles
cat /etc/profile
cat /etc/profile.d/*
cat /etc/bash.bashrc
cat /etc/bashrc 2>/dev/null

# User profiles
for home in /home/* /root; do
    echo "=== $home ==="
    cat $home/.bashrc 2>/dev/null
    cat $home/.bash_profile 2>/dev/null
    cat $home/.profile 2>/dev/null
    cat $home/.bash_login 2>/dev/null
    cat $home/.bash_logout 2>/dev/null
done

# Zsh profiles
cat /etc/zshrc 2>/dev/null
cat /etc/zsh/* 2>/dev/null
for home in /home/* /root; do
    cat $home/.zshrc 2>/dev/null
done

# Look for suspicious additions
grep -rE "(wget|curl|nc|python|perl|ruby|/tmp|/dev/shm)" /etc/profile* /etc/bash* /home/*/.bash* /root/.bash* 2>/dev/null
```
{% endcode %}

#### 7.5 SSH Persistence

{% code overflow="wrap" %}
```bash
# Authorized keys (backdoor access)
find / -name "authorized_keys" -type f 2>/dev/null -exec cat {} \;

# SSH daemon configuration
cat /etc/ssh/sshd_config
ls -la /etc/ssh/sshd_config.d/

# SSH client configuration
cat /etc/ssh/ssh_config
cat /home/*/.ssh/config 2>/dev/null

# SSH host keys (check for changes)
ls -la /etc/ssh/ssh_host_*

# Check for SSH port forwarding persistence
grep -E "^PermitRootLogin|^PubkeyAuthentication|^PasswordAuthentication|^AllowUsers|^AllowGroups|^GatewayPorts" /etc/ssh/sshd_config
```
{% endcode %}

#### 7.6 Library Preloading Persistence

```bash
# LD_PRELOAD environment
env | grep LD_PRELOAD
grep LD_PRELOAD /etc/environment

# Preload configuration
cat /etc/ld.so.preload
ls -la /etc/ld.so.conf.d/

# Check for malicious shared libraries
ldconfig -p | head -50
ldd /bin/ls  # Check for unexpected libraries
```

#### 7.7 Kernel Module Persistence

```bash
# Currently loaded modules
lsmod

# Module auto-load configuration
cat /etc/modules
cat /etc/modules-load.d/*
cat /etc/modprobe.d/*

# Module locations
ls -la /lib/modules/$(uname -r)/kernel/
ls -la /lib/modules/$(uname -r)/extra/ 2>/dev/null

# Recently modified modules
find /lib/modules -name "*.ko" -mtime -30 2>/dev/null
```

#### 7.8 Additional Persistence Locations

```bash
# At jobs
atq
at -c <job_number>
ls -la /var/spool/at/

# Message of the day (can run scripts)
cat /etc/motd
ls -la /etc/update-motd.d/

# XDG autostart
ls -la /etc/xdg/autostart/
ls -la /home/*/.config/autostart/ 2>/dev/null

# DBUS services
ls -la /usr/share/dbus-1/services/
ls -la /usr/share/dbus-1/system-services/

# Udev rules
ls -la /etc/udev/rules.d/
ls -la /lib/udev/rules.d/

# Polkit rules
ls -la /etc/polkit-1/rules.d/
ls -la /usr/share/polkit-1/rules.d/

# Git hooks (if git repos exist)
find / -name ".git" -type d 2>/dev/null -exec ls -la {}/hooks/ \;

# APT hooks (Debian/Ubuntu)
ls -la /etc/apt/apt.conf.d/
cat /etc/apt/apt.conf.d/* | grep -E "Pre-Invoke|Post-Invoke"

# YUM/DNF hooks (RHEL/CentOS)
ls -la /etc/yum/pluginconf.d/
ls -la /etc/dnf/plugins/
```

#### 7.9 Persistence Detection Summary

| Location             | Check Command                              | Risk Level |
| -------------------- | ------------------------------------------ | ---------- |
| Crontabs             | `crontab -l; cat /etc/crontab`             | High       |
| Systemd services     | `systemctl list-unit-files --type=service` | High       |
| SSH authorized\_keys | `find / -name authorized_keys`             | Critical   |
| Shell profiles       | `cat ~/.bashrc ~/.profile`                 | High       |
| LD\_PRELOAD          | `cat /etc/ld.so.preload`                   | Critical   |
| Kernel modules       | `lsmod; cat /etc/modules`                  | Critical   |
| Init scripts         | `ls /etc/init.d/`                          | Medium     |
| At jobs              | `atq`                                      | Medium     |
| Systemd timers       | `systemctl list-timers`                    | High       |

***

### Phase 8: Timeline Analysis

#### 8.1 Timeline Generation

**Using find for Timeline Data**

```bash
# Create timeline of file modifications
find / -type f -printf "%T+ %p\n" 2>/dev/null | sort > /evidence/timeline_mtime.txt

# Create timeline including access times
find / -type f -printf "%A+ ACCESS %p\n" 2>/dev/null >> /evidence/timeline.txt
find / -type f -printf "%T+ MODIFY %p\n" 2>/dev/null >> /evidence/timeline.txt
find / -type f -printf "%C+ CHANGE %p\n" 2>/dev/null >> /evidence/timeline.txt
sort /evidence/timeline.txt > /evidence/timeline_sorted.txt

# Focused timeline (exclude proc, sys, dev)
find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
    -type f -printf "%T+ MODIFY %p\n" 2>/dev/null | sort > /evidence/timeline_focused.txt
```

**Using Plaso/log2timeline**

```bash
# Extract timeline from disk image
log2timeline.py --storage-file timeline.plaso /evidence/disk.img

# Process collected artifacts directory
log2timeline.py --storage-file timeline.plaso /evidence/collection/

# Generate timeline output
psort.py -w timeline.csv timeline.plaso

# Filter by time range
psort.py -w timeline_filtered.csv timeline.plaso \
    "date > '2024-12-01 00:00:00' AND date < '2024-12-31 23:59:59'"

# Generate super timeline
psort.py -w supertimeline.csv timeline.plaso -o l2tcsv
```

#### 8.2 Timeline Correlation

**Identify Key Events**

```bash
# Focus on suspicious directories
grep -E "/(tmp|var/tmp|dev/shm|home)" timeline_sorted.txt | head -100

# Filter by specific time window (adjust dates)
awk '$1 >= "2024-12-01" && $1 <= "2024-12-31"' timeline_sorted.txt

# Correlate with known compromise time
COMPROMISE_TIME="2024-12-15"
grep "$COMPROMISE_TIME" timeline_sorted.txt

# Find files created/modified around incident time
grep "2024-12-15" timeline_sorted.txt | grep -E "\.(sh|py|pl|elf|bin)$"
```

#### 8.3 Timeline Analysis Focus Areas

```bash
1. INITIAL ACCESS WINDOW
   □ First signs of unauthorised access
   □ Authentication events
   □ New file creations in staging areas
   □ Network connection artifacts

2. EXECUTION PHASE
   □ New executable files
   □ Script creations/modifications
   □ Process execution artifacts
   □ Command history entries

3. PERSISTENCE ESTABLISHMENT
   □ Cron job modifications
   □ Service file changes
   □ SSH key additions
   □ Profile script modifications

4. LATERAL MOVEMENT
   □ SSH connections to other hosts
   □ New authorized_keys entries
   □ Network configuration changes

5. DATA STAGING/EXFILTRATION
   □ Archive file creation
   □ Large file modifications
   □ Unusual data access patterns
```

***

### Phase 9: Root Cause Analysis

#### 9.1 Attack Vector Identification

**Common Initial Access Vectors**

<table><thead><tr><th width="214">Vector</th><th width="192">Evidence Sources</th><th>Key Indicators</th></tr></thead><tbody><tr><td>SSH Brute Force</td><td>auth.log, btmp</td><td>Multiple failed attempts, eventual success</td></tr><tr><td>SSH Key Compromise</td><td>authorized_keys</td><td>Unauthorized key, timeline analysis</td></tr><tr><td>Web Application Exploit</td><td>Web logs, webshells</td><td>POST requests, new files in webroot</td></tr><tr><td>Supply Chain</td><td>Package logs</td><td>Modified packages, unusual updates</td></tr><tr><td>Credential Theft</td><td>auth.log</td><td>Login from unusual IP/time</td></tr><tr><td>Vulnerable Service</td><td>Service logs</td><td>Exploitation patterns, crashes</td></tr></tbody></table>

**Investigation Checklist**

```bash
□ What was the first malicious activity? (Timeline analysis)
□ What service/application was exploited?
□ Was it an authentication bypass or an exploitation?
□ Were credentials compromised? How?
□ Was there a vulnerability? (CVE identification)
□ Were patches available but not applied?
□ Was MFA in place and bypassed?
```

#### 9.2 Vulnerability Assessment

```bash
# Check system patch level
cat /etc/os-release
uname -r

# Debian/Ubuntu
apt list --upgradable
cat /var/log/apt/history.log | tail -100

# RHEL/CentOS
yum history
yum check-update
cat /var/log/yum.log | tail -100

# Check for known vulnerabilities
# Look up kernel version against CVE databases
# Check installed package versions against CVE advisories

# Web server version
apache2 -v 2>/dev/null || httpd -v 2>/dev/null
nginx -v 2>/dev/null

# Database versions
mysql --version 2>/dev/null
psql --version 2>/dev/null
```

#### 9.3 Attack Reconstruction

**Build Attack Narrative**

```bash
1. RECONNAISSANCE
   - Port scans detected?
   - Web scanning activity?
   - User enumeration attempts?

2. INITIAL COMPROMISE
   - Exact time of first access
   - Method of entry
   - Initial foothold location

3. POST-EXPLOITATION
   - Privilege escalation path
   - Tools deployed
   - Persistence mechanisms

4. LATERAL MOVEMENT
   - Other systems accessed
   - Methods used (SSH, remote execution)
   - Credential harvesting

5. OBJECTIVE COMPLETION
   - Data accessed/stolen
   - Systems damaged
   - Cryptomining/botnet activity

6. COVERING TRACKS
   - Log tampering evidence
   - File timestamp manipulation
   - History clearing
```

#### 9.4 Impact Assessment

```bash
□ CONFIDENTIALITY IMPACT
  - What data was accessed?
  - Was data exfiltrated?
  - Sensitive files read?

□ INTEGRITY IMPACT
  - Systems modified?
  - Data altered?
  - Configurations changed?
  - Malware installed?

□ AVAILABILITY IMPACT
  - Services disrupted?
  - Data destroyed?
  - Ransomware deployed?
  - System resources consumed?

□ SCOPE
  - Number of systems affected
  - Network segments compromised
  - User accounts compromised
  - Duration of compromise
```

#### 9.5 Root Cause Categories

<table><thead><tr><th width="147">Category</th><th width="267">Examples</th><th>Remediation Focus</th></tr></thead><tbody><tr><td>Vulnerability</td><td>Unpatched software, zero-day</td><td>Patch management, WAF</td></tr><tr><td>Configuration</td><td>Default credentials, open ports</td><td>Hardening, CIS benchmarks</td></tr><tr><td>Credential</td><td>Weak passwords, reused creds</td><td>MFA, password policy</td></tr><tr><td>Human</td><td>Phishing, social engineering</td><td>Security awareness</td></tr><tr><td>Supply Chain</td><td>Compromised package, update</td><td>Vendor management, integrity checks</td></tr><tr><td>Insider</td><td>Malicious employee</td><td>Access controls, monitoring</td></tr></tbody></table>

***

### Phase 10: Containment & Remediation Recommendations

#### 10.1 Immediate Containment Actions

```bash
□ Network isolation (if not already done)
□ Disable compromised accounts
□ Remove unauthorised SSH keys
□ Stop malicious processes
□ Block C2 infrastructure at firewall
□ Preserve evidence before remediation
```

#### 10.2 Remediation Checklist

```bash
□ CREDENTIALS
  - Reset all passwords on affected systems
  - Rotate SSH keys
  - Revoke and reissue API keys/tokens
  - Reset service account credentials

□ ACCESS CONTROLS
  - Remove unauthorised users
  - Audit sudo/wheel group membership
  - Review and update firewall rules
  - Implement/enforce MFA

□ PERSISTENCE REMOVAL
  - Remove malicious cron jobs
  - Delete malicious systemd services
  - Clean shell profiles
  - Remove unauthorised SSH keys
  - Unload malicious kernel modules
  - Delete LD_PRELOAD entries

□ SYSTEM HARDENING
  - Apply all security patches
  - Disable unnecessary services
  - Implement CIS benchmarks
  - Enable and configure auditd
  - Configure centralised logging

□ MONITORING ENHANCEMENT
  - Deploy/tune EDR solution
  - Implement file integrity monitoring
  - Enable comprehensive logging
  - Set up alerting for IOCs
```

#### 10.3 Indicators of Compromise (IOC) Documentation

### IOC Summary Template

#### File Indicators

| Type     | Value | Context              |
| -------- | ----- | -------------------- |
| SHA256   |       | Malicious binary     |
| Filename |       | Dropped file         |
| Path     |       | Persistence location |

#### Network Indicators

<table><thead><tr><th width="154">Type</th><th width="185">Value</th><th>Context</th></tr></thead><tbody><tr><td>IP</td><td></td><td>C2 server</td></tr><tr><td>Domain</td><td></td><td>Malware download</td></tr><tr><td>Port</td><td></td><td>Backdoor listener</td></tr></tbody></table>

#### Host Indicators

<table><thead><tr><th width="145">Type</th><th width="207">Value</th><th>Context</th></tr></thead><tbody><tr><td>Username</td><td></td><td>Created by attacker</td></tr><tr><td>Process</td><td></td><td>Malicious process</td></tr><tr><td>Service</td><td></td><td>Persistence mechanism</td></tr></tbody></table>

#### Behavioural Indicators

* Encoded PowerShell/Python execution
* Cron job running from /tmp
* SSH connections at unusual hours
* Large outbound data transfers

***

### Quick Reference: Essential Commands

#### System Overview

```bash
uname -a && hostname && id && date
uptime && who && w
```

#### Process Hunting

```bash
ps auxf | grep -v "^\[" | less
ls -la /proc/*/exe 2>/dev/null | grep -E "deleted|tmp|shm"
```

#### Network Hunting

```bash
ss -anp | grep ESTAB
ss -tlnp
```

#### File Hunting

```bash
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
find / -mtime -1 -type f 2>/dev/null | grep -v proc
```

#### Log Hunting

```bash
grep -E "Failed|Invalid|error|warning" /var/log/auth.log | tail -50
last -20
lastb -20 2>/dev/null
```

#### Persistence Hunting

```bash
crontab -l; cat /etc/crontab; ls /etc/cron.*
systemctl list-unit-files --type=service | grep enabled
find / -name authorized_keys 2>/dev/null
cat /etc/ld.so.preload
```

***

### Appendix A: Tool Installation

#### Essential DFIR Tools

```bash
# Debian/Ubuntu
apt update && apt install -y \
    sleuthkit \
    autopsy \
    volatility3 \
    yara \
    foremost \
    scalpel \
    dc3dd \
    ewf-tools \
    libewf-dev \
    rkhunter \
    chkrootkit \
    auditd \
    sysstat \
    lsof \
    htop \
    iotop \
    net-tools \
    tcpdump \
    tshark

# RHEL/CentOS
yum install -y \
    sleuthkit \
    yara \
    audit \
    sysstat \
    lsof \
    htop \
    iotop \
    net-tools \
    tcpdump \
    wireshark-cli
```

#### LiME Installation

```bash
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
# Copy lime-*.ko to target system
```

#### Volatility 3 Installation

```bash
pip3 install volatility3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
```

***

### Appendix B: Investigation Documentation Template

## Linux DFIR Investigation Report

### Case Information

* Case ID:
* Investigator:
* Date Started:
* Date Completed:
* System(s) Investigated:

### Executive Summary

\[Brief overview of incident and findings]

### Timeline of Events

| Date/Time | Event | Source | Notes |
| --------- | ----- | ------ | ----- |
|           |       |        |       |

### Technical Findings

#### Initial Access

* Vector:
* Timestamp:
* Evidence:

#### Persistence Mechanisms

* [ ] Mechanism 1
* [ ] Mechanism 2

#### Lateral Movement

* Systems accessed:
* Methods used:

#### Data Impact

* Data accessed:
* Data exfiltrated:

### Indicators of Compromise

\[IOC table]

### Root Cause Analysis

\[Detailed analysis]

### Recommendations

1.
2.
3.

### Evidence Inventory

| Item | Description | Hash | Location |
| ---- | ----------- | ---- | -------- |
|      |             |      |          |

### Appendices

* Raw evidence files
* Full command outputs
* Screenshots

***
