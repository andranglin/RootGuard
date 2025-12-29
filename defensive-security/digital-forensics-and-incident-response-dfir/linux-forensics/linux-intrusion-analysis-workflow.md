# Linux Intrusion Analysis Workflow

### Overview

This workflow provides a structured methodology for investigating Linux system compromises. Commands can be executed during live response or adapted for post-compromise disk analysis by prepending the mount path (e.g., `cat /media/compromised_disk/var/log/auth.log`).

**Investigation Phases:**

1. Preparation & Scoping
2. Live Response & Triage
3. Evidence Collection
4. Analysis & Investigation
5. Remediation & Reporting

***

### Phase 1: Preparation & Scoping

#### Initial Assessment Questions

Before beginning technical investigation, establish:

* What triggered the investigation? (Alert, user report, external notification)
* What is the suspected timeframe of compromise?
* What is the system's role? (Web server, database, workstation, etc.)
* What level of access does the attacker potentially have?
* Are there compliance/legal requirements for evidence handling?

#### Documentation Setup

```bash
# Create investigation directory structure
mkdir -p ~/investigation/{live_response,disk_images,memory_dumps,timeline,reports}
CASE_ID="CASE-$(date +%Y%m%d-%H%M)"
LOG_FILE=~/investigation/reports/${CASE_ID}-investigation.log

# Start logging all commands
script -a $LOG_FILE
```

***

### Phase 2: Live Response & Triage

**CRITICAL**: Execute live response commands before any remediation. Volatile data disappears on reboot or process termination.

#### 2.1 System Information Collection

**General System Information**

```bash
# Hostname and OS information
hostname
uname -a
cat /etc/os-release
cat /etc/issue

# System uptime and current time (for timeline correlation)
uptime
date
timedatectl

# Hardware information
lscpu
free -h
df -h
```

**Environment and Initialisation**

```bash
# Environment variables (may reveal attacker modifications)
env
printenv

# Shell configuration files (common persistence locations)
cat /etc/profile
cat /etc/bash.bashrc
cat ~/.bashrc
cat ~/.bash_profile
cat ~/.profile

# Startup programs
ls -la /etc/init.d/
systemctl list-unit-files --type=service --state=enabled
```

#### 2.2 Network Connections Analysis

**Active Connections**

```bash
# All network connections with process info
ss -tulpan
netstat -tulpan

# Established connections only (high priority for C2 detection)
ss -tan state established
netstat -tan | grep ESTABLISHED

# Listening services
ss -tlnp
netstat -tlnp

# Connections by process
lsof -i -P -n
```

**Network Configuration**

```bash
# Interface configuration
ip addr show
ifconfig -a

# Routing table
ip route show
route -n

# ARP cache (lateral movement indicators)
arp -a
ip neigh show

# DNS configuration
cat /etc/resolv.conf
cat /etc/hosts

# Firewall rules
iptables -L -n -v
iptables -t nat -L -n -v
ip6tables -L -n -v
ufw status verbose
firewall-cmd --list-all 2>/dev/null
```

**DNS and Domain Information**

```bash
# DNS zone transfer test (if applicable)
dig axfr @<dns-server> <domain>

# Recent DNS queries (if systemd-resolved)
resolvectl statistics
journalctl -u systemd-resolved --since "24 hours ago"
```

#### 2.3 User and Account Analysis

**Current Session Information**

```bash
# Current user and privileges
whoami
id
groups

# Currently logged-in users
w
who
users

# Last logins
last -a
lastb -a 2>/dev/null  # Failed logins (requires root)
lastlog

# Login history from journal
journalctl _COMM=sshd --since "7 days ago" | grep -E "(Accepted|Failed)"
```

**Account Enumeration**

```bash
# All user accounts
cat /etc/passwd
getent passwd

# Accounts with login shells
grep -v '/nologin\|/false' /etc/passwd

# UID 0 accounts (should only be root)
awk -F: '$3 == 0 {print}' /etc/passwd

# Recently modified accounts
ls -la /etc/passwd /etc/shadow /etc/group
stat /etc/passwd /etc/shadow /etc/group

# Password information
cat /etc/shadow  # Requires root

# Group memberships (focus on sudo, wheel, admin)
cat /etc/group
getent group sudo wheel admin docker

# Sudoers configuration
cat /etc/sudoers
cat /etc/sudoers.d/*
```

**SSH Analysis**

{% code overflow="wrap" %}
```bash
# SSH configuration
cat /etc/ssh/sshd_config
grep -E "^(PermitRootLogin|PasswordAuthentication|AuthorizedKeysFile|PermitEmptyPasswords)" /etc/ssh/sshd_config

# Authorized keys for all users
for user in $(cut -d: -f1 /etc/passwd); do
    home=$(getent passwd "$user" | cut -d: -f6)
    if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "=== $user ==="
        cat "$home/.ssh/authorized_keys"
    fi
done

# Known hosts (reveals lateral movement)
for user in $(cut -d: -f1 /etc/passwd); do
    home=$(getent passwd "$user" | cut -d: -f6)
    if [ -f "$home/.ssh/known_hosts" ]; then
        echo "=== $user ==="
        cat "$home/.ssh/known_hosts"
    fi
done

# SSH private keys (check for unauthorised keys)
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
```
{% endcode %}

#### 2.4 Process Analysis

**Process Enumeration**

```bash
# Process tree (shows parent-child relationships)
ps auxf
pstree -p

# All processes with full command line
ps aux --forest
ps -ef

# Processes with environment variables
ps auxe

# Process sorted by CPU/memory (cryptominer detection)
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20
```

**Suspicious Process Investigation**

```bash
# Processes running from unusual locations
ps aux | grep -E '/tmp/|/dev/shm/|/var/tmp/'

# Processes with deleted binaries (highly suspicious)
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'

# Process working directories
ls -la /proc/*/cwd 2>/dev/null

# Process file descriptors (network connections, open files)
ls -la /proc/<PID>/fd/

# Process memory maps
cat /proc/<PID>/maps

# Process environment variables
cat /proc/<PID>/environ | tr '\0' '\n'

# Process command line
cat /proc/<PID>/cmdline | tr '\0' ' '

# Process status details
cat /proc/<PID>/status
```

**Binary Recovery and Analysis**

```bash
# Recover deleted but running binary
cp /proc/<PID>/exe /tmp/recovered_binary

# Hash the recovered binary
md5sum /tmp/recovered_binary
sha256sum /tmp/recovered_binary

# Strings analysis
strings /tmp/recovered_binary | head -100
strings -a /tmp/recovered_binary | grep -E '(http|https|ftp|ssh|password|exec|system|/bin/)'
```

#### 2.5 Scheduled Tasks Analysis

**Cron Jobs**

{% code overflow="wrap" %}
```bash
# System cron
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# View contents of all cron directories
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    echo "=== $dir ==="
    for file in $dir/*; do
        [ -f "$file" ] && echo "--- $file ---" && cat "$file"
    done
done

# User cron jobs
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u $user -l 2>/dev/null && echo "=== Cron for $user ==="
done

# Cron job modification timestamps
stat /var/spool/cron/crontabs/* 2>/dev/null
```
{% endcode %}

**Systemd Timers**

{% code overflow="wrap" %}
```bash
# List all timers
systemctl list-timers --all

# Timer unit files
find /etc/systemd /usr/lib/systemd ~/.config/systemd -name "*.timer" -exec cat {} \; 2>/dev/null
```
{% endcode %}

**At Jobs**

```bash
# Pending at jobs
atq
at -l

# View at job contents
for job in $(atq | cut -f1); do
    echo "=== Job $job ==="
    at -c $job
done
```

#### 2.6 Persistence Mechanism Analysis

**Services and Systemd**

```bash
# All services
systemctl list-units --type=service --all

# Enabled services
systemctl list-unit-files --type=service --state=enabled

# Recently modified service files
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -30 -ls

# Service file contents for suspicious services
systemctl cat <service_name>

# Service drop-in overrides
find /etc/systemd/system -name "*.d" -type d -exec ls -la {} \;
```

**Init Scripts and RC**

```bash
# Init scripts
ls -la /etc/init.d/
cat /etc/rc.local 2>/dev/null

# RC directories
ls -la /etc/rc*.d/

# Inittab (legacy systems)
cat /etc/inittab 2>/dev/null
```

**Shell Initialisation Files**

```bash
# System-wide
cat /etc/profile
cat /etc/profile.d/*
cat /etc/bash.bashrc
cat /etc/environment

# User-specific (check all users)
for user in $(cut -d: -f1 /etc/passwd); do
    home=$(getent passwd "$user" | cut -d: -f6)
    for file in .bashrc .bash_profile .profile .zshrc .bash_login .bash_logout; do
        [ -f "$home/$file" ] && echo "=== $user: $file ===" && cat "$home/$file"
    done
done
```

**PAM Configuration**

```bash
# PAM modules (backdoor authentication)
ls -la /etc/pam.d/
cat /etc/pam.d/common-auth
cat /etc/pam.d/sshd
cat /etc/pam.d/su

# Check for unusual PAM modules
find /lib/security /lib64/security /usr/lib/security -name "*.so" -mtime -30 -ls 2>/dev/null
```

**MOTD Scripts**

```bash
# Message of the day scripts (executed at login)
ls -la /etc/update-motd.d/
cat /etc/update-motd.d/*

cat /etc/motd
```

**LD\_PRELOAD Hijacking**

```bash
# Check for LD_PRELOAD in environment
env | grep LD_PRELOAD
cat /etc/ld.so.preload
ldconfig -p | grep -v "^$"
```

#### 2.7 Webshell Detection

{% code overflow="wrap" %}
```bash
# Common webshell locations
find /var/www -name "*.php" -mtime -30 -ls
find /var/www -name "*.jsp" -mtime -30 -ls
find /var/www -name "*.asp*" -mtime -30 -ls

# Webshell signature detection
grep -r -l -E "(eval\(|base64_decode|shell_exec|system\(|passthru|exec\(|popen|proc_open)" /var/www/ 2>/dev/null

# PHP files with suspicious functions
find /var/www -name "*.php" -exec grep -l -E "(eval|base64_decode|gzinflate|str_rot13|assert)" {} \;

# Recently modified web files
find /var/www -type f -mtime -7 -ls

# Files with unusual permissions in webroot
find /var/www -type f -perm -o+w -ls
find /var/www -type f -user www-data -ls 2>/dev/null
```
{% endcode %}

#### 2.8 File System Analysis

**Suspicious Files and Directories**

```bash
# Hidden files and directories
find / -name ".*" -type f -ls 2>/dev/null | head -100
find / -name "...*" -ls 2>/dev/null  # Hidden with multiple dots

# Files in temporary directories
ls -la /tmp/ /var/tmp/ /dev/shm/
find /tmp /var/tmp /dev/shm -type f -ls 2>/dev/null

# SUID/SGID binaries (privilege escalation)
find / -perm -4000 -type f -ls 2>/dev/null
find / -perm -2000 -type f -ls 2>/dev/null

# Immutable files (attackers use to protect malware)
lsattr -R / 2>/dev/null | grep -E "^\-+i"

# Files with no owner (orphaned files)
find / -nouser -o -nogroup 2>/dev/null

# World-writable files and directories
find / -perm -0002 -type f -ls 2>/dev/null
find / -perm -0002 -type d -ls 2>/dev/null

# Recently modified executables
find /usr/bin /usr/sbin /bin /sbin -type f -mtime -30 -ls

# Large hidden files (data staging)
find / -name ".*" -size +100M -ls 2>/dev/null
```

**File Timeline Analysis**

```bash
# Files modified in last 24 hours
find / -mtime -1 -type f -ls 2>/dev/null

# Files accessed in last 24 hours
find / -atime -1 -type f -ls 2>/dev/null

# Files changed in specific timeframe
find / -newermt "2024-01-01" ! -newermt "2024-01-02" -type f -ls 2>/dev/null

# Specific user's files
find / -user <username> -type f -ls 2>/dev/null
```

**Package and Binary Analysis**

```bash
# Installed packages (Debian/Ubuntu)
dpkg -l
dpkg --get-selections

# Installed packages (RHEL/CentOS)
rpm -qa
yum list installed

# Recently installed packages
grep " install " /var/log/dpkg.log 2>/dev/null
grep " install " /var/log/apt/history.log 2>/dev/null
rpm -qa --last | head -20

# Verify package integrity
debsums -c 2>/dev/null  # Debian
rpm -Va 2>/dev/null      # RHEL

# Check binary against package
dpkg -S /usr/bin/ssh
rpm -qf /usr/bin/ssh
```

#### 2.9 Kernel and Module Analysis

```bash
# Loaded kernel modules
lsmod

# Module details
modinfo <module_name>

# Module configuration
cat /etc/modprobe.d/*
cat /etc/modules

# Kernel parameters
sysctl -a 2>/dev/null | grep -E "(ip_forward|accept_redirects|accept_source_route)"

# Compare against known-good baseline
# Look for suspicious modules: rootkits often load as kernel modules
# Research unfamiliar module names
```

#### 2.10 Command History Analysis

```bash
# Current user history
history
cat ~/.bash_history

# All user histories
for user in $(cut -d: -f1 /etc/passwd); do
    home=$(getent passwd "$user" | cut -d: -f6)
    for hist in .bash_history .zsh_history .history; do
        [ -f "$home/$hist" ] && echo "=== $user: $hist ===" && cat "$home/$hist"
    done
done

# MySQL history
cat ~/.mysql_history

# Recently used files (GNOME)
cat ~/.local/share/recently-used.xbel 2>/dev/null
```

#### 2.11 System Resource Anomalies

```bash
# System uptime and load
uptime
cat /proc/loadavg

# Memory usage details
free -h
cat /proc/meminfo

# Disk usage
df -h
du -sh /* 2>/dev/null | sort -h

# Open files count
lsof | wc -l
cat /proc/sys/fs/file-nr

# Process limits
ulimit -a
```

***

### Phase 3: Evidence Collection

#### 3.1 Live Response Data Export

```bash
# Create timestamped output directory
OUTPUT_DIR=~/investigation/live_response/$(date +%Y%m%d_%H%M%S)
mkdir -p $OUTPUT_DIR

# Collect all live response data
{
    echo "=== System Information ==="
    uname -a
    hostname
    date
    uptime
    
    echo "=== Network Connections ==="
    ss -tulpan
    
    echo "=== Processes ==="
    ps auxf
    
    echo "=== Users ==="
    w
    last -20
    
    # Add more sections as needed
} > $OUTPUT_DIR/live_response.txt 2>&1

# Collect specific artifacts
cp /etc/passwd $OUTPUT_DIR/
cp /etc/shadow $OUTPUT_DIR/ 2>/dev/null
cp /etc/group $OUTPUT_DIR/
tar -czf $OUTPUT_DIR/var_log.tar.gz /var/log/ 2>/dev/null
tar -czf $OUTPUT_DIR/etc_backup.tar.gz /etc/ 2>/dev/null
```

#### 3.2 Disk Imaging

```bash
# Identify target disk
lsblk
fdisk -l

# Create disk image with dd
dd if=/dev/sda of=/path/to/external/disk_image.dd bs=4M status=progress conv=noerror,sync

# With compression
dd if=/dev/sda bs=4M status=progress | gzip > /path/to/disk_image.dd.gz

# Using dc3dd (includes hashing)
dc3dd if=/dev/sda of=/path/to/disk_image.dd hash=sha256 log=/path/to/imaging.log

# Verify image integrity
md5sum /dev/sda
md5sum /path/to/disk_image.dd
sha256sum /dev/sda
sha256sum /path/to/disk_image.dd
```

#### 3.3 Memory Acquisition

**Using AVML (Microsoft)**

```bash
# Download AVML (run on a trusted system, transfer to target)
wget https://github.com/microsoft/avml/releases/latest/download/avml

# Acquire memory
chmod +x avml
./avml memory.lime

# Acquire with compression
./avml --compress memory.lime.compressed
```

**Using LiME**

```bash
# Build LiME module (must match kernel version)
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make

# Acquire memory
insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"

# Verify acquisition
ls -la /tmp/memory.lime
```

***

### Phase 4: Analysis & Investigation

#### 4.1 Log Analysis

**Authentication Logs**

```bash
# SSH authentication
grep -E "(Accepted|Failed|Invalid)" /var/log/auth.log
journalctl _COMM=sshd | grep -E "(Accepted|Failed)"

# Sudo usage
grep "sudo" /var/log/auth.log
journalctl _COMM=sudo

# su command usage
grep " su" /var/log/auth.log

# Account modifications
grep -E "(useradd|usermod|userdel|groupadd)" /var/log/auth.log
```

**System Logs**

```bash
# General system events
less /var/log/syslog
journalctl -p err --since "7 days ago"

# Kernel messages
dmesg | tail -100
journalctl -k --since "7 days ago"

# Boot logs
journalctl -b
cat /var/log/boot.log 2>/dev/null
```

**Web Server Logs**

{% code overflow="wrap" %}
```bash
# Apache access logs
cat /var/log/apache2/access.log
cat /var/log/httpd/access_log

# Nginx access logs
cat /var/log/nginx/access.log

# Error logs
cat /var/log/apache2/error.log
cat /var/log/nginx/error.log

# Access log analysis
# Top requesting IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# POST requests (potential exploitation)
grep "POST" /var/log/apache2/access.log

# Unique user agents
awk -F'"' '{print $6}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Status code distribution
awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn

# 404 errors (scanning activity)
grep " 404 " /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20

# Using GoAccess for visual analysis
goaccess /var/log/apache2/access.log --log-format=COMBINED -o report.html
```
{% endcode %}

**Application Logs**

```bash
# MySQL/MariaDB
cat /var/log/mysql/error.log
cat /var/log/mysqld.log

# PostgreSQL
cat /var/log/postgresql/*.log

# Cron execution
cat /var/log/cron
journalctl _COMM=cron

# Mail logs
cat /var/log/mail.log
cat /var/log/maillog

# FTP logs
cat /var/log/vsftpd.log
cat /var/log/xferlog
```

#### 4.2 Artifact Analysis

**Decode Suspicious Content**

```bash
# Base64 decode
echo "encoded_string" | base64 -d
base64 -d suspicious_file.txt

# Hex decode
xxd -r -p hex_file.txt

# URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('encoded_url'))"

# ROT13
echo "rot13_string" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**File Analysis**

```bash
# File type identification
file suspicious_file

# Strings extraction
strings suspicious_file
strings -a suspicious_file | grep -E "(http|https|ftp|password|exec|/bin/)"

# Hex dump
xxd suspicious_file | head -50
hexdump -C suspicious_file | head -50

# Binary comparison
diff <(xxd file1) <(xxd file2)
cmp -l file1 file2

# ELF binary analysis
readelf -h suspicious_binary
readelf -s suspicious_binary
objdump -d suspicious_binary | head -100
```

#### 4.3 Memory Analysis with Volatility

```bash
# Install Volatility 3
pip3 install volatility3

# Determine profile (kernel version)
uname -r  # On live system
strings memory.lime | grep -i "Linux version"

# Build symbol table (if needed)
# Download debug symbols for your kernel version
# Convert to JSON format for Volatility

# Run analysis
# Process listing
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree

# Network connections
vol -f memory.lime linux.sockstat

# Loaded modules
vol -f memory.lime linux.lsmod

# Bash history from memory
vol -f memory.lime linux.bash

# File handles
vol -f memory.lime linux.lsof

# Environment variables
vol -f memory.lime linux.envvars
```

#### 4.4 Disk Analysis

**Mount Disk Image**

```bash
# Create mount point
mkdir /mnt/evidence

# Mount raw image
mount -o ro,loop disk_image.dd /mnt/evidence

# Mount specific partition
# First identify partitions
fdisk -l disk_image.dd

# Calculate offset (start sector * 512)
mount -o ro,loop,offset=<offset> disk_image.dd /mnt/evidence

# Mount LVM volumes
kpartx -av disk_image.dd
vgscan
vgchange -ay
mount -o ro /dev/mapper/<vg-name>-<lv-name> /mnt/evidence
```

**File System Analysis with Sleuth Kit**

```bash
# Image information
img_stat disk_image.dd

# File system information
fsstat disk_image.dd

# List files
fls -r disk_image.dd

# Timeline creation
fls -r -m "/" disk_image.dd > body.txt
mactime -b body.txt > timeline.csv

# File recovery by inode
icat disk_image.dd <inode_number> > recovered_file

# Deleted file recovery
tsk_recover -e disk_image.dd /output/directory
```

**Timeline Generation with Plaso**

{% code overflow="wrap" %}
```bash
# Generate timeline
log2timeline.py --parsers linux,apache_access,apt_history timeline.plaso disk_image.dd

# Apply filters and output
psort.py -z UTC -o l2tcsv -w timeline.csv timeline.plaso "date > '2024-01-01' AND date < '2024-01-31'"

# Quick timeline with psteal
psteal.py --source disk_image.dd -o l2tcsv -w quick_timeline.csv
```
{% endcode %}

#### 4.5 File Recovery

**Using debugfs (ext3/4)**

```bash
# Interactive mode
debugfs -w /dev/sda2

# List deleted files
debugfs: lsdel

# Get inode information
debugfs: logdump -i <inode_number>

# Recover file by block
dd if=/dev/sda2 of=recovered.txt bs=4096 count=1 skip=<block_number>
```

**Using ext4magic**

```bash
# Install
apt-get install ext4magic

# List deleted files from last 6 hours
ext4magic /dev/sda2 -a $(date -d "-6hours" +%s) -f /path/to/search -l

# Recover specific files
ext4magic /dev/sda2 -a $(date -d "-6hours" +%s) -f /path/to/search -r -d /recovery/output

# Recover all deleted files
ext4magic /dev/sda2 -a $(date -d "-6hours" +%s) -m -d /recovery/output
```

**Using PhotoRec**

```bash
# Install
apt-get install testdisk

# Run PhotoRec (interactive)
photorec disk_image.dd

# Carve specific file types
photorec /d /output/dir /cmd disk_image.dd fileopt,everything,disable,jpg,enable,search
```

#### 4.6 Automated Scanning

**THOR Lite (Compromise Assessment)**

```bash
# Download and run THOR Lite
# Includes YARA and SIGMA rules
./thor-lite-linux-64 -a Filescan --intense

# Output review
cat thor-scan-results.txt
```

**Rootkit Detection**

```bash
# chkrootkit
apt-get install chkrootkit
chkrootkit

# rkhunter
apt-get install rkhunter
rkhunter --update
rkhunter --check

# Unhide (find hidden processes)
apt-get install unhide
unhide sys
unhide proc
```

**ClamAV Scan**

```bash
# Install and update
apt-get install clamav
freshclam

# Full scan
clamscan -r --infected /

# Scan specific directory
clamscan -r --infected /var/www/
```

***

### Phase 5: Privilege Escalation Hunting

#### Indicators of Privilege Escalation Attempts

{% code overflow="wrap" %}
```bash
# Check history for known privesc tools
for user in $(cut -d: -f1 /etc/passwd); do
    home=$(getent passwd "$user" | cut -d: -f6)
    [ -f "$home/.bash_history" ] && grep -E "(linpeas|linenum|linux-exploit-suggester|pspy|sudo|chmod \+s|/etc/passwd|/etc/shadow)" "$home/.bash_history" && echo "Found in $user's history"
done

# Suspicious file modifications
ls -la /etc/passwd /etc/shadow /etc/sudoers
stat /etc/passwd /etc/shadow /etc/sudoers

# SUID bit changes
find / -perm -4000 -mtime -30 -ls 2>/dev/null

# Capability modifications
getcap -r / 2>/dev/null

# Check for known kernel exploits signatures
uname -r
# Research: DirtyCow (CVE-2016-5195), DirtyPipe (CVE-2022-0847), DirtyCred (CVE-2022-2588)
# Check if kernel version is vulnerable

# Writable sensitive files
find /etc -writable -type f 2>/dev/null
ls -la /etc/cron* /etc/sudoers.d/ /etc/passwd /etc/shadow

# World-writable directories in PATH
echo $PATH | tr ':' '\n' | xargs -I {} find {} -perm -0002 -type d 2>/dev/null
```
{% endcode %}

***

### Phase 6: Reporting

#### Investigation Report Structure

```bash
# Incident Response Report

## Executive Summary
- Incident type
- Affected systems
- Timeframe
- Business impact
- Recommendations

## Timeline of Events
- Initial compromise
- Lateral movement
- Data access/exfiltration
- Detection
- Response actions

## Technical Findings
- Attack vector
- Persistence mechanisms
- Malware analysis
- IOCs discovered

## Evidence Summary
- Disk images collected
- Memory dumps
- Log files
- Network captures

## Recommendations
- Immediate remediation
- Long-term improvements
- Monitoring enhancements

## Appendices
- IOC list
- Command output
- Tool reports
```

#### IOC Export Format

```bash
# Generate IOC list
cat << EOF > iocs.txt
# IP Addresses
192.168.1.100 | C2 Server | High | 2024-01-15

# Domains
malicious-domain.com | C2 Domain | High | 2024-01-15

# File Hashes (SHA256)
abc123... | webshell.php | High | Webshell

# File Paths
/var/www/html/shell.php | Webshell | High

# User Accounts
backdoor_user | Unauthorized Account | High
EOF
```

***

### Quick Reference Commands

#### Network

<table><thead><tr><th width="242">Purpose</th><th>Command</th></tr></thead><tbody><tr><td>All connections</td><td><code>ss -tulpan</code></td></tr><tr><td>Established only</td><td><code>ss -tan state established</code></td></tr><tr><td>Listening ports</td><td><code>ss -tlnp</code></td></tr><tr><td>By process</td><td><code>lsof -i -P -n</code></td></tr></tbody></table>

#### Processes

<table><thead><tr><th width="251">Purpose</th><th>Command</th></tr></thead><tbody><tr><td>Process tree</td><td><code>ps auxf</code></td></tr><tr><td>Deleted binaries</td><td><code>ls -la /proc/*/exe 2>/dev/null | grep deleted</code></td></tr><tr><td>High CPU</td><td><code>ps aux --sort=-%cpu | head -10</code></td></tr><tr><td>Process details</td><td><code>cat /proc/&#x3C;PID>/cmdline status maps</code></td></tr></tbody></table>

#### Files

<table><thead><tr><th width="272">Purpose</th><th>Command</th></tr></thead><tbody><tr><td>Modified today</td><td><code>find / -mtime -1 -type f -ls 2>/dev/null</code></td></tr><tr><td>SUID files</td><td><code>find / -perm -4000 -type f -ls 2>/dev/null</code></td></tr><tr><td>Hidden files</td><td><code>find / -name ".*" -type f 2>/dev/null</code></td></tr><tr><td>Webshells</td><td><code>grep -r -l "eval|base64_decode|shell_exec" /var/www/</code></td></tr></tbody></table>

#### Persistence

<table><thead><tr><th width="277">Purpose</th><th>Command</th></tr></thead><tbody><tr><td>Cron jobs</td><td><code>cat /etc/crontab; ls /etc/cron.*</code></td></tr><tr><td>Services</td><td><code>systemctl list-unit-files --state=enabled</code></td></tr><tr><td>Authorized keys</td><td><code>find / -name authorized_keys -exec cat {} \;</code></td></tr><tr><td>Shell configs</td><td><code>cat /etc/profile ~/.bashrc ~/.profile</code></td></tr></tbody></table>

***

### Tool Quick Install

```bash
# Essential tools
apt-get update
apt-get install -y net-tools lsof strace ltrace gdb binutils \
    sleuthkit autopsy foremost scalpel dc3dd \
    chkrootkit rkhunter unhide clamav \
    yara volatility3

# Python tools
pip3 install volatility3 yara-python
```

***

### References

* [Linux Forensics Command Cheat Sheet - Ef's log](https://fahmifj.github.io/)
* [SANS Linux Incident Response](https://www.sans.org/)
* [LetsDefend Linux Forensics](https://letsdefend.io/)
* [The Sleuth Kit Documentation](https://sleuthkit.org/)
* [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
* [MITRE ATT\&CK for Linux](https://attack.mitre.org/matrices/enterprise/linux/)
* [HackTricks Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
