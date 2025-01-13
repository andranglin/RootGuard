---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Incident Response Basics

### Live Response Commands

These commands can review anomalous behaviour and verify compromise in real-time action. Some of the commands, such as `cat /var/www/html/webshell.php`, can also be used to perform post-compromise disk analysis, where we only need to supply the full path of the mounted compromised disk, for example, `cat /media/compromised_disk/var/www/html/webshell.php`.

### General Information

First, we will collect the required information regarding the system to be analysed.

{% code overflow="wrap" %}
```bash
# Display the current date and time. Verify the timezone.
date

# Timezone information
cat /etc/timezone

# System information
uname -a

# Network information
ifconfig
cat /etc/network/interfaces

# Display distro version
cat /etc/*-release

# Date of installation of the OS. Check the date
ls -ld /var/log/installer

# Display hostname
hostname
cat /etc/hostname
```
{% endcode %}

### System Information <a href="#system-information-1" id="system-information-1"></a>

```bash
date
uname –a
lsb_release -a
hostname
cat /proc/version
lsmod
```

### Initialisation Files <a href="#initialisation-files" id="initialisation-files"></a>

```bash
cat /etc/bash.bashrc
cat ~/.bash_profile 
cat ~/.bashrc 
```

### Environment and Startup Programs <a href="#environment-and-startup-programs" id="environment-and-startup-programs"></a>

```bash
env
cat /etc/profile
ls /etc/profile.d/
cat /etc/profile.d/*
```

### Configuration Information <a href="#configuration-information" id="configuration-information"></a>

```bash
ls /etc/*.d
cat /etc/*.d/*
```

### Review Network Connections

Investigate any malicious connection and unexpected IP address

{% code overflow="wrap" %}
```bash
#  List all TCP and UDP connections on your system along with their respective listening and non-listening sockets
netstat -antup

# kernel routing table
netstat -rn
route

# Check static DNS lookups
cat /etc/hosts
```
{% endcode %}

### Network Connections / Socket Stats <a href="#network-connections--socket-stats" id="network-connections--socket-stats"></a>

```bash
netstat
netstat -apetul
netstat -plan
netstat -plant
netstat -naote
ss
ss -l
ss -ta
ss -tp
```

### DNS Information for Domain <a href="#dns-information-for-domain" id="dns-information-for-domain"></a>

```bash
dig www.jaiminton.com a
dig www.jaiminton.com any
dig www.jaiminton.com ns
dig www.jaiminton.com soa
dig www.jaiminton.com hinfo
dig www.jaiminton.com txt
dig +short www.jaiminton.com
```

### IPs Allowed to Perform Domain Transfer <a href="#ips-allowed-to-perform-domain-transfer" id="ips-allowed-to-perform-domain-transfer"></a>

```bash
cat /etc/bind/named.conf.local
```

### IP Table Information <a href="#ip-table-information" id="ip-table-information"></a>

```bash
ls /etc/iptables
cat /etc/iptables/*.v4
cat /etc/iptables/*.v6
iptables -L
```

### Account Information <a href="#account-information" id="account-information"></a>

```bash
cat /etc/passwd
cat /etc/shadow
cat /etc/sudoers
cat /etc/sudoers.d/*
cut -d: -f1 /etc/passwd
getent passwd | cut -d: -f1
compgen -u
```

### Current User <a href="#current-user" id="current-user"></a>

```bash
whoami
who
```

### Last Logged-on Users <a href="#last-logged-on-users" id="last-logged-on-users"></a>

```bash
last
lastb
cat /var/log/auth.log
```

### Logon activities

Review the logon activities of the compromised host.

```bash
# Check users who are currently logged in
w

# Last login information for all users. It reads the /var/log/lastlog file
lastlog
cat /var/log/lastlog

# List of last logged-in users and their login times
last -f /var/log/wtmp

# Failed login attempts
last -f /var/log/btmp

# Searching for login activities in auth.log with specific keyword
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i user
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i Accepted
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i failed
grep -v cron /var/log/auth.log* | grep -v sudo | grep i "login:session"

# CentOS, Red Hat Enterprise Linux (RHEL) of auth.log
cat /var/log/secure
```

### Scheduled Tasks <a href="#scheduled-tasks" id="scheduled-tasks"></a>

```bash
ls /etc/cron.*
ls /etc/cron.*/*
cat /etc/cron.*/*
cat /etc/crontab
crontab -l
```

### Process Information <a href="#process-information-2" id="process-information-2"></a>

```bash
ps -s
ps -l
ps -o
ps -t
ps -m
ps -a
ps -ax
top
```

### Process Tree <a href="#process-tree" id="process-tree"></a>

```bash
ps -auxwf
```

### Process Command Line Information <a href="#process-command-line-information" id="process-command-line-information"></a>

```bash
cat /proc/[PID]/cmdline
cat /proc/[PID]/comm
```

### Detailed Process Information <a href="#detailed-process-information" id="detailed-process-information"></a>

```bash
ls -al /proc/[PID]
```

### Process Environment Variables (incl user who ran binary) <a href="#process-environment-variables-incl-user-who-ran-binary" id="process-environment-variables-incl-user-who-ran-binary"></a>

```bash
strings /proc/[PID]/environ
cat /proc/[PID]/environ
```

### Process File Descriptors/Maps (what the process is ‘accessing’ or using) <a href="#process-file-descriptorsmaps-what-the-process-is-accessing-or-using" id="process-file-descriptorsmaps-what-the-process-is-accessing-or-using"></a>

```bash
ls -al /proc/[PID]/fd
cat /proc/[PID]/maps
```

### Process Stack/Status Information (may reveal useful elements) <a href="#process-stackstatus-information-may-reveal-useful-elements" id="process-stackstatus-information-may-reveal-useful-elements"></a>

```bash
cat /proc/[PID]/stack
cat /proc/[PID]/status
```

### Deleted Binaries Which are Still Running <a href="#deleted-binaries-which-are-still-running" id="deleted-binaries-which-are-still-running"></a>

```bash
ls -alr /proc/*/exe 2> /dev/null |  grep deleted
```

### Process Working Directories (including common targeted directories) <a href="#process-working-directories-including-common-targeted-directories" id="process-working-directories-including-common-targeted-directories"></a>

```bash
ls -alr /proc/*/cwd
ls -alr /proc/*/cwd 2> /dev/null | grep tmp
ls -alr /proc/*/cwd 2> /dev/null | grep dev
ls -alr /proc/*/cwd 2> /dev/null | grep var
ls -alr /proc/*/cwd 2> /dev/null | grep home
```

### Review Processes

Review all running processes; the following command could identify potentially malicious processes

```bash
# Interactive process viewer
htop

# Currently running processes and its command
ps -aux

# List all open files associated with a specific process
lsof -p <PID>

# Directories that contain information about a specific process
ls /proc/<PID>
cat /proc/<PID>

# Show process in tree view
pstree -a
```

### Recover deleted binary, which is currently running <a href="#recover-deleted-binary-which-is-currently-running" id="recover-deleted-binary-which-is-currently-running"></a>

```bash
cp /proc/[PID]/exe /[destination]/[binaryname]
```

### Capture Binary Data for Review <a href="#capture-binary-data-for-review" id="capture-binary-data-for-review"></a>

```bash
cp /proc/[PID]/ /[destination]/[PID]/
```

### Binary Hash Information <a href="#binary-hash-information" id="binary-hash-information"></a>

```bash
sha1sum /[destination]/[binaryname]
md5sum /[destination]/[binaryname]
```

### <mark style="color:blue;">Recover a Deleted Process Binary.</mark>

This method attempts to recover the binary executable from the process’s memory by extracting a portion of the memory associated with the process.

{% code overflow="wrap" %}
```bash
cd /proc/1234/

# maps contain memory maps of the process, showing the memory regions used by the process
head -1 maps

# Extract memory content (1000 bytes) at specified ADDRESS to tmp directory
dd if=mem bs=1 skip=ADDRESS count=1000 of=/tmp/recovered_proc_file
```
{% endcode %}

### Review Activities

Investigating the executed commands of a user could give some context about an incident

{% code overflow="wrap" %}
```bash
# Check command history 
history

# Check all files with "history" in their name in the user's home directory
cat /home/$USER/.*_history

# Check the command history  (specific to bash shell)
cat /home/$USER/.bash_history

# Check the command history for the root user (specific to bash shell)
cat /root/.bash_history

# Check the MySQL command history for the root user
cat /root/.mysql_history

# Check the FTP command history 
cat /home/$USER/.ftp_history

# Check the SFTP command history 
cat /home/$USER/.sftp_history

# Check the VIM editor history 
cat /home/$USER/.viminfo

# Check the history of commands entered in the 'less' pager 
cat /home/$USER/.lesshst

# Check the Git configuration 
cat /home/$USER/.gitconfig

# List recent Git activity logs 
ls /home/$USER/.git/logs

# List Mozilla Firefox profiles, check history and downloads
ls /home/$USER/.mozilla/firefox

# List Google Chrome profiles, check history and downloads
ls /home/$USER/.config/google-chrome

# Search for relevant commands in the authentication logs excluding cron jobs
grep -v cron /var/log/auth.log* | grep -i -e "command=" -e "su:" -e "groupadd" -e "useradd" -e "passwd"
```
{% endcode %}

### Open Files and Space Usage <a href="#open-files-and-space-usage" id="open-files-and-space-usage"></a>

```bash
lsof
du
```

### Disk / Partition Information <a href="#disk--partition-information" id="disk--partition-information"></a>

```bash
fdisk -l
```

### Strings Present In File <a href="#strings-present-in-file" id="strings-present-in-file"></a>

```bash
strings [filepath]
strings -e b [filepath]
```

### Hidden Directories and Files <a href="#hidden-directories-and-files" id="hidden-directories-and-files"></a>

```bash
find / -type d -name ".*"
```

### Immutable Files and Directories (Often Suspicious) <a href="#immutable-files-and-directories-often-suspicious" id="immutable-files-and-directories-often-suspicious"></a>

```bash
lsattr / -R 2> /dev/null | grep "\----i"
```

### SUID/SGID and Sticky Bit Special Permissions <a href="#suidsgid-and-sticky-bit-special-permissions" id="suidsgid-and-sticky-bit-special-permissions"></a>

```bash
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;
```

### File and Directories with no user/group name <a href="#file-and-directories-with-no-usergroup-name" id="file-and-directories-with-no-usergroup-name"></a>

```bash
find / \( -nouser -o -nogroup \) -exec ls -lg  {} \;
```

### File Types in Current Directory <a href="#file-types-in-current-directory" id="file-types-in-current-directory"></a>

```bash
file * -p
```

### Executables on File System <a href="#executables-on-file-system" id="executables-on-file-system"></a>

```bash
find / -type f -exec file -p '{}' \; |  grep ELF
```

### Hidden Executables on File System <a href="#hidden-executables-on-file-system" id="hidden-executables-on-file-system"></a>

```bash
find / -name ".*" -exec file -p '{}' \; | grep ELF
```

### Files Modified Within the Past Day <a href="#files-modified-within-the-past-day" id="files-modified-within-the-past-day"></a>

```bash
find / -mtime -1
```

### Find Files for a Particular User <a href="#find-files-for-a-particular-user" id="find-files-for-a-particular-user"></a>

```bash
find /home/ -user fred -type f
```

### Hunting Unusual Files

{% code overflow="wrap" %}
```bash
; change# Search for files modified within the last 5 days and Check them for further inspection; change 5 if needed
find / -type f -mtime -5 | less

# Search for files modified within the last 5 days with "php" in their name and Check them for further inspection
find / -type f -mtime -5 | grep "php"

# Find files modified in the last 10 days in specified directories and Check them
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"

# Find files modified within the last day and print their paths
find / -type f -mtime -1 -print

# Search for files larger than 10,000 kilobytes and print their paths
find / -size +10000k -print

# List files in /usr/bin directory with their inode numbers and sort them numerically
ls -lai /usr/bin | sort -n

# List files in /bin directory recursively, sorted by modification time
ls -laR --sort=time /bin

# Find files owned by root with the setuid or setgid permissions and print their paths
find / -user root -perm -04000 -print

# List all devices in the /dev directory
ls /dev
```
{% endcode %}

### Installed Programs

{% code overflow="wrap" %}
```bash
# Examine commands used for package installations from the APT history log for tracking software changes
cat /var/log/apt/history.log | grep "Commandline"

# Retrieve package names and their statuses from the dpkg status file for software inventory analysis
cat /var/lib/dpkg/status | grep -E "Package:|Status:"

# Review entries from the dpkg log file indicating installed packages for change analysis
cat /var/log/dpkg.log | grep installed

# Identify executables in the /sbin directory and determine their package ownership using dpkg for attribution
find /sbin/ -exec dpkg -S {} \; | grep "no path found"

# List executables in standard system directories for anomaly detection
ls /usr/sbin /usr/bin /bin /sbin

# List files in the APT package cache directory for investigating downloaded packages
ls /var/cache/apt/archives

# Find based on date
find / -type f \( -newermt "2020-12-01" -and ! -newermt "2020-12-02" \)

```
{% endcode %}

### File Investigation

{% code overflow="wrap" %}
```bash
# Collect detailed metadata about the file for forensic analysis
stat <filename>

# Identify the file type and format to understand its nature
file <filename>

# Extract human-readable strings from the file for potential clues or analysis
strings <filename>

# Generate an MD5 checksum of the file to verify integrity and check against known malware signatures
md5sum <filename> # submit to VT
```
{% endcode %}

### Persistent Mechanisms

A persistent mechanism is a method used by attackers to maintain access to a compromised system across reboots or to ensure their malicious activities persist over time. Below is a potential list of the places attackers might add or modify to deploy their persistent access.&#x20;

#### **Review Account**

Review user account information and activity on the system to identify potentially active user accounts, detect anomalies in user account configurations, find files belonging to non-existent users, extract password hashes for analysis, examine group information for privilege analysis, review sudo configurations for potential privilege escalation, investigate SSH authentication keys and known hosts for unauthorized access, and analyze recently used files for user activity.

{% code overflow="wrap" %}
```bash
# Identify potentially active user accounts
cat /etc/passwd | grep bash
cat /etc/passwd | grep sh
cat /etc/passwd | grep dash

# Sort user accounts by their UID to detect anomalies
sort -nk3 -t: /etc/passwd

# Find files belonging to non-existent users (indicators of unauthorized access)
find / -nouser -print

# Extract password hashes for forensic analysis
cat /etc/shadow

# Examine group information for user privilege analysis
cat /etc/group

# Review sudo configuration for potential privilege escalation
cat /etc/sudoers

# Check for additional sudo configurations for backdoors
cat /etc/sudoers.d/*

# Investigate SSH authentication keys for potential unauthorized access
cat /home/$USER/.ssh/authorized_keys

# Analyze SSH known hosts for suspicious connections
cat /home/$USER/.ssh/known_hosts

# Review recently used files for user activity
cat /home/$USER/.recently-used.xbel
```
{% endcode %}

### Persistent Areas of Interest <a href="#persistent-areas-of-interest" id="persistent-areas-of-interest"></a>

```bash
/etc/rc.local
/etc/initd
/etc/rc*.d
/etc/modules
/etc/cron*
/var/spool/cron/*
/usr/lib/cron/
/usr/lib/cron/tabs
```

### **Webshell**

Identifying potential webshell installations or modifications

{% code overflow="wrap" %}
```bash
# Search for PHP files in the /var/www/html directory and print their modification timestamps
find /var/www/html -type f -name "*.php" -printf "%T@ %f\n" | sort -n | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1), $2}'

# Monitor Apache configuration files
tail -f /etc/apache2/*/*

# Monitor Nginx configuration files
tail -f /etc/nginx/*/*
```
{% endcode %}

### **Cron Tasks**

Identify any scheduled tasks or suspicious activities that may have been configured to execute at specific times

{% code overflow="wrap" %}
```bash
# View the configuration of the cron service managed by systemd
cat /lib/systemd/system/cron.service

# View the cron tasks scheduled for a specific user
crontab –u <user> -l

# View the system-wide crontab file containing system cron tasks
cat /etc/crontab

# Check all files in /etc/cron
tail -f /etc/cron.*/*

# List all user-specific cron files in the cron spool directory
ls /var/spool/cron/crontabs/*

# View the contents of the atjobs file, which contains at jobs scheduled by the at command
cat /var/spool/cron/atjobs
```
{% endcode %}

### **Services and Systemd**

Examine systemd configurations and unit files to identify any modifications or suspicious configurations that may have been made to services or startup processes.

{% code overflow="wrap" %}
```bash
# List enabled services and Check their associated start commands
for service in $(systemctl list-unit-files --type=service | grep enabled | awk '{print $1}'); do echo "Service: $service"; systemctl cat $service | grep ExecStart= | sed 's/^/Command: /'; echo "--------------------------------------------------"; done

# List custom systemd unit files in /etc/systemd/system/
ls /etc/systemd/system/

# List systemd unit files in /lib/systemd/system/
ls /lib/systemd/system/

# List systemd system generators
ls /lib/systemd/system-generators/*

# View contents of init.d scripts
more -f /etc/init.d/*

# List systemd user units in /lib/systemd/user/
ls /lib/systemd/user/*

# List custom systemd user units in /etc/systemd/user/
ls /etc/systemd/user/*

# List user systemd generators in /etc/systemd/user-generators/
ls /etc/systemd/user-generators/*

# List user systemd generators in /usr/local/lib/systemd/user-generators/
ls /usr/local/lib/systemd/user-generators/*

# List user systemd generators in /usr/lib/systemd/user-generators/
ls /usr/lib/systemd/user-generators/*
```
{% endcode %}

### **SSH Daemon**

Examine the configuration of the SSH daemon and related resource files

{% code overflow="wrap" %}
```bash
# View the SSH service configuration managed by systemd
cat /lib/systemd/system/ssh.service

# View the SSH daemon configuration file
cat /etc/ssh/sshd_config

# List any user-specific SSH resource files in the ~/.ssh directory
ls ~/.ssh/rc

# List system-wide SSH resource files in the /etc/ssh directory
ls /etc/ssh/sshrc
```
{% endcode %}

### **Login Shell**

Examine login shell configurations and scripts responsible for system initialization and startup processes.

```bash
# Check system-wide Bash initialization file
cat /etc/bash.bashrc

# Check user-specific Bash initialization file
cat /home/$USER/.bashrc

# Check user-specific Bash profile file
cat /home/$USER/.bash_profile

# Check system-wide profile file
cat /etc/profile

# Check scripts in the /etc/profile.d directory
cat /etc/profile.d/*

# Check user-specific profile file
cat /home/$USER/.profile

# Check user-specific Bash login file
cat /home/$USER/.bash_login

# Check user-specific Bash logout file
cat /home/$USER/.bash_logout

# Check system-wide Bash logout file
cat /etc/.bash_logout
```

### **rc scripts**

RC scripts responsible for system initialization and startup processes.

```bash
# Review rc scripts
cat /etc/rc*
```

### **Infected Binaries**

Uncover recently modified files that may indicate unauthorised activity or compromise.

```bash
# Find binaries modified within the last 10 days in specified directories
find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"

# List Python 3 related libraries and modules in /usr/lib directory
ls /usr/lib/python3*
```

### Pluggable Authentication Modules (PAM) <a href="#pluggable-authentication-modules-pam" id="pluggable-authentication-modules-pam"></a>

```bash
# Display contents of the PAM configuration file
cat /etc/pam.conf

# Check contents of the PAM directory
cat /etc/pam.d

cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/
```

### **Message of the Day (MOTD)**

“motd” stands for “message of the day”. These scripts may contain important system status updates, notifications, or potentially malicious content inserted by attackers.

{% code overflow="wrap" %}
```bash
# Examine the scripts responsible for generating dynamic messages displayed to users upon login
cat /etc/update-motd.d/*
```
{% endcode %}

### Unusual System Resources

These commands provide information about system uptime, memory usage, and disk space usage, which can help identify abnormal behaviour such as high resource consumption, potential denial of service attacks, or disk space exhaustion.

{% code overflow="wrap" %}
```bash
# Display system uptime and load average
uptime

# Display memory usage statistics
free

# Display disk space usage statistics
df
```
{% endcode %}

### Compromised Assessment Scanning

Using a CA scanner with YARA and SIGMA detection capabilities significantly speeds up our hunt for malicious and suspicious files in compromised systems. Running this scanner can save a considerable amount of time and prove invaluable during DFIR investigations.

### THOR Lite

{% code overflow="wrap" %}
```bash
# Download Thor Lite and the license from the Nextron website
cd thorlite/
./thor-lite-util update
./thor-lite-linux-64
```
{% endcode %}

### Hunting Rootkit

#### To hunt via 3rd party software

{% code overflow="wrap" %}
```bash
# Detect rootkits on Linux systems
chkrootkit

# Detect rootkits on Linux systems
rkhunter --check

# Comprehensive security auditing tool that includes checks for rootkits among other security issues:
lynis audit system

# Antivirus scanner for malware
clamscan -r /
```
{% endcode %}

#### Hunting and Check Files and Processes

{% code overflow="wrap" %}
```bash
# Inspect dir and files
find /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec ls -la {} \;

# Check running process with root priv
ps aux | grep -i root

# Check unusual network connections
netstat -antup

# Compare checksums or file hashes against known good values
sha256sum /bin/* /sbin/* /usr/bin/* /usr/sbin/* /lib/* /lib64/* /etc/* | sort > current_checksums.txt
```
{% endcode %}

### Investigate Loaded Kernel Modules

```bash
user@training:~$ lsmod
Module                  Size  Used by
tls                   114688  0
lime                   16384  0
cpuid                  16384  0
vboxsf                 36864  1
binfmt_misc            24576  1
intel_rapl_msr         20480  0
intel_rapl_common      40960  1 intel_rapl_msr
intel_powerclamp       24576  0
rapl                   20480  0
snd_intel8x0           45056  0
input_leds             16384  0
serio_raw              20480  0
joydev                 32768  0
snd_ac97_codec        180224  1 snd_intel8x0
ac97_bus               16384  1 snd_ac97_codec
snd_pcm               143360  2 snd_intel8x0,snd_ac97_codec
snd_timer              40960  1 snd_pcm
```

1. The first column lists the module names (tls, lime, etc.).
2. The second column shows the size of each module.
3. The third column (Used by) indicates which other modules use the listed module.

To identify whether a loaded kernel module or its dependencies are part of a rootkit or not, we may want to try these methods:

* Compare the list of loaded kernel modules (lsmod output) against a known good baseline.
* Look for modules that have suspicious names, sizes, or descriptions.
* Investigate the modules listed under the “Used by” column.
* Research any unfamiliar or suspicious modules online.

To get detailed information about a specific module:

```bash
modinfo <name of module>
```

Review configuration files that control module loading.

```bash
tail -f /etc/modprobe.d/*
```

## Collect Evidence

We have completed the collection of live response data and triage scripts, saving all results for further analysis alongside disk and memory analysis. At this stage, gathering disk and memory dumps is imperative to conduct a comprehensive and in-depth investigation. These disk and memory dumps will provide critical insights into the system's state, allowing us to identify any anomalies or malicious activity that may have occurred.

### Disk imaging using dd

Collecting digital disk image of the Linux system is essential to perform disk analysis offline. This activity is required to find suspicious files and folders, recover files and extract artifacts (triage) from the disk.

{% code overflow="wrap" %}
```bash
# List all devices to identify the disk device for disk imaging
lsblk

# List partition tables for disk devices
fdisk -l

# Perform disk imaging to an external disk or shared folder
# Replace "sdb" with the appropriate disk device identifier
dd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img

# Alternatively, use dcfldd to perform hashing while imaging
dcfldd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img hash=sha256 hashwindow=1M hashlog=/media/sf_tmp/linux_forensic.hash
```
{% endcode %}

### Memory Acquisition

Memory acquisition and memory analysis are rare in Linux forensics, as most analysts rely on live response actions and commands. To perform memory acquisition, we will use AVML or LIME.

#### AVML

```bash
# Go to https://github.com/microsoft/avml/releases
# Download avml binary
wget https://github.com/microsoft/avml/releases/download/v0.13.0/avml

# Execute avml
./avml memory.lime
```

#### LIME

{% code overflow="wrap" %}
```bash
# In the target machine, run this command to verify the kernel version
uname -r

# Using another machine with the same kernel version, git clone and compile the source. It will generate .ko file.
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src; sudo make

# Copy the .ko file into the target machine using SCP or Netcat

# In the target machine, run this command to generate a memory dump
sudo insmod lime-$(uname -r).ko "path=/media/sf_tmp/mem.lime format=lime"
```
{% endcode %}

## Investigation and Analysis

After collecting all the crucial evidence, we can proceed with the investigation and analysis of the triage evidence.

### Live Response and Triage Script Analysis

Based on the scripts and live command results, proceed with the investigation using a text editor such as VS Code. If the data is in CSV format, consider using tools like Timeline Explorer for better visualization and analysis.

### Memory analysis with Volatility

First, install volatility if not already installed.

{% code overflow="wrap" %}
```bash
sudo git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
apt install python3-pip
pip3 install -r requirements-minimal.txt
```
{% endcode %}

Then, build a Linux volatility profile to use Volatility for memory forensics. First, determine the kernel version to assist in building the table. Choose one. If you’re not confident, run `uname -r` in a compromised box.

{% code overflow="wrap" %}
```bash
remnux@remnux:/mnt/hgfs/tmp$ vol3 -f memory.lime banners
Volatility 3 Framework 1.0.1
Progress:  100.00		PDB scanning finished                  
Offset	Banner

0x58633668	Linux version 5.15.0-100-generic (buildd@lcy02-amd64-116) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #110-Ubuntu SMP Wed Feb 7 13:27:48 UTC 2024 (Ubuntu 5.15.0-100.110-generic 5.15.143)
0x699ae668	Linux version 5.15.0-101-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 (Ubuntu 5.15.0-101.111-generic 5.15.143)
0x6e600200	Linux version 5.15.0-101-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 (Ubuntu 5.15.0-101.111-generic 5.15.143)
0x70635778	Linux version 5.15.0-101-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 (Ubuntu 5.15.0-101.111-generic 5.15.143)3)
```
{% endcode %}

Then we proceed to download our debug symbol and convert it to a JSON file

{% code overflow="wrap" %}
```bash
# First, search your debug symbol on Google based on command banner result, for example, ubuntu: http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/
wget http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-5.15.0-101-generic-dbgsym_5.15.0-101.111_amd64.ddeb

# Git clone, compile dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json
go build

# Install the ddeb file. Once it done, a dbgsymbol file will write in /usr/lib/debug/boot/
dpkg -i http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-5.15.0-101-generic-dbgsym_5.15.0-101.111_amd64.ddeb

# Execute dwarf2json on the dbgsmbl file
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-5.15.0-101-generic > symbol.json

# Copy into volatility path
cp symbol.json /path/to/volatility3/symbols/linux/

# Verify the setup
python3 vol.py isfinfo
```
{% endcode %}

### Run the Analysis

{% code overflow="wrap" %}
```bash
# Help
root@remnux:~# vol3 -h | grep linux
    banners.Banners     Attempts to identify potential linux banners in an
    linux.bash.Bash     Recovers bash command history from memory.
    linux.check_afinfo.Check_afinfo
    linux.check_creds.Check_creds
    linux.check_idt.Check_idt
    linux.check_modules.Check_modules
    linux.check_syscall.Check_syscall
    linux.elfs.Elfs     Lists all memory mapped ELF files for all processes.
    linux.keyboard_notifiers.Keyboard_notifiers
    linux.lsmod.Lsmod   Lists loaded kernel modules.
    linux.lsof.Lsof     Lists all memory maps for all processes.
    linux.malfind.Malfind
    linux.proc.Maps     Lists all memory maps for all processes.
    linux.pslist.PsList
                        Lists the processes present in a particular linux
    linux.pstree.PsTree
    linux.tty_check.tty_check

# Example
oot@remnux:~# vol3 -f /mnt/hgfs/tmp/memory.lime linux.bash
Volatility 3 Framework 1.0.1
Progress:  100.00		Stacking attempts finished                 
PID	Process	CommandTime	Command

14100	bash	2024-04-01 03:05:59.000000 	sudo systemctl restart apache2
14100	bash	2024-04-01 03:05:59.000000 	sudo apt update
14100	bash	2024-04-01 03:05:59.000000 	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
14100	bash	2024-04-01 03:05:59.000000 	ll
14100	bash	2024-04-01 03:05:59.000000 	insmod
14100	bash	2024-04-01 03:05:59.000000 	cd LiME/
14100	bash	2024-04-01 03:05:59.000000 	sudo apt install dwarfdump
```
{% endcode %}

### Disk Analysis

Analysts can perform disk analysis using several tools, such as:

1. Autopsy
2. Sleauthkit commands
3. FTK Imager
4. elf-tools commands
5. Linux distros such as Tsurugi, SIFT or REMNUX (Need to mount the disk image first). Live response commands such as `find`, `cat`, `last -f` might helpful.

{% code overflow="wrap" %}
```bash
Note: If Autopsy or Sleauth-kit cannot open the disk partition, do convert the raw image file into E01 using FTK Imager ("Export Disk Image")
```
{% endcode %}

### Directories and Files Analysis

#### **Directory**

All directories from `/` to `/tmp` are crucial as well. Reviewing all the files in the system must ensure we find all possible findings. But what should we look at mainly during DFIR?

### Audit Logs <a href="#audit-logs" id="audit-logs"></a>

```bash
ls -al /var/log/*
ls -al /var/log/*tmp
utmpdump /var/log/btmp
utmpdump /var/run/utmp
utmpdump /var/log/wtmp
```

### Size Of File (Bytes) <a href="#size-of-file-bytes" id="size-of-file-bytes"></a>

```bash
wc -c [file]
```

### IP Making Most Requests in Access Log <a href="#ip-making-most-requests-in-access-log" id="ip-making-most-requests-in-access-log"></a>

```bash
cut -d " " -f 1 access.log | sort | uniq -c | sort -n -k 1,1
```

### Count of Unique IPs in Access Log <a href="#count-of-unique-ips-in-access-log" id="count-of-unique-ips-in-access-log"></a>

```bash
cut -d " " -f 1 access.log | sort -u | wc -l
```

### Unique User Agents in Access Log <a href="#unique-user-agents-in-access-log" id="unique-user-agents-in-access-log"></a>

```bash
awk -F \" '{ print $6 }' access.log | sort -u
```

### Most Requested URLs For POST Request in Access Log <a href="#most-requested-urls-for-post-request-in-access-log" id="most-requested-urls-for-post-request-in-access-log"></a>

```bash
awk -F \" '{ print $2 }' access.log | grep "POST" | sort | uniq -c | sort -n -k 1,1
```

### Lines In File <a href="#lines-in-file" id="lines-in-file"></a>

```bash
wc -l [file]
```

### Search Files Recursively in a Directory for Keyword <a href="#search-files-recursively-in-directory-for-keyword" id="search-files-recursively-in-directory-for-keyword"></a>

```bash
grep -H -i -r "password" /
```

### Log Analysis

Tools such as SIEM or CA scanners could speed up the analysis of the log analysis.

| Log File                       | Purpose of Analysis                                      |
| ------------------------------ | -------------------------------------------------------- |
| /var/log/syslog                | Analyze system events, errors, and warnings              |
| /var/log/kern.log              | Investigate kernel-level events and errors               |
| /var/log/dmesg                 | Examine kernel ring buffer for boot-time messages        |
| /var/logs/apache2/access.log\* | Analyze web server access logs for activity and requests |
| /var/log/httpd/                | Investigate HTTP server logs for web activity            |
| /var/log/mysqld.log            | Review MySQL server logs for database activity           |
| /var/log/mysql.log             | Examine MySQL logs for queries and errors                |
| /var/log/cron                  | Analyze cron job execution and scheduling                |
| /var/log/daemon.log            | Investigate daemon-related events and errors             |
| /var/log/auth.log              | Review authentication events and login attempts          |
| /var/log/secure                | Examine secure authentication logs (usually for SSH)     |
| /var/log/mail\*                | Analyze mail server logs for email activity              |
| /var/log/xferlog               | Investigate FTP server logs for file transfer activity   |

### **Access.log**

Examining access.log content:

{% code overflow="wrap" %}
```bash
192.168.0.164 - - [15/Mar/2024:08:33:33 +0000] "GET /wordpress/wp-admin/css/forms.min.css?ver=6.4.3 HTTP/1.1" 200 6874 "http://192.168.0.172/wordpress/wp-admin/install.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
```
{% endcode %}

* `192.168.0.164` = IP address of the client (remote host) that made the request to the server
* `[15/Mar/2024:08:33:33 +0000]` = Date and time when the request was received
* `GET /wordpress/wp-admin/css/forms.min.css?ver=6.4.3 HTTP/1.1` = HTTP Request
* `200` = HTTP status code
* `6874` = Response Size
* `http://192.168.0.172/wordpress/wp-admin/install.php` = Web page that referred the client to the requested URL
* `Mozilla/5.0 …` = User-Agent

We can use external tools such as `goaccess` to briefly analyze access.log.

### Strings Present In File <a href="#strings-present-in-file" id="strings-present-in-file"></a>

```bash
strings [filepath]
strings -e b [filepath]
```

### Decode base64 Encoded File <a href="#decode-base64-encoded-file" id="decode-base64-encoded-file"></a>

```bash
base64 -d [filename]
echo [b64stream] | base64 -d
```

### Difference Between 2 Files <a href="#difference-between-2-files" id="difference-between-2-files"></a>

```bash
diff [file1] [file2]
```

### Privilege Escalation Hunting Ideas

Execution of below commands/scripts in `~/*.history`:

{% code overflow="wrap" %}
```bash
# Find all files suid and sgid files
find / -perm -u=s -type f 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# list commands allowed using sudo
sudo -l

# GTFOBins: https://gtfobins.github.io/#

# Activity of compilation
gcc name.c -o exploit.out
./exploit.out
```
{% endcode %}

Existence and execution of Linux Privilege Escalation script such as:

1. LinPEAS
2. LinEnum
3. Linux Smart Enumeration
4. Linux exploit suggester

Kernel exploits:

1. Dirtycow
2. Dirtypipe
3. Dirtycred
4. GameOver(lay) Ubuntu Privilege Escalation
5. Many more…

Modification of these files:

```bash
/etc/init.d
/etc/cron.d 
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/passwd
/etc/shadow
/etc/at.allow
/etc/at.deny
/etc/crontab
/etc/cron.allow
/etc/cron.deny
/etc/anacrontab
/var/spool/cron/crontabs/root
/usr/lib
/lib
/etc/ld.so.conf
# Any scripts running as root
```

Another Aspects:

1. Weak/reused/plaintext passwords
2. Vulnerable installed software/binary

Get ideas from https://book.hacktricks.xyz/linux-hardening/privilege-escalation

### File Recovery

#### **debugfs for targeted file**

Using debugfs for ext3/4 file system Knowing the inode data:

{% code overflow="wrap" %}
```bash
debugfs -w /dev/sda2

# get block of data
logdump -i <inode number>

# Take note the `Blocks: (0-1)`'s value
dd if=/dev/sda2 of=data.txt bs=4096 count=1 skip=THE_VALUE
```
{% endcode %}

Not knowing the inode number:

{% code overflow="wrap" %}
```bash
debugfs -w /dev/sda2
lsdel
logdump -i <inode number>

# Take note the `Blocks: (0-1)`'s value
dd if=/dev/sda2 of=data.txt bs=4096 count=1 skip=THE_VALUE
```
{% endcode %}

### **Sleuth Kit**

#### Using tsk\_recover by SK

```bash
tsk_recover -h
tsk_recover -i raw -e image.dd /temp
```

#### **ext4magic**

Using ext4magic

```bash
sudo apt-get install ext4magic

# List deleted files from 6 hours ago
ext4magic /dev/sda2 -a $(date -d "-6hours" +%s) -f user/folder -l

# Recover file
ext4magic /dev/sda2 -a $(date -d "-6hours" +%s) -f user/folder -r -d ./recovered

# Recover all files
ext4magic /dev/sda2 -a $(date -d "-6hours" +%s) -f user/folder -m -d ./recovered
```

#### **Photorec**

```bash
apt-get install testdisk
photorec
```

### Generate Timeline Analysis

{% code overflow="wrap" %}
```bash
# Quitest timeline generator using psteal without parser, filter, sort
psteal.py --source disk_image.dd -o l2tcsv -w timeline.csv

# Simple generator
log2timeline.py out.plaso disk_image.dd

# List parsers
log2timeline.py --parsers list | more

# Use parsers
log2timeline.py -z UTC --parsers linux,apache_access,apt_history out2.plaso disk_image.dd

# Generate timeline with parser
log2timeline.py -z UTC -t / --parsers linux,apache_access,apt_history out.timeline ./

# Filter the timeline to only include specific date range
psort.py -z utc -o l2tcsv -w box.csv out.timeline "date > '2020-12-11 00:00:00' AND date < '2020-12-13 00:00:00'"
```
{% endcode %}

### References&#x20;

* [Linux Forensics Command Cheat Sheet | Ef’s log (fahmifj.github.io)](https://fahmifj.github.io/blog/linux-forensics-command-cheat-sheet/)
* [Linux Incident Response — Using ss for Network Analysis | SANS](https://www.sans.org/blog/linux-incident-response-using-ss-for-network-analysis/)
* [UFW Essentials: Common Firewall Rules and Commands | DigitalOcean](https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands)
* [Linux Incident Response Guide - DFIR - Halkyn Security Blog](https://www.halkynconsulting.co.uk/a/2020/11/linux-incident-response-guide/)
* [LetsDefend](https://app.letsdefend.io/training/lessons/incident-response-linux)
