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

# Host Compromise Assessment

### Collect General Information

<pre class="language-bash"><code class="lang-bash">Description: Display the current date and time. Verify the timezone.
Command: date
Example: date #Displaying the Current Date and Time
date +"%Y-%m-%d %H:%M:%S" #Displaying the Date in a Specific Format
sudo date -s "2025-01-14 13:53:00" #Setting the System Date and Time
<strong>date -u #Displaying the Date in UTC
</strong></code></pre>

{% code overflow="wrap" %}
```bash
Description: Timezone information
Command: cat
Example: cat /etc/timezone
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: System information
Command: uname
Example: uname -a
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Network information
Command: ifconfig
Example: cat /etc/network/interfaces
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Date of installation of the OS. Check the date
Command: ls -ld
Example: ls -ld /var/log/installer
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Display distro version
Command: cat
Example: cat /etc/*-release
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Display hostname
Command: hostname
Example: cat /etc/hostname
```
{% endcode %}

### Review Activities

Investigating the executed commands of a user could give some context about an incident.

```bash
Description: Check command history
Command: history
Example: history
```

{% code overflow="wrap" %}
```bash
Description: Check all files with "history" in their name in the user's home directory
Command: cat 
Example: cat /home/$USER/.*_history
```
{% endcode %}

```bash
Description: Check the command history  (specific to bash shell)
Command: cat 
Example: cat /home/$USER/.bash_history
```

{% code overflow="wrap" %}
```bash
Description: Check the command history for the root user (specific to bash shell)
Command: cat
Example: cat /root/.bash_history
```
{% endcode %}

```bash
Description: Check the MySQL command history for the root user
Command: cat
Example: cat /root/.mysql_history
```

```bash
Description: Check the FTP command history 
Command: cat
Example: cat /home/$USER/.ftp_history
```

{% code overflow="wrap" %}
```bash
Description: Check the SFTP command history 
Command: cat 
Example: cat /home/$USER/.sftp_history
```
{% endcode %}

```bash
Description: Check the VIM editor history 
Command: cat
Example: cat /home/$USER/.viminfo
```

```bash
Description: Check the history of commands entered in the 'less' pager 
Command: cat
Example: cat /home/$USER/.lesshst
```

{% code overflow="wrap" %}
```bash
Description: Check the Git configuration 
Command: cat
Example: cat /home/$USER/.gitconfig
```
{% endcode %}

```bash
Description: List recent Git activity logs 
Command: cat
Example: ls /home/$USER/.git/logs
```

```bash
Description: List Mozilla Firefox profiles, check history and downloads
Command: ls
Example: ls /home/$USER/.mozilla/firefox
```

{% code overflow="wrap" %}
```bash
Description: List Google Chrome profiles, check history and downloads
Command: ls
Example: ls /home/$USER/.config/google-chrome
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Search for relevant commands in the authentication logs excluding cron jobs
Command: grep
Example: grep -v cron /var/log/auth.log* | grep -i -e "command=" -e "su:" -e "groupadd" -e "useradd" -e "passwd"
```
{% endcode %}

### Hunting Unusual Files

{% code overflow="wrap" %}
```bash
Description: Search for files modified within the last 5 days and Check them for further inspection; change 5 if needed
Command: find
Example: find / -type f -mtime -5 | less
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Search for files modified within the last 5 days with "php" in their name and Check them for further inspection
Command: find
Example: find / -type f -mtime -5 | grep "php"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Find files modified in the last 10 days in specified directories and Check them
Command: find
Example: find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Find files modified within the last day and print their paths
Command: find
Example: find / -type f -mtime -1 -print
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Search for files larger than 10,000 kilobytes and print their paths
Command: find 
Example: find / -type f -mtime -1 -print
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Search for files larger than 10,000 kilobytes and print their paths
Command: find
Example: find / -size +10000k -print
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List files in /usr/bin directory with their inode numbers and sort them numerically
Command: ls
Example: ls -lai /usr/bin | sort -n
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List files in /bin directory recursively, sorted by modification time
Command: ls
Example: ls -laR --sort=time /bin
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Find files owned by root with the setuid or setgid permissions and print their paths
Command: ls
Example: find / -user root -perm -04000 -print
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List all devices in the /dev directory
Command: ls
Example: ls /dev
```
{% endcode %}

### Logon activities

Review the logon activities of the compromised host.

{% code overflow="wrap" %}
```bash
Description: Check users who are currently logged in
Command: w
Example: w
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Last login information for all users. It reads the /var/log/lastlog file
Command: lastlog
Example: cat /var/log/lastlog
```
{% endcode %}

```bash
Description: List of last logged-in users and their login times
Command: last
Example: last -f /var/log/wtmp
```

{% code overflow="wrap" %}
```bash
Description: Failed login attempts
Command: last
Example: last -f /var/log/btmp
```
{% endcode %}

```bash
Description: Searching for login activities in auth.log with specific keyword
Command: Grep
Example: grep -v cron /var/log/auth.log* | grep -v sudo | grep -i user
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i Accepted
grep -v cron /var/log/auth.log* | grep -v sudo | grep -i failed
grep -v cron /var/log/auth.log* | grep -v sudo | grep i "login:session"
```

{% code overflow="wrap" %}
```bash
Description: CentOS, Red Hat Enterprise Linux (RHEL) of auth.log
Command: cat
Example: cat /var/log/secure
```
{% endcode %}

### Review Processes

Review all running processes; the following command could identify potentially malicious processes

```bash
Description: Interactive process viewer
Command: htop
Example: htop
```

{% code overflow="wrap" %}
```bash
Description: Currently running processes and its command
Command: ps 
Example: ps -aux
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List all open files associated with a specific process
Command: lsof
Example: lsof -p <PID>
```
{% endcode %}

```bash
Description: Directories that contain information about a specific process
Command: ls, cat
Example: ls /proc/<PID>
cat /proc/<PID>
```

```bash
Description: Show process in tree view
Command: pstree
Example: pstree -a
```

### Installed Programs

{% code overflow="wrap" %}
```bash
Description: Examine commands used for package installations from the APT history log for tracking software changes
Command: cat grep
Example: cat /var/log/apt/history.log | grep "Commandline"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Retrieve package names and their statuses from the dpkg status file for software inventory analysis
Command: cat grep
Example: cat /var/lib/dpkg/status | grep -E "Package:|Status:"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Review entries from the dpkg log file indicating installed packages for change analysis
Command: cat
Example: cat /var/log/dpkg.log | grep installed
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Identify executables in the /sbin directory and determine their package ownership using dpkg for attribution
Command: find
Example: find /sbin/ -exec dpkg -S {} \; | grep "no path found"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List executables in standard system directories for anomaly detection
Command: ls 
Example: ls /usr/sbin /usr/bin /bin /sbin
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List files in the APT package cache directory for investigating downloaded packages
Command: ls
Example: ls /var/cache/apt/archives
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Find based on date
Command: find 
Example: find / -type f \( -newermt "2020-12-01" -and ! -newermt "2020-12-02" \)
```
{% endcode %}

### File Investigation

```bash
Description: Collect detailed metadata about the file for forensic analysis
Command: stat
Example: stat <filename>
```

{% code overflow="wrap" %}
```bash
Description: Identify the file type and format to understand its nature
Command: file
Example: file <filename>
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Extract human-readable strings from the file for potential clues or analysis
Command: strings
Example: strings <filename>
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Generate an MD5 checksum of the file to verify integrity and check against known malware signatures
Command: md5sum
Example: md5sum <filename> # submit to VT
```
{% endcode %}







### Persistent Mechanisms

A persistent mechanism is a method used by attackers to maintain access to a compromised system across reboots or to ensure their malicious activities persist over time. Below is a potential list of the places attackers might add or modify to deploy their persistent access.&#x20;

#### **Review Account**

Review user account information and activity on the system to identify potentially active user accounts, detect anomalies in user account configurations, find files belonging to non-existent users, extract password hashes for analysis, examine group information for privilege analysis, review sudo configurations for potential privilege escalation, investigate SSH authentication keys and known hosts for unauthorized access, and analyze recently used files for user activity.

{% code overflow="wrap" %}
```bash
Description: Identify potentially active user accounts
Command: cat
Example: cat /etc/passwd | grep bash
cat /etc/passwd | grep sh
cat /etc/passwd | grep dash
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Sort user accounts by their UID to detect anomalies
Command: sort
Example: sort -nk3 -t: /etc/passwd
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Find files belonging to non-existent users (indicators of unauthorized ac
Command: find
Example: find / -nouser -print
```
{% endcode %}

```bash
Description: Extract password hashes for forensic analysis
Command: cat
Example: cat /etc/shadow
```

{% code overflow="wrap" %}
```bash
Description: Examine group information for user privilege analysis
Command: cat 
Example: cat /etc/group
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Review sudo configuration for potential privilege escalation
Command: cat
Example: cat /etc/sudoers
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Check for additional sudo configurations for backdoors
Command: cat
Example: cat /etc/sudoers.d/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Investigate SSH authentication keys for potential unauthorized access
Command: cat
Example: cat /home/$USER/.ssh/authorized_keys
```
{% endcode %}

```bash
Description: Analyze SSH known hosts for suspicious connections
Command: cat
Example: cat /home/$USER/.ssh/known_hosts
```

{% code overflow="wrap" %}
```bash
Description: Review recently used files for user activity
Command: cat
Example: cat /home/$USER/.recently-used.xbel
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
Description: Search for PHP files in the /var/www/html directory and print their modification timestamps
Command: find
Example: find /var/www/html -type f -name "*.php" -printf "%T@ %f\n" | sort -n | awk '{print strftime("%Y-%m-%d %H:%M:%S", $1), $2}'
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Monitor Apache configuration files
Command: tail
Example: tail -f /etc/apache2/*/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Monitor Nginx configuration files
Command: tail
Example: tail -f /etc/nginx/*/*
```
{% endcode %}

### **Cron Tasks**

Identify any scheduled tasks or suspicious activities that may have been configured to execute at specific times

{% code overflow="wrap" %}
```bash
Description: View the configuration of the cron service managed by systemd
Command: cat
Example: cat /lib/systemd/system/cron.service
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: View the cron tasks scheduled for a specific user
Command: crontab
Example: crontab –u <user> -l
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: View the system-wide crontab file containing system cron tasks
Command: cat
Example: cat /etc/crontab
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Check all files in /etc/cron
Command: tail
Example: tail -f /etc/cron.*/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List all user-specific cron files in the cron spool directory
Command: ls
Example: ls /var/spool/cron/crontabs/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: View the contents of the atjobs file, which contains at jobs scheduled by the at command
Command: cat
Example: cat /var/spool/cron/atjobs
```
{% endcode %}

### **Services and Systemd**

Examine systemd configurations and unit files to identify any modifications or suspicious configurations that may have been made to services or startup processes.

{% code overflow="wrap" %}
```bash
Description: List enabled services and Check their associated start commands
Command: systemctl
Example: for service in $(systemctl list-unit-files --type=service | grep enabled | awk '{print $1}'); do echo "Service: $service"; systemctl cat $service | grep ExecStart= | sed 's/^/Command: /'; echo "--------------------------------------------------"; done
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List custom systemd unit files in /etc/systemd/system/
Command: ls 
Example: ls /etc/systemd/system/
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List systemd unit files in /lib/systemd/system/
Command: ls
Example: ls /lib/systemd/system/
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List systemd system generators
Command: ls 
Example: ls /lib/systemd/system-generators/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: View contents of init.d scripts
Command: more
Example: more -f /etc/init.d/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List systemd user units in /lib/systemd/user/
Command: ls
Example: ls /lib/systemd/user/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List custom systemd user units in /etc/systemd/user/
Command: ls
Example: ls /etc/systemd/user/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List user systemd generators in /etc/systemd/user-generators/
Command: ls
Example: ls /etc/systemd/user-generators/*
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List user systemd generators in /usr/local/lib/systemd/user-generators/
Command: ls
Example: ls /usr/local/lib/systemd/user-generators/*
```
{% endcode %}

```
Description: List user systemd generators in /usr/lib/systemd/user-generators/
Command: ls
Example: ls /usr/lib/systemd/user-generators/*
```

### **SSH Daemon**

Examine the configuration of the SSH daemon and related resource files

{% code overflow="wrap" %}
```bash
Description: View the SSH service configuration managed by systemd
Command: cat
Example: cat /lib/systemd/system/ssh.service
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: View the SSH daemon configuration file
Command: cat
Example: cat /etc/ssh/sshd_config
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List any user-specific SSH resource files in the ~/.ssh directory
Command: ls
Example: ls ~/.ssh/rc
```
{% endcode %}

```
Description: List system-wide SSH resource files in the /etc/ssh directory
Command: ls
Example: ls /etc/ssh/sshrc
```

### **Login Shell**

Examine login shell configurations and scripts responsible for system initialization and startup processes.

```bash
Description: Check system-wide Bash initialization file
Command: cat
Example: cat /etc/bash.bashrc
```

```bash
Description: Check user-specific Bash initialization file
Command: cat
Example: cat /home/$USER/.bashrc
```

{% code overflow="wrap" %}
```bash
Description: Check user-specific Bash profile file
Command: cat
Example: cat /home/$USER/.bash_profile
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Check system-wide profile file
Command: cat
Example: cat /etc/profile
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Check scripts in the /etc/profile.d directory
Command: cat
Example: cat /etc/profile.d/*
```
{% endcode %}

```bash
Description: Check user-specific profile file
Command: cat
Example: cat /home/$USER/.profile
```

```bash
Description: Check user-specific Bash login file
Command: cat
Example: cat /home/$USER/.bash_login
```

```bash
Description: Check user-specific Bash logout file
Command: cat
Example: cat /home/$USER/.bash_logout
```

```
Description: Check system-wide Bash logout file
Command: cat
Example: cat /etc/.bash_logout
```

### **rc scripts**

RC scripts responsible for system initialization and startup processes.

```bash
Description: Review rc scripts
Command: cat
Example: cat /etc/rc*
```

### **Infected Binaries**

Uncover recently modified files that may indicate unauthorised activity or compromise.

{% code overflow="wrap" %}
```bash
Description: Find binaries modified within the last 10 days in specified directori
Command: find
Example: find /lib /usr/bin /usr/sbin -type f -newermt "$(date -d '10 days ago' +'%Y-%m-%d')"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List Python 3 related libraries and modules in /usr/lib directory
Command: ls
Example: ls /usr/lib/python3*
```
{% endcode %}

### Pluggable Authentication Modules (PAM) <a href="#pluggable-authentication-modules-pam" id="pluggable-authentication-modules-pam"></a>

```bash
Description: Display contents of the PAM configuration file
Command: cat
Example: cat /etc/pam.conf
```

```bash
Description: Check contents of the PAM directory
Command: cat
Example: cat /etc/pam.d
cat /etc/pam.d/sudo
cat /etc/pam.conf
ls /etc/pam.d/
```

### **Message of the Day (MOTD)**

“motd” stands for “message of the day”. These scripts may contain important system status updates, notifications, or potentially malicious content inserted by attackers.

{% code overflow="wrap" %}
```bash
Description: Examine the scripts responsible for generating dynamic messages displayed to users upon login
Command: cat
Example: cat /etc/update-motd.d/*
```
{% endcode %}

### Unusual System Resources

These commands provide information about system uptime, memory usage, and disk space usage, which can help identify abnormal behaviour such as high resource consumption, potential denial of service attacks, or disk space exhaustion.

{% code overflow="wrap" %}
```bash
Description: Display system uptime and load average
Command: uptime
Example: uptime
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Display memory usage statistics
Command: free
Example: free
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Display disk space usage statistics
Command: df
Example: df
```
{% endcode %}

### Hunting Rootkit

#### To hunt via 3rd party software

{% code overflow="wrap" %}
```bash
Description: Detect rootkits on Linux systems
Command: chkrootkit
Example: chkrootkit
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Detect rootkits on Linux systems
Command: rkhunter
Example: rkhunter --check
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Comprehensive security auditing tool that includes checks for rootkits among other security issues:
Command: lynis audit system
Example: lynis audit system
```
{% endcode %}

```bash
Description: Antivirus scanner for malware
Command: clamscan -r /
Example: clamscan -r /
```

#### Hunting and Check Files and Processes

```bash
Description: Inspect dir and files
Command: fing
Example: find /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec ls -la {} \;
```

```bash
Description: Check running process with root priv
Command: ps
Example: ps aux | grep -i root
```

```bash
Description: Check unusual network connections
Command: netstat
Example: netstat -antup
```

{% code overflow="wrap" %}
```bash
Description: Compare checksums or file hashes against known good values
Command: sha256sum
Example: sha256sum /bin/* /sbin/* /usr/bin/* /usr/sbin/* /lib/* /lib64/* /etc/* | sort > current_checksums.txt
```
{% endcode %}

### Disk imaging using dd

Collecting digital disk image of the Linux system is essential to perform disk analysis offline. This activity is required to find suspicious files and folders, recover files and extract artifacts (triage) from the disk.

{% code overflow="wrap" %}
```bash
Description: List all devices to identify the disk device for disk imaging
Command: lsblk
Example: lsblk
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: List partition tables for disk devices
Command: fdisk
Example: fdisk -l
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Perform disk imaging to an external disk or shared folder
# Replace "sdb" with the appropriate disk device identifier
Command: dd
Example: dd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img
```
{% endcode %}

{% code overflow="wrap" %}
```bash
Description: Alternatively, use dcfldd to perform hashing while imaging
Command: dcfldd
Example: dcfldd if=/dev/sdb of=/media/sf_tmp/linux_forensic.img hash=sha256 hashwindow=1M hashlog=/media/sf_tmp/linux_forensic.hash
```
{% endcode %}

### References&#x20;

* [Linux Forensics Command Cheat Sheet | Ef’s log (fahmifj.github.io)](https://fahmifj.github.io/blog/linux-forensics-command-cheat-sheet/)
* [Linux Incident Response — Using ss for Network Analysis | SANS](https://www.sans.org/blog/linux-incident-response-using-ss-for-network-analysis/)
* [UFW Essentials: Common Firewall Rules and Commands | DigitalOcean](https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands)
* [Linux Incident Response Guide - DFIR - Halkyn Security Blog](https://www.halkynconsulting.co.uk/a/2020/11/linux-incident-response-guide/)
* [LetsDefend](https://app.letsdefend.io/training/lessons/incident-response-linux)
