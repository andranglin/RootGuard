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
