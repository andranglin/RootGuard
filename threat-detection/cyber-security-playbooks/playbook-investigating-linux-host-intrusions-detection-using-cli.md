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

# Playbook: Investigating Linux Host Intrusions Detection Using CLI

### Table of Contents

1. Initial Compromise Detection
   * Detect Suspicious Processes
   * Identify Exploited Services
   * Advanced Suspicious Command Detection
2. Persistence Mechanisms
   * Detect Cronjob Modifications
   * Monitor SSH Key Additions
   * Advanced Persistence Detection via Startup Scripts
3. Privilege Escalation and Credential Theft
   * Detect Sudo Abuse
   * Credential Dumping Attempts
   * Advanced Kernel Exploit Detection
4. Lateral Movement Detection
   * Detect SSH Lateral Movement
   * Monitor File Transfers via SCP or Rsync
   * Advanced Detection of Exploited Protocols
5. Data Exfiltration Indicators
   * Large Data Transfers via Network
   * Use of Compression Tools
   * DNS or HTTPS Exfiltration
6. Post-Incident Investigation
   * Correlation of File Hashes
   * Compromised User Accounts
   * Incident Timeline Reconstruction
7. Conclusion

***

This playbook provides a structured approach to investigating Linux-based intrusions on a host system. Each section focuses on specific detection and analysis phases using advanced queries and techniques. The focus is on using the commandline options

### 1. **Initial Compromise Detection**

The first step is identifying the initial point of compromise, often involving malicious processes or exploited services.

#### Query Option 1: Detect Suspicious Processes

```bash
ps aux --sort=-%cpu,-%mem | awk '{if($3>20.0 || $4>20.0) print $0}'
```

**Description:** Lists processes consuming abnormally high CPU or memory, which could indicate malicious activity. Results include process details and resource usage.

#### Query Option 2: Identify Exploited Services

```bash
sudo netstat -tulnp | grep -E '(:22|:80|:443)'
```

**Description:** Identifies active listening services on common ports (SSH, HTTP, HTTPS) and links them to associated processes. Useful for spotting compromised services.

#### Query Option 3: Advanced Suspicious Command Detection

```bash
journalctl -u ssh | grep -iE '(Accepted|Failed password|root login)'
```

**Description:** Searches SSH logs for signs of brute force or unauthorised access attempts. Results display timestamps, IP addresses, and access outcomes.

***

### 2. **Persistence Mechanisms**

Attackers often use persistence techniques to maintain access.

#### Query Option 1: Detect Cronjob Modifications

```bash
cat /etc/crontab /etc/cron.*/* | grep -v '^#'
```

**Description:** Extracts all active cronjobs, which may reveal malicious scripts scheduled for execution. Results show cronjob commands and schedules.

#### Query Option 2: Monitor SSH Key Additions

```bash
find /root/.ssh /home/*/.ssh -name authorized_keys -exec ls -l {} \;
```

**Description:** Tracks additions to SSH authorised\_keys files, often used for persistence. Results display file details and timestamps.

#### Query Option 3: Advanced Persistence Detection via Startup Scripts

{% code overflow="wrap" %}
```bash
find /etc/init.d /etc/systemd/system /etc/rc.d -type f -exec grep -i malicious_keyword {} +
```
{% endcode %}

**Description:** Scans startup scripts for suspicious keywords indicative of malicious persistence. Results include file paths and matching lines.

***

### 3. **Privilege Escalation and Credential Theft**

Detecting privilege escalation and credential theft attempts is crucial to mitigating further damage.

#### Query Option 1: Detect Sudo Abuse

```bash
cat /var/log/auth.log | grep 'sudo:' | grep 'COMMAND'
```

**Description:** Extracts logs of sudo command usage, revealing potential abuse of elevated privileges. Results include command details and users.

#### Query Option 2: Credential Dumping Attempts

```bash
grep -iE '(hashcat|john|mimikatz)' ~/.bash_history
```

**Description:** Searches shell history for usage of credential-dumping tools. Results display command-line activities.

#### Query Option 3: Advanced Kernel Exploit Detection

```bash
dmesg | grep -iE '(exploit|segfault|ptrace)'
```

**Description:** Analyses kernel logs for signs of exploit attempts. Results include timestamps and kernel messages.

***

### 4. **Lateral Movement Detection**

Attackers often spread across the network after the initial compromise.

#### Query Option 1: Detect SSH Lateral Movement

```bash
cat /var/log/auth.log | grep 'Accepted publickey'
```

**Description:** Identifies SSH logins using public key authentication. Results include IP addresses, usernames, and timestamps.

#### Query Option 2: Monitor File Transfers via SCP or Rsync

```bash
lsof -i :22 | grep 'ssh'
```

**Description:** Tracks file transfer activities over SSH. Results display active SSH sessions and file operations.

#### Query Option 3: Advanced Detection of Exploited Protocols

```bash
sudo tcpdump -i eth0 'port 22 or port 111' -vv
```

**Description:** Captures network traffic on ports commonly exploited (e.g., SSH, RPC). Results include packet details and connection attempts.

***

### 5. **Data Exfiltration Indicators**

Signs of data exfiltration should be promptly identified to mitigate loss.

#### Query Option 1: Large Data Transfers via Network

```bash
sudo iftop -i eth0 -n -P
```

**Description:** Monitors real-time network traffic for large outbound data transfers. Results include source and destination IPs and transfer sizes.

#### Query Option 2: Use of Compression Tools

```bash
find / -name '*.zip' -o -name '*.tar.gz' -exec ls -l {} \;
```

**Description:** Searches for recently created compressed files, often used for exfiltration. Results display file details and timestamps.

#### Query Option 3: DNS or HTTPS Exfiltration

```bash
sudo tcpdump -i eth0 'port 53 or port 443' -vv
```

**Description:** Analyses DNS or HTTPS traffic for unusual patterns indicative of exfiltration. Results include packet details and domain names.

***

### 6. **Post-Incident Investigation**

Once the threat is contained, further investigation can determine the scope and impact.

#### Query Option 1: Correlation of File Hashes

```bash
find / -type f -exec sha256sum {} + | grep -f known_hashes.txt
```

**Description:** Compares file hashes across the system to known malicious hashes. Results include file paths and matching hashes.

#### Query Option 2: Compromised User Accounts

```bash
cat /var/log/auth.log | grep 'Invalid user'
```

**Description:** Identifies login attempts targeting non-existent or disabled accounts. Results include usernames, IP addresses, and timestamps.

#### Query Option 3: Incident Timeline Reconstruction

```bash
ausearch -ts recent -m EXECVE,CONNECT -i
```

**Description:** Creates a timeline of executed commands and network connections. Results include detailed events with timestamps.

***

### Conclusion

This playbook provides a good approach to detecting and analysing Linux-based intrusions on a host machine. However, in some circumstances, the investigation requires going beyond a single host. On these occasions, refer to the Playbook: Investigating Linux Intrusions Across an Enterprise.
