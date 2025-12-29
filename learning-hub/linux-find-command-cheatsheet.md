# Linux Find Command Cheatsheet

### Core Syntax

```bash
find [starting_path] [options] [expression]
```

The command searches recursively from the starting path, evaluating each file against your expressions.

***

### Learning Workflow

**Phase 1: Foundation** — Master basic searches by name and type\
**Phase 2: Filtering** — Add time, size, and permission filters\
**Phase 3: Actions** — Execute commands on results\
**Phase 4: Combining** — Chain expressions with logical operators

***

### Phase 1: Basic Searches

#### By Name

```bash
# Exact filename match
find /var/log -name "syslog"

# Case-insensitive match
find /home -iname "readme.txt"

# Wildcard patterns (quote to prevent shell expansion)
find /etc -name "*.conf"
find /opt -name "log*"
```

#### By Type

| Flag      | Type          |
| --------- | ------------- |
| `-type f` | Regular file  |
| `-type d` | Directory     |
| `-type l` | Symbolic link |
| `-type s` | Socket        |
| `-type p` | Named pipe    |

```bash
# Find all directories named "config"
find /etc -type d -name "config"

# Find all symlinks in /usr
find /usr -type l
```

#### Depth Control

```bash
# Search only current directory (no recursion)
find /var/log -maxdepth 1 -name "*.log"

# Start searching at depth 2
find /home -mindepth 2 -name "*.sh"

# Search between depths 1 and 3
find /opt -mindepth 1 -maxdepth 3 -type f
```

***

### Phase 2: Filtering

#### By Time

Three time types, each with three variants:

| Base    | Meaning                              |
| ------- | ------------------------------------ |
| `mtime` | Modification time (content changed)  |
| `atime` | Access time (last read)              |
| `ctime` | Change time (metadata/inode changed) |

| Suffix   | Unit    |
| -------- | ------- |
| `-mtime` | Days    |
| `-mmin`  | Minutes |

```bash
# Modified in the last 24 hours
find /var/log -mtime -1

# Modified MORE than 30 days ago
find /tmp -mtime +30

# Modified exactly 7 days ago
find /home -mtime 7

# Accessed in the last 60 minutes
find /etc -amin -60

# Changed in the last 10 minutes (good for detecting recent activity)
find /etc -cmin -10
```

#### By Size

```bash
# Files larger than 100MB
find /var -size +100M

# Files smaller than 1KB
find /tmp -size -1k

# Files exactly 0 bytes (empty)
find /home -type f -size 0

# Size units: c (bytes), k (KB), M (MB), G (GB)
find / -size +1G 2>/dev/null
```

#### By Permissions

```bash
# Exact permission match
find /home -perm 644

# At least these permissions (all specified bits set)
find / -perm -644

# Any of these permissions (any specified bit set)
find / -perm /644

# World-writable files
find / -perm -002 -type f 2>/dev/null

# SUID bit set
find / -perm -4000 -type f 2>/dev/null

# SGID bit set
find / -perm -2000 -type f 2>/dev/null
```

#### By Ownership

```bash
# Files owned by user
find /home -user john

# Files owned by group
find /var -group www-data

# Files with no valid owner (orphaned)
find / -nouser 2>/dev/null

# Files with no valid group
find / -nogroup 2>/dev/null
```

***

### Phase 3: Actions

#### Display and Output

```bash
# Default action (print path)
find /etc -name "*.conf" -print

# Print with null delimiter (safe for filenames with spaces)
find /home -name "*.txt" -print0 | xargs -0 ls -la

# Custom output format
find /var/log -name "*.log" -printf "%p %s bytes\n"
find /home -type f -printf "%u %p\n"  # owner and path
```

**`-printf` Format Specifiers**

| Specifier | Meaning             |
| --------- | ------------------- |
| `%p`      | Full path           |
| `%f`      | Filename only       |
| `%s`      | Size in bytes       |
| `%u`      | Owner username      |
| `%g`      | Group name          |
| `%m`      | Permissions (octal) |
| `%T+`     | Modification time   |
| `%A+`     | Access time         |

#### Execute Commands

```bash
# Run command on each result ({} = placeholder)
find /tmp -name "*.tmp" -exec rm {} \;

# More efficient: batch multiple files per command
find /var/log -name "*.log" -exec ls -lh {} +

# Interactive prompt before each action
find /home -name "*.bak" -ok rm {} \;

# Delete directly (use with caution)
find /tmp -type f -mtime +7 -delete
```

#### Piping to Other Tools

```bash
# Handle filenames with spaces safely
find /home -name "*.sh" -print0 | xargs -0 chmod +x

# Count results
find /var/log -name "*.log" | wc -l

# Search within found files
find /etc -name "*.conf" -exec grep -l "password" {} +
```

***

### Phase 4: Combining Expressions

#### Logical Operators

```bash
# AND (implicit, or explicit with -a)
find /var -name "*.log" -size +10M
find /var -name "*.log" -a -size +10M

# OR
find /home -name "*.jpg" -o -name "*.png"

# NOT
find /etc -type f ! -name "*.conf"
find /tmp ! -user root

# Grouping with parentheses (escape for shell)
find /var \( -name "*.log" -o -name "*.txt" \) -mtime -1
```

#### Practical Combinations

```bash
# Config files modified recently, excluding backups
find /etc -name "*.conf" -mmin -60 ! -name "*.bak"

# Large files that aren't logs
find /var -size +100M -type f ! -name "*.log"

# Files owned by user OR group
find /home \( -user john -o -group developers \) -type f
```

***

### Troubleshooting Scenarios

#### Disk Space Investigation

```bash
# Top 20 largest files
find / -type f -exec du -h {} + 2>/dev/null | sort -rh | head -20

# Large files modified recently (possible runaway logs)
find /var -type f -size +500M -mtime -1

# Old files consuming space
find /tmp -type f -mtime +30 -exec du -sh {} + | sort -rh
```

#### Permission Issues

```bash
# Files not owned by expected user
find /var/www -type f ! -user www-data

# Directories missing execute permission
find /opt/app -type d ! -perm -111

# World-writable files (security check)
find /home -type f -perm -002 -ls
```

#### Recent Changes Investigation

```bash
# Files modified in last hour
find /etc -type f -mmin -60 -ls

# New files created today
find /var -type f -mtime 0 -ls

# Recently accessed executables
find /usr/bin -type f -amin -30
```

#### Broken Symlinks

```bash
# Find broken symbolic links
find /usr -xtype l

# Find and remove broken links
find /opt -xtype l -delete
```

#### Log File Management

```bash
# Compress old logs
find /var/log -name "*.log" -mtime +7 -exec gzip {} \;

# Remove rotated logs older than 30 days
find /var/log -name "*.gz" -mtime +30 -delete

# Find logs not modified in 24 hours (possible issues)
find /var/log -name "*.log" -mtime +1 -size 0
```

***

### DFIR-Relevant Searches

```bash
# Recently modified executables (persistence check)
find /usr/bin /usr/sbin /usr/local/bin -type f -mtime -7 -ls

# Hidden files and directories
find /home -name ".*" -type f
find /tmp -name ".*" -type d

# SUID/SGID binaries (privilege escalation vectors)
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# Files modified around incident time
find / -type f -newermt "2024-01-15 08:00" ! -newermt "2024-01-15 12:00" 2>/dev/null

# Executables in temp directories
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null

# Files with unusual extensions in web directories
find /var/www -type f \( -name "*.php5" -o -name "*.phtml" -o -name "*.asp" \)

# World-writable directories
find / -type d -perm -002 2>/dev/null

# Files owned by compromised account
find / -user compromised_user -type f -ls 2>/dev/null
```

***

### Performance Tips

```bash
# Suppress permission errors
find / -name "target" 2>/dev/null

# Exclude mounted filesystems
find / -xdev -name "*.conf"

# Exclude specific directories
find / -path "/proc" -prune -o -name "*.log" -print
find / \( -path "/proc" -o -path "/sys" \) -prune -o -type f -print

# Use -quit to stop after first match
find /var -name "specific.conf" -quit
```

***

### Quick Reference Card

| Task               | Command                                 |
| ------------------ | --------------------------------------- |
| Find by name       | `find /path -name "pattern"`            |
| Find by type       | `find /path -type f/d/l`                |
| Modified < 24h     | `find /path -mtime -1`                  |
| Larger than 100M   | `find /path -size +100M`                |
| Execute on results | `find /path ... -exec cmd {} \;`        |
| Delete matches     | `find /path ... -delete`                |
| Combine OR         | `find /path -name "*.a" -o -name "*.b"` |
| Exclude pattern    | `find /path ! -name "*.bak"`            |
| Suppress errors    | `find /path ... 2>/dev/null`            |
