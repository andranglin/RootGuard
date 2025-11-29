# PowerShell for Junior SOC Analysts

### From Zero to Security Hero - A Beginner's Complete Guide

***

### 👋 Welcome to Your PowerShell Journey!

If you're new to SOC work or PowerShell, you're in the right place! This guide assumes you're starting from scratch. We'll build your skills step-by-step, focusing on practical security tasks you'll do every day as a SOC analyst.

**What You'll Learn:**

* PowerShell basics explained in plain English
* How to investigate security alerts
* Finding suspicious activity on computers
* Analysing logs to spot attackers
* Automating repetitive security tasks
* Building your first security scripts

**No prior PowerShell experience needed!** We'll start with the absolute basics and build from there.

***

### 🎓 PowerShell Basics - Plain English Explanations

#### What is PowerShell?

Think of PowerShell as a way to talk directly to Windows computers. Instead of clicking through menus, you type commands. This is much faster for security work!

**Why PowerShell for SOC Analysts?**

* Investigate 100 computers as easily as investigating 1
* Find suspicious activity in seconds instead of hours
* Automate boring, repetitive tasks
* See information GUIs don't show you

#### Understanding Commands (Cmdlets)

PowerShell commands are called "cmdlets" (pronounced "command-lets"). They follow a Verb-Noun pattern:

```ps1
Get-Process    (Get = verb, Process = noun)
Stop-Service   (Stop = verb, Service = noun)
Start-Process  (Start = verb, Process = noun)
```

**Common Verbs:**

* `Get` = Retrieve information
* `Set` = Change something
* `Start` = Begin something
* `Stop` = End something
* `Remove` = Delete something
* `New` = Create something

#### Your First Commands

```powershell
# Get help on any command
Get-Help Get-Process

# See examples of how to use a command
Get-Help Get-Process -Examples

# Find commands (use * as wildcard)
Get-Command *process*

# See what properties an object has
Get-Process | Get-Member
```

**Pro Tip:** Use Tab to auto-complete! Type `Get-Proc` then hit Tab, and PowerShell fills in the rest!

***

### 📖 Beginner's Security Cheatsheet

#### Starting PowerShell

```powershell
# Regular PowerShell (for most tasks)
# Click Start, type "PowerShell", press Enter

# PowerShell as Administrator (for some security tasks)
# Click Start, type "PowerShell", right-click, "Run as Administrator"
```

#### Getting Help (Your #1 Tool!)

```powershell
# Basic help
Get-Help Get-Process

# Detailed help with examples
Get-Help Get-Process -Full

# Just show me examples!
Get-Help Get-Process -Examples

# Open help in browser
Get-Help Get-Process -Online

# Find commands about "service"
Get-Command *service*
```

#### Basic Process Investigation

```powershell
# See all running programs
Get-Process

# See specific columns only
Get-Process | Select-Object Name, Id, Path

# Sort by CPU usage (highest first)
Get-Process | Sort-Object CPU -Descending

# Find a specific process
Get-Process -Name chrome

# Find processes with "notepad" in the name
Get-Process | Where-Object {$_.Name -like "*notepad*"}

# Show processes NOT from Microsoft
Get-Process | Where-Object {$_.Company -notlike "Microsoft*"}

# Export to a file you can open in Excel
Get-Process | Export-Csv -Path C:\temp\processes.csv -NoTypeInformation
```

**What Am I Looking For?**

* Processes without a Company name (might be suspicious)
* Processes running from weird locations (like C:\Temp)
* Unfamiliar process names
* Processes using lots of CPU or memory

#### Service Investigation

```powershell
# List all services
Get-Service

# Show only running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Find a specific service
Get-Service -Name "Windows Defender"

# Show services that are set to start automatically
Get-Service | Where-Object {$_.StartType -eq "Automatic"}

# Find non-Microsoft services
Get-Service | Where-Object {$_.DisplayName -notlike "Microsoft*"}
```

**Security Note:** Attackers often install malicious services. Look for:

* Services with unusual names
* Services not from known vendors
* Services running from user folders

#### Network Connection Checks

{% code overflow="wrap" %}
```powershell
# See all active network connections
Get-NetTCPConnection

# Show only established connections (active right now)
Get-NetTCPConnection -State Established

# See what's listening for incoming connections
Get-NetTCPConnection -State Listen

# Show connections with process names
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

# Find which program owns a connection
Get-Process -Id 1234  # Replace 1234 with the OwningProcess number
```
{% endcode %}

**What to Look For:**

* Connections to suspicious IP addresses
* Unusual ports (not 80, 443, which are normal web traffic)
* Programs you don't recognize making connections

#### User Account Investigation

```powershell
# List all local users
Get-LocalUser

# Show only enabled accounts
Get-LocalUser | Where-Object {$_.Enabled -eq $true}

# List members of Administrators group
Get-LocalGroupMember -Group "Administrators"

# See when users last logged in
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

**Security Red Flags:**

* User accounts you don't recognise
* Accounts that shouldn't be administrators
* Recently created accounts
* Disabled accounts that are now enabled

#### Event Log Basics - Finding Failed Logins

```powershell
# Get recent Security log events
Get-WinEvent -LogName Security -MaxEvents 100

# Find failed login attempts (Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# Get just the most recent 20 failed logins
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20

# Failed logins in the last hour
$OneHourAgo = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=$OneHourAgo
}

# See the details in a readable format
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 | 
    Format-List TimeCreated, Message
```

**Important Event IDs to Remember:**

* **4624** = Successful login
* **4625** = Failed login (potential brute force!)
* **4688** = New process started
* **4672** = Special privileges assigned (admin login)
* **4720** = User account created

#### Event Log Basics - Process Creation

```powershell
# See programs that were started (Event ID 4688)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 50

# Find specific program executions
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 1000 |
    Where-Object {$_.Message -like "*powershell*"}

# See what commands were run (if command-line logging is enabled)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 50 |
    Format-List TimeCreated, Message
```

#### PowerShell Activity Logs

```powershell
# See PowerShell commands that were run (Event ID 4104)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 20

# Look for suspicious PowerShell activity
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 500 | Where-Object {
    $_.Message -like "*DownloadString*" -or
    $_.Message -like "*Invoke-Expression*" -or
    $_.Message -like "*IEX*"
}
```

**Why This Matters:** Attackers love using PowerShell! Look for:

* `Invoke-Expression` or `IEX` (running downloaded code)
* `DownloadString` (downloading from the internet)
* Long, encoded commands (trying to hide what they're doing)

#### File Investigation

```powershell
# List files in a folder
Get-ChildItem -Path C:\Users\YourName\Downloads

# Find all .exe files in a folder (including subfolders)
Get-ChildItem -Path C:\Temp -Recurse -Filter *.exe

# Find recently created files (last 24 hours)
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1)}

# Find files modified today
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime.Date -eq (Get-Date).Date}

# Get file hash (fingerprint)
Get-FileHash -Path C:\suspicious\file.exe -Algorithm SHA256

# Check multiple files at once
Get-ChildItem -Path C:\Downloads -Filter *.exe | Get-FileHash
```

**Security Uses:**

* Find recently downloaded executables
* Identify files by their hash
* Locate files in suspicious locations

#### Checking Startup Programs (Persistence)

```powershell
# Check Registry Run keys (programs that start with Windows)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Check Startup folder
Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# List scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}

# Show scheduled tasks with their actions
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | 
    Select-Object TaskName, TaskPath, State
```

**Why Check These?** Malware often sets itself to run automatically when Windows starts. These are the most common places it hides.

***

### 🔍 Common Investigation Scenarios

#### Scenario 1: "Check if someone tried to hack into this account"

```powershell
# Look for failed login attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100

# Count failed logins per username
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 1000 |
    ForEach-Object {
        # Extract username from the event
        $_.Properties[5].Value
    } | Group-Object | Sort-Object Count -Descending

# Find failed logins in the last 24 hours
$Yesterday = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=$Yesterday
} | Select-Object TimeCreated, Message
```

**What You're Looking For:**

* Many failed attempts = possible brute force attack
* Failed logins at odd hours (2 AM, etc.)
* Logins from unusual locations

#### Scenario 2: "This computer is acting weird, is there malware?"

```powershell
# Step 1: Check for suspicious processes
Get-Process | Where-Object {
    $_.Company -eq $null -and $_.Path -ne $null
} | Select-Object Name, Path, Id

# Step 2: Check for processes from temp folders
Get-Process | Where-Object {
    $_.Path -like "*\Temp\*" -or
    $_.Path -like "*\AppData\Local\Temp\*"
} | Select-Object Name, Path, Id

# Step 3: Look for unusual network connections
Get-NetTCPConnection -State Established | 
    Where-Object {$_.RemotePort -notin @(80, 443)} |
    Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess

# Step 4: Check what's set to run at startup
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

#### Scenario 3: "Someone ran a suspicious command - find out what happened"

```powershell
# Look for PowerShell execution
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 100

# Search for specific keywords
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 500 | Where-Object {
    $_.Message -like "*password*" -or
    $_.Message -like "*download*"
}

# Check process creation logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 100
```

#### Scenario 4: "Find all activity from this user in the last week"

```powershell
# Set time range
$StartTime = (Get-Date).AddDays(-7)

# Find logon events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624,4625
    StartTime=$StartTime
} | Where-Object {$_.Properties[5].Value -eq "USERNAME"} |
    Select-Object TimeCreated, Id, Message

# Find process executions by this user
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=$StartTime
} | Where-Object {$_.Properties[1].Value -like "*USERNAME*"} |
    Select-Object TimeCreated, Message
```

***

### 💡 Understanding PowerShell Concepts

#### Variables (Storing Information)

Variables let you save information to use later. They start with `$`:

```powershell
# Store a single value
$computerName = "WORKSTATION01"

# Store a list of computers
$computers = @("PC1", "PC2", "PC3")

# Store the current date/time
$now = Get-Date

# Store command output
$runningProcesses = Get-Process

# Use the variable
Get-Process -ComputerName $computerName
```

#### The Pipeline (Chaining Commands)

The pipeline `|` sends output from one command to another:

```powershell
# Step 1: Get all processes
# Step 2: Filter for Chrome
# Step 3: Show only Name and ID columns
Get-Process | Where-Object {$_.Name -eq "chrome"} | Select-Object Name, Id

# Think of it like an assembly line:
# Command 1 → Command 2 → Command 3 → Result
```

#### Filtering with Where-Object

`Where-Object` is like a filter - it only lets matching items through:

```powershell
# Show only running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Show processes using more than 100 MB memory
Get-Process | Where-Object {$_.WorkingSet -gt 100MB}

# Comparison operators:
# -eq  equals
# -ne  not equals
# -gt  greater than
# -lt  less than
# -like  wildcard match (use * for wildcard)
# -notlike  doesn't match pattern
```

#### Selecting Specific Properties

`Select-Object` picks which columns to show:

```powershell
# Show only Name and Status
Get-Service | Select-Object Name, Status

# Show first 10 results
Get-Process | Select-Object -First 10

# Show everything except certain columns
Get-Process | Select-Object * -ExcludeProperty Handles, Threads
```

#### Formatting Output

```powershell
# Table format (default for most commands)
Get-Process | Format-Table Name, Id, CPU

# List format (shows more detail)
Get-Process | Format-List Name, Id, Path, Company

# Auto-size columns to fit
Get-Process | Format-Table -AutoSize

# Grid view (interactive window)
Get-Process | Out-GridView
```

***

### 🎯 Your First Security Scripts

#### Script 1: Quick System Security Check

Save this as `Quick-SecurityCheck.ps1`:

{% code overflow="wrap" %}
```powershell
# Quick Security Check Script
# For: Junior SOC Analysts
# Purpose: Fast security overview of a computer

Write-Host "=== QUICK SECURITY CHECK ===" -ForegroundColor Cyan
Write-Host "Started at: $(Get-Date)" -ForegroundColor Green
Write-Host ""

# Check 1: Suspicious Processes
Write-Host "[1] Checking for suspicious processes..." -ForegroundColor Yellow
$suspiciousProcesses = Get-Process | Where-Object {
    $_.Company -eq $null -and $_.Path -ne $null
}

if ($suspiciousProcesses) {
    Write-Host "⚠ Found processes without company information:" -ForegroundColor Red
    $suspiciousProcesses | Select-Object Name, Path, Id | Format-Table
} else {
    Write-Host "✓ No obviously suspicious processes found" -ForegroundColor Green
}

# Check 2: Failed Login Attempts (last hour)
Write-Host "`n[2] Checking failed logins..." -ForegroundColor Yellow
$oneHourAgo = (Get-Date).AddHours(-1)
$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=$oneHourAgo
} -ErrorAction SilentlyContinue

if ($failedLogins) {
    Write-Host "⚠ Found $($failedLogins.Count) failed login(s) in last hour" -ForegroundColor Red
} else {
    Write-Host "✓ No failed logins in last hour" -ForegroundColor Green
}

# Check 3: Listening Network Ports
Write-Host "`n[3] Checking listening ports..." -ForegroundColor Yellow
$listening = Get-NetTCPConnection -State Listen | 
    Where-Object {$_.LocalPort -notin @(135, 445, 3389, 5985)}

if ($listening) {
    Write-Host "Found non-standard listening ports:" -ForegroundColor Yellow
    $listening | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table
} else {
    Write-Host "✓ Only standard ports listening" -ForegroundColor Green
}

# Check 4: Startup Programs
Write-Host "`n[4] Checking startup programs..." -ForegroundColor Yellow
$runKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
if ($runKey) {
    Write-Host "Programs set to run at startup:"
    $runKey.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | 
        Select-Object Name, Value | Format-Table
}

Write-Host "`n=== CHECK COMPLETE ===" -ForegroundColor Cyan
Write-Host "Finished at: $(Get-Date)" -ForegroundColor Green
```
{% endcode %}

**How to Run:**

1. Save the code above as `Quick-SecurityCheck.ps1`
2. Open PowerShell as Administrator
3. Navigate to where you saved it: `cd C:\Scripts`
4. Run it: `.\Quick-SecurityCheck.ps1`

#### Script 2: Failed Login Monitor

{% code overflow="wrap" %}
```powershell
# Failed Login Monitor
# Alerts when there are too many failed logins

# How many failed logins before we alert?
$threshold = 5

# How far back to look (in hours)?
$hoursBack = 1

# Get failed logins
$startTime = (Get-Date).AddHours(-$hoursBack)
$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=$startTime
} -ErrorAction SilentlyContinue

# Count them
$count = $failedLogins.Count

# Display results
Write-Host "Failed Login Check - Last $hoursBack hour(s)" -ForegroundColor Cyan
Write-Host "Failed attempts found: $count" -ForegroundColor Yellow

if ($count -gt $threshold) {
    Write-Host "⚠ ALERT: More than $threshold failed logins detected!" -ForegroundColor Red
    Write-Host "This could indicate a brute force attack.`n" -ForegroundColor Red
    
    # Show details
    Write-Host "Recent failed attempts:" -ForegroundColor Yellow
    $failedLogins | Select-Object TimeCreated, Message -First 10
} else {
    Write-Host "✓ Login attempts within normal range" -ForegroundColor Green
}
```
{% endcode %}

#### Script 3: Process Investigator

{% code overflow="wrap" %}
```powershell
# Process Investigator
# Helps investigate a specific process

# Get process name from user
$processName = Read-Host "Enter process name to investigate (e.g., chrome)"

# Find the process
$processes = Get-Process -Name $processName -ErrorAction SilentlyContinue

if (-not $processes) {
    Write-Host "Process '$processName' not found!" -ForegroundColor Red
    exit
}

foreach ($proc in $processes) {
    Write-Host "`n=== PROCESS DETAILS ===" -ForegroundColor Cyan
    Write-Host "Name: $($proc.Name)"
    Write-Host "Process ID: $($proc.Id)"
    Write-Host "Path: $($proc.Path)"
    Write-Host "Company: $($proc.Company)"
    Write-Host "Start Time: $($proc.StartTime)"
    Write-Host "CPU Time: $($proc.CPU) seconds"
    Write-Host "Memory: $([math]::Round($proc.WorkingSet / 1MB, 2)) MB"
    
    # Check signature
    if ($proc.Path) {
        $sig = Get-AuthenticodeSignature -FilePath $proc.Path
        Write-Host "Digital Signature: $($sig.Status)" -ForegroundColor $(
            if ($sig.Status -eq 'Valid') {'Green'} else {'Red'}
        )
    }
    
    # Check network connections
    $connections = Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq $proc.Id}
    if ($connections) {
        Write-Host "`nNetwork Connections:" -ForegroundColor Yellow
        $connections | Select-Object LocalPort, RemoteAddress, RemotePort, State | Format-Table
    }
}
```
{% endcode %}

***

### 📚 Learning Resources for Beginners

#### Free Online Resources

**Official Microsoft Documentation:**

* PowerShell 101 for Beginners: https://docs.microsoft.com/powershell/scripting/learn/ps101/00-introduction
* PowerShell Learn Modules: https://docs.microsoft.com/learn/browse/?terms=PowerShell

**YouTube Channels:**

* John Hammond (Security + PowerShell)
* ITPro.TV PowerShell courses
* Shane Young's PowerShell basics

**Practice Platforms:**

* OverTheWire Bandit (Linux/command line fundamentals)
* UnderTheWire (PowerShell-specific challenges)
* TryHackMe (security-focused practice)

#### Books for Beginners

* "Learn PowerShell in a Month of Lunches" by Travis Plunk
* "PowerShell for Sysadmins" by Adam Bertram
* "Windows PowerShell Cookbook" by Lee Holmes

#### Communities & Help

* Reddit: r/PowerShell (very beginner-friendly!)
* PowerShell.org Forums
* Discord: PowerShell Server
* Stack Overflow (tag: powershell)

***

### 🎓 Practice Exercises

#### Week 1 Exercises

**Exercise 1: Command Discovery**

1. Find all commands that work with services
2. Find all commands that work with processes
3. Find commands that can "stop" things

**Exercise 2: Process Investigation**

1. List all running processes
2. Find all Chrome processes
3. Find the process using the most memory
4. Export all processes to a CSV file

**Exercise 3: Service Management**

1. List all services
2. Find all stopped services
3. Find services that start automatically
4. Count how many services are running

#### Week 2 Exercises

**Exercise 4: Network Connections**

1. Show all established connections
2. Find what's listening on your computer
3. Identify which process owns port 443
4. Count total active connections

**Exercise 5: User Investigation**

1. List all local users
2. Find administrators
3. Show enabled vs disabled accounts
4. Find when each user last logged in

**Exercise 6: Pipeline Practice**

1. Get processes, filter for Microsoft, sort by memory
2. Get services, filter for running, export to CSV
3. Get processes, filter by name, show only 3 properties

#### Week 3-4 Exercises

**Exercise 7: Event Log Basics**

1. Get last 100 Security log events
2. Find Event ID 4624 (successful logins)
3. Count Event ID 4625 (failed logins) in last hour
4. Show failed logins in a readable format

**Exercise 8: Time-Based Filtering**

1. Find events from the last hour
2. Find events from yesterday
3. Find events between two specific times
4. Count events per hour

**Exercise 9: PowerShell Activity**

1. Find all PowerShell execution logs
2. Search for specific command keywords
3. Show who ran PowerShell commands
4. Find PowerShell run in last 24 hours

#### Week 5-6 Exercises

**Exercise 10: File Investigation**

1. List all files in Downloads folder
2. Find all .exe files
3. Find files created today
4. Calculate hash of a file

**Exercise 11: Startup Investigation**

1. Check both Run registry keys
2. Check Startup folders
3. List scheduled tasks
4. Identify non-Microsoft startup items

**Exercise 12: Building Your First Script**

1. Create a script that checks for suspicious processes
2. Add comments explaining what each line does
3. Save and run your script
4. Show results to a mentor/peer

***

### ⚠️ Common Beginner Mistakes (And How to Avoid Them)

#### Mistake 1: Not Using Get-Help

**Wrong Approach:** Guessing command parameters&#x20;

**Right Approach:** Always check help first

```powershell
# Always start with help!
Get-Help Get-Process -Examples
```

#### Mistake 2: Forgetting -ErrorAction

**Problem:** Scripts stop when they hit errors&#x20;

**Solution:** Use error handling

```powershell
# Bad: Will stop if folder doesn't exist
Get-ChildItem -Path C:\MightNotExist -Recurse

# Good: Continues even if there are errors
Get-ChildItem -Path C:\MightNotExist -Recurse -ErrorAction SilentlyContinue
```

#### Mistake 3: Not Filtering at the Source

**Slow Way:**

```powershell
# Gets ALL events, then filters (slow!)
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}
```

**Fast Way:**

```powershell
# Filters while getting events (fast!)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}
```

#### Mistake 4: Forgetting to Run as Administrator

Some commands need admin rights. If a command fails, try running PowerShell as Administrator.

#### Mistake 5: Not Exporting Results

Always save your findings!

```powershell
# Export so you have a record
Get-Process | Export-Csv -Path C:\Temp\processes.csv -NoTypeInformation
```

***

### 🎯 30-Day Challenge for Beginners

**Week 1: Foundations**

* Day 1-7: Run one new command every day and document what it does
* Goal: Learn 7 essential cmdlets by heart

**Week 2: Investigation Basics**

* Day 8-14: Investigate your own computer daily
* Goal: Find and document all startup programs, services, and scheduled tasks

**Week 3: Event Logs**

* Day 15-21: Check event logs daily for specific Event IDs
* Goal: Understand the top 10 security Event IDs

**Week 4: Scripting**

* Day 22-28: Write one small script per day
* Goal: Build a personal toolkit of 7 useful scripts

**Week 5: Real Practice**

* Day 29-30: Combine everything into a comprehensive security check
* Goal: Create your first professional investigation script

***

### 🏆 Success Milestones

#### Milestone 1: First Week ✓

* \[ ] Can open PowerShell and run basic commands
* \[ ] Understand Get-Help and Get-Command
* \[ ] Can list processes and services
* \[ ] Understand the pipeline concept

#### Milestone 2: First Month ✓

* \[ ] Can investigate processes, services, and network connections
* \[ ] Understand basic event log queries
* \[ ] Can filter and format output
* \[ ] Have written first simple script

#### Milestone 3: Two Months ✓

* \[ ] Comfortable with event log investigations
* \[ ] Can check for persistence mechanisms
* \[ ] Understand file hashing
* \[ ] Have a personal script library
* \[ ] Can conduct basic security investigations

#### Milestone 4: Ready for More ✓

* \[ ] Can investigate security alerts independently
* \[ ] Comfortable scripting common tasks
* \[ ] Understand what to look for in investigations
* \[ ] Ready to learn intermediate PowerShell

***

### 🚀 Next Steps After This Guide

Once you complete this beginner guide, you're ready for:

1. **Intermediate PowerShell Skills:**
   * Advanced filtering and searching
   * Remote computer investigation
   * Custom functions and modules
   * Error handling and logging
2. **Security-Specific Topics:**
   * MITRE ATT\&CK framework
   * Threat hunting techniques
   * Malware analysis basics
   * Incident response procedures
3. **Automation & Efficiency:**
   * Writing production scripts
   * Scheduled automation
   * Integration with SIEM tools
   * Building detection rules
4. **Certifications to Consider:**
   * CompTIA Security+
   * Microsoft Security Operations Analyst (SC-200)
   * GIAC Security Essentials (GSEC)

***

### 💡 Quick Reference Card

#### Most Important Commands for SOC Work

```powershell
# Get help on anything
Get-Help <command> -Examples

# Process investigation
Get-Process | Where-Object {$_.Company -eq $null}

# Service check
Get-Service | Where-Object {$_.Status -eq "Running"}

# Network connections
Get-NetTCPConnection -State Established

# Failed logins
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# Successful logins
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624}

# PowerShell activity
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
}

# Startup programs
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# File hash
Get-FileHash -Path C:\file.exe -Algorithm SHA256

# Export results
<command> | Export-Csv -Path C:\output.csv -NoTypeInformation
```

#### Key Event IDs to Memorise

| Event ID | What It Means                | Log Source             |
| -------- | ---------------------------- | ---------------------- |
| 4624     | Successful login             | Security               |
| 4625     | Failed login                 | Security               |
| 4688     | Process created              | Security               |
| 4672     | Admin privileges assigned    | Security               |
| 4720     | User account created         | Security               |
| 4728     | User added to security group | Security               |
| 4104     | PowerShell script block      | PowerShell/Operational |
| 7045     | Service installed            | System                 |

***

### 🆘 Getting Help When Stuck

**When you don't understand a command:**

```powershell
Get-Help <command> -Full
Get-Help <command> -Examples
Get-Help <command> -Online
```

**When you get an error:**

1. Read the error message carefully (it usually tells you what's wrong!)
2. Check if you need to run as Administrator
3. Search the error message on Google
4. Ask in PowerShell communities

**Where to Ask Questions:**

* Reddit: r/PowerShell (very helpful community!)
* PowerShell.org forums
* Stack Overflow (tag: PowerShell)
* Your SOC team members (they were beginners once too!)

**Pro Tip:** When asking for help, include:

* What you're trying to do
* The command you ran
* The error message you got
* What you've already tried

***

### 🎉 Final Words of Encouragement

**Remember:**

* Everyone starts as a beginner
* PowerShell becomes easier with practice
* Making mistakes is how you learn
* The SOC community is helpful and supportive
* Every expert was once where you are now

**Your Learning Mindset:**

* Practice a little bit every day (15-30 minutes)
* Don't rush - understanding beats memorisation
* Keep notes of commands that work for you
* Build your own cheat sheet as you learn
* Celebrate small wins!

**You've Got This!** 🚀

Start with Day 1, take it slow, and before you know it, you'll be confidently investigating security incidents with PowerShell. Welcome to the SOC analyst community!

***

_This guide is designed to grow with you. Bookmark it, refer back to it, and create your own notes as you learn!_
