# Account Usage Investigation Workflow & Cheatsheet

### Windows Enterprise DFIR - SOC Analyst Reference

***

### 🎯 Investigation Objectives

When investigating account usage, determine:

* **WHO**: Which accounts were used (local vs domain)
* **WHEN**: Timeline of authentication events
* **WHERE**: Source and destination systems
* **HOW**: Authentication method and logon type
* **WHAT**: Actions performed and resources accessed
* **WHY**: Legitimate business need or suspicious activity

***

### 📋 Quick Reference: Critical Event IDs

#### Authentication Events (Security.evtx)

| Event ID      | Description                  | Protocol | Priority    |
| ------------- | ---------------------------- | -------- | ----------- |
| **4624**      | Successful Logon             | Both     | 🔴 Critical |
| **4625**      | Failed Logon                 | Both     | 🔴 Critical |
| **4776**      | Credential Validation        | NTLM     | 🟠 High     |
| **4768**      | TGT Granted                  | Kerberos | 🟠 High     |
| **4769**      | Service Ticket Requested     | Kerberos | 🟡 Medium   |
| **4771**      | Pre-auth Failed              | Kerberos | 🔴 Critical |
| **4634/4647** | Logoff                       | Both     | 🟢 Low      |
| **4648**      | Explicit Credentials (runas) | Both     | 🔴 Critical |
| **4672**      | Admin Rights Logon           | Both     | 🔴 Critical |
| **4778**      | RDP Session Reconnect        | N/A      | 🟠 High     |
| **4779**      | RDP Session Disconnect       | N/A      | 🟡 Medium   |
| **4720**      | Account Created              | N/A      | 🔴 Critical |
| **4697**      | Service Installed            | N/A      | 🔴 Critical |

#### Service Events (System.evtx)

| Event ID | Description             | Priority    |
| -------- | ----------------------- | ----------- |
| **7045** | Service Installed       | 🔴 Critical |
| **7034** | Service Crashed         | 🟠 High     |
| **7036** | Service Start/Stop      | 🟡 Medium   |
| **7040** | Service Startup Changed | 🟠 High     |

***

### 🔍 Investigation Workflow

#### Phase 1: Initial Triage (First 15 Minutes)

**Step 1.1: Identify the Scope**

```bash
Questions to Answer:
□ What is the alert/indicator that triggered investigation?
□ Which user account(s) are involved?
□ Which system(s) are affected (workstation vs server vs DC)?
□ What is the suspected timeframe?
□ Is this a single incident or part of a campaign?
```

**Step 1.2: Quick Account Profiling**

```powershell
# Check if account is local or domain
net user <username> /domain
net user <username>

# Get account details
Get-ADUser <username> -Properties *

# Check current active sessions
query user
qwinsta

# List local administrators
net localgroup administrators
```

**Document:**

* Account type (Local/Domain/Cloud)
* Account status (Active/Disabled/Locked)
* Group memberships
* Account age and last password change

***

#### Phase 2: Authentication Analysis (30 Minutes)

**Step 2.1: Collect Authentication Events**

**On Workstation (Local Auth):**

```powershell
# Export Security log for analysis
wevtutil epl Security C:\Temp\Security_<hostname>.evtx

# Query specific events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624,4625,4648,4672,4776
    StartTime=(Get-Date).AddDays(-7)
} | Where-Object {$_.Properties[5].Value -eq '<username>'}
```

**On Domain Controller (Domain Auth):**

```powershell
# Query Kerberos events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4768,4769,4771,4776
    StartTime=(Get-Date).AddDays(-7)
} | Where-Object {$_.Properties[0].Value -eq '<username>'}
```

**Step 2.2: Analyse Logon Types**

**Logon Type Decision Tree:**

```bash
Type 2  → Console/Physical → Is this expected location?
Type 3  → Network → From which system? SMB, file shares
Type 7  → Unlock/Reconnect → Gap in activity?
Type 8  → Cleartext (!)→ Investigate immediately (insecure)
Type 9  → RunAs → What was executed? By whom?
Type 10 → RDP → From where? During business hours?
Type 11 → Cached → System offline? VPN connected?
```

**Red Flags:**

* Type 8 (cleartext credentials)
* Type 10 from unusual IPs/countries
* Type 3 during off-hours to sensitive servers
* Multiple Type 4625 (failed logons) followed by Type 4624 (brute force)
* Type 9 with service accounts

***

#### Phase 3: Timeline Construction (45 Minutes)

**Step 3.1: Build Authentication Timeline**

**PowerShell Timeline Script:**

```powershell
# Create timeline of all authentication events
$Events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624,4625,4648,4672,4776,4768,4769,4771,4778,4779
    StartTime=(Get-Date).AddDays(-7)
}

$Events | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID = $_.Id
        Username = $_.Properties[5].Value
        LogonType = $_.Properties[8].Value
        SourceIP = $_.Properties[18].Value
        Workstation = $_.Properties[11].Value
    }
} | Sort-Object TimeCreated | Export-Csv C:\Temp\auth_timeline.csv -NoTypeInformation
```

**Step 3.2: Correlate with Other Activity**

**Check for:**

```bash
□ Process execution (4688 events)
□ File access (4663 events)
□ Network connections (Firewall logs)
□ Service installations (7045, 4697)
□ Scheduled task creation (4698)
□ Registry modifications (NTUSER.DAT, SAM)
□ RDP Bitmap Cache artifacts
```

***

#### Phase 4: Deep Dive Analysis (1-2 Hours)

**Step 4.1: RDP Investigation**

**If Type 10 logons detected:**

```powershell
# Query RDP-specific events
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4778,4779
    StartTime=(Get-Date).AddDays(-7)
}

# Check Terminal Services logs
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    ID=21,22,23,24,25
    StartTime=(Get-Date).AddDays(-7)
}
```

**Artifact Collection:**

```bash
Location: %USERPROFILE%\AppData\Local\Microsoft\Terminal Server Client\Cache
Action: Collect BMC files for bitmap analysis
Tools: bmc-tools.py, bitmapcacheviewer.exe

Analysis:
□ What was visible on screen during RDP session?
□ Does it match expected business activity?
□ Any sensitive data visible?
□ Screenshots of malicious tools?
```

**Step 4.2: Registry Analysis**

**SAM Hive Analysis:**

```powershell
# Export SAM hive (requires SYSTEM privileges)
reg save HKLM\SAM C:\Temp\SAM.hive

# Offline analysis with RegRipper
rr.exe -r SAM.hive -f sam > sam_analysis.txt
```

**Look for:**

* Last login timestamps
* Password last set dates
* Login counts (high counts = automation/service account)
* Failed login attempts
* Cloud account indicators (InternetUserName value)
* Unusual RIDs or account creation times

**NTUSER.DAT Analysis:**

```powershell
# For each user profile
Get-ChildItem C:\Users\*/NTUSER.DAT | ForEach-Object {
    RECmd.exe --f $_.FullName --csv C:\Temp\Registry_Analysis\
}
```

**Check for:**

* Recent documents accessed
* Typed URLs (web activity)
* UserAssist (program execution)
* Run/RunOnce keys (persistence)
* MRU lists (recently used files)
* WordWheelQuery (search terms)

**Step 4.3: Service Analysis**

**Query Service Events:**

```powershell
# System log service events
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=7034,7035,7036,7040,7045
    StartTime=(Get-Date).AddDays(-7)
}

# Security log service events (if auditing enabled)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4697
    StartTime=(Get-Date).AddDays(-7)
}
```

**Red Flags:**

* Services installed during suspicious logon timeframe
* Service names with random characters
* Services running from temp directories
* Services with unusual account contexts
* Services that crash immediately after suspicious activity

**Step 4.4: User Access Logging (Server Only)**

**For Windows Server 2012+:**

```powershell
# Analyse UAL database
SumECmd.exe -d "C:\Windows\System32\LogFiles\Sum" --csv C:\Temp\UAL_Analysis\
```

**Extract:**

* Source IP addresses
* Accessed services
* Access timestamps
* Total access counts
* Authentication types
* User accounts used

***

#### Phase 5: Pattern Analysis (30 Minutes)

**Step 5.1: Identify Anomalies**

**Statistical Analysis:**

```bash
Baseline Questions:
□ What are normal logon hours for this account?
□ What are typical source IPs/systems?
□ What is normal logon type distribution?
□ What is average failed logon rate?
□ What systems does this account normally access?

Anomaly Detection:
□ Logons during unusual hours (nights/weekends)
□ Logons from unexpected geographic locations
□ Impossible travel (multiple locations, short timeframe)
□ Sudden spike in failed logons
□ New systems accessed
□ Changed logon type patterns
□ Access to sensitive systems without business justification
```

**Step 5.2: Check for Attack Indicators**

**Common Attack Patterns:**

| Attack Type              | Indicators                                          |
| ------------------------ | --------------------------------------------------- |
| **Password Spray**       | Multiple accounts, few failed attempts each, Type 3 |
| **Brute Force**          | Single account, many 4625 events, then 4624         |
| **Pass-the-Hash**        | Type 3 logons, NTLM auth, no Type 2 on source       |
| **Pass-the-Ticket**      | Kerberos auth without initial 4768, unusual SPNs    |
| **Golden Ticket**        | Long ticket lifetimes, unusual encryption types     |
| **Lateral Movement**     | Type 3 chain across multiple systems                |
| **Privilege Escalation** | 4672 events, Type 9 logons, new admin access        |
| **Persistence**          | Service installs (7045), scheduled tasks, Run keys  |
| **RDP Hijacking**        | 4778 without preceding 4624, session transfers      |

***

#### Phase 6: Lateral Movement Tracking (1 Hour)

**Step 6.1: Map Authentication Chain**

**Build Network Map:**

```bash
Workstation A → Server B → Server C → Domain Controller

For each hop:
1. Identify source system (from 4624 fields)
2. Identify destination system (log location)
3. Document authentication method (NTLM vs Kerberos)
4. Note logon type used
5. Record timestamp
6. Check for service/process spawned
```

**PowerShell Lateral Movement Detector:**

{% code overflow="wrap" %}
```powershell
# Identify Type 3 logon chains
$SourceSystems = @()
$Timeline = @()

Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
    StartTime=(Get-Date).AddHours(-24)
} | Where-Object {
    $_.Properties[8].Value -eq 3  # Type 3 logons
} | ForEach-Object {
    $Timeline += [PSCustomObject]@{
        Time = $_.TimeCreated
        TargetUser = $_.Properties[5].Value
        TargetSystem = $env:COMPUTERNAME
        SourceIP = $_.Properties[18].Value
        SourceHost = $_.Properties[11].Value
    }
}

# Analyze for pivot patterns
$Timeline | Group-Object SourceIP | 
    Where-Object {$_.Count -gt 5} |
    Select-Object Name, Count, @{N='Targets';E={$_.Group.TargetSystem | Select-Object -Unique}}
```
{% endcode %}

**Step 6.2: Correlate with Process Execution**

**Check what was executed after authentication:**

```powershell
# Get process creation events near logon time
$LogonTime = Get-Date "2025-11-29 14:30:00"

Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=$LogonTime.AddMinutes(-1)
    EndTime=$LogonTime.AddMinutes(5)
}
```

**Red Flags:**

* PowerShell execution immediately after Type 3 logon
* cmd.exe with suspicious command lines
* psexec, wmic, mmc, sc.exe usage
* Mimikatz or other credential dumping tools
* Remote management tools (TeamViewer, AnyDesk)

***

### 🛠️ Tool Quick Reference

#### Built-in Windows Tools

```powershell
# Query specific user logons
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | 
    Where-Object {$_.Properties[5].Value -eq 'username'}

# Export event log
wevtutil epl Security backup.evtx

# Query remote system
Get-WinEvent -ComputerName SERVER01 -FilterHashtable @{LogName='Security';ID=4624}

# Real-time monitoring
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} -MaxEvents 10

# Net commands
net user username /domain
net localgroup administrators
net accounts /domain
net session
net use
```

#### Registry Analysis Tools

```bash
# RegRipper
rr.exe -r NTUSER.DAT -f ntuser > output.txt
rr.exe -r SAM -f sam > sam_output.txt

# RECmd (Eric Zimmerman)
RECmd.exe --f "C:\Users\user\NTUSER.DAT" --csv C:\Output\
RECmd.exe --f "SAM.hive" --sk Users --recover false

# RegistryExplorer.exe (GUI - load hive and browse)
```

#### RDP Artifact Analysis

```bash
# BMC Tools
python bmc-tools.py -s C:\Cache\Cache0001.bin -d output_folder
bitmapcacheviewer.exe  # GUI tool

# Check RDP connections history
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
```

#### UAL Analysis (Server)

```bash
# SumECmd
SumECmd.exe -d "C:\Windows\System32\LogFiles\Sum" --csv C:\Output\

# KStrike
python KStrike.py -d Sum_folder -o output.csv
```

#### SAM Analysis

```bash
# samparser
python samparser.py SAM.hive > output.txt

# Extract password hashes (for cracking analysis)
secretsdump.py -sam SAM.hive -system SYSTEM.hive LOCAL
```

***

### 📊 Investigation Checklist

#### Initial Assessment

* \[ ] Identify affected account(s)
* \[ ] Determine account type (Local/Domain/Cloud)
* \[ ] Verify current account status
* \[ ] Establish investigation timeframe
* \[ ] Identify affected systems

#### Data Collection

* \[ ] Security.evtx from affected workstation
* \[ ] Security.evtx from Domain Controller
* \[ ] System.evtx from affected systems
* \[ ] Terminal Services logs (if RDP used)
* \[ ] SAM registry hive
* \[ ] NTUSER.DAT from user profile
* \[ ] RDP Bitmap Cache (if applicable)
* \[ ] UAL databases (if server)
* \[ ] Network traffic logs
* \[ ] EDR/AV logs

#### Authentication Analysis

* \[ ] Timeline of 4624/4625 events
* \[ ] Analyse logon types distribution
* \[ ] Identify source IPs/hostnames
* \[ ] Check for failed logon patterns
* \[ ] Verify authentication protocols used
* \[ ] Review explicit credential usage (4648)
* \[ ] Check for privilege escalation (4672)

#### Artifact Analysis

* \[ ] RDP session artifacts reviewed
* \[ ] Registry analysis completed
* \[ ] Service events examined
* \[ ] Process execution correlated
* \[ ] File access patterns checked
* \[ ] Network connections mapped

#### Lateral Movement

* \[ ] Authentication chain mapped
* \[ ] Pivot points identified
* \[ ] Affected systems documented
* \[ ] Attack timeline constructed

#### Pattern Analysis

* \[ ] Baseline behaviour established
* \[ ] Anomalies identified
* \[ ] Attack patterns matched
* \[ ] IOCs extracted
* \[ ] Risk assessment completed

#### Documentation

* \[ ] Timeline created
* \[ ] Evidence preserved
* \[ ] Screenshots captured
* \[ ] IOCs documented
* \[ ] Report prepared

***

### 🚨 Quick Win: High-Value Queries

#### Detect Potential Compromise

**1. Find after-hours admin logons:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} | 
    Where-Object {
        $_.TimeCreated.Hour -lt 6 -or $_.TimeCreated.Hour -gt 18
    }
```

**2. Detect password spray attempts:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} |
    Group-Object @{Expression={$_.Properties[19].Value}} |
    Where-Object {$_.Count -gt 5} |
    Select-Object Name, Count
```

**3. Find Type 10 (RDP) logons from external IPs:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} |
    Where-Object {
        $_.Properties[8].Value -eq 10 -and
        $_.Properties[18].Value -notlike "10.*" -and
        $_.Properties[18].Value -notlike "192.168.*"
    }
```

**4. Identify explicit credential usage (runas):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4648} |
    Select-Object TimeCreated, 
        @{N='User';E={$_.Properties[1].Value}},
        @{N='TargetUser';E={$_.Properties[5].Value}},
        @{N='TargetServer';E={$_.Properties[8].Value}}
```

**5. Find service installations during suspicious timeframe:**

```powershell
$SuspiciousTime = Get-Date "2025-11-29 14:00:00"
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} |
    Where-Object {
        $_.TimeCreated -ge $SuspiciousTime.AddMinutes(-10) -and
        $_.TimeCreated -le $SuspiciousTime.AddMinutes(10)
    }
```

***

### 🎓 Pro Tips

#### Efficiency Tips

1. **Use FilterHashtable** instead of Where-Object for faster queries
2. **Narrow timeframes** - don't query entire logs if you know the window
3. **Query remote systems** in parallel using PowerShell jobs
4. **Export to CSV** for analysis in Excel/Timeline Explorer
5. **Use date math**: `(Get-Date).AddDays(-7)` for relative dates

#### Analysis Tips

1. **Start broad, then narrow** - overview first, deep dive on anomalies
2. **Follow the data** - let artifacts guide your investigation
3. **Trust but verify** - logs can be cleared/modified
4. **Look for absence** - missing logs are suspicious
5. **Context matters** - one odd event might be normal, patterns aren't

#### Documentation Tips

1. **Screenshot everything** - you may need it for reports
2. **Note your commands** - reproducibility is critical
3. **Preserve original evidence** - work on copies
4. **Chain of custody** - document who, what, when, where
5. **Timeline format** - use ISO 8601 (YYYY-MM-DD HH:MM:SS)

#### Common Pitfalls

1. ❌ Only checking Security log (also check System, Application, specialised logs)
2. ❌ Ignoring logon type (Type 3 vs Type 10 context is critical)
3. ❌ Not checking Domain Controller (domain auth happens there)
4. ❌ Forgetting about log rotation (events may be archived)
5. ❌ Tunnel vision on one indicator (look for corroborating evidence)

***

### 📈 Escalation Criteria

**Escalate Immediately If:**

* ✅ Admin account compromise confirmed
* ✅ Domain Controller authentication anomalies
* ✅ Evidence of credential dumping tools
* ✅ Lateral movement to multiple critical systems
* ✅ After-hours access to sensitive data repositories
* ✅ Service account used interactively
* ✅ Cloud admin account suspicious activity
* ✅ Evidence of golden ticket or similar advanced attack
* ✅ Data exfiltration indicators
* ✅ Ransomware/malware execution correlated with logon

***

### 📚 Additional Resources

#### Microsoft Documentation

* Windows Security Log Encyclopedia
* Advanced Security Audit Policies
* Account Logon Events Reference

#### Tools

* Eric Zimmerman Tools Suite (KAPE, RECmd, Timeline Explorer)
* Volatility Framework (memory analysis)
* Chainsaw (Sigma rule detection for Windows Event Logs)
* DeepBlueCLI (PowerShell threat hunting)

#### Training

* SANS FOR500 (Windows Forensics)
* SANS FOR508 (Advanced Incident Response)
* MITRE ATT\&CK Framework (Credential Access, Lateral Movement tactics)

***

### 📋 Report Template Structure

```bash
1. EXECUTIVE SUMMARY
   - Incident overview
   - Impact assessment
   - Key findings
   - Recommendations

2. INVESTIGATION DETAILS
   - Timeline of events
   - Affected accounts and systems
   - Attack methodology
   - Evidence summary

3. TECHNICAL ANALYSIS
   - Authentication events analysis
   - Artifact findings
   - Lateral movement map
   - IOCs

4. RECOMMENDATIONS
   - Immediate actions
   - Short-term remediation
   - Long-term improvements

5. APPENDICES
   - Raw event logs
   - Commands used
   - Tool outputs
   - Screenshots
```

***

_Remember: The best investigation is methodical, documented, and reproducible. Take your time, be thorough, and let the evidence tell the story._
