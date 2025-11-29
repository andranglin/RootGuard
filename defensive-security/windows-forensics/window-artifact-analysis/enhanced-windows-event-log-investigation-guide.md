# Enhanced Windows Event Log Investigation Guide

### Comprehensive DFIR SOC Analyst Playbook

***

### 📚 Table of Contents

1. [Investigation Framework](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-framework)
2. [Account Usage Investigation](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#account-usage-investigation)
3. [Lateral Movement Detection](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#lateral-movement-detection)
4. [Persistence Mechanisms](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#persistence-mechanisms)
5. [Privilege Escalation](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#privilege-escalation)
6. [PowerShell & WMI Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#powershell--wmi-analysis)
7. [Malware Execution Evidence](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#malware-execution-evidence)
8. [Event Log Collection](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#event-log-collection)
9. [Tool Reference](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#tool-reference)
10. [Investigation Playbooks](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-playbooks)

***

### 🎯 Investigation Framework

#### Critical Event ID Quick Reference

| Category                  | Event IDs                    | Priority    | Log Location               |
| ------------------------- | ---------------------------- | ----------- | -------------------------- |
| **Authentication**        | 4624, 4625, 4634, 4647       | 🔴 Critical | Security.evtx              |
| **Admin Activity**        | 4672, 4648, 4720             | 🔴 Critical | Security.evtx              |
| **RDP Sessions**          | 4778, 4779                   | 🟠 High     | Security.evtx              |
| **Account Logon**         | 4776, 4768, 4769, 4771       | 🟠 High     | Security.evtx (DC)         |
| **Services**              | 7034, 7035, 7036, 7040, 7045 | 🟠 High     | System.evtx                |
| **Services (Security)**   | 4697                         | 🔴 Critical | Security.evtx              |
| **Scheduled Tasks**       | 106, 140, 141, 200, 201      | 🟠 High     | TaskScheduler/Operational  |
| **Scheduled Tasks (Sec)** | 4698, 4699, 4700, 4701, 4702 | 🔴 Critical | Security.evtx              |
| **Network Shares**        | 5140, 5145                   | 🟡 Medium   | Security.evtx              |
| **Process Tracking**      | 4688, 4689                   | 🟠 High     | Security.evtx              |
| **PowerShell**            | 4103, 4104, 4105, 4106       | 🔴 Critical | PowerShell/Operational     |
| **WMI Activity**          | 5857, 5858, 5859, 5860, 5861 | 🔴 Critical | WMI-Activity/Operational   |
| **WinRM/PS Remoting**     | 6, 91, 168                   | 🟠 High     | WinRM/Operational          |
| **Log Clearing**          | 1102, 104                    | 🔴 Critical | Security.evtx, System.evtx |
| **Registry Changes**      | 4656, 4657, 4658, 4660, 4663 | 🟡 Medium   | Security.evtx              |
| **Account Enumeration**   | 4798, 4799                   | 🟡 Medium   | Security.evtx              |
| **Malware/Crashes**       | 1000, 1001, 1002             | 🟡 Medium   | Application.evtx           |

#### Log Locations Quick Reference

{% code overflow="wrap" %}
```bash
Core Logs:
%SystemRoot%\System32\winevt\logs\Security.evtx
%SystemRoot%\System32\winevt\logs\System.evtx
%SystemRoot%\System32\winevt\logs\Application.evtx

Specialized Logs:
%SystemRoot%\System32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx
%SystemRoot%\System32\winevt\logs\Microsoft-Windows-WMI-Activity%4Operational.evtx
%SystemRoot%\System32\winevt\logs\Microsoft-Windows-WinRM%4Operational.evtx
%SystemRoot%\System32\winevt\logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
%SystemRoot%\System32\winevt\logs\Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx
%SystemRoot%\System32\winevt\logs\Microsoft-Windows-TaskScheduler%4Operational.evtx

Additional Artifacts:
%UserProfile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
C:\Windows\System32\config\SAM
C:\Users\<username>\NTUSER.DAT
%UserProfile%\AppData\Local\Microsoft\Terminal Server Client\Cache (BMC files)
C:\Windows\System32\LogFiles\Sum\*.mdb (UAL - Server only)
```
{% endcode %}

***

### 🔐 Account Usage Investigation

#### Phase 1: Initial Account Assessment

**1.1 Determine Account Type and Status**

**Check Local Account:**

```powershell
# Query local account
net user <username>

# PowerShell method
Get-LocalUser -Name <username> | Select-Object *
```

**Check Domain Account:**

{% code overflow="wrap" %}
```powershell
# Query domain account
net user <username> /domain

# PowerShell method
Get-ADUser <username> -Properties * | Select-Object Name, Enabled, LastLogonDate, PasswordLastSet, whenCreated, MemberOf
```
{% endcode %}

**Built-in Accounts to Recognise:**

* **SYSTEM**: Most powerful local account
* **LOCAL SERVICE**: Limited privileges, null session network access
* **NETWORK SERVICE**: Network resource access as authenticated user
* **\<Hostname>$**: Domain-joined computer account
* **DWM-#**: Desktop Window Manager
* **UMFD-#**: Font Driver Host
* **ANONYMOUS LOGON**: Null session authentication

***

#### Phase 2: Authentication Event Analysis

**2.1 Successful Logon Analysis (Event ID 4624)**

**Query Successful Logons:**

```powershell
# Extract all successful logons for specific user
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
    StartTime=(Get-Date).AddDays(-7)
} | Where-Object {$_.Properties[5].Value -eq '<username>'}

# Export to CSV for analysis
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            AccountName = $_.Properties[5].Value
            AccountDomain = $_.Properties[6].Value
            LogonID = $_.Properties[7].Value
            LogonType = $_.Properties[8].Value
            AuthPackage = $_.Properties[10].Value
            WorkstationName = $_.Properties[11].Value
            LogonGUID = $_.Properties[12].Value
            SourceNetworkAddress = $_.Properties[18].Value
            SourcePort = $_.Properties[19].Value
        }
    } | Export-Csv -Path C:\Temp\Logons_4624.csv -NoTypeInformation
```

**Using EvtxECmd:**

{% code overflow="wrap" %}
```powershell
# Parse Security log
.\EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\Security.evtx" --csv "C:\Analysis" --csvf Security_Parsed.csv

# Parse entire logs directory
.\EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv "C:\Analysis" --csvf AllLogs.csv
```
{% endcode %}

**Using DeepBlueCLI:**

```powershell
# Analyze local Security log
.\DeepBlue.ps1

# Analyze specific evtx file
.\DeepBlue.ps1 .\Security.evtx
```

**2.2 Logon Type Analysis**

**Critical Logon Types:**

| Type   | Name              | Description                  | Investigation Notes                          |
| ------ | ----------------- | ---------------------------- | -------------------------------------------- |
| **2**  | Interactive       | Console/Keyboard logon       | Physical or KVM access                       |
| **3**  | Network           | SMB, some RDP                | File shares, lateral movement                |
| **4**  | Batch             | Scheduled Tasks              | Non-interactive automation                   |
| **5**  | Service           | Windows Services             | Service account activity                     |
| **7**  | Unlock/Reconnect  | Screen unlock, RDP reconnect | Can indicate RDP session continuation        |
| **8**  | NetworkCleartext  | Credentials in cleartext     | ⚠️ SECURITY RISK - Possible downgrade attack |
| **9**  | NewCredentials    | RunAs/netonly                | Credential switching, lateral movement       |
| **10** | RemoteInteractive | RDP                          | Remote desktop sessions                      |
| **11** | CachedInteractive | Cached credentials           | Offline domain authentication                |
| **12** | CachedRemote      | Cached RDP                   | Microsoft account authentication             |
| **13** | CachedUnlock      | Cached unlock                | Similar to Type 7                            |

**Detection Query - Unusual Logon Types:**

```powershell
# Detect Type 8 (Cleartext) - ALWAYS INVESTIGATE
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | 
    Where-Object {$_.Properties[8].Value -eq 8} |
    Select-Object TimeCreated, 
        @{N='User';E={$_.Properties[5].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}},
        @{N='Workstation';E={$_.Properties[11].Value}}

# Detect Type 9 (RunAs) - Credential switching
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | 
    Where-Object {$_.Properties[8].Value -eq 9} |
    Select-Object TimeCreated, 
        @{N='User';E={$_.Properties[5].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}}
```

**2.3 Failed Logon Analysis (Event ID 4625)**

**Extract Failed Logons:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetAccount = $_.Properties[5].Value
            FailureReason = $_.Properties[8].Value  # Status code
            SubStatus = $_.Properties[9].Value
            LogonType = $_.Properties[10].Value
            SourceWorkstation = $_.Properties[13].Value
            SourceIP = $_.Properties[19].Value
        }
    } | Export-Csv -Path C:\Temp\FailedLogons_4625.csv -NoTypeInformation
```

**Common Error Codes:**

| Error Code     | Meaning                          | Threat Indicator               |
| -------------- | -------------------------------- | ------------------------------ |
| **0xC0000064** | User does not exist              | Username enumeration           |
| **0xC000006A** | Correct username, wrong password | Password guessing/brute force  |
| **0xC000006D** | Bad username or password         | Generic failure                |
| **0xC000006E** | Account restriction              | Policy violation               |
| **0xC000006F** | Time restriction                 | Outside allowed hours          |
| **0xC0000070** | Workstation restriction          | Unauthorized system access     |
| **0xC0000071** | Password expired                 | Account maintenance needed     |
| **0xC0000072** | Account disabled                 | Accessing disabled account     |
| **0xC0000193** | Account expired                  | Expired account access attempt |
| **0xC0000234** | Account locked                   | Multiple failed attempts       |

**Brute Force Detection:**

{% code overflow="wrap" %}
```powershell
# Detect brute force attempts
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddHours(-24)
} | Group-Object @{Expression={$_.Properties[19].Value}} |
    Where-Object {$_.Count -gt 10} |
    Select-Object Name, Count, @{N='Accounts';E={$_.Group.Properties[5].Value | Select-Object -Unique}} |
    Sort-Object Count -Descending
```
{% endcode %}

**Password Spray Detection:**

{% code overflow="wrap" %}
```powershell
# Detect password spray (many accounts, few attempts each)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddHours(-24)
} | Group-Object @{Expression={$_.Properties[19].Value}} |
    ForEach-Object {
        [PSCustomObject]@{
            SourceIP = $_.Name
            TotalFailures = $_.Count
            UniqueAccounts = ($_.Group.Properties[5].Value | Select-Object -Unique).Count
            AvgAttemptsPerAccount = [math]::Round($_.Count / ($_.Group.Properties[5].Value | Select-Object -Unique).Count, 2)
            AttackType = if (($_.Group.Properties[5].Value | Select-Object -Unique).Count -gt 10 -and 
                            ($_.Count / ($_.Group.Properties[5].Value | Select-Object -Unique).Count) -lt 5) 
                            {"Password Spray"} else {"Brute Force"}
        }
    } | Where-Object {$_.UniqueAccounts -gt 5} |
    Sort-Object TotalFailures -Descending
```
{% endcode %}

**2.4 Session Tracking (Logon ID Correlation)**

**Track Complete User Session:**

```powershell
# Get logon event
$LogonID = "0x123456"

# Find all events for this session
Get-WinEvent -FilterHashtable @{LogName='Security'} | 
    Where-Object {$_.Message -match $LogonID} |
    Select-Object TimeCreated, Id, Message |
    Sort-Object TimeCreated
```

**Calculate Session Duration:**

{% code overflow="wrap" %}
```powershell
# Find matching logon/logoff pairs
$Logons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624}
$Logoffs = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4634,4647}

$Sessions = $Logons | ForEach-Object {
    $LogonID = $_.Properties[7].Value
    $Logoff = $Logoffs | Where-Object {$_.Properties[3].Value -eq $LogonID} | Select-Object -First 1
    
    [PSCustomObject]@{
        User = $_.Properties[5].Value
        LogonTime = $_.TimeCreated
        LogoffTime = if ($Logoff) {$Logoff.TimeCreated} else {"Still Active"}
        Duration = if ($Logoff) {$Logoff.TimeCreated - $_.TimeCreated} else {(Get-Date) - $_.TimeCreated}
        LogonID = $LogonID
        LogonType = $_.Properties[8].Value
    }
}

$Sessions | Where-Object {$_.Duration.TotalHours -gt 8} | Format-Table
```
{% endcode %}

***

#### Phase 3: Administrator Account Activity

**3.1 Admin Logon Detection (Event ID 4672)**

**Query Admin Logons:**

```powershell
# Find all admin logons
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            AccountName = $_.Properties[1].Value
            AccountDomain = $_.Properties[2].Value
            LogonID = $_.Properties[3].Value
            Privileges = $_.Properties[4].Value
        }
    } | Export-Csv -Path C:\Temp\AdminLogons_4672.csv -NoTypeInformation
```

**Correlate with Successful Logon:**

{% code overflow="wrap" %}
```powershell
# Find 4624 followed by 4672 (proves admin logon)
$StartTime = (Get-Date).AddDays(-7)
$Logons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624;StartTime=$StartTime}
$AdminLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672;StartTime=$StartTime}

$Logons | ForEach-Object {
    $LogonID = $_.Properties[7].Value
    $AdminEvent = $AdminLogons | Where-Object {
        $_.Properties[3].Value -eq $LogonID -and
        [Math]::Abs(($_.TimeCreated - $_.TimeCreated).TotalSeconds) -lt 2
    }
    
    if ($AdminEvent) {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[5].Value
            LogonType = $_.Properties[8].Value
            SourceIP = $_.Properties[18].Value
            AdminPrivileges = "YES"
        }
    }
} | Export-Csv C:\Temp\ConfirmedAdminLogons.csv -NoTypeInformation
```
{% endcode %}

**After-Hours Admin Activity:**

```powershell
# Detect admin activity outside business hours
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} | 
    Where-Object {
        $Hour = $_.TimeCreated.Hour
        $Hour -lt 6 -or $Hour -gt 18  # Outside 6 AM - 6 PM
    } | Select-Object TimeCreated, 
        @{N='User';E={$_.Properties[1].Value}},
        @{N='DayOfWeek';E={$_.TimeCreated.DayOfWeek}},
        @{N='Hour';E={$_.TimeCreated.Hour}}
```

**3.2 Explicit Credentials / RunAs (Event ID 4648)**

**Detect RunAs Activity:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4648} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            SourceAccount = $_.Properties[1].Value
            TargetAccount = $_.Properties[5].Value
            TargetServer = $_.Properties[8].Value
            ProcessName = $_.Properties[11].Value
            SourceIP = $_.Properties[12].Value
        }
    } | Export-Csv C:\Temp\RunAs_4648.csv -NoTypeInformation
```

**Investigate Lateral Movement via RunAs:**

{% code overflow="wrap" %}
```powershell
# Find accounts using explicit credentials to access multiple systems
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4648} | 
    Group-Object @{Expression={$_.Properties[1].Value}} |
    Where-Object {$_.Count -gt 5} |
    ForEach-Object {
        [PSCustomObject]@{
            SourceAccount = $_.Name
            UseCount = $_.Count
            TargetSystems = ($_.Group.Properties[8].Value | Select-Object -Unique) -join ", "
            TargetAccounts = ($_.Group.Properties[5].Value | Select-Object -Unique) -join ", "
        }
    }
```
{% endcode %}

**3.3 Account Creation/Modification**

**Account Creation (Event ID 4720):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            NewAccount = $_.Properties[0].Value
            CreatedBy = $_.Properties[4].Value
            Domain = $_.Properties[5].Value
            Computer = $_.MachineName
        }
    } | Export-Csv C:\Temp\AccountCreation_4720.csv -NoTypeInformation
```

**Track Complete Account Lifecycle:**

{% code overflow="wrap" %}
```powershell
# Account lifecycle events
$AccountEvents = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4720,4722,4724,4728,4732,4735,4738,4756,4726
}

$AccountEvents | ForEach-Object {
    $EventName = switch ($_.Id) {
        4720 {"Account Created"}
        4722 {"Account Enabled"}
        4724 {"Password Reset Attempt"}
        4728 {"Added to Global Group"}
        4732 {"Added to Local Group"}
        4735 {"Local Group Changed"}
        4738 {"Account Changed"}
        4756 {"Added to Universal Group"}
        4726 {"Account Deleted"}
    }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Event = $EventName
        TargetAccount = $_.Properties[0].Value
        ActionBy = $_.Properties[4].Value
    }
} | Sort-Object TimeCreated | Export-Csv C:\Temp\AccountLifecycle.csv -NoTypeInformation
```
{% endcode %}

***

#### Phase 4: RDP Investigation

**4.1 RDP Session Analysis (Multiple Event Sources)**

**Event ID 4624 Type 10 (Standard RDP):**

```powershell
# Query Type 10 RDP logons
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | 
    Where-Object {$_.Properties[8].Value -eq 10} |
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[5].Value
            Domain = $_.Properties[6].Value
            SourceIP = $_.Properties[18].Value
            SourceHost = $_.Properties[11].Value
        }
    } | Export-Csv C:\Temp\RDP_Type10.csv -NoTypeInformation
```

**Event ID 4778/4779 (Session Reconnect/Disconnect):**

```powershell
# RDP session reconnects (often missed if only looking at Type 10)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4778,4779} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID = $_.Id
            Action = if ($_.Id -eq 4778) {"Connected"} else {"Disconnected"}
            User = $_.Properties[0].Value
            Domain = $_.Properties[1].Value
            SessionName = $_.Properties[2].Value
            ClientName = $_.Properties[3].Value
            ClientIP = $_.Properties[4].Value
        }
    } | Export-Csv C:\Temp\RDP_Sessions_4778_4779.csv -NoTypeInformation
```

**TerminalServices-LocalSessionManager:**

```powershell
# Detailed RDP session info
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    ID=21,22,23,24,25
} | ForEach-Object {
    $EventName = switch ($_.Id) {
        21 {"Session Logon Succeeded"}
        22 {"Shell Start"}
        23 {"Session Logoff Succeeded"}
        24 {"Session Disconnected"}
        25 {"Session Reconnected"}
    }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Event = $EventName
        User = $_.Properties[0].Value
        SessionID = $_.Properties[1].Value
        SourceIP = $_.Properties[2].Value
    }
} | Export-Csv C:\Temp\RDP_LocalSessionManager.csv -NoTypeInformation
```

**RDP Client Activity (Source System):**

```powershell
# Systems this machine has RDP'd to
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TerminalServices-RDPClient/Operational'
    ID=1024,1102
} | Select-Object TimeCreated, Id, Message
```

**Check Registry for RDP History:**

{% code overflow="wrap" %}
```powershell
# Registry keys showing RDP targets
$Users = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | 
    ForEach-Object {
        $SID = $_.PSChildName
        $ProfilePath = (Get-ItemProperty -Path $_.PSPath).ProfileImagePath
        
        # Load user hive if not already loaded
        $HivePath = "$ProfilePath\NTUSER.DAT"
        if (Test-Path $HivePath) {
            reg load "HKU\$SID" $HivePath 2>$null
            
            # Check for RDP server history
            $RDPServers = Get-ItemProperty -Path "Registry::HKU\$SID\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
            
            if ($RDPServers) {
                [PSCustomObject]@{
                    User = $ProfilePath
                    RDPTargets = ($RDPServers.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"}).Name
                }
            }
            
            # Unload hive
            [gc]::Collect()
            reg unload "HKU\$SID" 2>$null
        }
    }

$Users | Export-Csv C:\Temp\RDP_Registry_History.csv -NoTypeInformation
```
{% endcode %}

**4.2 RDP Bitmap Cache Analysis**

**Extract Bitmap Cache Files:**

{% code overflow="wrap" %}
```powershell
# Find BMC files for all users
$BMCFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache" -Recurse -File

$BMCFiles | ForEach-Object {
    [PSCustomObject]@{
        User = $_.FullName.Split('\')[2]
        FileName = $_.Name
        FilePath = $_.FullName
        CreatedDate = $_.CreationTime
        ModifiedDate = $_.LastWriteTime
        Size = $_.Length
    }
} | Export-Csv C:\Temp\BMC_Files.csv -NoTypeInformation
```
{% endcode %}

**Process with bmc-tools:**

{% code overflow="wrap" %}
```bash
# Extract images from BMC files
python bmc-tools.py -s "C:\Users\john\AppData\Local\Microsoft\Terminal Server Client\Cache\Cache0001.bin" -d "C:\Analysis\BMC_Output"
```
{% endcode %}

***

#### Phase 5: Account Logon Events (Domain Controller)

**5.1 NTLM Authentication (Event ID 4776)**

**Query NTLM Authentication on DC:**

{% code overflow="wrap" %}
```powershell
# Run on Domain Controller
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4776} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser = $_.Properties[1].Value
            Workstation = $_.Properties[2].Value
            Status = if ($_.Properties[3].Value -eq "0x0") {"Success"} else {"Failed"}
            ErrorCode = $_.Properties[3].Value
        }
    } | Export-Csv C:\Temp\NTLM_Auth_4776.csv -NoTypeInformation
```
{% endcode %}

**5.2 Kerberos Authentication**

**TGT Requests (Event ID 4768):**

{% code overflow="wrap" %}
```powershell
# Successful Kerberos TGT requests
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser = $_.Properties[0].Value
            Domain = $_.Properties[1].Value
            ClientIP = $_.Properties[9].Value
            Result = if ($_.Properties[6].Value -eq "0x0") {"Success"} else {"Failed"}
            ErrorCode = $_.Properties[6].Value
        }
    } | Export-Csv C:\Temp\Kerberos_TGT_4768.csv -NoTypeInformation
```
{% endcode %}

**Service Ticket Requests (Event ID 4769):**

{% code overflow="wrap" %}
```powershell
# Service ticket requests (resource access)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[0].Value
            Domain = $_.Properties[1].Value
            ServiceName = $_.Properties[2].Value
            ClientIP = $_.Properties[6].Value
            Result = if ($_.Properties[5].Value -eq "0x0") {"Success"} else {"Failed"}
        }
    } | Export-Csv C:\Temp\Kerberos_ServiceTicket_4769.csv -NoTypeInformation
```
{% endcode %}

**Failed Kerberos Pre-Auth (Event ID 4771):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4771} | 
    ForEach-Object {
        $ErrorCode = $_.Properties[4].Value
        $Reason = switch ($ErrorCode) {
            "0x6" {"Invalid/Non-existent User"}
            "0x7" {"Server Not Found"}
            "0xC" {"Policy Restriction"}
            "0x12" {"Account Locked/Disabled/Expired"}
            "0x17" {"Password Expired"}
            "0x18" {"Invalid Password"}
            "0x25" {"Clock Skew"}
            default {$ErrorCode}
        }
        
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser = $_.Properties[0].Value
            ClientIP = $_.Properties[6].Value
            ErrorCode = $ErrorCode
            FailureReason = $Reason
        }
    } | Export-Csv C:\Temp\Kerberos_Failed_4771.csv -NoTypeInformation
```

***

### 🚀 Lateral Movement Detection

#### Phase 1: Network Share Access

**1.1 Share Access Detection (Event ID 5140)**

**Query Share Access:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5140} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[1].Value
            SourceIP = $_.Properties[2].Value
            ShareName = $_.Properties[3].Value
            SharePath = $_.Properties[4].Value
            AccessMask = $_.Properties[5].Value
        }
    } | Export-Csv C:\Temp\ShareAccess_5140.csv -NoTypeInformation
```

**Detect Admin Share Access:**

```powershell
# Detect access to C$, ADMIN$, IPC$
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5140} | 
    Where-Object {
        $ShareName = $_.Properties[3].Value
        $ShareName -match '.*\$'  # Ends with $
    } | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[1].Value
            SourceIP = $_.Properties[2].Value
            ShareName = $_.Properties[3].Value
            Computer = $_.MachineName
        }
    } | Export-Csv C:\Temp\AdminShareAccess.csv -NoTypeInformation
```

**Detailed File Access (Event ID 5145):**

```powershell
# Requires "Detailed File Share" auditing
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5145} | 
    Where-Object {$_.Properties[8].Value -match "WriteData|AppendData"} |
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[1].Value
            SourceIP = $_.Properties[2].Value
            SharePath = $_.Properties[3].Value
            FilePath = $_.Properties[4].Value
            AccessMask = $_.Properties[8].Value
        }
    } | Export-Csv C:\Temp\DetailedFileAccess_5145.csv -NoTypeInformation
```

***

#### Phase 2: Service-Based Lateral Movement

**2.1 Remote Service Creation**

**Detect New Services (Event ID 7045 - System Log):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ServiceName = $_.Properties[0].Value
            ImagePath = $_.Properties[1].Value
            ServiceType = $_.Properties[2].Value
            StartType = $_.Properties[3].Value
            ServiceAccount = $_.Properties[4].Value
        }
    } | Export-Csv C:\Temp\NewServices_7045.csv -NoTypeInformation
```

**Detect New Services (Event ID 4697 - Security Log):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4697} | 
    ForEach-Object {
        $StartType = switch ($_.Properties[4].Value) {
            0 {"Boot"}
            1 {"System"}
            2 {"Automatic"}
            3 {"Manual"}
            4 {"Disabled"}
        }
        
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            CreatedBy = $_.Properties[1].Value
            ServiceName = $_.Properties[5].Value
            ServiceFile = $_.Properties[6].Value
            ServiceType = $_.Properties[7].Value
            StartType = $StartType
            ServiceAccount = $_.Properties[9].Value
        }
    } | Export-Csv C:\Temp\NewServices_4697.csv -NoTypeInformation
```

**Detect Suspicious Service Patterns:**

```powershell
# Find services from temp directories or with random names
Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} | 
    Where-Object {
        $ImagePath = $_.Properties[1].Value
        $ImagePath -match 'temp|tmp|appdata' -or
        $ImagePath -match '[a-z0-9]{8,}\.exe'  # Random-looking names
    } | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ServiceName = $_.Properties[0].Value
            ImagePath = $_.Properties[1].Value
            Reason = "Suspicious Path"
        }
    }
```

**Correlate with Network Logon:**

```powershell
# Services created shortly after Type 3 logons (remote creation)
$TimeWindow = 60  # seconds

$Services = Get-WinEvent -FilterHashtable @{LogName='System';ID=7045}
$Logons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | 
    Where-Object {$_.Properties[8].Value -eq 3}

$Services | ForEach-Object {
    $ServiceTime = $_.TimeCreated
    $RecentLogon = $Logons | Where-Object {
        [Math]::Abs(($_.TimeCreated - $ServiceTime).TotalSeconds) -lt $TimeWindow
    } | Select-Object -First 1
    
    if ($RecentLogon) {
        [PSCustomObject]@{
            ServiceCreated = $ServiceTime
            ServiceName = $_.Properties[0].Value
            ImagePath = $_.Properties[1].Value
            PriorLogonUser = $RecentLogon.Properties[5].Value
            PriorLogonIP = $RecentLogon.Properties[18].Value
            TimeDiff = ($ServiceTime - $RecentLogon.TimeCreated).TotalSeconds
        }
    }
} | Export-Csv C:\Temp\RemoteServiceCreation.csv -NoTypeInformation
```

***

#### Phase 3: Scheduled Task Lateral Movement

**3.1 Scheduled Task Analysis**

**Task Scheduler Log (Event IDs 106, 140, 141, 200, 201):**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TaskScheduler/Operational'
    ID=106,140,141,200,201
} | ForEach-Object {
    $EventName = switch ($_.Id) {
        106 {"Task Created"}
        140 {"Task Updated"}
        141 {"Task Deleted"}
        200 {"Task Executed"}
        201 {"Task Completed"}
    }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Event = $EventName
        TaskName = $_.Properties[0].Value
        User = if ($_.Properties.Count -gt 1) {$_.Properties[1].Value} else {"N/A"}
    }
} | Export-Csv C:\Temp\ScheduledTasks_TaskScheduler.csv -NoTypeInformation
```

**Security Log Task Events (Event IDs 4698, 4699, 4700, 4701, 4702):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4698,4699,4700,4701,4702} | 
    ForEach-Object {
        $EventName = switch ($_.Id) {
            4698 {"Task Created"}
            4699 {"Task Deleted"}
            4700 {"Task Enabled"}
            4701 {"Task Disabled"}
            4702 {"Task Updated"}
        }
        
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Event = $EventName
            TaskName = $_.Properties[0].Value
            CreatedBy = $_.Properties[1].Value
            TaskContent = $_.Properties[2].Value
        }
    } | Export-Csv C:\Temp\ScheduledTasks_Security.csv -NoTypeInformation
```

**Detect Deleted Tasks (Common Attacker Cleanup):**

```powershell
# Tasks deleted shortly after execution
$Deletions = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4699}
$Executions = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TaskScheduler/Operational';ID=200
}

$Deletions | ForEach-Object {
    $DeleteTime = $_.TimeCreated
    $TaskName = $_.Properties[0].Value
    
    $Execution = $Executions | Where-Object {
        $_.Properties[0].Value -eq $TaskName -and
        ($DeleteTime - $_.TimeCreated).TotalMinutes -lt 30
    } | Select-Object -First 1
    
    if ($Execution) {
        [PSCustomObject]@{
            TaskName = $TaskName
            ExecutedTime = $Execution.TimeCreated
            DeletedTime = $DeleteTime
            DeletedBy = $_.Properties[1].Value
            TimeDiff = ($DeleteTime - $Execution.TimeCreated).TotalMinutes
            Suspicious = "YES"
        }
    }
} | Export-Csv C:\Temp\SuspiciousTaskDeletions.csv -NoTypeInformation
```

**Analyze .job Files:**

{% code overflow="wrap" %}
```powershell
# Parse task .job files
$TaskFiles = Get-ChildItem "C:\Windows\Tasks\*.job" -ErrorAction SilentlyContinue
$TaskFilesNew = Get-ChildItem "C:\Windows\System32\Tasks\" -Recurse -File -ErrorAction SilentlyContinue

$AllTasks = @()
$TaskFilesNew | ForEach-Object {
    $Content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($Content -match '<Command>(.*?)</Command>') {
        $Command = $Matches[1]
        $AllTasks += [PSCustomObject]@{
            TaskFile = $_.FullName
            Command = $Command
            Created = $_.CreationTime
            Modified = $_.LastWriteTime
        }
    }
}

$AllTasks | Export-Csv C:\Temp\TaskFiles_Analysis.csv -NoTypeInformation
```
{% endcode %}

***

#### Phase 4: PsExec Detection

**4.1 Source System Artifacts**

**Check for PsExec Execution:**

{% code overflow="wrap" %}
```powershell
# Check for PsExec EULA acceptance (first-time use)
$Users = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | 
    ForEach-Object {
        $SID = $_.PSChildName
        $ProfilePath = (Get-ItemProperty -Path $_.PSPath).ProfileImagePath
        $Username = Split-Path $ProfilePath -Leaf
        
        # Load user hive
        $HivePath = "$ProfilePath\NTUSER.DAT"
        if (Test-Path $HivePath) {
            reg load "HKU\$SID" $HivePath 2>$null
            
            $EulaKey = "Registry::HKU\$SID\Software\Sysinternals\PsExec"
            if (Test-Path $EulaKey) {
                $EulaAccepted = Get-ItemProperty -Path $EulaKey -Name "EulaAccepted" -ErrorAction SilentlyContinue
                if ($EulaAccepted) {
                    [PSCustomObject]@{
                        Username = $Username
                        EulaAccepted = $EulaAccepted.EulaAccepted
                        LastWriteTime = (Get-Item $EulaKey).LastWriteTime
                    }
                }
            }
            
            [gc]::Collect()
            reg unload "HKU\$SID" 2>$null
        }
    }

$Users | Export-Csv C:\Temp\PsExec_EULA.csv -NoTypeInformation
```
{% endcode %}

**Process Execution Artifacts:**

```powershell
# Check Prefetch for PSEXEC.EXE
Get-ChildItem "C:\Windows\Prefetch\PSEXEC*.pf" | 
    ForEach-Object {
        [PSCustomObject]@{
            FileName = $_.Name
            Created = $_.CreationTime
            Modified = $_.LastWriteTime
        }
    }
```

**4.2 Destination System Artifacts**

**PSEXESVC.EXE Detection:**

```powershell
# Check for PSEXESVC in Windows directory
Get-ChildItem "C:\Windows\PSEXESVC.EXE" -ErrorAction SilentlyContinue | 
    Select-Object FullName, CreationTime, LastWriteTime

# Check Prefetch
Get-ChildItem "C:\Windows\Prefetch\PSEXESVC*.pf" | 
    ForEach-Object {
        [PSCustomObject]@{
            FileName = $_.Name
            Created = $_.CreationTime
            Modified = $_.LastWriteTime
        }
    }
```

**Service Registry Key:**

```powershell
# Check for PSEXESVC service key
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC"
if (Test-Path $ServiceKey) {
    Get-ItemProperty -Path $ServiceKey | 
        Select-Object ImagePath, Start, Type, ObjectName
}

# Also check deleted keys via forensic tools
```

**Event Log Correlation:**

{% code overflow="wrap" %}
```powershell
# Correlate multiple PsExec indicators
$TimeRange = (Get-Date).AddDays(-7)

# Type 2 Console logon (with -u option) or Type 3 Network logon
$Logons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624;StartTime=$TimeRange} | 
    Where-Object {$_.Properties[8].Value -in @(2,3)}

# Service creation
$Services = Get-WinEvent -FilterHashtable @{LogName='System';ID=7045;StartTime=$TimeRange} | 
    Where-Object {$_.Properties[0].Value -like "PSEXESVC*"}

# ADMIN$ share access
$Shares = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5140;StartTime=$TimeRange} | 
    Where-Object {$_.Properties[3].Value -eq "\\*\ADMIN$"}

# Correlate by time
$Services | ForEach-Object {
    $ServiceTime = $_.TimeCreated
    
    $RelatedLogon = $Logons | Where-Object {
        [Math]::Abs(($_.TimeCreated - $ServiceTime).TotalSeconds) -lt 10
    } | Select-Object -First 1
    
    $RelatedShare = $Shares | Where-Object {
        [Math]::Abs(($_.TimeCreated - $ServiceTime).TotalSeconds) -lt 10
    } | Select-Object -First 1
    
    [PSCustomObject]@{
        ServiceCreatedTime = $ServiceTime
        ServiceName = $_.Properties[0].Value
        LogonUser = if ($RelatedLogon) {$RelatedLogon.Properties[5].Value} else {"N/A"}
        LogonIP = if ($RelatedLogon) {$RelatedLogon.Properties[18].Value} else {"N/A"}
        ShareAccess = if ($RelatedShare) {"YES"} else {"NO"}
        Confidence = "HIGH"
    }
} | Export-Csv C:\Temp\PsExec_Correlation.csv -NoTypeInformation
```
{% endcode %}

***

#### Phase 5: WMI Lateral Movement

**5.1 WMI Activity Log Analysis**

**Query WMI Events:**

```powershell
# Event ID 5857: Provider loaded
# Event ID 5858: Query errors (includes hostname/username)
# Event ID 5859: Filter activity
# Event ID 5860: Consumer activity
# Event ID 5861: Permanent consumer creation

Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WMI-Activity/Operational'
    ID=5857,5858,5859,5860,5861
} | ForEach-Object {
    $EventName = switch ($_.Id) {
        5857 {"Provider Loaded"}
        5858 {"Query Error"}
        5859 {"Filter Activity"}
        5860 {"Consumer Activity"}
        5861 {"Permanent Consumer Created"}
    }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID = $_.Id
        Event = $EventName
        Message = $_.Message
    }
} | Export-Csv C:\Temp\WMI_Activity.csv -NoTypeInformation
```

**Detect Remote WMI (Event ID 5858):**

```powershell
# 5858 includes hostname and username for remote queries
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WMI-Activity/Operational'
    ID=5858
} | Where-Object {$_.Message -match "ClientMachine"} |
    ForEach-Object {
        if ($_.Message -match "ClientMachine = (.*?);") {
            $ClientMachine = $Matches[1]
        }
        if ($_.Message -match "User = (.*?)\n") {
            $User = $Matches[1]
        }
        
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ClientMachine = $ClientMachine
            User = $User
            Query = $_.Message
        }
    } | Export-Csv C:\Temp\WMI_Remote_Queries.csv -NoTypeInformation
```

**Process Execution Artifacts:**

```powershell
# Look for wmiprvse.exe execution
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | 
    Where-Object {$_.Properties[5].Value -match "wmiprvse.exe"} |
    Select-Object TimeCreated, 
        @{N='Process';E={$_.Properties[5].Value}},
        @{N='User';E={$_.Properties[1].Value}},
        @{N='CommandLine';E={$_.Properties[8].Value}}
```

***

#### Phase 6: PowerShell Remoting

**6.1 Source System Analysis**

**PowerShell/Operational Log:**

```powershell
# Event ID 4103: Module logging
# Event ID 4104: Script block logging
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4103,4104
} | Where-Object {
    $_.Message -match "Invoke-Command|Enter-PSSession|New-PSSession"
} | Select-Object TimeCreated, Id, Message | 
    Export-Csv C:\Temp\PowerShell_Remoting_Source.csv -NoTypeInformation
```

**WinRM/Operational Log:**

```powershell
# Event ID 6: WSMan session creation
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WinRM/Operational'
    ID=6
} | ForEach-Object {
    if ($_.Message -match "Destination: (.*?)\n") {
        $Destination = $Matches[1]
    }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Destination = $Destination
        User = $env:USERNAME
        Message = $_.Message
    }
} | Export-Csv C:\Temp\WinRM_Outbound.csv -NoTypeInformation
```

**PowerShell Console History:**

{% code overflow="wrap" %}
```powershell
# Read ConsoleHost_history.txt for all users
$Users = Get-ChildItem "C:\Users" -Directory

$Users | ForEach-Object {
    $HistoryPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    
    if (Test-Path $HistoryPath) {
        $History = Get-Content $HistoryPath
        [PSCustomObject]@{
            User = $_.Name
            HistoryFile = $HistoryPath
            LastModified = (Get-Item $HistoryPath).LastWriteTime
            CommandCount = $History.Count
            SuspiciousCommands = ($History | Where-Object {
                $_ -match "Invoke-|IEX|downloadstring|WebClient|Enter-PSSession|New-PSSession"
            }).Count
            Commands = $History -join "`n"
        }
    }
} | Export-Csv C:\Temp\PowerShell_History.csv -NoTypeInformation
```
{% endcode %}

**6.2 Destination System Analysis**

**Detect wsmprovhost.exe:**

```powershell
# Process creation for PowerShell remoting on destination
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | 
    Where-Object {$_.Properties[5].Value -match "wsmprovhost.exe"} |
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Process = $_.Properties[5].Value
            User = $_.Properties[1].Value
            ParentProcess = $_.Properties[13].Value
            CommandLine = $_.Properties[8].Value
        }
    } | Export-Csv C:\Temp\PowerShell_Remoting_Destination.csv -NoTypeInformation
```

**PowerShell Script Block Logging:**

```powershell
# Capture scripts executed via remoting
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} | Where-Object {$_.LevelDisplayName -eq "Warning"} |  # Suspicious scripts
    Select-Object TimeCreated, 
        @{N='ScriptBlock';E={$_.Properties[2].Value}},
        @{N='Path';E={$_.Properties[4].Value}} |
    Export-Csv C:\Temp\PowerShell_Suspicious_Scripts.csv -NoTypeInformation
```

**WinRM Event Log:**

```powershell
# Event ID 91: Session creation
# Event ID 168: Authenticating user
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WinRM/Operational'
    ID=91,168
} | Select-Object TimeCreated, Id, Message |
    Export-Csv C:\Temp\WinRM_Inbound.csv -NoTypeInformation
```

***

### 🔐 Persistence Mechanisms

#### Phase 1: Registry Run Keys

**1.1 Monitor Registry Modifications (Event IDs 4656, 4657, 4658, 4660, 4663)**

**Query Registry Modifications:**

```powershell
# Event ID 4657: Registry value modified
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4657} | 
    Where-Object {
        $ObjectName = $_.Properties[6].Value
        $ObjectName -match "CurrentVersion\\Run" -or
        $ObjectName -match "CurrentVersion\\RunOnce"
    } | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[1].Value
            RegistryPath = $_.Properties[6].Value
            OperationType = $_.Properties[8].Value
            OldValue = $_.Properties[10].Value
            NewValue = $_.Properties[11].Value
        }
    } | Export-Csv C:\Temp\Registry_RunKeys_4657.csv -NoTypeInformation
```

**Check Run Keys Manually:**

{% code overflow="wrap" %}
```powershell
# Check current Run keys
$RunKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$RunKeys | ForEach-Object {
    $KeyPath = $_
    if (Test-Path $KeyPath) {
        Get-ItemProperty -Path $KeyPath | 
            Select-Object PSPath, * -ExcludeProperty PS* | 
            ForEach-Object {
                $Props = $_.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"}
                $Props | ForEach-Object {
                    [PSCustomObject]@{
                        RegistryPath = $KeyPath
                        ValueName = $_.Name
                        Command = $_.Value
                        LastWriteTime = (Get-Item $KeyPath).LastWriteTime
                    }
                }
            }
    }
} | Export-Csv C:\Temp\Current_RunKeys.csv -NoTypeInformation
```
{% endcode %}

***

#### Phase 2: Scheduled Tasks

_See Phase 3 of Lateral Movement section for comprehensive Scheduled Task analysis_

***

#### Phase 3: Windows Services

_See Phase 2 of Lateral Movement section for comprehensive Service analysis_

***

#### Phase 4: WMI Event Subscription

**4.1 Detect WMI Persistence (Event ID 5861)**

**Query Permanent Event Consumers:**

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WMI-Activity/Operational'
    ID=5861
} | ForEach-Object {
    if ($_.Message -match 'CommandLineEventConsumer|ActiveScriptEventConsumer') {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ConsumerType = if ($_.Message -match 'CommandLineEventConsumer') {"CommandLine"} else {"Script"}
            Message = $_.Message
            Severity = "CRITICAL"
        }
    }
} | Export-Csv C:\Temp\WMI_EventConsumers_5861.csv -NoTypeInformation
```
{% endcode %}

**Enumerate WMI Event Subscriptions:**

```powershell
# List all event filters
Get-WmiObject -Namespace root\subscription -Class __EventFilter | 
    Select-Object Name, Query, QueryLanguage, CreatorSID |
    Export-Csv C:\Temp\WMI_EventFilters.csv -NoTypeInformation

# List all event consumers
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | 
    Select-Object Name, @{N='Type';E={$_.__CLASS}} |
    Export-Csv C:\Temp\WMI_EventConsumers.csv -NoTypeInformation

# List bindings (connects filters to consumers)
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | 
    Select-Object Consumer, Filter |
    Export-Csv C:\Temp\WMI_Bindings.csv -NoTypeInformation

# Detailed consumer analysis
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | 
    Select-Object Name, CommandLineTemplate, CreatorSID |
    Export-Csv C:\Temp\WMI_CommandLineConsumers.csv -NoTypeInformation

Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer | 
    Select-Object Name, ScriptingEngine, ScriptText, CreatorSID |
    Export-Csv C:\Temp\WMI_ScriptConsumers.csv -NoTypeInformation
```

**Hunt for Malicious Patterns:**

{% code overflow="wrap" %}
```powershell
# Look for suspicious keywords
$SuspiciousKeywords = @("powershell", "cmd", "wscript", "cscript", "eval", "downloadstring", "invoke", "exec")

Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | 
    ForEach-Object {
        $Consumer = $_
        $Suspicious = $false
        foreach ($Keyword in $SuspiciousKeywords) {
            if ($Consumer.CommandLineTemplate -match $Keyword) {
                $Suspicious = $true
                break
            }
        }
        
        if ($Suspicious) {
            [PSCustomObject]@{
                Name = $Consumer.Name
                CommandLine = $Consumer.CommandLineTemplate
                CreatorSID = $Consumer.CreatorSID
                Reason = "Contains suspicious keyword: $Keyword"
            }
        }
    } | Export-Csv C:\Temp\Suspicious_WMI_Consumers.csv -NoTypeInformation
```
{% endcode %}

***

### ⬆️ Privilege Escalation

#### Tracking Privilege Changes

**Group Membership Changes:**

```powershell
# Event IDs for group modifications
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4728,4732,4735,4756  # Added to groups
} | ForEach-Object {
    $EventName = switch ($_.Id) {
        4728 {"Added to Global Group"}
        4732 {"Added to Local Group"}
        4735 {"Local Group Changed"}
        4756 {"Added to Universal Group"}
    }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Event = $EventName
        TargetAccount = $_.Properties[0].Value
        Group = $_.Properties[2].Value
        AddedBy = $_.Properties[6].Value
    }
} | Export-Csv C:\Temp\GroupMembershipChanges.csv -NoTypeInformation
```

**Monitor Sensitive Groups:**

{% code overflow="wrap" %}
```powershell
# Focus on admin groups
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4732} | 
    Where-Object {
        $Group = $_.Properties[2].Value
        $Group -match "Administrators|Domain Admins|Enterprise Admins|Schema Admins|Backup Operators"
    } | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            UserAdded = $_.Properties[0].Value
            Group = $_.Properties[2].Value
            AddedBy = $_.Properties[6].Value
            Severity = "CRITICAL"
        }
    } | Export-Csv C:\Temp\AdminGroupChanges.csv -NoTypeInformation
```
{% endcode %}

***

### 💻 PowerShell & WMI Analysis

#### Phase 1: PowerShell Logging

**1.1 Script Block Logging (Event ID 4104)**

**Extract All Script Blocks:**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Level = $_.LevelDisplayName
        ScriptBlockId = $_.Properties[3].Value
        ScriptBlockText = $_.Properties[2].Value
        Path = $_.Properties[4].Value
    }
} | Export-Csv C:\Temp\PowerShell_ScriptBlocks_4104.csv -NoTypeInformation
```

**Filter Suspicious Scripts:**

```powershell
# Look for common attack patterns
$SuspiciousPatterns = @(
    "downloadstring", "downloadfile", "invoke-expression", "iex", 
    "invoke-webrequest", "invoke-restmethod", "net.webclient",
    "bitstransfer", "start-bitstransfer", "system.net.webclient",
    "-enc", "-encodedcommand", "frombase64string",
    "invoke-mimikatz", "invoke-shellcode", "invoke-wmimethod",
    "invoke-command", "enter-pssession", "new-pssession"
)

Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} | Where-Object {
    $ScriptText = $_.Properties[2].Value
    $Matched = $false
    foreach ($Pattern in $SuspiciousPatterns) {
        if ($ScriptText -match $Pattern) {
            $Matched = $true
            break
        }
    }
    $Matched
} | Select-Object TimeCreated, 
    @{N='Level';E={$_.LevelDisplayName}},
    @{N='ScriptBlock';E={$_.Properties[2].Value}} |
    Export-Csv C:\Temp\Suspicious_PowerShell_Scripts.csv -NoTypeInformation
```

**Detect Download Cradles:**

{% code overflow="wrap" %}
```powershell
# The infamous download cradle pattern
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} | Where-Object {
    $_.Properties[2].Value -match "IEX.*downloadstring|Invoke-Expression.*downloadstring"
} | Select-Object TimeCreated, @{N='Script';E={$_.Properties[2].Value}}
```
{% endcode %}

**Detect Obfuscation:**

```powershell
# Look for heavily obfuscated scripts
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} | Where-Object {
    $Script = $_.Properties[2].Value
    # Check for excessive backticks, string concatenation, encoding
    ($Script -split '`').Count -gt 10 -or
    ($Script -split '\+').Count -gt 20 -or
    $Script -match "char\[" -or
    $Script -match "\[convert\]::frombase64string" -or
    $Script -match "-join"
} | Select-Object TimeCreated, 
    @{N='Script';E={$_.Properties[2].Value}},
    @{N='Reason';E={"Possible Obfuscation"}}
```

**1.2 Module Logging (Event ID 4103)**

**Extract Pipeline Output:**

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4103
} | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        ContextInfo = $_.Properties[0].Value
        Payload = $_.Properties[1].Value
    }
} | Export-Csv C:\Temp\PowerShell_ModuleLogging_4103.csv -NoTypeInformation
```

***

#### Phase 2: WMI Analysis

_See Lateral Movement WMI section and Persistence WMI section above_

***

### 🦠 Malware Execution Evidence

#### Phase 1: Application and System Crashes

**Windows Error Reporting (Event IDs 1000-1002):**

{% code overflow="wrap" %}
```powershell
# Application crashes
Get-WinEvent -FilterHashtable @{LogName='Application';ID=1000,1001,1002} | 
    ForEach-Object {
        $EventName = switch ($_.Id) {
            1000 {"Application Error"}
            1001 {"Application Hang"}
            1002 {"Application Recovery"}
        }
        
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Event = $EventName
            Application = $_.Properties[0].Value
            FaultModule = if ($_.Properties.Count -gt 3) {$_.Properties[3].Value} else {"N/A"}
            ExceptionCode = if ($_.Properties.Count -gt 5) {$_.Properties[5].Value} else {"N/A"}
        }
    } | Export-Csv C:\Temp\ApplicationCrashes_1000.csv -NoTypeInformation
```
{% endcode %}

**System Critical Errors:**

```powershell
# System log critical/error/warning events
Get-WinEvent -FilterHashtable @{
    LogName='System'
    Level=1,2,3  # Critical, Error, Warning
    StartTime=(Get-Date).AddDays(-7)
} | Group-Object Id | 
    Sort-Object Count -Descending |
    Select-Object Count, Name, @{N='Message';E={$_.Group[0].Message}} |
    Export-Csv C:\Temp\System_Critical_Errors.csv -NoTypeInformation
```

**Analyze Windows Error Reports:**

```powershell
# Extract WER reports
$WERPath = "C:\ProgramData\Microsoft\Windows\WER\ReportQueue"
Get-ChildItem $WERPath -Recurse -Filter "Report.wer" | 
    ForEach-Object {
        $Content = Get-Content $_.FullName -Raw
        [PSCustomObject]@{
            ReportPath = $_.FullName
            Created = $_.CreationTime
            Content = $Content
        }
    } | Export-Csv C:\Temp\WER_Reports.csv -NoTypeInformation
```

***

#### Phase 2: Process Tracking

**Process Creation (Event ID 4688):**

```powershell
# Extract process creation events with command lines
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[1].Value
            Domain = $_.Properties[2].Value
            LogonID = $_.Properties[3].Value
            ProcessName = $_.Properties[5].Value
            ProcessID = $_.Properties[4].Value
            ParentProcessName = $_.Properties[13].Value
            CommandLine = $_.Properties[8].Value
            TokenElevationType = $_.Properties[9].Value
        }
    } | Export-Csv C:\Temp\ProcessCreation_4688.csv -NoTypeInformation
```

**Detect Suspicious Process Patterns:**

```powershell
# Processes from temp directories
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | 
    Where-Object {
        $ProcessPath = $_.Properties[5].Value
        $ProcessPath -match "temp|tmp|appdata\\local\\temp|downloads"
    } | Select-Object TimeCreated, 
        @{N='Process';E={$_.Properties[5].Value}},
        @{N='CommandLine';E={$_.Properties[8].Value}},
        @{N='User';E={$_.Properties[1].Value}}

# Renamed system tools
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | 
    Where-Object {
        $ProcessPath = $_.Properties[5].Value
        $ProcessPath -notmatch "system32|syswow64" -and
        $ProcessPath -match "cmd|powershell|wmic|psexec|net\.exe"
    }

# Suspicious parent-child relationships
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | 
    Where-Object {
        $ParentProcess = $_.Properties[13].Value
        $ChildProcess = $_.Properties[5].Value
        # Word/Excel spawning PowerShell/cmd
        ($ParentProcess -match "winword|excel|outlook" -and 
         $ChildProcess -match "powershell|cmd|wscript|cscript")
    }
```

***

### 📦 Event Log Collection

#### Live System Collection

**Method 1: Event Viewer Export**

```powershell
# Via GUI: Right-click log → Save Log As
# Formats: .evtx (native), .csv, .xml, .txt
```

**Method 2: wevtutil (Built-in)**

```powershell
# Export single log
wevtutil epl Security C:\Temp\Security.evtx

# Export with query filter
wevtutil epl Security C:\Temp\Security_Filtered.evtx "/q:*[System[(EventID=4624)]]"

# Export all logs
wevtutil el | ForEach-Object {
    $LogName = $_
    $FileName = $LogName -replace "/", "_"
    wevtutil epl $LogName "C:\Temp\Logs\$FileName.evtx"
}
```

**Method 3: PowerShell Get-WinEvent**

```powershell
# Export Security log
(Get-WmiObject -Class Win32_NTEventlogFile | 
    Where-Object LogfileName -EQ 'Security').BackupEventlog('C:\Temp\Security.evtx')

# Export all logs
Get-WmiObject -Class Win32_NTEventlogFile | ForEach-Object {
    $_.BackupEventlog("C:\Temp\$($_.LogfileName).evtx")
}

# Remote collection
Get-WinEvent -ComputerName SERVER01 -FilterHashtable @{LogName='Security';ID=4624} |
    Export-Csv C:\Temp\Remote_Security.csv -NoTypeInformation
```

**Method 4: PsLogList (Sysinternals)**

```powershell
# Dump live log to CSV
.\PsLogList.exe -s -x Security > C:\Temp\Security.csv

# Remote system collection
.\PsLogList.exe \\SERVER01 -s -x Security > C:\Temp\Remote_Security.csv

# With filter
.\PsLogList.exe -s -x -i 4624,4625 Security > C:\Temp\Filtered_Security.csv
```

**Method 5: KAPE**

{% code overflow="wrap" %}
```powershell
# Collect all event logs
.\kape.exe --tsource C: --target EventLogs --tdest C:\Temp\KAPE_Output

# With modules for parsing
.\kape.exe --tsource C: --target EventLogs --tdest C:\Temp\KAPE_Output --module EvtxECmd
```
{% endcode %}

**Method 6: Velociraptor**

```yaml
# Artifact collection
name: Windows.EventLogs.Collection
sources:
  - precondition: SELECT OS From info() where OS = 'windows'
    query: |
      SELECT FullPath, Size, Mtime
      FROM glob(globs='C:/Windows/System32/winevt/Logs/*.evtx')
```

***

#### Remote Collection at Scale

**Windows Event Forwarding (WEF)**

**Configure Collector:**

```powershell
# Enable WinRM
winrm quickconfig

# Configure subscriptions
wecutil cs subscription.xml
```

**Example Subscription XML:**

{% code overflow="wrap" %}
```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>Security_Events</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Forward security events</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <Query>
        <![CDATA[
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*[System[(EventID=4624 or EventID=4625)]]</Select>
            </Query>
        </QueryList>
        ]]>
    </Query>
</Subscription>
```
{% endcode %}

**PowerShell Remoting (at Scale)**

{% code overflow="wrap" %}
```powershell
# Define target computers
$Computers = Get-Content C:\Temp\computers.txt

# Collect from multiple systems
$Computers | ForEach-Object {
    $Computer = $_
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} -MaxEvents 1000
    } | Export-Csv "C:\Temp\$Computer_Security.csv" -NoTypeInformation
}

# Parallel processing
$Computers | ForEach-Object -Parallel {
    $Computer = $_
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        (Get-WmiObject -Class Win32_NTEventlogFile | 
            Where-Object LogfileName -EQ 'Security').BackupEventlog("\\COLLECTOR\Share\$env:COMPUTERNAME-Security.evtx")
    }
} -ThrottleLimit 10
```
{% endcode %}

***

### 🛠️ Tool Reference

#### EvtxECmd

**Installation:**

```powershell
# Download from https://ericzimmerman.github.io/
```

**Usage:**

{% code overflow="wrap" %}
```powershell
# Single file
.\EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\Security.evtx" --csv "C:\Analysis" --csvf Security.csv

# Entire directory
.\EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv "C:\Analysis" --csvf AllLogs.csv

# With maps (filtering)
.\EvtxECmd.exe -f Security.evtx --csv C:\Analysis --csvf Security.csv --maps C:\Maps

# From VSS
.\EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv C:\Analysis --vss
```
{% endcode %}

***

#### DeepBlueCLI

**Installation:**

```powershell
# Clone from https://github.com/sans-blue-team/DeepBlueCLI
git clone https://github.com/sans-blue-team/DeepBlueCLI.git
```

**Usage:**

```powershell
# Local Security log
.\DeepBlue.ps1

# Specific log
.\DeepBlue.ps1 -log security

# System log
.\DeepBlue.ps1 -log system

# Exported evtx file
.\DeepBlue.ps1 .\Security.evtx

# Multiple files
Get-ChildItem C:\Logs\*.evtx | ForEach-Object { .\DeepBlue.ps1 $_.FullName }
```

***

#### Chainsaw

**Installation:**

```powershell
# Download from https://github.com/countercept/chainsaw
```

**Usage:**

```powershell
# Hunt with Sigma rules
.\chainsaw hunt C:\Logs --rules .\sigma\ --mapping .\mappings\

# Search for specific events
.\chainsaw search C:\Logs -e 4624 -e 4625

# Output to CSV
.\chainsaw hunt C:\Logs --rules .\sigma\ --output csv
```

***

#### Hayabusa

**Installation:**

```powershell
# Download from https://github.com/Yamato-Security/hayabusa
```

**Usage:**

```powershell
# Timeline creation
.\hayabusa.exe csv-timeline -d C:\Logs -o timeline.csv

# Live analysis
.\hayabusa.exe csv-timeline -l -o live-timeline.csv

# With custom rules
.\hayabusa.exe csv-timeline -d C:\Logs -r .\rules\ -o timeline.csv
```

***

### 📋 Investigation Playbooks

#### Playbook 1: Suspected Compromised Account

```bash
1. Initial Triage (15 min)
   □ Verify account status (enabled/disabled)
   □ Check current active sessions
   □ Identify account type (local/domain/service)
   
2. Authentication Analysis (30 min)
   □ Extract all 4624/4625 events for account (7 days)
   □ Identify unusual logon types (especially Type 8, 9, 10)
   □ Check source IPs and geographic locations
   □ Identify failed logon patterns
   
3. Activity Analysis (45 min)
   □ Correlate with process execution (4688)
   □ Check for admin privilege usage (4672)
   □ Review explicit credential usage (4648)
   □ Examine PowerShell/WMI activity
   
4. Lateral Movement Check (30 min)
   □ Search for Type 3 logons to other systems
   □ Check service creation (7045, 4697)
   □ Review scheduled task activity (4698, 4699)
   □ Examine file share access (5140, 5145)
   
5. Persistence Check (30 min)
   □ Review registry run key changes (4657)
   □ Check for new services
   □ Examine scheduled tasks
   □ Audit WMI event subscriptions (5861)
   
6. Reporting (30 min)
   □ Create timeline of all activity
   □ Document IOCs
   □ Assess scope of compromise
   □ Recommend remediation actions
```

***

#### Playbook 2: Lateral Movement Investigation

```bash
1. Identify Source System (15 min)
   □ Determine initial compromise point
   □ Identify compromised account
   □ Establish timeframe
   
2. Map Network Logons (45 min)
   □ Extract all Type 3 logons from source
   □ Identify destination systems
   □ Check for Type 10 (RDP) logons
   □ Review 4648 events for credential switching
   
3. Technique Identification (60 min)
   □ Check for PsExec artifacts (PSEXESVC, 7045)
   □ Review WMI activity (5857-5861, wmiprvse)
   □ Examine PowerShell remoting (wsmprovhost, 4104)
   □ Check service creation on targets
   □ Review scheduled task creation
   □ Analyze share access (5140)
   
4. Privilege Escalation (30 min)
   □ Check for admin logons (4672)
   □ Review group membership changes (4732)
   □ Examine privilege assignment events
   
5. Scope Assessment (45 min)
   □ Create network diagram of compromise
   □ Identify all affected systems
   □ Determine data accessed
   □ Check for persistence mechanisms
   
6. Containment & Eradication (varies)
   □ Isolate affected systems
   □ Reset compromised credentials
   □ Remove persistence mechanisms
   □ Patch vulnerabilities
```

***

#### Playbook 3: PowerShell Attack Investigation

```bash
1. Initial Detection (15 min)
   □ Identify suspicious PowerShell alerts
   □ Note timestamp and affected system
   □ Check if process still running
   
2. Script Analysis (45 min)
   □ Extract script blocks (4104)
   □ Review module logging (4103)
   □ Check console history (ConsoleHost_history.txt)
   □ Decode base64/obfuscation
   
3. Execution Context (30 min)
   □ Identify parent process (4688)
   □ Check user account used
   □ Review process command line
   □ Determine if remote execution
   
4. Payload Analysis (60 min)
   □ Identify downloaded files
   □ Check for credential access tools
   □ Review network connections
   □ Examine persistence mechanisms
   
5. Lateral Movement (30 min)
   □ Check for PowerShell remoting (wsmprovhost)
   □ Review WinRM logs
   □ Identify remote targets
   
6. Remediation (varies)
   □ Remove malicious scripts
   □ Kill related processes
   □ Check other systems for same IOCs
   □ Enable enhanced PowerShell logging
```

***

### 📈 Quick Reference: Time-Saving Queries

#### Top 10 Failed Logon Sources

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} | 
    Group-Object @{Expression={$_.Properties[19].Value}} |
    Sort-Object Count -Descending | Select-Object -First 10
```

#### All Admin Activity Last 24 Hours

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4672
    StartTime=(Get-Date).AddDays(-1)
}
```

#### New Services Last 7 Days

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=7045
    StartTime=(Get-Date).AddDays(-7)
}
```

#### Suspicious PowerShell This Week

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
    StartTime=(Get-Date).AddDays(-7)
} | Where-Object {$_.LevelDisplayName -eq "Warning"}
```

#### All RDP Sessions Today

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
    StartTime=(Get-Date).Date
} | Where-Object {$_.Properties[8].Value -eq 10}
```

***

_This guide consolidates event log analysis, tool usage, and investigation workflows into a single reference. Bookmark for quick access during incidents._
