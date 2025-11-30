# PowerShell Mastery for Senior SOC Analysts

### Advanced Threat Hunting, Detection Engineering & Incident Response

***

### 🎯 Why This Matters for Senior SOC Analysts

As a Senior SOC Analyst, PowerShell is your force multiplier. While junior analysts click through GUIs, you're automating threat hunts across 10,000 endpoints. While others wait for SIEM alerts, you're proactively hunting APT persistence. This guide assumes you know security fundamentals and focuses on making you a PowerShell-wielding threat hunter.

**Key Focus Areas:**

* Advanced threat hunting at scale
* Custom detection engineering
* Automated incident response playbooks
* SIEM integration and log enrichment
* Cross-endpoint behavioural analysis
* Malware analysis and deobfuscation

***

### 🛡️ Senior SOC Analyst's Advanced PowerShell Cheatsheet

#### Advanced Discovery & Intelligence

```powershell
# Discover ALL cmdlets related to security
Get-Command -Module Microsoft.PowerShell.Security, Defender, NetSecurity

# Find commands by capability
Get-Command -ParameterName ComputerName  # All cmdlets supporting remote execution
Get-Command -Verb Invoke  # Execution-related cmdlets

# Deep object inspection
Get-Process | Get-Member -MemberType Properties
$event | Format-List -Property * -Force  # Show ALL properties including hidden

# Discover Sysmon capabilities
Get-WinEvent -ListLog * | Where-Object {$_.LogName -like "*Sysmon*"}
Get-WinEvent -ListProvider *Sysmon* | Select-Object -ExpandProperty Events
```

#### APT & Advanced Threat Hunting

{% code overflow="wrap" %}
```powershell
# === MITRE ATT&CK T1218: LOLBin Abuse Detection ===
$LOLBins = @(
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "installutil.exe", "msbuild.exe", "cscript.exe",
    "wscript.exe", "regasm.exe", "regsvcs.exe", "msiexec.exe"
)

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 5000 |
    Where-Object {
        $cmdline = $_.Properties[8].Value
        $procName = $_.Properties[5].Value
        
        $LOLBins | Where-Object {
            $cmdline -like "*$_*" -and (
                $cmdline -match "http" -or 
                $cmdline -match "script:" -or
                $cmdline -match "javascript:" -or
                $cmdline -match "-enc" -or
                $cmdline -match "\.tmp"
            )
        }
    } | Select-Object TimeCreated,
        @{N='Process';E={$_.Properties[5].Value}},
        @{N='CommandLine';E={$_.Properties[8].Value}},
        @{N='User';E={$_.Properties[1].Value}},
        @{N='ParentProcess';E={$_.Properties[13].Value}}

# === MITRE ATT&CK T1021.006: Lateral Movement via PSRemoting ===
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4103,4104
} -MaxEvents 10000 | Where-Object {
    $_.Message -match "Enter-PSSession|Invoke-Command|New-PSSession"
} | Select-Object TimeCreated,
    @{N='User';E={$_.UserId}},
    @{N='ScriptBlock';E={$_.Properties[2].Value}},
    @{N='Path';E={$_.Properties[4].Value}}

# === MITRE ATT&CK T1003: Credential Dumping Detection ===
# Hunt for LSASS access attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} -MaxEvents 5000 |
    Where-Object {
        $_.Properties[6].Value -like "*lsass.exe*"
    } | Select-Object TimeCreated,
        @{N='Process';E={$_.Properties[11].Value}},
        @{N='User';E={$_.Properties[1].Value}},
        @{N='AccessMask';E={$_.Properties[9].Value}}

# Sysmon Event 10: LSASS access (Mimikatz signature)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=10
} | Where-Object {
    $target = $_.Properties[4].Value  # TargetImage
    $granted = $_.Properties[6].Value  # GrantedAccess
    $target -like "*lsass.exe" -and $granted -in @("0x1010", "0x1410", "0x1438")
} | Select-Object TimeCreated,
    @{N='SourceProcess';E={$_.Properties[2].Value}},
    @{N='SourceUser';E={$_.Properties[3].Value}},
    @{N='GrantedAccess';E={$_.Properties[6].Value}}

# === MITRE ATT&CK T1558.003: Kerberoasting Detection ===
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -MaxEvents 10000 |
    Where-Object {
        $ticketEncryption = $_.Properties[7].Value
        $serviceName = $_.Properties[0].Value
        $ticketEncryption -eq "0x17" -and  # RC4 encryption (weak)
        $serviceName -notlike "*$*"  # Not a machine account
    } | Select-Object TimeCreated,
        @{N='Account';E={$_.Properties[1].Value}},
        @{N='ServiceName';E={$_.Properties[0].Value}},
        @{N='SourceIP';E={$_.Properties[6].Value}},
        @{N='TicketOptions';E={$_.Properties[5].Value}} |
    Group-Object Account | Where-Object {$_.Count -gt 5}  # Multiple SPN requests

# === MITRE ATT&CK T1003.006: DCSync Attack Detection ===
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} -MaxEvents 5000 |
    Where-Object {
        $props = $_.Properties[8].Value
        $props -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes
        $props -match "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes-All
        $props -match "89e95b76-444d-4c62-991a-0facbeda640c"      # DS-Replication-Get-Changes-In-Filtered-Set
    } | Select-Object TimeCreated,
        @{N='User';E={$_.Properties[1].Value}},
        @{N='Object';E={$_.Properties[6].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}}

# === MITRE ATT&CK T1053.005: Scheduled Task Persistence ===
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698} -MaxEvents 1000 |
    Where-Object {
        $taskContent = $_.Properties[0].Value
        $taskContent -match "powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32"
    } | Select-Object TimeCreated,
        @{N='TaskName';E={$_.Properties[1].Value}},
        @{N='User';E={$_.Properties[3].Value}},
        @{N='TaskContent';E={$_.Properties[0].Value}}

# === MITRE ATT&CK T1543.003: Windows Service Persistence ===
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 1000 |
    Where-Object {
        $servicePath = $_.Properties[1].Value
        $servicePath -notmatch "C:\\Windows\\" -and
        $servicePath -notmatch "C:\\Program Files" -or
        $servicePath -match "powershell|cmd|wscript|%COMSPEC%"
    } | Select-Object TimeCreated,
        @{N='ServiceName';E={$_.Properties[0].Value}},
        @{N='ImagePath';E={$_.Properties[1].Value}},
        @{N='ServiceType';E={$_.Properties[2].Value}},
        @{N='StartType';E={$_.Properties[4].Value}}

# === MITRE ATT&CK T1546: Event Triggered Execution ===
# WMI Event Subscriptions
Get-CimInstance -Namespace root/subscription -Class __EventFilter
Get-CimInstance -Namespace root/subscription -Class __EventConsumer
Get-CimInstance -Namespace root/subscription -Class __FilterToConsumerBinding

# Hunt for malicious WMI persistence
Get-CimInstance -Namespace root/subscription -Class __EventFilter | 
    Where-Object {
        $_.Query -match "powershell|cmd|wscript" -or
        $_.Query -match "http" -or
        $_.Name -notlike "SCM*"
    }
```
{% endcode %}

#### Process Analysis & Memory Hunting

{% code overflow="wrap" %}
```powershell
# Deep process inspection with parent-child relationships
Get-CimInstance Win32_Process | Select-Object ProcessId, Name, 
    ParentProcessId, CommandLine, ExecutablePath, CreationDate |
    ForEach-Object {
        $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
        $_ | Add-Member -NotePropertyName ParentName -NotePropertyValue $parent.Name -PassThru
    } | Where-Object {
        # Suspicious parent-child relationships
        ($_.Name -eq "cmd.exe" -and $_.ParentName -eq "wmiprvse.exe") -or
        ($_.Name -eq "powershell.exe" -and $_.ParentName -eq "winword.exe") -or
        ($_.Name -eq "powershell.exe" -and $_.ParentName -eq "excel.exe") -or
        ($_.Name -like "*.exe" -and $_.ParentName -eq "wscript.exe")
    }

# Hunt for process hollowing (mismatched disk path vs memory)
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    $proc = $_
    $expectedName = [System.IO.Path]::GetFileNameWithoutExtension($proc.Path)
    
    if ($proc.ProcessName -ne $expectedName) {
        [PSCustomObject]@{
            PID = $proc.Id
            ProcessName = $proc.ProcessName
            ExpectedName = $expectedName
            ActualPath = $proc.Path
            CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
            Suspicious = "Process Hollowing Indicator"
        }
    }
}

# Detect process injection via loaded DLLs
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    $proc = $_
    $unexpectedDLLs = $proc.Modules | Where-Object {
        $_.ModuleName -notmatch "^(kernel32|ntdll|user32|advapi32|msvcrt|ws2_32|ole32)" -and
        $_.FileName -notmatch "C:\\Windows\\" -and
        $_.FileName -notmatch "C:\\Program Files"
    }
    
    if ($unexpectedDLLs) {
        [PSCustomObject]@{
            ProcessName = $proc.Name
            PID = $proc.Id
            Path = $proc.Path
            UnexpectedDLLs = ($unexpectedDLLs.ModuleName -join ", ")
            DLLPaths = ($unexpectedDLLs.FileName -join "; ")
        }
    }
}

# Hunt for unsigned or suspicious processes
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
    
    [PSCustomObject]@{
        Name = $_.Name
        PID = $_.Id
        Path = $_.Path
        Signed = ($sig.Status -eq 'Valid')
        Signer = $sig.SignerCertificate.Subject
        Company = $_.Company
        CommandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
    }
} | Where-Object {
    -not $_.Signed -or 
    $_.Company -eq $null -or
    ($_.Path -like "*\Temp\*") -or
    ($_.Path -like "*\AppData\Local\*" -and $_.Path -notlike "*\Microsoft\*")
}

# Reconnaissance command detection in process command lines
$ReconPatterns = @(
    "whoami /all", "net user", "net group", "net localgroup administrators",
    "ipconfig /all", "systeminfo", "tasklist", "query user", "quser",
    "nltest", "dsquery", "ldapsearch", "bloodhound", "sharphound",
    "klist", "cmdkey", "netstat -ano", "route print", "arp -a"
)

Get-CimInstance Win32_Process | Where-Object {
    $cmdline = $_.CommandLine
    $ReconPatterns | Where-Object {$cmdline -match [regex]::Escape($_)}
} | Select-Object ProcessId, Name, 
    @{N='CommandLine';E={$_.CommandLine}}, 
    @{N='User';E={$_.GetOwner().User}},
    CreationDate | Sort-Object CreationDate -Descending
```
{% endcode %}

#### Network-Based Threat Hunting

{% code overflow="wrap" %}
```powershell
# === C2 Beaconing Detection via Connection Timing Analysis ===
function Find-BeaconingBehavior {
    param(
        [int]$MinConnections = 5,
        [int]$MaxStdDev = 10,
        [int]$MinInterval = 5,
        [int]$MaxInterval = 3600
    )
    
    $connections = Get-NetTCPConnection -State Established
    $grouped = $connections | Group-Object -Property RemoteAddress | 
        Where-Object {$_.Count -ge $MinConnections}
    
    foreach ($group in $grouped) {
        $remoteIP = $group.Name
        $conns = $group.Group | Sort-Object CreationTime
        
        if ($conns.Count -lt 2) { continue }
        
        # Calculate inter-connection intervals
        $intervals = for ($i = 1; $i -lt $conns.Count; $i++) {
            ($conns[$i].CreationTime - $conns[$i-1].CreationTime).TotalSeconds
        }
        
        if ($intervals.Count -eq 0) { continue }
        
        $avgInterval = ($intervals | Measure-Object -Average).Average
        $variance = ($intervals | ForEach-Object {
            [Math]::Pow($_ - $avgInterval, 2)
        } | Measure-Object -Average).Average
        $stdDev = [Math]::Sqrt($variance)
        
        # Regular, consistent timing suggests automated beaconing
        if ($stdDev -lt $MaxStdDev -and 
            $avgInterval -gt $MinInterval -and 
            $avgInterval -lt $MaxInterval) {
            
            $process = Get-Process -Id $conns[0].OwningProcess -ErrorAction SilentlyContinue
            
            [PSCustomObject]@{
                RemoteIP = $remoteIP
                ConnectionCount = $conns.Count
                AvgIntervalSec = [Math]::Round($avgInterval, 2)
                StdDeviation = [Math]::Round($stdDev, 2)
                Jitter = [Math]::Round(($stdDev / $avgInterval) * 100, 2)
                ProcessName = $process.Name
                ProcessPath = $process.Path
                PID = $conns[0].OwningProcess
                LocalPort = $conns[0].LocalPort
                RemotePort = $conns[0].RemotePort
                Confidence = if ($stdDev -lt 5) {"High"} elseif ($stdDev -lt 10) {"Medium"} else {"Low"}
            }
        }
    }
}

Find-BeaconingBehavior | Format-Table -AutoSize

# === DNS Tunneling & DGA Domain Detection ===
function Find-SuspiciousDNS {
    Get-DnsClientCache | Where-Object {
        $name = $_.Name
        $subdomain = ($name -split '\.')[0]
        
        # Suspicious indicators
        $subdomain.Length -gt 30 -or  # Unusually long subdomain (data exfil)
        ($name -match '^[a-z0-9]{15,}\.') -or  # Random-looking (DGA)
        ($name -match '\.(tk|ml|ga|cf|gq|xyz|top|club|work|click)$') -or  # Suspicious TLDs
        ($subdomain -match '^[A-Za-z0-9+/=]{20,}$') -or  # Base64-like encoding
        (($name -split '\.').Count -gt 5)  # Too many subdomains
    } | Select-Object Name, Type, TimeToLive, Data, Status,
        @{N='SubdomainLength';E={($_.Name -split '\.')[0].Length}},
        @{N='Entropy';E={
            $chars = ($_.Name -split '\.')[0].ToCharArray()
            $freq = $chars | Group-Object | ForEach-Object {$_.Count / $chars.Count}
            -($freq | ForEach-Object {$_ * [Math]::Log($_,2)} | Measure-Object -Sum).Sum
        }}
}

Find-SuspiciousDNS | Sort-Object Entropy -Descending | Format-Table -AutoSize

# === Comprehensive Network Connection Analysis ===
Get-NetTCPConnection -State Established | ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $sig = if ($process.Path) {
        Get-AuthenticodeSignature -FilePath $process.Path -ErrorAction SilentlyContinue
    }
    
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
        State = $_.State
        ProcessName = $process.Name
        ProcessPath = $process.Path
        PID = $_.OwningProcess
        Company = $process.Company
        Signed = ($sig.Status -eq 'Valid')
        CreationTime = $_.CreationTime
    }
} | Where-Object {
    # Filter for suspicious characteristics
    (
        $_.RemotePort -notin @(80, 443, 53, 22, 445, 3389) -and
        $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' -and
        $_.RemoteAddress -ne '127.0.0.1'
    ) -or
    (
        -not $_.Signed -and $_.ProcessPath -notmatch 'C:\\Windows\\'
    ) -or
    (
        $_.Company -eq $null -and $_.ProcessPath
    )
} | Sort-Object CreationTime -Descending

# === Port Scanning Detection ===
function Find-PortScanning {
    param([int]$TimeWindowMinutes = 15, [int]$ConnectionThreshold = 50)
    
    $StartTime = (Get-Date).AddMinutes(-$TimeWindowMinutes)
    $RecentConnections = Get-NetTCPConnection | Where-Object {
        $_.CreationTime -gt $StartTime
    }
    
    $RecentConnections | Group-Object -Property OwningProcess | Where-Object {
        $_.Count -gt $ConnectionThreshold
    } | ForEach-Object {
        $process = Get-Process -Id $_.Name -ErrorAction SilentlyContinue
        $uniqueIPs = ($_.Group | Select-Object -ExpandProperty RemoteAddress -Unique).Count
        $uniquePorts = ($_.Group | Select-Object -ExpandProperty RemotePort -Unique).Count
        
        [PSCustomObject]@{
            ProcessName = $process.Name
            ProcessPath = $process.Path
            Company = $process.Company
            PID = $_.Name
            TotalConnections = $_.Count
            UniqueDestIPs = $uniqueIPs
            UniqueDestPorts = $uniquePorts
            ScanIndicator = ($uniquePorts -gt 20 -or $uniqueIPs -gt 20)
            PortDiversity = [Math]::Round($uniquePorts / $_.Count, 2)
        }
    } | Where-Object {$_.ScanIndicator -eq $true}
}

Find-PortScanning | Format-Table -AutoSize

# === Suspicious Listening Services ===
Get-NetTCPConnection -State Listen | ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $sig = if ($process.Path) { 
        Get-AuthenticodeSignature -FilePath $process.Path -ErrorAction SilentlyContinue 
    }
    
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        ProcessName = $process.Name
        ProcessPath = $process.Path
        Company = $process.Company
        Signed = ($sig.Status -eq 'Valid')
        PID = $_.OwningProcess
    }
} | Where-Object {
    # Known good ports (exclude)
    $standardPorts = @(135, 445, 139, 3389, 5985, 5986, 49152..65535)
    
    ($_.LocalPort -notin $standardPorts) -and
    (
        $_.Company -notlike "Microsoft*" -or 
        -not $_.Signed -or
        $_.ProcessPath -like "*\Temp\*" -or
        $_.ProcessPath -like "*\AppData\*"
    )
} | Sort-Object LocalPort
```
{% endcode %}

#### Advanced Event Log Forensics

{% code overflow="wrap" %}
```powershell
# === PowerShell Script Block Logging Analysis ===
# Hunt for encoded/obfuscated PowerShell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 5000 | Where-Object {
    $scriptBlock = $_.Properties[2].Value
    
    # Obfuscation indicators
    $scriptBlock -match "frombase64string" -or
    $scriptBlock -match "\-enc.*[A-Za-z0-9+/=]{50,}" -or
    $scriptBlock -match "invoke-expression.*\(" -or
    $scriptBlock -match "iex\s+\(" -or
    $scriptBlock -match "invoke-command.*scriptblock" -or
    $scriptBlock -match "\.downloadstring" -or
    $scriptBlock -match "\.downloadfile" -or
    $scriptBlock -match "bitstransfer" -or
    $scriptBlock -match "start-bitstransfer" -or
    $scriptBlock -match "reflection\.assembly" -or
    $scriptBlock -match "bypass.*executionpolicy" -or
    $scriptBlock -match "noprofile.*noninteractive"
} | Select-Object TimeCreated,
    @{N='User';E={$_.UserId}},
    @{N='ScriptBlock';E={$_.Properties[2].Value}},
    @{N='Path';E={$_.Properties[4].Value}}

# === Decode Base64 PowerShell Commands ===
function Decode-Base64Command {
    param([string]$EncodedCommand)
    
    try {
        $bytes = [System.Convert]::FromBase64String($EncodedCommand)
        [System.Text.Encoding]::Unicode.GetString($bytes)
    } catch {
        "Failed to decode: $_"
    }
}

# Extract and decode from event logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 1000 |
    Where-Object {$_.Properties[8].Value -match "-enc\s+([A-Za-z0-9+/=]+)"} |
    ForEach-Object {
        $encoded = $matches[1]
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = $_.Properties[1].Value
            Process = $_.Properties[5].Value
            EncodedCommand = $encoded.Substring(0, [Math]::Min(50, $encoded.Length)) + "..."
            DecodedCommand = Decode-Base64Command -EncodedCommand $encoded
        }
    }

# === AMSI Bypass Detection ===
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} -MaxEvents 5000 | Where-Object {
    $_.Properties[2].Value -match "amsi" -and (
        $_.Properties[2].Value -match "AmsiScanBuffer" -or
        $_.Properties[2].Value -match "AmsiInitFailed" -or
        $_.Properties[2].Value -match "Reflection.Assembly.*Load" -or
        $_.Properties[2].Value -match "\[Ref\]\.Assembly" -or
        $_.Properties[2].Value -match "PatchAmsi" -or
        $_.Properties[2].Value -match "0x5fc" -or  # AMSI buffer offset
        $_.Properties[2].Value -match "0x8007"      # AMSI error code
    )
}

# === Advanced Log Correlation ===
# Correlate Security 4688 (process creation) with Sysmon 1 (process create)
function Get-CorrelatedProcessCreation {
    param(
        [datetime]$StartTime = (Get-Date).AddHours(-1),
        [datetime]$EndTime = (Get-Date)
    )
    
    $secEvents = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4688
        StartTime=$StartTime
        EndTime=$EndTime
    }
    
    $sysmonEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=1
        StartTime=$StartTime
        EndTime=$EndTime
    } -ErrorAction SilentlyContinue
    
    foreach ($secEvent in $secEvents) {
        $processName = $secEvent.Properties[5].Value
        $commandLine = $secEvent.Properties[8].Value
        $user = $secEvent.Properties[1].Value
        $eventTime = $secEvent.TimeCreated
        
        # Find matching Sysmon event (within 2 seconds)
        $matchingSysmon = $sysmonEvents | Where-Object {
            $timeDiff = [Math]::Abs(($_.TimeCreated - $eventTime).TotalSeconds)
            $timeDiff -lt 2 -and $_.Properties[4].Value -eq $processName
        } | Select-Object -First 1
        
        [PSCustomObject]@{
            Time = $eventTime
            ProcessName = $processName
            CommandLine = $commandLine
            User = $user
            ParentProcess = if ($matchingSysmon) {$matchingSysmon.Properties[20].Value}
            Hashes = if ($matchingSysmon) {$matchingSysmon.Properties[12].Value}
            SysmonCorrelated = ($null -ne $matchingSysmon)
        }
    }
}

# === Timeline Generation for Incident Response ===
function New-IncidentTimeline {
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [string]$TargetUser = "*",
        [string]$TargetHost = $env:COMPUTERNAME
    )
    
    $timeline = @()
    
    # Process creation events
    $timeline += Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4688
        StartTime=$StartTime
        EndTime=$EndTime
    } | ForEach-Object {
        [PSCustomObject]@{
            Timestamp = $_.TimeCreated
            EventType = "ProcessCreation"
            User = $_.Properties[1].Value
            Details = "$($_.Properties[5].Value) - $($_.Properties[8].Value)"
            Severity = "Info"
        }
    }
    
    # Logon events
    $timeline += Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4624,4625
        StartTime=$StartTime
        EndTime=$EndTime
    } | ForEach-Object {
        [PSCustomObject]@{
            Timestamp = $_.TimeCreated
            EventType = if ($_.Id -eq 4624) {"SuccessfulLogon"} else {"FailedLogon"}
            User = $_.Properties[5].Value
            Details = "LogonType: $($_.Properties[8].Value), Source: $($_.Properties[18].Value)"
            Severity = if ($_.Id -eq 4625) {"Warning"} else {"Info"}
        }
    }
    
    # PowerShell script execution
    $timeline += Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-PowerShell/Operational'
        ID=4104
        StartTime=$StartTime
        EndTime=$EndTime
    } -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Timestamp = $_.TimeCreated
            EventType = "PowerShellExecution"
            User = $_.UserId
            Details = $_.Properties[2].Value.Substring(0, [Math]::Min(100, $_.Properties[2].Value.Length))
            Severity = "Warning"
        }
    }
    
    # Network connections (Sysmon 3)
    $timeline += Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=3
        StartTime=$StartTime
        EndTime=$EndTime
    } -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Timestamp = $_.TimeCreated
            EventType = "NetworkConnection"
            User = $_.Properties[1].Value
            Details = "$($_.Properties[4].Value) -> $($_.Properties[14].Value):$($_.Properties[16].Value)"
            Severity = "Info"
        }
    }
    
    $timeline | Sort-Object Timestamp | Format-Table -AutoSize
}
```
{% endcode %}

#### Persistence Mechanism Hunter

{% code overflow="wrap" %}
```powershell
# === Comprehensive Persistence Location Scanner ===
function Find-AllPersistence {
    $results = @()
    
    # Registry Run Keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object {
                $_.Name -notmatch "^PS" -and $_.Value
            } | ForEach-Object {
                $results += [PSCustomObject]@{
                    Type = "RegistryRun"
                    Location = $key
                    Name = $_.Name
                    Value = $_.Value
                    Suspicious = ($_.Value -match "powershell|cmd|wscript|temp|appdata")
                }
            }
        }
    }
    
    # Startup Folders
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:USERPROFILE\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | ForEach-Object {
                $results += [PSCustomObject]@{
                    Type = "StartupFolder"
                    Location = $folder
                    Name = $_.Name
                    Value = $_.FullName
                    Suspicious = ($_.Extension -in @('.bat','.cmd','.vbs','.ps1','.lnk'))
                }
            }
        }
    }
    
    # Scheduled Tasks
    Get-ScheduledTask | Where-Object {
        $_.State -ne "Disabled" -and
        $_.TaskPath -notlike "\Microsoft\*"
    } | ForEach-Object {
        $action = $_.Actions.Execute
        $results += [PSCustomObject]@{
            Type = "ScheduledTask"
            Location = $_.TaskPath
            Name = $_.TaskName
            Value = "$action $($_.Actions.Arguments)"
            Suspicious = ($action -match "powershell|cmd|wscript|cscript|mshta")
        }
    }
    
    # Services
    Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -notmatch "C:\\Windows\\" -and
        $_.PathName -notmatch "C:\\Program Files"
    } | ForEach-Object {
        $results += [PSCustomObject]@{
            Type = "Service"
            Location = "Services"
            Name = $_.Name
            Value = $_.PathName
            Suspicious = $true
        }
    }
    
    # WMI Event Subscriptions
    Get-CimInstance -Namespace root/subscription -Class __EventFilter -ErrorAction SilentlyContinue |
        ForEach-Object {
            $results += [PSCustomObject]@{
                Type = "WMIEventFilter"
                Location = "WMI Subscription"
                Name = $_.Name
                Value = $_.Query
                Suspicious = ($_.Query -match "powershell|cmd")
            }
        }
    
    Get-CimInstance -Namespace root/subscription -Class __EventConsumer -ErrorAction SilentlyContinue |
        ForEach-Object {
            $results += [PSCustomObject]@{
                Type = "WMIEventConsumer"
                Location = "WMI Subscription"
                Name = $_.Name
                Value = if ($_.CommandLineTemplate) {$_.CommandLineTemplate} else {$_.ScriptText}
                Suspicious = $true
            }
        }
    
    # Browser extensions (common persistence)
    $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtPath) {
        Get-ChildItem -Path $chromeExtPath -Directory | ForEach-Object {
            $results += [PSCustomObject]@{
                Type = "BrowserExtension"
                Location = "Chrome"
                Name = $_.Name
                Value = $_.FullName
                Suspicious = $false  # Requires manual review
            }
        }
    }
    
    return $results
}

Find-AllPersistence | Where-Object {$_.Suspicious -eq $true} | Format-Table -AutoSize
```
{% endcode %}

#### Malware Analysis & Deobfuscation

{% code overflow="wrap" %}
```powershell
# === PowerShell Deobfuscation Toolkit ===
function Deobfuscate-PowerShell {
    param([string]$ObfuscatedScript)
    
    # Step 1: Decode Base64 if present
    if ($ObfuscatedScript -match "frombase64string\('([^']+)'\)" -or
        $ObfuscatedScript -match 'frombase64string\("([^"]+)"\)') {
        
        $base64 = $matches[1]
        $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
        Write-Host "`n=== Base64 Decoded ===" -ForegroundColor Cyan
        Write-Host $decoded
        $ObfuscatedScript = $decoded
    }
    
    # Step 2: Decompress GZIP if present
    if ($ObfuscatedScript -match "IO\.Compression\.GzipStream") {
        Write-Host "`n=== GZIP Compression Detected ===" -ForegroundColor Yellow
    }
    
    # Step 3: Replace common obfuscation patterns
    $patterns = @{
        '\$\{([^\}]+)\}' = '$($1)'  # ${var} to $(var)
        '"\+"' = ''  # Remove string concatenation
        "'\+'" = ''
        '\[char\](\d+)' = {[char][int]$args[0]}  # [char]65 to 'A'
    }
    
    foreach ($pattern in $patterns.Keys) {
        if ($ObfuscatedScript -match $pattern) {
            Write-Host "`nFound obfuscation pattern: $pattern" -ForegroundColor Yellow
        }
    }
    
    # Step 4: Identify suspicious cmdlets
    $dangerousCmdlets = @(
        "Invoke-Expression", "IEX", "Invoke-Command", "ICM",
        "Invoke-WebRequest", "IWR", "Invoke-RestMethod", "IRM",
        "Start-Process", "Start-Job", "New-Object Net.WebClient",
        "DownloadString", "DownloadFile", "DownloadData",
        "Reflection.Assembly", "Load", "System.Reflection",
        "Runtime.InteropServices", "VirtualAlloc", "CreateThread"
    )
    
    Write-Host "`n=== Dangerous Cmdlets Found ===" -ForegroundColor Red
    foreach ($cmdlet in $dangerousCmdlets) {
        if ($ObfuscatedScript -match [regex]::Escape($cmdlet)) {
            Write-Host "- $cmdlet" -ForegroundColor Red
        }
    }
    
    # Step 5: Extract URLs/IPs
    $urlPattern = 'https?://[^\s"\)'']+|(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    $urls = [regex]::Matches($ObfuscatedScript, $urlPattern) | 
        Select-Object -ExpandProperty Value -Unique
    
    if ($urls) {
        Write-Host "`n=== URLs/IPs Extracted ===" -ForegroundColor Cyan
        $urls | ForEach-Object {Write-Host $_ -ForegroundColor Green}
    }
    
    return $ObfuscatedScript
}

# === Extract IOCs from Scripts ===
function Extract-IOCs {
    param([string]$ScriptContent)
    
    $iocs = @{
        URLs = @()
        IPs = @()
        FileHashes = @()
        Domains = @()
        FilePaths = @()
    }
    
    # URLs
    $iocs.URLs = [regex]::Matches($ScriptContent, 'https?://[^\s"\)'']+') | 
        Select-Object -ExpandProperty Value -Unique
    
    # IP Addresses
    $iocs.IPs = [regex]::Matches($ScriptContent, '(?:[0-9]{1,3}\.){3}[0-9]{1,3}') | 
        Select-Object -ExpandProperty Value -Unique |
        Where-Object {$_ -notmatch '^(127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)'}
    
    # File hashes (MD5, SHA1, SHA256)
    $iocs.FileHashes = [regex]::Matches($ScriptContent, '\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b') | 
        Select-Object -ExpandProperty Value -Unique
    
    # File paths
    $iocs.FilePaths = [regex]::Matches($ScriptContent, '[A-Z]:\\(?:[^\s"\''<>|?*]+\\)*[^\s"\''<>|?*]+') | 
        Select-Object -ExpandProperty Value -Unique
    
    return $iocs
}

# === Analyze PowerShell Empire/Covenant Indicators ===
function Find-C2Indicators {
    param([string]$ScriptBlock)
    
    $indicators = @()
    
    # Empire indicators
    if ($ScriptBlock -match "defaultresponse|\/admin\/get\.php|SESSIONKEY|Empire") {
        $indicators += "PowerShell Empire"
    }
    
    # Covenant indicators
    if ($ScriptBlock -match "Covenant|GruntHTTP|/Grunt|elite") {
        $indicators += "Covenant C2"
    }
    
    # Cobalt Strike indicators
    if ($ScriptBlock -match "beacon|spawnas|powerpick|execute-assembly") {
        $indicators += "Cobalt Strike"
    }
    
    # Metasploit indicators
    if ($ScriptContent -match "meterpreter|ReflectivePEInjection|Invoke-Shellcode") {
        $indicators += "Metasploit"
    }
    
    # Generic C2 patterns
    if ($ScriptBlock -match "sleep.*rand|Start-Sleep.*Get-Random") {
        $indicators += "Jitter/Sleep Pattern (C2 Beacon)"
    }
    
    if ($ScriptBlock -match "while.*true.*try.*catch") {
        $indicators += "Infinite Loop with Error Handling (C2 Loop)"
    }
    
    return $indicators
}
```
{% endcode %}

#### Fleet-Scale Operations

{% code overflow="wrap" %}
```powershell
# === Parallel Threat Hunting Across Multiple Endpoints ===
function Invoke-FleetHunt {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerNames,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$HuntScript,
        
        [int]$ThrottleLimit = 10,
        
        [PSCredential]$Credential
    )
    
    $results = $ComputerNames | ForEach-Object -Parallel {
        $computer = $_
        $script = $using:HuntScript
        $cred = $using:Credential
        
        try {
            $params = @{
                ComputerName = $computer
                ScriptBlock = $script
                ErrorAction = 'Stop'
            }
            
            if ($cred) {
                $params.Credential = $cred
            }
            
            $result = Invoke-Command @params
            
            [PSCustomObject]@{
                Computer = $computer
                Status = "Success"
                Data = $result
                Error = $null
            }
        } catch {
            [PSCustomObject]@{
                Computer = $computer
                Status = "Failed"
                Data = $null
                Error = $_.Exception.Message
            }
        }
    } -ThrottleLimit $ThrottleLimit
    
    return $results
}

# Example: Hunt for Mimikatz across 100 endpoints
$endpoints = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name -First 100

$mimikatzHunt = {
    # Look for LSASS access in last hour
    Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ID=10
        StartTime=(Get-Date).AddHours(-1)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[4].Value -like "*lsass.exe*" -and
        $_.Properties[6].Value -eq "0x1010"
    }
}

$results = Invoke-FleetHunt -ComputerNames $endpoints -HuntScript $mimikatzHunt

# === Background Job Management for Long-Running Hunts ===
function Start-AsyncHunt {
    param(
        [scriptblock]$HuntScript,
        [string]$JobName = "ThreatHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    $job = Start-Job -Name $JobName -ScriptBlock $HuntScript
    
    Write-Host "Hunt job started: $JobName (ID: $($job.Id))" -ForegroundColor Green
    Write-Host "Monitor with: Get-Job -Id $($job.Id) | Receive-Job -Keep"
    
    return $job
}

# === Query EDR via API (Example: CrowdStrike) ===
function Search-CrowdStrikeHosts {
    param(
        [string]$Filter,
        [string]$APIKey,
        [int]$Limit = 100
    )
    
    $headers = @{
        "Authorization" = "Bearer $APIKey"
        "Content-Type" = "application/json"
    }
    
    $body = @{
        filter = $Filter
        limit = $Limit
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "https://api.crowdstrike.com/devices/queries/devices/v1" `
        -Method Post -Headers $headers -Body $body
    
    return $response
}
```
{% endcode %}

#### SIEM Integration & Alert Enrichment

{% code overflow="wrap" %}
```powershell
# === Splunk Query Automation ===
function Invoke-SplunkSearch {
    param(
        [string]$Query,
        [string]$SplunkServer,
        [PSCredential]$Credential,
        [string]$EarliestTime = "-1h"
    )
    
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
        "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    ))
    
    $headers = @{
        "Authorization" = "Basic $base64Auth"
    }
    
    $searchParams = @{
        search = "search $Query"
        earliest_time = $EarliestTime
        output_mode = "json"
    }
    
    $response = Invoke-RestMethod -Uri "https://$SplunkServer:8089/services/search/jobs/export" `
        -Method Post -Headers $headers -Body $searchParams
    
    return $response
}

# === Elastic/OpenSearch Query ===
function Search-ElasticSIEM {
    param(
        [string]$IndexPattern = "winlogbeat-*",
        [hashtable]$Query,
        [string]$ElasticURL,
        [PSCredential]$Credential
    )
    
    $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
        "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    ))
    
    $headers = @{
        "Authorization" = "Basic $base64Auth"
        "Content-Type" = "application/json"
    }
    
    $body = @{
        query = $Query
        size = 1000
    } | ConvertTo-Json -Depth 10
    
    $response = Invoke-RestMethod -Uri "$ElasticURL/$IndexPattern/_search" `
        -Method Post -Headers $headers -Body $body
    
    return $response.hits.hits
}

# === Automated Alert Enrichment ===
function Enrich-Alert {
    param(
        [string]$TargetHost,
        [string]$TargetUser,
        [string]$SourceIP
    )
    
    $enrichment = @{}
    
    # Get host information
    if ($TargetHost) {
        try {
            $comp = Get-ADComputer -Identity $TargetHost -Properties LastLogonDate, OperatingSystem
            $enrichment.HostLastLogon = $comp.LastLogonDate
            $enrichment.HostOS = $comp.OperatingSystem
        } catch {
            $enrichment.HostError = $_.Exception.Message
        }
    }
    
    # Get user information
    if ($TargetUser) {
        try {
            $user = Get-ADUser -Identity $TargetUser -Properties Department, Title, Manager
            $enrichment.UserDepartment = $user.Department
            $enrichment.UserTitle = $user.Title
            $enrichment.UserManager = $user.Manager
        } catch {
            $enrichment.UserError = $_.Exception.Message
        }
    }
    
    # IP geolocation and threat intel (example with AbuseIPDB)
    if ($SourceIP) {
        # Implement your threat intel lookup here
        $enrichment.SourceIP = $SourceIP
        $enrichment.ThreatIntel = "Check VirusTotal/AbuseIPDB/AlienVault OTX"
    }
    
    return $enrichment
}
```
{% endcode %}

#### Performance & Production Tips

```powershell
# === Optimize Large Dataset Processing ===
# BAD: Slow for large datasets
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4688}

# GOOD: Filter at source
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688}

# === Measure Script Performance ===
$elapsed = Measure-Command {
    # Your hunting script here
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 10000
}
Write-Host "Execution time: $($elapsed.TotalSeconds) seconds"

# === Error Handling for Production ===
function Get-SafeWinEvent {
    param($FilterHashtable)
    
    try {
        Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Stop
    } catch [System.Exception] {
        Write-Warning "Failed to query event log: $($_.Exception.Message)"
        return $null
    }
}

# === Logging Your Detections ===
function Write-DetectionLog {
    param(
        [string]$Finding,
        [string]$Severity,
        [string]$LogPath = "C:\SOC\detection_log.json"
    )
    
    $entry = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Finding = $Finding
        Severity = $Severity
        Analyst = $env:USERNAME
        Host = $env:COMPUTERNAME
    } | ConvertTo-Json
    
    Add-Content -Path $LogPath -Value $entry
}
```

***

### 📚 Advanced Resources

**Must-Read Documentation**

* MITRE ATT\&CK: https://attack.mitre.org
* Sigma Rules Repository: https://github.com/SigmaHQ/sigma
* Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
* JPCERT Tool Analysis: https://jpcertcc.github.io/ToolAnalysisResultSheet

**PowerShell Security Tools**

* PowerShell Empire: Study attack techniques
* Invoke-Obfuscation: Learn obfuscation patterns
* PSReflect: Understanding reflection-based attacks
* PowerSploit: Offensive PowerShell (for detection building)

**Practice Environments**

* Detection Lab: https://github.com/clong/DetectionLab
* GOAD (Game of Active Directory): https://github.com/Orange-Cyberdefense/GOAD
* Atomic Red Team: https://github.com/redcanaryco/atomic-red-team

***

***

### ⚡ Daily Habits for Mastery

1. **Read one APT report per week** - Extract TTPs and build detections
2. **Analyse real malware samples** - Understand attacker techniques
3. **Automate repetitive tasks** - Every manual step is a candidate for scripting
4. **Share detections with team** - Build your SOC's detection library
5. **Measure everything** - Track detection efficacy and false positive rates
6. **Stay current** - Follow @DanielBohannon, @HarmJ0y, @mattifestation on Twitter/X
7. **Contribute to community** - Publish Sigma rules, share detections

***

### 🛡️ Production Deployment Checklist

Before deploying scripts to production:

* \[ ] Comprehensive error handling implemented
* \[ ] Performance tested with large datasets
* \[ ] Logging and audit trail configured
* \[ ] Peer review completed
* \[ ] False positive rate measured and acceptable
* \[ ] Documentation written
* \[ ] Runbook created for SOC team
* \[ ] Integrated with ticketing/SOAR
* \[ ] Metrics and dashboards created
* \[ ] Incident response procedures updated

***

**Remember**: As a Senior SOC Analyst, you're not just detecting threats—you're building the detection infrastructure. Your PowerShell skills multiply your entire team's effectiveness.&#x20;

Focus on automation, scalability, and sharing knowledge.

**Hunt hard. Automate ruthlessly. Defend proactively.** 🛡️
