# Network Activity Forensics - SOC Analyst Cheatsheet

### Practical Guide for Network Connection & Usage Investigation

***

### Quick Reference: Network Artifacts Matrix

| Artifact              | What Reveals       | Time Range       | Key Data                     | Live/Dead | Volatility |
| --------------------- | ------------------ | ---------------- | ---------------------------- | --------- | ---------- |
| **Network List**      | Networks connected | Historical       | SSIDs, first/last connect    | Both      | Low        |
| **TCP/IP Interfaces** | IP addresses       | Current + recent | IPs, gateways, DNS           | Both      | Medium     |
| **SRUM**              | Data usage, apps   | 30-60 days       | Bytes sent/received, per-app | Both      | Low        |

***

### Investigation Priority Matrix

| Priority     | Artifact          | Best For                     | OS Support  | Key Value                   |
| ------------ | ----------------- | ---------------------------- | ----------- | --------------------------- |
| **CRITICAL** | SRUM              | Data exfiltration, app usage | Win8+       | Bytes sent/received per app |
| **HIGH**     | Network List      | Wi-Fi history, VPN           | All Windows | Connection timeline         |
| **MEDIUM**   | TCP/IP Interfaces | Current/recent IPs           | All Windows | Active network config       |

***

### Core Investigation Questions

#### Primary Questions:

1. **What networks has the device connected to?** (Wi-Fi, VPN history)
2. **What is the current/last IP address?** (Network configuration)
3. **Which applications used the network heavily?** (Data exfiltration)

#### Secondary Questions:

4. **When were networks first/last used?** (Timeline)
5. **How much data was sent/received?** (Volume analysis)
6. **Were VPN connections used?** (Anonymisation attempts)

***

### SOC Investigation Workflows

#### Workflow 1: Data Exfiltration Investigation (CRITICAL)

**Scenario:** Suspected data theft via network transfer

**Investigation Priority Order:**

**Step 1: Analyse SRUM (Network Data Usage) - CRITICAL** **Why first:** Shows bytes sent/received per application (smoking gun for data exfil)

**Location:**

```bash
C:\Windows\System32\SRU\SRUDB.dat
```

**Required Companion File:**

```bash
C:\Windows\System32\config\SOFTWARE (for application name resolution)
```

**Collection Commands:**

**PowerShell - Copy SRUM and SOFTWARE:**

{% code overflow="wrap" %}
```powershell
# Create output directory
$output = "C:\Cases\NetworkAnalysis"
New-Item -ItemType Directory -Path $output -Force | Out-Null

Write-Host "[+] Collecting SRUM Database..." -ForegroundColor Cyan

# Copy SRUM database
Copy-Item "C:\Windows\System32\SRU\SRUDB.dat" "$output\" -Force
Copy-Item "C:\Windows\System32\SRU\*.log" "$output\" -Force -ErrorAction SilentlyContinue

Write-Host "[+] Collecting SOFTWARE Hive..." -ForegroundColor Cyan

# Copy SOFTWARE hive (needed for app name resolution)
Copy-Item "C:\Windows\System32\config\SOFTWARE" "$output\" -Force
Copy-Item "C:\Windows\System32\config\SOFTWARE.LOG*" "$output\" -Force

Write-Host "[+] Collection Complete!" -ForegroundColor Green
Write-Host "[*] Output: $output" -ForegroundColor Yellow
Write-Host "[!] Parse with: SrumECmd.exe -d '$output' --csv '$output\Parsed'" -ForegroundColor Cyan
```
{% endcode %}

**Using SrumECmd (Zimmerman Tool) - REQUIRED:**

```bash
REM Parse SRUM with SOFTWARE hive
SrumECmd.exe -d "C:\Cases\NetworkAnalysis" --csv "C:\Cases\NetworkAnalysis\Parsed"

REM This creates multiple CSV files:
REM - *_NetworkData_NetworkUsage.csv (bytes sent/received per app)
REM - *_AppResourceUseInfo_AppResourceUseInfo.csv (app resource usage)
REM - *_NetworkConnectivityUsage_NetworkConnections.csv (connection history)
```

**Critical SRUM Tables:**

**1. Network Data Usage Table**

```bash
GUID: {973F5D5C-1D90-4944-BE8E-24B94231A174}
Output CSV: *_NetworkData_NetworkUsage.csv

Key Columns:
- App: Application name/path
- UserId: User SID
- BytesSent: Total bytes uploaded
- BytesRecvd: Total bytes downloaded
- Timestamp: When recorded (hourly intervals)
- InterfaceLuid: Network interface identifier
```

**2. Application Resource Usage Table**

```bash
GUID: {d10ca2fe-6fcf-4f6d-848e-b2e99266fa89}
Output CSV: *_AppResourceUseInfo_AppResourceUseInfo.csv

Key Columns:
- AppId: Application identifier
- UserId: User SID
- ForegroundCycleTime: CPU time in foreground
- BackgroundCycleTime: CPU time in background
- Timestamp: Recording time
```

**3. Network Connectivity Usage Table**

```bash
GUID: {DD6636C4-8929-4683-974E-22C046A43763}
Output CSV: *_NetworkConnectivityUsage_NetworkConnections.csv

Key Columns:
- AppId: Application identifier
- UserId: User SID
- InterfaceLuid: Network interface
- ConnectedTime: Duration connected
- Timestamp: Recording time
```

**Analysis - Data Exfiltration Detection:**

**PowerShell - Analyze SRUM CSV (After Parsing):**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Analyze SRUM network usage for data exfiltration
.DESCRIPTION
    Identifies applications with high data upload ratios
#>

param(
    [string]$SrumCsvPath = "C:\Cases\NetworkAnalysis\Parsed",
    [int]$TopN = 20,
    [double]$SuspiciousRatio = 0.1  # 10% upload ratio or higher
)

Write-Host "`n[+] Analyzing SRUM Network Usage..." -ForegroundColor Cyan

# Find the NetworkUsage CSV file
$networkCsv = Get-ChildItem $SrumCsvPath -Filter "*NetworkUsage.csv" | Select-Object -First 1

if (-not $networkCsv) {
    Write-Host "[!] NetworkUsage CSV not found!" -ForegroundColor Red
    exit
}

Write-Host "[*] Loading: $($networkCsv.Name)" -ForegroundColor Yellow

# Import and analyze
$data = Import-Csv $networkCsv.FullName

# Calculate upload ratios
$analysis = $data | Group-Object App | ForEach-Object {
    $app = $_.Name
    $totalSent = ($_.Group | Measure-Object -Property BytesSent -Sum).Sum
    $totalRecv = ($_.Group | Measure-Object -Property BytesRecvd -Sum).Sum
    $totalBytes = $totalSent + $totalRecv
    
    if ($totalBytes -gt 0) {
        $uploadRatio = $totalSent / $totalBytes
    } else {
        $uploadRatio = 0
    }
    
    [PSCustomObject]@{
        Application = $app
        BytesSent = $totalSent
        BytesReceived = $totalRecv
        TotalBytes = $totalBytes
        UploadRatio = [math]::Round($uploadRatio, 3)
        SentMB = [math]::Round($totalSent / 1MB, 2)
        RecvMB = [math]::Round($totalRecv / 1MB, 2)
        TotalMB = [math]::Round($totalBytes / 1MB, 2)
    }
} | Sort-Object BytesSent -Descending

# Display top network users
Write-Host "`n[*] Top $TopN Applications by Data Sent:" -ForegroundColor Yellow
Write-Host ("=" * 120)
$analysis | Select-Object -First $TopN | Format-Table -AutoSize

# Identify suspicious upload ratios
Write-Host "`n[!] SUSPICIOUS: High Upload Ratio Applications (>$($SuspiciousRatio * 100)%):" -ForegroundColor Red
Write-Host ("=" * 120)
$suspicious = $analysis | Where-Object {
    $_.UploadRatio -gt $SuspiciousRatio -and $_.TotalMB -gt 10
}

if ($suspicious) {
    $suspicious | Format-Table -AutoSize
    Write-Host "`n[!] Found $($suspicious.Count) applications with suspicious upload patterns!" -ForegroundColor Red
} else {
    Write-Host "No suspicious patterns detected." -ForegroundColor Green
}

# Look for unusual applications
Write-Host "`n[!] Checking for Unusual Application Paths..." -ForegroundColor Yellow
$unusualPaths = $analysis | Where-Object {
    $_.Application -like "*\Temp\*" -or 
    $_.Application -like "*\AppData\Local\Temp\*" -or
    $_.Application -like "*\Users\Public\*" -or
    $_.Application -like "*\Downloads\*" -or
    $_.Application -match "^[A-Z]:\\\w{1,8}\.exe"  # Short random names
}

if ($unusualPaths) {
    Write-Host ("[!] Found applications in suspicious paths:") -ForegroundColor Red
    $unusualPaths | Select-Object Application, SentMB, RecvMB | Format-Table -AutoSize
} else {
    Write-Host "No unusual application paths detected." -ForegroundColor Green
}

Write-Host "`n[+] Analysis Complete!" -ForegroundColor Green
```
{% endcode %}

**Red Flags in SRUM:**

**High Data Upload Indicators:**

* ✗ **High upload ratio** (sent >> received) → Data exfiltration
* ✗ **Unusual applications** with high network usage
* ✗ **Applications from temp directories** using network
* ✗ **Non-browser apps** with massive uploads
* ✗ **Compression tools** (7z, WinRAR) with network usage
* ✗ **Unknown executables** with high bandwidth

**Typical Patterns:**

**Normal (High Download, Low Upload):**

```bash
Chrome.exe:     Sent: 100 MB, Received: 5 GB (Download ratio: 98%)
Firefox.exe:    Sent: 50 MB,  Received: 2 GB (Download ratio: 97.5%)
OneDrive.exe:   Sent: 200 MB, Received: 1 GB (Upload ratio: 16.6% - normal sync)
```

**Suspicious (High Upload):**

```bash
unknown.exe:    Sent: 5 GB,   Received: 100 KB (Upload ratio: 99.9%) ← EXFILTRATION!
rclone.exe:     Sent: 10 GB,  Received: 1 MB   (Upload ratio: 99.9%) ← EXFILTRATION!
C:\Temp\x.exe:  Sent: 2 GB,   Received: 10 KB  (Upload ratio: 99.9%) ← EXFILTRATION!
```

**Data Exfiltration Tools in SRUM:**

```bash
Common tools that appear with high upload:
- rclone.exe (cloud sync tool)
- curl.exe / wget.exe (file transfer)
- ftp.exe (FTP client)
- pscp.exe / WinSCP (SCP/SFTP)
- mega-cmd.exe (MEGA cloud client)
- Python.exe / PowerShell with network libs
```

***

**Step 2: Check Network Connection History** **Why second:** Identifies what networks were used (including VPN)

**Registry Location:**

```bash
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
```

**PowerShell - Parse Network List:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Parse network connection history
#>

Write-Host "`n[+] Parsing Network Connection History..." -ForegroundColor Cyan

# Managed Networks (Domain/Corporate)
$managedPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed"
if (Test-Path $managedPath) {
    Write-Host "`n[*] Managed Networks (Corporate/Domain):" -ForegroundColor Yellow
    Write-Host ("=" * 80)
    
    Get-ChildItem $managedPath | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        
        $ssid = if ($props.Description) { 
            $props.Description 
        } elseif ($props.ProfileName) {
            $props.ProfileName
        } else {
            $_.PSChildName
        }
        
        $firstConnect = if ($props.FirstNetwork) {
            [DateTime]::FromFileTime($props.FirstNetwork)
        } else {
            "Unknown"
        }
        
        $lastConnect = if ($props.LastConnected) {
            [DateTime]::FromFileTime($props.LastConnected)
        } else {
            "Unknown"
        }
        
        [PSCustomObject]@{
            Network = $ssid
            FirstConnected = $firstConnect
            LastConnected = $lastConnect
            DomainName = $props.DomainName
            NetworkType = "Managed"
        }
    } | Format-Table -AutoSize
}

# Unmanaged Networks (Home/Public Wi-Fi)
$unmanagedPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
if (Test-Path $unmanagedPath) {
    Write-Host "`n[*] Unmanaged Networks (Public/Home Wi-Fi):" -ForegroundColor Yellow
    Write-Host ("=" * 80)
    
    Get-ChildItem $unmanagedPath | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        
        $ssid = if ($props.Description) {
            $props.Description
        } elseif ($props.ProfileName) {
            $props.ProfileName
        } else {
            "Unknown - " + $_.PSChildName
        }
        
        $firstConnect = if ($props.FirstNetwork) {
            [DateTime]::FromFileTime($props.FirstNetwork)
        } else {
            "Unknown"
        }
        
        $lastConnect = if ($props.LastConnected) {
            [DateTime]::FromFileTime($props.LastConnected)
        } else {
            "Unknown"
        }
        
        [PSCustomObject]@{
            Network = $ssid
            FirstConnected = $firstConnect
            LastConnected = $lastConnect
            NetworkType = "Unmanaged"
        }
    } | Format-Table -AutoSize
}
```
{% endcode %}

**Network List Forensic Value:**

* Network names (SSIDs)
* First connection timestamp
* Last connection timestamp
* Managed vs. Unmanaged (corporate vs. public)
* VPN connections appear as network entries

**Red Flags in Network List:**

* ✗ **VPN connections** during incident timeframe
* ✗ **Public/unknown Wi-Fi** on corporate device
* ✗ **Personal hotspot** connections
* ✗ **Connection timing** correlates with exfiltration
* ✗ **New networks** appearing during investigation period

***

**Step 3: Identify Current/Recent IP Configuration** **Why third:** Shows IP addresses used

**Registry Location:**

```bash
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}
```

**PowerShell - Enumerate Network Interfaces:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Enumerate TCP/IP interface configuration
#>

Write-Host "`n[+] Enumerating Network Interfaces..." -ForegroundColor Cyan

$interfacePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

Get-ChildItem $interfacePath | ForEach-Object {
    $guid = $_.PSChildName
    $props = Get-ItemProperty $_.PSPath
    
    # Skip empty/disabled interfaces
    if ($props.IPAddress -or $props.DhcpIPAddress) {
        Write-Host "`n--- Interface: $guid ---" -ForegroundColor Yellow
        
        [PSCustomObject]@{
            "Interface GUID" = $guid
            "DHCP Enabled" = $props.EnableDHCP
            "IP Address" = if ($props.DhcpIPAddress) { $props.DhcpIPAddress } else { $props.IPAddress }
            "Subnet Mask" = if ($props.DhcpSubnetMask) { $props.DhcpSubnetMask } else { $props.SubnetMask }
            "Default Gateway" = if ($props.DhcpDefaultGateway) { $props.DhcpDefaultGateway } else { $props.DefaultGateway }
            "DHCP Server" = $props.DhcpServer
            "DNS Servers" = if ($props.NameServer) { $props.NameServer } else { "Default" }
            "Domain" = $props.Domain
        } | Format-List
    }
}

# Also check current active configuration (live data)
Write-Host "`n[*] Current Active Network Configuration:" -ForegroundColor Cyan
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.IPAddress -ne "127.0.0.1"} | 
    Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize

Write-Host "`n[*] Current Routes:" -ForegroundColor Cyan
Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -ne "127.0.0.0/8"} |
    Select-Object DestinationPrefix, NextHop, InterfaceAlias | Format-Table -AutoSize
```
{% endcode %}

**TCP/IP Forensic Value:**

* Current and historical IP addresses
* DHCP vs. static configuration
* Default gateway (router)
* DNS server configuration
* DHCP server addresses

**Red Flags in Network Config:**

* ✗ **Unusual DNS servers** (attacker DNS, privacy DNS)
* ✗ **Suspicious gateways** (man-in-the-middle)
* ✗ **IP changes** during incident window
* ✗ **VPN interface** IP addresses

***

#### PowerShell Script: Complete Network Activity Investigation

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Comprehensive network activity investigation
.DESCRIPTION
    Collects SRUM, network list, TCP/IP config for analysis
.PARAMETER OutputPath
    Output directory for collected artifacts
#>

param(
    [string]$OutputPath = "C:\Cases\NetworkInvestigation"
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        NETWORK ACTIVITY INVESTIGATION                     ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

# Check OS version for SRUM availability
$osVersion = [Environment]::OSVersion.Version
if ($osVersion.Major -lt 6 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -lt 2)) {
    Write-Host "[!] WARNING: SRUM not available (requires Windows 8+)" -ForegroundColor Red
    Write-Host "[!] Current OS: $($osVersion.ToString())" -ForegroundColor Red
    $hasSRUM = $false
} else {
    $hasSRUM = $true
}

# ============================================================================
# 1. COLLECT SRUM DATABASE
# ============================================================================
if ($hasSRUM) {
    Write-Host "[1/5] Collecting SRUM Database..." -ForegroundColor Yellow
    
    try {
        Copy-Item "C:\Windows\System32\SRU\SRUDB.dat" "$OutputPath\" -Force
        Copy-Item "C:\Windows\System32\SRU\*.log" "$OutputPath\" -Force -ErrorAction SilentlyContinue
        Write-Host "  [✓] SRUM database collected" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed to copy SRUM: $_" -ForegroundColor Red
    }
    
    # Collect SOFTWARE hive (required for app name resolution)
    try {
        Copy-Item "C:\Windows\System32\config\SOFTWARE" "$OutputPath\" -Force
        Copy-Item "C:\Windows\System32\config\SOFTWARE.LOG*" "$OutputPath\" -Force -ErrorAction SilentlyContinue
        Write-Host "  [✓] SOFTWARE hive collected" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed to copy SOFTWARE hive: $_" -ForegroundColor Red
    }
} else {
    Write-Host "[1/5] Skipping SRUM (not available)" -ForegroundColor Gray
}

# ============================================================================
# 2. EXPORT NETWORK LIST REGISTRY
# ============================================================================
Write-Host "[2/5] Exporting Network List Registry..." -ForegroundColor Yellow
$networkListOutput = "$OutputPath\NetworkList_Export.txt"

"=" * 80 | Out-File $networkListOutput
"NETWORK LIST REGISTRY - $(Get-Date)" | Out-File $networkListOutput -Append
"=" * 80 | Out-File $networkListOutput -Append

# Managed Networks
$managedPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed"
if (Test-Path $managedPath) {
    "`n--- MANAGED NETWORKS ---" | Out-File $networkListOutput -Append
    Get-ChildItem $managedPath | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        "`nGUID: $($_.PSChildName)" | Out-File $networkListOutput -Append
        "Description: $($props.Description)" | Out-File $networkListOutput -Append
        "FirstNetwork: $($props.FirstNetwork)" | Out-File $networkListOutput -Append
        "LastConnected: $($props.LastConnected)" | Out-File $networkListOutput -Append
        "DomainName: $($props.DomainName)" | Out-File $networkListOutput -Append
    }
}

# Unmanaged Networks
$unmanagedPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
if (Test-Path $unmanagedPath) {
    "`n--- UNMANAGED NETWORKS ---" | Out-File $networkListOutput -Append
    Get-ChildItem $unmanagedPath | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        "`nGUID: $($_.PSChildName)" | Out-File $networkListOutput -Append
        "Description: $($props.Description)" | Out-File $networkListOutput -Append
        "FirstNetwork: $($props.FirstNetwork)" | Out-File $networkListOutput -Append
        "LastConnected: $($props.LastConnected)" | Out-File $networkListOutput -Append
    }
}

Write-Host "  [✓] Network list exported" -ForegroundColor Green

# ============================================================================
# 3. EXPORT TCP/IP CONFIGURATION
# ============================================================================
Write-Host "[3/5] Exporting TCP/IP Configuration..." -ForegroundColor Yellow
$tcpipOutput = "$OutputPath\TCPIP_Configuration.txt"

"=" * 80 | Out-File $tcpipOutput
"TCP/IP INTERFACE CONFIGURATION - $(Get-Date)" | Out-File $tcpipOutput -Append
"=" * 80 | Out-File $tcpipOutput -Append

$interfacePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
Get-ChildItem $interfacePath | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    
    "`n--- Interface: $($_.PSChildName) ---" | Out-File $tcpipOutput -Append
    "DHCP Enabled: $($props.EnableDHCP)" | Out-File $tcpipOutput -Append
    "IP Address: $(if ($props.DhcpIPAddress) { $props.DhcpIPAddress } else { $props.IPAddress })" | Out-File $tcpipOutput -Append
    "Subnet Mask: $(if ($props.DhcpSubnetMask) { $props.DhcpSubnetMask } else { $props.SubnetMask })" | Out-File $tcpipOutput -Append
    "Gateway: $(if ($props.DhcpDefaultGateway) { $props.DhcpDefaultGateway } else { $props.DefaultGateway })" | Out-File $tcpipOutput -Append
    "DHCP Server: $($props.DhcpServer)" | Out-File $tcpipOutput -Append
    "DNS: $($props.NameServer)" | Out-File $tcpipOutput -Append
}

# Current live configuration
"`n`n--- CURRENT ACTIVE CONFIGURATION ---" | Out-File $tcpipOutput -Append
Get-NetIPAddress -ErrorAction SilentlyContinue | 
    Where-Object {$_.AddressFamily -eq "IPv4"} | 
    Out-File $tcpipOutput -Append

Write-Host "  [✓] TCP/IP configuration exported" -ForegroundColor Green

# ============================================================================
# 4. COLLECT CURRENT NETWORK STATE
# ============================================================================
Write-Host "[4/5] Collecting Current Network State..." -ForegroundColor Yellow
$currentStateOutput = "$OutputPath\Current_Network_State.txt"

@"
================================================================================
CURRENT NETWORK STATE - $(Get-Date)
================================================================================

--- ACTIVE IP ADDRESSES ---
"@ | Out-File $currentStateOutput

ipconfig /all | Out-File $currentStateOutput -Append

"`n--- ROUTING TABLE ---" | Out-File $currentStateOutput -Append
route print | Out-File $currentStateOutput -Append

"`n--- ARP CACHE ---" | Out-File $currentStateOutput -Append
arp -a | Out-File $currentStateOutput -Append

"`n--- ACTIVE CONNECTIONS ---" | Out-File $currentStateOutput -Append
netstat -ano | Out-File $currentStateOutput -Append

Write-Host "  [✓] Current network state collected" -ForegroundColor Green

# ============================================================================
# 5. GENERATE SUMMARY
# ============================================================================
Write-Host "[5/5] Generating Summary..." -ForegroundColor Yellow
$summaryOutput = "$OutputPath\00_INVESTIGATION_SUMMARY.txt"

@"
╔════════════════════════════════════════════════════════════════════════════╗
║                NETWORK ACTIVITY INVESTIGATION SUMMARY                      ║
╚════════════════════════════════════════════════════════════════════════════╝

Investigation Date: $(Get-Date)
Computer: $env:COMPUTERNAME
OS Version: $($osVersion.ToString())
Analyst: $env:USERNAME

ARTIFACTS COLLECTED:
────────────────────────────────────────────────────────────────────────────
$(if ($hasSRUM) { "[✓]" } else { "[✗]" }) SRUM Database (SRUDB.dat)
$(if ($hasSRUM) { "[✓]" } else { "[✗]" }) SOFTWARE Hive (for app name resolution)
[✓] Network List Registry
[✓] TCP/IP Configuration
[✓] Current Network State (ipconfig, netstat, arp)

OUTPUT FILES:
────────────────────────────────────────────────────────────────────────────
$(if ($hasSRUM) { "SRUDB.dat                     → SRUM database (parse with SrumECmd)" } else { "SRUDB.dat                     → NOT AVAILABLE (Windows 7 or earlier)" })
$(if ($hasSRUM) { "SOFTWARE                      → Registry hive for app resolution" } else { "" })
NetworkList_Export.txt        → Connected networks history
TCPIP_Configuration.txt       → IP address history
Current_Network_State.txt     → Live network snapshot

RECOMMENDED NEXT STEPS:
────────────────────────────────────────────────────────────────────────────
$(if ($hasSRUM) {
@"
1. Parse SRUM with SrumECmd:
   SrumECmd.exe -d "$OutputPath" --csv "$OutputPath\Parsed"

2. Analyze NetworkUsage CSV for data exfiltration:
   - Sort by BytesSent (descending)
   - Look for high upload ratios (sent >> received)
   - Identify unusual applications with network usage
   - Check for apps from temp/appdata directories

3. Examine AppResourceUseInfo for execution context

4. Review NetworkConnections for connection duration
"@
} else {
@"
1. SRUM not available on this OS version (requires Windows 8+)
   
2. Focus on:
   - Network List for Wi-Fi/VPN history
   - TCP/IP config for IP addresses
   - Current network connections (netstat output)
"@
})

5. Correlate with:
   - Prefetch/BAM for application execution
   - Browser history for web-based transfers
   - LNK files for file access from network shares
   - Event logs (Security, System)

INVESTIGATION FOCUS AREAS:
────────────────────────────────────────────────────────────────────────────
→ High data uploads (potential exfiltration)
→ Unusual applications with network usage
→ VPN/anonymization tool usage
→ Public Wi-Fi connections
→ Timing correlation with incident window

TOOLS REQUIRED:
────────────────────────────────────────────────────────────────────────────
✓ SrumECmd.exe (Eric Zimmerman)
  Download: https://ericzimmerman.github.io/

════════════════════════════════════════════════════════════════════════════
"@ | Out-File $summaryOutput

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║            COLLECTION COMPLETE                             ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host "`nResults: $OutputPath" -ForegroundColor Cyan
Write-Host "Review: 00_INVESTIGATION_SUMMARY.txt`n" -ForegroundColor Yellow

if ($hasSRUM) {
    Write-Host "[!] NEXT: Parse SRUM with SrumECmd" -ForegroundColor Cyan
    Write-Host "    Command: SrumECmd.exe -d '$OutputPath' --csv '$OutputPath\Parsed'`n" -ForegroundColor White
}
```
{% endcode %}

***

### Workflow 2: VPN & Anonymisation Detection

**Scenario:** Detect use of VPN or anonymisation tools

#### Investigation Steps:

**Step 1: Check Network List for VPN Connections**

```
VPN connections appear as network entries:
- OpenVPN
- NordVPN
- ExpressVPN
- ProtonVPN
- Tor
```

**PowerShell - Detect VPN Networks:**

{% code overflow="wrap" %}
```powershell
# Search for VPN-related network names
$vpnKeywords = @("VPN", "OpenVPN", "Nord", "Express", "Proton", "Tor", "Tunnel")

$unmanagedPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"

Get-ChildItem $unmanagedPath | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    $description = $props.Description
    
    foreach ($keyword in $vpnKeywords) {
        if ($description -like "*$keyword*") {
            Write-Host "[!] VPN DETECTED: $description" -ForegroundColor Red
            Write-Host "    First Connected: $(if ($props.FirstNetwork) { [DateTime]::FromFileTime($props.FirstNetwork) } else { 'Unknown' })" -ForegroundColor Yellow
            Write-Host "    Last Connected: $(if ($props.LastConnected) { [DateTime]::FromFileTime($props.LastConnected) } else { 'Unknown' })" -ForegroundColor Yellow
            break
        }
    }
}
```
{% endcode %}

**Step 2: Check SRUM for VPN Application Usage**

```bash
After parsing SRUM, search for:
- openvpn.exe
- nordvpn.exe
- expressvpn.exe
- protonvpn.exe
- tor.exe
```

**Step 3: Correlate VPN Usage with Data Transfer**

```bash
Timeline:
1. VPN connected (Network List)
2. High data upload (SRUM)
3. VPN disconnected

= Data exfiltration via VPN
```

***

### Workflow 3: Baseline vs. Anomaly Detection

**Scenario:** Identify abnormal network usage patterns

#### Analysis Technique:

**Compare Application Network Usage:**

```bash
1. Parse SRUM for entire 30-60 day history
2. Calculate average daily upload per application
3. Identify spikes or anomalies
4. Correlate with incident timeframe
```

**PowerShell - Baseline Analysis:**

```powershell
# After parsing SRUM to CSV
$networkCsv = Import-Csv "C:\Cases\Parsed\NetworkUsage.csv"

# Group by application and date
$dailyUsage = $networkCsv | ForEach-Object {
    $date = ([DateTime]$_.Timestamp).Date
    $app = $_.App
    
    [PSCustomObject]@{
        Date = $date
        App = $app
        BytesSent = [long]$_.BytesSent
        BytesRecvd = [long]$_.BytesRecvd
    }
} | Group-Object Date, App | ForEach-Object {
    [PSCustomObject]@{
        Date = ($_.Group[0].Date)
        App = ($_.Group[0].App)
        TotalSent = ($_.Group | Measure-Object BytesSent -Sum).Sum
        TotalRecvd = ($_.Group | Measure-Object BytesRecvd -Sum).Sum
    }
}

# Calculate baseline (average)
$baseline = $dailyUsage | Group-Object App | ForEach-Object {
    $avgSent = ($_.Group | Measure-Object TotalSent -Average).Average
    $maxSent = ($_.Group | Measure-Object TotalSent -Maximum).Maximum
    
    [PSCustomObject]@{
        App = $_.Name
        AvgDailySent = [math]::Round($avgSent / 1MB, 2)
        MaxDailySent = [math]::Round($maxSent / 1MB, 2)
    }
}

# Identify anomalies (>3x average)
$anomalies = $dailyUsage | ForEach-Object {
    $app = $_.App
    $sent = $_.TotalSent
    
    $base = $baseline | Where-Object {$_.App -eq $app}
    if ($base) {
        $threshold = $base.AvgDailySent * 3 * 1MB
        
        if ($sent -gt $threshold) {
            [PSCustomObject]@{
                Date = $_.Date
                App = $app
                SentMB = [math]::Round($sent / 1MB, 2)
                AvgMB = $base.AvgDailySent
                Ratio = [math]::Round(($sent / 1MB) / $base.AvgDailySent, 1)
            }
        }
    }
}

if ($anomalies) {
    Write-Host "`n[!] ANOMALIES DETECTED (>3x average usage):" -ForegroundColor Red
    $anomalies | Sort-Object Date -Descending | Format-Table -AutoSize
}
```

***

### Detection Patterns & Red Flags

#### Data Exfiltration Indicators

**SRUM Patterns:**

```bash
HIGH UPLOAD RATIO:
✗ Application sent >> received (>50% upload ratio)
✗ Total upload >1 GB from single app
✗ Sustained high upload over multiple hours

SUSPICIOUS APPLICATIONS:
✗ Executables from temp directories
✗ Random executable names (a3f8b2.exe)
✗ Known exfiltration tools:
  - rclone.exe (cloud sync)
  - curl.exe, wget.exe (file transfer)
  - ftp.exe (FTP client)
  - pscp.exe, WinSCP (SCP/SFTP)
  - mega-cmd.exe (MEGA cloud)
  - Python.exe with network libs
  
TIMING PATTERNS:
✗ High uploads outside business hours
✗ Weekend/holiday activity
✗ Spike before resignation/termination
```

***

#### VPN/Anonymisation Usage

**Network List Indicators:**

```bash
✗ VPN network connections
✗ Tor connections
✗ Personal hotspot usage
✗ Public Wi-Fi on corporate device
```

**SRUM Indicators:**

```bash
✗ VPN client application usage
✗ Tor browser network activity
✗ Proxy applications
```

***

#### Lateral Movement Detection

**SRUM Indicators:**

```bash
✗ Remote management tools with network usage:
  - PsExec.exe
  - WinRM.exe
  - PowerShell.exe with network activity
  - Remote Desktop (mstsc.exe)
```

***

### Common Investigation Scenarios

#### Scenario 1: Cloud Storage Exfiltration

**Evidence Chain:**

```bash
1. SRUM: rclone.exe with 10 GB uploaded
2. Network List: No VPN (direct connection)
3. TCP/IP: Standard corporate IP
4. Timeline: Upload during off-hours
```

**Analysis:**

```powershell
# Search SRUM CSV for rclone
Import-Csv "NetworkUsage.csv" | Where-Object {$_.App -like "*rclone*"} | 
    Select-Object Timestamp, BytesSent, BytesRecvd | 
    Format-Table -AutoSize
```

***

#### Scenario 2: VPN-Based Data Theft

**Evidence Chain:**

```bash
1. Network List: NordVPN connected at 02:00 AM
2. SRUM: Unknown.exe with 5 GB upload
3. Network List: NordVPN disconnected at 03:30 AM
4. Files deleted (Recycle Bin)
```

**Timeline Correlation:**

```bash
02:00 - VPN connected
02:15 - Unknown.exe started uploading
03:00 - 5 GB uploaded
03:15 - Unknown.exe stopped
03:30 - VPN disconnected
03:45 - Files deleted
```

***

#### Scenario 3: Insider Threat Baseline Deviation

**Evidence Chain:**

```bash
Normal baseline:
- OneDrive.exe: 100 MB/day average

Anomaly detected:
- 3 weeks before resignation: 2 GB/day
- 2 weeks before resignation: 5 GB/day  
- 1 week before resignation: 10 GB/day
- Day before resignation: 20 GB uploaded

= Escalating data exfiltration
```

***

### SRUM Analysis Deep Dive

#### Understanding SRUM Data

**Recording Interval:**

* Data recorded approximately every hour
* Cumulative counters (total since boot)
* Requires aggregation for analysis

**Table Relationships:**

```bash
Network Data Usage → Application ID → App Resource Usage
   ↓
InterfaceLuid → Network Connectivity → Interface Details
   ↓
UserId (SID) → User Account
```

**Key Metrics:**

**BytesSent:**

* Total bytes uploaded by application
* Cumulative counter
* Resets on system reboot

**BytesRecvd:**

* Total bytes downloaded by application
* Cumulative counter
* Resets on system reboot

**Upload Ratio Calculation:**

```bash
Upload Ratio = BytesSent / (BytesSent + BytesRecvd)

Normal applications:
- Browsers: 2-5% upload ratio
- Email clients: 10-20% upload ratio
- Cloud backup: 40-60% upload ratio (normal sync)

Suspicious:
- Unknown apps: >80% upload ratio
- Non-cloud apps: >50% upload ratio
```

***

#### SRUM CSV Output Columns Reference

**NetworkUsage.csv:**

* `Timestamp` - Recording time
* `App` - Application path
* `UserId` - User SID
* `BytesSent` - Bytes uploaded
* `BytesRecvd` - Bytes downloaded
* `InterfaceLuid` - Network interface ID
* `L2ProfileId` - Network profile ID
* `L2ProfileFlags` - Profile flags

**AppResourceUseInfo.csv:**

* `Timestamp` - Recording time
* `AppId` - Application ID
* `UserId` - User SID
* `ForegroundCycleTime` - CPU time (foreground)
* `BackgroundCycleTime` - CPU time (background)
* `FaceTime` - Face detection time
* `ForegroundContextSwitches` - Context switches
* `BackgroundContextSwitches` - Context switches
* `ForegroundBytesRead` - Disk read (foreground)
* `ForegroundBytesWritten` - Disk write (foreground)

**NetworkConnections.csv:**

* `Timestamp` - Recording time
* `AppId` - Application ID
* `UserId` - User SID
* `InterfaceLuid` - Network interface
* `L2ProfileId` - Network profile
* `ConnectedTime` - Connection duration (seconds)
* `ConnectStartTime` - Connection start

***

### Tools & Commands Reference

#### SrumECmd (Eric Zimmerman)

**Basic Usage:**

```cmd
REM Parse SRUM database
SrumECmd.exe -d "C:\Cases\Evidence" --csv "C:\Cases\Output"

REM Parse with SOFTWARE hive for app names
SrumECmd.exe -d "C:\Cases\Evidence" --csv "C:\Cases\Output"
```

**Output Files:**

```bash
*_NetworkData_NetworkUsage.csv          → Bytes sent/received per app
*_AppResourceUseInfo_AppResourceUseInfo.csv → App resource usage
*_NetworkConnectivityUsage_NetworkConnections.csv → Connection history
*_AppTimeline_AppTimeline.csv           → Application timeline
```

**Analysis Priority:**

1. NetworkUsage.csv - Primary for data exfiltration
2. AppResourceUseInfo.csv - Context (app was running)
3. NetworkConnections.csv - Connection duration

***

#### Registry Queries

**Network List:**

{% code overflow="wrap" %}
```cmd
REM Managed networks
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed" /s

REM Unmanaged networks
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged" /s
```
{% endcode %}

**TCP/IP Interfaces:**

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s
```

***

#### Live Network Commands

```bash
REM Current IP configuration
ipconfig /all

REM Active connections with processes
netstat -anob

REM Routing table
route print

REM ARP cache
arp -a

REM DNS cache
ipconfig /displaydns
```

***

### Investigation Checklists

#### Data Exfiltration Investigation

* \[ ] Collect SRUM database (SRUDB.dat)
* \[ ] Collect SOFTWARE hive for app resolution
* \[ ] Parse with SrumECmd
* \[ ] Analyse NetworkUsage CSV
* \[ ] Sort by BytesSent (descending)
* \[ ] Calculate upload ratios
* \[ ] Identify applications with >50% upload ratio
* \[ ] Check for unusual application paths
* \[ ] Correlate with execution artifacts (Prefetch/BAM)
* \[ ] Check Network List for VPN usage
* \[ ] Build timeline of high upload events
* \[ ] Cross-reference with file access artifacts

#### VPN Detection Investigation

* \[ ] Parse Network List registry
* \[ ] Search for VPN keywords (OpenVPN, NordVPN, etc.)
* \[ ] Check first/last connection times
* \[ ] Parse SRUM for VPN client executables
* \[ ] Correlate VPN connection with data uploads
* \[ ] Check browser history for VPN provider sites
* \[ ] Review execution artifacts for VPN installers
* \[ ] Document VPN usage timeline

#### Network Baseline Investigation

* \[ ] Parse SRUM for full 30-60 day history
* \[ ] Calculate average daily usage per application
* \[ ] Identify maximum usage per application
* \[ ] Detect anomalies (>3x average)
* \[ ] Focus on anomalies during incident window
* \[ ] Correlate with user activity timeline
* \[ ] Document deviation patterns

***

### Best Practices

#### SRUM Collection

✅ **DO:**

* Collect both SRUDB.dat and SOFTWARE hive
* Collect .LOG files (transaction logs)
* Parse offline (don't open database live)
* Hash files before analysis
* Document collection timestamp

❌ **DON'T:**

* Open SRUDB.dat without SOFTWARE hive (app names won't resolve)
* Modify database during collection
* Skip transaction logs
* Forget OS version check (Win8+ only)

***

#### Analysis Methodology

✅ **DO:**

* Start with NetworkUsage.csv
* Calculate upload ratios
* Look for anomalies in app paths
* Correlate with execution artifacts
* Build timeline of network events
* Cross-reference multiple artifacts

❌ **DON'T:**

* Rely solely on SRUM
* Ignore low upload volumes (persistence C2)
* Skip baseline comparison
* Forget timezone conversions

***

### Limitations & Caveats

#### SRUM Limitations

```bash
✗ Windows 8+ only (not available Win7/XP)
✗ Hourly recording (not real-time)
✗ Counters reset on reboot
✗ 30-60 day retention (older data lost)
✗ Requires SOFTWARE hive for app names
✗ ESE database format (requires special parser)
```

#### Network List Limitations

```bash
✗ No bandwidth information
✗ Limited timestamp precision
✗ May not capture all network changes
✗ VPN connections may not always appear
```

#### TCP/IP Limitations

```bash
✗ Only shows last known configuration
✗ No historical IP addresses (unless DHCP records)
✗ No bandwidth usage
✗ Limited to local configuration
```

***

### Summary: Critical Takeaways

#### Artifact Strengths

**SRUM:**

* ✓ Best for: Data exfiltration detection
* ✓ Shows: Bytes sent/received per application
* ✓ Retention: 30-60 days
* ✗ Limitation: Windows 8+ only

**Network List:**

* ✓ Best for: Wi-Fi/VPN history
* ✓ Shows: Networks connected, first/last times
* ✓ Retention: Persistent
* ✗ Limitation: No bandwidth data

**TCP/IP Interfaces:**

* ✓ Best for: IP address history
* ✓ Shows: Current and recent IPs
* ✓ Retention: Recent only
* ✗ Limitation: No historical timeline

#### Investigation Strategy

1. **Check SRUM first** (data exfiltration smoking gun)
2. **Analyse upload ratios** (sent vs. received)
3. **Identify suspicious apps** (temp paths, unknown)
4. **Check Network List** (VPN usage)
5. **Review TCP/IP config** (IP addresses)
6. **Correlate with execution artifacts** (validate findings)

#### Key Principle

**SRUM is the gold standard for data exfiltration detection on Windows 8+. High upload ratios combined with unusual applications provide strong evidence of data theft.**

***

**Remember:** SRUM's bytes sent/received per application is your best evidence for data exfiltration. Calculate upload ratios and look for anomalies—normal applications download more than they upload!
