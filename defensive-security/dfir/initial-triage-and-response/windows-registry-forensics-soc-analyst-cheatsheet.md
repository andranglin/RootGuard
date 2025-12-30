# Windows Registry Forensics – SOC Analyst Cheatsheet

## Practical Guide for Live Response & Incident Investigation

***

### Quick Reference: Investigation Priority Matrix

| Priority     | Registry Area       | Investigation Type | Key Questions                  |
| ------------ | ------------------- | ------------------ | ------------------------------ |
| **CRITICAL** | Persistence Keys    | Malware/IR         | What runs at startup?          |
| **CRITICAL** | Services            | Malware/IR         | What malicious services exist? |
| **HIGH**     | USB/Mounted Devices | Data Exfil         | What devices connected?        |
| **HIGH**     | Network Activity    | Lateral Movement   | What shares accessed?          |
| **HIGH**     | RecentDocs/MRU      | User Activity      | What files accessed?           |
| **MEDIUM**   | Typed URLs          | Web Activity       | What sites visited?            |
| **MEDIUM**   | UserAssist          | Program Execution  | What programs run?             |
| **LOW**      | Search Terms        | User Intent        | What did user search for?      |

***

### SOC Investigation Workflows

#### Workflow 1: Malware Persistence Detection (CRITICAL)

**Scenario:** Suspected malware on endpoint, need to identify persistence mechanisms

**Registry Keys to Check (in order):**

#### **1. Run Keys (Most Common)**

**What it tells you:** Programs that execute at startup/login

```cmd
REM System-level (all users)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

REM User-level (current user)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"

REM Policy-based (harder to remove)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

REM 32-bit apps on 64-bit Windows
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
```

**Red Flags:**

* ✗ Unusual executable paths (temp folders, user directories)
* ✗ Obfuscated filenames (random characters)
* ✗ PowerShell/cmd.exe with encoded commands
* ✗ Executables in `%TEMP%`, `%APPDATA%`, `C:\Users\Public`
* ✗ Misspelt legitimate program names (svchost.exe vs svch0st.exe)

***

#### **2. Winlogon**

**What it tells you:** Programs executed during Windows login process

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Check these values:**

* `Shell` - Should be **"Explorer.exe"** ONLY
* `Userinit` - Should be **"C:\Windows\system32\userinit.exe,"**
* `TaskMan` - Should not exist (if exists, investigate)

**Red Flags:**

* ✗ Additional executables appended to Shell value
* ✗ Modified Userinit path or additional programs
* ✗ TaskMan value pointing to malware (hijacks Task Manager)

***

#### **3. Services**

**What it tells you:** Windows services (common persistence for advanced malware)

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services"
```

**PowerShell - Filter Suspicious Services:**

```powershell
# Get services with suspicious characteristics
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | 
    Where-Object {$_.ImagePath -like "*temp*" -or $_.ImagePath -like "*appdata*"} |
    Select-Object PSChildName, ImagePath, DisplayName, Start

# Start values: 0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled
```

**Red Flags:**

* ✗ Service ImagePath in temp/appdata directories
* ✗ Recently created services (check timestamps)
* ✗ Services with no DisplayName or Description
* ✗ ImagePath using cmd.exe or powershell.exe

***

#### **4. Image File Execution Options (IFEO)**

**What it tells you:** Debugger hijacking - programs executed instead of legitimate ones

{% code overflow="wrap" %}
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
```
{% endcode %}

**Red Flags:**

* ✗ Subkeys for common programs (sethc.exe, taskmgr.exe, etc.)
* ✗ "Debugger" value pointing to malicious executable
* ✗ Common targets: sethc.exe (Sticky Keys), utilman.exe (Utility Manager)

**Technique:** Attacker replaces legitimate program with malware debugger

***

#### **5. File Extension Hijacking**

**What it tells you:** Malware executes when you run .exe, .bat, .com files

```cmd
reg query "HKCR\exefile\shell\open\command"
reg query "HKCR\batfile\shell\open\command"
reg query "HKCR\comfile\shell\open\command"
```

**Expected values:**

* `exefile`: `"%1" %*`
* `batfile`: `"%1" %*`
* `comfile`: `"%1" %*`

**Red Flags:**

* ✗ Additional executable before `"%1"`
* ✗ Modified default value (should only be `"%1" %*`)

***

#### **6. Command Processor Autorun**

**What it tells you:** Commands executed every time cmd.exe runs

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Command Processor" /v AutoRun
reg query "HKCU\Software\Microsoft\Command Processor" /v AutoRun
```

**Red Flags:**

* ✗ AutoRun value exists (should not exist by default)
* ✗ Any PowerShell/cmd commands in AutoRun

***

#### **7. Browser Helper Objects (BHOs)**

**What it tells you:** Internet Explorer extensions (often malicious)

{% code overflow="wrap" %}
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
```
{% endcode %}

**Red Flags:**

* ✗ Unknown GUIDs (cross-reference with VirusTotal)
* ✗ Recently added BHOs
* ✗ BHOs with no associated legitimate software

***

### PowerShell Script: Comprehensive Persistence Check

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Quick persistence mechanism enumeration for SOC analysts
#>

Write-Host "[+] Checking Persistence Mechanisms..." -ForegroundColor Cyan

# Run Keys
Write-Host "`n[*] Run Keys (HKLM):" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue

Write-Host "`n[*] Run Keys (HKCU):" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue

# Winlogon
Write-Host "`n[*] Winlogon:" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | 
    Select-Object Shell, Userinit, TaskMan

# Suspicious Services
Write-Host "`n[*] Suspicious Services (Temp/AppData paths):" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | 
    Where-Object {$_.ImagePath -match "temp|appdata" -and $_.ImagePath -ne $null} |
    Select-Object PSChildName, ImagePath, Start | Format-Table -AutoSize

# IFEO
Write-Host "`n[*] Image File Execution Options (IFEO):" -ForegroundColor Yellow
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
    Where-Object {$_.Property -contains "Debugger"} |
    ForEach-Object {
        $debugger = Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
        if ($debugger) {
            Write-Host "  $($_.PSChildName) -> $($debugger.Debugger)" -ForegroundColor Red
        }
    }

Write-Host "`n[+] Persistence Check Complete!" -ForegroundColor Green
```
{% endcode %}

***

### Workflow 2: User Activity Investigation (High Priority)

**Scenario:** Insider threat, data theft, or understanding user actions during incident

#### Recent Files & Programs

**1. RecentDocs (Files Opened)**

**What it tells you:** Files recently opened from Windows Explorer

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
```

**PowerShell - Decode Binary Data:**

{% code overflow="wrap" %}
```powershell
# RecentDocs stores filenames in binary
$recentDocs = Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
$recentDocs.Property | ForEach-Object {
    $value = $recentDocs.GetValue($_)
    if ($value) {
        $filename = [System.Text.Encoding]::Unicode.GetString($value) -replace '\x00', ''
        Write-Host "$_`: $filename"
    }
}
```
{% endcode %}

**Forensic Value:**

* Files accessed even if deleted
* Includes network share files
* Shows file access order (MRU = Most Recently Used)

***

**2. OpenSaveMRU (Open/Save Dialog Usage)**

**What it tells you:** Files opened/saved via Open/Save dialogs

{% code overflow="wrap" %}
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"
```
{% endcode %}

**Subkeys by extension:**

* `*` - All files
* `txt` - Text files
* `pdf` - PDF files
* `docx` - Word documents
* etc.

**Cross-reference with:**

{% code overflow="wrap" %}
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU"
```
{% endcode %}

**LastVisitedMRU tells you:**

* Which application opened the file
* Folder path where file was located

***

**3. RunMRU (Start > Run Command History)**

**What it tells you:** Commands executed via Windows Run dialog

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
```

**Red Flags:**

* ✗ cmd.exe, powershell.exe with suspicious arguments
* ✗ Execution of files from temp directories
* ✗ Remote share access (`\\server\share`)
* ✗ Use of `PsExec`, `wmic`, or other remote tools

***

**4. TypedURLs (Internet Explorer Address Bar)**

**What it tells you:** URLs typed into IE/Windows Explorer address bar

```cmd
reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"
```

**Shows:**

* Manually typed URLs (not bookmarks/links clicked)
* File paths typed in Windows Explorer
* Up to 25 most recent entries

**Note:** Cleared when user clears browsing history

***

**5. UserAssist (Program Execution Tracking)**

**What it tells you:** Programs, shortcuts, control panel applets accessed by user

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
```

**Important:** Values are ROT-13 encoded

**PowerShell - Decode UserAssist:**

{% code overflow="wrap" %}
```powershell
# Function to decode ROT-13
function Decode-ROT13 {
    param([string]$Text)
    $result = ""
    foreach ($char in $Text.ToCharArray()) {
        if ($char -match '[A-Ma-m]') {
            $result += [char]([int]$char + 13)
        } elseif ($char -match '[N-Zn-z]') {
            $result += [char]([int]$char - 13)
        } else {
            $result += $char
        }
    }
    return $result
}

# Get UserAssist entries
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count" | 
    ForEach-Object {
        $_.Property | ForEach-Object {
            $decoded = Decode-ROT13 $_
            Write-Host "$decoded"
        }
    }
```
{% endcode %}

**Forensic Value:**

* Execution count for each program
* Last execution time
* Shows programs even if deleted

***

**6. Windows Search Terms**

**What it tells you:** What user searched for using Windows Search

```cmd
reg query "HKCU\Software\Microsoft\Search Assistant\ACMru\5603"
reg query "HKCU\Software\Microsoft\Search Assistant\ACMru\5604"
```

**Subkeys:**

* `5001` - Internet Search Assistant terms
* `5603` - Windows files/folders search
* `5604` - "Word or phrase in a file" search
* `5647` - "Computers or people" search

**Red Flags:**

* ✗ Searches for "password", "confidential", "payroll"
* ✗ File type searches (.pst, .pdf, financial terms)
* ✗ User/admin account searches

***

#### PowerShell Script: User Activity Timeline

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Enumerate user activity from registry
#>

Write-Host "[+] User Activity Investigation" -ForegroundColor Cyan

# RecentDocs
Write-Host "`n[*] Recent Documents:" -ForegroundColor Yellow
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# OpenSaveMRU - Recent file extensions
Write-Host "`n[*] Recent File Extensions Used:" -ForegroundColor Yellow
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" |
    Select-Object PSChildName | Format-Table -AutoSize

# RunMRU
Write-Host "`n[*] Run Command History:" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue |
    Select-Object * -ExcludeProperty PS* | Format-List

# TypedURLs
Write-Host "`n[*] Typed URLs:" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue |
    Select-Object url* | Format-List

# Search terms
Write-Host "`n[*] Windows Search Terms:" -ForegroundColor Yellow
reg query "HKCU\Software\Microsoft\Search Assistant\ACMru\5603" 2>$null

Write-Host "`n[+] User Activity Enumeration Complete!" -ForegroundColor Green
```
{% endcode %}

***

### Workflow 3: USB & External Device Investigation

**Scenario:** Data exfiltration via USB drive, unauthorised device usage

#### Critical Registry Keys

**1. USB Storage Devices**

**What it tells you:** All USB storage devices ever connected

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"
```

**PowerShell - Enumerate USB Devices:**

```powershell
# Get USB device details
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | 
    ForEach-Object {
        $device = $_.PSChildName
        Get-ChildItem $_.PSPath | ForEach-Object {
            $serial = $_.PSChildName
            $friendlyName = (Get-ItemProperty $_.PSPath).FriendlyName
            [PSCustomObject]@{
                Device = $device
                Serial = $serial
                FriendlyName = $friendlyName
            }
        }
    } | Format-Table -AutoSize
```

***

**2. Mounted Devices (Drive Letters)**

**What it tells you:** Drive letter assignments for USB and network drives

```cmd
reg query "HKLM\SYSTEM\MountedDevices"
```

**Shows:**

* `\DosDevices\E:`, `\DosDevices\F:`, etc. - USB drive letters
* Maps drive letters to device serial numbers

**Forensic Value:**

* Correlate drive letter to USB device
* Determine when device was mounted

***

**3. MountPoints2 (User-Specific Device Access)**

**What it tells you:** Which users accessed which devices

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
```

**Shows:**

* Volume GUIDs for accessed devices
* Network share paths (\server\share)

**Cross-reference:** Match GUIDs in MountPoints2 to MountedDevices to identify USB devices per user

***

**4. Network Drive Mapping**

**What it tells you:** Recently mapped network drives

{% code overflow="wrap" %}
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU"
```
{% endcode %}

**Red Flags:**

* ✗ Connections to unknown file servers
* ✗ Administrative shares (C$, ADMIN$, IPC$)
* ✗ Temporary network shares

***

#### PowerShell Script: USB & Device Investigation

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    USB and external device enumeration
#>

Write-Host "[+] USB & External Device Investigation" -ForegroundColor Cyan

# USB Storage devices
Write-Host "`n[*] USB Storage Devices:" -ForegroundColor Yellow
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | 
    ForEach-Object {
        Write-Host "  Device: $($_.PSChildName)"
        Get-ChildItem $_.PSPath | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath
            Write-Host "    Serial: $($_.PSChildName)"
            Write-Host "    Name: $($props.FriendlyName)" -ForegroundColor Green
        }
    }

# Mounted devices
Write-Host "`n[*] Currently/Recently Mounted Devices:" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SYSTEM\MountedDevices" | 
    Select-Object "\DosDevices\*" | Format-List

# User mount points
Write-Host "`n[*] User Mount Points (Current User):" -ForegroundColor Yellow
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -ErrorAction SilentlyContinue |
    Select-Object PSChildName | Format-Table -AutoSize

# Network drives
Write-Host "`n[*] Network Drive History:" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" -ErrorAction SilentlyContinue |
    Select-Object * -ExcludeProperty PS* | Format-List

Write-Host "`n[+] Device Investigation Complete!" -ForegroundColor Green
```
{% endcode %}

***

### Workflow 4: Network & Lateral Movement Investigation

**Scenario:** Detect lateral movement, remote access, credential dumping

#### Critical Indicators

**1. Network Share Access (MountPoints2)**

**What it tells you:** Remote shares accessed by user

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
```

**Look for:**

* `##servername#sharename` - Network share format
* Administrative shares: `##server#C$`, `##server#ADMIN$`
* Unusual share names: `##server#Temp$`, `##server#Exfil$`

**Red Flags:**

* ✗ Access to multiple servers (horizontal movement)
* ✗ Administrative shares (C$, ADMIN$)
* ✗ Non-standard share names
* ✗ Access from non-admin accounts

***

**2. Remote Desktop Activity**

**What it tells you:** RDP configuration and potential remote access

```cmd
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server"
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
```

**Check:**

* `fDenyTSConnections` = 0 means RDP is ENABLED
* `PortNumber` = RDP port (default 3389)

**PowerShell - Check RDP Status:**

{% code overflow="wrap" %}
```powershell
$rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
if ($rdp.fDenyTSConnections -eq 0) {
    Write-Host "[!] RDP is ENABLED" -ForegroundColor Red
} else {
    Write-Host "[+] RDP is disabled" -ForegroundColor Green
}
```
{% endcode %}

***

**3. Startup Approved Run (Network Locations)**

**What it tells you:** Programs configured to run from network shares

{% code overflow="wrap" %}
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
```
{% endcode %}

**Red Flags:**

* ✗ Executables running from UNC paths
* ✗ Scripts from network shares at startup

***

#### PowerShell Script: Network Activity Investigation

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Network and lateral movement investigation
#>

Write-Host "[+] Network & Lateral Movement Investigation" -ForegroundColor Cyan

# Network shares accessed
Write-Host "`n[*] Network Shares Accessed:" -ForegroundColor Yellow
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -ErrorAction SilentlyContinue |
    Where-Object {$_.PSChildName -like "*##*"} |
    ForEach-Object {
        $sharePath = $_.PSChildName -replace "##", "\\"
        Write-Host "  $sharePath" -ForegroundColor Cyan
    }

# RDP Status
Write-Host "`n[*] Remote Desktop Status:" -ForegroundColor Yellow
$rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
if ($rdp.fDenyTSConnections -eq 0) {
    Write-Host "  [!] RDP is ENABLED" -ForegroundColor Red
    $port = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name PortNumber
    Write-Host "  Port: $($port.PortNumber)" -ForegroundColor Yellow
} else {
    Write-Host "  [+] RDP is disabled" -ForegroundColor Green
}

# Mapped network drives
Write-Host "`n[*] Network Drive Mappings:" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" -ErrorAction SilentlyContinue |
    Select-Object * -ExcludeProperty PS* | Format-List

Write-Host "`n[+] Network Investigation Complete!" -ForegroundColor Green
```
{% endcode %}

***

### Workflow 5: System Information (Quick Triage)

**Scenario:** Need system context during incident response

#### Essential System Info

{% code overflow="wrap" %}
```cmd
REM OS Version
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName

REM Installation Date (Unix timestamp)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v InstallDate

REM Registered Owner
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner

REM Computer Name
reg query "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" /v ComputerName

REM Time Zone (minutes from UTC)
reg query "HKLM\System\CurrentControlSet\Control\TimeZoneInformation" /v ActiveTimeBias

REM System Root
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v SystemRoot
```
{% endcode %}

***

#### PowerShell Script: System Information Quick Triage

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Quick system information triage
#>

Write-Host "[+] System Information Triage" -ForegroundColor Cyan

# OS Information
Write-Host "`n[*] Operating System:" -ForegroundColor Yellow
$os = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
Write-Host "  Product: $($os.ProductName)"
Write-Host "  Edition: $($os.EditionID)"
Write-Host "  Build: $($os.CurrentBuildNumber)"
Write-Host "  Install Date: $([DateTimeOffset]::FromUnixTimeSeconds($os.InstallDate).DateTime)"

# Computer Name
Write-Host "`n[*] Computer Name:" -ForegroundColor Yellow
$computerName = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"
Write-Host "  $($computerName.ComputerName)"

# Time Zone
Write-Host "`n[*] Time Zone:" -ForegroundColor Yellow
$tz = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\TimeZoneInformation"
Write-Host "  Bias: $($tz.ActiveTimeBias) minutes from UTC"
Write-Host "  Standard Name: $($tz.StandardName)"

# Registered Owner
Write-Host "`n[*] Registered Owner:" -ForegroundColor Yellow
Write-Host "  $($os.RegisteredOwner)"

Write-Host "`n[+] System Triage Complete!" -ForegroundColor Green
```
{% endcode %}

***

### Advanced: Protected Storage & Credentials

#### Windows Protected Storage

**What it tells you:** Stored passwords (IE AutoComplete, Outlook, etc.)

**Location:**

```cmd
reg query "HKCU\Software\Microsoft\Protected Storage System Provider"
```

**Note:** Hidden by Registry Editor, even from administrators

**Access Methods:**

* Use specialised tools (NirSoft Protected Storage PassView)
* Requires appropriate privileges
* Data is encrypted per user account

***

#### LSA Secrets & Autologon Passwords

**What it tells you:** Cached credentials, service account passwords

{% code overflow="wrap" %}
```cmd
REM Requires SYSTEM privileges
reg query "HKLM\Security\Policy\Secrets"

REM Autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
```
{% endcode %}

**Red Flags:**

* ✗ AutoAdminLogon = 1 (auto login enabled)
* ✗ DefaultPassword value exists (plain text password!)
* ✗ LSA Secrets accessible (credential dumping indicator)

***

### SOC Incident Response Cheatsheet

#### Quick Commands for Live Response

**Rapid Persistence Check**

{% code overflow="wrap" %}
```cmd
@echo off
echo === PERSISTENCE CHECK ===
echo [+] Run Keys...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
echo.
echo [+] Services with suspicious paths...
reg query "HKLM\SYSTEM\CurrentControlSet\Services" | findstr /i "temp appdata"
echo.
echo [+] Winlogon...
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
echo.
echo [+] IFEO...
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
echo.
echo === CHECK COMPLETE ===
```
{% endcode %}

***

**USB Device Quick Check**

```cmd
@echo off
echo === USB DEVICE CHECK ===
echo [+] USB Storage Devices...
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"
echo.
echo [+] Mounted Devices...
reg query "HKLM\SYSTEM\MountedDevices"
echo.
echo [+] User Mount Points...
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
echo.
echo === CHECK COMPLETE ===
```

***

**User Activity Quick Check**

```cmd
@echo off
echo === USER ACTIVITY CHECK ===
echo [+] Recent Documents...
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
echo.
echo [+] Run History...
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
echo.
echo [+] Typed URLs...
reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"
echo.
echo === CHECK COMPLETE ===
```

***

#### PowerShell One-Liners

{% code overflow="wrap" %}
```powershell
# Get all Run keys (system and user)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Find services with suspicious image paths
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | Where-Object {$_.ImagePath -match "temp|appdata|users"} | Select-Object PSChildName, ImagePath

# Check Winlogon Shell value
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").Shell

# Enumerate USB devices
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -Recurse | Select-Object Name

# Get typed URLs
Get-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"

# Check RDP status
if ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) {"RDP Enabled"} else {"RDP Disabled"}
```
{% endcode %}

***

### Detection Rules & IOCs

#### High-Confidence Malware Indicators

**Run Key Patterns:**

```bash
ImagePath contains:
- %TEMP%
- %APPDATA%\Local\Temp
- C:\Users\Public
- Obfuscated PowerShell (hidden window, encoded command)
```

**Service Patterns:**

```bash
ImagePath contains:
- rundll32.exe [random].dll
- cmd.exe /c start
- powershell.exe -enc [base64]
```

**File Extension Hijacking:**

```bash
exefile default value != "%1" %*
```

**IFEO Abuse:**

```bash
Debugger value exists for:
- sethc.exe (Sticky Keys)
- utilman.exe (Utility Manager)  
- osk.exe (On-Screen Keyboard)
- taskmgr.exe (Task Manager)
```

***

### Common Anti-Forensics Techniques

#### 1. Clearing MRU Lists

**Action:** User runs "Clear Recent Items" or third-party cleaners

**What's deleted:**

* RecentDocs
* RunMRU
* TypedURLs
* OpenSaveMRU
* LastVisitedMRU

**Detection:**

* Check for presence of CCleaner, BleachBit in installed programs
* Look for execution evidence in Prefetch/Amcache
* MRU keys missing = potential evidence destruction

***

#### 2. Registry Key Deletion

**Action:** Attacker deletes persistence keys after establishing alternate persistence

**Detection:**

* Registry transaction logs may contain deleted keys
* Volume Shadow Copies preserve old registry state
* Use RegRipper with VSS to compare historical state

***

#### 3. Timestamp Manipulation

**Action:** Modify registry key LastWriteTime

**Detection:**

* Difficult to detect without baseline
* Compare with other timestamp sources (event logs, file system)
* Unusual timestamp patterns (all keys same time)

***

### Registry Analysis Tools

#### Built-in Windows

* **reg.exe** - Command-line registry editor
* **regedit.exe** - GUI registry editor
* **PowerShell** - Registry PSDrive (HKLM:, HKCU:)

#### Forensic Tools

* **RegRipper** - Automated registry parsing (best for offline analysis)
* **Registry Explorer (Eric Zimmerman)** - GUI registry viewer with bookmarks
* **RECmd** - Command-line registry parser
* **Registry Viewer (AccessData)** - Commercial option

#### Live Response Tools

* **KAPE** - Collection of registry hives and triage
* **Velociraptor** - Remote registry collection and analysis
* **GRR** - Google Rapid Response for enterprise scale

***

### Exporting Registry for Analysis

#### Export Specific Keys

```bash
REM Export to .reg file
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\cases\run_keys.reg

REM Export entire hive
reg save HKLM\SYSTEM C:\cases\SYSTEM
reg save HKLM\SOFTWARE C:\cases\SOFTWARE
reg save HKLM\SAM C:\cases\SAM
reg save HKLM\SECURITY C:\cases\SECURITY
reg save HKU\.DEFAULT C:\cases\DEFAULT
```

#### User Registry Hives

```bash
REM Current user (must be logged in)
reg save HKCU C:\cases\NTUSER.DAT

REM All users (offline)
copy C:\Users\[username]\NTUSER.DAT C:\cases\
copy C:\Users\[username]\AppData\Local\Microsoft\Windows\UsrClass.dat C:\cases\
```

#### PowerShell - Mass Export

{% code overflow="wrap" %}
```powershell
# Export all Run keys to single file
$output = "C:\cases\run_keys_export.txt"

"HKLM Run Keys" | Out-File $output
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $output -Append

"HKCU Run Keys" | Out-File $output -Append
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File $output -Append

"HKLM RunOnce Keys" | Out-File $output -Append
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" | Out-File $output -Append
```
{% endcode %}

***

### Registry Forensics Best Practices

#### Live System Analysis

✅ **Do:**

* Use non-invasive read-only commands
* Export keys before making changes
* Document all actions with timestamps
* Use PowerShell for scripting (logged in transcripts)

❌ **Don't:**

* Modify registry during investigation
* Run untrusted scripts as admin
* Clear or delete keys during live analysis
* Shutdown without checking ClearPagefileAtShutdown

***

#### Offline Analysis

✅ **Do:**

* Copy entire registry hives for analysis
* Mount hives read-only
* Use RegRipper for automated extraction
* Check Volume Shadow Copies for historical state
* Document hive file hashes before analysis

❌ **Don't:**

* Analyse on production system
* Mount hives in write mode
* Forget to check transaction logs (.LOG, .LOG1, .LOG2)

***

#### Documentation

✅ **Document:**

* All commands executed
* Timestamp of analysis
* Registry key paths and values found
* Suspicious entries with context
* Tool versions used
* Hash values of exported hives

***

### Quick Reference: Registry Hive Locations

#### System Hives (HKLM)

```bash
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SECURITY
C:\Windows\System32\config\DEFAULT
```

#### User Hives

{% code overflow="wrap" %}
```bash
C:\Users\[username]\NTUSER.DAT (HKCU)
C:\Users\[username]\AppData\Local\Microsoft\Windows\UsrClass.dat (HKCU\Software\Classes)
```
{% endcode %}

#### Transaction Logs

```bash
.LOG   - Transaction log
.LOG1  - Backup transaction log
.LOG2  - Additional backup log
```

***

### Investigation Checklist

#### Malware/Persistence Investigation

* \[ ] Check all Run/RunOnce keys (HKLM and HKCU)
* \[ ] Check Winlogon Shell and Userinit values
* \[ ] Enumerate all services for suspicious ImagePath
* \[ ] Check IFEO for debugger hijacking
* \[ ] Verify file extension associations (exefile, batfile, comfile)
* \[ ] Check Command Processor AutoRun
* \[ ] Review Browser Helper Objects
* \[ ] Check Active Setup entries
* \[ ] Review Startup Approved items

#### User Activity Investigation

* \[ ] Enumerate RecentDocs
* \[ ] Check OpenSaveMRU and LastVisitedMRU
* \[ ] Review RunMRU command history
* \[ ] Extract TypedURLs
* \[ ] Decode UserAssist entries
* \[ ] Check Windows Search terms (ACMru)
* \[ ] Review TypedPaths (manually entered paths)

#### Data Exfiltration Investigation

* \[ ] Enumerate USB devices (USBSTOR)
* \[ ] Check MountedDevices for drive letters
* \[ ] Review MountPoints2 for user device access
* \[ ] Check mapped network drives
* \[ ] Look for network share connections
* \[ ] Review external device timeline

#### Lateral Movement Investigation

* \[ ] Check MountPoints2 for remote shares
* \[ ] Review network drive mappings
* \[ ] Check RDP status and configuration
* \[ ] Look for PsExec indicators
* \[ ] Review authentication methods (Winlogon)
* \[ ] Check for credential dumping tools

***

### Common SOC Use Cases

#### Use Case 1: Ransomware Detection

**Indicators to check:**

* New Run keys pointing to suspicious executables
* Services with odd names or temp paths
* Command Processor AutoRun
* Recent file activity (RecentDocs) showing mass file access
* UserAssist showing ransomware executable launch

***

#### Use Case 2: Insider Threat

**Indicators to check:**

* USB device connections (USBSTOR)
* Files accessed via OpenSaveMRU
* Network share mappings to external/personal storage
* Search terms indicating data theft intent
* Typed URLs to file-sharing sites

***

#### Use Case 3: Credential Theft

**Indicators to check:**

* ProcDump execution (memory dump tool)
* Access to Protected Storage
* Winlogon AutoAdminLogon enabled
* LSA Secrets access attempts
* Mimikatz or similar tool indicators

***

#### Use Case 4: Lateral Movement

**Indicators to check:**

* Multiple remote share connections (MountPoints2)
* Administrative share usage (C$, ADMIN$)
* RDP enabled on workstation
* PSExec or remote execution tools
* Network drive mappings to multiple hosts

***

### Summary: Critical Registry Keys by Investigation Type

| Investigation Type      | Critical Keys                                |
| ----------------------- | -------------------------------------------- |
| **Malware Persistence** | Run, RunOnce, Services, Winlogon, IFEO       |
| **User Activity**       | RecentDocs, OpenSaveMRU, RunMRU, TypedURLs   |
| **USB/Data Exfil**      | USBSTOR, MountedDevices, MountPoints2        |
| **Lateral Movement**    | MountPoints2 (shares), Map Network Drive MRU |
| **Credential Theft**    | Winlogon (autologon), Protected Storage      |
| **System Info**         | CurrentVersion, ComputerName, TimeZone       |

**Key Principle:** Registry analysis reveals attacker actions even after files are deleted - persistence mechanisms, user activity, and device usage leave persistent traces that survive file deletion and anti-forensics efforts.
