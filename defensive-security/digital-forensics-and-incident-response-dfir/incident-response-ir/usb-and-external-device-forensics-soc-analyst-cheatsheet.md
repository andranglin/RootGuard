# USB & External Device Forensics - SOC Analyst Cheatsheet

### Practical Guide for USB Device Investigation & Data Exfiltration

***

### Quick Reference: USB Artifacts Matrix

| Artifact                 | What It Reveals        | Location                      | Volatility | Key Value                        |
| ------------------------ | ---------------------- | ----------------------------- | ---------- | -------------------------------- |
| **USBSTOR**              | Device identity        | SYSTEM hive                   | Persistent | Vendor, product, serial          |
| **MountPoints2**         | User attribution       | NTUSER.DAT                    | Persistent | Which user accessed device       |
| **Timestamps**           | Connection times       | SYSTEM hive, setupapi.dev.log | Medium     | First/last connect, removal      |
| **Volume Serial Number** | Device-to-file linking | Event 1006, EMDMgmt           | Medium     | **Critical for LNK correlation** |
| **Drive Letters**        | Mount points           | MountedDevices                | Last only  | Historical not available         |

***

### Investigation Priority Matrix

| Priority     | Artifact              | Best For                | Key Value                      |
| ------------ | --------------------- | ----------------------- | ------------------------------ |
| **CRITICAL** | USBSTOR + USB         | Device identification   | Vendor, product, serial number |
| **CRITICAL** | Volume Serial Number  | File access correlation | **Links USB to LNK files**     |
| **CRITICAL** | MountPoints2          | User attribution        | Which user accessed USB        |
| **HIGH**     | Connection Timestamps | Timeline construction   | First/last connection times    |
| **MEDIUM**   | Drive Letters         | Current mapping         | Drive letter assignments       |

***

### Core Investigation Questions

#### Primary Questions:

1. **What devices connected?** (USBSTOR - Device identification)
2. **When did they connect?** (Timestamps - Timeline)
3. **Who accessed them?** (MountPoints2 - User attribution)
4. **What files were accessed?** (VSN + LNK files - File correlation)

#### The Critical Link:

**Volume Serial Number (VSN)** is the KEY to linking USB devices to file access via LNK files!

***

### Understanding USB Forensics Components

#### Key Concept: Multiple Serial Numbers

**DO NOT CONFUSE:**

| Serial Number Type             | What It Is             | Where Found                    | Purpose                            |
| ------------------------------ | ---------------------- | ------------------------------ | ---------------------------------- |
| **USB Unique Serial**          | Device firmware serial | USBSTOR key                    | Identifies physical USB device     |
| **Volume Serial Number (VSN)** | File system serial     | Event 1006, EMDMgmt, LNK files | **Links device to files accessed** |
| **Printed Serial**             | Label on device        | Physical device                | May not match internal serial      |

**Critical Understanding:**

```bash
USB Device connects → Assigned VSN (if formatted)
Files accessed from USB → LNK files created with VSN embedded
VSN in LNK file = VSN from USB device = PROOF of file access
```

***

### SOC Investigation Workflows

#### Workflow 1: Data Exfiltration Investigation (CRITICAL)

**Scenario:** Suspected data theft via USB drive

**Investigation Steps (Priority Order):**

**Step 1: Identify ALL USB Devices Connected**

**Registry Location: SYSTEM\CurrentControlSet\Enum\USBSTOR**

**PowerShell - Enumerate USB Devices:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Enumerate all USB storage devices ever connected
#>

Write-Host "[+] Enumerating USB Storage Devices..." -ForegroundColor Cyan

$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

if (Test-Path $usbStorPath) {
    Get-ChildItem $usbStorPath | ForEach-Object {
        $deviceKey = $_
        $deviceInfo = $_.PSChildName
        
        # Parse device info: Disk&Ven_XXX&Prod_YYY&Rev_ZZZ
        if ($deviceInfo -match "Disk&Ven_(.+)&Prod_(.+)&Rev_(.+)") {
            $vendor = $matches[1].Trim("_")
            $product = $matches[2].Trim("_")
            $revision = $matches[3].Trim("_")
            
            Write-Host "`n--- Device: $vendor $product ---" -ForegroundColor Yellow
            Write-Host "  Revision: $revision" -ForegroundColor Gray
            
            # Get serial number(s)
            Get-ChildItem $deviceKey.PSPath | ForEach-Object {
                $serial = $_.PSChildName
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                
                # Check for Windows-generated serial (has & in 2nd position)
                if ($serial.Length -ge 2 -and $serial[1] -eq '&') {
                    $serialType = "Windows-Generated (No Unique Serial)"
                } else {
                    $serialType = "Device Unique Serial"
                }
                
                Write-Host "`n  Serial Number: $serial" -ForegroundColor Cyan
                Write-Host "  Type: $serialType" -ForegroundColor $(if ($serialType -like "*Windows*") { "Yellow" } else { "Green" })
                
                if ($props.FriendlyName) {
                    Write-Host "  Friendly Name: $($props.FriendlyName)" -ForegroundColor White
                }
                
                # Get ParentIdPrefix (links to SCSI)
                if ($props.ParentIdPrefix) {
                    Write-Host "  ParentIdPrefix: $($props.ParentIdPrefix)" -ForegroundColor Gray
                }
            }
        }
    }
} else {
    Write-Host "[!] USBSTOR key not found" -ForegroundColor Red
}
```
{% endcode %}

**Key USBSTOR Fields:**

* **Vendor** - Manufacturer (Kingston, SanDisk, etc.)
* **Product** - Model name
* **Version/Revision** - Firmware version
* **Serial Number** - Device identifier
* **FriendlyName** - Windows display name
* **ParentIdPrefix** - Links USBSTOR to SCSI key

**Red Flags:**

* ✗ **Unknown vendors** (unrecognised brands)
* ✗ **Multiple similar devices** (many USBs in short time)
* ✗ **Recently connected devices** during incident window
* ✗ **Windows-generated serials** (& in 2nd position = device lacks unique serial)

***

**Step 2: Extract Connection Timestamps (First/Last Connection)**

**Three Sources for Timestamps:**

**A. SYSTEM Registry Properties Keys (Most Reliable)**

**Location:**

{% code overflow="wrap" %}
```bash
SYSTEM\CurrentControlSet\Enum\USBSTOR\{Device}\{Serial}\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####

Where #### is:
0064 - First Install (Windows 7+)
0066 - Last Connected (Windows 8+)
0067 - Last Removal (Windows 8+)
```
{% endcode %}

**PowerShell - Extract Timestamps:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Extract USB connection timestamps from SYSTEM registry
#>

function Convert-FileTimeToDateTime {
    param([byte[]]$FileTimeBytes)
    
    if ($FileTimeBytes.Length -ge 8) {
        try {
            $fileTime = [BitConverter]::ToInt64($FileTimeBytes, 0)
            return [DateTime]::FromFileTime($fileTime)
        } catch {
            return "Unable to parse"
        }
    }
    return "Invalid data"
}

Write-Host "[+] Extracting USB Connection Timestamps..." -ForegroundColor Cyan

$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

Get-ChildItem $usbStorPath | ForEach-Object {
    $deviceKey = $_
    
    Get-ChildItem $deviceKey.PSPath | ForEach-Object {
        $serialKey = $_
        $serial = $_.PSChildName
        
        # Properties key
        $propsPath = Join-Path $serialKey.PSPath "Properties\{83da6326-97a6-4088-9453-a19231573b29}"
        
        if (Test-Path $propsPath) {
            Write-Host "`n--- Serial: $serial ---" -ForegroundColor Yellow
            
            # First Install (0064)
            $firstInstall = Get-ItemProperty "$propsPath\0064" -Name "(default)" -ErrorAction SilentlyContinue
            if ($firstInstall) {
                $time = Convert-FileTimeToDateTime $firstInstall.'(default)'
                Write-Host "  First Install: $time" -ForegroundColor Green
            }
            
            # Last Connected (0066)
            $lastConnected = Get-ItemProperty "$propsPath\0066" -Name "(default)" -ErrorAction SilentlyContinue
            if ($lastConnected) {
                $time = Convert-FileTimeToDateTime $lastConnected.'(default)'
                Write-Host "  Last Connected: $time" -ForegroundColor Cyan
            }
            
            # Last Removal (0067)
            $lastRemoval = Get-ItemProperty "$propsPath\0067" -Name "(default)" -ErrorAction SilentlyContinue
            if ($lastRemoval) {
                $time = Convert-FileTimeToDateTime $lastRemoval.'(default)'
                Write-Host "  Last Removal: $time" -ForegroundColor Yellow
            }
        }
    }
}
```
{% endcode %}

**B. setupapi.dev.log (First Connection - LOCAL TIMEZONE!)**

**Location:** `C:\Windows\inf\setupapi.dev.log`

**CRITICAL:** Timestamps in **LOCAL TIMEZONE** (not UTC like most forensic artifacts!)

**PowerShell - Parse setupapi.dev.log:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Parse setupapi.dev.log for USB connections
#>

param(
    [string]$LogPath = "C:\Windows\inf\setupapi.dev.log",
    [string]$SearchSerial = ""  # Optional: search for specific serial
)

Write-Host "[+] Parsing setupapi.dev.log..." -ForegroundColor Cyan
Write-Host "[!] WARNING: Timestamps are in LOCAL TIMEZONE" -ForegroundColor Yellow

if (Test-Path $LogPath) {
    $content = Get-Content $LogPath
    
    $usbEntries = @()
    $currentEntry = $null
    
    foreach ($line in $content) {
        # Look for USB device installation start
        if ($line -match ">>>  \[Device Install.*?\- (.+?)\]" -or $line -match "Device Install.*?USB") {
            if ($currentEntry) {
                $usbEntries += $currentEntry
            }
            $currentEntry = @{
                Lines = @($line)
                Timestamp = $null
                Serial = $null
            }
        }
        
        if ($currentEntry) {
            $currentEntry.Lines += $line
            
            # Extract timestamp (format: >>> Section start 2024/11/30 14:23:45.123)
            if ($line -match ">>>.*?(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3})") {
                $currentEntry.Timestamp = $matches[1]
            }
            
            # Extract serial number
            if ($line -match "Device Serial Number = (.+)") {
                $currentEntry.Serial = $matches[1].Trim()
            }
        }
    }
    
    if ($currentEntry) {
        $usbEntries += $currentEntry
    }
    
    # Display results
    if ($SearchSerial) {
        $filtered = $usbEntries | Where-Object { $_.Serial -like "*$SearchSerial*" }
        Write-Host "`n[*] Entries matching '$SearchSerial':" -ForegroundColor Yellow
        $filtered | ForEach-Object {
            Write-Host "  Timestamp: $($_.Timestamp) (LOCAL TIME)" -ForegroundColor Cyan
            Write-Host "  Serial: $($_.Serial)" -ForegroundColor White
        }
    } else {
        Write-Host "`n[*] Found $($usbEntries.Count) USB device entries" -ForegroundColor Yellow
        Write-Host "[*] Recent entries:" -ForegroundColor Yellow
        
        $usbEntries | Select-Object -Last 10 | ForEach-Object {
            Write-Host "`n  Timestamp: $($_.Timestamp) (LOCAL TIME)" -ForegroundColor Cyan
            Write-Host "  Serial: $($_.Serial)" -ForegroundColor White
        }
    }
} else {
    Write-Host "[!] setupapi.dev.log not found" -ForegroundColor Red
}
```
{% endcode %}

**C. Event ID 1006 (Connection/Disconnection Events)**

**Location:** `Microsoft-Windows-Partition/Diagnostic.evtx`

**Event ID 1006:** Logged for each USB connect/disconnect

**Caveat:** Log cleared during major OS updates

**PowerShell - Parse Event 1006:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Parse Event 1006 for USB connections
#>

param(
    [string]$EventLog = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Partition%4Diagnostic.evtx",
    [int]$Days = 30
)

Write-Host "[+] Parsing Partition Diagnostic Events..." -ForegroundColor Cyan

if (Test-Path $EventLog) {
    $startTime = (Get-Date).AddDays(-$Days)
    
    $events = Get-WinEvent -Path $EventLog -FilterXPath "*[System[EventID=1006]]" -ErrorAction SilentlyContinue
    
    if ($events) {
        Write-Host "[*] Found $($events.Count) partition events" -ForegroundColor Yellow
        
        $events | Sort-Object TimeCreated -Descending | ForEach-Object {
            $xml = [xml]$_.ToXml()
            
            Write-Host "`n--- Event: $($_.TimeCreated) ---" -ForegroundColor Yellow
            Write-Host "Event Data:" -ForegroundColor Gray
            
            $xml.Event.EventData.Data | ForEach-Object {
                Write-Host "  $($_.Name): $($_.'#text')" -ForegroundColor Cyan
            }
        }
    } else {
        Write-Host "[!] No Event 1006 entries found" -ForegroundColor Red
    }
} else {
    Write-Host "[!] Partition Diagnostic log not found" -ForegroundColor Red
}
```
{% endcode %}

**Timestamp Summary Table:**

| Source               | Type                    | Timezone  | Reliability | Availability       |
| -------------------- | ----------------------- | --------- | ----------- | ------------------ |
| **Properties 0064**  | First Install           | UTC       | High        | Win7+              |
| **Properties 0066**  | Last Connected          | UTC       | High        | Win8+              |
| **Properties 0067**  | Last Removal            | UTC       | High        | Win8+              |
| **setupapi.dev.log** | First Connection        | **LOCAL** | High        | Persistent         |
| **Event 1006**       | Each connect/disconnect | UTC       | Medium      | Cleared on updates |

***

**Step 3: Identify User Attribution (MountPoints2)**

**Critical for Attribution:** Which user account accessed the USB device?

**Registry Location:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`

**How It Works:**

1. USB device assigned Volume GUID
2. User accesses USB → MountPoints2 entry created in their NTUSER.DAT
3. Volume GUID links to specific USB device

**PowerShell - Check Current User:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Check current user's MountPoints2 for USB access
#>

Write-Host "[+] Checking MountPoints2 for USB Device Access..." -ForegroundColor Cyan

$mountPoints = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

if (Test-Path $mountPoints) {
    $entries = Get-ChildItem $mountPoints
    
    if ($entries) {
        Write-Host "`n[*] Found $($entries.Count) mount point entries for $env:USERNAME" -ForegroundColor Yellow
        
        foreach ($entry in $entries) {
            $guid = $entry.PSChildName
            
            # Volume GUIDs start with {
            # Network shares start with ##
            if ($guid -like "{*}") {
                Write-Host "`n  Volume GUID: $guid" -ForegroundColor Cyan
                
                # Try to get additional details
                $props = Get-ItemProperty $entry.PSPath -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                        Write-Host "    $($_.Name): $($_.Value)" -ForegroundColor Gray
                    }
                }
            }
        }
        
        Write-Host "`n[+] To correlate GUIDs with devices, check SYSTEM\MountedDevices" -ForegroundColor Yellow
    } else {
        Write-Host "[!] No mount points found for current user" -ForegroundColor Gray
    }
} else {
    Write-Host "[!] MountPoints2 key not found" -ForegroundColor Red
}
```
{% endcode %}

**Offline Analysis (All Users):**

{% code overflow="wrap" %}
```powershell
# For offline analysis, need to load each user's NTUSER.DAT
# Example for specific user:

$userProfile = "C:\Users\Alice"
$ntuserPath = "$userProfile\NTUSER.DAT"

# Load hive (requires admin)
reg load "HKU\TempUser" $ntuserPath

# Query MountPoints2
reg query "HKU\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

# Unload hive
reg unload "HKU\TempUser"
```
{% endcode %}

***

**Step 4: Extract Volume Serial Number (VSN) - THE CRITICAL LINK**

**Why VSN is Critical:**

```bash
USB Device → Formatted with file system → Assigned VSN
Files accessed on USB → LNK files created
LNK files contain VSN (embedded in shell item)
VSN in LNK = VSN from USB device = PROOF of file access from that specific USB
```

**Three Methods to Get VSN:**

**Method 1: Event ID 1006 (Windows 10+)**

Event 1006 may include VBR (Volume Boot Record) data containing VSN

**VSN Location in VBR:**

* FAT: Offset 0x43 (4 bytes)
* exFAT: Offset 0x64 (4 bytes)
* NTFS: Offset 0x48 (8 bytes, but only first 4 bytes used)

**Method 2: EMDMgmt Registry Key (Legacy)**

**Location:** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`

**Caveat:** Often missing on modern systems with SSDs

**PowerShell - Extract from EMDMgmt:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Extract Volume Serial Numbers from EMDMgmt
#>

Write-Host "[+] Checking EMDMgmt for Volume Serial Numbers..." -ForegroundColor Cyan

$emdMgmtPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt"

if (Test-Path $emdMgmtPath) {
    Get-ChildItem $emdMgmtPath | ForEach-Object {
        $entry = Get-ItemProperty $_.PSPath
        
        Write-Host "`n--- Entry: $($_.PSChildName) ---" -ForegroundColor Yellow
        
        # Look for volume serial number (last integer in key name)
        if ($_.PSChildName -match "(\d+)$") {
            $vsnDecimal = $matches[1]
            $vsnHex = "{0:X}" -f [int]$vsnDecimal
            
            Write-Host "  Volume Serial (Decimal): $vsnDecimal" -ForegroundColor Cyan
            Write-Host "  Volume Serial (Hex): $vsnHex" -ForegroundColor Green
        }
        
        # Display all properties
        $entry.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "[!] EMDMgmt key not found (common on modern systems)" -ForegroundColor Yellow
}
```
{% endcode %}

**Method 3: Cross-Reference with LNK Files (Most Reliable)**

LNK files contain VSN! Extract from LNK files and correlate back to USB devices.

**Using LECmd (Zimmerman Tool):**

{% code overflow="wrap" %}
```bash
REM Parse LNK files
LECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\Output" --csvf lnk.csv -q

REM Filter CSV for:
REM - DriveType = "Removable"
REM - VolumeSerialNumber column
REM This gives you VSN of USB devices that had files accessed
```
{% endcode %}

***

**Step 5: Correlate Device to File Access (THE KEY CORRELATION)**

**Critical Workflow:**

1. **Extract USB Device Info:**
   * Device serial number (USBSTOR)
   * Connection timestamps (Properties keys)
   * User who accessed it (MountPoints2)
2. **Extract VSN:**
   * From Event 1006 or EMDMgmt
   * OR from LNK files (DriveType = Removable)
3. **Find LNK Files with Matching VSN:**
   * Parse all LNK files with LECmd
   * Filter for matching VolumeSerialNumber
   * These LNK files = files accessed from that USB
4. **Build Timeline:**
   * USB connected at time X
   * Files accessed (LNK timestamps)
   * USB disconnected at time Y

**Complete Correlation Script:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Complete USB to file access correlation
.DESCRIPTION
    Links USB devices to files accessed via VSN correlation
.NOTES
    Requires LECmd to parse LNK files first
#>

param(
    [string]$LnkCsvPath = "C:\Cases\Output\lnk.csv",
    [string]$OutputPath = "C:\Cases\USB_File_Correlation.txt"
)

Write-Host "`n[+] USB Device to File Access Correlation" -ForegroundColor Cyan
Write-Host "=" * 80

# Check if LNK CSV exists
if (-not (Test-Path $LnkCsvPath)) {
    Write-Host "[!] LNK CSV not found at: $LnkCsvPath" -ForegroundColor Red
    Write-Host "[!] Run LECmd first: LECmd.exe -d 'C:\Users' --csv 'C:\Cases\Output' --csvf lnk.csv -q" -ForegroundColor Yellow
    exit
}

# Import LNK data
Write-Host "[*] Loading LNK file data..." -ForegroundColor Yellow
$lnkData = Import-Csv $LnkCsvPath

# Filter for removable drives
$usbFiles = $lnkData | Where-Object { $_.DriveType -eq "Removable" -or $_.DriveType -eq "2" }

if ($usbFiles) {
    Write-Host "[*] Found $($usbFiles.Count) LNK files from removable drives" -ForegroundColor Green
    
    # Group by Volume Serial Number
    $byVsn = $usbFiles | Group-Object VolumeSerialNumber
    
    "=" * 80 | Out-File $OutputPath
    "USB DEVICE TO FILE ACCESS CORRELATION - $(Get-Date)" | Out-File $OutputPath -Append
    "=" * 80 | Out-File $OutputPath -Append
    
    foreach ($vsnGroup in $byVsn) {
        $vsn = $vsnGroup.Name
        $files = $vsnGroup.Group
        
        "`n--- Volume Serial Number: $vsn ---" | Out-File $OutputPath -Append
        "Total Files Accessed: $($files.Count)" | Out-File $OutputPath -Append
        "`nFiles:" | Out-File $OutputPath -Append
        
        Write-Host "`n--- Volume Serial Number: $vsn ---" -ForegroundColor Yellow
        Write-Host "Files accessed: $($files.Count)" -ForegroundColor Cyan
        
        $files | ForEach-Object {
            $entry = "  $($_.TargetCreated) | $($_.TargetPath)"
            Write-Host $entry -ForegroundColor Gray
            $entry | Out-File $OutputPath -Append
        }
    }
    
    Write-Host "`n[+] Correlation saved to: $OutputPath" -ForegroundColor Green
    
    # Summary by VSN
    Write-Host "`n[*] Summary by Volume Serial Number:" -ForegroundColor Yellow
    $byVsn | ForEach-Object {
        Write-Host "  VSN $($_.Name): $($_.Count) files" -ForegroundColor Cyan
    }
    
} else {
    Write-Host "[!] No LNK files from removable drives found" -ForegroundColor Red
}
```
{% endcode %}

***

**Step 6: Identify Drive Letter Assignments**

**Registry Location:** `SYSTEM\MountedDevices`

**Caveat:** Only shows LAST drive letter assignment (no historical record)

**PowerShell - Check Drive Letters:**

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Check USB drive letter assignments
#>

Write-Host "[+] Checking Drive Letter Assignments..." -ForegroundColor Cyan

$mountedDevices = "HKLM:\SYSTEM\MountedDevices"

if (Test-Path $mountedDevices) {
    $props = Get-ItemProperty $mountedDevices
    
    # Filter for DosDevices (drive letters)
    $props.PSObject.Properties | Where-Object { $_.Name -like "\DosDevices\*" } | ForEach-Object {
        $driveLetter = $_.Name -replace "\\DosDevices\\", ""
        $data = $_.Value
        
        # Try to extract serial number from data
        if ($data) {
            $dataString = [System.Text.Encoding]::Unicode.GetString($data)
            Write-Host "`n  Drive: $driveLetter" -ForegroundColor Yellow
            Write-Host "  Data: $($dataString -replace '\x00', '')" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "[!] MountedDevices key not found" -ForegroundColor Red
}
```
{% endcode %}

***

#### Complete USB Investigation Script

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Comprehensive USB Device Investigation
.DESCRIPTION
    Performs complete USB forensic analysis
#>

param(
    [string]$OutputPath = "C:\Cases\USB_Investigation"
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       USB DEVICE FORENSIC INVESTIGATION                   ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

# Helper function
function Convert-FileTimeToDateTime {
    param([byte[]]$FileTimeBytes)
    if ($FileTimeBytes.Length -ge 8) {
        try {
            $fileTime = [BitConverter]::ToInt64($FileTimeBytes, 0)
            return [DateTime]::FromFileTime($fileTime)
        } catch {
            return "Unable to parse"
        }
    }
    return "No data"
}

# ============================================================================
# 1. ENUMERATE USB DEVICES
# ============================================================================
Write-Host "[1/5] Enumerating USB Storage Devices..." -ForegroundColor Yellow
$devicesOutput = "$OutputPath\01_USB_Devices.txt"

"=" * 80 | Out-File $devicesOutput
"USB STORAGE DEVICES - $(Get-Date)" | Out-File $devicesOutput -Append
"=" * 80 | Out-File $devicesOutput -Append

$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

if (Test-Path $usbStorPath) {
    $deviceCount = 0
    
    Get-ChildItem $usbStorPath | ForEach-Object {
        $deviceKey = $_
        $deviceInfo = $_.PSChildName
        
        if ($deviceInfo -match "Disk&Ven_(.+)&Prod_(.+)&Rev_(.+)") {
            $vendor = $matches[1].Trim("_")
            $product = $matches[2].Trim("_")
            $revision = $matches[3].Trim("_")
            
            "`n--- Device #$($deviceCount + 1) ---" | Out-File $devicesOutput -Append
            "Vendor: $vendor" | Out-File $devicesOutput -Append
            "Product: $product" | Out-File $devicesOutput -Append
            "Revision: $revision" | Out-File $devicesOutput -Append
            
            # Get serial numbers
            Get-ChildItem $deviceKey.PSPath | ForEach-Object {
                $serial = $_.PSChildName
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                
                "`nSerial Number: $serial" | Out-File $devicesOutput -Append
                
                if ($serial.Length -ge 2 -and $serial[1] -eq '&') {
                    "  Type: Windows-Generated (Device lacks unique serial)" | Out-File $devicesOutput -Append
                } else {
                    "  Type: Device Unique Serial" | Out-File $devicesOutput -Append
                }
                
                if ($props.FriendlyName) {
                    "  Friendly Name: $($props.FriendlyName)" | Out-File $devicesOutput -Append
                }
                
                if ($props.ParentIdPrefix) {
                    "  ParentIdPrefix: $($props.ParentIdPrefix)" | Out-File $devicesOutput -Append
                }
            }
            
            $deviceCount++
        }
    }
    
    "`n`nTotal Devices: $deviceCount" | Out-File $devicesOutput -Append
    Write-Host "  [✓] Found $deviceCount USB devices" -ForegroundColor Green
} else {
    "[!] USBSTOR key not found" | Out-File $devicesOutput
    Write-Host "  [!] USBSTOR key not found" -ForegroundColor Red
}

# ============================================================================
# 2. EXTRACT CONNECTION TIMESTAMPS
# ============================================================================
Write-Host "[2/5] Extracting Connection Timestamps..." -ForegroundColor Yellow
$timestampsOutput = "$OutputPath\02_Connection_Timestamps.txt"

"=" * 80 | Out-File $timestampsOutput
"USB CONNECTION TIMESTAMPS - $(Get-Date)" | Out-File $timestampsOutput -Append
"=" * 80 | Out-File $timestampsOutput -Append

if (Test-Path $usbStorPath) {
    Get-ChildItem $usbStorPath | ForEach-Object {
        $deviceKey = $_
        
        Get-ChildItem $deviceKey.PSPath | ForEach-Object {
            $serialKey = $_
            $serial = $_.PSChildName
            
            $propsPath = Join-Path $serialKey.PSPath "Properties\{83da6326-97a6-4088-9453-a19231573b29}"
            
            if (Test-Path $propsPath) {
                "`n--- Serial: $serial ---" | Out-File $timestampsOutput -Append
                
                # First Install (0064)
                $firstInstall = Get-ItemProperty "$propsPath\0064" -Name "(default)" -ErrorAction SilentlyContinue
                if ($firstInstall) {
                    $time = Convert-FileTimeToDateTime $firstInstall.'(default)'
                    "First Install (UTC): $time" | Out-File $timestampsOutput -Append
                }
                
                # Last Connected (0066)
                $lastConnected = Get-ItemProperty "$propsPath\0066" -Name "(default)" -ErrorAction SilentlyContinue
                if ($lastConnected) {
                    $time = Convert-FileTimeToDateTime $lastConnected.'(default)'
                    "Last Connected (UTC): $time" | Out-File $timestampsOutput -Append
                }
                
                # Last Removal (0067)
                $lastRemoval = Get-ItemProperty "$propsPath\0067" -Name "(default)" -ErrorAction SilentlyContinue
                if ($lastRemoval) {
                    $time = Convert-FileTimeToDateTime $lastRemoval.'(default)'
                    "Last Removal (UTC): $time" | Out-File $timestampsOutput -Append
                }
            }
        }
    }
    
    Write-Host "  [✓] Timestamps extracted" -ForegroundColor Green
}

# ============================================================================
# 3. CHECK USER ATTRIBUTION
# ============================================================================
Write-Host "[3/5] Checking User Attribution (MountPoints2)..." -ForegroundColor Yellow
$userOutput = "$OutputPath\03_User_Attribution.txt"

"=" * 80 | Out-File $userOutput
"USER ATTRIBUTION - $(Get-Date)" | Out-File $userOutput -Append
"=" * 80 | Out-File $userOutput -Append

$mountPoints = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

if (Test-Path $mountPoints) {
    "`n--- Current User: $env:USERNAME ---" | Out-File $userOutput -Append
    
    $entries = Get-ChildItem $mountPoints
    
    if ($entries) {
        "Found $($entries.Count) mount points" | Out-File $userOutput -Append
        
        foreach ($entry in $entries) {
            $guid = $entry.PSChildName
            
            if ($guid -like "{*}") {
                "`n  Volume GUID: $guid" | Out-File $userOutput -Append
            }
        }
    } else {
        "No mount points found for current user" | Out-File $userOutput -Append
    }
} else {
    "MountPoints2 key not found" | Out-File $userOutput -Append
}

Write-Host "  [✓] User attribution checked" -ForegroundColor Green
Write-Host "  [!] For all users, analyze offline NTUSER.DAT hives" -ForegroundColor Yellow

# ============================================================================
# 4. CHECK DRIVE LETTER ASSIGNMENTS
# ============================================================================
Write-Host "[4/5] Checking Drive Letter Assignments..." -ForegroundColor Yellow
$driveOutput = "$OutputPath\04_Drive_Letters.txt"

"=" * 80 | Out-File $driveOutput
"DRIVE LETTER ASSIGNMENTS - $(Get-Date)" | Out-File $driveOutput -Append
"=" * 80 | Out-File $driveOutput -Append
"`n[!] Only shows LAST assignment (no historical)" | Out-File $driveOutput -Append

$mountedDevices = "HKLM:\SYSTEM\MountedDevices"

if (Test-Path $mountedDevices) {
    $props = Get-ItemProperty $mountedDevices
    
    "`nRemovable Drive Letters:" | Out-File $driveOutput -Append
    
    $props.PSObject.Properties | Where-Object { $_.Name -like "\DosDevices\[E-Z]:*" } | ForEach-Object {
        $driveLetter = $_.Name -replace "\\DosDevices\\", ""
        "  Drive: $driveLetter" | Out-File $driveOutput -Append
    }
}

Write-Host "  [✓] Drive letters checked" -ForegroundColor Green

# ============================================================================
# 5. CHECK SETUPAPI.DEV.LOG
# ============================================================================
Write-Host "[5/5] Checking setupapi.dev.log..." -ForegroundColor Yellow
$setupapiOutput = "$OutputPath\05_Setupapi_Log.txt"

"=" * 80 | Out-File $setupapiOutput
"SETUPAPI.DEV.LOG ANALYSIS - $(Get-Date)" | Out-File $setupapiOutput -Append
"=" * 80 | Out-File $setupapiOutput -Append
"`n[!] WARNING: Timestamps are in LOCAL TIMEZONE (not UTC)" | Out-File $setupapiOutput -Append

$setupapiPath = "C:\Windows\inf\setupapi.dev.log"

if (Test-Path $setupapiPath) {
    $content = Get-Content $setupapiPath -Tail 100
    
    "`nLast 100 lines:" | Out-File $setupapiOutput -Append
    $content | Out-File $setupapiOutput -Append
    
    Write-Host "  [✓] setupapi.dev.log saved (last 100 lines)" -ForegroundColor Green
} else {
    "[!] setupapi.dev.log not found" | Out-File $setupapiOutput
    Write-Host "  [!] setupapi.dev.log not found" -ForegroundColor Red
}

# ============================================================================
# GENERATE SUMMARY
# ============================================================================
$summaryOutput = "$OutputPath\00_INVESTIGATION_SUMMARY.txt"

@"
╔════════════════════════════════════════════════════════════════════════════╗
║              USB DEVICE INVESTIGATION SUMMARY                              ║
╚════════════════════════════════════════════════════════════════════════════╝

Investigation Date: $(Get-Date)
Computer: $env:COMPUTERNAME
Analyst: $env:USERNAME

ANALYSIS PERFORMED:
────────────────────────────────────────────────────────────────────────────
[✓] USB Device Enumeration (USBSTOR)
[✓] Connection Timestamps (Properties keys, 0064/0066/0067)
[✓] User Attribution (MountPoints2 - current user)
[✓] Drive Letter Assignments (MountedDevices)
[✓] setupapi.dev.log Analysis

OUTPUT FILES:
────────────────────────────────────────────────────────────────────────────
01_USB_Devices.txt           → All USB devices ever connected
02_Connection_Timestamps.txt → First/last connection times
03_User_Attribution.txt      → User mount points (current user only)
04_Drive_Letters.txt         → Drive letter assignments
05_Setupapi_Log.txt          → Setup log (last 100 lines)

CRITICAL NEXT STEPS:
────────────────────────────────────────────────────────────────────────────
1. Parse LNK files with LECmd to get Volume Serial Numbers:
   LECmd.exe -d "C:\Users" --csv "$OutputPath" --csvf lnk.csv -q

2. Filter LNK CSV for DriveType = "Removable" to find USB file access

3. Correlate Volume Serial Number (VSN) from:
   - Event ID 1006 (Microsoft-Windows-Partition/Diagnostic.evtx)
   - EMDMgmt registry key (if available)
   - LNK files (VolumeSerialNumber column)

4. Match VSN to USB device to prove file access

5. For all users' MountPoints2, load offline NTUSER.DAT hives:
   reg load "HKU\TempUser" "C:\Users\[username]\NTUSER.DAT"
   reg query "HKU\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

6. Build complete timeline:
   - USB connected (timestamps)
   - Files accessed (LNK files)
   - USB disconnected (timestamps)

KEY INVESTIGATION PRINCIPLES:
────────────────────────────────────────────────────────────────────────────
→ Volume Serial Number (VSN) is THE KEY to linking USB to files
→ VSN != USB Unique Serial (different identifiers!)
→ setupapi.dev.log timestamps are LOCAL timezone (not UTC!)
→ Only last drive letter assignment stored (no historical)
→ MountPoints2 proves user accessed specific USB (per-user attribution)
→ Windows 10/11 stores up to 1 year of USB data

TOOLS REQUIRED:
────────────────────────────────────────────────────────────────────────────
✓ LECmd.exe (LNK file parser) - CRITICAL for VSN extraction
✓ Registry Explorer - For offline registry analysis
✓ USBDeview - Alternative GUI tool

Download: https://ericzimmerman.github.io/

════════════════════════════════════════════════════════════════════════════
"@ | Out-File $summaryOutput

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║            INVESTIGATION COMPLETE                          ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host "`nResults: $OutputPath" -ForegroundColor Cyan
Write-Host "Review: 00_INVESTIGATION_SUMMARY.txt`n" -ForegroundColor Yellow

Write-Host "[!] CRITICAL NEXT STEP: Parse LNK files for file access evidence" -ForegroundColor Red
Write-Host "    Command: LECmd.exe -d 'C:\Users' --csv '$OutputPath' --csvf lnk.csv -q`n" -ForegroundColor White
```
{% endcode %}

***

### Real Investigation Scenarios

#### Scenario 1: Data Exfiltration via USB

**Evidence Chain:**

```bash
1. USBSTOR: Kingston USB 32GB connected
2. Timestamps: First connected 2024-11-29 14:23 UTC
3. MountPoints2: Alice's account has Volume GUID entry
4. LECmd: 50 LNK files with DriveType="Removable", VSN=1A2B-3C4D
5. LNK files: HR_Salaries_2024.xlsx, Customer_Database.sql
6. Timestamps: Last removal 2024-11-29 15:45 UTC
7. Recycle Bin: Original files deleted after USB copy

CONCLUSION: Alice copied sensitive files to USB, then deleted originals
```

**Timeline:**

```bash
14:23 - USB connected (USBSTOR timestamp 0066)
14:30 - Files accessed from C:\ (Recent Files)
14:35 - Files copied to USB (LNK with VSN=1A2B-3C4D)
14:40 - Original files deleted (Recycle Bin)
15:45 - USB disconnected (USBSTOR timestamp 0067)
```

***

#### Scenario 2: Unauthorised Device Usage

**Evidence Chain:**

```bash
1. USBSTOR: Unknown brand "Generic USB" (suspicious)
2. Serial: Has & in 2nd position = Windows-generated (no unique serial)
3. Timestamps: Connected 02:30 AM (off-hours)
4. MountPoints2: Bob's account accessed device
5. LECmd: malware.exe accessed from USB (VSN=9876-5432)
6. Prefetch: malware.exe executed shortly after

CONCLUSION: Unauthorised USB containing malware used by Bob
```

***

#### Scenario 3: VSN Correlation Success

**Investigation Steps:**

```bash
1. Find LNK file: secret_document.xlsx.lnk
2. Extract VSN from LNK: AB12-CD34
3. Search EMDMgmt or Event 1006 for VSN=AB12-CD34
4. Match to Kingston USB serial XXXXX
5. Check USBSTOR timestamps for that serial
6. Check MountPoints2 for user attribution

RESULT: Proved file accessed from specific USB device by specific user
```

***

### Quick Reference Commands

#### Registry Queries

```cmd
REM USB devices
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"

REM Connection timestamps
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven*" /s

REM User mount points
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

REM Drive letters
reg query "HKLM\SYSTEM\MountedDevices"

REM Volume serial numbers (legacy)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt"
```

#### PowerShell One-Liners

{% code overflow="wrap" %}
```powershell
# List USB devices
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | ForEach-Object {$_.PSChildName}

# Current user mount points
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" | Select-Object PSChildName

# Event 1006 (last 20)
Get-WinEvent -Path "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Partition%4Diagnostic.evtx" -FilterXPath "*[System[EventID=1006]]" -MaxEvents 20 | Select-Object TimeCreated, Message
```
{% endcode %}

***

### Investigation Checklists

#### USB Data Exfiltration Investigation

* \[ ] Enumerate all USB devices (USBSTOR)
* \[ ] Extract connection timestamps (Properties 0064/0066/0067)
* \[ ] Identify Windows-generated serials (& in 2nd position)
* \[ ] Check MountPoints2 for user attribution
* \[ ] Parse LNK files with LECmd
* \[ ] Filter LNK for DriveType = "Removable"
* \[ ] Extract Volume Serial Numbers from LNK files
* \[ ] Correlate VSN to USB device
* \[ ] Build timeline: connect → access → disconnect
* \[ ] Check for file deletion (Recycle Bin)
* \[ ] Cross-reference with Recent Files registry
* \[ ] Document complete evidence chain

#### Unauthorised Device Investigation

* \[ ] Identify unknown/suspicious devices (USBSTOR)
* \[ ] Check connection times (off-hours indicator)
* \[ ] Verify authorised device list
* \[ ] Check user attribution (MountPoints2)
* \[ ] Look for malware/suspicious files (LNK + Prefetch)
* \[ ] Review execution artifacts (Prefetch, BAM)
* \[ ] Check for policy violations
* \[ ] Document user and device details

#### Timeline Construction

* \[ ] Extract all timestamp sources (0064/0066/0067)
* \[ ] Parse setupapi.dev.log (LOCAL timezone!)
* \[ ] Parse Event 1006 (if available)
* \[ ] Extract LNK file access times
* \[ ] Correlate all timestamps in single timeline
* \[ ] Note timezone differences
* \[ ] Build narrative of events

***

### USB Forensics Tools

#### Essential Tools

**Zimmerman Tools:**

* **LECmd** - LNK file parser (CRITICAL for VSN extraction)
* **Registry Explorer** - Offline registry analysis
* **Timeline Explorer** - Timeline visualisation

**NirSoft:**

* **USBDeview** - GUI USB device viewer
* **USBLogView** - setupapi.dev.log parser

**Microsoft:**

* **Registry Editor** - Live registry queries
* **Event Viewer** - Event 1006 analysis

***

### Best Practices

#### Live Response

✅ **DO:**

* Collect registry hives (SYSTEM, SOFTWARE, NTUSER.DAT)
* Copy setupapi.dev.log immediately
* Export Event 1006 before it's cleared
* Collect all LNK files from all users
* Document current time and timezone
* Hash all collected artifacts

❌ **DON'T:**

* Plug in your own USB (creates new entries!)
* Modify registry during investigation
* Forget timezone differences (setupapi = LOCAL)
* Skip LNK file collection (VSN source!)

***

#### Offline Analysis

✅ **DO:**

* Load registry hives read-only
* Parse all user NTUSER.DAT files
* Correlate VSN across all sources
* Cross-reference with LNK files
* Build complete timeline
* Validate all correlations

❌ **DON'T:**

* Rely on single artifact
* Skip VSN correlation
* Ignore setupapi timezone
* Forget about Windows-generated serials

***

### Summary: Critical Takeaways

#### The Most Important Concept

**Volume Serial Number (VSN) is THE KEY:**

```bash
USB Device → VSN assigned → Files accessed → LNK created with VSN
VSN in LNK file = VSN from USB = PROOF of file access from that USB
```

#### Key Differences to Remember

| Serial Type                    | Purpose                 | Where Found               |
| ------------------------------ | ----------------------- | ------------------------- |
| **USB Unique Serial**          | Identifies physical USB | USBSTOR registry          |
| **Volume Serial Number (VSN)** | Identifies file system  | **LNK files, Event 1006** |
| **Printed Serial**             | Marketing label         | Physical device           |

#### Top 5 USB Investigation Steps

1. **USBSTOR** - Identify devices connected
2. **Timestamps** - When connected (0064/0066/0067)
3. **MountPoints2** - Who accessed device
4. **VSN** - Extract from LNK files
5. **Correlation** - Match VSN to prove file access

#### Critical Registry Paths

{% code overflow="wrap" %}
```bash
Device Identity:
SYSTEM\CurrentControlSet\Enum\USBSTOR\{Device}\{Serial}

Timestamps:
SYSTEM\CurrentControlSet\Enum\USBSTOR\{Device}\{Serial}\Properties\{83da6326-...}\0064|0066|0067

User Attribution:
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

VSN (Legacy):
SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt
```
{% endcode %}

#### Key Principle

**USB forensics requires correlation of multiple artifacts. The Volume Serial Number (VSN) from LNK files is your most reliable evidence linking a USB device to specific file access. Always cross-reference USBSTOR, timestamps, MountPoints2, and LNK files to build complete evidence chain.**

***

**Remember:** Volume Serial Number (VSN) is THE critical link between USB devices and files accessed. Extract VSN from LNK files (DriveType=Removable) and correlate with USB device records. This proves which files were accessed from which USB device!
