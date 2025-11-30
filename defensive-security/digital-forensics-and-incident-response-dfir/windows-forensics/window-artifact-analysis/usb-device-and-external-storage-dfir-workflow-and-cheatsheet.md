# USB Device & External Storage - DFIR Workflow & Cheatsheet

## Quick Reference: Investigation Priority Matrix

| Priority   | Artifact                  | Key Questions Answered          | Persistence | OS Version |
| ---------- | ------------------------- | ------------------------------- | ----------- | ---------- |
| **HIGH**   | USBSTOR Registry          | What devices? When? Serial?     | High        | All        |
| **HIGH**   | LNK Files                 | What files accessed from USB?   | Very High   | All        |
| **HIGH**   | Connection Timestamps     | First/Last plug times?          | High        | Win7+      |
| **MEDIUM** | MountPoints2              | Which users accessed device?    | High        | All        |
| **MEDIUM** | Partition/Diagnostic Logs | Connect/Disconnect events?      | Medium      | Win7+      |
| **MEDIUM** | setupapi.dev.log          | First connection time?          | Low         | All        |
| **MEDIUM** | Volume Serial Number      | Link device to files?           | Medium      | Varies     |
| **LOW**    | Windows Portable Devices  | Last drive letter? Volume name? | Medium      | Vista+     |
| **LOW**    | Event Logs                | Detailed activity?              | Low         | All        |

***

## Investigation Workflow

## Phase 1: USB Device Identification (Critical Priority)

**Goal:** Identify all USB devices ever connected to the system

### **1.1 Primary USB Device Enumeration**

**What it tells you:** Vendor, Product, Version, Serial Number, First/Last Connection

**Registry Locations:**

**USBSTOR (Primary - Storage Devices):**

```bash
SYSTEM\CurrentControlSet\Enum\USBSTOR
```

**USB (All USB Devices):**

```bash
SYSTEM\CurrentControlSet\Enum\USB
```

**SCSI (Linked Storage):**

```bash
SYSTEM\CurrentControlSet\Enum\SCSI
```

**HID (Human Interface Devices):**

```bash
SYSTEM\CurrentControlSet\Enum\HID
```

**Key Structure:**

```bash
USBSTOR\
  Disk&Ven_<Vendor>&Prod_<Product>&Rev_<Version>\
    <SerialNumber>\
      Properties\{83da6326-97a6-4088-9453-a19231573b29}\
        0064 - First Install (Win7+)
        0066 - Last Connected (Win8+)  
        0067 - Last Removal (Win8+)
```

**Key Investigation Points:**

* ✓ **Vendor**: Manufacturer (SanDisk, Kingston, etc.)
* ✓ **Product**: Device model/type
* ✓ **Version**: Firmware revision
* ✓ **Serial Number**: Unique device identifier
* ⚠️ **"&" in 2nd character** = No unique serial (Windows-generated)
* ⚠️ **Internal serial ≠ printed label serial**
* ✓ **ParentIdPrefix**: Links USBSTOR → SCSI keys
* ✓ **Properties timestamps**: 64-bit FILETIME format

**Data Retention:**

```bash
Windows 10/11: Up to 1 year of data
Older systems: May vary by version
Legacy data: SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration
```

**Analysis Commands:**

**PowerShell - Enumerate USB Devices:**

```powershell
# Get all USBSTOR devices
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -Recurse |
    ForEach-Object {
        $path = $_.PSPath
        $name = $_.PSChildName
        if ($name -match "^Disk&Ven_(.+)&Prod_(.+)&Rev_(.+)") {
            [PSCustomObject]@{
                Vendor = $matches[1]
                Product = $matches[2]
                Revision = $matches[3]
                FullPath = $path
            }
        }
    } | Format-Table -AutoSize

# Get device serial numbers
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" |
    Select-Object @{N='SerialNumber';E={$_.PSChildName}},
                  @{N='DevicePath';E={$_.Name}} |
    Format-Table -AutoSize
```

**Registry Export for Analysis:**

```batch
REM Export USB device keys
reg export "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" USBSTOR.reg
reg export "HKLM\SYSTEM\CurrentControlSet\Enum\USB" USB.reg
reg export "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI" SCSI.reg
reg export "HKLM\SYSTEM\CurrentControlSet\Enum\HID" HID.reg
```

**Forensic Value:**

```bash
✓ Complete inventory of USB devices
✓ Device make/model identification
✓ Unique serial number (if available)
✓ First installation date (Win7+)
✓ Last connection date (Win8+)
✓ Last removal date (Win8+)
✓ Proof device was connected to THIS system
```

***

### **1.2 Connection Timestamps (First, Last, Removal)**

**What it tells you:** Precise timing of USB device usage

**Method 1: Registry Properties (Win7+)**

**Location:**

{% code overflow="wrap" %}
```bash
SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_&Prod_&Rev_\<SerialNumber>\Properties\{83da6326-97a6-4088-9453-a19231573b29}\

Property Keys:
0064 - First Install (Device Driver Installation) - Win7+
0066 - Last Connected - Win8+
0067 - Last Removal - Win8+
```
{% endcode %}

**Alternate Location (SCSI):**

{% code overflow="wrap" %}
```bash
SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_<Vendor>&Prod_<Product>\<USBSerial#>\Properties\{83da6326-97a6-4088-9453-a19231573b29}\

Same property keys: 0064, 0066, 0067
```
{% endcode %}

**Timestamp Format:** Windows 64-bit FILETIME (100-nanosecond intervals since 1601-01-01)

**PowerShell - Extract Timestamps:**

{% code overflow="wrap" %}
```powershell
# Function to convert FILETIME to readable date
function Convert-FileTime {
    param([byte[]]$bytes)
    if ($bytes.Length -eq 8) {
        $fileTime = [BitConverter]::ToInt64($bytes, 0)
        [DateTime]::FromFileTime($fileTime)
    }
}

# Get USB connection timestamps
$usbPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
Get-ChildItem $usbPath -Recurse | Where-Object {
    $_.PSPath -match "Properties.*83da6326"
} | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{
        DevicePath = $_.PSPath
        FirstInstall = if ($props.'0064') { Convert-FileTime $props.'0064' } else { "N/A" }
        LastConnected = if ($props.'0066') { Convert-FileTime $props.'0066' } else { "N/A" }
        LastRemoval = if ($props.'0067') { Convert-FileTime $props.'0067' } else { "N/A" }
    }
} | Format-Table -AutoSize
```
{% endcode %}

**Method 2: setupapi.dev.log (First Connection)**

**Location:**

```bash
C:\Windows\inf\setupapi.dev.log
```

**Key Investigation Points:**

* ✓ Text log file (searchable)
* ✓ Records Plug and Play driver installations
* ✓ **Timestamps in LOCAL TIME ZONE** (important!)
* ✓ Search by device serial number
* ✓ Shows first time device was ever connected

**Analysis Command:**

```powershell
# Search for specific USB serial number
Select-String -Path "C:\Windows\inf\setupapi.dev.log" `
    -Pattern "<SERIAL_NUMBER>" -Context 5,5

# Extract all USB device installations
Select-String -Path "C:\Windows\inf\setupapi.dev.log" `
    -Pattern "Device Install.*USB" |
    Select-Object LineNumber, Line
```

**Method 3: Partition/Diagnostic Event Log (All Connections)**

**Location:**

```bash
%SYSTEMROOT%\System32\winevt\logs\Microsoft-Windows-Partition%4Diagnostic.evtx
```

**Key Investigation Points:**

* ✓ **Event ID 1006**: Device connect/disconnect events
* ✓ Includes connect time, disconnect time
* ✓ May include VBR data with Volume Serial Number
* ⚠️ **Log cleared during major OS updates**
* ✓ Available Win7+

**PowerShell - Parse Event Log:**

{% code overflow="wrap" %}
```powershell
# Extract USB connection events
Get-WinEvent -Path "C:\Windows\System32\winevt\logs\Microsoft-Windows-Partition%4Diagnostic.evtx" |
    Where-Object {$_.Id -eq 1006} |
    Select-Object TimeCreated, Message |
    Format-List

# Export to CSV
Get-WinEvent -Path "C:\Windows\System32\winevt\logs\Microsoft-Windows-Partition%4Diagnostic.evtx" |
    Where-Object {$_.Id -eq 1006} |
    Export-Csv "USB_Connections.csv" -NoTypeInformation
```
{% endcode %}

**Forensic Value:**

```bash
✓ First installation = First time ever connected
✓ Last connected = Most recent connection
✓ Last removal = When device was unplugged
✓ Timeline of all connect/disconnect events
✓ Proof of temporal device usage
```

***

## Phase 2: Device-to-User Attribution (High Priority)

**Goal:** Identify which user accounts accessed the USB device

### **2.1 User MountPoints2 (Per-User USB Access)**

**What it tells you:** Which users had the USB device connected while logged in

**Location (Per User):**

```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

Live Path (per user):
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
```

**Investigation Workflow:**

#### **Step 1: Get Device Volume GUID from MountedDevices**

```bash
SYSTEM\MountedDevices
```

#### **Step 2: Match Volume GUID in User's MountPoints2**

```bash
If Volume GUID exists in MountPoints2:
  → User was logged in when device was connected
  → User account has access to USB device
```

**PowerShell - User Attribution:**

{% code overflow="wrap" %}
```powershell
# Step 1: Get all Volume GUIDs from MountedDevices
$mountedDevices = Get-ItemProperty "HKLM:\SYSTEM\MountedDevices"

# Step 2: Check each user's MountPoints2
$users = Get-ChildItem "C:\Users" -Directory
foreach ($user in $users) {
    $ntuser = "C:\Users\$($user.Name)\NTUSER.DAT"
    if (Test-Path $ntuser) {
        # Load user hive (requires admin)
        reg load "HKU\TempUser" $ntuser 2>$null
        
        $mountPoints = Get-ChildItem "Registry::HKU\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -ErrorAction SilentlyContinue
        
        if ($mountPoints) {
            Write-Host "User: $($user.Name)" -ForegroundColor Cyan
            $mountPoints | ForEach-Object { 
                Write-Host "  Volume GUID: $($_.PSChildName)"
            }
        }
        
        # Unload hive
        reg unload "HKU\TempUser" 2>$null
    }
}
```
{% endcode %}

**RegRipper Analysis:**

```batch
REM Extract MountPoints2 from each user
rr.exe -r "C:\Users\Alice\NTUSER.DAT" -p mountpoints2

REM Process all user hives
for /D %U in (C:\Users\*) do (
    rr.exe -r "%U\NTUSER.DAT" -p mountpoints2 >> MountPoints_All_Users.txt
)
```

**Forensic Value:**

```bash
✓ Attribution: Which specific user accounts accessed USB
✓ Proves user was logged in during device connection
✓ Multiple users = shared device access
✓ Timestamp: Last Write Time of MountPoints2 key
```

***

## Phase 3: Drive Letter & Volume Identification (Medium Priority)

**Goal:** Determine drive letter assignment and volume name

### **3.1 Last Drive Letter Assignment**

**What it tells you:** Last drive letter (E:, F:, etc.) assigned to USB device

**Location 1: MountedDevices (Primary)**

```bash
SYSTEM\MountedDevices
```

**Key Investigation Points:**

* ✓ Maps drive letters to Volume GUIDs and Serial Numbers
* ✓ Only shows LAST device mapped to each drive letter
* ⚠️ **No historical records** (only current/last mapping)
* ✓ Value names: `\DosDevices\E:`, `\DosDevices\F:`, etc.
* ✓ Value data contains device serial number

**PowerShell - Extract Drive Letters:**

```powershell
# Get all drive letter mappings
$mountedDevices = Get-ItemProperty "HKLM:\SYSTEM\MountedDevices"

$mountedDevices.PSObject.Properties | Where-Object {
    $_.Name -match "\\DosDevices\\"
} | ForEach-Object {
    $driveLetter = $_.Name -replace '.*\\DosDevices\\', ''
    $serialData = $_.Value
    
    # Convert byte array to readable format
    $serialHex = ($serialData | ForEach-Object { $_.ToString("X2") }) -join " "
    
    [PSCustomObject]@{
        DriveLetter = $driveLetter
        SerialData = $serialHex
    }
} | Format-Table -AutoSize
```

**Location 2: Windows Portable Devices (Volume Name)**

```bash
SOFTWARE\Microsoft\Windows Portable Devices\Devices
```

**Key Investigation Points:**

* ✓ Contains friendly device names
* ✓ Volume labels and device descriptions
* ✓ Match serial numbers to get volume name

**Location 3: VolumeInfoCache (Windows Search)**

```bash
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache
```

**Key Investigation Points:**

* ✓ Volume label (friendly name)
* ✓ Device type information
* ✓ Last mount time

**Forensic Value:**

```bash
✓ Drive letter at time of use (correlates with file paths)
✓ Volume name (helps identify specific device)
✓ User-friendly device identification
⚠️ Only last assignment available (no history)
```

***

## Phase 4: Volume Serial Number (VSN) Analysis

**Goal:** Link USB device to specific files via VSN

### **4.1 Volume Serial Number Extraction**

**What it tells you:** File system VSN (NOT device unique serial)

**Understanding VSNs:**

```bash
USB Unique Serial Number:  Hardware-based, in device firmware
Volume Serial Number (VSN): File system-based, assigned at format time
                            NOT the same as unique serial!
                            Used in LNK files and shell items
```

**Method 1: EMDMgmt Registry (Legacy)**

**Location:**

```bash
SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt
```

**Extraction Process:**

```bash
1. Find key matching Volume Name + USB Unique Serial Number
2. Locate last integer number in matching line
3. Convert decimal value to hexadecimal = VSN
```

**Key Investigation Points:**

* ⚠️ **Often missing on modern SSD systems**
* ✓ Useful for older systems
* ✓ Links device serial to VSN

**Method 2: Partition/Diagnostic Event Log (Win10+)**

**Location:**

```bash
%SYSTEMROOT%\System32\winevt\logs\Microsoft-Windows-Partition%4Diagnostic.evtx
```

**Key Investigation Points:**

* ✓ **Event ID 1006** may include VBR data
* ✓ VSN embedded in Volume Boot Record (VBR)
* ✓ VSN location in VBR:
  * **FAT**: Offset 0x43 (4 bytes)
  * **exFAT**: Offset 0x64 (4 bytes)
  * **NTFS**: Offset 0x48 (4 bytes)
* ⚠️ Log cleared during major OS updates

**PowerShell - Extract VSN from Event:**

{% code overflow="wrap" %}
```powershell
# Get Event 1006 with VBR data
Get-WinEvent -Path "C:\Windows\System32\winevt\logs\Microsoft-Windows-Partition%4Diagnostic.evtx" |
    Where-Object {$_.Id -eq 1006} |
    ForEach-Object {
        $message = $_.Message
        if ($message -match "Serial Number: ([0-9A-F]+)") {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                VolumeSerial = $matches[1]
                FullMessage = $message
            }
        }
    } | Format-Table -AutoSize
```
{% endcode %}

**Method 3: LNK File Extraction (Most Reliable)**

```bash
LNK files contain VSN of source drive
Extract VSN from LNK files of files accessed from USB
(See LNK Files section below)
```

**Forensic Value:**

```bash
✓ Correlate USB device to specific files
✓ Link LNK files to specific USB device
✓ Match shell items in registry
✓ Prove file originated from specific device
✓ Timeline correlation (VSN in multiple artifacts)
```

***

## Phase 5: File Access Evidence (Critical Priority)

**Goal:** Identify specific files accessed from USB device

### **5.1 LNK (Shortcut) Files Analysis**

**What it tells you:** Files opened from USB, even if deleted

**Primary Locations:**

```bash
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\
```

**LNK File Naming Convention:**

```bash
Pre-Win10: supersecretfile.xlsx.lnk
  - Opening new file overwrites existing LNK

Win10+: supersecretfile.xlsx.lnk, supersecretfile.txt.lnk
  - Extensions prevent overwriting
  - Each file extension gets unique LNK
```

**Key Investigation Points:**

* ✓ **Persists after target file deletion** (high value!)
* ✓ .lnk extension hidden in Windows Explorer
* ✓ Only latest access recorded per filename
* ✓ Created automatically when file opened

**LNK File Metadata (Embedded):**

```bash
✓ Target file path (original location)
✓ Target file size
✓ Target file timestamps (Created, Modified, Accessed)
✓ Volume Information:
  - Volume Type (Fixed, Removable, Network)
  - Volume Serial Number (VSN)
  - Volume Label/Name
✓ Network Share information (if applicable)
✓ System name where target stored
✓ MAC address (sometimes)
✓ File attributes (read-only, hidden, archive, etc.)
```

**LNK File Timestamps:**

```bash
Creation Time of LNK = First time file of that name opened
Modification Time of LNK = Last time file of that name opened
```

**Analysis Commands:**

**Basic Directory Listing:**

```batch
REM Display LNK modification time (last accessed)
dir "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\*.lnk"

REM Display LNK creation time (first accessed)
dir /tc "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\*.lnk"

REM Show all details
dir /ta /tc "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\*.lnk"
```

**ExifTool Analysis:**

{% code overflow="wrap" %}
```batch
REM Extract all metadata from LNK file
exiftool "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\document.docx.lnk"

REM Process all LNK files
exiftool -csv "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" > lnk_analysis.csv
```
{% endcode %}

**LECmd (Eric Zimmerman) - Comprehensive Parsing:**

**Single File:**

{% code overflow="wrap" %}
```batch
LECmd.exe -f "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\document.docx.lnk"

LECmd.exe -f "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\users.lnk" --csv "C:\Cases\Output"
```
{% endcode %}

**Directory of Files:**

{% code overflow="wrap" %}
```batch
LECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent" --csv "C:\Cases\LnkFiles" -q

LECmd.exe -d "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent" --all --csv "C:\Cases\Output"
```
{% endcode %}

**Entire System (All Users):**

```batch
LECmd.exe -d "C:\Users" --csv "C:\Cases\AllUsers_LNK" --csvf AllUsers_LNK.csv
```

**PowerShell - Find USB-Related LNK Files:**

{% code overflow="wrap" %}
```powershell
# Search for LNK files with removable drive paths (E:, F:, etc.)
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        $linkPath = $_.FullName
        # Use LECmd or parse manually
        Write-Host "Found: $linkPath"
    }
```
{% endcode %}

**Forensic Value:**

```bash
✓ Files accessed from USB device (by path)
✓ Volume Serial Number (links to specific USB)
✓ Timeline: When file first/last accessed
✓ File metadata even if file deleted
✓ System name (if file on network)
✓ Proof of file existence
✓ User attribution (LNK in user profile)
✓ MAC address correlation (network shares)
```

**USB-Specific Investigation:**

```bash
1. Parse all LNK files with LECmd
2. Filter for Volume Type = "Removable"
3. Extract Volume Serial Numbers
4. Match VSN to USB device (via Event Log or EMDMgmt)
5. List all files accessed from each USB device
6. Create timeline of USB file access
```

***

## Phase 6: System Context (Supporting Priority)

**Goal:** Establish system configuration and timeline context

### **6.1 Operating System Version**

**What it tells you:** OS type, version, installation dates, update history

**Location:**

```bash
SOFTWARE\Microsoft\Windows NT\CurrentVersion
SYSTEM\Setup\Source OS
```

**CurrentVersion Key Data:**

```bash
ProductName       - OS type (Windows 10 Pro, Windows 11 Enterprise, etc.)
EditionID         - Edition identifier
DisplayVersion    - User-facing version (22H2, 23H2, etc.)
ReleaseId         - Release identifier
CurrentBuildNumber - Build number (19045, 22621, etc.)
InstallTime       - Installation time of CURRENT build (not original!)
```

**Source OS Keys (Update History):**

```bash
Created for each major OS update:
ProductName, EditionID    - OS type
BuildBranch, ReleaseId    - Version info
CurrentBuildNumber        - Build number
InstallTime               - When this build was installed
```

**Key Investigation Points:**

* ✓ **InstallTime** in key name is extraneous (ignore)
* ✓ **InstallTime value** = actual installation time
  * Win10+: 64-bit FILETIME format
  * Older: Unix 32-bit epoch format
* ✓ Helps determine system age
* ✓ Explains artifact availability (Win7 vs Win10 vs Win11)

**PowerShell - Extract OS Info:**

{% code overflow="wrap" %}
```powershell
# Current OS version
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" |
    Select-Object ProductName, EditionID, DisplayVersion, CurrentBuildNumber, InstallTime

# Historical updates
Get-ChildItem "HKLM:\SYSTEM\Setup\Source OS" |
    ForEach-Object {
        Get-ItemProperty $_.PSPath |
            Select-Object ProductName, BuildBranch, CurrentBuildNumber, InstallTime
    }
```
{% endcode %}

**Forensic Value:**

```bash
✓ Determines which USB artifacts available
✓ Explains data retention (Win10/11 = 1 year)
✓ Timeline context for system updates
✓ Artifact location changes per OS version
```

***

### **6.2 Computer Name**

**What it tells you:** System hostname

**Location:**

```bash
SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName

Value: ComputerName
```

**Key Investigation Points:**

* ✓ Facilitates correlation with logs
* ✓ Network activity attribution
* ✓ Multi-system investigation
* ✓ Matches hostname in LNK files

**PowerShell:**

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"

# Or simply:
$env:COMPUTERNAME
hostname
```

***

### **6.3 System Last Shutdown Time**

**What it tells you:** When system was last powered off

**Location:**

```bash
SYSTEM\CurrentControlSet\Control\Windows

Value: ShutdownTime (64-bit FILETIME)
```

**Shutdown Count (Windows XP Only):**

```
SYSTEM\CurrentControlSet\Control\Watchdog\Display

Value: Shutdown count
```

**PowerShell:**

{% code overflow="wrap" %}
```powershell
# Get last shutdown time
$shutdownBytes = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Windows").ShutdownTime
$shutdownTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($shutdownBytes, 0))
Write-Host "Last Shutdown: $shutdownTime"

# Alternative: Event Log method
Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074,6006,6008} -MaxEvents 10 |
    Select-Object TimeCreated, Message | Format-List
```
{% endcode %}

**Forensic Value:**

```bash
✓ Detect unusual shutdown patterns
✓ User behaviour analysis
✓ System availability timeline
✓ Correlate with USB removal times
```

***

### **6.4 System Boot & Autostart Programs**

**What it tells you:** Programs that run at boot/login (persistence mechanisms)

**Locations:**

**User-Level Autostart:**

```bash
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**System-Level Autostart:**

```bash
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Services:**

```bash
SYSTEM\CurrentControlSet\Services

If Start value = 0x02 → Service starts at boot
If Start value = 0x00 → Driver starts at boot
```

**Key Investigation Points:**

* ✓ Malware persistence detection
* ✓ Unauthorised program execution
* ✓ USB-based malware delivery
* ⚠️ Not exhaustive (many autorun locations exist)

**PowerShell - Enumerate Autoruns:**

```powershell
# System Run keys
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# User Run keys (current user)
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Services set to auto-start
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" |
    Where-Object {$_.Start -eq 2 -or $_.Start -eq 0} |
    Select-Object PSChildName, Start, ImagePath
```

**RegRipper:**

```bash
rr.exe -r SYSTEM -p services
rr.exe -r SOFTWARE -p run
rr.exe -r NTUSER.DAT -p run
```

**Forensic Value:**

```bash
✓ Detect malware from USB devices
✓ Persistence mechanisms
✓ Unauthorised software
✓ Audit installed programs
```

***

## Phase 7: Event Log Correlation (Supporting Priority)

**Goal:** Detailed timeline from Windows Event Logs

### **7.1 System Event Log**

**Location:**

```bash
%SYSTEMROOT%\System32\winevt\logs\System.evtx
```

**Key Event IDs:**

```bash
20001 - Plug and Play driver install attempted
20003 - Plug and Play driver install attempted
```

**PowerShell:**

```powershell
Get-WinEvent -FilterHashtable @{
    Path='C:\Windows\System32\winevt\logs\System.evtx'
    ID=20001,20003
} | Select-Object TimeCreated, Message | Format-List
```

***

### **7.2 Security Event Log**

**Location:**

```bash
%SYSTEMROOT%\System32\winevt\logs\Security.evtx
```

**Key Event IDs:**

```bash
4663 - Attempt to access removable storage object
4656 - Failure to access removable storage object  
6416 - New external device recognised on system
```

**Key Investigation Points:**

* ⚠️ **Depends on audit settings** (may not be enabled)
* ✓ Detailed access attempts
* ✓ Failed access (permissions issues)
* ✓ Device recognition events

**PowerShell:**

```powershell
Get-WinEvent -FilterHashtable @{
    Path='C:\Windows\System32\winevt\logs\Security.evtx'
    ID=4663,4656,6416
} | Select-Object TimeCreated, Message | Format-List
```

***

### **7.3 Partition/Diagnostic Event Log (Already Covered)**

**Location:**

```bash
%SYSTEMROOT%\System32\winevt\logs\Microsoft-Windows-Partition%4Diagnostic.evtx
```

**Key Event ID:**

```bash
1006 - Device connect/disconnect (most important for USB!)
```

***

#### Phase 8: Cloud Sync & OneDrive (Modern Systems)

**Goal:** Identify cloud-synced files that may have USB origin

**8.1 OneDrive Integration**

**What it tells you:** OneDrive sync status, file metadata, cloud storage

**Installation & Enablement:**

* ✓ Installed by default on Windows 8+
* ✓ Must be enabled by user authentication
* ✓ Requires Microsoft Cloud account

**Default Local Storage Locations:**

```bash
Personal: %USERPROFILE%\OneDrive
Business: %USERPROFILE%\OneDrive - <CompanyName>
```

**Registry Configuration:**

```bash
NTUSER\Software\Microsoft\OneDrive\Accounts\<Personal | Business1>

Contains: Actual local file storage location
```

**Metadata Locations:**

**SyncDiagnostics Log:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Local\Microsoft\OneDrive\logs\<Personal | Business1>\SyncDiagnostics.log
```
{% endcode %}

**SyncEngine ODL Logs:**

```bash
%USERPROFILE%\AppData\Local\Microsoft\OneDrive\logs\<Personal | Business1>\*.odl
```

**User CID File:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Local\Microsoft\OneDrive\settings\<Personal | Business1>\<UserCid>.dat
```
{% endcode %}

**Key Investigation Points:**

* ✓ **Critical**: Always check registry for actual storage location
* ✓ Metadata files only exist if OneDrive enabled
* ✓ SyncDiagnostics.log may contain file metadata
* ⚠️ Some files only stored in cloud (not local)
* ✓ Deleted items: Recycle bin for 30 days (personal) / 93 days (business)
* ✓ OneDrive for Business: Unified Audit Logs = 90 days of activity

**PowerShell - Check OneDrive Status:**

{% code overflow="wrap" %}
```powershell
# Check if OneDrive enabled per user
$users = Get-ChildItem "C:\Users" -Directory
foreach ($user in $users) {
    $oneDrivePath = "C:\Users\$($user.Name)\AppData\Local\Microsoft\OneDrive"
    if (Test-Path $oneDrivePath) {
        Write-Host "User: $($user.Name) - OneDrive Enabled" -ForegroundColor Green
        
        # Check for sync logs
        $logs = Get-ChildItem "$oneDrivePath\logs" -Recurse -Filter "SyncDiagnostics.log" -ErrorAction SilentlyContinue
        if ($logs) {
            Write-Host "  Sync logs found: $($logs.Count)"
        }
    }
}
```
{% endcode %}

**USB to OneDrive Scenario:**

```bash
1. User copies files from USB to local OneDrive folder
2. OneDrive syncs to cloud
3. Local file may be deleted but remains in cloud
4. SyncDiagnostics.log may show file metadata
5. LNK files point to OneDrive local path
6. Check cloud recycle bin for deleted items
```

**Forensic Value:**

```bash
✓ Files copied from USB may sync to cloud
✓ Deleted local files may persist in cloud recycle bin
✓ Sync logs provide file metadata
✓ 30-93 day recycle bin retention
✓ Business accounts: 90-day audit logs
✓ Cross-device sync complicates timeline
```

***

## Advanced Investigation Techniques

### Complete USB Device Timeline Reconstruction

**Step-by-Step Process:**

**1. Identify All Devices:**

```bash
- Parse USBSTOR\Enum\USB\SCSI registries
- Document: Vendor, Product, Version, Serial Number
- Export device list
```

**2. Extract All Timestamps:**

```bash
- Registry Properties: 0064 (First), 0066 (Last), 0067 (Removal)
- setupapi.dev.log: First installation
- Partition/Diagnostic.evtx: All connections (Event 1006)
- Compile master device timeline
```

**3. Determine Drive Letter Assignment:**

```bash
- Check SYSTEM\MountedDevices
- Match serial number to drive letter
- Note: Only last assignment available
```

**4. Extract Volume Serial Number:**

```bash
- Method 1: EMDMgmt registry (if available)
- Method 2: Event 1006 VBR data
- Method 3: LNK files (most reliable)
- Document VSN for each device
```

**5. User Attribution:**

```bash
- For each user NTUSER.DAT:
  - Check MountPoints2 for Volume GUIDs
  - Match to devices in MountedDevices
- Document: User X accessed Device Y
```

**6. File Access Analysis:**

```bash
- Parse all LNK files (LECmd)
- Filter by Volume Type = "Removable"
- Match Volume Serial Number to devices
- List files accessed per device per user
```

**7. Create Master Timeline:**

```bash
Combine:
- Device connection timestamps
- File access timestamps (LNK)
- Event log entries
- User login/logout times
- OneDrive sync activity (if applicable)
```

**8. Correlation & Analysis:**

```bash
- Map files to devices by VSN
- Identify sensitive file access
- Detect data exfiltration patterns
- Document evidence chain
```

***

## USB Device Identification Cheat Sheet

**Quick Device Info Extraction:**

```bash
Vendor: USBSTOR key path
Product: USBSTOR key path  
Serial: USBSTOR subkey name
ParentIdPrefix: USBSTOR\...\ParentIdPrefix value
SCSI Link: SCSI\...\<ParentIdPrefix>
DiskId: SCSI\...\Partmgr\DiskId
Drive Letter: MountedDevices (last only)
Volume Name: Windows Portable Devices
Volume Serial: EMDMgmt or Event 1006 or LNK files
First Install: Properties\...\0064
Last Connected: Properties\...\0066  
Last Removal: Properties\...\0067
Users: MountPoints2 per user NTUSER.DAT
```

***

### LNK File to USB Device Mapping

**Workflow:**

```bash
1. Parse LNK file with LECmd
2. Extract Volume Serial Number from LNK
3. Search for VSN in:
   - EMDMgmt registry
   - Event 1006 logs
   - Other LNK files
4. Match VSN to USB device serial number
5. Confirm with Volume Name correlation
6. Document: File X accessed from Device Y on Drive Z:
```

**LECmd CSV Output Columns of Interest:**

```bash
SourceFile: Path to LNK file
TargetPath: Original file location
VolumeSerialNumber: VSN (links to USB device)
VolumeLabel: Friendly name
DriveType: Removable = USB
FileSize: Target file size
TargetCreated: File creation time
TargetModified: File modification time
TargetAccessed: File access time
```

***

#### Cross-Artifact Correlation Matrix

| Artifact                  | Provides             | Links To              | Time Precision       |
| ------------------------- | -------------------- | --------------------- | -------------------- |
| USBSTOR                   | Device ID, Serial    | SCSI, MountedDevices  | Install/Last/Removal |
| Properties 0064/0066/0067 | Timestamps           | Device serial         | Precise (FILETIME)   |
| setupapi.dev.log          | First install        | Serial number         | Local timezone       |
| Event 1006                | All connections, VSN | Device, VSN, Timeline | Precise              |
| MountedDevices            | Drive letter, Serial | Device serial, GUID   | Last only            |
| MountPoints2              | User, GUID           | User, Device          | Key write time       |
| LNK Files                 | VSN, Files, Path     | Device via VSN        | Create/Modify        |
| EMDMgmt                   | VSN                  | Serial, VSN           | N/A                  |

***

## Investigation Checklists

#### Initial USB Triage Checklist

* \[ ] Identify all user accounts on system
* \[ ] Document system OS version and build
* \[ ] Record current date/time and timezone
* \[ ] Export SYSTEM registry hive
* \[ ] Export SOFTWARE registry hive
* \[ ] Export all user NTUSER.DAT files
* \[ ] Copy setupapi.dev.log
* \[ ] Copy Partition/Diagnostic.evtx
* \[ ] Copy System.evtx and Security.evtx
* \[ ] Collect all user Recent folders (LNK files)

#### USB Device Enumeration

* \[ ] Parse USBSTOR registry
* \[ ] Parse USB registry
* \[ ] Parse SCSI registry
* \[ ] Parse HID registry (peripherals)
* \[ ] Document all device serials
* \[ ] Check for "&" in serial (non-unique)
* \[ ] Extract ParentIdPrefix values
* \[ ] Cross-reference USBSTOR ↔ SCSI

#### Timestamp Extraction

* \[ ] Extract Properties 0064, 0066, 0067
* \[ ] Convert FILETIME to readable dates
* \[ ] Parse setupapi.dev.log (first install)
* \[ ] Extract Event 1006 from Partition log
* \[ ] Compile device timeline
* \[ ] Document timezone for all timestamps
* \[ ] Cross-validate timestamps

#### Drive Letter & Volume Analysis

* \[ ] Parse MountedDevices
* \[ ] Map drive letters to serials
* \[ ] Extract Windows Portable Devices
* \[ ] Get volume names/labels
* \[ ] Extract VSN from EMDMgmt (if present)
* \[ ] Extract VSN from Event 1006
* \[ ] Extract VSN from LNK files
* \[ ] Create VSN → Device mapping table

#### User Attribution

* \[ ] For each user NTUSER.DAT:
  * \[ ] Parse MountPoints2
  * \[ ] Extract Volume GUIDs
  * \[ ] Match to MountedDevices
  * \[ ] Document user → device access
* \[ ] Note MountPoints2 last write times
* \[ ] Identify shared device access

#### File Access Investigation

* \[ ] Collect all LNK files (all users)
* \[ ] Parse with LECmd to CSV
* \[ ] Filter for DriveType = "Removable"
* \[ ] Extract Volume Serial Numbers
* \[ ] Match VSNs to USB devices
* \[ ] List files per device per user
* \[ ] Extract file timestamps
* \[ ] Check for deleted file evidence

#### OneDrive Investigation (if applicable)

* \[ ] Check OneDrive enablement per user
* \[ ] Document local storage paths
* \[ ] Collect SyncDiagnostics.log
* \[ ] Review sync logs for USB files
* \[ ] Check cloud recycle bin (30-93 days)
* \[ ] Request Unified Audit Logs (Business)
* \[ ] Correlate USB file → Cloud sync

#### Event Log Analysis

* \[ ] Extract Event 20001, 20003 (System)
* \[ ] Extract Event 4663, 4656, 6416 (Security)
* \[ ] Extract Event 1006 (Partition/Diagnostic)
* \[ ] Create event timeline
* \[ ] Correlate with registry timestamps
* \[ ] Document all connect/disconnect events

#### Timeline & Reporting

* \[ ] Build master USB device timeline
* \[ ] Document first/last connection per device
* \[ ] List all files accessed per device
* \[ ] Map users to devices
* \[ ] Identify sensitive file access
* \[ ] Create evidence summary
* \[ ] Generate visual timeline
* \[ ] Prepare findings report

***

## Essential DFIR Tools

#### Registry Analysis

```bash
✓ RegRipper (rr.exe) - Automated USB parsing
✓ RegistryExplorer (Eric Zimmerman) - Manual browsing
✓ RECmd (Eric Zimmerman) - Batch processing
✓ Registry Viewer (AccessData)
```

#### LNK File Analysis

```bash
✓ LECmd (Eric Zimmerman) - Best LNK parser
✓ ExifTool - Metadata extraction
✓ LnkParse (Python) - Open-source
✓ Windows File Analyzer
```

#### Event Log Analysis

```bash
✓ Event Log Explorer - GUI viewer
✓ EvtxECmd (Eric Zimmerman) - CSV export
✓ PowerShell Get-WinEvent - Built-in
✓ LogParser - Microsoft tool
```

#### USB-Specific Tools

```bash
✓ USB Detective - Commercial USB forensics
✓ USB Historian - USB artifact parser
✓ USBDeview (NirSoft) - Live USB enumeration
✓ DeviceCleanup - Historical device listing
```

#### Comprehensive Suites

```bash
✓ KAPE - USB artifact collection targets
✓ Autopsy - USB device timeline module
✓ X-Ways Forensics - USB templates
✓ Magnet AXIOM - Full USB analysis
✓ FTK - Enterprise USB forensics
```

#### Timeline Tools

```bash
✓ Plaso/Log2Timeline - Super timeline
✓ TimelineExplorer (Zimmerman) - Timeline viewer
✓ DCode - Timestamp decoder
```

***

## Quick Command Reference

#### PowerShell USB Investigation Script

{% code overflow="wrap" %}
```powershell
<#
.SYNOPSIS
    Comprehensive USB Device Investigation Script
.DESCRIPTION
    Collects USB artifacts from Windows system
#>

# Set variables
$case = "USB-INVESTIGATION-2024"
$dest = "C:\Cases\$case"

# Create directory structure
New-Item -ItemType Directory -Path "$dest\Registry" -Force
New-Item -ItemType Directory -Path "$dest\LNK_Files" -Force
New-Item -ItemType Directory -Path "$dest\EventLogs" -Force
New-Item -ItemType Directory -Path "$dest\Logs" -Force

Write-Host "[+] Collecting USB Artifacts for Case: $case" -ForegroundColor Cyan

# 1. Export Registry Hives
Write-Host "[+] Exporting Registry Hives..." -ForegroundColor Yellow
reg export "HKLM\SYSTEM" "$dest\Registry\SYSTEM.reg" /y
reg export "HKLM\SOFTWARE" "$dest\Registry\SOFTWARE.reg" /y

# 2. Collect User NTUSER.DAT Files
Write-Host "[+] Collecting User Registry Hives..." -ForegroundColor Yellow
$users = Get-ChildItem "C:\Users" -Directory -Exclude "Public","Default*"
foreach ($user in $users) {
    $ntuser = "C:\Users\$($user.Name)\NTUSER.DAT"
    if (Test-Path $ntuser) {
        Copy-Item $ntuser "$dest\Registry\NTUSER_$($user.Name).DAT" -Force
    }
}

# 3. Collect LNK Files
Write-Host "[+] Collecting LNK Files..." -ForegroundColor Yellow
foreach ($user in $users) {
    $recentPath = "C:\Users\$($user.Name)\AppData\Roaming\Microsoft\Windows\Recent"
    $officePath = "C:\Users\$($user.Name)\AppData\Roaming\Microsoft\Office\Recent"
    
    if (Test-Path $recentPath) {
        Copy-Item "$recentPath\*.lnk" "$dest\LNK_Files\$($user.Name)_Recent\" -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $officePath) {
        Copy-Item "$officePath\*.lnk" "$dest\LNK_Files\$($user.Name)_Office\" -Force -ErrorAction SilentlyContinue
    }
}

# 4. Copy Event Logs
Write-Host "[+] Copying Event Logs..." -ForegroundColor Yellow
Copy-Item "C:\Windows\System32\winevt\logs\System.evtx" "$dest\EventLogs\" -Force
Copy-Item "C:\Windows\System32\winevt\logs\Security.evtx" "$dest\EventLogs\" -Force
Copy-Item "C:\Windows\System32\winevt\logs\Microsoft-Windows-Partition%4Diagnostic.evtx" "$dest\EventLogs\" -Force -ErrorAction SilentlyContinue

# 5. Copy setupapi.dev.log
Write-Host "[+] Copying setupapi.dev.log..." -ForegroundColor Yellow
Copy-Item "C:\Windows\inf\setupapi.dev.log" "$dest\Logs\" -Force

# 6. Enumerate Current USB Devices
Write-Host "[+] Enumerating USB Devices..." -ForegroundColor Yellow
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" -Recurse |
    Select-Object PSPath, PSChildName |
    Export-Csv "$dest\USB_Devices_Registry.csv" -NoTypeInformation

# 7. Generate Collection Report
Write-Host "[+] Generating Collection Report..." -ForegroundColor Yellow
$report = @"
USB Investigation Collection Report
====================================
Case: $case
Collection Date: $(Get-Date)
Computer Name: $env:COMPUTERNAME
OS Version: $((Get-WmiObject Win32_OperatingSystem).Caption)

Artifacts Collected:
- Registry Hives: SYSTEM, SOFTWARE, $(($users | Measure-Object).Count) user NTUSER.DAT files
- LNK Files: $(((Get-ChildItem "$dest\LNK_Files" -Recurse -Filter "*.lnk" | Measure-Object).Count)) files
- Event Logs: System, Security, Partition/Diagnostic
- Setup Logs: setupapi.dev.log
"@

$report | Out-File "$dest\Collection_Report.txt"

Write-Host "[+] Collection Complete!" -ForegroundColor Green
Write-Host "[+] Output Location: $dest" -ForegroundColor Green
```
{% endcode %}

#### Batch USB Parsing Script

{% code overflow="wrap" %}
```batch
@echo off
REM USB Artifact Parsing Script
REM Requires Eric Zimmerman Tools

set CASE=USB-INVESTIGATION-2024
set DEST=C:\Cases\%CASE%\Analysis
set TOOLS=C:\Tools\ZimmermanTools

mkdir "%DEST%"

echo [+] Parsing USB Artifacts...

REM Parse Registry with RegRipper
echo [+] Running RegRipper...
"%TOOLS%\rr.exe" -r "%DEST%\..\Registry\SYSTEM" -p usbstor > "%DEST%\USBSTOR_Analysis.txt"
"%TOOLS%\rr.exe" -r "%DEST%\..\Registry\SYSTEM" -p usbdevices > "%DEST%\USB_Devices.txt"

REM Parse LNK Files with LECmd
echo [+] Parsing LNK Files...
"%TOOLS%\LECmd.exe" -d "%DEST%\..\LNK_Files" --csv "%DEST%" --csvf USB_LNK_Files.csv -q

REM Parse Event Logs
echo [+] Parsing Event Logs...
"%TOOLS%\EvtxECmd.exe" -f "%DEST%\..\EventLogs\System.evtx" --csv "%DEST%" --csvf System_Events.csv
"%TOOLS%\EvtxECmd.exe" -f "%DEST%\..\EventLogs\Security.evtx" --csv "%DEST%" --csvf Security_Events.csv
"%TOOLS%\EvtxECmd.exe" -f "%DEST%\..\EventLogs\Microsoft-Windows-Partition%%4Diagnostic.evtx" --csv "%DEST%" --csvf Partition_Events.csv

echo [+] Analysis Complete!
echo [+] Results: %DEST%
pause
```
{% endcode %}

#### Timeline Creation with Plaso

{% code overflow="wrap" %}
```bash
# Create super timeline from collected artifacts
log2timeline.py --storage-file usb_timeline.plaso C:\Cases\USB-INVESTIGATION-2024\

# Filter for USB-related events
psort.py -o l2tcsv -w usb_timeline.csv usb_timeline.plaso "date > '2024-01-01'"

# Focus on specific event types
psort.py -o l2tcsv -w usb_events.csv usb_timeline.plaso "parser contains 'winreg' OR parser contains 'lnk'"
```
{% endcode %}

***

## Common Forensic Scenarios

### Scenario 1: Data Exfiltration via USB

**Investigation Steps:**

```bash
1. Identify all USB devices connected
   - Parse USBSTOR, extract serials
   - Focus on dates around incident

2. Determine user(s) who accessed device
   - Check MountPoints2 per user
   - Correlate with login times

3. Identify files copied to USB
   - Parse LNK files
   - Filter for removable volumes
   - Match VSN to device

4. Build timeline
   - Device connection time
   - File access times
   - File modification times
   - Device removal time

5. Document findings
   - User X accessed Device Y (Serial Z)
   - Files A, B, C copied to device
   - Timeline: Connected → Files Accessed → Removed
```

### Scenario 2: Unauthorised USB Device

**Investigation Steps:**

```bash
1. Enumerate all devices from USBSTOR
2. Compare against authorised device list
3. Check device first install time (Property 0064)
4. Identify user via MountPoints2
5. Review autorun programs (malware check)
6. Check LNK files for executed programs from USB
7. Review Event 6416 (new device recognised)
8. Document unauthorised access
```

### Scenario 3: Deleted File Recovery from USB

**Investigation Steps:**

```bash
1. Parse LNK files for USB device access
2. Extract VSN from LNK metadata
3. Match VSN to device serial
4. List all files accessed from that VSN
5. Check if files still exist locally
6. Review OneDrive sync (may be in cloud)
7. Check cloud recycle bin (30-93 days)
8. Attempt filesystem carving if device available
```

### Scenario 4: Malware Delivery via USB

**Investigation Steps:**

```bash
1. Identify suspicious USB device
2. Extract first install time
3. Check autorun programs added around that time
4. Review LNK files for executed programs
5. Check Event 20001/20003 (driver install)
6. Parse setupapi.dev.log
7. Review System boot programs
8. Correlate with AV logs
9. Document infection vector
```

***

## Investigation Gotchas & Notes

#### USB Device Serial Numbers

```bash
✓ "&" in 2nd position = Windows-generated (non-unique)
⚠️ Same device on different systems may have different serial
✓ Internal serial ≠ printed label serial
✓ Some devices share generic serials
```

#### Timestamps

```bash
✓ Registry Properties: 64-bit FILETIME (UTC)
✓ setupapi.dev.log: Local timezone (CRITICAL!)
✓ Event logs: Usually UTC, check log properties
⚠️ Always document timezone for all timestamps
```

#### Drive Letter Assignments

```bash
⚠️ Only LAST assignment stored (no history)
✓ Same device may get different letters over time
✓ Letters can be reassigned to different devices
✓ Use VSN for definitive device→file correlation
```

#### Volume Serial Numbers

```bash
⚠️ VSN ≠ USB Unique Serial Number
✓ VSN = File system serial (assigned at format)
✓ Formatting USB changes VSN
✓ VSN is THE key to link device→files
⚠️ EMDMgmt often missing on modern systems
✓ LNK files most reliable VSN source
```

#### LNK Files

```bash
✓ Persist after file deletion (HIGH VALUE!)
⚠️ Pre-Win10: Same filename overwrites LNK
✓ Win10+: Extension prevents overwriting
✓ .lnk extension always hidden in Explorer
✓ Only most recent access recorded per file
```

#### Event Logs

```bash
⚠️ Partition/Diagnostic log cleared on major updates
⚠️ Security events depend on audit policy
✓ System log usually reliable for USB events
✓ Logs can be cleared (check for gaps)
```

#### OneDrive

```bash
✓ Only enabled if user authenticated
⚠️ Some files only in cloud (not local)
✓ Deleted items: 30 days (personal), 93 days (business)
✓ Business: Unified Audit Logs = 90 days
⚠️ Sync complicates file origin determination
```

***

## Best Practices

#### Evidence Preservation

```bash
1. Use write-blocking for USB devices
2. Image USB device if available
3. Hash all artifacts before analysis
4. Work on copies, never originals
5. Document all collection steps
6. Preserve original timestamps
7. Maintain chain of custody
```

#### Analysis Methodology

```bash
1. Start with device identification
2. Extract all available timestamps
3. Correlate across multiple artifacts
4. Cross-reference registry → logs → LNK files
5. Build comprehensive timeline
6. Validate findings with multiple sources
7. Document all correlations
```

#### Reporting

```bash
1. Clear device identification (Make, Model, Serial)
2. Precise timeline with timezone
3. User attribution with evidence
4. File access documentation
5. Visual timeline when possible
6. Executive summary for non-technical audience
7. Technical appendix with tool output
```

***

**Critical Principles:**

* Volume Serial Number (VSN) is the key to linking devices to files
* Cross-artifact correlation is essential for accurate attribution
* Timestamps come from multiple sources with different precisions
* LNK files are the most reliable source for file access evidence
* Always document timezone for all timestamps
* User attribution requires MountPoints2 analysis

**Key Evidence Chain:** Device Serial → Drive Letter → VSN → LNK Files → Specific Files → User Attribution
