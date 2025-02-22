---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# External Device & USB Usage

### USB Device Identification

**Description:** Track USB devices plugged into a machine.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
SYSTEM\CurrentControlSet\Enum\USBSTOR
SYSTEM\CurrentControlSet\Enum\USB
SYSTEM\CurrentControlSet\Enum\SCSI
SYSTEM\CurrentControlSet\Enum\HID
```
{% endcode %}

**Interpretation:**

* Identify vendor, product, and version of a USB device plugged into a machine
* Determine the first and last times a device was plugged into the machine
* Devices that do not have a unique internal serial number will have an “&” in the second character of the serial number
* The internal serial number provided in these keys may not match the serial number printed on the device
* ParentIdPrefix links the USB key to SCSI key
* SCSI\<ParentIdPrefix>\Device Parameters\Partmgr\DiskId matches Partition/Diagnostic log and Windows Portable Devices key
* Different versions of Windows store this data for different amounts of time. Windows 10/11 can store up to one year of dat
* Some older data may be present in SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration
* HID key tracks peripherals connected to the system

### Drive Letter and Volume Name

**Description:** Discover a device's last drive letter and volume name when plugged into the system.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
SOFTWARE\Microsoft\Windows Portable Devices\Devices
SYSTEM\MountedDevices Examine available drive letter values looking for a serial number match in value data
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache
```
{% endcode %}

**Interpretation:**

* Only the last USB device mapped to a specific drive letter can be identified. Historical records are not available.

### User Information

**Description:** Identify user accounts tied to a unique USB Device.&#x20;

**Location:**

```cs
- Document device Volume GUID from SYSTEM\MountedDevices
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
```

**Interpretation:**

If a Volume GUID match is made within MountPoints2, we can conclude the associated user profile was logged in while that device was present.

### Connection Timestamps (First & Last Times)

**Description:** Connection timestamps determine the temporal usage of specific USB devices connected to a Windows Machine.&#x20;

**Location:**

**First-Time** Plug and Play Log Files

```cs
C:\Windows\inf\setupapi.dev.log
```

**Interpretation:**

* Search for Device Serial Number
* Log File times are set to local time zone Location First, Last, and Removal Times

{% code overflow="wrap" %}
```cs
SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_&Prod_\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####
 SYSTEM\CurrentControlSet\Enum\SCSI\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####
- 0064 = First Install (Win7+)
- 0066 = Last Connected (Win8+)
- 0067 = Last Removal (Win8+)
```
{% endcode %}

**Interpretation:**

Timestamps are stored in Windows 64-bit FILETIME format.

&#x20;**Location**:

Connection Times

```cs
%SYSTEM ROOT%\System32\winevt\logs\Microsoft-Windows-Partition/Diagnostic.evtx
```

**Interpretation:**

* Event ID 1006 is recorded for each device connect/disconnect
* Log cleared during major OS updates

### Volume Serial Number (VSN)

**Description:** Discover the VSN assigned to the file system partition on the USB. (NOTE: This is not the USB Unique Serial Number, which is hardcoded into the device firmware, nor the serial number on any external labels attached.)&#x20;

L**ocation:**

```cs
SOFTWARE\Microsoft\WindowsNT\CurrentVersion\EMDMgmt
```

* Find a key match using the Volume Name and USB Unique Serial Number:
* Find the last integer number in the matching line
* Convert decimal value to hex serial number
* This key is often missing from modern systems using SSD devices
* Win10+: %SYSTEM ROOT%\System32\winevt\logs\Microsoft-Windows-Partition/Diagnostic.evtx
* Event ID 1006 may include VBR data, which contains the VSN
* VSN is 4 bytes located at offsets 0x43 (FAT), 0x64 (exFAT), or 0x48 (NTFS) within each VBR
* Log cleared during major OS updates&#x20;

**Interpretation:**

&#x20;The VSN and device Volume Name can help correlate devices to specific files via shell items in LNK files and registry locations.

### Operating System Version

**Description:** This determines the operating system type, version, build number and installation dates for the current installation and previous updates.&#x20;

**Location:**

```cs
SOFTWARE\Microsoft\Windows NT\CurrentVersion
SYSTEM\Setup\Source OS
```

**Interpretation** :

CurrentVersion key stores:

* ProductName, EditionID – OS type
* DisplayVersion, ReleaseId, CurrentBuildNumber – Version info
* InstallTime – Installation time of current build (not original installation)

Source OS keys are created for each historical OS update:

* ProductName, EditionID – OS type
* BuildBranch, ReleaseId, CurrentBuildNumber – Version info
* InstallTime – Installation time of this build version
* Times present in names of Source OS keys are extraneous:
* InstallTime = 64-bit FILETIME format (Win10+)
* InstallDate = Unix 32-bit epoch format (both times should be equivalent)

### Computer Name

**Description:** This stores the hostname of the system in the ComputerName value.&#x20;

**Location:**

```cs
SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
```

**Interpretation:**

The hostname can facilitate the correlation of log data and other artefacts.

### System Boot & Autostart Programs

**Description**: System Boot and Autostart programs will run on system boot or at user login.&#x20;

**Location:**

```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SYSTEM\CurrentControlSet\Services
```

If the Start value is set to 0x02, then the service application will start at boot (0x00 for drivers)&#x20;

**Interpretation:**

* It is useful for finding malware and auditing installed software
* This is not an exhaustive list of autorun locations

### System Last Shutdown Time

**Description:** It is the last time the system was shutdown. On Windows XP, the number of shutdowns is also recorded.&#x20;

**Location:**

```cs
SYSTEM\CurrentControlSet\Control\Windows (Shutdown Time)
SYSTEM\CurrentControlSet\Control\Watchdog\Display (Shutdown Count – WinXP only)
```

**Interpretation**

* Determining the last shutdown time can help detect user behaviour and system anomalies
* Windows 64-bit FILETIME format

### Shortcut (LNK) Files

**Description:** Windows uses the folder _C:\Users%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent_ to store LNK files associated with files a user has recently accessed, typically by double-clicking on it in a Windows Explorer window.

If the file is reopened, it will be overwritten with the latest file access regardless of whether the file exists in a different directory.

In Windows 10 and later, Microsoft started adding the extension of the LNK file and preventing supersecretfile.xlsx from overwriting the LNK file for supersecretfile.txt.

Even so, it’s good to remember that only the latest open is recorded for a given file name. It is also important to note that LNK files persist in the Recent directory despite the file itself having been deleted. When viewing the directory in Windows Explorer, the .lnk extension is never shown, even when “show file extensions” is selected in the folder option.s

Windows automatically creates shortcut files, tracking files and folders a user opens.&#x20;

**Location:**

```cs
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\
```

Note these are the primary locations of LNK files. They can also be found in other locations.&#x20;

**Interpretation:**

* Date/Time file of that name was first opened
* Creation Date of Shortcut (LNK) File
* Date/Time file of that name was last opened
* Last Modification Date of Shortcut (LNK) File
* LNK Target File (Internal LNK File Information) Data:
* Modified, Access, and Creation times of the target file
* Volume Information (Name, Type, Serial Number)
* Network Share information
* Original Location
* Name of System&#x20;

**Tools for investigation:**

```cs
dir filename.xxx.lnk (display modification time)
dir/tc filename.xxx.lnk (display file creation time)
```

Exiftool :

```cs
ExifTool [filename.xxx.lnk](http://filename.xxx.lnk)
```

Parse with Zimmerman Tool (Link Explorer Commandline (LECmd)) Single file:

{% code overflow="wrap" %}
```cs
LECmd.exe -f C:\Users\angliad\AppData\Microsoft\Windows\Recent\Peggy.jpg.lnk
LECmd.exe -f c:\users\%username%\AppData\Roaming\Microsoft\Windows\Recent\users.lnk --csv <output-path>.csv
```
{% endcode %}

Directory of files:

{% code overflow="wrap" %}
```cs
LECmd.exe -d C:\Users\angliad\AppData\Microsoft\Windows\Recent --csv G:\LnkFiles -q
LECmd.exe -d "c:\users\%username%\AppData\Roaming\Microsoft\Windows\Recent" --all --csv <output-path>.csv
```
{% endcode %}

**Forensic Value:**

1. The path and size of the target file
2. Timestamps for both the target file and the LNK file
3. The attributes associated with the target file ( i. e. read-only, hidden, archive, etc
4. The system name, volume name, volume serial number, and sometimes the MAC address of the system where the target is stored
5. Files opened from a specific removable USB device
6. Identification of files which no longer exist on a local machine

### Event Logs

**Description:** Removable device activity can be audited in multiple Windows event logs. **Location**

```cs
%SYSTEM ROOT%\System32\winevt\logs\System.evtx
```

**Interpretation:**

* Event IDs 20001, 20003 – Plug and Play driver install attempted&#x20;

**Location:**

```cs
%SYSTEM ROOT%\System32\winevt\logs\Security.evtx
```

**Interpretation:**

* 4663 – Attempt to access removable storage object (Security log)
* 4656 – Failure to access removable storage object (Security log)
* 6416 – A new external device was recognized on the system (Security log)
* Security log events are dependent on system audit settings&#x20;

**Location Connection Times:**

```cs
%SYSTEM ROOT%\System32\winevt\logs\Microsoft-Windows-Partition/Diagnostic.evtx
```

**Interpretation:**

* Event ID 1006 is recorded for each device connect/disconnect

### OneDrive

**Description:** OneDrive is installed by default on Windows 8+ systems, although it must be enabled by a user authenticating to their Microsoft Cloud account before use.&#x20;

**Location:**

Default local file storage:

```cs
%USERPROFILE%\OneDrive (Personal)
%USERPROFILE%\OneDrive - <CompanyName> (Business)
```

File storage folder location info:

```cs
NTUSER\Software\Microsoft\OneDrive\Accounts\<Personal | Business1>
```

File metadata:

```cs
%USERPROFILE%\AppData\Local\Microsoft\OneDrive\logs\<Personal | Business1>
SyncDiagnostics.log
SyncEngine “odl” logs

%USERPROFILE%\AppData\Local\Microsoft\OneDrive\settings\<Personal | Business1>
<UserCid>.dat
```

**Interpretation:**

* It is critical to check the registry to confirm the local file storage location.
* Metadata files only exist if OneDrive is enabled
* SyncDiagnostics.log can sometimes contain file metadata
* Some files are only stored in the cloud and will not be stored locally
* Deleted items are stored in an online recycle bin for up to 30 days (personal) or 93 days (business)
* OneDrive for Business Unified Audit Logs in Microsoft 365 provide 90 days of user activity logging
