# External Device Usage

**Which** devices have connected to the host?

**What** are the names of the files and folders that have been accessed on the external device?

### USB Device Identification

#### **Description**

Track USB devices plugged into a machine.&#x20;

#### **Location**

{% code overflow="wrap" %}
```cs
SYSTEM\CurrentControlSet\Enum\USBSTOR
SYSTEM\CurrentControlSet\Enum\USB
SYSTEM\CurrentControlSet\Enum\SCSI
SYSTEM\CurrentControlSet\Enum\HID
```
{% endcode %}

#### **Interpretation**

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

**Location**

{% code overflow="wrap" %}
```cs
SOFTWARE\Microsoft\Windows Portable Devices\Devices
SYSTEM\MountedDevices Examine available drive letter values looking for a serial number match in value data
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache
```
{% endcode %}

**Interpretation**

* Only the last USB device mapped to a specific drive letter can be identified. Historical records are not available.

### User Information

**Description:** Identify user accounts tied to a unique USB Device.&#x20;

**Location:**

```cs
Document device Volume GUID from SYSTEM\MountedDevices
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
```

**Interpretation**

If a Volume GUID match is made within MountPoints2, we can conclude the associated user profile was logged in while that device was present.

### Connection Timestamps (First & Last Times)

#### **Description**

Connection timestamps are recorded when USB devices are connected to the Windows local host.&#x20;

**Location**

```cs
C:\Windows\inf\setupapi.dev.log
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\winevt\Logs
```

#### Caveats&#x20;

The timestamps are recorded in the local timezone

Forensic Analysis Tools&#x20;

* USBDView&#x20;
* Registry Explorer

**Forensic Value**

* Search for Device Serial Number
* Log File times are set to local time zone Location First, Last, and Removal Times
* USB device connection timestamps
* USB device connection history
* USB device serial number
* Last removal timestamp

{% code overflow="wrap" %}
```cs
SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_&Prod_\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####
 SYSTEM\CurrentControlSet\Enum\SCSI\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####
- 0064 = First Install (Win7+)
- 0066 = Last Connected (Win8+)
- 0067 = Last Removal (Win8+)
```
{% endcode %}

**Interpretation**

* Timestamps are stored in Windows 64-bit FILETIME format.

Location

Connection Times

```cs
%SYSTEM ROOT%\System32\winevt\logs\Microsoft-Windows-Partition/Diagnostic.evtx
```

**Interpretation**

* Event ID 1006 is recorded for each device connect/disconnect
* Log cleared during major OS updates

### Volume Serial Number (VSN)

**Description:** Discover the VSN assigned to the file system partition on the USB. (NOTE: This is not the USB Unique Serial Number, which is hardcoded into the device firmware, nor the serial number on any external labels attached.)&#x20;

L**ocation**

```cs
SOFTWARE\Microsoft\WindowsNT\CurrentVersion\EMDMgmt
```

* Find a key match using the volume name and USB unique serial number:
* Find the last integer number in the matching line
* Convert decimal value to hex serial number
* This key is often missing from modern systems using SSD devices
* Win10+: %SYSTEM ROOT%\System32\winevt\logs\Microsoft-Windows-Partition/Diagnostic.evtx
* Event ID 1006 may include VBR data, which contains the VSN
* VSN is 4 bytes located at offsets 0x43 (FAT), 0x64 (exFAT), or 0x48 (NTFS) within each VBR
* Log cleared during major OS updates&#x20;

**Interpretation**

The VSN and device volume name can help correlate devices to specific files via shell items in LNK files and registry locations.

USB Device Serial Number

```
SYSTEM\CurrentControlSet\Enum\USBStor
```

Volume Serial Number (as decimal)

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt
```

Associated User (with GUID)

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2
```

USB Device Vendor ID (VID) & Product ID (PID)

```
SYSTEM\CurrentControlSet\Enum\USB
```

Mounted Drive Letters

```
SYSTEM\MountedDevices
```

Connection Times

```
C:\Windows\inf\setupapi.dev.log
```

