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

# Registry Analysis

The Windows registry contains information that is helpful during a forensic analysis. It is an excellent source for evidential data, and knowing the type of information that could possibly exist in the registry and its location is critical during the forensic analysis process.

## <mark style="color:blue;">Recent opened Programs/Files/URLs</mark>

{% code overflow="wrap" %}
```atom
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU
```
{% endcode %}

**MRU** is the abbreviation for the most frequently used. This key maintains a list of recently opened or saved files via Windows Explorer-style dialogue boxes (Open/Save dialogue box). For instance, files (e.g. .txt, .pdf, htm, .jpg) that are recently opened or saved files from within a web browser are maintained. _Documents that are opened or saved via Microsoft Office programs are not maintained._ Whenever a new entry is added to the **OpenSaveMRU** key, the  registry value is created or updated in

{% code overflow="wrap" %}
```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
```
{% endcode %}

This key correlates to the previous **OpenSaveMRU** key to provide extra information: each binary registry value under this key contains a recently used program executable filename and the folder path of a file to which the program has been used to open or save it.

The list of files recently opened directly from **Windows Explorer** is stored into

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

This key corresponds to **%USERPROFILE%Recent** (_My Recent Documents_) and contains local or network files that are recently opened and only the filename in binary form is stored.

## <mark style="color:blue;">Start>Run</mark>

The list of entries executed using the **Start>Run** command is maintained in this key:

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

If a file is executed via the Run command, it will leave traces in the previous two keys, OpenSaveMRU and RecentDocs. _Deleting the subkeys in RunMRU does not remove the history list in the Run command box immediately._ Content of RunMRU Key: Using the Windows “Recent Opened Documents” Clear List feature via **Control Panel**>T**askbar and Start Menu**, an attacker can remove the Run command history list. In fact, executing the Clear List function will remove the following registry keys and their subkeys:

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
```

## <mark style="color:blue;">UserAssist</mark>

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

This key contains two **GUID** subkeys: each subkey maintains a list of system objects such as program, shortcut, and control panel applets a user has accessed. Registry values under these subkeys are weakly encrypted using the ROT-13 algorithm, which basically substitutes a character with another character 13 positions away from it in the ASCII table.

### <mark style="color:blue;">Recent URLs</mark>

```cs
HKCU\Software\Microsoft\Internet Explorer\TypedURLs
```

This key contains a listing of 25 recent URLs (or file path) that is typed in the **Internet Explorer** (IE) or **Windows Explorer** address bar: the key will only show links that are fully typed, automatically completed while typing, or links that are selected from the list of stored URLs in IE address bar. _Websites that are accessed via IE Favourites are not recorded, and if the user clears the URL history using Clear History via IE Internet Options menu, this key will be completely removed._

### <mark style="color:blue;">Pagefile</mark>

```cs
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
```

This key maintains the configuration of Windows virtual memory: the paging file (usually **C:pagefile.sys**) may contain evidential information that could be removed once the suspect computer is shutdown.

This key contains a registry value called **ClearPagefileAtShutdown**, which specifies whether Windows should clear the paging file when the computer shuts down (by default, Windows does not clear the paging file). During a forensic analysis, _you should check this value before shutting down a suspect computer!_

### <mark style="color:blue;">Windows Search</mark>

```cs
HKCU\Software\Microsoft\Search Assistant\ACMru
```

This key contains recent search terms using Windows default search. There may be up to four subkeys:

* **5001**: Contains a list of terms used for the Internet Search Assistant
* **5603**: Contains the list of terms used for the Windows files and folders search
* **5604**: Contains a list of terms used in the “word or phrase in a file” search
* **5647**: Contains a list of terms used in the “for computers or people” search

### <mark style="color:blue;">Installed programs</mark>

All programs listed in **Control Panel**>**Add/Remove Programs** correspond to one subkey into this key:

```cs
HKLM\SOFTWARE\Microsoft\Windows\Current\Version\Uninstall
```

Subkeys usually contain these two common registry values:

* **DisplayName** — program name
* **UninstallString** — application Uninstall component’s file path, which indirectly refers to application installation path Other possible useful registry values may exist, which include information on install date, install source and application version.

### <mark style="color:blue;">Mounted drives</mark>

The list of mounted devices, with associated persistent volume names and unique internal identifiers for respective devices, is contained into

```cs
HKLM\SYSTEM\MountedDevices
```

This key lists any mounted volume and assigns a drive letter, including **USB** storage devices and external **DVD/CDROM** drives. From the listed registry values, the value’s name that starts with “DosDevices” and ends with the associated drive letter contains information regarding that particular mounted device. Similar information is also contained in:

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPCVolume
```

which is located under the respective device **GUID** subkey and in the binary registry value named Data. This key is a point of interest during a forensic analysis: the key records shares on remote systems such **C$**, **Temp$**, etc. _The existence of_ _**ProcDump**_ _indicates the dumping of credentials within lsass.exe address space. Sc.exe indicates the addition of persistence, such as Run keys or services. The presence of .rar files may indicate data exfiltration._

The history of recently mapped network drives is stored into

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
```

In addition, a permanent subkey (unless manually removed from the registry) regarding the mapped network drive is also created in

```cs
HKCU\Software\Microsoft\Windows\Current\VersionExplorer\MountPoints2
```

and the subkey is named in the form of **##servername#sharedfolder**.

### <mark style="color:blue;">USB Storage</mark>

The key:

```cs
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
```

Contains additional information about the list of mounted USB storage devices, including external memory cards. _When used in conjunction with two previous keys will provide evidential information._

### <mark style="color:blue;">Autorun</mark>

There are different keys related to the automatic running of programs.

```cs
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

This first key usually contains programs or component paths that are automatically run during system startup without requiring user interaction: malware usually leaves a trace in this key to be persistent whenever the system reboots.

### <mark style="color:blue;">RunServices and RunServicesOnce</mark>

Can control automatic startup of services. They can be assigned to a specific user account or to a computer:

```cs
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Services
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Services
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ServicesOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ServicesOnce
```

**Command Processor Autorun**

This key contains command that is automatically executed each time cmd.exe is run:

```cs
HKLM\SOFTWARE\Microsoft\Command Processor
HKCU\Software\Microsoft\Command Processor
```

Modification to this key requires administrative privilege. _Usually, malware exploits this feature to load itself without the user’s knowledge._

### <mark style="color:blue;">Winlogon</mark>

This key has a registry value named Shell with default data Explorer.exe.

```cs
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

Malware appends the malware executable file to the default value’s data to stay persistence across system reboots and logins (_modification to this key requires administrative privilege_).

### <mark style="color:blue;">Services</mark>

This key contains a list of Windows services:

```cs
HKLM\SYSTEM\CurrentControlSet\Services
```

Each subkey represents a service and contains the service’s information, such as startup configuration and executable image path.

### <mark style="color:blue;">Debugging</mark>

This key allows an administrator to map an executable filename to a different debugger source, allowing the user to debug a program using a different program:

```cs
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

_Modification to this key requires administrative privilege._ This feature could be exploited to launch a completely different program under the cover of the initial program.

### <mark style="color:blue;">File extensions</mark>

This key contains instructions to execute any .exe extension file:

```cs
HKCR\exe\fileshell\opencommand
```

Normally, this key contains one default value with data “%1” %_. Still, if the value’s data is changed to something similar to somefilename.exe “%1” %_, the investigator should suspect another hidden program invoked automatically when the actual .exe file is executed. _Malware normally modifies this value to load itself covertly._ This technique applies to other similar keys, including:

```cs
HKEY_CLASSES_ROOT\batfile\shell\open\command
HKEY_CLASSES_ROOT\comfile\shell\open\command
```

### <mark style="color:blue;">Windows Protect Storage</mark>

**Protected Storage** is a service used by **Microsoft** products to provide a secure area to store private information. Information that could be stored in Protected Storage includes, for example, Internet Explorer AutoComplete strings and passwords, Microsoft Outlook and Outlook Express accounts’ passwords. **Windows Protected Storage** is maintained under this key:

```cs
HKCU\Software\Microsoft\Protected Storage System Provider
```

_Registry Editor hides these registry keys from users viewing, including administrators._

## <mark style="color:blue;">Windows Registry Enumeration</mark>

### Operating System Information

```cs
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion"
```

### Product Name

```cs
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName
```

### Installation Date

```cs
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v InstallDate
```

### Registered Name

```cs
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner
```

### System Boot Information

```cs
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v SystemRoot
```

### Timezone Information (in minutes from UTC)

{% code overflow="wrap" %}
```cs
reg query "HKLM\System\CurrentControlSet\Control\TimeZoneinformation" /v ActiveTirneBias
```
{% endcode %}

### Map of Network Drivers

{% code overflow="wrap" %}
```cs
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
MRU
```
{% endcode %}

### Mounted Devices

```cs
reg query "HKLM\System\MountedDevices"
```

### USB Devices

```cs
reg query "HKLM\System\CurrentControlSet\Enum\USBStor"
```

### Password keys LSA secret cat certain vpn, autologon, other passwords

```cs
reg query "HKEY LOCAL MACHINE\Security\Policy\Secrets"
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\autoadminlogon"
```

### Capture Startup Applications

{% code overflow="wrap" %}
```cs
reg query "hklm\software\wow6432node\microsoft\windows\currentversion\run
reg query "hklm\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query "hklm\software\wow6432node\microsoft\windows\currentversion\runonce
reg query "hkcu\software\wow6432node\microsoft\windows\currentversion\run
reg query "hkcu\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query "hkcu\software\wow6432node\microsoft\windows\currentversion\runonce
```
{% endcode %}

### Kernel and User Services

```cs
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion"
```

### Software Installed in the System

```cs
reg query "HKLM\Software"
```

### Installed Software for the User

```cs
reg query "HKCU\Software"
```

### Latest Documents

```cs
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
```

### The Last Positions of the User

{% code overflow="wrap" %}
```cs
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedtmu" & \Opensavetmu
```
{% endcode %}

### URLs Typed

```cs
reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"
```

### MRU Lists

```cs
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
```

### The Last Registry Key Used

```cs
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\RegEdit" /v LastKeY
```

### <mark style="color:blue;">Launch Paths</mark>

```cs
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" & \Runonce
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" & \Runonce
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load" & \Run
```

### <mark style="color:blue;">Activation of Remote Desktop</mark>

{% code overflow="wrap" %}
```cs
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server"
Set-ItemProperty -Path 'HKLM\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```
{% endcode %}

### Important Registry Keys

There are many other registry keys of interest, the following are some of those keys:

{% code overflow="wrap" %}
```cs
reg query "hkcu\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "hkcu\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains"
reg query "hklm\Software\Microsoft\Windows NT\CurrentVersion\Windows"
reg query "hklm\Software\Microsoft\Windows\CurrentVersion\policies\system"
reg query "hklm\Software\Microsoft\Active Setup\Installed Components"
reg query "hklm\Software\Microsoft\Windows\CurrentVersion\App Paths"
reg query "hklm\software\microsoft\windows nt\CurrentVersion\winlogon"
reg query "hklm\software\microsoft\security center\svc"
reg query "hkcu\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
reg query "hkcu\Software\Microsoft\Windows\CurrentVersion\explorer\RunMru"
reg query "hklm\Software\Microsoft\Windows\CurrentVersion\explorer\Startmenu"
reg query "hklm\System\CurrentControlSet\Control\Session Manager"
reg query "hklm\Software\Microsoft\Windows\CurrentVersion\explorer\Shell Folders"
reg query "hklm\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
reg query "hklm\System\CurrentControlSet\Control\Session Manager\AppCertDlls"
reg query "hklm\ Software \Classes\exefile\shell\open\command"
reg query "hklm\BCD00000000"
reg query "hklm\system\currentcontrolset\control\lsa"
reg query "hklm\ Software \Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
reg query "hklm\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
reg query "hkcu\Software\Microsoft\Internet Explorer\Extensions"
reg query "hklm\Software\Microsoft\Internet Explorer\Extensions"
reg query "hklm\Software\Wow6432Node\ Microsoft\Internet Explorer\Extensions"
```
{% endcode %}
