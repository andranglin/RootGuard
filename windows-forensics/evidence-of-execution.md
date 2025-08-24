---
description: >-
  Prefetch, Amcache.hve, ShimCache, Shell Bags, Jump Lists, Recycle Bin, Master
  File Table ($MFT), $J, $LogFile, Alternate Data Streams (ADS), and Link File -
  Shortcut (.ink)
---

# Evidence of Execution

## Prefetch

**Description:** Prefetch is a performance optimization mechanism to reduce boot and application loading times. The cache manager can use these prefetch files like a cheatsheet to speed up the loading process. It is not enabled by default on Windows servers.

Prefetch provides evidence of the execution of applications, embedded within each prefetch file is the total number of times an application has been executed, the original path of execution, and the last time of execution. It increases the performance of a system by pre-loading code pages of commonly used applications. The cache monitors "helper files", recording them in a .pf file.

* Workstation operating systems (not servers) have prefetching on by default to improve performance.
* It lists up to 1024 files on Win8+.
* Prefetch files on win10 and 11 are compressed, with up to eight execution times available inside the Prefetch file. **To check the status of prefetching, open the following location in the Registry editor:**

{% code overflow="wrap" %}
```cs
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
- 0: Prefetching Disabled
- 1: Application Prefetching Enabled
- 2: Boot Prefetching Enabled
- 3: Application and Boot both Enabled
```
{% endcode %}

**Investigator Note: Look for multiple prefetch files with the same executable name; this would indicate two executables with the same name were run from different locations.** As an example, if you were to see multiple prefetch files for **cmd.exe,** it might indicate a file named **cmd.exe** was executed from somewhere outside of the standard **C:\Windows\System32** folder and that “new” **cmd.exe** might turn into a valuable finding!

Some exceptions to this rule are Windows “hosting” applications, such as **svchost, dllhost, backgroundtaskhost, and rundll32**, the hash value at the end of each prefetch file is calculated based on the full path and any command line arguments and therefore you are likely to see multiple prefetch files for each.

**Pro Tip:** Running live response tools on a target system will cause new prefetch files to be created for those live response executables. Plus, each system has a limited number of prefetch files, which can result in the deletion of the oldest prefetch files. Therefore, prioritise the collection of the prefetch directory to ensure important evidence isn't lost. **Location**

```cs
C:\Windows\Prefetch
```

Naming format: (exename)-(hash).pf

{% code overflow="wrap" %}
```cs
- SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
	-EnablePrefetcher value: (0 = disabled; 3 = application launch and boot enabled)
```
{% endcode %}

**Tools for Data Capture:**

PECmd.exe, WinPrefetchView .exe **Preferred tool** Prefetch Explorer Command Line (PECmd):&#x20;

Single file analysis:

{% code overflow="wrap" %}
```cs
.\PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf
.\PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf --csv "<path-to-working-directory>" --csvf <filename>.csv
```
{% endcode %}

Directory analysis:

```cs
.\PECmd.exe –d "C:\Windows\Prefetch"
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv
```

&#x20;Process a directory of Prefetch files, including VSS, and send the results to a file with higher precision timestamps

{% code overflow="wrap" %}
```cs
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv --vss --mp
```
{% endcode %}

Advance Usage: Using the comma-separated list of keywords will cause any hits to be shown in red.

{% code overflow="wrap" %}
```cs
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv -k "system32, downloads, fonts"
```
{% endcode %}

PECmd can extract and process files from Volume Shadow Copies using the “--vss” option. This will process Prefetch from ALL Volume Shadow Copies. The output files will be separated by individual VSS numbers.

```cs
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv --vss
```

FTK Imager

* Browse to "C:\Windows\Prefetch" **Available Metadata** The metadata that can be found in a single prefetch file is as follows:

{% code overflow="wrap" %}
```cs
- Executable’s name
- Eight character hash of the executable path.
- The path of the executable file
- Creation, modified, and accessed timestamp of executable
- Run count (Number of times the application has been executed)
- Last run time
- The timestamp for the last 8 run times (1 last run time and other 7 other last run times)
- Volume information
- File Referenced by the executable
- Directories referenced by the executable
- Each .pf file includes embedded data, including the last eight execution times, the total number of times executed, and device and file handles used by the program
```
{% endcode %}

**Prefetch Analysis and Interpretation:**

* Date/Time .exe was first executed
  * Creation date of .pf file (-10 seconds) Date/Time .exe was last executed
  * Modification date of .pf file (-10 seconds
    * The last time of execution is stored inside the .pf file as well
      * Windows 10/11 embeds the last eight execution times in the .pf file

**Pro Tip:** Just because a .pf was created, it does NOT mean that the program was successful in execution. Many “broken” programs that attempt execution will still be assigned a .pf file. **Forensic Value**

1. The executable's name
2. The absolute Path to the executable
3. The number of times that the program ran within the system
4. The last time the application ran
5. A list of DLLs used by the program

***

## Amcache.hve

**Description:** The Amcache.hve is a registry hive file that stores information related to the execution of programs when a user performs certain actions, such as running host-based applications, installing new applications, or running portable applications from external devices. It tracks installed applications, programs executed (or present), drivers loaded, and more. Amcache also tracks the SHA1 hash for executables and drivers.

**Investigator Note:** Amcache provides full path information, file size, publisher metadata for executables and loaded drivers, and several different timestamps. What sets this artifact apart from nearly all the others is it also tracks the **SHA1 hash** for executables and drivers. This is a rarity in forensic artifacts and can be of great value when trying to identify either known goods (e.g., Microsoft files) or known bad (e.g., a renamed version of mimikatz.exe). **Pro Tip: ShimCache is not a reliable source of application execution; it does not prove execution but can be used to prove the existence or presence of a file on the system.**

**Location:**

```cs
C:\Windows\AppCompat\Programs\Amcache.hve
```

**Interpretation:**

* A complete registry hive with multiple sub-keys
* Full path, file size, file modification time, compilation time, and publisher metadata
* SHA1 hash of executables and drivers Amcache should be used as an indication of executable and driver presence on the system, but not to prove actual execution

**Tools for investigation:**

Registry Explorer (Zimmerman Tools)

{% code overflow="wrap" %}
```cs
- File > Live System > Armcache.hve  (review the loaded registry hives, keys and subkeys)
```
{% endcode %}

Extract Amcache files: FTK Imager

{% code overflow="wrap" %}
```cs
File > Add Evidence Item > Physical Drive > Next > Select Drive > Finish
Next step: Navigate to the partition containing the OS , then Windows > appcompat > Programs
Next step: Select: Amcache.hive, Amcache.hive.LOG1, Amcache.hive.LOG2, then right-click and select Export Files > browse the storage location
Next, analyse with AmcacheParser
```
{% endcode %}

AmcacheParser (Zimmerman Tools)

{% code overflow="wrap" %}
```cs
.\AmcacheParser.exe -f "C:\User\username\Desktop\amcache\Amcache.hve" -i --csv C:\Users\username\Desktop\EvidenceFolder
```
{% endcode %}

For live systems:

{% code overflow="wrap" %}
```cs
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" -i --csv C:\Users\username\Desktop\EvidenceFolder
.\AmcacheParser.exe -f c:\Windows\AppCompat\Programs\Amcache.hve -b G:\Blacklist.txt --csv G:\Amcache
```
{% endcode %}

**Investigator Note:**

* Tracks installed applications, loaded drivers, and unassociated executables
* Full path, file size, file modification time, compilation time, publisher metadata
* SHA1 hashes of executables and drivers are one of the most exciting features
* Entries can also be due to automated file discovery or program installation and do NOT always indicate program execution. **Pro Tip:** Use this artifact as an indication of executable and driver presence on the system and the metadata it tracks for each file. Other artifacts (such as Prefetch) can be used to prove execution and execution times.

**Forensic Value:**

1. The executable names and full paths
2. Last executed time
3. The size of the binary and its version
4. The executable hash (SHA1)

***

## ShimCache

**Description:** Microsoft’s Application Compatibility Cache is designed to detect and remediate program compatibility challenges when a program launches. A program might have been built to work on a previous version of Windows. To avoid compatibility issues, Microsoft employs a subsystem allowing a program to invoke properties of different operating system versions. It Allows Windows to track executable files and scripts that may require special compatibility settings to run properly. It is maintained within kernel memory and serialized to the registry upon system shutdown or restart. **Investigator Note:** Windows uses this database to determine if a program needs shimming for compatibility. One of the more interesting and useful aspects of **AppCompatCache** is each executable is checked and added to the registry regardless of whether it needs to be shimmed. From a forensic perspective, we use information from the **AppCompatCache** to track application execution, including name, full path, and last modification time of the executable.

**Pro Tip: ShimCache in Win10 and later is not a reliable source of application execution; it does not prove execution but can be used to prove the existence or presence of a file on the system.**

**Location:**

**ShimCache** artifact source file is located at C:\Windows\System32\config\SYSTEM. Registry Key is located on a live system at:

```cs
HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache
```

**Investigator Note:** To determine the most recent controlset in use, in the SYSTEM folder, click Select > Current and review the value of the control

**Tools for investigation:**

AppCompatCacheParser (Zimmerman Tools)

{% code overflow="wrap" %}
```cs
.\AppCompatCacheParser.exe --csv c:\temp --csvf results.csv
.\AppCompatCacheParser.exe --csv "C:\Users\username\Desktop\Analysis\" --csvf Shimcache.csv
```
{% endcode %}

**Interpretation:**

Any executable present in the file system could be found in this key. Data can be particularly useful for identifying the presence of malware on devices where other application execution data is missing (such as Windows servers).

* Full path of the executable
* Windows 7+ contains up to 1,024 entries
* No execution time is available
* Executables can be preemptively added to the database before execution. The existence of an executable in this key does not prove actual execution.

**Tools for investigation:**

Shimcache Parser for a captured image:

{% code overflow="wrap" %}
```cs
.\AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv G:\AppCompatCache
```
{% endcode %}

**ShimCache Analysis and Interpretation:**

When reviewing the output from the **AppCompatCache**, note the following:

1. The most recent events are on top (which is very helpful since most versions don’t include execution time)
2. New entries are only written on shutdown. One of the most useful capabilities of the **AppCompatCache** is if an attacker has removed their tools from the system and was careful to also delete the corresponding prefetch (.pf) files, **AppCompatCache** entries might provide clues that the application existed.

**Investigator Notes:** the existence of an entry in the **AppCompatCache** registry key no longer proves execution. When investigating evidence of execution, the first challenge is getting the data. This can be accomplished by agent-based tools or via collection scripts. Analysis can begin by looking at well-known attack patterns. One or two-letter executable names, executions occurring from unusual folders such as the **$Recycle.Bin** or **System Volume Information** and searching common malware names like **pwdump** or **mimikatz** are all good starts. When attackers perform reconnaissance and live off the land, they will use built-in tools, but those tools might be rare in certain parts of the network. Searching for **psexec** activity, command-line WMI with **wmic.exe, reg.exe,** or **schtasks.exe** could pay dividends.

**Forensic Value:**

1. The executable or script file names and full paths
2. The standard information's last modified date
3. The size of the binary
4. Finally, whether the file ran on the system (just browsed through Explorer)

***

## Shell Bags

**Description:** Windows tracks and records user’s view settings and preferences while exploring folders. These view settings (size, view mode, position) of a folder window are stored in ShellBags registry keys. ShellBags keeps track of the view settings of a folder window once the folder has been viewed through Windows Explorer. ShellBags does not only track the view settings of a folder on the local machine but also on removable devices and network folders.s

**Location:**

Primary Data:

```cs
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags
USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
```

Residual Desktop Items and Network Shares:

```cs
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
```

**Interpretation:**

* Massive collection of data on folders accessed by each user
* Folder file system timestamps are archived in addition to the first and last interaction times
* “Exotic” items recorded like mobile device info, control panel access, and Zip archive access

**Tools For Investigation:**

SBECmd.exe , ShellBagsExplorer.exe , sbag64.exe

```cs
SQLECmd.exe -f "C:\Temp\someFile.db" --csv "c:\temp\out"
SQLECmd.exe -d "C:\Temp\" --csv "c:\temp\out"
SQLECmd.exe -d "C:\Temp\" --hunt --csv "c:\temp\out"
```

**Forensic Value:**

1. User’s navigation activity on the system
2. Timestamps analysis
3. Deleted folders
4. Folders accessed within the local machine
5. Folders accessed from removable devices
6. Folders accessed from network folders

***

## Jump Lists

**Description: Windows Jump Lists allow users to quickly access frequently or recently used items via the taskbar.** First introduced in Windows 7, they can identify applications in use and a wealth of metadata about items accessed via those applications.&#x20;

**Location and Structure of Jumplist Artifacts:**

In Windows systems, two types of Jump Lists can be created:

```cs
.automaticDestinations-ms (autoDest) files in AutomaticDestinations subdirectory.
.customDestinations-ms (custDest) files in CustomDestinations subdirectory.
```

Each file consists of 16-digit hexadecimal number which is the AppID (Application Identifier) followed by automaticDestinations-ms or customDestinations-ms extension. Note that these files are hidden, and navigating through Windows Explorer will not reveal them even if you turn on hidden items in Windows Explorer. They can be viewed by entering the full path in the Windows Explorer address bar. AutomaticDestinations: The AutomaticDestinations Jump List files are located in the following directory:

```cs
C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
```

These Jump List files are created automatically when the users open a file or an application. The files are Microsoft Compound File Binary (CFB) file format, also called OLE (Object Linking and Embedding) files. These files contain streams of individual hexadecimal numbered SHLLINK streams and a DestList stream. CustomDestinations: The CustomDestinations Jump List files are located in the following directory:

```cs
C:\%UserProfile%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations
```

These are custom-made Jump Lists, created when a user pins a file or an application to the Taskbar or Start Menu. These files' structure differs from AutomaticDestinations Jump List files; it follows a structure of sequential MS-SHLLINK binary format. **Location**

```cs
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
```

**Interpretation:**

* Each jump list file is named according to an application identifier (AppID). List of Jump List IDs -> https://dfi r.to/EZJumpList
* Automatic Jump List Creation Time = First time an item is added to the jump list. Typically, the first time an object is opened by the application.
* Automatic Jump List Modification Time = Last time item added to the jump list. Typically, the last time the application opened an object.&#x20;

**Tools for investigation:**&#x20;

Run against a single Jumplist and the output stored on the R: drive to the “Jumplists” folder

{% code overflow="wrap" %}
```cs
JLECmd.exe -f C:\Users\<username>\AppData\Microsoft\Windows\Recent\AutomaticDestinations\ff103e2cc310d0d.automaticDestinations-ms --csv R:\evidence\Jumplists -q
```
{% endcode %}

Against all automatic jumplist files stored for the user “Donald”.

{% code overflow="wrap" %}
```cs
JLECmd.exe -d E:\Users\username\AppData\Microsoft\Windows\Recent\AutomaticDestinations --csv G:\evidence\Jumplists -q
```
{% endcode %}

***

## Recycle Bin

**Description** When a user deletes a file, the file is moved into a temporary storage location for deleted files named Recycle Bin. Windows creates two files each time a file is placed in the Recycle Bin $I and $R with a string of six character identifiers generated for each file. $R file is a renamed copy of the “deleted” file. While the $I file replaces the usage INFO2 file as the source of accompanying metadata.&#x20;

**Location:**

Hidden System Folder

```cs
C:\$Recycle.Bin
```

**Interpretation:**

* Each user is assigned a SID sub-folder that can be mapped to a user via the Registry
* Win7+: Files preceded by $I###### contain original filename and deletion date/time
* Win7+: Files preceded by $R###### contain original deleted file contents Deleted Items and File Existence&#x20;

**Tools for investigation:**

Browse Recycle Bin:

* dir/a
  * cd $Recycle.Bin
    * dir/a
    * cd to SID of interest
    * dir
    * type $I\*\*\*\*\*\*.png (show original location of file)
    * copy $R\*\*\*\*\*\*.png \users\username\Desktop\filename.png (Copy file for further analysis)

Parse with Zimmerman Tool (RBCmd.exe)

{% code overflow="wrap" %}
```cs
RBCmd.exe -f \$Recycle.Bin\SID-Of-Interest\$Ifile-of-interest.png
RBCmd.exe -d C:\$Recycle.Bin\ -q --csv \Users\username\Desktop\ --csvf username-recycle-bin.csv
```
{% endcode %}

**Forensic Value:**

1. The original file name and path
2. The deleted file size
3. The date and time of deletion

***

## Master File Table ($MFT)

**Description:** A master file table is a database in which information about every file and directory on an NT File System (NTFS) volume is kept. An MFT will have a minimum one record for every file and directory on the NTFS logical volume. Moreover, each record contains attributes that tell the operating system how to handle the file or directory associated with the record.

**Location:**

```cs
NTFS/root/$MFT (Extracted from FTK
```

**Tools For Investigation:**

MFTECmd.exe, MFTExplorer .exe

```cs
MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out" --csvf MyOutputFile.csv
MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out"
```

**Forensic Value:**

1. Timeline Analysis
2. Information about a file or directory
3. File Type, Size
4. Date /Time when created, modified and accessed

***

## $J

**Description:** The $J data stream contains the contents of the change journal and includes information such as the date and time of the change, the reason for the change, the MFT entry, the MFT parent entry and others. This information can be useful for an investigation, for example, when the attacker deletes files and directories while he moves inside an organisation to hide his tracks.

**Location:**

```cs
NTFS/root/$Extend/$RmMetadata/$UsnJrnl/$J (Extracted from FTK)
```

**Tools For Investigation:**

MFTECmd.exe

```cs
MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out" --csvf MyOutputFile.csv
MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out"
MFTECmd.exe -f "C:\Temp\SomeMFT" --json "c:\temp\jsonout"
MFTECmd.exe -f "C:\Temp\SomeMFT" --body "c:\temp\bout" --bdl c
MFTECmd.exe -f "C:\Temp\SomeMFT" --de 5-5
```

**Forensic Value:**

1. Timeline Analysis
2. File Activity Analysis (Open, Close and Update
3. Evidence of renamed and deleted files

***

## $LogFile

**Description**: This file is stored in the MFT entry number 2; every time there is a change in the NTFS Metadata, a transaction is recorded in the $ LogFile. These transactions are recorded to make it possible to redo or undo file system operations. Why would $LogFile be important for investigation? Because the $LogFile records all operations in the NTFS volume, such as file creation, deletion, renaming, and copy.

**Location:**

```cs
NTFS/root/$LogFile (Extracted from FTK)
```

**Tools For Investigation:**

* NTFS\_Log\_Tracker.exe
* LogFileParser .exe

**Forensic Value:**

1. Timeline Analysis
2. File Activity Analysis (Open, Close and Update
3. Evidence of renamed and deleted files

***

## Alternate Data Streams (ADS)

**Destination: Alternate Data Streams (ADS) are file attributes only found on the NTFS file system to store different data streams.** The ability is to fork file data into existing files without affecting their functionality, size, or display to traditional file browsing utilities like dir or Windows Explorer. In addition to the default stream Zone. Identifier,” which is normally used for a file.

**Location:**

```cs
Within the same file! There is no specific path.
```

**Tools For Investigation:**

```cs
streams.exe 
Powershell.exe (Get-Item)
AlternateStreamView.exe
cmd.exe (dir / R)
```

**Forensic Value:**

1. Find the presence of a secret or malicious file inside the file record of an innocent file
2. Find hidden hacking toolkit
3. Find hidden files or information

***

## Link File - Shortcut (.ink)

**Description:** A shortcut file is a small file with information used to access or point to another file. Windows operating system automatically creates LNK files when users open a non-executable file or document. Windows creates these LNK files frequently and their creation is performed in the background without the user's explicit knowledge. Shortcut files are most often referred to as Link files by forensic analysts based on their .lnk file extension.

**Location:**

```cs
%USERPROFILE%\Recent
%USERPROFILE\Application\Data\Microsoft\Office\Recent
```

**Tools For Investigation:**

```cs
LECmd.exe -f "C:\Temp\foobar.lnk"
LECmd.exe -f "C:\Temp\somelink.lnk" --json "D:\jsonOutput" --pretty
LECmd.exe -d "C:\Temp" --csv "c:\temp" --html c:\temp --xml c:\temp\xml -q
LECmd.exe -f "C:\Temp\some other link.lnk" --nid --neb
LECmd.exe -d "C:\Temp" --all
```

**Forensic Value:**

1. The path and size of the target file
2. Timestamps for both the target file and the LNK file
3. The attributes associated with the target file (e.g. read-only, hidden, archive, etc
4. The system name, volume name, volume serial number, and sometimes the MAC address of the system where the target is stored
5. Files opened from a specific removable USB device
6. Identification of files which no longer exist on a local machine

***

## Shortcut (LNK) Files

**Description:** Windows uses the folder _C:\Users%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent_ to store LNK files associated with files a user has recently accessed, typically by double-clicking on it in a Windows Explorer window.

If the file is reopened, it will be overwritten with the latest file access regardless of whether the file exists in a different directory.

In Windows 10 and later, Microsoft started adding the extension of the LNK file and preventing supersecretfile.xlsx from overwriting the LNK file for supersecretfile.txt.

Even so, it’s good to remember that only the latest open is recorded for a given file name. It is also important to note that LNK files persist in the Recent directory despite the file itself having been deleted. When viewing the directory in Windows Explorer, the .lnk extension is never shown, even when “show file extensions” is selected in the folder options.

Windows automatically creates shortcut files, tracking files and folders a user opens.&#x20;

**Location:**

```cs
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\
```

Note: these are the primary locations of LNK files. They can also be found in other locations.&#x20;

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
LECmd.exe -f C:\Users\username\AppData\Microsoft\Windows\Recent\Peggy.jpg.lnk
LECmd.exe -f c:\users\%username%\AppData\Roaming\Microsoft\Windows\Recent\users.lnk --csv <output-path>.csv
```
{% endcode %}

Directory of files:

{% code overflow="wrap" %}
```cs
LECmd.exe -d C:\Users\username\AppData\Microsoft\Windows\Recent --csv G:\LnkFiles -q
LECmd.exe -d "c:\users\%username%\AppData\Roaming\Microsoft\Windows\Recent" --all --csv <output-path>.csv
```
{% endcode %}

***

## UserAssist

**Description:** UserAssist tracks every _GUI-based_ program launched are recorded in this registry key. This key contains two GUID subkeys (_CEBFF5CD_ Executable File Execution, _F4E57C4B_ Shortcut File Execution). Each subkey maintains a list of system objects such as program, shortcut, and control panel applets a user has accessed. Registry values under these subkeys are weakly encrypted using the ROT-13 algorithm, which substitutes a character with another character 13 positions away from it in the ASCII table.

Digital Forensics Value of UserAssist Artifacts: Analysis of program executions is essential in cases such as tracing malware and detecting anti-forensic tools. UserAssist artifact provides valuable information that helps identify the presence and execution history of malicious programs on a system even after deletion.

**Location:**

_C:\Users\[UserName]\NTUSER.DAT_. Within the _NTUSER.DAT hive_, the artifact data can be found at the following location:

{% code overflow="wrap" %}
```cs
Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```
{% endcode %}

Registry:

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
- CEBFF5CD under Count tracks Application File Execution
- F4E57C4B under Count tracks Shortcut File Execution
```

_Investigator Note:_ Files are in ROT 13. Select the file of interest to decode, right-click, select Modify, copy the value, go to CyberChef, and select ROT13 recipe to decode. A better option is Registry Explorer (Zimmerman Tools)

{% code overflow="wrap" %}
```cs
Run as Administrator, browse File > Live System > Users > username NTUSER.DAT
Next,  expand ROOT > Software > Microsoft > Windows > CurrentVersion > Explorer > UserAssist  (browse the keys of interest: CEBFF5CD, F4E57C4B)
```
{% endcode %}

**Interpretation:**&#x20;

The NTUSER.DAT file is a registry hive file. The registry file format is a binary file like a filesystem with a group of keys, subkeys and values. These files are used by the operating system to store user, system, and application configurations.

* GUIDs identify the type of execution (Win7+)
* CEBFF5CD Executable File Execution
* F4E57C4B Shortcut File Execution
* Values are ROT-13 Encoded
* Application path, last run time, run count, focus time and focus count **Tools for investigation**

```cs
RegRipper (rr. exe) 
RegistryExplorer.exe
```

**Forensic Value:**

1. The executed GUI program name
2. The executed GUI program path
3. Last executed time
4. Run count

***

## Last Visited Most Recently Used (MRU)

**Description:** Tracks applications in use by the user and the directory location for the last file accessed by the application.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\
```
{% endcode %}

**Note**: The RecentDocs key is found at:

```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

Other items of interest are related to folders that are accessed by a Windows application using the common Open/Save dialog, which is found at:

* NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32 Or files that are accessed by a Windows application using the common Open File or Save File dialog found at:

{% code overflow="wrap" %}
```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```
{% endcode %}

Finally, items of interest regarding commands a user runs via the Windows Run utility are found at:

```cs
NTUSER.DAT\ Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

**Interpretation:** We get two important pieces of information from this key: applications executed by the user and the last place in the file system that those applications interacted with. Interesting and hidden directories are often identified via this registry key.&#x20;

**Tools for investigation:**

* Regedit or other registry viewer application

***

## AutoStart Extension Points (ASEP)

**Description:** Windows has a lot of AutoStart Extension Points (ASEP), making it easier for the malware to persist so that it can continue doing its work in the background. What is Persistence? Persistence refers to the malware’s ability to remain active and running on a compromised system, even after the system reboots. This is the key feature of malware that allows it to continue to cause harm or exploit the system even after the initial infection.

What is Windows Registry, and What is a Registry Key? The Windows Registry is a hierarchical database that stores configuration settings and options on Microsoft Windows operating systems. Windows creates this database of configuration settings during installation. It contains information and settings for low-level operating system components, applications and users on the computer.&#x20;

**Location:**

AutoStart Persistence Locations:

```cs
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

**Tools for investigation:**

Kape

{% code overflow="wrap" %}
```cs
.\kape.exe --tsource C: --tdest C:\Users\username\Desktop\ASEP-tout --tflush  --target RegistryHives --mdest C:\Users\username\Desktop\ASEP-mout --mflush --module RECmd_RegistryASEPs
```
{% endcode %}

**Interpretation** Evidence of Persistence:

* Scheduled Tasks
* Service Replacement
* Service Creation
* Auto-Start Registry Keys
* DLL Search Order Hijacking
* Trojaned Legitimate System Libraries
* More Advance - Local Group Policy, MS Office Add-In, or BIOS Flashing **Investigative Notes:**
* It is an excellent starting place to look for malicious activity on a system
* This slide represents only a fraction of possible locations
* AutoStart data compared across many systems (stacking) might help identify compromised systems&#x20;

**Tools for investigation:**

Kape

{% code overflow="wrap" %}
```cs
.\kape.exe --tsource C: --tdest C:\Users\username\Desktop\ASEP-tout --tflush  --target RegistryHives --mdest C:\Users\username\Desktop\ASEP-mout --mflush --module RECmd_RegistryASEPs
```
{% endcode %}

Autoruns

{% code overflow="wrap" %}
```cs
.\autorunsc64.exe -accepteula -a * -s -h -c > .\autoruns-citadeldc01.csv
		.\autorunsc64.exe runs Autorunsc64.exe from the thumbdrive
		-accepteula accepts the End User License Agreement
		-a * Show all startup locations
		-s Verify digital signatures
		-h Show file hashes
		-c Print as csv
		.\autoruns-citadeldc01.csv redirect output to a CSV
```
{% endcode %}

RECmd

```cs
RECmd.exe --bn BatchExamples\RegistryASEPs.reb -d D:\Triage --nl --csv D:\Temp
```

Analyse output using Timeline Explorer:

* Zoom in on a specific persistence mechanism (CurrentVersion\Run keys
* Look for Windows services with suspicious image paths
* Perform further data reduction by looking for service image paths, _not_ in the System32 folder
* Sort by registry LastWrite times to focus on a specific period of attacker activity. Reference: [https://www.sans.org/blog/finding-registry-malware-persistence-with-recmd/](https://www.sans.org/blog/finding-registry-malware-persistence-with-recmd/)

{% file src="../.gitbook/assets/SANS DFIR Windows Artifact Analysis Evidence Of Execution.pdf" %}
