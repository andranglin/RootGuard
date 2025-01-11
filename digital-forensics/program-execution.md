---
icon: laptop-code
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

# Program Execution

## <mark style="color:blue;">Prefetch</mark>

**Description** Prefetch is a performance optimization mechanism to reduce boot and application loading times. The cache manager can use these prefetch files like a cheatsheet to speed up the loading process. It is not enabled by default on Windows servers. Prefetch provides evidence of the execution of applications, embedded within each prefetch file is the total number of times an application has been executed, the original path of execution, and the last time of execution. It increases the performance of a system by pre-loading code pages of commonly used applications. The cache monitors "helper files", recording them in a .pf file.

* Workstation operating systems (not servers) have prefetching on by default to improve performance.
* It lists up to 1024 files on Win8+.
* Prefetch files on win10 and 11 are compressed, with each having up to eight execution times available inside the Prefetch file. **To check the status of prefetching, open the following location in the Registry editor:**

{% code overflow="wrap" %}
```cs
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
- 0: Prefetching Disabled
- 1: Application Prefetching Enabled
- 2: Boot Prefetching Enabled
- 3: Application and Boot both Enabled
```
{% endcode %}

**Investigator Note:** Lookout for multiple prefetch files with the same executable name, this would indicate two executables with the same name were run from different locations. As an example, if you were to see multiple prefetch files for **cmd.exe,** it might indicate a file named **cmd.exe** was executed from somewhere outside of the standard **C:\Windows\System32** folder and that “new” **cmd.exe** might turn into a valuable finding!

Some exceptions to this rule are Windows “hosting” applications, such as **svchost, dllhost, backgroundtaskhost, and rundll32**, the hash value at the end of each prefetch file is calculated based on the full path and any command line arguments and therefore you are likely to see multiple prefetch files for each.

**Pro tip:** Running live response tools on a target system will cause new prefetch files to be created for those live response executables. Plus, each system has a limited number of prefetch files, so this can result in the deletion of the oldest prefetch files. Therefore, prioritise the collection of the prefetch directory to ensure important evidence isn't lost.&#x20;

**Location:**

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

**Tools for Data Capture** PECmd.exe, WinPrefetchView .exe **Preferred tool** Prefetch Explorer Command Line (PECmd): Single file analysis:

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

&#x20;  Process a directory of Prefetch fi les, including VSS, and send the results to file with higher precision timestamps

{% code overflow="wrap" %}
```cs
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv --vss --mp
```
{% endcode %}

Advance Usage: Using a comma-separated list of keywords will cause any hits to be shown in red.

{% code overflow="wrap" %}
```cs
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv -k "system32, downloads, fonts"
```
{% endcode %}

PECmd can extract and process files from Volume Shadow Copies by using the “--vss” option. This will process Prefetch from ALL Volume Shadow Copies. The output files will be separated by individual VSS numbers.

```cs
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv --vss
```

FTK Imager

* Browse to "C:\Windows\Prefetch" **Available Metadata** The metadata that can be found in a single prefetch file is as follows:

{% code overflow="wrap" %}
```cs
- Executable’s name
- Eight-character hash of the executable path.
- The path of the executable file
- Creation, modified, and accessed timestamp of executable
- Run count (Number of times the application has been executed)
- Last run time
- The timestamp for the last 8 run times (1 last run time and other 7 other last run times)
- Volume information
- File Referenced by the executable
- Directories referenced by the executable
- Each .pf file includes embedded data, including the last eight execution times, total number of times executed, and device and file handles used by the program
```
{% endcode %}

**Prefetch Analysis and Interpretation** Date/Time .exe was first executed

* Creation date of .pf file (-10 seconds) Date/Time .exe was last executed
* Modification date of .pf file (-10 seconds
  * The last time of execution was stored inside the .pf file as well
  * Windows 10/11 embeds the last eight execution times in the .pf file

**Pro tip:** Just because a .pf was created, it does NOT mean that the program was successful in execution. Many “broken” programs that attempt execution will still be assigned a .pf file. **Forensic Value**

1. The executable's name
2. The absolute Path to the executable
3. The number of times that the program ran within the system
4. The last time the application ran
5. A list of DLLs used by the program Background Activity Moderator (BAM)/Desktop Activity Moderator (DAM)\*\* **Description** BAM is a Windows service that controls the activity of background applications. The BAM entries are updated when _Windows boots_. Also, there is dam\UserSettings Desktop Activity Monitor (DAM), which stores similar information to BAM.

**Location:**

In the Windows registry, the following locations contain information related to BAM and DAM. This location contains information about last run programs, their full paths, and last execution time.

```cs
SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet*\Services\bam\State\UserSettings\<SID>
```

**Interpretation:**

* Provides full path of file executed and last execution date/time
* Typically, up to one week of data is available
* “State” key used in Win10 1809+

**Tools for investigation:**

RegistryExplorer.exe, BamParser .py

```cs
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings" /s /v *.exe
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings" /s /v *.exe
```

**Forensic Value:**

1. Evidence of execution
2. The executable's name
3. The absolute path to the executable
4. The last time the application ran

## <mark style="color:blue;">ShimCache</mark>

**Description** Microsoft’s Application Compatibility Cache is designed to detect and remediate program compatibility challenges when a program launches. A program might have been built to work on a previous version of Windows. To avoid compatibility issues, Microsoft employs a subsystem allowing a program to invoke properties of different operating system versions. It Allows Windows to track executable files and scripts that may require special compatibility settings to run properly. It is maintained within kernel memory and serialized to the registry upon system shutdown or restart. **Investigator**&#x20;

**Note:** Windows uses this database to determine if a program needs shimming for compatibility. One of the more interesting and useful aspects of **AppCompatCache** is each executable is checked and added to the registry regardless of whether it needs to be shimmed. From a forensic perspective, we use information from the **AppCompatCache** to track application execution, including name, full path, and last modification time of the executable.

**Pro Tip: ShimCache in Win10 and later is not a reliable source of application execution; it does not prove execution but can be used to prove the existence or presence of a file on the system.**

**Location:**

**The shimCache** artifact source file is located at C:\Windows\System32\config\SYSTEM. Registry Key is located on a live system at:

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

* The full path of ethe executable
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

**Investigator Notes:** the existence of an entry in the **AppCompatCache** registry key no longer proves execution. When investigating evidence of execution, the first challenge is getting the data. This can be accomplished by agent-based tools or via collection scripts. Analysis can begin by looking at well-known attack patterns. One or two-letter executable names, executions from unusual folders such as the **$Recycle.Bin** or **System Volume Information** and searching common malware names like **pwdump** or **mimikatz** are all good starts. When attackers perform reconnaissance and live off the land, they will use built-in tools, but those tools might be rare in certain parts of the network. Searching for **psexec** activity, command-line WMI with **wmic.exe, reg.exe,** or **schtasks.exe** could pay dividends.

**Forensic Value**

1. The executable or script file names and full paths
2. The standard information's last modified date
3. The size of the binary
4. Finally, whether the file ran on the system (just browsed through Explorer.

## <mark style="color:blue;">Amcache.hve</mark>

**Description** The Amcache.hve is a registry hive file that stores information related to the execution of programs when a user performs certain actions, such as running host-based applications, installing new applications, or running portable applications from external devices. It tracks installed applications, programs executed (or present), drivers loaded, and more. Amcache also tracks the SHA1 hash for executables and drivers.

**Investigator Note:** Amcache provides full path information, file size, publisher metadata for executables and loaded drivers, and several different timestamps. What sets this artifact apart from nearly all the others is it also tracks the **SHA1 hash** for executables and drivers. This is a rarity in forensic artifacts and can be of great value when trying to identify either known goods (e.g., Microsoft files) or known bad (e.g., a renamed version of mimikatz.exe).&#x20;

**Pro Tip: ShimCache is not a reliable source of application execution; it does not prove execution but can be used to prove the existence or presence of a file on the system.**

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
* Entries can also be due to automated file discovery or program installation and do NOT always indicate program execution **Pro Tip:** Use this artifact as an indication of executable and driver presence on the system and the metadata it tracks for each file. Other artifacts (such as Prefetch) can be used to prove execution and execution times.

**Forensic Value:**

1. The executable names and full paths
2. Last executed time
3. The size of the binary and its version
4. The executable hash (SHA1)

## <mark style="color:blue;">Jump Lists</mark>

**Description Jump Lists allow the user to quickly access frequently or recently used items via the taskbar.** In investigation, it can be used to identify applications in use and metadata about items accessed via those applications. It provides the user with a graphical interface associated with each installed application and lists files previously accessed by it.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
-CMD: dir/ad/on/w
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations (via Taskbar)
```
{% endcode %}

**Interpretation:**

Each jump list file is named according to an application identifier (AppID). List of Jump List IDs -> https://dfi r.to/EZJumpList

* Each Jump List contains a collection of items interacted with (up to \~2000 items per application)
* Each entry is represented as a LNK shell item providing additional data
* Target Timestamps
* File Size
* Local Drive | Removable Media | Network Share Info
* Entries are kept in MRU order, including a timestamp for each item. Tools for investigation JLECmd – JumpList Explorer Command Line Edition Run against a single Jumplist. Output is stored on the G: drive to the “Jumplists” folder.

{% code overflow="wrap" %}
```cs
JLECmd.exe -f C:\Users\Donald\AppData\Microsoft\Windows\Recent\AutomaticDestinations\ff103e2cc310d0d.automaticDestinations-ms --csv G:\Jumplists -q
```
{% endcode %}

Run against all automatic jumplist files stored for the user “Donald”.

{% code overflow="wrap" %}
```cs
JLECmd.exe -d C:\Users\Donald\AppData\Microsoft\Windows\Recent\AutomaticDestinations --csv G:\Jumplists -q
```
{% endcode %}

**Forensic Value:**

1. User activity who have interactively on the system
2. Recover user’s traces of recently accessed directories from the Windows Explorer jump list
3. History of attempted lateral movement by checking Remote Desktop jump lists, as they provide a list of recent connections
4. Destination IPs and ports via RDP

## <mark style="color:blue;">UserAssist</mark>

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

## <mark style="color:blue;">Windows 10 Timeline</mark>

**Description:** Windows 10 Timeline info covering user activities is stored in the **ActivitiesCache. db** file with the following path. The **ActivitiesCache. db** ’file is an SQLite database. **StartTime** means the moment when an application was launched. **EndTime** means the moment when an application ceases to be used. **ExpirationTime** is when the storage duration for a record covering a user activity expires in the database. **LastModifiedTime** is when a record covering a PC user activity has been last modified (if such an activity has been repeated several times).

Windows 10 Timeline provides information about the applications executed on the computer within the last 30 days, such as the application name, the time when the application was launched, and the application usage duration. This information is of forensic value, as it can help examiners reconstruct previous events on a particular device, even if the files, documents or applications have been deleted.

**Structure of Windows 10 Timeline Artifacts** ActivitiesCache.db is an SQLite database containing multiple tables. To be more specific, 7 tables (**Activity, ActivityOperation, Activity\_PackageId, AppSettings, DataEncryptionKeys, ManualSequence and Metadata**); however, only a subset of the tables contain forensically valuable information.

**Location:**

User activates displayed in the timeline are stored in ActivitiesCache.db, which is located at:

{% code overflow="wrap" %}
```cs
C:\Users\<profile>\AppData\Local\ConnectedDevicesPlatform\<account-ID>\ActivitiesCache.db
%USERPROFILE%\AppData\Local\ConnectedDevicesPlatform\<Profile ID>\ActivitiesCache.db
```
{% endcode %}

**Interpretation:**

* The full path of the executed application
* Start time, end time, and duration
* Items opened within the application
* URLs visited
* Databases are still present even after feature deprecation in late-Win10

**Tools for investigation:**

DB Browser for SQLite:

* The easiest way is to look at the data contained in **ActivitiesCache.db** using an SQLite viewer, such as DB Browser for SQLite, a free tool.
* By switching tables in the Browse Data tab, it is possible to view their contents and record information that is potentially of interest for an investigation _WxTCmd_ Parser for Windows 10 Timeline:

{% code overflow="wrap" %}
```cs
WxTCmd.exe -f "C:\Users\eric\AppData\Local\ConnectedDevicesPlatform\L.eric\ActivitiesCache.db" --csv c:\temp
WxTCmd.exe -f C:\Users\sansdfir\AppData\Local\ConnectedDevicesPlatform\L.SANSDFIR\ActivitiesCache.db --csv C:\users\sansdfir\Desktop\out
```
{% endcode %}

**Forensic Value:**

1. Timeline Analysis
2. Information about an application and file
3. Date /Time when started, created, modified and accessed

## <mark style="color:blue;">System Resource Usage Monitor  (SRUM)</mark>

**Description:** SRUM is considered a gold mine of forensic information, as it contains all the activities on a system. SRUM tracks and records program executions, power consumption, network activities, and more information that can be retrieved even if the source has been deleted. The info enables the examiner to gain insights into a system's previous activities and events. SRUM records 30 to 60 days of historical system performance, including applications run, user accounts responsible, network connections, and bytes sent/received per application per hour.

**Location:**

```cs
C:\Windows\System32\SRU\SRUDB.dat
```

Structure of SRUM Artifacts: SRUM artifacts are stored in an Extensible Storage Engine (ESE) database format. This database contains multiple tables recording all the activities on a particular system.

**Interpretation:**

* SRUDB.dat is an Extensible Storage Engine database.
* Three tables in SRUDB.dat are particularly important:
* {973F5D5C-1D90-4944-BE8E-24B94231A174} = Network Data Usage
* {d10ca2fe-6fcf-4f6d-848e-b2e99266fa89} = Application Resource Usage
* {DD6636C4-8929-4683-974E-22C046A43763} = Network Connectivity Usage

**Tools for investigation:**

Windows.Forensics.SRUM artifact Copying file from the live system: FTK Imager Export both SRUDB and Software Hive:

* Navigate: "C:\Windows\System32\SRU\SRUDB.dat" right-click SRUDB.dat, select Export Files, choose storage location, OK.
* Navigate: "C:\Windows\System32\config\\
  * Select: SOFTWARE, SOFTWARE.LOG1, SOFTWARE.LOG2  and export files to the same location as SRUDB.dat SrumECmd Parser:

```cs
SrumECmd.exe -d \Users\username\Desktop\sru --csv \Users\username\Desktop\Output
```

**Forensic Value:**

1. Program executions
2. Power consumption
3. Network activities
4. Bytes Received & Sent

## <mark style="color:blue;">Last Visited Most Recently Used (MRU)</mark>

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

```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
```

Or files that are accessed by a Windows application using the common Open File or Save File dialog found at:

{% code overflow="wrap" %}
```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```
{% endcode %}

Finally, items of interest regarding commands a user runs via the Windows Run utility are found at:

```cs
NTUSER.DAT\ Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

**Interpretation** We get two important pieces of information from this key: applications executed by the user and the last place in the file system that those applications interacted with. Interesting and hidden directories are often identified via this registry key. **Tools for investigation**

* Regedit or other registry viewer applications.

## <mark style="color:blue;">Background Activity Moderator (BAM)/Desktop Activity Moderator (DAM)</mark>

**Description:** BAM is a Windows service that controls activity of background applications. The BAM entries are updated when _Windows boots_. Also, there is dam\UserSettings Desktop Activity Monitor (DAM), which stores similar information to BAM.

**Location:**

In the Windows registry, the following locations contain information related to BAM and DAM. This location contains information about last run programs, their full paths, and last execution time.

```cs
SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet*\Services\bam\State\UserSettings\<SID>
```

**Interpretation:**

* Provides full path of file executed and last execution date/time
* Typically, up to one week of data is available
* “State” key used in Win10 1809+

**Tools for investigation:**

RegistryExplorer.exe, BamParser .py

```cs
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings" /s /v *.exe
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings" /s /v *.exe
```

**Forensic Value:**

1. Evidence of execution
2. The executable's name
3. The absolute path to the executable
4. The last time the application ran

## <mark style="color:blue;">Commands Executed in the Run Dialog</mark>

**Description: A history of commands typed into the Run dialogue box is stored for each user.**&#x20;

**Location:**

```cs
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

**Interpretation** :

It is an MRU key with temporal order via the MRUList key.

**Tools for investigation**

* Regedit or other registry viewer application

## <mark style="color:blue;">**PowerShell**</mark>

**Description** PowerShell is a cross-platform task automation solution comprising a command line shell, a scripting language, and a configuration management framework. PowerShell in Windows 10 saves the last 4096 commands stored in a plain text file located in each user's profile.

**Location:**

{% code overflow="wrap" %}
```cs
C:Users\<username>\appData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
{% endcode %}

**Tool:**

```cs
notepad.exe
```

**Forensic Value:**

1. Evidence of PowerShell commands executed by the user

## <mark style="color:blue;">Master File Table ($MFT)</mark>

**Description:** A master file table is a database containing information about every file and directory on an NT File System (NTFS) volume. An MFT will have at least one record for every file and directory on the NTFS logical volume. Moreover, each record contains attributes that tell the operating system how to handle the file or directory associated with the record.

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

## <mark style="color:blue;">$J</mark>

**Description** The $J data stream contains the contents of the change journal and includes information such as the date and time of the change, the reason for the change, the MFT entry, the MFT parent entry and others. This information can be useful for an investigation, for example, in a scenario where the attacker is deleting files and directories while he moves inside an organization in order to hide his tracks.

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

## <mark style="color:blue;">$LogFile</mark>

**Description:** This file is stored in the MFT entry number 2, and every time there is a change in the NTFS Metadata, a transaction is recorded in the $ LogFile. These transactions are recorded to make it possible to redo or undo file system operations. Why would $LogFile be important for investigation? Because the $LogFile records all operations in the NTFS volume, such as file creation, deletion, renaming, and copy.

**Location:**

```cs
NTFS/root/$LogFile (Extracted from FTK)
```

**Tools For Investigation:**

NTFS\_Log\_Tracker.exe , LogFileParser .exe

**Forensic Value:**

1. Timeline Analysis
2. File Activity Analysis (Open, Close and Update
3. Evidence of renamed and deleted files

## <mark style="color:blue;">Alternate Data Streams (ADS)</mark>

**Destination: Alternate Data Streams (ADS) are file attributes only found on the NTFS file system to store different streams of data.** The ability is to fork file data into existing files without affecting their functionality, size, or display to traditional file browsing utilities like dir or Windows Explorer. In addition to the default stream Zone. Identifier, which is normally used for a file.

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
