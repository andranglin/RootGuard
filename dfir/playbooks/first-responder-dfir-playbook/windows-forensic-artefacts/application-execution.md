# Application Execution

## Objectives

**Which** executables have been run?

**When** were the executables run?&#x20;

**Who** ran the executables?

## Prefetch

**Description** Prefetch files (.pf) store file and directory information referenced by an application within 10 seconds of when the application is first run in order to improve system performance.

#### **Caveats**

* Prefetch must be enabled on the host in order to generate prefetch files. This is not enabled by default on most instances of Windows Server.
* Workstation operating systems (not servers) have prefetching on by default to improve performance.&#x20;
* It lists up to 1024 files on Win8+.&#x20;
* Prefetch files on win10 and 11 are compressed, with each having up to eight execution times available inside the Prefetch file.

#### Forensic Value

* Applications known to have run on the host
* Date & time of last application execution
* Date & time of previous application executions
* Files and device handles referenced by the application

**Location**

```cs
C:\Windows\Prefetch
```

To check the status of prefetch, open the following location in the Registry editor:

{% code overflow="wrap" %}
```cs
 reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
EnablePrefetcher value: (0 = disabled; 3 = application launch and boot enabled)
	
0: Prefetching Disabled
1: Application Prefetching Enabled
2: Boot Prefetching Enabled
3: Application and Boot both Enabled
```
{% endcode %}

The metadata that can be found in a single prefetch file is as follows:

{% code overflow="wrap" %}
```atom
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

**Note:** Lookout for multiple prefetch files with the same executable name, this would indicate two executables with the same name were run from different locations. As an example, if you were to see multiple prefetch files for **cmd.exe,** it might indicate a file named **cmd.exe** was executed from somewhere outside of the standard **C:\Windows\System32** folder and that “new” **cmd.exe** might turn into a valuable finding!

Some exceptions to this rule are Windows “hosting” applications, such as **svchost, dllhost, backgroundtaskhost, and rundll32**, the hash value at the end of each prefetch file is calculated based on the full path and any command line arguments and therefore you are likely to see multiple prefetch files for each.

Running live response tools on a target system will cause new prefetch files to be created for those live response executables. Plus, each system has a limited number of prefetch files, so this can result in the deletion of the oldest prefetch files. Therefore, prioritise the collection of the prefetch directory to ensure important evidence isn't lost.&#x20;

#### Data Capture

Use KAPE to capture a triage image:

{% code overflow="wrap" %}
```powershell
kape.exe --tsource C: --tdest E:\KAPE_Output --tflush --target !BasicCollection
```
{% endcode %}

#### **Forensic Analysis Tools**

PECmd (Zimmerman tool), WinPrefetchView (NirSoft)

Single file analysis

{% code overflow="wrap" %}
```cs
.\PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf
.\PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-8E75B5BB.pf --csv "<path-to-working-directory>" --csvf <filename>.csv
```
{% endcode %}

Directory analysis

```cs
.\PECmd.exe –d "C:\Windows\Prefetch"
.\PECmd.exe -d C:\Windows\Prefetch\ -q --csv G:\Prefetch --csvf prefetch.csv
```

&#x20;Process a directory of Prefetch files, including VSS, and send the results to file with higher precision timestamps

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

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 141350.png" alt=""><figcaption></figcaption></figure>

#### Other Options

FTK Imager

Browse to "C:\Windows\Prefetch" **Available Metadata** The metadata that can be found in a single prefetch file is as follows:

{% code overflow="wrap" %}
```atom
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

**Prefetch Analysis and Interpretation**&#x20;

* Date/Time .exe was first executed
* Creation date of .pf file (-10 seconds)
* Modification date of .pf file (-10 seconds)
  * The last time of execution was stored inside the .pf file as well
  * Windows 10/11 embeds the last eight execution times in the .pf file

**Note:** Just because a .pf was created, it does NOT mean that the program was successful in execution. Many “broken” programs that attempt execution will still be assigned a .pf file.&#x20;

#### **Forensic Value**

1. The executable's name
2. The absolute Path to the executable
3. The number of times that the program ran within the system
4. The last time the application ran
5. A list of DLLs used by the program Background Activity Moderator (BAM)/Desktop Activity Moderator (DAM)\*\* **Description** BAM is a Windows service that controls the activity of background applications. The BAM entries are updated when _Windows boots_. Also, there is dam\UserSettings Desktop Activity Monitor (DAM), which stores similar information to BAM.

**Location**

In the Windows registry, the following locations contain information related to **BAM** and **DAM**. This location contains information about last run programs, their full paths, and last execution time.

```cs
SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet*\Services\bam\State\UserSettings\<SID>
```

**Interpretation**

* Provides full path of file executed and last execution date/time
* Typically, up to one week of data is available
* “State” key used in Win10 1809+

**Tools for investigation**

RegistryExplorer.exe, BamParser .py

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings" /s /v *.exe
reg query "HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings" /s /v *.exe
```

**Forensic Value**

1. Evidence of execution
2. The executable's name
3. The absolute path to the executable
4. The last time the application ran

***

## ShimCache

**Description**&#x20;

The Application Compatibility Cache detects if an application needs additional compatibility requirements in order to run. It is designed to detect and remediate program compatibility challenges when a program launches. A program might have been built to work on a previous version of Windows, so to avoid compatibility issues, Microsoft employs a subsystem allowing a program to invoke properties of different operating system versions. It Allows Windows to track executable files and scripts that may require special compatibility settings to run properly. It is maintained within kernel memory and serialized to the registry upon system shutdown or restart.&#x20;

Windows uses this database to determine if a program needs shimming for compatibility. One of the more interesting and useful aspects of **AppCompatCache** is each executable is checked and added to the registry regardless of whether it needs to be shimmed. From a forensic perspective, we use information from the **AppCompatCache** to track application execution, including name, full path, and last modification time of the executable.

#### Caveats&#x20;

Information available from the Shimcache will differ between versions of Windows, i.e., the execution flag is not available on Windows XP and below. ShimCache in Win10 and later is not a reliable source of application execution; it does not pro**ve execution but can be used to prove the existence or presence of a file on the system.**

**Location**

```powershell
C:\Windows\System32\config\SYSTEM
```

Registry Key is located on a live system at:

```powershell
HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache
```

**Note:** To determine the most recent controlset in use, in the SYSTEM folder, click Select > Current and review the value of the control

**Forensic Analysis Tools**

AppCompatCacheParser (Zimmerman Tools)

Shimcache Parser for a captured image:

{% code overflow="wrap" %}
```cs
.\AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv G:\AppCompatCache
```
{% endcode %}

{% code overflow="wrap" %}
```cs
.\AppCompatCacheParser.exe --csv c:\temp --csvf results.csv
.\AppCompatCacheParser.exe --csv "C:\Users\username\Desktop\Analysis\" --csvf Shimcache.csv
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 141455.png" alt=""><figcaption></figcaption></figure>

**Forensic Value**

1. Last modification date of executable
2. File path of executed applications
3. Whether the application has been executed
4. _The executable or script file names and full paths_
5. _The standard information's last modified date_
6. _The size of the binary_
7. _Finally, whether the file ran on the system (just browsed through Explorer._

#### **Analysis and Interpretation**

When reviewing the output from the **AppCompatCache**, note the following:

The most recent events are on top (which is very helpful since most versions don’t include execution time)

New entries are only written on shutdown. One of the most useful capabilities of the **AppCompatCache** is if an attacker has removed their tools from the system and was careful to also delete the corresponding prefetch (.pf) files, **AppCompatCache** entries might provide clues that the application existed.

The existence of an entry in the **AppCompatCache** registry key no longer proves execution. When investigating evidence of execution, the first challenge is getting the data. This can be accomplished by agent-based tools or via collection scripts. Analysis can begin by looking at well-known attack patterns. One or two-letter executable names, executions from unusual folders such as the **$Recycle.Bin** or **System Volume Information** and searching common malware names like **pwdump** or **mimikatz** are all good starts. When attackers perform reconnaissance and live off the land, they will use built-in tools, but those tools might be rare in certain parts of the network. Searching for **psexec** activity, command-line WMI with **wmic.exe, reg.exe,** or **schtasks.exe** could pay dividends.

***

## Amcache.hve

#### **Description**&#x20;

Amcache monitors installed applications, executed programs, drivers loaded, and more.  It is a registry hive file that stores information related to the execution of programs when a user performs certain actions, such as running host-based applications, installing new applications, or running portable applications from external devices. It tracks installed applications, programs executed (or present), drivers loaded, and more. Amcache also tracks the SHA1 hash for executables and drivers.

Amcache provides full path information, file size, publisher metadata for executables and loaded drivers, and several different timestamps. What sets this artifact apart from nearly all the others is it also tracks the **SHA1 hash** for executables and drivers. This is a rarity in forensic artifacts and can be of great value when trying to identify either known goods (e.g., Microsoft files) or known bad (e.g., a renamed version of mimikatz.exe).&#x20;

#### **Caveats**&#x20;

Amcache should not be used as evidence of application execution without additional findings from other artefacts. Instead, it should be used as evidence of application existence. Associated .LOG and .tmp.LOG files should be recovered for parsing

**Location**

```cs
C:\Windows\AppCompat\Programs\Amcache.hve
```

**Forensic Value**

* _Track installed applications_
* _Full file paths, file sizes, and compilation metadata_
* _SHA1 hashes of executables and drivers_
* _Drivers referenced by the application_

#### Forensic Analysis Tools&#x20;

RegRipper&#x20;

AmcacheParser (Zimmerman tool)

{% code overflow="wrap" %}
```cs
File > Live System > Armcache.hve  (review the loaded registry hives, keys and subkeys)
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

For live systems

{% code overflow="wrap" %}
```cs
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" -i --csv C:\Users\username\Desktop\EvidenceFolder
.\AmcacheParser.exe -f c:\Windows\AppCompat\Programs\Amcache.hve -b G:\Blacklist.txt --csv G:\Amcache
```
{% endcode %}

***

## Jump Lists

**Description**&#x20;

Jump Lists record information about frequently used and recently accessed files and application&#x73;**.** It allows the user to quickly access frequently or recently used items via the taskba&#x72;**.** In investigation, it can be used to identify applications in use and metadata about items accessed via those applications. It provides the user with a graphical interface associated with each installed application and lists files previously accessed by it.&#x20;

**Location**

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
-CMD: dir/ad/on/w
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations (via Taskbar)
```
{% endcode %}

#### Caveats&#x20;

CustomDestinations are created when the user ‘pins’ a file or application.

#### **Interpretation**

Each jump list file is named according to an application identifier (AppID). List of Jump List IDs -> https://dfi r.to/EZJumpList

* Each Jump List contains a collection of items interacted with (up to \~2000 items per application)
* Each entry is represented as a LNK shell item providing additional data
* Target Timestamps
* File Size
* Local Drive | Removable Media | Network Share Info
* Entries are kept in MRU order, including a timestamp for each item. Tools for investigation JLECmd – JumpList Explorer Command Line Edition Run against a single Jumplist. Output is stored on the G: drive to the “Jumplists” folder.

#### Forensic Analysis Tools&#x20;

JumpList Explorer (Zimmerman Tool)

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

**Forensic Value**

1. User activity for who have interactively on the system
2. Recover user’s traces of recently accessed directories from the Windows Explorer jump list
3. History of attempted lateral movement by checking Remote Desktop jump lists, as they provide a list of recent connections
4. Destination IPs and ports via RDP
5. Jump List timestamps
6. Last time an application opened an object
7. First time an application was added to the Jump List
