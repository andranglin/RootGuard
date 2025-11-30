# File & Folder Knowledge

**Which** files and folders has the user been aware of?

**When** were the files interacted with?

## Recent Files

**Description:**

This is a registry key to track files and folders that have been recently opened and is used to populate 'recent’ lists on Windows menus. The Recents Folder artifact contains files and folders that were recently opened or saved. It is closely related to the Windows MRU and JumpList artefacts. It is useful to a DFIR investigator because it can show what files the user was recently focused on. In an intrusion case with an account takeover, this list could show what files the attacker was interested in. These could be documents with intellectual property or configuration files for their attack tools.

For an insider threat case, it can show the documents the user was opening. In a general investigation, knowing what documents the user recently opened can reveal what they used the computer for.

It can also list file paths and times for files that have since been deleted or were on a removable drive.&#x20;

**Location**

{% code overflow="wrap" %}
```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
C:\Users\%UserName%\AppData\Roaming\Microsoft\Windows\Recent
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```
{% endcode %}

#### Caveats&#x20;

The number of recently accessed files is limited

#### Forensic Analysis Tools&#x20;

* Registry Explorer

#### Forensic Value

* The last 150 files accessed by a user
* The last 20 files opened by the user of each extension type
* The last 30 folders opened by the user

***

## Shortcut (LNK) Files

#### **Description**

LNK (shortcut) files are automatically created when a user opens a file or folder.

Windows uses the folder _C:\Users%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent_ to store LNK files associated with files a user has recently accessed, typically by double-clicking on it in a Windows Explorer window. If the file is reopened, it will be overwritten with the latest file access regardless of whether the file exists in a different directory.

In Windows 10 and later, Microsoft started adding the extension of the LNK file and preventing supersecretfile.xlsx from overwriting the LNK file for supersecretfile.txt. Even so, it’s good to remember that only the latest open is recorded for a given file name. It is also important to note that LNK files persist in the Recent directory despite the file itself having been deleted. When viewing the directory in Windows Explorer, the .lnk extension is never shown, even when “show file extensions” is selected in the folder options.

Shortcut files are automatically created by Windows, tracking files and folders opened by a user.&#x20;

#### **Location**

```cs
C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\
```

Caveats&#x20;

* These are the primary locations of LNK files. They can also be found in other locations.&#x20;

#### **Forensic Value**

* Timestamp of when a file was first accessed
* Timestamp of when the shortcut was last accessed
* Timestamps of the target file
* Volume / storage information of the target file
* Creation Date of Shortcut (LNK) File
* Timestamp of the file was last opened
* Last Modification Date of Shortcut (LNK) File
* LNK Target File (Internal LNK File Information) Data:
  * Modified, Access, and Creation times of the target file
  * Volume Information (Name, Type, Serial Number)
  * Network Share information
  * Original Location
  * Name of System

#### Forensic Analysis Tools&#x20;

* LECmd (Zimmerman Tool)

```cs
dir filename.xxx.lnk (display modification time)
dir/tc filename.xxx.lnk (display file creation time)
```

Exiftool

```cs
exiftool [filename.xxx.lnk](http://filename.xxx.lnk)
```

Parse with Zimmerman Tool (Link Explorer Commandline (LECmd)) Single file:

{% code overflow="wrap" %}
```cs
LECmd.exe -f C:\Users\username\AppData\Microsoft\Windows\Recent\Peggy.jpg.lnk
LECmd.exe -f c:\users\%username%\AppData\Roaming\Microsoft\Windows\Recent\users.lnk --csv <output-path>.csv
```
{% endcode %}

Directory of files

{% code overflow="wrap" %}
```cs
LECmd.exe -d C:\Users\username\AppData\Microsoft\Windows\Recent --csv G:\LnkFiles -q
LECmd.exe -d "c:\users\%username%\AppData\Roaming\Microsoft\Windows\Recent" --all --csv <output-path>.csv
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 141610.png" alt=""><figcaption></figcaption></figure>

***

## Shell Bags

#### Description

Shellbags contain the folder names and paths of folders accessed using the local host. This can include network locations and paths to removable devices.&#x20;

Every time Windows Explorer interacts with a folder, an entry is created in the user’s Shellbags. Folders also include other “Explorer Like” items like the Control Panel, zip files, ISOs, and mounted encrypted containers. The simple existence of a directory in Shellbags is evidence the specific user account once interacted with that folder. Shellbags may persist long after the original directories, files, and physical devices have since been removed. ShellBags are a set of Windows Registry keys located in NTUser.dat and USRClass.dat Registry hives (primarily USRClass.dat) that maintain viewing preferences of folders when using Windows Explorer. We used to say the Shellbags tracked folders that a user opened.

#### Location&#x20;

```powershell
• USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags 
• USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 
• NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU 
• NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags 
```

#### Caveats&#x20;

Folder names and paths only&#x20;

#### Forensic Analysis Tools&#x20;

* ShellBags Explorer (Zimmerman tool)

To process a single user’s ShellBags data:

```
SBECmd.exe -d E:\Users\nromanoff --csv G:\temp\sbe_out

```

To process all users in the Users folder:

```
SBECmd.exe -d E:\Users --csv G:\tmp\sbe_out
```

#### Forensic Value

* Folders accessed per user
* Folder interaction timestamps
* Identifications of network locations
* Identification of mounted or mapped volumes (including removable media)

***

## Recycle Bin

#### **Description**

The Recycle Bin stores ‘deleted’ files and folders, and subsequent metadata for each user. When a user deletes a file, it is moved into a temporary storage location for deleted files named Recycle Bin.  Windows creates two files each time a file is placed in the Recycle Bin $I and $R with a string six-character identifier generated for each file. The $R file is a renamed copy of the “deleted” file and the $I file replaces the usage INFO2 file as the source of accompanying metadata.&#x20;

#### **Location**

Hidden System Folder

```cs
C:\$Recycle.Bin
```

#### Caveats&#x20;

The Recycle Bin exists per volume and per user. Deleting a file from a different volume may not be stored within C:$Recycle.Bin

**Interpretation:**

* Each user is assigned a SID sub-folder that can be mapped to a user via the Registry
* Win7+: Files preceded by $I###### contain original filename and deletion date/time
* Win7+: Files preceded by $R###### contain original deleted file contents Deleted Items and File Existence **Tools for investigation** Browse Recycle Bin:
* dir/a
  * cd $Recycle.Bin
    * dir/a
    * cd to SID of interest
    * dir
    * type $I\*\*\*\*\*\*.png (show original location of file)
    * copy $R\*\*\*\*\*\*.png \users\angliad\Desktop\filename.png (Copy file for further analysis)

#### Forensic Analysis Tools

RBCmd (Zimmerman tool)

{% code overflow="wrap" %}
```cs
RBCmd.exe -f \$Recycle.Bin\SID-Of-Interest\$Ifile-of-interest.png
RBCmd.exe -d C:\$Recycle.Bin\ -q --csv \Users\angliad\Desktop\ --csvf username-recycle-bin.csv
```
{% endcode %}

**Forensic Value**

1. Original location of the deleted item
2. Original contents of the deleted item
3. The deleted file size
4. Deletion timestamp of the file or folder

***

