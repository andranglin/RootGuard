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

# File and Folder Opening

## Open/Save Most Recently Used (MRU)

**Description:** The OpenSave MRU data is stored in a User’s NTUSER.DAT registry hive. It’s in two different locations depending on the version of Windows. They both have the same structure, though, which is sub-keys based on the file extension, such as “docx”, “txt”, or “zip”. This key tracks files opened or saved within a Windows shell dialog box. This big data set includes Microsoft Office applications, web browsers, chat clients, and the most commonly used applications.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDLg32\OpenSavePidlMRU
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
```
{% endcode %}

**Interpretation:**&#x20;

Each extension sub-key can contain up to 20 values. Their name is a counter (0 to 19), and the value is a binary structure that contains the path (and other data). However, the path is not stored as an easy-to-read string. Instead, it is stored as a “PIDL”, a list of IDs representing entries in a folder. The file name is stored in the value, though in ASCII and UTF-16.

A “MRUListEx” value contains an ordered list of counters (i.e. 0 to 19) representing what order the files were last used. In the below example, you can see that two was the most recent, then 1, and then 0.

* The “\*” key – This subkey tracks the most recent files of any extension input in an OpenSave dialog
* .??? (Three-letter extension) – This subkey stores file info from the OpenSave dialog by specific extension

## Recent Files

**Description:** The Recents Folder artifact contains files and folders that were recently opened or saved. It is closely related to the Windows MRU and JumpList artifacts. The registry key tracks the last files and folders opened. How is a Windows Recents Folder Artifact Useful in DFIR? It is useful to a DFIR investigator because it can show what files the user was recently focused on. In an intrusion case with an account takeover, this list could show what files the attacker was interested in. These could be documents with intellectual property or configuration files for their attack tools.

For an insider threat case, it can show the documents the user was opening. In a general investigation, knowing what documents the user recently opened can reveal what they used the computer for.

It can also list file paths and times for files that have since been deleted or were on a removable drive.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
C:\Users\%UserName%\AppData\Roaming\Microsoft\Windows\Recent
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```
{% endcode %}

**Interpretation:**

* RecentDocs – Rollup key tracking the order of the last 150 files or folders opened. MRU list tracks the temporal order in which each file/folder was opened.
* .??? – These subkeys store the last 20 files opened by the user of each extension type. MRU list tracks the temporal order in which each file was opened. The most recently used (MRU) item is associated with the last write time of the key, providing one timestamp of file opening for each file extension type.
* Folder – This subkey stores the last 30 folders opened by the user. The most recently used (MRU) item in this key is associated with the last write time of the key, providing the time of opening for that folder.

## MS Word Reading Locations

**Description:** Beginning with Word 2013, the user's last known position within a Word document is recorded.&#x20;

**Location:**

* NTUSER\Software\Microsoft\Office\<Version>\Word\Reading Locations Interpretation
* Another source tracking recent documents opened
* The last closed time is also tracked along with the last position within the file.
* The last session duration can be determined with the last opened date in the Office File MRU key.

## Last Visited Most Recently Used (MRU)

**Description:** Tracks applications in use by the user and the directory location for the last file accessed by the application.&#x20;

**Location:**

{% code overflow="wrap" %}
```powershell
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\
```
{% endcode %}

**Note**: The RecentDocs key is found at:

```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

Other items of interest are related to folders that are accessed by a Windows application using the common Open/Save dialog which is found at:

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

**Interpretation:** We get two important pieces of information from this key: applications executed by the user and the last place in the file system that those applications interacted with. Interesting and hidden directories are often identified via this registry key. **Tools for investigation**

* Regedit or other registry viewer applications.

## Shortcut (LNK) Files

**Description:** Windows uses the folder _C:\Users%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent_ to store LNK files associated with files a user has recently accessed, typically by double-clicking on it in a Windows Explorer window.

If the file is reopened, it will be overwritten with the latest file access regardless of whether the file exists in a different directory.

In Windows 10 and later, Microsoft started adding the extension of the LNK file and preventing supersecretfile.xlsx from overwriting the LNK file for supersecretfile.txt.

Even so, it’s good to remember that only the latest open is recorded for a given file name. It is also important to note that LNK files persist in the Recent directory despite the file itself having been deleted. When viewing the directory in Windows Explorer, the .lnk extension is never shown, even when “show file extensions” is selected in the folder options.

Shortcut files are automatically created by Windows, tracking files and folders opened by a user.&#x20;

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
* Name of System **Tools for Investigation**

```cs
dir filename.xxx.lnk (display modification time)
dir/tc filename.xxx.lnk (display file creation time)
```

Exiftool :

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

Directory of files:

{% code overflow="wrap" %}
```cs
LECmd.exe -d C:\Users\username\AppData\Microsoft\Windows\Recent --csv G:\LnkFiles -q
LECmd.exe -d "c:\users\%username%\AppData\Roaming\Microsoft\Windows\Recent" --all --csv <output-path>.csv
```
{% endcode %}

## Office Recent Files

**Description: MS Office programs track their own recent file list to make it easier for users to access previously opened files.**&#x20;

**Location:**

* NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\File MRU
* 16.0 = Office 2016/2019/M365
* 15.0 = Office 2013
* NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\User MRU\LiveId\_####\File MRU
* Microsoft 365
* NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>\User MRU\AD\_####\File MRU
* Microsoft 365 (Azure Active Directory) **Interpretation**
* Similar to the Recent Files registry key, this tracks the last files opened by each MS Office application
* Unlike the Recent Files registry key, full path information is recorded along with the last opened time for each entry

## Office Trust Records

**Description:** Records trust relationships afforded to documents by a user when presented with a security warning. This is stored so the user is only required to grant permission the first time the document is opened.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
NTUSER\Software\Microsoft\Offi ce\<Version>\<AppName>\Security\Trusted Documents\TrustRecords
HKEY_CURRENT_USER\Software\Microsoft\Office\[office_version]\Word\Security\Trusted Documents\TrustRecords
```
{% endcode %}

**Interpretation:**

* Can identify documents opened by the user and user interaction in trusting the file
* Records file path, time the document was trusted, and which permissions were granted&#x20;

**Tools for investigation:**

Whenever a user clicks on 'Enable Editing; or 'Enable Content', Microsoft Office will add the path to the document as a Registry value under the program's TrustRecords key. The last four bytes of the trusted document's value data are set to FF FF FF 7F, which means that the user enabled macros in the document, which is a very common vector for a computer to become infected. We can check for potential malicious documents whose macros have been enabled by checking the values under the following keys and then collecting the documents for further forensics.

{% code overflow="wrap" %}
```cs
HKEY_CURRENT_USER\Software\Microsoft\Office\[office_version]\Word\Security\Trusted Documents\TrustRecords
HKEY_CURRENT_USER\Software\Microsoft\Office\[office_version]\Excel\Security\Trusted Documents\TrustRecords
```
{% endcode %}

From the CLI:

{% code overflow="wrap" %}
```cs
reg query "HKCU\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords" /s
```
{% endcode %}

## Office OAlerts

**Description:** MS Office programs produce alerts for the user when they attempt actions such as closing a file without saving it first.&#x20;

**Location:**

OAlerts.evtx

**Interpretation:**

* All Office applications use Event ID 300
* Events include the program name and dialog message, showing some user activity within the application.

**Tools for investigation:**

EvtxECmd – Windows Event Log Parser

{% code overflow="wrap" %}
```cs
./EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv C:\Users\sansdfir\Desktop\out --csvf evtxecmd_out.csv --inc 300,4625
```
{% endcode %}

Note: Use in combination with EventLogs2Process Script

## Internet Explorer/Edge file

**Description: Internet Explorer History databases have long-held information on local and remote file access (via network shares), giving us an excellent means for determining files accessed on the system per user.** Information can be present even on Win11+ systems missing the Internet Explorer application. **Location** The Edge cached files stored in the following directory:

{% code overflow="wrap" %}
```cs
C:\Users\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxx\AC\#!001\MicrosoftEdge\Cache\
```
{% endcode %}

The Edge last active browsing session is stored in the following directory:

{% code overflow="wrap" %}
```cs
C:\Users\user_name\AppData\Local\Packages\Microsoft.MicrosoftEdge_xxxx\AC\MicrosoftEdge\User\Default\Recovery\Active\
```
{% endcode %}

Internet Explorer:

{% code overflow="wrap" %}
```cs
IE10–11 & Win10+: %USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat
```
{% endcode %}

Both Edge and IE history records are stored in the same database:

```cs
C:\Users\user_name\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat
```

**Interpretation:**

* Entries recorded as: \*file:C:/directory/filename.ext
* This does not mean the file was opened in a browser

## Deleted Items and File Existence

### **Thumbs.db**

**Description: Hidden file in the directory where images on the machine exist stored in smaller thumbnail graphics.** Thumbs.db catalogues pictures in a folder and stores a copy of the thumbnail even if the pictures were deleted. **Location** Each folder maintains a separate Thumbs.db file after being viewed in thumbnail view (OS version dependent)

**Interpretation**:

* Thumbnail image of the original picture
* Last Modification Time (XP Only)
* Original Filename (XP Only)
* Most relevant for XP systems, but Thumbs.db files can be created on more modern OS versions in unusual circumstances, such as when folders are viewed via UNC paths.

## Windows Search Database

**Description:** Windows Search indexes more than 900 file types, including email and file metadata, allowing users to search based on keywords. **Location**

```cs
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex
```

**Interpretation:**

* Database in Extensible Storage Engine format
* Gather logs contain a candidate list for files to be indexed over each 24 hours
* Extensive file metadata and even partial content can be present

## Thumbcache

**Description:** Thumbnails of pictures, documents, and folders exist in a set of databases called the thumbcache. It is maintained for each user based on the thumbnail sizes viewed (e.g., small, medium, large, and extra large). It can catalogue the previous contents of a folder even upon file deletion. (Available in Windows Vista+)&#x20;

**Location:**

```cs
%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer
```

**Interpretation:**

* Database files are named similarly to: Thumbcache\_256.db
* Each database file represents thumbnails stored in different sizes or to fit different user interface components
* Thumbnail copies of pictures can be extracted, and the Thumbnail Cache ID can be cross-referenced within the Windows Search Database to identify the filename, path, and additional file metadata.&#x20;

**Tools**

```cs
thumbcache_viewer.exe
thumbs_viewer.exe
```

### Recycle Bin

**Description** When a user deletes a file, the file is moved into a temporary storage location for deleted files named Recycle Bin. Windows creates two files each time a file is placed in the Recycle Bin $I and $R with a string six-character identifier generated for each file. $R file is a renamed copy of the “deleted” file. While the $I file replaces the usage INFO2 file as the source of accompanying metadata.&#x20;

**Location:**

Hidden System Folder

```cs
C:\$Recycle.Bin
```

**Interpretation:**

* Each user is assigned a SID sub-folder that can be mapped to a user via the Registry
* Win7+: Files preceded by $I###### contain original filename and deletion date/time
* Win7+: Files preceded by $R###### contain original deleted file contents Deleted Items and File Existence&#x20;

**Forensic Value**

1. The original file name and path
2. The deleted file size
3. The date and time of deletion&#x20;

**Tools:**

RBCmd.exe, Rifiuti2, Recbin exe, EnCase, FTK, Autopsy, RecycleDump.py, $ I\_Parse.exe

{% code overflow="wrap" %}
```cs
RBCmd.exe -f \$Recycle.Bin\SID-Of-Interest\$Ifile-of-interest.png
RBCmd.exe -d C:\$Recycle.Bin\ -q --csv \Users\username\Desktop\ --csvf username-recycle-bin.csv
```
{% endcode %}

## Internet Explorer file

**Description:** Internet Explorer History databases have long held information on local and remote (via network shares) file access, giving us an excellent means for determining files accessed on the system, per user. Information can be present even on Win11+ systems missing the Internet Explorer application.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
IE10-11 and Win10+: %USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat
```
{% endcode %}

**Interpretation:**

```cs
Entries are recorded as: file:///C:/<directory>/<filename>.<ext>
```

* It does not mean the file was opened in a browser

## WordWheelQuery

**Description:** WordWheelQuery is a registry key that stores keywords searched from the folder search menu bar. Keywords are added in Unicode and listed in the temporal order in an MRU list. It maintains an ordered list of terms in the File Explorer search dialog.&#x20;

**Location:**

```cs
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
=
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```

_Investigator Notes: Keywords are added in Unicode and listed in the temporal order in an MRU list User Typed Paths._ Users can type a path directly into the File Explorer path bar instead of navigating the folder structure to locate a file. Folders accessed in this manner are recorded in the TypedPaths key.&#x20;

**Location:**

```cs
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

**Interpretation:**

* This indicates a user had knowledge of a particular file system location
* It can expose hidden and commonly accessed locations, including those present on external drives or network shares&#x20;
* **Tools:**

```cs
RegRipper (rr.exe) 
RegistryExplorer.exe
```

**Forensic Value:**

1. User Activity
2. Last folder search conducted (Last Write Time
3. Keywords searched
