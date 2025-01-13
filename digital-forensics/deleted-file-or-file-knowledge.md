---
icon: laptop-code
cover: ../.gitbook/assets/Screenshot 2025-01-05 105840 (1).png
coverY: 0
layout:
  cover:
    visible: true
    size: full
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

# Deleted File or File Knowledge

### Thumbs.db

**Description: Hidden file in the directory where images on the machine exist stored in smaller thumbnail graphics.** Thumbs.db catalogues pictures in a folder and stores a copy of the thumbnail even if the pictures were deleted.

**Location:**

Each folder maintains a separate Thumbs.db file after being viewed in thumbnail view (OS version dependent)

**Interpretation:**

Includes:

* Thumbnail image of the original picture
* Last Modification Time (XP Only)
* Original Filename (XP Only)
* Most relevant for XP systems, but Thumbs.db files can be created on more modern OS versions in unusual circumstances, such as when folders are viewed via UNC paths.

### Thumbcache

**Description:** Thumbnails of pictures, documents, and folders exist in a set of databases called the thumbcache. It is maintained for each user based on the thumbnail sizes viewed (e.g., small, medium, large, and extra large). It can catalog the previous contents of a folder even upon file deletion. (Available in Windows Vista+)&#x20;

**Location:**

```cs
%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer
```

**Interpretation:**

* Database files are named similarly to: Thumbcache\_256.db
* Each database file represents thumbnails stored in different sizes or to fit different user interface components
* Thumbnail copies of pictures can be extracted, and the Thumbnail Cache ID can be cross-referenced within the Windows Search Database to identify the filename, path, and additional file metadata&#x20;

**Tools:**

```cs
thumbcache_viewer.exe
thumbs_viewer.exe
```

### Recycle Bin

**Description:** When a user deletes a file, the file is moved into a temporary storage location for deleted files named Recycle Bin. Windows creates two files each time a file is placed in the Recycle Bin $I and $R with a string six-character identifier generated for each file. $R file is a renamed copy of the “deleted” file. While the $I file replaces the usage INFO2 file as the source of accompanying metadata.&#x20;

**Location:**

Hidden System Folder

```cs
C:\$Recycle.Bin
```

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

Parse with Zimmerman Tool (RBCmd.exe)

{% code overflow="wrap" %}
```cs
RBCmd.exe -f \$Recycle.Bin\SID-Of-Interest\$Ifile-of-interest.png
RBCmd.exe -d C:\$Recycle.Bin\ -q --csv \Users\angliad\Desktop\ --csvf username-recycle-bin.csv
```
{% endcode %}

**Forensic Value:**

1. The original file name and path
2. The deleted file size
3. The date and time of deletion

### Internet Explorer File

**Description: Internet Explorer History databases have long-held information on local and remote (via network shares) file access, giving us an excellent means for determining files accessed on the system per user.** Information can be present even on Win11+ systems missing the Internet Explorer application.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
IE10-11 and Win10+: %USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat
```
{% endcode %}

**Interpretation:**

```cs
- Entries are recorded as: file:///C:/<directory>/<filename>.<ext>
```

* It does not mean the file was opened in a browser

### WordWheelQuery

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

**Tools:**

```cs
RegRipper (rr.exe) 
RegistryExplorer.exe
```

**Forensic Value:**

1. User Activity
2. Last folder search conducted (Last Write Time
3. Keywords searched

### Last Visited Most Recently Used (MRU)

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

**Interpretation:**

&#x20;We get two important pieces of information from this key: applications executed by the user, and the last place in the file system that those applications interacted with. Interesting and hidden directories are often identified via this registry key.&#x20;

**Tools for investigation:**

* Regedit or other registry viewer applications.

### Windows Search Database

**Description:** Windows Search indexes more than 900 file types, including email and file metadata, allowing users to search based on keywords.&#x20;

**Location:**

```cs
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex
```

**Interpretation:**

* Database in Extensible Storage Engine format
* Gather logs contain a candidate list for files to be indexed over each 24 hours
* Extensive file metadata and even partial content can be present.
