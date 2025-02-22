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

# File Download

### Open/Save Most Recently Used (MRU)

**Description:** The OpenSave MRU data is stored in a User’s NTUSER.DAT registry hive. It’s in two different locations depending on the version of Windows. They both have the same structure, though, which is sub-keys based on the file extension, such as “docx”, “txt”, or “zip”. This key tracks files opened or saved within a Windows shell dialog box. This big data set includes Microsoft Office applications, web browsers, chat clients, and the most commonly used applications.&#x20;

**Location:**

{% code overflow="wrap" %}
```cs
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDLg32\OpenSavePidlMRU
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
```
{% endcode %}

**Interpretation:**

Each extension sub-key can contain up to 20 values. Their name is a counter (0 to 19), and the value is a binary structure that contains the path (and other data). However, the path is not stored as an easy-to-read string. Instead, it is stored as a “PIDL”, a list of IDs representing entries in a folder. The file name is stored in the value, though in ASCII and UTF-16.

A “MRUListEx” value contains an ordered list of counters (i.e. 0 to 19) representing what order the files were last used. In the below example, you can see that two was the most recent, then 1, and then 0.

* The “\*” key – This subkey tracks the most recent files of any extension input in an OpenSave dialog
* .??? (Three-letter extension) – This subkey stores file info from the OpenSave dialog by specific extension

### Recent Files

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
* .??? – These subkeys store the last 20 files opened by the user of each extension type. MRU list tracks the temporal order in which each file was opened. The most recently used (MRU) item is associated with the key's last write time, providing one timestamp of file opening for each file extension type.
* Folder – This subkey stores the last 30 folders opened by the user. The most recently used (MRU) item in this key is associated with the key's last write time, providing the time of opening for that folder.

### Internet Explorer/Edge File

**Description: Internet Explorer History databases have long-held information on local and remote file access (via network shares), giving us an excellent means for determining files accessed on the system per user.** Information can be present even on Win11+ systems missing the Internet Explorer application.&#x20;

**Location:**

The Edge cached files are stored in the following directory:

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

### History and Download History

**Description:** History and Download History records websites visited by date and time. **Location** Firefox

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random text>.default\places.sqlite
```
{% endcode %}

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History
```

**Interpretation:**

* Web browser artifacts are stored for each local user account
* Most browsers also record the number of times visited (frequency)
* Look for multiple profiles in Chromium browsers, including “Default",  “Profile1", etc.

### Browser Downloads

**Description:** Modern browsers include built-in download manager applications capable of keeping a history of every file downloaded by the user. This browser artifact can provide excellent information about websites visited and corresponding items downloaded.&#x20;

**Location:**

Firefox 3-25

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\ Firefox\Profiles\<random text>.default\downloads.sqlite
```
{% endcode %}

Firefox 26+

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\places.sqlite- moz_annos table
```
{% endcode %}

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History
```

* Downloads and download\_url\_chains tables **Interpretation** Download metadata includes:
* Filename, size, and type
* Source website and referring page
* Download start and end times
* The file system saves the location
* State information, including success and failure

### Email Attachments

**Description:** The e-mail industry estimates that 80% of e-mail data is stored via attachments. E-mail standards only allow text. Attachments must be encoded in MIME / base64 format.&#x20;

**Location:**&#x20;

**Outlook**

```cs
%USERPROFILE%\AppData\Local\Microsoft\Outlook
```

**Interpretation:**

MS Outlook data files found in these locations include OST and PST files. One should also check the OLK and Content. Outlook folder, which might roam depending on the specific version of Outlook used.
