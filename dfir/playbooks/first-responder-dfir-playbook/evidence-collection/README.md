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

# Evidence Collection

Efficient tools and capabilities for Digital Forensics and Incident Response (DFIR) evidence collection are critical in today’s fast-evolving cyber threat landscape, where time is often the deciding factor in mitigating damage and preserving evidence. When a security incident occurs—be it a ransomware attack, data breach, or insider threat—the window to collect volatile data, such as running processes, network connections, or memory contents, can close within minutes as systems are powered off or adversaries cover their tracks. Tools like KAPE, Velociraptor, and FTK Imager enable responders to rapidly acquire triage data or full forensic images, ensuring that ephemeral evidence isn’t lost.&#x20;

This speed accelerates the identification of attack vectors and compromised assets and supports timely containment, reducing the potential for prolonged downtime, financial loss, or reputational harm. Beyond speed, efficiency in DFIR tools enhances the accuracy and reliability of evidence collection, which is foundational for both technical resolution and legal admissibility. Modern tools are designed to minimise system impact while maximising data integrity—features like write-blocking, hash verification (e.g., MD5/SHA1 in FTK Imager), and structured output formats (e.g., JSONL in Velociraptor) ensure that collected evidence remains unaltered and defensible in court. Inefficient or manual methods, such as relying solely on native OS commands, risk missing critical artefacts, introducing errors, or failing to meet chain-of-custody standards. Efficient tools automate repetitive tasks, reduce human error, and provide comprehensive coverage—capturing everything from registry hives to unallocated disk space—enabling analysts to confidently build a complete picture of the incident.&#x20;

Robust DFIR capabilities foster organisational resilience and preparedness, aligning technical responses with business and regulatory demands. Efficient tools allow teams to scale evidence collection across multiple endpoints, whether for a single compromised laptop or a network-wide breach, without overwhelming limited resources. This scalability is vital for meeting compliance requirements (e.g., GDPR, HIPAA) that mandate rapid incident reporting and evidence preservation. Moreover, streamlined workflows—such as KAPE’s triage collections or PowerShell’s scripted automation—empower even smaller teams to handle complex investigations, freeing them to focus on analysis and remediation rather than collection logistics. Investing in efficient DFIR tools transforms evidence collection from a bottleneck into a strategic advantage, strengthening an organisation’s ability to respond, recover, and defend against future threats.

The following page of this playbook provides some guidance for conducting DFIR in a Windows environment.

[Acquire Triage Image Using Kape](acquire-triage-image-using-kape.md)

[Acquire Triage Data Using Velociraptor](acquire-triage-data-using-velociraptor.md)

[Acquire Triage Data Using PowerShell](acquire-triage-data-using-powershell.md)

[Acquire Triage Memory Image](acquire-triage-memory-image.md)

[Acquire Image Using FTK](acquire-image-using-ftk.md)

### System and user Information (via Registry) <a href="#system-and-user-information-via-registry" id="system-and-user-information-via-registry"></a>

<table><thead><tr><th width="261">Filesystem</th><th>Location</th><th>Tools or Commands</th></tr></thead><tbody><tr><td>Operating System Version</td><td><code>SOFTWARE\Microsoft\Windows NT\CurrentVersion</code></td><td>Registry Explorer</td></tr><tr><td>System Boot &#x26; Autostart Programs</td><td>Run registries</td><td>Registry Explorer</td></tr><tr><td>Computer Name</td><td><code>SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName</code></td><td>Registry Explorer</td></tr><tr><td>System Last Shutdown Time</td><td><code>SYSTEM\CurrentControlSet\Control\Windows</code></td><td>Registry Explorer</td></tr><tr><td>Cloud Account Details</td><td><code>SAM\Domains\Account\Users\&#x3C;RID>\InternetUserName</code></td><td>Registry Explorer</td></tr><tr><td>User Accounts</td><td><code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList</code></td><td>Registry Explorer</td></tr><tr><td>Last Login and Password Change</td><td><code>SAM\Domains\Account\Users</code></td><td>Registry Explorer</td></tr></tbody></table>

### Application Execution <a href="#application-execution" id="application-execution"></a>

| Filesystem                          | Location                                                                                     | Tools or Commands                                                                                              |
| ----------------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Shimcache                           | `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache`                             | RegRipper                                                                                                      |
| Amcache.hve                         | `C:\Windows\AppCompat\Programs\Amcache.hve`                                                  | Registry Explorer                                                                                              |
| UserAssist                          | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\`                  | Registry Explorer                                                                                              |
| Win10 Timeline                      | `C:\%USERPROFILE%\AppData\Local\ConnectedDevicesPlatform\L.Administrator\ActivitiesCache.db` | `WxTCmd.exe -f "ActivitiesCache.db" --csv D:\Hands-On`                                                         |
| SRUM                                | `C:\Windows\System32\sru\SRUDB.dat`                                                          | srum-dump                                                                                                      |
| BAM / DAM                           | `SYSTEM\ControlSet001\Services\bam\State\UserSettings\`                                      | Registry Explorer                                                                                              |
| Prefetch, MFT, USNJ                 | `C:\Windows\prefetch`                                                                        | `PECmd.exe -d D:\Windows\Prefetch, MFT, USNJ--csv "D:\Hands-On" --csvf prefetch.csv` or WinPrefetch, MFT, USNJ |
| Task Bar Feature Usage              | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage`                     | Registry Explorer                                                                                              |
| Jumplist                            | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`            | Jumplist Explorer                                                                                              |
| Last Visited MRU                    | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`  | RegRipper                                                                                                      |
| CapabilityAccessManager             | `NTUSER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore`      | Registry Explorer                                                                                              |
| Commands Executed in the Run Dialog | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`                           | Registry Explorer                                                                                              |
| Services                            | `System\CurrentControlSet\Services`                                                          | Registry Explorer                                                                                              |

### File and Folder Opening <a href="#file-and-folder-opening" id="file-and-folder-opening"></a>

| Filesystem                 | Location                                                                                        | Tools or Commands  |
| -------------------------- | ----------------------------------------------------------------------------------------------- | ------------------ |
| Shellbag                   | `NTUSER.dat\Software\Microsoft\Windows\Shell\Bags`                                              | Shellbags Explorer |
| Open/Save MRU              | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`        | Registry Explorer  |
| Shortcut (LNK) Files       | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\|Office\Recent\`                               | Autopsy            |
| Jumplist                   | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`               | Jumplist Explorer  |
| Recent Files               | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`                      | Registry Explorer  |
| Office Recent Files        | `NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>`                                      | Registry Explorer  |
| Office Trust Records       | `NTUSER\Software\Microsoft\Offi ce\<Version>\<AppName>\Security\Trusted Documents\TrustRecords` | Registry Explorer  |
| MS Word Reading Locations  | `NTUSER\Software\Microsoft\Offi ce\<Version>\Word\Reading Locations`                            | Registry Explorer  |
| Office OAlerts             | OAlerts.evtx                                                                                    | Event log explorer |
| Last Visited MRU           | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`     | Registry Explorer  |
| Internet Explorer file:/// | `%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat`                         | Text Editor        |

### Deleted Items and File Existence <a href="#deleted-items-and-file-existence" id="deleted-items-and-file-existence"></a>

| Filesystem                 | Location                                                                       | Tools or Commands                    |
| -------------------------- | ------------------------------------------------------------------------------ | ------------------------------------ |
| Recycle Bin                | `C:\$Recycle.Bin`                                                              | Recbin                               |
| Thumbcache                 | `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`                       | Thumbcache Viewer                    |
| User Typed Paths           | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`         | Registry Explorer                    |
| Search – WordWheelQuery    | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | Registry Explorer                    |
| Internet Explorer file:/// | `%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat`        | Text Editor                          |
| Windows Search Database    | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`        | LostPassword’s Search Index Examiner |

### Browser Activity <a href="#browser-activity" id="browser-activity"></a>

| Filesystem       | Location                                             | Tools or Commands |
| ---------------- | ---------------------------------------------------- | ----------------- |
| Browser activity | `C:\Users\%user%\AppData\Local\\Roaming\BrowserName` | DBBrowser         |

### Network Usage <a href="#network-usage" id="network-usage"></a>

| Filesystem         | Location                                                        | Tools or Commands |
| ------------------ | --------------------------------------------------------------- | ----------------- |
| Network History    | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Network*`         | Registry Explorer |
| Timezone           | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`          | Registry Explorer |
| WLAN Event Log     | `Microsoft-Windows-WLAN-AutoConfig Operational.evtx`            | Event log viewer  |
| Network Interfaces | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` | Registry Explorer |
| SRUM               | `C:\Windows\System32\sru\SRUDB.dat`                             | srum-dump         |

### USB Usage <a href="#usb-usage" id="usb-usage"></a>

| Filesystem                   | Location                                                                                                 | Tools or Commands |
| ---------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------- |
| USB Device Identification    | `SYSTEM\CurrentControlSet\Enum\*`                                                                        | Registry Explorer |
| Drive Letter and Volume Name | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` and `SYSTEM\MountedDevices`                        | Registry Explorer |
| User Information             | `SYSTEM\MountedDevices` and `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Registry Explorer |
| Connection Timestamps        | `SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_&Prod_\USBSerial`                                        | Registry Explorer |
| Volume Serial Number (VSN)   | `SOFTWARE\Microsoft\WindowsNT\CurrentVersion\EMDMgmt`                                                    | Registry Explorer |
| Shortcut (LNK) Files         | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\\Office\Recent\`                                        | Autopsy           |
| Event Logs                   | `System.evtx`                                                                                            | Event log viewer  |



### Reference

[https://fareedfauzi.github.io/2023/12/22/Windows-Forensics-checklist-cheatsheet.html](https://fareedfauzi.github.io/2023/12/22/Windows-Forensics-checklist-cheatsheet.html)\
[https://www.jaiminton.com/cheatsheet/DFIR/#](https://www.jaiminton.com/cheatsheet/DFIR/)\
[https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md)
