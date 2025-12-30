# Evidence Collection

Speed and integrity determine whether evidence survives—and whether your investigation succeeds.

***

### Why Efficient Collection Matters

When an incident occurs, volatile evidence disappears fast. Running processes, network connections, and memory contents can be lost within minutes as systems shut down or attackers cover their tracks.

Efficient tooling solves three problems:

<table><thead><tr><th width="154">Challenge</th><th>Solution</th></tr></thead><tbody><tr><td><strong>Speed</strong></td><td>Rapid triage before volatile data is lost</td></tr><tr><td><strong>Integrity</strong></td><td>Write-blocking, hashing, and structured output ensure evidence is defensible</td></tr><tr><td><strong>Scale</strong></td><td>Collect across multiple endpoints without overwhelming limited resources</td></tr></tbody></table>

***

### Core Tooling

<table><thead><tr><th width="175">Tool</th><th>Primary Use</th></tr></thead><tbody><tr><td><strong>KAPE</strong></td><td>Rapid triage collection, targeted artifact acquisition</td></tr><tr><td><strong>Velociraptor</strong></td><td>Scalable collection across endpoints, structured JSONL output</td></tr><tr><td><strong>FTK Imager</strong></td><td>Full forensic imaging with hash verification</td></tr><tr><td><strong>PowerShell</strong></td><td>Scripted automation for live response</td></tr></tbody></table>

***

### Key Principles

* **Capture volatile data first** — Memory, processes, and network connections before disk artifacts
* **Maintain integrity** — Hash verification (MD5/SHA1/SHA256) and write-blocking preserve chain of custody
* **Automate collection** — Reduces human error and ensures comprehensive artifact coverage
* **Document everything** — Collection timestamps, methods, and personnel for legal admissibility

***

### Business Alignment

Efficient evidence collection supports:

* **Regulatory compliance** — GDPR, HIPAA, and others mandate rapid incident reporting and evidence preservation
* **Faster containment** — Quick identification of attack vectors reduces downtime and financial impact
* **Legal defensibility** — Properly collected evidence holds up in court and supports law enforcement engagement

***

_The following sections provide practical guidance for conducting DFIR collections in Windows environments._

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
