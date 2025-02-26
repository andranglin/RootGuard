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

# Windows Forensic Artefacts

5.1 Application Execution

Prefetch

* Purpose: Tracks application execution times and associated files.
* Location: C:\Windows\Prefetch\\\*.pf
* Collection:
  * PowerShell: Get-ChildItem "C:\Windows\Prefetch" | Export-Csv E:\Evidence\prefetch\_files.csv
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target Prefetch
  * Eric Zimmerman’s PECmd: PECmd.exe -d "C:\Windows\Prefetch" --csv E:\Evidence\prefetch.csv
* Analysis: Look for unusual executables (e.g., SVCH0ST.EXE-12345678.pf).

Amcache

* Purpose: Logs application execution history and SHA-1 hashes.
* Location: C:\Windows\appcompat\Programs\Amcache.hve
* Collection:
  * PowerShell: Copy-Item "C:\Windows\appcompat\Programs\Amcache.hve" -Destination E:\Evidence\amcache.hve
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target Amcache
  * Eric Zimmerman’s AmcacheParser: AmcacheParser.exe -f "E:\Evidence\amcache.hve" --csv E:\Evidence\amcache.csv
* Analysis: Check for recently executed suspicious files.

Jump Lists

* Purpose: Tracks recently opened files per application.
* Location: C:\Users\\\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
* Collection:
  * PowerShell: Get-ChildItem "C:\Users\\\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -Recurse | Export-Csv E:\Evidence\jumplists.csv
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target JumpLists
  * Eric Zimmerman’s JLECmd: JLECmd.exe -d "C:\Users\CompromisedUser\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv E:\Evidence\jumplists.csv
* Analysis: Identify files accessed by malware.

Shimcache

* Purpose: Tracks executed applications via Application Compatibility shim.
* Location: Registry HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
* Collection:
  * PowerShell: reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" E:\Evidence\shimcache.reg /y
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target ShimCache
  * Eric Zimmerman’s AppCompatCacheParser: AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv E:\Evidence\shimcache.csv
* Analysis: Detect historical execution of malicious binaries.

5.2 File & Folder Knowledge

Recent Files

* Purpose: Tracks recently accessed files.
* Location: C:\Users\\\*\AppData\Roaming\Microsoft\Windows\Recent\\\*.lnk
* Collection:
  * PowerShell: Get-ChildItem "C:\Users\\\*\AppData\Roaming\Microsoft\Windows\Recent" -Recurse | Export-Csv E:\Evidence\recent\_files.csv
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target RecentDocs
* Analysis: Look for ransomware-encrypted file access.

LNK Files

* Purpose: Shortcut files with metadata about target files.
* Location: C:\Users\\\*\AppData\Roaming\Microsoft\Windows\Recent\\
* Collection:
  * PowerShell: Get-ChildItem "C:\Users\\\*\AppData\Roaming\Microsoft\Windows\Recent\\\*.lnk" | Export-Csv E:\Evidence\lnk\_files.csv
  * Eric Zimmerman’s LECmd: LECmd.exe -d "C:\Users\CompromisedUser\AppData\Roaming\Microsoft\Windows\Recent" --csv E:\Evidence\lnk.csv
* Analysis: Trace file origins and timestamps.

Shell Bags

* Purpose: Records folder access history.
* Location: Registry HKCU\Software\Microsoft\Windows\Shell\Bags
* Collection:
  * PowerShell: reg export "HKCU\Software\Microsoft\Windows\Shell\Bags" E:\Evidence\shellbags.reg /y
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target ShellBags
  * Eric Zimmerman’s ShellBag Explorer: SBECmd.exe -d "C:\Users\CompromisedUser\NTUSER.DAT" --csv E:\Evidence\shellbags.csv
* Analysis: Identify accessed directories.

Recycle Bin

* Purpose: Tracks deleted files.
* Location: C:\\$Recycle.Bin\\
* Collection:
  * PowerShell: Get-ChildItem "C:\\$Recycle.Bin" -Recurse -Force | Export-Csv E:\Evidence\recycle\_bin.csv
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target RecycleBin
* Analysis: Recover deleted malware or evidence.

5.3 External Device Usage

Connection Timestamps & Device Information

* Purpose: Tracks USB and external device connections.
* Location: Registry HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR, Event Logs (ID 10000).
* Collection:
  * PowerShell: Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\\\*" | Export-Csv E:\Evidence\usbstor.csv
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target USBDevices
  * Velociraptor: velociraptor.exe collect -a Windows.USB.Devices --output E:\Evidence\usb.json
  * Event Logs: Get-WinEvent -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" | Where-Object { $\_.Id -eq 10000 } | Export-Csv E:\Evidence\usb\_events.csv
* Analysis: Detect unauthorized device usage.

5.4 Network Activity

Network History

* Purpose: Logs network connections.
* Location: netstat, DNS cache, Event Logs.
* Collection:
  * PowerShell: netstat -ano | Out-File E:\Evidence\netstat.txt; ipconfig /displaydns | Out-File E:\Evidence\dns\_cache.txt
  * Velociraptor: velociraptor.exe collect -a Windows.Network.Netstat --output E:\Evidence\netstat.json
  * Wireshark: wireshark -i Ethernet -w E:\Evidence\network.pcap
* Analysis: Identify C2 traffic.

SRUM (System Resource Usage Monitor)

* Purpose: Tracks network and application usage over time.
* Location: C:\Windows\System32\sru\SRUDB.dat
* Collection:
  * PowerShell: Copy-Item "C:\Windows\System32\sru\SRUDB.dat" -Destination E:\Evidence\srudb.dat
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target SRUM
  * Eric Zimmerman’s SRUM Dump: SRUmdump.exe -f "E:\Evidence\srudb.dat" --csv E:\Evidence\srum.csv
* Analysis: Correlate app execution with network activity.

5.5 Event Logs

Windows Event Logs

* Collection:
  * PowerShell: Get-WinEvent -LogName "Security" -MaxEvents 5000 | Export-Clixml E:\Evidence\security.xml
  * KAPE: kape.exe --tsource C: --tdest E:\Evidence --target EventLogs
  * Velociraptor: velociraptor.exe collect -a Windows.EventLogs.Security --output E:\Evidence\security\_logs.json

Creating an Event Log Timeline

* PowerShell:
  * Get-WinEvent -LogName @("Security","System","Application") -MaxEvents 10000 | Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated | Export-Csv E:\Evidence\event\_timeline.csv
* Eric Zimmerman’s EvtxECmd:
  * EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv E:\Evidence\event\_timeline.csv
* Magnet Axiom Cyber: Load .evtx files → Export timeline.

Notable Event IDs – User Account Access

* 4624: Successful login – Get-WinEvent -LogName "Security" | Where-Object { $\_.Id -eq 4624 } | Export-Csv E:\Evidence\logins.csv
* 4625: Failed login – Get-WinEvent -LogName "Security" | Where-Object { $\_.Id -eq 4625 } | Export-Csv E:\Evidence\failed\_logins.csv

Notable Event IDs – User Account Management

* 4720: Account created – Get-WinEvent -LogName "Security" | Where-Object { $\_.Id -eq 4720 } | Export-Csv E:\Evidence\account\_creation.csv
* 4722: Account enabled – Get-WinEvent -LogName "Security" | Where-Object { $\_.Id -eq 4722 }

Notable Event IDs – Remote Desktop Activity

* 4624 (Logon Type 10): RDP login – Get-WinEvent -LogName "Security" | Where-Object { $\_.Id -eq 4624 -and $\_.Properties\[8].Value -eq 10 } | Export-Csv E:\Evidence\rdp\_logins.csv
* 1149: RDP connection – Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" | Where-Object { $\_.Id -eq 1149 }

Notable Event IDs – Hunting Persistence

* 7045: Service installed – Get-WinEvent -LogName "System" | Where-Object { $\_.Id -eq 7045 } | Export-Csv E:\Evidence\services.csv
* 4697: Service creation (Security) – Get-WinEvent -LogName "Security" | Where-Object { $\_.Id -eq 4697 }

Notable Event IDs – PowerShell Activity

* 4103: PowerShell execution – Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $\_.Id -eq 4103 } | Export-Csv E:\Evidence\powershell.csv
* 4104: Script block logging – Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object { $\_.Id -eq 4104 }

***
