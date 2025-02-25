---
cover: ../../.gitbook/assets/Screenshot 2025-01-04 151057.png
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

# First Responder Cyber Incident Response Playbook

### Objective

As a first responder, your mission is to:

* Detect and assess a cyber incident across an enterprise Windows environment.
* Contain the threat to prevent escalation, lateral movement, or data loss.
* Collect and preserve forensic evidence, including detailed Windows artefacts.
* Document all actions for legal, compliance, and IR team handoff.

***

### Section 1: Pre-Incident Preparation

1.1 Environment Familiarisation

{% tabs %}
{% tab title="Asset Management" %}
{% code overflow="wrap" %}
```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object @{N='Name';E={$_.CSName}},@{N='OS';E={$_.Caption}},@{N='Version';E={$_.Version}},@{N='Build';E={$_.BuildNumber}},@{N='InstallDate';E={$_.InstallDate}},@{N='LastBoot';E={$_.LastBootUpTime}},@{N='FreeMemoryMB';E={[math]::Round($_.FreePhysicalMemory/1024,2)}} | Export-Csv "C:\Inventory\device_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
```
{% endcode %}
{% endtab %}

{% tab title="Network IP Details" %}
{% code overflow="wrap" %}
```powershell
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" | Select-Object @{N='Adapter';E={$_.Description}},@{N='IPAddress';E={($_.IPAddress -join ', ')}},@{N='Subnet';E={($_.IPSubnet -join ', ')}},@{N='Gateway';E={($_.DefaultIPGateway -join ', ')}},@{N='MAC';E={$_.MACAddress}},@{N='DHCP';E={$_.DHCPEnabled}},@{N='DNSServers';E={($_.DNSServerSearchOrder -join ', ')}} | Export-Csv "C:\Inventory\ip_details_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
```
{% endcode %}
{% endtab %}

{% tab title="Baseline Monitoring KQL" %}
{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| summarize ConnectedIPs = make_set(RemoteIP), Protocols = make_set(Protocol), EventCount = count() by DeviceName, LocalIP
| project DeviceName, LocalIP, ConnectedIPs, Protocols, EventCount
```
{% endcode %}



{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| summarize ConnectedIPs = make_set(RemoteIP), Protocols = make_set(Protocol), ConnectionCount = count() by DeviceName, LocalIP
| project DeviceName, LocalIP, ConnectedIPs, Protocols, ConnectionCount
```
{% endcode %}
{% endtab %}
{% endtabs %}

1.2 Incident Response Toolkit

* Tools: MDE, Sentinel, Splunk, PowerShell, Velociraptor, KAPE, Eric Zimmerman’s Tools, Magnet Axiom Cyber, Cyber Triage, Sysinternals, Wireshark, FTK Imager.

***

### Section 2: Incident Detection and Initial Assessment

2.1 Detection Triggers

{% tabs %}
{% tab title="Security Event (KQL)" %}
{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (4624, 4625, 4672, 4688) // Common security-related Event IDs
| project TimeGenerated, Account, EventID, Activity, Computer, IpAddress
| order by TimeGenerated desc
```
{% endcode %}
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows sourcetype="WinEventLog:Security" EventCode IN (4624, 4625, 4672, 4688)
| table _time, user, EventCode, action, host, src_ip
| sort - _time
```
{% endcode %}
{% endtab %}
{% endtabs %}

2.2 Scope Assessment

{% tabs %}
{% tab title="Sentinel" %}
{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where FileName == "svch0st.exe"
| summarize AffectedHosts = dcount(DeviceName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), ProcessCount = count(), AffectedHostsList = make_set(DeviceName) by FileName
```
{% endcode %}
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=edr process_name="svch0st.exe"
| stats dc(host) as AffectedHosts, earliest(_time) as FirstSeen, latest(_time) as LastSeen, count as ProcessCount, values(host) as AffectedHostsList by process_name
```
{% endcode %}
{% endtab %}
{% endtabs %}

2.3 Documentation Kickoff

* Timeline: Add-Content -Path E:\Evidence\timeline.txt -Value "$(Get-Date -Format "MM/dd/yyyy HH:mm EST") - Detection"

***

### Section 3: Containment (Short-Term)

3.1 Network-Level Containment

{% tabs %}
{% tab title="Defender (Live Response)" %}
#### **Isolate a Device Using the Defender Live Response Console**

1.  Initiate Live Response Session

    Click Go Hunt → Initiate Live Response session.
2.  Isolate the Device

    In the Live Response console, enter:

    ```powershell
    isolate
    ```

    To verify isolation status:

    ```
    isolationstatus
    ```
3.  (Optional) Release Isolation

    To reconnect the device:

    ```
    release
    ```
{% endtab %}

{% tab title="PowerShell (Live Response)" %}


Steps to Isolate a Device Using Live Response in Microsoft Defender

1. Start a Live Response Session:
   * On the device’s page, look for the ellipsis (...) in the top-right corner of the Response Actions section.
   * Select Initiate Live Response Session (you might need to expand "Advanced actions" depending on your UI version).
   * Confirm the action if prompted. Once the session starts, a command-line interface (CLI) will appear in the portal with a prompt like Connected to \<DeviceName>.
2. Execute Commands to Isolate the Device:
   *   In the Live Response CLI, you’ll manually disable network connectivity to isolate the device. Since Live Response supports PowerShell, you can run a command to disable all active network adapters:

       {% code overflow="wrap" %}
       ```powershell
       run powershell.exe -Command "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Disable-NetAdapter -Confirm:$false"
       ```
       {% endcode %}

       * What this does:
         * Get-NetAdapter: Lists all network adapters on the device.
         * Where-Object { $\_.Status -eq 'Up' }: Filters for only active adapters.
         * Disable-NetAdapter -Confirm:$false: Disables them without prompting.
       * Result: The device loses network connectivity, but Defender’s cloud communication typically persists due to its low-level sensor exceptions.
3. Verify the Isolation:
   *   Check the network adapter status to confirm:

       {% code overflow="wrap" %}
       ```powershell
       run powershell.exe -Command "Get-NetAdapter | Select-Object Name, Status | Out-File C:\temp\netstatus.txt"
       ```
       {% endcode %}

       * This saves the adapter status to a file on the device.
   *   Retrieve the file to review:

       ```powershell
       getfile C:\temp\netstatus.txt
       ```

       * The output should show all adapters as "Disabled" (except possibly virtual adapters used by Defender).
   *   Alternatively, test connectivity:

       ```powershell
       run cmd.exe -Command "ping 8.8.8.8"
       ```

       * If isolated, this should fail or timeout.
4. End the Live Response Session:
   *   Once you’ve confirmed isolation, type:

       ```powershell
       exit
       ```

       * Or click Disconnect Session in the portal UI to close the session.

Optional: Use a Pre-Uploaded ScriptFor efficiency or reusability, you can upload a PowerShell script to the Live Response library beforehand:

* Go to Settings > Endpoints > Live Response > Library > Upload File.
*   Upload this script (e.g., isolate\_device.ps1):

    {% code overflow="wrap" %}
    ```powershell
    # Isolate device by disabling network adapters
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false
    Write-Output "Device isolated - network adapters disabled."
    ```
    {% endcode %}
*   In the Live Response session, run it:

    ```powershell
    run isolate_device.ps1
    ```
{% endtab %}

{% tab title="PowerShell" %}
{% code overflow="wrap" %}
```powershell
New-NetFirewallRule -DisplayName "BlockC2" -RemoteAddress 203.0.113.5 -Action Block
```
{% endcode %}

**PowerShell Function: Isolate-Devicepowershell**

{% code overflow="wrap" %}
```powershell
function Isolate-Device {
    param (
        [string]$DeviceName
    )

    try {
        Invoke-Command -ComputerName $DeviceName -ScriptBlock {
            # Get all active network adapters
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
            if ($adapters) {
                # Collect the names of the active adapters
                $adapterNames = $adapters | ForEach-Object { $_.Name }
                # Disable the active adapters without confirmation
                Disable-NetAdapter -Name $adapterNames -Confirm:$false -ErrorAction Stop
                # Log the isolation action in the event log
                Write-EventLog -LogName Application -Source "Windows PowerShell" -EventId 1000 -Message "Device isolated by disabling adapters: $($adapterNames -join ', ')"
            } else {
                # Log if no active adapters were found
                Write-EventLog -LogName Application -Source "Windows PowerShell" -EventId 1000 -Message "No active network adapters found to disable."
            }
        } -ErrorAction Stop
        Write-Host "Successfully isolated device: $DeviceName"
    } catch {
        Write-Error "Failed to isolate device: $DeviceName. Error: $_"
    }
}
```
{% endcode %}

***

How to Use the Script

1. Run the Script: Ensure you have this function loaded in your PowerShell session (e.g., save it in a .ps1 file and dot-source it, or paste it directly into your session).
2.  Call the Function: Execute the function by providing the target device’s name, like this:powershell

    ```powershell
    Isolate-Device -DeviceName "TargetComputerName"
    ```

    Replace "TargetComputerName" with the actual name of the device you want to isolate.

***

**PowerShell Function: Enable-Devicepowershell**

{% code overflow="wrap" %}
```powershell
function Enable-Device {
    param (
        [string]$DeviceName
    )

    try {
        Invoke-Command -ComputerName $DeviceName -ScriptBlock {
            # Get all disabled network adapters
            $adapters = Get-NetAdapter | Where-Object { $_.Status -ne 'Up' }
            if ($adapters) {
                # Collect the names of the disabled adapters
                $adapterNames = $adapters | ForEach-Object { $_.Name }
                # Enable the disabled adapters without confirmation
                Enable-NetAdapter -Name $adapterNames -Confirm:$false -ErrorAction Stop
                # Log the re-enablement action in the event log
                Write-EventLog -LogName Application -Source "Windows PowerShell" -EventId 1001 -Message "Device re-enabled by enabling adapters: $($adapterNames -join ', ')"
            } else {
                # Log if no disabled adapters were found
                Write-EventLog -LogName Application -Source "Windows PowerShell" -EventId 1001 -Message "No disabled network adapters found to enable."
            }
        } -ErrorAction Stop
        Write-Host "Successfully re-enabled device: $DeviceName"
    } catch {
        Write-Error "Failed to re-enable device: $DeviceName. Error: $_"
    }
}
```
{% endcode %}

***

How to Use the Script

1. Load the Function: Save this script in a .ps1 file (e.g., Enable-Device.ps1) and dot-source it in your PowerShell session (. .\Enable-Device.ps1), or paste it directly into your session.
2.  Run the Function: Execute it by providing the target device’s name:powershell

    ```powershell
    Enable-Device -DeviceName "TargetComputerName"
    ```

    Replace "TargetComputerName" with the name of the device you want to re-enable.

***
{% endtab %}
{% endtabs %}

3.2 System-Level Containment

{% tabs %}
{% tab title="PowerShell for Manual System-Level Containment" %}
This method assumes remote or local execution capability.

Script: Comprehensive Containmentpowershell

{% code overflow="wrap" %}
```powershell
# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Run as Administrator required."
    exit
}

# Disable all active network adapters
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
if ($adapters) {
    $adapterNames = $adapters | ForEach-Object { $_.Name }
    Disable-NetAdapter -Name $adapterNames -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Network adapters disabled: $adapterNames"
} else {
    Write-Host "No active adapters found."
}

# Block all outbound and inbound traffic with Windows Firewall
New-NetFirewallRule -DisplayName "Block All Outbound" -Direction Outbound -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Block All Inbound" -Direction Inbound -Action Block -Enabled True
Write-Host "Firewall rules applied to block all traffic."

# Optional: Stop non-essential services (e.g., file sharing)
Stop-Service -Name "Server" -Force -ErrorAction SilentlyContinue
Stop-Service -Name "Workstation" -Force -ErrorAction SilentlyContinue
Write-Host "Stopped non-essential services."
```
{% endcode %}

How It Works:

* Network Adapters: Disables all active adapters, cutting physical network access.
* Firewall Rules: Blocks all inbound and outbound traffic as a secondary layer, even if adapters are re-enabled.
* Services: Stops services like "Server" (SMB sharing) and "Workstation" (SMB client) to limit local network interactions.

Usage:

* Run locally: Save as Contain-System.ps1 and execute in an elevated PowerShell session.
* Run remotely: Use Invoke-Command -ComputerName "TargetDevice" -ScriptBlock { \<script above> } if remoting is still available.

Reversal: PowerShell

{% code overflow="wrap" %}
```powershell
# Re-enable adapters
Enable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -ne 'Up' } | ForEach-Object { $_.Name }) -Confirm:$false
# Remove firewall rules
Remove-NetFirewallRule -DisplayName "Block All Outbound"
Remove-NetFirewallRule -DisplayName "Block All Inbound"
# Restart services
Start-Service -Name "Server"
Start-Service -Name "Workstation"
```
{% endcode %}

***

3\. Windows Firewall for Network ContainmentIf physical adapter control isn’t desired, you can use the Windows Firewall to block all network traffic at the system level.

Steps (via PowerShell): PowerShell

{% code overflow="wrap" %}
```powershell
# Block all traffic
New-NetFirewallRule -DisplayName "Containment Outbound" -Direction Outbound -Action Block -Enabled True
New-NetFirewallRule -DisplayName "Containment Inbound" -Direction Inbound -Action Block -Enabled True
```
{% endcode %}

Why This Works:

* Firewall rules apply system-wide, preventing all network communication regardless of adapter state.
* Easier to reverse than disabling adapters, as it doesn’t require physical access if remoting is lost.

Reversal: PowerShell

```powershell
Remove-NetFirewallRule -DisplayName "Containment Outbound"
Remove-NetFirewallRule -DisplayName "Containment Inbound"
```

***

4\. Defender Live Response for Containment&#x20;

You can manually execute commands to isolate a device.&#x20;

Steps:

1.  Start Live Response:

    Go to the device page in the Defender portal and select Initiate Live Response Session.
2.  Disable Adapters:

    Run:

    {% code overflow="wrap" %}
    ```cmake
    run cmd.exe -Command "for /f \"skip=1\" %%a in ('wmic path Win32_NetworkAdapter where \"DeviceEnabled=true\" get DeviceID') do (wmic path Win32_NetworkAdapter where \"DeviceID='%%a'\" call Disable)"
    ```
    {% endcode %}
3.  Verify:

    Check status:

    {% code overflow="wrap" %}
    ```powershell
    run cmd.exe -Command "wmic path Win32_NetworkAdapter get DeviceID, DeviceEnabled"
    ```
    {% endcode %}

Reversal:

Re-enable adapters:

{% code overflow="wrap" %}
```powershell
run cmd.exe -Command "for /f \"skip=1\" %%a in ('wmic path Win32_NetworkAdapter get DeviceID') do (wmic path Win32_NetworkAdapter where \"DeviceID='%%a'\" call Enable)"
```
{% endcode %}

***
{% endtab %}

{% tab title="Disable RDP" %}
Command modifies a specific registry key on a Windows system to disable remote desktop (RDP) connections.

{% code overflow="wrap" %}
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
```
{% endcode %}

VerificationTo confirm the change:

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
```
{% endcode %}

Look for fDenyTSConnections : 1 in the output.

**Reversal**&#x20;

To re-enable Remote Desktop:

{% code overflow="wrap" %}
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
```
{% endcode %}

To fully stop the service:

```powershell
Stop-Service -Name TermService -Force
```
{% endtab %}
{% endtabs %}

3.3 Enterprise-Wide Checks

{% tabs %}
{% tab title="Defender (KQL)" %}
Basic Check:

```kusto
DeviceFileEvents
| where FileName contains "ransom"
```
{% endtab %}

{% tab title="Defender KQL" %}
{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where FileName has "ransom" or InitiatingProcessFileName has "ransom"
| where ActionType in ("FileCreated", "FileModified", "FileDeleted", "FileRenamed")
| extend FilePath = tolower(strcat(FolderPath, "\\", FileName))
| summarize 
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    AffectedDevices = dcount(DeviceName),
    FilePaths = make_set(FilePath),
    InitiatingProcesses = make_set(InitiatingProcessFileName)
    by FileName, ActionType
| where EventCount > 1 or AffectedDevices > 1
| order by LastSeen desc
```
{% endcode %}
{% endtab %}
{% endtabs %}

***

### Section 4: Evidence Collection

4.1 Volatile Data Collection

* PowerShell: netstat -ano | Out-File E:\Evidence\netstat.txt
* Velociraptor: velociraptor.exe collect -a Windows.Memory.Acquisition --output E:\Evidence\memory.bin

4.2 Non-Volatile Data Collection

* KAPE: kape.exe --tsource C: --tdest E:\Evidence --target SANS\_Triage

4.3 Memory and Disk Imaging

* FTK Imager: ftkimager.exe "PhysicalDrive0" E:\Evidence\memory.dmp --mem

***

### Section 5: Windows Forensic Artefacts

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

### Section 6: Initial Analysis

6.1 Threat Identification

* MDE: KQL: DeviceProcessEvents | where FileName == "svch0st.exe"
* Cyber Triage: CyberTriage.exe --analyze --input E:\Evidence\kape\_output

6.2 Persistence Detection

* Autoruns: autoruns.exe -a E:\Evidence\autoruns.ar

6.3 Network Analysis

* Wireshark: wireshark -r E:\Evidence\network.pcap -Y "ip.addr == 203.0.113.5"

***

Section 7: Escalation and Reporting

7.1 Notify Stakeholders

* PowerShell: Send-MailMessage -To "ciso@contoso.com" -Subject "Incident 2025-02-25"

7.2 Secure Evidence

* BitLocker: manage-bde -on E: -RecoveryPassword 123456-789012-...

7.3 Handoff

* Log: “02/25/2025 15:30 EST – Evidence to IR Lead.”

***

### Section 8: Do’s and Don’ts

* Do: Collect all artefact types; use multiple tools for validation.
* Don’t: Alter timestamps; skip artefact collection.

***

### Example Scenario: Malware Execution

1. 14:30 EST: MDE alert → svch0st.exe.
2. 14:35 EST: Isolate → isolate in MDE.
3. 14:40 EST: KAPE → kape.exe --tsource C: --tdest E:\Evidence --target Prefetch,Amcache
4. 14:50 EST: PowerShell → Get-WinEvent -LogName "Security" | Where-Object { $\_.Id -eq 4624 } | Export-Csv E:\Evidence\logins.csv
5. 15:00 EST: PECmd → PECmd.exe -d "C:\Windows\Prefetch" --csv E:\Evidence\prefetch.csv
6. 15:15 EST: Escalate.

***
