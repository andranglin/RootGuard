# Acquire Triage Data Using Powershell

### 1. Preparation

* Launch PowerShell: Open PowerShell as Administrator (powershell.exe or pwsh.exe for PowerShell Core). Right-click the Start menu > "Windows PowerShell (Admin)" or use Run > PowerShell > Ctrl+Shift+Enter.
*   Set Output Location: Define a directory for triage data (e.g., local drive or external USB). Create it with:

    ```powershell
    $OutputPath = "D:\TriageOutput"
    New-Item -Path $OutputPath -ItemType Directory -Force
    ```
*   Execution Policy: Check with Get-ExecutionPolicy. If restricted (Restricted), bypass it temporarily:

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
    </code></pre>
*   Logging: Start a transcript to log commands and output:powershell

    ```powershell
    Start-Transcript -Path "$OutputPath\PowerShellTranscript.txt"
    ```

### 2. Define Triage&#x20;

**Objectives**

For effective triage, collect artifacts that reveal system state, user activity, potential persistence, and compromise indicators:

* System info (OS, hardware, users)
* Running processes and services
* Network activity (connections, DNS, ARP)
* Event logs (system, security, application)
* Registry (persistence, configuration)
* Filesystem (recent files, prefetch, temp)
* Scheduled tasks and accounts

Comprehensive Collection Script Below is a detailed PowerShell script (Triage.ps1) to collect these artifacts. Copy this into a .ps1 file or run commands individually.

{% code overflow="wrap" %}
```powershell
# Define output directory and timestamp
$OutputPath = "D:\TriageOutput"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -Path $OutputPath -ItemType Directory -Force

# Start logging
Start-Transcript -Path "$OutputPath\TriageTranscript_$Timestamp.txt"

# --- System Information ---
Write-Host "Collecting system information..."
Get-ComputerInfo | Export-Csv -Path "$OutputPath\SystemInfo_$Timestamp.csv" -NoTypeInformation
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, InstallDate, LastBootUpTime | Export-Csv -Path "$OutputPath\OSDetails_$Timestamp.csv" -NoTypeInformation
Get-WmiObject Win32_LoggedOnUser | Select-Object Antecedent, Dependent | Export-Csv -Path "$OutputPath\LoggedOnUsers_$Timestamp.csv" -NoTypeInformation

# --- Processes and Services ---
Write-Host "Collecting process and service data..."
Get-Process | Select-Object Name, Id, Path, StartTime, Company, CPU, Handles | Export-Csv -Path "$OutputPath\Processes_$Timestamp.csv" -NoTypeInformation
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, CommandLine, CreationDate, ParentProcessId | Export-Csv -Path "$OutputPath\ProcessDetails_$Timestamp.csv" -NoTypeInformation
Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv -Path "$OutputPath\Services_$Timestamp.csv" -NoTypeInformation

# --- Network Activity ---
Write-Host "Collecting network data..."
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime | Export-Csv -Path "$OutputPath\NetConnections_$Timestamp.csv" -NoTypeInformation
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | Export-Csv -Path "$OutputPath\UDPEndpoints_$Timestamp.csv" -NoTypeInformation
Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State | Export-Csv -Path "$OutputPath\ARPCache_$Timestamp.csv" -NoTypeInformation
Get-DnsClientCache | Select-Object Entry, Data, TimeToLive | Export-Csv -Path "$OutputPath\DNSCache_$Timestamp.csv" -NoTypeInformation
netstat -anob | Out-File -FilePath "$OutputPath\Netstat_$Timestamp.txt"

# --- Event Logs ---
Write-Host "Collecting event logs..."
$EventLogs = @("System", "Security", "Application")
foreach ($log in $EventLogs) {
    Get-WinEvent -LogName $log -MaxEvents 5000 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -Path "$OutputPath\$log`Events_$Timestamp.csv" -NoTypeInformation
}

# --- Registry Data ---
Write-Host "Collecting registry data..."
$RegPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\System\CurrentControlSet\Services"
)
foreach ($path in $RegPaths) {
    $FileName = ($path -replace "[:\\]", "_") + "_$Timestamp.csv"
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Export-Csv -Path "$OutputPath\$FileName" -NoTypeInformation
}
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall "$OutputPath\InstalledSoftware_$Timestamp.reg" /y 2>$null

# --- File System Artifacts ---
Write-Host "Collecting filesystem artifacts..."
# Recent files (last 7 days)
Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, LastWriteTime, CreationTime, Length | Export-Csv -Path "$OutputPath\RecentFiles_$Timestamp.csv" -NoTypeInformation
# Prefetch files
New-Item -Path "$OutputPath\Prefetch" -ItemType Directory -Force
Copy-Item -Path "C:\Windows\Prefetch\*.pf" -Destination "$OutputPath\Prefetch" -ErrorAction SilentlyContinue
# Temp files
Get-ChildItem -Path "$env:TEMP" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime | Export-Csv -Path "$OutputPath\TempFiles_$Timestamp.csv" -NoTypeInformation

# --- Scheduled Tasks ---
Write-Host "Collecting scheduled tasks..."
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName, TaskPath, State, Actions | Export-Csv -Path "$OutputPath\ScheduledTasks_$Timestamp.csv" -NoTypeInformation
schtasks /query /fo csv /v | Out-File -FilePath "$OutputPath\ScheduledTasksDetailed_$Timestamp.csv"

# --- User Accounts ---
Write-Host "Collecting user account data..."
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Export-Csv -Path "$OutputPath\LocalUsers_$Timestamp.csv" -NoTypeInformation
net user | Out-File -FilePath "$OutputPath\NetUsers_$Timestamp.txt"

# --- Compress Output ---
Write-Host "Compressing triage data..."
Compress-Archive -Path "$OutputPath\*" -DestinationPath "D:\TriageData_$Timestamp.zip" -Force

# Stop logging
Stop-Transcript
Write-Host "Triage data collection complete. Output saved to D:\TriageData_$Timestamp.zip"
```
{% endcode %}

### 3. Execute the Collection

*   Run the Script: Save as Triage.ps1 and execute:powershell

    ```powershell
    .\Triage.ps1
    ```
* Alternative: Copy-paste commands into an admin PowerShell session or run individually.
* Duration: Takes 5-20 minutes depending on system size, event log volume, and filesystem recursion depth.

### 4. Verify and Analyse

* Output Check: Inspect $OutputPath for:
  * CSV files (e.g., Processes\_20250226\_123456.csv)
  * Text files (e.g., Netstat\_20250226\_123456.txt)
  * Exported files (e.g., Prefetch folder, .reg files)
  * ZIP archive (e.g., TriageData\_20250226\_123456.zip)
* **Analysis Tools:**
  * CSVs: Open in Excel or import with Import-Csv for filtering.
  * Prefetch: Use PEcmd or forensic suites (Autopsy, FTK).
  * Event Logs: Parse with Event Log Explorer or custom scripts.
  * Registry: Import .reg files or analyse CSVs in RegRipper.

### 5. Advanced Enhancements

*   Memory Dump: Pair with DumpIt or winpmem for RAM capture (PowerShell can’t do this natively):

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Start-Process -FilePath "C:\Tools\DumpIt.exe" -ArgumentList "/O $OutputPath\MemoryDump_$Timestamp.raw" -Wait
    </code></pre>
*   Hash Files: Add MD5 hashes for integrity:

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ChildItem "$OutputPath\Prefetch" | Get-FileHash -Algorithm MD5 | Export-Csv "$OutputPath\PrefetchHashes_$Timestamp.csv" -NoTypeInformation
    </code></pre>
*   Remote Execution: Run on networked systems:

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Invoke-Command -ComputerName TARGET-PC -FilePath .\Triage.ps1 -Credential (Get-Credential)
    </code></pre>

### 6. Tips and Considerations

* Scope Control: Adjust -MaxEvents (e.g., 5000 to 1000) or file search depth to speed up collection.
* Error Handling: ErrorAction SilentlyContinue skips inaccessible areas (e.g., locked files).
* Live Only: For forensic images, mount them first (e.g., via Arsenal Image Mounter) and adjust paths.
* Stealth: Use a USB or remote session to minimise footprint; avoid writing to C: if possible.
* Permissions: Admin rights are required for most cmdlets (e.g., Get-WinEvent, Get-ScheduledTask).
