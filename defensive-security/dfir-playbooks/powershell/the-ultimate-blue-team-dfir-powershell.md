# The Ultimate Blue Team/DFIR Powershell

This is the single file that every DFIR, SOC analyst, and incident commander keeps open\
during a full-blown PowerShell-driven malware incident investigation.

### Analyst Machine – One-Time Full Module Loadout

**Note**: You do this ONCE on your personal jump box/IR laptop. Never again.

These are the exact modules used by Mandiant, CrowdStrike IR, Microsoft DART, and elite SOCs.

{% code overflow="wrap" %}
```ps1
# All install to CurrentUser – you do NOT need local admin on your own laptop.
Install-Module -Name `
    PSHunt, PowerHunt, DeepBlueCLI, SigmaRule, PSSigma, PowerForensics, `
    Velociraptor, ImportExcel, PSWriteHTML, BurntToast, Terminal-Icons, `
    Microsoft.PowerShell.ConsoleGuiTools, Kansa, Get-Evtx, PoshRSJob `
    -Scope CurrentUser -Force -AllowClobber -ErrorAction SilentlyContinue
    # ↑ -Force = overwrite older versions
    # ↑ -AllowClobber = overwrite conflicting commands (yes, we want that)
    # ↑ -ErrorAction SilentlyContinue = don't stop if one module is already installed

# Now import everything you will touch in the next 72 hours of hell
Import-Module PSHunt, PowerHunt, DeepBlueCLI, SigmaRule, PowerForensics, Velociraptor, `
              ImportExcel, PSWriteHTML, BurntToast, Terminal-Icons, Kansa, Get-Evtx
    # You will thank yourself later when you’re typing at 120 WPM under pressure

# Make the console not look like 1998
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH/ys.omp.json" | Invoke-Expression
    # ys.omp.json = clean, blue-team-style theme used by most elite teams
Set-PSReadLineOption -PredictionSource HistoryAndPlugin -PredictionViewStyle ListView
    # Gives you inline + list prediction – saves hundreds of keystrokes per incident
```
{% endcode %}

### Verify Every Single Defence Is Actually On.

**Note:** (Run on EVERY compromised endpoint you touch)

{% code overflow="wrap" %}
```ps1
# If any of these return False or $null → the attacker already won before the ransom note
Get-MpComputerStatus | Select-Object `
    AMSIEnable,                     # If False → every in-memory payload just sailed through
    RealTimeProtectionEnabled,      # Should be True
    BehaviorMonitorEnabled,         # Critical for blocking fileless ransomware
    ScriptScanningEnabled           # Blocks malicious .ps1, .vbs, etc.

# Check if attacker disabled Defender via group policy (very common)
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -ErrorAction SilentlyContinue
    # If value = 1 → Defender is deliberately turned off → immediate red flag

# AppLocker / WDAC – the single best defence against PowerShell attacks
Get-AppLockerPolicy -Effective | Format-Table Name, EnforcementMode
    # You want to see "Audit" or "Enforced" for Exe, Script, and DLL rules

# PowerShell logging – if these are off, you are legally blind
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"    -Name EnableModuleLogging
    # Both must be 1. If 0 → go scream at the sysadmins

# ConstrainedLanguage mode = 95% of red team PowerShell attacks die instantly
$ExecutionContext.SessionState.LanguageMode
    # Must return "ConstrainedLanguage"
    # If it says "FullLanguage" → attacker is laughing at you right now

# Credential Guard / HVCI – blocks LSASS dumping
Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select SecurityServicesRunning
    # You want to see "CredentialGuard" and "Hvci" in the list

# Full automated hardening audit using PowerHunt module
Invoke-PowerHunt -AuditPowerShell | Format-Table
    # Gives you a red/yellow/green scorecard – screenshot this for the report
```
{% endcode %}

### Daily Proactive Threat Hunting

(Run every single shift, every single day)

{% code overflow="wrap" %}
```ps1
# DeepBlueCLI – the fastest, most accurate malicious PowerShell detector known to man
# Used in literally every major ransomware investigation since 2018
.\DeepBlue.ps1 "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    # Output tells you exactly which script blocks are malicious, encoded, suspicious, etc.

# PSHunt / PowerHunt – prebuilt hunts specifically for 2025 red team techniques
Start-PSHunt -HuntName "AMSI Bypass"           # Finds AmsiUtils, amsiInitFailed, 0x80070057 patches
Start-PSHunt -HuntName "Encoded Command"       # Finds huge -enc blobs → 99% chance it’s ransomware
Start-PSHunt -HuntName "Suspicious DownloadString"  # Classic C2 beacon
Start-PSHunt -HuntName "Ransomware Payload"    # Specifically tuned for LockBit/ALPHV style payloads
Start-PSHunt -HuntName "Credential Dumping"    # Mimikatz, SharpDPAPI, comsvcs.dll MiniDump, etc.

# Run Sigma rules directly inside PowerShell – no external tools needed
Test-SigmaRule -RulePath "C:\Sigma\rules\windows\powershell_amsi_bypass.yml" -Timespan 48h
Test-SigmaRule -RulePath "C:\Sigma\rules\windows\powershell_suspicious_invocation.yml"
    # Sigma is the industry standard – these rules are updated weekly by the community
```
{% endcode %}

### Full Malware/Credential Theft Incident Triage

**Note**: → This is the EXACT function you run at 3:17 a.m. when the ransom note hits

{% code overflow="wrap" %}
```ps1
function Invoke-FullPowerShellRansomwareTriage {
    # Create a timestamped case folder – never overwrite evidence
    $Case = "C:\DFIR\Cases\Ransomware_PS_$(Get-Date -f yyyyMMdd_HHmm)"
    New-Item -ItemType Directory -Path $Case -Force | Out-Null

    Write-Host "`n=== STARTING FULL POWERSHELL RANSOMWARE TRIAGE ===`n" -ForegroundColor Red

    # 1. Patient Zero – the very first beacon (Cobalt Strike, Sliver, Covenant, Brute Ratel, etc.)
    Write-Host "[1/10] Hunting initial C2 beacon..." -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -ErrorAction SilentlyContinue |
      Where-Object {$_.Message -match "DownloadString|WebClient|IEX.*http|c2|beacon|grunt|sliver|empire|covenant|bruteratel"} |
      Select-Object TimeCreated, @{n="User";e={$_.Properties[0].Value}}, Message |
      Export-Csv "$Case\01_InitialBeacon.csv" -NoTypeInformation

    # 2. Defence evasion – attacker disabling AMSI, ETW, ConstrainedLanguage
    Write-Host "[2/10] Hunting AMSI/ETW/ConstrainedLanguage bypass..." -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
      Where-Object {$_.Message -match "AmsiUtils|amsiInitFailed|EtwEventWrite|VirtualProtect|0x80070057|0xC3|languageMode"} |
      Export-Csv "$Case\02_DefenseEvasion.csv" -NoTypeInformation

    # 3. Credential dumping – the crown jewels
    Write-Host "[3/10] Hunting credential access (LSASS, Mimikatz, Kerberoasting, LAPS)..." -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
      Where-Object {$_.Message -match "MiniDump|comsvcs|sekurlsa|SharpDPAPI|logonpasswords|KerberosRequestorSecurityToken|LAPS|Get-AdmPwdPassword"} |
      Export-Csv "$Case\03_CredentialDumping.csv" -NoTypeInformation

    # 4. Lateral movement – how they spread
    Write-Host "[4/10] Hunting lateral movement (PSRemoting, WMI, Invoke-Command)..." -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
      Where-Object {$_.Message -match "Enter-PSSession|Invoke-Command.*-ComputerName|Invoke-WmiMethod|Win32_Process.*Create"} |
      Export-Csv "$Case\04_LateralMovement.csv" -NoTypeInformation

    # 5. Final ransomware payload – the money shot
    Write-Host "[5/10] Hunting final ransomware execution..." -ForegroundColor Yellow
    # Huge encoded command → almost always the encrypted payload
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103} |
      Where-Object {$_.Properties[2].Value.Length -gt 8000} |
      Export-Csv "$Case\05_EncodedRansomwarePayload.csv" -NoTypeInformation

    # Fileless reflective PE injection (2025 favorite)
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
      Where-Object {$_.Message -match "FromBase64String.*GzipStream|Reflection.*Assembly|ReflectivePEInjection|Invoke-Expression.*Invoke"} |
      Export-Csv "$Case\05_FilelessRansomware.csv" -NoTypeInformation

    # 6. DeepBlueCLI – automated malicious PowerShell detection (gold standard)
    Write-Host "[6/10] Running DeepBlueCLI full analysis..." -ForegroundColor Yellow
    .\DeepBlue.ps1 "$env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" | Export-Csv "$Case\DeepBlueCLI_Full.csv"

    # 7. PowerForensics – find fileless drops, renamed exes, prefetch evidence
    Write-Host "[7/10] Parsing $UsnJrnl and Prefetch..." -ForegroundColor Yellow
    Get-ForensicUsnJrnlInformation | Where-Object FileName -match "\.ps1|\.exe|\.dll|\.bat|\.vbs" | Export-Csv "$Case\UsnJrnl_Drops.csv"
    Get-ForensicPrefetch | Export-Csv "$Case\Prefetch.csv"

    # 8. Velociraptor artifact collection (if you have the module)
    if (Get-Command Invoke-Velociraptor -ErrorAction SilentlyContinue) {
        Write-Host "[8/10] Collecting Velociraptor artifacts..." -ForegroundColor Yellow
        Invoke-Velociraptor -Artifact Windows.EventLogs.PowerShellOperational -Output "$Case\Velociraptor_PS.evtx"
        Invoke-Velociraptor -Artifact Windows.Memory.Acquire -Output "$Case\memory.raw"
    }

    # 9. Leadership-ready HTML timeline
    Write-Host "[9/10] Generating executive timeline..." -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
      ConvertTo-HTMLReport -Title "PowerShell Ransomware Incident" -PreContent "<h1>Incident Timeline – $(Get-Date)</h1>" |
      Out-File "$Case\Timeline.html"

    # 10. Excel workbook for the CISO
    Write-Host "[10/10] Exporting to Excel..." -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
      Export-Excel "$Case\Full_Investigation.xlsx" -WorksheetName "4104_ScriptBlocks" -AutoSize -TableName "ScriptBlocks"

    # Wake up the incident commander
    New-BurntToastNotification -Text "RANSOMWARE TRIAGE COMPLETE" -AppLogo "C:\Windows\System32\Shell32.dll,196" -Sound Critical

    Write-Host "`n=== TRIAGE COMPLETE – CASE FOLDER: $Case ===`n" -ForegroundColor Green
    explorer.exe $Case   # Opens the folder automatically
}
# ←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←
# RUN THIS FUNCTION THE SECOND A RANSOM NOTE APPEARS:
Invoke-FullPowerShellRansomwareTriage
# ←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←
```
{% endcode %}

### Immediate Containment - Kill Everything&#x20;

**Note**: (Run when encryption is confirmed)

{% code overflow="wrap" %}
```ps1
Write-Host "EXECUTING HARD CONTAINMENT – KILLING ALL POWERSHELL AND LOLBINS" -ForegroundColor Red
Get-Process -Name pwsh,powershell,wscript,cscript,mshta,regsvr32,rundll32,cmd,conhost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "DISABLING PSREMOTING AND WINRM – STOPPING LATERAL MOVEMENT" -ForegroundColor Red
Disable-PSRemoting -Force
Stop-Service WinRM -Force

Write-Host "BLOCKING SMB AND RDP OUTBOUND – STOPPING RANSOMWARE SPREAD" -ForegroundColor Red
New-NetFirewallRule -DisplayName "IR-Block-SMB-Out" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "IR-Block-RDP-Out" -Direction Outbound -Protocol TCP -RemotePort 3389 -Action Block -ErrorAction SilentlyContinue
```
{% endcode %}

### Full Evidence Collection – Do This Before Anyone Reboots

{% code overflow="wrap" %}
```ps1
$Case = "C:\DFIR\LiveResponse_$(Get-Date -f yyyyMMdd_HHmm)"
New-Item -ItemType Directory -Path $Case -Force

Write-Host "COLLECTING FULL EVENT LOGS..." -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'} -ErrorAction SilentlyContinue | Export-Csv "$Case\PS_Operational_Full.csv" -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4648,4672,4688,4625} | Export-Csv "$Case\Security_Logons.csv"

Write-Host "DUMPING LSASS (ONLY IF CREDENTIAL GUARD IS OFF)..." -ForegroundColor Cyan
if (-not ((Get-CimInstance Win32_DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning -contains "CredentialGuard")) {
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id "$Case\lsass.dmp" full
}

Write-Host "COLLECTING MFT, USNJRNL, PREFETCH..." -ForegroundColor Cyan
Get-ForensicMasterFileTable | Export-Csv "$Case\MFT.csv" -NoTypeInformation
Get-ForensicUsnJrnlInformation | Export-Csv "$Case\UsnJrnl.csv"
Get-ForensicPrefetch | Export-Csv "$Case\Prefetch.csv"
```
{% endcode %}

### Post-Incident Hardening – Never Get Hit The Same Way Twice

{% code overflow="wrap" %}
```ps1
Write-Host "ENABLING FULL POWERSHELL LOGGING DOMAIN-WIDE..." -ForegroundColor Green
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

Write-Host "DEPLOYING BLOCKING APPLOCKER/WDAC POLICY..." -ForegroundColor Green
Set-PowerHuntAppLockerPolicy -BlockPowerShell -BlockLOLBins

Write-Host "ENABLING CREDENTIAL GUARD + HVCI (REBOOT REQUIRED)..." -ForegroundColor Green
bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" loadoptions DISABLE-LSA-ISO,DISABLE-VBS
```
{% endcode %}
