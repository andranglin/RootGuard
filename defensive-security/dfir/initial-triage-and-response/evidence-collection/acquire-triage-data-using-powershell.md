# Windows Live Triage with PowerShell

**Purpose:** Capture a limited, documented snapshot of live Windows host state.  
**Status:** Static technical review, 20 October 2026. Commands are examples requiring authorised lab testing.  
**Platform:** Windows PowerShell 5.1 or PowerShell 7, subject to cmdlet/module availability.

## Before collecting

Confirm incident authorisation, machine identity, evidence destination, free space, collection time and time zone. Prefer a controlled destination with restricted access; do not use an arbitrary untrusted USB drive. Live commands cause observable system changes and do not provide forensically complete disk or memory images.

**Do not change execution policy as a routine prerequisite.** This procedure uses individual commands and does not need a script execution-policy bypass.

## Collection sequence

Use a uniquely named directory for the incident and device. Verify the destination is not on an untrusted or attacker-controlled share. Running these read-oriented commands still changes normal system state.

```powershell
$Case = "IR-CASE-001"
$HostName = $env:COMPUTERNAME
$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$Out = Join-Path "D:\IR-Evidence" "$Case-$HostName-$Stamp"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
Get-Date -Format o | Out-File (Join-Path $Out "collection-time.txt")
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, LastBootUpTime |
    Export-Csv (Join-Path $Out "os.csv") -NoTypeInformation
Get-CimInstance Win32_Process |
    Select-Object Name, ProcessId, ParentProcessId, CommandLine, CreationDate |
    Export-Csv (Join-Path $Out "processes.csv") -NoTypeInformation
Get-CimInstance Win32_Service |
    Select-Object Name, State, StartMode, PathName |
    Export-Csv (Join-Path $Out "services.csv") -NoTypeInformation
Get-NetTCPConnection -ErrorAction Continue |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Export-Csv (Join-Path $Out "tcp.csv") -NoTypeInformation
Get-ScheduledTask |
    Select-Object TaskName, TaskPath, State |
    Export-Csv (Join-Path $Out "tasks.csv") -NoTypeInformation
```

**Expected results:** Separate CSV exports with current processes, services, network sockets and tasks. Some commands require elevation or Windows modules; record errors and permissions failures. Data may change during collection. Output path must be checked before execution.

## Evidence integrity and limitations

- Record collection operator, start/end time, tool and PowerShell version, host identifier and output location.
- Hash *completed* files with `Get-FileHash -Algorithm SHA256 -LiteralPath <path>`, then verify hashes after transfer. Exporting CSV is not equivalent to acquiring source forensic artefacts.
- Collect raw event logs and other artefacts with approved forensic tooling, respecting retention and legal requirements. A CSV view omits source metadata.
- Do not assume that missing processes, sockets or tasks establish absence of attacker activity.

## Decision and handoff

Correlate with EDR process ancestry, Windows events, identity logs, persistence artefacts and network data. Mark facts and hypotheses separately. Escalate active compromise for incident-approved containment.

[Evidence Acquisition and Integrity](../../field-guides/evidence-acquisition-and-integrity.md) · [Windows Endpoint Triage](../../field-guides/windows-endpoint-triage.md)
