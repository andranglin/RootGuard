# Windows Endpoint Triage: First-Response Field Guide

> **RootGuard technical reference** · **Environment:** Verify product, platform and telemetry prerequisites · **Validation:** Refer to the status below; examples are not automatically production-ready.

**Reviewed:** 20 October 2026 
**Status:** Methodology reference; commands must be validated and authorised locally.

## Initial decisions

Before collecting evidence, confirm authority, incident severity, asset identity, business criticality, retention requirements and the appropriate escalation route. Decide whether immediate containment outweighs loss of volatile evidence. **Do not delay necessary containment merely to complete a forensic checklist.**

Record the system name, hostname, unique asset identifier, current time and time zone, investigator, incident ID, acquisition method, tool versions and any observable changes caused by collection.

## Collection priorities

| Evidence | Example source | Considerations |
| --- | --- | --- |
| Volatile state | Processes, network connections, logged-on sessions | Collect before reboot when safe; commands can alter host state |
| Endpoint security telemetry | EDR alerts, process trees, network and file events | Check retention, sensor health and clock accuracy |
| Persistence | Scheduled tasks, services, Run keys, WMI subscriptions | Establish baseline and creation timestamps |
| Execution artefacts | Prefetch, Amcache, Shimcache, BAM, UserAssist | Different artefacts establish different kinds of activity; no single artefact proves execution by a specific user |
| Event records | Windows Security, System, PowerShell, Sysmon when configured | Coverage depends on auditing and forwarding |
| File system | MFT, USN Journal, relevant file metadata and hashes | Interpret timestamps in context and consider anti-forensics |
| Memory | Approved RAM acquisition utility | Requires permissions, adequate storage and a trained operator |

## Read-only oriented triage examples

Run only when authorised and record command outputs and any errors. These commands query the live system and **are not forensically non-intrusive**.

```powershell
Get-Date -Format o
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion
Get-Process | Select-Object ProcessName, Id, Path, StartTime
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
Get-ScheduledTask | Select-Object TaskName, TaskPath, State
Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName
```

Some fields are unavailable without elevation or on unsupported platforms. Capture failures rather than silently omitting them.

For selected Windows event logs, first check log availability and export using approved tooling. Avoid clearing logs or changing policy. Do not bypass PowerShell execution policy as a routine acquisition prerequisite.

## Evidence integrity

Use approved tooling for forensic copies, record hashes such as SHA-256, and protect original files from changes. A hash verifies file consistency between acquisition and later examination; it does not independently prove how the data was captured or who handled it.

Maintain a chain-of-custody record with evidence ID, source, time, collector, method, destination, hash, transfers and access log. Preserve the original time zone and document conversion into UTC in timelines.

## Triage interpretation

Separate **observed fact**, **analyst inference** and **hypothesis**. Correlate execution artefacts with logs, account events, process lineage and network evidence. Record absent or incomplete telemetry explicitly.

## Next steps

- [Evidence acquisition planning](evidence-acquisition-and-integrity.md)
- [Windows artefact interpretation](windows-artifact-interpretation.md)
- [Evidence collection references](../initial-triage-and-response/evidence-collection/README.md)
