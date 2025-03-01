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

# Lateral Movement Discovery

## Lateral Movement Discovery

{% code overflow="wrap" %}
```powershell
Scheduled Tasks Lateral Movement Detection (Destinations)
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4698';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4702';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4699';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4700';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4701';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='106';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='140';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='141';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='200';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TaskScheduler/Maintenance'; Id='201';} | FL TimeCreated,Message*`

Get-ChildItem -path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\' | Get-ItemProperty | FL Path, Actions

gci -path C:\Windows\System32\Tasks\ -recurse -File
```
{% endcode %}

### PsExec Lateral Movement Detection (Destinations)

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='2'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\ADMIN$'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045'; Data='PSEXESVC'} | FL TimeCreated,Message
```
{% endcode %}

### Services Lateral Movement Detection (Destinations)

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4697';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7034';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7035';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7036';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7040';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='System'; Id='7045';} | FL TimeCreated,Message
```
{% endcode %}

### Map Network Shares Lateral Movement Detection (Destinations)

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4776';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4768';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4769';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140'; Data='\\*\C$'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5145';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='5140';} | FL TimeCreated,Message
```
{% endcode %}

### WMI/WMIC Lateral Movement Detection (Destinations)

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5857';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5860';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WMI-Activity/Operational'; Id='5861';} | FL TimeCreated,Message
```
{% endcode %}

### PowerShell Lateral Movement Detection (Destinations)

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='3'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4672';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4103';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='4104';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id='53504';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='400';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Windows PowerShell'; Id='403';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='91';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WinRM/Operational'; Id='168';} | FL TimeCreated,Message
```
{% endcode %}

### Remote Desktop Lateral Movement Detection (Destinations)

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4624'; Data='10'} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4778';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4779';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id='98';} | FL Message,ProcessId,TimeCreated
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id='131';} | FL Message,ProcessId,TimeCreated
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='21';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='22';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='25';} | FL TimeCreated,Message
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id='41';} | FL TimeCreated,Message
```
{% endcode %}
