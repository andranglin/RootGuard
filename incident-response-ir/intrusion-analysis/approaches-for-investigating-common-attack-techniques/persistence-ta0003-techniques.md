---
icon: laptop-code
---

# Persistence (TA0003) Techniques

### <mark style="color:blue;">Introduction</mark>

Investigating persistence mechanisms in a network, Windows workstations, and server systems is crucial in understanding how attackers maintain access to compromised environments. Persistence allows attackers to regain entry even after initial entry points are closed, making it a critical aspect of forensic analysis.

#### Understand Common Persistence Techniques

* **Registry Keys:** Autoruns, Run keys, and other registry locations where programs can be set to run on startup.
* **Startup Folders:** Programs placed in these directories will automatically launch at startup.
* **Scheduled Tasks:** Malicious tasks can be scheduled to run at specific times or intervals.
* **Service Creation:** Malware can install itself as a service, which is automatically started by Windows.
* **DLL Hijacking:** Malware replaces legitimate DLLs or adds malicious DLLs referenced by legitimate programs.
* **WMI Event Subscriptions:** WMI can execute scripts or binaries in response to certain system events.
* A**ccount Manipulation:** Creation of new user accounts or modification of existing accounts for future access.

#### Data Collection and Preservation

* **Forensic Imaging:** Use tools like FTK Imager or dd to create images of affected systems.
* **Live System Data:** If possible, gather live data, including running processes, network connections, and currently loaded drivers.
* **Log Collection:** Collect security logs, system logs, application logs, and event logs.

#### Analysis Techniques

* **Registry Analysis:** Use tools like Registry Explorer or RegRipper to analyse registry hives for unauthorised modifications.
* **File System Analysis:** Tools like Autopsy or X-Ways can analyse file systems for suspicious files in startup directories, unusual file creation/modification dates, or hidden files.
* **Scheduled Task Analysis:** Review Windows Task Scheduler for any unrecognised or suspicious tasks.
* **Service Analysis:** Examine the list of installed services for unknown or modified services.
* **Log Analysis:** Investigate logs for evidence of account creation, modification, or other signs of unauthorised access.

#### Investigate Common Persistence Locations

* **Autostart Locations:** Check common autostart locations like `HKCU\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\Software\Microsoft\Windows\CurrentVersion\Run.`
* **Startup Directories:** Inspect directories like %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup.
* **Task Scheduler:** Look for tasks that execute on system start or at regular intervals.
* **Services:** Analyse the list of services (services.msc) for new or modified entries.

#### Network Analysis

* **Endpoint Detection and Response (EDR):** Use EDR tools to monitor network traffic for signs of C2 communication.
* **SIEM Systems:** Analyse aggregated logs for patterns indicative of persistence mechanisms.

#### 6. Utilise Specialised Forensic Tools

* **Sysinternals Suite:** Tools like Autoruns can help identify programs configured to run during system bootup.
* **PowerShell Scripts:** Scripts like Get-Service, Get-ScheduledTask, or custom scripts can help identify anomalies.

#### Documentation and Reporting

* **Detailed Documentation:** Keep a detailed record of all findings, methods used, and evidence paths.
* **Reporting:** Prepare a comprehensive report outlining the persistence mechanisms found, their impact, and recommendations for remediation.

#### Remediation and Recovery

* **Remove Persistence Mechanisms:** Based on findings, remove or disable the identified persistence mechanisms.
* **Strengthen Defenses:** Update security policies, patch vulnerabilities, and adjust endpoint protection strategies.

#### Post-Incident Analysis

* **Review and Learn:** Analyse the incident to understand how the persistence was established and improve defences accordingly.

#### Key Considerations

* **Legal and Compliance:** Ensure compliance with legal and organisational guidelines.
* **Chain of Custody:** Maintain a clear chain of custody for all forensic evidence.
* **Confidentiality:** Ensure that sensitive data is handled appropriately.

Persistence investigation requires a comprehensive approach, leveraging various tools and techniques to uncover how attackers maintain access. Tailor your investigation to the specifics of the incident and the environment you are dealing with.

### <mark style="color:blue;">Using KQL to Investigate Persistence Activities in an Environment Using Defender/Sentinel</mark>

Persistence techniques allow adversaries to maintain access to a compromised system even after reboots or other interruptions.

### <mark style="color:blue;">**1. T1547 - Boot or Logon Autostart Execution**</mark>

**Objective**: Detect mechanisms that automatically execute code upon boot or user logon.&#x20;

1. **Detect Registry Run Key Modifications**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("\\Run", "\\RunOnce", "\\RunServices") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to registry keys used to launch programs at startup.

2. **Monitor Startup Folder for New Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect new files added to the Startup folder.

3. **Detect New Service Creation**

{% code overflow="wrap" %}
```cs
    DeviceServiceEvents | where ActionType == "ServiceInstalled" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the installation of new services that could be used for persistence.

4. **Identify New Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the creation of new scheduled tasks.

5. **Monitor for Autorun Entries in the Registry**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

_Purpose_: Identify autorun entries that can be used to persist malicious code.

6. **Detect Creation of WMI Event Subscriptions**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "EventFilter" and ProcessCommandLine has "create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the creation of WMI event subscriptions that can be used for persistence.

7. **Identify Modifications to Userinit Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to the Userinit registry key, which can be used to launch programs at logon.

8. **Monitor for DLLs Added to Startup Folders**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileExtension == ".dll" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect DLL files added to startup folders for persistence.

9. **Detect Modifications to Shell Registry Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for changes to the Shell registry key that can be used to persist malware.

10. **Identify New Logon Scripts**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "Scripts\\Logon" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect new logon scripts that can be used for persistence.

### <mark style="color:blue;">**2. T1053 - Scheduled Task/Job**</mark>

**Objective**: Detect the creation or modification of scheduled tasks or jobs that persistently execute malicious code.&#x20;

1. **Detect Creation of New Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of new scheduled tasks.

2. **Monitor for Changes to Existing Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /change" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect changes made to existing scheduled tasks.

3. **Identify Scheduled Task Executing Suspicious Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" and ProcessCommandLine has_any ("powershell.exe", "cmd.exe", "wscript.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for scheduled tasks executing commands commonly used in attacks.

4. **Detect Scheduled Task Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "taskeng.exe" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the execution of scheduled tasks.

5. **Monitor for Scheduled Task Executions by Non-Admin Users**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "taskeng.exe" and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect scheduled tasks being executed by non-administrative users.

6. **Identify Scheduled Task Execution with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "taskeng.exe" and TokenElevationType == "Full" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for scheduled tasks running with elevated privileges.

7. **Detect Suspicious Task Scheduler Executables**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("taskeng.exe", "taskschd.msc") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify suspicious use of task scheduler executables.

8. **Monitor for AT Command Usage**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "at" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of the AT command to schedule tasks.

9. **Identify Suspicious Scheduled Task Parameters**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks" and ProcessCommandLine has_any ("/TN", "/TR", "/SC") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for suspicious parameters in scheduled tasks.

10. **Detect Creation of Hidden Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks /create" and ProcessCommandLine has "/RU SYSTEM" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of hidden or system-level scheduled tasks.

### <mark style="color:blue;">**3. T1060 - Registry Run Keys / Startup Folder**</mark>

**Objective**: Detect the use of registry run keys or startup folders to maintain persistence on a system.&#x20;

1. **Detect New Entries in Registry Run Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify new or modified entries in registry run keys.

2. **Monitor Startup Folder for New Executables**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileExtension == ".exe" and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect new executable files added to the Startup folder.

3. **Identify DLLs Added to Registry Run Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") and RegistryValueData has ".dll" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect DLLs added to registry run keys for persistence.

4. **Monitor for Suspicious Modifications to RunOnce Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify suspicious modifications to RunOnce registry keys.

5. **Detect Executables Added to Startup Folders**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileExtension == ".exe" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for executables added to Startup folders that could be used for persistence.

6. **Identify Script Files Added to Startup Folders**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath endswith "Startup" and FileExtension in (".vbs", ".ps1", ".bat") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect script files added to Startup folders for persistence.

7. **Monitor for Suspicious Entries in RunServices Keys**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices") | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify suspicious entries in RunServices registry keys.

8. **Detect Modifications to Shell Registry Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for changes to the Shell registry key that may indicate persistence.

9. **Identify Modifications to Userinit Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey == "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to the Userinit registry key for persistence.

10. **Monitor for Unusual Activity in Common Startup Locations**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect unusual activity in common startup locations.

### <mark style="color:blue;">**4. T1543 - Create or Modify System Process**</mark>

**Objective**: Detect the creation or modification of system processes for persistence.&#x20;

1. **Detect New Service Creation**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the installation of new services that could be used for persistence.

2. **Monitor for Service Configuration Changes**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceModified" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect changes to existing service configurations.

3. **Identify Services Set to Auto Start**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and ServiceStartType == "Auto" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for services configured to start automatically, which may be used for persistence.

4. **Detect Services Running Executables from Non-Standard Locations**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessFolderPath has_not "C:\\Windows\\System32" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify services running executables from unusual or non-standard locations.

5. **Monitor for New Service Executables**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FilePath has "\\System32\\services.exe" | project Timestamp, DeviceName, FileName, FilePath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect new executables associated with services.

6. **Identify Suspicious Service Descriptions**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and ServiceDescription has_any ("backdoor", "trojan", "rat") | project Timestamp, DeviceName, ServiceName, ServiceDescription, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for suspicious service descriptions that may indicate malicious intent.

7. **Detect Modifications to System Services**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceModified" and InitiatingProcessAccountName != "SYSTEM" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify modifications to system services by non-system accounts.

8. **Monitor for Services with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessAccountName == "SYSTEM" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine
```
{% endcode %}

_Purpose_: Detect services installed with elevated privileges.

9. **Identify Services Executing Suspicious Commands**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessCommandLine has_any ("powershell.exe", "cmd.exe", "wscript.exe") | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for services executing suspicious commands.

10. **Detect Services Executing Non-Executable Files**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" and InitiatingProcessCommandLine has_any (".txt", ".log", ".pdf") | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify services configured to execute non-executable files.

### <mark style="color:blue;">**5. T1176 - Browser Extensions**</mark>

**Objective**: Detect the installation or modification of browser extensions that can be used for persistence.&#x20;

1. **Detect New Browser Extension Installation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("chrome.exe", "firefox.exe", "edge.exe") and ProcessCommandLine has "ExtensionInstall" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the installation of new browser extensions.

2. **Monitor for Changes to Existing Browser Extensions**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("Chrome\\Extensions", "Firefox\\Profiles", "Edge\\Extensions") and FileOperation == "Modify" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to existing browser extensions.

3. **Identify Browser Extensions with Suspicious Permissions**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("chrome.exe", "firefox.exe", "edge.exe") and ProcessCommandLine has_any ("<all_urls>", "activeTab") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for browser extensions requesting suspicious permissions.

4. **Detect Browser Extensions Executing Scripts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("chrome.exe", "firefox.exe", "edge.exe") and ProcessCommandLine has ".js" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify browser extensions executing JavaScript files.

5. **Monitor for Unusual Activity in Browser Extension Folders**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("Chrome\\Extensions", "Firefox\\Profiles", "Edge\\Extensions") and FileOperation == "Create" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect unusual activity in browser extension folders.

6. **Identify Browser Extensions Making Network Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and InitiatingProcessFileName in ("chrome.exe", "firefox.exe", "msedge.exe") | project Timestamp, DeviceName, RemoteIP, InitiatingProcessCommandLine
```
{% endcode %}

_Purpose_: Monitor for network requests made by browser extensions.

7. **Detect Extensions Accessing Sensitive Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where InitiatingProcessFileName in ("chrome.exe", "firefox.exe", "msedge.exe") and FilePath has_any (".docx", ".xlsx", ".pdf") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify browser extensions accessing sensitive files.

8. **Monitor for Browser Extensions Installed by Non-Admin Users**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("chrome.exe", "firefox.exe", "edge.exe") and InitiatingProcessAccountName != "Administrator" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect browser extensions installed by non-administrative users.

9. **Identify Browser Extensions Executing System Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("chrome.exe", "firefox.exe", "edge.exe") and ProcessCommandLine has_any ("cmd.exe", "powershell.exe", "wscript.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for browser extensions executing system commands.

10. **Detect Browser Extensions with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("chrome.exe", "firefox.exe", "edge.exe") and TokenElevationType == "Full" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify browser extensions operating with elevated privileges.

### <mark style="color:blue;">**6. T1546 - Event Triggered Execution**</mark>

**Objective**: Detect the creation or modification of event triggers that persistently execute malicious code in response to specific events.&#x20;

1. **Detect Creation of WMI Event Filters**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "EventFilter" and ProcessCommandLine has "create" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of WMI event filters for persistence.

2. **Monitor for Modification of WMI Event Filters**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "EventFilter" and ProcessCommandLine has "modify" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect modifications to existing WMI event filters.

3. **Identify WMI Event Consumers Creating or Modifying Files**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "CommandLineEventConsumer" and ProcessCommandLine has_any ("cmd.exe", "powershell.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for WMI event consumers that create or modify files.

4. **Detect WMI Event Consumers Executing Suspicious Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "CommandLineEventConsumer" and ProcessCommandLine has_any ("explorer.exe", "taskeng.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify WMI event consumers executing suspicious commands.

5. **Monitor for New or Modified System Log Event Filters**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\System\\CurrentControlSet\\Services\\EventLog" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect new or modified system log event filters.

6. **Identify Task Scheduler Event Triggers**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks" and ProcessCommandLine has "/SC ONLOGON" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for task scheduler event triggers associated with logon events.

7. **Detect Creation of Hidden WMI Event Consumers**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "wmic" and ProcessCommandLine has "CommandLineEventConsumer" and ProcessCommandLine has "/NOINTERACTIVE" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the creation of hidden WMI event consumers.

8. **Monitor for Suspicious Event Triggers Related to User Activity**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks" and ProcessCommandLine has_any ("/SC ONIDLE", "/SC ONWORKSTATIONUNLOCK") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect event triggers that execute in response to user activity.

9. **Identify System Service Event Triggers**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceModified" and ServiceStartType == "TriggerStart" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for system services configured to trigger on specific events.

10. **Detect Scheduled Task Event Triggers with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "schtasks" and ProcessCommandLine has_any ("/SC ONSTART", "/SC ONLOGON") and TokenElevationType == "Full" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify scheduled tasks with event triggers that run with elevated privileges.
