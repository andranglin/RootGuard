# Persistence (TA0003)

### **Sub-technique: T1547.001 - Registry Run Keys / Startup Folder**

**Objective**: Detect persistence mechanisms using registry run keys or startup folders.&#x20;

1. **Registry Run Key Modifications**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents
| where RegistryKey has_any ("Run", "RunOnce", "Startup")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessFileName
```
{% endcode %}

**Purpose**: Detect modifications to registry run keys.

2. **Startup Folder File Additions**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FolderPath endswith "Startup"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Monitor new files added to the startup folder.

3. **Detect Registry Changes for Auto-Start Programs**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents
| where RegistryKey has "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

**Purpose**: Monitor changes to registry keys that control auto-start programs.

4. **Monitor for Suspicious StartUp Folder Activity**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FolderPath endswith "Startup"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, ActionType
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect suspicious file creation in the startup folder.

5. **Detect DLLs Added to Startup**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FolderPath endswith "Startup" and FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, ActionType
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify DLL files added to startup folders.

6. **Registry Persistence via RunOnce Key**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents
| where RegistryKey has "RunOnce"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessFileName
```
{% endcode %}

**Purpose**: Monitor the RunOnce registry key for persistence.

7. **Detect Hidden Files in Startup Folder**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FolderPath endswith "Startup" and FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, ActionType, InitiatingProcessCommandLine
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify hidden files in startup folders.

8. **Monitor Registry Modifications by Non-Admins**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents
| where RegistryKey has_any ("Run", "RunOnce", "Startup") and InitiatingProcessAccountName != "Administrator"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
```
{% endcode %}

**Purpose**: Detect registry modifications by non-administrative users.

9. **Detect Changes to Windows Startup Programs**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents
| where RegistryKey has "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
```
{% endcode %}

**Purpose**: Monitor for changes to startup programs in the registry.

10. **Monitor Startup Folder for Script Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents
| where FolderPath endswith "Startup" and (FileName endswith ".bat" or FileName endswith ".vbs" or FileName endswith ".ps1")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect script files added to startup folders.
