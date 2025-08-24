# Execution (TA0002)

### **Sub-technique: T1059.001 - PowerShell**

**Objective**: Detect malicious PowerShell script execution.&#x20;

1. **Detect PowerShell Script Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify PowerShell script execution.

2. **Detect Obfuscated PowerShell Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine matches regex "(?i)[^a-zA-Z0-9\\s]"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect obfuscated PowerShell commands.

3. **PowerShell Download and Execute**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "Invoke-WebRequest"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify PowerShell commands downloading and executing content.

4. **Detect PowerShell Executed from Suspicious Directories**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine matches regex "C:\\\\Users\\\\[^\\\\] +\\\\AppData\\\\Local\\\\Temp"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect PowerShell execution from temporary directories.

5. **Detect PowerShell Encoded Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "EncodedCommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
{% endcode %}

**Purpose**: Identify PowerShell commands executed with encoded strings.

6. **Monitor PowerShell for Command Line Length**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and strlen(ProcessCommandLine) > 1000
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect long command-line executions that could indicate complex scripts.

7. **PowerShell Execution by Non-Admin Users**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and InitiatingProcessAccountName != "Administrator"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Monitor PowerShell usage by non-administrative users.

8. **PowerShell Process Chaining**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("cmd.exe", "wscript.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect PowerShell chained with other interpreters.

9. **Detect PowerShell Execution via Macro**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has "WINWORD.EXE"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify PowerShell executed from Microsoft Word macros.

10. **Monitor PowerShell Remoting**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has "Enter-PSSession"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, AccountDomain, ActionType, FolderPath, FileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Detect the use of PowerShell Remoting.
