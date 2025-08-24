# Privilege Escalation (TA0004)

### **Sub-technique: T1068 - Exploitation for Privilege Escalation**

**Objective**: Detect exploitation attempts to gain higher privileges on the system.&#x20;

1. **Processes Running with Elevated Privileges**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessIntegrityLevel == "High" or ProcessIntegrityLevel == "System"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
{% endcode %}

**Purpose**: Identify processes running with elevated privileges.

2. **Known Exploitation Tools**

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("mimikatz", "procdump", "secretsdump")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessFileName
```
{% endcode %}

**Purpose**: Detect known exploitation tools.

3. **New Driver Installation**

{% code overflow="wrap" %}
```cs
DeviceDriverEvents
| where ActionType == "DriverInstalled"
| project Timestamp, DeviceName, DriverName, InitiatingProcessAccountName
```
{% endcode %}

**Purpose**: Monitor new driver installations that may be used for privilege escalation.

4. **Kernel Module Load Events**

{% code overflow="wrap" %}
```cs
DeviceImageLoadEvents
| where FileName endswith ".sys"
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Detect loading of new kernel modules.

5. **Exploitation via Process Injection**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any ("inject", "reflective")
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Identify process injection attempts.

6. **Detect UAC Bypass Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "bypassuac"
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Monitor attempts to bypass User Account Control.

7. **Privilege Escalation via Service Creation**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "sc create"
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Detect service creation attempts that may be used for privilege escalation.

8. **Detecting Usage of Exploit Mitigation Bypass**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has_any ("exploit", "mitigation", "bypass")
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Identify attempts to bypass exploit mitigation controls.

9. **Privilege Escalation Using Scheduled Tasks**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "schtasks /create"
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Monitor for scheduled tasks used for privilege escalation.

10. **Detect Privilege Escalation via Windows Installer**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents
| where ProcessCommandLine has "msiexec"
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```
{% endcode %}

**Purpose**: Identify privilege escalation attempts using Windows Installer.
