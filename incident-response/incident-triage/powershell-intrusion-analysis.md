# PowerShell Intrusion Analysis

### **Introduction**

PowerShell has become an indispensable tool in **Digital Forensics and Incident Response (DFIR)**, offering unparalleled flexibility and efficiency for investigating and responding to cyber incidents. As a robust command-line shell and scripting language, PowerShell is built into Windows operating systems, making it readily accessible for both system administrators and DFIR analysts.

Its importance lies in its ability to query, interact with, and manipulate nearly every aspect of a Windows system. PowerShell provides analysts with powerful cmdlets and scripts to gather forensic artefacts, analyse logs, investigate execution activity, and automate repetitive tasks. Furthermore, its deep integration with Windows APIs and system internals allows for rapid data collection and analysis during an active investigation.

In addition to its forensic capabilities, PowerShell is a critical tool for incident response. It can be used to identify active threats, terminate malicious processes, block network connections, and remediate compromised systems in real-time. However, its power also makes it a favourite tool of attackers, emphasising the need for DFIR professionals to understand its capabilities fully—not only to leverage it for defence but also to detect its misuse.

Mastering PowerShell equips DFIR practitioners with the skills to efficiently analyse systems, respond to threats, and bolster an organisation\u2019s cybersecurity posture in today\u2019s fast-paced and complex threat landscape.

### Get General insight and System Information

**Get System Information:**

{% code overflow="wrap" %}
```powershell
Get-ComputerInfo
```
{% endcode %}

**Get Operating System Details:**

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_OperatingSystem
```
{% endcode %}

**Get Hardware Information:**&#x20;

```powershell
Get-WmiObject -Class Win32_ComputerSystem
```

**Get Installed Software:**

```powershell
Get-WmiObject -Class Win32_Product
```

**Check For Local User Accounts:**&#x20;

```powershell
Get-LocalUser
```

**Get the last logon time for the user “John” by using**&#x20;

{% code overflow="wrap" %}
```powershell
net user
net user John | Select-String "Last logon"
```
{% endcode %}

**Retrieve information about users and their last logon times:**

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

**Get more detailed information, including last logon times**

{% code overflow="wrap" %}
```powershell
Get-LocalUser | ForEach-Object {  
	$user = $_.Name  
	$details = net user $user  
	[PSCustomObject]@{  
		UserName = $user  
		Enabled = $_.Enabled  
		FullName = ($details | Select-String "Full Name" | ForEach-Object { $_ -replace ".*Full Name *" })  
			LastLogon = ($details | Select-String "Last logon" | ForEach-Object { $_ -replace ".*Last logon *" })  
	}  
} | Format-Table -AutoSize
```
{% endcode %}

Let's say John is a suspicious user here, and we need to investigate this. Retrieve detailed information about the user John:

```powershell
Get-LocalUser -Name John | Format-List *
```

List the groups that the user John is a member of

{% code overflow="wrap" %}
```powershell
Get-LocalGroup | ForEach-Object {  
$group = $_.Name  
$members = Get-LocalGroupMember -Group $group  
$members | Where-Object { $_.Name -eq "John" } | Select-Object @{Name="GroupName";Expression={$group}}, Name  }
```
{% endcode %}

### Networking Information Gathering

**Get network configuration**

{% code overflow="wrap" %}
```powershell
Get-NetIPConfiguration

# Search for select properties:
Get-NetIPConfiguration | Select-Object -Property InterfaceAlias, IPv4Address, IPv6Address, DNServer
```
{% endcode %}

**Get active network connections**

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection
Get-NetIPAddress

# Search for specific port:
Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 443 } | Select-Object OwningProcess, RemoteAddress, RemotePort | Sort-Object OwningProcess | Get-Unique
```
{% endcode %}

**Get DNS information**

```powershell
Get-DnsClientServerAddress
```

**Check if there is a record defined with**

```powershell
Resolve-DnsName
```

**List network routes now**

```powershell
Get-NetRoute
```

We need to do some more detailed research

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "10.34.2.3" -and $_.LocalPort -eq 445 } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```
{% endcode %}

And

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "10.34.2.3" -and $_.LocalPort -eq 139 } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```
{% endcode %}

**To see if ports 139 and 445 are actively listening on your system**

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 139 -or $_.LocalPort -eq 445 -or $_.RemotePort -eq 139 -or $_.RemotePort -eq 445 }
```
{% endcode %}

**To inspect firewall rules related to ports 139 and 445**

{% code overflow="wrap" %}
```powershell
Get-NetFirewallRule | Where-Object { $_.LocalPort -eq 139 -or $_.LocalPort -eq 445 }
```
{% endcode %}

**To identify which processes are using ports 139 or 445**

{% code overflow="wrap" %}
```powershell
Get-Process -IncludeUserName | Where-Object { $_.TCPConnections.LocalEndPoint.Port -eq 139 -or $_.TCPConnections.LocalEndPoint.Port -eq 445 }
```
{% endcode %}

**To verify SMB configuration and settings**

```powershell
Get-SmbServerConfiguration  
Get-SmbClientConfiguration
```

**Determine if the machine is part of an Active Directory (AD) domain**

```powershell
(Get-WmiObject Win32_ComputerSystem).PartOfDomain
```

**Retrieve more detailed information about the domain membership**

```powershell
Get-WmiObject Win32_ComputerSystem | Select-Object Domain, DomainRole
```

### **User Accounts and Groups**

**Inspect user accounts and groups**

{% code overflow="wrap" %}
```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon  
Get-LocalGroup | Select-Object Name, Description
```
{% endcode %}

**Check membership for suspect user “John” in each group**

```powershell
Get-LocalGroupMember -Group "Administrators"  
Get-LocalGroupMember -Group "Users"  
Get-LocalGroupMember -Group "Remote Desktop Users"
```

**Check for the privilege of the suspect user**

{% code overflow="wrap" %}
```powershell
#Check for user "Jenny"  
$UserName = "Jenny"  
Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -eq $UserName }  
Get-LocalGroupMember -Group "Users" | Where-Object { $_.Name -eq $UserName } 
Get-LocalGroupMember -Group "Remote Desktop Users" | Where-Object { $_.Name -eq $UserName }
```
{% endcode %}

**Check if the user “John” has any scheduled tasks:**

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "John" } | Select-Object TaskName, State, Actions
```
{% endcode %}

**Check if the user “Jenny” has any scheduled tasks:**&#x20;

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "Jenny" } | Select-Object TaskName, State, Actions
```
{% endcode %}

### **Get Schedule Task Information**

**Get general information about tasks:**

```powershell
Get-ScheduledTask
```

**Get some general details about scheduled tasks**

```powershell
Get-ScheduledTask | Get-ScheduledTaskInfo | Select-Object TaskName, Actions
```

To determine if a scheduled task is suspicious, focus on understanding its purpose, verifying its actions, and comparing it against known legitimate tasks in your environment.

Use:&#x20;

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask -TaskName "GameOver" | Get-ScheduledTaskInfo | Select-Object TaskName, Actions
```
{% endcode %}

Use:&#x20;

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask -TaskName "falshupdate22" | Get-ScheduledTaskInfo | Select-Object TaskName, Actions
```
{% endcode %}

"You need to specifically look at the Clean file system entry. This is highly suspicious and attempts to destroy evidence or something like that. You can use PowerShell commands effectively to gather detailed information about a scheduled task, including its properties and actions.

Use:

```powershell
$task = Get-ScheduledTask | Where TaskName -EQ "Clean file system"  
$task  
$task.Actions
```

**Display all properties for a detailed analysis of the task now**

```powershell
$task = Get-ScheduledTask | Where-Object { $_.TaskName -eq "NameOfSuspiciousTask" }  
$task | Format-List * # Display all properties for detailed analysis  
$task.Actions # Display actions configured for the task  
$task.Triggers # Display triggers configured for the task
```

**You can perform a detailed analysis of a task by running the following**

```powershell
# Retrieve the scheduled task object  
$task = Get-ScheduledTask -TaskName "Clean file system"  
  
# Display all properties of the scheduled task  
$task | Format-List *  
  
# Display actions configured for the task  
$task.Actions  
  
# Display triggers configured for the task  
$task.Triggers  
  
# Display settings and security descriptor  
$task.Settings  
$task.SecurityDescriptor  
  
# Display task principal and version  
$task.Principal  
$task.Version
```

The `MSFT_TaskDailyTrigger` class provides properties that define how often the task runs, at what time, and any intervals or repetitions required. Here are some key properties of `MSFT_TaskDailyTrigger`

Then use it:

{% code overflow="wrap" %}
```powershell
$trigger = Get-ScheduledTask -TaskName "Clean file system" | Select-Object -ExpandProperty Triggers | Where-Object { $_.GetType().Name -eq 'MSFT_TaskDailyTrigger' }  
$trigger | Format-List *
```
{% endcode %}

Or you can use:

{% code overflow="wrap" %}
```powershell
# Retrieve the scheduled task object  
$task = Get-ScheduledTask -TaskName "Clean file system"  
  
# Display triggers configured for the task  
$task.Triggers | Where-Object { $_.GetType().Name -eq 'MSFT_TaskDailyTrigger' } | Format-List *
```
{% endcode %}

### **Check Startup Programs**

To access and display the values under the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

```powershell
# Define the path to the registry key  
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"  
  
# Get the registry key properties  
Get-ItemProperty -Path $registryPath
```

**Get Processes**

```powershell
Get-Process
```

**Review the security event logs for login activities related to the user “John”:**

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | Where-Object { $_.Properties[5].Value -eq "John" } | Select-Object TimeCreated, Id, Message
```
{% endcode %}

**Investigate if the user “John” and “Jenny” has any scheduled tasks:**

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "John" } | Select-Object TaskName, State, Actions
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "Jenny" } | Select-Object TaskName, State, Actions
```
{% endcode %}

**Check for processes currently running under the user “John”:**

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object { $_.StartInfo.UserName -eq "John" } | Select-Object Name, Id, CPU, Path
```
{% endcode %}

**Look for activities performed by the user “John” in the system and application event logs:**

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} | Where-Object { $_.Properties[1].Value -eq "John" } | Select-Object TimeCreated, Id, Message
```
{% endcode %}

**Now let’s get general details via System logs:**&#x20;

```powershell
Get-WinEvent -FilterHashtable @{LogName=’System’; Level=2}
```

**Get the scheduled tasks:**

```powershell
Get-ScheduledTask | Format-Table -AutoSize
```

**Double-check the daily running task:**

```powershell
(Get-ScheduledTask -TaskName "Clean file system").Actions
```

**Get more detailed information about this:**

```powershell
Get-ScheduledTask -TaskName "Clean file system" | Select-Object *
```

**We have witnessed suspicious scripts and activities found in the&#x20;**_**TMP**_**&#x20;location.**

**Check the contents of the Temp file location:**

```powershell
Get-ChildItem C:\Temp | Select-Object Name, CreationTime
```

**Identify if any running processes are executing from the&#x20;**_**TMP**_**&#x20;directory:**

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object { $_.Path -like "$env:TEMP*" } | Select-Object Id, ProcessName, Path
```
{% endcode %}

**Look at the contents of some files in&#x20;**_**TMP**_**:**

```powershell
Get-Content C:\Temp\mim-out.txt
```

**Take a look at the startup entries again:**&#x20;

```powershell
Get-CimInstance -ClassName Win32_StartupCommand
```

**Look at the security logs again:**&#x20;

```powershell
Get-WinEvent -LogName "Security"
```

**Look for logs signed with 4672 or other Eventlog**

**Create a detailed query:**

```powershell
$Specials = Get-WinEvent -LogName "Security" | Where-Object {$_.Id -eq "4672"}
```

**Check for any suspicious registry entries that might point to Temp:**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path HKLM:\Software\Microsoft\Windows\CurrentVersion | Get-ItemProperty
```
{% endcode %}

**Get a registry entry associated with a suspect file, for instance,&#x20;**_**mim.exe**_

```powershell
Get-ItemProperty -Path "HKCU:\Environment" -Name UserInitMprLogonScript
```

**Check the properties of `mim.exe` to gather more information about it:**

{% code overflow="wrap" %}
```powershell
$mimPath = Get-ItemProperty -Path "HKCU:\Environment" -Name UserInitMprLogonScript | Select-Object -ExpandProperty UserInitMprLogonScript  
Get-Item -Path $mimPath | Select-Object FullName, LastWriteTime, Length  
  
# Or just define manually  
$mimPath = 'C:\TMP\mim.exe'  
Get-Item -Path $mimPath | Select-Object FullName, LastWriteTime, Length
```
{% endcode %}

**Check digital signatures to verify if `mim.exe` is digitally signed:**&#x20;

```powershell
Get-AuthenticodeSignature -FilePath $mimPath
```

**Compute the hash of the file and check it against known malware databases like VirusTotal**

```powershell
Get-FileHash -Path $mimPath -Algorithm SHA256
```

**Check if there are any scheduled tasks related to `mim.exe`.**

```powershell
Get-ScheduledTask | Where-Object { $_.Actions.Exec.Path -eq $mimPath }
```

**Check for other startup entries that might reference `mim.exe`.**

{% code overflow="wrap" %}
```powershell
Get-CimInstance -ClassName Win32_StartupCommand | Where-Object { $_.Command -like "*mim.exe*" }
```
{% endcode %}

**Below, we can write two more queries that you can use for log files.**

```powershell
Get-WinEvent -LogName Security | Where-Object { $_.Message -like "*mim.exe*" }  
Get-WinEvent -LogName Application | Where-Object { $_.Message -like "*mim.exe*" }
```

**Determine the system information and user details**

{% code overflow="wrap" %}
```powershell
Get-ComputerInfo  
Get-LocalUser  
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```
{% endcode %}

**Check group memberships for a user**

```powershell
Get-LocalGroupMember -Group "Administrators"  
Get-LocalGroupMember -Group "Users"
```

**Check the profile path and home directory for the user, for instance, "sam"**

{% code overflow="wrap" %}
```powershell
Get-LocalUser -Name sam | Select-Object Name, PrincipalSource, Enabled, LastLogon, Description, SID
```
{% endcode %}

**Get the system event log**

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName System | Sort-Object TimeCreated  
Get-WinEvent -LogName Security | Sort-Object TimeCreated  
Get-WinEvent -LogName Application | Sort-Object TimeCreated
```
{% endcode %}

To reveal registry added or changing activity using `Get-WinEvent` for the `System` log, you can filter for specific **Event ID**s related to registry changes. Common Event IDs for registry changes include:

* **4656**: A handle to an object was requested.
* **4657**: A registry value was modified.
* **4663**: An attempt was made to access an object.
* **4659**: A handle to an object was requested with the intent to delete. You can use:

{% code overflow="wrap" %}
```powershell
$eventIds = @(4656, 4657, 4663, 4659)  
Get-WinEvent -LogName System | Where-Object { $eventIds -contains $_.Id } | Select-Object -First 10
```
{% endcode %}

For a word-based search, the following command is useful:

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName System | Select-Object TimeCreated, Id, Message | Where-Object { $_.Message -like "*registry*" } | Sort-Object TimeCreated
```
{% endcode %}

**Scheduled tasks might be used to execute the malicious scripts periodically or at specific events:**

```powershell
Get-ScheduledTask | Select-Object TaskName, State, Actions | Format-Table -AutoSize
```

**If PowerShell was used to execute commands, you can check the PowerShell history:**

{% code overflow="wrap" %}
```powershell
Get-Content -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-Object -Last 50
```
{% endcode %}

**Startup programs could include the malicious payload or its components:**

{% code overflow="wrap" %}
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-Table -AutoSize
```
{% endcode %}

**Let’s create a query for events:**

```powershell
Get-WinEvent -ListLog * | findstr "Print"
```

* **Circular Log Type:** This indicates that the log file is configured to overwrite old entries with new ones once the log reaches its maximum size. This is useful for logs that accumulate data continuously.
* **Size:** The size of the log file in bytes.
* **Number of Entries:** The number of events currently logged in that file. For example, We found events recorded as **Admin** and **Operational**. Investigate it:

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-PrintService/Admin"} | fl -property *
```
{% endcode %}

If you want to search for specific patterns in the log files, you can use `Select-String` as follows:

{% code overflow="wrap" %}
```powershell
# Search for a specific pattern in the PrintService Operational log  
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Admin" | Select-Object -ExpandProperty Message | Select-String "Print"
```
{% endcode %}

**Verify that a file, for example, `ualapi.dll` is legitimate and hasn’t been tampered with:**

```powershell
Get-Item "C:\Windows\System32\ualapi.dll" | Get-AuthenticodeSignature
```

**Obtain the process information defined in the ualapi.dll file event:**

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName Application | Where-Object { $_.Message -like "*ualapi.dll*" } | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize
```
{% endcode %}

Or:

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName System -FilterXPath "*[System/EventID=13]" | Where-Object { $_.Message -like "*ualapi.dll*" } | Sort-Object TimeCreated | Format-List -Property *
```
{% endcode %}

### PowerShell Incident Response Resources

[Powershell Digital Forensics & Incident Response (DFIR)](https://github.com/Bert-JanP/Incident-Response-Powershell) - The repository contains multiple PowerShell scripts that can help you respond to cyber attacks on Windows Devices. (Credit Bert-JanP)

[PowerShell Commands for Incident Response](https://www.securityinbits.com/incident-response/powershell-commands-for-incident-response/) - Learn different PowerShell Commands that can be used in Incident Response to remediate the machine. (written by [Ayush Anand](https://www.securityinbits.com/author/securityinbits_tl34lv/))

How to Run PowerShell Script on Remote Computers - The article looks at several examples of how to use PowerShell Remoting interactive session mode and persistent connections to run PS1 a script on a remote computer. (written by [Cyril Kardashevsky](https://theitbros.com/author/administrator/) )

[CyberRaiju](https://www.jaiminton.com/) - Digital Forensics and Incident Response (written by Jai Minton)
