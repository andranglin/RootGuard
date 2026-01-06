# Collection Discovery

### **Introduction**

PowerShell is a powerful and versatile tool widely used by security operations (SecOps) teams to manage systems, automate tasks, and conduct detailed investigations. Its robust scripting capabilities and deep integration with Windows make it indispensable for **Digital Forensics and Incident Response (DFIR)**. One of its critical applications in DFIR is uncovering **Collection Discovery** activities. Collection Discovery involves identifying and investigating attackers' unauthorised gathering of sensitive data or intellectual property within an enterprise network. PowerShell empowers SecOps teams to efficiently detect and analyse these activities, enabling swift containment and mitigation of data-related threats.

***

### **Capabilities of PowerShell for Collection Discovery in DFIR**

**1. Detecting File and Directory Enumeration:**

PowerShell can monitor and analyse commands used to enumerate files and directories, which is often an initial step in data collection. This includes detecting suspicious access to shared drives, sensitive directories, or files with specific extensions, such as `.docx`, `.xlsx`, or `.pdf`.

**2. Investigating Unauthorised Data Access:**

Attackers may attempt to access or exfiltrate confidential data. PowerShell provides the ability to query audit logs, monitor file system activity, and detect unauthorised access to critical resources.

**3. Monitoring Data Aggregation Tools:**

PowerShell can identify the use of tools or scripts designed for aggregating data, such as`robocopy`, custom PowerShell scripts or third-party utilities. It can also monitor for unusual compression or archiving activities, such as the creation of `.zip` or `.rar` files.

**4. Analysing Network File Transfers:**

PowerShell enables analysts to detect suspicious file transfers over the network, such as uploads to cloud storage services, transfers via SMB shares, or unusual HTTP/FTP activity.

**5. Detecting Credential Collection:**

Collection Discovery often includes harvesting credentials stored on systems. PowerShell can identify attempts to access the Windows Credential Manager, SAM database, or tools like Mimikatz, which are used to collect credentials.

**6. Inspecting Registry and Configuration Changes:**

Attackers may modify registry settings or system configurations to enable easier data collection. PowerShell can query and analyse registry keys and configuration files for unauthorised changes.

**7. Querying Event Logs for Data Collection Patterns:**

PowerShell can analyse event logs to identify patterns indicative of data collection, such as abnormal read/write operations, access to large volumes of data, or failed access attempts.

***

### **Efficiency Provided by PowerShell in Collection Discovery**

1. **Comprehensive Visibility**: PowerShell offers access to critical data sources, such as file systems, logs, and network configurations, enabling analysts to thoroughly investigate collection activities.
2. **Real-Time Monitoring**: PowerShell supports real-time detection and analysis, allowing SecOps teams to identify collection attempts as they occur and take immediate action.
3. **Scalability**: Using **PowerShell Remoting**, analysts can simultaneously investigate collection activities across multiple systems, ensuring comprehensive coverage in enterprise environments.
4. **Automation and Efficiency**: Repetitive tasks, such as scanning directories for sensitive file access or monitoring audit logs, can be automated using PowerShell scripts, saving time and ensuring consistency.
5. **Tailored Detection Rules**: PowerShell scripts can be customised to detect specific collection techniques aligned with the **MITRE ATT\&CK framework**, enhancing the precision of investigations.
6. **Integration with Security Tools**: PowerShell integrates seamlessly with platforms like Microsoft Sentinel, Defender for Endpoint, and SIEM solutions, enabling enriched data analysis and automated threat response.

***

By leveraging PowerShell’s capabilities, SecOps teams can efficiently uncover and analyse Collection Discovery activities in enterprise networks. This enables proactive defence against data theft and ensures the organisation’s sensitive information remains secure.

### Collection Discovery

### 1. **File and Data Collection**

**1.1. Detecting Large File Searches**

**Purpose**: Identify searches for large files, which may indicate data collection.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*" -Recurse -File |  Where-Object {$_.Length -gt 100MB} |  Select-Object FullName, Length
```
{% endcode %}

**1.2. Monitoring for File Searches by Extension**

**Purpose**: Detect searches for specific file types, such as documents or spreadsheets.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*" -Recurse -Include *.docx, *.xlsx, *.pdf |  Select-Object FullName, LastWriteTime
```
{% endcode %}

### 2. **Clipboard Data Collection**

**2.1. Monitoring Clipboard Access**

{% code overflow="wrap" %}
```powershell
Get-EventLog -LogName Application -Source 'ClipSp' | Select-Object TimeGenerated, EntryType, Message
```
{% endcode %}

**2.2. Detecting Clipboard Content Retrieval**

**Purpose**: Identify attempts to read clipboard contents programmatically.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'Clipboard'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

### 3. **Keystroke Logging**

**3.1. Detecting Keylogger Installation**

**Purpose**: Identify the presence of keylogging software.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\*" -Filter "*keylogger*" -Recurse | Select-Object FullName, CreationTime
```
{% endcode %}

**3.2. Monitoring for Keystroke Logging Activity**

**Purpose**: Detect processes indicative of keystroke logging.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -like '*logger*'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

### 4. **Screenshot and Video Capture**

**4.1. Detecting Screenshot Capture Programs**

**Purpose**: Identify tools used for capturing screenshots.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Snagit|Greenshot|SnippingTool'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**4.2. Monitoring Video Capture Software**

**Purpose**: Detect software used for video capture.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'OBS|Camtasia|Debut'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

### 5. **Audio Capture and Surveillance**

**5.1. Monitoring for Audio Recording Software**

**Purpose**: Identify software that may be used to record audio.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Audacity|AudioHijack|SoundRecorder'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**5.2. Detecting Use of System Microphone**

**Purpose**: Monitor for applications accessing the system's microphone.

{% code overflow="wrap" %}
```powershell
Get-WmiObject -Class Win32_PnPEntity |  Where-Object {($_.Name -match "Microphone") -and ($_.Status -eq "OK")} | Select-Object Name, Status
```
{% endcode %}

### 6. **Credential and Authentication Data Collection**

**6.1. Monitoring for Credential Dumping Tools**

**Purpose**: Detect the use of tools like Mimikatz for extracting credentials.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'mimikatz'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

**6.2. Detecting Access to Credential Stores**

**Purpose**: Identify attempts to access stored credentials, such as password vaults.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'Credentials'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

### 7. **Email and Messaging Data Collection**

**7.1. Monitoring for Email Client Activity**

**Purpose**: Detect unusual activity in email clients, such as bulk exports.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=3005} | Where-Object {$_.Message -match 'Outlook'} | Select-Object TimeCreated, @{n='Event';e={$_.Message}}
```
{% endcode %}

**7.2. Detecting Access to Messaging Applications**

**Purpose**: Identify access to messaging applications like Skype, Teams, etc.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Teams|Skype|Slack'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

### 8. **Browser Data Collection**

**8.1. Detecting Access to Browser Data**

**Purpose**: Monitor for access to browser data, including cookies and history.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default" -Include Cookies, History -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

**8.2. Monitoring Browser Extensions for Data Collection**

**Purpose**: Detect malicious or suspicious browser extensions.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Recurse | Select-Object FullName, LastWriteTime
```
{% endcode %}

### 9. **Data Staging and Compression**

**9.1. Detecting Data Compression Tools**

**Purpose**: Identify the use of tools like WinRAR or 7-Zip for compressing data.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'WinRAR|7z'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**9.2. Monitoring for Creation of Archive Files**

**Purpose**: Detect the creation of archive files that may indicate data staging.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Users\*" -Recurse -Include *.zip, *.rar, *.7z | Select-Object FullName, LastWriteTime
```
{% endcode %}

### 10. **Cloud and Remote Storage Access**

**10.1. Monitoring for Cloud Storage Access**

**Purpose**: Detect access to cloud storage services like Dropbox, Google Drive, etc.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Dropbox|GoogleDrive|OneDrive'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**10.2. Detecting File Uploads to Remote Servers**

**Purpose**: Identify file uploads to remote servers, indicating potential exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'File Write'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

