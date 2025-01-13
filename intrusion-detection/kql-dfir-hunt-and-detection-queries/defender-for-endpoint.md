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

# Defender For Endpoint

### Detect Local User Account Creation on Endpoint

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where TimeGenerated > ago(7d) // Analyze events from the past 7 days
| where ActionType == "UserAccountCreated" // Filter events where user accounts are created
| where AccountName != "defaultuser1" // Exclude default system-created accounts
| extend 
    AccountDomain = tostring(AccountDomain), // Extract domain of the created account
    ActorDomain = tostring(InitiatingProcessAccountDomain) // Domain of the actor initiating the action
| project 
    TimeGenerated, // Timestamp of the event
    DeviceName, // Device where the account was created
    ['Account Created Name'] = AccountName, // Name of the created account
    AccountDomain, // Domain of the created account
    Actor = InitiatingProcessAccountName, // Account initiating the process
    ActorDomain, // Domain of the actor account
    ActionType // Type of action taken
| order by TimeGenerated desc // Sort by most recent events
```
{% endcode %}

### Detecting Anomalous RDP Connections

**Use Case:** This query is designed to detect anomalous RDP activity in your environment, potentially indicating lateral movement or brute force attempts. By excluding known legitimate processes and focusing on private IPs, the query ensures that it highlights significant anomalies for further investigation.

{% code overflow="wrap" %}
```kusto
// Define parameters
let starttime = 30d; // Analysis window for anomaly detection
let timeframe = 2h; // Time bin for summarization
let sensitivity = 3; // Sensitivity for anomaly detection
let threshold = 2; // Minimum RDP events threshold for anomaly consideration
// Identify devices with anomalous RDP activity
let outlierdevices = 
    DeviceNetworkEvents
    | where TimeGenerated > ago(starttime) // Filter events within the analysis window
    | where LocalIPType == "Private" // Focus on private IPs
    | where RemotePort == "3389" // Filter for RDP activity
    | where InitiatingProcessFileName != "Microsoft.Tri.Sensor.exe" // Exclude known legitimate processes
    | summarize RDPEvents = count() by DeviceName, bin(TimeGenerated, timeframe) // Summarize RDP activity by device and time bin
    | where RDPEvents > threshold // Filter devices with high RDP activity
    | summarize 
        EventCount = make_list(RDPEvents), // Collect event counts over time
        TimeGenerated = make_list(TimeGenerated) // Collect time bins
        by DeviceName
    | extend outliers = series_decompose_anomalies(EventCount, sensitivity) // Perform anomaly detection
    | mv-expand TimeGenerated, EventCount, outliers // Expand lists for detailed analysis
    | where outliers == 1 // Filter for anomalous events
    | distinct DeviceName; // Get unique list of devices with anomalies
// Analyze detailed RDP activity for anomalous devices and display in a table
DeviceNetworkEvents
| where TimeGenerated > ago(starttime) // Filter events within the analysis window
| where DeviceName in (outlierdevices) // Focus on anomalous devices
| where LocalIPType == "Private" // Focus on private IPs
| where RemotePort == "3389" // Filter for RDP activity
| where InitiatingProcessFileName != "Microsoft.Tri.Sensor.exe" // Exclude known legitimate processes
| summarize 
    RDPCount = count(), // Total RDP activity count
    TimeRange = make_list(bin(TimeGenerated, timeframe)), // Collect time bins for activity
    IPAddresses = make_set(RemoteIP), // Collect unique remote IP addresses
    ProcessNames = make_set(InitiatingProcessFileName), // Collect initiating process file names
    InitiatingAccount = make_set(InitiatingProcessAccountName) // Collect user accounts initiating RDP
    by DeviceName // Group by device
| project 
    DeviceName, // Name of the device
    InitiatingAccount, // List of accounts initiating the activity
    RDPCount, // Total RDP activity count
    TimeRange, // Time bins of activity
    IPAddresses, // List of unique remote IPs involved in the activity
    ProcessNames // List of processes initiating the activity
| order by RDPCount desc // Sort by RDP activity count in descending order
```
{% endcode %}

### Detect Encoded Powershell and Decode

**Use Case:** This advanced query enables SOC analysts to: Detect and investigate suspicious encoded PowerShell commands. Decode and analyse commands to identify potential malicious activity. Highlight commands containing known malicious patterns for prioritisation.

{% code overflow="wrap" %}
```kusto
// Advanced query to detect and decode suspicious encoded PowerShell commands
DeviceProcessEvents
| where TimeGenerated >= ago(7d) // Set a time range for analysis
| where InitiatingProcessAccountName != "system"
| where (ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell") // Filter for PowerShell processes
| where (ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-encodedcommand" 
         or InitiatingProcessCommandLine contains "-enc" or InitiatingProcessCommandLine contains "-encodedcommand") // Focus on encoded commands
| extend 
    EncodedCommand = extract(@'\s+([A-Za-z0-9+/]{20,}[=]{0,2})$', 1, ProcessCommandLine) // Extract base64-encoded command
| where isnotempty(EncodedCommand) // Ensure extracted commands are non-empty
| extend 
    DecodedCommand = base64_decode_tostring(EncodedCommand) // Decode the base64-encoded command
| where isnotempty(DecodedCommand) // Ensure decoded commands are valid
| extend 
    CommandLength = strlen(DecodedCommand), // Measure the length of the decoded command
    SuspiciousKeywords = iif(DecodedCommand matches regex "(Add-MpPreference|Set-MpPreference|Invoke-WebRequest|IEX|Start-Process|DownloadString)", "True", "False") // Identify suspicious patterns in decoded commands
| project 
    TimeGenerated, // Timestamp of the event
    DeviceName, // Device where the event occurred
    InitiatingProcessAccountName, // User account that initiated the process
    InitiatingProcessCommandLine, // Full command line of the initiating process
    ProcessCommandLine, // Full command line of the process
    EncodedCommand, // Extracted base64-encoded command
    DecodedCommand, // Decoded command
    CommandLength, // Length of the decoded command
    SuspiciousKeywords // Indicator for suspicious patterns
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

### Detect Inbound Public RDP Connections

**Use Case:** Detect and analyse inbound network connections that may indicate potential security risks, particularly focusing on RDP connections and suspicious svchost processes.

{% code overflow="wrap" %}
```kusto
// Detect suspicious inbound RDP connections
DeviceNetworkEvents
| where TimeGenerated >= ago(7d) // Set a time range for analysis
| where ActionType == "InboundConnectionAccepted" // Focus on accepted inbound connections
| where LocalIPType == "Private" and RemoteIPType == "Public" // Filter connections from public to private IPs
| where LocalPort == 3389 or InitiatingProcessCommandLine has_cs "svchost.exe -k termsvcs -s TermService" // Focus on RDP port or related svchost process
| extend 
    IsRDPConnection = iff(LocalPort == 3389, "True", "False"), // Flag RDP-specific connections
    SuspiciousProcess = iif(InitiatingProcessCommandLine has_cs "svchost.exe -k termsvcs -s TermService", "True", "False") // Flag suspicious processes
| project 
    TimeGenerated, // Event timestamp
    DeviceName, // Name of the device
    DeviceId, // Device identifier
    InitiatingProcessAccountName, // Initiating Account
    LocalIP, // Local IP address
    LocalPort, // Local port number
    RemoteIP, // Remote IP address initiating the connection
    InitiatingProcessCommandLine, // Command line of the initiating process
    IsRDPConnection, // Flag for RDP-specific connections
    SuspiciousProcess // Flag for suspicious svchost process
| order by TimeGenerated desc // Sort by most recent events
```
{% endcode %}

### Detect Successful RDP Connections from Public to Private Address

{% code overflow="wrap" %}
```kusto
// Advanced query to detect successful RDP connections from public to private IPs
DeviceNetworkEvents
| where TimeGenerated >= ago(7d) // Set time range for analysis
| where ActionType == "ConnectionSuccess" // Filter for successful connections
| where RemotePort == "3389" // Focus on RDP port
| where LocalIPType == "Private" and RemoteIPType == "Public" // Restrict to public-to-private connections
| extend 
    IsSuspiciousAccount = iif(InitiatingProcessAccountName in~ ("Administrator", "Admin", "Guest"), "True", "False"), // Flag suspicious accounts
    Country = tostring(parse_json(AdditionalFields).RemoteCountry), // Extract country from AdditionalFields if available
    Organization = tostring(parse_json(AdditionalFields).RemoteOrganization) // Extract organization info if available
| project 
    TimeGenerated, // Event timestamp
    DeviceName, // Device where the connection occurred
    LocalIP, // Local IP accepting the connection
    RemoteIP, // Remote IP initiating the connection
    RemoteUrl, // Associated remote URL (if any)
    InitiatingProcessAccountName, // User account initiating the process
    InitiatingProcessCommandLine, // Command line of the initiating process
    Country, // Country of the remote IP
    Organization, // Organization associated with the remote IP
    IsSuspiciousAccount // Flag for suspicious accounts
    | order by TimeGenerated desc // Sort by most recent events
```
{% endcode %}

### Detect Multiple Failed Remote Logons

**Use Case:** This query helps detect suspicious patterns of failed logon attempts, such as: Brute Force Attacks: High-volume logon attempts from a single remote IP. Lateral Movement Attempts: Failed logons across multiple devices or accounts. Threat Intelligence Correlation: Identifying known malicious IPs attempting access.

{% code overflow="wrap" %}
```kusto
// Advanced query to detect suspicious failed remote interactive logon attempts
DeviceLogonEvents
| where TimeGenerated > ago(1d) // Analyze events from the last day
| where LogonType == "RemoteInteractive" // Focus on remote interactive logon types (e.g., RDP)
| where ActionType == "LogonFailed" // Include only failed logon attempts
| summarize
    LogonAttemptCount = count(), // Total number of logon attempts
    DistinctDeviceCount = dcount(DeviceName), // Number of distinct devices
    DeviceList = make_set(DeviceName), // List of devices
    Accounts = make_set(AccountName), // List of accounts involved
    DistinctAccountCount = dcount(AccountName) // Number of distinct accounts
    by RemoteIP, bin(TimeGenerated, 1h) // Group by remote IP and 1-hour time bins
| where DistinctDeviceCount >= 3 or LogonAttemptCount >= 10 // Filter for suspicious patterns
| project 
    TimeGenerated, // Time window of the activity
    RemoteIP, // Remote IP involved in the logon attempts
    LogonAttemptCount, // Total failed logon attempts
    DistinctDeviceCount, // Number of distinct devices targeted
    DeviceList, // List of devices targeted
    DistinctAccountCount, // Number of distinct accounts involved
    Accounts // List of accounts involved
| order by LogonAttemptCount desc // Sort by the highest number of logon attempts
```
{% endcode %}

### Detect Putty Connections

**Use Cases:** Detect Unauthorised SSH/Telnet/RDP Connections: Identifies potential misuse of PuTTY to connect to sensitive or unauthorised external systems. Investigate Suspicious Remote Connections: Provides geolocation, process details, and port usage for deeper forensic analysis. Detect Misuse of Privileged Accounts: Flags PuTTY usage by accounts that might be used for lateral movement or external exfiltration.

{% code overflow="wrap" %}
```kusto
// Advanced query to detect successful PuTTY connections from private to public IPs
DeviceNetworkEvents
| where TimeGenerated >= ago(7d) // Analyze events from the past 7 days
| where ActionType == "ConnectionSuccess" // Focus on successful connections
| where LocalIPType == "Private" and RemoteIPType == "Public" // Filter for private-to-public IP connections
| where InitiatingProcessCommandLine has_cs "putty.exe" // Case-insensitive filter for PuTTY usage
| extend 
    RemoteGeoInfo = parse_json(AdditionalFields).RemoteCountry, // Extract country information from AdditionalFields
    SuspiciousPort = iif(RemotePort in (22, 23, 3389), "True", "False"), // Flag suspicious ports (SSH, Telnet, RDP)
    ProcessHash = tostring(parse_json(AdditionalFields).InitiatingProcessSHA256) // Extract SHA256 hash of the initiating process
| project 
    TimeGenerated, // Event timestamp
    DeviceName, // Name of the device where the connection occurred
    InitiatingProcessAccountName, // Account initiating the process
    LocalIP, // Local IP involved in the connection
    RemoteIP, // Remote IP of the connection
    RemoteUrl, // Associated remote URL
    RemotePort, // Port used for the connection
    RemoteGeoInfo, // Geolocation of the remote IP
    SuspiciousPort, // Indicator for commonly targeted ports
    ProcessHash, // SHA256 hash of the initiating process
    InitiatingProcessCommandLine // Full command line of the initiating process
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

### Detect RDP Recon Activities

**Use Cases:** Detect Potential Brute Force or Lateral Movement: Identify devices with unusual RDP activity targeting multiple distinct IPs within a short timeframe. Investigate Malicious RDP Usage: Flag devices with excessive or suspicious RDP connection activity. Monitor for Unauthorized Activity: Detect potential misuse of RDP by correlating accounts and devices involved.

{% code overflow="wrap" %}
```kusto
// Parameters for analysis
let timerange = 1d; // Define the analysis time range
let window = 20m; // Define the time window for grouping events
let threshold = 5; // Define the threshold for the number of target devices
// Detect unusual RDP activity across devices
DeviceNetworkEvents
| where TimeGenerated > ago(timerange) // Analyze events within the defined time range
| where ActionType == "ConnectionSuccess" // Focus on successful connections
| where RemotePort == "3389" // Filter for RDP traffic
| where InitiatingProcessFileName != "Microsoft.Tri.Sensor.exe" // Exclude known legitimate RDP mapping process
| summarize 
    TargetDeviceList = make_set(RemoteIP), // Aggregate unique remote IPs
    AssociatedAccounts = make_set (InitiatingProcessAccountName), // Collect accounts associated with the connections
    CountOfDevices = dcount(RemoteIP) // Count distinct remote IPs
    by bin(TimeGenerated, window), DeviceName // Group by time window and device
| where CountOfDevices > threshold // Filter devices exceeding the target threshold
| extend 
    IsSuspicious = iif(CountOfDevices > (2 * threshold), "High", "Moderate") // Add a severity indicator
| project 
    TimeGenerated, // Event timestamp
    DeviceName, // Name of the device
    TargetDeviceList, // List of targeted remote IPs
    CountOfDevices, // Number of distinct devices targeted
    AssociatedAccounts, // List of accounts involved in the connections
    IsSuspicious // Severity level of the activity
| order by CountOfDevices desc // Sort by the highest number of targeted devices

```
{% endcode %}

### Detect Registry Tampering

**Use Cases:** Detect and Investigate Registry Tampering: Identify attempts to modify critical registry keys, which may indicate malware or privilege escalation attempts. Monitor Successful Tampering: Highlight successful tampering attempts for immediate response. Assess Threat Levels: Prioritise high-risk events involving critical keys with successful tampering. Forensic Analysis: Use detailed process and registry key information for post-incident investigations.

{% code overflow="wrap" %}
```kusto
// Detect registry tampering attempts with safe field extraction
DeviceEvents
| where TimeGenerated >= ago(7d) // Analyze events from the last 7 days
| where ActionType == "TamperingAttempt" // Focus on tampering attempts
| extend AdditionalFieldsJson = parse_json(AdditionalFields) // Parse AdditionalFields into a JSON object
| extend 
    TamperingAction = tostring(AdditionalFieldsJson['TamperingAction']), // Extract tampering action type
    Status = tostring(AdditionalFieldsJson['Status']), // Extract tampering attempt status
    OriginalRegistryValue = tostring(AdditionalFieldsJson['OriginalValue']), // Original value of the registry key
    AttemptedRegistryValue = tostring(AdditionalFieldsJson['TamperingAttemptedValue']), // Value attempted during the tampering
    TargetRegistryKey = tostring(AdditionalFieldsJson['Target']) // Target registry key
| where isnotempty(TamperingAction) and TamperingAction == "RegistryModification" // Ensure valid registry modification actions
| extend 
    IsSuccessful = iif(Status == "Succeeded", "True", "False"), // Add a flag for successful tampering attempts
    IsCriticalKey = iif(TargetRegistryKey has_cs "HKEY_LOCAL_MACHINE" or TargetRegistryKey has_cs "HKEY_CURRENT_USER", "True", "False") // Flag critical registry keys
| project 
    TimeGenerated, // Timestamp of the event
    DeviceName, // Name of the device where the tampering occurred
    InitiatingProcessAccountName, // Account initiating the tampering attempt
    InitiatingProcessCommandLine, // Command line of the initiating process
    TamperingAction, // Type of tampering action
    Status, // Status of the tampering attempt
    IsSuccessful, // Indicator if the tampering was successful
    TargetRegistryKey, // Registry key targeted for tampering
    OriginalRegistryValue, // Original value of the registry key
    AttemptedRegistryValue // Value attempted during the tampering
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

### Detect ISO File Mounts Followed by Browser-launched URL Activity

**Use Cases:** Detect Suspicious ISO File Mounts: Correlates ISO file mounts with subsequent browser activity, potentially indicating phishing or lateral movement attempts. Identify Malicious URL Usage: Links browser activity to recently mounted ISO files, often a vector for malicious payloads. Investigate User Behavior: Associates user accounts and devices with specific file and web activity for deeper forensic analysis.

{% code overflow="wrap" %}
```kusto
// Detect ISO file mounts followed by browser-launched URL activity within 20 minutes
let DeviceFileEventsISO = DeviceFileEvents
| where TimeGenerated > ago(7d) // Analyze file creation events from the past day
| where ActionType == "FileCreated" // Focus on file creation actions
| where FileName endswith "iso.lnk" // Filter for files ending with "iso.lnk"
| extend ISOMountTime = TimeGenerated // Alias for ISO mount time
| project 
    ISOMountTime, 
    DeviceName, 
    FileName, 
    FolderPath, 
    InitiatingProcessAccountName;
let BrowserEvents = DeviceEvents
| where TimeGenerated > ago(1d) // Analyze browser activity from the past day
| where ActionType == "BrowserLaunchedToOpenUrl" // Focus on browser-launched URL actions
| where RemoteUrl startswith "http" // Filter URLs that start with "http" (valid web URLs)
| extend URLOpenTime = TimeGenerated // Alias for URL open time
| project 
    URLOpenTime, 
    DeviceName, 
    InitiatingProcessAccountName, 
    RemoteIP, 
    RemoteUrl, 
    RemotePort;
DeviceFileEventsISO
| join kind=inner (BrowserEvents) on DeviceName, InitiatingProcessAccountName // Join on device and account name
| where URLOpenTime between ((ISOMountTime) .. (ISOMountTime + timespan(20m))) // Find browser activity within 20 minutes of ISO file mount
| extend ['ISO FileName'] = trim(@".lnk", FileName) // Remove ".lnk" from the file name
| project 
    ISOMountTime, // ISO file mount time
    URLOpenTime, // Browser URL open time
    ['ISO FileName'], // Trimmed ISO file name
    DeviceName, // Device involved
    InitiatingProcessAccountName, // Account initiating the events
    RemoteUrl, // URL opened
    RemoteIP, // Remote IP address of the URL
    RemotePort // Remote port of the URL
| order by ISOMountTime desc // Sort by the most recent ISO file mounts
```
{% endcode %}

### Identify Historical "whoami" Activity

**Use Cases:** Detect Suspicious "whoami" Usage: Identify devices or accounts with recent "whoami" activity that have no prior history, which might indicate reconnaissance by attackers. Monitor Command Usage Trends: Track new or unusual accounts executing commands like "whoami" as part of a forensic investigation. Investigate Account and Device Behavior: Correlate account activity with device activity for enhanced context during incident response.

{% code overflow="wrap" %}
```kusto
// Step 1: Identify historical "whoami" activity (past 30 days, excluding the last day)
let HistoricalWhoamiActivity = 
    DeviceProcessEvents
    | where TimeGenerated > ago(30d) and TimeGenerated <= ago(1d) // Analyze the past 30 days, excluding the last day
    | where InitiatingProcessCommandLine contains "whoami" // Filter for "whoami" commands
    | distinct DeviceName, InitiatingProcessAccountName; // Get unique combinations of devices and accounts
// Step 2: Identify recent "whoami" activity (last day)
let RecentWhoamiActivity = 
    DeviceProcessEvents
    | where TimeGenerated > ago(1d) // Analyze activity from the last day
    | where InitiatingProcessCommandLine contains "whoami" // Filter for "whoami" commands
    | project 
        TimeGenerated, 
        DeviceName, 
        InitiatingProcessAccountName, 
        InitiatingProcessCommandLine; // Retain relevant fields
// Step 3: Identify "whoami" activity in the last day but not in historical data
RecentWhoamiActivity
| join kind=rightanti (
    HistoricalWhoamiActivity
) on DeviceName, InitiatingProcessAccountName // Exclude historical activity
| project 
    DeviceName, // Device where the activity occurred
    InitiatingProcessAccountName // Account initiating the command
```
{% endcode %}

### Detect Suspicious PowerShell Commands Altering the Execution Policy

**Use Cases:** Detect Execution Policy Changes: Identify unauthorized or suspicious modifications to PowerShell's execution policy. Investigate Potential Misuse of PowerShell: Correlate execution policy changes with user accounts and parent processes to detect abuse. Threat Hunting: Highlight non-system accounts making potentially malicious changes to PowerShell settings.

{% code overflow="wrap" %}
```kusto
// Detect suspicious PowerShell commands altering the execution policy
DeviceEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days
| where ActionType == "PowerShellCommand" // Filter for PowerShell command events
| where InitiatingProcessFileName has_cs "powershell.exe" // Ensure case-insensitive match for PowerShell process
| where InitiatingProcessAccountName !in ("system", "nt authority\\system") // Exclude system-level accounts
| extend Command = tostring(parse_json(AdditionalFields).Command) // Safely extract the Command field
| where Command == "Set-ExecutionPolicy" // Focus on execution policy modification commands
| extend 
    ExecutionPolicy = tostring(parse_json(AdditionalFields).ExecutionPolicy), // Extract the targeted execution policy
    ProcessID = tostring(ProcessId), // Include the process ID for tracking
    ParentProcessName = tostring(InitiatingProcessParentFileName) // Add parent process for context
| project 
    TimeGenerated, // Timestamp of the event
    DeviceName, // Name of the device
    InitiatingProcessAccountName, // Account initiating the PowerShell command
    Command, // PowerShell command executed
    ExecutionPolicy, // Targeted execution policy
    ProcessID, // ID of the PowerShell process
    ParentProcessName // Name of the parent process
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

### Powershell Connecting to Internet Systems

**Use Cases:** Monitor PowerShell Network Activity: Detect PowerShell commands making network connections to public IPs from private IPs. Investigate Unauthorized Access: Identify unusual or suspicious network activity initiated by user accounts. Threat Hunting: Highlight potential lateral movement or exfiltration attempts using PowerShell.

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days (adjust as needed)
| where InitiatingProcessAccountName !in~ ("system", "local service") // Exclude system-level processes
| where InitiatingProcessCommandLine contains "powershell" // Focus on PowerShell-related commands
| where LocalIPType == "Private" // Restrict to private local IPs
| where RemoteIPType == "Public" // Restrict to public remote IPs
| project 
    TimeGenerated, // Event timestamp
    DeviceName, // Device where the event occurred
    InitiatingProcessAccountName, // User account initiating the process
    InitiatingProcessCommandLine, // Full command line of the initiating process
    LocalIP, // Local IP address involved
    RemoteIP, // Remote IP address involved
    RemotePort, // Remote port used in the connection
    RemoteUrl // Remote URL accessed
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

### Detect Users Added to Local Administrators Group

**Use Cases:** Monitor Privilege Escalation: Detect unauthorized addition of accounts to local administrator groups. Threat Hunting: Identify potential lateral movement or privilege escalation by attackers. Audit and Compliance: Provide evidence of group membership changes for compliance reporting. Investigate Insider Threats: Highlight unexpected group membership changes initiated by legitimate accounts.

{% code overflow="wrap" %}
```kusto
// Detect users added to local administrators group
DeviceEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days (adjust as needed)
| where ActionType == "GroupMembershipAdded" // Focus on group membership changes
| extend GroupName = tostring(parse_json(AdditionalFields).TargetGroupName), // Extract the target group name
         AddedAccount = tostring(parse_json(AdditionalFields).AddedMember), // Extract the account being added
         InitiatorAccount = tostring(InitiatingProcessAccountName), // Extract the account initiating the change
         InitiatorCommandLine = tostring(InitiatingProcessCommandLine) // Extract the command line of the process
| where GroupName has_cs "Administrators" // Focus on changes to the Administrators group
| project 
    TimeGenerated, // Timestamp of the event
    DeviceName, // Device where the change occurred
    AddedAccount, // Account added to the group
    InitiatorAccount, // Account initiating the change
    InitiatorCommandLine, // Command line of the initiating process
    GroupName // Name of the group modified
| extend 
    IsSuspicious = iif(InitiatorAccount == "system" or AddedAccount has "admin", "False", "True") // Flag suspicious changes
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

### Detect Known Credential Dumping Tools or Techniques

**Use Cases:** Detailed Credential Dumping Analysis: Provides in-depth context for each detected event. Parent-Child Process Relationships: Useful for tracking execution chains and identifying anomalous parent processes. Scope of Impact: Highlights the number of affected devices and accounts for prioritising investigations.

{% code overflow="wrap" %}
```kusto
// Step 1: Detect known credential dumping tools or techniques
let credential_dumping_tools = DeviceProcessEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days
| where InitiatingProcessFileName has_any ("procdump.exe", "mimikatz.exe", "rundll32.exe", "powershell.exe") // Common tools
| where InitiatingProcessCommandLine has_any ("lsass", "dump", "sekurlsa", "samdump", "credentials") // Suspicious keywords
| extend DumpingTechnique = "Known Tool or Command"
| project 
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    DeviceId,
    DumpingTechnique;
// Step 2: Monitor suspicious access to LSASS (Local Security Authority Subsystem Service)
let lsass_access = DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where FileName == "lsass.exe" // LSASS process
| where InitiatingProcessFileName has_any ("procdump.exe", "mimikatz.exe", "rundll32.exe") or InitiatingProcessFileName endswith "exe" // Access from unusual executables
| extend DumpingTechnique = "Suspicious LSASS Access"
| project 
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    DeviceId,
    DumpingTechnique;
// Step 3: Monitor suspicious file access to security-sensitive files
let sensitive_file_access = DeviceFileEvents
| where TimeGenerated >= ago(30d)
| where FolderPath has_any ("\\Windows\\System32\\config\\SAM", "\\Windows\\System32\\config\\SYSTEM") // Accessing SAM or SYSTEM files
| extend DumpingTechnique = "Sensitive File Access"
| project 
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    FolderPath,
    InitiatingProcessFileName,
    DeviceId,
    DumpingTechnique;
// Step 4: Combine and deduplicate results from all techniques
credential_dumping_tools
| union lsass_access
| union sensitive_file_access
| summarize
    EventCount = count(), // Count of events
    AffectedDevices = dcount(DeviceName), // Unique devices affected
    AffectedAccounts = dcount(InitiatingProcessAccountName), // Unique accounts involved
    Events = make_set(pack('TimeGenerated', TimeGenerated, 
                           'DeviceName', DeviceName,
                           'InitiatingProcessAccountName', InitiatingProcessAccountName,
                           'InitiatingProcessCommandLine', InitiatingProcessCommandLine,
                           'InitiatingProcessFileName', InitiatingProcessFileName,
                           'FolderPath', FolderPath)) // Consolidate detailed event information
    by DumpingTechnique, bin(TimeGenerated, 1h) // Summarize by technique and time
| order by TimeGenerated desc // Sort by most recent events
| mv-expand Events // Expand consolidated events for detailed view
| extend 
    TimeGenerated = tostring(Events.TimeGenerated),
    DeviceName = tostring(Events.DeviceName),
    InitiatingProcessAccountName = tostring(Events.InitiatingProcessAccountName),
    InitiatingProcessCommandLine = tostring(Events.InitiatingProcessCommandLine),
    InitiatingProcessFileName = tostring(Events.InitiatingProcessFileName),
    ParentProcessName = tostring(Events.ParentProcessName),
    ParentProcessId = tostring(Events.ParentProcessId),
    FolderPath = tostring(Events.FolderPath)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    ParentProcessName,
    ParentProcessId,
    FolderPath,
    DumpingTechnique,
    EventCount,
    AffectedDevices,
    AffectedAccounts;
```
{% endcode %}

### Certutil Remote Download

**Use Cases:** Detect Malicious File Downloads: Identify attackers leveraging certutil to download malicious files remotely. Investigate Certutil Abuse: Certutil is often abused in living-off-the-land attacks; this query highlights such activity. Threat Hunting: Proactively search for potential threats involving certutil usage. Incident Response: Quickly correlate certutil events with potential lateral movement or privilege escalation.

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days
| where InitiatingProcessFileName has_cs "certutil.exe" // Focus on certutil.exe
| where InitiatingProcessCommandLine has_any ("-urlcache", "-split", "http", "https") // Indicators of remote downloads
| extend 
    RemoteUrl = extract(@"(http[s]?://[^\s]+)", 0, InitiatingProcessCommandLine), // Extract the remote URL
    IsSuspicious = iff("RemoteUrl" has "malicious.com" or "RemoteUrl" has "unknown.com", "True", "False") // Example suspicious domain check
| project 
    TimeGenerated, // Event timestamp
    DeviceName, // Device where the command was executed
    InitiatingProcessAccountName, // Account initiating the certutil command
    InitiatingProcessCommandLine, // Full command line of the certutil process
    RemoteUrl, // Extracted remote URL
    ProcessCommandLine, // Name of the parent process
    ProcessId, // Parent process ID
    DeviceId, // Device ID for additional correlation
    IsSuspicious // Indicator if the URL matches known suspicious patterns
| order by TimeGenerated desc // Sort by most recent events
```
{% endcode %}

### Detect Browser-Launched URL Activity on a Compromised Device

**Use Cases:** Detect Malicious Web Activity: Identify suspicious URLs accessed on a compromised device. Threat Hunting: Correlate browser activity with other suspicious behavior on the same device. Incident Response: Prioritize investigation of events involving flagged suspicious domains. Proactive Defense: Use domain-level insights to refine URL filtering policies.

{% code overflow="wrap" %}
```kusto
// Parameters
let CompromisedDevice = "PC01.exampledomain.com"; // Specify the compromised device
let SearchWindow = 48h; // Time window for analysis
// Query to detect browser-launched URL activity
DeviceEvents
| where TimeGenerated >= ago(SearchWindow) // Use 'TimeGenerated' for consistency
| where DeviceName == CompromisedDevice // Filter by the specified compromised device
| where ActionType == "BrowserLaunchedToOpenUrl" // Focus on browser-launched URL events
| where RemoteUrl startswith "http" // Filter for valid web URLs
| extend 
    Domain = extract(@"^(?:https?://)?([^/]+)", 1, RemoteUrl), // Extract domain from URL
    IsSuspicious = iif("Domain" has_any ("malicious.com", "suspiciousdomain.com"), "True", "False") // Example suspicious domain check
| project 
    Timestamp = TimeGenerated, // Timestamp of the event
    DeviceName, // Device name
    RemoteUrl, // Full URL accessed
    Domain, // Extracted domain from URL
    IsSuspicious, // Flag for suspicious domains
    InitiatingProcessFileName, // File name of the initiating process
    InitiatingProcessCommandLine, // Full command line of the initiating process
    InitiatingProcessFolderPath // Folder path of the initiating process
| order by Timestamp desc // Sort by the most recent events
```
{% endcode %}

### Detect All Processes Created By Malicious File

**Use Cases:** Detect and Investigate Malicious File Activity: Identify file activity for a specific SHA1 hash or filename. Correlate File and Process Activity: Link file presence with processes executing or interacting with it. Incident Response: Trace malicious file activity for root cause analysis and remediation. Threat Hunting: Enhance detection strategies by identifying patterns in malicious file execution.

{% code overflow="wrap" %}
```kusto
// Define key parameters
let MaliciousFileSHA1 = "Add SHA1 Hash"; // SHA1 hash of the malicious file
let MaliciousFileName = "Add Filename"; // Name of the malicious file
let SearchWindow = 48h; // Customizable time window
// Step 1: Extract file locations where the malicious file was observed
let FileInfoLocation = materialize(
    DeviceFileEvents
    | where TimeGenerated > ago(SearchWindow)
    | where (not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) 
        or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName))
    | summarize FileLocations = make_set(tolower(FolderPath))
);
// Step 2: Extract file names of the malicious file
let FileInfoFileName = materialize(
    DeviceFileEvents
    | where TimeGenerated > ago(SearchWindow)
    | where (not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) 
        or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName))
    | summarize Filenames = make_set(tolower(FileName))
);
// Step 3: Extract SHA1 hashes of the malicious file
let FileInfoFileSHA1 = materialize(
    DeviceFileEvents
    | where TimeGenerated > ago(SearchWindow)
    | where (not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) 
        or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName))
    | summarize FileInfoFileSHA1 = make_set(SHA1)
);
// Step 4: Correlate file activity with process events
let ProcessActivity = DeviceProcessEvents
| where TimeGenerated > ago(SearchWindow)
| where InitiatingProcessCommandLine has_any (FileInfoLocation)
| project
    Timestamp = TimeGenerated,
    DeviceName,
    ActionType,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine;
// Step 5: Combine results for a comprehensive view
union isfuzzy=true
    (FileInfoFileName), // Malicious file names
    (FileInfoLocation), // Locations of the malicious file
    (FileInfoFileSHA1), // SHA1 hashes of the malicious file
    (ProcessActivity) // Process activity related to the malicious file
| project-reorder 
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    FileInfoFileSHA1,
    FileLocations,
    Filenames
| sort by Timestamp desc;
```
{% endcode %}

### Inbound Connections Compromised Device

**Use Cases:** Detect Malicious Inbound Connections: Identify unauthorized access attempts on compromised devices. Enrich Threat Investigation: Correlate inbound connections with process activity for a complete picture. Incident Response: Prioritize investigation of critical connections flagged as suspicious. Threat Hunting: Proactively monitor devices for potential exploitation or lateral movement.

{% code overflow="wrap" %}
```kusto
// Parameters
let CompromisedDevice = "PC01.exampledomain.com"; // Specify the compromised device
let SearchWindow = 48h; // Time window for analysis
// Step 1: Detect inbound connections to the compromised device
let InboundConnections = DeviceNetworkEvents
| where TimeGenerated >= ago(SearchWindow) // Analyze events within the time window
| where DeviceName == CompromisedDevice // Focus on the specified compromised device
| where ActionType == "InboundConnectionAccepted" // Filter for accepted inbound connections
| extend RemoteIPCategory = iif(RemoteIPType == "Public", "External", "Internal") // Categorize remote IP
| extend IsSuspiciousPort = iif(RemotePort in (22, 23, 3389, 445), "True", "False") // Flag suspicious ports
| extend ThreatIntelMatch = iif(RemoteIP in (ThreatIntelligenceIndicator), "True", "False") // Match against threat intelligence
| project 
    TimeGenerated, 
    DeviceName, 
    LocalIP, 
    LocalPort, 
    RemoteIP, 
    RemoteIPCategory, 
    RemotePort, 
    IsSuspiciousPort, 
    ThreatIntelMatch;
// Step 2: Correlate with process activity for enriched context
let ProcessActivity = DeviceProcessEvents
| where TimeGenerated >= ago(SearchWindow)
| where DeviceName == CompromisedDevice
| project 
    TimeGenerated, 
    DeviceName, 
    InitiatingProcessAccountName, 
    InitiatingProcessCommandLine, 
    InitiatingProcessFileName, 
    FileName, 
    ProcessId;
// Step 3: Combine network events with process activity
InboundConnections
| join kind=leftouter (ProcessActivity) on DeviceName
| extend IsCritical = iif(IsSuspiciousPort == "True" or ThreatIntelMatch == "True", "True", "False") // Flag critical connections
| project 
    TimeGenerated, 
    DeviceName, 
    LocalIP, 
    LocalPort, 
    RemoteIP, 
    RemotePort, 
    RemoteIPCategory, 
    IsSuspiciousPort, 
    ThreatIntelMatch, 
    IsCritical, 
    InitiatingProcessAccountName, 
    InitiatingProcessCommandLine, 
    InitiatingProcessFileName, 
    FileName, 
    ProcessId
| order by TimeGenerated desc;
```
{% endcode %}

### List Malicious Activities

**Use Cases:** Centralized View of Security Events: Provides a single pane of glass for all security-related events from a compromised device. Incident Response: Enables quick correlation and triage of ASR, AV, SmartScreen, AMSI, exploit guard, and tampering events. Forensic Analysis: Supplies detailed context for each event to support root cause analysis and containment strategies.

{% code overflow="wrap" %}
```kusto
// Parameters
let CompromisedDevice = "PC01.exampledomain.com"; // Specify the compromised device
let SearchWindow = 48h; // Customizable time window
// Step 1: Collect all ASR triggers from the compromised device
let ASREvents = DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType startswith "ASR"
| project 
    EventType = "ASR Event",
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    AccountDomain,
    AccountName;
// Step 2: Collect all SmartScreen events
let SmartScreenEvents = DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType in ('SmartScreenAppWarning', 'SmartScreenUrlWarning')
| extend 
    SmartScreenTrigger = iff(ActionType == "SmartScreenUrlWarning", RemoteUrl, FileName),
    ReasonForTrigger = tostring(parse_json(AdditionalFields).Experience)
| project 
    EventType = "SmartScreen Event",
    Timestamp,
    DeviceName,
    ActionType,
    SmartScreenTrigger,
    ReasonForTrigger,
    InitiatingProcessCommandLine;
// Step 3: List all AV detections
let AntivirusDetections = DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType == "AntivirusDetection"
| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
| project 
    EventType = "Antivirus Detection",
    Timestamp,
    DeviceName,
    ActionType,
    ThreatName,
    FileName,
    FolderPath,
    SHA1,
    InitiatingProcessAccountSid;
// Step 4: List all tampering actions
let TamperingAttempts = DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType == "TamperingAttempt"
| extend 
    TamperingAction = tostring(parse_json(AdditionalFields).TamperingAction),
    Status = tostring(parse_json(AdditionalFields).Status),
    Target = tostring(parse_json(AdditionalFields).Target)
| project 
    EventType = "Tampering Attempt",
    Timestamp,
    DeviceName,
    ActionType,
    TamperingAction,
    Status,
    Target,
    InitiatingProcessCommandLine;
// Step 5: List all exploit guard events
let ExploitGuardEvents = DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType startswith "ExploitGuard"
| project 
    EventType = "Exploit Guard Event",
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    RemoteUrl;
// Step 6: List all AMSI events
let AMSIEvents = DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType contains "Amsi"
| extend Description = tostring(parse_json(AdditionalFields).Description)
| project 
    EventType = "AMSI Event",
    Timestamp,
    DeviceName,
    ActionType,
    Description,
    FolderPath;
// Step 7: Combine all results into one unified output
(union isfuzzy=true
    ASREvents,
    SmartScreenEvents,
    AntivirusDetections,
    TamperingAttempts,
    ExploitGuardEvents,
    AMSIEvents
)
| sort by Timestamp desc // Sort results by the most recent event
```
{% endcode %}

### Detecting LOLBins with Network Activity

**Use Cases**: Detect LOLBin Abuse: Identify LOLBins used for network activity, often indicative of malicious behavior. Analyze Network Activity: Extract and analyze IP addresses used in LOLBin command lines. Prioritize Public IP Activity: Highlight events involving public IPs to focus on potential exfiltration or attacker communication. Threat Hunting: Correlate LOLBin activity with other indicators of compromise for proactive threat detection.

{% code overflow="wrap" %}
```kusto
// Define parameters
let IPRegex = @"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"; // Regex to extract IPs
let LOLBins = dynamic([
    "AppInstaller.exe", "cmd.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", 
    "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmdkey.exe", "cmdl32.exe", 
    "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", 
    "CustomShellHost.exe", "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", 
    "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", 
    "Expand.exe", "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", 
    "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", 
    "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Ldifde.exe", 
    "Makecab.exe", "Mavinject.exe", "Msedge.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", 
    "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", 
    "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", "Pcalua.exe", 
    "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", 
    "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", 
    "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", 
    "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", 
    "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", 
    "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", 
    "Wmic.exe", "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", 
    "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", 
    "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", 
    "Url.dll", "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", 
    "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", "DefaultPack.EXE", 
    "Devinit.exe"
]);
// Query for LOLBins with network activity
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (LOLBins) // Match against known LOLBins
| extend CommandLineIP = extract(IPRegex, 0, InitiatingProcessCommandLine) // Extract IPs from command line
| where isnotempty(CommandLineIP) // Filter for events with extracted IPs
| extend IsPublicIP = not(ipv4_is_private(CommandLineIP)) // Optional: Identify public IPs
| project 
    Timestamp = TimeGenerated, // Event timestamp
    DeviceName, // Device where the event occurred
    InitiatingProcessFileName, // Name of the LOLBin executable
    InitiatingProcessCommandLine, // Full command line of the initiating process
    RemoteIP, // Remote IP address
    CommandLineIP, // Extracted IP from command line
    IsPublicIP // Whether the IP is public
| sort by Timestamp desc; // Sort results by most recent events
```
{% endcode %}

### Detect and Analyse LOLBin Activity

**Use Cases:** Detect Malicious Use of LOLBins: Identify unusual or frequent usage of LOLBins, which may indicate attacker activity. Investigate Process Ancestry: Analyze parent processes to identify suspicious chains leading to LOLBin execution. Correlate LOLBin Usage Across Devices and Accounts: Track patterns of LOLBin usage across devices or user accounts to uncover potential lateral movement. Prioritize Investigation: Focus on LOLBins with high Total Executions or unusual parent processes.

{% code overflow="wrap" %}
```kusto
// Define LOLBins (Living-Off-The-Land Binaries and Scripts)
let LOLBins = dynamic([
    "AppInstaller.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", 
    "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", 
    "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", 
    "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", 
    "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Explorer.exe", 
    "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", "fltMC.exe", "Forfiles.exe", "Ftp.exe", 
    "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", 
    "Installutil.exe", "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", "Msedge.exe", 
    "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", 
    "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", 
    "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", 
    "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", 
    "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", 
    "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", 
    "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", 
    "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", 
    "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", "wt.exe", 
    "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", 
    "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", "Zipfldr.dll", "Comsvcs.dll", 
    "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", 
    "Createdump.exe", "csi.exe", "DefaultPack.EXE", "Devinit.exe"
]);
// Query for LOLBin activity
DeviceProcessEvents
| where InitiatingProcessFileName in~ (LOLBins) // Filter for processes matching LOLBins
| extend 
    ExecutingAccount = tostring(InitiatingProcessAccountName), // Account executing the process
    ParentProcess = tostring(InitiatingProcessParentFileName), // Parent process for context
    Device = tostring(DeviceName) // Device where the execution occurred
| summarize 
    TotalExecutions = count(), // Count total executions
    DevicesInvolved = dcount(Device), // Count distinct devices
    AccountsInvolved = dcount(ExecutingAccount), // Count distinct user accounts
    ParentProcesses = make_set(ParentProcess) // List distinct parent processes
    by InitiatingProcessFileName // Group by the LOLBin name
| sort by TotalExecutions desc; // Sort by the highest number of executions
```
{% endcode %}

### Detect Signs of Fileless Malware

**Use Cases:** Detect Fileless Malware: Identify behaviors commonly associated with fileless malware. Threat Hunting: Uncover patterns in script execution, registry modifications, and in-memory attacks. Incident Response: Correlate suspicious activities to identify and prioritize potential compromises. Proactive Monitoring: Enhance detection capabilities for fileless threats that evade traditional file-based detection.

{% code overflow="wrap" %}
```kusto
// Define suspicious processes and script interpreters commonly abused for fileless malware
let SuspiciousProcesses = dynamic(["powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "wmic.exe", "cmd.exe", "regsvr32.exe", "msiexec.exe"]);
let SuspiciousRegistryKeys = dynamic(["HKCU\\Software\\Classes\\ms-settings", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"]);
// Step 1: Detect suspicious process execution
let SuspiciousProcessesDetected = DeviceProcessEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days
| where InitiatingProcessFileName in~ (SuspiciousProcesses)
| extend IsEncodedCommand = iif(InitiatingProcessCommandLine contains "-enc", "True", "False") // Detect encoded PowerShell commands
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, IsEncodedCommand;
// Step 2: Detect suspicious script or registry modifications
let SuspiciousRegistryModifications = DeviceEvents
| where TimeGenerated >= ago(30d)
| where ActionType == "RegistryKeyValueModified"
| where AdditionalFields.TargetRegistryKey in~ (SuspiciousRegistryKeys)
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessAccountName, TargetRegistryKey = AdditionalFields.TargetRegistryKey, InitiatingProcessCommandLine;
// Step 3: Detect potential in-memory execution or injection
let MemoryInjectionActivity = DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where InitiatingProcessFileName in~ (SuspiciousProcesses)
| where ActionType == "CodeInjection" or ActionType == "ProcessHollowing" // Detect code injection or hollowing
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine;
// Step 4: Correlate network activity with script interpreters
let SuspiciousNetworkActivity = DeviceNetworkEvents
| where TimeGenerated >= ago(30d)
| where InitiatingProcessFileName in~ (SuspiciousProcesses)
| where RemoteIPType == "Public" // Focus on connections to public IPs
| extend RemoteDomain = extract(@"https?://([^/]+)", 1, RemoteUrl) // Extract domain from URL
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteDomain, RemotePort, InitiatingProcessCommandLine;
// Step 5: Combine all suspicious activities into a unified dataset
union isfuzzy=true
    SuspiciousProcessesDetected,
    SuspiciousRegistryModifications,
    MemoryInjectionActivity,
    SuspiciousNetworkActivity
| extend Indicator = case(
    ActionType == "RegistryKeyValueModified", "Suspicious Registry Modification",
    ActionType == "CodeInjection", "Code Injection Detected",
    ActionType == "ProcessHollowing", "Process Hollowing Detected",
    not(isempty(RemoteDomain)), "Suspicious Network Activity",
    IsEncodedCommand == "True", "Encoded Command Execution",
    "Suspicious Process Execution")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, TargetRegistryKey, InitiatingProcessParentFileName, RemoteIP, RemoteDomain, RemotePort, Indicator
| order by TimeGenerated desc;
```
{% endcode %}

### Detect Signs of Lateral Movement Using WMI

**Use Cases:** Detect Lateral Movement via WMI: Identify attackers leveraging WMI for remote command execution or reconnaissance. Threat Hunting: Proactively search for unusual WMI activity across the network. Incident Response: Correlate WMI-related activity with other indicators of compromise. Persistence Detection: Detect registry modifications associated with WMI persistence mechanisms.

{% code overflow="wrap" %}
```kusto
// Define suspicious WMI processes
let SuspiciousWMIBinaries = dynamic(["wmic.exe", "wmiprvse.exe", "wmiprvse.dll", "winmgmt.exe", "wmiprop.dll", "wmiclient.exe"]);
// Step 1: Detect suspicious WMI process executions
let WMISuspiciousProcesses = DeviceProcessEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days
| where InitiatingProcessFileName in~ (SuspiciousWMIBinaries)
| extend IsRemoteExecution = iif(InitiatingProcessCommandLine contains "/node:" or InitiatingProcessCommandLine matches regex @"\s+/node:\s*\S+", "True", "False") // Detect remote WMI execution
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, IsRemoteExecution;
// Step 2: Detect network activity from WMI processes
let WMINetworkActivity = DeviceNetworkEvents
| where TimeGenerated >= ago(30d)
| where InitiatingProcessFileName in~ (SuspiciousWMIBinaries)
| where RemoteIPType == "Public" or ipv4_is_private(RemoteIP) == false // Focus on external or remote IPs
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, InitiatingProcessCommandLine;
// Step 3: Detect suspicious WMI-related registry changes
let WMIRegistryModifications = DeviceEvents
| where TimeGenerated >= ago(30d)
| where ActionType == "RegistryKeyValueModified"
| where AdditionalFields.TargetRegistryKey has_any ("HKLM\\SOFTWARE\\Microsoft\\WBEM", "HKCU\\SOFTWARE\\Microsoft\\WBEM")
| project TimeGenerated, DeviceName, ActionType, TargetRegistryKey = AdditionalFields.TargetRegistryKey, InitiatingProcessCommandLine;
// Step 4: Detect process creation by WMI (indicating remote execution)
let WMIProcessCreation = DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where InitiatingProcessFileName in~ (SuspiciousWMIBinaries)
| where ActionType == "CreateProcess" // Detect process creation triggered by WMI
| project TimeGenerated, DeviceName, InitiatingProcessParentFileName, ProcessCommandLine, InitiatingProcessCommandLine;
// Step 5: Combine and enrich results
union isfuzzy=true
    WMISuspiciousProcesses,
    WMINetworkActivity,
    WMIRegistryModifications,
    WMIProcessCreation
| extend Indicator = case(
    IsRemoteExecution == "True", "Remote WMI Execution Detected",
    ActionType == "RegistryKeyValueModified", "WMI Registry Modification",
    not(isempty(RemoteIP)), "Suspicious Network Activity from WMI Process",
    ActionType == "CreateProcess", "Process Creation by WMI",
    "Suspicious WMI Activity"
)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, InitiatingProcessParentFileName, ProcessCommandLine, TargetRegistryKey, Indicator
| order by TimeGenerated desc;
```
{% endcode %}

### Detect Signs of Privilege Escalation

**Use Cases:** Detect Privilege Escalation: Identify accounts or processes attempting to elevate privileges. Proactive Threat Hunting: Uncover patterns of suspicious behavior indicative of privilege escalation. Incident Response: Correlate detected events with other indicators of compromise. Audit and Compliance: Monitor for unauthorized privilege changes.

{% code overflow="wrap" %}
```kusto
// Define parameters for monitoring privileged activities
let PrivilegedGroups = dynamic(["Administrators", "Domain Admins", "Enterprise Admins"]);
let SuspiciousProcesses = dynamic(["powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "taskmgr.exe"]);
let SuspiciousRegistryKeys = dynamic([
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
    "HKLM\\SECURITY\\SAM"
]);
// Step 1: Detect group membership changes involving privileged groups
let GroupMembershipChanges = IdentityDirectoryEvents
| where TimeGenerated >= ago(30d)
| where ActionType == "GroupMembershipAdded"
| extend TargetGroup = parse_json(AdditionalFields).['TO.GROUP']
| where TargetGroup in~ (PrivilegedGroups) // Focus on privileged groups
| project 
    TimeGenerated, 
    DeviceName, 
    AccountName = parse_json(AdditionalFields).['ACTOR.ACCOUNT'], 
    ActionType, 
    TargetGroup;
// Step 2: Detect suspicious process executions
let SuspiciousProcessesDetected = DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where InitiatingProcessFileName in~ (SuspiciousProcesses)
| where InitiatingProcessCommandLine has_any ("-enc", "-EncodedCommand", "bypass", "hidden", "/c", "elevate") // Indicators of escalation
| extend IsEncodedCommand = iif(InitiatingProcessCommandLine contains "-enc", "True", "False")
| project 
    TimeGenerated, 
    DeviceName, 
    InitiatingProcessAccountName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    IsEncodedCommand;
// Step 3: Detect registry modifications related to privilege escalation
let RegistryModifications = DeviceEvents
| where TimeGenerated >= ago(30d)
| where ActionType == "RegistryKeyValueModified"
| where AdditionalFields.TargetRegistryKey in~ (SuspiciousRegistryKeys)
| project 
    TimeGenerated, 
    DeviceName, 
    ActionType, 
    TargetRegistryKey = AdditionalFields.TargetRegistryKey, 
    InitiatingProcessCommandLine;
// Step 4: Detect token manipulation attempts
let TokenManipulation = DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where ActionType == "TokenElevationAttempt"
| extend ElevationType = parse_json(AdditionalFields).ElevationType
| project 
    TimeGenerated, 
    DeviceName, 
    InitiatingProcessAccountName, 
    InitiatingProcessFileName, 
    ElevationType, 
    InitiatingProcessCommandLine;
// Step 5: Detect creation of new local administrator accounts
let NewAdminAccounts = DeviceEvents
| where TimeGenerated >= ago(30d)
| where ActionType == "UserAccountCreated"
| where AdditionalFields.NewUserType == "Administrator"
| project 
    TimeGenerated, 
    DeviceName, 
    NewAccountName = AdditionalFields.NewUserName, 
    ActionType, 
    InitiatingProcessCommandLine;
// Step 6: Combine all detected activities into a unified dataset
union isfuzzy=true
    GroupMembershipChanges,
    SuspiciousProcessesDetected,
    RegistryModifications,
    TokenManipulation,
    NewAdminAccounts
| extend Indicator = case(
    ActionType == "GroupMembershipAdded", "Privileged Group Membership Change",
    ActionType == "RegistryKeyValueModified", "Suspicious Registry Modification",
    ActionType == "TokenElevationAttempt", "Token Manipulation Attempt",
    ActionType == "UserAccountCreated", "New Administrator Account Created",
    IsEncodedCommand == "True", "Encoded Command Execution",
    "Suspicious Privilege Escalation Activity"
)
| project 
    TimeGenerated, 
    DeviceName, 
    InitiatingProcessAccountName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    TargetRegistryKey, 
    ElevationType, 
    NewAccountName, 
    TargetGroup, 
    Indicator
| order by TimeGenerated desc;
```
{% endcode %}

### Detect Suspicious PowerShell Activity

**Use Cases:** Detect Fileless Malware: Identify obfuscated or encoded commands often used in fileless attacks. Monitor Outbound Connections: Detect PowerShell processes establishing external network connections. Detect Script Execution from Untrusted Paths: Identify unauthorized or unexpected PowerShell script execution. Threat Hunting: Investigate suspicious PowerShell usage across endpoints.

{% code overflow="wrap" %}
```kusto
// Define suspicious PowerShell indicators
let SuspiciousPhrases = dynamic(["-enc", "-EncodedCommand", "-noni", "-nop", "-exec bypass", "-windowstyle hidden", "iex", "invoke-expression", "invoke-command", "downloadstring", "downloadfile"]);
let KnownPowerShellHosts = dynamic(["powershell.exe", "pwsh.exe"]);
// Step 1: Detect suspicious PowerShell process executions
let SuspiciousPowerShellProcesses = DeviceProcessEvents
| where TimeGenerated >= ago(3d) // Analyze events from the last 30 days
| where InitiatingProcessFileName in~ (KnownPowerShellHosts) // Focus on PowerShell hosts
| where InitiatingProcessCommandLine has_any (SuspiciousPhrases) // Match suspicious phrases
| extend IsEncoded = iif(InitiatingProcessCommandLine contains "-enc", "True", "False") // Flag encoded commands
| project 
    TimeGenerated, 
    DeviceName, 
    InitiatingProcessAccountName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    IsEncoded;
// Step 2: Detect PowerShell activity involving remote URLs
let PowerShellWithNetworkActivity = DeviceNetworkEvents
| where TimeGenerated >= ago(3d)
| where InitiatingProcessFileName in~ (KnownPowerShellHosts)
| where RemoteIPType == "Public" // Focus on connections to public IPs
| extend Domain = extract(@"https?://([^/]+)", 1, RemoteUrl) // Extract domain from URL
| project 
    TimeGenerated, 
    DeviceName, 
    InitiatingProcessFileName, 
    RemoteIP, 
    RemotePort, 
    Domain, 
    InitiatingProcessCommandLine;
// Step 3: Detect execution of PowerShell scripts from unexpected locations
let SuspiciousScriptLocations = DeviceFileEvents
| where TimeGenerated >= ago(3d)
| where FileName endswith ".ps1" // Focus on PowerShell script files
| where FolderPath !startswith "C:\\Windows\\" // Exclude typical system directories
| project 
    TimeGenerated, 
    DeviceName, 
    FileName, 
    FolderPath, 
    InitiatingProcessCommandLine;
// Step 4: Detect PowerShell module loading from unusual locations
let SuspiciousModuleLoads = DeviceEvents
| where TimeGenerated >= ago(3d)
| where ActionType == "PowerShellModuleLoaded"
| where AdditionalFields.ModulePath !startswith "C:\\Windows\\System32\\WindowsPowerShell\\" // Exclude default module paths
| project 
    TimeGenerated, 
    DeviceName, 
    ActionType, 
    ModulePath = AdditionalFields.ModulePath, 
    InitiatingProcessCommandLine;
// Step 5: Combine all suspicious PowerShell activities into a unified dataset
union isfuzzy=true
    SuspiciousPowerShellProcesses,
    PowerShellWithNetworkActivity,
    SuspiciousScriptLocations,
    SuspiciousModuleLoads
| extend Indicator = case(
    IsEncoded == "True", "Encoded PowerShell Command",
    not(isempty(Domain)), "PowerShell Network Activity",
    ActionType == "PowerShellModuleLoaded", "Suspicious PowerShell Module Load",
    FileName endswith ".ps1", "Execution of Suspicious PowerShell Script",
    "Suspicious PowerShell Activity"
)
| project 
    TimeGenerated, 
    DeviceName, 
    InitiatingProcessAccountName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteIP, 
    RemotePort, 
    Domain, 
    FileName, 
    FolderPath, 
    ModulePath, 
    Indicator
| order by TimeGenerated desc;
```
{% endcode %}

### Detect Suspicious WMI Activity with Remote IPs

**Use Cases:** Detect Lateral Movement: Identify potential misuse of WMIC.exe for lateral movement within a network. Proactive Threat Hunting: Investigate WMI commands making connections to remote IPs. Incident Response: Correlate WMI activity with suspicious remote connections for further analysis. Filter Noise: Automatically exclude localhost and private IPs to focus on external connections.

{% code overflow="wrap" %}
```kusto
// Define the IP regex pattern
let IPRegex = @"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}";
// Query to detect WMI usage with remote IPs
DeviceProcessEvents
| where TimeGenerated >= ago(30d) // Analyze events from the last 30 days (adjust as needed)
| where FileName =~ "WMIC.exe" // Focus on WMI command-line executions
| extend RemoteIP = extract(IPRegex, 0, ProcessCommandLine) // Extract remote IPs from the command line
| where isnotempty(RemoteIP) // Only include entries with valid extracted IPs
| where not(RemoteIP in~ ("127.0.0.1", "::1")) // Exclude localhost IPs
| extend IsPrivateIP = ipv4_is_private(RemoteIP) // Identify private IPs
| extend IsSuspiciousIP = not(IsPrivateIP) // Flag non-private IPs as suspicious
| project 
    TimeGenerated, // Event timestamp
    DeviceName, // Name of the device where WMI was executed
    ProcessCommandLine, // Full command line of the WMI execution
    RemoteIP, // Extracted remote IP address
    IsPrivateIP, // Whether the IP is private
    IsSuspiciousIP // Whether the IP is flagged as suspicious
| order by TimeGenerated desc; // Sort results by the most recent events
```
{% endcode %}
