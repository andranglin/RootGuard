# Defender For Identity

### <mark style="color:blue;">Devices Accessed By Compromised Device</mark>

**Use Case:** Query helpful for identifying lateral movement and suspicious activities stemming from the compromised device. It enables SOC analysts to correlate activity and prioritise mitigation steps effectively.&#x20;

Defender&#x20;

{% tabs %}
{% tab title="Defender" %}
<pre class="language-kusto" data-overflow="wrap"><code class="lang-kusto"><strong>// Define the compromised device and search window
</strong>let CompromisedDevice = "PC01.exampledomain.com";
let SearchWindow = 48h; // Customizable: h = hours, d = days

// Query to investigate devices accessed by the compromised device
IdentityLogonEvents
| where TimeGenerated >= ago(SearchWindow) // Use Sentinel's default time field
| where DeviceName == CompromisedDevice // Filter for the compromised device
| extend 
    FormattedTimestamp = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss'), // Human-readable timestamp
    AccessDetails = strcat(ActionType, " via ", Protocol) // Combine action type and protocol for detailed context
| summarize
    TotalAccessedDevices = dcount(DestinationDeviceName), // Count unique destination devices accessed
    AccessedDevices = make_set(DestinationDeviceName), // List of destination devices accessed
    AccountsUsed = make_set(AccountName), // List of accounts used in the access
    AccountDomains = make_set(AccountDomain), // List of account domains
    ActionsPerformed = make_set(ActionType), // List of unique action types
    ProtocolsUsed = make_set(Protocol), // List of unique protocols
    IPAddressesInvolved = make_set(IPAddress), // List of unique IP addresses involved
    TargetDevices = make_set(TargetDeviceName), // List of target devices
    AccessEventCount = count() // Total number of access events
    by bin(TimeGenerated, 1h), DeviceName // Group by time bins and device
| project 
    FormattedTimestamp, // Include formatted timestamp
    DeviceName, // Compromised device
    TotalAccessedDevices, // Number of unique devices accessed
    AccessedDevices, // List of accessed devices
    AccountsUsed, // List of accounts used
    AccountDomains, // List of account domains
    ActionsPerformed, // List of actions performed
    ProtocolsUsed, // List of protocols used
    IPAddressesInvolved, // List of IP addresses
    TargetDevices, // List of target devices
    AccessEventCount // Count of access events
| order by FormattedTimestamp desc // Sort by the most recent events
</code></pre>
{% endtab %}

{% tab title="Sentinel" %}
{% code overflow="wrap" %}
```kusto
// Define the compromised device and search window
let CompromisedDevice = "PC01.exampledomain.com";
let SearchWindow = 48h; // Customizable: h = hours, d = days
// Query to investigate devices accessed by the compromised device
IdentityLogonEvents
| where TimeGenerated >= ago(SearchWindow) // Use Sentinel's default time field
| where DeviceName == CompromisedDevice // Filter for the compromised device
| extend 
    FormattedTimestamp = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss'), // Human-readable timestamp
    AccessDetails = strcat(ActionType, " via ", Protocol) // Combine ActionType and Protocol for detailed context
| summarize
    TotalAccessedDevices = dcount(DestinationDeviceName), // Count unique destination devices accessed
    AccessedDevices = make_set(DestinationDeviceName), // List of destination devices accessed
    AccountsUsed = make_set(AccountName), // List of accounts used in the access
    AccountDomains = make_set(AccountDomain), // List of account domains
    ActionsPerformed = make_set(ActionType), // List of unique action types
    ProtocolsUsed = make_set(Protocol), // List of unique protocols
    IPAddressesInvolved = make_set(IPAddress), // List of unique IP addresses involved
    TargetDevices = make_set(TargetDeviceName), // List of target devices
    AccessEventCount = count() // Total number of access events
    by bin(TimeGenerated, 1h), DeviceName // Group by hourly time bins and device
| project 
    TimeGenerated, // Include formatted timestamp
    DeviceName, // Compromised device
    TotalAccessedDevices, // Number of unique devices accessed
    AccessedDevices, // List of accessed devices
    AccountsUsed, // List of accounts used
    AccountDomains, // List of account domains
    ActionsPerformed, // List of actions performed
    ProtocolsUsed, // List of protocols used
    IPAddressesInvolved, // List of IP addresses
    TargetDevices, // List of target devices
    AccessEventCount // Count of access events
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}
{% endtab %}
{% endtabs %}

### <mark style="color:blue;">Identify All Suspicious Activities From The Compromised Accounts</mark>

**Use Case:** This query is useful for investigating potential lateral movement, unauthorised access, or malicious actions originating from compromised accounts. It provides actionable insights to guide further analysis and remediation.

{% code overflow="wrap" %}
```kusto
// Define the compromised accounts and search window
let CompromisedAccounts = dynamic(["user1", "user2"]); // Add compromised account list
let SearchWindow = 48h; // Customizable: h = hours, d = days
// Query to investigate suspicious activities from compromised accounts
IdentityLogonEvents
| where TimeGenerated >= ago(SearchWindow) // Filter based on the search window
| where AccountName in (CompromisedAccounts) // Focus on compromised accounts
| extend 
    FormattedTimestamp = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss'), // Human-readable timestamp
    ActivityDetails = strcat(ActionType, " via ", Protocol, " on ", DeviceName) // Combine action details
| summarize
    TotalDevicesAccessed = dcount(DestinationDeviceName), // Count unique destination devices accessed
    AccessedDevices = make_set(DestinationDeviceName), // List of destination devices accessed
    ActionTypesPerformed = make_set(ActionType), // List of unique action types
    ProtocolsUsed = make_set(Protocol), // List of protocols used
    IPAddressesInvolved = make_set(IPAddress), // List of unique IP addresses
    TargetDevices = make_set(TargetDeviceName), // List of target devices
    TotalActivities = count() // Total number of suspicious activities
    by bin(TimeGenerated, 1h), AccountName // Group by hourly bins and account
| project 
    TimeGenerated, // Include formatted timestamp
    AccountName, // Compromised account
    TotalDevicesAccessed, // Number of devices accessed
    AccessedDevices, // List of accessed devices
    ActionTypesPerformed, // List of actions performed
    ProtocolsUsed, // List of protocols used
    IPAddressesInvolved, // List of IP addresses
    TargetDevices, // List of target devices
    TotalActivities // Count of total activities
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

Description: Use the SecurityEvent table to Identify all suspicious activities from the compromised accounts

{% code overflow="wrap" %}
```kusto
// Define the list of accounts to monitor
let MonitoredAccounts = dynamic(["User1", "User2", "User3"]); // Add the list of accounts
let ExcludedEventIDs = dynamic([8002, 4634]); // Add excluded Event IDs
// Query to filter security events
SecurityEvent
| where Account in (MonitoredAccounts) // Use dynamic list for account matching
| where EventID !in (ExcludedEventIDs) // Exclude unwanted Event IDs
| project 
    TimeGenerated, // Include timestamp
    Account, // Include account name
    Computer, // Include computer name
    EventID, // Include event ID
    Activity, // Include activity description
    CommandLine, // Include command-line details
    FileHash, // Include file hash
    FilePath, // Include file path
    Process, // Include process information
    WorkstationName, // Include workstation name
    EventData // Include additional event data
| order by TimeGenerated desc, Account asc // Sort by most recent events and account name
```
{% endcode %}

### <mark style="color:blue;">Identify Failed Login Attempts From Users</mark>

{% code overflow="wrap" %}
```kusto
// Define search parameters
let SearchWindow = 30d; // Customizable time window
let TargetAccount = "UserName"; // Replace with the compromised username
// Query to analyze failed login attempts for a specific user
SecurityEvent
| where TimeGenerated >= ago(SearchWindow) // Filter events based on the search window
| where EventID == 4625 // Focus on failed login attempts
| where AccountType == "User" // Include only user accounts
| where Account contains TargetAccount // Filter for the specific username
| project 
    TimeGenerated, // Event timestamp
    Account, // Account name
    Computer, // Computer name
    FailureReason, // Reason for login failure
    IpAddress, // IP address of the source
    LogonProcessName, // Logon process used
    LogonTypeName, // Logon type description
    ProcessName // Name of the process involved
| order by TimeGenerated desc // Sort by most recent events
```
{% endcode %}

**Use Case:** This query is ideal for monitoring failed login attempts in cloud environments where Azure AD is the authentication provider. It provides detailed insights into failed attempts, aiding in detecting brute force attacks or identifying suspicious login activity. Let me know if you need further adjustments! Failed login attempts for one or multiple user accounts from the SigninLogs table

{% code overflow="wrap" %}
```kusto
// Define search parameters
let SearchWindow = 48h; // Customizable time window
let TargetAccounts = dynamic(["user1@exampledomain.com", "user2@exampledomain.com"]); // Replace with one or more user accounts
// Query to identify failed login attempts for specified accounts
SigninLogs
| where TimeGenerated >= ago(SearchWindow) // Filter based on the search window
| where UserPrincipalName in (TargetAccounts) // Filter for specific user accounts
| where ResultType != "0" // Filter for failed sign-ins (ResultType "0" indicates success)
| extend 
    FailureReason = tostring(Status.errorCode), // Extract failure reason
    AppName = tostring(AppDisplayName), // Extract application name
    IPAddress = tostring(IPAddress), // Extract source IP address
    Device = tostring(DeviceDetail.operatingSystem), // Extract device OS
    Browser = tostring(DeviceDetail.browser), // Extract browser details
    Location = tostring(LocationDetails.state), // Extract location details (state-level)
    RiskLevel = tostring(RiskDetail), // Extract user risk level
    ConditionalAccessStatus = tostring(ConditionalAccessStatus), // Extract conditional access status
    MFARequired = tostring(AuthenticationRequirement), // Check if MFA was required
    CorrelationId = tostring(CorrelationId) // Extract correlation ID for tracing related events
| project 
    TimeGenerated, // Event timestamp
    UserPrincipalName, // User attempting the login
    FailureReason, // Reason for failure
    IPAddress, // IP address of the source
    Location, // Location of the sign-in
    Device, // Device OS
    Browser, // Browser details
    AppName, // Application being accessed
    RiskLevel, // User risk level
    ConditionalAccessStatus, // Conditional access policies status
    MFARequired, // Was MFA required
    CorrelationId, // Correlation ID
    ResultDescription // Description of the result
| summarize 
    FailedAttempts = count(), // Count of failed attempts
    SourceIPAddresses = make_set(IPAddress), // Unique IP addresses
    Devices = make_set(Device), // Unique devices
    Browsers = make_set(Browser), // Unique browsers
    FailureReasons = make_set(FailureReason), // Unique failure reasons
    RiskLevels = make_set(RiskLevel), // Unique risk levels
    ConditionalAccessOutcomes = make_set(ConditionalAccessStatus), // Conditional access outcomes
    MFAStatuses = make_set(MFARequired) // MFA statuses
    by UserPrincipalName, bin(TimeGenerated, 1h) // Group by user and hourly bins
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

A query using the IdentityLogonEvents table to identify failed login attempts with additional insights for investigation:&#x20;

**Use Case:** This query is useful for identifying failed login attempts, understanding their context (e.g., IPs, devices, failure reasons), and detecting anomalies like brute force attacks or misconfigurations. It provides detailed and actionable information for investigation and remediation.

{% code overflow="wrap" %}
```kusto
// Define search parameters
let SearchWindow = 48d; // Set the time window for the query to the last 48 days
let TargetAccounts = dynamic(["user1", "user2"]); // Specify the list of accounts to monitor for failed logins
// Query to identify failed login attempts for specified accounts
IdentityLogonEvents
| where Timestamp >= ago(SearchWindow) // Filter events within the defined time window
| where AccountName in (TargetAccounts) // Filter events for specific target accounts
| where ActionType == "LogonFailed" // Focus only on failed logon attempts
| extend 
    FailureReason = tostring(FailureReason), // Extract the reason for the logon failure
    LogonType = tostring(LogonType), // Extract the type of logon (e.g., interactive, remote)
    IPAddress = tostring(IPAddress), // Extract the source IP address of the logon attempt
    Computer = tostring(DeviceName), // Extract the computer or device name where the event occurred
    SourceSystem = tostring(SourceSystem), // Extract the source system of the event (e.g., Windows, Azure AD)
    Location = tostring(Location), // Extract the geographic location of the login attempt
    DeviceName = tostring(DeviceName), // Extract the name of the device involved in the login attempt
    DestinationDeviceName = tostring(DestinationDeviceName), // Extract the destination device name (if applicable)
    DestinationIPAddress = tostring(DestinationIPAddress), // Extract the destination IP address (if applicable)
    TargetDeviceName = tostring(TargetDeviceName), // Extract the name of the target device
    Protocol = tostring(Protocol) // Extract the protocol used during the logon attempt
| project 
    Timestamp, // Include the timestamp of the event
    AccountName, // Include the user account that attempted the login
    DeviceName, // Include the name of the device involved in the login attempt
    DestinationDeviceName, // Include the name of the destination device
    DestinationIPAddress, // Include the IP address of the destination device
    TargetDeviceName, // Include the name of the target device
    Protocol, // Include the protocol used during the logon attempt
    FailureReason, // Include the reason for the logon failure
    IPAddress, // Include the source IP address of the login attempt
    Computer, // Include the name of the computer or device where the event occurred
    LogonType, // Include the type of logon (e.g., interactive, remote)
    SourceSystem, // Include the source system of the event
    Location, // Include the geographic location of the login attempt
    AdditionalFields // Include any additional event details
| summarize 
    FailedAttempts = count(), // Count the total number of failed login attempts
    DeviceNames = make_set(DeviceName), // Aggregate unique device names involved in the events
    DestinationDeviceNames = make_set(DestinationDeviceName), // Aggregate unique destination device names
    DestinationIPAddresses = make_set(DestinationIPAddress), // Aggregate unique destination IP addresses
    TargetDeviceNames = make_set(TargetDeviceName), // Aggregate unique target device names
    Protocols = make_set(Protocol), // Aggregate unique protocols used during the logon attempts
    SourceIPAddresses = make_set(IPAddress), // Aggregate unique source IP addresses
    Computers = make_set(Computer), // Aggregate unique computers or devices where events occurred
    FailureReasons = make_set(FailureReason), // Aggregate unique reasons for the logon failures
    LogonTypes = make_set(LogonType), // Aggregate unique logon types
    Locations = make_set(Location) // Aggregate unique geographic locations
    by AccountName, bin(Timestamp, 1h) // Group results by account and hourly time bins
| order by Timestamp desc // Sort the results by the most recent events
```
{% endcode %}

### <mark style="color:blue;">Lateral Movement By Compromised Accounts</mark>

**Use Case:** This query is tailored for detecting lateral movement by compromised accounts in your environment. By monitoring logon activity across devices, it helps identify patterns that could indicate attempts to expand access within the network.

{% code overflow="wrap" %}
```kusto
// Define search parameters
let SearchWindow = 48h; // Set the time window for the query
let CompromisedAccounts = dynamic(["user1", "user2"]); // Replace with known or suspected compromised accounts
// Query to detect lateral movement by compromised accounts
IdentityLogonEvents
| where Timestamp >= ago(SearchWindow) // Filter events within the defined time window
| where AccountName in (CompromisedAccounts) // Filter for specific compromised accounts
| where ActionType in ("LogonSuccess", "LogonFailed") // Focus on logon events (both success and failure)
| extend 
    SourceIPAddress = tostring(IPAddress), // Extract the source IP address
    TargetDevice = tostring(DeviceName), // Extract the name of the target device
    DestinationDeviceName = tostring(DestinationDeviceName), // Extract destination device name
    DestinationIPAddress = tostring(DestinationIPAddress), // Extract destination IP address
    LogonType = tostring(LogonType), // Extract the logon type (e.g., interactive, remote)
    FailureReason = iff(ActionType == "LogonFailed", tostring(FailureReason), "N/A"), // Failure reason for failed logons
    Protocol = tostring(Protocol), // Extract the protocol used during the logon
    SourceSystem = tostring(SourceSystem) // Extract the source system (e.g., Windows, Azure AD)
| project 
    Timestamp, // Event timestamp
    AccountName, // Account attempting the logon
    SourceIPAddress, // Source IP address of the logon
    TargetDevice, // Name of the target device
    DestinationDeviceName, // Destination device name
    DestinationIPAddress, // Destination IP address
    LogonType, // Logon type (e.g., remote, interactive)
    Protocol, // Protocol used during the logon attempt
    SourceSystem, // Source system of the logon event
    FailureReason // Reason for logon failure (if applicable)
| summarize 
    TotalLogonAttempts = count(), // Total number of logon attempts
    TargetDevices = make_set(TargetDevice), // List of unique target devices
    DestinationDevices = make_set(DestinationDeviceName), // List of unique destination devices
    SourceIPAddresses = make_set(SourceIPAddress), // List of unique source IP addresses
    DestinationIPAddresses = make_set(DestinationIPAddress), // List of unique destination IP addresses
    LogonTypes = make_set(LogonType), // List of unique logon types
    Protocols = make_set(Protocol), // List of unique protocols used
    FailureReasons = make_set(FailureReason) // List of failure reasons (for failed attempts)
    by AccountName, bin(Timestamp, 1h) // Group by account and hourly time bins
| order by Timestamp desc // Sort by the most recent events
```
{% endcode %}

### <mark style="color:blue;">User Added To Sensitive Group</mark>

**Use Case:** This query provides a detailed audit of group membership changes involving sensitive groups, including the initiator of the change and the added user. It is particularly useful for identifying unauthorized or suspicious changes in group memberships. Let me know if further refinements are needed!

{% code overflow="wrap" %}
```kusto
// Define sensitive groups to monitor
let SensitiveGroups = dynamic(['Domain Admins', 'Enterprise Admins', 'Exchange Admins']); // Add sensitive groups to this list
// Query to identify membership changes in sensitive groups
IdentityDirectoryEvents
| where Timestamp >= ago(30d) // Filter events within the last 30 days
| where ActionType == "Group Membership changed" // Focus on group membership change actions
| extend ParsedFields = parse_json(AdditionalFields) // Parse AdditionalFields once for efficiency
| extend 
    Group = tostring(ParsedFields['TO.GROUP']), // Extract the target group
    AddedUser = tostring(ParsedFields['TO.ACCOUNT']), // Extract the user added to the group
    InitiatorAccount = tostring(ParsedFields['ACTOR.ACCOUNT']) // Extract the account that initiated the change
| where isnotempty(Group) and Group in (SensitiveGroups) // Ensure the group is not empty and matches sensitive groups
| project 
    Timestamp, // Include the timestamp of the event
    Group, // The sensitive group whose membership was changed
    AddedUser, // The user added to the sensitive group
    InitiatorAccount, // Account used to initiate the group addition
    ActionType, // Action type for context
    AdditionalFields // Include all additional fields for further context if needed
| order by Timestamp desc // Sort results by the most recent changes
```
{% endcode %}

### <mark style="color:blue;">Anomalous Group Policy Discovery</mark>

**Use Case:** This query is ideal for detecting: Unauthorised enumeration of Group Policies. Suspicious activity from new or unexpected devices, accounts, or IP addresses. Potential reconnaissance or pre-attack activity.

{% code overflow="wrap" %}
```kusto
// Define thresholds for anomaly detection
let HighFrequencyThreshold = 10; // Define a threshold for high-frequency queries
let LookbackPeriod = 7d; // Period to analyze regular activity
let RecentPeriod = 1d; // Recent period for detecting anomalies
// Identify normal activity for Group Policy discovery in the lookback period
let NormalActivity = materialize(
    IdentityQueryEvents
    | where TimeGenerated >= ago(LookbackPeriod) // Analyze activity over the lookback period
    | where QueryType == "AllGroupPolicies" // Focus on Group Policy discovery
    | summarize 
        Devices = make_set(DeviceName), // Collect devices performing regular queries
        Accounts = make_set(AccountName), // Collect accounts performing regular queries
        IPAddresses = make_set(IPAddress) // Collect IPs performing regular queries
);
// Detect recent anomalous Group Policy discovery
IdentityQueryEvents
| where TimeGenerated >= ago(RecentPeriod) // Focus on recent activity
| where QueryType == "AllGroupPolicies" // Focus on Group Policy discovery
| summarize 
    QueryCount = count(), // Count the number of queries
    Devices = make_set(DeviceName), // List unique devices
    Accounts = make_set(AccountName), // List unique accounts
    IPAddresses = make_set(IPAddress) // List unique IPs
    by bin(TimeGenerated, 1h), DeviceName, AccountName, IPAddress // Group by time and source details
| extend IsHighFrequency = QueryCount > HighFrequencyThreshold // Detect high-frequency querying
| project 
    TimeGenerated, // Event time
    DeviceName, // Device performing the query
    AccountName, // Account performing the query
    IPAddress, // IP performing the query
    QueryCount, // Number of queries
    IsHighFrequency // Flag for high-frequency queries
| order by TimeGenerated desc // Sort by the most recent events
```
{% endcode %}

### <mark style="color:blue;">SMB File Copy</mark>

**Use Case:** This query detects SMB file copy events that are initiated by suspect accounts. It helps identify unauthorised file transfers, providing relevant details for further investigation.

{% code overflow="wrap" %}
```kusto
// Define suspect accounts
let CompromisedAccounts = dynamic(['account1', 'account2']); // Add suspect accounts here
// Query to detect unauthorized SMB file copy events
IdentityDirectoryEvents
| where ActionType == "SMB file copy" // Filter only SMB file copy events
| where AccountName in (CompromisedAccounts) // include events initiated by suspect accounts
| extend 
    SMBFileCopyCount = toint(parse_json(AdditionalFields).Count), // Extract and convert SMB file copy count
    FilePath = tostring(parse_json(AdditionalFields).FilePath), // Extract file path
    FileName = tostring(parse_json(AdditionalFields).FileName) // Extract file name
| project 
    Timestamp, // Event timestamp
    ActionType, // Action type for context
    SourceDeviceName = DeviceName, // Rename DeviceName to SourceDeviceName
    DestinationDeviceName, // Destination device name
    FilePath, // File path of the copied file
    FileName, // File name of the copied file
    SMBFileCopyCount, // Number of files copied
    AccountName // Accout name 
| order by Timestamp desc // Sort results by the most recent events
```
{% endcode %}

### <mark style="color:blue;">Identify Suspicious SMB Activity</mark>

{% code overflow="wrap" %}
```kusto
// Query to detect shared folder access with specific permissions
SecurityEvent
| where TimeGenerated >= ago(61d) // Filter for events in the last day
| where EventID == 5140 // Focus on "A network share object was accessed" events
| where AccessMask in ("0x120089", "0x13019f", "0x1301bf", "0x1401bf", "0x1411ff") // Filter specific access levels
| summarize EventCount = count() // Count occurrences of each unique combination
    by Computer, AccountName, ShareName, ShareLocalPath
| order by EventCount desc // Sort by the highest number of events
```
{% endcode %}
