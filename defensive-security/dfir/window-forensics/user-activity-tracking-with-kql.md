# User Activity Tracking with KQL

### Microsoft Sentinel & Defender XDR - SOC Analyst Playbook

***

### 🎯 Overview

This playbook provides KQL queries and investigation workflows for account usage analysis across:

* **Microsoft Sentinel** (Azure Sentinel)
* **Microsoft Defender XDR** (Defender for Endpoint, Identity, Cloud Apps)
* **Azure Active Directory (Entra ID)**
* **Windows Security Events**

***

### 📊 Data Sources Quick Reference

#### Available Tables

| Table Name                          | Source                  | Description                     | Retention       |
| ----------------------------------- | ----------------------- | ------------------------------- | --------------- |
| **SecurityEvent**                   | Windows Events          | Security.evtx via Log Analytics | 90 days default |
| **IdentityLogonEvents**             | Defender for Identity   | Domain authentication           | 30 days         |
| **DeviceLogonEvents**               | Defender for Endpoint   | Local logons                    | 30 days         |
| **DeviceEvents**                    | Defender for Endpoint   | General device activity         | 30 days         |
| **SigninLogs**                      | Azure AD/Entra ID       | Cloud authentication            | 30 days         |
| **AADNonInteractiveUserSignInLogs** | Azure AD                | Service principal/app auth      | 30 days         |
| **AuditLogs**                       | Azure AD                | Account changes                 | 30 days         |
| **IdentityDirectoryEvents**         | Defender for Identity   | AD changes                      | 30 days         |
| **CloudAppEvents**                  | Defender for Cloud Apps | SaaS activity                   | 30 days         |
| **BehaviorAnalytics**               | Sentinel UEBA           | User behavior anomalies         | 14 days         |
| **OfficeActivity**                  | Office 365              | Exchange/SharePoint/Teams       | 90 days         |

#### Event ID to Table Mapping

| Windows Event ID        | Sentinel Table | Defender XDR Table  |
| ----------------------- | -------------- | ------------------- |
| 4624 (Logon)            | SecurityEvent  | DeviceLogonEvents   |
| 4625 (Failed Logon)     | SecurityEvent  | DeviceLogonEvents   |
| 4648 (Explicit Creds)   | SecurityEvent  | DeviceEvents        |
| 4672 (Admin Logon)      | SecurityEvent  | DeviceLogonEvents   |
| 4776 (NTLM Auth)        | SecurityEvent  | IdentityLogonEvents |
| 4768 (Kerberos TGT)     | SecurityEvent  | IdentityLogonEvents |
| 4769 (Kerberos Service) | SecurityEvent  | IdentityLogonEvents |
| 4771 (Kerberos Failed)  | SecurityEvent  | IdentityLogonEvents |

***

### 🔍 Phase 1: Initial Triage Queries

#### 1.1 Quick Account Profile (Sentinel)

```kql
// Get comprehensive account overview
let TargetAccount = "john.doe@contoso.com"; // or "DOMAIN\\username"
let TimeRange = 7d;
// Check if account exists and get details
IdentityInfo
| where TimeGenerated > ago(TimeRange)
| where AccountUPN == TargetAccount or AccountName contains TargetAccount
| summarize 
    arg_max(TimeGenerated, *),
    GroupMemberships = make_set(GroupMembership),
    Tags = make_set(Tags)
| project 
    AccountName,
    AccountUPN,
    AccountDomain,
    Department,
    JobTitle,
    Manager,
    IsAccountEnabled,
    GroupMemberships,
    Tags,
    LastSeen = TimeGenerated
```

#### 1.2 Quick Account Profile (Defender XDR)

```kql
// Get account activity summary
let TargetAccount = "john.doe";
let TimeRange = 7d;
DeviceLogonEvents
| where Timestamp > ago(TimeRange)
| where AccountName == TargetAccount
| summarize 
    TotalLogons = count(),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    FailedLogons = countif(ActionType == "LogonFailed"),
    UniqueDevices = dcount(DeviceName),
    UniqueIPs = dcount(RemoteIP),
    LogonTypes = make_set(LogonType),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
| extend FailureRate = round(FailedLogons * 100.0 / TotalLogons, 2)
```

#### 1.3 Is This Account Under Attack? (Quick Check)

{% code overflow="wrap" %}
```kql
// Rapid compromise indicators
let TargetAccount = "john.doe@contoso.com";
let TimeRange = 24h;
union 
    // Failed logons
    (SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4625
    | where TargetUserName contains TargetAccount
    | summarize FailedLogons = count() by IpAddress
    | where FailedLogons > 10
    | extend Indicator = "High Failed Logons", Severity = "High"),
    // Impossible travel
    (SigninLogs
    | where TimeGenerated > ago(TimeRange)
    | where UserPrincipalName == TargetAccount
    | where ResultType == "0"
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | order by TimeGenerated asc
    | serialize
    | extend PrevCountry = prev(Country), TimeDiff = datetime_diff('minute', TimeGenerated, prev(TimeGenerated))
    | where Country != PrevCountry and TimeDiff < 60
    | summarize ImpossibleTravel = count()
    | where ImpossibleTravel > 0
    | extend Indicator = "Impossible Travel", Severity = "Critical"),
    // Suspicious logon type changes
    (DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where AccountName contains TargetAccount
    | summarize LogonTypes = make_set(LogonType)
    | where array_length(LogonTypes) > 3
    | extend Indicator = "Multiple Logon Types", Severity = "Medium")
| project Indicator, Severity
```
{% endcode %}

***

### 🔐 Phase 2: Authentication Analysis

#### 2.1 Complete Authentication Timeline (Sentinel)

{% code overflow="wrap" %}
```kql
// Unified authentication timeline across all sources
let TargetAccount = "john.doe@contoso.com";
let TimeRange = 7d;
union 
    // Windows Security Events
    (SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID in (4624, 4625, 4648, 4672, 4776, 4768, 4769, 4771)
    | where TargetUserName contains TargetAccount or Account contains TargetAccount
    | extend 
        AuthType = case(
            EventID == 4624, "Successful Logon",
            EventID == 4625, "Failed Logon",
            EventID == 4648, "Explicit Credentials",
            EventID == 4672, "Admin Logon",
            EventID == 4776, "NTLM Auth",
            EventID == 4768, "Kerberos TGT",
            EventID == 4769, "Kerberos Service",
            EventID == 4771, "Kerberos Failed",
            "Other"
        ),
        LogonTypeName = case(
            LogonType == "2", "Interactive",
            LogonType == "3", "Network",
            LogonType == "4", "Batch",
            LogonType == "5", "Service",
            LogonType == "7", "Unlock",
            LogonType == "8", "NetworkCleartext",
            LogonType == "9", "NewCredentials",
            LogonType == "10", "RDP",
            LogonType == "11", "CachedInteractive",
            strcat("Type ", LogonType)
        )
    | project 
        TimeGenerated,
        Source = "WindowsEvent",
        AuthType,
        Status = case(EventID in (4625, 4771), "Failed", "Success"),
        Account = TargetUserName,
        Computer,
        IpAddress,
        LogonTypeName,
        EventID),
    // Azure AD Sign-ins
    (SigninLogs
    | where TimeGenerated > ago(TimeRange)
    | where UserPrincipalName == TargetAccount
    | extend 
        AuthType = "Azure AD Sign-in",
        Status = case(ResultType == "0", "Success", "Failed")
    | project 
        TimeGenerated,
        Source = "AzureAD",
        AuthType,
        Status,
        Account = UserPrincipalName,
        Computer = DeviceDetail.displayName,
        IpAddress = IPAddress,
        LogonTypeName = AppDisplayName,
        EventID = ResultType),
    // Defender for Identity
    (IdentityLogonEvents
    | where Timestamp > ago(TimeRange)
    | where AccountUpn == TargetAccount or AccountName contains TargetAccount
    | extend 
        AuthType = Protocol,
        Status = case(ActionType == "LogonSuccess", "Success", "Failed")
    | project 
        TimeGenerated = Timestamp,
        Source = "DefenderIdentity",
        AuthType,
        Status,
        Account = AccountName,
        Computer = DestinationDeviceName,
        IpAddress = IPAddress,
        LogonTypeName = LogonType,
        EventID = ActionType),
    // Defender for Endpoint
    (DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where AccountName contains TargetAccount
    | extend 
        AuthType = "Local Logon",
        Status = case(ActionType == "LogonSuccess", "Success", "Failed")
    | project 
        TimeGenerated = Timestamp,
        Source = "DefenderEndpoint",
        AuthType,
        Status,
        Account = AccountName,
        Computer = DeviceName,
        IpAddress = RemoteIP,
        LogonTypeName = LogonType,
        EventID = ActionType)
| order by TimeGenerated desc
| extend 
    Hour = hourofday(TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated)
```
{% endcode %}

#### 2.2 Failed Logon Analysis - Brute Force Detection

```kql
// Detect brute force and password spray attacks
let TimeRange = 24h;
let FailedThreshold = 10;
SecurityEvent
| where TimeGenerated > ago(TimeRange)
| where EventID == 4625 // Failed logons
| extend 
    FailureReason = case(
        Status == "0xC000006D", "Bad Username",
        Status == "0xC000006E", "Account Restriction",
        Status == "0xC000006F", "Time Restriction",
        Status == "0xC0000070", "Workstation Restriction",
        Status == "0xC0000071", "Password Expired",
        Status == "0xC0000072", "Account Disabled",
        Status == "0xC000006A", "Bad Password",
        Status == "0xC0000234", "Account Locked",
        Status == "0xC0000193", "Account Expired",
        Status == "0xC0000064", "Account Does Not Exist",
        Status
    )
| summarize 
    FailedAttempts = count(),
    TargetAccounts = make_set(TargetUserName),
    UniqueAccounts = dcount(TargetUserName),
    FailureReasons = make_set(FailureReason),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    Computers = make_set(Computer)
    by IpAddress
| where FailedAttempts >= FailedThreshold
| extend 
    Duration = datetime_diff('minute', EndTime, StartTime),
    AttackType = case(
        UniqueAccounts > 10 and FailedAttempts / UniqueAccounts < 5, "Password Spray",
        UniqueAccounts < 3 and FailedAttempts > 50, "Brute Force",
        "Suspicious Activity"
    ),
    Severity = case(
        FailedAttempts > 100, "Critical",
        FailedAttempts > 50, "High",
        "Medium"
    )
| order by FailedAttempts desc
| project 
    IpAddress,
    AttackType,
    Severity,
    FailedAttempts,
    UniqueAccounts,
    TargetAccounts,
    Duration,
    StartTime,
    EndTime,
    Computers,
    FailureReasons
```

#### 2.3 Successful Logon After Failed Attempts (Successful Breach)

{% code overflow="wrap" %}
```kql
// Find accounts where brute force succeeded
let TimeRange = 24h;
let FailedThreshold = 5;
let SuccessWindow = 30m;
let FailedLogons = SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4625
    | summarize 
        FailedCount = count(),
        LastFailed = max(TimeGenerated)
        by IpAddress, TargetUserName, Computer;
let SuccessfulLogons = SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4624
    | where LogonType in ("2", "3", "10") // Interactive, Network, RDP
    | project 
        SuccessTime = TimeGenerated,
        IpAddress,
        Account = TargetUserName,
        Computer,
        LogonType;
FailedLogons
| where FailedCount >= FailedThreshold
| join kind=inner (SuccessfulLogons) on IpAddress, $left.TargetUserName == $right.Account, Computer
| where datetime_diff('minute', SuccessTime, LastFailed) between (0 .. 30)
| project 
    Computer,
    Account,
    IpAddress,
    FailedAttempts = FailedCount,
    LastFailedAttempt = LastFailed,
    SuccessfulLogon = SuccessTime,
    TimeBetween = datetime_diff('minute', SuccessTime, LastFailed),
    LogonType,
    Severity = "Critical"
| order by SuccessfulLogon desc
```
{% endcode %}

#### 2.4 Logon Type Analysis (Sentinel)

```kql
// Analyze logon type distribution and anomalies
let TargetAccount = "john.doe";
let TimeRange = 30d;
let BaselinePeriod = 14d;
// Get baseline logon type distribution
let Baseline = SecurityEvent
    | where TimeGenerated between (ago(TimeRange) .. ago(BaselinePeriod))
    | where EventID == 4624
    | where TargetUserName contains TargetAccount
    | summarize BaselineCount = count() by LogonType
    | extend BaselinePercentage = round(100.0 * BaselineCount / toscalar(
        SecurityEvent
        | where TimeGenerated between (ago(TimeRange) .. ago(BaselinePeriod))
        | where EventID == 4624
        | where TargetUserName contains TargetAccount
        | summarize count()
    ), 2);
// Get recent logon type distribution
let Recent = SecurityEvent
    | where TimeGenerated > ago(BaselinePeriod)
    | where EventID == 4624
    | where TargetUserName contains TargetAccount
    | summarize RecentCount = count() by LogonType
    | extend RecentPercentage = round(100.0 * RecentCount / toscalar(
        SecurityEvent
        | where TimeGenerated > ago(BaselinePeriod)
        | where EventID == 4624
        | where TargetUserName contains TargetAccount
        | summarize count()
    ), 2);
// Compare and identify anomalies
Baseline
| join kind=fullouter (Recent) on LogonType
| extend 
    LogonType = coalesce(LogonType, LogonType1),
    LogonTypeName = case(
        LogonType == "2", "Interactive (Console)",
        LogonType == "3", "Network",
        LogonType == "4", "Batch",
        LogonType == "5", "Service",
        LogonType == "7", "Unlock/Reconnect",
        LogonType == "8", "NetworkCleartext",
        LogonType == "9", "NewCredentials (RunAs)",
        LogonType == "10", "Remote Desktop",
        LogonType == "11", "CachedInteractive",
        strcat("Type ", LogonType)
    ),
    BaselineCount = coalesce(BaselineCount, 0),
    RecentCount = coalesce(RecentCount, 0),
    BaselinePercentage = coalesce(BaselinePercentage, 0.0),
    RecentPercentage = coalesce(RecentPercentage, 0.0)
| extend 
    PercentageChange = round(RecentPercentage - BaselinePercentage, 2),
    IsAnomaly = case(
        BaselineCount == 0 and RecentCount > 0, "NEW",
        abs(RecentPercentage - BaselinePercentage) > 20, "ANOMALY",
        "NORMAL"
    )
| order by IsAnomaly desc, abs(PercentageChange) desc
| project 
    LogonType,
    LogonTypeName,
    BaselineCount,
    BaselinePercentage,
    RecentCount,
    RecentPercentage,
    PercentageChange,
    IsAnomaly
```

***

### 🗺️ Phase 3: Lateral Movement Detection

#### 3.1 Network Logon Chain Analysis (Defender XDR)

```kql
// Detect lateral movement patterns
let TimeRange = 24h;
let TargetAccount = "john.doe";
// Get all network logons
let NetworkLogons = DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where AccountName contains TargetAccount
    | where LogonType in ("Network", "RemoteInteractive")
    | where ActionType == "LogonSuccess"
    | project 
        Timestamp,
        SourceDevice = DeviceName,
        SourceIP = RemoteIP,
        Account = AccountName,
        LogonType
    | order by Timestamp asc;
// Detect pivot chains
NetworkLogons
| serialize
| extend 
    NextDevice = next(SourceDevice),
    NextTimestamp = next(Timestamp),
    TimeDelta = datetime_diff('second', next(Timestamp), Timestamp)
| where TimeDelta < 300 // Within 5 minutes
| where SourceDevice != NextDevice
| summarize 
    LateralMoveCount = count(),
    Path = make_list(strcat(SourceDevice, " -> ", NextDevice)),
    Timeline = make_list(Timestamp),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by Account
| where LateralMoveCount >= 2
| extend Severity = case(
    LateralMoveCount > 10, "Critical",
    LateralMoveCount > 5, "High",
    "Medium"
)
| order by LateralMoveCount desc
```

#### 3.2 Lateral Movement with Process Correlation

{% code overflow="wrap" %}
```kql
// Correlate logons with suspicious process execution
let TimeRange = 24h;
let SuspiciousProcesses = dynamic([
    "powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe", 
    "mmc.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
]);
// Get network logons
let Logons = DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where LogonType == "Network"
    | where ActionType == "LogonSuccess"
    | project LogonTime = Timestamp, DeviceName, AccountName, RemoteIP;
// Get process creations
let Processes = DeviceProcessEvents
    | where Timestamp > ago(TimeRange)
    | where FileName has_any (SuspiciousProcesses)
    | project ProcessTime = Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName;
// Correlate
Logons
| join kind=inner (Processes) on DeviceName, AccountName
| where datetime_diff('second', ProcessTime, LogonTime) between (0 .. 300)
| project 
    DeviceName,
    AccountName,
    RemoteIP,
    LogonTime,
    ProcessTime,
    TimeDelta = datetime_diff('second', ProcessTime, LogonTime),
    SuspiciousProcess = FileName,
    CommandLine = ProcessCommandLine
| order by LogonTime asc
```
{% endcode %}

#### 3.3 Administrative Reconnaissance Detection

```kql
// Detect admin enumeration and reconnaissance
let TimeRange = 24h;
let ReconCommands = dynamic([
    "net view", "net user", "net group", "net localgroup",
    "whoami", "ipconfig", "systeminfo", "tasklist",
    "net accounts", "net share", "net session"
]);
DeviceProcessEvents
| where Timestamp > ago(TimeRange)
| where ProcessCommandLine has_any (ReconCommands)
| summarize 
    ReconCommandCount = count(),
    Commands = make_set(ProcessCommandLine),
    Devices = make_set(DeviceName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountName
| where ReconCommandCount >= 3
| extend 
    Severity = case(
        ReconCommandCount > 10, "Critical",
        ReconCommandCount > 5, "High",
        "Medium"
    )
| order by ReconCommandCount desc
```

#### 3.4 Pass-the-Hash Detection (Sentinel)

{% code overflow="wrap" %}
```kql
// Detect potential pass-the-hash attacks
let TimeRange = 24h;
// Look for NTLM authentication without preceding local logon
let NTLMAuth = SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4776 // NTLM authentication
    | extend SourceComputer = Computer
    | project NTLMTime = TimeGenerated, TargetUserName, SourceComputer, Workstation;
let LocalLogons = SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4624
    | where LogonType == "2" // Interactive
    | project LogonTime = TimeGenerated, Account = TargetUserName, Computer;
// Find NTLM without recent local logon
NTLMAuth
| join kind=leftanti (
    LocalLogons 
    | where LogonTime > ago(24h)
) on $left.TargetUserName == $right.Account, $left.Workstation == $right.Computer
| summarize 
    SuspiciousNTLM = count(),
    Workstations = make_set(Workstation),
    SourceSystems = make_set(SourceComputer),
    Timeline = make_list(NTLMTime)
    by TargetUserName
| where SuspiciousNTLM >= 3
| extend Severity = "High"
| order by SuspiciousNTLM desc
```
{% endcode %}

***

### 🚨 Phase 4: Privilege Escalation & Admin Activity

#### 4.1 Detect New Admin Rights Assignments

{% code overflow="wrap" %}
```kql
// Monitor for admin rights granted
let TimeRange = 7d;
union
    // Windows Events - Admin logons
    (SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4672 // Special privileges assigned
    | where PrivilegeList contains "SeDebugPrivilege" or PrivilegeList contains "SeBackupPrivilege"
    | extend EventType = "SpecialPrivileges"
    | project TimeGenerated, Account = TargetUserName, Computer, EventType, PrivilegeList),
    // Azure AD - Role assignments
    (AuditLogs
    | where TimeGenerated > ago(TimeRange)
    | where OperationName in ("Add member to role", "Add eligible member to role")
    | extend Account = tostring(TargetResources[0].userPrincipalName)
    | extend Role = tostring(TargetResources[0].modifiedProperties[0].newValue)
    | extend EventType = "RoleAssignment"
    | project TimeGenerated, Account, EventType, Role),
    // Defender for Identity - Group membership changes
    (IdentityDirectoryEvents
    | where Timestamp > ago(TimeRange)
    | where ActionType == "Group Membership changed"
    | where DestinationDeviceName contains "Admin" or DestinationDeviceName contains "Domain"
    | extend EventType = "GroupMembership"
    | project TimeGenerated = Timestamp, Account = AccountName, EventType, Group = DestinationDeviceName)
| order by TimeGenerated desc
```
{% endcode %}

#### 4.2 Explicit Credential Usage (RunAs)

{% code overflow="wrap" %}
```kql
// Detect runas and explicit credential usage
let TimeRange = 7d;
let TargetAccount = ""; // Leave empty for all accounts
SecurityEvent
| where TimeGenerated > ago(TimeRange)
| where EventID == 4648 // Logon with explicit credentials
| where isempty(TargetAccount) or TargetUserName contains TargetAccount
| extend 
    SourceAccount = Account,
    TargetAccountUsed = TargetUserName,
    TargetServer = TargetServerName
| summarize 
    Count = count(),
    TargetServers = make_set(TargetServer),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceAccount, TargetAccountUsed, Computer
| where Count >= 3
| extend 
    Severity = case(
        TargetAccountUsed contains "admin" or TargetAccountUsed contains "svc", "High",
        Count > 10, "Medium",
        "Low"
    )
| order by Severity desc, Count desc
```
{% endcode %}

#### 4.3 Service Account Interactive Logon Detection

```kql
// Service accounts should never log on interactively
let ServiceAccounts = dynamic(["svc-", "service-", "sa-"]); // Adjust patterns
let TimeRange = 7d;
DeviceLogonEvents
| where Timestamp > ago(TimeRange)
| where LogonType in ("Interactive", "RemoteInteractive")
| where AccountName has_any (ServiceAccounts)
| summarize 
    InteractiveLogons = count(),
    Devices = make_set(DeviceName),
    IPs = make_set(RemoteIP),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountName
| extend Severity = "Critical"
| order by InteractiveLogons desc
```

***

### 🌍 Phase 5: Azure AD / Cloud Authentication Analysis

#### 5.1 Comprehensive Azure AD Sign-in Analysis

```kql
// Detailed Azure AD authentication analysis
let TargetAccount = "john.doe@contoso.com";
let TimeRange = 7d;
SigninLogs
| where TimeGenerated > ago(TimeRange)
| where UserPrincipalName == TargetAccount
| extend 
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    State = tostring(LocationDetails.state),
    Latitude = tostring(LocationDetails.geoCoordinates.latitude),
    Longitude = tostring(LocationDetails.geoCoordinates.longitude),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    DeviceBrowser = tostring(DeviceDetail.browser),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    TrustType = tostring(DeviceDetail.trustType),
    Status = case(ResultType == "0", "Success", "Failed"),
    FailureReason = case(
        ResultType == "50053", "Account Locked",
        ResultType == "50055", "Password Expired",
        ResultType == "50057", "Account Disabled",
        ResultType == "50126", "Invalid Credentials",
        ResultType == "50074", "Strong Auth Required",
        ResultType == "50076", "MFA Required",
        ResultType == "50079", "User needs to enroll MFA",
        ResultType == "50158", "External Security Challenge",
        ResultType == "53003", "Blocked by CA Policy",
        ResultType == "70008", "Session Expired",
        ResultDescription
    ),
    RiskLevel = tostring(RiskLevelDuringSignIn),
    RiskState = tostring(RiskState)
| project 
    TimeGenerated,
    UserPrincipalName,
    Status,
    FailureReason,
    AppDisplayName,
    IPAddress,
    Country,
    City,
    DeviceOS,
    DeviceBrowser,
    IsCompliant,
    IsManaged,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    RiskLevel,
    RiskState,
    MfaDetail = AuthenticationDetails
| order by TimeGenerated desc
```

#### 5.2 Impossible Travel Detection

{% code overflow="wrap" %}
```kql
// Detect impossible travel scenarios
let TargetAccount = "john.doe@contoso.com";
let TimeRange = 7d;
let MaxTravelSpeedKmH = 900; // ~airplane speed
SigninLogs
| where TimeGenerated > ago(TimeRange)
| where UserPrincipalName == TargetAccount
| where ResultType == "0" // Successful only
| extend 
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| where isnotnull(Latitude) and isnotnull(Longitude)
| order by TimeGenerated asc
| serialize
| extend 
    PrevLatitude = prev(Latitude),
    PrevLongitude = prev(Longitude),
    PrevCity = prev(City),
    PrevCountry = prev(Country),
    PrevTime = prev(TimeGenerated)
| where PrevLatitude != Latitude or PrevLongitude != Longitude
| extend 
    TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime),
    // Haversine formula for distance
    dLat = radians(Latitude - PrevLatitude),
    dLon = radians(Longitude - PrevLongitude),
    a = sin(dLat/2) * sin(dLat/2) + cos(radians(PrevLatitude)) * cos(radians(Latitude)) * sin(dLon/2) * sin(dLon/2),
    c = 2 * atan2(sqrt(a), sqrt(1-a)),
    DistanceKm = 6371 * c // Earth radius in km
| extend 
    RequiredSpeedKmH = round(DistanceKm / (TimeDiffMinutes / 60.0), 2)
| where RequiredSpeedKmH > MaxTravelSpeedKmH
| project 
    TimeGenerated,
    UserPrincipalName,
    PreviousLocation = strcat(PrevCity, ", ", PrevCountry),
    CurrentLocation = strcat(City, ", ", Country),
    DistanceKm = round(DistanceKm, 2),
    TimeDiffMinutes,
    RequiredSpeedKmH,
    PreviousIP = prev(IPAddress),
    CurrentIP = IPAddress,
    Severity = "Critical"
| order by TimeGenerated desc
```
{% endcode %}

#### 5.3 Anomalous Application Access

```kql
// Detect access to unusual applications
let TargetAccount = "john.doe@contoso.com";
let TimeRange = 30d;
let BaselinePeriod = 21d;
// Get baseline applications
let BaselineApps = SigninLogs
    | where TimeGenerated between (ago(TimeRange) .. ago(BaselinePeriod))
    | where UserPrincipalName == TargetAccount
    | where ResultType == "0"
    | summarize by AppDisplayName;
// Get recent applications
SigninLogs
| where TimeGenerated > ago(BaselinePeriod)
| where UserPrincipalName == TargetAccount
| where ResultType == "0"
| where AppDisplayName !in (BaselineApps)
| summarize 
    AccessCount = count(),
    IPAddresses = make_set(IPAddress),
    Locations = make_set(LocationDetails.countryOrRegion),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by AppDisplayName
| extend Severity = case(
    AppDisplayName contains "Admin" or AppDisplayName contains "Graph", "High",
    "Medium"
)
| order by FirstAccess desc
```

#### 5.4 Conditional Access Policy Failures

```kql
// Analyze Conditional Access policy blocks
let TimeRange = 7d;
SigninLogs
| where TimeGenerated > ago(TimeRange)
| where ConditionalAccessStatus == "failure"
| extend 
    PolicyDetails = parse_json(ConditionalAccessPolicies)
| mvexpand PolicyDetails
| extend 
    PolicyName = tostring(PolicyDetails.displayName),
    PolicyResult = tostring(PolicyDetails.result)
| where PolicyResult == "failure"
| summarize 
    BlockCount = count(),
    Users = make_set(UserPrincipalName),
    IPAddresses = make_set(IPAddress),
    Countries = make_set(LocationDetails.countryOrRegion),
    Applications = make_set(AppDisplayName)
    by PolicyName
| order by BlockCount desc
```

***

### 🎯 Phase 6: Behavioral Analytics (UEBA)

#### 6.1 User Risk Score Analysis

```kql
// Analyze user behavior anomalies
let TargetAccount = "john.doe@contoso.com";
let TimeRange = 7d;
BehaviorAnalytics
| where TimeGenerated > ago(TimeRange)
| where UserPrincipalName == TargetAccount or UserName contains TargetAccount
| extend 
    ActivityType = ActivityType,
    RiskScore = InvestigationPriority,
    AnomalyDetails = UsersInsights
| summarize 
    TotalAnomalies = count(),
    HighRiskEvents = countif(InvestigationPriority > 7),
    ActivityTypes = make_set(ActivityType),
    AnomalyReasons = make_set(UsersInsights),
    AvgRiskScore = avg(InvestigationPriority),
    MaxRiskScore = max(InvestigationPriority)
    by UserPrincipalName
| extend Severity = case(
    MaxRiskScore > 8, "Critical",
    MaxRiskScore > 5, "High",
    "Medium"
)
```

#### 6.2 Peer Group Comparison

```kql
// Compare user activity to peer group
let TargetAccount = "john.doe@contoso.com";
let TimeRange = 7d;
// Get target user's department/group
let UserDepartment = IdentityInfo
    | where AccountUPN == TargetAccount
    | summarize arg_max(TimeGenerated, Department)
    | project Department;
// Compare logon patterns
let TargetActivity = DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where AccountName contains TargetAccount
    | summarize TargetLogons = count();
let PeerActivity = IdentityInfo
    | where Department in (UserDepartment)
    | where AccountUPN != TargetAccount
    | join kind=inner (
        DeviceLogonEvents
        | where Timestamp > ago(TimeRange)
    ) on $left.AccountName == $right.AccountName
    | summarize PeerLogons = count() by AccountUPN
    | summarize AvgPeerLogons = avg(PeerLogons), StdDev = stdev(PeerLogons);
TargetActivity
| extend 
    AvgPeerLogons = toscalar(PeerActivity | project AvgPeerLogons),
    StdDev = toscalar(PeerActivity | project StdDev)
| extend 
    DeviationFromPeers = round((TargetLogons - AvgPeerLogons) / StdDev, 2),
    IsAnomaly = case(
        abs((TargetLogons - AvgPeerLogons) / StdDev) > 3, "Significant Anomaly",
        abs((TargetLogons - AvgPeerLogons) / StdDev) > 2, "Moderate Anomaly",
        "Normal"
    )
```

***

### 🔧 Phase 7: Advanced Hunting Techniques

#### 7.1 Multi-Stage Attack Detection

{% code overflow="wrap" %}
```kql
// Detect complete attack chain: Initial Access -> Lateral Movement -> Privilege Escalation
let TimeRange = 24h;
let Stage1_InitialAccess = DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where LogonType == "RemoteInteractive"
    | where ActionType == "LogonSuccess"
    | project 
        Stage = "Initial Access",
        Timestamp,
        DeviceName,
        AccountName,
        RemoteIP;
let Stage2_LateralMovement = DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where LogonType == "Network"
    | where ActionType == "LogonSuccess"
    | project 
        Stage = "Lateral Movement",
        Timestamp,
        DeviceName,
        AccountName,
        RemoteIP;
let Stage3_PrivilegeEscalation = SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4672
    | project 
        Stage = "Privilege Escalation",
        Timestamp = TimeGenerated,
        DeviceName = Computer,
        AccountName = TargetUserName,
        RemoteIP = IpAddress;
// Combine stages
union Stage1_InitialAccess, Stage2_LateralMovement, Stage3_PrivilegeEscalation
| order by AccountName, Timestamp asc
| serialize
| extend 
    NextStage = next(Stage),
    NextTimestamp = next(Timestamp),
    NextDevice = next(DeviceName)
| where AccountName == next(AccountName) // Same account
| extend TimeDelta = datetime_diff('minute', NextTimestamp, Timestamp)
| where TimeDelta < 60 // Within 1 hour
| summarize 
    AttackPath = make_list(Stage),
    Timeline = make_list(Timestamp),
    Devices = make_list(DeviceName),
    SourceIPs = make_set(RemoteIP)
    by AccountName
| where array_length(AttackPath) >= 2
| extend Severity = "Critical"
```
{% endcode %}

#### 7.2 Account Reconnaissance and Exploitation

{% code overflow="wrap" %}
```kql
// Detect recon followed by account compromise
let TimeRange = 48h;
// Stage 1: Reconnaissance
let Recon = DeviceProcessEvents
    | where Timestamp > ago(TimeRange)
    | where ProcessCommandLine has_any ("net user", "net group", "whoami", "net localgroup", "dsquery")
    | summarize 
        ReconCommands = make_set(ProcessCommandLine),
        ReconTime = min(Timestamp),
        ReconDevice = any(DeviceName)
        by InitiatingProcessAccountName;
// Stage 2: Account Usage
let AccountUsage = DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where ActionType == "LogonSuccess"
    | summarize 
        LogonTime = min(Timestamp),
        LogonDevice = any(DeviceName)
        by AccountName;
// Correlate
Recon
| join kind=inner (AccountUsage) on $left.InitiatingProcessAccountName == $right.AccountName
| where datetime_diff('hour', LogonTime, ReconTime) between (0 .. 24)
| project 
    AccountName,
    ReconDevice,
    ReconTime,
    ReconCommands,
    LogonDevice,
    LogonTime,
    TimeBetween = datetime_diff('hour', LogonTime, ReconTime),
    Severity = "High"
```
{% endcode %}

#### 7.3 Data Exfiltration via Compromised Account

```kql
// Detect unusual data access patterns
let TimeRange = 7d;
let BaselinePeriod = 21d;
let TargetAccount = "john.doe@contoso.com";
// Get baseline file access
let Baseline = OfficeActivity
    | where TimeGenerated between (ago(TimeRange + BaselinePeriod) .. ago(TimeRange))
    | where UserId == TargetAccount
    | where Operation in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull")
    | summarize BaselineCount = count();
// Get recent file access
let Recent = OfficeActivity
    | where TimeGenerated > ago(TimeRange)
    | where UserId == TargetAccount
    | where Operation in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull")
    | summarize 
        RecentCount = count(),
        Files = make_set(OfficeObjectId),
        Operations = make_set(Operation),
        UniqueFiles = dcount(OfficeObjectId)
    | extend BaselineCount = toscalar(Baseline);
Recent
| extend 
    PercentIncrease = round((RecentCount - BaselineCount) * 100.0 / BaselineCount, 2),
    IsAnomaly = case(
        RecentCount > BaselineCount * 3, "Critical",
        RecentCount > BaselineCount * 2, "High",
        "Normal"
    )
| where IsAnomaly != "Normal"
```

***

### 📊 Phase 8: Workbooks and Dashboards

#### 8.1 Account Usage Overview Dashboard (KQL for Workbook)

{% code overflow="wrap" %}
```kql
// Comprehensive account usage metrics
let TimeRange = 7d;
let TargetAccount = "john.doe@contoso.com";
// Logon success rate
let LogonMetrics = union
    (SecurityEvent | where TimeGenerated > ago(TimeRange) | where EventID in (4624, 4625)),
    (DeviceLogonEvents | where Timestamp > ago(TimeRange))
| where AccountName contains TargetAccount or TargetUserName contains TargetAccount
| summarize 
    TotalAttempts = count(),
    Successful = countif(EventID == 4624 or ActionType == "LogonSuccess"),
    Failed = countif(EventID == 4625 or ActionType == "LogonFailed")
| extend SuccessRate = round(Successful * 100.0 / TotalAttempts, 2);
// Geographic distribution
let GeoDistribution = SigninLogs
    | where TimeGenerated > ago(TimeRange)
    | where UserPrincipalName == TargetAccount
    | where ResultType == "0"
    | summarize Count = count() by Country = tostring(LocationDetails.countryOrRegion)
    | top 10 by Count;
// Device distribution
let DeviceDistribution = DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where AccountName contains TargetAccount
    | summarize Count = count() by DeviceName
    | top 10 by Count;
// Hourly activity pattern
let HourlyPattern = union
    (SecurityEvent | where TimeGenerated > ago(TimeRange) | where EventID == 4624),
    (DeviceLogonEvents | where Timestamp > ago(TimeRange) | where ActionType == "LogonSuccess")
| extend Hour = hourofday(coalesce(TimeGenerated, Timestamp))
| summarize Count = count() by Hour
| order by Hour asc;
// Combine all metrics
print Metrics = pack_all(
    LogonMetrics,
    GeoDistribution,
    DeviceDistribution,
    HourlyPattern
)
```
{% endcode %}

#### 8.2 Real-Time Monitoring Query

```kql
// Live monitoring of account activity
let MonitorAccounts = dynamic(["admin", "svc-", "da-"]); // High-value accounts
union
    (SecurityEvent
    | where TimeGenerated > ago(5m)
    | where EventID in (4624, 4625, 4648, 4672)
    | where TargetUserName has_any (MonitorAccounts)
    | extend Source = "SecurityEvent"),
    (DeviceLogonEvents
    | where Timestamp > ago(5m)
    | where AccountName has_any (MonitorAccounts)
    | extend Source = "DefenderEndpoint"),
    (SigninLogs
    | where TimeGenerated > ago(5m)
    | where UserPrincipalName has_any (MonitorAccounts)
    | extend Source = "AzureAD")
| order by coalesce(TimeGenerated, Timestamp) desc
| take 100
```

***

### 🚀 Phase 9: Automated Response Queries

#### 9.1 Automated Threat Hunting - Scheduled Query

```kql
// Run every 15 minutes to detect active compromises
let TimeRange = 15m;
let Threats = union
    // Brute force attempts
    (SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4625
    | summarize FailedAttempts = count() by IpAddress, TargetUserName
    | where FailedAttempts > 10
    | extend ThreatType = "Brute Force", Severity = "High"),
    // Impossible travel
    (SigninLogs
    | where TimeGenerated > ago(TimeRange)
    | where ResultType == "0"
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | order by UserPrincipalName, TimeGenerated asc
    | serialize
    | where UserPrincipalName == prev(UserPrincipalName)
    | where Country != prev(Country)
    | where datetime_diff('minute', TimeGenerated, prev(TimeGenerated)) < 60
    | extend ThreatType = "Impossible Travel", Severity = "Critical"),
    // Lateral movement
    (DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where LogonType == "Network"
    | summarize DeviceCount = dcount(DeviceName) by AccountName
    | where DeviceCount > 5
    | extend ThreatType = "Lateral Movement", Severity = "High"),
    // Privilege escalation
    (SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4672
    | where TargetUserName !endswith "$" // Exclude computer accounts
    | extend ThreatType = "Privilege Escalation", Severity = "High");
Threats
| summarize 
    ThreatCount = count(),
    Details = make_bag(pack_all())
    by ThreatType, Severity
| where ThreatCount > 0
```

#### 9.2 Incident Creation Query (For Automation Rules)

```kql
// Trigger incident when account compromise indicators detected
let TimeRange = 1h;
let CompromiseIndicators = union
    // Failed then successful
    (SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID in (4625, 4624)
    | where TargetUserName !endswith "$"
    | summarize 
        Failed = countif(EventID == 4625),
        Success = countif(EventID == 4624),
        IPs = make_set(IpAddress)
        by TargetUserName
    | where Failed > 10 and Success > 0
    | extend Indicator = "Brute Force Success"),
    // Service account interactive
    (DeviceLogonEvents
    | where Timestamp > ago(TimeRange)
    | where AccountName startswith "svc-" or AccountName startswith "service-"
    | where LogonType == "Interactive"
    | extend Indicator = "Service Account Interactive"),
    // Off-hours admin
    (SecurityEvent
    | where TimeGenerated > ago(TimeRange)
    | where EventID == 4672
    | extend Hour = hourofday(TimeGenerated)
    | where Hour < 6 or Hour > 20
    | extend Indicator = "Off-Hours Admin");
CompromiseIndicators
| summarize 
    Indicators = make_set(Indicator),
    Count = count()
| extend 
    Severity = case(Count >= 3, "High", "Medium"),
    Title = strcat("Account Compromise Detected - ", Count, " indicators"),
    Description = tostring(Indicators)
```

***

### 🎓 Pro Tips and Best Practices

#### Query Optimization

```kql
// ❌ SLOW - Filtering after query
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where TargetUserName == "john.doe"

// ✅ FAST - Use FilterHashtable approach
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4624 and TargetUserName == "john.doe"

// ✅ FASTER - Put most selective filter first
SecurityEvent
| where TargetUserName == "john.doe" // Most selective
| where TimeGenerated > ago(7d)
| where EventID == 4624
```

#### Time Range Best Practices

```kql
// ❌ Don't use absolute dates (not reusable)
| where TimeGenerated between (datetime(2025-11-29) .. datetime(2025-11-30))

// ✅ Use relative dates (reusable)
| where TimeGenerated > ago(1d)

// ✅ Use parameters for flexibility
let TimeRange = 7d;
| where TimeGenerated > ago(TimeRange)
```

#### Null Handling

```kql
// Always handle potential nulls
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotnull(Country) and Country != ""

// Use coalesce for fallbacks
| extend AccountName = coalesce(TargetUserName, AccountName, "Unknown")
```

#### Summarization Tips

```kql
// Use make_set for unique values (no duplicates)
| summarize IPs = make_set(IPAddress) by AccountName

// Use make_list for all values (with duplicates)
| summarize Commands = make_list(ProcessCommandLine) by AccountName

// Use make_bag for key-value pairs
| summarize Details = make_bag(pack("IP", IPAddress, "Time", TimeGenerated))
```

***

### 🔔 Alert Rules (Analytic Rules)

#### High-Priority Alert: Admin Account Brute Force Success

```kql
// Alert when brute force against admin succeeds
let TimeRange = 1h;
let FailedThreshold = 10;
let AdminAccounts = IdentityInfo
    | where GroupMembership has "Admin"
    | summarize by AccountName;
SecurityEvent
| where TimeGenerated > ago(TimeRange)
| where EventID in (4625, 4624)
| where TargetUserName in (AdminAccounts)
| summarize 
    Failed = countif(EventID == 4625),
    Success = countif(EventID == 4624),
    arg_max(TimeGenerated, *)
    by TargetUserName, IpAddress
| where Failed >= FailedThreshold and Success > 0
| extend 
    Severity = "High",
    Tactics = "CredentialAccess",
    Techniques = "T1110"
```

#### Alert: Impossible Travel Detected

{% code overflow="wrap" %}
```kql
// Alert on impossible travel (adjust for your org)
let TimeRange = 6h;
let MaxSpeedKmH = 900;
SigninLogs
| where TimeGenerated > ago(TimeRange)
| where ResultType == "0"
| extend 
    Lat = toreal(LocationDetails.geoCoordinates.latitude),
    Lon = toreal(LocationDetails.geoCoordinates.longitude)
| where isnotnull(Lat)
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend 
    PrevLat = prev(Lat),
    PrevLon = prev(Lon),
    PrevTime = prev(TimeGenerated),
    PrevIP = prev(IPAddress)
| where UserPrincipalName == prev(UserPrincipalName)
| extend 
    TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime),
    dLat = radians(Lat - PrevLat),
    dLon = radians(Lon - PrevLon),
    a = sin(dLat/2) * sin(dLat/2) + cos(radians(PrevLat)) * cos(radians(Lat)) * sin(dLon/2) * sin(dLon/2),
    Distance = 6371 * 2 * atan2(sqrt(a), sqrt(1-a)),
    RequiredSpeed = Distance / (TimeDiff / 60.0)
| where RequiredSpeed > MaxSpeedKmH
| project 
    TimeGenerated,
    UserPrincipalName,
    PreviousLocation = strcat(prev(LocationDetails.city), ", ", prev(LocationDetails.countryOrRegion)),
    CurrentLocation = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    DistanceKm = round(Distance, 2),
    TimeDiffMinutes = TimeDiff,
    RequiredSpeedKmH = round(RequiredSpeed, 2),
    PreviousIP = PrevIP,
    CurrentIP = IPAddress
| extend 
    Severity = "High",
    Tactics = "InitialAccess",
    Techniques = "T1078"
```
{% endcode %}

***

### 📚 Investigation Playbook Cheatsheet

#### Quick Investigation Steps

1. **Identify Account Type**

{% code overflow="wrap" %}
```kql
IdentityInfo | where AccountUPN == "user@domain.com" | project AccountName, AccountDomain, Department, Manager
```
{% endcode %}

2. **Get Recent Activity Summary**

```kql
union DeviceLogonEvents, SigninLogs
| where Timestamp > ago(7d) or TimeGenerated > ago(7d)
| where AccountName == "user" or UserPrincipalName == "user@domain.com"
| summarize count() by bin(coalesce(Timestamp, TimeGenerated), 1h)
| render timechart
```

3. **Check for Failed Logons**

```kql
SecurityEvent | where EventID == 4625 | where TargetUserName == "user"
| summarize count() by IpAddress | top 10 by count_
```

4. **Review Recent Admin Activity**

```kql
SecurityEvent | where EventID == 4672 | where TargetUserName == "user"
| where TimeGenerated > ago(24h)
```

5. **Check Lateral Movement**

```kql
DeviceLogonEvents
| where AccountName == "user"
| where LogonType == "Network"
| summarize DeviceCount = dcount(DeviceName), Devices = make_set(DeviceName)
```

***

### 🔗 Integration with SOAR

#### Logic App/Playbook Trigger Query

```kql
// Query for automated playbook execution
let Compromised = SecurityEvent
    | where TimeGenerated > ago(5m)
    | where EventID == 4625
    | summarize FailedCount = count() by TargetUserName, IpAddress
    | where FailedCount > 20;
Compromised
| extend 
    Action = "DisableAccount",
    Priority = "High",
    AssignedTo = "SOC-L2"
```

***

_Remember: Always validate queries in a test environment first. Adjust thresholds based on your organisation's baseline. Document all customisations._
