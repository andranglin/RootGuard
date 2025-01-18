---
description: Queries created in KQL and SPL
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

# Authentication From Suspicious DeviceName

### KQL Queries

Using KQL (Kusto Query Language) query to identify suspicious authentication attempts originating from unusual or suspicious workstation names. This query assumes you're working with Azure Monitor, Sentinel, or a similar platform that supports KQL and logs such as **SecurityEvent**, **SigninLogs**, or other authentication-related logs.

{% tabs %}
{% tab title="SecurityEvent" %}
Using KQL (Kusto Query Language) query to identify suspicious authentication attempts originating from unusual or suspicious workstation names. This query assumes you're working with Azure Monitor, Sentinel, or a similar platform that supports KQL and logs such as **SecurityEvent**, **SigninLogs**, or other authentication-related logs.

{% code overflow="wrap" %}
```kusto
// Define a list of known suspicious workstation patterns
let SuspiciousWorkstations = dynamic(["UNKNOWN", "TEMP", "WORKSTATION-", "DESKTOP-"]);
// Query authentication logs
SecurityEvent
| where EventID in (4624, 4625)  // Filter for logon success (4624) or failure (4625) events
| extend WorkstationName = iff(isnotempty(Workstation), Workstation, Computer) // Extract workstation/computer name
| where WorkstationName has_any (SuspiciousWorkstations) 
      or WorkstationName matches regex @"^(TEMP|DESKTOP|UNKNOWN|WORKSTATION-).*$"  // Match dynamic list or regex patterns
| summarize
    LogonAttempts = count(),
    UniqueUserCount = dcount(TargetUserName),
    FailedAttempts = countif(EventID == 4625)
    by WorkstationName, TargetUserName, LogonType, bin(TimeGenerated, 1h)
| extend LogonTypeDescription = case(
    LogonType == 2, "Interactive",
    LogonType == 3, "Network",
    LogonType == 10, "Remote Interactive",
    LogonType == 7, "Unlock",
    LogonType == 5, "Service",
    LogonType == 4, "Batch",
    "Unknown"
)
| order by LogonAttempts desc
| project TimeGenerated, WorkstationName, TargetUserName, LogonTypeDescription, LogonAttempts, FailedAttempts, UniqueUserCount
```
{% endcode %}

Key Details:

1. **Dynamic List of Suspicious Names**: Adjust `SuspiciousWorkstations` to include prefixes, patterns, or specific workstation names you consider suspicious.
2. **Event IDs**: Targets Windows Security Event IDs for logon success (`4624`) and failure (`4625`).
3. **Regex Matching**: Matches patterns using a regex for flexible detection of workstation naming conventions.
4. **Summarization**: Group data by workstation name, user, and logon type for better analysis and filtering.
5. **Logon Type Mapping**: Provides a human-readable description of the logon type for better context.

**Results:**

* **WorkstationName**: The suspicious workstation name.
* **TargetUserName**: User attempting to log in.
* **LogonTypeDescription**: Describes how the logon was attempted (e.g., Interactive, Network, Remote Interactive).
* **LogonAttempts**: Total authentication attempts.
* **FailedAttempts**: Count of failed logon attempts.

You may have to tweak the query to include additional suspicious patterns or integrate it with threat intelligence feeds for enhanced correlation.&#x20;
{% endtab %}

{% tab title="DeviceLogonEvents" %}
To discover authentication events originating from suspicious workstation names using the `DeviceLogonEvents` table in Microsoft Sentinel or another Log Analytics environment:

{% code overflow="wrap" %}
```kusto
// Define a list of suspicious workstation patterns
let SuspiciousWorkstations = dynamic(["UNKNOWN", "TEMP", "WORKSTATION-", "DESKTOP-"]);
// Query DeviceLogonEvents table
DeviceLogonEvents
| extend WorkstationName = iff(isnotempty(DeviceName), DeviceName,
AccountName) // Normalize workstation/computer name
| where WorkstationName has_any (SuspiciousWorkstations) 
      or WorkstationName matches regex @"^(TEMP|DESKTOP|UNKNOWN|WORKSTATION-).*$"  // Match dynamic list or regex patterns
| summarize
    LogonAttempts = count(),
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulAttempts = countif(ActionType == "LogonSuccess"),
    UniqueUserCount = dcount(AccountName)
    by WorkstationName, AccountName, LogonType, bin(Timestamp, 1h)
| extend LogonTypeDescription = case(
    LogonType == "Interactive", "Interactive",
    LogonType == "Network", "Network",
    LogonType == "RemoteInteractive", "Remote Interactive",
    LogonType == "Service", "Service",
    LogonType == "Batch", "Batch",
    LogonType == "Unlock", "Unlock",
    "Unknown"
)
| order by LogonAttempts desc
| project Timestamp, WorkstationName, AccountName, LogonTypeDescription, LogonAttempts, SuccessfulAttempts, FailedAttempts, UniqueUserCount
```
{% endcode %}

#### Explanation of the Query:

1. **Suspicious Patterns**:
   * `SuspiciousWorkstations`defines known suspicious naming patterns (e.g., `TEMP`, `UNKNOWN`, etc.).
   * Includes `has_any` for quick matching and regex for flexible pattern detection.
2. **Table and Fields**:
   * The `DeviceLogonEvents`table is queried.
   * Extracts workstation or device names using `DeviceName` or `AccountName`
3. **Filters**:
   * Filters records with workstation names matching the suspicious patterns.
4. **Aggregation**:
   * Groups result by workstation name, account name, and logon type.
   * Summarises total logon attempts, failed attempts, successful attempts, and unique user count.
5. **Logon Type Mapping**:
   * Maps the `LogonType` to descriptive text for better interpretation.
6. **Output**:
   * Results are sorted by the number of logon attempts and projected to show:
     * Timestamp, WorkstationName, AccountName, LogonTypeDescription, TotalAttempts, SuccessfulAttempts, FailedAttempts, and UniqueUserCount.

#### Customisation:

* **Additional Filters**: Add conditions for specific user accounts, logon times, or suspicious IPs if required.
* **Time Binning**: Adjust `bin(Timestamp, 1h)` to a different interval (e.g., 5 minutes or daily).
* **Threat Intelligence Integration**: Correlate workstation names with known threat actor tools or tactics.
{% endtab %}

{% tab title="IdentityLogonEvents" %}
Using KQL query to discover authentication attempts from suspicious workstation names using the `IdentityLogonEvents` table in Microsoft Sentinel or Log Analytics:

{% code overflow="wrap" %}
```kusto
// Define a list of suspicious workstation patterns
let SuspiciousWorkstations = dynamic(["UNKNOWN", "TEMP", "WORKSTATION-", "DESKTOP-"]);
// Query IdentityLogonEvents table
IdentityLogonEvents
| extend WorkstationName = iff(isnotempty(DeviceName), DeviceName, TargetDeviceName) // Normalize workstation/device field
| where WorkstationName has_any (SuspiciousWorkstations)
      or WorkstationName matches regex @"^(TEMP|DESKTOP|UNKNOWN|WORKSTATION-).*$"  // Match patterns or dynamic list
| summarize
    TotalAttempts = count(),
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulAttempts = countif(ActionType == "LogonSuccess"),
    UniqueUsers = dcount(AccountDisplayName)
    by WorkstationName, AccountDisplayName, LogonType, bin(Timestamp, 1h)
| extend LogonTypeDescription = case(
    LogonType == "Interactive", "Interactive",
    LogonType == "RemoteInteractive", "Remote Interactive",
    LogonType == "Network", "Network",
    LogonType == "Batch", "Batch",
    LogonType == "Service", "Service",
    "Unknown"
)
| order by TotalAttempts desc
| project Timestamp, WorkstationName, AccountDisplayName, LogonTypeDescription, TotalAttempts, SuccessfulAttempts, FailedAttempts, UniqueUsers
```
{% endcode %}

#### Key Features of the Query:

1. **Suspicious Patterns**:
   * `SuspiciousWorkstations`includes known suspicious naming conventions (e.g., `TEMP`, `WORKSTATION-`).
   * Matches using `has_any` and `regex` for flexible detection.
2. **Field Normalisation**:
   * Uses `DeviceName` or `TargetDeviceName` to extract workstation or device information.
3. **Logon Event Filtering**:
   * Focuses on logon events where the workstation name matches suspicious patterns.
4. **Aggregation**:
   * Summarises:
     * `TotalAttempts`: Total logon attempts.
     * `FailedAttempts`: Count of failed logon attempts.
     * `SuccessfulAttempts`: Count of successful logon attempts.
     * `UniqueUsers`: Count of distinct users attempting logons.
5. **Logon Type Mapping**:
   * Converts raw `LogonType` values into meaningful descriptions.
6. **Results**:
   * Sorted by total attempts and includes:
     * `Timestamp`, `WorkstationName`, `AccountDisplayName`, `LogonTypeDescription`, `TotalAttempts`, `SuccessfulAttempts`, `FailedAttempts`, and `UniqueUsers`.

#### Customisation Options:

* **Time Filtering**: Add `| where Timestamp between (startTime .. endTime)` to restrict the timeframe.
* **Additional Filters**: Add filters for specific user accounts, IP addresses, or logon statuses.
* **Suspicious Patterns**: Update `SuspiciousWorkstations` to include organisation-specific patterns or known attacker conventions.
{% endtab %}

{% tab title="SigninLogs" %}
Using KQL query to discover authentication attempts from suspicious workstation names using the `SigninLogs` table in Microsoft Sentinel or Azure Log Analytics:

{% code overflow="wrap" %}
```kusto
// Define a list of suspicious workstation patterns
let SuspiciousWorkstations = dynamic(["UNKNOWN", "TEMP", "WORKSTATION-", "DESKTOP-"]);
// Query SigninLogs table
SigninLogs
| extend WorkstationName = iff(isnotempty(DeviceDetail.deviceDisplayName), tostring(DeviceDetail.deviceDisplayName), tostring(DeviceDetail.operatingSystem)) // Extract and cast to string
| where WorkstationName has_any (SuspiciousWorkstations)
      or WorkstationName matches regex @"^(TEMP|DESKTOP|UNKNOWN|WORKSTATION-).*$"  // Match dynamic list or regex patterns
| summarize
    TotalAttempts = count(),
    FailedAttempts = countif(ResultType != "0"), // Non-zero ResultType indicates failure
    SuccessfulAttempts = countif(ResultType == "0"),
    UniqueUsers = dcount(UserPrincipalName)
    by tostring(WorkstationName), UserPrincipalName, AppDisplayName, bin(TimeGenerated, 1h)
| order by TotalAttempts desc
| project TimeGenerated, WorkstationName, UserPrincipalName, AppDisplayName, TotalAttempts, SuccessfulAttempts, FailedAttempts, UniqueUsers
```
{% endcode %}

#### Explanation:

1. **Suspicious Patterns**:
   * `SuspiciousWorkstations` Defines workstation name patterns commonly linked to suspicious activity.
   * Uses `has_any` for a quick match and `regex` for flexible pattern matching.
2. **Field Normalisation**:
   * Extracts workstation name from `DeviceDetail.deviceDisplayName` or falls back to `DeviceDetail.operatingSystem` if empty.
3. **Logon Results**:
   * `ResultType == "0"` Indicates successful logons.
   * Any other `ResultType` is treated as a failure.
4. **Aggregation**:
   * Groups by `WorkstationName`, `UserPrincipalName`, and `AppDisplayName`.
   * Summarizes:
     * `TotalAttempts`: Total authentication attempts.
     * `FailedAttempts`: Count of failed logons.
     * `SuccessfulAttempts`: Count of successful logons.
     * `UniqueUsers`: Count of distinct users.
5. **Time Binning**:
   * Bins results into 1-hour intervals using `bin(TimeGenerated, 1h)`.
6. **Results**:
   * Sorted by `TotalAttempts`and displays:
     * `TimeGenerated`, `WorkstationName`, `UserPrincipalName`, `AppDisplayName`, `TotalAttempts`, `SuccessfulAttempts`, `FailedAttempts`, and `UniqueUsers`.

#### Customisation:

* **Patterns**: Update `SuspiciousWorkstations` to include organisation-specific suspicious workstation naming conventions.
* **Time Range**: Add a time filter using `| where TimeGenerated between (datetime(YYYY-MM-DD HH:MM:SS) .. datetime(YYYY-MM-DD HH:MM:SS))`.
* **Additional Fields**: Extend with other fields from `SigninLogs` for more context, such as IP addresses or location data.
{% endtab %}
{% endtabs %}

### Splunk Query:

{% tabs %}
{% tab title="Wineventlog" %}
Using Splunk query to discover authentication events originating from suspicious workstation names. This query assumes you're using Windows Event Logs (`index=wineventlog`) or a similar data source for authentication events.

Note: The fields in your Splunk logs may differ slightly; for example, AccountName may be displayed as Account\_Name.

{% code overflow="wrap" %}
```kusto
index=wineventlog EventCode IN (4624, 4625) 
| eval WorkstationName=coalesce(Workstation, ComputerName)  // Normalize workstation field names
| search WorkstationName IN ("TEMP*", "DESKTOP-*", "UNKNOWN", "WORKSTATION-*")  // Match known suspicious patterns
| eval Suspicious = if(match(WorkstationName, "^(TEMP|DESKTOP|UNKNOWN|WORKSTATION-).*$"), "Yes", "No")
| stats count AS TotalAttempts, 
        count(eval(EventCode=4625)) AS FailedAttempts, 
        dc(UserName) AS UniqueUsers 
        by WorkstationName, UserName, LogonType, Suspicious
| eval LogonTypeDescription=case(
        LogonType=="2", "Interactive",
        LogonType=="3", "Network",
        LogonType=="10", "Remote Interactive",
        LogonType=="7", "Unlock",
        LogonType=="5", "Service",
        LogonType=="4", "Batch",
        true(), "Unknown"
    )
| where Suspicious="Yes" 
| sort - TotalAttempts
| table WorkstationName, UserName, LogonTypeDescription, TotalAttempts, FailedAttempts, UniqueUsers
```
{% endcode %}

#### Key Details:

1. **EventCode Filtering**:
   * `4624`: Logon success.
   * `4625`: Logon failure.
2. **Normalization**:
   * Uses `coalesce()` to handle scenarios where either `Workstation` or `ComputerName` maybe populated.
3. **Suspicious Workstation Patterns**:
   * Matches common suspicious workstation naming conventions like `TEMP*`, `DESKTOP-*`, `UNKNOWN`, or `WORKSTATION-*`.
   * Regex patterns used in `match()` provide flexibility.
4. **Stats Aggregation**:
   * Aggregates data to summarise:
     * `TotalAttempts`: Total authentication attempts.
     * `FailedAttempts`: Failed login attempts.
     * `UniqueUsers`: Unique users attempting to log in from suspicious workstations.
5. **Logon Type Description**:
   * Maps `LogonType` values to human-readable descriptions for better context.
6. **Filtering and Sorting**:
   * Displays results only for suspicious workstations (`where Suspicious="Yes"`).
   * Sorts results by the highest number of total attempts.
7. **Output**:
   * Displays key fields like `WorkstationName`, `UserName`, `LogonTypeDescription`, and summarised stats.

#### Customisation:

* **Suspicious Patterns**: Adjust the `search` clause or `match()` function to include additional patterns or specific workstation names based on your organisation's threat models.
* **Additional Fields**: Extend the query with fields like `SourceIP` or `DestinationIP` for more in-depth analysis.
* **Enrichment**: Integrate with threat intelligence feeds to correlate suspicious workstation names or IPs.
{% endtab %}

{% tab title="Authlogs" %}
Detecting authentication events from suspicious workstation names, assuming the use of a custom authentication-related index (e.g., `index=authlogs`) and avoiding `wineventlog`. This query works with generic authentication data sources.

Note: The fields in your Splunk logs may differ slightly; for example, AccountName may be displayed as Account\_Name.

{% code overflow="wrap" %}
```splunk-spl
index=authlogs sourcetype=authentication 
| eval WorkstationName=coalesce(device_name, host_name, client_hostname)  // Normalize workstation name field
| search WorkstationName IN ("TEMP*", "DESKTOP-*", "UNKNOWN*", "WORKSTATION-*")  // Match suspicious patterns
| eval Suspicious=if(match(WorkstationName, "^(TEMP|DESKTOP|UNKNOWN|WORKSTATION-).*"), "Yes", "No")
| stats count AS TotalAttempts, 
        count(eval(status="failure")) AS FailedAttempts, 
        count(eval(status="success")) AS SuccessfulAttempts, 
        dc(user) AS UniqueUsers 
        by WorkstationName, user, logon_type, Suspicious
| eval LogonTypeDescription=case(
        logon_type=="interactive", "Interactive",
        logon_type=="network", "Network",
        logon_type=="remote", "Remote Interactive",
        logon_type=="service", "Service",
        logon_type=="batch", "Batch",
        true(), "Unknown"
    )
| where Suspicious="Yes"
| sort - TotalAttempts
| table WorkstationName, user, LogonTypeDescription, TotalAttempts, SuccessfulAttempts, FailedAttempts, UniqueUsers
```
{% endcode %}

#### Key Details:

1. **Custom Index and Sourcetype**:
   * Replace `index=authlogs` and `sourcetype=authentication` with your specific index and sourcetype for authentication data.
2. **Normalisation**:
   * Uses `coalesce()` to extract workstation names from possible fields (`device_name`, `host_name`, or `client_hostname`).
3. **Suspicious Patterns**:
   * Matches workstation names using both the `IN` clause for patterns and a regex (`match()` function).
4. **Stats Aggregation**:
   * Aggregates data to summarise:
     * `TotalAttempts`: Total logon attempts.
     * `FailedAttempts`: Failed logon attempts.
     * `SuccessfulAttempts`: Successful logon attempts.
     * `UniqueUsers`: Count of distinct users involved.
5. **Logon Type Mapping**:
   * Converts `logon_type` into human-readable descriptions.
6. **Filtering and Sorting**:
   * Filters suspicious workstation names with `where Suspicious="Yes"`.
   * Sorts results by the number of total attempts.
7. **Output**:
   * Presents key fields: `WorkstationName`, `user`, `LogonTypeDescription`, `TotalAttempts`, `SuccessfulAttempts`, `FailedAttempts`, and `UniqueUsers`.

#### Customisation:

* **Field Names**: Update field names to match your specific dataset (e.g., `device_name`, `status`, `user`, etc.).
* **Patterns**: Adjust workstation name patterns based on your environment or known threat actor behaviour.
* **Time Filtering**: Add `earliest` and `latest` time filters for specific date ranges, e.g., `earliest=-24h`.
{% endtab %}
{% endtabs %}
