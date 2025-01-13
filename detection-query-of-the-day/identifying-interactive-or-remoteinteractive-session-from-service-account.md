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

# Identifying Interactive or RemoteInteractive Session From Service Account

### KQL Queries:

{% tabs %}
{% tab title="DeviceLogonEvents" %}
KQL query for discovering **Interactive** or **RemoteInteractive** logon sessions initiated by service accounts using the `DeviceLogonEvents`table in Microsoft Sentinel or Azure Log Analytics:

{% code overflow="wrap" %}
```kusto
// Define a list of known service account patterns (customize as needed)
let ServiceAccountPatterns = dynamic(["svc_", "service_", "sa_"]);
// Query DeviceLogonEvents for Interactive or RemoteInteractive logon types
DeviceLogonEvents
| where LogonType in ("Interactive", "RemoteInteractive", "CachedInteractive")  // Filter for desired logon types
| extend IsServiceAccount = iff(AccountName matches regex @"^(svc_|service_|sa_).*", true, false) // Identify service accounts
| where IsServiceAccount == true // Filter only service accounts
| summarize
    TotalLogons = count(),
    UniqueDevices = dcount(DeviceName),
    FailedAttempts = countif(ActionType == "LogonFailed"),
    SuccessfulLogons = countif(ActionType == "LogonSuccess")
    by AccountName, LogonType, bin(Timestamp, 1h)
| order by TotalLogons desc
| project Timestamp, AccountName, LogonType, TotalLogons, SuccessfulLogons, FailedAttempts, UniqueDevices
```
{% endcode %}

#### Key Details:

1. **Service Account Identification**:
   * `ServiceAccountPatterns`: A list of patterns that match typical service account naming conventions (e.g., `svc_`, `service_`, `sa_`).
   * Uses `matches regex` to check if the `AccountName` matches these patterns. Customise patterns to fit your organisation.
2. **Logon Type Filtering**:
   * Filters for `Interactive` and `RemoteInteractive` logon types, which are uncommon for service accounts.
3. **Logon Status**:
   * Separates successful and failed logon attempts using `countif(LogonType == "LogonSuccess")` and `countif(LogonType == "LogonFailed")`.
4. **Aggregation**:
   * Groups by `AccountName` and `LogonType` to summarise:
     * `TotalLogons`: Total logon attempts.
     * `SuccessfulLogons`: Number of successful logons.
     * `FailedAttempts`: Number of failed logon attempts.
     * `UniqueDevices`: Number of unique devices involved.
5. **Time Binning**:
   * Group results into 1-hour intervals using `bin(Timestamp, 1h)`.
6. **Results**:
   * Displays key fields, sorted by the number of total logon attempts:
     * `Timestamp`, `AccountName`, `LogonType`, `TotalLogons`, `SuccessfulLogons`, `FailedAttempts`, and `UniqueDevices`.

#### Customisation:

* **Service Account Patterns**:
  * Modify `ServiceAccountPatterns` to include all patterns used in your environment.
* **Time Range**:
  * Add a specific time filter, e.g., `| where Timestamp between (startTime .. endTime)`.

#### Use Case:

Identifies potential misuse of service accounts, as they should not typically perform interactive or remote interactive logons.&#x20;
{% endtab %}

{% tab title="IdentityLogonEvents" %}
KQL query for discovering **Interactive** or **RemoteInteractive** logon sessions initiated by service accounts using the `IdentityLogonEvents` table:

{% code overflow="wrap" %}
```kusto
// Define patterns to identify service accounts
let ServiceAccountPatterns = dynamic(["svc_", "service_", "sa_", "admin_"]);
// Query IdentityLogonEvents table
IdentityLogonEvents
| where LogonType in ("Interactive", "RemoteInteractive", "CachedInteractive")  // Filter for interactive session types
| extend IsServiceAccount = iff(AccountDisplayName matches regex @"^(svc_|service_|sa_|admin_).*", true, false) // Match service account patterns
| where IsServiceAccount == true // Retain only service accounts
| summarize
    TotalLogons = count(),
    SuccessfulLogons = countif(ActionType == "LogonSuccess"),
    FailedLogons = countif(ActionType == "LogonFailed"),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(AccountDisplayName)
    by AccountDisplayName, LogonType, bin(TimeGenerated, 1h)
| order by TotalLogons desc
| project TimeGenerated, AccountDisplayName, LogonType, TotalLogons, SuccessfulLogons, FailedLogons, UniqueDevices, UniqueUsers
```
{% endcode %}

#### Explanation:

1. **Service Account Patterns**:
   * `ServiceAccountPatterns`: A list of naming patterns to identify service accounts (e.g., `svc_`, `service_`, `sa_`, `admin_`).
   * Customise this list to match your organisation's service account naming conventions.
2. **Logon Type Filtering**:
   * Filters the `LogonType` field for `Interactive` and `RemoteInteractive` logon types.
3. **Service Account Identification**:
   * Uses `matches regex` to check if `AccountDisplayName` matches the patterns defined in `ServiceAccountPatterns`.
   * Adds a new field `IsServiceAccount` to flag service accounts.
4. **Logon Status**:
   * Separates successful and failed logon attempts:
     * `SuccessfulLogons`: LogonStatus = `Success`.
     * `FailedLogons`: LogonStatus = `Failure`.
5. **Aggregation**:
   * Groups results by `AccountDisplayName` (service account) and `LogonType`.
   * Summarises:
     * `TotalLogons`: Total number of logon attempts.
     * `SuccessfulLogons`: Count of successful logons.
     * `FailedLogons`: Count of failed logons.
     * `UniqueDevices`: Number of unique devices accessed.
     * `UniqueUsers`: Number of distinct users involved (if applicable).
6. **Time Binning**:
   * Group results into 1-hour intervals using `bin(TimeGenerated, 1h)`.
7. **Output**:
   * Displays key fields in the final output: `TimeGenerated`, `AccountDisplayName`, `LogonType`, `TotalLogons`, `SuccessfulLogons`, `FailedLogons`, `UniqueDevices`, and `UniqueUsers`.

#### Customisation:

* **Service Account Patterns**:
  * Add or modify patterns in `ServiceAccountPatterns` to reflect specific service account naming conventions.
* **Time Filtering**:
  * Add a filter to focus on specific time ranges, e.g., `| where TimeGenerated between (datetime(YYYY-MM-DD HH:MM:SS) .. datetime(YYYY-MM-DD HH:MM:SS))`.

This query identifies potential misuse of service accounts, which typically should not initiate interactive or remote interactive sessions.
{% endtab %}

{% tab title="SecurityEvent" %}
KQL query to discover **Interactive** or **RemoteInteractive** logon sessions initiated by service accounts using the `SecurityEvent` table:

{% code overflow="wrap" %}
```kusto
// Define patterns to identify service accounts
let ServiceAccountPatterns = dynamic(["svc_", "service_", "sa_", "admin_"]);
// Query SecurityEvent table for logon events
SecurityEvent
| where EventID == 4624 // Logon Success
| where LogonType in (2, 10) // Interactive (2) and RemoteInteractive (10) logon types
| extend IsServiceAccount = iff(AccountName matches regex @"^(svc_|service_|sa_|admin_).*", true, false) // Identify service accounts
| where IsServiceAccount == true // Filter for service accounts only
| summarize
    TotalLogons = count(),
    UniqueDevices = dcount(Computer),
    UniqueUsers = dcount(AccountName),
    FailedAttempts = countif(EventID == 4625) // Include failed logons if needed
    by AccountName, LogonType, bin(TimeGenerated, 1h)
| extend LogonTypeDescription = case(
    LogonType == 2, "Interactive",
    LogonType == 10, "Remote Interactive",
    "Unknown"
)
| order by TotalLogons desc
| project TimeGenerated, AccountName, LogonTypeDescription, TotalLogons, UniqueDevices, UniqueUsers
```
{% endcode %}

#### Explanation:

1. **Service Account Patterns**:
   * `ServiceAccountPatterns` contains naming patterns (e.g., `svc_`, `service_`, `sa_`, `admin_`) to identify service accounts. Customise as needed for your environment.
2. **Event ID Filtering**:
   * Filters for Event ID `4624` (logon success) and `4625` (logon failure if needed).
   * Focuses on `LogonType` values:
     * `2`: Interactive logon.
     * `10`: RemoteInteractive logon.
3. **Service Account Identification**:
   * Uses `matches regex` to flag accounts whose `AccountName` matches the defined patterns.
   * Adds a `IsServiceAccount` flag to identify service accounts.
4. **Aggregation**:
   * Groups data by `AccountName` and `LogonType`, summarising:
     * `TotalLogons`: Total number of successful logons.
     * `UniqueDevices`: Number of unique devices involved.
     * `UniqueUsers`: Number of distinct users associated with the logons.
     * `FailedAttempts`: Optionally includes failed attempts (Event ID `4625`).
5. **Logon Type Description**:
   * Converts numeric `LogonType` values into human-readable descriptions.
6. **Time Binning**:
   * Group data into 1-hour intervals using `bin(TimeGenerated, 1h)`.
7. **Output**:
   * Final results show key details: `TimeGenerated`, `AccountName`, `LogonTypeDescription`, `TotalLogons`, `UniqueDevices`, and `UniqueUsers`.

#### Customization:

* **Additional Filters**:
  * Add filters for specific domains, devices, or time ranges (e.g., `| where TimeGenerated between (datetime(YYYY-MM-DD HH:MM:SS) .. datetime(YYYY-MM-DD HH:MM:SS))`).
* **Alerting**:
  * Integrate this query with Azure Sentinel alerts to trigger notifications for suspicious service account usage.

This query detects potential misuse of service accounts for interactive or remote interactive logons, which are often anomalous behaviour.
{% endtab %}
{% endtabs %}

### Splunk Query

{% tabs %}
{% tab title="Wineventlog" %}
Splunk query to discover **Interactive** or **RemoteInteractive** logon sessions initiated by service accounts. This query works with Windows Security Event Logs or similar authentication-related data sources. Note: The fields in your Splunk logs may differ slightly; for example, AccountName may be displayed as Account\_Name.

{% code overflow="wrap" %}
```splunk-spl
index=wineventlog sourcetype=WinEventLog EventCode=4624 
| eval LogonTypeDescription=case(
    LogonType=="2", "Interactive",
    LogonType=="10", "Remote Interactive",
    true(), "Other"
) 
| search LogonType IN (2, 10)  // Filter for Interactive and Remote Interactive logon types
| eval IsServiceAccount=if(match(AccountName, "^(svc_|service_|sa_|admin_).*"), "Yes", "No")  // Identify service accounts
| search IsServiceAccount="Yes"  // Retain only service accounts
| stats count AS TotalLogons, 
        count(eval(LogonStatus="Failure")) AS FailedLogons, 
        count(eval(LogonStatus="Success")) AS SuccessfulLogons, 
        dc(dest) AS UniqueDevices, 
        dc(AccountName) AS UniqueAccounts 
        by AccountName, LogonTypeDescription
| sort - TotalLogons
| table AccountName, LogonTypeDescription, TotalLogons, SuccessfulLogons, FailedLogons, UniqueDevices, UniqueAccounts
```
{% endcode %}

#### Query Details:

1. **Event Code Filtering**:
   * `EventCode=4624`: Represents successful logon events.
   * If you want to include failed logons, use `EventCode=4625`.
2. **Logon Type Description**:
   * Maps numeric `LogonType` values:
     * `2`: Interactive logon.
     * `10`: RemoteInteractive logon.
3. **Service Account Identification**:
   * Uses `match()` to identify accounts matching service account naming conventions (`svc_`, `service_`, `sa_`, `admin_`). Modify as needed for your environment.
4. **Filtering for Service Accounts**:
   * Filters the results to only include logons initiated by service accounts (`IsServiceAccount="Yes"`).
5. **Statistics**:
   * Aggregates logon events to show:
     * `TotalLogons`: Total logon attempts.
     * `SuccessfulLogons`: Successful logons.
     * `FailedLogons`: Failed logons (if EventCode=4625 is included).
     * `UniqueDevices`: Unique destination devices.
     * `UniqueAccounts`: Count of distinct service accounts involved.
6. **Output**:
   * Displays the key details: `AccountName`, `LogonTypeDescription`, `TotalLogons`, `SuccessfulLogons`, `FailedLogons`, `UniqueDevices`, and `UniqueAccounts`.

#### Customisation:

* **Index and Sourcetype**:
  * Replace `index=your_index` and `sourcetype=your_sourcetype` with the appropriate values for your data source.
* **Service Account Patterns**:
  * Adjust the regex in `match()` to align with your organization's naming conventions.
* **Time Range**:
  * Add a time filter such as `earliest=-24h` or use the Splunk time picker.

This query identifies anomalous use of service accounts in interactive or remote sessions, helping detect potential misuse or compromise.
{% endtab %}

{% tab title="AuthLogs" %}
Splunk query to identify **Interactive** or **RemoteInteractive** logon sessions initiated by service accounts, assuming a non-`wineventlog` index and using authentication-related logs:

{% code overflow="wrap" %}
```splunk-spl
index=custom_auth_logs sourcetype=authentication_logs 
| eval LogonTypeDescription=case(
    logon_type=="2", "Interactive",
    logon_type=="10", "Remote Interactive",
    true(), "Other"
)
| search logon_type IN (2, 10)  // Filter for Interactive and Remote Interactive logon types
| eval IsServiceAccount=if(match(user, "^(svc_|service_|sa_|admin_).*"), "Yes", "No")  // Identify service accounts
| search IsServiceAccount="Yes"  // Retain only service accounts
| stats count AS TotalLogons, 
        count(eval(status="failure")) AS FailedLogons, 
        count(eval(status="success")) AS SuccessfulLogons, 
        dc(dest_host) AS UniqueDevices, 
        dc(user) AS UniqueServiceAccounts 
        by user, LogonTypeDescription
| sort - TotalLogons
| table user, LogonTypeDescription, TotalLogons, SuccessfulLogons, FailedLogons, UniqueDevices, UniqueServiceAccounts
```
{% endcode %}

#### Key Details:

1. **Auth\_Logs Index**:
   * Replace `index=custom_auth_logs` and `sourcetype=authentication_logs` with the appropriate index and sourcetype for your authentication logs.
   * This could be a custom log source like VPN, PAM, or third-party authentication solutions.
2. **Logon Type Mapping**:
   * Converts raw numeric `logon_type` values into human-readable descriptions:
     * `2`: Interactive logon.
     * `10`: Remote Interactive logon.
3. **Service Account Identification**:
   * Matches user accounts based on naming conventions such as `svc_`, `service_`, `sa_`, or `admin_`. Adjust these patterns based on your organization’s naming conventions.
4. **Filters**:
   * Focuses on logons initiated by service accounts (`IsServiceAccount="Yes"`) and specifically `Interactive` and `RemoteInteractive` sessions.
5. **Statistics**:
   * Aggregates results to show:
     * `TotalLogons`: Total logon attempts.
     * `SuccessfulLogons`: Count of successful logons.
     * `FailedLogons`: Count of failed logons.
     * `UniqueDevices`: Number of unique destination hosts involved.
     * `UniqueServiceAccounts`: Number of distinct service accounts.
6. **Output**:
   * Displays the key fields: `user` (service account), `LogonTypeDescription`, `TotalLogons`, `SuccessfulLogons`, `FailedLogons`, `UniqueDevices`, and `UniqueServiceAccounts`.

#### Customisation:

* **Adjust Index and Sourcetype**:
  * Modify `index` and `sourcetype` to match your environment’s log sources.
* **Additional Fields**:
  * Include fields like `src_ip`, `dest_ip`, or `geo_location` for more context if available.
* **Time Filters**:
  * Use `earliest=-24h` or `earliest` and `latest` for specific time ranges.

This query helps uncover suspicious or anomalous use of service accounts for interactive or remote interactive sessions, which are typically not standard behaviour.
{% endtab %}
{% endtabs %}
