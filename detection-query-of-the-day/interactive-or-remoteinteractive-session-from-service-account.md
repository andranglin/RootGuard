# Interactive or RemoteInteractive Session From Service Account

### <mark style="color:blue;">KQL Queries:</mark>

{% tabs %}
{% tab title="DeviceLogonEvents" %}
KQL query to discover **Interactive** or **RemoteInteractive** logon sessions initiated by service accounts using the `DeviceLogonEvents` table in Microsoft Sentinel or Azure Log Analytics:

{% code overflow="wrap" %}
```kusto
// Define a list of known service account patterns (customize as needed)
let ServiceAccountPatterns = dynamic(["svc_", "service_", "sa_"]);
// Query DeviceLogonEvents for Interactive or RemoteInteractive logon types
DeviceLogonEvents
| where LogonType in ("Interactive", "RemoteInteractive")  // Filter for desired logon types
| extend IsServiceAccount = iff(AccountName matches regex @"^(svc_|service_|sa_).*", true, false) // Identify service accounts
| where IsServiceAccount == true // Filter only service accounts
| summarize
    TotalLogons = count(),
    UniqueDevices = dcount(DeviceName),
    FailedAttempts = countif(LogonType == "LogonFailed"),
    SuccessfulLogons = countif(LogonType == "LogonSuccess")
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
   * Groups by `AccountName` and `LogonType` to summarize:
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

{% tab title="Second Tab" %}

{% endtab %}
{% endtabs %}







dd
