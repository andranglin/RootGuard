# Detect Potential Cleartext Credentials in Commandline

### Description of the Query:

This KQL query is designed to detect **potential cleartext credentials in command-line arguments**. Attackers often use command-line tools to pass sensitive information, such as usernames and passwords, in plaintext. This can expose credentials to logging systems or unauthorised users, making it a significant security risk.

The query focuses on identifying process creation events (`ProcessCreate`) where the command line contains patterns indicative of cleartext credentials. These patterns include keywords like `password`, `pwd`, `username`, `user`, `pass`, and base64-encoded strings that may represent encoded credentials. By analysing these patterns, security teams can identify potential misuse of command-line tools for credential exposure.

### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect Potential Cleartext Credentials in Command Line
DeviceProcessEvents
| where Timestamp > ago(1d) // Limit results to the last 24 hours
| where ActionType == "ProcessCreate" // Focus on process creation events
| extend CommandLineLower = tolower(ProcessCommandLine) // Convert command line to lowercase for case-insensitive matching
| where CommandLineLower has_any (
    "password=", 
    "pwd=", 
    "username=", 
    "user=", 
    "pass=", 
    "credential=", 
    "-password", 
    "-pwd", 
    "-username", 
    "-user", 
    "-pass", 
    "-credential"
) // Look for common credential-related keywords
| extend Base64Pattern = extract(@"([A-Za-z0-9+/=]{20,})", 0, ProcessCommandLine) // Extract potential base64-encoded strings
| extend IsBase64Credential = iff(Base64Pattern != "", true, false) // Check if a base64 pattern was found
| where IsBase64Credential == true or CommandLineLower has_any ("password", "pwd", "username", "user", "pass", "credential")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    Base64Pattern,
    IsBase64Credential,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

### Explanation of the Query:

1. **Filtering Process Creation Events** :
   * The query starts by filtering for `ProcessCreate` events (`ActionType == "ProcessCreate"`) within the last 24 hours (`Timestamp > ago(1d)`).
2. **Converting Command Line to Lowercase** :
   * The `CommandLineLower` field is created by converting the `ProcessCommandLine` to lowercase using `tolower()`. This ensures case-insensitive matching for credential-related keywords.
3. **Detecting Credential Keywords** :
   * The query checks if the `CommandLineLower` contains common keywords associated with cleartext credentials:
     * `password=`, `pwd=`, `username=`, `user=`, `pass=`, `credential=`
     * `-password`, `-pwd`, `-username`, `-user`, `-pass`, `-credential`
   * These keywords are often used in command lines to pass credentials.
4. **Extracting Base64-Encoded Strings** :
   * The `extract` function is used to identify potential base64-encoded strings in the command line. The regex pattern `[A-Za-z0-9+/=]{20,}` matches sequences of characters that resemble base64 encoding.
   * The `Base64Pattern` field stores the extracted base64 string, if any.
5. **Flagging Base64 Credentials** :
   * The `IsBase64Credential` field is set to `true` if a base64 pattern is found in the command line.
6. **Filtering for Suspicious Activity** :
   * The query filters for events where either:
     * A base64-encoded string is detected (`IsBase64Credential == true`), or
     * The command line contains one of the credential-related keywords.
7. **Projecting Relevant Columns** :
   * The query projects relevant fields such as:
     * `Timestamp`: When the event occurred.
     * `DeviceName`: The name of the device where the process was created.
     * `InitiatingProcessAccountName`: The account name of the user who initiated the process.
     * `ProcessName`: The name of the process being created.
     * `ProcessCommandLine`: The full command line used to launch the process.
     * `Base64Pattern`: Any potential base64-encoded string found in the command line.
     * `IsBase64Credential`: Indicates whether a base64 pattern was detected.
     * `ActionType`: The type of action (e.g., `ProcessCreate`).
8. **Sorting Results** :
   * The results are sorted by `Timestamp` in descending order to show the most recent events first.

### Use Case:

This query is particularly useful for detecting:

* **Cleartext Passwords**: Attackers or users passing passwords in plaintext via command-line arguments.
* **Base64-Encoded Credentials**: Attackers encode credentials in base64 to obfuscate them.
* **Misconfigured Tools**: Legitimate tools configured to pass credentials insecurely.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious command-line activity and investigate potential credential exposure.

### Notes:

* **False Positives**: Legitimate administrative tasks may also include credentials in command lines. Analysts should review the results to differentiate between benign and malicious activity.
* **Customisation**: The list of credential-related keywords can be expanded based on the organisation's environment and known attack vectors.
* **Performance**: To optimise performance, consider narrowing the time range or filtering by specific devices/users if needed.

\


\
