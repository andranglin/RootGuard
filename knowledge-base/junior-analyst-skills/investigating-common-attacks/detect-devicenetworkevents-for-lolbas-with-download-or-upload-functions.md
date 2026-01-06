# Detect DeviceNetworkEvents for LOLBAS with Download or Upload Functions

### Description of the Query:

This KQL query is designed to detect **DeviceNetworkEvents** originating from **Living Off the Land Binaries and Scripts (LOLBAS)** that have download or upload capabilities. LOLBAS refers to legitimate tools or binaries present on a system that attackers can misuse for malicious purposes, such as downloading payloads, exfiltrating data, or communicating with command-and-control (C2) servers.

The query focuses on identifying network activity (`DeviceNetworkEvents`) initiated by known LOLBAS tools capable of performing download or upload operations. Examples include `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `powershell.exe`, and others. By correlating these events with network activity, security teams can identify potential misuse of these tools for malicious purposes.

### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect DeviceNetworkEvents from LOLBAS with Download or Upload Functions
DeviceNetworkEvents
| where Timestamp > ago(1d) // Limit results to the last 24 hours
| where InitiatingProcessFileName  has_any (
    "certutil.exe", 
    "bitsadmin.exe", 
    "mshta.exe", 
    "powershell.exe", 
    "cmd.exe", 
    "cscript.exe", 
    "wscript.exe", 
    "curl.exe", 
    "wget.exe", 
    "ftp.exe"
) // Filter for known LOLBAS tools with download/upload capabilities
| extend UserName = tostring(split(InitiatingProcessAccountName, @"\")[1]) // Extract username for context
| extend IsDownloadOrUpload = iff(InitiatingProcessCommandLine has_any ("download", "upload", "http", "https", "ftp"), true, false)
| where IsDownloadOrUpload == true // Focus on events involving download or upload activity
| project
    Timestamp,
    DeviceName,
    UserName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    LocalIP,
    LocalPort,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

### Explanation of the Query:

1. **Filtering Network Events** :
   * The query starts by filtering for `DeviceNetworkEvents` within the last 24 hours (`Timestamp > ago(1d)`).
2. **Identifying LOLBAS Tools** :
   * It specifically looks for network events initiated by known LOLBAS tools that are commonly abused for download or upload activities:
     * `certutil.exe`: Often used to download files by encoding/decoding base64 content.
     * `bitsadmin.exe`: Used to download files in the background.
     * `mshta.exe`: Executes scripts or downloads files via HTTP/HTTPS.
     * `powershell.exe`: Executes commands or scripts, including downloading files.
     * `cmd.exe`, `cscript.exe`, `wscript.exe`: Execute scripts or commands that may involve network activity.
     * `curl.exe`, `wget.exe`, `ftp.exe`: Tools explicitly designed for downloading or uploading files.
3. **Detecting Download/Upload Activity** :
   * The query checks if the `InitiatingProcessCommandLine` contains keywords such as `download`, `upload`, `http`, `https`, or `ftp`. These keywords indicate that the tool was likely used for network-based file transfers.
4. **Extracting Contextual Information** :
   * The `UserName` is extracted from the `InitiatingProcessAccountName` to provide additional context about the user account under which the activity occurred.
   * The `IsDownloadOrUpload` flag is set to `true` if the process command line matches the criteria for download or upload activity.
5. **Projecting Relevant Columns** :
   * The query projects relevant fields such as:
     * `Timestamp`: When the event occurred.
     * `DeviceName`: The name of the device where the network activity originated.
     * `UserName`: The user account associated with the activity.
     * `InitiatingProcessName`: The name of the LOLBAS tool initiating the network activity.
     * `InitiatingProcessCommandLine`: The command line used to launch the tool.
     * `RemoteIP`, `RemotePort`, `LocalIP`, `LocalPort`: Details about the network connection.
     * `SentBytes`, `ReceivedBytes`: Amount of data transferred during the session.
     * `ActionType`: The type of network action (e.g., connection, data transfer).
6. **Sorting Results** :
   * The results are sorted by `Timestamp` in descending order to show the most recent events first.

### Use Case:

This query is particularly useful for detecting:

* **Malware Downloads**: Attackers using LOLBAS tools to download malicious payloads from remote servers.
* **Data Exfiltration**: Legitimate tools being misused to upload sensitive data to external servers.
* **Command-and-Control (C2)**: LOLBAS tools communicating with C2 servers for further instructions.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious network activity involving LOLBAS tools and investigate potential threats.

### Notes:

* **False Positives**: Legitimate administrative tasks may also use these tools for legitimate purposes. Analysts should review the results to differentiate between benign and malicious activity.
* **Customisation**: The list of LOLBAS tools can be expanded based on the organisation's environment and known attack vectors.
* **Performance**: To optimise performance, consider narrowing the time range or filtering by specific devices/users if needed.<br>
