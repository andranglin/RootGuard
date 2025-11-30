# Detect When Large Number of Files Downloaded From OneDrive or SharePoint

### Description of the Query:

This KQL query is designed to detect a large number of files downloaded from **OneDrive** or **SharePoint** within a specific time frame. Attackers often abuse cloud storage services like OneDrive and SharePoint to exfiltrate sensitive data by downloading large numbers of files in a short period. This behaviour can indicate data theft, unauthorised access, or insider threats.

The query identifies events where users download multiple files from OneDrive or SharePoint. It leverages logs from Microsoft 365 (e.g., `OfficeActivity` or `CloudAppEvents`) to track file download activities. By analysing the volume of downloads per user within a given time window, security teams can identify suspicious patterns indicative of data exfiltration.

### KQL Query:

{% code overflow="wrap" %}
```kusto
let start_time = ago(1d);
let threshold = 50; // Adjust this threshold based on your environment's normal activity
let highVolumeDownloads = 
    OfficeActivity
    | where TimeGenerated >= start_time
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileSyncDownloadedPartial")
    | where UserType == "Regular"
    | summarize 
        FileCount = count(), 
        UniqueFiles = dcount(OfficeId) 
    by UserId, UserAgent, SourceFileName, 
       bin(TimeGenerated, 1h), 
       SourceRelativeUrl
    | extend Site_ = iff(isnotempty(SourceRelativeUrl), 
                          case(
                              SourceRelativeUrl contains "/personal/", "OneDrive",
                              SourceRelativeUrl contains "/sites/", "SharePoint",
                              "Unknown"
                          ), 
                          "Unknown")
    | where FileCount > threshold
    | project TimeGenerated, UserId, UserAgent, Site_, SourceFileName, FileCount, UniqueFiles;
highVolumeDownloads
```
{% endcode %}

### Explanation of the Query:

1. **Filtering File Download Events** :
   * The query starts by filtering for `FileDownloaded` events (`Operation == "FileDownloaded"`) within the last 24 hours (`TimeGenerated > ago(1d)`).
2. **Focusing on OneDrive and SharePoint** :
   * It specifically looks for events where the `Source` field contains `"OneDrive"` or `"SharePoint"`. This ensures that only downloads from these cloud storage services are analyzed.
3. **Extracting Username** :
   * The `User` field is extracted from the `UserId` field by splitting it at the `@` symbol. This provides the username for contextual analysis.
4. **Summarizing Download Activity** :
   * The query aggregates the following metrics for each user and client IP address:
     * `TotalDownloads`: The total number of file download events.
     * `UniqueFilesDownloaded`: The number of unique files downloaded (using `ObjectId` as the identifier).
     * `FirstDownloadTime`: The timestamp of the first download event.
     * `LastDownloadTime`: The timestamp of the most recent download event.
5. **Flagging Suspicious Activity** :
   * The query flags users who meet either of the following thresholds:
     * `TotalDownloads > 100`: More than 100 file download events.
     * `UniqueFilesDownloaded > 50`: More than 50 unique files downloaded.
   * These thresholds can be adjusted based on your organization's typical usage patterns.
6. **Projecting Relevant Columns** :
   * The query projects relevant fields such as:
     * `TimeGenerated`: The timestamp of the most recent download event.
     * `User`: The username associated with the activity.
     * `ClientIP`: The IP address of the device used for the downloads.
     * `TotalDownloads`: The total number of file download events.
     * `UniqueFilesDownloaded`: The number of unique files downloaded.
     * `FirstDownloadTime` and `LastDownloadTime`: The time range of the download activity.
     * `IsHighVolume`: Indicates whether the activity exceeds the high-volume threshold.
7. **Sorting Results** :
   * The results are sorted by `TotalDownloads` in descending order to prioritize users with the highest download volumes.

#### Use Case:

This query is particularly useful for detecting:

* **Data Exfiltration**: Attackers or insiders downloading large numbers of files to steal sensitive data.
* **Insider Threats**: Employees downloading excessive amounts of data, potentially for malicious purposes.
* **Compromised Accounts**: Stolen credentials being used to download files en masse.

Security teams can use this query in Microsoft Sentinel or other SIEM platforms to monitor for suspicious download activity and investigate potential data exfiltration.

### Notes:

* **False Positives**: Legitimate administrative tasks or bulk downloads by authorized users may trigger this query. Analysts should review the results to differentiate between benign and malicious activity.
* **Customization**: The thresholds (`TotalDownloads > 100`, `UniqueFilesDownloaded > 50`) can be adjusted based on the organization's environment and typical usage patterns.
* **Performance**: To optimize performance, consider narrowing the time range or filtering by specific users or IP addresses if needed.
