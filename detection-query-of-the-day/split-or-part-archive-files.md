# Split or Part Archive Files

{% tabs %}
{% tab title="DeviceFileEvents (Defender/Sentinel)" %}
Detecting split or part archive files in a dataset can be useful for identifying potential data exfiltration or malicious activity. The following is a KQL query that works with the DeviceFileEvents table in Microsoft Sentinel to discover split or part archive files based on naming patterns:

{% code overflow="wrap" %}
```kusto
// Define patterns for split or part archive file names
let SplitArchivePatterns = dynamic(["*.part*", "*.zip.*", "*.rar.*", "*.z*.*", "*.tar.*", "*.gz.*"]);
// Query the FileEvents table
DeviceFileEvents
| extend FileExtension = tolower(split(FileName, ".")[-1]) // Extract file extension
| where FileName matches regex @"(.*\.(part[0-9]+|zip\.[0-9]+|rar\.[0-9]+|z\.[0-9]+|tar\.[0-9]+|gz\.[0-9]+))$" 
      or FileName has_any (SplitArchivePatterns) // Match patterns or dynamic list
| summarize
    TotalFiles = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(RequestAccountName),
    FileSizeSum = sum(FileSize)
    by FileName, FolderPath, FileExtension, bin(Timestamp, 1h)
| order by TotalFiles desc
| project Timestamp, FileName, FolderPath, FileExtension, TotalFiles, UniqueDevices, UniqueUsers, FileSizeSum
```
{% endcode %}

#### Explanation:

1. **Patterns for Split/Part Files**:
   * `SplitArchivePatterns`: Defines patterns that identify split or part archive files, such as `.part1`, `.zip.001`, `.rar.002`, `.z.003`, etc.
   * Uses `matches regex` and `has_any` for flexible pattern matching.
2. **File Extension Extraction**:
   * Extracts the file extension from the `FileName` field using `split()` and converts it to lowercase for case-insensitive comparison.
3. **Filters**:
   * Filters the `FileName` field to match naming conventions for split or part archive files using `matches regex` or the predefined pattern list.
4. **Aggregation**:
   * Summarises:
     * `TotalFiles`: Number of files matching the pattern.
     * `UniqueDevices`: Number of unique devices involved.
     * `UniqueUsers`: Number of distinct users associated with the files.
     * `FileSizeSum`: Sum of file sizes for the detected files.
5. **Time Binning**:
   * Group results into 1-hour intervals using `bin(Timestamp, 1h)` for temporal analysis.
6. **Results**:
   * Displays key fields such as `Timestamp`, `FileName`, `FilePath`, `FileExtension`, `TotalFiles`, `UniqueDevices`, `UniqueUsers`, and `FileSizeSum`.

#### Customisation:

* **Patterns**:
  * Add or modify patterns in `SplitArchivePatterns` to align with your organisation's requirements.
* **Time Filtering**:
  * Add a specific time range filter, e.g., `| where Timestamp between (startTime .. endTime)`.
* **Additional Fields**:
  * Include fields like `UserPrincipalName`, `SourceIP`, or `DestinationIP` for more context.

This query can help detect potentially suspicious activity related to split or part archive files in your environment.
{% endtab %}

{% tab title="Sysmon (Splunk)" %}
Splunk query to identify **split or part archive files** using Sysmon logs:

{% code overflow="wrap" %}
```splunk-spl
Index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11 
| eval FileExtension=lower(mvindex(split(FileName, "."), -1))  // Extract file extension
| search FileName IN ("*.part*", "*.zip.*", "*.rar.*", "*.z.*", "*.tar.*", "*.gz.*", "*.001", "*.002", "*.003")  // Match split or part archive patterns
| stats count AS TotalFiles, 
        dc(Computer) AS UniqueHosts, 
        dc(User) AS UniqueUsers, 
        sum(FileSize) AS TotalFileSize 
        by FileName, FilePath, FileExtension
| sort - TotalFiles
| table FileName, FilePath, FileExtension, TotalFiles, UniqueHosts, UniqueUsers, TotalFileSize
```
{% endcode %}

#### Explanation:

1. **Index and Sourcetype**:
   * The query assumes `index=sysmon` and `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. Adjust as per your environment.
2. **Event Code**:
   * `EventCode=11`corresponds to Sysmon FileCreate events, capturing file creation activity.
3. **File Extension Extraction**:
   * Uses `split()` and `mvindex()` to extract the file extension and normalise it to lowercase for uniform comparison.
4. **Split/Part File Patterns**:
   * Searches for files matching common split or part archive patterns:
     * Examples: `.part*`, `.zip.*`, `.rar.*`, `.001`, `.002`, etc.
5. **Statistics**:
   * Aggregates data using `stats`to show:
     * `TotalFiles`: Number of files matching the pattern.
     * `UniqueHosts`: Number of unique hosts involved.
     * `UniqueUsers`: Number of distinct users associated with file creation.
     * `TotalFileSize`: Sum of file sizes for matched files.
6. **Sorting and Display**:
   * Sorts results by `TotalFiles` in descending order.
   * Displays relevant fields: `FileName`, `FilePath`, `FileExtension`, `TotalFiles`, `UniqueHosts`, `UniqueUsers`, and `TotalFileSize`.

#### Customisation:

* **Patterns**:
  * Expand or adjust file patterns to include additional split archive naming conventions.
* **Fields**:
  * Verify the field names (`FileName`, `FilePath`, `FileSize`, `Computer`, `User`) and adjust them to match your Sysmon log schema.
* **Time Filters**:
  * Use Splunk's time picker or add time range filters like `earliest=-24h`.

#### Use Case:

This query helps detect the creation of split or part archive files on endpoints, which could indicate potential data staging for exfiltration or malicious activity.
{% endtab %}
{% endtabs %}
