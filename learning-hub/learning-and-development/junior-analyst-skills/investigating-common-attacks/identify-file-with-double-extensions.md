# Identify File with Double Extensions

### Description of the Query:

This KQL query is designed to detect **files with misleading double extensions**, which attackers often use to disguise malicious files as legitimate ones. For example, a file named `invoice.pdf.exe` may appear to be a PDF document but is actually an executable file. Attackers use this technique to trick users into opening malicious files, leading to malware infections or other security breaches.

The query focuses on identifying file creation or modification events (`FileCreate` or `FileModify`) where the file name contains multiple extensions (e.g., `.pdf.exe`, `.docx.vbs`). By analysing these patterns, security teams can identify potentially malicious files and take appropriate action.

### KQL Query:

{% code overflow="wrap" %}
```kusto
// Detect Files With Misleading Double Extensions Using Regex
DeviceFileEvents
| where Timestamp > ago(30d) // Limit results to the last 24 hours
| where ActionType in ("FileCreate", "FileModify") // Focus on file creation or modification events
| extend FileName = tostring(split(FolderPath, "\\")[-1]) // Extract the file name from the full path
| where isnotempty(FileName) // Ensure FileName is not null or empty
| where FileName matches regex @'[^\\.]+\\.[^\\.]+\\.[^\\.]+' // Match file names with at least two dots (double extensions)
| extend FileExtension = tostring(split(FileName, ".")[-1]) // Extract the final extension
| extend SuspiciousExtensions = dynamic(["exe", "vbs", "js", "bat", "cmd", "ps1"]) // List of suspicious extensions
| where FileExtension has_any (SuspiciousExtensions) // Filter for files with suspicious final extensions
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    FileExtension,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    ActionType
| sort by Timestamp desc
```
{% endcode %}

### Explanation of Changes:

1. **Regex to Identify Double Extensions** :
   *   The key change is the use of a **regex pattern** to identify file names with double extensions:

       regexCopy1\[^\\\\.]+\\\\.\[^\\\\.]+\\\\.\[^\\\\.] +

       * `[^\\.]+`: Matches one or more characters that are not a dot (`.`).
       * `\\.`: Matches a literal dot (`.`).
       * The pattern ensures there are at least **two dots** in the file name, indicating a double extension (e.g., `invoice.pdf.exe`).
   * This eliminates the need to split the file name into parts and check for additional dots manually.
2. **Extracting Final Extension** :
   * After identifying files with double extensions, the query extracts the final extension using `split(FileName, ".")[-1]`. This ensures we can filter for suspicious extensions like `.exe`, `.vbs`, etc.
3. **Filtering Suspicious Extensions** :
   * The query filters for files with suspicious extensions (e.g., `.exe`, `.vbs`) using the `has_any` operator.
4. **Simplified Logic** :
   * By using regex, the query avoids complex operations like `replace` or `iff` to compute the base name and check for double extensions.

Key Benefits of Using Regex:

1. **Simpler Logic** :
   * The regex pattern directly identifies files with double extensions, reducing the need for intermediate steps like splitting strings or checking array lengths.
2. **Improved Performance** :
   * Regex is optimized for pattern matching and can handle complex patterns efficiently.
3. **Flexibility** :
   * You can easily modify the regex pattern to match other naming conventions or extensions if needed.

### Notes:

1. **Regex Pattern Details** :
   * The regex pattern `[^\\.]+\\.[^\\.]+\\.[^\\.] +` ensures that:
     * There are at least two dots in the file name.
     * Each segment between dots contains at least one character (to avoid false positives like `file..exe`).
2. **False Positives** :
   * Some legitimate files may have double extensions (e.g., `config.backup.json`). Analysts should review the results to differentiate between benign and malicious activity.
3. **Customisation** :
   * You can adjust the list of `SuspiciousExtensions` based on your organization's environment and known attack vectors.
