# Password in Group Policy Preferences (GPP) Compromise

### **Introduction**

**Group Policy Preferences (GPP)** is a feature in Microsoft Active Directory that allows administrators to configure and deploy system settings, including mapped drives, scheduled tasks, and local user accounts, across domain-joined computers. GPP once supported the deployment of local accounts with embedded passwords stored in the policy files. However, these passwords were encrypted using a weak AES key that was published publicly by Microsoft.

Attackers can exploit this vulnerability to extract plaintext passwords from GPP files, potentially gaining unauthorised access to sensitive systems. This technique is categorised under the **Credential Access** tactic in the **MITRE ATT\&CK Framework** (ID: T1552.006).

***

### **How Password in GPP Compromise Works**

1. **Group Policy Preferences and Passwords:**
   * GPP allowed administrators to configure local user accounts or services with passwords stored in XML files within the SYSVOL directory (`\\<domain>\SYSVOL\<domain>\Policies\`).
   * These XML files were encrypted using a fixed AES key, which Microsoft included in their documentation.
2. **Attack Workflow:**
   * **Reconnaissance:**
     * Attackers gain access to the domain and enumerate GPP files in the SYSVOL share.
     * These files are accessible to all domain-authenticated users due to the default permissions on SYSVOL.
   * **Decryption:**
     * Attackers extract the encrypted password from GPP XML files and decrypt it using the publicly available AES key.
   * **Credential Abuse:**
     * The decrypted password may belong to an administrative account, allowing attackers to escalate privileges or move laterally within the network.
3. **GPP Password Files of Interest:**
   * **Groups.xml**: Local group accounts and passwords.
   * **Services.xml**: Service accounts and passwords.
   * **Scheduledtasks.xml**: Task-related accounts and passwords.

***

### **Risks of GPP Compromise**

1. **Wide Access:**
   * Any domain-authenticated user can read the SYSVOL share and access GPP files.
2. **Privilege Escalation:**
   * The compromised credentials may belong to accounts with administrative privileges, enabling further exploitation.
3. **Lateral Movement:**
   * Attackers can use the extracted credentials to access other systems or escalate privileges.
4. **Persistence:**
   * Compromised credentials can be reused later, especially if not regularly rotated.

***

### **Indicators of GPP Compromise**

1. **Unusual Access to SYSVOL:**
   * Unexpected or unauthorised access to SYSVOL, particularly to GPP XML files.
2. **Enumeration of GPP Files:**
   * Commands or scripts targeting files like `Groups.xml`, `Services.xml`, or `Scheduledtasks.xml`.
3. **Use of Known Attack Tools:**
   * Use of tools like **PowerShell**, **Impacket**, or **Mimikatz** to query SYSVOL for GPP files.
4. **New Local Accounts or Privilege Changes:**
   * Creation of new local administrator accounts on systems using credentials extracted from GPP.

***

### **Mitigation Strategies**

1. **Audit and Remove GPP Passwords:**
   *   Search for and remove any passwords stored in GPP XML files:

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ChildItem -Path \\&#x3C;domain>\SYSVOL\&#x3C;domain>\Policies -Recurse -Include *.xml | Select-String -Pattern "cpassword"
       </code></pre>
2. **Rotate Credentials:**
   * Reset passwords for any accounts found in GPP files to prevent further misuse.
3. **Restrict SYSVOL Access:**
   * Limit SYSVOL access to authorised users wherever possible without breaking AD functionality.
4. **Disable Local Administrator Accounts:**
   * Disable or remove unnecessary local administrator accounts to reduce attack surfaces.
5. **Monitor SYSVOL Access:**
   * Enable auditing on the SYSVOL directory to detect unauthorised access attempts.

***

### **Detection Strategies**

1. **Monitor for SYSVOL Enumeration:**
   * Look for file access patterns targeting GPP XML files in the SYSVOL share.
   * Use Windows Event ID **5145** (A file was accessed) to track file access activity.
2. **Detect Decryption Activity:**
   * Monitor for tools or scripts using the known AES decryption key for GPP files.
3. **Analyse Lateral Movement:**
   * Look for logons or authentications from accounts with credentials found in GPP.
4. **Monitor Suspicious Commands:**
   * Track commands used to query GPP files:
     * `dir \\<domain>\SYSVOL\<domain>\Policies`
     * `findstr "cpassword"`

***

### **Detection Query Examples**

**PowerShell for Finding GPP Passwords:**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path \\<domain>\SYSVOL\<domain>\Policies -Recurse -Include *.xml | Select-String -Pattern "cpassword"
```
{% endcode %}

**Windows Event Query:**

Search for Event ID **5145** for file access activity on `\\<domain>\SYSVOL`.

***

The use of passwords in Group Policy Preferences is a significant security risk, especially in environments where older configurations persist. Organisations must actively search for and remove these passwords, rotate compromised credentials, and monitor access to the SYSVOL share to prevent exploitation. By implementing proper detection and mitigation measures, you can significantly reduce the risks associated with this type of compromise.

### KQL Detection Queries

To detect potential **Password in Group Policy Preferences (GPP) compromise** in Microsoft Sentinel using **KQL**, we need to monitor access to the SYSVOL share, specifically for activity involving files like `Groups.xml`, `Services.xml`, or `Scheduledtasks.xml`. Additionally, we can search for the **cpassword** field in these files, which indicates a password stored in GPP.

{% tabs %}
{% tab title="Query 1" %}
#### **KQL Query to Detect GPP Password Enumeration**

This query identifies suspicious access to GPP XML files and potential enumeration in the SYSVOL share

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 5145  // File Access Auditing
| extend AccessedFile = tostring(EventData.ShareName) + "\\" + tostring(EventData.RelativeTargetName)
| where AccessedFile contains "\\SYSVOL" and (AccessedFile endswith ".xml" or AccessedFile contains "Groups.xml" or AccessedFile contains "cpassword")
| summarize AccessCount = count(), 
            AccessedFiles = make_set(AccessedFile), 
            UniqueUsers = dcount(Account), 
            Accounts = make_set(Account), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
    by Computer, IpAddress
| where AccessCount > 10  // Threshold for suspicious activity, adjust as needed
| extend SuspiciousActivity = case(
    AccessCount > 50, "High",
    AccessCount > 10, "Medium",
    "Low"
)
| where SuspiciousActivity in ("High", "Medium")
| project Computer, IpAddress, AccessCount, UniqueUsers, Accounts, AccessedFiles, FirstSeen, LastSeen, SuspiciousActivity
| sort by SuspiciousActivity desc, AccessCount desc
```
{% endcode %}

#### **Query Breakdown**

1. **Target Event ID 5145:**
   * Event ID **5145** logs file access on shared resources, including SYSVOL.
2. **Filter SYSVOL Access:**
   * Looks for access to `\\SYSVOL` and specifically targets XML files or entries containing `cpassword`.
3. **Aggregate Activity:**
   * Tracks:
     * `AccessCount`: Total file access attempts.
     * `AccessedFiles`: The set of accessed XML files.
     * `UniqueUsers` and `Accounts`: Number of unique users accessing the files.
     * `FirstSeen` and `LastSeen`: Time range of activity.
4. **Threshold for Suspicious Activity:**
   * Flags activity with more than 10 file access attempts, assigning a **SuspiciousActivity** score:
     * **High:** Over 50 accesses.
     * **Medium:** Over 10 accesses.
5. **Output Details:**
   * Displays key information for investigation, such as the computer, source IP, accounts involved, and files accessed.
{% endtab %}

{% tab title="Query 2" %}
#### **Advanced Query with Keyword Matching**

This query searches for GPP-related keywords (`cpassword`) in the content of accessed files if the logs contain such data.

{% code overflow="wrap" %}
```spl
SecurityEvent
| where EventID == 5145
| extend AccessedFile = tostring(EventData.ShareName) + "\\" + tostring(EventData.RelativeTargetName)
| where AccessedFile contains "\\SYSVOL" and (AccessedFile endswith ".xml" or AccessedFile contains "Groups.xml")
| extend FileContent = extract(".*(cpassword.*)</", 1, tostring(EventData.Data))  // Extract 'cpassword' field if present
| where isnotempty(FileContent)
| summarize AccessCount = count(), 
            AccessedFiles = make_set(AccessedFile), 
            SuspiciousContent = make_set(FileContent), 
            UniqueUsers = dcount(Account), 
            Accounts = make_set(Account), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
    by Computer, IpAddress
| where AccessCount > 5
| project Computer, IpAddress, AccessCount, UniqueUsers, Accounts, AccessedFiles, SuspiciousContent, FirstSeen, LastSeen
| sort by AccessCount desc
```
{% endcode %}

#### **Detection Enhancements**

1. **Whitelist Known Users or Systems:**
   *   Exclude authorized administrative accounts or systems that legitimately access these files:

       <pre class="language-kusto" data-overflow="wrap"><code class="lang-kusto">| where not(Account in ("AdminAccount1", "BackupService"))
       </code></pre>
2. **Threshold Adjustment:**
   * Adjust the `AccessCount > 10` threshold based on your environment’s baseline activity.
3. **Time-Based Grouping:**
   *   To detect bursts of activity, group events into time intervals:

       ```kql
       kqlCopyEdit| bin TimeGenerated span=15m
       ```
4. **Audit SYSVOL Content Periodically:**
   *   Use PowerShell to identify GPP files containing passwords:

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ChildItem -Path \\&#x3C;domain>\SYSVOL\&#x3C;domain>\Policies -Recurse -Include *.xml | Select-String -Pattern "cpassword"
       </code></pre>

***

#### **Additional Recommendations**

1. **Set Alerts:**
   * Configure alerts in Sentinel for `SuspiciousActivity = High` to notify SOC analysts of potential enumeration or compromise.
2. **Monitor Access Patterns:**
   * Keep an eye on patterns of access to the SYSVOL share from unexpected accounts or IP addresses.
3. **Harden SYSVOL Permissions:**
   * Limit access to SYSVOL to only authorized users.
4. **Eliminate GPP Passwords:**
   * Search for and remove any remaining GPP passwords using PowerShell and ensure password deployment practices follow modern security standards.
{% endtab %}

{% tab title="Query 3" %}
Query to detect the presence of passwords in Group Policy Preferences (GPP):

{% code overflow="wrap" %}
```kusto
// Define the time range for the query
let startTime = ago(7d);
let endTime = now();

// Step 1: Identify GPP XML files containing passwords
let GPP_Passwords = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 5145 // File Accessed
| extend FilePath = tostring(TargetObject)
| where FilePath contains "Groups.xml" or FilePath contains "Services.xml" or FilePath contains "ScheduledTasks.xml"
| extend AccountName = tostring(TargetUserName), Domain = tostring(TargetDomainName), ClientIP = tostring(IpAddress)
| project AccountName, Domain, ClientIP, FilePath, TimeGenerated;

// Step 2: Identify suspicious access patterns
let SuspiciousAccess = GPP_Passwords
| summarize AccessCount = count(), UniqueIPs = dcount(ClientIP), ClientIPs = make_set(ClientIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AccountName, FilePath
| where AccessCount > 5 // Adjust threshold based on your environment
| project AccountName, FilePath, AccessCount, UniqueIPs, ClientIPs, FirstSeen, LastSeen
| sort by AccessCount desc;

// Step 3: Combine results to identify potential compromises
SuspiciousAccess
| project AccountName, FilePath, AccessCount, UniqueIPs, ClientIPs, FirstSeen, LastSeen

```
{% endcode %}

Query performs the following steps:

1. **Defines the time range** for the query to look back over the past 7 days.
2. **Identifies GPP XML files** containing passwords by looking for file access events (Event ID 5145) related to specific XML files (`Groups.xml`, `Services.xml`, `ScheduledTasks.xml`).
3. **Extracts relevant information** such as the account name, domain, client IP, and file path.
4. **Aggregates the data** to count the number of accesses and unique IPs per account and file path.
5. **Filters the results** to include only those with more than 5 accesses (adjust the threshold based on your environment).
6. **Displays the results** in a table format, sorted by the number of accesses.
{% endtab %}
{% endtabs %}

### Splunk Detection Queries

To detect **Password in Group Policy Preferences (GPP) compromise** in Splunk, you can focus on **file access events** within the SYSVOL share, particularly targeting `.xml` files like `Groups.xml`, `Services.xml`, or `Scheduledtasks.xml` where passwords might be stored. Additionally, you can identify the presence of the **cpassword** field in these files.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query for GPP Password Compromise Detection

{% code overflow="wrap" %}
```spl
index=windows EventCode=5145
| eval AccessedFile = Resource + "\\" + Object_Name
| where like(AccessedFile, "%\\SYSVOL%") AND (like(AccessedFile, "%.xml") OR match(AccessedFile, "(Groups|Services|Scheduledtasks)\\.xml$"))
| stats count AS AccessCount, 
        values(AccessedFile) AS AccessedFiles, 
        dc(Account_Name) AS UniqueUsers, 
        values(Account_Name) AS Accounts, 
        dc(IpAddress) AS UniqueIPs, 
        values(IpAddress) AS SourceIPs, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName
| where AccessCount > 10  // Threshold: Adjust based on baseline activity
| eval SuspiciousScore = case(
    AccessCount > 50, "High",
    AccessCount > 20, "Medium",
    AccessCount > 10, "Low"
)
| where SuspiciousScore IN ("High", "Medium")
| table ComputerName, AccessedFiles, AccessCount, UniqueUsers, Accounts, UniqueIPs, SourceIPs, FirstSeen, LastSeen, SuspiciousScore
| sort - SuspiciousScore, -AccessCount

```
{% endcode %}

#### **Query Breakdown**

1. **Target Event ID 5145:**
   * **EventCode 5145** logs file access on shared resources, including the SYSVOL directory.
2. **Focus on GPP Files:**
   * Filters for access to `.xml` files in the SYSVOL share, especially files like `Groups.xml`, `Services.xml`, and `Scheduledtasks.xml`.
3. **Aggregate Suspicious Activity:**
   * Groups file access events by `ComputerName` and aggregates key metrics:
     * **AccessCount:** Total file access attempts.
     * **AccessedFiles:** Specific files accessed.
     * **UniqueUsers:** Number of distinct users involved.
     * **UniqueIPs and SourceIPs:** IP addresses accessing the files.
4. **Apply Suspicious Thresholds:**
   * Assigns a **SuspiciousScore** based on the volume of file access:
     * **High:** Over 50 accesses.
     * **Medium:** Over 20 accesses.
5. **Output Details:**
   * Displays key data for investigation, including accessed files, user accounts, source IPs, and time range.
{% endtab %}

{% tab title="Query 2" %}
Query to detect the presence of passwords in Group Policy Preferences (GPP):

{% code overflow="wrap" %}
```spl
index=windows sourcetype=add_your_sourcetype
| eval FilePath = mvindex(TargetObject, 1)
| where EventCode=5145 // File Accessed
| search FilePath IN ("*Groups.xml*", "*Services.xml*", "*ScheduledTasks.xml*")
| stats count AS AccessCount, values(IpAddress) AS ClientIPs, dc(IpAddress) AS UniqueIPs BY AccountName, FilePath
| where AccessCount > 5 // Adjust threshold based on your environment
| table _time, AccountName, FilePath, AccessCount, UniqueIPs, ClientIPs
| sort - AccessCount
```
{% endcode %}

Query performs the following steps:

1. **Filters events** to include only those with EventCode 5145, which corresponds to file access events.
2. **Evaluates the FilePath** to identify the target XML files (`Groups.xml`, `Services.xml`, `ScheduledTasks.xml`).
3. **Aggregates the data** to count the number of accesses and unique IPs per AccountName and FilePath.
4. **Filters the results** to include only those with more than 5 accesses (adjust the threshold based on your environment).
5. **Displays the results** in a table format, sorted by the number of accesses.
{% endtab %}

{% tab title="Query 3" %}
Advanced Query: Searching for "cpassword" in Logs

If your Splunk environment captures file content or metadata, you can extend the query to detect the `cpassword` field directly:

{% code overflow="wrap" %}
```spl
index=windows EventCode=5145
| eval AccessedFile = Resource + "\\" + Object_Name
| where like(AccessedFile, "%\\SYSVOL%") AND (like(AccessedFile, "%.xml") OR match(AccessedFile, "(Groups|Services|Scheduledtasks)\\.xml$"))
| eval FileContent = extract(".*(cpassword=.*)</", 1, _raw)  // Extract 'cpassword' if present
| where isnotempty(FileContent)
| stats count AS AccessCount, 
        values(AccessedFile) AS AccessedFiles, 
        values(FileContent) AS SuspiciousContent, 
        dc(Account_Name) AS UniqueUsers, 
        values(Account_Name) AS Accounts, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName
| where AccessCount > 5
| table ComputerName, AccessedFiles, SuspiciousContent, AccessCount, UniqueUsers, Accounts, FirstSeen, LastSeen
| sort - AccessCount desc
```
{% endcode %}

#### **Customisations**

1. **Adjust Thresholds:**
   * Modify `AccessCount > 10` based on your environment’s normal activity levels.
2. **Whitelist Legitimate Activity:**
   *   Exclude trusted accounts or systems that access SYSVOL:

       <pre class="language-spl" data-overflow="wrap"><code class="lang-spl">| search NOT Account_Name IN ("trusted_admin", "service_account")
       </code></pre>
3. **Add Time-Based Grouping:**
   *   Group events into smaller time intervals to detect bursts of activity:

       ```spl
       | bin _time span=15m
       ```
4. **Monitor All Access to SYSVOL:**
   *   Expand the query to detect broader patterns of unusual SYSVOL access:

       ```spl
       | where like(AccessedFile, "%\\SYSVOL%")
       ```

***

#### **Detection Recommendations**

1. **Set Alerts:**
   * Configure alerts for `SuspiciousScore = High` to notify SOC analysts of potential GPP compromise.
2. **Audit SYSVOL:**
   *   Regularly check for GPP passwords using PowerShell:

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ChildItem -Path \\&#x3C;domain>\SYSVOL\&#x3C;domain>\Policies -Recurse -Include *.xml | Select-String -Pattern "cpassword"
       </code></pre>
3. **Rotate Compromised Credentials:**
   * Immediately rotate credentials if a `cpassword` is detected in GPP XML files.
4. **Harden SYSVOL Permissions:**
   * Restrict access to SYSVOL to minimise exposure to unauthorised users.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
