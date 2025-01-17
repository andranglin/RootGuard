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

# Authentication Server Response (AS-REP) Roasting

### **Introduction to AS-REP Roasting**

AS-REP Roasting is a post-exploitation technique used by attackers to extract and crack password hashes for user accounts in a Kerberos authentication environment. It specifically targets user accounts that have **"Do not require Kerberos preauthentication"** enabled, exploiting a feature of the Kerberos protocol that allows attackers to obtain encrypted password hashes without direct interaction with the target user.

AS-REP Roasting is categorised under the **Credential Access** tactic in the MITRE ATT\&CK framework (ID: T1558.004) and is often used to escalate privileges or move laterally within a compromised environment.

***

### **How AS-REP Roasting Works**

1. **Kerberos Overview:**
   * In a typical Kerberos authentication process, pre-authentication requires the client to prove its identity by encrypting a timestamp with the user's password hash and sending it to the Key Distribution Center (KDC). This mechanism prevents offline brute-force attacks against Kerberos accounts.
2. **No Preauthentication Accounts:**
   * Some accounts in Active Directory may have the **"Do not require Kerberos preauthentication"** flag enabled. This is often done for compatibility with legacy systems or misconfiguration.
   * For these accounts, the KDC skips the preauthentication step and directly sends an encrypted **AS-REP** message containing the user's Ticket Granting Ticket (TGT).
3. **Attack Workflow:**
   * **Discovery:** The attacker enumerates accounts in Active Directory to identify those with preauthentication disabled.
   * **Request AS-REP:** The attacker requests authentication for the target account without needing any credentials.
   * **Receive AS-REP:** The KDC responds with an AS-REP message encrypted using the target user's password hash.
   * **Offline Hash Cracking:** The attacker extracts the encrypted hash from the AS-REP message and uses tools like `John the Ripper` or `Hashcat` to perform an offline brute-force or dictionary attack to recover the plaintext password.

***

### **Why AS-REP Roasting is Effective**

* **No Interaction with the Target User:** Unlike techniques like phishing, AS-REP Roasting does not require user interaction, making it stealthier.
* **Offline Cracking:** Once the attacker retrieves the AS-REP hash, the cracking process is entirely offline, bypassing detection systems that monitor real-time activities.
* **Weak Passwords:** Environments with weak password policies are highly vulnerable as attackers can easily crack poorly secured hashes.

***

### **Detection and Mitigation**

**Detection:**

1. **Log Monitoring:**
   * Monitor Windows Security Event Logs for Kerberos authentication anomalies:
     * Event ID 4768: Kerberos Authentication Ticket Request.
     * Event ID 4771: Kerberos Pre-authentication Failed.
     * Event ID 4625:  This event is generated when an account fails to log on.
     * Event ID 4738, 5136: These events are generated when a user account is changed
   * Look for multiple AS-REP requests from a single host or for rarely used accounts.
2. **Network Traffic Analysis:**
   * Use tools like Zeek or Wireshark to detect Kerberos AS-REP traffic originating from unusual IP addresses or hosts.
3. **Threat Hunting:**
   *   Query Active Directory to identify accounts with the `DONT_REQUIRE_PREAUTH` attribute enabled:

       {% code overflow="wrap" %}
       ```powershell
       Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
       ```
       {% endcode %}
4. **Use EDR/SIEM Tools:**
   * Configure detection rules for tools like Splunk, Elastic, or Microsoft Sentinel to flag unusual AS-REP requests.

**Mitigation:**

1. **Disable Legacy Settings:**
   * Audit and disable the "Do not require Kerberos pre-authentication" setting for all accounts unless absolutely necessary.
2. **Enforce Strong Passwords:**
   * Implement strong password policies and enforce multi-factor authentication (MFA) to make brute-force attacks impractical.
3. **Limit Privileges:**
   * Ensure accounts with sensitive privileges do not have pre-authentication disabled.
4. **Regular Audits:**
   * Periodically audit Active Directory for misconfigurations, including accounts with `DONT_REQUIRE_PREAUTH` enabled.

***

### **Common Tools for AS-REP Roasting**

1. **Impacket (GetNPUsers.py):**
   * Enumerates accounts with pre-authentication disabled and extracts AS-REP hashes.
2. **Rubeus:**
   * A powerful tool for Kerberos abuse, including AS-REP Roasting.
3. **Cracking Tools:**
   * Tools like `John the Ripper` and `Hashcat` are used to crack the extracted hashes offline.

***

AS-REP Roasting highlights how minor misconfigurations in Kerberos authentication can lead to significant security risks. By understanding how the attack works and implementing proactive detection and mitigation measures, organisations can better protect their Active Directory environments from credential theft and lateral movement threats.

### KQL Dection Queries:

{% tabs %}
{% tab title="Query 1" %}
{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4768  // Kerberos Authentication Ticket (AS-REP)
| extend AccountName = TargetUserName, 
         Domain = TargetDomainName,
         ClientIP = IpAddress,
         FailureCode = Status
| where FailureCode in ("0x0", "0x12")  // Success (0x0) or pre-auth not required (0x12)
| summarize RequestCount = count(), UniqueIPs = dcount(ClientIP), ClientIPs = make_set(ClientIP)
    by AccountName, Domain
| where RequestCount > 10 or UniqueIPs > 3  // Threshold: tune these values based on your environment
| extend SuspiciousActivity = case(
    RequestCount > 10 and UniqueIPs > 3, "High",
    RequestCount > 10, "Moderate",
    UniqueIPs > 3, "Moderate",
    "Low"
)
| project AccountName, Domain, RequestCount, UniqueIPs, ClientIPs, SuspiciousActivity
| sort by SuspiciousActivity desc, RequestCount desc
```
{% endcode %}

#### **Explanation of the Query**

1. **Filter for Event ID 4768:**
   * **Event ID 4768** corresponds to "Kerberos Authentication Ticket Request" in Windows Security logs.
   * This is the event generated when the KDC responds with an AS-REP.
2. **Focus on Preauthentication Disabled:**
   * Pre-authentication disabled is indicated by **FailureCode = 0x12**.
   * The query also considers **Success (0x0)** to identify successful AS-REP requests that might indicate compromised accounts.
3. **Summarisation:**
   * Groups data by the `AccountName` and `Domain`.
   * Tracks the total number of requests (`RequestCount`) and distinct client IPs (`UniqueIPs`).
   * Also lists all involved client IPs for further investigation.
4. **Anomalous Behavior Detection:**
   * Flags accounts with more than 10 requests or requests originating from more than 3 unique IPs.
   * These thresholds (`RequestCount > 10` or `UniqueIPs > 3`) can be adjusted based on your environment.
5. **Severity Classification:**
   * Adds a `SuspiciousActivity` field to classify detected activity as **High**, **Moderate**, or **Low** based on thresholds.
6. **Presentation:**
   * Displays key details such as account name, domain, request count, unique IPs, and their suspicious activity level for SOC analysts.

***

#### **Adjustments for Environment**

* **Tune Thresholds:** Customise `RequestCount > 10` and `UniqueIPs > 3` based on the normal behaviour in your organisation.
* **Exclude Whitelisted Accounts/IPs:** Use a lookup table or additional filters to exclude known safe accounts or IP addresses.
* **Correlate with Other Events:**
  * Combine with Event ID 4625 (failed logons) or Event ID 4771 (Kerberos pre-auth failures) for better context.
{% endtab %}

{% tab title="Query 2" %}
{% code overflow="wrap" %}
```kusto
// Define the time range for the query
let startTime = ago(7d);
let endTime = now();
// Define a list of known service accounts to exclude from the results
let knownServiceAccounts = dynamic(["krbtgt", "svc_", "admin_", "backup_"]);
// Step 1: Identify AS-REP requests from accounts with pre-authentication disabled
let asRepRequests = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4768 // AS-REP request
| parse EventData with * 'TargetUserName">' TargetUserName '<' * 'TicketEncryptionType">' TicketEncryptionType '<' *
| where TicketEncryptionType in ("0x17", "0x18") // RC4-HMAC and AES128-CTS-HMAC-SHA1-96
| where TargetUserName !in (knownServiceAccounts)
| summarize requestCount = count() by TargetUserName, bin(TimeGenerated, 1h)
| where requestCount > 5;
// Step 2: Combine the results to identify suspicious activity
asRepRequests
| project TimeGenerated, TargetUserName, requestCount
| order by TimeGenerated desc
```
{% endcode %}

Query performs the following steps:

1. **Defines the time range** for the query to look back over the past 7 days.
2. **Identifies AS-REP requests** from accounts with pre-authentication disabled, filtering out known service accounts to focus on potentially suspicious activity.
3. **Filters AS-REP requests** using weak encryption types (RC4-HMAC and AES128-CTS-HMAC-SHA1-96).
4. **Aggregates the data** to count the number of AS-REP requests per TargetUserName.
5. **Filters the results** to include only those with more than 5 requests within a 1-hour timeframe.
6. **Displays the results** in a table format, sorted by time.
{% endtab %}

{% tab title="Query 3" %}
{% code overflow="wrap" %}
```kusto
let Threshold_RequestCount = 10; // Adjust based on environment baseline
let Threshold_UniqueIPs = 3; // Adjust based on environment baseline
let RareAccountThreshold = 5; // Threshold for rare accounts (logons)
// Step 1: Identify AS-REP events (Event ID 4768)
let ASREP_Events = SecurityEvent
| where EventID == 4768
| extend AccountName = tostring(TargetUserName),
         Domain = tostring(TargetDomainName),
         ClientIP = tostring(IpAddress),
         FailureCode = tostring(Status)
| where FailureCode == "0x12"  // Preauthentication not required
| project AccountName, Domain, ClientIP, FailureCode, TimeGenerated;
// Step 2: Aggregate AS-REP activity
let Aggregated_ASREP = ASREP_Events
| summarize RequestCount = count(), 
            UniqueIPs = dcount(ClientIP),
            ClientIPs = make_set(ClientIP), 
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by AccountName, Domain;
// Step 3: Identify Rare Accounts (Low Authentication Activity)
let RareAccounts = SecurityEvent
| where EventID == 4624  // Successful Logon
| summarize LogonCount = count(), LogonIPs = make_set(IpAddress) by AccountName
| where LogonCount < RareAccountThreshold
| project AccountName, LogonCount, LogonIPs;
// Step 4: Combine AS-REP Events with Rare Account Info
Aggregated_ASREP
| join kind=leftouter (RareAccounts) on AccountName
| extend IsRareAccount = iff(isnull(LogonCount), 1, 0)
| extend SuspiciousScore = case(
    RequestCount > Threshold_RequestCount and UniqueIPs > Threshold_UniqueIPs and IsRareAccount == 1, 3,
    RequestCount > Threshold_RequestCount and UniqueIPs > Threshold_UniqueIPs, 2,
    RequestCount > Threshold_RequestCount or UniqueIPs > Threshold_UniqueIPs, 1,
    0
)
| where SuspiciousScore > 0
| project AccountName, Domain, RequestCount, UniqueIPs, ClientIPs, FirstSeen, LastSeen, IsRareAccount, SuspiciousScore
| sort by SuspiciousScore desc, RequestCount desc

)
| where SuspiciousScore > 0
| project AccountName, Domain, RequestCount, UniqueIPs, ClientIPs, EncryptionTypes, FirstSeen, LastSeen, IsRareAccount, SuspiciousScore
| sort by SuspiciousScore desc, RequestCount desc
```
{% endcode %}

#### **Explanation of the Query**

1. **Detecting AS-REP Roasting:**
   * Looks for Event ID **4768** (Kerberos Authentication Ticket Request) with **`FailureCode == "0x12"`**, signaling a response from the KDC for accounts without preauthentication.
2. **Rare Account Detection:**
   * Correlates with Event ID **4624** (successful logons) to identify accounts with limited activity (`LogonCount < RareAccountThreshold`).
3. **Suspicious Scoring:**
   * Assigns a **`SuspiciousScore`** based on the following:
     * High request count (`RequestCount > Threshold_RequestCount`).
     * High number of unique IPs (`UniqueIPs > Threshold_UniqueIPs`).
     * Account rarity (`IsRareAccount == 1`).
4. **Output Insights:**
   * Presents actionable insights such as `RequestCount`, `UniqueIPs`, and `IsRareAccount` to prioritize suspicious accounts.

***

#### **Customisations and Next Steps**

* **Thresholds:** Adjust the thresholds (`Threshold_RequestCount`, `Threshold_UniqueIPs`, and `RareAccountThreshold`) to align with your organization's baseline.
* **Filtering Known Activity:** Add filters or join with lookup tables to exclude known safe accounts or IP addresses.
* **Alerting:** Configure alerts in Microsoft Sentinel for **`SuspiciousScore > 2`** to detect high-risk activities.
{% endtab %}

{% tab title="Quey 4" %}
{% code overflow="wrap" %}
```kusto
// Define the time range for the query
let startTime = ago(7d);
let endTime = now();
// Define thresholds for suspicious activity
let Threshold_RequestCount = 10;
let Threshold_UniqueIPs = 3;
let RareAccountThreshold = 5;
// Step 1: Identify AS-REP events (Event ID 4768)
let ASREP_Events = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4768
| extend AccountName = tostring(TargetUserName), Domain = tostring(TargetDomainName), ClientIP = tostring(IpAddress), FailureCode = tostring(Status)
| where FailureCode == "0x12" // Preauthentication not required
| project AccountName, Domain, ClientIP, FailureCode, TimeGenerated;
// Step 2: Aggregate AS-REP activity
let Aggregated_ASREP = ASREP_Events
| summarize RequestCount = count(), UniqueIPs = dcount(ClientIP), ClientIPs = make_set(ClientIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AccountName, Domain;
// Step 3: Identify Rare Accounts (Low Authentication Activity)
let RareAccounts = SecurityEvent
| where EventID == 4624 // Successful Logon
| summarize LogonCount = count(), LogonIPs = make_set(IpAddress) by AccountName
| where LogonCount < RareAccountThreshold
| project AccountName, LogonCount, LogonIPs;
// Step 4: Combine AS-REP Events with Rare Account Info
Aggregated_ASREP
| join kind=leftouter (RareAccounts) on AccountName
| extend IsRareAccount = iff(isnull(LogonCount), 1, 0)
| extend SuspiciousScore = case(
    RequestCount > Threshold_RequestCount and UniqueIPs > Threshold_UniqueIPs and IsRareAccount == 1, 3,
    RequestCount > Threshold_RequestCount and UniqueIPs > Threshold_UniqueIPs, 2,
    RequestCount > Threshold_RequestCount or UniqueIPs > Threshold_UniqueIPs, 1,
    0
)
| where SuspiciousScore > 0
| project AccountName, Domain, RequestCount, UniqueIPs, ClientIPs, FirstSeen, LastSeen, IsRareAccount, SuspiciousScore
| sort by SuspiciousScore desc, RequestCount desc
```
{% endcode %}

Query performs the following steps:

1. **Defines the time range** for the query to look back over the past 7 days.
2. **Identifies AS-REP events** (Event ID 4768) with pre-authentication disabled (FailureCode == "0x12").
3. **Aggregates AS-REP activity** to count the number of requests and unique IPs per account.
4. **Identifies rare accounts** with low authentication activity (Event ID 4624).
5. **Combines AS-REP events with rare account information** to calculate a SuspiciousScore based on multiple factors.
6. **Displays the results** in a table format, sorted by SuspiciousScore and RequestCount.
{% endtab %}
{% endtabs %}

### Splunk Detection Queries

{% tabs %}
{% tab title="Windows" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows (sourcetype="WinEventLog:Security" OR EventCode=4768)
| eval TargetAccount=TargetUserName, ClientIP=IpAddress, FailureCode=Status
| where FailureCode="0x12"  // Preauthentication not required
| stats count AS RequestCount, values(ClientIP) AS RequestingIPs, dc(ClientIP) AS UniqueIPs, min(_time) AS FirstSeen, max(_time) AS LastSeen 
    BY TargetAccount
| eval SuspiciousScore = case(
    RequestCount > 10 AND UniqueIPs > 3, "High",
    RequestCount > 10 OR UniqueIPs > 3, "Medium",
    RequestCount <= 10 AND UniqueIPs <= 3, "Low"
)
| where SuspiciousScore IN ("High", "Medium")  // Filter only significant activity
| table TargetAccount, RequestCount, UniqueIPs, RequestingIPs, FirstSeen, LastSeen, SuspiciousScore
| sort - SuspiciousScore, -RequestCount
```
{% endcode %}

**Query Breakdown**

1. **Filter for Event ID 4768:**
   * Searches for Kerberos authentication ticket requests in Windows Security logs.
   * Focuses on instances where `FailureCode="0x12"` (preauthentication is not required).
2. **Extract Relevant Fields:**
   * `TargetUserName`: The account being requested.
   * `IpAddress`: The source IP making the request.
3. **Aggregate Data:**
   * Counts the number of requests per `TargetAccount` (`RequestCount`).
   * Identifies distinct source IPs (`UniqueIPs`).
   * Captures the time range of activity (`FirstSeen`, `LastSeen`).
4. **Calculate Suspicious Score:**
   * Assigns a **"High"** score if both `RequestCount > 10` and `UniqueIPs > 3`.
   * Assigns a **"Medium"** score if either condition is true.
   * Assigns a **"Low"** score for benign activity.
5. **Filter and Display:**
   * Excludes low-risk activity by keeping only `High` and `Medium` scores.
   * Displays a concise table with actionable details for SOC analysts.

***

#### **Customisations**

* **Threshold Tuning:**
  * Adjust thresholds (`RequestCount > 10` and `UniqueIPs > 3`) based on your organisation’s baseline activity.
*   **Whitelist Legitimate Accounts:**

    * Add a filter to exclude known legitimate accounts (e.g., a lookup of service accounts).

    ```spl
    splCopyEdit| search NOT [ | inputlookup known_safe_accounts.csv ]
    ```
* **Alert Configuration:**
  * Use this query as the basis for Splunk alerts, triggering notifications for `SuspiciousScore = High`.

***

#### **Additional Recommendations**

1. **Correlation with Failed Logons:**
   * Combine with Event ID **4625** (failed logons) to check if attackers are also attempting brute force or password spraying.
2. **Integration with Threat Intelligence:**
   * Cross-reference the `ClientIP` field with known malicious IPs from threat intelligence feeds.
{% endtab %}

{% tab title="Sysmon" %}
Sysmon Query for AS-REP Roasting Detection

{% code overflow="wrap" %}
```splunk-spl
index=sysmon EventCode=13
| eval TargetAccount=AccountName, ClientIP=coalesce(IpAddress, SourceHost), RequestingHost=ComputerName
| stats count AS RequestCount, values(ClientIP) AS RequestingIPs, dc(ClientIP) AS UniqueIPs, min(_time) AS FirstSeen, max(_time) AS LastSeen 
    BY TargetAccount, RequestingHost
| where RequestCount > 10 OR UniqueIPs > 3  // Adjust thresholds based on environment
| eval SuspiciousScore = case(
    RequestCount > 20 AND UniqueIPs > 5, "High",
    RequestCount > 10 OR UniqueIPs > 3, "Medium",
    RequestCount <= 10 AND UniqueIPs <= 3, "Low"
)
| where SuspiciousScore IN ("High", "Medium")  // Exclude low-priority activity
| table TargetAccount, RequestingHost, RequestCount, UniqueIPs, RequestingIPs, FirstSeen, LastSeen, SuspiciousScore
| sort - SuspiciousScore, -RequestCount
```
{% endcode %}

1. **Focus on Sysmon Event ID 13:**
   * Event ID 13 logs Kerberos Service Ticket Requests, which attackers exploit in AS-REP roasting.
   * Index and source (`index=sysmon`) may vary based on your Splunk setup.
2. **Extract Relevant Fields:**
   * `AccountName`: The account being targeted for service ticket requests.
   * `IpAddress` / `SourceHost`: IP address or host making the request.
   * `ComputerName`: The hostname of the requesting machine.
3. **Aggregate Data:**
   * `RequestCount`: Total number of requests for the target account.
   * `UniqueIPs`: Number of unique IP addresses making the requests.
   * `FirstSeen`, `LastSeen`: Time range of activity for the target account.
4. **Apply Suspicious Thresholds:**
   * Flag high-frequency requests or those originating from multiple unique IPs:
     * **High:** RequestCount > 20 and UniqueIPs > 5.
     * **Medium:** RequestCount > 10 or UniqueIPs > 3.
   * Adjust thresholds (`RequestCount > 10`, `UniqueIPs > 3`) based on the environment.
5. **Filter and Present:**
   * Excludes low-risk activity.
   * Displays key details (`TargetAccount`, `RequestingHost`, `RequestingIPs`, etc.) for SOC analysts.

***

#### **Customisations and Enhancements**

* **Whitelist Legitimate Activity:**
  *   Exclude known safe accounts or IPs:

      ```spl
      splCopyEdit| search NOT [ | inputlookup known_safe_accounts.csv ]
      ```
* **Time-Based Analysis:**
  * Include `FirstSeen` and `LastSeen` to track attack patterns over time.
* **Dashboard Integration:**
  * Visualize `RequestCount` trends for targeted accounts or create heatmaps of `UniqueIPs`.

***

#### **Additional Considerations**

1. **Correlate with Active Directory Logs:**
   * Combine this query with Event ID **4768** from Windows Security logs for better context.
2. **Validate with Threat Intelligence:**
   * Check `RequestingIPs` against known malicious IPs or threat feeds.
{% endtab %}

{% tab title="Sysmon" %}
{% code overflow="wrap" %}
```splunk-spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| eval AccountName = mvindex(Account_Name, 1)
| where EventCode=4768 AND Status="0x12" // Preauthentication not required
| stats count AS RequestCount, values(IpAddress) AS ClientIPs, dc(IpAddress) AS UniqueIPs BY AccountName
| where RequestCount > 10 OR UniqueIPs > 3 // Adjust thresholds based on your environment
| table _time, AccountName, RequestCount, UniqueIPs, ClientIPs
| sort - RequestCount
```
{% endcode %}

Query performs the following steps:

1. **Filters events** to include only those from the Sysmon index with the specified sourcetype.
2. **Evaluates the AccountName** to identify the target user.
3. **Filters AS-REP requests** (EventCode 4768) where preauthentication is not required (Status="0x12").
4. **Aggregates the data** to count the number of AS-REP requests per AccountName and the number of unique IPs.
5. **Filters the results** to include only those with more than 10 requests or more than 3 unique IPs.
6. **Displays the results** in a table format, sorted by RequestCount.
{% endtab %}
{% endtabs %}
