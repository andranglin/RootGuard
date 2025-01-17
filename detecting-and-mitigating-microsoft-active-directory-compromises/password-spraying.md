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

# Password Spraying

### **Introduction to Password Spraying**

**Password spraying** is a technique used by attackers to gain unauthorized access to user accounts by exploiting weak or commonly used passwords. Unlike traditional brute-force attacks that repeatedly try many passwords on a single account (risking account lockout due to failed attempts), password spraying involves attempting a single password across multiple accounts. This method helps avoid triggering lockout policies, making it a stealthier and more effective attack technique.

Password spraying is categorized under the **Credential Access** tactic in the MITRE ATT\&CK framework (ID: T1110.003) and is frequently used as a precursor to further attacks, such as lateral movement, privilege escalation, or data exfiltration.

***

#### **How Password Spraying Works**

1. **Account Discovery:**
   * Attackers compile a list of valid usernames or email addresses.
   * This can be achieved through OSINT (Open Source Intelligence), compromised databases, or reconnaissance tools.
2. **Weak Password Selection:**
   * Commonly used passwords, such as `Password123`, `Welcome1`, or season/year combinations like `Spring2025`, are selected as attack vectors.
3. **Spraying Process:**
   * A single weak password is tested across multiple accounts.
   * If unsuccessful, another password is selected, avoiding consecutive failed attempts on any single account to evade lockout policies.
4. **Successful Compromise:**
   * Once a valid username-password pair is identified, the attacker gains unauthorized access to the account.
   * They can then escalate privileges or use the account to launch further attacks.

***

#### **Why Password Spraying is Effective**

1. **Avoids Lockouts:**
   * By distributing authentication attempts across many accounts, attackers stay under account lockout thresholds.
2. **Exploits Weak Password Policies:**
   * Organizations with poorly enforced password complexity policies are especially vulnerable.
3. **Large Attack Surface:**
   * Modern organizations with hundreds or thousands of user accounts provide attackers with ample opportunities.
4. **Low Detection Probability:**
   * Spraying attacks mimic normal authentication attempts, making them harder to detect.

***

#### **Indicators of Password Spraying**

1. **High Volume of Failed Logons:**
   * A significant number of failed authentication attempts distributed across multiple accounts within a short timeframe.
2. **Unusual Authentication Sources:**
   * Logon attempts originating from unknown or suspicious IP addresses, especially from geographic locations where the organization has no presence.
3. **Targeting Multiple Accounts:**
   * Logon failures affecting many accounts, often with the same password.
4. **Successful Logons Following Failures:**
   * Successful logons from the same IP after multiple failed attempts suggest spraying success.

***

#### **Mitigation Strategies**

1. **Strong Password Policies:**
   * Enforce password complexity requirements (e.g., length, special characters, and no common passwords).
   * Implement password expiration policies.
2. **Multi-Factor Authentication (MFA):**
   * Require MFA for all user accounts, making password spraying ineffective even if the password is compromised.
3. **Account Lockout Policies:**
   * Configure account lockout settings to limit the number of failed login attempts.
4. **Monitor Authentication Logs:**
   * Continuously analyze logs for patterns of failed and successful logons.
   * Set alerts for unusual logon activity.
5. **Limit Exposure:**
   * Reduce publicly accessible account lists, such as employee directories or email address formats.
6. **User Awareness Training:**
   * Educate users on creating strong passwords and recognizing social engineering techniques.

***

#### **Detection Techniques**

1. **Log Analysis:**
   * Monitor logs for failed login attempts (e.g., Event ID **4625** in Windows).
   * Detect patterns of failures distributed across multiple accounts from the same IP.
2. **Correlation Rules:**
   * Use SIEM solutions (e.g., Splunk, Sentinel) to detect suspicious patterns, such as failed logons from unusual IPs followed by a successful logon.
3. **Geographic Analysis:**
   * Flag logons from locations inconsistent with the user's typical behaviour.
4. **Threat Intelligence Integration:**
   * Cross-reference IP addresses with known malicious actors or threat intelligence feeds.

***

Password spraying remains a prevalent and effective attack method due to its simplicity and the prevalence of weak passwords in many organizations. By understanding how it works and proactively implementing strong defences and monitoring, organizations can significantly reduce their exposure to this attack vector.

KQL Detection Queries

{% tabs %}
{% tab title="Query 1" %}
Query to Detect Password Spraying

{% code overflow="wrap" %}
```kusto
let FailedLogons = SecurityEvent
| where EventID == 4625  // Failed logons
| extend AccountName = tostring(TargetUserName), 
         ClientIP = tostring(IpAddress), 
         FailureReason = tostring(Status)
| summarize FailedAttempts = count(), UniqueAccounts = dcount(AccountName) 
    by ClientIP, bin(TimeGenerated, 15m)  // Group by client IP and 15-minute intervals
| where FailedAttempts > 10 and UniqueAccounts > 5;  // Thresholds for potential spraying

let SuccessfulLogons = SecurityEvent
| where EventID == 4624  // Successful logons
| extend AccountName = tostring(TargetUserName), ClientIP = tostring(IpAddress)
| summarize SuccessfulAttempts = count(), UniqueAccounts = dcount(AccountName) 
    by ClientIP, bin(TimeGenerated, 15m);

FailedLogons
| join kind=inner (SuccessfulLogons) on ClientIP, TimeGenerated
| extend SuspiciousScore = case(
    FailedAttempts > 20 and UniqueAccounts > 10 and SuccessfulAttempts > 5, "High",
    FailedAttempts > 10 and UniqueAccounts > 5, "Medium",
    "Low"
)
| project TimeGenerated, ClientIP, FailedAttempts, SuccessfulAttempts, UniqueAccounts, SuspiciousScore
| where SuspiciousScore in ("High", "Medium")
| sort by SuspiciousScore desc, FailedAttempts desc
```
{% endcode %}

#### **Query Breakdown**

1. **Failed Logons (Event ID 4625):**
   * Captures failed logon events, grouping by `ClientIP` and aggregating failed attempts over 15-minute intervals.
   * Identifies IPs with a high number of failed attempts and multiple targeted accounts:
     * `FailedAttempts > 10`: Adjust based on environment baseline.
     * `UniqueAccounts > 5`: Indicates many accounts were targeted.
2. **Successful Logons (Event ID 4624):**
   * Captures successful logons from the same IPs within the same 15-minute window.
   * Identifies instances where spraying attempts succeeded.
3. **Suspicious Scoring:**
   * Assigns a `SuspiciousScore` based on the severity of activity:
     * **High:** Over 20 failed attempts, more than 10 accounts, and successful logons.
     * **Medium:** Over 10 failed attempts and 5 accounts targeted.
4. **Correlation:**
   * Joins failed logon data with successful logon data using `ClientIP` and `TimeGenerated`.
5. **Final Output:**
   * Displays the client IP, time, number of failed attempts, number of successful attempts, and targeted accounts.
   * Focuses on **High** and **Medium** suspicious activity.

***

#### **Customisations**

1. **Threshold Tuning:**
   * Adjust thresholds (`FailedAttempts > 10`, `UniqueAccounts > 5`) based on the baseline of your environment.
2. **Time Binning:**
   * Modify `bin(TimeGenerated, 15m)` to adjust the time window for detecting spraying.
3. **Exclusions:**
   *   Exclude trusted IPs or service accounts to reduce false positives:

       {% code overflow="wrap" %}
       ```kusto
       | where not (ClientIP in ("trusted_ip1", "trusted_ip2") or AccountName startswith "svc_")
       ```
       {% endcode %}

***

#### **Additional Recommendations**

1. **Alert Configuration:**
   * Set up alerts for `SuspiciousScore = High` to notify SOC analysts.
2. **Dashboard Integration:**
   * Create a visualisation showing failed logon trends, unique accounts targeted, and suspicious IPs.
3. **Threat Intelligence:**
   * Cross-reference `ClientIP` with known malicious IPs from threat intelligence feeds.
{% endtab %}

{% tab title="Query 2" %}
{% code overflow="wrap" %}
```kusto
// Define the time range for the query
let startTime = ago(7d);
let endTime = now();

// Define thresholds for suspicious activity
let Threshold_FailedLogons = 10;
let Threshold_UniqueIPs = 3;
let RareAccountThreshold = 5;

// Step 1: Identify failed logon attempts (Event ID 4625)
let FailedLogons = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4625
| extend AccountName = tostring(TargetUserName), Domain = tostring(TargetDomainName), ClientIP = tostring(IpAddress), FailureReason = tostring(Status)
| project AccountName, Domain, ClientIP, FailureReason, TimeGenerated;

// Step 2: Aggregate failed logon activity
let Aggregated_FailedLogons = FailedLogons
| summarize FailedLogonCount = count(), UniqueIPs = dcount(ClientIP), ClientIPs = make_set(ClientIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AccountName, Domain;

// Step 3: Identify Rare Accounts (Low Authentication Activity)
let RareAccounts = SecurityEvent
| where EventID == 4624 // Successful Logon
| summarize LogonCount = count(), LogonIPs = make_set(IpAddress) by AccountName
| where LogonCount < RareAccountThreshold
| project AccountName, LogonCount, LogonIPs;

// Step 4: Combine Failed Logon Events with Rare Account Info
Aggregated_FailedLogons
| join kind=leftouter (RareAccounts) on AccountName
| extend IsRareAccount = iff(isnull(LogonCount), 1, 0)
| extend SuspiciousScore = case(
    FailedLogonCount > Threshold_FailedLogons and UniqueIPs > Threshold_UniqueIPs and IsRareAccount == 1, 3,
    FailedLogonCount > Threshold_FailedLogons and UniqueIPs > Threshold_UniqueIPs, 2,
    FailedLogonCount > Threshold_FailedLogons or UniqueIPs > Threshold_UniqueIPs, 1,
    0
)
| where SuspiciousScore > 0
| project AccountName, Domain, FailedLogonCount, UniqueIPs, ClientIPs, FirstSeen, LastSeen, IsRareAccount, SuspiciousScore
| sort by SuspiciousScore desc, FailedLogonCount desc
```
{% endcode %}

Query performs the following steps:

1. **Defines the time range** for the query to look back over the past 7 days.
2. **Identifies failed logon attempts** (Event ID 4625) and extracts relevant information.
3. **Aggregates failed logon activity** to count the number of failed logons and unique IPs per account.
4. **Identifies rare accounts** with low authentication activity (Event ID 4624).
5. **Combines failed logon events with rare account information** to calculate a SuspiciousScore based on multiple factors.
6. **Displays the results** in a table format, sorted by SuspiciousScore and FailedLogonCount.
{% endtab %}
{% endtabs %}

Splunk Detection Queries

{% tabs %}
{% tab title="Basic Query" %}
Basic Splunk Query for Password Spraying Detection

{% code overflow="wrap" %}
```splunk-spl
index=windows (EventCode=4625 OR EventCode=4624)
| eval LogonType = case(EventCode=4625, "Failed Logon", EventCode=4624, "Successful Logon")
| stats count AS TotalAttempts, 
        count(eval(EventCode=4625)) AS FailedAttempts, 
        count(eval(EventCode=4624)) AS SuccessfulAttempts, 
        values(AccountName) AS TargetAccounts, 
        dc(AccountName) AS UniqueAccounts, 
        values(IpAddress) AS SourceIPs, 
        dc(IpAddress) AS UniqueSourceIPs 
    BY LogonType, IpAddress
| where FailedAttempts > 10 AND UniqueAccounts > 5  // Threshold: Failed attempts across multiple accounts
| eval SuspiciousScore = case(
    FailedAttempts > 20 AND UniqueAccounts > 10, "High",
    FailedAttempts > 10 AND UniqueAccounts > 5, "Medium",
    true(), "Low"
)
| where SuspiciousScore IN ("High", "Medium")
| table IpAddress, TotalAttempts, FailedAttempts, SuccessfulAttempts, UniqueAccounts, SourceIPs, SuspiciousScore
| sort - SuspiciousScore, -FailedAttempts
```
{% endcode %}

**Query Breakdown**

1. **Filters Relevant Events:**
   * `EventCode=4625`: Failed logons.
   * `EventCode=4624`: Successful logons.
2. **Evaluates Logon Type:**
   * Labels events as "Failed Logon" or "Successful Logon" for clarity.
3. **Aggregates Data:**
   * `FailedAttempts`: Count of failed logons per source IP.
   * `SuccessfulAttempts`: Count of successful logons per source IP.
   * `UniqueAccounts`: Number of distinct accounts targeted by the source IP.
   * `SourceIPs`: IP addresses involved in the activity.
4. **Detects Suspicious Behavior:**
   * Flags source IPs with:
     * More than **10 failed attempts** across **5 or more accounts**.
     * Assigns a "High" or "Medium" **SuspiciousScore** for prioritized analysis.
5. **Excludes Low-Risk Activity:**
   * Focuses only on high or medium risk patterns by filtering out low scores.
{% endtab %}

{% tab title="Advance Query" %}
Advanced Query with Temporal Analysis

{% code overflow="wrap" %}
```kusto
index=windows (EventCode=4625 OR EventCode=4624)
| eval LogonType = case(EventCode=4625, "Failed Logon", EventCode=4624, "Successful Logon")
| bin _time span=15m  // Group events into 15-minute intervals
| stats count AS TotalAttempts, 
        count(eval(EventCode=4625)) AS FailedAttempts, 
        count(eval(EventCode=4624)) AS SuccessfulAttempts, 
        values(AccountName) AS TargetAccounts, 
        dc(AccountName) AS UniqueAccounts, 
        values(IpAddress) AS SourceIPs, 
        dc(IpAddress) AS UniqueSourceIPs 
    BY _time, IpAddress
| where FailedAttempts > 10 AND UniqueAccounts > 5
| eval SuspiciousScore = case(
    FailedAttempts > 20 AND UniqueAccounts > 10, "High",
    FailedAttempts > 10 AND UniqueAccounts > 5, "Medium",
    true(), "Low"
)
| where SuspiciousScore IN ("High", "Medium")
| table _time, IpAddress, TotalAttempts, FailedAttempts, SuccessfulAttempts, UniqueAccounts, SourceIPs, SuspiciousScore
| sort - _time, -SuspiciousScore, -FailedAttempts
```
{% endcode %}

#### **Query Enhancements**

*   **Whitelist Known Sources or Accounts:**

    {% code overflow="wrap" %}
    ```kusto
    | search NOT [ | inputlookup whitelist_ips.csv ]
    ```
    {% endcode %}
* **Threshold Adjustments:**
  * Tune `FailedAttempts > 10` and `UniqueAccounts > 5` based on your environment’s normal behaviour.
* **Include Geolocation:**
  *   Add geographic context to identify activity from unexpected regions:

      {% code overflow="wrap" %}
      ```kusto
      | iplocation IpAddress
      | table IpAddress, Country, Region, City, TotalAttempts, FailedAttempts, SuccessfulAttempts
      ```
      {% endcode %}

***

#### **Recommendations**

1. **Create Alerts:**
   * Trigger alerts for `SuspiciousScore = High` to notify SOC analysts in realtime.
2. **Correlate with Threat Intelligence:**
   * Cross-reference `SourceIPs` with threat feeds to identify known malicious actors.
3. **Build Dashboards:**
   * Visualize password spraying activity trends and affected accounts in a Splunk dashboard.
{% endtab %}
{% endtabs %}

