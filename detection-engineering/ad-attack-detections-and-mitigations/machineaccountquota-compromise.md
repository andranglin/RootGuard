# MachineAccountQuota Compromise

### **Introduction**

**MachineAccountQuota** is an attribute in Active Directory that specifies how many machine accounts a user can create in the domain. By default, this value is set to **10**, meaning any authenticated domain user can create up to 10 machine accounts without administrative privileges. While this setting supports certain use cases, it also introduces a security risk if exploited by attackers.

Compromise of MachineAccountQuota occurs when an attacker abuses this privilege to create unauthorised machine accounts. These accounts can then be used for malicious purposes, such as lateral movement, privilege escalation, or persistence, often bypassing standard account monitoring mechanisms.

This technique is categorised under the **Persistence** and **Credential Access** tactics in the **MITRE ATT\&CK Framework**.

***

### **How MachineAccountQuota Compromise Works**

1. **Discovery:**
   * Attackers first enumerate the domain to identify the current **MachineAccountQuota** setting.
   * This can be done using tools like `PowerShell` or `BloodHound`.
2. **Creating Machine Accounts:**
   * If the quota is greater than **0**, attackers create new machine accounts. These accounts often have names ending with `$` (e.g., `MACHINE01$`).
3. **Abusing Machine Accounts:**
   * Machine accounts are assigned credentials, just like user accounts. Attackers extract the credentials (password hashes) for further use.
   * These accounts may be leveraged to:
     * Perform **lateral movement** within the domain.
     * Bypass monitoring systems that focus on user accounts.
     * Establish **persistence** by hiding malicious activities behind machine accounts.
4. **Further Exploitation:**
   * Attackers may use tools like **Impacket**, **Rubeus**, or **Mimikatz** to dump the machine account's credentials, request Kerberos tickets, or escalate privileges.

***

### **Why MachineAccountQuota Compromise is Dangerous**

1. **Default Configuration Risk:**
   * The default value of 10 allows any authenticated domain user to create machine accounts, significantly expanding the attack surface.
2. **Hard-to-Monitor Accounts:**
   * Machine accounts are often less scrutinised than user accounts, making them ideal for covert operations.
3. **Persistence and Evasion:**
   * Attackers can create machine accounts and use them to maintain access even after compromised user accounts are disabled or locked.
4. **Privilege Escalation:**
   * By controlling machine accounts, attackers can escalate privileges or impersonate legitimate systems.

***

### **Indicators of MachineAccountQuota Compromise**

1. **Unusual Account Creation:**
   * Creation of multiple machine accounts (accounts ending with `$`) by non-administrative users.
2. **High Volume of New Machine Accounts:**
   * A significant number of machine accounts created within a short period.
3. **Suspicious Logon Activity:**
   * Newly created machine accounts logging into sensitive systems or initiating lateral movement.
4. **Abnormal Usage of Machine Accounts:**
   * Machine accounts performing tasks typically associated with user accounts, such as accessing shared resources or running administrative commands.

***

### **Detection Strategies**

1. **Monitor Account Creation Logs:**
   * Windows Event ID **4741**: Logs when a computer account is created.
   * Windows Event ID **4720**: Logs when a user account is created (occasionally relevant if attackers disguise machine accounts as users).
2. **Look for Anomalous Behavior:**
   * Machine accounts (names ending with `$`) logging in from unusual locations or performing abnormal activities.
3. **Audit Active Directory:**
   *   Periodically check the **MachineAccountQuota** setting using PowerShell:

       ```powershell
       powershellCopyEditGet-ADDomain | Select-Object Name, ms-DS-MachineAccountQuota
       ```
4. **Correlate with Threat Intelligence:**
   * Cross-reference newly created accounts with known attack patterns or malicious tools.

***

### **Mitigation Strategies**

1. **Reduce MachineAccountQuota:**
   *   Set `ms-DS-MachineAccountQuota` to **0** for most environments where non-administrative users do not need to create machine accounts:

       ```powershell
       powershellCopyEditSet-ADDomain -Identity "DomainName" -MachineAccountQuota 0
       ```
2. **Restrict Account Creation Rights:**
   * Limit the ability to create machine accounts to specific administrative groups.
3. **Enable Logging and Alerts:**
   * Configure alerts for unusual account creation activity (Event ID 4741).
4. **Audit Existing Machine Accounts:**
   * Regularly review machine accounts to ensure they are legitimate and necessary.
5. **Monitor for Tools and TTPs:**
   * Watch for signs of attacker tools such as BloodHound, Impacket, or Rubeus, which are commonly used to enumerate and exploit Active Directory.

***

The **MachineAccountQuota** feature, while useful in specific scenarios, poses a significant security risk if left misconfigured. By understanding how attackers exploit this setting and implementing proactive detection and mitigation strategies, organisations can better protect their Active Directory environments from compromise.

The **MachineAccountQuota** attribute in Active Directory defines the number of machine accounts a user can create in the domain. Attackers exploit this setting to register new machine accounts and abuse these accounts for lateral movement, persistence, or further exploitation. Detecting **MachineAccountQuota** abuse requires monitoring account creations and anomalous behaviours related to machine accounts.

### KQL Detection  Query

To detect **MachineAccountQuota compromise** using **KQL** in Microsoft Sentinel or other platforms you can monitor for unusual creation of machine accounts (accounts ending with `$`) by non-administrative users. These activities are primarily logged under **Windows Security Event ID 4741** (A computer account was created).

{% tabs %}
{% tab title="Query 1" %}
Query for Detecting MachineAccountQuota Compromise

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4741  // Computer account creation
| extend CreatedAccount = TargetUserName, InitiatorAccount = SubjectUserName
| where CreatedAccount endswith "$"  // Focus on machine accounts
| summarize CreationCount = count(), 
            CreatedAccounts = make_set(CreatedAccount), 
            UniqueInitiators = dcount(InitiatorAccount), 
            Initiators = make_set(InitiatorAccount), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
    by InitiatorAccount
| where CreationCount > 5  // Threshold: Adjust based on baseline activity
| extend SuspiciousScore = case(
    CreationCount > 10, "High",
    CreationCount > 5, "Medium",
    "Low"
)
| where SuspiciousScore in ("High", "Medium")  // Focus on suspicious activity
| project InitiatorAccount, CreationCount, CreatedAccounts, UniqueInitiators, Initiators, FirstSeen, LastSeen, SuspiciousScore
| sort by SuspiciousScore desc, CreationCount desc
```
{% endcode %}

#### **Query Breakdown**

1. **Target Event:**
   * **EventID 4741:** Captures the creation of computer accounts in Active Directory.
2. **Focus on Machine Accounts:**
   * Filters accounts with names ending in `$` (standard naming convention for machine accounts).
3. **Aggregate Data:**
   * Groups activities by the `InitiatorAccount` (the user who created the accounts).
   * Tracks:
     * **CreationCount**: Total number of machine accounts created.
     * **CreatedAccounts**: List of machine accounts created.
     * **UniqueInitiators**: Number of unique users initiating account creation.
     * **Initiators**: Names of users initiating the activity.
4. **Threshold for Suspicion:**
   * Flags users who create more than 5 machine accounts within a specific time period.
   * Assigns a **SuspiciousScore** based on the volume of accounts created:
     * **High:** More than 10 accounts.
     * **Medium:** More than 5 accounts.
5. **Output:**
   * Provides key details for investigation, including the initiator, the created accounts, and the time range of activity.
{% endtab %}

{% tab title="Querty 2" %}
Advanced Query with Temporal Analysis

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4741
| extend CreatedAccount = TargetUserName, InitiatorAccount = SubjectUserName
| where CreatedAccount endswith "$"
| bin TimeGenerated span=15m  // Group events into 15-minute intervals
| summarize CreationCount = count(), CreatedAccounts = make_set(CreatedAccount) 
    by InitiatorAccount, bin(TimeGenerated, 15m)
| where CreationCount > 3  // Adjust based on environment baseline
| extend SuspiciousScore = case(
    CreationCount > 5, "High",
    CreationCount > 3, "Medium",
    "Low"
)
| where SuspiciousScore in ("High", "Medium")
| project TimeGenerated, InitiatorAccount, CreationCount, CreatedAccounts, SuspiciousScore
| sort by TimeGenerated, SuspiciousScore desc, CreationCount desc
```
{% endcode %}

#### **Customisations**

1. **Whitelist Known Legitimate Activity:**
   *   Exclude trusted service accounts or administrators:

       {% code overflow="wrap" %}
       ```kusto
       | where not (InitiatorAccount in ("trusted_admin", "service_account"))
       ```
       {% endcode %}
2. **Tune Thresholds:**
   * Adjust thresholds for `CreationCount` and `TimeGenerated` based on your environment’s baseline.
3. **Correlate with Other Events:**
   * Combine this query with events like **logon activity** (Event ID 4624) or **privilege escalation** to detect related malicious behaviour.

***

#### **Additional Recommendations**

1. **Audit MachineAccountQuota Settings:**
   *   Periodically check the `ms-DS-MachineAccountQuota` value in your domain:

       {% code overflow="wrap" %}
       ```powershell
       Get-ADDomain | Select-Object Name, ms-DS-MachineAccountQuota
       ```
       {% endcode %}
2. **Enable Alerts:**
   * Configure alerts for `SuspiciousScore = High` to notify SOC analysts of potential abuse.
3. **Dashboard Integration:**
   * Visualize trends in machine account creation for proactive monitoring.
{% endtab %}
{% endtabs %}

### Splunk Detection Query

The **MachineAccountQuota** attribute in Active Directory defines the number of machine accounts a user can create in the domain. Attackers exploit this setting to register new machine accounts and abuse these accounts for lateral movement, persistence, or further exploitation. Detecting **MachineAccountQuota** abuse requires monitoring account creations and anomalous behaviours related to machine accounts.

{% tabs %}
{% tab title="First Tab" %}
Splunk Query for MachineAccountQuota Compromise Detection

{% code overflow="wrap" %}
```splunk-spl
index=windows EventCode=4741 OR EventCode=4720
| eval AccountName = coalesce(TargetUserName, AccountName)
| eval EventDescription = case(
    EventCode == 4741, "Computer Account Created",
    EventCode == 4720, "User Account Created",
    true(), "Unknown Event"
)
| stats count AS CreationCount, 
        values(EventDescription) AS EventTypes, 
        values(AccountName) AS CreatedAccounts, 
        values(CallerUserName) AS Initiators, 
        dc(AccountName) AS UniqueCreatedAccounts, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY CallerUserName
| where UniqueCreatedAccounts > 5  // Threshold: High volume of account creations
| eval SuspiciousActivity = case(
    UniqueCreatedAccounts > 10, "High",
    UniqueCreatedAccounts > 5, "Medium",
    true(), "Low"
)
| where SuspiciousActivity IN ("High", "Medium")
| table CallerUserName, CreationCount, UniqueCreatedAccounts, CreatedAccounts, EventTypes, FirstSeen, LastSeen, SuspiciousActivity
| sort - SuspiciousActivity, -CreationCount
```
{% endcode %}

#### **Query Breakdown**

1. **Target Events:**
   * **EventCode 4741:** Logs when a computer account is created.
   * **EventCode 4720:** Logs when a user account is created. This helps identify any abuse disguised as user account creation.
   * **EventCode 4624:** This event is generated when an object successfully logs on
   * **EventCode 4724:** This event is generated when an attempt is made to reset an object’s password.
2. **Field Normalisation:**
   * Combines `TargetUserName` and `AccountName` to identify the newly created accounts.
   * Tracks the `CallerUserName`, which is the initiator of the account creation.
3. **Event Grouping:**
   * Aggregates account creation events by the initiator (`CallerUserName`).
   * Captures the number of unique accounts created (`UniqueCreatedAccounts`) and the types of events involved (`EventTypes`).
4. **Suspicious Thresholds:**
   * Flags initiators creating more than **5 unique accounts** as potentially suspicious.
   * Assigns **"High"** severity if more than 10 accounts are created in a short timeframe.
5. **Final Output:**
   * Displays key details for investigation:
     * **CallerUserName**: Who created the accounts.
     * **CreatedAccounts**: The accounts that were created.
     * **EventTypes**: Types of events (computer or user account creations).
     * **SuspiciousActivity**: Risk level based on the volume of account creations.
{% endtab %}

{% tab title="Second Tab" %}
Advanced Query with Temporal Analysis

{% code overflow="wrap" %}
```splunk-spl
index=windows EventCode=4741 OR EventCode=4720
| eval AccountName = coalesce(TargetUserName, AccountName)
| bin _time span=15m  // Group events into 15-minute intervals
| stats count AS CreationCount, 
        values(AccountName) AS CreatedAccounts, 
        dc(AccountName) AS UniqueCreatedAccounts 
    BY CallerUserName, _time
| where UniqueCreatedAccounts > 3  // Adjust based on environment baseline
| eval SuspiciousActivity = case(
    UniqueCreatedAccounts > 5, "High",
    UniqueCreatedAccounts > 3, "Medium",
    true(), "Low"
)
| where SuspiciousActivity IN ("High", "Medium")
| table _time, CallerUserName, CreationCount, UniqueCreatedAccounts, CreatedAccounts, SuspiciousActivity
| sort - _time, -SuspiciousActivity, -CreationCount

```
{% endcode %}

#### **Customisations**

1. **Threshold Tuning:**
   * Adjust `UniqueCreatedAccounts > 5` based on normal activity in your domain.
   * Fine-tune `bin _time span=15m` to capture short bursts of activity.
2. **Whitelist Legitimate Activity:**
   *   Exclude known service accounts or administrators:

       {% code overflow="wrap" %}
       ```kusto
       | where NOT CallerUserName IN ("trusted_admin", "service_account")
       ```
       {% endcode %}
3. **Account Filtering:**
   *   Focus specifically on machine accounts (accounts ending with `$`):

       ```kusto
       | where like(AccountName, "%$")
       ```

***

#### **Additional Recommendations**

1. **Audit MachineAccountQuota Settings:**
   *   Regularly check the `ms-DS-MachineAccountQuota` setting in your Active Directory:

       {% code overflow="wrap" %}
       ```powershell
       Get-ADDomain | Select-Object Name, ms-DS-MachineAccountQuota
       ```
       {% endcode %}
2. **Correlate with Other Events:**
   * Look for lateral movement or privilege escalation attempts following the creation of machine accounts.
3. **Create Alerts:**
   * Configure alerts in Splunk for **"High" SuspiciousActivity**.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
