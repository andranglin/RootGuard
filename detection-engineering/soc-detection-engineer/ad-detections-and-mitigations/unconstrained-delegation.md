# Unconstrained Delegation

### **Introduction**

**Unconstrained delegation** is a feature in Microsoft Active Directory (AD) that allows a server or service to impersonate any user who authenticates to it. This is done by granting the server access to the user's Kerberos **Ticket-Granting Tickets (TGTs)**, which are stored in memory. While designed to support scenarios where a service needs to act on behalf of a user across multiple resources, unconstrained delegation introduces significant security risks if misconfigured or exploited by attackers.

Unconstrained delegation is classified under the **Credential Access** and **Privilege Escalation** tactics in the **MITRE ATT\&CK Framework**, as it allows attackers to elevate privileges, impersonate users, and move laterally within a network.

***

### **How Unconstrained Delegation Works**

1. **Kerberos Delegation Overview:**
   * In Kerberos authentication, a **TGT** is issued to users, allowing them to request service tickets without re-entering credentials.
   * Delegation allows a service or computer to use a user's credentials to access other services on their behalf.
2. **Unconstrained Delegation Mechanism:**
   * When unconstrained delegation is enabled, a server or service receives the TGT of any user who authenticates to it.
   * The server can then use the TGT to impersonate the user and access other resources in the domain.
3. **Misuse by Attackers:**
   * If attackers compromise a machine or service account with unconstrained delegation, they can extract TGTs from memory using tools like **Mimikatz**.
   * Extracted TGTs enable attackers to impersonate domain users, including **Domain Admins**, and move laterally within the network.

***

### **Risks Associated with Unconstrained Delegation**

1. **Exposure of TGTs:**
   * Any TGT stored in memory on an unconstrained delegation-enabled system is at risk of being stolen.
2. **Privilege Escalation:**
   * If high-privilege accounts (e.g., Domain Admins) authenticate to an unconstrained delegation-enabled service, their TGTs can be used to escalate privileges.
3. **Lateral Movement:**
   * Attackers can use the stolen TGTs to impersonate users and access other systems or resources in the domain.
4. **Stealthy Persistence:**
   * Attackers can maintain access by exploiting unconstrained delegation-enabled systems without modifying existing user accounts.

***

### **How Attackers Exploit Unconstrained Delegation**

1. **Environment Discovery:**
   * Attackers enumerate domain objects to identify computers or services with unconstrained delegation enabled. This can be done using tools like **BloodHound** or PowerShell commands.
   *   For example:

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
       </code></pre>
2. **Compromise Target System:**
   * The attacker compromises a machine or service account configured for unconstrained delegation.
3. **Extract TGTs:**
   * Using tools like **Mimikatz**, the attacker dumps the TGTs of users who authenticated to the system.
4. **Impersonate Users:**
   * The attacker uses the stolen TGTs to impersonate domain users, including privileged accounts.

***

### **Indicators of Unconstrained Delegation Abuse**

1. **Unusual Logons:**
   * Logon events (Event ID **4624**) from service accounts or machines configured for unconstrained delegation.
2. **Abnormal Account Usage:**
   * Service accounts or computers accessing resources they typically do not interact with.
3. **Enumeration Activities:**
   * Attackers running commands or tools to identify unconstrained delegation-enabled systems.
4. **Kerberos TGT Requests:**
   * Multiple Kerberos TGT requests (Event ID **4768**) from a single source.

***

### **Mitigation Strategies**

1. **Restrict Delegation:**
   * Avoid enabling unconstrained delegation whenever possible. Use **constrained delegation** or **resource-based constrained delegation (RBCD)** instead.
2. **Audit and Monitor:**
   *   Regularly audit domain controllers, servers, and service accounts for unconstrained delegation:

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
       </code></pre>
3. **Network Segmentation:**
   * Segregate high-value resources (e.g., domain controllers) from systems configured for delegation.
4. **Log and Monitor for Anomalies:**
   * Monitor for Kerberos ticket requests, especially TGT requests from unconstrained delegation-enabled systems.
5. **Protect Privileged Accounts:**
   * Ensure privileged accounts like Domain Admins do not log into systems configured for unconstrained delegation.
6. The following security controls should be implemented to mitigate unconstrained delegation:&#x20;
   * Ensure computer objects are not configured for unconstrained delegation. If delegation is required for a computer object, use resource-based constrained delegation instead.
   * Ensure privileged user objects are configured as ‘sensitive and cannot be delegated’. This can be configured by using the ‘Account is sensitive and cannot be delegated’ option on the user object in Active Directory Users and Computers.
   * Ensure privileged user objects are members of the Protected Users security group. Members of this security group cannot be delegated.&#x20;
   * Disable the Print Spooler service on Domain Controllers. This prevents the Print Spooler service from being used to coerce a Domain Controller into authenticating to another system.

***

### **Detection Techniques**

1. **Identify Systems with Unconstrained Delegation:**
   * Query Active Directory for machines and accounts with the `TrustedForDelegation` attribute enabled.
2. **Monitor TGT Access:**
   * Detect suspicious access to Kerberos TGTs using Event IDs **4768**, **4769**, and **4624**.
3. **Logon Monitoring:**
   * Flag unexpected logons from accounts or services configured for delegation.
4. Events that detect an unconstrained delegation compromise:
   * **Event ID 4103:** Event generated when PowerShell executes and logs pipeline execution details.
   * **Event ID 4104:** Event generated when PowerShell executes code to capture scripts and commands.
   * **Event ID 4624:** Event generated when malicious actors need to authenticate to a computer object configured for unconstrained delegation.
   * **Event ID 4688:** Event generated when a new process is created, such as extracting TGTs from the LSASS process (this is commonly done using malicious tools)
   * **Event ID 4770:** Event generated when a TGT is renewed. By default, TGTs have a maximum lifetime of seven days; however, malicious actors may choose to renew a TGT to extend its lifetime.

***

Unconstrained delegation is a powerful feature but poses significant security risks when misconfigured or exploited. By understanding how it works, recognising its risks, and implementing proper controls, organisations can minimise their exposure to delegation-based attacks. Proactive auditing, monitoring, and replacing unconstrained delegation with more secure alternatives (e.g., constrained delegation) are essential steps to strengthen Active Directory security.

### KQL Detection Queries

To detect systems or accounts with **Unconstrained Delegation** in Active Directory using **KQL** in Microsoft Sentinel, you can query Active Directory event logs or configuration data. Specifically, you'll look for objects where the **TrustedForDelegation** attribute is set to **true**.

{% tabs %}
{% tab title="Query 1" %}
Query for Unconstrained Delegation Detection

{% code overflow="wrap" %}
```kusto
// Define the time range for the query
let startTime = ago(7d);
let endTime = now();

// Step 1: Identify systems with unconstrained delegation enabled
let UnconstrainedDelegationSystems = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4742 // Event ID for "A computer account was changed"
| extend AccountName = tostring(TargetUserName), DelegationFlag = tostring(Attributes)
| where DelegationFlag contains "TRUSTED_FOR_DELEGATION"
| project AccountName, TimeGenerated;

// Step 2: Monitor TGT requests from unconstrained delegation systems
let TGTRequests = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4768 // Event ID for "A Kerberos authentication ticket (TGT) was requested"
| extend AccountName = tostring(TargetUserName), ClientIP = tostring(IpAddress)
| project AccountName, ClientIP, TimeGenerated;

// Step 3: Combine the results to identify suspicious activity
UnconstrainedDelegationSystems
| join kind=inner (TGTRequests) on AccountName
| summarize TGTRequestCount = count(), UniqueIPs = dcount(ClientIP), ClientIPs = make_set(ClientIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AccountName
| where TGTRequestCount > 5 // Adjust threshold based on your environment
| project AccountName, TGTRequestCount, UniqueIPs, ClientIPs, FirstSeen, LastSeen
| sort by TGTRequestCount desc

```
{% endcode %}

Query performs the following steps:

1. **Identifies systems** with unconstrained delegation enabled by looking for Event ID 4742.
2. **Monitors TGT requests** from these systems by looking for Event ID 4768.
3. **Combines the results** to identify suspicious activity, such as multiple TGT requests from unique IPs.
{% endtab %}

{% tab title="Query 2" %}
Query for Unconstrained Delegation Detection

{% code overflow="wrap" %}
```kusto
// Query for systems or accounts configured with unconstrained delegation
SecurityEvent
| where EventID == 4742  // Event ID 4742: A computer account was changed
| extend ModifiedAccount = TargetUserName, 
         InitiatorAccount = SubjectUserName, 
         AttributeChanged = tostring(EventData.AttributeName)
| where AttributeChanged == "TrustedForDelegation"  // Focus on delegation changes
| summarize Count = count(), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated), 
            ModifiedAccounts = make_set(ModifiedAccount), 
            Initiators = make_set(InitiatorAccount)
    by Computer
| where Count > 0
| project Computer, ModifiedAccounts, Initiators, Count, FirstSeen, LastSeen
| order by LastSeen desc
```
{% endcode %}

#### **Explanation of the Query**

1. **Target Event ID 4742:**
   * Event ID **4742** logs changes to a computer account in Active Directory.
   * Look for modifications to the **TrustedForDelegation** attribute.
2. **Filter for Delegation Changes:**
   * Focus on events where the `TrustedForDelegation` attribute is modified, indicating that unconstrained delegation was enabled.
3. **Summarize Data:**
   * Group by `Computer` to identify systems where delegation has been configured.
   * Track:
     * `ModifiedAccounts`: Accounts that were modified.
     * `Initiators`: Users or accounts that made the changes.
     * `FirstSeen` and `LastSeen`: Time range of the changes.
4. **Project Key Fields:**
   * Display the computer name, affected accounts, initiators, and timestamps for SOC analysts to investigate further.
{% endtab %}

{% tab title="Query 3" %}
#### **Query for Enumerating Existing Unconstrained Delegation Configurations**

If you want to query existing configurations instead of tracking changes:

{% code overflow="wrap" %}
```kusto
AADDomainServicesSigninLogs
| where TimeGenerated >= ago(30d)
| where isnotempty(DeviceTrustLevel)  // Attribute related to trust configurations
| extend TrustedForDelegation = case(
    DeviceTrustLevel contains "Delegation", true,
    DeviceTrustLevel !contains "Delegation", false
)
| where TrustedForDelegation == true
| summarize Count = count(), 
            AffectedDevices = make_set(DeviceName), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated)
| project AffectedDevices, Count, FirstSeen, LastSeen
| order by Count desc
```
{% endcode %}

#### **Customisations**

1. **Audit Unconstrained Delegation Configurations:**
   *   Use PowerShell to query all systems with `TrustedForDelegation` enabled:

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
       </code></pre>
2. **Whitelist Trusted Systems:**
   *   Exclude known safe systems or accounts:

       ```kql
       kqlCopyEdit| where Computer !in ("DC1", "TrustedService")
       ```
3. **Correlate with TGT Requests:**
   * Combine this query with Event IDs **4768** and **4769** (Kerberos ticket activity) to identify TGT usage from unconstrained delegation-enabled systems.

***

#### **Detection Recommendations**

* **Alerts:**
  * Set up alerts to notify SOC analysts whenever a system or account is configured for unconstrained delegation.
* **Dashboards:**
  * Build dashboards to monitor delegation changes and analyze trends.
* **Continuous Monitoring:**
  * Regularly query and audit Active Directory for misconfigured or unnecessary delegation settings.
{% endtab %}
{% endtabs %}

### Splunk Detection Queries

To detect **Unconstrained Delegation** in Splunk, you can query Windows Event Logs for specific configurations or changes in the **TrustedForDelegation** attribute. These changes are typically logged under **Event ID 4742** (A computer account was changed) and **Event ID 5136** (Directory Service Object Modified).

{% tabs %}
{% tab title="Query 1" %}
Splunk Query to Detect Unconstrained Delegation Changes

{% code overflow="wrap" %}
```spl
index=windows (EventCode=4742 OR EventCode=5136)
| eval ModifiedAccount = coalesce(TargetUserName, ObjectName), 
        InitiatorAccount = coalesce(SubjectUserName, UserID), 
        ChangedAttribute = case(
            EventCode == 4742, "TrustedForDelegation",
            EventCode == 5136, AttributeName,
            true(), "Unknown"
        )
| where ChangedAttribute="TrustedForDelegation"
| stats count AS ChangeCount, 
        values(ModifiedAccount) AS ModifiedAccounts, 
        values(InitiatorAccount) AS Initiators, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName
| where ChangeCount > 0
| table ComputerName, ModifiedAccounts, Initiators, ChangeCount, FirstSeen, LastSeen
| sort - LastSeen
```
{% endcode %}

#### **Explanation of the Query**

1. **Target Events:**
   * **EventCode=4742:** Logs changes to computer accounts in Active Directory.
   * **EventCode=5136:** Captures modifications to directory objects, such as the **TrustedForDelegation** attribute.
2. **Attribute Filtering:**
   * Focus on changes where the `TrustedForDelegation` attribute is modified.
3. **Field Extraction:**
   * `ModifiedAccount`: The account or object whose delegation setting was changed.
   * `InitiatorAccount`: The user or account that initiated the change.
4. **Summarize and Aggregate:**
   * Count the number of delegation changes (`ChangeCount`).
   * Group by `ComputerName` to identify affected systems.
   * Capture the first and last modification times (`FirstSeen`, `LastSeen`).
5. **Filter and Present:**
   * Exclude results with no delegation changes (`ChangeCount > 0`).
   * Display key details for SOC analysts to investigate further.
{% endtab %}

{% tab title="Query 2" %}
#### **Advanced Splunk Query for Enumerating Existing Unconstrained Delegation Configurations**

To list all systems or accounts with unconstrained delegation enabled:

{% code overflow="wrap" %}
```spl
index=windows EventCode=5136
| eval ModifiedAccount = coalesce(TargetUserName, ObjectName), 
        InitiatorAccount = coalesce(SubjectUserName, UserID)
| search AttributeName="TrustedForDelegation" AttributeValue="True"
| stats count AS TotalDelegationEnabled, 
        values(ModifiedAccount) AS DelegatedAccounts, 
        values(InitiatorAccount) AS Initiators, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName
| where TotalDelegationEnabled > 0
| table ComputerName, DelegatedAccounts, Initiators, TotalDelegationEnabled, FirstSeen, LastSeen
| sort - TotalDelegationEnabled

```
{% endcode %}

#### **Customisations**

1. **Whitelist Trusted Systems:**
   *   Exclude known safe systems (e.g., trusted services or domain controllers):

       <pre class="language-splunk-spl" data-overflow="wrap"><code class="lang-splunk-spl">| search NOT ComputerName IN ("TrustedDC1", "TrustedAppServer")
       </code></pre>
2. **Thresholds for Suspicious Activity:**
   *   Add thresholds for excessive delegation changes:

       ```spl
       splCopyEdit| where ChangeCount > 5
       ```
3. **Time-Based Grouping:**
   *   To detect bursts of delegation changes, group events into time intervals:

       ```spl
       splCopyEdit| bin _time span=15m
       ```

***

#### **Detection Recommendations**

1. **Set Alerts:**
   * Create alerts to notify when unconstrained delegation is enabled, particularly on sensitive systems or accounts.
2. **Monitor Kerberos Activity:**
   * Combine this query with Kerberos-related Event IDs (**4768**, **4769**) to detect suspicious ticket activity from delegation-enabled systems.
3. **Audit Active Directory:**
   *   Regularly review systems with `TrustedForDelegation` enabled using:

       <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
       </code></pre>

***

#### **Key Events for Context**

* **Event ID 4742:** Logs changes to computer accounts, including delegation-related attributes.
* **Event ID 5136:** Captures directory object modifications, including the `TrustedForDelegation` attribute.
* **Event IDs 4768 & 4769:** Can provide context for Kerberos activity initiated by delegation-enabled accounts.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
