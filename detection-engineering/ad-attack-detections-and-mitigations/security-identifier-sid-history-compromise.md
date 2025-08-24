# Security Identifier (SID) History Compromise

### **Introduction**

In Microsoft Active Directory (AD), the **Security Identifier (SID) History** attribute is used to maintain a record of SIDs from previous domains when objects like users or groups are migrated. This allows users to retain access to resources in the original domain without requiring reconfiguration. While SID History is essential for seamless domain migrations and consolidations, it can be exploited in a **SID History Compromise** attack.

Every object in AD DS has a unique and immutable SID that AD DS uses to identify the object and determine its privileges when accessing systems, services and resources. As usernames can be changed, AD DS relies on the SID to distinguish between objects to ensure that the correct access is provided to an object. In addition to the ‘SID’ attribute, there is the ‘sIDHistory’ attribute which stores previous SIDs. If a SID is changed, for example, when an object is migrated from one domain to another, the object will be given a new SID and its previous SID will be stored in the ‘sIDHistory’ attribute.

Attackers who compromise an account with privileged access, such as a domain administrator, can inject arbitrary SIDs, including those of privileged groups like "Domain Admins" or "Enterprise Admins," into the SID History attribute of another account. This grants the attacker unauthorized access to resources and privileges across domains, bypassing standard access controls.

***

### **Attack Description**

Threat actors can exploit the SID History functionality to establish persistence and hide in an AD DS environment. This technique is performed after the attacker achieves initial access and privilege escalation and requires administrator privileges to a Domain Controller. With this access, malicious actors can add a SID to the sIDHistory of an object they control. The SID added to the ‘sIDHistory’ attribute is typically from a privileged user object or security group, such as the default administrator user object or the Domain Admins security group.

A **SID History Compromise** attack typically involves:

1. **Privilege Escalation**: The attacker compromises an account with sufficient privileges to modify SID History attributes (e.g., a domain administrator account).
2. **SID Injection**: Using tools like Mimikatz, the attacker injects a privileged SID (e.g., Domain Admins SID) into the SID History attribute of a low-privileged user or service account.
3. **Access Resources**: The compromised account now inherits the permissions associated with the injected SID, allowing unauthorized access to resources or escalation of privileges.
4. **Stealth and Persistence**: Since SID History is an attribute tied to AD objects, the attack can persist unless the attribute is thoroughly audited.

SID History compromise is dangerous because it bypasses traditional privilege monitoring, focusing on assigned roles rather than inherited permissions.

***

### **Detection Techniques**

1. **Monitor for Changes in SID History**:
   * Use audit logs to detect modifications to the SID History attribute. Changes should be rare and correlate with legitimate migration activities.
   * Event ID 5136 (Directory Service Object Modification) in AD logs can track changes to attributes like SID History.
2. **Detect Unusual Privileged Access**:
   * Identify non-privileged accounts accessing resources typically restricted to administrators.
   * Look for anomalous account logons or access patterns.
3. **Correlate Account Privileges**:
   * Compare an account's explicit group membership against inherited permissions from SID History. Sudden elevation in access can indicate abuse.
4.  **Events that Detect a SID History Compromise:**

    Source of events: Domain Controllers

    * **Event ID 1102:** Events generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if a Domain Controller has been compromised.
    * **Event ID 4103:** Events generated when PowerShell executes and logs pipeline execution details. Common malicious tools used to execute a SID History compromise, such as Mimikatz, use PowerShell. Analysing this event for PowerShell execution relating to SID History may indicate dumping of the ntds.dit file.
    * **Event ID 4104:** Events generated when PowerShell executes code to capture scripts and commands. Common malicious tools used to execute a SID History compromise, such as Mimikatz, use PowerShell. Analysing this event for PowerShell execution relating to SID History may indicate dumping of the ntds.dit file.
    * **Events ID 4675:** Events generated when SIDs are filtered. Domain hopping with Golden Tickets and SID History may use SIDs that get filtered. If this event is generated, it may indicate a SID History compromise has been attempted.
    * **Event ID 4738:** Events generated when the ‘sIDHistory’ attribute is modified for a user object.
5. **Analyse Logon Sessions**:
   * Track Event ID 4624 (Logon Success) and correlate with resource access logs to detect unauthorised use of inherited permissions.

***

### **Mitigation Techniques**

1. **Restrict Access to Modify SID History**:
   * Limit permissions to modify SID History attributes to a small, trusted group of administrators.
   * Regularly review and validate permissions using tools like `dsacls`.
2. **Enable Advanced Auditing**:
   * Enable auditing for directory service changes to capture SID History modifications (Event ID 5136).
   * Centralise logs in a SIEM solution for continuous monitoring.
3. **Regularly Audit SID History**:
   * Use scripts or tools to identify accounts with unexpected or privileged SIDs in their SID History.
   * Remove unnecessary SIDs from the attribute after verifying resource access requirements.
4. **Deploy Conditional Access and MFA**:
   * Use conditional access policies to restrict privileged account usage and enforce Multi-Factor Authentication (MFA) for all administrative actions.
5. **Monitor and Detect Anomalies**:
   * Employ User and Entity Behavior Analytics (UEBA) to detect unusual privilege escalation or resource access patterns.
   * Analyse historical data to establish baselines for normal account behaviour.
6. **Harden Domain Controllers**:
   * Restrict direct access to domain controllers and enforce stringent security policies to minimise the risk of compromise.
7. **The following security controls should be implemented to mitigate a SID History compromise:**
   * Ensure the ‘sIDHistory’ attribute is not used. Unless migrating user objects from one domain to another, the ‘sIDHistory’ attribute should not be required. If no user objects are configured with this attribute, then a SID History compromise is not possible.
   * Ensure the ‘sIDHistory’ attribute is checked weekly. Malicious actors may add a value to the ‘sIDHistory’ attribute of a user object they control to establish persistence. Regularly checking for this attribute on Active Directory objects may increase detection of this persistence strategy.
   * Enable SID Filtering for domain and forest trusts. This prevents SIDs of built-in security groups, such as Domain Admins and Enterprise Admins, being used in TGTs across domains. However, malicious actors can still use the SIDs of other security groups if the Relative Identifier is greater than 1000.

***

By monitoring and auditing the use of SID History, organisations can reduce the risk of compromise, detect unauthorised changes promptly, and maintain a secure AD environment. These practices also mitigate the persistence and impact of SID History-related attacks.

### KQL Detection Queries

**The following KQL queries** detect potential **Security Identifier (SID) History Compromise** activity in Microsoft Sentinel. This query focuses on monitoring changes to the SID History attribute, unusual access patterns, and privilege escalation using inherited permissions.

{% tabs %}
{% tab title="Query 1" %}
KQL Query for Detecting SID History Compromise

{% code overflow="wrap" %}
```kusto
// Step 1: Detect Changes to the SID History Attribute
let SIDHistoryChanges = AuditLogs
| where OperationName == "Modify Directory Object"
| where TargetResources contains "SIDHistory"  // Attribute changes related to SID History
| extend ChangedBy = tostring(parse_json(InitiatedBy).user.userPrincipalName), 
         TargetAccount = tostring(parse_json(TargetResources[0]).userPrincipalName),
         SIDHistoryChangeDetails = tostring(parse_json(TargetResources[0]).modifiedProperties)
| project TimeGenerated, ChangedBy, TargetAccount, SIDHistoryChangeDetails;

// Step 2: Detect Unusual Privileged Access
let PrivilegedAccess = SecurityEvent
| where EventID == 4672  // Special privilege logon
| where TargetUserName != "Administrator"  // Exclude expected privileged accounts
| extend SuspiciousPrivilege = case(
    Privileges contains "SeTakeOwnershipPrivilege" or Privileges contains "SeBackupPrivilege", true, false)
| where SuspiciousPrivilege
| project TimeGenerated, AccountName, Privileges, IpAddress, LogonType;

// Step 3: Correlate Unusual SID Usage
let UnusualSIDUsage = SecurityEvent
| where EventID == 4624  // Logon Success
| where TargetUserName !endswith "$"  // Exclude machine accounts
| extend SIDDetails = parse_json(AdditionalInfo)
| where SIDDetails contains "SIDHistory"
| project TimeGenerated, TargetUserName, IpAddress, WorkstationName, SIDDetails;

// Step 4: Correlate All Suspicious Activities
SIDHistoryChanges
| join kind=inner (PrivilegedAccess) on $left.ChangedBy == $right.AccountName
| join kind=inner (UnusualSIDUsage) on $left.TargetAccount == $right.TargetUserName
| summarize Count = count(), PrivilegeCount = countif(Privileges != ""), SIDUsageCount = countif(SIDDetails != "") by ChangedBy, TargetAccount, Privileges, SIDDetails, IpAddress
| where Count > 1
| project TimeGenerated, ChangedBy, TargetAccount, Privileges, SIDDetails, IpAddress, Count
| order by Count desc
```
{% endcode %}

#### **Explanation of the Query**

1. **Detect Changes to SID History Attribute**:
   * Tracks attribute modifications (`OperationName == "Modify Directory Object"`) in the `AuditLogs`.
   * Filters for changes related to the `SIDHistory` attribute and captures details of the change, the initiating user, and the target account.
2. **Monitor Privileged Access**:
   * Monitors Event ID 4672 (Special Privilege Logon) to detect accounts using elevated privileges.
   * Flags specific privileges such as `SeTakeOwnershipPrivilege` or `SeBackupPrivilege` often associated with SID History abuse.
3. **Correlate SID Usage**:
   * Looks for logon events (Event ID 4624) with `SIDHistory` attributes in the `AdditionalInfo` field.
   * Tracks accounts leveraging inherited permissions via SID History.
4. **Correlate Suspicious Activities**:
   * Joins all three datasets to surface accounts involved in suspicious SID History modifications, privilege escalation, and SID usage.
5. **Threshold and Aggregation**:
   * Highlights accounts with more than one correlated activity, flagging them for further investigation.

***

#### **Customisations**

* Replace specific privileges (`SeTakeOwnershipPrivilege`, `SeBackupPrivilege`) with others based on your environment.
* Adjust the `Count > 1` threshold for correlating activities to align with your organisation’s baseline behaviour.
* Include additional filtering for sensitive accounts or groups (e.g., `Domain Admins`).

***

#### **Output**

The query provides details on:

* The user making changes to the `SIDHistory` attribute.
* The target account and associated privileges or SIDs used.
* The IP address and logon type involved in the activity.

#### **Usage**

This query is ideal for integration into Microsoft Sentinel dashboards or alerting workflows, enabling proactive detection and response to **SID History Compromise** activities.
{% endtab %}

{% tab title="Query 2" %}
A KQL query to detect potential Security Identifier (SID) History Compromise activities by monitoring specific event IDs that are indicative of such activities:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (1102, 4103, 4104, 4675, 4738)
| extend EventDescription = case(
    EventID == 1102, "Security audit log cleared",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
    EventID == 4675, "SID filtering",
    EventID == 4738, "SID History attribute modified",
    "Unknown Event"
)
| project TimeGenerated, EventID, EventDescription, Computer, Account, LogonType, LogonProcessName, IpAddress, IpPort
| sort by TimeGenerated desc
```
{% endcode %}

Query helps identify events related to a potential SID History Compromise by monitoring key event IDs and providing relevant details for further investigation.
{% endtab %}

{% tab title="Query 3" %}
Advanced KQL Query for Detecting SID History Compromise

The following is a more **advanced KQL query** to detect potential **Security Identifier (SID) History Compromise**. This version enhances detection by correlating multiple suspicious activities, including SID history modifications, privilege escalations, unusual logon patterns, and high-value account usage.

{% code overflow="wrap" %}
```kusto
// Step 1: Detect Changes to the SID History Attribute
let SIDHistoryChanges = AuditLogs
| where OperationName in ("Modify Directory Object", "Set Directory Object")
| where TargetResources contains "SIDHistory"  // Changes related to SIDHistory attribute
| extend ChangedBy = tostring(parse_json(InitiatedBy).user.userPrincipalName), 
         TargetAccount = tostring(parse_json(TargetResources[0]).userPrincipalName),
         SIDHistoryChangeDetails = tostring(parse_json(TargetResources[0]).modifiedProperties)
| project TimeGenerated, ChangedBy, TargetAccount, SIDHistoryChangeDetails, Result, CorrelationId;

// Step 2: Detect Privileged Account Activity
let PrivilegedAccountActivity = SecurityEvent
| where EventID in (4672, 4728, 4732)  // Privileged logon and group membership changes
| where Privileges contains "SeTakeOwnershipPrivilege" or Privileges contains "SeBackupPrivilege" or Privileges contains "SeRestorePrivilege"
| extend SuspiciousPrivilege = case(
    EventID == 4672, "Privileged Logon Detected",
    EventID in (4728, 4732), "Group Membership Modified",
    "Other")
| project TimeGenerated, AccountName, Privileges, IpAddress, EventID, SuspiciousPrivilege;

// Step 3: Monitor Unusual Logon Activity
let UnusualLogons = SecurityEvent
| where EventID == 4624  // Logon Success
| where LogonType in (3, 10)  // Network or remote logons
| where TargetUserName !endswith "$"  // Exclude machine accounts
| extend SIDDetails = parse_json(AdditionalInfo)
| where SIDDetails contains "SIDHistory"  // Logons leveraging SIDHistory
| project TimeGenerated, TargetUserName, LogonType, IpAddress, WorkstationName, SIDDetails;

// Step 4: Identify High-Value Account Usage
let HighValueAccounts = SecurityEvent
| where EventID in (4624, 4672)  // Logon and special privilege logons
| where TargetUserName in ("Administrator", "Domain Admins", "Enterprise Admins")  // Focus on privileged accounts
| project TimeGenerated, TargetUserName, AccountDomain, IpAddress, Privileges, EventID;

// Step 5: Correlate Suspicious Activities
SIDHistoryChanges
| join kind=inner (PrivilegedAccountActivity) on $left.ChangedBy == $right.AccountName
| join kind=inner (UnusualLogons) on $left.TargetAccount == $right.TargetUserName
| join kind=inner (HighValueAccounts) on $left.TargetAccount == $right.TargetUserName
| summarize Count = count(), PrivilegeCount = countif(EventID == 4672), SIDLogonCount = countif(LogonType in (3, 10)), HighValueAccountCount = countif(TargetUserName in ("Administrator", "Domain Admins", "Enterprise Admins")) by ChangedBy, TargetAccount, Privileges, SIDDetails, IpAddress
| where Count > 2  // Only show accounts with multiple suspicious activities
| project TimeGenerated, ChangedBy, TargetAccount, Privileges, SIDDetails, IpAddress, Count, PrivilegeCount, SIDLogonCount, HighValueAccountCount
| order by Count desc
```
{% endcode %}

#### **Enhancements in This Query**

1. **Multiple Event Types**:
   * Tracks a broader range of events, including:
     * **SIDHistory attribute modifications** (from `AuditLogs`).
     * **Privileged logons** and **group membership changes** (Event IDs `4672`, `4728`, `4732`).
     * **Logons using SIDHistory** (Event ID `4624` with `SIDDetails` attribute).
2. **Behavioral Correlation**:
   * Correlates changes to `SIDHistory` with logon activity, privilege escalation, and usage of high-value accounts.
3. **Focused Monitoring**:
   * Flags usage of sensitive privileges (`SeTakeOwnershipPrivilege`, `SeBackupPrivilege`, etc.) and access to high-value accounts (`Domain Admins`, `Enterprise Admins`).
4. **Threshold for Alerting**:
   * Highlights accounts involved in **multiple suspicious activities** (`Count > 2`), reducing false positives.

***

#### **Customisations**

* **Privilege List**: Expand or modify privileges of interest based on your organisation's environment (e.g., `SeDebugPrivilege`).
* **High-Value Accounts**: Update the list of privileged accounts to include environment-specific critical accounts.
* **Thresholds**: Adjust the `Count > 2` threshold based on activity baselines.

***

#### **Output**

The query provides:

* Details of the user modifying the `SIDHistory` attribute (`ChangedBy`).
* The account that was targeted for modification (`TargetAccount`).
* Privileges used, IP addresses involved, and any SID-related details.
* Counts of correlated suspicious activities for prioritisation.

***

#### **Usage**

Integrate this query into Microsoft Sentinel dashboards or alert workflows for proactive monitoring of **SID History Compromise**. By correlating attribute changes, logon activity, and privilege escalation, it helps detect and investigate attacks effectively.
{% endtab %}

{% tab title="Query 4" %}
The following is another advanced KQL query to detect potential Security Identifier (SID) History Compromise activities by incorporating additional filtering, anomaly detection, and correlation with other logs:

{% code overflow="wrap" %}
```kusto
let suspiciousEvents = SecurityEvent
| where EventID in (1102, 4103, 4104, 4675, 4738)
| extend EventDescription = case(
    EventID == 1102, "Security audit log cleared",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
    EventID == 4675, "SID filtering",
    EventID == 4738, "SID History attribute modified",
    "Unknown Event"
)
| project TimeGenerated, EventID, EventDescription, Computer, Account, LogonType, LogonProcessName, IpAddress, IpPort;

let anomalyDetection = suspiciousEvents
| summarize Count = count() by EventID, bin(TimeGenerated, 1h)
| where Count > 5; // Adjust threshold based on your environment

let correlatedEvents = suspiciousEvents
| join kind=inner (
    SecurityEvent
    | where EventID in (4624, 4625) // Logon events
    | project LogonTime = TimeGenerated, Account, IpAddress, LogonType
) on Account, IpAddress
| where TimeGenerated between (LogonTime - 1h) and (LogonTime + 1h);

suspiciousEvents
| union anomalyDetection
| union correlatedEvents
| sort by TimeGenerated desc
```
{% endcode %}

Query includes:

1. **Anomaly Detection**: Identifies spikes in event occurrences within a 1-hour window.
2. **Correlation with Logon Events**: Correlates suspicious events with logon events to identify potential unauthorised access.
3. **Enhanced Filtering**: Filters and sorts the results for easier analysis.

Feel free to adjust the thresholds and parameters based on your specific environment and requirements.
{% endtab %}
{% endtabs %}

### Splunk Detection Queries

The following are **Splunk queries** to detect **Security Identifier (SID) History Compromise**. This query identifies suspicious modifications to the SIDHistory attribute, privileged activities, and unusual access patterns associated with SIDHistory usage.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query for SID History Compromise Detection

{% code overflow="wrap" %}
```splunk-spl
index=security OR index=windows OR index=active_directory
sourcetype=WinEventLog:Security
(EventCode=5136 OR EventCode=4624 OR EventCode=4672 OR EventCode=4728 OR EventCode=4732)
| eval EventCategory=case(
    EventCode==5136, "Directory Modification",
    EventCode==4624, "Logon",
    EventCode==4672, "Privileged Logon",
    EventCode IN (4728, 4732), "Group Membership Change",
    true(), "Other")
| eval SuspiciousActivity=case(
    EventCode==5136 AND Modified_Properties contains "SIDHistory", "SIDHistory Modified",
    EventCode==4672 AND (Privileges IN ("SeTakeOwnershipPrivilege", "SeBackupPrivilege", "SeRestorePrivilege")), "Privileged Logon",
    EventCode==4624 AND Additional_Info contains "SIDHistory", "SIDHistory Logon",
    EventCode IN (4728, 4732) AND Group_Name IN ("Domain Admins", "Enterprise Admins"), "Group Membership Change",
    true(), null)
| where isnotnull(SuspiciousActivity)
| stats count as EventCount values(SuspiciousActivity) as DetectedActivities values(Target_User_Name) as AccountsAffected values(Source_Network_Address) as IPs by EventCategory, EventCode, Target_Domain, Object_Name, User_Name
| where EventCount > 2  // Threshold for correlated suspicious activities
| table _time, User_Name, EventCategory, EventCode, AccountsAffected, IPs, DetectedActivities, EventCount, Object_Name, Target_Domain
| sort - EventCount
```
{% endcode %}

#### **Explanation of the Query**

1. **Log Sources and Event Codes**:
   * Searches across Active Directory and Windows security logs for relevant events:
     * **5136**: Directory modification (used to track SIDHistory attribute changes).
     * **4624**: Logon success (used to track logons leveraging SIDHistory).
     * **4672**: Special privilege logons (used to detect privileged account activities).
     * **4728**, **4732**: Group membership changes (used to track escalation to privileged groups).
2. **Event Categorisation**:
   * Categorises events into:
     * **Directory Modification**: Tracks changes to the `SIDHistory` attribute.
     * **Logon**: Detects logons using SIDHistory.
     * **Privileged Logon**: Flags logons using sensitive privileges (`SeTakeOwnershipPrivilege`, `SeBackupPrivilege`, etc.).
     * **Group Membership Change**: Identifies addition of accounts to privileged groups (`Domain Admins`, `Enterprise Admins`).
3. **Suspicious Activity Detection**:
   * Flags:
     * Changes to the `SIDHistory` attribute.
     * Privileged logons and group membership changes.
     * SIDHistory-related logons from suspicious accounts or IPs.
4. **Aggregation and Thresholds**:
   * Correlates suspicious events by `User_Name`, `Target_Domain`, and `Object_Name`.
   * Displays results where the number of suspicious events (`EventCount`) exceeds a threshold (`> 2`).

***

#### **Customisations**

1. **Thresholds**:
   * Adjust `EventCount > 2` to reflect your environment’s activity baseline.
2. **Critical Accounts**:
   * Extend the query to track environment-specific privileged accounts or groups.
3. **Domains and IPs**:
   * Focus on specific domains or IP ranges if needed to filter high-risk activity.

***

#### **Output**

The query provides:

* A summary of the user involved (`User_Name`), the type of suspicious activity detected (`DetectedActivities`), and associated accounts (`AccountsAffected`).
* Relevant events (`EventCode`), IP addresses (`IPs`), and objects (`Object_Name`) involved.
* Count of correlated suspicious events for prioritisation.

***

#### **Usage**

Use this query to:

* **Create Alerts**: Set up alerts for real-time detection of SID History Compromise.
* **Dashboards**: Integrate the query into Splunk dashboards for monitoring and investigation.
* **Incident Response**: Correlate suspicious activities to investigate potential privilege escalation or lateral movement.

This query enhances detection and response capabilities for **SID History Compromise** by combining attribute changes, privilege escalation, and anomalous access patterns.
{% endtab %}

{% tab title="Query 2" %}
Splunk query to detect potential Security Identifier (SID) History Compromise activities by monitoring specific event codes that are indicative of such activities:

{% code overflow="wrap" %}
```splunk-spl
index=security
| search EventCode IN (1102, 4103, 4104, 4675, 4738)
| eval EventDescription = case(
    EventCode == 1102, "Security audit log cleared",
    EventCode == 4103, "PowerShell pipeline execution details",
    EventCode == 4104, "PowerShell script execution",
    EventCode == 4675, "SID filtering",
    EventCode == 4738, "SID History attribute modified",
    true(), "Unknown Event"
)
| table _time, EventCode, EventDescription, host, user, LogonType, LogonProcessName, src_ip, src_port
| sort -_time
```
{% endcode %}

Query helps to identify events related to a potential SID History Compromise by monitoring key event codes and providing relevant details for further investigation.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)

