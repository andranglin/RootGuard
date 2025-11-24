# One-way Domain Trust Bypass

### **Introduction**

In multi-domain Active Directory (AD) environments, **one-way domain trust** is a mechanism that allows users in one domain (the trusted domain) to access resources in another domain (the trusting domain). This trust relationship is often used to facilitate resource sharing while maintaining administrative separation between domains. However, this setup can be exploited by attackers through a **one-way domain trust bypass**, enabling unauthorised access to resources in the trusting domain. This occurs when attackers abuse the trust relationship to escalate privileges, perform lateral movement, or access sensitive data.

One-way trust bypass attacks are particularly concerning in environments where domains with varying security levels coexist. Attackers can exploit misconfigurations, weak security practices, or compromised accounts in the trusted domain to gain access to the trusting domain, circumventing security controls and potentially compromising the entire environment.

***

### **Attack Description**

A one-way domain trust bypass leverages the asymmetric nature of trust between domains. In this scenario:

1. The trusted domain allows its users to authenticate to resources in the trusting domain.
2. The trusting domain does not grant reciprocal access to resources in the trusted domain, creating a one-way trust.

Attackers can exploit this by:

* **Compromising Accounts in the Trusted Domain**: Using credentials from the trusted domain to access resources in the trusting domain.
* **Abusing Misconfigurations**: Exploiting weak trust configurations, such as overly permissive access controls or lack of network segmentation.
* **Forging Kerberos Tickets**: Using tools like Mimikatz to create Service Tickets (Silver Tickets) or Golden Tickets to impersonate users in the trusted domain and access resources in the trusting domain.

Once access is gained, attackers may escalate privileges, perform reconnaissance, and pivot to other systems, potentially compromising the trusting domain entirely.

***

### **Detection Techniques**

1.  **Events that detect a One-Way Domain Trust Bypass**

    Source of detection:

    * **Event ID 1102:** Events generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if a Domain Controller has been compromised.
    * **Event ID 4103:** Events generated when PowerShell executes and logs pipeline execution details. Common malicious tools used to retrieve the TDO password hash, like Mimikatz, use PowerShell. Analysing this event for unusual PowerShell executions on Domain Controllers may indicate the TDO has been compromised.
    * Event ID 4104: Events generated when PowerShell executes code to capture scripts and commands. Common malicious tools used to retrieve the TDO password hash, such as Mimikatz, use PowerShell. Analysing this event for unusual PowerShell executions on Domain Controllers may indicate the TDO has been compromised.
    * Event ID 4768: Events generated when a TGT is requested. After the TDO password hash has been retrieved, it is commonly used to request a TGT in the trusted domain. If the User ID value matches the TDO username, this may indicate the TDO has been compromised and a one-way domain trust bypass has occurred.
2. **Monitor Cross-Domain Authentication**:
   * Analyse logon events (Event ID 4624) to detect unusual authentication from accounts in the trusted domain.
   * Look for service ticket requests (Event ID 4769) involving accounts from the trusted domain accessing high-value systems in the trusting domain.
3. **Track Administrative Activities**:
   * Review events for privileged account usage from the trusted domain, such as group membership changes (Event ID 4728/4732).
4. **Detect Anomalous Traffic**:
   * Monitor network traffic between domains for unusual access patterns or connections to sensitive resources.
5. **Identify Suspicious Ticket Activity**:
   * Look for forged Kerberos tickets (e.g., abnormal ticket encryption types or unusually long ticket lifetimes).
6. **Behavioural Analysis**:
   * Use User and Entity Behavior Analytics (UEBA) to detect deviations from normal cross-domain access patterns.

***

### **Mitigation Techniques**

1. **The following security controls should be implemented to mitigate a one-way domain trust bypass:**
   * Limit access to Domain Controllers to only privileged users that require access. This reduces the number of opportunities for malicious actors to gain access to Domain Controllers.
   * Restrict privileged access pathways to Domain Controllers to jump servers and secure admin workstations using only the ports and services that are required for administration. Domain Controllers are classified as ‘Tier 0’ assets within Microsoft’s ‘Enterprise Access Model’.&#x20;
   * Encrypt and securely store backups of Domain Controllers and limit access to only Backup Administrators. Backups of Domain Controllers need to be afforded the same security as the actual Domain Controllers. Malicious actors may target backup systems to gain access to critical and sensitive computer objects, such as Domain Controllers.
   * Only use Domain Controllers for AD DS and do not install any non-security-related services or applications. This reduces the attack surface of Domain Controllers as there are fewer services, ports and applications that may be vulnerable and used to compromise a Domain Controller.&#x20;
   * Centrally log and analyse Domain Controller logs in a timely manner to identify malicious activity. Domain Controller logs provide a rich source of information that is important for investigating potentially malicious activity on Domain Controllers and in the domain.
   * Disable the Print Spooler service on Domain Controllers. For example, malicious actors have targeted the Print Spooler service on Domain Controllers as a technique to authenticate to a system they control to collect the Domain Controllers computer object password hash or TGT. Malicious actors can then use this to authenticate to the Domain Controller they coerced and gain administrative access.
2. **Harden Trust Configurations**:
   * Use selective authentication for one-way trusts to restrict access to specific resources.
   * Disable unnecessary trusts and ensure all trusts are actively managed.
3. **Enforce Strong Account Security**:
   * Implement multi-factor authentication (MFA) for all accounts in both trusted and trusting domains.
   * Regularly review and rotate credentials for privileged accounts.
4. **Enable Advanced Logging**:
   * Enable detailed Kerberos, logon, and group membership auditing in both domains.
   * Collect and centralise logs for analysis in a SIEM solution.
5. **Segment and Isolate Networks**:
   * Implement network segmentation to limit access between domains, allowing only necessary traffic.
   * Restrict domain controller communication to known, authorised systems.
6. **Regularly Audit Trust Relationships**:
   * Conduct periodic reviews of trust configurations to ensure they follow the principle of least privilege.
   * Test for misconfigurations or overly permissive access settings.
7. **Deploy Threat Detection Tools**:
   * Use tools like Microsoft Defender for Identity, Splunk, or Azure Sentinel to detect and alert on anomalous cross-domain activity.

***

By proactively monitoring and securing domain trust relationships, organisations can prevent attackers from exploiting one-way domain trust bypass vulnerabilities, reducing the risk of privilege escalation and lateral movement across domains.

### KQL Detection Queries

The following KQL queries are designed to detect potential **One-Way Domain Trust Bypass** activity in Microsoft Sentinel. The query focuses on identifying unusual cross-domain authentication patterns, service ticket requests, and access attempts from accounts in the trusted domain to the trusting domain.

{% tabs %}
{% tab title="Query 1" %}
KQL Query to Detect One-Way Domain Trust Bypass

{% code overflow="wrap" %}
```kusto
// Step 1: Detect cross-domain logons from the trusted domain
let CrossDomainLogons = SecurityEvent
| where EventID == 4624  // Logon event
| where LogonType in (3, 10)  // Network or remote interactive logons
| where TargetUserName contains "@" and AccountDomain != TargetDomainName  // Cross-domain authentication
| extend TrustDirection = case(AccountDomain != TargetDomainName, "One-Way Trust", "Other")
| project TimeGenerated, AccountDomain, TargetDomainName, TargetUserName, LogonType, IpAddress, WorkstationName, TrustDirection;

// Step 2: Monitor service ticket requests from trusted domain accounts
let CrossDomainServiceTickets = SecurityEvent
| where EventID == 4769  // Kerberos Service Ticket Request
| where TargetUserName endswith "$" == false  // Exclude machine accounts
| where AccountDomain != TargetDomainName  // Cross-domain activity
| project TimeGenerated, AccountDomain, TargetDomainName, TargetUserName, ServiceName, IpAddress, TicketOptions;

// Step 3: Detect suspicious access patterns to sensitive systems
let HighValueSystems = SecurityEvent
| where EventID in (4624, 4672)  // Logon and special privilege logon
| where TargetDomainName == "<TrustingDomain>"  // Replace with trusting domain name
| where AccountDomain != TargetDomainName
| where TargetUserName in ("Domain Admins", "Enterprise Admins")  // Focus on privileged accounts
| project TimeGenerated, AccountDomain, TargetDomainName, TargetUserName, Privileges, IpAddress, WorkstationName;

// Step 4: Correlate all suspicious cross-domain activities
CrossDomainLogons
| join kind=inner (CrossDomainServiceTickets) on $left.TargetUserName == $right.TargetUserName
| join kind=inner (HighValueSystems) on $left.TargetUserName == $right.TargetUserName
| project TimeGenerated, AccountDomain, TargetDomainName, TargetUserName, LogonType, ServiceName, Privileges, IpAddress, WorkstationName, TrustDirection
| sort by TimeGenerated desc
```
{% endcode %}

#### **Explanation of the Query**

1. **Cross-Domain Logons**:
   * Detects logon events (`EventID 4624`) where the `AccountDomain` differs from the `TargetDomainName`.
   * Focuses on network and remote logons (`LogonType 3, 10`), commonly used in domain trust scenarios.
2. **Service Ticket Requests**:
   * Monitors Kerberos Service Ticket Requests (`EventID 4769`) where accounts from the trusted domain request access to services in the trusting domain.
3. **Privileged Access Attempts**:
   * Highlights attempts to log onto high-value systems or privileged accounts (`Domain Admins`, `Enterprise Admins`) in the trusting domain.
4. **Correlation**:
   * Combines suspicious logon activity, service ticket requests, and privileged access attempts to identify potential one-way trust bypass scenarios.

***

#### **Customisations**

* Replace `<TrustingDomain>` with the name of the trusting domain in your environment.
* Adjust thresholds or add additional focus areas, such as specific privileged groups or critical systems.
* Extend the query to include IP reputation checks or behavioural baselines.

***

#### **Output**

The query surfaces potential one-way domain trust bypass activities, providing details on:

* The account and domain involved.
* The type of logon or access attempt.
* The systems or services accessed.
* Associated IP addresses and workstation names.

#### **Usage**

Integrate this query into Microsoft Sentinel dashboards or alert rules to monitor and respond to one-way domain trust bypass attempts in realtime.
{% endtab %}

{% tab title="Query 2" %}
A KQL query to detect potential One-Way Domain Trust Bypass activities by monitoring specific event IDs that are indicative of such activities:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (1102, 4103, 4104, 4768, 4624, 4769, 4728, 4732)
| extend EventDescription = case(
    EventID == 1102, "Security audit log cleared",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
    EventID == 4768, "TGT requested",
    EventID == 4624, "Logon event",
    EventID == 4769, "Service ticket request",
    EventID == 4728, "Group membership change",
    EventID == 4732, "Group membership change",
    "Unknown Event"
)
| project TimeGenerated, EventID, EventDescription, Computer, Account, LogonType, LogonProcessName, IpAddress, IpPort
| sort by TimeGenerated desc

```
{% endcode %}

The query helps to identify events related to a potential One-Way Domain Trust Bypass by monitoring key event IDs and providing relevant details for further investigation.
{% endtab %}

{% tab title="Query 3" %}
The following is a more **advanced KQL query** for detecting **One-Way Domain Trust Bypass** activity. This version incorporates multiple log sources, behaviour analysis, thresholds, and correlation across suspicious authentication, Kerberos activity, and high-value resource access.

{% code overflow="wrap" %}
```kusto
// Step 1: Identify Cross-Domain Authentication
let CrossDomainLogons = SecurityEvent
| where EventID == 4624  // Logon event
| where LogonType in (3, 10)  // Network or remote interactive logons
| where TargetUserName contains "@" and AccountDomain != TargetDomainName  // Cross-domain authentication
| extend TrustDirection = case(AccountDomain != TargetDomainName, "One-Way Trust", "Other")
| extend SuspiciousLogon = iff(TrustDirection == "One-Way Trust" and LogonType == 3 and IpAddress != "KnownIPRange", true, false)  // Flag unusual patterns
| project TimeGenerated, AccountDomain, TargetDomainName, TargetUserName, LogonType, IpAddress, WorkstationName, TrustDirection, SuspiciousLogon;

// Step 2: Detect Suspicious Kerberos Service Ticket Requests
let CrossDomainServiceTickets = SecurityEvent
| where EventID == 4769  // Kerberos Service Ticket Request
| where TargetUserName endswith "$" == false  // Exclude machine accounts
| where AccountDomain != TargetDomainName  // Cross-domain activity
| extend SuspiciousTicket = iff(TicketOptions has "forwardable" or TicketOptions has "renewable", true, false)  // Flag suspicious ticket options
| project TimeGenerated, AccountDomain, TargetDomainName, TargetUserName, ServiceName, IpAddress, TicketOptions, SuspiciousTicket;

// Step 3: Monitor High-Value Resource Access
let HighValueAccess = SecurityEvent
| where EventID in (4624, 4672)  // Logon and special privilege logon
| where TargetDomainName == "<TrustingDomain>"  // Replace with trusting domain
| where AccountDomain != TargetDomainName
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Administrator")  // Focus on privileged accounts
| extend SuspiciousAccess = true
| project TimeGenerated, AccountDomain, TargetDomainName, TargetUserName, Privileges, IpAddress, WorkstationName, SuspiciousAccess;

// Step 4: Detect Anomalous Authentication Failures
let AnomalousFailures = SecurityEvent
| where EventID == 4625  // Logon failure
| where AccountDomain != TargetDomainName
| summarize FailureCount = count() by TargetUserName, AccountDomain, IpAddress
| where FailureCount > 5  // Threshold for unusual failures
| extend SuspiciousFailures = true;

// Step 5: Correlate All Suspicious Activities
CrossDomainLogons
| join kind=inner (CrossDomainServiceTickets) on $left.TargetUserName == $right.TargetUserName
| join kind=inner (HighValueAccess) on $left.TargetUserName == $right.TargetUserName
| join kind=leftouter (AnomalousFailures) on $left.TargetUserName == $right.TargetUserName
| summarize SuspiciousEvents = count(), SuspiciousLogonCount = countif(SuspiciousLogon), SuspiciousTicketCount = countif(SuspiciousTicket), SuspiciousAccessCount = countif(SuspiciousAccess), SuspiciousFailuresCount = countif(SuspiciousFailures) by TargetUserName, AccountDomain, TargetDomainName, IpAddress
| where SuspiciousLogonCount > 1 or SuspiciousTicketCount > 1 or SuspiciousAccessCount > 0 or SuspiciousFailuresCount > 0
| project TargetUserName, AccountDomain, TargetDomainName, IpAddress, SuspiciousLogonCount, SuspiciousTicketCount, SuspiciousAccessCount, SuspiciousFailuresCount, SuspiciousEvents
| order by SuspiciousEvents desc

```
{% endcode %}

#### **Enhancements in This Query**

1. **Behavioural Analysis**:
   * Flags suspicious patterns like cross-domain logons (`LogonType == 3`), unusual IPs, and service ticket options (`forwardable` or `renewable`).
2. **High-Value Resource Access**:
   * Focuses on privileged accounts (`Domain Admins`, `Enterprise Admins`, `Administrator`) and their activities on high-value systems in the trusting domain.
3. **Thresholds for Anomalies**:
   * Tracks repeated authentication failures (`FailureCount > 5`) to detect brute force or misconfiguration attempts.
4. **Multi-Source Correlation**:
   * Correlates cross-domain logons, Kerberos service ticket activity, high-value resource access, and authentication failures for holistic detection.
5. **Dynamic Filtering**:
   * Customisable domain names (`<TrustingDomain>`) and IP ranges (`KnownIPRange`) for environmental tuning.

***

#### **Customisations**

* Replace `<TrustingDomain>` with the name of your trusting domain.
* Adjust thresholds, such as `FailureCount > 5` or `SuspiciousLogonCount > 1`, based on your environment’s baseline behaviour.
* Extend or refine the list of high-value accounts or groups for more precise monitoring.

***

#### **Output**

The query provides:

* Number of suspicious events by activity type (logons, tickets, access attempts, and failures).
* Details of accounts, domains, IP addresses, and aggregated suspicious activity counts.

#### **Usage**

Integrate this query into Microsoft Sentinel dashboards or alerting systems for continuous monitoring and detection of **One-Way Domain Trust Bypass** attempts, enabling timely investigation and response.
{% endtab %}

{% tab title="Query 4" %}
The following is another advanced KQL query to detect potential One-Way Domain Trust Bypass activities by incorporating additional filtering, anomaly detection, and correlation with other logs:

{% code overflow="wrap" %}
```kusto
let suspiciousEvents = SecurityEvent
| where EventID in (1102, 4103, 4104, 4768, 4624, 4769, 4728, 4732)
| extend EventDescription = case(
    EventID == 1102, "Security audit log cleared",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
    EventID == 4768, "TGT requested",
    EventID == 4624, "Logon event",
    EventID == 4769, "Service ticket request",
    EventID == 4728, "Group membership change",
    EventID == 4732, "Group membership change",
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

**Splunk queries** to detect potential **One-Way Domain Trust Bypass** activity. The query analyses cross-domain authentication events, Kerberos activity, and privileged access patterns, and correlates these logs for comprehensive detection.

{% tabs %}
{% tab title="Query 1 " %}
Splunk Query for One-Way Domain Trust Bypass Detection

{% code overflow="wrap" %}
```splunk-spl
index=security OR index=windows OR index=active_directory
sourcetype=WinEventLog:Security
(EventCode=4624 OR EventCode=4769 OR EventCode=4625 OR EventCode=4672)
| eval EventCategory=case(
    EventCode==4624, "Logon",
    EventCode==4769, "Service Ticket Request",
    EventCode==4625, "Logon Failure",
    EventCode==4672, "Privileged Logon"
)
| eval TrustType=if(Account_Domain != Target_Domain, "One-Way Trust", "Same Domain")
| eval SuspiciousActivity=case(
    EventCode==4624 AND Logon_Type IN (3, 10) AND TrustType=="One-Way Trust", "Suspicious Cross-Domain Logon",
    EventCode==4769 AND TrustType=="One-Way Trust", "Suspicious Service Ticket Request",
    EventCode==4625 AND TrustType=="One-Way Trust", "Repeated Cross-Domain Failures",
    EventCode==4672 AND TrustType=="One-Way Trust", "Privileged Cross-Domain Access"
)
| where isnotnull(SuspiciousActivity)
| stats count as EventCount values(EventCategory) as EventTypes values(SuspiciousActivity) as SuspiciousActions by Account_Name, Account_Domain, Target_Domain, Target_User_Name, Source_Network_Address
| where EventCount > 3  // Threshold for significant activity
| table _time, Account_Name, Account_Domain, Target_Domain, Target_User_Name, Source_Network_Address, EventCount, EventTypes, SuspiciousActions
| sort - EventCount
```
{% endcode %}

#### **Explanation of the Query**

1. **Search Scope**:
   * Includes logs from relevant indexes (`index=security`, `index=windows`, `index=active_directory`).
   * Targets key events:
     * `4624` (Successful Logon): Identifies cross-domain logons.
     * `4769` (Kerberos Service Ticket Request): Flags unusual ticket activity.
     * `4625` (Failed Logon): Tracks repeated cross-domain authentication failures.
     * `4672` (Privileged Logon): Monitors privileged account activity.
2. **Trust Evaluation**:
   * Compares `Account_Domain` and `Target_Domain` to identify one-way trust scenarios.
3. **Suspicious Activity Flags**:
   * Flags events indicative of one-way trust abuse:
     * Cross-domain logons (`Logon_Type 3, 10` for network or remote logons).
     * Service ticket requests across domains.
     * Repeated failed logons (`4625`).
     * Privileged access attempts (`4672`).
4. **Statistical Correlation**:
   * Aggregates suspicious activities by user, domain, and source IP to identify patterns.
5. **Dynamic Thresholding**:
   * Filters results with `EventCount > 3` to highlight significant cross-domain activity.

***

#### **Customisations**

* Adjust thresholds (`EventCount > 3`) based on your environment’s normal activity.
* Modify the domain comparison (`TrustType`) logic to suit specific trust relationships.
* Extend the list of monitored EventCodes or refine filters for high-value accounts or systems.

***

#### **Output**

This query provides:

* User and domain details involved in potential one-way trust abuse.
* IP addresses and event types associated with the activity.
* Aggregated counts of suspicious events for prioritisation.

***

#### **Usage**

* **Alerts**: Configure Splunk alerts for real-time detection of one-way domain trust bypass attempts.
* **Dashboards**: Visualise cross-domain activities in a dedicated dashboard to monitor trends.
* **Investigations**: Use this query to investigate potential privilege escalation or lateral movement across domains.

By integrating this query into your security operations, you can proactively identify and respond to **One-Way Domain Trust Bypass** attacks.
{% endtab %}

{% tab title="Query 2" %}
A Splunk query to detect potential One-Way Domain Trust Bypass activities by monitoring specific event codes that are indicative of such activities:

{% code overflow="wrap" %}
```splunk-spl
index=windows
| search EventCode IN (1102, 4103, 4104, 4768, 4624, 4769, 4728, 4732)
| eval EventDescription = case(
    EventCode == 1102, "Security audit log cleared",
    EventCode == 4103, "PowerShell pipeline execution details",
    EventCode == 4104, "PowerShell script execution",
    EventCode == 4768, "TGT requested",
    EventCode == 4624, "Logon event",
    EventCode == 4769, "Service ticket request",
    EventCode == 4728, "Group membership change",
    EventCode == 4732, "Group membership change",
    true(), "Unknown Event"
)
| table _time, EventCode, EventDescription, host, user, LogonType, LogonProcessName, src_ip, src_port
| sort -_time
```
{% endcode %}

The query will help you identify events related to a potential One-Way Domain Trust Bypass by monitoring key event codes and providing relevant details for further investigation.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
