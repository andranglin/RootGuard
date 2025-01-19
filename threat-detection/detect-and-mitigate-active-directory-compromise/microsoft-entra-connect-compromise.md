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

# Microsoft Entra Connect Compromise

### **Introduction**

Microsoft Entra Connect (formerly Azure AD Connect) is a critical tool for synchronising on-premises Active Directory (AD) with Azure Active Directory (Azure AD). It allows organisations to manage identities across hybrid environments seamlessly. A **Microsoft Entra Connect Compromise** occurs when attackers exploit misconfigurations, vulnerabilities, or compromised credentials related to the Entra Connect server or its components. Such compromises can enable adversaries to manipulate identity synchronisation, escalate privileges, or exfiltrate sensitive data.

Due to its role in bridging on-premises and cloud environments, the Entra Connect server is a high-value target. If compromised, attackers can pivot between on-premises infrastructure and Azure AD, posing significant risks, such as unauthorised access, data breaches, and loss of identity control.

***

### **Attack Description**

A Microsoft Entra Connect compromise typically involves the attacker gaining access to the Entra Connect server or its service accounts. Attackers may exploit:

1. **Compromised Credentials**: Access to the highly privileged service account used for directory synchronisation can allow attackers to manipulate or inject malicious changes into synchronised identities.
2. **Misconfigurations**: Weak configurations, such as insecure storage of credentials or overly permissive access controls, can be exploited.
3. **Vulnerabilities**: Exploiting unpatched vulnerabilities in the Entra Connect software.
4. **Pass-through Authentication (PTA) or Password Hash Sync (PHS)**: Attackers may intercept authentication requests or alter synchronisation to gain unauthorised access.

Once compromised, attackers can:

* Elevate privileges by creating or modifying accounts in Azure AD.
* Synchronise malicious changes to on-premises AD.
* Extract password hashes for offline cracking.
* Disable security configurations, such as MFA or conditional access policies.

***

### **Detection Techniques**

1. **Events that Detect a Microsoft Entra Connect Compromise:**

**Source of Events:** Microsoft Entra Connect Servers

* **Event ID 611:** Event generated when the PHS has failed. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 650:** Events generated when password synchronisation starts retrieving updated passwords from Active Directory. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 651:** Events generated when password synchronisation finishes retrieving updated passwords from Active Directory. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 656:** Events generated when password synchronisation indicates that a password change occurred and there was an attempt to sync this password to Microsoft Entra ID. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 657:** Events generated when a password change request is successfully sent to Microsoft Entra ID. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* Event ID 1102: Events generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if a Microsoft Entra Connect server has been compromised.
* **Event ID 4103:** Events generated when PowerShell executes and logs pipeline execution details. AADInternals, a popular toolkit used for exploiting Microsoft Entra Connect, uses PowerShell for its execution. This event can indicate the use of PowerShell-based malicious tools, which may assist in identifying if a malicious actor attempted to exploit Microsoft Entra Connect.
* **Event ID 4104:** Events generated when PowerShell executes code to capture scripts and commands. AADInternals, a popular toolkit used for exploiting Microsoft Entra Connect, uses PowerShell for its execution. This event can indicate the use of PowerShell-based malicious tools, which may assist in identifying if a malicious actor attempted to exploit Microsoft Entra Connect.

2. **Secure Entra Connect Server**:

* Restrict access to the server to only necessary administrators and enforce multi-factor authentication (MFA).
* Apply the principle of least privilege to all service accounts and ensure they are used solely for their intended purpose.

3. **Update and Patch Regularly**:

* Keep Microsoft Entra Connect software up to date to address vulnerabilities.
* Apply security patches for both the operating system and associated components.

4. **Enable Advanced Logging**:

* Enable Azure AD audit and sign-in logs for comprehensive visibility.
* Enable and monitor directory synchronisation logs to detect unauthorised changes.

1. **Monitor Unusual Activities**:
   * Track changes in synchronised objects, such as new privileged accounts or altered group memberships.
   * Identify suspicious synchronisation activities, including unexpected schema changes or frequent sync cycles.
2. **Log Analysis**:

* Analyse Entra Connect server logs for anomalous events, such as:
  * Unauthorised access attempts.
  * Changes to synchronisation configurations.
  * Updates to the synchronisation schedule.
* Use Azure AD logs to detect unusual admin activities, such as privilege escalation or MFA disabling.

6. **Network Traffic Analysis**:

* Monitor for unexpected communication from the Entra Connect server, such as connections to unauthorised external IPs.

7. **Behavioural Analysis**:

* Use User and Entity Behavior Analytics (UEBA) to detect deviations from normal behaviour of Entra Connect-related accounts or services.

***

### **Mitigation Techniques**

1. Events that Detect a Microsoft Entra Connect Compromise: Source of Events:&#x20;

* **Event ID 611:** Event generated when the PHS has failed. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 650:** Events generated when password synchronisation starts retrieving updated passwords from Active Directory. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 651:** Events generated when password synchronisation finishes retrieving updated passwords from Active Directory. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 656:** Events generated when password synchronisation indicates that a password change occurred and there was an attempt to sync this password to Microsoft Entra ID. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* **Event ID 657:** Events generated when a password change request is successfully sent to Microsoft Entra ID. This event can be analysed to identify unusual password synchronisation activity that could indicate a compromise against Microsoft Entra Connect.
* Event ID 1102: Events generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if a Microsoft Entra Connect server has been compromised.
* **Event ID 4103:** Events generated when PowerShell executes and logs pipeline execution details. AADInternals, a popular toolkit used for exploiting Microsoft Entra Connect, uses PowerShell for its execution. This event can indicate the use of PowerShell-based malicious tools, which may assist in identifying if a malicious actor attempted to exploit Microsoft Entra Connect.
* **Event ID 4104:** Events generated when PowerShell executes code to capture scripts and commands. AADInternals, a popular toolkit used for exploiting Microsoft Entra Connect, uses PowerShell for its execution. This event can indicate the use of PowerShell-based malicious tools, which may assist in identifying if a malicious actor attempted to exploit Microsoft Entra Connect.

2. **Secure Entra Connect Server**:

* Restrict access to the server to only necessary administrators and enforce multi-factor authentication (MFA).
* Apply the principle of least privilege to all service accounts and ensure they are used solely for their intended purpose.

3. **Update and Patch Regularly**:

* Keep Microsoft Entra Connect software up to date to address vulnerabilities.
* Apply security patches for both the operating system and associated components.

4. **Enable Advanced Logging**:

* Enable Azure AD audit and sign-in logs for comprehensive visibility.
* Enable and monitor directory synchronisation logs to detect unauthorised changes.

5. **Harden Configurations**:

* Encrypt credentials stored on the Entra Connect server using secure mechanisms.
* Regularly review and harden synchronisation rules and configurations.

6. **Implement Conditional Access and MFA**:

* Use conditional access policies to limit access to the Entra Connect server.
* Enforce MFA for all privileged accounts.

7. **Conduct Regular Security Assessments**:

* Periodically audit the Entra Connect environment to identify misconfigurations, weak credentials, and potential vulnerabilities.

***

By securing Microsoft Entra Connect and monitoring for suspicious activities, organisations can significantly reduce the risks associated with this critical identity synchronisation tool and maintain a robust security posture across hybrid environments.

### KQL Detection Queries

The following is a set of KQL queries for detecting potential signs of a **Microsoft Entra Connect Compromise** in Microsoft Sentinel. This query identifies unusual activities related to Entra Connect, such as unauthorized changes to synchronisation configurations, unusual access patterns, and anomalous privileged activities.

{% tabs %}
{% tab title="Query 1" %}
KQL Query to Detect Microsoft Entra Connect Compromise

{% code overflow="wrap" %}
```kusto
// Step 1: Detect changes to Entra Connect synchronization configurations
let ConfigChangeEvents = AuditLogs
| where OperationName contains "Set Directory Synchronization" or OperationName contains "Update Sync Configuration"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, ResultDescription;

// Step 2: Detect unusual privileged account activity
let PrivilegedAccountActivity = SigninLogs
| where Identity contains "DirectorySynchronization" or Identity endswith "@yourdomain.com"
| where ConditionalAccessStatus == "NotApplied" or AuthenticationMethodsUsed !contains "MFA"
| summarize Count = count() by Identity, AppDisplayName, ResultDescription, IPAddress, TimeGenerated
| where Count > 1;

// Step 3: Monitor unexpected synchronization activity
let SyncActivity = AuditLogs
| where OperationName contains "Start Directory Synchronization"
| where TimeGenerated between (ago(1h) .. now())
| summarize SyncCount = count() by InitiatedBy, ResultDescription, TimeGenerated
| where SyncCount > 1;

// Step 4: Correlate all suspicious activities
ConfigChangeEvents
| join kind=inner (PrivilegedAccountActivity) on $left.InitiatedBy == $right.Identity
| join kind=inner (SyncActivity) on $left.InitiatedBy == $right.InitiatedBy
| project TimeGenerated, InitiatedBy, OperationName, AppDisplayName, IPAddress, ResultDescription, SyncCount
| order by TimeGenerated desc
```
{% endcode %}

#### **How This Query Works**

1. **Detect Configuration Changes**:
   * The first section (`ConfigChangeEvents`) looks for operations that modify directory synchronisation settings, such as schema updates or configuration rule changes.
2. **Privileged Account Activity**:
   * The second section (`PrivilegedAccountActivity`) identifies suspicious activities from privileged accounts associated with Entra Connect. It flags:
     * Accounts bypassing conditional access policies or MFA.
     * Repeated login attempts with unusual results.
3. **Unexpected Synchronisation**:
   * The third section (`SyncActivity`) monitors frequent synchronisation operations initiated within a short time frame, which may indicate unauthorised activity.
4. **Correlation**:
   * The final section correlates all detected anomalies (config changes, privileged access, and unexpected synchronisation) to surface potential compromises.

***

#### **Customisations**

* Replace `@yourdomain.com` with your organisation’s domain.
* Adjust the `TimeGenerated` range (e.g., `ago(1h)`) to suit your monitoring needs.
* Add specific account names or IP address ranges for focused monitoring.

***

#### **Output**

The query provides details such as the initiating account, operation type, IP address, and activity descriptions, helping you detect and respond to potential **Microsoft Entra Connect Compromises** effectively. Integrate this into your Sentinel dashboards or set up alerts for continuous monitoring.
{% endtab %}

{% tab title="Query 2" %}
A KQL query to detect potential Microsoft Entra Connect compromises by monitoring specific event IDs that are indicative of such activities:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (611, 650, 651, 656, 657, 1102, 4103, 4104)
| extend EventDescription = case(
    EventID == 611, "PHS failed",
    EventID == 650, "Password sync started",
    EventID == 651, "Password sync finished",
    EventID == 656, "Password change detected",
    EventID == 657, "Password change request sent",
    EventID == 1102, "Security audit log cleared",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
    "Unknown Event"
)
| project TimeGenerated, EventID, EventDescription, Computer, Account, LogonType, LogonProcessName, IpAddress, IpPort
| sort by TimeGenerated desc

```
{% endcode %}

The query will help you identify events related to a potential Microsoft Entra Connect compromise by monitoring key event IDs and providing relevant details for further investigation.
{% endtab %}

{% tab title="Query 3" %}
Advanced KQL Query for Microsoft Entra Connect Compromise:

The following is a more **advanced KQL query** to detect **Microsoft Entra Connect Compromise**, incorporating additional log sources, deeper behavioural analysis, and more detailed correlations. This query tracks unusual configuration changes, suspicious synchronization activities, and anomalous privileged account behaviours.

{% code overflow="wrap" %}
```kusto
// Step 1: Identify Configuration Changes in Microsoft Entra Connect
let ConfigChangeEvents = AuditLogs
| where OperationName in ("Set Directory Synchronization", "Update Sync Configuration", "Modify Directory Sync Scope", "Set Password Hash Sync Configuration")
| extend IsConfigChange = true
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, ResultDescription, CorrelationId;

// Step 2: Detect Unusual Synchronization Activity
let FrequentSyncActivity = AuditLogs
| where OperationName == "Start Directory Synchronization"
| where TimeGenerated between (ago(1h) .. now())  // Detect frequent syncs in a short time
| summarize SyncCount = count() by InitiatedBy, ResultDescription, TimeGenerated
| where SyncCount > 3  // Threshold for frequent synchronization
| extend IsFrequentSync = true
| project InitiatedBy, SyncCount, ResultDescription, TimeGenerated;

// Step 3: Monitor Privileged Account Activity
let PrivilegedAccountActivity = SigninLogs
| where Identity contains "DirectorySynchronization" or Identity endswith "@yourdomain.com"
| where AuthenticationDetails !contains "MFA" or ConditionalAccessStatus == "NotApplied"  // Identify accounts bypassing MFA or CA policies
| summarize Count = count() by Identity, AppDisplayName, ResultDescription, IPAddress, TimeGenerated
| where Count > 2  // Threshold for repeated privileged activities
| extend IsSuspiciousAccount = true
| project Identity, AppDisplayName, IPAddress, Count, ResultDescription, TimeGenerated;

// Step 4: Track Administrative Changes to IdP
let AdminActivity = AuditLogs
| where OperationName in ("Update Federation Settings", "Update Directory Configuration", "Modify Trust Relationship")
| extend IsAdminChange = true
| project TimeGenerated, InitiatedBy, OperationName, ResultDescription, CorrelationId;

// Step 5: Correlate Suspicious Activities
ConfigChangeEvents
| join kind=inner (FrequentSyncActivity) on InitiatedBy
| join kind=inner (PrivilegedAccountActivity) on $left.InitiatedBy == $right.Identity
| join kind=leftouter (AdminActivity) on $left.InitiatedBy == $right.InitiatedBy
| project TimeGenerated, InitiatedBy, OperationName, SyncCount, AppDisplayName, IPAddress, ResultDescription, IsConfigChange, IsFrequentSync, IsSuspiciousAccount, IsAdminChange
| order by TimeGenerated desc
```
{% endcode %}

#### **Features of the Query**

1. **Comprehensive Monitoring**:
   * Tracks configuration changes, synchronisation frequency, privileged account behaviours, and administrative updates.
2. **Dynamic Thresholds**:
   * Flags frequent synchronisations (`SyncCount > 3`) and repeated suspicious account activities (`Count > 2`).
3. **Enhanced Correlation**:
   * Combines findings across multiple sources (`AuditLogs`, `SigninLogs`) to provide a holistic view of potentially compromised Entra Connect activities.
4. **Detection of MFA and Conditional Access Bypasses**:
   * Flags privileged accounts that bypass MFA or Conditional Access policies, which are critical for securing the Entra Connect server.

***

#### **Customisations**

* **Thresholds**:
  * Adjust `SyncCount > 3` and `Count > 2` based on your organisation’s activity patterns.
* **Domain Filtering**:
  * Replace `@yourdomain.com` with your organisation’s domain.
* **Targeted Operations**:
  * Add or remove operations (`OperationName`) relevant to your environment.

***

#### **Output**

The query provides detailed information, including:

* Initiating accounts (`InitiatedBy`).
* Operation types (`OperationName`).
* Synchronisation patterns (`SyncCount`).
* Privileged account activities (`IsSuspiciousAccount`).
* Administrative changes to the IdP (`IsAdminChange`).

#### **Usage**

Integrate this query into your Microsoft Sentinel dashboards or configure it as an alert rule to detect and respond to potential **Microsoft Entra Connect compromises** proactively.
{% endtab %}

{% tab title="Query 4" %}
An advanced KQL query to detect potential Microsoft Entra Connect compromises by incorporating additional filtering, anomaly detection, and correlation with other logs:

{% code overflow="wrap" %}
```kusto
let suspiciousEvents = SecurityEvent
| where EventID in (611, 650, 651, 656, 657, 1102, 4103, 4104)
| extend EventDescription = case(
    EventID == 611, "PHS failed",
    EventID == 650, "Password sync started",
    EventID == 651, "Password sync finished",
    EventID == 656, "Password change detected",
    EventID == 657, "Password change request sent",
    EventID == 1102, "Security audit log cleared",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
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

Adjust the thresholds and parameters based on your specific environment and requirements.
{% endtab %}
{% endtabs %}

Splunk Detection Queries

**Splunk query** to detect potential **Microsoft Entra Connect Compromise**. The query correlates suspicious activities such as configuration changes, frequent synchronisation, anomalous privileged account activities, and bypassed security measures.

{% tabs %}
{% tab title="Query 1" %}
**Splunk Query for Microsoft Entra Connect Compromise**

{% code overflow="wrap" %}
```splunk-spl
index=security OR index=azuread OR index=windows
sourcetype=AzureAuditLogs OR sourcetype=AzureSigninLogs OR sourcetype=WinEventLog:Security
(
  (OperationName="Set Directory Synchronization" OR OperationName="Update Sync Configuration" OR OperationName="Modify Directory Sync Scope" OR OperationName="Set Password Hash Sync Configuration")
  OR (OperationName="Start Directory Synchronization")
  OR (EventCode=4624 OR EventCode=4625) 
)
| eval EventCategory=case(
    OperationName IN ("Set Directory Synchronization", "Update Sync Configuration", "Modify Directory Sync Scope", "Set Password Hash Sync Configuration"), "ConfigChange",
    OperationName="Start Directory Synchronization", "FrequentSync",
    (EventCode=4624 OR EventCode=4625) AND AuthenticationDetails !contains "MFA" AND ConditionalAccessStatus="NotApplied", "PrivilegedAccountActivity",
    true(), "Other"
)
| stats count by EventCategory, OperationName, InitiatedBy, TargetResources, IpAddress, ResultDescription, TimeGenerated
| eval IsSuspicious=case(
    EventCategory="ConfigChange", "Config Change Detected",
    EventCategory="FrequentSync" AND count > 3, "Frequent Synchronization Detected",
    EventCategory="PrivilegedAccountActivity", "Privileged Activity Detected",
    true(), "Unknown Activity"
)
| where IsSuspicious IN ("Config Change Detected", "Frequent Synchronization Detected", "Privileged Activity Detected")
| table _time, EventCategory, InitiatedBy, OperationName, IpAddress, TargetResources, ResultDescription, IsSuspicious
| sort - _time
```
{% endcode %}

#### **Explanation of the Query**

1. **Search Scope**:
   * Includes logs from `AzureAuditLogs`, `AzureSigninLogs`, and `Windows Security Logs`.
   * Searches for relevant operations:
     * Directory synchronisation configuration changes.
     * Frequent synchronisation events.
     * Authentication events (e.g., `EventCode=4624` for successful logins, `EventCode=4625` for failed logins).
2. **Categorisation of Events**:
   * Classifies detected activities into:
     * **ConfigChange**: Directory synchronisation configuration changes.
     * **FrequentSync**: Repeated synchronisation operations.
     * **PrivilegedAccountActivity**: Privileged accounts bypassing MFA or Conditional Access policies.
3. **Suspicious Activity Identification**:
   * Flags configuration changes (`ConfigChange`).
   * Detects frequent synchronisations exceeding a threshold (`FrequentSync` with `count > 3`).
   * Highlights privileged account activities bypassing key security controls (`PrivilegedAccountActivity`).
4. **Dynamic Correlation**:
   * Correlates findings across logs to surface suspicious activities in Entra Connect.

***

#### **Customisations**

* **Thresholds**:
  * Adjust `count > 3` for synchronisation frequency based on your environment.
* **Domain Filtering**:
  * Add specific account or domain filters if needed (e.g., `InitiatedBy` ending in your domain).
* **Specific Events**:
  * Expand the `EventCategory` logic to include additional relevant Azure or Windows events.

***

#### **Output**

The query provides details such as:

* Event category (`EventCategory`).
* Suspicious activity description (`IsSuspicious`).
* Accounts involved (`InitiatedBy`).
* Operation types and associated resources.

#### **Usage**

Use this query to create Splunk alerts or dashboards for continuous monitoring of potential **Microsoft Entra Connect compromises**. By focusing on correlated anomalies, it helps detect and mitigate threats effectively.
{% endtab %}

{% tab title="Query 2" %}
Splunk query to detect potential Microsoft Entra Connect compromises by monitoring specific event codes that are indicative of such activities:

{% code overflow="wrap" %}
```splunk-spl
index=windows
| search EventCode IN (611, 650, 651, 656, 657, 1102, 4103, 4104)
| eval EventDescription = case(
    EventCode == 611, "PHS failed",
    EventCode == 650, "Password sync started",
    EventCode == 651, "Password sync finished",
    EventCode == 656, "Password change detected",
    EventCode == 657, "Password change request sent",
    EventCode == 1102, "Security audit log cleared",
    EventCode == 4103, "PowerShell pipeline execution details",
    EventCode == 4104, "PowerShell script execution",
    true(), "Unknown Event"
)
| table _time, EventCode, EventDescription, host, user, LogonType, LogonProcessName, src_ip, src_port
| sort -_time
```
{% endcode %}

Query will help you identify events related to a potential Microsoft Entra Connect compromise by monitoring key event codes and providing relevant details for further investigation.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
* [Microsoft Entra ID Protection Documentation](https://learn.microsoft.com/en-us/entra/id-protection/)
* [Microsoft Entra Architecture](https://learn.microsoft.com/en-us/entra/architecture/architecture)
