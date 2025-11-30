# Golden Security Assertion Markup Language (SAML)

### Introduction

The **Golden SAML** attack is a sophisticated technique targeting federated identity systems that utilise Security Assertion Markup Language (SAML) for authentication. In this attack, adversaries exploit the trust relationship between identity providers (IdPs) and service providers (SPs) to forge authentication tokens. By compromising the private key of the IdP or gaining administrative access, attackers can create valid SAML assertions, impersonate any user (including administrators), and gain unauthorised access to federated services. This attack is particularly dangerous in cloud environments, such as Office 365, AWS, and GCP, where SAML is commonly used for single sign-on (SSO).

***

### Attack Description

SAML is a widely adopted standard for enabling SSO, allowing users to authenticate once and access multiple services. The IdP generates and signs SAML assertions, which the SPs trust to grant access. In a Golden SAML attack, an attacker obtains the IdP’s private key or gains access to its signing mechanisms. With this, they can forge SAML tokens without interacting with the IdP or triggering authentication processes. These forged tokens allow attackers to impersonate any user and access any resource that trusts the IdP.

Golden SAML attacks are highly stealthy since they bypass standard authentication logs and audits. They are particularly effective for lateral movement and persistence in compromised environments, as the attacker can continually generate valid tokens as long as they have access to the signing key.

***

### **Detection Techniques**

Detecting a Golden SAML can be challenging, especially after threat actors have compromised the environment and are using forged SAML responses to access service providers. The first opportunity to detect a Golden SAML is the generation of event 70, resulting from the compromise of an AD FS server and the export of the private key. Event 70 can be analysed to determine whether the export was authorised. If attackers successfully execute a Golden SAML and forge SAML responses to authenticate to service providers, then the AD FS and service provider's authentication events can be correlated to identify inconsistencies that may indicate the use of forged SAML responses.

1. **Events that detect a Golden SAML**
   * **Event ID 70:** Event generated when a certificate’s private key is exported. Extracting the private key is the first step in a Golden SAML.
   * **Event ID 307:** Event generated when there is a change to the AD FS configuration. Malicious actors may add a new trusted AD FS server they can control instead of extracting the certificate and other information from an existing AD FS server.
   * **Event ID 510:** The event provides additional information and can be correlated with event 307 with the same instance ID. Any events generated for changes to AD FS should be investigated to confirm if the changes were authorised or not.
   * **Event ID 1007:** Event generated when a certificate is exported. The first step of a Golden SAML is to export the signing certificate from an AD FS server.
   * **Event ID 1102:** Event generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if an AD FS server has been compromised.
   * **Event ID 1200:** Event generated when AD FS issues a valid token as part of the authentication process with a service provider, such as Microsoft 365 or Azure. A Golden SAML bypass AD FS servers, resulting in the absence of this event (and event 1202). This event can be correlated with authentication events from service providers to identify the absence of AD FS authentication events, which may be a sign that a forged SAML response was used.
   * **Event ID 1202:** Event generated when AD FS validates a new credential as part of the authentication process with a service provider, such as Microsoft 365 or Azure. A Golden SAML bypasses AD FS servers, resulting in the absence of this event (and event 1200). This event can be correlated with authentication events from service providers to identify the absence of AD FS authentication events, which may be a sign that a forged SAML response was used.
   * **Event ID 4662:** Event generated when the AD FS DKM container in Active Directory is accessed. The ‘Active Directory Service Access’ setting needs to be configured for auditing with ‘Read All Properties’ configured for the AD FS parent and child containers in Active Directory. This event should be monitored for the ‘thumbnailPhoto’ attribute with a Globally Unique Identifier (GUID) value matching ‘{8d3bca50-1d7e-11d0-a081-00aa006c33ed}’. This attributed GUID stores the DKM master key and should only be periodically accessed by the AD FS service account. Each time this event is generated, it should be analysed to determine if the activity was authorised.
2. **Monitor SAML Assertions**:
   * Analyse SAML assertion logs for anomalies such as tokens issued without corresponding authentication events or with extended lifetimes.
   * Look for tokens generated for high-privilege accounts, especially during non-business hours or from unusual locations.
3. **Cross-Check Authentication Events**:
   * Correlate authentication logs from SPs with IdP logs to identify discrepancies, such as tokens being used without a matching authentication event.
4. **Monitor Administrative Activity**:
   * Track changes to IdP configurations, particularly updates to signing certificates or unusual administrative access patterns.
5. **Behavioural Analysis**:
   * Use user and entity behaviour analytics (UEBA) to detect unusual activities from accounts, such as accessing multiple high-value resources in a short timeframe.

***

### **Mitigation Techniques**

1. **The following security controls should be implemented to mitigate a Golden SAML**:
   * Ensure the AD FS service account is a gMSA. This minimises the likelihood of the account being compromised via other techniques, such as Kerberoasting or DCSync.
   * Ensure the AD FS service account is used only for AD FS and no other purpose. By using the AD FS service account only for AD FS, and no other purpose, it reduces its attack surface by not exposing its credentials to other systems.
   * Ensure passwords for AD FS server local administrator accounts are long (30-character minimum), unique, unpredictable, and managed. Microsoft’s Local Administrator Password Solution (LAPS) can be used to achieve this. Threat actors can target local administrator accounts to gain access to AD FS servers, so these accounts need to be protected from compromise.
   * Limit access to AD FS servers to only privileged users that require access. This may be a smaller subset of privileged users than the Domain Admins security group. This reduces the number of opportunities for malicious actors to gain access to AD FS servers.
   * Restrict privileged access pathways to AD FS servers to jump servers and secure admin workstations using only the ports and services that are required. AD FS servers are classified as ‘Tier 0’ assets within Microsoft’s ‘Enterprise Access Model’.
   * Only use AD FS servers for AD FS and ensure no other non-security-related services or applications are installed. This reduces the attack surface of AD FS servers as there are fewer services, ports, and applications that may be vulnerable and can be used to compromise an AD FS server.  Centrally log and analyse AD FS server logs in a timely manner to identify malicious activity. If malicious actors gain privileged access to AD FS servers, this activity should be identified as soon as possible to respond and limit the impact.
   * Encrypt and securely store backups of AD FS servers and limit access to only Backup Administrators. Backups of AD FS servers need to be afforded the same security as the actual AD FS servers. Malicious actors may target backup systems to gain access to critical and sensitive computer objects, such as AD FS servers.&#x20;
   * Rotate AD FS token-signing and encryption certificates every 12 months, or sooner if an AD FS server has been compromised or suspected to have been compromised. Both certificates need to be rotated twice in rapid succession to revoke all existing AD FS tokens.
2. **Secure Private Keys**:
   * Protect IdP private keys using hardware security modules (HSMs) or equivalent secure storage solutions.
   * Regularly rotate signing certificates and keys to limit the impact of potential compromise.
3. **Enable Logging and Auditing**:
   * Configure the IdP to log all SAML-related events, including token issuance and administrative activities.
   * Use Security Information and Event Management (SIEM) systems to analyse these logs for suspicious patterns.
4. **Implement Conditional Access Policies**:
   * Enforce additional authentication measures for high-risk activities or privileged accounts using conditional access policies.
   * Limit access to sensitive applications based on user roles, devices, and locations.
5. **Hardening and Monitoring IdP**:
   * Apply the latest security patches and updates to the IdP to address known vulnerabilities.
   * Limit administrative access to the IdP and enforce multi-factor authentication (MFA) for all privileged accounts.
6. **Periodic Audits**:
   * Regularly review the configuration of the federated identity system for misconfigurations or unnecessary trust relationships.
   * Perform security assessments to ensure the integrity of the IdP and SP infrastructure.

***

Golden SAML attacks highlight the importance of securing identity infrastructure in federated environments. By implementing robust detection and mitigation techniques, organisations can reduce the risk of unauthorised access and maintain the integrity of their authentication processes.

### KQL Detection Queries

To detect a **Golden SAML** attack in Microsoft Sentinel or Azure Monitor, you can use the following **KQL** queries. These queries identify anomalies in Security Assertion Markup Language (SAML) token activities, such as tokens issued without corresponding authentication events or unusual administrative changes to the Identity Provider (IdP).

{% tabs %}
{% tab title="Query 1" %}
KQL Query to Detect Golden SAML Activity

{% code overflow="wrap" %}
```kusto
// Step 1: Detect anomalies in SAML token issuance
let SAMLTokenEvents = SecurityEvent
| where EventID in (4768, 4769, 4771)  // Kerberos pre-auth, service ticket requests, and failures
| extend SAMLToken = case(
    EventID == 4769, "Service Ticket Request",
    EventID == 4771, "Pre-authentication Failure",
    "Other")
| project TimeGenerated, AccountName, Computer, IpAddress, SAMLToken, LogonType;

// Step 2: Identify token issuance without authentication
let UnlinkedSAMLTokens = SAMLTokenEvents
| summarize TokenCount = count() by AccountName, Computer, IpAddress
| where TokenCount > 1  // Detect repeated token activity
| join kind=leftanti (SecurityEvent | where EventID == 4624) on $left.AccountName == $right.AccountName;

// Step 3: Monitor administrative changes to the IdP
let IdPConfigChanges = SecurityEvent
| where EventID == 5136  // Directory object modification
| where ObjectClass in ("msDS-PrincipalName", "ServiceConnectionPoint")  // IdP-related objects
| project TimeGenerated, AccountName, ObjectName, OperationType, IpAddress;

// Step 4: Correlate SAML token anomalies with IdP changes
SAMLTokenEvents
| join kind=inner (UnlinkedSAMLTokens) on $left.AccountName == $right.AccountName
| join kind=inner (IdPConfigChanges) on $left.AccountName == $right.AccountName
| project TimeGenerated, AccountName, SAMLToken, OperationType, ObjectName, IpAddress
| sort by TimeGenerated desc
```
{% endcode %}

#### **How This Query Works**

1. **Monitor SAML Token Anomalies**:
   * Tracks Kerberos events (4768, 4769, 4771) to identify token issuance anomalies.
   * Highlights tokens issued without corresponding authentication (e.g., EventID 4624).
2. **Detect Repeated Token Use**:
   * Aggregates token activity for the same account and flags repeated activity, which might indicate forged tokens.
3. **Track IdP Configuration Changes**:
   * Focuses on directory changes related to the IdP, such as alterations to service principal names (SPNs) or Service Connection Points (SCPs).
4. **Correlation**:
   * Combines anomalies in token usage and configuration changes to surface potential Golden SAML attacks.

***

#### **Customisations**

* **Thresholds**: Adjust `TokenCount > 1` to suit your environment's baseline activity.
* **Include Specific Resources**: Add filters for high-value applications or services, such as AWS or Office 365.
* **Integrate UEBA**: Combine with user behaviour analysis to detect deviations from normal activity
{% endtab %}

{% tab title="Query 2" %}
KQL query to detect Golden Security Assertion Markup Language (SAML) attacks by looking for specific event IDs that are indicative of such activities:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (70, 307, 510, 1007, 1102, 1200, 1202, 4662)
| extend EventDescription = case(
    EventID == 70, "Certificate's private key exported",
    EventID == 307, "Change to AD FS configuration",
    EventID == 510, "Additional information related to AD FS configuration change",
    EventID == 1007, "Certificate exported",
    EventID == 1102, "Security audit log cleared",
    EventID == 1200, "AD FS issued a valid token",
    EventID == 1202, "AD FS validated a new credential",
    EventID == 4662, "Access to AD FS DKM container in Active Directory",
    "Unknown Event"
)
| project TimeGenerated, EventID, EventDescription, Computer, Account, LogonType, LogonProcessName, IpAddress, IpPort
| sort by TimeGenerated desc
```
{% endcode %}

The query will help you identify events related to Golden SAML attacks by monitoring key event IDs and providing relevant details for further investigation
{% endtab %}

{% tab title="Query 3" %}
Advanced KQL Query for Golden SAML Detection

{% code overflow="wrap" %}
```kusto
// Step 1: Identify SAML Token Issuance Events
let SAMLTokenEvents = SecurityEvent
| where EventID in (4768, 4769, 4771)  // Kerberos pre-auth, service ticket requests, and failures
| extend TokenType = case(
    EventID == 4769, "Service Ticket Request",
    EventID == 4771, "Pre-authentication Failure",
    "Other")
| project TimeGenerated, AccountName, Computer, IpAddress, TokenType, TargetDomainName;

// Step 2: Detect Unauthenticated Token Usage
let UnauthenticatedTokens = SAMLTokenEvents
| summarize TokenCount = count() by AccountName, IpAddress, TargetDomainName
| where TokenCount > 1  // Tokens issued without valid authentication
| join kind=leftanti (SecurityEvent | where EventID == 4624  // Successful logons
                      | project AccountName, IpAddress) on $left.AccountName == $right.AccountName;

// Step 3: Monitor Administrative IdP Changes
let IdPChanges = SecurityEvent
| where EventID == 5136  // Directory object modifications
| where ObjectClass in ("msDS-PrincipalName", "ServiceConnectionPoint", "CertificateAuthority")
| extend ChangeType = case(
    AdditionalInfo contains "Updated", "Modified",
    AdditionalInfo contains "Deleted", "Deleted",
    "Other")
| project TimeGenerated, AccountName, ObjectName, ChangeType, IpAddress;

// Step 4: Identify Unusual Token Usage Patterns
let UnusualTokenUsage = SAMLTokenEvents
| where TargetDomainName has "federation" or TargetDomainName has "auth"
| summarize EventCount = count() by AccountName, TargetDomainName, IpAddress
| where EventCount > 5  // Excessive token usage
| project AccountName, TargetDomainName, IpAddress, EventCount;

// Step 5: Correlate Suspicious Activity
UnauthenticatedTokens
| join kind=inner (IdPChanges) on $left.AccountName == $right.AccountName
| join kind=inner (UnusualTokenUsage) on $left.AccountName == $right.AccountName
| project TimeGenerated, AccountName, IpAddress, TargetDomainName, TokenCount, ChangeType, ObjectName, EventCount
| sort by TimeGenerated desc
```
{% endcode %}

#### **How This Query Works**

1. **SAML Token Issuance**:
   * Identifies Kerberos-related events (4768, 4769, 4771) for token issuance and pre-authentication.
   * Tracks the type of token and basic details for correlation.
2. **Unauthenticated Token Detection**:
   * Flags tokens issued without a corresponding successful authentication (EventID 4624).
3. **IdP Administrative Changes**:
   * Monitors changes to key IdP attributes, including SPNs, Service Connection Points, and certificates.
4. **Unusual Token Patterns**:
   * Detects excessive token usage targeting federated domains or authentication endpoints.
5. **Correlation**:
   * Links anomalies in token issuance, administrative changes, and usage patterns to surface potential Golden SAML attacks.

***

#### **Key Features**

* **Thresholds**:
  * Adjust `TokenCount > 1` and `EventCount > 5` to align with your environment’s normal behaviour.
* **Target Resources**:
  * Focus on specific domains (`federation`, `auth`) associated with SAML authentication.
* **Enhanced Monitoring**:
  * Integrate results into dashboards or alerts for proactive monitoring.
{% endtab %}

{% tab title="Query 4" %}
Advanced KQL query that includes additional filtering, anomaly detection, and correlation with other logs to enhance the detection of Golden SAML attacks:

{% code overflow="wrap" %}
```kusto
let suspiciousEvents = SecurityEvent
| where EventID in (70, 307, 510, 1007, 1102, 1200, 1202, 4662)
| extend EventDescription = case(
    EventID == 70, "Certificate's private key exported",
    EventID == 307, "Change to AD FS configuration",
    EventID == 510, "Additional information related to AD FS configuration change",
    EventID == 1007, "Certificate exported",
    EventID == 1102, "Security audit log cleared",
    EventID == 1200, "AD FS issued a valid token",
    EventID == 1202, "AD FS validated a new credential",
    EventID == 4662, "Access to AD FS DKM container in Active Directory",
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
2. **Correlation with Logon Events**: Correlates suspicious events with logon events to identify potential unauthorized access.
3. **Enhanced Filtering**: Filters and sorts the results for easier analysis.

Feel free to adjust the thresholds and parameters based on your specific environment and requirements.
{% endtab %}
{% endtabs %}

### Splunk Detection Queries

The following **Splunk queries are** designed to detect potential **Golden SAML** attacks and focus on identifying anomalies in SAML token issuance, unusual service provider access, and administrative changes to Identity Provider (IdP) configurations.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query for Golden SAML Detection

{% code overflow="wrap" %}
```spl
index=windows
sourcetype=WinEventLog:Security
(EventCode=4768 OR EventCode=4769 OR EventCode=4771 OR EventCode=5136)
| eval TokenType=case(EventCode==4769, "Service Ticket Request",
                      EventCode==4771, "Pre-authentication Failure",
                      EventCode==4768, "TGT Request",
                      true(), "Other")
| eval SuspiciousActivity=case(
    EventCode==4769 AND TargetUserName!="krbtgt" AND TargetUserName!="$MACHINE_ACCOUNT$", "Potential SAML Forgery",
    EventCode==5136 AND ObjectClass IN ("msDS-PrincipalName", "ServiceConnectionPoint", "CertificateAuthority"), "IdP Configuration Change",
    true(), null)
| where isnotnull(SuspiciousActivity)
| stats count values(SuspiciousActivity) as SuspiciousActions by TargetUserName, IpAddress, ComputerName, TokenType
| where count > 2  // Threshold: More than two suspicious actions
| table _time, TargetUserName, IpAddress, ComputerName, TokenType, SuspiciousActions, count
| sort - _time
```
{% endcode %}

#### **Explanation of the Query**

1. **Search Scope**:
   * Query across relevant index(`ndex=windows`) for events related to Kerberos and directory changes.
2. **Kerberos Events**:
   * **EventCode=4768**: TGT request (may indicate account usage).
   * **EventCode=4769**: Service ticket requests (may reveal forged tickets).
   * **EventCode=4771**: Pre-authentication failure (could signal brute-force attempts).
3. **IdP Configuration Changes**:
   * **EventCode=5136**: Tracks changes to directory objects, focusing on SAML-related objects like SPNs and signing certificates.
4. **Suspicious Activity Flagging**:
   * Flags potential SAML forgery based on service ticket requests that don’t target typical accounts (`krbtgt` or machine accounts).
   * Detects configuration changes in IdP-related attributes (`msDS-PrincipalName`, `ServiceConnectionPoint`, etc.).
5. **Aggregation and Threshold**:
   * Aggregates activity by `TargetUserName`, `IpAddress`, and `TokenType`.
   * Filters results where more than two suspicious actions occur (`count > 2`).
6. **Output**:
   * Displays key details like the user, IP address, and type of suspicious activity, sorted by time.

***

#### **Customisations**

* **Thresholds**:
  * Adjust `count > 2` based on your environment's baseline.
* **Specific Attributes**:
  * Include additional attributes or services critical to your environment.
* **Correlations**:
  * Enhance this query by combining it with logs from federation services, cloud providers, or application logs.

***

#### **Usage**

This Splunk query identifies potential **Golden SAML** activities by correlating Kerberos events and IdP changes, providing visibility into potential forgery attempts and configuration tampering. Integrate the results into a dashboard or set up alerts for continuous monitoring.
{% endtab %}

{% tab title="Query 2" %}
Splunk query to detect Golden Security Assertion Markup Language (SAML) attacks by looking for specific event IDs that are indicative of such activities:

{% code overflow="wrap" %}
```spl
index=security
| search EventCode IN (70, 307, 510, 1007, 1102, 1200, 1202, 4662)
| eval EventDescription = case(
    EventCode == 70, "Certificate's private key exported",
    EventCode == 307, "Change to AD FS configuration",
    EventCode == 510, "Additional information related to AD FS configuration change",
    EventCode == 1007, "Certificate exported",
    EventCode == 1102, "Security audit log cleared",
    EventCode == 1200, "AD FS issued a valid token",
    EventCode == 1202, "AD FS validated a new credential",
    EventCode == 4662, "Access to AD FS DKM container in Active Directory",
    true(), "Unknown Event"
)
| table _time, EventCode, EventDescription, host, user, LogonType, LogonProcessName, src_ip, src_port
| sort -_time

```
{% endcode %}


{% endtab %}

{% tab title="Query 3" %}
A more advanced Splunk query that includes additional filtering, anomaly detection, and correlation with other logs to enhance the detection of Golden SAML attacks:

{% code overflow="wrap" %}
```spl
index=security
| search EventCode IN (70, 307, 510, 1007, 1102, 1200, 1202, 4662)
| eval EventDescription = case(
    EventCode == 70, "Certificate's private key exported",
    EventCode == 307, "Change to AD FS configuration",
    EventCode == 510, "Additional information related to AD FS configuration change",
    EventCode == 1007, "Certificate exported",
    EventCode == 1102, "Security audit log cleared",
    EventCode == 1200, "AD FS issued a valid token",
    EventCode == 1202, "AD FS validated a new credential",
    EventCode == 4662, "Access to AD FS DKM container in Active Directory",
    true(), "Unknown Event"
)
| table _time, EventCode, EventDescription, host, user, LogonType, LogonProcessName, src_ip, src_port;

let anomalyDetection = search EventCode IN (70, 307, 510, 1007, 1102, 1200, 1202, 4662)
| stats count by EventCode, bin(_time, "1h")
| where count > 5; // Adjust threshold based on your environment

let correlatedEvents = search EventCode IN (70, 307, 510, 1007, 1102, 1200, 1202, 4662)
| join type=inner [
    search EventCode IN (4624, 4625) // Logon events
    | eval LogonTime = _time
    | table LogonTime, user, src_ip, LogonType
] on user, src_ip
| where _time >= LogonTime - 3600 AND _time <= LogonTime + 3600;

search EventCode IN (70, 307, 510, 1007, 1102, 1200, 1202, 4662)
| append [search anomalyDetection]
| append [search correlatedEvents]
| sort -_time
```
{% endcode %}

Query includes:

1. **Anomaly Detection**: Identifies spikes in event occurrences within a 1-hour window.
2. **Correlation with Logon Events**: Correlates suspicious events with logon events to identify potential unauthorized access.
3. **Enhanced Filtering**: Filters and sorts the results for easier analysis.

Adjust the thresholds and parameters based on your specific environment and requirements.
{% endtab %}

{% tab title="Query 4" %}
Advanced Splunk Query for Golden SAML Detection

An **advanced Splunk query** for detecting potential **Golden SAML** attacks. This version incorporates additional correlations across multiple event types, monitors unusual token usage patterns, and includes federated authentication events for a more comprehensive detection approach.

{% code overflow="wrap" %}
```spl
index=windows OR index=azuread OR index=federation
sourcetype=WinEventLog:Security OR sourcetype=AzureADLogs OR sourcetype=FederationLogs
(EventCode=4768 OR EventCode=4769 OR EventCode=4771 OR EventCode=5136 OR EventID=1200)
| eval TokenType=case(EventCode==4768, "TGT Request",
                      EventCode==4769, "Service Ticket Request",
                      EventCode==4771, "Pre-authentication Failure",
                      EventID==1200, "Federated Authentication",
                      true(), "Other")
| eval SuspiciousActivity=case(
    EventCode==4769 AND TargetUserName!="krbtgt" AND TargetUserName!="$MACHINE_ACCOUNT$", "Potential SAML Forgery",
    EventCode==5136 AND ObjectClass IN ("msDS-PrincipalName", "ServiceConnectionPoint", "CertificateAuthority"), "IdP Configuration Change",
    EventID==1200 AND (AuthDetails has "saml" AND NOT AuthDetails has "interactive"), "Anomalous Federated Authentication",
    true(), null)
| where isnotnull(SuspiciousActivity)
| stats count values(SuspiciousActivity) as SuspiciousActions values(TokenType) as TokenTypes values(IpAddress) as IPs by TargetUserName, ComputerName
| eval UnusualCount=if(count > 3, "Yes", "No")  // Flag high-volume activity
| where count > 2 OR UnusualCount="Yes"
| table _time, TargetUserName, ComputerName, IPs, TokenTypes, SuspiciousActions, count, UnusualCount
| sort - _time
```
{% endcode %}

#### **Explanation of Enhancements**

1. **Expanded Data Sources**:
   * Incorporates logs from Azure AD (`index=azuread`) and federated authentication systems (`index=federation`) alongside Kerberos logs.
   * Specifically looks for Event ID 1200 from federated authentication logs, which is associated with SAML-based logins.
2. **Token Usage Patterns**:
   * Tracks common Kerberos token events (`EventCode=4768, 4769, 4771`).
   * Monitors unusual federated authentication patterns (e.g., SAML tokens issued without interactive logins).
3. **IdP Configuration Changes**:
   * Monitors directory changes (`EventCode=5136`) related to IdP attributes such as SPNs, certificates, or service connection points.
4. **Suspicious Activity Evaluation**:
   * Flags:
     * SAML service ticket requests targeting non-standard accounts.
     * IdP configuration modifications that could indicate tampering.
     * Anomalous federated authentication behaviour (e.g., non-interactive SAML logins).
5. **Statistical Correlation**:
   * Aggregates activity by `TargetUserName` and associated IPs or token types.
   * Highlights accounts with repeated suspicious actions or unusually high activity.
6. **Dynamic Thresholding**:
   * Introduces a dynamic flag (`UnusualCount`) for accounts exceeding normal thresholds (`count > 3`).

***

#### **Customisations**

* **Federated Services**:
  * Add specific federation service logs if you use AWS, Office 365, or custom SAML providers.
* **Authentication Details**:
  * Modify `AuthDetails` filtering to include service-specific SAML token attributes.
* **Thresholds**:
  * Adjust thresholds (`count > 2`) based on normal activity in your environment.

***

#### **Usage**

This advanced query offers deep insights by correlating Kerberos logs, federated authentication logs, and directory changes. It can identify forged SAML tokens, detect tampered IdP configurations, and highlight anomalous token usage patterns. Integrate into a Splunk dashboard or set up alerts for real-time monitoring of potential **Golden SAML** attacks.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
