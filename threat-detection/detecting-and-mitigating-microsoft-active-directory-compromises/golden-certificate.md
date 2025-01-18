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

# Golden Certificate

### **Introduction to Golden Certificate**

A **Golden Certificate** is an advanced attack technique used to compromise Active Directory Certificate Services (AD CS). Similar to the **Golden Ticket** in Kerberos attacks, a Golden Certificate allows an attacker to forge a legitimate certificate that can be used to impersonate any user, escalate privileges, or maintain persistent access within a domain environment. The attack exploits the trust model of the Public Key Infrastructure (PKI) and the inherent design of certificates issued by AD CS.

Golden Certificate attacks are particularly dangerous because they bypass traditional authentication mechanisms and leverage the inherent trust that certificates provide. This technique falls under the **Persistence**, **Credential Access**, and **Privilege Escalation** tactics in the **MITRE ATT\&CK Framework** (e.g., T1552.003).

***

### **How Golden Certificate Attacks Work**

1. **Understanding AD CS and PKI:**
   * AD CS acts as a Certificate Authority (CA), issuing certificates to authenticate users, devices, and services within a domain.
   * Certificates are signed by the CA's private key, making them inherently trusted by all systems in the domain.
2. **Key Components of a Golden Certificate Attack:**
   * **CA Certificate and Private Key:** The CA's private key is the cornerstone of trust in a PKI. If attackers compromise it, they can sign arbitrary certificates.
   * **Certificate Templates:** Define how certificates are issued and what they can be used for (e.g., authentication or encryption).
3. **Attack Workflow:**
   * **Step 1: Compromise the CA:** Attackers gain access to the CA server or extract its private key.
   * **Step 2: Create a Malicious Certificate:** Using the stolen private key, attackers generate a custom certificate that can impersonate any user or device in the domain.
   * **Step 3: Exploit the Certificate:** The attacker uses the certificate to authenticate to domain services, access sensitive data, or escalate privileges.
4. **Persistence:**
   * Since certificates have long expiration periods and can be reused, they provide attackers with persistent access even if passwords are reset or accounts are disabled.

***

### **Risks of a Golden Certificate**

1. **Domain-Wide Trust Abuse:**
   * A compromised CA private key allows attackers to issue certificates that are trusted throughout the domain.
2. **Privilege Escalation:**
   * Attackers can impersonate high-privilege accounts (e.g., domain admins) by forging certificates for those accounts.
3. **Stealth and Persistence:**
   * Certificate-based authentication is less likely to trigger alerts compared to password or token-based authentication.
4. **Bypass Multi-Factor Authentication (MFA):**
   * Since certificates authenticate at the domain level, they often bypass MFA mechanisms.

***

### **Indicators of a Golden Certificate Attack**

1. **Unauthorised Access to CA Servers:**
   * Unusual logons (Event ID **4624**) or failed logons (Event ID **4625**) targeting CA servers.
2. **Certificate Signing:**
   * Unexpected certificate signing activities in AD CS logs (Event ID **4887**).
3. **Anomalous Certificate Usage:**
   * Certificates being used to authenticate unexpected accounts or from unusual systems.
4. **Unauthorised Access to Private Keys:**
   * Attempts to access or export the CA's private key (Event ID **5136**).

***

### **Detection Techniques**

1. **Monitor Access to CA Servers:**
   * Track logons to CA servers and monitor for privilege escalation attempts.
2. **Analyse Certificate Requests:**
   * Review certificate issuance logs for suspicious templates or accounts.
3. **Inspect Certificate Signing Logs:**
   * Look for certificates issued for high-privilege accounts or using unapproved templates.
4. **Track Certificate Authentication:**
   * Monitor for Kerberos or other authentication mechanisms using certificates.

***

### **Mitigation Strategies**

1. **Protect the CA Private Key:**
   * Restrict access to the CA server and its private key.
   * Use hardware security modules (HSMs) to store private keys securely.
2. **Audit Certificate Templates:**
   * Regularly review and restrict certificate templates to prevent abuse.
3. **Implement Strong Access Controls:**
   * Limit administrative access to the CA server.
4. **Enable Enhanced Logging:**
   * Configure AD CS to log certificate issuance, revocation, and usage.
5. **The following security controls should be implemented to mitigate a Golden Certificate:**
   * Use MFA to authenticate privileged users of systems. MFA for privileged users can hinder malicious actors from gaining access to a CA using stolen credentials, thus preventing the extraction of a CA certificate and private key.
   * Implement application control on AD CS CAs. An effective application control configuration on CAs prevents the execution of malicious executables such as Mimikatz.
   * Use a Hardware Security Module (HSM) to protect key material for AD CS CAs. Protect private keys by using a HSM with CAs. If a HSM is used, the private key for CAs cannot be backed up and exfiltrated by malicious actors.
   * Limit access to AD CS CAs to only privileged users that require access. This may be a smaller subset of privileged users than the Domain Admins security group and reduces the number of opportunities for malicious actors to gain access to a CA.
   * Restrict privileged access pathways to AD CS CA servers to jump servers and secure admin workstations using only the ports and services that are required for administration. AD CS servers are classified as ‘Tier 0’ assets within Microsoft’s ‘Enterprise Access Model’.
   * Only use AD CS CA servers for AD CS and do not install any non-security-related services or applications. This reduces the attack surface of AD CS CA servers as there are fewer services, ports and applications that may be vulnerable and used to compromise an AD CS CA server.
   * Encrypt and securely store backups of AD CS CA servers and limit access to only Backup Administrators. Backups of AD CS CA servers need to be afforded the same security as the actual AD CS CA servers. Malicious actors may target backup systems to gain access to critical and sensitive computer objects, such as AD CS CA servers.
   * Centrally log and analyse AD CS CA logs in a timely manner to identify malicious activity. If malicious actors gain privileged access to a CA, this activity should be identified as soon as possible to respond and limit the impact.
6. **Rotate CA Private Keys:**
   * Regularly renew and replace CA private keys to minimise the impact of compromise.

***

### **Key Logs to Monitor**

* AD CS CA event auditing is not enabled by default. To configure audit logging for AD CS CAs:&#x20;
  * Enable ‘Audit object access’ for Certificate Services in Group Policy for CAs. This can be found within the ‘Advanced Audit Policy Configuration’ within Security Settings.
  * Enable ‘Backup and restore the CA database’ as events to audit in the Auditing tab within the properties for CAs.
* **Events that Detect a Golden Certificate**
  * **Event ID 70: E**vent generated when a certificate is exported. This event should be filtered to check that the ‘subjectName’ field matches that of a CA certificate.
  * **Event ID 1102:** Event generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if an AD CS CA has been compromised.
  * **Event ID 4103:** Event generated when PowerShell executes and logs pipeline execution details. Common tools such as Certutil and Mimikatz use PowerShell. Analysing this event for PowerShell execution relating to these tools may indicate a Golden Certificate.
  * **Event ID 4104:** This event is generated when PowerShell executes code to capture scripts and commands. Common tools such as Certutil and Mimikatz use PowerShell. Analysing this event for PowerShell execution relating to these tools may indicate a Golden Certificate.
  * **Event ID 4876:** Event triggered when a backup of the CA database is started. This does not return any logs for exporting the private key, but may be an indicator of other potentially suspicious activity occurring on a CA
* **AD CS Logs:**
  * Event ID **4887:** A certificate was issued.
  * Event ID **4888:** A certificate was revoked.
* **Windows Security Logs:**
  * Event ID **4624:** Successful logons.
  * Event ID **4625:** Failed logons.
* **Directory Service Logs:**
  * Event ID **5136:** Directory object modified (e.g., private key access or export).

***

Golden Certificate attacks exploit the inherent trust and power of a compromised Certificate Authority to gain stealthy and persistent access to a domain. By protecting CA servers, securing private keys, and monitoring certificate activity, organisations can significantly reduce their exposure to this devastating attack vector.&#x20;

### KQL Detection Queries

Detecting a **Golden Certificate** attack involves monitoring unauthorised access to Certificate Authority (CA) servers, suspicious certificate issuance, and unusual certificate usage. Since a **Golden Certificate** relies on access to a compromised CA private key, detection focuses on CA-related activities, authentication patterns, and certificate issuance logs.

{% tabs %}
{% tab title="Query 1" %}
#### **KQL Query to Detect Golden Certificate Activity**

{% code overflow="wrap" %}
```kusto
// Query for suspicious certificate issuance activity
SecurityEvent
| where EventID in (4886, 4887, 4624, 4625)  // Include certificate-related and authentication events
| extend EventDescription = case(
    EventID == 4886, "Certificate Request",
    EventID == 4887, "Certificate Issued",
    EventID == 4624, "Successful Logon",
    EventID == 4625, "Failed Logon",
    true(), "Unknown"
)
| extend Requestor = tostring(parse_json(EventData.RequestorName)),
         CertificateTemplate = tostring(EventData.TemplateName),
         SerialNumber = tostring(EventData.SerialNumber),
         TargetServer = tostring(EventData.TargetServerName)
| where (EventID == 4887 and CertificateTemplate contains "Admin") or (EventID == 4624 and TargetServer contains "CA")  // Suspicious templates or logon to CA server
| summarize EventCount = count(), 
            Requestors = make_set(Requestor), 
            Templates = make_set(CertificateTemplate), 
            SerialNumbers = make_set(SerialNumber), 
            LogonIPs = make_set(IpAddress), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
    by TargetServer, EventID, EventDescription
| extend SuspiciousActivity = case(
    EventCount > 5 and Templates contains "Domain Admin", "High",
    Templates contains "Admin", "Medium",
    true(), "Low"
)
| where SuspiciousActivity in ("High", "Medium")
| project TargetServer, EventDescription, Templates, Requestors, SerialNumbers, LogonIPs, EventCount, FirstSeen, LastSeen, SuspiciousActivity
| sort by LastSeen desc
```
{% endcode %}

#### **Query Breakdown**

1. **Targeted Event IDs:**
   * **4886:** Certificate requested.
   * **4887:** Certificate issued.
   * **4624:** Successful logons (potential access to the CA server).
   * **4625:** Failed logons (unauthorised attempts).
2. **Extract Key Fields:**
   * `Requestor`: Account requesting the certificate.
   * `CertificateTemplate`: Template used for certificate issuance.
   * `SerialNumber`: Issued certificate’s serial number.
   * `TargetServer`: Target server involved in logons or certificate requests.
3. **Filter Suspicious Activity:**
   * Focuses on:
     * Certificates issued using high-privilege templates (e.g., "Admin" or "Domain Admin").
     * Logons to CA servers that are abnormal or unauthorised.
4. **Aggregate Data:**
   * Groups events by `TargetServer` and `EventID`.
   * Tracks details like templates used, requestors, and serial numbers.
5. **Suspicious Scoring:**
   * Assign scores to events based on templates and activity volume:
     * **High:** High-privilege templates with multiple requests.
     * **Medium:** Administrative templates.
6. **Output Details:**
   * Displays key details for further analysis, including server name, suspicious templates, requestors, and time range.
{% endtab %}

{% tab title="Query 2" %}
#### **Advanced Query for Certificate Authentication Detection**

To monitor certificate-based authentication, focus on Kerberos activity where certificates are used:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4769  // Kerberos Service Ticket Operation
| extend TicketType = tostring(EventData.TicketOptions), 
         TargetUser = tostring(EventData.TargetUserName), 
         IssuingCA = tostring(EventData.IssuingAuthority)
| where TicketType contains "forwardable" or TicketType contains "renewable"  // Focus on suspicious Kerberos tickets
| summarize TicketCount = count(), 
            TargetUsers = make_set(TargetUser), 
            CAs = make_set(IssuingCA), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
    by IssuingCA
| where TicketCount > 5  // Adjust based on baseline activity
| project IssuingCA, TicketCount, TargetUsers, CAs, FirstSeen, LastSeen
| sort by TicketCount desc
```
{% endcode %}

#### **Customisations**

1. **Whitelist Legitimate Templates or Accounts:**
   *   Exclude known safe templates or accounts:

       {% code overflow="wrap" %}
       ```kusto
       | where not(CertificateTemplate contains "SafeTemplate") and not(Requestor has "TrustedServiceAccount")
       ```
       {% endcode %}
2. **Adjust Thresholds:**
   * Modify thresholds for `EventCount` and `TicketCount` to align with your environment’s activity.
3. **Time-Based Grouping:**
   *   Group events into smaller intervals to detect bursts of activity:

       ```kusto
       | bin TimeGenerated span=15m
       ```

***

#### **Recommendations**

1. **Set Alerts:**
   * Configure alerts for:
     * High scores in certificate issuance activity.
     * Unusual logons to CA servers.
2. **Audit AD CS Configuration:**
   *   Regularly review certificate templates and permissions using:

       ```powershell
       certutil -v -template
       ```
3. **Monitor CA Private Key Access:**
   * Check for unauthorised access or export attempts for the CA private key.
4. **Apply Patches:**
   * Address vulnerabilities like **CVE-2022-26923** that can be exploited in AD CS environments.
{% endtab %}

{% tab title="Query 3" %}
Query to detect potential Golden Certificate attacks:

{% code overflow="wrap" %}
```kusto
// Define the time range for the query
let startTime = ago(7d);
let endTime = now();

// Step 1: Identify suspicious certificate requests
let SuspiciousCertRequests = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4886 // Certificate Services received a certificate request
| extend Requester = tostring(TargetUserName), RequesterIP = tostring(IpAddress), CertTemplate = tostring(TemplateName)
| summarize RequestCount = count(), UniqueIPs = dcount(RequesterIP), RequesterIPs = make_set(RequesterIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Requester, CertTemplate
| where RequestCount > 5 // Adjust threshold based on your environment
| project Requester, CertTemplate, RequestCount, UniqueIPs, RequesterIPs, FirstSeen, LastSeen;

// Step 2: Identify certificate issuance events
let CertIssuanceEvents = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4887 // Certificate Services issued a certificate
| extend Issuer = tostring(TargetUserName), IssuerIP = tostring(IpAddress), CertTemplate = tostring(TemplateName)
| summarize IssuanceCount = count(), UniqueIPs = dcount(IssuerIP), IssuerIPs = make_set(IssuerIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Issuer, CertTemplate
| where IssuanceCount > 5 // Adjust threshold based on your environment
| project Issuer, CertTemplate, IssuanceCount, UniqueIPs, IssuerIPs, FirstSeen, LastSeen;

// Step 3: Combine suspicious certificate requests and issuance events
SuspiciousCertRequests
| join kind=inner (CertIssuanceEvents) on CertTemplate
| project Requester, Issuer, CertTemplate, RequestCount, IssuanceCount, UniqueIPs, RequesterIPs, IssuerIPs, FirstSeen, LastSeen
| order by RequestCount desc, IssuanceCount desc
```
{% endcode %}

Query performs the following steps:

1. **Defines the time range** for the query to look back over the past 7 days.
2. **Identifies suspicious certificate requests** by looking for Event ID 4886 and summarizing the data based on the requester and certificate template.
3. **Identifies certificate issuance events** by looking for Event ID 4887 and summarizing the data based on the issuer and certificate template.
4. **Combines the results** to identify potential compromises by matching suspicious certificate requests with issuance events.
{% endtab %}
{% endtabs %}

### Splunk Dection Queries

Detecting a **Golden Certificate** attack in Splunk involves monitoring unusual certificate issuance events, unauthorised access to Certificate Authority (CA) servers, and anomalous certificate usage for authentication. Below is a Splunk query to detect potential Golden Certificate activities based on **AD CS logs**, **Windows Security logs**, and Kerberos activity.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query to Detect Golden Certificate

{% code overflow="wrap" %}
```splunk-spl
index=windows (EventCode=4886 OR EventCode=4887 OR EventCode=4624 OR EventCode=4769)
| eval EventDescription = case(
    EventCode == 4886, "Certificate Request",
    EventCode == 4887, "Certificate Issued",
    EventCode == 4624, "Successful Logon",
    EventCode == 4769, "Kerberos Service Ticket",
    true(), "Unknown"
)
| eval CertificateTemplate = coalesce(TemplateName, ""), 
        Requestor = coalesce(RequestorName, TargetUserName),
        TargetServer = coalesce(TargetServerName, ComputerName)
| where (EventCode==4887 AND CertificateTemplate IN ("DomainAdmin", "Administrator", "PrivilegedAccess"))  // Suspicious templates
  OR (EventCode==4624 AND TargetServer LIKE "%CertificateServices%")  // Logon to CA server
  OR (EventCode==4769 AND TicketOptions IN ("forwardable", "renewable"))  // Anomalous Kerberos tickets
| stats count AS EventCount, 
        values(EventDescription) AS EventTypes, 
        values(CertificateTemplate) AS Templates, 
        values(Requestor) AS Requestors, 
        values(TargetServer) AS TargetServers, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName
| where EventCount > 5  // Threshold for suspicious activity
| eval SuspiciousScore = case(
    Templates IN ("DomainAdmin", "Administrator"), "High",
    Templates IN ("PrivilegedAccess"), "Medium",
    true(), "Low"
)
| where SuspiciousScore IN ("High", "Medium")
| table ComputerName, EventTypes, Templates, Requestors, TargetServers, EventCount, FirstSeen, LastSeen, SuspiciousScore
| sort - SuspiciousScore, -EventCount
```
{% endcode %}

#### **Query Breakdown**

1. **Target Event Codes:**
   * **4886:** Certificate requested.
   * **4887:** Certificate issued.
   * **4624:** Successful logons (used to detect CA server access).
   * **4769:** Kerberos Service Ticket events (to track certificate-based authentication).
2. **Field Parsing:**
   * Extract key fields like `CertificateTemplate`, `Requestor`, and `TargetServer` from logs.
3. **Focus on Suspicious Activity:**
   * Filters for:
     * Certificates issued using high-privilege templates (e.g., "DomainAdmin", "Administrator").
     * Logons to CA servers (`TargetServer LIKE "%CertificateServices%"`).
     * Kerberos tickets with unusual options (e.g., `forwardable`, `renewable`).
4. **Aggregate Suspicious Events:**
   * Groups events by `ComputerName` and aggregates event types, templates, and requestors.
5. **Threshold and Scoring:**
   * Flags computers with multiple suspicious events and assigns a **SuspiciousScore**:
     * **High:** Usage of "DomainAdmin" or "Administrator" templates.
     * **Medium:** Usage of "PrivilegedAccess" templates.
6. **Output:**
   * Displays key details, including the server, event types, suspicious templates, requestors, and the time range of activity.
{% endtab %}

{% tab title="Query 2" %}
#### **Advanced Query for Unauthorised Private Key Access**

To detect potential access or export attempts for the CA private key:

{% code overflow="wrap" %}
```splunk-spl
index=windows EventCode=5136
| eval ObjectName = coalesce(ObjectName, ""), 
        AttributeName = coalesce(AttributeName, "")
| where ObjectName LIKE "%CertificateAuthority%" AND AttributeName == "msPKI-PrivateKey"
| stats count AS AccessAttempts, 
        values(Account_Name) AS Accounts, 
        values(IpAddress) AS SourceIPs, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ObjectName
| where AccessAttempts > 0
| table ObjectName, AccessAttempts, Accounts, SourceIPs, FirstSeen, LastSeen
| sort - AccessAttempts
```
{% endcode %}

#### **Customisations**

1. **Whitelist Trusted Templates or Accounts:**
   *   Exclude known safe templates or accounts:

       {% code overflow="wrap" %}
       ```kusto
       | where NOT CertificateTemplate IN ("SafeTemplate") AND NOT Requestor IN ("TrustedAdmin", "ServiceAccount")
       ```
       {% endcode %}
2. **Adjust Thresholds:**
   * Modify `EventCount > 5` based on the normal activity levels in your environment.
3. **Time-Based Grouping:**
   *   Add `bin _time` to detect bursts of activity:

       ```spl
       | bin _time span=15m
       ```
4. **Track Privileged Template Usage:**
   *   Monitor usage of all templates associated with administrative privileges:

       {% code overflow="wrap" %}
       ```kusto
       | where CertificateTemplate IN ("DomainAdmin", "Administrator", "EnterpriseAdmin")
       ```
       {% endcode %}

***

#### **Detection Recommendations**

1. **Set Alerts:**
   * Configure alerts for:
     * High-risk templates being used.
     * Multiple access attempts to CA private keys.
2. **Audit Certificate Templates:**
   *   Regularly review permissions and configurations of certificate templates:

       ```powershell
       certutil -v -template
       ```
3. **Protect the CA Private Key:**
   * Use hardware security modules (HSMs) to store CA private keys securely.
4. **Monitor Certificate Authentication:**
   * Identify unusual or unauthorized authentication using certificates in Kerberos or other authentication protocols.
{% endtab %}

{% tab title="Query 3" %}
Query to detect potential Golden Certificate attacks:

{% code overflow="wrap" %}
```splunk-spl
index=windows sourcetype=add_your_sourcetype
| eval AccountName = mvindex(Account_Name, 1)
| where EventCode IN (4886, 4887) // Certificate Services received a certificate request or issued a certificate
| stats count AS EventCount, values(IpAddress) AS SourceIPs, dc(IpAddress) AS UniqueSourceIPs BY AccountName, EventCode
| where EventCount > 5 // Adjust threshold based on your environment
| table _time, AccountName, EventCode, EventCount, UniqueSourceIPs, SourceIPs
| sort - EventCount
```
{% endcode %}

Query performs the following steps:

1. **Filters events** to include only those with EventCode 4886 (Certificate Services received a certificate request) and EventCode 4887 (Certificate Services issued a certificate).
2. **Evaluates the AccountName** to identify the user involved in the certificate request or issuance.
3. **Aggregates the data** to count the number of events and unique IPs per AccountName and EventCode.
4. **Filters the results** to include only those with more than 5 events (adjust the threshold based on your environment).
5. **Displays the results** in a table format, sorted by the number of events.
{% endtab %}
{% endtabs %}
