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

# Active Directory Certificate Services (AD CS) Compromise

### **Introduction to Active Directory Certificate Services (AD CS) Compromise**

**Active Directory Certificate Services (AD CS)** is a Microsoft role that enables organisations to build and manage a Public Key Infrastructure (PKI). AD CS is often used to issue and manage certificates for secure communication, authentication, and encryption within a Windows environment. While AD CS is a powerful tool for securing an enterprise, misconfigurations or improper implementation can make it a prime target for attackers.

An **AD CS compromise** occurs when attackers exploit vulnerabilities, misconfigurations, or design flaws in the PKI infrastructure to escalate privileges, impersonate users or devices, and establish persistent access within a network. This tactic is classified under the **Credential Access**, **Privilege Escalation**, and **Persistence** tactics in the **MITRE ATT\&CK Framework** (e.g., T1552.003).

***

### **How Active Directory Certificate Services Works**

1. **Certificate Authority (CA):**
   * AD CS acts as a Certificate Authority that issues and manages certificates based on predefined templates.
2. **Certificate Templates:**
   * Templates define the rules for certificate issuance, including permissions, key usage, and subject details.
3. **Authentication and Security:**
   * Certificates issued by AD CS can be used for authentication, encrypting communications, signing emails, and more.
4. **Integration with Active Directory:**
   * AD CS integrates tightly with Active Directory, allowing seamless use of certificates for domain accounts and resources.

***

### **How Attackers Exploit AD CS**

1. **Misconfigured Certificate Templates:**
   * Templates with overly permissive configurations (e.g., allowing enrollment by unauthorised users or services) can be abused to issue certificates for privilege escalation.
2. **Escalation via Certificate Requests:**
   * Attackers forge certificate requests to impersonate privileged accounts, such as domain administrators.
3. **NTLM Relay Attacks:**
   * Vulnerabilities like **CVE-2022-26923** allow attackers to abuse the AD CS Enrollment Web Service to relay NTLM authentication and obtain certificates.
4. **Persistent Access:**
   * Certificates are long-lived compared to passwords and can be reused by attackers to maintain access, even if credentials are rotated.
5. **Service Account Exploitation:**
   * Attackers compromise service accounts with certificate enrollment privileges and use them to request malicious certificates.
6. **Certificate Theft:**
   * Once a certificate and private key are stolen, attackers can impersonate legitimate users or services.

***

### **Risks of AD CS Compromise**

1. **Privilege Escalation:**
   * Certificates can grant attackers elevated privileges within the domain.
2. **Lateral Movement:**
   * Stolen certificates allow attackers to access other resources or impersonate users.
3. **Persistence:**
   * Certificates provide long-term access, bypassing password expiration policies and multifactor authentication (MFA).
4. **Stealthy Attacks:**
   * Certificates can be used to establish encrypted channels, making attacker activity harder to detect.

***

### **Indicators of AD CS Compromise**

1. **Unusual Certificate Requests:**
   * Certificates requested by unauthorised accounts or for privileged templates.
2. **Misconfigured Templates:**
   * Templates allowing enrollment by non-administrative users or accounts.
3. **Excessive Access to AD CS Servers:**
   * Unauthorised users accessing the Certificate Authority (CA) server or enrollment web services.
4. **Use of Stolen Certificates:**
   * Authentication or encryption activity involving certificates not typically used by the legitimate account.

***

### **Detection Techniques**

1. **Monitor Certificate Issuance:**
   * Track certificate requests and issuance using AD CS logs (Event ID **4886**, **4887**, **4888**, etc.).
     * **Event ID 39:** Event generated when no strong certificate mappings can be found, and the certificate does not have a new Security Identifier (SID) extension that the Key Distribution Centre (KDC) could validate.
     * **Event ID 40: E**vent generated when a certificate is supplied that was issued to the user before the user existed in Active Directory, and no strong mapping is found.
     * **Event ID 41:** Event generated when a certificate is supplied where the SID contained in the new extension of the user's certificate does not match the user’s SID, implying that the certificate was issued to another user.
     * **Event ID 1102:** Event generated when the Security audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Can assist in identifying if an AD CS CA has been compromised.
     * **Event ID 4674:** Event generated when an attempt is made to perform privileged operations on a protected subsystem object after the object is already opened.
     * **Event ID 4768:** Event generated when a TGT is requested. The ‘PreAuthType’ of ‘16’ indicates that a certificate was used in the TGT request.
     * **Event ID 4886:** Event generated when AD CS receives a certificate request. This may indicate if malicious actors attempted to elevate privileges by requesting an authentication certificate for a privileged user.
     * **Event ID 4887:** Event generated when AD CS approves a certificate request and issues a certificate. This may be used to indicate when malicious actors successfully escalated privileges using AD CS.
     * **Event ID 4899:** Event generated when a certificate template is updated. This may occur when malicious actors attempt to modify a certificate template to introduce additional features that may make it vulnerable to privilege escalation.
     * **Event ID 4900:** Event generated when security settings on a Certificate Services template are updated. This may occur when the Access Control List on the template has been modified to potentially introduce vulnerable conditions, such as modification of enrolment rights to a certificate template.
2. AD CS event auditing is not enabled by default. Follow these steps to configure audit logging for AD CS:
   * Enable ‘Audit object access’ for Certificate Services in Group Policy for AD CS CAs. This can be found within the ‘Advanced Audit Policy Configuration’ within Security Settings.
   * Within the CA properties, the Auditing tab shows configurations of events to log. Enable all available options.
3. **Detect Misconfigured Templates:**
   *   Audit certificate templates for permissions and key usages that could allow abuse:

       ```powershell
       certutil -v -template
       ```
4. **Analyse NTLM Relay Attacks:**
   * Monitor network traffic and logs for NTLM relay activity targeting AD CS Enrollment Web Services.
5. **Track Certificate Usage:**
   * Use SIEM tools to identify authentication activity involving unusual certificates.

***

### **Mitigation Strategies**

1. **Harden Certificate Templates:**
   * Review and restrict permissions on certificate templates to limit who can enrol for certificates.
2. **Enable Enhanced Key Usage (EKU):**
   * Configure templates to restrict certificates to specific purposes, reducing the attack surface.
3. **Audit AD CS Configurations:**
   * Regularly review CA configurations, template permissions, and enrollment methods.
4. **Implement Strong Access Controls:**
   * Restrict access to AD CS servers, enrollment services, and certificate templates.
5. **Monitor Certificate Revocation:**
   * Use Certificate Revocation Lists (CRLs) to invalidate compromised certificates.
6. **The following security controls should be implemented to mitigate an ESC1 AD CS compromise:**&#x20;
   * Remove the Enrolee Supplies Subject flag. Do not allow users to provide their own SAN in the certificate signing request for templates configured for client authentication. Templates configured with the Enrolee Supplies Subject flag allow a user to provide their own SAN.
   * Restrict standard user object permissions on certificate templates. Standard user objects should not have write permissions on certificate templates. User objects with write permissions may be able to change enrolment permissions or configure additional settings to make the certificate template vulnerable.
   * Remove vulnerable AD CS CA configurations. Ensure that the CA is not configured with the EDITF\_ATTRIBUTESUBJECTALTNAME2 flag. When configured, this allows a SAN to be provided on any certificate template.
   * Require CA Certificate Manager approval for certificate templates that allow the SAN to be supplied. This ensures certificate templates that require CA certificate manager approval are not issued automatically when requested; instead, they must be approved using certificate manager before the certificate is issued.
   * Remove EKUs that enable user authentication. This prevents malicious actors from exploiting the certificate to authenticate as other users.
   * Limit access to AD CS CA servers to only privileged users that require access. This may be a smaller subset of privileged users than the Domain Admins security group and reduces the number of opportunities for malicious actors to gain access to CA servers.
   * Restrict privileged access pathways to AD CS CA servers to jump servers and secure admin workstations using only the ports and services that are required for administration. AD CS servers are classified as ‘Tier 0’ assets within Microsoft’s ‘Enterprise Access Model’.
   * Only use AD CS CA servers for AD CS and do not install any non-security-related services or applications. This reduces the attack surface of AD CS CA servers as there are fewer services, ports and applications that may be vulnerable and used to compromise an AD CS CA server.
   * Encrypt and securely store backups of AD CS CA servers and limit access to only Backup Administrators. Backups of AD CS CA servers need to be afforded the same security as the actual AD CS CA servers. Malicious actors may target backup systems to gain access to critical and sensitive computer objects, such as AD CS CA servers.
   * Centrally log and analyse AD CS CA server logs in a timely manner to identify malicious activity. If malicious actors gain privileged access to a CA server, this activity should be identified as soon as possible to respond and limit the impact.
7. **Apply Patches:**
   * Ensure your environment is protected against vulnerabilities like **CVE-2022-26923**.

***

#### **Example Threat Hunting Queries**

**Identify Misconfigured Templates in AD CS:**

```powershell
certutil -template | findstr "Permissions"
```

**Monitor Certificate Requests in Logs:**

* Look for Event ID **4886** for certificate requests and **4887** for issued certificates in the Certificate Services logs.

***

AD CS provides critical infrastructure for secure authentication and encryption, but misconfigurations or vulnerabilities can make it a target for attackers. A compromised AD CS environment can lead to privilege escalation, lateral movement, and persistent access, often with minimal detection. By hardening configurations, monitoring certificate activity, and addressing vulnerabilities, organisations can significantly reduce the risks associated with AD CS compromise.

### KQL Detection Queries

Detecting potential compromise of **Active Directory Certificate Services (AD CS)** requires monitoring certificate issuance, template misuse, unauthorised access to AD CS services, and suspicious certificate requests. This detection can be achieved by querying logs from Windows Event Logs (Certificate Services logs) and Active Directory in Microsoft Sentinel using **KQL**.

{% tabs %}
{% tab title="Query 1" %}
Query to detect potential compromises in Active Directory Certificate Services (AD CS):

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
2. **Identifies suspicious certificate requests** by looking for Event ID 4886 and summarising the data based on the requester and certificate template.
3. **Identifies certificate issuance events** by looking for Event ID 4887 and summarising the data based on the issuer and certificate template.
4. **Combines the results** to identify potential compromises by matching suspicious certificate requests with issuance events.
{% endtab %}

{% tab title="Query 2" %}
KQL Query to Detect AD CS Misuse and Compromise

{% code overflow="wrap" %}
```kusto
// Query Certificate Services Logs for Suspicious Certificate Activity
SecurityEvent
| where EventID in (4886, 4887, 4888, 4889)  // Certificate Services events
| extend EventDescription = case(
    EventID == 4886, "Certificate Request",
    EventID == 4887, "Certificate Issued",
    EventID == 4888, "Certificate Revoked",
    EventID == 4889, "Certificate Denied",
    "Unknown"
)
| extend Requestor = parse_json(tostring(EventData.RequestorName)), 
         Template = tostring(EventData.TemplateName),
         SerialNumber = tostring(EventData.SerialNumber)
| summarize EventCount = count(), 
            Requestors = make_set(Requestor), 
            Templates = make_set(Template), 
            SerialNumbers = make_set(SerialNumber), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
    by EventID, EventDescription, Computer
| where EventID == 4886 or EventID == 4887  // Focus on certificate requests and issuance
| where Templates contains "Administrator" or Templates contains "DomainAdmin"  // Look for suspicious templates
| extend SuspiciousActivity = case(
    Templates contains "Administrator", "High",
    Templates contains "DomainAdmin", "High",
    true(), "Low"
)
| where SuspiciousActivity == "High"
| project Computer, EventDescription, Templates, Requestors, SerialNumbers, FirstSeen, LastSeen, SuspiciousActivity
| sort by LastSeen desc
```
{% endcode %}

#### **Query Breakdown**

1. **Target Event IDs:**
   * **4886**: Certificate request.
   * **4887**: Certificate issued.
   * **4888**: Certificate revoked.
   * **4889**: Certificate request denied.
2. **Extract Key Fields:**
   * `Requestor`: The account that requested the certificate.
   * `Template`: The template used to issue the certificate.
   * `SerialNumber`: The serial number of the issued certificate.
3. **Filter for Suspicious Activity:**
   * Focuses on templates commonly abused by attackers, such as those allowing **administrator** or **domain admin** privileges.
4. **Summarize and Aggregate:**
   * Groups data by event type and tracks:
     * `EventCount`: Total number of events.
     * `Requestors`: Unique accounts requesting certificates.
     * `Templates`: Templates used.
     * `FirstSeen` and `LastSeen`: Time range of events.
5. **Flag Suspicious Activity:**
   * Assigns a **High SuspiciousActivity** score to requests using sensitive templates.
6. **Output:**
   * Displays key information for further investigation, sorted by the most recent activity.
{% endtab %}

{% tab title="Query 2" %}
#### **Advanced Query: Correlate with NTLM Relay Attacks**

To detect potential NTLM relay attacks targeting AD CS, monitor for network activity around AD CS servers:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4624  // Successful logons
| extend TargetServer = tostring(EventData.TargetServerName), 
         LogonType = tostring(EventData.LogonType), 
         AccountName = tostring(EventData.TargetUserName)
| where TargetServer has "CertificateServices" and LogonType == "3"  // Network logons to AD CS server
| summarize LogonCount = count(), 
            Accounts = make_set(AccountName), 
            FirstSeen = min(TimeGenerated), 
            LastSeen = max(TimeGenerated) 
    by TargetServer
| where LogonCount > 5  // Adjust threshold based on baseline activity
| project TargetServer, LogonCount, Accounts, FirstSeen, LastSeen
| sort by LogonCount desc
```
{% endcode %}

#### **Customisations**

1. **Threshold Adjustments:**
   * Adjust thresholds for event counts or specific templates based on your environment’s baseline.
2. **Whitelist Trusted Templates or Accounts:**
   *   Exclude known safe templates or service accounts:

       {% code overflow="wrap" %}
       ```kusto
       | where not(Templates contains "SafeTemplate") and not(Requestors has "TrustedServiceAccount")
       ```
       {% endcode %}
3. **Time-Based Analysis:**
   *   Group events into smaller intervals (e.g., 15 minutes) to detect bursts of suspicious activity:

       ```kusto
       | bin TimeGenerated span=15m
       ```
4. **Monitor Privileged Templates:**
   *   Regularly audit templates with elevated permissions:

       ```powershell
       certutil -v -template
       ```

***

#### **Additional Recommendations**

1. **Set Alerts:**
   * Configure alerts in Sentinel for activity involving sensitive templates or abnormal logon patterns to AD CS servers.
2. **Audit AD CS Configurations:**
   * Regularly review templates and CA configurations to identify misconfigurations or excessive permissions.
3. **Monitor Certificate Usage:**
   * Track certificates used for authentication or encryption to ensure they align with expected usage.
4. **Apply Patches:**
   * Ensure your environment is updated to address vulnerabilities such as **CVE-2022-26923**.
{% endtab %}
{% endtabs %}

### Splunk Detection Queries

To detect **Active Directory Certificate Services (AD CS) compromise** in Splunk, you can focus on Windows Security logs and Certificate Services logs for suspicious certificate requests, template abuse, and unauthorized access to Certificate Authority (CA) servers. Below is a Splunk query to detect suspicious AD CS activity.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query to Detect AD CS Compromise

{% code overflow="wrap" %}
```splunk-spl
index=windows (EventCode=4886 OR EventCode=4887 OR EventCode=4888 OR EventCode=4889)
| eval EventDescription = case(
    EventCode == 4886, "Certificate Request",
    EventCode == 4887, "Certificate Issued",
    EventCode == 4888, "Certificate Revoked",
    EventCode == 4889, "Certificate Denied",
    true(), "Unknown"
)
| eval Requestor = mvindex(split(RequestorName, "\\"), -1),  // Extract username
        Template = TemplateName, 
        SerialNumber = CertificateSerialNumber
| stats count AS EventCount, 
        values(Requestor) AS Requestors, 
        values(Template) AS Templates, 
        values(SerialNumber) AS SerialNumbers, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY EventCode, EventDescription, ComputerName
| where EventCode IN (4886, 4887)  // Focus on certificate requests and issuance
| where Templates like "%Admin%" OR Templates like "%DomainAdmin%"  // Look for suspicious templates
| eval SuspiciousScore = case(
    Templates like "%Admin%", "High",
    Templates like "%DomainAdmin%", "High",
    true(), "Low"
)
| where SuspiciousScore == "High"
| table ComputerName, EventDescription, Templates, Requestors, SerialNumbers, FirstSeen, LastSeen, SuspiciousScore
| sort - LastSeen
```
{% endcode %}

#### **Query Breakdown**

1. **Target Events:**
   * **4886:** Certificate request.
   * **4887:** Certificate issued.
   * **4888:** Certificate revoked.
   * **4889:** Certificate denied.
2. **Field Parsing:**
   * Extract key fields like `RequestorName`, `TemplateName`, and `CertificateSerialNumber`.
   * Use `mvindex` to clean up usernames if they include domain prefixes.
3. **Summarize Events:**
   * Groups events by `EventCode` and aggregates key details like `Templates`, `Requestors`, and `SerialNumbers`.
4. **Filter Suspicious Activity:**
   * Focuses on templates associated with high privileges (e.g., "Admin" or "DomainAdmin").
5. **Assign Suspicious Scores:**
   * Assigns a "High" score to requests using sensitive templates for easy prioritization.
6. **Output Key Details:**
   * Displays computers, event descriptions, templates, and requestors for SOC investigation.
{% endtab %}

{% tab title="Query 2" %}
Query to detect potential compromises in Active Directory Certificate Services (AD CS):

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

{% tab title="Query 3" %}
#### **Advanced Query: Detect Unauthorized Logins to AD CS Servers**

To detect unauthorized or unusual access to AD CS servers, you can monitor logon activity:

{% code overflow="wrap" %}
```splunk-spl
index=windows (EventCode=4624 OR EventCode=4625)
| eval LogonTypeDescription = case(
    LogonType == 2, "Interactive",
    LogonType == 3, "Network",
    LogonType == 10, "RemoteInteractive",
    true(), "Other"
)
| stats count AS LogonCount, 
        values(LogonTypeDescription) AS LogonTypes, 
        values(AccountName) AS Accounts, 
        values(IpAddress) AS SourceIPs, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName
| where ComputerName like "%CertificateServices%"  // Focus on CA servers
| where LogonCount > 5  // Adjust threshold based on baseline activity
| table ComputerName, LogonTypes, Accounts, SourceIPs, LogonCount, FirstSeen, LastSeen
| sort - LogonCount
```
{% endcode %}

#### **Customisations**

1. **Whitelist Trusted Templates:**
   *   Exclude known safe templates:

       {% code overflow="wrap" %}
       ```splunk-spl
       | where NOT Templates IN ("SafeTemplate1", "SafeTemplate2")
       ```
       {% endcode %}
2. **Adjust Thresholds:**
   * Modify the thresholds for `LogonCount` or event volume based on your organization's normal behaviour.
3. **Filter Authorized Accounts:**
   *   Exclude accounts that are authorized to request certificates or access CA servers:

       ```splunk-spl
       | where NOT Requestors IN ("TrustedServiceAccount", "CAAdmin")
       ```
4. **Time-Based Analysis:**
   *   Add time-based grouping to detect bursts of activity:

       ```splunk-spl
       | bin _time span=15m
       ```

***

#### **Additional Recommendations**

1. **Set Alerts:**
   * Configure alerts in Splunk for high-risk activity, such as:
     * Certificate requests using sensitive templates.
     * Unauthorized logins to CA servers.
2. **Audit Certificate Templates:**
   *   Periodically review certificate templates for overly permissive configurations:

       ```powershell
       certutil -v -template
       ```
3. **Monitor Certificate Usage:**
   * Track certificates used for authentication or encryption to ensure they align with expected usage.
4. **Protect Against NTLM Relay Attacks:**
   * Harden AD CS by applying patches for known vulnerabilities (e.g., **CVE-2022-26923**) and disabling NTLM where possible.

***

#### **Key Logs to Monitor**

* **Certificate Services Logs:**
  * Event IDs: 4886, 4887, 4888, 4889.
* **Windows Security Logs:**
  * Event IDs: 4624 (successful logons) and 4625 (failed logons).
{% endtab %}
{% endtabs %}

