# Golden Ticket

### Introduction

The **Golden Ticket** is a highly advanced and dangerous attack technique leveraged by threat actors to gain persistent and virtually unlimited access to an organisation's network. It targets **Active Directory (AD)**, which is the cornerstone of identity and access management in most enterprise environments. The attack exploits the core functionality of Kerberos, a network authentication protocol, allowing attackers to impersonate any user or service in the domain.

Named after the concept of a "golden ticket" that provides unlimited access, this technique represents a worst-case scenario for security professionals, as it bypasses standard authentication mechanisms and is exceedingly difficult to detect.

***

### Attack Description

In a **Golden Ticket** attack, the adversary generates a forged Kerberos ticket-granting ticket (**TGT**) using the Kerberos protocol. This allows them to authenticate as any user, including privileged accounts like Domain Admins, for an indefinite period. The attack hinges on compromising the **KRBTGT account**, a highly sensitive account used to encrypt and sign all TGTs in the domain.

The key elements of the attack are:

1. **Prerequisites:**
   * The attacker must have administrative access to a domain controller or access to the domain's **KRBTGT account hash**.
   * This is typically achieved through techniques like **credential theft**, **Pass-the-Hash**, or exploitation of Active Directory vulnerabilities.
2. **Execution:**
   * Once the KRBTGT hash is obtained, the attacker uses tools like **Mimikatz** to forge a valid TGT.
   * The forged ticket is then injected into the current session, allowing the attacker to impersonate any user or service on the domain.
3. **Capabilities:**
   * Persistent access: The forged TGT can be configured to remain valid indefinitely, even after password resets.
   * Privilege escalation: The attacker can impersonate high-privilege accounts, such as Domain Admins, to perform sensitive operations.
   * Stealth: The attack often bypasses traditional detection methods, as the TGT appears legitimate to the domain.
4. **Detection and Mitigation Challenges:**
   * Since the Golden Ticket relies on the compromised KRBTGT hash, typical password changes do not mitigate the risk.
   * Detecting Golden Tickets is challenging because they leverage the same cryptographic mechanisms used by legitimate tickets.
5. **Indicators of Compromise (IoCs):**
   * Unusual account activity, such as privilege escalation without prior authorisation.
   * Authentication events where the TGT does not match normal ticket issuance patterns.
   * Abnormal logins from service accounts or sensitive administrative accounts.

***

### Significance for Security Operations Centres (SOCs)

The Golden Ticket attack is particularly devastating in the context of **enterprise security** because of its capability to completely compromise Active Directory environments. SOC analysts and security teams must prioritise proactive threat hunting and defence strategies to mitigate its impact, including:

* **Regular KRBTGT password resets** (twice, in a staggered manner, to invalidate all existing tickets).
* Monitoring for suspicious activities in the **Windows Security Event Logs**, such as Event ID 4769 (Kerberos Service Ticket Request).
* Implementing tools and techniques for **Active Directory auditing** and **Kerberos traffic inspection**.
* Deploying Endpoint Detection and Response (EDR) and threat-hunting solutions like **Velociraptor** or **Defender XDR** to identify anomalous patterns.

By understanding the mechanics and implications of the Golden Ticket attack, SOC teams can better defend against this high-impact threat.

### KQL Detection Queries

To detect a **Golden Ticket** attack using KQL (Kusto Query Language) in tools like Microsoft Sentinel or Defender for Endpoint, you can analyse Windows Security Event Logs, mainly focusing on Kerberos ticketing events.&#x20;

{% tabs %}
{% tab title="Query 1" %}
KQL Query: Detecting Golden Ticket Attack

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (4768, 4769, 4770) // Kerberos authentication events
| extend TicketOptions = extractjson("$.TicketOptions", AdditionalInfo, typeof(string))
| where EventID == 4768 and TicketOptions contains "0x40810010" // Unusual TGT flags
    or EventID == 4769 and ServiceName == "krbtgt" and (TimeToLive > 10d or TimeToLive == 0) // Abnormally long ticket lifetime
    or EventID == 4770 and Status in ("0xC00000BB", "0xC000019B") // Unusual status codes for Kerberos requests
| extend AnomalousAttributes = iff(EventID == 4768, "Suspicious TGT request", 
                            iff(EventID == 4769, "Abnormal Service Ticket Request", 
                            "TGT Renewal Anomaly"))
| summarize Count = count() by Computer, AccountName, TargetDomainName, EventID, AnomalousAttributes, bin(TimeGenerated, 1h)
| order by Count desc
```
{% endcode %}

#### Explanation of Query Logic

1. **Filter Events**:
   * Focus on Kerberos-related event IDs:
     * `4768`: TGT request.
     * `4769`: Service ticket request.
     * `4770`: TGT renewal.
2. **Unusual Flags in TGT**:
   * A Golden Ticket often includes uncommon ticket options (`0x40810010`) that indicate high privilege and a manually crafted ticket.
3. **Abnormally Long Ticket Lifetimes**:
   * Legitimate Kerberos tickets have limited lifetimes (typically 10 hours). Golden Tickets often have unusually long or unlimited lifetimes (`TimeToLive == 0`).
4. **Status Code Anomalies**:
   * Certain status codes like `0xC00000BB` (invalid ticket) or `0xC000019B` (service request anomaly) may indicate suspicious activity.
5. **Anomalous Attributes**:
   * Events are labeled with attributes that point to their anomalous nature for easier SOC investigation.
6. **Summarisation**:
   * Events are grouped and counted by key dimensions, such as `Computer`, `AccountName`, and `EventID`, allowing SOC analysts to spot trends or outliers.

***

#### Next Steps for Investigation

1. **Validate with Additional Context**:
   * Cross-reference detected anomalies with other logs, such as process creation or lateral movement events.
2. **Examine KRBTGT Activity**:
   * Look for unauthorised access to the KRBTGT account and verify its password change history.
3. **Forensic Actions**:
   * Isolate affected systems and reset KRBTGT passwords (twice) to invalidate forged tickets.
{% endtab %}

{% tab title="Query 2" %}
Query to detect potential Golden Ticket attacks in your environment:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4769
| where TargetUserName endswith "$"
| where ServiceName == "krbtgt"
| where TicketOptions has_any ("renewable", "forwardable")
| project TimeGenerated, Computer, TargetUserName, ServiceName, TicketOptions, IpAddress, AccountName
```
{% endcode %}

Query looks for Kerberos Service Ticket Requests (Event ID 4769) where the target username ends with a dollar sign (`$`), indicating a service account, and the service name is `krbtgt`. It also checks for ticket options that are renewable or forwardable, which are common characteristics of Golden Ticket attacks.
{% endtab %}

{% tab title="Query 3" %}
Advanced KQL Query: Detecting Golden Ticket Activity

{% code overflow="wrap" %}
```kusto
let KerberosAnomalies = SecurityEvent
| where EventID in (4768, 4769, 4770) // Focus on Kerberos-related events
| extend TicketOptions = extractjson("$.TicketOptions", AdditionalInfo, typeof(string))
| extend EncryptedData = extractjson("$.EncryptedData", AdditionalInfo, typeof(string))
| extend TimeToLive = extractjson("$.TimeToLive", AdditionalInfo, typeof(int))
| extend TargetServiceName = iif(EventID == 4769, ServiceName, "N/A")
| extend AnomalousBehavior = case(
    EventID == 4768 and TicketOptions contains "0x40810010", "Suspicious TGT Options",
    EventID == 4769 and TargetServiceName == "krbtgt" and (TimeToLive > 10d or TimeToLive == 0), "Abnormal Ticket Lifetime",
    EventID == 4770 and Status in ("0xC00000BB", "0xC000019B"), "TGT Renewal Anomaly",
    EventID == 4768 and AccountName contains "$", "Service Account TGT Request",
    EventID == 4769 and EncryptedData contains "AES256_CTS_HMAC_SHA1_96", "Unusual Encryption Method",
    "Normal"
)
| where AnomalousBehavior != "Normal";
let SuspiciousActivity = SecurityEvent
| where EventID in (4624, 4672, 4688) // Privileged logons and process creation events
| extend LogonType = extractjson("$.LogonType", AdditionalInfo, typeof(int))
| extend PrivilegeElevated = (EventID == 4672)
| extend ParentCommandLine = extractjson("$.ParentCommandLine", AdditionalInfo, typeof(string))
| where PrivilegeElevated == true or LogonType in (2, 3) // Interactive or Network logons
| extend AnomalousBehavior = case(
    EventID == 4624 and AccountName contains "$", "Unusual Service Account Logon",
    EventID == 4688 and ProcessName endswith "mimikatz.exe", "Suspicious Process Execution",
    "Normal"
)
| where AnomalousBehavior != "Normal";
KerberosAnomalies
| union SuspiciousActivity
| summarize Count = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Computer, AccountName, TargetDomainName, EventID, AnomalousBehavior
| extend TimeWindow = LastSeen - FirstSeen
| order by Count desc
```
{% endcode %}

#### Explanation of Advanced Features

1. **Enhanced Detection Criteria**:
   * Adds additional layers to identify Golden Ticket patterns:
     * Suspicious encryption methods (`AES256_CTS_HMAC_SHA1_96`), often used in manually forged tickets.
     * Service accounts (`$`) making unusual TGT requests.
     * Elevated privilege actions or anomalous logon behaviours.
2. **Behavioural Context**:
   * Incorporates related events like privileged logons (`EventID 4672`) and process executions (`EventID 4688`) to correlate potential misuse of privileges with Kerberos anomalies.
3. **Dynamic Labelling**:
   * Events are dynamically tagged with `AnomalousBehavior` descriptions to help analysts understand the context.
4. **Summarisation and Prioritisation**:
   * Groups suspicious activities by computer, account, and domain, along with timestamps (`FirstSeen`, `LastSeen`) for a time-based view of the attack.
5. **Combining Activity**:
   * Merges results from Kerberos-specific anomalies with broader suspicious activities (e.g., unusual process executions) for a holistic threat view.

***

#### Advanced Use Cases

* **Golden Ticket Behaviour Analysis**: Detect extended persistence or lateral movement enabled by forged TGTs.
* **Prioritised Alerts**: Focus on accounts or systems with multiple anomalous activities.
* **Forensic Investigation**: Time window (`TimeWindow`) and event summaries aid in tracing attack paths.

***

#### Recommendations for Customisation

* Adjust the thresholds for **TimeToLive** and logon types to align with your organisation’s specific Kerberos and logon policies.
* Incorporate integration with **Defender XDR** or **Active Directory audit logs** for deeper analysis of account behaviours.
* Add threat intelligence feeds to cross-reference accounts or IPs involved in the anomalies.
{% endtab %}

{% tab title="Query 4" %}
Query to detect potential Golden Ticket attacks, incorporating additional details and filtering for suspicious activities:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (4768, 4769, 4770, 4771)
| where TargetUserName endswith "$"
| where ServiceName == "krbtgt"
| where TicketOptions has_any ("renewable", "forwardable")
| extend AccountDomain = split(TargetUserName, "@")[1]
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 3
    | where AuthenticationPackageName == "Kerberos"
    | project LogonTime = TimeGenerated, LogonComputer = Computer, LogonIpAddress = IpAddress, LogonAccountName = AccountName
) on $left.IpAddress == $right.LogonIpAddress
| project TimeGenerated, Computer, TargetUserName, ServiceName, TicketOptions, IpAddress, AccountName, LogonTime, LogonComputer, LogonAccountName, AccountDomain
| order by TimeGenerated desc
```
{% endcode %}

Query does the following:

1. Looks for Kerberos-related events (Event IDs 4768, 4769, 4770, 4771).
2. Filters for service accounts (TargetUserName ending with `$`) and the `krbtgt` service.
3. Checks for ticket options that are renewable or forwardable.
4. Extracts the account domain from the TargetUserName.
5. Joins with logon events (Event ID 4624) to correlate Kerberos authentication with logon activities.
6. Projects relevant fields and orders the results by the time generated.

This query should help you detect more sophisticated Golden Ticket attacks by correlating Kerberos ticket requests with actual logon events.
{% endtab %}
{% endtabs %}

### Splunk Detection Query

The following are Splunk queries to detect potential **Golden Ticket** attacks by analysing Windows Security Event Logs, focusing on suspicious Kerberos activity:

{% tabs %}
{% tab title="Query 1" %}
Splunk Query: Detecting Golden Ticket Activity

{% code overflow="wrap" %}
```spl
index=wineventlog (EventCode=4768 OR EventCode=4769 OR EventCode=4770) 
| eval AnomalousBehavior = case(
    EventCode==4768 AND like(Ticket_Options, "%0x40810010%"), "Suspicious TGT Options",
    EventCode==4769 AND like(Service_Name, "%krbtgt%") AND (Ticket_Lifetime > 864000 OR Ticket_Lifetime=0), "Abnormally Long Ticket Lifetime",
    EventCode==4770 AND (Status="0xC00000BB" OR Status="0xC000019B"), "TGT Renewal Failure",
    EventCode==4768 AND like(Account_Name, "%$"), "Service Account TGT Request",
    EventCode==4769 AND like(Encryption_Type, "%AES256_CTS_HMAC_SHA1_96%"), "Unusual Encryption Method",
    1=1, "Normal"
)
| search AnomalousBehavior!="Normal"
| stats count, earliest(_time) AS FirstSeen, latest(_time) AS LastSeen BY host, Account_Name, Service_Name, AnomalousBehavior
| eval TimeWindow = tostring(LastSeen - FirstSeen, "duration")
| rename host AS Computer, Account_Name AS AccountName, Service_Name AS ServiceName
| table Computer, AccountName, ServiceName, AnomalousBehavior, count, FirstSeen, LastSeen, TimeWindow
| sort - count
```
{% endcode %}

#### Explanation of Query Components

1. **Events of Interest**:
   * Event ID 4768: TGT request (Ticket Granting Ticket).
   * Event ID 4769: Service ticket request.
   * Event ID 4770: TGT renewal.
2. **Anomalous Conditions**:
   * **Suspicious TGT Options**: Detects rare Kerberos flags (e.g., `0x40810010`) used in manually crafted TGTs.
   * **Long Ticket Lifetimes**: Golden Tickets often have lifetimes exceeding normal thresholds (e.g., 10 days) or are set to never expire (`Lifetime = 0`).
   * **Renewal Failures**: Certain Kerberos renewal errors (`0xC00000BB`, `0xC000019B`) may indicate tampered tickets.
   * **Unusual Encryption**: Looks for encryption types associated with manual ticket crafting (`AES256_CTS_HMAC_SHA1_96`).
   * **Service Account Activity**: Service accounts (`$`) making unexpected TGT requests.
3. **Behaviour Labeling**:
   * Assigns a descriptive label (`AnomalousBehavior`) to suspicious activities for easier investigation.
4. **Summarization**:
   * Groups anomalies by key attributes such as `host`, `Account_Name`, and `Service_Name`.
   * Calculates timestamps (`FirstSeen`, `LastSeen`) to establish a timeframe for the activity.
   * Adds a `TimeWindow` field to show the duration between the first and last detected anomalies.
5. **Result Presentation**:
   * Displays key fields (`Computer`, `AccountName`, `ServiceName`, `AnomalousBehavior`) for SOC investigation.
   * Orders results by the number of anomalies (`count`) to prioritise investigation.

***

#### Recommendations for Optimisation

1. **Log Field Extraction**:
   * Ensure fields like `Ticket_Options`, `Service_Name`, `Encryption_Type`, and `Ticket_Lifetime` are extracted from your Windows Event Logs.
2. **Baseline Normal Behavior**:
   * Identify normal patterns for Kerberos activity in your environment and adjust thresholds (e.g., ticket lifetimes) accordingly.
3. **Correlate with Additional Logs**:
   * Combine results with process execution (EventCode 4688) or privilege escalation logs (EventCode 4672) for broader context.
4. **Alerting**:
   * Set up alerts in Splunk for high-priority anomalies like `Suspicious TGT Options` or `Abnormally Long Ticket Lifetimes`.
{% endtab %}

{% tab title="Query 2" %}
Splunk query to detect potential Golden Ticket attacks in your environment:

{% code overflow="wrap" %}
```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4768 OR EventCode=4769 OR EventCode=4770 OR EventCode=4771)
TargetUserName="*$"
ServiceName="krbtgt"
TicketOptions="*renewable*" OR TicketOptions="*forwardable*"
| stats count by _time, ComputerName, TargetUserName, ServiceName, TicketOptions, IpAddress, AccountName
| sort -_time
```
{% endcode %}

Query does the following:

1. Searches for Kerberos-related events (Event Codes 4768, 4769, 4770, 4771).
2. Filters for service accounts (TargetUserName ending with `$`) and the `krbtgt` service.
3. Checks for ticket options that are renewable or forwardable.
4. Aggregates the results by time, computer name, target username, service name, ticket options, IP address, and account name.
5. Sorts the results by time in descending order.

This should help you detect potential Golden Ticket attacks by identifying suspicious Kerberos ticket requests.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
