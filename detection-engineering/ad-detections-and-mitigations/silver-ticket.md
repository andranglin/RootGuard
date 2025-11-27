# Silver Ticket

### **Introduction**

The **Silver Ticket** is a sophisticated attack method within the Kerberos authentication framework that allows attackers to forge **service tickets** (Ticket Granting Service or TGS tickets) for specific services in a Windows domain environment. Unlike the **Golden Ticket**, which targets the entire Key Distribution Center (KDC) and domain, the Silver Ticket attack is more targeted, focusing on a single service. This makes it a stealthier approach for lateral movement and persistence in the environment, as it bypasses the initial Ticket Granting Ticket (TGT) process and avoids logging events in the domain controller.

***

### Attack Description

The attack relies on the attacker obtaining the **NTLM hash** or **Kerberos password hash** of a service account, often through credential dumping tools like Mimikatz. With this information, the attacker can forge a valid TGS ticket for the targeted service. This ticket allows them to impersonate users and interact with the service as if they were authenticated, without involving the domain controller for validation. Common targets include services such as SQL Server, SharePoint, and file servers, where attackers can exfiltrate data, escalate privileges, or maintain persistence.

The Silver Ticket is particularly dangerous because it does not require a connection to the KDC once the ticket is forged. This limits the detection opportunities in domain controller logs and makes the attack challenging to identify using traditional monitoring tools.

***

### **Detection Techniques**

Detecting a Silver Ticket is especially difficult as malicious actors commonly use it to avoid detection. With a forged TGS, threat actors can authenticate directly to a computer object without interacting with a Domain Controller (DC), avoiding any events being logged on a DC. To detect a Silver Ticket, events from the targeted computer object must be analysed. It is common for organisations to log authentication events on DC and less so from other computers in the domain. Cybercriminals are aware of this and may use a Silver Ticket to avoid detection.

1. **Events That Detect a Silver Ticket**
   * Event ID 4624
     * Source: Target computer
     * Description: An event is generated when an account is logged into a computer. It can be correlated and analysed with event 4627 for signs of a potential Silver Ticket.
   * Event ID 4627
     * Source: Target computer
     * Description: Event generated alongside event 4624 and provides additional information regarding the group membership of the logged-in account. This event can be analysed for discrepancies associated with the user object that logged on, such as mismatching SID and group membership information.
     * A Silver Ticket forges the TGS, which can contain false information, such as a different SID to the user object logging on and different group memberships. Malicious actors falsify this information to escalate their privileges on the target computer object.
2. **Analyse Kerberos Service Ticket Logs**:
   * Monitor for anomalies in service ticket requests, such as unusually long ticket lifetimes or tickets for non-existent services.
   * Use tools like Microsoft Sentinel or Splunk to detect abnormal service account usage patterns.
3. **Detect Unusual Service Account Activity**:
   * Review logs for service accounts that do not typically initiate logins but show unexpected access activity.
   * Track authentication events that bypass the TGT process.
4. **Monitor for Tools and Techniques**:
   * Identify usage of tools like Mimikatz in the environment, which are often employed to obtain NTLM hashes for forging tickets.
   * Watch for unauthorised processes accessing sensitive files or directories associated with Kerberos credentials.

***

### **Mitigation Techniques**

1. **Harden Service Accounts**:
   * Use strong, complex passwords for service accounts and rotate them regularly.
   * Employ Group Managed Service Accounts (gMSAs) where possible, as they automatically manage and rotate passwords.
2. **Restrict Service Account Privileges**:
   * Follow the principle of least privilege to ensure service accounts only have the access they require.
   * Remove unnecessary permissions and disable unused accounts.
3. **Enable Kerberos Logging**:
   * Turn on advanced logging for Kerberos events (Event IDs 4768, 4769, 4771) to capture ticketing anomalies.
4. **Implement Privileged Access Management (PAM)**:
   * Use PAM solutions to control and monitor privileged accounts, limiting the exposure of service account credentials.
5. **The following security controls should be implemented to mitigate a Silver Ticket:**&#x20;
   * Create user objects with SPNs as a group of Managed Service Accounts (gMSAs). gMSAs have automatic password rotation, a 120-character password and simplified SPN management. These security features protect the password from being cracked, reducing the likelihood of a successful Silver Ticket. However, if creating user objects with SPNs as gMSAs is not feasible, set a minimum 30-character password that is unique, unpredictable and managed is set.&#x20;
   * Change all computer object (including Domain Controller) passwords every 30 days. Malicious actors can establish persistence in Active Directory using a computer object’s password; ensuring all computer object passwords (including Domain Controller passwords) are changed every 30 days can mitigate this persistence technique.
   * Ensure computer objects are not members of privileged security groups, such as the Domain Admins security group. If malicious actors obtain a computer object’s password hash, then they gain any privileges the computer object has in the domain.&#x20;
   * Ensure the Domain Computers security group does not have write or modify permissions to any objects in Active Directory. All computer objects are members of the Domain Computers security group. If this security group has rights over other objects, then malicious actors can use these rights to compromise other objects, potentially escalate their privileges, and perform lateral movement.
6. **Network Segmentation and Monitoring**:
   * Limit access to critical services and resources using network segmentation.
   * Deploy monitoring solutions to detect abnormal traffic patterns or suspicious activity targeting service accounts.

By implementing robust detection and mitigation measures, organisations can significantly reduce their risk of falling victim to Silver Ticket attacks while improving their overall security posture.

### KQL Detection Queries

The following are **KQL (Kusto Query Language)** queries to detect potential **Silver Ticket** activity by analysing anomalous Kerberos Service Ticket usage patterns in logs. This query looks for signs like unusual service ticket activity, missing pre-authentication (bypassing the KDC), or service accounts behaving abnormally.

{% tabs %}
{% tab title="Query 1" %}
KQL Query to Detect Silver Ticket Activity

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4769 // Kerberos Service Ticket Request
| extend TargetUser = TargetUserName, Service = ServiceName
| where isnotempty(TargetUser) and isnotempty(Service)
| where TicketEncryptionType in ("0x17", "0x18", "0x12") // AES and RC4 encryption types commonly abused
| where (ClientAddress == "127.0.0.1" or ClientAddress == "::1") // Potentially local Silver Ticket activity
   or (isnotempty(Service) and Service !endswith "$" and Service != "krbtgt") // Non-standard service accounts targeted
| summarize Count = count(), UniqueServices = dcount(Service) by TargetUser, Service, TimeGenerated, ClientAddress
| where Count > 1 or UniqueServices > 1 // Unusual activity for the same account or service
| project TimeGenerated, TargetUser, Service, ClientAddress, Count, UniqueServices
| order by TimeGenerated desc
```
{% endcode %}

#### **Explanation of Query Logic**

1. **Event ID 4769**: Monitors Kerberos Service Ticket Request events, where attackers forge service tickets.
2. **Ticket Encryption Types**: Filters for encryption types commonly used in Kerberos (`AES` or `RC4`), which are often exploited in Silver Ticket attacks.
3. **Client Address**: Detects suspicious local activity (`127.0.0.1` or `::1`), which can indicate forged tickets being used on the same host.
4. **Unusual Service Accounts**:
   * Excludes standard accounts (e.g., `krbtgt` or machine accounts ending in `$`) to focus on abnormal targets.
5. **Aggregation and Thresholds**:
   * Identifies patterns of repetitive or anomalous service requests involving the same user or service.

#### **Enhancements for Specific Environments**

* Adjust the thresholds (e.g., `Count > 1`) to align with your environment's baseline.
* Include additional filters for service accounts commonly targeted (e.g., SQL, SharePoint).
* Integrate alerts or dashboards in Microsoft Sentinel to automate detection and response.
{% endtab %}

{% tab title="Query 2" %}
Query to detect potential Silver Ticket attacks by analysing anomalous Kerberos Service Ticket usage patterns in your logs:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (4768, 4769, 4770, 4771)
| where TargetUserName endswith "$"
| where ServiceName != "krbtgt"
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
2. Filters for service accounts (TargetUserName ending with `$`) and excludes the `krbtgt` service.
3. Checks for ticket options that are renewable or forwardable.
4. Extracts the account domain from the TargetUserName.
5. Joins with logon events (Event ID 4624) to correlate Kerberos authentication with logon activities.
6. Projects relevant fields and orders the results by the time generated.

This should help you detect potential Silver Ticket attacks by identifying suspicious Kerberos ticket requests and correlating them with logon events.
{% endtab %}

{% tab title="Query 3" %}
Advanced KQL Query for Silver Ticket Detection

The following is an **advanced KQL query** for detecting **Silver Ticket activity**, leveraging additional fields and logic to pinpoint anomalous Kerberos service ticket usage. This query incorporates correlation across multiple events, focusing on suspicious patterns like forged service tickets, unusual client IPs, and inconsistent usage behaviours.

{% code overflow="wrap" %}
```kotlin
let ServiceTicketEvents = SecurityEvent
| where EventID == 4769  // Kerberos Service Ticket Request
| extend TicketOptions = tostring(parse_json(AdditionalInfo).TicketOptions), 
         EncryptionType = tostring(parse_json(AdditionalInfo).EncryptionType),
         FailureCode = tostring(parse_json(AdditionalInfo).FailureCode)
| where isnotempty(TicketOptions) and isnotempty(EncryptionType)
| project TimeGenerated, TargetUserName, ServiceName, ClientAddress, TicketOptions, EncryptionType, FailureCode;

// Step 2: Identify Suspicious Local Client Activity
let LocalActivity = ServiceTicketEvents
| where ClientAddress in ("127.0.0.1", "::1")  // Local loopback addresses
| extend SuspiciousLocalActivity = true;

// Step 3: Look for Service Accounts Not Following Expected Patterns
let AnomalousServices = ServiceTicketEvents
| where ServiceName !endswith "$" and ServiceName != "krbtgt"  // Non-machine or non-krbtgt services
| summarize Count = count() by ServiceName, TargetUserName
| where Count > 1;  // Anomaly: Repeated access to a single service account

// Step 4: Monitor Encryption Anomalies
let EncryptionAnomalies = ServiceTicketEvents
| where EncryptionType in ("0x17", "0x18", "0x12")  // Common encryption types abused in Silver Tickets
| extend EncryptionAnomaly = true;

// Step 5: Correlation of Suspicious Activity
ServiceTicketEvents
| join kind=inner (LocalActivity) on $left.TargetUserName == $right.TargetUserName
| join kind=inner (AnomalousServices) on $left.ServiceName == $right.ServiceName
| join kind=inner (EncryptionAnomalies) on $left.EncryptionType == $right.EncryptionType
| project TimeGenerated, TargetUserName, ServiceName, ClientAddress, TicketOptions, EncryptionType, SuspiciousLocalActivity, EncryptionAnomaly
| order by TimeGenerated desc
```
{% endcode %}

#### **How This Query Works**

1. **EventID 4769**:
   * Focuses on Kerberos Service Ticket Request events for identifying potential forged tickets.
2. **Local Activity Detection**:
   * Filters for requests originating from local addresses (`127.0.0.1`, `::1`), which may indicate forged tickets in use on the same host.
3. **Anomalous Service Account Usage**:
   * Highlights services that are accessed repeatedly in an unusual manner, excluding standard machine accounts (`$`) and the `krbtgt` account.
4. **Encryption Anomalies**:
   * Identifies encryption types (`AES`, `RC4`) that are commonly exploited in Silver Ticket attacks.
5. **Correlated Suspicious Activity**:
   * Combines the findings from local activity, anomalous service usage, and encryption anomalies to surface only the most suspicious events.

***

#### **Further Customisation**

* **Thresholds**: Adjust `Count > 1` or include additional conditions based on your environment’s baseline.
* **User Behavior**: Incorporate user-specific baselining to identify deviations.
* **Integration**: Feed the results into **Microsoft Sentinel** or a SIEM dashboard for automated alerting and analysis.
{% endtab %}

{% tab title="Query 4" %}
An advanced KQL query to detect potential Silver Ticket attacks, incorporating additional details and filtering for suspicious activities:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (4768, 4769, 4770, 4771)
| where TargetUserName endswith "$"
| where ServiceName != "krbtgt"
| where TicketOptions has_any ("renewable", "forwardable")
| extend AccountDomain = split(TargetUserName, "@")[1]
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 3
    | where AuthenticationPackageName == "Kerberos"
    | project LogonTime = TimeGenerated, LogonComputer = Computer, LogonIpAddress = IpAddress, LogonAccountName = AccountName
) on $left.IpAddress == $right.LogonIpAddress
| join kind=inner (
    SecurityEvent
    | where EventID == 4672
    | where PrivilegeList has "SeTcbPrivilege"
    | project PrivilegeTime = TimeGenerated, PrivilegeComputer = Computer, PrivilegeIpAddress = IpAddress, PrivilegeAccountName = AccountName
) on $left.IpAddress == $right.PrivilegeIpAddress
| project TimeGenerated, Computer, TargetUserName, ServiceName, TicketOptions, IpAddress, AccountName, LogonTime, LogonComputer, LogonAccountName, PrivilegeTime, PrivilegeComputer, PrivilegeAccountName, AccountDomain
| order by TimeGenerated desc

```
{% endcode %}

Query does the following:

1. Looks for Kerberos-related events (Event IDs 4768, 4769, 4770, 4771).
2. Filters for service accounts (TargetUserName ending with `$`) and excludes the `krbtgt` service.
3. Checks for ticket options that are renewable or forwardable.
4. Extracts the account domain from the TargetUserName.
5. Joins with logon events (Event ID 4624) to correlate Kerberos authentication with logon activities.
6. Further joins with privilege assignment events (Event ID 4672) to detect the assignment of sensitive privileges.
7. Projects relevant fields and orders the results by the time generated.

This should help you detect more sophisticated Silver Ticket attacks by correlating Kerberos ticket requests with logon events and privilege assignments.
{% endtab %}
{% endtabs %}

### Splunk Detection Queries

The following are **Splunk queries** designed to detect **Silver Ticket** activity by analysing Kerberos-related events, focusing on anomalies like unusual service ticket usage, forged tickets, and suspicious patterns in authentication.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query for Silver Ticket Detection

{% code overflow="wrap" %}
```spl
index=windows
sourcetype=WinEventLog:Security
(EventCode=4769)  // Kerberos Service Ticket Operation
| eval ClientAddress=if(Client_Address=="::1" OR Client_Address=="127.0.0.1", "localhost", Client_Address)
| where isnotnull(ClientAddress) 
| search Ticket_Encryption_Type IN ("0x17", "0x18", "0x12") // AES and RC4 encryption types
| where Service_Name!="krbtgt$" AND NOT Service_Name IN ("$MACHINE$", "$OTHER_STANDARD_ACCOUNTS$") 
| stats count as RequestCount values(ClientAddress) as ClientAddresses values(Service_Name) as ServiceNames by TargetUserName
| where RequestCount > 1 OR mvcount(ServiceNames) > 1
| table _time, TargetUserName, ClientAddresses, ServiceNames, RequestCount
| sort - _time
```
{% endcode %}

#### **Explanation of the Query**

1. **Search Scope**:
   * Searches in relevant security indexes (`index=security` or `index=windows`).
   * Looks for events with`EventCode=4769`, which corresponds to Kerberos Service Ticket Operations.
2. **Client Address Check**:
   * Flags requests originating from suspicious local addresses (`127.0.0.1`, `::1`), which may indicate local forged ticket usage.
3. **Encryption Types**:
   * Filters for common encryption types abused in Silver Ticket attacks: `AES` (`0x17`, `0x18`) and `RC4` (`0x12`).
4. **Service Account Filtering**:
   * Excludes standard accounts like `krbtgt$` or machine accounts (accounts ending with `$`), focusing on unusual service targets.
5. **Statistical Analysis**:
   * Aggregates results by `TargetUserName`, counts repeated requests (`RequestCount`), and identifies multiple services accessed (`mvcount(ServiceNames)`).
   * Flags users or accounts with repeated access or anomalous patterns.
6. **Output**:
   * Displays results with key information: time, target user, client addresses, service names, and request count, sorted by recent activity.

***

#### **Customisation Options**

* **Thresholds**: Adjust `RequestCount > 1` or add environment-specific conditions.
* **Target Services**: Add known critical services like SQL, SharePoint, or other high-value assets.
* **Correlation**: Combine this query with `EventCode=4771` (Kerberos Pre-authentication Failure) or `EventCode=4625` (Failed Logins) for deeper insights.
{% endtab %}

{% tab title="Query 2" %}
The following is a Splunk query to detect potential Silver Ticket attacks by analyzing Kerberos-related events and focusing on anomalies like unusual service ticket usage, forged tickets, and suspicious patterns in authentication:

{% code overflow="wrap" %}
```spl
index=windows
sourcetype=WinEventLog:Security
(EventCode=4768 OR EventCode=4769 OR EventCode=4770 OR EventCode=4771)
TargetUserName="*$"
ServiceName!="krbtgt"
TicketOptions="*renewable*" OR TicketOptions="*forwardable*"
| stats count by _time, ComputerName, TargetUserName, ServiceName, TicketOptions, IpAddress, AccountName
| sort -_time

```
{% endcode %}

The query does the following:

1. Searches for Kerberos-related events (Event Codes 4768, 4769, 4770, 4771).
2. Filters for service accounts (TargetUserName ending with `$`) and excludes the `krbtgt` service.
3. Checks for ticket options that are renewable or forwardable.
4. Aggregates the results by time, computer name, target username, service name, ticket options, IP address, and account name.
5. Sorts the results by time in descending order.

This should help you detect potential Silver Ticket attacks by identifying suspicious Kerberos ticket requests.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
