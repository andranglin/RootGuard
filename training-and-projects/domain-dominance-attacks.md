# Domain Dominance Attacks

## <mark style="color:blue;">What is</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Domain Dominance**</mark>&#x20;

Refers to a stage in an adversary’s attack lifecycle where they gain control over a network's **Active Directory (AD) domain** or significant portions of it. This is a critical phase because AD is the backbone of identity and access management in most enterprise environments. Controlling an AD domain allows attackers to elevate privileges, persist in the environment, and move laterally across the network undetected.

***

### <mark style="color:blue;">**Key Objectives of Domain Dominance Attacks**</mark>

1. **Privilege Escalation:**
   * Attackers escalate their privileges to domain or enterprise administrator levels.
2. **Persistence:**
   * The attacker ensures continued access to the network by creating backdoors, new accounts, or modifying AD policies.
3. **Lateral Movement:**
   * Gaining access to other systems and resources within the domain using compromised credentials or stolen Kerberos tickets.
4. **Data Exfiltration or Destruction:**
   * Gaining access to sensitive data or deploying ransomware.

***

### <mark style="color:blue;">**Techniques Used**</mark>

Attackers employ a variety of techniques to achieve Domain Dominance:

1. **Credential Dumping:**
   * Tools like `Mimikatz` extract credentials from memory or domain controllers.
2. **Pass-the-Hash:**
   * Using hashed credentials to authenticate without knowing the plaintext password.
3. **Golden Ticket Attack:**
   * Forging Kerberos tickets using the `KRBTGT` account hash.
4. **Silver Ticket Attack:**
   * Forging service-specific Kerberos tickets.
5. **DCSync Attack:**
   * Simulating a domain controller to replicate AD data, including password hashes.
6. **DCShadow Attack:**
   * Registering a rogue domain controller to manipulate AD objects covertly.
7. **SID History Injection:**
   * Modifying the Security Identifier (SID) history attribute of accounts for privilege escalation.
8. **Kerberoasting:**
   * Requesting service tickets to crack service account passwords offline.

***

### <mark style="color:blue;">**Indicators of Domain Dominance Attacks**</mark>

Detecting domain dominance attacks involves monitoring specific actions and anomalies in Active Directory logs:

* Unauthorised modifications to AD groups, policies, or schema.
* Unusual logon activities (e.g., from unexpected IPs or hosts).
* Requests for sensitive AD attributes or files (`NTDS.dit`, SYSVOL).
* Elevated usage of administrative privileges.
* Abnormal Kerberos ticket requests or renewals.

***

### <mark style="color:blue;">**Implications**</mark>

If an attacker achieves Domain Dominance:

1. They can impersonate any user or service in the environment.
2. They can disable or bypass security controls like endpoint detection and response (EDR).
3. They can exfiltrate sensitive data or launch further attacks, such as ransomware.

***

### <mark style="color:blue;">**Mitigations**</mark>

1. **Secure Privileged Accounts:**
   * Use multi-factor authentication (MFA) and limit administrative access.
2. **Implement Least Privilege:**
   * Minimise privileges for all accounts and services.
3. **Active Directory Hardening:**
   * Enable logging and auditing for critical AD activities.
   * Regularly monitor for unauthorised AD object changes.
4. **Use Tiered Administration:**
   * Separate high-privileged accounts from standard accounts.
5. **Patch Vulnerabilities:**
   * Regularly update systems to mitigate exploitation of known AD vulnerabilities.

***

## <mark style="color:blue;">Defending Against Domain Dominance Attacks</mark>

This requires a multifaceted approach combining detection techniques, proactive defence mechanisms, and specialised tools. Below is an exploration of specific detection methods and tools to mitigate the risks of domain dominance attacks.

***

### <mark style="color:blue;">**1. Detection Techniques**</mark>

**1.1 Log Monitoring and Analysis**

Monitoring Active Directory and system logs for anomalies is critical.

* **Kerberos Events:**
  * Monitor events like `Event ID 4769` (Service Ticket Request) and `Event ID 4770` (Ticket Granted Renewed).
  * Look for unusual requests involving `krbtgt` or other critical service accounts.
* **Account Modification Events:**
  * Track `Event ID 4732` (Add to Privileged Group) and `Event ID 4728` (Add to Global Group).
* **Replication Events:**
  * Monitor `Event ID 4662` (Access to Directory Services Objects) for unusual replication activities.

**1.2 Anomaly-Based Detection**

Detect deviations from normal user behaviour using behavioural analytics:

* Unusual logon hours or from new geographic locations.
* Large numbers of requests for sensitive AD attributes.
* Abnormal Kerberos ticket lifetimes or encryption types.

**1.3 Honey Tokens**

Deploy fake AD accounts or objects (e.g., decoy service principal names) to detect unauthorised attempts:

* Monitor for access attempts on decoy accounts.
* Track service ticket requests for decoy SPNs (useful for Kerberoasting detection).

**1.4 PowerShell and Script Logging**

Enable **PowerShell Script Block Logging** to detect malicious AD commands:

* Commands like `Get-ADUser`, `Get-ADGroup`, or replication-related commands (e.g., `Repadmin.exe`).

***

### <mark style="color:blue;">**2. Tools for Defence**</mark>

**2.1 Active Directory Monitoring Tools**

Specialised tools for monitoring and defending AD environments:

* **BloodHound Enterprise**:
  * Graph-based analysis to identify AD misconfigurations and attack paths.
  * Highlights privilege escalation paths and vulnerable accounts.
* **Purple Knight**:
  * Scans AD environments for weaknesses, such as excessive privileges or delegation risks.
* **ADAudit Plus**:
  * Tracks real-time changes to AD objects, including group memberships, GPOs, and permissions.

**2.2 SIEM Platforms**

Use a Security Information and Event Management (SIEM) solution to aggregate logs, detect anomalies, and trigger alerts:

* **Microsoft Sentinel:**
  * Query-based detection for domain dominance techniques using KQL.
  * Integration with Azure AD for comprehensive monitoring.
* **Splunk**:
  * Use SPL queries for detailed analysis of AD-related logs.

**2.3 Endpoint Detection and Response (EDR)**

Deploy EDR solutions to detect lateral movement and credential theft:

* **Microsoft Defender for Identity**:
  * Detects DCSync, Pass-the-Hash, and other domain dominance techniques.
  * Provides real-time alerts for suspicious AD activities.
* **CrowdStrike Falcon**:
  * Monitors endpoint activity for credential dumping and ticket forgery attempts.

**2.4 Threat Intelligence Platforms**

Integrate IoC feeds and threat intelligence tools to detect known adversary tactics:

* **ThreatConnect** or **Recorded Future**:
  * Feeds for detecting IoCs associated with domain dominance tools like `Mimikatz` or `Impacket`.

***

### <mark style="color:blue;">**3. Proactive Defence Strategies**</mark>

**3.1 Active Directory Hardening**

* Disable unused accounts and services.
* Use **Protected Users** group to prevent credential theft for privileged accounts.
* Enforce strong password policies and use tools like **LAPS** (Local Administrator Password Solution).

**3.2 Privilege Management**

* Implement **Tiered Administrative Model**:
  * Separate high-privilege accounts from daily-use accounts.
  * Use jump servers for administrative access.
* Restrict **Replication Rights**:
  * Limit `Replicating Directory Changes` to only required accounts.

**3.3 Multi-Factor Authentication (MFA)**

Deploy MFA for all privileged accounts, including service accounts.

**3.4 Network Segmentation**

* Segment the network to limit lateral movement.
* Use firewalls or endpoint protection to restrict access to domain controllers.

**3.5 Kerberos Configuration**

* Set shorter Kerberos ticket lifetimes.
* Enable PAC (Privilege Attribute Certificate) validation.

***

### <mark style="color:blue;">**4. Threat Hunting Examples**</mark>

**Note:** _Always test and evaluate queries, as not all will work in an environment and will depend on the log sources that are collected and monitored._

**4.1 Kerberoasting Detection**

Hunt for abnormal Kerberos ticket requests:

{% tabs %}
{% tab title="Defender/Sentinel" %}
```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType in ("0x12", "0x17")
| summarize count() by ClientAddress, ServiceName, bin(TimeGenerated, 1h)
```
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows 
sourcetype=WinEventLog:Security
EventCode=4769
| eval is_suspicious=if((TicketEncryptionType!="0x12" AND TicketEncryptionType!="0x17") OR (ClientAddress!="<expected_IP_ranges>"), 1, 0)
| stats count by TimeGenerated, TargetUserName, ServiceName, TicketEncryptionType, ClientAddress, is_suspicious
| where is_suspicious=1
| table TimeGenerated, TargetUserName, ServiceName, TicketEncryptionType, ClientAddress
| sort - TimeGenerated
```
{% endcode %}
{% endtab %}
{% endtabs %}

**4.2 DCSync Detection**

Hunt for directory replication service attempts:

{% tabs %}
{% tab title="Defender/Sentinel" %}
```kusto
SecurityEvent
| where EventID == 4662
| where Properties has "Replicating Directory Changes"
| summarize count() by SubjectUserName, TargetAccount, bin(TimeGenerated, 1h)
```
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
ObjectServer=DS
| search Properties="Replicating Directory Changes" OR Properties="Replicating Directory Changes All"
| stats count by _time, SubjectAccountName, TargetObject, ObjectName, Properties
| rename SubjectAccountName as "AccountName", TargetObject as "Target", ObjectName as "ObjectAccessed"
| sort - _time
```
{% endcode %}
{% endtab %}
{% endtabs %}

**4.3 Abnormal Logons**

Identify unexpected logon patterns:

{% tabs %}
{% tab title="Defender/Sentinel" %}
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType in (2, 3) // Interactive or Network logon
| where AccountName !in ("<known service accounts>")
| summarize count() by IpAddress, AccountName, bin(TimeGenerated, 1h)
```
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows 
sourcetype=WinEventLog:Security
EventCode=4624
| eval LogonTypeDescription=case(
    LogonType=="2", "Interactive",
    LogonType=="3", "Network",
    LogonType=="4", "Batch",
    LogonType=="5", "Service",
    LogonType=="7", "Unlock",
    LogonType=="8", "NetworkCleartext",
    LogonType=="9", "NewCredentials",
    LogonType=="10", "RemoteInteractive",
    LogonType=="11", "CachedInteractive",
    true(), "Other"
)
| eval IsSuspicious=if(
    (IpAddress!="<known_ip_range>" AND UserName!="<excluded_service_accounts>") OR 
    (LogonType=="10" AND IpAddress!="<expected_RDP_ip_ranges>") OR
    (Date_Wday NOT IN ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday") AND Date_Hour NOT IN (9, 10, 11, 12, 13, 14, 15, 16)),
    "Yes", "No"
)
| where IsSuspicious="Yes"
| stats count by _time, UserName, IpAddress, WorkstationName, LogonTypeDescription
| sort - _time
```
{% endcode %}
{% endtab %}
{% endtabs %}

***

## <mark style="color:blue;">**Types of Domain Dominance Attacks and Detection Queries**</mark>&#x20;

Typically associated with adversaries attempting to gain control over an Active Directory (AD) domain to extend their influence and persist in a compromised environment. Below is an overview of some key techniques and how to detect them using **KQL queries**:

***

### <mark style="color:blue;">**1. Credential Dumping**</mark>

**Note:** _Always test and evaluate queries, as not all will work in an environment and will depend on the log sources that are collected and monitored._

Adversaries dump credentials from domain controllers or other AD-related hosts using tools like `Mimikatz` or techniques such as `DCSync`.

{% tabs %}
{% tab title="Defender/Sentinel" %}
{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (4662, 4672, 4723, 4738, 4740)
| where TargetObject contains "NTDS.dit" or ObjectClass == "directory service access"
| extend AccountUsed = iff(EventID == 4662, SubjectUserName, TargetUserName)
| summarize count() by EventID, AccountUsed, bin(TimeGenerated, 1h)
```
{% endcode %}
{% endtab %}

{% tab title="Splunk" %}
#### **1. Credential Dumping via LSASS**

Detect suspicious access to the `lsass.exe` process:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4688
| where NewProcessName="C:\\Windows\\System32\\lsass.exe" OR ParentProcessName="C:\\Windows\\System32\\lsass.exe"
| stats count by _time, NewProcessName, ParentProcessName, ProcessId, SubjectUserName, SubjectLogonId
| rename NewProcessName as "Executed Process", ParentProcessName as "Parent Process"
| sort - _time
```
{% endcode %}

**Key Indicators:**

* Unusual processes spawning or accessing `lsass.exe`, such as **Mimikatz** or malicious scripts.

***

#### **2. Credential Dumping via NTDS.dit Access**

Detect access to the Active Directory database file (`NTDS.dit`):

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
| where ObjectName="C:\\Windows\\NTDS\\NTDS.dit"
| stats count by _time, SubjectUserName, AccessMask, ObjectName, ProcessName
| rename SubjectUserName as "Accessing Account", ObjectName as "Accessed Object", ProcessName as "Executing Process"
| sort - _time
```
{% endcode %}

**Key Indicators:**

* Unauthorized access to `NTDS.dit` using `AccessMask` values that indicate read or dump operations.

***

#### **3. SAM Database Access**

Detect unauthorised access to the Security Account Manager (SAM) database:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4663
| where ObjectName="C:\\Windows\\System32\\config\\SAM"
| stats count by _time, SubjectUserName, AccessMask, ObjectName, ProcessName
| rename SubjectUserName as "Accessing Account", ObjectName as "Accessed Object", ProcessName as "Executing Process"
| sort - _time
```
{% endcode %}

**Key Indicators:**

* Processes accessing `C:\\Windows\\System32\\config\\SAM` that are not part of routine system operations.

***

#### **4. Tools like Mimikatz**

Detect the use of suspicious tools known for credential dumping:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4688
| where NewProcessName IN ("C:\\Users\\*\\Desktop\\mimikatz.exe", "C:\\Windows\\Temp\\*")
| stats count by _time, NewProcessName, CommandLine, SubjectUserName, ParentProcessName
| rename NewProcessName as "Suspicious Process", CommandLine as "Executed Command"
| sort - _time
```
{% endcode %}

**Key Indicators:**

* Unusual processes like **mimikatz.exe**, or those spawned from temporary directories.

***

#### **5. Unusual Dump File Creations**

Detect suspicious file dumps, such as those created using the **procdump** tool:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4663
| where ObjectName matches ".*\\.dmp"
| stats count by _time, SubjectUserName, ObjectName, AccessMask, ProcessName
| rename SubjectUserName as "Accessing Account", ObjectName as "Dump File Created", ProcessName as "Executing Process"
| sort - _time
```
{% endcode %}

**Key Indicators:**

* Creation of `.dmp` files in suspicious directories, often indicative of credential dumping.

***

#### **6. Suspicious DLL Loading**

Detect malicious DLLs loaded for credential dumping:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=7045
| where ImagePath IN ("C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\samlib.dll")
| stats count by _time, ServiceName, ImagePath, SubjectUserName
| rename ServiceName as "Service", ImagePath as "DLL Path"
| sort - _time
```
{% endcode %}

#### **7. Follow-Up Actions**

1. **Investigate Accessing Accounts:**
   * Verify if the `SubjectUserName` is authorised for such actions.
2. **Correlate with Other Logs:**
   * Look for privilege escalation (`EventCode=4672`) or abnormal logons (`EventCode=4624`).
3. **Alerting:**
   * Set up Splunk alerts for these queries to notify the SOC of potential credential dumping.
{% endtab %}
{% endtabs %}

### <mark style="color:blue;">**2. DCSync Attack**</mark>

Adversaries use the `Replicating Directory Changes` permission to retrieve credentials from domain controllers.

{% tabs %}
{% tab title="Defender/Sentinel" %}
```kusto
SecurityEvent
| where EventID == 4662
| where ObjectServer == "DS" and Properties has "Replicating Directory Changes"
| summarize count() by TargetAccount, SubjectUserName, bin(TimeGenerated, 1h)
```
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
| where ObjectServer=="DS" AND (Properties="Replicating Directory Changes" OR Properties="Replicating Directory Changes All")
| stats count by _time, SubjectAccountName, ObjectName, Properties, OperationType
| rename SubjectAccountName as "Account Performing Action", ObjectName as "Accessed Object", Properties as "Permissions Used", OperationType as "Action"
| sort - _time
```
{% endcode %}

***

#### **Explanation of the Query**

1. **Filter by Event Code:**
   * `EventCode=4662`: Indicates access to directory service objects.
2. **Monitor Replication Permissions:**
   * Look for the use of `Replicating Directory Changes` or `Replicating Directory Changes All`, which are necessary for AD replication and are often abused in DCSync attacks.
3. **Aggregate and Analyse:**
   * `stats` groups results by key attributes like the account performing the action, the object accessed, and the permissions used.
4. **Sort Results:**
   * Sort events by `_time` to display the most recent activities.

***

#### **Enhanced Query with Anomalies**

To refine the detection, include conditions for unexpected accounts and suspicious IP addresses:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
| where ObjectServer=="DS" AND (Properties="Replicating Directory Changes" OR Properties="Replicating Directory Changes All")
| eval IsSuspicious=if(AccountName!="<authorized_replication_account>" OR IpAddress!="<trusted_ip_range>", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectAccountName, ObjectName, Properties, IpAddress
| rename SubjectAccountName as "Account Performing Action", ObjectName as "Accessed Object", Properties as "Permissions Used", IpAddress as "Source IP"
| sort - _time
```
{% endcode %}

***

#### **Key Indicators of a DCSync Attack**

1. **Account Used:**
   * Check if the account (`SubjectAccountName`) is authorized for replication activities. DCSync often abuses standard user accounts with elevated permissions.
2. **Permissions:**
   * Look for replication-specific permissions: `Replicating Directory Changes` and `Replicating Directory Changes All`.
3. **Accessed Object:**
   * Monitor for objects like `CN=DomainDnsZones` or sensitive AD attributes, such as `msDS-KeyVersionNumber`.
4. **Source IP:**
   * Verify if the request originates from a trusted domain controller or unexpected systems.

***

#### **Follow-Up Actions**

1. **Investigate Accounts:**
   * Confirm whether the `SubjectAccountName` belongs to legitimate replication accounts or privileged users.
2. **Validate Source IP:**
   * Check if the request originates from trusted domain controllers or anomalous systems.
3. **Correlate with Other Events:**
   * Look for associated authentication events (`EventCode=4624`) or privilege escalations (`EventCode=4672`).
4. **Set Alerts:**
   * Configure Splunk alerts for this query to notify your SOC in realtime.
{% endtab %}
{% endtabs %}

***

### <mark style="color:blue;">**3. Golden Ticket Attack**</mark>

Attackers use stolen `KRBTGT` account credentials to forge Kerberos tickets.

{% tabs %}
{% tab title="Defender/Sentinel" %}
```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName contains "krbtgt"
| extend IsSuspicious = ClientAddress !in ("<Known IP ranges>")
| summarize count() by ClientAddress, ServiceName, bin(TimeGenerated, 1h)
```
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4769
| where ServiceName="krbtgt"
| eval IsSuspicious=if(ClientAddress!="<trusted_ip_range>" OR TicketOptions="0x40810010" OR TicketEncryptionType!="0x12", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, ServiceName, ClientAddress, TicketOptions, TicketEncryptionType
| rename SubjectUserName as "Requesting Account", ServiceName as "Service Name", ClientAddress as "Source IP", TicketOptions as "Ticket Flags", TicketEncryptionType as "Encryption Type"
| sort - _time
```
{% endcode %}

***

#### **Explanation of the Query**

1. **Filter by Kerberos Service Ticket Requests:**
   * `EventCode=4769`: Indicates a Kerberos service ticket request.
   * `ServiceName="krbtgt"`: Focuses on requests involving the Kerberos Ticket Granting Service (`krbtgt`), often targeted in Golden Ticket attacks.
2. **Evaluate Suspicious Patterns:**
   * `ClientAddress`: Check if the source IP is outside `<trusted_ip_range>`.
   * `TicketOptions="0x40810010"`: Common flag used in Golden Tickets.
   * `TicketEncryptionType!="0x12"`: Indicates non-standard encryption types.
3. **Highlight Suspicious Events:**
   * Use `eval` to flag anomalies and filter suspicious events with `where IsSuspicious="Yes"`.
4. **Aggregate and Display Key Information:**
   * `stats` groups results by time, requesting account, source IP, and ticket details.

***

#### **Enhanced Query for Authentication Ticket Requests**

Golden Tickets may also generate anomalies in TGT (Ticket Granting Ticket) requests (`Event ID 4768`):

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4768
| where ServiceName="krbtgt"
| eval IsSuspicious=if(TicketEncryptionType!="0x12" OR ClientAddress!="<trusted_ip_range>", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, ServiceName, ClientAddress, TicketEncryptionType
| rename SubjectUserName as "Requesting Account", ServiceName as "Service Name", ClientAddress as "Source IP", TicketEncryptionType as "Encryption Type"
| sort - _time
```
{% endcode %}

***

#### **Key Indicators of a Golden Ticket Attack**

1. **Unusual `krbtgt` Service Requests:**
   * Multiple requests involving the `krbtgt` account.
2. **Non-Standard Encryption Types:**
   * Golden Tickets often use custom or unusual encryption types.
3. **Abnormal Source IP:**
   * Requests from unexpected systems or IP ranges.
4. **Long-Lived Tickets:**
   * Golden Tickets may have unusually long lifetimes.

***

#### **Follow-Up Actions**

1. **Investigate `Requesting Account`:**
   * Verify if the account is authorized to request tickets involving the `krbtgt` service.
2. **Validate Source IP:**
   * Confirm if the IP is within trusted ranges or corresponds to known systems.
3. **Correlate with Other Events:**
   * Check for abnormal logons (`EventCode=4624`) or privilege escalation (`EventCode=4672`).
4. **Set Alerts:**
   * Configure alerts to notify the SOC for any flagged events.
{% endtab %}
{% endtabs %}

***

### <mark style="color:blue;">**4. Silver Ticket Attack**</mark>

Adversaries forge Kerberos tickets for services other than `krbtgt`.

{% tabs %}
{% tab title="Defender/Sentinel" %}
```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName !contains "krbtgt"
| summarize count() by TargetAccount, ClientAddress, bin(TimeGenerated, 1h)
```
{% endtab %}

{% tab title="Splunk" %}
#### **Detect Silver Ticket Activity**

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4769
| where ServiceName!="krbtgt" AND (ServiceName="CIFS" OR ServiceName="HTTP" OR ServiceName="LDAP")
| eval IsSuspicious=if(ClientAddress!="<trusted_ip_range>" OR TicketEncryptionType!="0x12", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, ServiceName, ClientAddress, TicketEncryptionType
| rename SubjectUserName as "Requesting Account", ServiceName as "Kerberos Service", ClientAddress as "Source IP", TicketEncryptionType as "Encryption Type"
| sort - _time
```
{% endcode %}

***

#### **Explanation of the Query**

1. **Filter for Kerberos Service Ticket Requests:**
   * `EventCode=4769`: Logs related to Kerberos service ticket requests.
   * `ServiceName!="krbtgt"`: Exclude TGT-related requests (used in Golden Ticket attacks).
   * Focus on services often targeted by Silver Tickets, like `CIFS`, `HTTP`, or `LDAP`.
2. **Identify Suspicious Patterns:**
   * `ClientAddress!="<trusted_ip_range>"`: Detect requests from unusual or external IP addresses.
   * `TicketEncryptionType!="0x12"`: Non-standard Kerberos encryption types can indicate forged tickets.
3. **Aggregate Suspicious Events:**
   * Use `stats` to group results by key attributes like `ServiceName` and `ClientAddress`.
4. **Display Key Details:**
   * Rename fields for clarity, such as `SubjectUserName` (the account requesting the ticket) and `ClientAddress` (source IP).

***

#### **Enhanced Query with Anomaly Detection**

For environments with known patterns, use statistical baselines to detect anomalies:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4769
| where ServiceName!="krbtgt"
| stats count by SubjectUserName, ServiceName, ClientAddress, TicketEncryptionType
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by ServiceName
| eval IsAnomalous=if(count > avg_count + (2 * stdev_count), "Yes", "No")
| where IsAnomalous="Yes"
| table _time, SubjectUserName, ServiceName, ClientAddress, count, avg_count, stdev_count, TicketEncryptionType
```
{% endcode %}

***

#### **Indicators of a Silver Ticket Attack**

1. **Unusual Service Names:**
   * Tickets for sensitive services (`CIFS`, `HTTP`, `LDAP`) not typically accessed by the detected account.
2. **Anomalous Encryption Types:**
   * Non-standard `TicketEncryptionType` values, especially those differing from your environment's norms (e.g., `0x12`).
3. **Suspicious Client Addresses:**
   * Requests from IPs outside known ranges (`ClientAddress` not matching `<trusted_ip_range>`).

***

#### **Follow-Up Actions**

1. **Investigate Requesting Accounts:**
   * Verify if `SubjectUserName` is authorized to access the targeted service.
2. **Validate Source IP Addresses:**
   * Confirm whether `ClientAddress` originates from a legitimate host or unexpected location.
3. **Correlate with Other Events:**
   * Look for concurrent privilege escalations (`EventCode=4672`) or unusual logons (`EventCode=4624`).
4. **Alerting and Automation:**
   * Configure alerts for flagged events to notify SOC teams in realtime.
{% endtab %}
{% endtabs %}

***

### <mark style="color:blue;">**5. Pass-the-Hash (PtH)**</mark>

Attackers use hashed credentials to authenticate without knowing the plaintext password.

{% tabs %}
{% tab title="Defender/Sentinel" %}
{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 3 and AuthenticationPackageName == "NTLM"
| summarize count() by TargetUserName, IpAddress, LogonType, bin(TimeGenerated, 1h)
```
{% endcode %}
{% endtab %}

{% tab title="Splunk" %}
#### **Detect Pass-the-Hash Activity**

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4624
| where LogonType=3 AND AuthenticationPackageName="NTLM"
| eval IsSuspicious=if(LogonType=3 AND AuthenticationPackageName="NTLM" AND (IpAddress!="<trusted_ip_range>" OR AccountName!="<known_service_accounts>"), "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, AccountName, IpAddress, WorkstationName, AuthenticationPackageName, LogonType
| rename AccountName as "Targeted Account", IpAddress as "Source IP", WorkstationName as "Destination Host", AuthenticationPackageName as "Auth Method", LogonType as "Logon Type"
| sort - _time
```
{% endcode %}

***

#### **Explanation of the Query**

1. **Filter for Logon Events:**
   * `EventCode=4624`: Indicates successful logons.
   * `LogonType=3`: Focus on network logons (often targeted by PtH attacks).
   * `AuthenticationPackageName="NTLM"`: Identifies NTLM-based authentication.
2. **Identify Suspicious Patterns:**
   * Non-standard `IpAddress`: Detect requests from IPs outside `<trusted_ip_range>`.
   * Unusual `AccountName`: Flag accounts not in `<known_service_accounts>`.
3. **Aggregate Suspicious Events:**
   * Group results by time, account name, IP address, and destination host.
4. **Display Key Details:**
   * Provide a clear overview of `Targeted Account`, `Source IP`, and `Auth Method`.

***

#### **Enhanced Query with High-Frequency Detection**

Pass-the-Hash attacks often involve multiple logon attempts across different systems.

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4624
| where LogonType=3 AND AuthenticationPackageName="NTLM"
| stats count by AccountName, IpAddress, WorkstationName
| where count > 10
| sort - count
```
{% endcode %}

***

#### **Indicators of a Pass-the-Hash Attack**

1. **Unusual Accounts:**
   * Use of privileged accounts like `Administrator` from unknown systems.
2. **Unexpected IPs:**
   * Requests originating from external or untrusted IP addresses.
3. **High-Frequency Attempts:**
   * Multiple NTLM-based authentication requests from the same IP or account within a short time.

***

#### **Follow-Up Actions**

1. **Investigate Account Activity:**
   * Confirm whether the `Targeted Account` is legitimate and authorized.
2. **Validate Source IPs:**
   * Check whether the `Source IP` belongs to known systems.
3. **Correlate with Other Events:**
   * Look for privilege escalation attempts (`EventCode=4672`) or unusual administrative activities.
4. **Configure Alerts:**
   * Set up alerts for flagged events to notify your SOC in realtime.
{% endtab %}
{% endtabs %}

***

### <mark style="color:blue;">**6. Pass-the-Ticket (PtT)**</mark>

Adversaries use valid Kerberos tickets to authenticate to systems.

{% tabs %}
{% tab title="Defender/Sentinel" %}
{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4768
| where TicketEncryptionType in ("0x12", "0x17")
| extend IsSuspicious = IssuingServer !in ("<Known Kerberos Servers>")
| summarize count() by TicketEncryptionType, IssuingServer, bin(TimeGenerated, 1h)
```
{% endcode %}
{% endtab %}

{% tab title="Splunk" %}
#### **Query to Detect Pass-the-Ticket Activity**

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4769
| eval IsSuspicious=if((TicketEncryptionType!="0x12" AND TicketEncryptionType!="0x17") OR ClientAddress!="<trusted_ip_range>" OR AccountName!="<known_service_accounts>", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, ServiceName, TicketEncryptionType, ClientAddress, LogonGuid
| rename SubjectUserName as "Account", ServiceName as "Kerberos Service", TicketEncryptionType as "Encryption Type", ClientAddress as "Source IP"
| sort - _time
```
{% endcode %}

***

#### **Explanation of the Query**

1. **Filter by Kerberos Service Ticket Requests:**
   * `EventCode=4769`: Monitors for Kerberos service ticket (TGS) requests.
2. **Identify Suspicious Patterns:**
   * Non-standard encryption types (`TicketEncryptionType` not `0x12` or `0x17`).
   * Requests from unexpected IPs (`ClientAddress` not in `<trusted_ip_range>`).
   * Anomalous accounts (`AccountName` not in `<known_service_accounts>`).
3. **Aggregate Suspicious Events:**
   * Use `stats` to group results by key attributes such as `ServiceName`, `Encryption Type`, and `Source IP`.
4. **Display Key Details:**
   * Show `Account`, `Kerberos Service`, `Source IP`, and encryption type.

***

#### **Enhanced Query for TGT Requests**

Pass-the-Ticket attacks might also exploit Ticket Granting Tickets (TGTs). Use the following query for monitoring TGT activity (`EventCode=4768`):

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4768
| eval IsSuspicious=if(TicketEncryptionType!="0x12" OR ClientAddress!="<trusted_ip_range>", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, ServiceName, TicketEncryptionType, ClientAddress
| rename SubjectUserName as "Account", ServiceName as "Kerberos Service", TicketEncryptionType as "Encryption Type", ClientAddress as "Source IP"
| sort - _time
```
{% endcode %}

***

#### **Indicators of Pass-the-Ticket Attacks**

1. **Unusual Ticket Encryption Types:**
   * Common Kerberos encryption types are `0x12` (AES256) and `0x17` (AES128). Any deviation could indicate ticket forgery.
2. **Suspicious Source IPs:**
   * Requests originating from untrusted or external IP addresses.
3. **Abnormal Accounts:**
   * Privileged accounts (e.g., `Administrator`) used unexpectedly or from unauthorized hosts.
4. **High-Frequency Events:**
   * Multiple TGS or TGT requests in a short period.

***

#### **Follow-Up Actions**

1. **Investigate Accounts:**
   * Validate whether the `SubjectUserName` corresponds to authorized users or services.
2. **Verify Source IPs:**
   * Check if the `ClientAddress` belongs to trusted systems.
3. **Correlate with Other Logs:**
   * Look for associated logon events (`EventCode=4624`) or privilege escalation attempts (`EventCode=4672`).
4. **Alerting:**
   * Configure real-time alerts for flagged events to notify your SOC team.
{% endtab %}
{% endtabs %}

### <mark style="color:blue;">**7. DCShadow Attack**</mark>

An attacker uses rogue domain controller replication to manipulate AD objects.

{% tabs %}
{% tab title="Defender/Sentinel" %}
```kusto
SecurityEvent
| where EventID == 4662
| where ObjectClass == "domainDNS" and Properties has "msDS-KeyVersionNumber"
| summarize count() by SubjectUserName, ObjectName, bin(TimeGenerated, 1h)
```
{% endtab %}

{% tab title="Splunk" %}
#### **Detect DCShadow Attack**

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
| where ObjectServer=="DS" AND (Properties="Replicating Directory Changes" OR Properties="Replicating Directory Changes All")
| eval IsSuspicious=if(AccountName!="<authorized_replication_account>" OR ClientAddress!="<trusted_ip_range>", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, AccountName, ClientAddress, ObjectName, Properties
| rename SubjectUserName as "Performing Account", AccountName as "Target Account", ClientAddress as "Source IP", ObjectName as "Modified Object", Properties as "Replication Permissions"
| sort - _time
```
{% endcode %}

***

#### **Explanation of the Query**

1. **Monitor Access to Directory Services Objects:**
   * `EventCode=4662`: Captures directory replication activities.
2. **Focus on Replication Permissions:**
   * Detect use of replication-specific permissions such as:
     * `Replicating Directory Changes`
     * `Replicating Directory Changes All`
3. **Evaluate Suspicious Patterns:**
   * Flag events involving unexpected accounts (`AccountName`).
   * Identify source IPs outside the `<trusted_ip_range>`.
4. **Aggregate Suspicious Events:**
   * Use `stats` to group and display results by attributes like `ObjectName` and `ClientAddress`.
5. **Display Key Details:**
   * Present clear information about the `Performing Account`, `Source IP`, and `Modified Object`.

***

#### **Enhanced Query for Shadow Domain Controller Registration**

Detect potential shadow domain controllers by monitoring changes to the `msDS-Behavior-Version` attribute (schema version):

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
| where ObjectServer=="DS" AND ObjectName="CN=Schema,CN=Configuration,DC=<your_domain>"
| eval IsSuspicious=if(Properties="msDS-Behavior-Version", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, ClientAddress, ObjectName, Properties
| rename SubjectUserName as "Performing Account", ClientAddress as "Source IP", ObjectName as "Modified Object", Properties as "Attribute Modified"
| sort - _time
```
{% endcode %}

***

#### **Indicators of a DCShadow Attack**

1. **Unusual Accounts:**
   * Unauthorized accounts attempting replication or schema changes.
2. **Unexpected Source IPs:**
   * Requests originating from systems that are not domain controllers.
3. **Modification of Critical Attributes:**
   * Changes to sensitive AD attributes like `msDS-Behavior-Version`, `msDS-KeyVersionNumber`, or `AdminSDHolder`.

***

#### **Follow-Up Actions**

1. **Investigate Performing Accounts:**
   * Verify whether the `SubjectUserName` is authorized to perform replication or schema changes.
2. **Check Source IP:**
   * Validate the `ClientAddress` against known domain controllers or trusted systems.
3. **Correlate with Other Events:**
   * Look for additional replication-related logs (`EventCode=4662`) or privilege escalations (`EventCode=4672`).
4. **Set Alerts:**
   * Configure Splunk alerts to notify SOC teams of any flagged events in realtime.
{% endtab %}
{% endtabs %}

***

### <mark style="color:blue;">**8. SID History Injection**</mark>

Adversaries inject Security Identifier (SID) histories into accounts for privilege escalation.

{% tabs %}
{% tab title="Defender/Sentinel" %}
{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4670
| where Properties has "SIDHistory"
| summarize count() by TargetAccount, SubjectUserName, bin(TimeGenerated, 1h)
```
{% endcode %}
{% endtab %}

{% tab title="Splunk" %}
#### **Detect SID History Injection**

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
| where ObjectServer=="DS" AND Properties="SIDHistory"
| eval IsSuspicious=if(AccountName!="<trusted_admin_account>" OR ClientAddress!="<trusted_ip_range>", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, AccountName, ClientAddress, ObjectName, Properties
| rename SubjectUserName as "Performing Account", AccountName as "Target Account", ClientAddress as "Source IP", ObjectName as "Modified Object", Properties as "Modified Attribute"
| sort - _time
```
{% endcode %}

***

#### **Explanation of the Query**

1. **Monitor Access to Directory Services Objects:**
   * `EventCode=4662`: Indicates access or changes to directory objects.
2. **Focus on the `SIDHistory` Attribute:**
   * The `Properties="SIDHistory"` filter specifically targets modifications to the `SIDHistory` attribute.
3. **Evaluate Suspicious Patterns:**
   * `AccountName!="<trusted_admin_account>"`: Exclude authorized accounts such as domain administrators.
   * `ClientAddress!="<trusted_ip_range>"`: Exclude requests from known or trusted IP ranges.
4. **Aggregate Suspicious Events:**
   * Use `stats` to group events by attributes such as `ObjectName` and `ClientAddress`.
5. **Display Key Details:**
   * Provide insights into the `Performing Account`, `Target Account`, and `Modified Attribute`.

***

#### **Enhanced Query for Monitoring Attribute Changes**

If you want to monitor additional sensitive attribute changes, extend the query to include attributes like `AdminCount` or `PrimaryGroupID`:

{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4662
| where ObjectServer=="DS" AND (Properties="SIDHistory" OR Properties="AdminCount" OR Properties="PrimaryGroupID")
| eval IsSuspicious=if(AccountName!="<trusted_admin_account>" OR ClientAddress!="<trusted_ip_range>", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, SubjectUserName, AccountName, ClientAddress, ObjectName, Properties
| rename SubjectUserName as "Performing Account", AccountName as "Target Account", ClientAddress as "Source IP", ObjectName as "Modified Object", Properties as "Modified Attribute"
| sort - _time
```
{% endcode %}

***

#### **Indicators of SID History Injection**

1. **Unauthorised Accounts:**
   * Use of non-admin or unexpected accounts to modify `SIDHistory`.
2. **Suspicious IPs:**
   * Modifications originating from systems outside your trusted domain controller or admin networks.
3. **High-Frequency Changes:**
   * Repeated changes to `SIDHistory` within a short time frame.

***

#### **Follow-Up Actions**

1. **Investigate Performing Accounts:**
   * Verify whether the `Performing Account` has legitimate access to modify `SIDHistory`.
2. **Validate Source IP:**
   * Confirm whether the `Source IP` corresponds to a trusted admin workstation or system.
3. **Correlate with Other Events:**
   * Look for privilege escalations (`EventCode=4672`) or unusual logons (`EventCode=4624`) related to the same account.
4. **Set Alerts:**
   * Configure alerts in Splunk to notify the SOC of any flagged `SIDHistory` modifications.
{% endtab %}
{% endtabs %}

***

### <mark style="color:blue;">General Guidance:</mark>

1. **Enable Advanced Auditing:** Ensure auditing is configured for sensitive AD activities, especially replication, credential access, and privilege escalation attempts.
2. **Monitor Kerberos Events:** Track unusual Kerberos ticket requests and errors.
3. **Analyze Administrative Activity:** Focus on changes to sensitive groups like Domain Admins and changes to `KRBTGT` accounts.
4. **Threat Hunting:** Regularly search for anomalies in your AD logs using the above KQL queries.

***

## <mark style="color:blue;">Automating the Detection</mark>

### <mark style="color:blue;">**1. Set Up Detection Rules**</mark>

Detection rules trigger alerts when specific patterns are detected. The following is an example of configuring a detection rule in Microsoft Sentinel.

**Steps to Configure:**

1. **Navigate to Sentinel:**
   * Go to **Microsoft Sentinel** in your Azure portal.
   * Select your workspace.
2. **Create a New Analytics Rule:**
   * Under the **Configuration** section, select **Analytics**.
   * Click **+ Create** and choose **Scheduled query rule**.
3. **Define the Rule Settings:**
   * **Name:** Choose a descriptive name, e.g., "Detect DCSync Attack."
   * **Description:** Provide a detailed description of the attack being detected.
   * **Severity:** Assign a severity level (e.g., High for DCSync or Golden Ticket attacks).
   * **Tactics and Techniques:** Map the rule to MITRE ATT\&CK tactics and techniques (e.g., `TA0004: Privilege Escalation`, `T1003: Credential Dumping`).
4. **Paste the KQL Query:**
   * Copy and paste one of the KQL queries from the previous sections.
   * Test the query to ensure it returns meaningful results.
5. **Set Scheduling:**
   * Choose how often the query should run (e.g., every 5 minutes, every hour).
   * Configure the lookback period for log analysis (e.g., Last 1 Hour).
6. **Define Alerts:**
   * Set thresholds for triggering an alert based on query results.
   * For instance, trigger an alert if the count exceeds 1 for specific Event IDs.

***

### <mark style="color:blue;">**2. Create Automated Responses**</mark>

Automated responses reduce manual effort in investigating and remediating the detection. Use Playbooks in Sentinel to orchestrate actions.

**Example Playbook Actions:**

1. **Notify Analysts:**
   * Send email or Teams notifications with details of the alert.
2. **Block Threats:**
   * Isolate compromised accounts or block IP addresses using Azure AD Conditional Access or firewall rules.
3. **Enrich Alerts:**
   * Use integrations with threat intelligence services to enrich IoCs.

***

### <mark style="color:blue;">**3. Continuous Threat Hunting**</mark>

Even with detection rules in place, periodic threat hunting ensures you catch what rules might miss.

**Golden Ticket or Silver Ticket Attacks**:

{% tabs %}
{% tab title="Defender/Sentinel" %}
{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (4769, 4770)
| where ServiceName matches regex @"krbtgt|svc.*"
| where ClientAddress not in ("<Known IP ranges>")
| extend SuspiciousActivity = iff(ClientAddress != "<Expected Addresses>", "Yes", "No")
| summarize count(), min(TimeGenerated), max(TimeGenerated) by ClientAddress, ServiceName
```
{% endcode %}
{% endtab %}

{% tab title="Splunk" %}
{% code overflow="wrap" %}
```splunk-spl
index=windows
sourcetype=WinEventLog:Security
EventCode=4769
| where ServiceName="krbtgt"
| eval IsSuspicious=if(ClientAddress!="<trusted_ip_range>" OR TicketOptions="0x40810010" OR TicketEncryptionType!="0x12", "Yes", "No")
| where IsSuspicious="Yes"
| stats count by _time, ServiceName, ClientAddress, TargetUserName, TicketEncryptionType, TicketOptions
| rename ServiceName as "Kerberos Service", ClientAddress as "Source IP", TargetUserName as "Account Targeted"
| sort - _time
```
{% endcode %}
{% endtab %}
{% endtabs %}

***

### <mark style="color:blue;">**4. Configure Dashboards**</mark>

Create a dashboard in Sentinel to visualize detection metrics and patterns for Domain Dominance attacks.

**Suggested Widgets:**

* **Event Trends:** Display a timeline of detections for each attack type.
* **Top Targeted Accounts:** Show frequently targeted accounts (e.g., Admins, KRBTGT).
* **Suspicious IP Addresses:** Highlight unusual IPs from Kerberos authentication logs.

***

### <mark style="color:blue;">**5. Testing and Tuning**</mark>

Regularly test the rules by simulating attacks using tools like:

* **Mimikatz:** To test credential dumping detections.
* **BloodHound:** For identifying DCSync-like activities.
* **Kerberoasting Scripts:** To test Kerberos-related rules.
