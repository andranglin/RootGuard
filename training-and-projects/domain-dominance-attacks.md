# Domain Dominance Attacks

## <mark style="color:blue;">**Domain Dominance**</mark>&#x20;

Refers to a stage in an adversary’s attack lifecycle where they gain control over a network's **Active Directory (AD) domain** or significant portions of it. This is a critical phase because AD is the backbone of identity and access management in most enterprise environments. Controlling an AD domain allows attackers to elevate privileges, persist in the environment, and move laterally across the network undetected.

***

### <mark style="color:blue;">**Key Objectives of Domain Dominance**</mark>

1. **Privilege Escalation:**
   * Attackers escalate their privileges to domain or enterprise administrator levels.
2. **Persistence:**
   * The attacker ensures continued access to the network by creating backdoors, new accounts, or modifying AD policies.
3. **Lateral Movement:**
   * Gaining access to other systems and resources within the domain using compromised credentials or stolen Kerberos tickets.
4. **Data Exfiltration or Destruction:**
   * Gaining access to sensitive data or deploying ransomware.

***

### <mark style="color:blue;">**Techniques Used in Domain Dominance**</mark>

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

### <mark style="color:blue;">**Indicators of Domain Dominance**</mark>

Detecting domain dominance attacks involves monitoring specific actions and anomalies in Active Directory logs:

* Unauthorised modifications to AD groups, policies, or schema.
* Unusual logon activities (e.g., from unexpected IPs or hosts).
* Requests for sensitive AD attributes or files (`NTDS.dit`, SYSVOL).
* Elevated usage of administrative privileges.
* Abnormal Kerberos ticket requests or renewals.

***

### <mark style="color:blue;">**Implications of Domain Dominance**</mark>

If an attacker achieves Domain Dominance:

1. They can impersonate any user or service in the environment.
2. They can disable or bypass security controls like endpoint detection and response (EDR).
3. They can exfiltrate sensitive data or launch further attacks, such as ransomware.

***

### <mark style="color:blue;">**Mitigations for Domain Dominance**</mark>

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

## <mark style="color:blue;">Defending Against Domain Dominance</mark>

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

**4.1 Kerberoasting Detection**

Hunt for abnormal Kerberos ticket requests:

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType in ("0x12", "0x17")
| summarize count() by ClientAddress, ServiceName, bin(TimeGenerated, 1h)
```

**4.2 DCSync Detection**

Hunt for directory replication service attempts:

```kusto
SecurityEvent
| where EventID == 4662
| where Properties has "Replicating Directory Changes"
| summarize count() by SubjectUserName, TargetAccount, bin(TimeGenerated, 1h)
```

**4.3 Abnormal Logons**

Identify unexpected logon patterns:

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType in (2, 3) // Interactive or Network logon
| where AccountName !in ("<known service accounts>")
| summarize count() by IpAddress, AccountName, bin(TimeGenerated, 1h)
```

***

## <mark style="color:blue;">**Domain Dominance Attacks**</mark>&#x20;

Typically associated with adversaries attempting to gain control over an Active Directory (AD) domain to extend their influence and persist in a compromised environment. Below is an overview of some key techniques and how to detect them using **KQL queries**:

***

### <mark style="color:blue;">**1. Credential Dumping**</mark>

Adversaries dump credentials from domain controllers or other AD-related hosts using tools like `Mimikatz` or techniques such as `DCSync`.

```kusto
SecurityEvent
| where EventID in (4662, 4672, 4723, 4738, 4740)
| where TargetObject contains "NTDS.dit" or ObjectClass == "directory service access"
| extend AccountUsed = iff(EventID == 4662, SubjectUserName, TargetUserName)
| summarize count() by EventID, AccountUsed, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">**2. DCSync Attack**</mark>

Adversaries use the `Replicating Directory Changes` permission to retrieve credentials from domain controllers.

```kusto
SecurityEvent
| where EventID == 4662
| where ObjectServer == "DS" and Properties has "Replicating Directory Changes"
| summarize count() by TargetAccount, SubjectUserName, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">**3. Golden Ticket Attack**</mark>

Attackers use stolen `KRBTGT` account credentials to forge Kerberos tickets.

```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName contains "krbtgt"
| extend IsSuspicious = ClientAddress !in ("<Known IP ranges>")
| summarize count() by ClientAddress, ServiceName, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">**4. Silver Ticket Attack**</mark>

Adversaries forge Kerberos tickets for services other than `krbtgt`.

```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName !contains "krbtgt"
| summarize count() by TargetAccount, ClientAddress, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">**5. Pass-the-Hash (PtH)**</mark>

Attackers use hashed credentials to authenticate without knowing the plaintext password.

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 3 and AuthenticationPackageName == "NTLM"
| summarize count() by TargetUserName, IpAddress, LogonType, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">**6. Pass-the-Ticket (PtT)**</mark>

Adversaries use valid Kerberos tickets to authenticate to systems.

```kusto
SecurityEvent
| where EventID == 4768
| where TicketEncryptionType in ("0x12", "0x17")
| extend IsSuspicious = IssuingServer !in ("<Known Kerberos Servers>")
| summarize count() by TicketEncryptionType, IssuingServer, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">**7. DCShadow Attack**</mark>

An attacker uses rogue domain controller replication to manipulate AD objects.

```kusto
SecurityEvent
| where EventID == 4662
| where ObjectClass == "domainDNS" and Properties has "msDS-KeyVersionNumber"
| summarize count() by SubjectUserName, ObjectName, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">**8. SID History Injection**</mark>

Adversaries inject Security Identifier (SID) histories into accounts for privilege escalation.

```kusto
SecurityEvent
| where EventID == 4670
| where Properties has "SIDHistory"
| summarize count() by TargetAccount, SubjectUserName, bin(TimeGenerated, 1h)
```

***

### <mark style="color:blue;">General Guidance:</mark>

1. **Enable Advanced Auditing:** Ensure auditing is configured for sensitive AD activities, especially replication, credential access, and privilege escalation attempts.
2. **Monitor Kerberos Events:** Track unusual Kerberos ticket requests and errors.
3. **Analyze Administrative Activity:** Focus on changes to sensitive groups like Domain Admins and changes to `KRBTGT` accounts.
4. **Threat Hunting:** Regularly search for anomalies in your AD logs using the above KQL queries.

***

## <mark style="color:blue;">Automating the detection of</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Domain Dominance Attacks**</mark>

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
