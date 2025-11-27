# Skeleton Key

### **Introduction**

The **Skeleton Key** attack is an advanced persistence technique targeting Microsoft Active Directory (AD) environments. It involves injecting a malicious patch into the Local Security Authority Subsystem Service (LSASS) process on a domain controller, allowing attackers to bypass authentication mechanisms. This creates a "skeleton key" password that works for any user account without altering existing credentials or logs. The attack is particularly dangerous because it enables covert and persistent access to all accounts within the domain.

Skeleton Key attacks exploit the trust and centralization inherent in Active Directory systems. Once the malware is injected, it effectively enables the attacker to authenticate as any user while maintaining a low profile, making detection challenging.

***

### **Attack Description**

A Skeleton Key attack unfolds as follows:

1. **Initial Compromise**: The attacker gains administrative access to a domain controller, often through privilege escalation techniques or by compromising high-privilege accounts.
2. **Injection of Malicious Code**: The attacker injects a malicious DLL into the LSASS process on the domain controller. This modifies the authentication flow to allow a hardcoded "skeleton key" password.
3. **Stealthy Access**: Using the skeleton key password, the attacker can authenticate as any user, including administrators, without altering credentials in the directory.
4. **Persistence**: The skeleton key remains active until the domain controller is rebooted. If not remediated, attackers can reinject the key after a reboot.

Skeleton Key attacks are often conducted with tools like **Mimikatz** and require administrative-level access to the domain controller.

***

### **Detection Techniques**

1. **Monitor LSASS Process Modifications**:
   * Look for signs of unauthorised access or injections into the LSASS process.
   * Use Event ID 4688 (Process Creation) to detect execution of suspicious tools like Mimikatz.
2. **Unusual Authentication Behavior**:
   * Analyse authentication logs for repeated logins from the same account using different devices or IPs.
   * Correlate Event ID 4624 (Successful Logon) to identify anomalous patterns such as simultaneous logins to multiple systems.
3. **Memory Analysis**:
   * Perform memory forensics on domain controllers to detect injected DLLs or modifications to LSASS.
4. **Network Traffic Analysis**:
   * Monitor for lateral movement and unexpected authentication attempts across the network.
5. **Behavioral Analytics**:
   * Use User and Entity Behavior Analytics (UEBA) to detect deviations in normal user behaviour, especially for high-privilege accounts.
6.  Events that Detect a Skeleton Key

    Source of detection

    * **Event ID 1102:** Events generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if a Domain Controller has been compromised.
    * **Event ID 3033:** Events generated when a driver fails to load because it does not meet Microsoft’s signing requirements. This indicates that a code integrity check determined that a process, usually LSASS.exe, attempted to load a driver that did not meet the Microsoft signing level requirements. These drivers fail to load if LSASS protection is enabled and should be audited before enabling protection. Furthermore, an unknown driver or plugin may indicate attempted tampering with the LSASS process.
    * **Event ID 3063:** Events generated when a driver failed to load because it did not meet the security requirements for shared sections. This indicates a code integrity check determined that a process, usually lsass.exe, attempted to load a driver that did not meet the security requirements for shared sections. These drivers will fail to load if LSASS protection is enabled and should be audited before enabling protection. An unknown driver or plugin may also indicate attempted tampering with the LSASS process.
    * **Event ID 4103:** Events generated when PowerShell executes and logs pipeline execution details. Common malicious tools used to execute a Skeleton Key, such as Mimikatz, use PowerShell. Analysing this event for PowerShell execution relating to a Skeleton Key may indicate a compromise.
    * **Event ID 4104:** Events generated when code is executed by PowerShell, capturing scripts and the commands run. Abnormal script execution should be investigated, noting that PowerShell-based tools such as Invoke-Mimikatz can be utilised to deploy a Skeleton Key without having to copy any files onto the Domain Controller.
    * **Event ID 4663:** Events generated when an attempt was made to access an object. If ‘Kernel Object Auditing’ is enabled, this will include logging when a process attempts to access the memory of the LSASS process. This is the most direct indicator of tampering with the LSASS process. Any event with the object as ‘lsass.exe’ from an unexpected process (including remote administrative tools such as PowerShell Remoting \[wsmprovhost.exe]), could indicate the deployment of a Skeleton Key. Certain antivirus or endpoint solutions may access the LSASS process; therefore, it is important to determine what security solutions are present and expected on the host.
    * **Event ID 4673:** Events generated when a privileged service is called. This event triggers when the ‘SeDebugPrivilege’ privilege is enabled, which is required to successfully execute a Skeleton Key. This event also triggers when the ‘SeTCBPrivilege’ privilege is used. The ‘SeTCBPrivilege’ privilege allows for the impersonation of the system account and is often requested by Mimikatz.
    * **Event ID 4697:** Events generated when a service has been installed on the system. If this is an unknown kernel mode driver it may indicate a malicious or vulnerable driver being leveraged for exploitation, such as to bypass LSA protection. A service type field of ‘0x1’ or ‘0x2’ can indicate kernel driver services. Services are also installed with the use of some remoting tools, such as PSExec.
    * **Event ID 4703:** Events generated when a user right is adjusted. The addition of the ‘SeDebugPrivilege’ privilege, or other sensitive privileges such as ‘SeTCBPrivilege’, for an account may indicate attempts to deploy a Skeleton Key.

***

### **Mitigation Techniques**

1. **Limit Access to Domain Controllers**:
   * Restrict administrative access to domain controllers to a minimal number of trusted accounts.
   * Enforce multi-factor authentication (MFA) for all privileged accounts.
2. **Patch and Update Regularly**:
   * Ensure all domain controllers are up-to-date with the latest security patches to mitigate known vulnerabilities.
3. **Monitor for Known Attack Tools**:
   * Use endpoint detection and response (EDR) tools to identify the presence of tools like Mimikatz.
4. **Enable Secure LSASS Protections**:
   * On supported Windows versions, enable **Credential Guard** and configure LSASS to run as a protected process to prevent tampering.
5. **Auditing and Logging**:
   * Enable advanced auditing for process creation, authentication, and administrative actions.
   * Centralise logs in a SIEM solution for continuous monitoring.
6. **Periodic Memory Dumps**:
   * Regularly analyse memory dumps of domain controllers for signs of injected code.
7. **The following security controls should be implemented to mitigate Skeleton Key:**
   * Limit access to Domain Controllers to only privileged users that require access. This reduces the number of opportunities for malicious actors to gain access to Domain Controllers.
   * Restrict privileged access pathways to Domain Controllers to jump servers and secure admin workstations using only the ports and services that are required for administration. Domain Controllers are classified as ‘Tier 0’ assets within Microsoft’s ‘Enterprise Access Model’.
   * Run the LSASS process in protected mode. This makes it more difficult to override the LSASS process, which is required for Skeleton Key to succeed.
   * Implement Microsoft’s vulnerable driver blocklist. Restricting known malicious or vulnerable drivers on Domain Controllers makes it more difficult for malicious actors to bypass LSASS protection.
   * Restrict driver execution to an approved set. Restricting the drivers that can be loaded on Domain Controllers to an approved set hardens it against attempts to bypass LSASS protection. This can be achieved through application control solutions, including Microsoft’s Windows Defender Application Control.
   * Only use Domain Controllers for AD DS and do not install any non-security-related services or applications. This reduces the attack surface of Domain Controllers as there are fewer services, ports and applications that may be vulnerable and used to compromise a Domain Controller.&#x20;
   * Centrally log and analyse Domain Controller logs in a timely manner to identify malicious activity. Domain Controller logs provide a rich source of information that is important for investigating potentially malicious activity on Domain Controllers and in the domain.
   * Disable the Print Spooler service on Domain Controllers. For example, threat actors have targeted the Print Spooler service on Domain Controllers as a technique to authenticate to a system they control to collect the Domain Controllers computer object password hash or TGT. Malicious actors can then use this to authenticate to the Domain Controller they coerced and gain administrative access
8. **Incident Response Planning**:
   * Have a robust incident response plan in place to quickly isolate and remediate compromised domain controllers.

***

Skeleton Key attacks represent a critical risk to Active Directory environments due to their stealth and impact. By implementing strong access controls, proactive monitoring, and regular audits, organisations can reduce the likelihood of such attacks and enhance their overall security posture.

### KQL Detection Queries

Detecting a **Skeleton Key** attack requires identifying suspicious activity on domain controllers, such as unauthorised LSASS process modifications, abnormal authentication patterns, or lateral movement activity. The following is a **query** tailored to detect potential **Skeleton Key** activity in Microsoft Sentinel.

{% tabs %}
{% tab title="Query 1" %}
KQL Query to Detect Skeleton Key

{% code overflow="wrap" %}
```kusto
// Step 1: Detect Suspicious Process Activity on Domain Controllers
let SuspiciousProcess = SecurityEvent
| where EventID == 4688  // Process Creation
| where ParentImage endswith "lsass.exe" or NewProcessName has "mimikatz" or CommandLine contains "sekurlsa::"
| extend IsSuspiciousProcess = true
| project TimeGenerated, Computer, AccountName, ParentImage, NewProcessName, CommandLine, IsSuspiciousProcess;

// Step 2: Identify Unusual Authentication Patterns
let UnusualAuthentication = SecurityEvent
| where EventID == 4624  // Successful Logon
| where LogonType in (3, 10)  // Network and remote interactive logons
| where TargetUserName !endswith "$"  // Exclude machine accounts
| summarize LoginCount = count() by TargetUserName, IpAddress, Computer, LogonType
| where LoginCount > 5  // High frequency of logins in a short period
| extend IsSuspiciousLogin = true
| project TimeGenerated, TargetUserName, IpAddress, Computer, LogonType, LoginCount, IsSuspiciousLogin;

// Step 3: Monitor Privileged Account Activity
let PrivilegedActivity = SecurityEvent
| where EventID == 4672  // Special Privilege Logon
| extend SuspiciousPrivilege = Privileges contains "SeDebugPrivilege"  // Privilege often used for LSASS tampering
| where SuspiciousPrivilege
| project TimeGenerated, AccountName, Privileges, Computer, IpAddress;

// Step 4: Correlate All Suspicious Activities
SuspiciousProcess
| join kind=inner (UnusualAuthentication) on Computer
| join kind=inner (PrivilegedActivity) on Computer
| summarize Count = count(), LoginCount = max(LoginCount), PrivilegeCount = countif(SuspiciousPrivilege) by Computer, AccountName, TargetUserName, CommandLine, Privileges, IpAddress
| where Count > 2  // Threshold for correlated suspicious activities
| project TimeGenerated, Computer, AccountName, TargetUserName, CommandLine, Privileges, IpAddress, Count, LoginCount, PrivilegeCount
| order by Count desc
```
{% endcode %}

#### **Explanation of the Query**

1. **Step 1: Detect Suspicious Processes**:
   * Monitors for processes created with `lsass.exe` as the parent or suspicious tools like Mimikatz.
   * Filters for commands (`sekurlsa::`) associated with Skeleton Key activities.
2. **Step 2: Identify Unusual Authentication**:
   * Tracks high-frequency logins (`4624`) from the same account or IP address, which may indicate Skeleton Key usage.
   * Focuses on network or remote logons (`LogonType 3, 10`).
3. **Step 3: Privileged Account Activity**:
   * Detects privileged logons (`4672`) where sensitive privileges like `SeDebugPrivilege` are granted, often used for LSASS tampering.
4. **Step 4: Correlation**:
   * Combines suspicious process activity, unusual authentication patterns, and privileged logon activity on the same domain controller.
   * Highlights cases where multiple indicators of compromise occur (`Count > 2`).

***

#### **Customisations**

* Adjust thresholds like `LoginCount > 5` or `Count > 2` based on your organisation’s activity baseline.
* Add filters for specific tools or command-line arguments known to be used in Skeleton Key attacks.
* Include additional privileged actions, such as `SeTakeOwnershipPrivilege` or `SeBackupPrivilege`.

***

#### **Output**

The query provides:

* The domain controller (`Computer`) where activity occurred.
* The accounts (`AccountName`, `TargetUserName`) involved in suspicious processes or logons.
* Details of suspicious commands, privileges, and IP addresses.

***

#### **Usage**

Integrate this query into Microsoft Sentinel for:

* **Dashboards**: Visualise suspicious activity related to domain controllers.
* **Alerts**: Set up real-time alerts for correlated suspicious activity.
* **Investigation**: Use the output to prioritise response to potential Skeleton Key attacks.

This advanced query leverages process monitoring, authentication analysis, and privilege detection to identify **Skeleton Key** attacks effectively.
{% endtab %}

{% tab title="Query 2" %}
KQL query to detect potential Skeleton Key attacks by monitoring specific event IDs that are indicative of such activities:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID in (1102, 3033, 3063, 4103, 4104, 4663, 4673, 4697, 4703)
| extend EventDescription = case(
    EventID == 1102, "Security audit log cleared",
    EventID == 3033, "Driver failed to load (Microsoft signing requirements)",
    EventID == 3063, "Driver failed to load (security requirements for shared sections)",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
    EventID == 4663, "Attempt to access an object",
    EventID == 4673, "Privileged service called",
    EventID == 4697, "Service installed on the system",
    EventID == 4703, "User right adjusted",
    "Unknown Event"
)
| project TimeGenerated, EventID, EventDescription, Computer, Account, LogonType, LogonProcessName, IpAddress, IpPort
| sort by TimeGenerated desc
```
{% endcode %}

The above query will help to identify events related to a potential Skeleton Key attack by monitoring key event IDs and providing relevant details for further investigation.
{% endtab %}

{% tab title="Query 3" %}
The following is a more **advanced KQL query** for detecting potential **Skeleton Key** activity. This query uses multiple layers of detection, including memory tampering detection, abnormal authentication patterns, privilege escalation, and lateral movement correlations.

{% code overflow="wrap" %}
```kusto
// Step 1: Detect Suspicious Processes and LSASS Tampering
let SuspiciousProcessActivity = SecurityEvent
| where EventID == 4688  // Process Creation
| where ParentImage endswith "lsass.exe" or NewProcessName has "mimikatz" or CommandLine contains "sekurlsa::"
| extend ProcessType = case(
    NewProcessName has "mimikatz", "Mimikatz Detected",
    CommandLine contains "sekurlsa::", "Skeleton Key Command",
    ParentImage endswith "lsass.exe", "LSASS Tampering",
    "Other")
| project TimeGenerated, Computer, AccountName, ParentImage, NewProcessName, CommandLine, ProcessType;

// Step 2: Detect Unusual Authentication Patterns
let UnusualAuthenticationPatterns = SecurityEvent
| where EventID == 4624  // Successful Logon
| where LogonType in (3, 10)  // Network and remote interactive logons
| where TargetUserName !endswith "$"  // Exclude machine accounts
| summarize LoginCount = count() by TargetUserName, IpAddress, Computer, LogonType
| where LoginCount > 5  // High login frequency threshold
| extend AuthenticationType = "Suspicious Authentication"
| project TimeGenerated, TargetUserName, IpAddress, Computer, LogonType, LoginCount, AuthenticationType;

// Step 3: Monitor Privileged Logons
let PrivilegedLogons = SecurityEvent
| where EventID == 4672  // Special Privilege Logon
| extend PrivilegedAction = case(
    Privileges contains "SeDebugPrivilege", "Debug Privilege Used",
    Privileges contains "SeTakeOwnershipPrivilege", "Ownership Privilege Used",
    Privileges contains "SeBackupPrivilege", "Backup Privilege Used",
    "Other")
| project TimeGenerated, AccountName, Computer, Privileges, PrivilegedAction;

// Step 4: Track Anomalous Lateral Movement
let LateralMovementDetection = SecurityEvent
| where EventID == 4624  // Logon Success
| where LogonType == 3  // Network logon
| where TargetUserName != AccountName  // Lateral movement detection
| summarize MovementCount = count() by TargetUserName, SourceComputer = Computer, DestinationComputer = TargetComputer, IpAddress
| where MovementCount > 3  // Threshold for abnormal lateral movement
| project TimeGenerated, TargetUserName, SourceComputer, DestinationComputer, IpAddress, MovementCount;

// Step 5: Correlate Suspicious Activities
SuspiciousProcessActivity
| join kind=inner (UnusualAuthenticationPatterns) on Computer
| join kind=inner (PrivilegedLogons) on Computer
| join kind=inner (LateralMovementDetection) on Computer
| summarize Count = count(), LoginFrequency = max(LoginCount), PrivilegedActions = countif(PrivilegedAction != ""), LateralMoves = max(MovementCount) by Computer, AccountName, TargetUserName, ProcessType, Privileges, CommandLine, IpAddress
| where Count > 3  // Highlight cases with multiple correlated suspicious activities
| project TimeGenerated, Computer, AccountName, TargetUserName, ProcessType, Privileges, CommandLine, IpAddress, Count, LoginFrequency, PrivilegedActions, LateralMoves
| order by Count desc
```
{% endcode %}

#### **Key Enhancements in This Query**

1. **Expanded Detection Criteria**:
   * Detects LSASS tampering, Mimikatz usage, and Skeleton Key commands via process monitoring (`EventID 4688`).
   * Identifies abnormal authentication patterns by correlating logon events (`EventID 4624`).
2. **Privileged Actions**:
   * Tracks sensitive privileges like `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, and `SeBackupPrivilege`, commonly abused during Skeleton Key attacks.
3. **Lateral Movement Monitoring**:
   * Identifies unusual lateral movement patterns where users log into multiple systems within a short time.
4. **Correlated Detection**:
   * Combines process tampering, authentication anomalies, privilege escalation, and lateral movement into a single query to detect complex attack patterns.
5. **Dynamic Thresholds**:
   * Thresholds (`LoginCount > 5`, `MovementCount > 3`, `Count > 3`) can be customised to fit the environment’s activity baseline.

***

#### **Customisations**

* **Thresholds**:
  * Adjust `LoginCount`, `MovementCount`, and `Count` to reflect typical activity in your organisation.
* **Process Detection**:
  * Add additional known malicious commands or tools used in Skeleton Key attacks.
* **Privilege Monitoring**:
  * Expand the privilege list to include other sensitive privileges specific to your environment.

***

#### **Output**

The query provides:

* Suspicious processes (`ProcessType`) and commands (`CommandLine`).
* Privileged actions (`Privileges`) and associated accounts.
* Lateral movement activity and authentication anomalies.
* Counts of correlated suspicious events for prioritisation.

***

#### **Usage**

This advanced query can be integrated into Microsoft Sentinel for:

1. **Real-Time Alerts**: Detect Skeleton Key activity as it occurs.
2. **Dashboards**: Visualise anomalies across authentication, processes, and privilege usage.
3. **Investigations**: Prioritise incidents with multiple correlated events.

By leveraging detailed correlation, this query improves detection accuracy and helps uncover sophisticated Skeleton Key attacks.
{% endtab %}

{% tab title="Query 4" %}
Below is another advanced KQL query to detect potential Skeleton Key attacks by incorporating additional filtering, anomaly detection, and correlation with other logs:

{% code overflow="wrap" %}
```kusto
let suspiciousEvents = SecurityEvent
| where EventID in (1102, 3033, 3063, 4103, 4104, 4663, 4673, 4697, 4703)
| extend EventDescription = case(
    EventID == 1102, "Security audit log cleared",
    EventID == 3033, "Driver failed to load (Microsoft signing requirements)",
    EventID == 3063, "Driver failed to load (security requirements for shared sections)",
    EventID == 4103, "PowerShell pipeline execution details",
    EventID == 4104, "PowerShell script execution",
    EventID == 4663, "Attempt to access an object",
    EventID == 4673, "Privileged service called",
    EventID == 4697, "Service installed on the system",
    EventID == 4703, "User right adjusted",
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

The following are **Splunk queries** designed to detect potential **Skeleton Key** activity. This query identifies LSASS tampering, unusual authentication patterns, privilege escalation, and lateral movement commonly associated with Skeleton Key attacks.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query for Skeleton Key Detection

{% code overflow="wrap" %}
```spl
index=security OR index=windows OR index=active_directory
sourcetype=WinEventLog:Security
(EventCode=4688 OR EventCode=4624 OR EventCode=4672)
| eval ActivityType=case(
    EventCode==4688, "Process Creation",
    EventCode==4624, "Authentication",
    EventCode==4672, "Privileged Logon",
    true(), "Other")
| eval SuspiciousActivity=case(
    EventCode==4688 AND (New_Process_Name IN ("mimikatz.exe", "procdump.exe") OR Parent_Process_Name="lsass.exe"), "LSASS Tampering",
    EventCode==4688 AND Command_Line LIKE "*sekurlsa::*", "Skeleton Key Command Detected",
    EventCode==4624 AND Logon_Type IN (3, 10) AND Target_User_Name!="Administrator" AND Target_User_Name !endswith "$", "Unusual Authentication",
    EventCode==4672 AND Privileges IN ("SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege"), "Suspicious Privileged Logon",
    true(), null)
| where isnotnull(SuspiciousActivity)
| stats count as EventCount values(SuspiciousActivity) as DetectedActivities values(Target_User_Name) as TargetUsers values(Source_Network_Address) as SourceIPs by ActivityType, EventCode, ComputerName, User_Name
| where EventCount > 2  // Threshold for correlated activity
| table _time, ComputerName, User_Name, TargetUsers, SourceIPs, ActivityType, DetectedActivities, EventCount
| sort - EventCount
```
{% endcode %}

#### **Explanation of the Query**

1. **Search Scope**:
   * Searches across relevant indexes (`index=security`, `index=windows`, `index=active_directory`) for event types associated with Skeleton Key activities:
     * **4688**: Process creation for detecting LSASS tampering and suspicious tools like `mimikatz.exe`.
     * **4624**: Authentication events for detecting unusual login behaviour.
     * **4672**: Privileged logon events for monitoring sensitive privilege usage.
2. **Activity Classification**:
   * Assigns an `ActivityType` to each event for easier categorisation:
     * Process Creation, Authentication, and Privileged Logon.
3. **Suspicious Activity Flags**:
   * Flags events indicative of Skeleton Key activity:
     * **LSASS tampering**: Parent process is `lsass.exe` or suspicious processes like `mimikatz.exe`.
     * **Skeleton Key commands**: Presence of commands such as `sekurlsa::`.
     * **Unusual authentication**: Frequent logons from non-administrator accounts or network logon types (3, 10).
     * **Suspicious privileges**: Sensitive privileges like `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, or `SeBackupPrivilege`.
4. **Event Aggregation and Thresholding**:
   * Groups events by `ActivityType`, `ComputerName`, and `User_Name`.
   * Filters results where `EventCount > 2` to surface significant activity.

***

#### **Customisations**

1. **Thresholds**:
   * Adjust `EventCount > 2` based on your organisation's normal activity levels.
2. **Process Detection**:
   * Add more known malicious tools or commands (e.g., `procdump.exe`, `taskmgr.exe`) to the `New_Process_Name` or `Command_Line` checks.
3. **Accounts**:
   * Add specific accounts or roles to monitor, such as domain administrators or service accounts.
4. **Privileges**:
   * Expand the privileges list to include additional sensitive privileges used in your environment.

***

#### **Output**

The query provides:

* **ComputerName**: The system where the suspicious activity occurred.
* **User\_Name**: The account executing the activity.
* **TargetUsers**: Accounts targeted in suspicious logons.
* **SourceIPs**: IP addresses associated with the activity.
* **ActivityType**: Classification of the event (e.g., Process Creation, Authentication).
* **DetectedActivities**: Specific suspicious behaviors flagged.
* **EventCount**: Total number of correlated suspicious events.

***

#### **Usage**

* **Real-Time Alerts**: Set up Splunk alerts to trigger on high event counts or specific suspicious activities.
* **Dashboards**: Use the query in a Splunk dashboard to monitor for Skeleton Key activities in realtime.
* **Incident Response**: Investigate events flagged in the query to determine the scope and impact of potential Skeleton Key attacks.

This Splunk query provides a robust framework for detecting and responding to Skeleton Key attacks by correlating key indicators across process, authentication, and privilege events.
{% endtab %}

{% tab title="Query 2" %}
Splunk query to detect potential Skeleton Key attacks by monitoring specific event codes that are indicative of such activities:

{% code overflow="wrap" %}
```spl
index=windows
| search EventCode IN (1102, 3033, 3063, 4103, 4104, 4663, 4673, 4697, 4703)
| eval EventDescription = case(
    EventCode == 1102, "Security audit log cleared",
    EventCode == 3033, "Driver failed to load (Microsoft signing requirements)",
    EventCode == 3063, "Driver failed to load (security requirements for shared sections)",
    EventCode == 4103, "PowerShell pipeline execution details",
    EventCode == 4104, "PowerShell script execution",
    EventCode == 4663, "Attempt to access an object",
    EventCode == 4673, "Privileged service called",
    EventCode == 4697, "Service installed on the system",
    EventCode == 4703, "User right adjusted",
    true(), "Unknown Event"
)
| table _time, EventCode, EventDescription, host, user, LogonType, LogonProcessName, src_ip, src_port
| sort -_time
```
{% endcode %}

The query will help to identify events related to a potential Skeleton Key attack by monitoring key event codes and providing relevant details for further investigation.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
