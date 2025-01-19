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

# Dumping ntds.dit

### **Introduction to Dumping NTDS.dit**

The **NTDS.dit** file is the Active Directory (AD) database that stores all directory information, including user account data, group memberships, and most critically, password hashes. Dumping the **NTDS.dit** file is a technique used by attackers to extract this sensitive information and gain unauthorised access to an organisation's domain.

Dumping the **NTDS.dit** file is categorised under the **Credential Access** tactic in the **MITRE ATT\&CK Framework** (ID: T1003.003). This technique provides attackers with a wealth of information for lateral movement, privilege escalation, and persistence within a compromised network.

***

### **How NTDS.dit Dumping Works**

1. **Understanding NTDS.dit:**
   * Located in `C:\Windows\NTDS\`, this file contains:
     * **Password Hashes:** NTLM and Kerberos hashes for all domain users.
     * **Account Metadata:** Group memberships, account states, and other attributes.
2. **Challenges for Attackers:**
   * **Locked Access:** The NTDS.dit file is locked by the Local Security Authority Subsystem Service (LSASS) and cannot be directly copied while the domain controller is running.
   * **Encryption:** Certain sections of the file are encrypted.
3. **Common Methods to Dump NTDS.dit:**
   * **VSS (Volume Shadow Copy Service):**
     * Attackers create a shadow copy of the system and extract NTDS.dit from the backup.
   * **NTDSUtil Tool:**
     * Native Windows tool abused to export AD data, including password hashes.
   * **DSRM (Directory Services Restore Mode):**
     * Reboots the domain controller into Directory Services Restore Mode to directly access NTDS.dit.
   * **Mimikatz and Impacket:**
     * Tools like **Mimikatz** and **secretsdump.py** allow attackers to extract hashes remotely via the `DRSUAPI` protocol.
4. **Decryption of Password Hashes:**
   * To decrypt password hashes, attackers extract the **SYSTEM hive** from the registry (e.g., `HKLM\SYSTEM`) to retrieve the boot key used to decrypt the NTDS.dit file.

***

### **Risks of NTDS.dit Dumping**

1. **Complete Credential Access:**
   * Provides NTLM and Kerberos hashes for all accounts in the domain, including privileged accounts like **Domain Admins**.
2. **Stealthy Attacks:**
   * Once dumped, hashes can be used offline, making detection difficult.
3. **Lateral Movement and Escalation:**
   * Enables attackers to move laterally and escalate privileges by impersonating any user.
4. **Persistence:**
   * Hashes can be reused to create Golden Tickets or pass-the-hash attacks for long-term access.

***

### **Indicators of NTDS.dit Dumping**

1. **Shadow Copy Creation:**
   * Unauthorised use of **Volume Shadow Copy Service (VSS)** commands (e.g., `vssadmin`, `diskshadow`).
2. **Export Operations:**
   * Use of **ntdsutil** to export directory data.
3. **Registry Access:**
   * Access to `HKLM\SYSTEM` hive for boot key extraction.
4. **Unusual Logon Patterns:**
   * Logons using NTLM hashes, often seen after hash extraction.
5. **Directory Access Events:**
   * Access to `C:\Windows\NTDS\NTDS.dit`.

***

### **Detection Techniques**

Tools such as Volume Shadow Copy Service and Ntdsutil are commonly used by malicious actors to dump the ntds.dit file and the SYSTEM hive from Domain Controllers. These tools can be executed using PowerShell. If PowerShell logging is enabled, these tool names and their parameters are recorded, which can help identify if an attempt was made to compromise the ntds.dit file. Additionally, monitoring for signs of compromise by analysing events for unusual authentication events, such as objects that do not normally authenticate or authenticate during unusual times of the day, can assist in identifying malicious activity.

1. **Monitor Shadow Copy Creation:**
   * Look for commands like:
     * `vssadmin create shadow /for=C:`
     * `diskshadow`.
2. **Detect NTDSUtil Abuse:**
   * Monitor command-line usage of `ntdsutil` with suspicious parameters:
     * `ntdsutil "ac i ntds" "ifm"`
3. **Registry Monitoring:**
   * Track access to `HKLM\SYSTEM` hive for potential key extraction.
4. **Events that Detect Dumping ntds.dit:**
   * **Event ID 1102:** Event generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if a Domain Controller has been compromised.
   * **Event ID 4103:** Event generated when PowerShell executes and logs pipeline execution details. Malicious actors commonly leverage PowerShell in their compromises. Analysing this event for PowerShell execution relating to the ntds.dit file may indicate dumping of the ntds.dit file.
   * **Event ID 4104:** Event generated when PowerShell executes code to capture scripts and commands. Malicious actors commonly leverage PowerShell in their compromises. Analysing this event for PowerShell execution relating to the ntds.dit file may indicate dumping of the ntds.dit file.
   * **Event ID 4656:** Event generated when a handle to an object has been requested, such as a file: for example, when malicious actors attempt to access the ntds.dit file in any way (e.g., read, write or delete). If the ‘Object Name’ value in the event matches the ntds.dit file, this may indicate the ntds.dit file has been compromised.
   * **Event ID 4663:** Event generated when the System Access Control List (SACL) is enabled for the ntds.dit file and an attempt is made to access, read, write, or modify an object, such as a file. If the ‘Object Name’ value in the event matches the ntds.dit file, this may indicate the ntds.dit file has been compromised.
   * **Event ID 4688:** Event generated when a new process has been created. This event provides context of the commands and parameters that are executed when a new process is created. Malicious actors are likely to create a new process when dumping the ntds.dit file, such as via PowerShell, Volume Shadow Copy Service or Ntdsutil.
   * **Event ID 8222:** Event generated when a shadow copy is made. Making a shadow copy of the ntds.dit file is a common way to bypass file lock restrictions. This event can be analysed to determine if the shadow copy was legitimate or not.
5. **Audit File Access:**
   * Monitor file access to `C:\Windows\NTDS\NTDS.dit`.
6. **Analyse Network Traffic:**
   * Detect the use of tools like **secretsdump.py**, which leverage the `DRSUAPI` protocol.

***

### **Mitigation Strategies**

1. Mitigating dumping ntds.dit&#x20;

Mitigating techniques targeting the ntds.dit file begins with hardening Domain Controllers by restricting privileged access pathways, disabling unused services and ports, not installing additional features or applications, using antivirus and endpoint detection and response solutions, and monitoring for signs of compromise. These mitigations reduce the attack surface of Domain Controllers and increase the likelihood of detecting malicious activity.

**The following security controls should be implemented to mitigate dumping ntds.dit:**

* Limit access to Domain Controllers to only privileged users that require access. This reduces the number of opportunities for malicious actors to gain access to Domain Controllers.
* Restrict privileged access pathways to Domain Controllers to jump servers and secure admin workstations using only the ports and services that are required for administration. Domain Controllers are classified as ‘Tier 0’ assets within Microsoft’s ‘Enterprise Access Model’.
* Encrypt and securely store backups of Domain Controllers and limit access to only Backup Administrators. Backups of Domain Controllers need to be afforded the same security as the actual Domain Controllers. Malicious actors may target backup systems to gain access to critical and sensitive computer objects, such as Domain Controllers.
* Only use Domain Controllers for AD DS and do not install any non-security-related services or applications. This reduces the attack surface of Domain Controllers as there are fewer services, ports and applications that may be vulnerable and used to compromise a Domain Controller.
* Centrally log and analyse Domain Controller logs in a timely manner to identify malicious activity. Domain Controller logs provide a rich source of information that is important for investigating potentially malicious activity on Domain Controllers and in the domain.
* Disable the Print Spooler service on Domain Controllers. For example, malicious actors have targeted the Print Spooler service on Domain Controllers as a technique to authenticate to a system they control to collect the Domain Controllers computer object password hash or TGT. Malicious actors can then use this to authenticate to the Domain Controller they coerced and gain administrative access.
* Disable the Server Message Block (SMB) version 1 protocol on Domain Controllers. There are multiple Active Directory compromises that leverage weaknesses in the SMBv1 protocol to gain access to systems, including Domain Controllers. Disabling SMBv1 on Domain Controllers and on all systems in a domain mitigates compromises that leverage the SMBv1 protocol.

1. **Protect Domain Controllers:**
   * Restrict physical and remote access to domain controllers.
   * Use firewalls to limit communication with domain controllers.
2. **Restrict Shadow Copy Access:**
   * Limit access to tools like `vssadmin` and `diskshadow`.
3. **Secure Registry Keys:**
   * Limit access to `HKLM\SYSTEM` to prevent boot key extraction.
4. **Enable Advanced Auditing:**
   * Configure auditing for file access, shadow copy operations, and command-line execution.
5. **Monitor for Known Tools:**
   * Detect tools like **Mimikatz**, **Impacket**, or **ntdsutil** in use.

***

### **Common Tools Used for NTDS.dit Dumping**

1. **Mimikatz:**
   * Extracts hashes and secrets directly from memory or NTDS.dit.
2. **Impacket (secretsdump.py):**
   * Extracts hashes remotely using the DRSUAPI protocol.
3. **NTDSUtil:**
   * Native Windows tool used to export AD data.
4. **Volume Shadow Copy Tools:**
   * `vssadmin` or `diskshadow` to create shadow copies.

***

Dumping the **NTDS.dit** file provides attackers with a powerful mechanism to compromise an entire Active Directory domain. By securing domain controllers, monitoring for unusual activities like shadow copy creation or registry access, and limiting the use of native tools like `ntdsutil`, organisations can significantly reduce their risk.&#x20;

### KQL Detection Queries

Detecting attempts to **dump the NTDS.dit file** involves monitoring shadow copy creation, unauthorised access to the **NTDS.dit** file, and suspicious use of tools like `ntdsutil`. Below is a **KQL query** for Microsoft Sentinel to identify potential NTDS.dit dumping activity.

{% tabs %}
{% tab title="Query 1" %}
Query to detect potential dumping of the `ntds.dit` file:

{% code overflow="wrap" %}
```kusto
// Define the time range for the query
let startTime = ago(7d);
let endTime = now();

// Step 1: Identify suspicious access to NTDS.dit
let NTDSAccessEvents = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 4662 // An operation was performed on an object
| extend ObjectName = tostring(TargetObject), AccessMask = tostring(AccessMask)
| where ObjectName contains "ntds.dit" and AccessMask contains "0x100" // Access to NTDS.dit
| extend AccountName = tostring(TargetUserName), Domain = tostring(TargetDomainName), ClientIP = tostring(IpAddress)
| project AccountName, Domain, ClientIP, ObjectName, AccessMask, TimeGenerated;

// Step 2: Identify shadow copy creation events
let ShadowCopyEvents = SecurityEvent
| where TimeGenerated between (startTime .. endTime)
| where EventID == 5136 // A directory service object was modified
| extend ObjectName = tostring(TargetObject), OperationType = tostring(OperationType)
| where ObjectName contains "ShadowCopy" and OperationType contains "Create"
| extend AccountName = tostring(TargetUserName), Domain = tostring(TargetDomainName), ClientIP = tostring(IpAddress)
| project AccountName, Domain, ClientIP, ObjectName, OperationType, TimeGenerated;

// Step 3: Combine suspicious NTDS.dit access and shadow copy creation events
NTDSAccessEvents
| join kind=inner (ShadowCopyEvents) on AccountName
| summarize AccessCount = count(), UniqueIPs = dcount(ClientIP), ClientIPs = make_set(ClientIP), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AccountName, Domain
| where AccessCount > 5 // Adjust threshold based on your environment
| project AccountName, Domain, AccessCount, UniqueIPs, ClientIPs, FirstSeen, LastSeen
| sort by AccessCount desc
```
{% endcode %}

Query performs the following steps:

1. **Defines the time range** for the query to look back over the past 7 days.
2. **Identifies suspicious access** to the `ntds.dit` file by looking for Event ID 4662.
3. **Identifies shadow copy creation events** by looking for Event ID 5136.
4. **Combines the results** to identify potential compromises by matching suspicious NTDS.dit access with shadow copy creation events.
{% endtab %}

{% tab title="Query 2" %}
KQL Query to Detect NTDS.dit Dumping

{% code overflow="wrap" %}
```kusto
// Detect shadow copy creation, NTDS.dit access, and suspicious registry activity
SecurityEvent
| where EventID in (4688, 4663, 5145)  // Process creation, file access, and file share access events
| extend CommandLine = tostring(ProcessCommandLine),
         AccessedObject = tostring(EventData.ObjectName),
         FileAccessRights = tostring(EventData.AccessMask)
| where (EventID == 4688 and (CommandLine has "vssadmin" or CommandLine has "ntdsutil" or CommandLine has "diskshadow"))
    or (EventID == 4663 and AccessedObject has "NTDS.dit")
    or (EventID == 5145 and AccessedObject has "\\NTDS\\")
| summarize EventCount = count(), 
            SuspiciousCommands = make_set(CommandLine), 
            AccessedObjects = make_set(AccessedObject), 
            UniqueAccounts = dcount(AccountName), 
            Accounts = make_set(AccountName), 
            min(TimeGenerated) as FirstSeen, 
            max(TimeGenerated) as LastSeen 
    by Computer, EventID
| where EventCount > 1  // Adjust based on baseline activity
| extend SuspiciousActivity = case(
    EventID == 4688 and SuspiciousCommands contains "vssadmin", "High",
    EventID == 4663 and AccessedObjects contains "NTDS.dit", "High",
    EventID == 5145 and AccessedObjects contains "\\NTDS\\", "Medium",
    true(), "Low"
)
| where SuspiciousActivity in ("High", "Medium")
| project Computer, EventID, SuspiciousCommands, AccessedObjects, Accounts, EventCount, FirstSeen, LastSeen, SuspiciousActivity
| sort by SuspiciousActivity desc, LastSeen desc
```
{% endcode %}

#### **Query Breakdown**

1. **Targeted Event IDs:**
   * **4688:** Process creation (to detect suspicious commands like `vssadmin`, `diskshadow`, or `ntdsutil`).
   * **4663:** Object access (to track access to `C:\Windows\NTDS\NTDS.dit`).
   * **5145:** File share access (to detect remote access to NTDS.dit over shared directories).
2. **Filter Suspicious Commands and File Access:**
   * **Shadow Copy Creation:** Detect commands like `vssadmin create shadow` or `diskshadow`.
   * **NTDS.dit Access:** Monitor direct access to the NTDS.dit file or its directory.
   * **File Share Access:** Track access to the `\\NTDS\\` directory.
3. **Aggregate and Summarize:**
   * Groups events by `Computer` and `EventID` to track suspicious activity.
   * Captures suspicious commands, accessed objects, and involved accounts.
4. **Flag Suspicious Activity:**
   * Assigns a **High** or **Medium** score based on event type and context:
     * **High:** Shadow copy creation or direct NTDS.dit access.
     * **Medium:** Remote file share access to NTDS.dit.
5. **Output:**
   * Displays key details, including the computer, suspicious commands, accessed objects, and time range of activity.
{% endtab %}

{% tab title="Query 3" %}
#### **Advanced Query for Registry Key Monitoring**

To detect attempts to access the **SYSTEM** hive for decrypting NTDS.dit, monitor registry access:

{% code overflow="wrap" %}
```kusto
SecurityEvent
| where EventID == 4663
| extend RegistryKey = tostring(EventData.ObjectName)
| where RegistryKey contains "HKLM\\SYSTEM"
| summarize AccessCount = count(), 
            AccessedKeys = make_set(RegistryKey), 
            Accounts = make_set(AccountName), 
            min(TimeGenerated) as FirstSeen, 
            max(TimeGenerated) as LastSeen 
    by Computer
| where AccessCount > 3  // Adjust threshold
| project Computer, AccessedKeys, Accounts, AccessCount, FirstSeen, LastSeen
| sort by AccessCount desc

```
{% endcode %}

#### **Customisations**

1. **Whitelist Trusted Activities:**
   *   Exclude known administrative tasks or service accounts:

       ```kusto
       | where not(AccountName in ("AdminAccount", "BackupService"))
       ```
2. **Adjust Thresholds:**
   * Modify thresholds (`EventCount > 1` or `AccessCount > 3`) based on baseline activity.
3. **Time-Based Grouping:**
   *   Use `bin TimeGenerated` to detect bursts of activity:

       ```kusto
       | bin TimeGenerated span=15m
       ```

***

#### **Recommendations**

1. **Enable Advanced Auditing:**
   * Ensure auditing is configured for:
     * **Process Creation** (4688).
     * **Object Access** (4663).
     * **File Share Access** (5145).
2. **Set Alerts:**
   * Configure alerts for:
     * Shadow copy creation commands.
     * Access to `NTDS.dit` or `HKLM\SYSTEM`.
3. **Restrict Access:**
   * Limit access to domain controllers and critical registry keys.
4. **Monitor Tools:**
   * Detect use of known tools like `Mimikatz` or `secretsdump.py`
{% endtab %}
{% endtabs %}

Splunk Detection Queries

To detect **NTDS.dit dumping** in **Splunk**, you should focus on monitoring activities like shadow copy creation, access to the NTDS.dit file, and usage of tools like `vssadmin`, `diskshadow`, or `ntdsutil`. Below is a Splunk query to detect suspicious activities associated with dumping NTDS.dit.

{% tabs %}
{% tab title="Query 1" %}
Splunk Query to Detect NTDS.dit Dumping

{% code overflow="wrap" %}
```splunk-spl
index=windows (EventCode=4688 OR EventCode=4663 OR EventCode=5145)
| eval EventDescription = case(
    EventCode == 4688, "Process Creation",
    EventCode == 4663, "Object Access",
    EventCode == 5145, "File Share Access",
    true(), "Unknown"
)
| eval CommandLine = coalesce(Process_Command_Line, ""),
        AccessedObject = coalesce(Object_Name, ""),
        FileSharePath = coalesce(Share_Name, "")
| where (EventCode == 4688 AND (CommandLine like "%vssadmin%" OR CommandLine like "%diskshadow%" OR CommandLine like "%ntdsutil%"))
    OR (EventCode == 4663 AND AccessedObject like "%NTDS.dit%")
    OR (EventCode == 5145 AND FileSharePath like "%\\NTDS\\%")
| stats count AS EventCount, 
        values(CommandLine) AS SuspiciousCommands, 
        values(AccessedObject) AS AccessedObjects, 
        values(Account_Name) AS Accounts, 
        values(Source_Network_Address) AS SourceIPs, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName, EventCode, EventDescription
| eval SuspiciousScore = case(
    EventCode == 4688 AND SuspiciousCommands LIKE "%vssadmin%", "High",
    EventCode == 4663 AND AccessedObjects LIKE "%NTDS.dit%", "High",
    EventCode == 5145 AND FileSharePath LIKE "%\\NTDS\\%", "Medium",
    true(), "Low"
)
| where SuspiciousScore IN ("High", "Medium")
| table ComputerName, EventDescription, SuspiciousCommands, AccessedObjects, Accounts, SourceIPs, EventCount, FirstSeen, LastSeen, SuspiciousScore
| sort - SuspiciousScore, -EventCount
```
{% endcode %}

#### **Query Breakdown**

1. **Targeted Event Codes:**
   * **4688:** Detects process creation for commands like `vssadmin`, `diskshadow`, and `ntdsutil`.
   * **4663:** Tracks object access to files like `NTDS.dit`.
   * **5145:** Monitors file share access to directories containing `NTDS.dit`.
2. **Filter Suspicious Commands and Access:**
   * Detects:
     * Shadow copy creation commands (`vssadmin`, `diskshadow`).
     * Attempts to access `NTDS.dit`.
     * File share access to the `\\NTDS\\` directory.
3. **Aggregate and Summarise:**
   * Groups events by `ComputerName` and `EventCode`.
   * Aggregates suspicious commands, accessed objects, and involved accounts.
4. **Suspicious Scoring:**
   * Assigns **High** or **Medium** scores to events based on their likelihood of being malicious:
     * **High:** Shadow copy creation or direct NTDS.dit access.
     * **Medium:** Remote file share access to NTDS.dit.
5. **Output:**
   * Displays the computer, suspicious commands, accessed objects, accounts, source IPs, and event details for investigation.
{% endtab %}

{% tab title="Query 2" %}
#### **Additional Query: Detect Shadow Copy Creation**

To focus on shadow copy creation, use the following query:

{% code overflow="wrap" %}
```splunk-spl
index=windows EventCode=4688
| eval CommandLine = coalesce(Process_Command_Line, "")
| where CommandLine like "%vssadmin create shadow%" OR CommandLine like "%diskshadow%"
| stats count AS ShadowCopyCount, 
        values(CommandLine) AS Commands, 
        values(Account_Name) AS Accounts, 
        min(_time) AS FirstSeen, 
        max(_time) AS LastSeen 
    BY ComputerName
| where ShadowCopyCount > 0
| table ComputerName, Commands, Accounts, ShadowCopyCount, FirstSeen, LastSeen
| sort - ShadowCopyCount
```
{% endcode %}

#### **Customisations**

1. **Whitelist Trusted Activity:**
   *   Exclude known administrative or backup tasks:

       ```splunk-spl
       | where NOT Account_Name IN ("BackupService", "TrustedAdmin")
       ```
2. **Adjust Thresholds:**
   *   Modify thresholds for event counts based on your environment’s baseline:

       ```splunk-spl
       | where EventCount > 1
       ```
3. **Time-Based Grouping:**
   *   Use time-based grouping to detect bursts of activity:

       ```splunk-spl
       | bin _time span=15m
       ```

***

#### **Detection Recommendations**

1. **Set Alerts:**
   * Create alerts for:
     * Shadow copy creation commands.
     * Access to `NTDS.dit` or the `\\NTDS\\` directory.
2. **Enable Advanced Auditing:**
   * Ensure auditing is enabled for:
     * **Process Creation** (4688).
     * **Object Access** (4663).
     * **File Share Access** (5145).
3. **Restrict Access:**
   * Limit access to domain controllers and critical files like `NTDS.dit`.
4. **Monitor for Known Tools:**
   * Look for tools like `Mimikatz`, `secretsdump.py`, and other utilities in use.
{% endtab %}

{% tab title="Query 2" %}
Query to detect potential dumping of the `ntds.dit` file:

{% code overflow="wrap" %}
```splunk-spl
index=your_index sourcetype=your_sourcetype
| eval ObjectName = mvindex(TargetObject, 1)
| where EventCode=4662 // An operation was performed on an object
| search ObjectName="*ntds.dit*" AND AccessMask="0x100" // Access to NTDS.dit
| stats count AS AccessCount, values(IpAddress) AS ClientIPs, dc(IpAddress) AS UniqueIPs BY AccountName
| where AccessCount > 5 // Adjust threshold based on your environment
| table _time, AccountName, AccessCount, UniqueIPs, ClientIPs
| sort - AccessCount
```
{% endcode %}

Query performs the following steps:

1. **Filters events** to include only those with EventCode 4662, which corresponds to operations performed on objects.
2. **Searches for access to the** `ntds.dit` **file** by filtering for ObjectName containing "ntds.dit" and AccessMask "0x100".
3. **Aggregates the data** to count the number of access events and unique IPs per AccountName.
4. **Filters the results** to include only those with more than 5 access events (adjust the threshold based on your environment).
5. **Displays the results** in a table format, sorted by the number of access events.
{% endtab %}
{% endtabs %}

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
