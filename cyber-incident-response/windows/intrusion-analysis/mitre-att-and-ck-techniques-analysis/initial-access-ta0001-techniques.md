---
icon: laptop-code
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

# Initial Access (TA0001) Techniques

### Introduction

Investigating initial access in a network, particularly in Windows workstations and server systems, involves a structured approach to identify how an unauthorised entity first gained entry. This process is critical for understanding the scope and impact of a security incident.

Initial Preparation and Response

* **Initial Assessment:** Confirm the breach and assess the scope.
* **Secure Your Environment:** Ensure the investigation is conducted securely to prevent further compromise.
* **Containment:** Isolate affected systems to prevent lateral movement or further damage.
* **Preserve Evidence:** Immediately secure and preserve logs and data that could be critical for the investigation.

Identify Entry Points

* **Review Logs:** Check security logs, system logs, application logs, and firewall logs for unusual activities.
* **Analyse Network Traffic:** Look for anomalies in network traffic that could indicate unauthorised access.
* **Examine Entry Points:** Common entry points include email (phishing), remote desktop protocol (RDP), web applications, and external devices.

System-Specific Investigations

* **Windows Workstation:**
  * Check Event Viewer for login attempts, application errors, and system messages.
  * Analyse the Windows Security Logs for failed login attempts or unusual successful logins.
  * Use tools like Process Explorer to examine running processes for signs of malicious activity.
* **Windows Server:**
  * Examine IIS logs if the server hosts web applications.
  * Review Active Directory logs for unauthorised changes.
  * Check database logs to see if the server hosts critical databases.

Forensic Analysis

* **Disk and Memory Forensics:** Use tools like Volatility for memory analysis and Autopsy for disk forensics.
* **Timeline Analysis:** Build a timeline of events to understand the sequence of actions taken by the attacker.
* **Artifact Analysis:** Examine files, registry entries, and other system artefacts for signs of tampering or unauthorised access.

Malware Analysis (If Applicable)

* **Identify Malware:** Use antivirus scans and malware analysis tools to identify and analyse malicious software.
* **Reverse Engineering:** If skilled resources are available, reverse-engineering malware can provide insights into its capabilities and origin.

Utilise Threat Intelligence

* **Cross-reference Indicators of Compromise (IoCs):** Compare findings with known IoCs from threat intelligence sources.
* **Contextualise the Attack:** Understand if the attack is part of a more extensive campaign or linked to known threat actors.

Interviews and Internal Investigation

* **Conduct Interviews:** Talk to users who might have witnessed unusual activities or received phishing emails.
* **Review Internal Policies:** Check for any recent changes in network or security policies that could have opened vulnerabilities.

Documentation and Reporting

* **Detail Findings:** Document every step taken and evidence found during the investigation.
* **Report to Stakeholders:** Provide clear and comprehensive reports to relevant stakeholders, including technical details and business impact.

Post-Investigation Actions

* **Remediation:** Address the identified vulnerabilities and entry points.
* **Monitoring:** Enhance monitoring capabilities to detect similar attempts in the future.
* **Lessons Learned:** Conduct a post-mortem to improve security posture and response capabilities.

Legal and Compliance Considerations

* **Legal Compliance:** Ensure the investigation complies with legal requirements and industry standards.
* **Data Protection:** Be mindful of privacy and data protection laws when handling sensitive information.

Forensic investigation of initial access is a meticulous and detailed process. Each step is critical to uncovering the full scope of the intrusion and preventing future incidents. Stay updated with the latest forensic techniques and tools as cyber threats evolve.

### Using KQL to Investigate Initial Access Activities in an Environment Using Defender/Sentinel

Initial Access is the first stage in the attack lifecycle, where adversaries gain entry into a network.

Note: While there are more straightforward methods for looking at these kinds of attacks, the goal is to tackle them from a beginner's point of view without utilising intricate KQL queries that a Junior SOC analyst would find challenging to understand the intent of the query.

### **1. T1190 - Exploit Public-Facing Application**

**Objective**: Detect attempts to exploit vulnerabilities in public-facing applications to gain unauthorised access.&#x20;

1.  **Detect Unusual HTTP POST Requests**

    _Purpose_: Identify suspicious POST requests that might exploit attempt.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has "POST" | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

2.  **Monitor Web Server Logs for Exploit Patterns**

    _Purpose_: Detect patterns in web logs that may indicate exploitation.

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "IIS\\Logs" or FolderPath has "Apache\\Logs" | where FileName contains ".log" | summarize count() by FileName, DeviceName, FilePath
```
{% endcode %}

3.  **Detect Suspicious Input in Web Forms**

    _Purpose_: Identify attempts at SQL injection or XSS.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("<script>", "UNION SELECT", "' OR 1=1") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

4.  **Identify Access to Vulnerable Endpoints**

    _Purpose_: Detect attempts to access known vulnerable endpoints.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("admin", "login", "upload") | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

5.  **Monitor for Known Exploit Tools**

    _Purpose_: Identify the use of automated tools to exploit web applications.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("sqlmap", "metasploit", "dirbuster") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

6.  **Detect Web Shell Uploads**

    _Purpose_: Monitor for the upload of web shells.

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".aspx" or FileName endswith ".php" | summarize count() by FileName, DeviceName
```
{% endcode %}

7.  **Monitor for Suspicious GET Requests**

    _Purpose_: Identify GET requests that attempt to execute commands.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has "GET" and ProcessCommandLine contains "cmd" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

8.  **Detect Suspicious File Uploads**

    _Purpose_: Monitor for excessive file uploads.

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("uploads", "files", "images") | summarize count() by FileName, DeviceName | where count() > 10
```
{% endcode %}

9.  **Monitor for Exploit Attempts via HTTP Headers**

    _Purpose_: Detect exploit attempts via HTTP headers.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("User-Agent:", "Referer:") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

10. **Identify Unexpected Application Behaviour**

    _Purpose_: Monitor for web servers executing unexpected processes.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "w3wp.exe" or ProcessCommandLine has "httpd.exe" | where ProcessCommandLine has_any ("cmd.exe", "powershell.exe") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

### **2. T1078 - Valid Accounts**

**Objective**: Detect unauthorised access using stolen or compromised credentials.

1.  **Detect Logins from Unusual Locations**

    _Purpose_: Identify logins from unfamiliar IP addresses.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "Network" and AccountType == "User" | summarize count() by TargetUserName, IPAddress | where count() > 1
```
{% endcode %}

2.  **Monitor Logins Outside Business Hours**

    _Purpose_: Detect logins occurring outside regular working hours.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Success" and LogonTime between (startofday(now()) - 7d) and (startofday(now()) - 1d) | where hour(LogonTime) < 6 or hour(LogonTime) > 18 | summarize count() by TargetUserName, LogonTime
```
{% endcode %}

3.  **Detect Failed Login Attempts**

    _Purpose_: Identify multiple failed login attempts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" | summarize count() by TargetUserName, DeviceName | where count() > 5`
```
{% endcode %}

4.  **Identify Privileged Account Use**

    _Purpose_: Monitor the usage of privileged accounts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Privileged" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

5.  **Detect Logins from Multiple Geolocations**

    _Purpose_: Identify users logging in from multiple geolocations in a short period.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | summarize locations=make_set(IPAddressCountry) by TargetUserName | where array_length(locations) > 1
```
{% endcode %}

6.  **Monitor for New Account Creations**

    _Purpose_: Detect the creation of new accounts.

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "NewUserCreated" | project Timestamp, TargetUserName, InitiatingProcessAccountName
```
{% endcode %}

7.  **Detect Account Deletions**

    _Purpose_: Monitor for account deletions.

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "UserDeleted" | project Timestamp, TargetUserName, InitiatingProcessAccountName
```
{% endcode %}

8.  **Monitor for Account Privilege Escalation**

    _Purpose_: Detect unauthorised privilege escalations.

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "Add member to role" and RoleName == "Global Administrator" | project Timestamp, TargetUserName, InitiatingProcessAccountName
```
{% endcode %}

9.  **Detect Suspicious Use of Service Accounts**

    _Purpose_: Monitor the use of service accounts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName has "svc-" or TargetUserName has "service" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

10. **Identify Logins with Disabled Accounts**

    _Purpose_: Detect login attempts with disabled accounts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountEnabled == "False" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Detect login attempts with disabled accounts.

### **3. T1195 - Supply Chain Compromise**

**Objective**: Detect indicators of a supply chain compromise where an adversary infiltrates via a third-party service or software.

1.  **Monitor for New or Unknown Software Installations**

    _Purpose_: Detect installation of software from potentially compromised supply chains.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("msiexec", "setup.exe", "install.exe") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

2.  **Identify Changes to Critical System Files**

    _Purpose_: Monitor for modifications to critical system files.

{% code overflow="wrap" %}
```csharp
DeviceFileEvents | where FolderPath has_any ("C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)") | where FileOperation == "Modify" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

3.  **Detect Communication with Known Malicious IPs**

    _Purpose_: Identify communication with IP addresses known to be associated with supply chain attacks.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("known_malicious_ips_list") | project Timestamp, DeviceName, RemoteIP, RemotePort
```
{% endcode %}

4.  **Monitor for Unusual Application Behaviour**

    _Purpose_: Detect unexpected execution of system tools by third-party applications.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("cmd.exe", "powershell.exe") and InitiatingProcessFileName != "cmd.exe" and InitiatingProcessFileName != "powershell.exe" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

5.  **Identify Suspicious DLL Loads**

    _Purpose_: Monitor for DLL loads that may indicate a compromised application.

{% code overflow="wrap" %}
```cs
DeviceImageLoadEvents | where FileName endswith ".dll" and FolderPath has_any ("C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

6.  **Detect New or Unknown Network Connections**

    _Purpose_: Identify new or unknown network connections that could indicate a supply chain attack.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "ConnectionSuccess" and RemoteIP !in ("known_good_ips_list") | summarize count() by RemoteIP, LocalIP | where count() > 5
```
{% endcode %}

7.  **Monitor for Changes to Startup Programs**

    _Purpose_: Detect unauthorised changes to startup programs.

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

8.  **Identify Unauthorised Code Signing**

    _Purpose_: Monitor for unauthorised code signing that could indicate a compromised application.

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".exe" or FileName endswith ".dll" | where FileOperation == "Modify" and CertificateIssuer !in ("trusted_issuers_list") | project Timestamp, DeviceName, FileName, CertificateIssuer
```
{% endcode %}

9.  **Detect Changes to System Services**

    _Purpose_: Identify changes to system services that may be linked to a supply chain compromise.

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" or ActionType == "ServiceModified" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine
```
{% endcode %}

10. **Monitor for Suspicious Scripting Activity**

    _Purpose_: Detect the execution of scripts that could be associated with a supply chain attack.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any (".ps1", ".vbs", ".bat") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

### **4. T1199 - Trusted Relationship**

**Objective**: Detect unauthorised access or activity stemming from a trusted relationship, such as a partner or vendor.

1.  **Monitor for Logins from Partner Networks**

    _Purpose_: Identify logins originating from partner networks.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where IPAddress in ("partner_ip_range") | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

2.  **Detect Unusual Activity from Trusted Accounts**

    _Purpose_: Monitor for unusual activity from accounts associated with trusted relationships.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("trusted_account_list") | summarize count() by TargetUserName, DeviceName, LogonTime | where count() > 5
```
{% endcode %}

3.  **Identify Access to Critical Systems by Trusted Accounts**

    _Purpose_: Detect access to critical systems by trusted accounts.

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where TargetUserName in ("trusted_account_list") and DeviceName in ("critical_systems_list") | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

4.  **Monitor for Changes to Permissions of Trusted Accounts**

    _Purpose_: Detect changes to permissions for trusted accounts.

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where TargetUserName in ("trusted_account_list") and ActionType == "PermissionModified" | project Timestamp, TargetUserName, InitiatingProcessAccountName, PermissionsChanged
```
{% endcode %}

5.  **Detect Unusual File Access by Trusted Accounts**

    _Purpose_: Identify unusual file access by trusted accounts.

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where InitiatingProcessAccountName in ("trusted_account_list") and FolderPath in ("sensitive_directories_list") | summarize count() by InitiatingProcessAccountName, DeviceName, FolderPath
```
{% endcode %}

6.  **Monitor for Network Connections from Trusted Vendors**

    _Purpose_: Detect network connections originating from vendor networks.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("vendor_ip_range") | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

7.  **Identify Changes to Firewall Rules by Trusted Accounts**

    _Purpose_: Monitor changes to firewall rules by trusted accounts.

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" | where InitiatingProcessAccountName in ("trusted_account_list") | project Timestamp, DeviceName, RegistryKey, RegistryValueName
```
{% endcode %}

8.  **Detect Installation of Software by Trusted Accounts**

    _Purpose_: Identify software installation by trusted accounts.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("install.exe", "setup.exe") and InitiatingProcessAccountName in ("trusted_account_list") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

9.  **Monitor for Changes to Network Configurations by Trusted Accounts**

    _Purpose_: Detect changes to network configurations by trusted accounts.

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" | where InitiatingProcessAccountName in ("trusted_account_list") | project Timestamp, DeviceName, RegistryKey, RegistryValueName
```
{% endcode %}

10. **Identify Unusual Email Activity from Trusted Accounts**

    _Purpose_: Monitor for unusual email activity from trusted domains.

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where SenderAddress in ("trusted_email_domains") | summarize count() by SenderAddress, RecipientAddress
```
{% endcode %}

### **5. T1133 - External Remote Services**

**Objective**: Detect unauthorised access via external remote services such as VPNs, RDP, or other remote access tools.

1.  **Detect RDP Logins from Unfamiliar IPs**

    _Purpose_: Identify RDP logins from unfamiliar IP addresses.

{% code overflow="wrap" %}
```csharp
IdentityLogonEvents | where LogonType == "RemoteInteractive" and IPAddress not in ("known_good_ips") | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

2.  **Monitor VPN Connections from Unusual Locations**

    _Purpose_: Detect VPN connections from unusual locations.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and RemoteIP not in ("trusted_ip_ranges") | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

3.  **Identify SSH Logins from External Sources**

    _Purpose_: Monitor SSH logins from external IP addresses.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "SSH" and IPAddress not in ("internal_ip_range") | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

4.  **Monitor for Remote Desktop Gateway Access**

    _Purpose_: Identify access to Remote Desktop Gateways.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and DeviceName contains "RDGateway" | summarize count() by TargetUserName, DeviceName, IPAddress
```
{% endcode %}

5.  **Detect Multiple Failed Remote Login Attempts**

    _Purpose_: Identify multiple failed remote login attempts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Failed" | summarize count() by TargetUserName, IPAddress | where count() > 5
```
{% endcode %}

6.  **Monitor for RDP Connections Outside Business Hours**

    _Purpose_: Detect RDP connections outside normal working hours.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and (hour(LogonTime) < 6 or hour(LogonTime) > 18) | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

7.  **Detect Use of Remote Access Tools**

    _Purpose_: Identify the use of remote access tools.

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("teamviewer.exe", "anydesk.exe", "vncviewer.exe") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

8.  **Identify VPN Logins from Multiple Geolocations**

    _Purpose_: Monitor VPN logins from multiple geolocations.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "VPN" | summarize locations=make_set(IPAddressCountry) by TargetUserName | where array_length(locations) > 1
```
{% endcode %}

9.  **Monitor for External Access to Administrative Accounts**

    _Purpose_: Detect remote access to administrative accounts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Privileged" and LogonType == "RemoteInteractive" | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

10. **Detect VPN Access from Blacklisted Countries**

    _Purpose_: Identify VPN access attempts from blacklisted countries.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "VPN" and IPAddressCountry in ("blacklisted_countries_list") | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

### **6. T1078.004 - Cloud Accounts**

**Objective**: Detect unauthorised access using compromised cloud accounts.

1.  **Monitor Cloud Logins from Unusual Locations**

    _Purpose_: Detect cloud account access from unexpected countries.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and IPAddressCountry != "United States" // Adjust based on your primary country | summarize count() by TargetUserName, IPAddressCountry
```
{% endcode %}

2.  **Detect Multiple Cloud Logins from Different Locations**

    _Purpose_: Identify users logging in from multiple locations in a short period.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" | summarize locations=make_set(IPAddressCountry) by TargetUserName | where array_length(locations) > 1
```
{% endcode %}

3.  **Monitor for Cloud Account Logins During Off-Hours**

    _Purpose_: Detect cloud account logins outside normal working hours.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and (hour(LogonTime) < 6 or hour(LogonTime) > 18) | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

4.  **Identify Failed Cloud Login Attempts**

    _Purpose_: Monitor for failed cloud login attempts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and LogonResult == "Failed" | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

5.  **Detect Use of Cloud Admin Accounts**

    _Purpose_: Identify logins using cloud admin accounts.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and TargetUserName contains "admin" | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

6.  **Monitor for Cloud Account Privilege Escalation**

    _Purpose_: Detect unauthorised privilege escalations in cloud accounts.

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "Add member to role" and AccountType == "Cloud" | project Timestamp, TargetUserName, InitiatingProcessAccountName, RoleName
```
{% endcode %}

7.  **Detect Cloud Account Logins from Unrecognised Devices**

    _Purpose_: Monitor for logins from unrecognised devices.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and DeviceName !in ("known_devices_list") | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

8.  **Monitor for Cloud Account Logins via Unusual Methods**

    _Purpose_: Detect cloud account logins using unusual methods.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and LogonType not in ("Web", "MobileApp") | summarize count() by TargetUserName, LogonType
```
{% endcode %}

9.  **Identify Suspicious Cloud Account Activity**

    _Purpose_: Monitor OAuth2 logins for suspicious activity.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and LogonType == "OAuth2" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

10. **Detect Unauthorised Cloud API Calls**

    _Purpose_: Identify unauthorised API calls made using cloud accounts.

{% code overflow="wrap" %}
```cs
IdentityAPIEvents | where AccountType == "Cloud" and APIType == "Unauthorized" | project Timestamp, TargetUserName, APIEndpoint, ResponseCode
```
{% endcode %}

### **7. T1566 - Phishing**

**Objective**: Detect phishing attempts aimed at gaining unauthorised access to systems or credentials.&#x20;

1.  **Monitor for Emails Containing Suspicious Attachments**

    _Purpose_: Identify emails with suspicious attachments that may be phishing attempts.

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "Invoice" or EmailAttachmentFileName endswith ".exe" or EmailAttachmentFileName endswith ".js" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}

2.  **Detect Emails from Unfamiliar Domains**

    _Purpose_: Monitor for emails originating from unfamiliar domains.

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where SenderDomain not in ("known_domains_list") | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

3.  **Identify Multiple Failed Login Attempts Following Phishing Emails**

    Purpose: Detect multiple failed login attempts after a phishing campaign.

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" | where Timestamp between (startofday(now()) - 1d) and (startofday(now())) | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

4\.  **Monitor for Credential Harvesting Attempts**

_Purpose_: Identify potential credential harvesting attempts.

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and URL contains "login" and ResponseCode == 302 | project Timestamp, RemoteIP, URL
```
{% endcode %}

5.  **Detect Email Links Leading to Malicious Sites**

    _Purpose_: Monitor emails with links that could lead to malicious websites.

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailBody contains "http://" or EmailBody contains "https://" | project Timestamp, EmailSenderAddress, EmailSubject, EmailBody
```
{% endcode %}

6.  **Identify Unusual Email Forwarding Rules**

    _Purpose_: Detect unauthorised email forwarding rules that may indicate a phishing attack.

{% code overflow="wrap" %}
```cs
IdentityEmailEvents | where ActionType == "SetForwardingRule" | project Timestamp, TargetUserName, EmailForwardingRule
```
{% endcode %}

7.  **Monitor for Phishing Emails Spoofing Trusted Domains**

    _Purpose_: Identify phishing emails spoofing trusted domains.

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where SenderDomain == "trusted_domain" and SenderAddress not in ("trusted_emails_list") | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

8.  **Detect Suspicious Email Activity After Clicking Phishing Links**

    _Purpose_: Monitor for suspicious email activity following phishing attempts.

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "Urgent" or EmailBody contains "click here" | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

9.  **Identify Emails Containing Suspicious Macros**

    _Purpose_: Detect emails with attachments containing macros that may be used for phishing.

{% code overflow="wrap" %}
```kusto
DeviceEmailEvents | where EmailAttachmentFileName endswith ".docm" or EmailAttachmentFileName endswith ".xlsm" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}

10. **Monitor for Executable Files Sent via Email**

    _Purpose_: Identify emails containing executable files that could be part of a phishing attack.

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailAttachmentFileName endswith ".exe" or EmailAttachmentFileName endswith ".bat" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}
