---
icon: laptop-code
---

# Initial Access (TA0001) Techniques

### <mark style="color:blue;">Introduction</mark>

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

## <mark style="color:blue;">Using KQL to Investigate Initial Access Activities in an Environment Using Defender/Sentinel</mark>

Initial Access is the first stage in the attack lifecycle, where adversaries gain entry into a network.

Note: While there are simpler methods for looking at these kinds of attacks, the goal is to tackle them from a beginner's point of view without utilising intricate KQL queries that a Junior SOC analyst wouldn't find difficult to comprehend.

### <mark style="color:blue;">**1. T1190 - Exploit Public-Facing Application**</mark>

**Objective**: Detect attempts to exploit vulnerabilities in public-facing applications to gain unauthorised access.&#x20;

1. **Detect Unusual HTTP POST Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has "POST" | summarize count() by RemoteIP, LocalIP | where count() > 10
```
{% endcode %}

_Purpose_: Identify suspicious POST requests that might indicate an exploit attempt.

2. **Monitor Web Server Logs for Exploit Patterns**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "IIS\\Logs" or FolderPath has "Apache\\Logs" | where FileName contains ".log" | summarize count() by FileName, DeviceName, FilePath
```
{% endcode %}

_Purpose_: Detect patterns in web server logs that may indicate exploitation.

3. **Detect Suspicious Input in Web Forms**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("<script>", "UNION SELECT", "' OR 1=1") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify attempts at SQL injection or XSS.

4. **Identify Access to Vulnerable Endpoints**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("admin", "login", "upload") | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

_Purpose_: Detect attempts to access known vulnerable endpoints.

5. **Monitor for Known Exploit Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("sqlmap", "metasploit", "dirbuster") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify the use of automated tools to exploit web applications.

6. **Detect Web Shell Uploads**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".aspx" or FileName endswith ".php" | summarize count() by FileName, DeviceName
```
{% endcode %}

_Purpose_: Monitor for the upload of web shells.

7. **Monitor for Suspicious GET Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has "GET" and ProcessCommandLine contains "cmd" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify GET requests that attempt to execute commands.

8. **Detect Suspicious File Uploads**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("uploads", "files", "images") | summarize count() by FileName, DeviceName | where count() > 10
```
{% endcode %}

_Purpose_: Monitor for excessive file uploads.

9. **Monitor for Exploit Attempts via HTTP Headers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 or RemotePort == 443 | where ProcessCommandLine has_any ("User-Agent:", "Referer:") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect exploit attempts via HTTP headers.

10. **Identify Unexpected Application Behavior**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "w3wp.exe" or ProcessCommandLine has "httpd.exe" | where ProcessCommandLine has_any ("cmd.exe", "powershell.exe") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Monitor for web servers executing unexpected processes.

### <mark style="color:blue;">**2. T1078 - Valid Accounts**</mark>

**Objective**: Detect unauthorized access using stolen or compromised credentials.

1. **Detect Logins from Unusual Locations**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "Network" and AccountType == "User" | summarize count() by TargetUserName, IPAddress | where count() > 1
```
{% endcode %}

_Purpose_: Identify logins from unfamiliar IP addresses.

2. **Monitor Logins Outside Business Hours**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Success" and LogonTime between (startofday(now()) - 7d) and (startofday(now()) - 1d) | where hour(LogonTime) < 6 or hour(LogonTime) > 18 | summarize count() by TargetUserName, LogonTime
```
{% endcode %}

_Purpose_: Detect logins occurring outside regular working hours.

3. **Detect Failed Login Attempts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" | summarize count() by TargetUserName, DeviceName | where count() > 5`
```
{% endcode %}

_Purpose_: Identify multiple failed login attempts.

4. **Identify Privileged Account Use**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Privileged" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Monitor the usage of privileged accounts.

5. **Detect Logins from Multiple Geolocations**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | summarize locations=make_set(IPAddressCountry) by TargetUserName | where array_length(locations) > 1
```
{% endcode %}

_Purpose_: Identify users logging in from multiple geolocations in a short period.

6. **Monitor for New Account Creations**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "NewUserCreated" | project Timestamp, TargetUserName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the creation of new accounts.

7. **Detect Account Deletions**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "UserDeleted" | project Timestamp, TargetUserName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for account deletions.

8. **Monitor for Account Privilege Escalation**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "Add member to role" and RoleName == "Global Administrator" | project Timestamp, TargetUserName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect unauthorized privilege escalations.

9. **Detect Suspicious Use of Service Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName has "svc-" or TargetUserName has "service" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Monitor the use of service accounts.

10. **Identify Logins with Disabled Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountEnabled == "False" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Detect login attempts with disabled accounts.

### <mark style="color:blue;">**3. T1195 - Supply Chain Compromise**</mark>

**Objective**: Detect indicators of a supply chain compromise where an adversary infiltrates via a third-party service or software.

1. **Monitor for New or Unknown Software Installations**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("msiexec", "setup.exe", "install.exe") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect installation of software from potentially compromised supply chains.

2. **Identify Changes to Critical System Files**

{% code overflow="wrap" %}
```csharp
DeviceFileEvents | where FolderPath has_any ("C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)") | where FileOperation == "Modify" | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

_Purpose_: Monitor for modifications to critical system files.

3. **Detect Communication with Known Malicious IPs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("known_malicious_ips_list") | project Timestamp, DeviceName, RemoteIP, RemotePort
```
{% endcode %}

_Purpose_: Identify communication with IP addresses known to be associated with supply chain attacks.

4. **Monitor for Unusual Application Behavior**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("cmd.exe", "powershell.exe") and InitiatingProcessFileName != "cmd.exe" and InitiatingProcessFileName != "powershell.exe" | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect unexpected execution of system tools by third-party applications.

5. **Identify Suspicious DLL Loads**

{% code overflow="wrap" %}
```cs
DeviceImageLoadEvents | where FileName endswith ".dll" and FolderPath has_any ("C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)") | project Timestamp, DeviceName, FileName, FolderPath
```
{% endcode %}

_Purpose_: Monitor for DLL loads that may indicate a compromised application.

6. **Detect New or Unknown Network Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where ActionType == "ConnectionSuccess" and RemoteIP !in ("known_good_ips_list") | summarize count() by RemoteIP, LocalIP | where count() > 5
```
{% endcode %}

_Purpose_: Identify new or unknown network connections that could indicate a supply chain attack.

7. **Monitor for Changes to Startup Programs**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```
{% endcode %}

_Purpose_: Detect unauthorized changes to startup programs.

8. **Identify Unauthorized Code Signing**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName endswith ".exe" or FileName endswith ".dll" | where FileOperation == "Modify" and CertificateIssuer !in ("trusted_issuers_list") | project Timestamp, DeviceName, FileName, CertificateIssuer
```
{% endcode %}

_Purpose_: Monitor for unauthorized code signing that could indicate a compromised application.

9. **Detect Changes to System Services**

{% code overflow="wrap" %}
```cs
DeviceServiceEvents | where ActionType == "ServiceInstalled" or ActionType == "ServiceModified" | project Timestamp, DeviceName, ServiceName, InitiatingProcessCommandLine
```
{% endcode %}

_Purpose_: Identify changes to system services that may be linked to a supply chain compromise.

10. **Monitor for Suspicious Scripting Activity**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any (".ps1", ".vbs", ".bat") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Detect the execution of scripts that could be associated with a supply chain attack.

### <mark style="color:blue;">**4. T1199 - Trusted Relationship**</mark>

**Objective**: Detect unauthorized access or activity stemming from a trusted relationship, such as a partner or vendor.

1. **Monitor for Logins from Partner Networks**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where IPAddress in ("partner_ip_range") | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Identify logins originating from partner networks.

2. **Detect Unusual Activity from Trusted Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where TargetUserName in ("trusted_account_list") | summarize count() by TargetUserName, DeviceName, LogonTime | where count() > 5
```
{% endcode %}

_Purpose_: Monitor for unusual activity from accounts associated with trusted relationships.

3. **Identify Access to Critical Systems by Trusted Accounts**

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where TargetUserName in ("trusted_account_list") and DeviceName in ("critical_systems_list") | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Detect access to critical systems by trusted accounts.

4. **Monitor for Changes to Permissions of Trusted Accounts**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where TargetUserName in ("trusted_account_list") and ActionType == "PermissionModified" | project Timestamp, TargetUserName, InitiatingProcessAccountName, PermissionsChanged
```
{% endcode %}

_Purpose_: Detect changes to permissions for trusted accounts.

5. **Detect Unusual File Access by Trusted Accounts**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where InitiatingProcessAccountName in ("trusted_account_list") and FolderPath in ("sensitive_directories_list") | summarize count() by InitiatingProcessAccountName, DeviceName, FolderPath
```
{% endcode %}

_Purpose_: Identify unusual file access by trusted accounts.

6. **Monitor for Network Connections from Trusted Vendors**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("vendor_ip_range") | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

_Purpose_: Detect network connections originating from vendor networks.

7. **Identify Changes to Firewall Rules by Trusted Accounts**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" | where InitiatingProcessAccountName in ("trusted_account_list") | project Timestamp, DeviceName, RegistryKey, RegistryValueName
```
{% endcode %}

_Purpose_: Monitor changes to firewall rules by trusted accounts.

8. **Detect Installation of Software by Trusted Accounts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("install.exe", "setup.exe") and InitiatingProcessAccountName in ("trusted_account_list") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify software installation by trusted accounts.

9. **Monitor for Changes to Network Configurations by Trusted Accounts**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" | where InitiatingProcessAccountName in ("trusted_account_list") | project Timestamp, DeviceName, RegistryKey, RegistryValueName
```
{% endcode %}

_Purpose_: Detect changes to network configurations by trusted accounts.

10. **Identify Unusual Email Activity from Trusted Accounts**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where SenderAddress in ("trusted_email_domains") | summarize count() by SenderAddress, RecipientAddress
```
{% endcode %}

_Purpose_: Monitor for unusual email activity from trusted domains.

### <mark style="color:blue;">**5. T1133 - External Remote Services**</mark>

**Objective**: Detect unauthorized access via external remote services such as VPNs, RDP, or other remote access tools.

1. **Detect RDP Logins from Unfamiliar IPs**

{% code overflow="wrap" %}
```csharp
IdentityLogonEvents | where LogonType == "RemoteInteractive" and IPAddress not in ("known_good_ips") | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Identify RDP logins from unfamiliar IP addresses.

2. **Monitor VPN Connections from Unusual Locations**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and RemoteIP not in ("trusted_ip_ranges") | summarize count() by RemoteIP, LocalIP
```
{% endcode %}

_Purpose_: Detect VPN connections from unusual locations.

3. **Identify SSH Logins from External Sources**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "SSH" and IPAddress not in ("internal_ip_range") | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Monitor SSH logins from external IP addresses.

4. **Monitor for Remote Desktop Gateway Access**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and DeviceName contains "RDGateway" | summarize count() by TargetUserName, DeviceName, IPAddress
```
{% endcode %}

_Purpose_: Identify access to Remote Desktop Gateways.

5. **Detect Multiple Failed Remote Login Attempts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Failed" | summarize count() by TargetUserName, IPAddress | where count() > 5
```
{% endcode %}

_Purpose_: Identify multiple failed remote login attempts.

6. **Monitor for RDP Connections Outside Business Hours**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and (hour(LogonTime) < 6 or hour(LogonTime) > 18) | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Detect RDP connections outside normal working hours.

7. **Detect Use of Remote Access Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("teamviewer.exe", "anydesk.exe", "vncviewer.exe") | project Timestamp, DeviceName, ProcessCommandLine
```
{% endcode %}

_Purpose_: Identify the use of remote access tools.

8. **Identify VPN Logins from Multiple Geolocations**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "VPN" | summarize locations=make_set(IPAddressCountry) by TargetUserName | where array_length(locations) > 1
```
{% endcode %}

_Purpose_: Monitor VPN logins from multiple geolocations.

9. **Monitor for External Access to Administrative Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Privileged" and LogonType == "RemoteInteractive" | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Detect remote access to administrative accounts.

10. **Detect VPN Access from Blacklisted Countries**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "VPN" and IPAddressCountry in ("blacklisted_countries_list") | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Identify VPN access attempts from blacklisted countries.

### <mark style="color:blue;">**6. T1078.004 - Cloud Accounts**</mark>

**Objective**: Detect unauthorized access using compromised cloud accounts.

1. **Monitor Cloud Logins from Unusual Locations**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and IPAddressCountry != "United States" // Adjust based on your primary country | summarize count() by TargetUserName, IPAddressCountry
```
{% endcode %}

_Purpose_: Detect cloud account access from unexpected countries.

2. **Detect Multiple Cloud Logins from Different Locations**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" | summarize locations=make_set(IPAddressCountry) by TargetUserName | where array_length(locations) > 1
```
{% endcode %}

_Purpose_: Identify users logging in from multiple locations in a short period.

3. **Monitor for Cloud Account Logins During Off-Hours**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and (hour(LogonTime) < 6 or hour(LogonTime) > 18) | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Detect cloud account logins outside normal working hours.

4. **Identify Failed Cloud Login Attempts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and LogonResult == "Failed" | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Monitor for failed cloud login attempts.

5. **Detect Use of Cloud Admin Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and TargetUserName contains "admin" | summarize count() by TargetUserName, IPAddress
```
{% endcode %}

_Purpose_: Identify logins using cloud admin accounts.

6. **Monitor for Cloud Account Privilege Escalation**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents | where ActionType == "Add member to role" and AccountType == "Cloud" | project Timestamp, TargetUserName, InitiatingProcessAccountName, RoleName
```
{% endcode %}

_Purpose_: Detect unauthorized privilege escalations in cloud accounts.

7. **Detect Cloud Account Logins from Unrecognized Devices**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and DeviceName !in ("known_devices_list") | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

_Purpose_: Monitor for logins from unrecognized devices.

8. **Monitor for Cloud Account Logins via Unusual Methods**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and LogonType not in ("Web", "MobileApp") | summarize count() by TargetUserName, LogonType
```
{% endcode %}

_Purpose_: Detect cloud account logins using unusual methods.

9. **Identify Suspicious Cloud Account Activity**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountType == "Cloud" and LogonType == "OAuth2" | summarize count() by TargetUserName, DeviceName, LogonTime
```
{% endcode %}

_Purpose_: Monitor OAuth2 logins for suspicious activity.

10. **Detect Unauthorized Cloud API Calls**

{% code overflow="wrap" %}
```cs
IdentityAPIEvents | where AccountType == "Cloud" and APIType == "Unauthorized" | project Timestamp, TargetUserName, APIEndpoint, ResponseCode
```
{% endcode %}

_Purpose_: Identify unauthorized API calls made using cloud accounts.

### <mark style="color:blue;">**7. T1566 - Phishing**</mark>

**Objective**: Detect phishing attempts aimed at gaining unauthorized access to systems or credentials.&#x20;

1. **Monitor for Emails Containing Suspicious Attachments**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "Invoice" or EmailAttachmentFileName endswith ".exe" or EmailAttachmentFileName endswith ".js" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}

_Purpose_: Identify emails with suspicious attachments that may be phishing attempts.

2. **Detect Emails from Unfamiliar Domains**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where SenderDomain not in ("known_domains_list") | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

_Purpose_: Monitor for emails originating from unfamiliar domains.

3. **Identify Multiple Failed Login Attempts Following Phishing Emails**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" | where Timestamp between (startofday(now()) - 1d) and (startofday(now())) | summarize count() by TargetUserName, DeviceName
```
{% endcode %}

{% code overflow="wrap" %}
```csharp
_Purpose_: Detect multiple failed login attempts after a phishing campaign.
```
{% endcode %}

4\. **Monitor for Credential Harvesting Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 443 and URL contains "login" and ResponseCode == 302 | project Timestamp, RemoteIP, URL
```
{% endcode %}

_Purpose_: Identify potential credential harvesting attempts.

1. **Detect Email Links Leading to Malicious Sites**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailBody contains "http://" or EmailBody contains "https://" | project Timestamp, EmailSenderAddress, EmailSubject, EmailBody
```
{% endcode %}

_Purpose_: Monitor emails with links that could lead to malicious websites.

6. **Identify Unusual Email Forwarding Rules**

{% code overflow="wrap" %}
```cs
IdentityEmailEvents | where ActionType == "SetForwardingRule" | project Timestamp, TargetUserName, EmailForwardingRule
```
{% endcode %}

_Purpose_: Detect unauthorized email forwarding rules that may indicate a phishing attack.

7. **Monitor for Phishing Emails Spoofing Trusted Domains**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where SenderDomain == "trusted_domain" and SenderAddress not in ("trusted_emails_list") | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

_Purpose_: Identify phishing emails spoofing trusted domains.

8. **Detect Suspicious Email Activity After Clicking Phishing Links**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "Urgent" or EmailBody contains "click here" | project Timestamp, EmailSenderAddress, EmailSubject
```
{% endcode %}

_Purpose_: Monitor for suspicious email activity following phishing attempts.

9. **Identify Emails Containing Suspicious Macros**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailAttachmentFileName endswith ".docm" or EmailAttachmentFileName endswith ".xlsm" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}

_Purpose_: Detect emails with attachments containing macros that may be used for phishing.

10. **Monitor for Executable Files Sent via Email**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailAttachmentFileName endswith ".exe" or EmailAttachmentFileName endswith ".bat" | project Timestamp, EmailSenderAddress, EmailSubject, EmailAttachmentFileName
```
{% endcode %}

_Purpose_: Identify emails containing executable files that could be part of a phishing attack.
