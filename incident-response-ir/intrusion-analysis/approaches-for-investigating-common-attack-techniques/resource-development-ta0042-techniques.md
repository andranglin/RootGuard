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

# Resource Development (TA0042) Techniques

Resource Development techniques involve adversaries establishing, maintaining, or expanding resources used for future operations. These resources can include infrastructure, accounts, or tools that enable various stages of an attack.

### <mark style="color:blue;">**1. T1583.001 - Acquire Infrastructure: Domains**</mark>

**Objective**: Detect and investigate attempts to acquire or register domains that could be used for malicious purposes.&#x20;

1. **Detect Access to Domain Registration Sites**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("godaddy.com", "namecheap.com", "domains.google") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to domain registration sites, which could indicate an attempt to acquire a domain for malicious use.

2. **Monitor for DNS Queries to Newly Registered Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where DNSQueryType == "A" and RemoteUrl endswith_any (".xyz", ".top", ".club") // Example TLDs often used in attacks | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect DNS queries to newly registered domains that might be used in future attacks.

3. **Identify Access to Suspicious Domains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl endswith_any (".biz", ".info", ".pw") // Example TLDs often used by attackers | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for access to domains associated with malicious activity.

4. **Detect WHOIS Queries for Domain Information**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "whois" and ProcessCommandLine has_any ("-h", "--host") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of WHOIS queries to gather information about domains, possibly for reconnaissance.

5. **Monitor for Creation of Malicious Subdomains**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "admin" and RemoteUrl contains "dns" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to create subdomains that could be used in phishing or C2 operations.

6. **Identify Domain Name System (DNS) Registration Changes**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "dns" and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DNS registration changes that might indicate the setup of malicious infrastructure.

### <mark style="color:blue;">**2. T1583.002 - Acquire Infrastructure: Server**</mark>

**Objective**: Detect and investigate attempts to acquire or configure servers that could be used for malicious purposes.&#x20;

1. **Detect Access to Cloud Provider Portals**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("aws.amazon.com", "portal.azure.com", "cloud.google.com") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to cloud provider portals, which could indicate an attempt to acquire server infrastructure.

2. **Monitor for Use of Cloud CLI Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("aws", "az", "gcloud") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of cloud command-line interface (CLI) tools to manage cloud resources.

3. **Identify SSH Connections to Unrecognized Servers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 22 and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for SSH connections to external servers that may be part of malicious infrastructure.

4. **Detect File Transfers to External Servers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RequestMethod == "PUT" and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | project Timestamp, DeviceName, RemoteIP, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify file transfers to external servers, possibly for setting up C2 infrastructure.

5. **Monitor for Configuration of External Servers**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("nginx", "apache", "httpd") and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the setup and configuration of web servers on external infrastructure.

6. **Identify Use of VPNs or Proxies to Manage External Servers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("vpn", "proxy") and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") // replace with internal IP ranges | project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for VPN or proxy usage that could be used to anonymously manage malicious servers.

### <mark style="color:blue;">**3. T1584.001 - Compromise Infrastructure: Domains**</mark>

**Objective**: Detect and investigate attempts to compromise or take control of existing domains, often used for phishing or C2 operations.&#x20;

1. **Detect Unusual DNS Changes**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "dns" and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes to DNS settings that might indicate domain compromise.

2. **Monitor for Access to Domain Management Panels**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("myaccount.godaddy.com", "my.freenom.com") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect access to domain management panels that could be used to compromise domains.

3. **Identify WHOIS Lookup Activity for Domain Reconnaissance**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "whois" and ProcessCommandLine has_any ("-h", "--host") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for WHOIS lookups that may be part of reconnaissance efforts for domain compromise.

4. **Detect Changes in Domain Registrant Information**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "registrar" and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify changes in domain registrant information that could indicate compromise.

5. **Monitor for Email Forwarding Rules on Domain Email Accounts**

{% code overflow="wrap" %}
```cs
DeviceEmailEvents | where EmailSubject contains "forwarding" and InitiatingProcessAccountName != "Admin" | project Timestamp, DeviceName, EmailSubject, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the creation of email forwarding rules that could be used to divert communications.

6. **Identify DNS Hijacking Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "dns" and RequestMethod == "PATCH" | project Timestamp, DeviceName, RemoteUrl, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DNS changes that could be part of a DNS hijacking attempt.

### <mark style="color:blue;">**4. T1588.002 - Obtain Capabilities: Tool**</mark>

**Objective**: Detect and investigate attempts to acquire or download tools that could be used for malicious purposes, such as malware, exploit kits, or hacking tools.&#x20;

1. **Detect Downloads from Known Hacking Tool Repositories**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("github.com", "exploit-db.com", "malwarebazaar.com") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify downloads from websites known to host hacking tools or exploits.

2. **Monitor for Installation of Common Hacking Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("mimikatz", "metasploit", "cobalt strike") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the installation or execution of known hacking tools.

3. **Identify Use of `wget` or `curl` to Download Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("wget", "curl") and ProcessCommandLine has ("http", "https") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of command-line tools to download potentially malicious files.

4. **Detect Use of PowerShell to Download Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Invoke-WebRequest", "Invoke-RestMethod") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of PowerShell to download and execute tools from the internet.

5. **Monitor for Use of `certutil` to Download Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "certutil" and ProcessCommandLine has "urlcache" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of `certutil` to download files, which may be used to bypass security controls.

6. **Identify Installation of Toolkits or Exploit Packs**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("install.sh", "setup.exe", "payload.exe") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the installation of toolkits or exploit packs that could be used in attacks.

### <mark style="color:blue;">**5. T1584.002 - Compromise Infrastructure: Server**</mark>

**Objective**: Detect and investigate attempts to compromise existing servers, which can then be used to host malicious content or as part of a botnet.&#x20;

1. **Detect Brute Force Attacks Against SSH**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "Network" and AuthenticationPackage == "NTLM" and LogonResult == "Failed" and TargetPort == 22 | project Timestamp, DeviceName, AccountName, LogonResult, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify failed SSH logon attempts that may indicate brute force attacks on a server.

2. **Monitor for Exploitation of Web Servers**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 80 and RequestMethod == "POST" and RequestSize > 1000 | project Timestamp, DeviceName, RemoteUrl, RequestMethod, RequestSize, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to exploit web servers by monitoring for large or unusual POST requests.

3. **Identify Use of Exploits Against Known Vulnerabilities**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("CVE", "exploit", "payload") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of exploits targeting known vulnerabilities on servers.

4. **Detect Unauthorized SSH Connections**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 22 and Direction == "Inbound" and RemoteIP not in ("192.168.1.0/24", "10.0.0.0/8") | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify unauthorized SSH connections to internal servers.

5. **Monitor for Server Configuration Changes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("nginx.conf", "httpd.conf", "sshd_config") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect changes to server configuration files that could indicate compromise.

6. **Identify Installation of Backdoors on Servers**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("backdoor", "nc -l", "reverse shell") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the installation of backdoors on compromised servers.

### <mark style="color:blue;">**6. T1585.001 - Establish Accounts: Social Media Accounts**</mark>

**Objective**: Detect and investigate the creation or use of social media accounts that could be used for spreading malicious content, phishing, or disinformation. **s**:

1. **Detect Access to Social Media Platforms**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("facebook.com", "twitter.com", "instagram.com") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to social media platforms that could be used for account creation.

2. **Monitor for Use of Automation Tools on Social Media**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("selenium", "puppeteer", "autoit") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of automation tools that could be used to create or manage social media accounts at scale.

3. **Identify Bulk Account Creation Activities**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "signup" and RequestMethod == "POST" | summarize AccountCreationCount = count() by DeviceName, InitiatingProcessAccountName | where AccountCreationCount > 5 | project Timestamp, DeviceName, AccountCreationCount, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for multiple account creation attempts from a single device.

4. **Detect Unusual Social Media Activity from Internal Devices**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains_any ("facebook.com", "twitter.com", "instagram.com") and TimeGenerated between (startofday(ago(1d))) .. (endofday(ago(1d))) | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify unusual social media activity, such as large volumes of posts or interactions.

5. **Monitor for Use of Social Media APIs**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "api" and RemoteUrl contains_any ("facebook", "twitter", "instagram") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of social media APIs that could be used for automated posting or account management.

6. **Identify Use of Proxy Services to Access Social Media**

{% code overflow="wrap" %}
```cs
    DeviceNetworkEvents | where RemoteUrl contains "proxy" and RemoteUrl contains_any ("facebook", "twitter", "instagram") | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for proxy usage to access social media platforms, which could be used to hide the origin of account creation or management activities.
