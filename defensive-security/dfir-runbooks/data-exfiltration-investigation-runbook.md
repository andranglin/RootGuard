# Data Exfiltration Investigation Runbook

## SOC & DFIR Operations Guide

**Environment:** Windows AD | Microsoft 365 | Defender XDR | Sentinel | Entra ID | Palo Alto Prisma Access.

***

## Overview & Scope

This runbook provides standardised procedures for investigating data exfiltration attacks across the hybrid enterprise environment. Data exfiltration is a critical phase in the attack lifecycle where adversaries steal sensitive data from the organisation, often representing the primary objective of sophisticated attacks.

### What is Data Exfiltration?

Data exfiltration (also known as data theft, data extrusion, or data leakage) is the unauthorised transfer of data from an organisation. It can be performed by external threat actors who have compromised the environment or by malicious insiders abusing their legitimate access.

**Key Considerations:**

* Exfiltration is often the final stage before an attack is discovered
* Data theft may occur over extended periods (low and slow)
* Ransomware actors increasingly exfiltrate before encrypting (double extortion)
* Insider threats may use legitimate tools and access
* Cloud services create new exfiltration vectors

### Data at Risk Categories

<table><thead><tr><th width="247">Category</th><th width="381">Examples</th><th>Sensitivity</th></tr></thead><tbody><tr><td><strong>Personally Identifiable Information (PII)</strong></td><td>SSN, addresses, phone numbers, DOB</td><td>High</td></tr><tr><td><strong>Protected Health Information (PHI)</strong></td><td>Medical records, insurance data</td><td>Critical</td></tr><tr><td><strong>Financial Data</strong></td><td>Credit cards, bank accounts, financial reports</td><td>Critical</td></tr><tr><td><strong>Intellectual Property</strong></td><td>Source code, patents, trade secrets, designs</td><td>Critical</td></tr><tr><td><strong>Customer Data</strong></td><td>Customer lists, contracts, communications</td><td>High</td></tr><tr><td><strong>Employee Data</strong></td><td>HR records, salaries, performance reviews</td><td>High</td></tr><tr><td><strong>Authentication Data</strong></td><td>Passwords, keys, certificates, tokens</td><td>Critical</td></tr><tr><td><strong>Strategic Information</strong></td><td>M&#x26;A plans, business strategies, pricing</td><td>High</td></tr><tr><td><strong>Legal/Compliance</strong></td><td>Legal holds, audit data, compliance reports</td><td>High</td></tr></tbody></table>

### Exfiltration Methods

#### By Channel

<table><thead><tr><th width="204">Channel</th><th width="340">Description</th><th>Detection Difficulty</th></tr></thead><tbody><tr><td><strong>Network (Unencrypted)</strong></td><td>HTTP, FTP, SMB to external</td><td>Low</td></tr><tr><td><strong>Network (Encrypted)</strong></td><td>HTTPS, SFTP, encrypted tunnels</td><td>Medium-High</td></tr><tr><td><strong>Email</strong></td><td>Attachments, body content</td><td>Low-Medium</td></tr><tr><td><strong>Cloud Storage</strong></td><td>OneDrive, Dropbox, Google Drive, etc.</td><td>Medium</td></tr><tr><td><strong>Removable Media</strong></td><td>USB drives, external HDD</td><td>Medium</td></tr><tr><td><strong>Physical</strong></td><td>Printed documents, photos of screens</td><td>High</td></tr><tr><td><strong>Covert Channels</strong></td><td>DNS tunneling, steganography, ICMP</td><td>High</td></tr><tr><td><strong>Application-Based</strong></td><td>Messaging apps, file sharing apps</td><td>Medium</td></tr></tbody></table>

#### By Technique

<table><thead><tr><th width="315">Technique</th><th width="276">Description</th><th>MITRE ID</th></tr></thead><tbody><tr><td><strong>Exfiltration Over C2</strong></td><td>Using existing C2 channel</td><td>T1041</td></tr><tr><td><strong>Exfiltration Over Web Service</strong></td><td>Cloud storage, paste sites</td><td>T1567</td></tr><tr><td><strong>Exfiltration Over Alternative Protocol</strong></td><td>DNS, ICMP, non-standard ports</td><td>T1048</td></tr><tr><td><strong>Automated Exfiltration</strong></td><td>Scheduled/triggered data theft</td><td>T1020</td></tr><tr><td><strong>Data Transfer Size Limits</strong></td><td>Chunking to avoid detection</td><td>T1030</td></tr><tr><td><strong>Scheduled Transfer</strong></td><td>Off-hours to avoid detection</td><td>T1029</td></tr><tr><td><strong>Exfiltration Over Physical Medium</strong></td><td>USB, external drives</td><td>T1052</td></tr><tr><td><strong>Exfiltration Over Bluetooth</strong></td><td>Wireless data transfer</td><td>T1011.001</td></tr></tbody></table>

#### By Actor Type

<table><thead><tr><th width="210">Actor</th><th width="263">Motivation</th><th>Typical Methods</th></tr></thead><tbody><tr><td><strong>External Threat Actor</strong></td><td>Espionage, extortion, sale</td><td>C2, cloud upload, encrypted</td></tr><tr><td><strong>Ransomware Operator</strong></td><td>Double extortion leverage</td><td>Bulk transfer, cloud upload</td></tr><tr><td><strong>Nation-State</strong></td><td>Intelligence gathering</td><td>Low and slow, covert channels</td></tr><tr><td><strong>Malicious Insider</strong></td><td>Financial gain, revenge</td><td>Email, USB, cloud sync</td></tr><tr><td><strong>Negligent Insider</strong></td><td>Convenience, lack of awareness</td><td>Email, personal cloud</td></tr><tr><td><strong>Departing Employee</strong></td><td>Taking work, competitive advantage</td><td>USB, personal email, cloud</td></tr></tbody></table>

### Data Exfiltration Lifecycle

```bash
1. Target Identification
   └── Identify valuable data locations, access methods

2. Access & Collection
   ├── Access file shares, databases, cloud storage
   ├── Search for sensitive content
   └── Stage data for exfiltration

3. Preparation
   ├── Compress/archive data
   ├── Encrypt to avoid DLP
   └── Split into smaller chunks

4. Exfiltration
   ├── Transfer via chosen channel
   ├── May occur over extended period
   └── Often during off-hours

5. Covering Tracks
   ├── Delete staging files
   ├── Clear logs
   └── Remove access artifacts
```

***

## Detection Sources & Data Mapping

### Log Sources Matrix

<table><thead><tr><th width="221">Platform</th><th>Log Table</th><th>Exfiltration-Relevant Data</th></tr></thead><tbody><tr><td>Defender for Endpoint</td><td><code>DeviceFileEvents</code></td><td>File access, copy, archive creation</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceNetworkEvents</code></td><td>Outbound transfers, DNS queries</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceEvents</code></td><td>USB activity, Bluetooth, print</td></tr><tr><td>Defender for Endpoint</td><td><code>DeviceProcessEvents</code></td><td>Compression tools, exfil utilities</td></tr><tr><td>Cloud Apps</td><td><code>CloudAppEvents</code></td><td>Cloud storage uploads, sharing</td></tr><tr><td>Exchange Online</td><td><code>EmailEvents</code>, <code>EmailAttachmentInfo</code></td><td>Email with attachments</td></tr><tr><td>SharePoint/OneDrive</td><td><code>OfficeActivity</code></td><td>Downloads, sharing, sync</td></tr><tr><td>Purview</td><td><code>DlpAll</code></td><td>DLP policy matches</td></tr><tr><td>Purview</td><td><code>InsiderRiskManagement</code></td><td>Insider risk alerts</td></tr><tr><td>Sentinel</td><td><code>AzureActivity</code></td><td>Azure resource data access</td></tr><tr><td>Sentinel</td><td><code>ThreatIntelligenceIndicator</code></td><td>Known exfil infrastructure</td></tr><tr><td>Prisma Access</td><td><code>PaloAltoPrismaAccess</code></td><td>Network transfers, URL categories</td></tr><tr><td>Entra ID</td><td><code>SigninLogs</code>, <code>AuditLogs</code></td><td>Application access patterns</td></tr></tbody></table>

### Critical Event Categories

#### File Operations

| Event Type                       | Description                  | Risk Indicator                  |
| -------------------------------- | ---------------------------- | ------------------------------- |
| **Mass file access**             | Bulk file opens/reads        | High volume in short time       |
| **Archive creation**             | ZIP, RAR, 7z creation        | Large archives, sensitive paths |
| **File copy to removable**       | Copy to USB/external         | Any sensitive data              |
| **File rename/extension change** | Disguising files             | Hiding data type                |
| **Sensitive file access**        | Labeled/classified files     | Unusual accessor or volume      |
| **File download from cloud**     | SharePoint/OneDrive download | Bulk downloads                  |

#### Network Activity

| Event Type                    | Description              | Risk Indicator                 |
| ----------------------------- | ------------------------ | ------------------------------ |
| **Large outbound transfers**  | High upload volume       | Unusual destination            |
| **Transfers to file sharing** | Cloud storage uploads    | Personal accounts              |
| **DNS tunneling**             | Data in DNS queries      | High volume, long queries      |
| **Non-standard ports**        | Data on unusual ports    | Encrypted traffic on odd ports |
| **Known bad destinations**    | C2, paste sites          | Threat intel matches           |
| **After-hours transfers**     | Off-peak large transfers | Unusual for user               |

#### Email Activity

| Event Type                  | Description              | Risk Indicator           |
| --------------------------- | ------------------------ | ------------------------ |
| **Large attachments**       | Files over threshold     | Unusual for sender       |
| **Sensitive attachments**   | Labeled files attached   | External recipients      |
| **Personal email forwards** | Forwarding to personal   | Any corporate data       |
| **Bulk email to external**  | Many external recipients | Data in body/attachments |
| **Encrypted attachments**   | Password-protected files | Avoiding DLP             |

#### Cloud Activity

| Event Type                  | Description               | Risk Indicator        |
| --------------------------- | ------------------------- | --------------------- |
| **External sharing**        | Sharing with outside org  | Sensitive content     |
| **Anonymous links**         | Anyone with link access   | Sensitive files       |
| **Sync to personal device** | OneDrive/SharePoint sync  | Unmanaged devices     |
| **Third-party app access**  | OAuth apps accessing data | Excessive permissions |
| **Bulk downloads**          | Mass file downloads       | Unusual volume        |

### Windows Event IDs

<table><thead><tr><th width="144">Event ID</th><th width="142">Log</th><th>Description</th><th>Relevance</th></tr></thead><tbody><tr><td><strong>4663</strong></td><td>Security</td><td>Object access attempt</td><td>File access tracking</td></tr><tr><td><strong>4656</strong></td><td>Security</td><td>Handle to object requested</td><td>File access audit</td></tr><tr><td><strong>4658</strong></td><td>Security</td><td>Handle closed</td><td>File operation complete</td></tr><tr><td><strong>4660</strong></td><td>Security</td><td>Object deleted</td><td>Evidence destruction</td></tr><tr><td><strong>4670</strong></td><td>Security</td><td>Permissions changed</td><td>Access modification</td></tr><tr><td><strong>5140</strong></td><td>Security</td><td>Network share accessed</td><td>Share enumeration</td></tr><tr><td><strong>5145</strong></td><td>Security</td><td>Share object access check</td><td>File share access</td></tr><tr><td><strong>6416</strong></td><td>Security</td><td>External device recognized</td><td>USB detection</td></tr><tr><td><strong>4688</strong></td><td>Security</td><td>Process creation</td><td>Archive tools</td></tr><tr><td><strong>307</strong></td><td>PrintService</td><td>Document printed</td><td>Print exfiltration</td></tr></tbody></table>

***

## Investigation Workflows

### General Data Exfiltration Investigation

**Objective:** Identify, scope, and contain data exfiltration, determine what data was stolen, and assess impact.

#### Step 1: Initial Triage

1. Identify the alert source (DLP, UEBA, network, endpoint)
2. Determine the user/account involved
3. Identify the data type/sensitivity flagged
4. Check for related alerts or incidents
5. Assess initial scope and urgency

#### Step 2: User Context Analysis

1. Review user's role and normal data access
2. Check employment status (departing, notice period)
3. Review recent HR flags or performance issues
4. Identify if user has legitimate business need
5. Check for prior security incidents

#### Step 3: Activity Timeline Construction

1. Query all data access for user (7-30 days)
2. Identify anomalous access patterns
3. Document file types and sensitivity
4. Map access to exfiltration attempts
5. Correlate with authentication events

#### Step 4: Exfiltration Channel Identification

1. Review network connections and transfers
2. Check email for attachments/forwards
3. Review cloud storage activity
4. Check for removable media usage
5. Review print activity

#### Step 5: Data Impact Assessment

1. Identify all data potentially exfiltrated
2. Classify data by sensitivity level
3. Determine regulatory implications (PII, PHI, PCI)
4. Assess business impact
5. Document for legal/compliance

#### Step 6: Scope Expansion

1. Check for similar activity by other users
2. Search for data on known bad destinations
3. Review shared infrastructure/access
4. Check for accomplices or shared accounts
5. Assess if part of larger compromise

***

### Cloud Storage Exfiltration Investigation

**Objective:** Investigate data theft via cloud storage services (OneDrive, SharePoint, Dropbox, Google Drive, etc.).

#### Detection Indicators

* Large volume file downloads from SharePoint/OneDrive
* Syncing to unmanaged/personal devices
* External sharing of sensitive files
* Anonymous link creation for sensitive content
* Personal cloud storage app usage
* Bulk downloads before account changes

#### Investigation Steps

1. **Identify Cloud Activity**
   * Query CloudAppEvents for upload/download activity
   * Check OfficeActivity for SharePoint/OneDrive operations
   * Review Shadow IT usage via MDCA
   * Identify personal vs. corporate accounts
2. **Analyse Access Patterns**
   * Compare to baseline access behaviour
   * Check for bulk operations
   * Identify accessed file sensitivity
   * Review timing (off-hours, last day)
3. **External Sharing Review**
   * List all external shares by user
   * Check for anonymous links created
   * Review share recipients
   * Identify sensitive content shared
4. **Sync Activity Analysis**
   * Check for OneDrive sync to personal devices
   * Review device registration status
   * Identify unmanaged device syncs
   * Check for selective sync of sensitive folders
5. **Third-Party Cloud Apps**
   * Review OAuth app authorisations
   * Check for data access by apps
   * Identify personal cloud storage apps
   * Review MDCA sanctioned/unsanctioned apps

***

### Email-Based Exfiltration Investigation

**Objective:** Investigate data theft via email attachments or body content.

#### Detection Indicators

* Emails with large attachments to external recipients
* Sensitive files attached to personal email
* Password-protected attachments (DLP bypass)
* Bulk email to external addresses
* Auto-forward rules to external addresses
* Email to known personal accounts

#### Investigation Steps

1. **Email Pattern Analysis**
   * Query EmailEvents for external sends
   * Review attachment sizes and types
   * Check for DLP policy matches
   * Identify unusual recipients
2. **Attachment Analysis**
   * Review EmailAttachmentInfo for details
   * Check file types and names
   * Identify sensitive content indicators
   * Review if encrypted/password-protected
3. **Forwarding Rules Review**
   * Check for inbox rules forwarding externally
   * Review mailbox forwarding configuration
   * Identify delegates with forward permissions
   * Check mobile device forwarding
4. **Recipient Analysis**
   * Categorise recipients (personal, competitor, unknown)
   * Check for first-time recipients
   * Review recipient domains
   * Identify patterns in recipients

***

### Endpoint-Based Exfiltration Investigation

**Objective:** Investigate data theft via endpoint methods (USB, Bluetooth, print, local storage).

#### Detection Indicators

* USB device connections
* Large file copies to removable media
* Bluetooth file transfers
* Mass printing activity
* Archive creation with sensitive files
* Airdrop or similar local transfers

#### Investigation Steps

1. **Removable Media Analysis**
   * Query DeviceEvents for USB connections
   * Identify device types and serial numbers
   * Review files copied to devices
   * Check for encrypted transfers
2. **Archive/Compression Activity**
   * Query for ZIP, RAR, 7z creation
   * Review archive contents if available
   * Check source directories
   * Identify password protection
3. **Print Activity**
   * Query print logs for document printing
   * Identify sensitive documents printed
   * Review print volume anomalies
   * Check print-to-file activity
4. **Local Transfer Methods**
   * Check for Bluetooth transfers
   * Review network sharing activity
   * Check for Airdrop (if applicable)
   * Review cloud sync client activity

***

### Network-Based Exfiltration Investigation

**Objective:** Investigate data theft via network channels, including C2, web uploads, and covert channels.

#### Detection Indicators

* Large outbound data transfers
* Transfers to unknown or suspicious IPs
* Non-standard port usage
* DNS tunnelling patterns
* ICMP data transfer
* Encrypted traffic to unusual destinations

#### Investigation Steps

1. **Traffic Volume Analysis**
   * Query DeviceNetworkEvents for large transfers
   * Identify top talkers (bytes out)
   * Compare to baseline network usage
   * Check for sustained vs. burst transfers
2. **Destination Analysis**
   * Review destination IPs and domains
   * Check threat intelligence for IOCs
   * Identify known file sharing sites
   * Review geographic anomalies
3. **Protocol Analysis**
   * Check for non-standard ports
   * Review encrypted traffic destinations
   * Identify potential tunnelling (DNS, ICMP)
   * Check for C2 pattern indicators
4. **Prisma Access Analysis**
   * Review URL filtering logs
   * Check for file sharing categories
   * Identify blocked upload attempts
   * Review data transfer by application

***

### Insider Threat Investigation

**Objective:** Investigate potential malicious insider data theft with sensitivity to HR and legal requirements.

#### Pre-Investigation Considerations

> ⚠️ **Important:** Insider threat investigations are sensitive. Before proceeding:
>
> * Coordinate with HR and Legal
> * Follow established insider threat procedures
> * Maintain confidentiality
> * Document chain of custody
> * Consider union/works council requirements

#### Risk Indicators

| Indicator                  | Category   | Weight     |
| -------------------------- | ---------- | ---------- |
| Resignation submitted      | Employment | High       |
| Performance issues         | HR         | Medium     |
| Passed over for promotion  | HR         | Medium     |
| Working unusual hours      | Behavioral | Low-Medium |
| Excessive data access      | Technical  | High       |
| USB usage increase         | Technical  | Medium     |
| Email to personal accounts | Technical  | High       |
| Accessing unrelated data   | Technical  | High       |

#### Investigation Steps

1. **Context Gathering**
   * Coordinate with HR on employment status
   * Review role and normal data access needs
   * Check for known grievances or issues
   * Identify access to sensitive data
2. **Behavioral Analysis**
   * Compare recent activity to baseline
   * Identify access pattern changes
   * Review login times and locations
   * Check for policy violations
3. **Data Access Review**
   * Query all file access (extended timeline)
   * Identify access outside normal scope
   * Review search queries if available
   * Check for bulk download patterns
4. **Exfiltration Channel Review**
   * Check all potential exfil channels
   * Review email to personal addresses
   * Check USB and removable media
   * Review cloud storage activity
   * Check print logs
5. **Evidence Preservation**
   * Preserve logs with timestamps
   * Document findings thoroughly
   * Maintain chain of custody
   * Prepare for potential legal action

***

## KQL Query Cheat Sheet

### File Access Analysis

#### Mass File Access Detection

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileRead", "FileOpen", "FileCopied")
| summarize 
    FileCount = count(),
    UniqueFiles = dcount(FileName),
    UniqueFolders = dcount(FolderPath),
    SensitiveFiles = countif(FolderPath has_any ("confidential", "secret", "hr", "finance", "legal"))
    by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1h)
| where FileCount > 100 or SensitiveFiles > 10
| sort by FileCount desc
```
{% endcode %}

#### Sensitive File Access by Unusual Users

{% code overflow="wrap" %}
```kusto
let sensitiveLocations = dynamic(["\\HR\\", "\\Finance\\", "\\Legal\\", "\\Executive\\", "\\Confidential\\", "\\Secret\\"]);
let baseline = DeviceFileEvents
| where Timestamp between (ago(30d) .. ago(1d))
| where FolderPath has_any (sensitiveLocations)
| summarize by InitiatingProcessAccountName, FolderPath;
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has_any (sensitiveLocations)
| join kind=leftanti baseline on InitiatingProcessAccountName, FolderPath
| summarize 
    AccessCount = count(),
    Files = make_set(FileName, 20),
    Folders = make_set(FolderPath, 10)
    by InitiatingProcessAccountName, DeviceName
| sort by AccessCount desc
```
{% endcode %}

#### Archive Creation with Sensitive Files

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| extend FileSizeMB = FileSize / 1048576.0
| where FileSizeMB > 50  // Large archives
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FileSizeMB, FolderPath
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("7z.exe", "winrar.exe", "winzip.exe", "powershell.exe", "tar.exe")
    | where ProcessCommandLine has_any (".zip", ".rar", ".7z", "Compress-Archive")
    | project ArchiveTime = Timestamp, DeviceName, ArchiveCommand = ProcessCommandLine
) on DeviceName
| where abs(datetime_diff('minute', Timestamp, ArchiveTime)) < 5
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FileSizeMB, ArchiveCommand
```
{% endcode %}

#### File Copy to External Paths

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated", "FileModified", "FileCopied")
| where FolderPath matches regex @"^[A-Z]:\\" and FolderPath !startswith "C:\\"  // Non-C: drives
    or FolderPath startswith "\\\\"  // Network paths
    or FolderPath has_any ("usb", "removable", "external")
| summarize 
    CopyCount = count(),
    TotalSizeMB = sum(FileSize) / 1048576.0,
    Files = make_set(FileName, 20)
    by DeviceName, InitiatingProcessAccountName, FolderPath
| where CopyCount > 10 or TotalSizeMB > 100
| sort by TotalSizeMB desc
```
{% endcode %}

***

### USB/Removable Media Detection

#### USB Device Connections

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PnpDeviceConnected"
| extend DeviceDescription = tostring(parse_json(AdditionalFields).DeviceDescription)
| extend DeviceId = tostring(parse_json(AdditionalFields).DeviceId)
| where DeviceDescription has_any ("USB", "Mass Storage", "Removable")
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceDescription, 10)
    by DeviceName, InitiatingProcessAccountName
| sort by ConnectionCount desc
```

#### Files Written to Removable Media

```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath matches regex @"^[D-Z]:\\"  // Non-C: drives (potential USB)
| where FolderPath !has "Program Files" and FolderPath !has "Windows"
| summarize 
    FileCount = count(),
    TotalSizeMB = sum(FileSize) / 1048576.0,
    FileTypes = make_set(tostring(split(FileName, ".")[-1]), 20)
    by DeviceName, InitiatingProcessAccountName, FolderPath
| where FileCount > 20 or TotalSizeMB > 100
| sort by TotalSizeMB desc
```

***

### Cloud Storage Exfiltration

#### SharePoint/OneDrive Download Activity

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize 
    DownloadCount = count(),
    UniqueFiles = dcount(ObjectName),
    TotalSize = sum(toint(RawEventData.FileSizeBytes)) / 1048576.0
    by AccountDisplayName, AccountObjectId, bin(Timestamp, 1d)
| where DownloadCount > 100 or TotalSize > 500
| sort by DownloadCount desc
```
{% endcode %}

#### External Sharing Detection

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("SharingSet", "AddedToSecureLink", "AnonymousLinkCreated", "SharingInvitationCreated")
| extend SharedWith = tostring(parse_json(RawEventData).TargetUserOrGroupName)
| extend FileName = tostring(ObjectName)
| where SharedWith !endswith "yourdomain.com" or isempty(SharedWith)
| project Timestamp, AccountDisplayName, ActionType, FileName, SharedWith, FolderPath = tostring(parse_json(RawEventData).ObjectId)
| sort by Timestamp desc
```
{% endcode %}

#### Anonymous Link Creation

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType == "AnonymousLinkCreated"
| extend FileName = tostring(ObjectName)
| extend LinkScope = tostring(parse_json(RawEventData).EventData)
| project Timestamp, AccountDisplayName, FileName, LinkScope, IPAddress
| sort by Timestamp desc
```
{% endcode %}

#### Third-Party Cloud Storage Usage

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Dropbox", "Google Drive", "Box", "WeTransfer", "iCloud", "pCloud")
| where ActionType has_any ("upload", "create", "share")
| summarize 
    ActivityCount = count(),
    Actions = make_set(ActionType, 10),
    Files = make_set(ObjectName, 20)
    by AccountDisplayName, Application, bin(Timestamp, 1d)
| sort by ActivityCount desc
```
{% endcode %}

***

### Email Exfiltration Detection

#### Large Attachments to External Recipients

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Outbound"
| where RecipientEmailAddress !endswith "yourdomain.com"
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp > ago(7d)
    | where FileSize > 5000000  // > 5MB
) on NetworkMessageId
| summarize 
    EmailCount = count(),
    TotalAttachmentSizeMB = sum(FileSize) / 1048576.0,
    Recipients = make_set(RecipientEmailAddress, 20),
    Attachments = make_set(FileName, 20)
    by SenderFromAddress, bin(Timestamp, 1d)
| where TotalAttachmentSizeMB > 50
| sort by TotalAttachmentSizeMB desc
```

#### Emails to Personal Domains

{% code overflow="wrap" %}
```kusto
let personalDomains = dynamic(["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "protonmail.com", "mail.com"]);
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Outbound"
| extend RecipientDomain = tostring(split(RecipientEmailAddress, "@")[1])
| where RecipientDomain in (personalDomains)
| join kind=leftouter EmailAttachmentInfo on NetworkMessageId
| summarize 
    EmailCount = count(),
    WithAttachments = countif(isnotempty(FileName)),
    TotalSizeMB = sum(FileSize) / 1048576.0,
    Recipients = make_set(RecipientEmailAddress, 10)
    by SenderFromAddress
| where EmailCount > 10 or WithAttachments > 5
| sort by WithAttachments desc
```
{% endcode %}

#### Password-Protected Attachments (DLP Bypass)

{% code overflow="wrap" %}
```kusto
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(7d)
    | where EmailDirection == "Outbound"
    | where RecipientEmailAddress !endswith "yourdomain.com"
) on NetworkMessageId
| where FileType == "zip" or tostring(ThreatTypes) has "encrypted"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileSize
| sort by Timestamp desc
```
{% endcode %}

***

### Network Exfiltration Detection

#### Large Outbound Transfers

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where LocalIP startswith "10." or LocalIP startswith "192.168." or LocalIP startswith "172."
| summarize 
    TotalBytesSent = sum(SentBytes),
    TotalBytesReceived = sum(ReceivedBytes),
    ConnectionCount = count(),
    UniqueDestinations = dcount(RemoteIP),
    TopDestinations = make_set(RemoteIP, 10)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| extend SentMB = TotalBytesSent / 1048576.0
| where SentMB > 100
| sort by SentMB desc
```
{% endcode %}

#### Transfers to File Sharing Sites

```kusto
let fileSharingSites = dynamic([
    "dropbox.com", "drive.google.com", "wetransfer.com", "sendspace.com",
    "mediafire.com", "mega.nz", "box.com", "pcloud.com", "sync.com",
    "file.io", "gofile.io", "anonfiles.com", "transfer.sh"
]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (fileSharingSites)
| summarize 
    Connections = count(),
    TotalBytesSent = sum(SentBytes),
    Sites = make_set(RemoteUrl, 10)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| extend SentMB = TotalBytesSent / 1048576.0
| where SentMB > 10
| sort by SentMB desc
```

#### DNS Tunnelling Detection

```kusto
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "DnsQueryResponse"
| extend QueryLength = strlen(RemoteUrl)
| extend Labels = countof(RemoteUrl, ".")
| where QueryLength > 50 or Labels > 5
| summarize 
    QueryCount = count(),
    AvgQueryLength = avg(QueryLength),
    MaxQueryLength = max(QueryLength),
    UniqueDomains = dcount(RemoteUrl)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where QueryCount > 100 or AvgQueryLength > 50
| sort by QueryCount desc
```

#### After-Hours Large Transfers

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| extend Hour = hourofday(Timestamp)
| extend DayOfWeek = dayofweek(Timestamp)
| where Hour < 6 or Hour > 22 or DayOfWeek in (0d, 6d)
| summarize 
    TotalBytesSent = sum(SentBytes),
    Connections = count(),
    Destinations = make_set(RemoteIP, 10)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| extend SentMB = TotalBytesSent / 1048576.0
| where SentMB > 50
| sort by SentMB desc
```

***

### Staging & Preparation Detection

#### Data Staging Directory Detection

{% code overflow="wrap" %}
```kusto
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileCopied")
| where FolderPath has_any ("\\temp\\", "\\tmp\\", "\\staging\\", "\\export\\", "\\backup\\", "\\extract\\")
    or FolderPath matches regex @"C:\\Users\\[^\\]+\\Desktop\\[^\\]+"
| summarize 
    FileCount = count(),
    TotalSizeMB = sum(FileSize) / 1048576.0,
    FileTypes = make_set(tostring(split(FileName, ".")[-1]), 10),
    UniqueFiles = dcount(FileName)
    by DeviceName, InitiatingProcessAccountName, FolderPath
| where FileCount > 50 or TotalSizeMB > 100
| sort by TotalSizeMB desc
```
{% endcode %}

#### Compression Tool Usage

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("7z.exe", "7za.exe", "winrar.exe", "rar.exe", "winzip.exe", "zip.exe", "tar.exe")
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Compress-Archive", "ZipFile", "[System.IO.Compression"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
```
{% endcode %}

#### Database Export Tools

{% code overflow="wrap" %}
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sqlcmd.exe", "bcp.exe", "mysqldump.exe", "pg_dump.exe", "mongodump.exe", "exp.exe")
    or ProcessCommandLine has_any ("SELECT * FROM", "BULK INSERT", "INTO OUTFILE", "COPY TO")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
```
{% endcode %}

***

### DLP & Purview Alerts

#### DLP Policy Matches

```kusto
// If using Microsoft Purview DLP
// This query structure depends on your DLP log ingestion
DlpAll
| where Timestamp > ago(7d)
| where PolicyName != ""
| summarize 
    MatchCount = count(),
    Policies = make_set(PolicyName, 10),
    Locations = make_set(Location, 10)
    by User, bin(Timestamp, 1d)
| where MatchCount > 5
| sort by MatchCount desc
```

#### Insider Risk Alerts

{% code overflow="wrap" %}
```kusto
// If using Microsoft Purview Insider Risk Management
SecurityAlert
| where TimeGenerated > ago(7d)
| where ProviderName == "Insider Risk Management"
| project TimeGenerated, AlertName, Description, UserPrincipalName = tostring(Entities[0].Name), Severity
| sort by TimeGenerated desc
```
{% endcode %}

***

### User Behaviour Analysis

#### User Data Access Baseline Comparison

{% code overflow="wrap" %}
```kusto
// Establish baseline
let baseline = CloudAppEvents
| where Timestamp between (ago(30d) .. ago(7d))
| where ActionType in ("FileDownloaded", "FileUploaded", "FileShared")
| summarize 
    BaselineAvgDaily = count() / 23.0  // 23 days of data
    by AccountDisplayName;
// Compare recent activity
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileDownloaded", "FileUploaded", "FileShared")
| summarize 
    RecentAvgDaily = count() / 7.0
    by AccountDisplayName
| join kind=inner baseline on AccountDisplayName
| extend Deviation = (RecentAvgDaily - BaselineAvgDaily) / BaselineAvgDaily * 100
| where Deviation > 200  // More than 200% increase
| project AccountDisplayName, BaselineAvgDaily, RecentAvgDaily, DeviationPercent = round(Deviation, 2)
| sort by DeviationPercent desc
```
{% endcode %}

#### Departing Employee Monitoring

{% code overflow="wrap" %}
```kusto
// Assuming you have a list of departing employees
let departingUsers = dynamic(["user1@domain.com", "user2@domain.com"]);
union
    (CloudAppEvents
    | where Timestamp > ago(7d)
    | where AccountDisplayName in (departingUsers)
    | where ActionType in ("FileDownloaded", "FileUploaded", "FileShared", "FileCopied")
    | project Timestamp, User = AccountDisplayName, Activity = ActionType, Details = tostring(ObjectName), Source = "CloudApp"),
    (DeviceFileEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessAccountName in (departingUsers)
    | where ActionType in ("FileCreated", "FileCopied", "FileModified")
    | project Timestamp, User = InitiatingProcessAccountName, Activity = ActionType, Details = FileName, Source = "Endpoint"),
    (EmailEvents
    | where Timestamp > ago(7d)
    | where SenderFromAddress in (departingUsers)
    | where EmailDirection == "Outbound"
    | project Timestamp, User = SenderFromAddress, Activity = "EmailSent", Details = Subject, Source = "Email")
| sort by Timestamp desc
```
{% endcode %}

***

### Print Activity Detection

#### Mass Printing Detection

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PrintJobEvent"
| extend DocumentName = tostring(parse_json(AdditionalFields).DocumentName)
| extend PrinterName = tostring(parse_json(AdditionalFields).PrinterName)
| extend PageCount = toint(parse_json(AdditionalFields).PageCount)
| summarize 
    PrintJobs = count(),
    TotalPages = sum(PageCount),
    UniqueDocuments = dcount(DocumentName),
    Printers = make_set(PrinterName, 5)
    by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1d)
| where TotalPages > 100 or UniqueDocuments > 20
| sort by TotalPages desc
```

#### Sensitive Document Printing

{% code overflow="wrap" %}
```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "PrintJobEvent"
| extend DocumentName = tostring(parse_json(AdditionalFields).DocumentName)
| where DocumentName has_any ("confidential", "secret", "restricted", "sensitive", "proprietary", "internal only")
| extend PrinterName = tostring(parse_json(AdditionalFields).PrinterName)
| project Timestamp, DeviceName, InitiatingProcessAccountName, DocumentName, PrinterName
| sort by Timestamp desc
```
{% endcode %}

***

## Response Actions & Remediation

### Immediate Containment Actions

| Scenario                         | Action                             | Method                   |
| -------------------------------- | ---------------------------------- | ------------------------ |
| **Active Exfiltration Detected** | Block network access               | Prisma Access / Firewall |
| **Insider Threat Confirmed**     | Disable account                    | Entra ID + AD            |
| **USB Exfiltration**             | Block USB ports                    | MDE device policy        |
| **Cloud Sharing Active**         | Revoke sharing permissions         | SharePoint Admin         |
| **Email Exfiltration**           | Block outbound email               | Exchange transport rule  |
| **Compromised Account**          | Reset credentials, revoke sessions | Entra ID                 |
| **Malware-Based Exfil**          | Isolate endpoint                   | MDE device isolation     |

### Account Containment

```powershell
# Disable Entra ID account
Update-MgUser -UserId "user@domain.com" -AccountEnabled:$false

# Revoke all sessions
Revoke-MgUserSignInSession -UserId "user@domain.com"

# Block sign-in (Conditional Access)
# Create CA policy blocking specific user

# Disable on-premises AD account
Disable-ADAccount -Identity "username"
```

### Data Access Revocation

{% code overflow="wrap" %}
```powershell
# Connect to SharePoint Online
Connect-SPOService -Url https://yourtenant-admin.sharepoint.com

# Remove all sharing for a specific file/folder
# (Requires specific file/site context)

# Revoke anonymous links
# Via SharePoint Admin Center or PowerShell

# Remove external sharing for user's OneDrive
Set-SPOSite -Identity "https://yourtenant-my.sharepoint.com/personal/user_domain_com" -SharingCapability Disabled
```
{% endcode %}

### Email Containment

{% code overflow="wrap" %}
```powershell
# Block user from sending email
Set-Mailbox -Identity "user@domain.com" -MessageCopyForSentAsEnabled $false
Set-TransportRule -Name "Block User Outbound" -From "user@domain.com" -DeleteMessage $true

# Remove forwarding
Set-Mailbox -Identity "user@domain.com" -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false

# Remove inbox rules
Get-InboxRule -Mailbox "user@domain.com" | Remove-InboxRule -Confirm:$false
```
{% endcode %}

### Endpoint Containment

```powershell
# Block USB via Intune/MDE
# Configure Device Control policies in MDE

# Isolate device via MDE
# Via Security Center portal or API

# Block network access
# Via Prisma Access / Firewall rules
```

### Evidence Preservation

#### Critical Evidence to Preserve

<table><thead><tr><th width="219">Evidence Type</th><th>Source</th><th>Retention</th></tr></thead><tbody><tr><td><strong>File access logs</strong></td><td>MDE, SharePoint, OneDrive</td><td>Export immediately</td></tr><tr><td><strong>Network logs</strong></td><td>Prisma Access, MDE</td><td>Export immediately</td></tr><tr><td><strong>Email logs</strong></td><td>Exchange, MDO</td><td>Export/hold</td></tr><tr><td><strong>Sign-in logs</strong></td><td>Entra ID</td><td>Export immediately</td></tr><tr><td><strong>Audit logs</strong></td><td>Unified Audit Log</td><td>Export immediately</td></tr><tr><td><strong>Endpoint forensics</strong></td><td>MDE Live Response</td><td>Collect if needed</td></tr><tr><td><strong>DLP alerts</strong></td><td>Purview</td><td>Document</td></tr></tbody></table>

#### Evidence Collection Script

{% code overflow="wrap" %}
```powershell
# Create evidence directory
$evidencePath = "C:\IR_Exfil_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidencePath -Force

# Export Unified Audit Log
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date
$userId = "suspect@domain.com"

Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -UserIds $userId -ResultSize 5000 |
    Export-Csv "$evidencePath\UnifiedAuditLog.csv" -NoTypeInformation

# Export sign-in logs (via Graph)
$signIns = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$userId'" -Top 1000
$signIns | Export-Csv "$evidencePath\SignInLogs.csv" -NoTypeInformation

# Export mailbox audit log
Search-MailboxAuditLog -Identity $userId -StartDate $startDate -EndDate $endDate -ShowDetails |
    Export-Csv "$evidencePath\MailboxAuditLog.csv" -NoTypeInformation

# Compress evidence
Compress-Archive -Path $evidencePath -DestinationPath "$evidencePath.zip" -Force

Write-Host "Evidence collected to: $evidencePath.zip"
```
{% endcode %}

***

## Quick Reference Cards

### Exfiltration Indicator Checklist

#### File Activity Red Flags

* \[ ] Mass file access (>100 files/hour)
* \[ ] Access to files outside normal scope
* \[ ] Archive creation (ZIP, RAR, 7z)
* \[ ] Large archives (>100MB)
* \[ ] File access during off-hours
* \[ ] Access spike before leaving
* \[ ] Renamed file extensions
* \[ ] Access to backup/export folders

#### Network Red Flags

* \[ ] Large outbound transfers (>100MB)
* \[ ] Transfers to file sharing sites
* \[ ] Non-standard port usage
* \[ ] DNS query anomalies (length, volume)
* \[ ] Encrypted traffic to unknown IPs
* \[ ] After-hours data transfers
* \[ ] Traffic to paste sites
* \[ ] C2-like beaconing patterns

#### Email Red Flags

* \[ ] Large attachments to external
* \[ ] Emails to personal accounts
* \[ ] Password-protected attachments
* \[ ] Bulk external emails
* \[ ] Forwarding rules to external
* \[ ] Unusual attachment types
* \[ ] Emails to competitors

#### Cloud Storage Red Flags

* \[ ] Bulk downloads from SharePoint
* \[ ] External sharing of sensitive files
* \[ ] Anonymous link creation
* \[ ] Sync to unmanaged devices
* \[ ] Personal cloud app usage
* \[ ] Third-party OAuth access
* \[ ] Sharing with personal accounts

#### Endpoint Red Flags

* \[ ] USB device connections
* \[ ] Files copied to removable media
* \[ ] Mass printing
* \[ ] Bluetooth transfers
* \[ ] Screen capture tools
* \[ ] Clipboard history abuse
* \[ ] Screenshot of sensitive data

### Data Classification Quick Reference

<table><thead><tr><th width="156">Classification</th><th>Examples</th><th>Handling</th></tr></thead><tbody><tr><td><strong>Public</strong></td><td>Marketing materials, press releases</td><td>No restrictions</td></tr><tr><td><strong>Internal</strong></td><td>General business docs, policies</td><td>Internal only</td></tr><tr><td><strong>Confidential</strong></td><td>Financial reports, contracts</td><td>Need-to-know</td></tr><tr><td><strong>Restricted</strong></td><td>PII, PHI, trade secrets</td><td>Strict controls</td></tr><tr><td><strong>Top Secret</strong></td><td>M&#x26;A, strategic plans</td><td>Executive only</td></tr></tbody></table>

### Common Exfiltration Tools

<table><thead><tr><th width="170">Tool</th><th width="199">Type</th><th>Indicators</th></tr></thead><tbody><tr><td><strong>rclone</strong></td><td>Cloud sync</td><td>rclone.exe, config files</td></tr><tr><td><strong>WinSCP</strong></td><td>SFTP/SCP</td><td>winscp.exe, .ini files</td></tr><tr><td><strong>FileZilla</strong></td><td>FTP</td><td>filezilla.exe, sitemanager.xml</td></tr><tr><td><strong>MegaSync</strong></td><td>Cloud</td><td>megasync.exe</td></tr><tr><td><strong>Dropbox</strong></td><td>Cloud sync</td><td>Dropbox.exe</td></tr><tr><td><strong>Google Drive</strong></td><td>Cloud sync</td><td>googledrivesync.exe</td></tr><tr><td><strong>curl/wget</strong></td><td>HTTP transfer</td><td>curl.exe, wget.exe</td></tr><tr><td><strong>PowerShell</strong></td><td>Various</td><td>Invoke-WebRequest, Upload</td></tr><tr><td><strong>certutil</strong></td><td>Encode/Decode</td><td>-encode, -decode flags</td></tr><tr><td><strong>bitsadmin</strong></td><td>Download</td><td>/transfer command</td></tr></tbody></table>

### Regulatory Considerations

<table><thead><tr><th width="177">Data Type</th><th width="215">Regulations</th><th>Notification Requirements</th></tr></thead><tbody><tr><td><strong>PII (US)</strong></td><td>State breach laws</td><td>Varies by state (typically 30-60 days)</td></tr><tr><td><strong>PII (EU)</strong></td><td>GDPR</td><td>72 hours to authority</td></tr><tr><td><strong>PHI</strong></td><td>HIPAA</td><td>60 days</td></tr><tr><td><strong>Financial</strong></td><td>GLBA, SOX</td><td>Varies</td></tr><tr><td><strong>PCI</strong></td><td>PCI-DSS</td><td>Varies by contract</td></tr><tr><td><strong>Government</strong></td><td>FISMA, FedRAMP</td><td>Immediate to 24 hours</td></tr></tbody></table>

***

## Escalation Matrix

### Severity Classification

<table><thead><tr><th width="127">Severity</th><th width="433">Criteria</th><th>Response Time</th></tr></thead><tbody><tr><td>🔴 <strong>Critical</strong></td><td>Active exfiltration of critical data, confirmed insider threat, ransomware exfil before encryption</td><td>Immediate - 15 min</td></tr><tr><td>🟠 <strong>High</strong></td><td>Large data transfer detected, sensitive data exposed externally, departing employee with data</td><td>30 min - 1 hour</td></tr><tr><td>🟡 <strong>Medium</strong></td><td>DLP policy violations, unusual access patterns, potential data staging</td><td>4 hours</td></tr><tr><td>🟢 <strong>Low</strong></td><td>Minor policy violations, blocked exfil attempts, awareness issues</td><td>Next business day</td></tr></tbody></table>

### Escalation Triggers

| Condition                          | Escalation Level                |
| ---------------------------------- | ------------------------------- |
| Confirmed exfil of restricted data | DFIR + Legal + CISO             |
| PII/PHI data exposed               | DFIR + Legal + Privacy Officer  |
| Intellectual property theft        | DFIR + Legal + Business Owner   |
| Active insider threat              | DFIR + HR + Legal               |
| Ransomware exfiltration            | DFIR + CISO + Leadership        |
| Customer data exposed              | DFIR + Legal + Customer Success |
| >1GB confirmed exfiltrated         | Tier 2 SOC + DFIR               |
| Regulatory data involved           | Legal + Compliance + Privacy    |

### External Notifications

<table><thead><tr><th width="189">Scenario</th><th width="224">Notify</th><th>Timeline</th></tr></thead><tbody><tr><td>PII breach (US)</td><td>State AG offices</td><td>Per state law (30-60 days typical)</td></tr><tr><td>PII breach (EU)</td><td>Data Protection Authority</td><td>72 hours</td></tr><tr><td>PHI breach</td><td>HHS OCR</td><td>60 days (or 60 days for &#x3C;500 individuals)</td></tr><tr><td>PCI breach</td><td>Card brands, acquirer</td><td>Immediately</td></tr><tr><td>Government data</td><td>Relevant agency</td><td>Per contract/regulation</td></tr><tr><td>Cyber insurance</td><td>Carrier</td><td>Per policy (usually 24-72 hours)</td></tr></tbody></table>

***

## MITRE ATT\&CK Mapping

### Exfiltration (TA0010)

<table><thead><tr><th width="270">Technique</th><th width="116">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Exfiltration Over C2 Channel</td><td>T1041</td><td>Using existing C2</td><td>DeviceNetworkEvents, C2 patterns</td></tr><tr><td>Exfiltration Over Alternative Protocol</td><td>T1048</td><td>DNS, ICMP tunneling</td><td>DeviceNetworkEvents, DNS logs</td></tr><tr><td>Exfiltration Over Web Service</td><td>T1567</td><td>Cloud storage upload</td><td>CloudAppEvents</td></tr><tr><td>Exfiltration Over Web Service: Cloud Storage</td><td>T1567.002</td><td>Dropbox, Google Drive, etc.</td><td>CloudAppEvents, DeviceNetworkEvents</td></tr><tr><td>Exfiltration Over Physical Medium</td><td>T1052</td><td>USB, external drives</td><td>DeviceEvents (PnP)</td></tr><tr><td>Automated Exfiltration</td><td>T1020</td><td>Scripted data theft</td><td>DeviceProcessEvents</td></tr><tr><td>Scheduled Transfer</td><td>T1029</td><td>Timed exfiltration</td><td>DeviceNetworkEvents (time analysis)</td></tr><tr><td>Data Transfer Size Limits</td><td>T1030</td><td>Chunking data</td><td>DeviceNetworkEvents (patterns)</td></tr><tr><td>Transfer Data to Cloud Account</td><td>T1537</td><td>To attacker cloud</td><td>CloudAppEvents</td></tr></tbody></table>

### Collection (TA0009) - Pre-Exfiltration

<table><thead><tr><th width="196">Technique</th><th width="143">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Archive Collected Data</td><td>T1560</td><td>ZIP, RAR creation</td><td>DeviceFileEvents, DeviceProcessEvents</td></tr><tr><td>Archive via Utility</td><td>T1560.001</td><td>Using compression tools</td><td>DeviceProcessEvents</td></tr><tr><td>Archive via Library</td><td>T1560.002</td><td>Programmatic compression</td><td>DeviceProcessEvents</td></tr><tr><td>Data from Local System</td><td>T1005</td><td>Local file collection</td><td>DeviceFileEvents</td></tr><tr><td>Data from Network Shared Drive</td><td>T1039</td><td>Shared drive access</td><td>DeviceFileEvents, Event 5140</td></tr><tr><td>Data from Cloud Storage</td><td>T1530</td><td>Cloud data collection</td><td>CloudAppEvents</td></tr><tr><td>Data Staged: Local Staging</td><td>T1074.001</td><td>Staging before exfil</td><td>DeviceFileEvents</td></tr><tr><td>Data Staged: Remote Staging</td><td>T1074.002</td><td>Remote staging</td><td>DeviceFileEvents</td></tr><tr><td>Email Collection</td><td>T1114</td><td>Collecting email data</td><td>OfficeActivity</td></tr><tr><td>Screen Capture</td><td>T1113</td><td>Screenshots</td><td>DeviceProcessEvents</td></tr><tr><td>Clipboard Data</td><td>T1115</td><td>Clipboard content</td><td>DeviceEvents</td></tr></tbody></table>

### Related Techniques

<table><thead><tr><th width="178">Tactic</th><th>Technique</th><th width="126">ID</th><th>Relevance</th></tr></thead><tbody><tr><td>Defense Evasion</td><td>Obfuscated Files</td><td>T1027</td><td>Encrypting before exfil</td></tr><tr><td>Defense Evasion</td><td>Indicator Removal</td><td>T1070</td><td>Deleting evidence</td></tr><tr><td>Impact</td><td>Data Encrypted for Impact</td><td>T1486</td><td>Ransomware with exfil</td></tr></tbody></table>

***

## Appendix: Investigation Commands

### File Access Analysis

{% code overflow="wrap" %}
```powershell
# Get recent file access by user (requires auditing enabled)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663
} -MaxEvents 1000 | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = $_.Properties[1].Value
        Object = $_.Properties[6].Value
        AccessMask = $_.Properties[8].Value
        Process = $_.Properties[11].Value
    }
} | Where-Object {$_.User -eq "DOMAIN\username"}

# Find large files created recently
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {$_.Length -gt 100MB -and $_.CreationTime -gt (Get-Date).AddDays(-7)} |
    Select-Object FullName, @{N='SizeMB';E={$_.Length/1MB}}, CreationTime |
    Sort-Object SizeMB -Descending

# Find archive files
Get-ChildItem -Path C:\Users -Recurse -Include *.zip,*.rar,*.7z -ErrorAction SilentlyContinue |
    Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)} |
    Select-Object FullName, @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}}, CreationTime
```
{% endcode %}

### Network Transfer Analysis

{% code overflow="wrap" %}
```powershell
# Get network connections with high data transfer
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            ProcessName = $proc.Name
            ProcessPath = $proc.Path
        }
    } | Where-Object {$_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"}

# Check DNS client cache for suspicious domains
Get-DnsClientCache | Where-Object {$_.Entry -notmatch "\.(microsoft|windows|office|azure)\.com$"} |
    Select-Object Entry, Data, TimeToLive
```
{% endcode %}

### Cloud Activity Analysis

```powershell
# Using Microsoft Graph to get sign-in activity
Connect-MgGraph -Scopes "AuditLog.Read.All"

$userId = "user@domain.com"
$signIns = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$userId'" -Top 100

$signIns | Select-Object CreatedDateTime, AppDisplayName, IpAddress, 
    @{N='Location';E={"$($_.Location.City), $($_.Location.CountryOrRegion)"}},
    @{N='Device';E={$_.DeviceDetail.DisplayName}},
    Status

# Get user's OAuth app consents
$user = Get-MgUser -UserId $userId
Get-MgUserOauth2PermissionGrant -UserId $user.Id | ForEach-Object {
    $app = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId
    [PSCustomObject]@{
        AppName = $app.DisplayName
        Scopes = $_.Scope
        ConsentType = $_.ConsentType
    }
}
```

### Email Analysis

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Get outbound emails with attachments
$startDate = (Get-Date).AddDays(-7)
$endDate = Get-Date
$sender = "user@domain.com"

Get-MessageTrace -SenderAddress $sender -StartDate $startDate -EndDate $endDate |
    Where-Object {$_.ToIP -ne $null} |
    Select-Object Received, Subject, RecipientAddress, Size, Status

# Check for forwarding rules
Get-InboxRule -Mailbox "user@domain.com" | 
    Where-Object {$_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo} |
    Select-Object Name, ForwardTo, ForwardAsAttachmentTo, RedirectTo, Enabled

# Check mailbox forwarding
Get-Mailbox -Identity "user@domain.com" | 
    Select-Object ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
```

### USB/Removable Media Analysis

{% code overflow="wrap" %}
```powershell
# Get USB device history from registry
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" |
    Select-Object FriendlyName, ContainerID, @{N='LastConnected';E={
        $_.PSPath -match 'USBSTOR\\(.+)\\(.+)$'
        $deviceId = $Matches[2]
        $lastWrite = (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\$($Matches[1])\$deviceId").LastWriteTime
        $lastWrite
    }}

# Get recent removable drive events from event log
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
    ID = 2003, 2100, 2101
} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Message
```
{% endcode %}

### Comprehensive User Activity Export

{% code overflow="wrap" %}
```powershell
# Comprehensive user activity collection for investigation
$userId = "suspect@domain.com"
$outputPath = "C:\Investigation_$($userId.Replace('@','_').Replace('.','_'))_$(Get-Date -Format 'yyyyMMdd')"
New-Item -ItemType Directory -Path $outputPath -Force

# Export Unified Audit Log
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

Write-Host "Exporting Unified Audit Log..."
$auditLogs = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -UserIds $userId -ResultSize 5000
$auditLogs | Export-Csv "$outputPath\UnifiedAuditLog.csv" -NoTypeInformation

Write-Host "Exporting Sign-In Logs..."
Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome
$signIns = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$userId'" -Top 1000
$signIns | Export-Csv "$outputPath\SignInLogs.csv" -NoTypeInformation

Write-Host "Exporting Email Activity..."
Connect-ExchangeOnline -ShowBanner:$false
$messages = Get-MessageTrace -SenderAddress $userId -StartDate $startDate -EndDate $endDate
$messages | Export-Csv "$outputPath\SentEmails.csv" -NoTypeInformation

$received = Get-MessageTrace -RecipientAddress $userId -StartDate $startDate -EndDate $endDate
$received | Export-Csv "$outputPath\ReceivedEmails.csv" -NoTypeInformation

Write-Host "Exporting Inbox Rules..."
$rules = Get-InboxRule -Mailbox $userId
$rules | Export-Csv "$outputPath\InboxRules.csv" -NoTypeInformation

Write-Host "Exporting Mailbox Configuration..."
$mailbox = Get-Mailbox -Identity $userId
$mailbox | Select-Object * | Export-Csv "$outputPath\MailboxConfig.csv" -NoTypeInformation

Write-Host "Creating summary..."
$summary = @"
Investigation Summary
=====================
User: $userId
Export Date: $(Get-Date)
Date Range: $startDate to $endDate

Files Exported:
- UnifiedAuditLog.csv: $($auditLogs.Count) records
- SignInLogs.csv: $($signIns.Count) records
- SentEmails.csv: $($messages.Count) records
- ReceivedEmails.csv: $($received.Count) records
- InboxRules.csv: $($rules.Count) records
- MailboxConfig.csv: Mailbox configuration

Notes:
- Review for unusual activity patterns
- Check sign-in locations and devices
- Review email recipients and attachments
- Check inbox rules for forwarding
"@
$summary | Out-File "$outputPath\Summary.txt"

Write-Host "Compressing evidence..."
Compress-Archive -Path $outputPath -DestinationPath "$outputPath.zip" -Force

Write-Host "Evidence collection complete: $outputPath.zip"
```
{% endcode %}

***

## Prevention & Hardening

### DLP Policy Recommendations

| Policy                   | Scope                        | Action                           |
| ------------------------ | ---------------------------- | -------------------------------- |
| **Credit Card Numbers**  | Email, SharePoint, Endpoints | Block external sharing, notify   |
| **SSN/National ID**      | All locations                | Block external, alert SOC        |
| **Health Records (PHI)** | All locations                | Block external, encrypt          |
| **Source Code**          | Endpoints, Cloud             | Block USB, alert on cloud upload |
| **Financial Reports**    | SharePoint, Email            | Block external sharing           |
| **Customer PII**         | All locations                | Block external, log all access   |

### Endpoint Controls

| Control                  | Purpose                       | Implementation         |
| ------------------------ | ----------------------------- | ---------------------- |
| **USB Blocking**         | Prevent removable media exfil | MDE Device Control     |
| **Cloud App Control**    | Block unsanctioned apps       | MDCA + Prisma Access   |
| **Print Restrictions**   | Prevent print exfil           | GPO / Intune           |
| **Clipboard Control**    | Prevent copy/paste            | Application Guard      |
| **Screen Capture Block** | Prevent screenshots           | Information Protection |

### Network Controls

| Control                  | Purpose                           | Implementation     |
| ------------------------ | --------------------------------- | ------------------ |
| **Egress Filtering**     | Block unauthorized transfers      | Prisma Access      |
| **Category Blocking**    | Block file sharing sites          | URL Filtering      |
| **Data Transfer Limits** | Alert on large uploads            | Network monitoring |
| **DNS Monitoring**       | Detect tunneling                  | DNS security       |
| **SSL Inspection**       | Visibility into encrypted traffic | Prisma Access      |

***

> 🔒 **Critical Reminder:** Data exfiltration investigations often have legal, HR, and regulatory implications. Always coordinate with Legal and HR before taking action on insider threat cases. Preserve evidence meticulously with documented chain of custody. Be aware of privacy regulations that may affect investigation methods in different jurisdictions. Time is critical—once data leaves the organization, recovery may be impossible.
