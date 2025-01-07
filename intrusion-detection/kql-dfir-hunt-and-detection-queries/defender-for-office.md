---
cover: ../../.gitbook/assets/Screenshot 2025-01-05 160037.png
coverY: 0
---

# Defender For Office

### <mark style="color:blue;">Identify Email Attachments Send From Compromised Mailbox</mark>

{% code overflow="wrap" %}
```kusto
// Define search parameters
let CompromisedMailbox = "user1@exampledomain.com"; // Specify the compromised mailbox
let SearchWindow = 48h; // Set the search window for analysis
// Query to analyze emails sent from the compromised mailbox with attachments
EmailEvents
| where Timestamp >= ago(SearchWindow) // Filter for events within the search window
| where SenderFromAddress == CompromisedMailbox // Focus on the compromised mailbox
| where AttachmentCount > 0 // Include only emails with attachments
| join kind=leftouter EmailAttachmentInfo on NetworkMessageId // Join with attachment info using NetworkMessageId
| project
    Timestamp, // Email timestamp
    NetworkMessageId, // Unique identifier for the email
    SenderFromAddress, // Sender's email address
    RecipientEmailAddress, // Recipient's email address
    Subject, // Email subject
    ThreatTypes, // Identified threats (if any)
    SHA256 // Hash of the attachment
| join kind=leftouter DeviceFileEvents on SHA256 // Join with file events using attachment hash
| summarize
    EmailRecipients = make_set(RecipientEmailAddress), // Aggregate unique email recipients
    EmailSubjects = make_set(Subject), // Aggregate unique email subjects
    DevicesWithFile = make_set(DeviceName) // Aggregate devices interacting with the attachment
    by SHA256, NetworkMessageId // Group by attachment hash and email ID
| extend
    TotalRecipients = array_length(EmailRecipients), // Count unique email recipients
    DevicesWithFileInteraction = array_length(DevicesWithFile) // Count unique devices interacting with the file
//| order by Tim desc // Sort by the most recent email event
```
{% endcode %}

### <mark style="color:blue;">Identifying Executable File Attachments Sent to Users</mark>

**Use Case:** Threat Actors often use executable files to gain initial access. This query detects a common set of extensions that are normally targeted at Windows systems.

{% code overflow="wrap" %}
```kusto
// Executable Extensions to monitor
let ExecutableExtensions = dynamic(['cab','bat', 'cmd', 'com', 'cpl', 'dll', 'ex', 'exe', 'jse', 'lnk', 'msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf','scr','paf','msi','job']);
// Query to analyze inbound emails with executable attachments
EmailEvents
| where EmailDirection == "Inbound" // Filter for inbound emails only
| join kind=inner EmailAttachmentInfo on NetworkMessageId // Join with attachment info to include only emails with attachments
| extend 
    FileExtension = tostring(extract(@".*\.(.*)", 1, FileName)) // Extract the file extension from the filename
| where isnotempty(FileExtension) // Exclude events with empty file extensions
| where FileExtension in~ (ExecutableExtensions) // Filter for executable file extensions (case-insensitive match)
| summarize 
    TargetMailboxes = make_set(RecipientEmailAddress), // Aggregate unique recipient email addresses
    SenderAddresses = make_set(SenderFromAddress), // Aggregate unique sender addresses
    EmailSubjects = make_set(Subject) // Aggregate unique email subjects
    by SHA256, FileName // Group by attachment hash and file name
| order by FileName asc // Sort results alphabetically by file name for better readability
```
{% endcode %}

## <mark style="color:blue;">Search for Malware File Detected In Office 365</mark>

**Use Case:** This advanced query allows SOC analysts to: Detect and prioritize malware activity within Office workloads. Identify patterns in malware types and affected file extensions. Gain insights into impacted users and files for targeted remediation.

{% code overflow="wrap" %}
```kusto
// Advanced search for file malware detection in OfficeActivity
OfficeActivity
| where Operation == "FileMalwareDetected" // Focus on malware detection events
| extend 
    FileExtension = tostring(extract(@".*\.(.*)", 1, SourceFileName)) // Extract file extension from the file name
| where isnotempty(SourceFileName) // Ensure the source file name is not empty
| project 
    TimeGenerated, // Timestamp of the detection event
    OfficeWorkload, // Office workload where the event was triggered
    SourceFileName, // Name of the file with detected malware
    FileExtension, // Extracted file extension for analysis
    OfficeObjectId, // Office object ID related to the event
    UserId // User account associated with the activity
| summarize 
    MalwareDetectionCount = count(), // Count of detections
    ImpactedFiles = make_set(SourceFileName), // Aggregate impacted file names
    ImpactedUsers = make_set(UserId) // Aggregate impacted user IDs
    by OfficeWorkload, FileExtension // Group results by workload and file extension
| order by MalwareDetectionCount desc // Sort by the number of detections in descending order
```
{% endcode %}

### <mark style="color:blue;">Identify Potential Phishing Campaign</mark>

{% code overflow="wrap" %}
```kusto
// Define suspicious indicators
let SuspiciousKeywords = dynamic(["urgent", "invoice", "payment", "click", "login", "verify", "security"]);
let ExecutableExtensions = dynamic(["bat", "cmd", "com", "exe", "jse", "lnk", "ps1", "vbs", "vbe", "wsf"]);
// Query to detect potential phishing campaigns
EmailEvents
| where EmailDirection == "Inbound" // Focus on inbound emails
| where Timestamp >= ago(7d) // Search within the last 7 days
| extend 
    HasSuspiciousSubject = iif(tostring(Subject) has_any (SuspiciousKeywords), 1, 0), // Flag emails with suspicious subjects
    HasLink = iif(UrlCount > 0, 1, 0) // Flag emails containing URLs
| join kind=leftouter EmailAttachmentInfo on NetworkMessageId // Join to include attachment details
| extend 
    FileExtension = tostring(extract(@".*\.(.*)", 1, FileName)), // Extract file extension
    IsExecutableAttachment = iif(ExecutableExtensions in~ (ExecutableExtensions), 1, 0) // Flag potentially malicious attachments
| summarize 
    TotalEmails = count(), // Count total emails in the potential campaign
    Recipients = make_set(RecipientEmailAddress), // List of unique recipients
    Senders = make_set(SenderFromAddress), // List of unique senders
    SuspiciousSubjects = make_set(Subject), // List of unique suspicious subjects
    MaliciousFileNames = make_set(FileName, 10), // List of suspicious attachment file names (limited to 10)
    URLsDetected = sum(HasLink), // Count of emails with URLs
    SuspiciousSubjectCount = sum(HasSuspiciousSubject), // Count of emails with suspicious subjects
    ExecutableAttachments = sum(IsExecutableAttachment) // Count of emails with executable attachments
    by bin(Timestamp, 1h), SenderFromAddress // Group by time (hourly bins) and sender
| where TotalEmails > 10 or SuspiciousSubjectCount > 5 or ExecutableAttachments > 0 or URLsDetected > 0 // Filter potential campaigns based on thresholds
| project 
    Timestamp, // Time of the campaign
    SenderFromAddress, // Sender initiating the potential campaign
    TotalEmails, // Total emails sent by the sender
    Recipients, // Unique recipients
    SuspiciousSubjects, // List of suspicious subjects
    MaliciousFileNames, // Suspicious attachment file names
    URLsDetected, // Count of emails containing URLs
    SuspiciousSubjectCount, // Count of emails with suspicious subjects
    ExecutableAttachments // Count of emails with executable attachments
| order by Timestamp desc // Sort by the most recent campaigns
```
{% endcode %}

## <mark style="color:blue;">Identifying Emails Categorised as Suspicious Delivered to Users</mark>&#x20;

**Use Case:** This query is ideal for investigating emails sent to a compromised address, analyzing associated threats, and understanding post-delivery actions to mitigate risks effectively.

{% code overflow="wrap" %}
```kusto
// Define parameters
let CompromisedEmailAddress = "user1@exampledomain.com"; // Specify the compromised email address
let Timeframe = 2d; // Set the investigation timeframe
// Extract relevant email events for the compromised email address
let EmailInformation = EmailEvents
| where RecipientEmailAddress == CompromisedEmailAddress // Filter emails sent to the compromised address
| where Timestamp >= ago(Timeframe) // Restrict to the defined timeframe
| where DeliveryAction != "Blocked" // Exclude blocked emails
| project 
    Timestamp, // Time of the email
    NetworkMessageId, // Unique identifier for the email
    SenderMailFromAddress, // Sender's mail address
    SenderFromAddress, // Sender's displayed address
    SenderDisplayName, // Sender's display name
    ThreatNames; // Any identified threats
// Join email events with post-delivery events for additional context
EmailInformation
| join kind=inner (
    EmailPostDeliveryEvents
    | where isnotempty(ThreatTypes) // Include only events with detected threats
    | project 
        Timestamp, // Time of the post-delivery action
        NetworkMessageId, // Unique identifier for the email
        Action, // Action taken post-delivery
        ActionType, // Type of the action
        ActionTrigger, // What triggered the action
        ActionResult, // Result of the action
        DeliveryLocation, // Location where the email was delivered
        ThreatTypes, // Types of threats detected
        DetectionMethods // Methods used to detect threats
) on NetworkMessageId
| project 
    Timestamp, // Timestamp of the event
    NetworkMessageId, // Email identifier
    SenderMailFromAddress, // Sender's mail address
    SenderFromAddress, // Sender's displayed address
    SenderDisplayName, // Sender's display name
    ThreatNames, // Threats identified at delivery
    Action, // Post-delivery action taken
    ActionType, // Type of post-delivery action
    ActionTrigger, // What triggered the post-delivery action
    ActionResult, // Result of the post-delivery action
    DeliveryLocation, // Location where the email was delivered
    ThreatTypes, // Threat types detected post-delivery
    DetectionMethods // Methods used to detect threats
| order by Timestamp desc // Sort by the most recent events
```
{% endcode %}

### <mark style="color:blue;">Identify User UrlClick Events</mark>&#x20;

**User Cases:** Identify emails with URLs sent to user and they may have clicked URL and it wasn’t blocked.

{% code overflow="wrap" %}
```kusto
// Define parameters
let CompromisedEmailAddress = "adrian.anglin@sperrymarine.com"; // Specify the compromised email address
let Timeframe = 2d; // Set the investigation timeframe
// Extract relevant email events for the compromised email address
let EmailInformation = EmailEvents
| where RecipientEmailAddress == CompromisedEmailAddress // Filter emails sent to the compromised address
| where Timestamp >= ago(Timeframe) // Restrict to the defined timeframe
| where UrlCount > 0 // Include only emails containing URLs
| project 
    Timestamp, // Time of the email
    NetworkMessageId, // Unique identifier for the email
    SenderMailFromAddress, // Sender's mail address
    SenderFromAddress, // Sender's displayed address
    SenderDisplayName, // Sender's display name
    ThreatNames; // Any identified threats
// Join with URL click events for additional insights
EmailInformation
| join kind=inner (
    UrlClickEvents
    | where Timestamp >= ago(Timeframe) // Restrict to the defined timeframe
    | where ActionType != "ClickBlocked" // Exclude clicks that were blocked
    | where Workload == "Email" // Focus on email-related clicks
    | project 
        Timestamp, // Time of the URL click event
        Url, // Clicked URL
        IPAddress, // IP address from which the URL was clicked
        NetworkMessageId // Unique identifier for the email
) on NetworkMessageId
| project 
    Timestamp, // Timestamp of the event
    NetworkMessageId, // Email identifier
    SenderMailFromAddress, // Sender's mail address
    SenderFromAddress, // Sender's displayed address
    SenderDisplayName, // Sender's display name
    ThreatNames, // Threats identified in the email
    Url, // Clicked URL
    IPAddress // IP address from which the URL was clicked
| order by Timestamp desc // Sort by the most recent events
```
{% endcode %}
