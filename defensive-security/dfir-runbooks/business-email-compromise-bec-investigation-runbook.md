# Business Email Compromise (BEC) Investigation Runbook

## SOC & DFIR Operations Guide

**Environment:** Windows AD | Microsoft 365 | Defender XDR | Sentinel | Entra ID | Palo Alto Prisma Access

***

## Overview & Scope

This runbook provides standardised procedures for investigating Business Email Compromise (BEC) attacks across the Microsoft 365 environment. BEC attacks are sophisticated social engineering schemes that exploit email to defraud organisations, often resulting in significant financial losses and data breaches.

### What is Business Email Compromise?

BEC is a type of cybercrime where attackers use email fraud to target organisations. Unlike traditional phishing, BEC attacks are highly targeted, well-researched, and often involve impersonating trusted parties or compromising legitimate email accounts.

**Key Statistics:**

* BEC accounts for the largest financial losses in cybercrime
* Often no malware involved - relies on social engineering
* Targets finance, HR, executives, and legal departments

### BEC Attack Categories

#### By Attack Type

| Type                       | Description                                                | Target               | Financial Risk |
| -------------------------- | ---------------------------------------------------------- | -------------------- | -------------- |
| **CEO Fraud**              | Impersonation of executive requesting urgent wire transfer | Finance team         | Critical       |
| **Account Compromise**     | Takeover of legitimate email account                       | Any employee         | High           |
| **Invoice Fraud**          | Fake or modified invoices from "vendors"                   | Accounts Payable     | Critical       |
| **Vendor Impersonation**   | Impersonating suppliers/partners                           | Procurement, Finance | High           |
| **Attorney Impersonation** | Fake legal requests requiring urgent action                | Executives, Finance  | High           |
| **Data Theft**             | Targeting HR/Finance for W-2s, PII, payroll data           | HR, Payroll          | High           |
| **Gift Card Scam**         | Request to purchase gift cards                             | Any employee         | Medium         |
| **Payroll Diversion**      | Request to change direct deposit information               | HR, Payroll          | High           |

#### By Compromise Method

| Method                     | Description                                              | Detection Difficulty |
| -------------------------- | -------------------------------------------------------- | -------------------- |
| **Spoofing**               | Forging sender address to appear legitimate              | Low-Medium           |
| **Look-alike Domains**     | Using domains similar to legitimate ones (typosquatting) | Medium               |
| **Display Name Deception** | Matching display name but different email address        | Low                  |
| **Account Takeover (ATO)** | Compromising actual email account                        | High                 |
| **Mailbox Rule Abuse**     | Creating rules to hide attacker activity                 | High                 |
| **Reply-Chain Hijacking**  | Inserting into existing email conversations              | Very High            |
| **Compromised Vendor**     | Using actually compromised third-party accounts          | Very High            |

### BEC Attack Lifecycle

```bash
1. Reconnaissance
   └── Research target organisation, executives, vendors, financial processes

2. Initial Contact / Compromise
   ├── Phishing for credentials
   ├── Domain spoofing setup
   └── Account takeover

3. Establish Presence (if ATO)
   ├── Create inbox rules to hide activity
   ├── Monitor email for opportunities
   └── Gather intelligence on processes

4. Execution
   ├── Send fraudulent request
   ├── Create urgency/pressure
   └── Provide payment instructions

5. Cash Out
   ├── Wire transfer to attacker account
   ├── Gift card codes sent
   └── Payroll diverted
```

***

## Detection Sources & Data Mapping

### Log Sources Matrix

<table><thead><tr><th width="183">Platform</th><th>Log Table</th><th>BEC-Relevant Data</th></tr></thead><tbody><tr><td>Defender for Office</td><td><code>EmailEvents</code></td><td>Email metadata, delivery status</td></tr><tr><td>Defender for Office</td><td><code>EmailAttachmentInfo</code></td><td>Attachment analysis</td></tr><tr><td>Defender for Office</td><td><code>EmailUrlInfo</code></td><td>URLs in emails</td></tr><tr><td>Defender for Office</td><td><code>EmailPostDeliveryEvents</code></td><td>Post-delivery actions (ZAP)</td></tr><tr><td>Defender for Office</td><td><code>UrlClickEvents</code></td><td>User URL clicks</td></tr><tr><td>Exchange Online</td><td><code>OfficeActivity</code></td><td>Mailbox operations, rules</td></tr><tr><td>Exchange Online</td><td><code>CloudAppEvents</code></td><td>Mail send, forwarding</td></tr><tr><td>Entra ID</td><td><code>SigninLogs</code></td><td>Account access patterns</td></tr><tr><td>Entra ID</td><td><code>AuditLogs</code></td><td>Account changes</td></tr><tr><td>Entra ID</td><td><code>AADNonInteractiveUserSignInLogs</code></td><td>App-based sign-ins</td></tr><tr><td>Entra ID</td><td><code>RiskyUsers</code>, <code>RiskySignIns</code></td><td>Identity Protection alerts</td></tr><tr><td>Sentinel</td><td><code>SecurityAlert</code></td><td>Correlated BEC alerts</td></tr><tr><td>Sentinel</td><td><code>ThreatIntelligenceIndicator</code></td><td>Known BEC IOCs</td></tr></tbody></table>

### Critical Detection Indicators

#### Email-Level Indicators

<table><thead><tr><th>Indicator</th><th width="310">Description</th><th>Risk Level</th></tr></thead><tbody><tr><td><strong>External sender with internal display name</strong></td><td>Spoofing executive names</td><td>High</td></tr><tr><td><strong>Look-alike domain</strong></td><td>Typosquatted or similar domain</td><td>High</td></tr><tr><td><strong>Reply-to mismatch</strong></td><td>Reply address differs from sender</td><td>High</td></tr><tr><td><strong>First-time sender</strong></td><td>Never communicated before</td><td>Medium</td></tr><tr><td><strong>Urgent financial request</strong></td><td>Wire transfer, gift cards</td><td>Critical</td></tr><tr><td><strong>Changed banking details</strong></td><td>New account information</td><td>Critical</td></tr><tr><td><strong>External forwarding rule</strong></td><td>Mail forwarded outside org</td><td>Critical</td></tr><tr><td><strong>Unusual sending patterns</strong></td><td>Off-hours, unusual recipients</td><td>Medium</td></tr></tbody></table>

#### Account Compromise Indicators

<table><thead><tr><th>Indicator</th><th width="282">Description</th><th>Risk Level</th></tr></thead><tbody><tr><td><strong>Impossible travel</strong></td><td>Sign-ins from distant locations</td><td>High</td></tr><tr><td><strong>New inbox rules</strong></td><td>Especially delete/forward rules</td><td>Critical</td></tr><tr><td><strong>Suspicious sign-in properties</strong></td><td>New device, browser, location</td><td>Medium</td></tr><tr><td><strong>Mail forwarding changes</strong></td><td>SMTP forwarding added</td><td>Critical</td></tr><tr><td><strong>Delegate access added</strong></td><td>New mailbox permissions</td><td>High</td></tr><tr><td><strong>Bulk email operations</strong></td><td>Mass delete, forward, export</td><td>High</td></tr><tr><td><strong>OAuth app consent</strong></td><td>New app with mail permissions</td><td>High</td></tr><tr><td><strong>Legacy protocol sign-in</strong></td><td>IMAP/POP3 authentication</td><td>High</td></tr></tbody></table>

#### Behavioral Indicators

<table><thead><tr><th width="262">Indicator</th><th width="303">Description</th><th>Risk Level</th></tr></thead><tbody><tr><td><strong>Urgency language</strong></td><td>"ASAP", "urgent", "confidential"</td><td>Medium</td></tr><tr><td><strong>Authority assertion</strong></td><td>"CEO approved", "don't tell anyone"</td><td>High</td></tr><tr><td><strong>Process bypass requests</strong></td><td>"Skip normal approval"</td><td>Critical</td></tr><tr><td><strong>Gift card requests</strong></td><td>Purchase and send codes</td><td>High</td></tr><tr><td><strong>Banking change requests</strong></td><td>New wire instructions</td><td>Critical</td></tr><tr><td><strong>W-2/Tax form requests</strong></td><td>Bulk PII requests</td><td>High</td></tr><tr><td><strong>Unusual payment amounts</strong></td><td>Outside normal ranges</td><td>Medium</td></tr></tbody></table>

***

## Investigation Workflows

### BEC Alert Triage

**Objective:** Quickly assess if a reported email is a BEC attempt and determine if any action has been taken.

#### Step 1: Initial Assessment

1. Identify the reported email (subject, sender, recipient, time)
2. Determine alert source (user report, automated detection, MDO)
3. Check if email was delivered or blocked
4. Assess the request type (wire transfer, gift cards, data)
5. Determine urgency based on potential financial impact

#### Step 2: Email Analysis

1. Review email headers for spoofing indicators
2. Check sender domain reputation and age
3. Analyze display name vs. actual email address
4. Review reply-to address configuration
5. Check for look-alike domain usage
6. Examine email content for social engineering tactics

#### Step 3: Recipient Impact Assessment

1. Identify all recipients of the email
2. Check if any recipients replied or clicked links
3. Review any attachments opened
4. Determine if any actions were taken (wire sent, etc.)
5. Contact recipients to verify no action taken

#### Step 4: Classification

<table><thead><tr><th width="203">Classification</th><th>Criteria</th><th>Action</th></tr></thead><tbody><tr><td><strong>External Impersonation</strong></td><td>Spoofed/look-alike domain</td><td>Block domain, warn users</td></tr><tr><td><strong>Account Compromise</strong></td><td>Sent from legitimate internal account</td><td>Contain account, full investigation</td></tr><tr><td><strong>Vendor Compromise</strong></td><td>From actual compromised vendor</td><td>Contact vendor, block sender</td></tr><tr><td><strong>False Positive</strong></td><td>Legitimate email incorrectly flagged</td><td>Whitelist, close alert</td></tr></tbody></table>

***

### Account Takeover (ATO) Investigation

**Objective:** Investigate suspected email account compromise used for BEC.

#### Step 1: Confirm Compromise

1. Review sign-in logs for anomalies
2. Check for impossible travel scenarios
3. Look for new device/browser/location sign-ins
4. Review MFA challenge results
5. Check Identity Protection risk scores

#### Step 2: Assess Mailbox Activity

1. Query mailbox audit logs for suspicious operations
2. Check for inbox rule creation/modification
3. Review sent items for unauthorised emails
4. Check deleted items for evidence destruction
5. Review mail forwarding configuration

#### Step 3: Identify Attacker Actions

1. Map timeline of unauthorised access
2. Identify emails sent by attacker
3. Document inbox rules created
4. Check for OAuth app consents
5. Review delegate access changes

#### Step 4: Determine Impact

1. List all recipients of fraudulent emails
2. Check if financial requests were made
3. Identify any data exfiltrated
4. Review if other accounts were targeted
5. Assess vendor/partner notification needs

#### Step 5: Containment

1. Reset user password immediately
2. Revoke all active sessions
3. Remove malicious inbox rules
4. Disable mail forwarding
5. Revoke suspicious OAuth apps
6. Enable/verify MFA
7. Block attacker IPs if identified

***

### Invoice/Payment Fraud Investigation

**Objective:** Investigate BEC attempts targeting financial transactions.

#### Step 1: Email Trail Analysis

1. Locate the original fraudulent email
2. Identify the full email thread/conversation
3. Determine if legitimate thread was hijacked
4. Check for prior reconnaissance emails
5. Document all related communications

#### Step 2: Financial Request Analysis

1. Review the specific financial request
2. Compare requested account to known vendor details
3. Verify with vendor through separate channel
4. Check for recent "banking change" notifications
5. Review invoice details for inconsistencies

#### Step 3: Payment Status

<table><thead><tr><th width="202">Status</th><th>Immediate Action</th></tr></thead><tbody><tr><td><strong>Not Sent</strong></td><td>Block payment, warn finance team</td></tr><tr><td><strong>Pending</strong></td><td>Cancel immediately, contact bank</td></tr><tr><td><strong>Sent &#x3C; 24 hours</strong></td><td>Contact bank for recall</td></tr><tr><td><strong>Sent > 24 hours</strong></td><td>Contact bank, likely unrecoverable</td></tr></tbody></table>

#### Step 4: Source Identification

1. Determine if sender account was compromised
2. Check if vendor's email was compromised
3. Identify if domain spoofing was used
4. Review for man-in-the-middle indicators
5. Check for prior account access anomalies

#### Step 5: Recovery Actions

1. Contact bank immediately for wire recall
2. File IC3/FBI complaint for significant amounts
3. Preserve all evidence for law enforcement
4. Notify cyber insurance carrier
5. Document timeline for legal purposes

***

### Executive Impersonation Investigation

**Objective:** Investigate BEC attempts impersonating executives.

#### Step 1: Impersonation Analysis

1. Identify the impersonated executive
2. Compare spoofed email to legitimate address
3. Check domain registration details
4. Review email authentication results (SPF/DKIM/DMARC)
5. Analyse writing style and signature

#### Step 2: Target Analysis

1. Identify all recipients targeted
2. Determine why these recipients were chosen
3. Check for prior reconnaissance against targets
4. Review if organisational info is publicly available
5. Assess social engineering sophistication

#### Step 3: Campaign Scope

1. Search for similar emails to other employees
2. Check for other impersonated executives
3. Look for variations in sender domains
4. Identify common infrastructure (IPs, domains)
5. Determine if targeted campaign or spray attack

#### Step 4: Response Coordination

1. Alert executive being impersonated
2. Send targeted warning to potential victims
3. Block identified spoofing infrastructure
4. Update email filters/rules
5. Consider organisation-wide alert

***

### Inbox Rule Abuse Investigation

**Objective:** Investigate malicious inbox rules created by attackers.

#### Common Malicious Rule Patterns

<table><thead><tr><th width="212">Rule Type</th><th width="251">Purpose</th><th>Detection</th></tr></thead><tbody><tr><td><strong>Delete incoming</strong></td><td>Hide responses about fraud</td><td>Rule deletes from specific senders</td></tr><tr><td><strong>Move to RSS/Archive</strong></td><td>Hide from primary view</td><td>Rule moves to obscure folders</td></tr><tr><td><strong>Forward externally</strong></td><td>Exfiltrate ongoing mail</td><td>Forwarding to external address</td></tr><tr><td><strong>Delete sent items</strong></td><td>Hide attacker's emails</td><td>Rule deletes sent mail</td></tr><tr><td><strong>Mark as read</strong></td><td>Prevent notification</td><td>Rule marks as read immediately</td></tr><tr><td><strong>Auto-reply</strong></td><td>Automate responses</td><td>Suspicious auto-reply content</td></tr></tbody></table>

#### Investigation Steps

1. **Export all inbox rules**
   * Query OfficeActivity for rule operations
   * Review current rules via PowerShell/Admin Center
   * Check for hidden/obfuscated rules
2. **Analyse rule creation timeline**
   * Correlate with sign-in anomalies
   * Check who created the rules
   * Identify source IP/device
3. **Assess rule impact**
   * Determine what mail was affected
   * Check forwarding destinations
   * Review deleted/moved messages
4. **Remove malicious rules**
   * Delete all attacker-created rules
   * Document rules for evidence
   * Monitor for re-creation

***

## KQL Query Cheat Sheet

### Email Analysis Queries

#### Suspicious External Senders with Internal Display Names

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where SenderFromDomain != "yourdomain.com"
| extend DisplayName = extract(@"^([^<]+)", 1, SenderFromAddress)
| where DisplayName has_any ("CEO Name", "CFO Name", "Controller Name")  // Add your executives
| project Timestamp, Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, DisplayName
| sort by Timestamp desc
```
{% endcode %}

#### Look-alike Domain Detection

{% code overflow="wrap" %}
```kusto
let legitimateDomains = dynamic(["yourdomain.com", "vendor1.com", "vendor2.com"]);
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where SenderFromDomain !in (legitimateDomains)
| extend DomainSimilarity = 
    case(
        SenderFromDomain matches regex @"yourdoma[il1]n\.com", "Typosquat",
        SenderFromDomain matches regex @"y0urdomain\.com", "Homoglyph",
        SenderFromDomain matches regex @"yourdomain-.*\.com", "Hyphenated",
        SenderFromDomain matches regex @"yourdomain\..*", "TLD variation",
        "Other"
    )
| where DomainSimilarity != "Other"
| summarize Count = count(), Recipients = make_set(RecipientEmailAddress) by SenderFromDomain, DomainSimilarity
| sort by Count desc
```
{% endcode %}

#### Reply-To Mismatch Detection

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where isnotempty(SenderReplyToAddress)
| where SenderFromAddress != SenderReplyToAddress
| where SenderReplyToAddress !endswith "yourdomain.com"
| project Timestamp, Subject, SenderFromAddress, SenderReplyToAddress, RecipientEmailAddress
| sort by Timestamp desc
```
{% endcode %}

#### First-Time Sender to Executive

{% code overflow="wrap" %}
```kusto
let executives = dynamic(["ceo@yourdomain.com", "cfo@yourdomain.com", "controller@yourdomain.com"]);
let baseline = EmailEvents
| where Timestamp between (ago(90d) .. ago(7d))
| where RecipientEmailAddress in (executives)
| summarize by SenderFromAddress, RecipientEmailAddress;
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress in (executives)
| where EmailDirection == "Inbound"
| join kind=leftanti baseline on SenderFromAddress, RecipientEmailAddress
| project Timestamp, Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress
| sort by Timestamp desc
```
{% endcode %}

#### Emails with Financial Keywords

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(24h)
| where EmailDirection == "Inbound"
| where Subject has_any (
    "wire transfer",
    "bank account",
    "payment",
    "invoice",
    "urgent",
    "confidential",
    "gift card",
    "direct deposit",
    "W-2",
    "W2",
    "tax form",
    "ACH",
    "routing number"
)
| project Timestamp, Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, DeliveryAction
| sort by Timestamp desc
```
{% endcode %}

***

### Account Compromise Detection

#### Sign-in Anomalies for Mail Users

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where AppDisplayName has_any ("Outlook", "Exchange", "Office 365")
| where ResultType == 0  // Successful
| summarize 
    Locations = make_set(Location),
    IPs = make_set(IPAddress),
    Devices = make_set(DeviceDetail.displayName),
    SignInCount = count()
    by UserPrincipalName
| where array_length(Locations) > 3 or array_length(IPs) > 10
| sort by array_length(Locations) desc
```

#### Impossible Travel for Email Access

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where AppDisplayName has_any ("Outlook", "Exchange", "Office 365")
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevLocation = prev(Location), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser and Location != PrevLocation
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes < 60
| project TimeGenerated, UserPrincipalName, Location, PrevLocation, TimeDiffMinutes, IPAddress
```
{% endcode %}

#### Legacy Protocol Authentication

{% code overflow="wrap" %}
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Other clients")
| where ResultType == 0
| summarize 
    AuthCount = count(),
    IPs = make_set(IPAddress),
    Locations = make_set(Location)
    by UserPrincipalName, ClientAppUsed
| sort by AuthCount desc
```
{% endcode %}

#### New OAuth App Consent with Mail Permissions

{% code overflow="wrap" %}
```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties[4].newValue)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings")
| project TimeGenerated, AppName, Permissions, ConsentedBy, Result
| sort by TimeGenerated desc
```
{% endcode %}

***

### Mailbox Activity Analysis

#### Inbox Rule Creation/Modification

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| extend RuleName = tostring(parse_json(RawEventData).Parameters[0].Value)
| extend RuleConditions = tostring(RawEventData)
| project Timestamp, AccountDisplayName, ActionType, RuleName, RuleConditions, IPAddress
| sort by Timestamp desc
```
{% endcode %}

#### Suspicious Inbox Rules (Forwarding/Deletion)

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RawData = parse_json(RawEventData)
| extend Parameters = RawData.Parameters
| mv-expand Parameters
| where Parameters.Name in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", "DeleteMessage", "MoveToFolder")
| extend RuleName = tostring(RawData.Parameters[0].Value)
| extend ParameterName = tostring(Parameters.Name)
| extend ParameterValue = tostring(Parameters.Value)
| project Timestamp, AccountDisplayName, RuleName, ParameterName, ParameterValue, IPAddress
| sort by Timestamp desc
```
{% endcode %}

#### Email Forwarding Configuration Changes

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Set-Mailbox", "Set-MailboxJunkEmailConfiguration")
| where RawEventData has_any ("ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward")
| extend ModifiedProperties = parse_json(RawEventData).Parameters
| project Timestamp, AccountDisplayName, ActionType, ModifiedProperties, IPAddress
| sort by Timestamp desc
```
{% endcode %}

#### Bulk Email Operations

```kusto
CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType in ("SoftDelete", "HardDelete", "Move", "MoveToDeletedItems")
| summarize 
    OperationCount = count(),
    Operations = make_set(ActionType)
    by AccountDisplayName, bin(Timestamp, 1h)
| where OperationCount > 50
| sort by OperationCount desc
```

#### Delegate/Permission Changes

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Add-MailboxPermission", "Add-RecipientPermission", "Set-Mailbox")
| where RawEventData has_any ("FullAccess", "SendAs", "SendOnBehalf", "GrantSendOnBehalfTo")
| extend ModifiedMailbox = tostring(parse_json(RawEventData).Parameters[0].Value)
| extend GrantedTo = tostring(parse_json(RawEventData).Parameters[1].Value)
| project Timestamp, AccountDisplayName, ActionType, ModifiedMailbox, GrantedTo, IPAddress
| sort by Timestamp desc
```
{% endcode %}

***

### Sent Email Analysis

#### Emails Sent to External Recipients

```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "Send"
| extend Recipients = tostring(parse_json(RawEventData).Recipients)
| where Recipients !has "yourdomain.com"
| summarize 
    ExternalSends = count(),
    Recipients = make_set(Recipients, 20)
    by AccountDisplayName, bin(Timestamp, 1d)
| where ExternalSends > 50
| sort by ExternalSends desc
```

#### Emails with Wire Transfer Keywords (Sent)

{% code overflow="wrap" %}
```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "Send"
| extend Subject = tostring(parse_json(RawEventData).Subject)
| where Subject has_any ("wire", "transfer", "payment", "bank account", "routing", "ACH")
| extend Recipients = tostring(parse_json(RawEventData).Recipients)
| project Timestamp, AccountDisplayName, Subject, Recipients, IPAddress
| sort by Timestamp desc
```
{% endcode %}

#### Unusual Sending Patterns (Off-Hours)

```kusto
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "Send"
| extend Hour = hourofday(Timestamp)
| extend DayOfWeek = dayofweek(Timestamp)
| where Hour < 6 or Hour > 22 or DayOfWeek in (0d, 6d)  // Off-hours or weekends
| summarize 
    OffHoursSends = count(),
    Subjects = make_set(tostring(parse_json(RawEventData).Subject), 10)
    by AccountDisplayName
| where OffHoursSends > 10
| sort by OffHoursSends desc
```

***

### Threat Intelligence Correlation

#### Known BEC Domains

```kusto
let becDomains = externaldata(Domain: string)
[@"https://your-threat-intel/bec-domains.csv"] with (format="csv");
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain in (becDomains)
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, DeliveryAction
```

#### Emails from Recently Registered Domains

{% code overflow="wrap" %}
```kusto
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| join kind=inner (
    // If you have domain age data in threat intel
    ThreatIntelligenceIndicator
    | where IndicatorType == "domain"
    | extend DomainAge = datetime_diff('day', now(), ExpirationDateTime)
    | where DomainAge < 30
    | project Domain = DomainName
) on $left.SenderFromDomain == $right.Domain
| project Timestamp, Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress
```
{% endcode %}

***

### Investigation Queries

#### Full Email Timeline for User

{% code overflow="wrap" %}
```kusto
let targetUser = "user@yourdomain.com";
let timeframe = 7d;
union
    (EmailEvents
    | where Timestamp > ago(timeframe)
    | where RecipientEmailAddress =~ targetUser or SenderFromAddress =~ targetUser
    | project Timestamp, EventType = "Email", Details = strcat(SenderFromAddress, " -> ", RecipientEmailAddress, ": ", Subject)),
    (CloudAppEvents
    | where Timestamp > ago(timeframe)
    | where AccountDisplayName =~ targetUser
    | where ActionType in ("Send", "MailItemsAccessed", "New-InboxRule", "Set-InboxRule")
    | project Timestamp, EventType = ActionType, Details = tostring(RawEventData)),
    (SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where UserPrincipalName =~ targetUser
    | where AppDisplayName has_any ("Outlook", "Exchange", "Office")
    | project Timestamp = TimeGenerated, EventType = "SignIn", Details = strcat(Location, " - ", IPAddress, " - ", AppDisplayName))
| sort by Timestamp asc
```
{% endcode %}

#### Identify All Emails in Fraudulent Thread

{% code overflow="wrap" %}
```kusto
let fraudSubject = "Re: Urgent Wire Transfer";
let timeframe = 30d;
EmailEvents
| where Timestamp > ago(timeframe)
| where Subject has fraudSubject or ConversationId == "conversation-id-here"
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, ConversationId
| sort by Timestamp asc
```
{% endcode %}

#### Cross-Reference Sign-ins with Email Activity

{% code overflow="wrap" %}
```kusto
let targetUser = "compromised@yourdomain.com";
let suspiciousIP = "1.2.3.4";
union
    (SigninLogs
    | where TimeGenerated > ago(7d)
    | where UserPrincipalName =~ targetUser
    | where IPAddress == suspiciousIP
    | project Timestamp = TimeGenerated, Activity = "SignIn", Details = strcat(AppDisplayName, " from ", Location))),
    (CloudAppEvents
    | where Timestamp > ago(7d)
    | where AccountDisplayName =~ targetUser
    | where IPAddress == suspiciousIP
    | project Timestamp, Activity = ActionType, Details = tostring(RawEventData))
| sort by Timestamp asc
```
{% endcode %}

***

## Response Actions & Remediation

### Immediate Response Actions

#### BEC Email Reported (No Action Taken)

<table><thead><tr><th width="147">Step</th><th>Action</th><th>Tool/Method</th></tr></thead><tbody><tr><td>1</td><td>Block sender domain</td><td>Exchange Admin / MDO</td></tr><tr><td>2</td><td>Delete email from all mailboxes</td><td>Threat Explorer - Soft Delete</td></tr><tr><td>3</td><td>Add domain to block list</td><td>MDO Tenant Allow/Block List</td></tr><tr><td>4</td><td>Submit to Microsoft</td><td>Report as phishing</td></tr><tr><td>5</td><td>Alert targeted users</td><td>Direct communication</td></tr><tr><td>6</td><td>Update email rules</td><td>Transport rules if needed</td></tr></tbody></table>

#### Account Compromise Confirmed

<table><thead><tr><th width="128">Step</th><th>Action</th><th>Tool/Method</th></tr></thead><tbody><tr><td>1</td><td>Reset password immediately</td><td>Entra ID / AD</td></tr><tr><td>2</td><td>Revoke all sessions</td><td><code>Revoke-MgUserSignInSession</code></td></tr><tr><td>3</td><td>Remove malicious inbox rules</td><td>Exchange Admin / PowerShell</td></tr><tr><td>4</td><td>Disable mail forwarding</td><td>Exchange Admin</td></tr><tr><td>5</td><td>Revoke OAuth app consents</td><td>Entra ID Enterprise Apps</td></tr><tr><td>6</td><td>Enable/Reset MFA</td><td>Entra ID</td></tr><tr><td>7</td><td>Review sent items</td><td>Search for fraudulent emails</td></tr><tr><td>8</td><td>Notify recipients of fraudulent emails</td><td>Direct contact</td></tr><tr><td>9</td><td>Block attacker IPs</td><td>Conditional Access</td></tr><tr><td>10</td><td>Monitor for re-compromise</td><td>Enhanced monitoring</td></tr></tbody></table>

#### Financial Fraud Occurred

<table><thead><tr><th width="135">Step</th><th>Action</th><th>Timeline</th></tr></thead><tbody><tr><td>1</td><td>Contact bank immediately</td><td>Within minutes</td></tr><tr><td>2</td><td>Request wire recall</td><td>ASAP (&#x3C; 24 hours critical)</td></tr><tr><td>3</td><td>Preserve all evidence</td><td>Immediately</td></tr><tr><td>4</td><td>File IC3 complaint</td><td>Same day</td></tr><tr><td>5</td><td>Notify cyber insurance</td><td>Same day</td></tr><tr><td>6</td><td>Engage law enforcement</td><td>If significant amount</td></tr><tr><td>7</td><td>Document everything</td><td>Ongoing</td></tr></tbody></table>

### PowerShell Remediation Commands

#### Account Containment

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ReadWrite.All", "Mail.ReadWrite"

# Block sign-in
Update-MgUser -UserId "user@domain.com" -AccountEnabled:$false

# Revoke all sessions
Revoke-MgUserSignInSession -UserId "user@domain.com"

# Reset password (requires additional permissions)
$newPassword = ConvertTo-SecureString "TempP@ssw0rd123!" -AsPlainText -Force
Update-MgUser -UserId "user@domain.com" -PasswordProfile @{
    Password = "TempP@ssw0rd123!"
    ForceChangePasswordNextSignIn = $true
}
```

#### Remove Malicious Inbox Rules

{% code overflow="wrap" %}
```powershell
# List all inbox rules
Get-InboxRule -Mailbox "user@domain.com" | Format-List Name, Description, Enabled, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder

# Remove specific rule
Remove-InboxRule -Mailbox "user@domain.com" -Identity "Rule Name" -Confirm:$false

# Remove ALL inbox rules (use with caution)
Get-InboxRule -Mailbox "user@domain.com" | Remove-InboxRule -Confirm:$false

# Check for forwarding
Get-Mailbox "user@domain.com" | Select-Object ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward

# Remove forwarding
Set-Mailbox "user@domain.com" -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false
```
{% endcode %}

#### Remove OAuth App Consents

```powershell
# List OAuth grants for user
$userId = (Get-MgUser -UserId "user@domain.com").Id
Get-MgUserOauth2PermissionGrant -UserId $userId | Format-List

# Get service principals with delegated permissions
$grants = Get-MgUserOauth2PermissionGrant -UserId $userId
foreach ($grant in $grants) {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId
    Write-Host "App: $($sp.DisplayName) - Scopes: $($grant.Scope)"
}

# Remove specific OAuth grant
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "grant-id"
```

#### Purge Malicious Emails

{% code overflow="wrap" %}
```powershell
# Using Compliance Search (Security & Compliance PowerShell)
Connect-IPPSSession

# Create search
New-ComplianceSearch -Name "BEC_Purge_$(Get-Date -Format 'yyyyMMdd')" `
    -ExchangeLocation All `
    -ContentMatchQuery 'from:attacker@malicious.com AND subject:"Wire Transfer Request"'

# Start search
Start-ComplianceSearch -Identity "BEC_Purge_$(Get-Date -Format 'yyyyMMdd')"

# Check status
Get-ComplianceSearch -Identity "BEC_Purge_$(Get-Date -Format 'yyyyMMdd')"

# Purge results (Soft Delete)
New-ComplianceSearchAction -SearchName "BEC_Purge_$(Get-Date -Format 'yyyyMMdd')" -Purge -PurgeType SoftDelete

# Purge results (Hard Delete - use with caution)
New-ComplianceSearchAction -SearchName "BEC_Purge_$(Get-Date -Format 'yyyyMMdd')" -Purge -PurgeType HardDelete
```
{% endcode %}

#### Block Sender Domain

{% code overflow="wrap" %}
```powershell
# Add to Tenant Block List
New-TenantAllowBlockListItems -ListType Sender -Block -Entries "malicious-domain.com" -NoExpiration

# Create transport rule to block domain
New-TransportRule -Name "Block BEC Domain - malicious-domain.com" `
    -FromAddressMatchesPatterns "@malicious-domain\.com$" `
    -DeleteMessage $true `
    -SetSCL 9
```
{% endcode %}

***

## Quick Reference Cards

### BEC Red Flags Checklist

#### Email Content Red Flags

* \[ ] Urgent or time-sensitive request
* \[ ] Request to bypass normal procedures
* \[ ] Request for secrecy ("don't tell anyone")
* \[ ] Changed payment/banking details
* \[ ] Gift card purchase request
* \[ ] W-2 or employee data request
* \[ ] Unusual sender for request type
* \[ ] Grammar/spelling inconsistent with sender
* \[ ] Generic greeting instead of personal

#### Technical Red Flags

* \[ ] External sender with internal display name
* \[ ] Reply-to differs from sender address
* \[ ] Newly registered domain (< 30 days)
* \[ ] Look-alike/typosquatted domain
* \[ ] Failed SPF/DKIM/DMARC
* \[ ] Sent from free email provider
* \[ ] Embedded links to credential harvest
* \[ ] Attachment with macro/script

#### Account Red Flags

* \[ ] Sign-in from new location
* \[ ] Impossible travel detected
* \[ ] New inbox rules created
* \[ ] Mail forwarding enabled
* \[ ] OAuth app with mail permissions
* \[ ] Legacy protocol authentication
* \[ ] Bulk email deletions
* \[ ] Off-hours activity

### Domain Analysis Quick Reference

<table><thead><tr><th width="187">Check</th><th width="205">Tool/Method</th><th>What to Look For</th></tr></thead><tbody><tr><td>Domain Age</td><td>WHOIS lookup</td><td>&#x3C; 30 days = suspicious</td></tr><tr><td>Registration</td><td>WHOIS</td><td>Privacy protection, unusual registrar</td></tr><tr><td>Similarity</td><td>Visual comparison</td><td>Typos, homoglyphs, hyphens</td></tr><tr><td>MX Records</td><td>DNS lookup</td><td>Legitimate mail infrastructure</td></tr><tr><td>SPF/DKIM/DMARC</td><td>Email headers</td><td>Pass/Fail status</td></tr><tr><td>Reputation</td><td>VirusTotal, URLVoid</td><td>Known malicious indicators</td></tr><tr><td>SSL Certificate</td><td>Browser/SSLLabs</td><td>Valid cert, matches domain</td></tr></tbody></table>

### Email Header Analysis

<table><thead><tr><th width="242">Header</th><th>What to Check</th></tr></thead><tbody><tr><td><code>From:</code></td><td>Display name vs. actual address</td></tr><tr><td><code>Reply-To:</code></td><td>Matches From? Different domain?</td></tr><tr><td><code>Return-Path:</code></td><td>Envelope sender, should match</td></tr><tr><td><code>Received:</code></td><td>Mail server path, originating IP</td></tr><tr><td><code>Authentication-Results:</code></td><td>SPF, DKIM, DMARC pass/fail</td></tr><tr><td><code>X-Originating-IP:</code></td><td>Sender's IP address</td></tr><tr><td><code>Message-ID:</code></td><td>Domain should match sender</td></tr><tr><td><code>X-MS-Exchange-*</code></td><td>Microsoft-specific headers</td></tr></tbody></table>

### Common BEC Phrases

<table><thead><tr><th width="172">Category</th><th>Example Phrases</th></tr></thead><tbody><tr><td><strong>Urgency</strong></td><td>"ASAP", "urgent matter", "time-sensitive", "need this today"</td></tr><tr><td><strong>Secrecy</strong></td><td>"keep this confidential", "between us", "don't discuss with others"</td></tr><tr><td><strong>Authority</strong></td><td>"CEO approved", "I've already authorized", "board decision"</td></tr><tr><td><strong>Unavailability</strong></td><td>"I'm in a meeting", "traveling", "can't talk now"</td></tr><tr><td><strong>Process Bypass</strong></td><td>"skip normal process", "exception this time", "I'll approve later"</td></tr><tr><td><strong>Financial</strong></td><td>"wire transfer", "updated bank details", "new account"</td></tr></tbody></table>

***

## Escalation Matrix

### Severity Classification

<table><thead><tr><th width="129">Severity</th><th width="443">Criteria</th><th>Response Time</th></tr></thead><tbody><tr><td>🔴 <strong>Critical</strong></td><td>Wire transfer sent, active ATO with ongoing fraud, multiple executives compromised</td><td>Immediate - 15 min</td></tr><tr><td>🟠 <strong>High</strong></td><td>Wire transfer requested (not sent), confirmed ATO, finance team targeted</td><td>30 min - 1 hour</td></tr><tr><td>🟡 <strong>Medium</strong></td><td>BEC attempt blocked, suspicious account activity, single user targeted</td><td>4 hours</td></tr><tr><td>🟢 <strong>Low</strong></td><td>Obvious spam/phishing, blocked by filters, no user interaction</td><td>Next business day</td></tr></tbody></table>

### Escalation Triggers

<table><thead><tr><th width="303">Condition</th><th>Escalation Level</th></tr></thead><tbody><tr><td>Wire transfer completed</td><td>DFIR + Legal + Finance + CISO</td></tr><tr><td>Wire transfer pending</td><td>Tier 2 SOC + Finance (urgent)</td></tr><tr><td>Executive account compromised</td><td>DFIR + Tier 2 SOC + CISO</td></tr><tr><td>Multiple accounts compromised</td><td>DFIR + Tier 2 SOC</td></tr><tr><td>Vendor compromise suspected</td><td>Tier 2 SOC + Procurement</td></tr><tr><td>Data exfiltration (W-2, PII)</td><td>DFIR + Legal + HR + Privacy</td></tr><tr><td>> $50,000 potential exposure</td><td>CISO + Legal + Finance</td></tr></tbody></table>

### External Notifications

<table><thead><tr><th width="189">Scenario</th><th>Notify</th><th>Timeline</th></tr></thead><tbody><tr><td>Wire fraud > $50,000</td><td>FBI IC3, Local FBI field office</td><td>Immediately</td></tr><tr><td>Any wire fraud</td><td>Bank fraud department</td><td>Immediately</td></tr><tr><td>Wire fraud</td><td>Cyber insurance carrier</td><td>Within 24 hours</td></tr><tr><td>Data breach (PII)</td><td>Legal for regulatory assessment</td><td>Within 24 hours</td></tr><tr><td>Vendor compromise</td><td>Affected vendor</td><td>After internal assessment</td></tr><tr><td>Customer impact</td><td>Affected customers</td><td>Per legal/regulatory requirements</td></tr></tbody></table>

***

## MITRE ATT\&CK Mapping

### Initial Access

<table><thead><tr><th>Technique</th><th width="125">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Phishing: Spearphishing Attachment</td><td>T1566.001</td><td>Malicious attachment to gain access</td><td>EmailAttachmentInfo, MDO alerts</td></tr><tr><td>Phishing: Spearphishing Link</td><td>T1566.002</td><td>Malicious link to credential harvest</td><td>EmailUrlInfo, UrlClickEvents</td></tr><tr><td>Phishing: Spearphishing via Service</td><td>T1566.003</td><td>Via LinkedIn, social media</td><td>User reports</td></tr><tr><td>Valid Accounts: Cloud Accounts</td><td>T1078.004</td><td>Compromised cloud credentials</td><td>SigninLogs anomalies</td></tr></tbody></table>

### Persistence

<table><thead><tr><th>Technique</th><th width="126">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Account Manipulation: Email Forwarding</td><td>T1098.002</td><td>Auto-forward to external</td><td>OfficeActivity, CloudAppEvents</td></tr><tr><td>Account Manipulation: Additional Cloud Roles</td><td>T1098.003</td><td>Grant additional permissions</td><td>AuditLogs</td></tr><tr><td>Office Application Startup: Outlook Rules</td><td>T1137.005</td><td>Malicious inbox rules</td><td>CloudAppEvents (New-InboxRule)</td></tr></tbody></table>

### Collection

<table><thead><tr><th>Technique</th><th width="113">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Email Collection: Local Email Collection</td><td>T1114.001</td><td>Export mailbox locally</td><td>OfficeActivity (Export)</td></tr><tr><td>Email Collection: Remote Email Collection</td><td>T1114.002</td><td>Access via compromised account</td><td>MailItemsAccessed</td></tr><tr><td>Email Collection: Email Forwarding Rule</td><td>T1114.003</td><td>Forward to attacker</td><td>Inbox rules with forward</td></tr></tbody></table>

### Impact

<table><thead><tr><th width="139">Technique</th><th width="69">ID</th><th width="250">Description</th><th>Detection</th></tr></thead><tbody><tr><td>Financial Theft</td><td>T1657</td><td>Wire fraud, invoice manipulation</td><td>User reports, email content analysis</td></tr></tbody></table>

### Relevant Reconnaissance

<table><thead><tr><th>Technique</th><th width="126">ID</th><th>Description</th><th>Detection</th></tr></thead><tbody><tr><td>Gather Victim Org Information</td><td>T1591</td><td>Research organization structure</td><td>N/A (external)</td></tr><tr><td>Gather Victim Identity Information: Email Addresses</td><td>T1589.002</td><td>Harvest email addresses</td><td>N/A (external)</td></tr><tr><td>Search Open Websites/Domains</td><td>T1593</td><td>Find org info publicly</td><td>N/A (external)</td></tr></tbody></table>

***

## Prevention & Hardening

### Email Security Configuration

#### DMARC Implementation

{% code overflow="wrap" %}
```bash
# DNS TXT Record for DMARC
_dmarc.yourdomain.com  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100"
```
{% endcode %}

| DMARC Policy   | Description    | Recommendation     |
| -------------- | -------------- | ------------------ |
| `p=none`       | Monitor only   | Initial deployment |
| `p=quarantine` | Send to spam   | Intermediate       |
| `p=reject`     | Block delivery | Production         |

#### Transport Rules for BEC Protection

```powershell
# Warn on external emails impersonating executives
New-TransportRule -Name "External Executive Impersonation Warning" `
    -FromScope NotInOrganization `
    -HeaderMatchesMessageHeader "From" `
    -HeaderMatchesPatterns "CEO Name|CFO Name|Controller Name" `
    -PrependSubject "[EXTERNAL - VERIFY SENDER] " `
    -SetSCL 5

# Block external senders using internal domain in display name
New-TransportRule -Name "Block Spoofed Internal Display Name" `
    -FromScope NotInOrganization `
    -HeaderMatchesMessageHeader "From" `
    -HeaderMatchesPatterns "@yourdomain\.com" `
    -DeleteMessage $true
```

#### Defender for Office 365 Configuration

| Feature              | Setting                         | Purpose                         |
| -------------------- | ------------------------------- | ------------------------------- |
| **Anti-phishing**    | Enable impersonation protection | Protect executives/VIPs         |
| **Anti-phishing**    | Enable mailbox intelligence     | Learn user patterns             |
| **Safe Links**       | Enable URL rewriting            | Protect against malicious links |
| **Safe Attachments** | Enable dynamic delivery         | Scan attachments                |
| **User reported**    | Enable report button            | Easy user reporting             |

### User Awareness Checklist

#### Training Topics

* \[ ] What is BEC and why it's dangerous
* \[ ] Recognising suspicious email characteristics
* \[ ] Verifying financial requests out-of-band
* \[ ] Reporting suspicious emails properly
* \[ ] Never sharing credentials via email
* \[ ] Recognising urgency manipulation

#### Verification Procedures

<table><thead><tr><th width="263">Request Type</th><th>Verification Method</th></tr></thead><tbody><tr><td>Wire transfer</td><td>Phone call to known number</td></tr><tr><td>Bank account change</td><td>In-person or video verification</td></tr><tr><td>Gift card purchase</td><td>Phone call to requester</td></tr><tr><td>W-2/Tax data</td><td>HR verification</td></tr><tr><td>Password/Credential</td><td>Never provide via email</td></tr><tr><td>Large purchases</td><td>Multi-person approval</td></tr></tbody></table>

***

## Appendix: Investigation Commands

### Email Header Analysis

{% code overflow="wrap" %}
```powershell
# Get message trace
Get-MessageTrace -SenderAddress "sender@domain.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

# Get detailed message trace
Get-MessageTraceDetail -MessageTraceId "message-trace-id" -RecipientAddress "recipient@yourdomain.com"

# Get message headers
$headers = Get-MessageTrace -MessageId "<message-id>" | Get-MessageTraceDetail
$headers | Where-Object {$_.Event -eq "Receive"} | Select-Object -ExpandProperty Data
```
{% endcode %}

### Mailbox Forensics

{% code overflow="wrap" %}
```powershell
# Search mailbox audit log
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
    -UserIds "user@yourdomain.com" `
    -Operations "New-InboxRule","Set-InboxRule","Set-Mailbox","MailItemsAccessed" `
    -ResultSize 1000

# Get mailbox folder statistics (identify hidden folders)
Get-MailboxFolderStatistics -Identity "user@yourdomain.com" | 
    Select-Object Name, FolderPath, ItemsInFolder, FolderSize |
    Sort-Object ItemsInFolder -Descending

# Get mailbox audit log (classic)
Search-MailboxAuditLog -Identity "user@yourdomain.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ShowDetails
```
{% endcode %}

### OAuth App Investigation

```powershell
# List all OAuth apps with mail permissions
$servicePrincipals = Get-MgServicePrincipal -All
foreach ($sp in $servicePrincipals) {
    $grants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id
    $mailGrants = $grants | Where-Object {$_.Scope -match "Mail"}
    if ($mailGrants) {
        Write-Host "App: $($sp.DisplayName)"
        Write-Host "  Scopes: $($mailGrants.Scope)"
        Write-Host "  ConsentType: $($mailGrants.ConsentType)"
        Write-Host ""
    }
}

# Get app role assignments
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "app-id" | 
    Select-Object AppRoleId, PrincipalDisplayName, CreatedDateTime
```

### Evidence Preservation

{% code overflow="wrap" %}
```powershell
# Export mailbox to PST (requires eDiscovery)
# Create eDiscovery case in Compliance Center first

# Export audit logs
$auditLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -UserIds "compromised@yourdomain.com" -ResultSize 5000
$auditLogs | Export-Csv "BEC_AuditLogs_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Export sign-in logs via Graph
$signIns = Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'compromised@yourdomain.com'" -Top 1000
$signIns | Export-Csv "BEC_SignIns_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Export inbox rules
$rules = Get-InboxRule -Mailbox "compromised@yourdomain.com"
$rules | Export-Csv "BEC_InboxRules_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```
{% endcode %}

### Bulk User Analysis

{% code overflow="wrap" %}
```powershell
# Check all users for forwarding rules
$mailboxes = Get-Mailbox -ResultSize Unlimited
$forwardingEnabled = @()

foreach ($mbx in $mailboxes) {
    if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) {
        $forwardingEnabled += [PSCustomObject]@{
            User = $mbx.UserPrincipalName
            ForwardingSmtpAddress = $mbx.ForwardingSmtpAddress
            ForwardingAddress = $mbx.ForwardingAddress
            DeliverToMailboxAndForward = $mbx.DeliverToMailboxAndForward
        }
    }
}

$forwardingEnabled | Export-Csv "Forwarding_Audit.csv" -NoTypeInformation

# Check all users for inbox rules with external forwarding
$allRules = @()
foreach ($mbx in $mailboxes) {
    $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue
    $suspiciousRules = $rules | Where-Object {
        $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage
    }
    foreach ($rule in $suspiciousRules) {
        $allRules += [PSCustomObject]@{
            User = $mbx.UserPrincipalName
            RuleName = $rule.Name
            ForwardTo = $rule.ForwardTo
            RedirectTo = $rule.RedirectTo
            DeleteMessage = $rule.DeleteMessage
            Enabled = $rule.Enabled
        }
    }
}

$allRules | Export-Csv "InboxRules_Audit.csv" -NoTypeInformation
```
{% endcode %}

***

> BEC attacks represent the highest financial risk category in cybercrime. Time is critical when wire transfers are involved. Always escalate potential wire fraud immediately—banks have limited windows to recall transfers (typically 24-48 hours, sometimes less).&#x20;
>
> Document everything meticulously for potential law enforcement involvement and insurance claims.
