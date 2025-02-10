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

# Windows Security Logs (Identity and Logon Activities)

**Note: Sometimes, you may have to customise the queries to your environment. Also, queries will only work if the data is available.**

### **Windows Security Logs (Identity and Logon Activities)**

**Overview:**

Windows Security Logs contain rich information about identity and logon activities. These logs are crucial for detecting unauthorized logons, privilege escalation, and lateral movement.

**25 Example Queries for Identity and Logon Activities:**

1. **Track Successful Logon Events (Event ID 4624)**\
   &#xNAN;_&#x45;vent ID 4624 records successful logon events, which can be analyzed for suspicious activity._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where ActionType == "LogonSuccess" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

2. **Monitor Failed Logon Attempts (Event ID 4625)**\
   &#xNAN;_&#x4D;ultiple failed logon attempts may indicate a brute force attack._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where ActionType == "LogonFailed" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

3. **Track Interactive Logons (LogonType 2, Event ID 4624)**\
   &#xNAN;_&#x49;nteractive logons are physical or RDP logons to a system._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "Interactive" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

4. **Detect Use of Service Accounts for Logon (LogonType 5)**\
   &#xNAN;_&#x53;ervice accounts may be used to maintain persistence within the network._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "Service" | summarize count() by AccountName, DeviceName
```
{% endcode %}

5. **Monitor Privileged Logons (Event ID 4672)**\
   &#xNAN;_&#x50;rivileged accounts logon events can be tracked for signs of abuse._

```cs
DeviceEvents | where EventID == 4672 | summarize count() by AccountName, DeviceName
```

6. **Detect Kerberos Logon Failures (Event ID 4771)**\
   &#xNAN;_&#x46;ailed Kerberos logon attempts may indicate credential theft or brute force attacks._

{% code overflow="wrap" %}
```cs
DeviceEvents | where EventID == 4771 | summarize count() by AccountName, DeviceName, FailureReason
```
{% endcode %}

7. **Track NTLM Logon Events (Event ID 4624)**\
   &#xNAN;_&#x4E;TLM logons can be used for lateral movement through pass-the-hash attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "NTLM" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

8. **Monitor Account Lockout Events (Event ID 4740)**\
   &#xNAN;_&#x41;ccount lockouts may indicate attempted brute force attacks or credential theft._

{% code overflow="wrap" %}
```cs
DeviceEvents | where EventID == 4740 | summarize count() by AccountName, DeviceName, TargetAccountName
```
{% endcode %}

9. **Detect Logon Events During Unusual Hours**\
   &#xNAN;_&#x55;nusual logon times may indicate unauthorized access outside of business hours._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where todatetime(Timestamp) between (datetime(01:00) .. datetime(05:00)) | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

10. **Track Interactive Logon Failures (LogonType 2)**\
    &#xNAN;_&#x46;ailed interactive logons may indicate unauthorized attempts to access a system._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "Interactive" and ActionType == "LogonFailed" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

11. **Detect Unusual Logon Locations for Users (GeoLocation Analysis)**\
    &#xNAN;_&#x55;sers logging in from unusual locations may indicate credential compromise._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | summarize count() by AccountName, DeviceName, GeoLocation | where GeoLocation != "expected_location"
```
{% endcode %}

12. **Monitor Remote Logons Using RDP (Event ID 4624, LogonType 10)**\
    &#xNAN;_&#x52;emote logons using RDP may be an indication of lateral movement or remote access attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType == "RemoteInteractive" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

13. **Detect Unsuccessful Logon Attempts for Privileged Accounts**\
    &#xNAN;_&#x46;ailed logon attempts for admin accounts may indicate credential guessing or brute force attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName contains "admin" and ActionType == "LogonFailed" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

14. **Track Use of Temporary or Guest Accounts for Logon**\
    &#xNAN;_&#x54;emporary or guest accounts being used for logon may indicate unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName contains "guest" or AccountName contains "temp" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

15. **Monitor Use of Smartcards for Logon (Event ID 4776)**\
    &#xNAN;_&#x4C;ogons using smartcards can be tracked to ensure they are legitimate._

{% code overflow="wrap" %}
```cs
DeviceEvents | where EventID == 4776 | summarize count() by AccountName, DeviceName
```
{% endcode %}

16. **Detect Logon Attempts Using Stale Credentials (Expired Passwords)**\
    &#xNAN;_&#x52;epeated attempts to logon with expired credentials may indicate an attacker is using stolen credentials._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where Status == "ExpiredPassword" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

17. **Track Failed Logon Attempts Due to Bad Passwords**\
    &#xNAN;_&#x42;ad password failures may indicate a brute force or credential stuffing attack._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where Status == "BadPassword" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

18. **Monitor Use of Shadow Credentials for Logon Attempts**\
    &#xNAN;_&#x53;hadow credentials (e.g., certificate-based) may be used for unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "Certificate" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

19. **Track Successful Logons Using Unusual Account Types (Service, System)**\
    &#xNAN;_&#x55;nusual logon types may indicate an attacker is using system or service accounts._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where LogonType in ("Service", "System") | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

20. **Detect Multiple Logon Attempts from a Single IP Address (Credential Stuffing)**\
    &#xNAN;_&#x4D;ultiple logon attempts from the same IP may indicate credential stuffing attacks._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | summarize count() by RemoteIP, AccountName | where count_ > 10
```
{% endcode %}

21. **Monitor Use of Administrative Accounts for Interactive Logons**\
    &#xNAN;_&#x49;nteractive logons using administrative accounts can be tracked for unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName contains "admin" and LogonType == "Interactive" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

22. **Track Unusual Authentication Attempts Using NTLM (Event ID 4624)**\
    &#xNAN;_&#x4E;TLM authentication may be used for lateral movement or unauthorized access._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AuthenticationPackage == "NTLM" | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

23. **Detect Logons Using Expired or Disabled Accounts**\
    &#xNAN;_&#x4C;ogon attempts using disabled or expired accounts may indicate account compromise._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where Status in ("ExpiredAccount", "DisabledAccount") | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

24. **Monitor Logon Attempts Using Compromised Accounts (Known Breaches)**\
    &#xNAN;_&#x4B;nown compromised accounts from breaches can be monitored for logon attempts._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName in (list_of_compromised_accounts) | summarize count() by AccountName, DeviceName, RemoteIP
```
{% endcode %}

25. **Track Use of Anonymous Logon Accounts (Event ID 4624, Account: ANONYMOUS)**\
    &#xNAN;_&#x41;nonymous logon attempts may indicate unauthorized access attempts._

{% code overflow="wrap" %}
```cs
DeviceLogonEvents | where AccountName == "ANONYMOUS LOGON" | summarize count() by DeviceName, RemoteIP
```
{% endcode %}
