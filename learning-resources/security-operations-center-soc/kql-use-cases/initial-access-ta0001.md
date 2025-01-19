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

# Initial Access (TA0001)

### **Sub-technique: T1078.001 - Default Accounts**

**Objective**: Detect unauthorised access using default accounts.&#x20;

1. **Default Account Logins**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents
| where AccountName in ("Administrator", "Guest", "root")
| summarize event_count = count() by AccountName, DeviceName, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, AccountName, DeviceName, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Monitor login events using default accounts.

2. **Detect Administrator Account Usage**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents
| where AccountName == "Administrator"
| summarize event_count = count() by DeviceName, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, DeviceName, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Identify unusual usage of the Administrator account.

3. **Guest Account Logins**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents
| where AccountName == "Guest"
| summarize event_count = count() by DeviceName, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, DeviceName, event_count
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect any use of the Guest account.

4. **Multiple Failed Login Attempts for Default Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents
| where AccountName in ("Administrator", "Guest", "root") and ActionType == "LogonFailed"
| summarize event_count = count() by AccountName, DeviceName, IPAddress, DestinationDeviceName, DestinationPort, DestinationIPAddress, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, AccountName, DeviceName, event_count, IPAddress, DestinationDeviceName, DestinationPort, DestinationIPAddress
| order by event_count desc
```
{% endcode %}

**Purpose**: Identify failed login attempts for default accounts.

5. **Detect Unauthorized Access Attempts to Default Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents 
| where AccountName in ("Administrator", "Guest") and LogonType != "Local"
| summarize event_count = count() by AccountName, DeviceName, IPAddress, DestinationDeviceName, DestinationPort, DestinationIPAddress, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, AccountName, DeviceName, event_count, IPAddress, DestinationDeviceName, DestinationPort, DestinationIPAddress
| order by event_count desc
```
{% endcode %}

**Purpose**: Detect remote access attempts to default accounts.

6. **Logins from Multiple IPs for Default Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents
| where AccountName in ("Administrator", "Guest")
| summarize event_count = count() by AccountName, IPAddress, TimeGenerated, DeviceName, LogonType
| where event_count > 1
| project AccountName, IPAddress, event_count, TimeGenerated, DeviceName, LogonType
| order by event_count desc
```
{% endcode %}

**Purpose**: Identify default account logins from multiple IPs.

7. **Identify Default Accounts with Elevated Privileges**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents
| where AccountName in ("Administrator", "Guest", "root") and ActionType == "LogonFailed"
| summarize event_count = count() by AccountName, IPAddress, DeviceName, LogonType, AccountDomain, OSPlatform, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, AccountName, IPAddress, event_count, DeviceName, LogonType, AccountDomain, OSPlatform
| order by event_count desc
```
{% endcode %}

**Purpose**: Monitor default accounts for elevation to administrative privileges.

8. **Detect Default Account Creation**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents
| where ActionType == "NewUserCreated" and AccountName in ("Administrator", "Guest")
| summarize event_count = count() by AccountName, DeviceName, AccountDomain, ActionType, DestinationDeviceName,DestinationIPAddress, Application, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, AccountName, DeviceName, event_count, AccountDomain, ActionType, DestinationDeviceName,DestinationIPAddress, Application
| order by event_count desc
```
{% endcode %}

**Purpose**: Identify the creation of default accounts.

9. **Detect Changes to Default Account Permissions**

{% code overflow="wrap" %}
```cs
IdentityDirectoryEvents
| where ActionType == "UserAccountControlChanged" and AccountName in ("Administrator", "Guest")
| summarize event_count = count() by AccountName, DeviceName, AccountDomain, ActionType, DestinationDeviceName,DestinationIPAddress, Application, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, AccountName, DeviceName, event_count, AccountDomain, ActionType, DestinationDeviceName,DestinationIPAddress, Application
| order by event_count desc
```
{% endcode %}

**Purpose**: Monitor for permission changes to default accounts.

10. **Detect Default Account Logins During Off-Hours**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents
| where AccountName in ("Administrator", "Guest") and (toint(format_datetime(TimeGenerated, 'HH')) < 6 or toint(format_datetime(TimeGenerated, 'HH')) > 18)
| summarize event_count = count() by AccountName, DeviceName, IPAddress, LogonType, AccountDomain, OSPlatform, bin(TimeGenerated, 1h)
| where event_count > 1
| project TimeGenerated, AccountName, DeviceName, event_count, IPAddress, LogonType, AccountDomain, OSPlatform
| order by event_count desc
```
{% endcode %}

**Purpose**: Identify off-hour logins using default accounts.
