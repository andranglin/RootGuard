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

# Account Usage

## <mark style="color:blue;">Authentication Events</mark>

**Description:** Authentication Events identify where authentication of credentials occurred. They can be particularly useful when tracking local vs. domain account usage.&#x20;

**Location:**

```cs
%SYSTEM ROOT%\System32\winevt\logs\Security.evtx
```

**Interpretation:**

* Recorded on the system that authenticated credential
* Local Account/Workgroup = on workstation
* Domain/Active Directory = on the domain controller
* Event ID Codes (NTLM protocol)
* 4776: Successful/Failed account authentication
* Event ID Codes (Kerberos protocol)
* 4768: Ticket Granting Ticket was granted (successful logon)
* 4769: Service Ticket requested (access to server resource)
* 4771: Pre-authentication failed (failed logon)

## <mark style="color:blue;">Logon Event Types</mark>

**Description:** Logon Events provide very specific information regarding the nature of account authorizations on a system. In addition to date, time, username, hostname, and success/failure status of a logon, Logon Events also enable us to determine by exactly what means a logon was attempted.&#x20;

**Location:**

```cs
%SYSTEM ROOT%\System32\winevt\logs\Security.evtx
```

**Interpretation:** Event ID 4624 **Logon Type Explanation** 2 Logon via console 3 Network Logon 4 Batch Logon 5 Windows Service Logon 7 Credentials used to unlock screen; **RDP session reconnect** 8 Network logon sending credentials (cleartext) 9 Different credentials used than logged on user 10 Remote interactive logon (RDP) 11 Cached credentials used to logon 12 Cached remote interactive (similar to Type 10) 13 Cached unlock (similar to Type 7)

## <mark style="color:blue;">User Accounts</mark>

**Description:** Identify local and domain accounts with interactive logins to the system.&#x20;

**Location:**

```cs
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
```

**Interpretation:**

* Useful for mapping SID to user account name
* Subkeys are named for user SIDs and contain a ProfileImagePath indicating the user’s profile path

## <mark style="color:blue;">Remote Desktop Protocol (RDP) Usage</mark>

**Description:** Track RDP logons and session reconnections to target machines.&#x20;

**Location:**

**Security Log**

```cs
%SYSTEM ROOT%\System32\winevt\logs\Security.evtx
```

**Interpretation:**

* Multiple events can be used to track accounts used for RDP
* Event ID 4624 – Logon Type 10
* Event ID 4778 – Session Connected/Reconnected
* Event ID 4779 – Session Disconnected
* Event log provides the hostname and IP address of the remote machine making the connection.
* Multiple dedicated RDP/Terminal Services logs are also available on modern Windows versions

## <mark style="color:blue;">RDP Bitmap Cache (BMC)</mark>

**Description:** RDP is a known protocol developed by Microsoft that allows users to connect to other Windows operating systems with GUI. RDP Bitmap Cache was implemented to enhance the RDP user experience and reduce the data throughput on the network. It stores bitmap-sized images of RDP sessions into a file so that the session reuses these images and reduces the potential lag.

**Location:**

```cs
%USERPROFILE%\AppData\Local\Microsoft\Terminal Server Client\Cache
```

**Tools For Investigation:**

```cs
bitmapcacheviewer.exe
bmc-tools .py
```

**Forensic Value:**

1. RDP session photos, screenshots, images, captures
2. RDP activity evidence, in the case of the target system,  the artifact is collected from the client side

## <mark style="color:blue;">Successful/Failed Logons</mark>

**Description:** Profile account creation, attempted logons, and account usage.&#x20;

**Location:**

```cs
% SYSTEM ROOT%\System32\winevt\logs\Security.evtx
```

**Interpretation:**

* 4624 – Successful Logon
* 4625 – Failed Logon
* 4634 | 4647 – Successful Logoff
* 4648 – Logon using explicit credentials (runas)
* 4672 – Account logon with superuser rights (Administrator)
* 4720 – An account was created

## <mark style="color:blue;">Last Login and Password Change</mark>

**Description:** The SAM registry hive maintains a list of local accounts and associated configuration information and it Lists the last time the password of a specific local user has been changed.&#x20;

**Location:**

```cs
C:\Windows\system32\config\SAM
SAM\Domains\Account\Users
```

**Interpretation:**

* Accounts listed by their relative identifiers (RID)
* Last login time, last password change, login counts, group membership, account creation time and more can be determined
* Only the last logon and password change time will be stored in the registry key

## <mark style="color:blue;">NTUSER.DAT</mark>

**Description:** It’s a hidden file in every user profile and contains the settings and preferences for each user. Windows accomplishes this by first storing that information in the Registry in the _HKEY\_CURRENT\_USER_ hive. Then, when the user signs out or shuts down, Windows saves that information to the NTUSER.DAT file. The next time the user sign in, Windows will load _NTUSER.DAT_ to memory, and all preferences load to the Registry again.

**Location:**

```cs
C:\Users\<username>\NTUSER.DAT
```

**Tools For Investigation:**

RegRipper (rr. exe) , RECmd.exe , RegistryExplorer.exe

```
RECmd.exe --f "C:\Temp\UsrClass 1.dat" --sk URL --recover false --nl
RECmd.exe --f "D:\temp\UsrClass 1.dat" --StartDate "11/13/2014 15:35:01"
RECmd.exe --f "D:\temp\UsrClass 1.dat" --RegEx --sv "(App|Display)Name"
```

**Forensic Value:**

1. Collecting registry hive ( HKEY\_CURRENT\_ USER) through its supporting file ( NTUSER.DAT)
2. Forensic data user activity, setting via registry hive
3. Forensic artifacts (Recent Docs, Typed URLs, UserAssist, Recent Apps, Run and Run Once, ComDig32 Subkey, Typed Paths Subkey, Microsoft Office applications and the MRU subkey, RunMRU, Windows search function and the WordWheelQuery

## <mark style="color:blue;">Security Account Manager (SAM)</mark>

**Description** Security Account Manager (SAM) is a database file in Windows that stores users' passwords. It can be used to authenticate local and remote users. SAM uses cryptographic measures to prevent unauthenticated users from accessing the system. The user passwords are stored in a hashed format in a registry hive, either as an LM or NTLM hash.

**Location:**

```cs
C:\Windows\System32\config\SAM
```

**Tools For Investigation:**

RegRipper (rr. exe), samparser.py

**Forensic Value:**

1. User information
2. Group information
3. Authentication information
4. User’s security settings
5. Login count

## <mark style="color:blue;">User Access Logging (UAL)</mark>

**Description:** UAL is a feature included by default in _Server editions of Microsoft Windows_ only, starting with Server 2012. Microsoft defines UAL as a feature that logs unique client access requests, in the form of IP addresses and usernames, of installed products and roles on the local server.

**Location:**

```cs
C:\Windows\System32\LogFiles\Sum\*.mdb
```

**Tools For Investigation:**

SumECmd.exe, KStrike.py

```cs
SumECmd.exe -d "C:\Temp\sum" --csv "C:\Temp\"
```

**Forensic Value:**

1. Service accessed
2. The user account that performed the access
3. User’s source IP
4. Last Access Time
5. Total Accesses
6. Type of authentication access

### <mark style="color:blue;">Cloud Account Details</mark>

**Description:** Microsoft Cloud Accounts stores account information in the SAM hive, including the email address associated with the account.&#x20;

**Location:**

```cs
SAM\Domains\Account\Users\<RID>\InternetUserName
```

**Interpretation:**

* InternetUserName value contains the email address tied to the account
* The presence of this value identifies the account as a Microsoft cloud account

## <mark style="color:blue;">Last Login and Password Change</mark>

**Description:** The SAM registry hive maintains a list of local accounts and associated configuration information.&#x20;

**Location:**

* SAM\Domains\Account\Users **Interpretation**
* Accounts listed by their relative identifiers (RID)
* Last login time, last password change, login counts, group membership, account creation time and more can be determined.

### <mark style="color:blue;">Service Events</mark>

**Description:** Analyse logs for suspicious Windows service creation, persistence, and services that started or stopped around the time of a suspected compromise. Service events also record account information.&#x20;

**Location:**

```cs
%SYSTEM ROOT%\System32\winevt\logs\System.evtx
%SYSTEM ROOT%\System32\winevt\logs\Security.evtx
```

**Interpretation:**

* Most relevant events are present in the System Log:
* 7034 – Service crashed unexpectedly
* 7035 – Service sent a Start/Stop control
* 7036 – Service started or stopped
* 7040 – Start type changed (Boot | On Request | Disabled)
* 7045 – A service was installed on the system (Win2008R2+)
* Auditing can be enabled in the Security log on Win10+:
* 4697 – A service was installed on the system (from Security log)
* A large amount of malware and worms in the wild utilize Services
* Services started on boot illustrate persistence (desirable in malware)
* Services can crash due to attacks like process injection
