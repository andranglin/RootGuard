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

# Credential Access (TA0006) Techniques

Credential Access techniques involve adversaries attempting to steal account credentials such as usernames and passwords.

### <mark style="color:blue;">**1. T1003 - OS Credential Dumping**</mark>

**Objective**: Detect attempts to extract credentials stored on the operating system, such as those in memory, registries, or files.&#x20;

1. **Detect LSASS Memory Dump**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "procdump.exe" and ProcessCommandLine has "lsass" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of tools like `procdump.exe` to dump the memory of the LSASS process.

2. **Monitor for Mimikatz Execution**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("mimikatz", "sekurlsa::logonpasswords") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the execution of Mimikatz, a tool commonly used for credential dumping.

3. **Identify SAM Registry Hive Extraction**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("reg save", "sam", "SYSTEM") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for attempts to extract the SAM registry hive, which contains password hashes.

4. **Detect NTDS.dit File Access**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName == "NTDS.dit" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to the NTDS.dit file, which stores Active Directory credentials.

5. **Monitor for Use of Volume Shadow Copy Service (VSS)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("vssadmin", "shadowcopy", "ntds.dit") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of VSS to copy the NTDS.dit file or other sensitive files.

6. **Identify Use of DCSync to Replicate Domain Credentials**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "dcsync" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for DCSync attacks that attempt to replicate domain credentials from a domain controller.

7. **Detect Use of CrackMapExec**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "CrackMapExec" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of CrackMapExec, a tool often used for credential dumping and lateral movement.

8. **Monitor for Unauthorized Access to LSASS**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where FileName == "lsass.exe" and InitiatingProcessCommandLine has_any ("mimikatz", "procdump", "taskmgr", "process hacker") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect unauthorized processes accessing the LSASS process.

9. **Identify Suspicious Registry Reads**

{% code overflow="wrap" %}
```cs
DeviceRegistryEvents | where RegistryKey has_any ("HKLM\\SAM", "HKLM\\SYSTEM") and InitiatingProcessFileName != "services.exe" | project Timestamp, DeviceName, RegistryKey, RegistryValueName, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for unauthorized registry reads that could indicate credential dumping.

10. **Detect Password Extraction via PowerShell**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-ADReplAccount", "Get-Credential", "Export-Credential") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify PowerShell commands that attempt to extract or export credentials.

### <mark style="color:blue;">**2. T1110 - Brute Force**</mark>

**Objective**: Detect attempts to gain unauthorized access to accounts by systematically guessing passwords.&#x20;

1. **Detect Multiple Failed Logon Attempts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" | summarize FailedAttempts = count() by AccountName, DeviceName | where FailedAttempts > 10 | project Timestamp, AccountName, DeviceName, FailedAttempts
```
{% endcode %}

_Purpose_: Identify accounts experiencing multiple failed logon attempts, which may indicate brute force attempts.

2. **Monitor for Suspicious RDP Logon Failures**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonType == "RemoteInteractive" and LogonResult == "Failed" | summarize FailedAttempts = count() by AccountName, DeviceName | where FailedAttempts > 5 | project Timestamp, AccountName, DeviceName, FailedAttempts
```
{% endcode %}

_Purpose_: Detect failed RDP logon attempts that may be part of a brute force attack.

3. **Identify Brute Force Attempts on Service Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName startswith "svc_" and LogonResult == "Failed" | summarize FailedAttempts = count() by AccountName, DeviceName | where FailedAttempts > 5 | project Timestamp, AccountName, DeviceName, FailedAttempts`
```
{% endcode %}

_Purpose_: Monitor for brute force attempts targeting service accounts.

4. **Detect SSH Brute Force Attempts**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort == 22 and ActionType == "NetworkSessionDenied" | summarize FailedAttempts = count() by RemoteIP, DeviceName | where FailedAttempts > 10 | project Timestamp, RemoteIP, DeviceName, FailedAttempts
```
{% endcode %}

_Purpose_: Identify SSH brute force attempts based on denied network sessions.

5. **Monitor for Brute Force Attempts Against Local Admin Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName == "Administrator" and LogonResult == "Failed" | summarize FailedAttempts = count() by AccountName, DeviceName | where FailedAttempts > 3 | project Timestamp, AccountName, DeviceName, FailedAttempts
```
{% endcode %}

_Purpose_: Detect brute force attempts targeting the local Administrator account.

6. **Identify Use of Automated Brute Force Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("Hydra", "Medusa", "Ncrack") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the execution of automated brute force tools.

7. **Detect Unusual Account Lockouts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "AccountLocked" | summarize LockoutCount = count() by AccountName, DeviceName | where LockoutCount > 1 | project Timestamp, AccountName, DeviceName, LockoutCount
```
{% endcode %}

_Purpose_: Identify accounts that have been locked out due to repeated failed logon attempts.

8. **Monitor for Failed Logons Across Multiple Devices**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where LogonResult == "Failed" | summarize FailedAttempts = count() by AccountName | where FailedAttempts > 10 | project Timestamp, AccountName, FailedAttempts
```
{% endcode %}

_Purpose_: Detect failed logon attempts occurring across multiple devices, which may indicate distributed brute force attacks.

9. **Identify Unusual Logon Attempts by Non-Admin Accounts**

{% code overflow="wrap" %}
```cs
IdentityLogonEvents | where AccountName has_not_any ("admin", "administrator") and LogonResult == "Failed" | summarize FailedAttempts = count() by AccountName, DeviceName | where FailedAttempts > 5 | project Timestamp, AccountName, DeviceName, FailedAttempts
```
{% endcode %}

_Purpose_: Monitor for brute force attempts targeting non-administrative accounts.

10. **Detect Brute Force Attempts on Remote Access Services**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemotePort in (3389, 22, 443) and ActionType == "NetworkSessionDenied" | summarize FailedAttempts = count() by RemoteIP, DeviceName | where FailedAttempts > 10 | project Timestamp, RemoteIP, DeviceName, FailedAttempts
```
{% endcode %}

_Purpose_: Identify brute force attempts targeting remote access services such as RDP, SSH, or VPN.

### <mark style="color:blue;">**3. T1555 - Credentials from Password Stores**</mark>

**Objective**: Detect attempts to access or extract credentials stored in password stores or credential managers.&#x20;

1. **Detect Access to Windows Credential Manager**

{% code overflow="wrap" %}
```csharp
DeviceProcessEvents | where ProcessCommandLine has "cmdkey" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to access credentials stored in the Windows Credential Manager using `cmdkey`.

2. **Monitor for Access to the Windows Vault**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Vault" and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to access files within the Windows Vault directory.

3. **Identify Use of Browsing Data Extraction Tools**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("WebBrowserPassView", "ChromePass", "FirefoxDecrypt") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the execution of tools designed to extract credentials from web browsers.

4. **Detect Access to LSA Secrets**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "secretsdump.py" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to dump LSA secrets using tools like `secretsdump.py`.

5. **Monitor for PowerShell Credential Dumping Commands**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Get-Credential", "Export-Credential") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect PowerShell commands attempting to dump or export credentials.

6. **Identify Suspicious Access to Keychain on macOS (if applicable)**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "security find-generic-password" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for suspicious access to the macOS Keychain, which stores user credentials.

7. **Detect Access to Saved Passwords in Web Browsers**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("\\AppData\\Local\\Google\\Chrome\\User Data", "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles") and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to access files associated with saved passwords in web browsers.

8. **Monitor for Unusual Access to DPAPI Master Keys**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Protect" and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect access to DPAPI (Data Protection API) master keys, which are used to protect stored credentials.

9. **Identify Access to Password-Protected Archives**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension in (".zip", ".rar", ".7z") and ProcessCommandLine has "password" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for attempts to access or extract credentials from password-protected archives.

10. **Detect Access to Credential Files in Remote Desktop Clients**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Remote Desktop" and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to credential files stored by Remote Desktop clients.

### <mark style="color:blue;">**4. T1552 - Unsecured Credentials**</mark>

**Objective**: Detect attempts to locate or use unsecured credentials, such as plaintext passwords or keys, stored in files or environment variables.&#x20;

1. **Detect Access to Plaintext Credential Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension in (".txt", ".log", ".conf", ".ini") and FileName has_any ("password", "credentials", "creds") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to files that may contain plaintext credentials.

2. **Monitor for Environment Variables Containing Credentials**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("$env:AWS_SECRET_ACCESS_KEY", "$env:AZURE_CLIENT_SECRET") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect commands that access environment variables containing credentials.

3. **Identify Access to SSH Private Keys**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension == ".pem" or FileName contains "id_rsa" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for access to SSH private keys that may be stored insecurely.

4. **Detect Access to Cloud Provider Credential Files**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has_any ("aws_credentials", "azure_credentials", "gcloud_credentials.json") | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to access cloud provider credential files.

5. **Monitor for Access to Hardcoded Credentials in Scripts**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension in (".ps1", ".sh", ".bat") and FileContent contains "password" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect access to scripts that may contain hardcoded credentials.

6. **Identify Use of Commands to Dump Stored Credentials**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("gpg --decrypt", "openssl rsa") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for the use of commands that could decrypt stored credentials.

7. **Detect Access to Credential Files in Version Control**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any (".git", ".svn") and FileName contains "credentials" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to credential files stored in version control systems.

8. **Monitor for Access to SQL Connection Strings**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileExtension in (".config", ".json", ".xml") and FileContent contains "ConnectionString" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

{% code overflow="wrap" %}
```
_Purpose_: Detect access to configuration files that may contain SQL connection strings with embedded credentials.
```
{% endcode %}

9\. **Identify Download of Publicly Exposed Credential Files**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl contains "/secrets/" or "/credentials/" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for downloads from URLs that may expose unsecured credentials.

10. **Detect Unencrypted Passwords Stored in Browser Extensions**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("Chrome\\Extensions", "Firefox\\Profiles") and FileContent contains "password" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify access to browser extensions that may store unencrypted passwords.

### <mark style="color:blue;">**5. T1111 - Two-Factor Authentication Interception**</mark>

**Objective**: Detect attempts to intercept or bypass two-factor authentication (2FA) mechanisms.&#x20;

1. **Detect Attempts to Access 2FA Backup Codes**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has "2fa_backup_codes" and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to access files containing 2FA backup codes.

2. **Monitor for Unusual 2FA Push Notifications**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP has_any ("authy.com", "duosecurity.com", "google.com") and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteIP, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect suspicious 2FA push notifications that may indicate interception.

3. **Identify Phishing Attacks Targeting 2FA Credentials**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl has_any ("2fa", "auth", "otp") and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for phishing attempts that target 2FA credentials.

4. **Detect Access to OTP Generator Apps**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("Google Authenticator", "Authy", "Microsoft Authenticator") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to access or interact with OTP generator apps.

5. **Monitor for Unusual 2FA Verification Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteIP in ("216.58.0.0/16", "23.45.0.0/16") and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteIP, RequestMethod, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect unusual or repeated 2FA verification requests that may indicate interception attempts.

6. **Identify Attempts to Modify 2FA Settings**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("disable_2fa", "remove_otp", "change_auth_method") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for attempts to disable or modify 2FA settings.

7. **Detect Use of Tools for 2FA Interception**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("evilginx", "Modlishka", "man-in-the-middle") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify the use of tools designed to intercept 2FA tokens.

8. **Monitor for Access to 2FA Secret Keys**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName contains "otp_secret" and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect access to files containing 2FA secret keys.

9. **Identify Access to SIM Cards or Mobile Devices**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("SIM", "phone", "mobile device") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for attempts to intercept 2FA by accessing SIM cards or mobile devices.

10. **Detect Cloning or Reprovisioning of 2FA Devices**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("clone_device", "reprovision", "generate_otp") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to clone or reprovision devices used for generating 2FA codes.

### <mark style="color:blue;">**6. T1528 - Steal Application Access Token**</mark>

**Objective**: Detect attempts to steal or use application access tokens to gain unauthorized access to resources.&#x20;

1. **Detect Unusual Access to OAuth Tokens**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName contains "oauth" and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to access OAuth tokens stored on the system.

2. **Monitor for Use of Stolen Access Tokens**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl has_any ("token", "access_token") and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect the use of stolen access tokens to authenticate API requests.

3. **Identify Access to Web Browser Session Tokens**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FolderPath has_any ("\\AppData\\Local\\Google\\Chrome\\User Data", "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles") and FileName contains "session" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for access to files containing web browser session tokens.

4. **Detect Token Injection Attempts**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "Invoke-RestMethod" and ProcessCommandLine has "Authorization: Bearer" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to inject stolen tokens into API requests.

5. **Monitor for Access Token Replay Attacks**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl has "api" and RequestHeaders contains "Authorization: Bearer" | project Timestamp, DeviceName, RemoteUrl, RequestHeaders, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect replay of stolen access tokens in API requests.

6. **Identify Unusual Use of JWT Tokens**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has "jwt" | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for suspicious usage of JWT (JSON Web Tokens) which might indicate token theft.

7. **Detect Unauthorized Access to Cloud Provider Tokens**

{% code overflow="wrap" %}
```cs
DeviceFileEvents | where FileName has_any ("gcloud", "aws", "azure") and FileOperation == "Read" | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify unauthorized access to cloud provider tokens stored on the system.

8. **Monitor for Attempts to Export Access Tokens**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("export_token", "extract_token") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Detect attempts to export or extract access tokens from applications.

9. **Identify Suspicious OAuth Token Refresh Requests**

{% code overflow="wrap" %}
```cs
DeviceNetworkEvents | where RemoteUrl has "refresh_token" and RequestMethod == "POST" | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Monitor for unusual or repeated OAuth token refresh requests.

10. **Detect Malicious Token Exchange Processes**

{% code overflow="wrap" %}
```cs
DeviceProcessEvents | where ProcessCommandLine has_any ("token_exchange", "exchange_token") | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```
{% endcode %}

_Purpose_: Identify attempts to perform token exchange processes that may be part of an attack.
