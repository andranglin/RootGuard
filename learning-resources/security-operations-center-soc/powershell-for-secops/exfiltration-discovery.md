---
hidden: true
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

# Exfiltration Discovery

### Exfiltration Discovery

#### 1. **Network Traffic and Connection Monitoring**

**1.1. Detecting Large Data Transfers**

**Purpose**: Identify large data transfers to external IP addresses, which may indicate data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{n='DataTransferred';e={($_.OwningProcess).ToString()}}
```
{% endcode %}

**1.2. Monitoring Unusual Outbound Connections**

**Purpose**: Detect outbound connections to suspicious or uncommon destinations.

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notin 'KnownGoodIPs'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort
```
{% endcode %}

#### 2. **Cloud Storage and Remote Access**

**2.1. Detecting Access to Cloud Storage Services**

**Purpose**: Monitor for access to cloud storage platforms like Dropbox, Google Drive, and OneDrive.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'Dropbox|GoogleDrive|OneDrive'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**2.2. Monitoring for File Uploads to Remote Servers**

**Purpose**: Identify file uploads to remote servers, which may indicate exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[8].Value -match 'File Write'} | Select-Object TimeCreated, @{n='ObjectName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### 3. **Email-Based Exfiltration**

**3.1. Detecting Large Email Attachments**

**Purpose**: Identify large email attachments that may contain exfiltrated data.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-EventLog/Email" | Where-Object {($_.Message -match 'Attachment: ') -and ($_.Message -match '[0-9]{5,} bytes')} | Select-Object TimeCreated, @{n='Attachment';e={$_.Message -match 'Attachment: (.*)' -replace 'Attachment: '}}
```
{% endcode %}

**3.2. Monitoring Use of Personal Email Accounts**

**Purpose**: Detect the use of personal email accounts for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" | Where-Object {($_.Message -match 'Subject: ') -and ($_.Message -match '@gmail.com|@yahoo.com')} | Select-Object TimeCreated, @{n='Recipient';e={$_.Message -match 'Recipient: (.*)' -replace 'Recipient: '}}
```
{% endcode %}

#### 4. **USB and Removable Media**

**4.1. Detecting USB Device Insertions**

**Purpose**: Monitor the insertion of USB devices, which may be used for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=20001} | Where-Object {$_.Message -match 'USB'} | Select-Object TimeCreated, @{n='Device';e={$_.Message -match 'Device: (.*)' -replace 'Device: '}}
```
{% endcode %}

**4.2. Monitoring File Transfers to USB Drives**

**Purpose**: Detect file transfers to USB devices.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match 'E:\\'} |  # Assuming E: is the USB drive letter Select-Object TimeCreated, @{n='FileName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### 5. **Compression and Encryption**

**5.1. Detecting Use of Compression Tools**

**Purpose**: Identify the use of tools like WinRAR or 7-Zip for compressing data.

{% code overflow="wrap" %}
```powershell
Get-Process | Where-Object {$_.ProcessName -match 'WinRAR|7z'} | Select-Object ProcessName, Id, StartTime
```
{% endcode %}

**5.2. Monitoring Encryption Tool Usage**

**Purpose**: Detect the use of encryption tools, indicating attempts to secure exfiltrated data.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -match 'gpg.exe|openssl.exe'} | Select-Object TimeCreated, @{n='ProcessName';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[9].Value}}
```
{% endcode %}

#### 6. **Steganography and Data Hiding**

**6.1. Detecting Steganography Tools**

**Purpose**: Identify the use of steganography tools for hiding data in images or other files.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\*" -Recurse -Include *steg* | Select-Object FullName, LastWriteTime
```
{% endcode %}

**6.2. Monitoring for Unusual File Types in Sensitive Locations**

**Purpose**: Detect unusual file types or hidden data in sensitive directories.

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\SensitiveData\*" -Recurse -Include *.jpg, *.png | Select-Object FullName, LastWriteTime
```
{% endcode %}

#### 7. **Network Protocol Abuse**

**7.1. Detecting ICMP Exfiltration**

**Purpose**: Monitor for data exfiltration attempts using ICMP (ping).

{% code overflow="wrap" %}
```powershell
Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 7} |  # ICMP Echo Select-Object LocalAddress, RemoteAddress, RemotePort
```
{% endcode %}

**7.2. Monitoring for DNS Data Exfiltration**

**Purpose**: Identify attempts to use DNS queries for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |  Where-Object {($_.Message -match "TXT") -or ($_.Message -match "TXT Record")} | Select-Object TimeCreated, @{n='DomainName';e={$_.Message -match 'QueryName: (.*)' -replace 'QueryName: '}}
```
{% endcode %}

#### 8. **SFTP and FTP Transfers**

**8.1. Detecting SFTP Transfers**

**Purpose**: Identify data transfers using SFTP.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "SFTP") -and ($_.Message -match "Upload")} | Select-Object TimeCreated, @{n='RemoteAddress';e={$_.Message -match 'RemoteAddress: (.*)' -replace 'RemoteAddress: '}}
```
{% endcode %}

**8.2. Monitoring FTP Uploads**

**Purpose**: Detect data uploads via FTP.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "FTP") -and ($_.Message -match "Upload")} | Select-Object TimeCreated, @{n='RemoteAddress';e={$_.Message -match 'RemoteAddress: (.*)' -replace 'RemoteAddress: '}}
```
{% endcode %}

#### 9. **Physical Media Exfiltration**

**9.1. Monitoring CD/DVD Write Events**

**Purpose**: Detect attempts to write data to CD/DVD media.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "CD") -or ($_.Message -match "DVD")} | Select-Object TimeCreated, @{n='Action';e={$_.Message -match 'Action: (.*)' -replace 'Action: '}}
```
{% endcode %}

**9.2. Detecting Data Copy to External Hard Drives**

**Purpose**: Monitor for data copies to external hard drives.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Properties[6].Value -match 'F:\\'} |  # Assuming F: is the external drive letter Select-Object TimeCreated, @{n='FileName';e={$_.Properties[6].Value}}
```
{% endcode %}

#### 10. **HTTP/S and Web-based Exfiltration**

**10.1. Detecting HTTP POST Requests**

**Purpose**: Identify HTTP POST requests that may be used for data exfiltration.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "POST") -and ($_.Message -match "http")} | Select-Object TimeCreated, @{n='URL';e={$_.Message -match 'URL: (.*)' -replace 'URL: '}}
```
{% endcode %}

**10.2. Monitoring Web Uploads**

**Purpose**: Detect uploads via web forms or other HTTP/S methods.

{% code overflow="wrap" %}
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Security-Auditing" |  Where-Object {($_.Message -match "Upload") -and ($_.Message -match "http")} | Select-Object TimeCreated, @{n='URL';e={$_.Message -match 'URL: (.*)' -replace 'URL: '}}
```
{% endcode %}
