# Nmap Protocol Scan

Nmap (Network Mapper) is a versatile tool for network discovery and security auditing. This cheat sheet focuses on protocol-specific scans, covering authentication and identity services, network protocols, and common vulnerabilities. Each section includes Nmap commands with explanations, use cases, and tips to maximise effectiveness. Use this guide for targeted reconnaissance, ensuring you have permission to scan the target network.

***

### Authentication & Identity Services

These scans target protocols and services used for authentication and identity management, often revealing misconfigurations or weak credentials.

#### LDAP (Ports 389, 636)

Lightweight Directory Access Protocol (LDAP) is used for directory services, often in corporate environments (e.g., Active Directory).

{% code overflow="wrap" %}
```bash
nmap -p 389,636 --script=ldap* <target>                             # Runs all LDAP scripts (e.g., enumeration, search)
nmap --script "(ldap*) and not brute" -p 389 <target>               # Runs LDAP scripts, excluding brute-force
nmap -p 636 --script=ldap-search,ldap-rootdse <target>              # Queries LDAP directory and root DSE (secure port)
```
{% endcode %}

**Context**: LDAP scans help identify directory structures, user accounts, or misconfigurations in Active Directory or other LDAP servers.&#x20;

**Tips**:

* Use `--script=ldap-rootdse` to retrieve server metadata.
* Avoid brute-force scripts (`ldap-brute`) unless explicitly permitted, as they can lock accounts.
* Combine with `-sV` to confirm LDAP service versions.

#### Kerberos (Port 88)

Kerberos is a network authentication protocol used in Windows domains.

{% code overflow="wrap" %}
```bash
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" <target>  # Enumerates valid Kerberos users
nmap -p 88 --script=krb5-info <target>                                                  # Gathers Kerberos server info
```
{% endcode %}

**Context**: These scripts identify valid usernames or server details in Kerberos realms, useful for domain enumeration.&#x20;

**Tips**:

* Specify the correct realm (e.g., `DOMAIN.LOCAL`) for accurate results.
* Use with caution, as enumeration may trigger security alerts.

#### SMB (Ports 139, 445)

Server Message Block (SMB) is used for file sharing and Windows services.

{% code overflow="wrap" %}
```bash
/nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb2-capabilities,smb2-security-mode <target>  # Enumerates shares, users, OS, and security settings
nmap --script smb-vuln* -p 445 <target>                                                  # Checks for SMB vulnerabilities (e.g., EternalBlue)
nmap -p 445 --script=smb-null-session <target>                                           # Tests for anonymous SMB access
```
{% endcode %}

**Context**: SMB scans reveal shared folders, user accounts, and potential vulnerabilities like null sessions or outdated protocols.&#x20;

**Tips**:

* Combine with `-sV` to detect SMB versions (e.g., SMBv1, SMBv2).
* Check for null sessions (`smb-null-session`) to identify misconfigured servers.
* Be cautious with `smb-vuln*`, as some scripts may disrupt services.

#### RDP (Port 3389)

Remote Desktop Protocol (RDP) enables remote access to Windows systems.

{% code overflow="wrap" %}
```bash
nmap -p 3389 --script=rdp-enum-encryption <target>                  # Checks RDP encryption levels
nmap -p 3389 --script=rdp-vuln-ms12-020 <target>                    # Tests for MS12-020 vulnerability (RDP DoS)
nmap -p 3389 --script=rdp-ntlm-info <target>                        # Extracts NTLM authentication info
```
{% endcode %}

**Context**: RDP scans identify weak encryption or vulnerabilities that could allow unauthorised access.&#x20;

**Tips**:

* Use `rdp-vuln-ms12-020` to check for older, vulnerable RDP implementations.
* Combine with `--script-args` to test specific credentials if permitted.

#### WinRM (Ports 5985, 5986)

Windows Remote Management (WinRM) is used for remote administration.

{% code overflow="wrap" %}
```bash
nmap -p 5985,5986 --script=http-windows-enum <target>               # Enumerates Windows services via WinRM
nmap -p 5985,5986 --script=winrm-enum-users <target>                # Lists WinRM users
```
{% endcode %}

**Context**: WinRM scans help identify remote management configurations and potential user accounts.&#x20;

**Tips**:

* Use on Windows environments to uncover misconfigured remote access.
* Combine with HTTP scripts if WinRM uses HTTP/HTTPS protocols.

***

### Network Services

These scans target common network services, focusing on enumeration and vulnerability detection.

#### FTP (Port 21)

File Transfer Protocol (FTP) is used for file transfers.

{% code overflow="wrap" %}
```bash
nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie <target>  # Checks for anonymous access, bounce attacks, and known vulnerabilities
```
{% endcode %}

**Context**: FTP scans identify anonymous access, server types, and exploitable backdoors.&#x20;

**Tips**:

* `ftp-anon` checks for anonymous login (common misconfiguration).
* Use `ftp-bounce` to test for outdated servers vulnerable to bounce attacks.

#### SSH (Port 22)

Secure Shell (SSH) is used for secure remote access.

{% code overflow="wrap" %}
```bash
nmap -p 22 --script=ssh-hostkey,ssh-auth-methods,sshv1,ssh2-enum-algos,ssh-brute <target>  # Enumerates host keys, authentication methods, and attempts brute-forcing
```
{% endcode %}

**Context**: SSH scans reveal supported algorithms, host keys, and potential weak credentials.&#x20;

**Tips**:

* Avoid `ssh-brute` unless permitted, as it may lock accounts.
* Use `sshv1` to detect outdated, insecure SSHv1 protocol.

#### Telnet (Port 23)

Telnet provides unencrypted remote access (rarely used today).

{% code overflow="wrap" %}
```bash
nmap -p 23 --script=telnet-encryption,telnet-ntlm-info <target>  # Checks for encryption and NTLM info
```
{% endcode %}

**Context**: Telnet scans identify legacy systems and authentication details.&#x20;

**Tips**:

* Telnet is inherently insecure; its presence may indicate a misconfiguration.
* Use `telnet-ntlm-info` for Windows environments.

#### SMTP (Ports 25, 465, 587)

Simple Mail Transfer Protocol (SMTP) handles email delivery.

{% code overflow="wrap" %}
```bash
nmap -p 25,465,587 --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info <target>  # Enumerates commands, users, and checks for open relays
```
{% endcode %}

**Context**: SMTP scans identify misconfigured mail servers, open relays, or valid usernames.&#x20;

**Tips**:

* `smtp-open-relay` checks for servers that allow unauthorised email relaying.
* Combine with `-sV` to detect mail server software.

#### DNS (Port 53)

Domain Name System (DNS) resolves domain names to IPs.

{% code overflow="wrap" %}
```bash
nmap -p 53 --script=dns-zone-transfer,dns-nsid,dns-service-discovery,dns-recursion,dns-cache-snoop,dns-random-srcport <target>  # Tests zone transfers, recursion, and service discovery
```
{% endcode %}

**Context**: DNS scans reveal domain structures, recursion settings, or cached data.&#x20;

**Tips**:

* `dns-zone-transfer` can expose entire domain records if misconfigured.
* Use `-sU` for UDP-based DNS scans.

#### TFTP (Port 69)

Trivial File Transfer Protocol (TFTP) is used for simple file transfers.

{% code overflow="wrap" %}
```bash
/nmap -sU -p 69 --script=tftp-enum <target>  # Enumerates TFTP files and directories
```
{% endcode %}

**Context**: TFTP scans identify accessible files or misconfigured servers.&#x20;

**Tips**:

* Requires `-sU` (UDP scan) as TFTP uses UDP.
* Look for configuration files or firmware in TFTP directories.

#### POP3 (Ports 110, 995)

Post Office Protocol (POP3) retrieves emails.

{% code overflow="wrap" %}
```bash
nmap -p 110,995 --script=pop3-capabilities,pop3-brute <target>  # Checks server capabilities and attempts brute-forcing
```
{% endcode %}

**Context**: POP3 scans identify server features and potential weak credentials.&#x20;

**Tips**:

* Use `pop3-brute` cautiously to avoid account lockouts.
* Combine with `-sV` to detect POP3 server versions.

#### IMAP (Ports 143, 993)

Internet Message Access Protocol (IMAP) manages email access.

{% code overflow="wrap" %}
```bash
nmap -p 143,993 --script=imap-capabilities,imap-brute <target>  # Enumerates capabilities and attempts brute-forcing
```
{% endcode %}

**Context**: IMAP scans reveal server features and authentication weaknesses.&#x20;

**Tips**:

* Similar to POP3, avoid `imap-brute` unless permitted.
* Check for SSL/TLS support on port 993.

#### SNMP (Ports 161, 162)

Simple Network Management Protocol (SNMP) manages network devices.

{% code overflow="wrap" %}
```bash
nmap -sU -p 161,162 --script=snmp-info,snmp-interfaces,snmp-processes,snmp-win32-services,snmp-brute,snmp-sysdescr <target>  # Enumerates device info, interfaces, and services
```
{% endcode %}

**Context**: SNMP scans extract device details, often revealing sensitive configurations.&#x20;

**Tips**:

* Requires `-sU` (UDP scan) for SNMP.
* Test default community strings (e.g., `public, private`) with `snmp-brute`.

#### R-Services (Ports 512, 513, 514)

Remote services (rlogin, rsh, rexec) are legacy protocols for remote access.

```bash
nmap -p 512,513,514 --script=rpcinfo <target>  # Enumerates RPC services
```

**Context**: R-services are rare but indicate outdated, insecure systems if present.&#x20;

**Tips**:

* Combine with `-sV` to confirm service versions.
* Presence of r-services often warrants deeper investigation.

#### IPMI (Port 623)

Intelligent Platform Management Interface (IPMI) manages server hardware.

{% code overflow="wrap" %}
```bash
nmap -p 623 --script=ipmi-version,ipmi-cipher-zero <target>  # Checks IPMI version and cipher vulnerabilities
```
{% endcode %}

**Context**: IPMI scans identify remote management interfaces and known vulnerabilities.&#x20;

**Tips**:

* `ipmi-cipher-zer`o checks for weak encryption settings.
* Often found on server hardware (e.g., Dell iDRAC, HP iLO).

#### RSync (Port 873)

Rsync synchronises files between systems.

{% code overflow="wrap" %}
```bash
nmap -p 873 --script=rsync-list-modules <target>  # Lists available rsync modules
```
{% endcode %}

**Context**: Rsync scans reveal accessible file shares or modules.&#x20;

**Tips**:

* Check for anonymous access or exposed sensitive directories.
* Combine with `-sV` to identify rsync versions.

#### MSSQL (Ports 1433, 1434, 2433)

Microsoft SQL Server manages databases.

{% code overflow="wrap" %}
```bash
nmap -p 1433,1434,2433 --script=ms-sql-info,ms-sql-empty-password,ms-sql-dump-hashes,ms-sql-brute,ms-sql-config <target>  # Enumerates server info, credentials, and configurations
```
{% endcode %}

**Context**: MSSQL scans identify database instances, weak passwords, and configurations.&#x20;

**Tips**:

* `ms-sql-empty-password` checks for default or blank credentials.
* Use cautiously to avoid locking out accounts.

#### Oracle TNS (Port 1521)

Oracle Transparent Network Substrate (TNS) manages Oracle database connections.

{% code overflow="wrap" %}
```bash
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute <target>  # Enumerates Oracle version and SIDs
```
{% endcode %}

**Context**: Oracle scans reveal database instances and potential SIDs for further attacks.&#x20;

**Tips**:

* `oracle-sid-brute` attempts to guess database SIDs; use with permission.
* Combine with `-sV` to confirm Oracle versions.

#### NFS (Port 2049)

Network File System (NFS) shares files across networks.

{% code overflow="wrap" %}
```bash
nmap -p 2049 --script=nfs-ls,nfs-statfs,nfs-showmount,nfs-acls <target>  # Lists NFS shares and permissions
```
{% endcode %}

**Context**: NFS scans identify shared directories and access controls.&#x20;

**Tips**:

* `nfs-showmount` reveals mountable shares; check for world-readable shares.
* Combine with `-sV` to detect NFS versions.

#### MySQL (Port 3306)

MySQL is a popular open-source database.

{% code overflow="wrap" %}
```bash
nmap -p 3306 --script=mysql-info,mysql-users,mysql-databases,mysql-empty-password,mysql-query,mysql-brute,mysql-dump-hashes <target>  # Enumerates MySQL info, users, and credentials
```
{% endcode %}

**Context**: MySQL scans reveal database details and potential weak credentials.&#x20;

**Tips**:

* `mysql-empty-password` checks for default or blank credentials.
* Avoid `mysql-brute` unless permitted.

#### PostgreSQL (Ports 5432, 5433)

PostgreSQL is an open-source relational database.

{% code overflow="wrap" %}
```bash
/nmap -p 5432 --script=pgsql-brute,pgsql-databases,pgsql-users <target>  # Enumerates databases, users, and attempts brute-forcing
nmap -p 5432 --script=pgsql-enum <target>                               # Enumerates PostgreSQL details
nmap -p 5433 --script=pgsql-info <target>                               # Gathers info on secure PostgreSQL port
```
{% endcode %}

**Context**: PostgreSQL scans identify database configurations and credentials.&#x20;

**Tips**:

* Use `pgsql-info` to confirm SSL/TLS on port 5433.
* Avoid brute-forcing unless permitted.

#### NetBIOS (Ports 137, 138)

NetBIOS provides name resolution and session services in Windows networks.

{% code overflow="wrap" %}
```bash
nmap -p 137,138 --script=nbstat,smb-os-discovery,smb-enum-shares,smb-enum-users <target>  # Enumerates NetBIOS and SMB details
```
{% endcode %}

**Context**: NetBIOS scans reveal Windows network information and shares.&#x20;

**Tips**:

* Combine with SMB scans for comprehensive Windows enumeration.
* Requires `-sU` for UDP-based NetBIOS scans.

#### VNC (Port 5900)

Virtual Network Computing (VNC) enables remote desktop access.

{% code overflow="wrap" %}
```bash
nmap -p 5900 --script=vnc-info,vnc-title,vnc-brute <target>  # Gathers VNC info and attempts brute-forcing
```
{% endcode %}

**Context**: VNC scans identify remote desktop configurations and credentials.&#x20;

**Tips**:

* `vnc-title` reveals VNC session names, useful for reconnaissance.
* Avoid `vnc-brute` unless permitted.

#### Redis (Port 6379)

Redis is an in-memory data store.

{% code overflow="wrap" %}
```bash
nmap -p 6379 --script=redis-info,redis-brute <target>  # Gathers Redis info and attempts brute-forcing
```
{% endcode %}

**Context**: Redis scans reveal server details and potential weak authentication.&#x20;

**Tips**:

* Check for unprotected Redis instances (common misconfiguration).
* Avoid brute-forcing unless permitted.

#### Elasticsearch (Port 9200)

Elasticsearch is a search and analytics engine.

{% code overflow="wrap" %}
```bash
nmap -p 9200 --script=http-elasticsearch-head,http-title,http-methods,http-headers <target>  # Enumerates Elasticsearch info and HTTP details
```
{% endcode %}

**Context**: Elasticsearch scans identify exposed search clusters and configurations.&#x20;

**Tips**:

* Check for unauthorised access or exposed APIs.
* Combine with `-sV` to detect Elasticsearch versions.

#### Memcached (Port 11211)

Memcached is a distributed memory caching system.

{% code overflow="wrap" %}
```bash
nmap -p 11211 --script=memcached-info <target>  # Gathers Memcached server info
```
{% endcode %}

**Context**: Memcached scans reveal caching server details and potential exposures.&#x20;

**Tips**:

* Check for unauthenticated access, a common misconfiguration.
* Requires `-sU` for UDP-based scans.

#### RPCBind (Port 111)

Remote Procedure Call (RPC) bind service maps RPC services.

```bash
nmap -sU -sT -p 111 --script=rpcinfo <target>  # Enumerates RPC services
```

**Context**: RPCBind scans identify available RPC services (e.g., NFS, NIS).&#x20;

**Tips**:

* Use both `-sU` and `-sT` for comprehensive RPC scanning.
* Combine with NFS or r-services scans.

#### SIP (Port 5060)

Session Initiation Protocol (SIP) manages VoIP communications.

{% code overflow="wrap" %}
```bash
nmap -sU -p 5060 --script=sip-methods,sip-enum-users <target>  # Enumerates SIP methods and users
```
{% endcode %}

**Context**: SIP scans reveal VoIP configurations and potential user accounts.&#x20;

**Tips**:

* Requires `-sU` for UDP-based SIP scans.
* Check for weak SIP credentials or exposed endpoints.

#### MQTT (Port 1883)

Message Queuing Telemetry Transport (MQTT) is used for IoT messaging.

{% code overflow="wrap" %}
```bash
nmap -p 1883 --script=mqtt-subscribe,mqtt-connect <target>  # Tests MQTT connectivity and subscriptions
```
{% endcode %}

**Context**: MQTT scans identify IoT messaging configurations.&#x20;

**Tips**:

* Check for unauthenticated access, common in IoT devices.
* Combine with `-sV` to detect MQTT broker versions.

#### RMI (Port 1099)

Remote Method Invocation (RMI) is used for Java remote objects.

{% code overflow="wrap" %}
```bash
nmap -p 1099 --script=rmi-dumpregistry,rmi-vuln-classloader <target>  # Enumerates RMI registry and checks for vulnerabilities
```
{% endcode %}

**Context**: RMI scans target Java-based applications for misconfigurations.&#x20;

**Tips**:

* `rmi-vuln-classloader` checks for deserialization vulnerabilities.
* Combine with `-sV` to identify Java versions.

#### NTP (Port 123)

Network Time Protocol (NTP) synchronises clocks.

{% code overflow="wrap" %}
```bash
nmap -sU -p 123 --script=ntp-info,ntp-monlist <target>  # Gathers NTP info and checks for monlist amplification
```
{% endcode %}

**Context**: NTP scans reveal server details and potential DDoS vulnerabilities.&#x20;

**Tips**:

* `ntp-monlist` checks for amplification attack vectors.
* Requires `-sU` for UDP-based scans.

#### Docker (Port 2375)

Docker manages containerised applications.

```bash
nmap -p 2375 --script=docker-version <target>  # Gathers Docker version info
```

**Context**: Docker scans identify exposed container management APIs.&#x20;

**Tips**:

* Check for unauthenticated access, a critical misconfiguration.
* Combine with `-sV` to confirm Docker versions.

#### RabbitMQ (Port 5672)

RabbitMQ is a message broker for distributed systems.

```bash
nmap -p 5672 --script=rabbitmq-info <target>  # Gathers RabbitMQ server info
```

**Context**: RabbitMQ scans reveal messaging configurations and potential exposures.&#x20;

**Tips**:

* Check for default credentials (e.g., guest/guest).
* Combine with `-sV` to detect RabbitMQ versions.

#### Jenkins (Port 8080)

Jenkins is a CI/CD automation server.

{% code overflow="wrap" %}
```bash
nmap -p 8080 --script=http-jenkins-info,http-headers,http-title <target>  # Enumerates Jenkins info and HTTP details
```
{% endcode %}

**Context**: Jenkins scans identify exposed CI/CD servers and potential vulnerabilities.&#x20;

**Tips**:

* Check for anonymous access or script console exposure.
* Combine with `http-vuln*` scripts for deeper vulnerability checks.

#### AJP (Port 8009)

Apache JServ Protocol (AJP) connects web servers to application servers.

{% code overflow="wrap" %}
```bash
nmap -p 8009 --script=ajp-methods,ajp-headers,ajp-auth <target>  # Enumerates AJP methods and authentication
```
{% endcode %}

**Context**: AJP scans check for misconfigurations, including Ghostcat (CVE-2020-1938).&#x20;

**Tips**:

* Look for file inclusion vulnerabilities with `ajp-auth`.
* Combine with `-sV` to detect Apache Tomcat versions.

#### Kubernetes API Server (Port 6443)

Kubernetes manages container orchestration.

{% code overflow="wrap" %}
```bash
nmap -p 6443 --script=http-kubernetes-info,http-headers,http-title <target>  # Gathers Kubernetes API info
```
{% endcode %}

**Context**: Kubernetes scans identify exposed APIs or misconfigured kubelets.&#x20;

**Tips**:

* Check for unauthorised access or exposed dashboards.
* Combine with -sV to detect Kubernetes versions.

#### CouchDB (Port 5984)

CouchDB is a NoSQL database.

{% code overflow="wrap" %}
```bash
nmap -p 5984 --script=http-couchdb-info,http-title,http-headers <target>  # Gathers CouchDB info and HTTP details
```
{% endcode %}

**Context**: CouchDB scans check for exposed databases and vulnerabilities (e.g., CVE-2017-12635). **Tips**:

* Look for unauthenticated access or admin party mode.
* Combine with -sV to detect CouchDB versions.

#### VMware (Ports 902, 903, 443)

VMware manages virtualisation platforms.

{% code overflow="wrap" %}
```bash
nmap -p 902,903,443 --script=vmware-version <target>  # Gathers VMware version info
```
{% endcode %}

**Context**: VMware scans identify virtualisation environments and potential weaknesses.&#x20;

**Tips**:

* Check for outdated VMware versions with known vulnerabilities.
* Combine with `-sV` for version detection.

#### TeamViewer (Port 5938)

TeamViewer enables remote desktop access.

```bash
nmap -p 5938 --script=teamviewer-info <target>  # Gathers TeamViewer server info
```

**Context**: TeamViewer scans identify remote access configurations.&#x20;

**Tips**:

* Check for exposed instances or weak configurations.
* Combine with `-sV` to detect TeamViewer versions.

#### Bacula (Port 9101)

Bacula is a backup system.

```bash
nmap -p 9101 --script=bacula-info <target>  # Gathers Bacula server info
```

**Context**: Bacula scans identify backup system configurations.&#x20;

**Tips**:

* Check for unauthenticated access or misconfigured backups.
* Combine with `-sV` to detect Bacula versions.

#### X11 (Port 6000)

X11 is a windowing system for graphical interfaces.

```bash
nmap -p 6000 --script=x11-access <target>  # Checks for X11 access controls
```

**Context**: X11 scans identify exposed graphical interfaces, often on Linux systems.&#x20;

**Tips**:

* Look for unauthenticated access, a critical misconfiguration.
* Rarely used in modern systems but indicates legacy setups.

#### Web Services (Ports 80, 443, 8080, 8443)

Web services include HTTP/HTTPS servers and applications.

{% code overflow="wrap" %}
```bash
/nmap -p 80,443,8080,8443 --script=http-title,http-methods,http-enum,http-headers,http-server-header,http-auth-finder,http-vuln* <target>  # Enumerates web server details and vulnerabilities
```
{% endcode %}

**Context**: Web scans identify server configurations, frameworks, and vulnerabilities.&#x20;

**Tips**:

* `http-vuln*` checks for CVEs and misconfigurations.
* Combine with `-sV` to detect web server versions (e.g., Apache, Nginx).

#### WebDAV (Ports 80, 443, 8080)

WebDAV extends HTTP for collaborative file management.

{% code overflow="wrap" %}
```bash
nmap -p 80,443,8080 --script=http-webdav-scan <target>  # Scans for WebDAV configurations
```
{% endcode %}

**Context**: WebDAV scans reveal file-sharing extensions on web servers.&#x20;

**Tips**:

* Check for unauthorised access or write permissions.
* Combine with HTTP scripts for comprehensive web enumeration.

#### Apache Hadoop (Port 50070)

Hadoop is a big data processing framework.

```bash
nmap -p 50070 --script=http-hadoop-info <target>  # Gathers Hadoop server info
```

**Context**: Hadoop scans identify exposed big data clusters.&#x20;

**Tips**:

* Check for unauthenticated access to NameNode or DataNode.
* Combine with `-sV` to detect Hadoop versions.

#### Tomcat (Ports 8080, 8443)

Apache Tomcat is a Java-based web server.

{% code overflow="wrap" %}
```bash
nmap -p 8080,8443 --script=http-tomcat-manager,http-tomcat-users <target>  # Enumerates Tomcat manager and users
```
{% endcode %}

**Context**: Tomcat scans check for manager access and user enumeration.&#x20;

**Tips**:

* Look for default credentials (e.g., admin/admin) in `http-tomcat-manager`.
* Combine with `http-vuln*` for CVE checks.

#### Zookeeper (Port 2181)

ZooKeeper coordinates distributed systems.

```bash
nmap -p 2181 --script=zookeeper-info <target>  # Gathers ZooKeeper server info
```

**Context**: ZooKeeper scans reveal coordination service details.&#x20;

**Tips**:

* Check for unauthenticated access, common in misconfigured clusters.
* Combine with `-sV` to detect ZooKeeper versions.

#### Kafka (Port 9092)

Kafka is a distributed streaming platform.

```bash
nmap -p 9092 --script=kafka-info <target>  # Gathers Kafka server info
```

**Context**: Kafka scans identify streaming platform configurations.&#x20;

**Tips**:

* Check for exposed brokers or unauthenticated access.
* Combine with `-sV` to detect Kafka versions.

#### Varnish (Port 6081)

Varnish is a caching proxy.

```bash
nmap -p 6081 --script=http-headers,http-title <target>  # Gathers Varnish server info
```

**Context**: Varnish scans identify caching proxy configurations.&#x20;

**Tips**:

* Check for misconfigured caching rules or exposed backends.
* Combine with `-sV` to detect Varnish versions.

***

### Other Useful Nmap Scripts

Additional scripts for automation, brute-forcing, and vulnerability detection.

#### Common Automation & Miscellaneous Scripts

{% code overflow="wrap" %}
```bash
nmap --script=default,safe <target>                         # Runs default and safe scripts
nmap -p- --min-rate=10000 -T4 <target>                     # Fast full port scan
nmap -sV --version-all -p <port> <target>                  # Aggressive service detection
nmap -sC -sV <target>                                      # Default scripts with version detection
nmap -Pn -n -sS -p- -T4 <target>                           # Stealth SYN scan, no DNS resolution
```
{% endcode %}

**Context**: These commands provide quick, automated scans for broad reconnaissance.&#x20;

**Tips**:

* Use `-T4` for faster scans on reliable networks.
* Combine `-sC` and `-sV` for comprehensive initial scans.

#### Brute Force

{% code overflow="wrap" %}
```bash
nmap -p 21,22,23,25,80,110,143,443,3306,5432,6379,8080 --script brute <target>  # Attempts brute-forcing on multiple services
```
{% endcode %}

**Context**: Brute-force scripts test credentials across various protocols.&#x20;

**Tips**:

* Use with caution and explicit permission to avoid account lockouts.
* Specify `--script-args userdb=<file>,passdb=<file>` for custom credential lists.

#### Vulnerability Detection

{% code overflow="wrap" %}
```bash
nmap --script vuln <target>                                # Runs all vulnerability scripts
nmap -p 80,443 --script=http-vuln* <target>                # Checks for HTTP vulnerabilities
nmap -p 445 --script=smb-vuln* <target>                    # Checks for SMB vulnerabilities
```
{% endcode %}

**Context**: Vulnerability scripts identify known CVEs and misconfigurations.&#x20;

**Tips**:

* Combine with `-sV` for accurate vulnerability detection.
* Use `--script` vuln for a broad vulnerability sweep.

#### Web Technologies & Frameworks

{% code overflow="wrap" %}
```bash
nmap -p 80,443 --script=http-headers,http-title,http-methods,http-enum,http-php-version,http-aspnet-debug,http-wordpress-enum,http-drupal-enum <target>  # Enumerates web technologies and frameworks
```
{% endcode %}

**Context**: These scripts identify web server frameworks (e.g., WordPress, Drupal) and configurations. **Tips**:

* `http-wordpress-enum` and `http-drupal-enum` are useful for CMS enumeration.
* Combine with `http-vuln*` to check for framework-specific vulnerabilities.

***

### Best Practices

1. **Obtain Permission**: Always ensure you have explicit authorisation before scanning.
2. **Start with Safe Scans**: Use `-sC`, `-sV`, or `safe` scripts for initial reconnaissance.
3. **Optimise for Stealth**: Use `-sS`, -`T2`, or `-f` to reduce detectability.
4. **Combine Scans**: Pair `-sV` with protocol-specific scripts for accurate results.
5. **Avoid Intrusive Scripts**: Use brute-force or vulnerability scripts only with permission.
6. **Save Output**: Use -oA \<prefix> to store results in multiple formats for analysis.
7. **Analyse Results**: Filter outputs (e.g., `grep open`) and prioritise open ports/services for further testing.

***

### Output Analysis Tips

* **Open Ports**: Focus on services like HTTP, SMB, or RDP for deeper enumeration.
* **Filtered Ports**: Indicate firewalls; use evasion techniques (`-f`, -D) to probe further.
* **Service Versions**: Use -sV to identify software versions for vulnerability research.
* **Use `--reason`**: Understand why ports are open, closed, or filtered.
* **Parse Outputs**: Use tools like `grep, xsltproc`, or `nmaptocsv` to analyse `-oG` or `-oX` outputs.
