# Information Gathering

### Information Gathering Phase in Penetration Testing

The Information Gathering phase, often referred to as reconnaissance, marks the beginning of active penetration testing once the Pre-Engagement phase is complete and all contractual agreements are finalised. This critical stage involves collecting detailed data about the target organisation, its infrastructure, employees, and operational processes. As the foundation of any successful penetration test, Information Gathering provides the insights necessary to identify vulnerabilities, plan attacks, and execute exploits effectively. This phase is iterative, revisited throughout the testing process as new information uncovers additional attack vectors.&#x20;

Information Gathering can be categorised into four key areas:

1. **Open-Source Intelligence (OSINT)**
2. **Infrastructure Mapping**
3. **Service Discovery**
4. **Host Analysis**

Each category is essential to building a comprehensive understanding of the target environment, enabling testers to craft targeted strategies for exploitation. This phase leverages both publicly available data and active probing to map the attack surface, identify security controls, and pinpoint potential weaknesses.

### Open-Source Intelligence (OSINT)

Open-Source Intelligence (OSINT) focuses on collecting publicly available information about the target organisation without directly interacting with its systems. This non-intrusive approach leverages freely accessible sources, such as websites, social media, public records, and code repositories, to uncover details about the organisation’s operations, personnel, and technology stack.

Key activities in OSINT include:

* **Company Research:** Analyse the organisation’s website, press releases, job postings, or public filings to identify business units, partnerships, or technologies in use. For example, a job posting for a “Cloud Architect” may reveal the use of specific cloud platforms.
* **Employee Profiling:** Gather information about employees, such as names, roles, or contact details, from platforms like LinkedIn or corporate directories. This data can support social engineering attacks, such as phishing campaigns.
* **Code Repositories:** Examine platforms like GitHub or GitLab for exposed source code, configuration files, or credentials. Misconfigured repositories may reveal sensitive data, such as API keys, passwords, or SSH keys, which could grant immediate access to systems.
* **Public Records and Forums:** Review WHOIS records, domain registrations, or industry forums to identify domain names, subdomains, or historical infrastructure changes.

If critical vulnerabilities, such as exposed credentials or keys, are discovered during OSINT, the testing team must follow the incident handling procedures outlined in the Rules of Engagement (RoE). This typically involves pausing testing, notifying the client’s designated contact, and allowing administrators to address the issue before proceeding. For instance, a publicly accessible SSH key represents an immediate security risk that must be mitigated to prevent real-world exploitation.

OSINT is powerful because it exploits information that organisations or employees may inadvertently share, often unaware of its sensitivity. By piecing together these fragments, testers can build a detailed picture of the target’s attack surface.&#x20;

### Infrastructure Mapping&#x20;

Infrastructure Mapping focuses on creating a detailed blueprint of the organisation’s network architecture, both externally (from the internet) and internally (within the network). This phase combines OSINT with active reconnaissance to identify servers, hosts, and network configurations, ensuring all findings align with the agreed-upon scope.

Key activities include:

* **Network Enumeration:** Use tools like Nmap, Shodan, or Censys to identify active hosts, IP addresses, and network ranges. DNS queries can reveal name servers, mail servers, or cloud instances, providing a map of the organisation’s digital footprint.
* **Security Control Identification:** Detect firewalls, intrusion detection systems (IDS), or web application firewalls (WAFs) to understand the organisation’s defensive posture. This informs evasive testing strategies to bypass detection during later phases.
* **Scope Validation:** Cross-reference discovered assets with the scoping document to ensure testing remains within authorised boundaries. For example, an IP address discovered during enumeration must be confirmed as in-scope before further analysis.
* **Internal Perspective:** For internal tests, map the network to identify domain controllers, file servers, or other critical assets. This can support techniques like password spraying, where a single password is tested across multiple user accounts to gain initial access.

Infrastructure Mapping provides a high-level view of the target’s topology, enabling testers to prioritise high-value assets and tailor their approach based on the organisation’s security measures.

### Service Discovery

Service Discovery involves identifying and analysing the services running on hosts or servers within the target environment. This phase focuses on understanding the purpose, version, and configuration of each service to uncover potential vulnerabilities.&#x20;

Key activities include:

* **Service Identification:** Use tools like Nmap or Netcat to detect open ports and associated services, such as HTTP, FTP, or SMB. For each service, determine its role (e.g., web server, file sharing) and how it interacts with other systems.
* **Version Analysis:** Identify the software version of each service to check for known vulnerabilities. For example, an outdated Apache server may be susceptible to exploits listed in CVE databases.
* **Configuration Assessment:** Examine service configurations for weaknesses, such as default credentials, misconfigured permissions, or exposed administrative interfaces. For instance, an FTP server allowing anonymous access could provide a foothold for attackers.
* **Logical Conclusions:** Infer the service’s purpose within the organisation’s operations. For example, a database service may indicate a critical application, guiding testers toward high-impact vulnerabilities.

Service Discovery is critical because outdated or misconfigured services are common entry points for attackers. Administrators may hesitate to update stable systems to avoid disrupting operations, leaving vulnerabilities unpatched and exploitable.

### Host Analysis

Host Analysis drills down to the individual hosts or servers identified during Infrastructure Mapping, examining their operating systems, services, and configurations in detail. This phase combines active scanning with OSINT to build a comprehensive profile of each host.

Key activities include:

* **Operating System Fingerprinting:** Use tools like Nmap or Xprobe2 to determine the operating system (e.g., Windows Server 2019, Ubuntu 20.04) and its patch level. Outdated systems, such as Windows Server 2008, may have known vulnerabilities that are no longer supported by the vendor.
* **Service Details:** Catalogue all services running on the host, including their versions, ports, and configurations. For example, a host running an old version of Microsoft SQL Server may be vulnerable to privilege escalation attacks.
* **Internal Analysis:** For internal tests, examine the host for sensitive files, local services, or scripts that could be exploited during the Post-Exploitation phase. For instance, misconfigured cron jobs or stored credentials may provide opportunities for privilege escalation.
* **Role Identification:** Determine the host’s role in the network, such as a web server, domain controller, or employee workstation, to assess its value as a target.
* **OSINT Integration:** Cross-reference host details with public information, such as vendor documentation or forum discussions, to infer configurations or vulnerabilities.

Internally, testers often discover services that are inaccessible externally, which administrators may assume are secure due to their isolation. However, misconfigurations, such as weak permissions or default settings, can make these services exploitable once initial access is gained.

### Key Considerations

To ensure effective Information Gathering, testers must:

* **Adhere to Scope:** Only collect data within the agreed-upon boundaries to avoid legal or ethical violations.
* **Balance Active and Passive Techniques:** Use passive OSINT to minimise detection during external tests, while active scans provide deeper insights for internal assessments.
* Handle Sensitive Findings: Follow RoE protocols for reporting critical vulnerabilities, such as exposed credentials, to prevent real-world exploitation.
* **Document Thoroughly:** Maintain detailed records of all findings, including tools used, data sources, and timestamps, to support later phases and reporting.
* **Adapt to Context:** Tailor reconnaissance to the organisation’s environment, such as focusing on cloud infrastructure for a SaaS provider or physical assets for a retail chain.

### Conclusion

The Information Gathering phase is the cornerstone of penetration testing, providing the data needed to identify vulnerabilities, plan exploits, and assess the target’s security posture. By systematically collecting and analysing information through OSINT, Infrastructure Mapping, Service Discovery, and Host Analysis, testers build a comprehensive understanding of the target environment. This phase’s iterative nature ensures that new insights continuously refine the testing strategy, maximising the effectiveness of subsequent phases like Vulnerability Assessment and Exploitation. A thorough and ethical approach to Information Gathering sets the stage for a successful penetration test, delivering actionable results to strengthen the client’s defences.
