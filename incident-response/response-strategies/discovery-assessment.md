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

# Discovery Assessment

**Discovery**: Techniques Forensically investigating discovery techniques on workstations and server systems involves identifying how an attacker or malicious entity gathered information about your systems and network. Discovery is a tactic in the MITRE ATT\&CK framework that encompasses various techniques adversaries use to gain knowledge about the system, network, and environment they have compromised.

### 1. Understanding Common Discovery Techniques

* **System and Network Discovery**: Identifying system configurations, network resources, and devices.
* **Account Discovery**: Gathering information about user accounts.
* **File and Directory Discovery**: Searching for files and directories of interest.
* **Software Discovery**: Identifying installed applications and software.
* **Command and Control Discovery**: Detecting communication with C\&C servers.

### 2. Data Collection and Preservation

* **Forensic Imaging**: Use tools like EnCase, AXIOM Cyber, FTK Imager or dd to create images of affected systems.
* **Memory Capture**: Employ tools like Magnet RAM Capture or WinPmem to capture volatile memory.
* **Log Collection**: Collect security logs, system logs, application logs, and command execution logs.

### 3. Log Analysis

* **Security and System Logs**: Look for signs of reconnaissance activities, such as frequent access to system information utilities or scripts.
* **Authentication Logs**: Check for unusual login attempts or user enumeration activities.
* **Network Logs**: Review logs for signs of network scanning or mapping activities.

### 4. File and Directory Analysis

* **File Access Logs**: Investigate logs to access specific files or directories containing sensitive information.
* **File System Forensics**: Analyse file systems for tools or scripts to be used in the discovery process.

### 5. Command History Analysis

* **Command Line Logs**: Windows systems log command line activity, including PowerShell, in Event Logs. Look for commands related to system reconnaissance (like **netstat**, **ipconfig**, **whoami**, and **net** commands).
* **Bash History (Unix/Linux)**: Review **.bash\_history** or equivalent files for executed commands that could be used for discovery.

### 6. Network Traffic Analysis

* **Network Monitoring Tools**: Use tools like Wireshark or Tcpdump to analyse captured network traffic for reconnaissance patterns.
* **DNS Query Logs**: Review DNS logs for domain lookups that may indicate reconnaissance or mapping of internal resources.

### 7. Artifact Analysis

* **Prefetch Files (Windows)**: Analyse Prefetch files to determine if any tools commonly used for discovery were executed.
* **Registry Analysis (Windows)**: Check registry keys for traces of commands or tool execution.

### 8. Use of Specialised Forensic Tools

* **Forensic Suites**: Tools like EnCase, Autopsy, or X-Ways for comprehensive system analysis.
* **Sysinternals Suite (Windows)**: Use tools like Process Monitor and Process Explorer for real-time system monitoring.

### 9. Documentation and Reporting

* **Detailed Documentation**: Record all findings, methodologies, and evidence paths.
* **Forensic Report**: Compile a comprehensive report detailing the investigation, findings, and potential impact.

### 10. Post-Investigation Actions

* **Mitigation and Remediation**: Implement security measures to counter the identified discovery techniques.
* **Recovery**: Restore systems and data from backups where necessary.
* **Enhancing Defenses**: Update security policies and tools based on the findings.

### **11.**  Tools and Techniques

* Digital Forensics:
  * Specialised tools for evidence collection and analysis:
    * OpenText EnCase Forensics (commercial tool)
    * FTK (Forensic Toolkit)
    * Volatility (memory forensics)
    * Autopsy (open-source)
    * Cyber Triage (commercial tool)
    * Binalyze AIR (commercial tool)
    * Belkasoft (commercial tool)
    * Oxygen Forensics (commercial tool)
    * X-ways Forensics (commercial tool)
    * The Sleuth Kit (open-source tool)
    * Eric Zimmerman Tools (open-source tool)
  * Techniques include timeline analysis, file recovery, and reverse engineering.
* Incident Response:
  * Tools for monitoring, containment, and eradication:
    * SIEM (Splunk, QRadar, Microsoft Sentinel, Sumo Logic, Graylog, Elastic Security, LogRhythm, Datadog, Exabeam)
    * EDR (CrowdStrike, SentinelOne, Defender for Endpoint, Cortex XDR, FortiEDR)
    * Firewalls and IDS/IPS systems
  * Techniques include log analysis, threat containment, and system restoration.

### **12. Key Considerations**

* **Chain of Custody**: Maintain a clear chain of custody for all evidence.
* **Legal Compliance**: Ensure the investigation is compliant with legal and organisational policies.
* **Data Confidentiality**: Handle all data securely, maintaining its confidentiality and integrity.

Each case of discovery by an attacker can be unique, requiring a tailored approach based on the specifics of the incident and the environment.
