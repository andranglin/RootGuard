---
icon: laptop-code
---

# Lateral Movement Assessment

**Description:** Forensically investigating lateral movement techniques on workstations and server systems is crucial to understanding how an attacker moves within a network after gaining initial access. Lateral movement involves techniques that enable an attacker to access and control remote systems within a network.

### **1. Understanding Common Lateral Movement Techniques**

* **Remote Services**: Such as RDP, SSH, VNC.
* **Exploitation of Trust**: Utilising valid credentials or exploiting trusted relationships between systems.
* **File Shares: Access** network shares to move files or execute code.
* **Pass-the-Hash/Pass-the-Ticket**: Stealing and reusing authentication tokens.
* **Remote Execution Tools**: Tools like PsExec or remote scripting like PowerShell Remoting.

### **2. Initial Data Collection**

* **Forensic Imaging**: Create exact copies of the hard drives of affected systems using tools like FTK Imager or dd.
* **Memory Capture**: Capture volatile memory from systems using tools like WinPmem or Magnet RAM Capture.
* **Log Collection**: Gather security logs, system logs, application logs, and especially Windows Event Logs.

### **3. Analysing Remote Access**

* **Security and System Logs**: Review logs for signs of remote access activities, like RDP logins (Event ID 4624 with logon type 10).
* **Authentication Logs**: Examine logs for abnormal authentication patterns or use of unusual user accounts.

### **4. Network Traffic Analysis**

* **Network Monitoring Tools**: Use tools like Wireshark or Tcpdump to analyse network traffic for remote access protocols or unusual internal traffic patterns.
* **Flow Data Analysis**: Review NetFlow data for evidence of lateral movements.

### **5. Investigating Account Usage**

* **User Account Analysis**: Look for evidence of unauthorised use of user accounts, especially privileged ones.
* **Pass-the-Hash/Pass-the-Ticket Detection**: Analyse memory dumps or security logs for signs of these techniques.

### **6. File and Directory Analysis**

* **File Access and Movement**: Check file access logs for indications of files being accessed or moved in a manner consistent with lateral movement.
* **Artifact Analysis**: Look for artifacts left by remote execution tools or scripts.

### **7. Analysing Use of Remote Services**

* **RDP, SSH, and Other Protocols**: Examine logs and settings related to these services for unauthorised access or configuration changes.
* **Service Configuration**: Review the configuration of services commonly used for lateral movement.

### **8. Specialised Forensic Tools Usage**

* **Forensic Suites**: Tools like EnCase, Autopsy, or X-Ways for comprehensive analysis.
* **Sysinternals Suite**: For in-depth analysis of Windows systems, including tools like Process Explorer and TCPView.

### **9. Documentation and Reporting**

* **Detailed Documentation**: Record all findings, processes used and evidence paths.
* **Forensic Report**: Compile a comprehensive report detailing the lateral movement investigation.

### **10. Post-Investigation Actions**

* **Mitigation and Remediation**: Implement necessary measures to contain and eradicate the attacker's presence.
* **Recovery**: Restore affected systems from clean backups.
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

* **Chain of Custody**: Maintain an accurate chain of custody for all forensic evidence.
* **Legal Compliance**: Ensure that the investigation complies with legal requirements.
* **Data Confidentiality**: Maintain the confidentiality and integrity of data throughout the investigation.

Lateral movement investigations require a detailed and methodical approach, as attackers often use sophisticated methods to avoid detection. Tailor the investigation to the specifics of the incident and the environment in which you operate.
