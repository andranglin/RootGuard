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

# Defence Evasion Assessment

**Description:** Forensically investigating defence evasion involves understanding and identifying attackers' methods to avoid detection and bypass security measures on workstations and server systems. Defence evasion is a critical tactic in the MITRE ATT\&CK framework, and it includes techniques like disabling security software, deleting logs, obfuscation, rootkits, privilege escalation, and more.

### **1. Understanding Defence Evasion Techniques**

* **Disabling Security Software**: Check for evidence of disabled or tampered antivirus, firewalls, or other security tools.
* **Log Tampering**: Look for signs of altered or deleted logs.
* **Obfuscation and Encoding**: Identify the use of obfuscation in scripts and commands to evade detection.
* **Rootkits**: Search for evidence of rootkits that hide malicious activity.
* **File Deletion and Hiding**: Investigate techniques to hide or delete files.
* **Privilege Escalation**: Ascertain if the elevation of privileges was part of the evasion strategy.

### **2. Data Collection and Preservation**

* **Forensic Imaging**: Create complete images of affected systems using tools like FTK Imager or dd.
* **Memory Capture**: Use tools like WinPmem or Magnet RAM Capture for memory imaging.
* **Log Collection**: Gather all relevant logs, including security, system, and application logs.

**3. Investigation of Security Software Tampering**

* **Antivirus and EDR Logs**: Check the logs of antivirus or EDR solutions for signs of deactivation or bypass.
* **Firewall Configuration**: Review firewall settings for unauthorised changes.
* **Windows Defender**: Look for changes in Windows Defender settings, especially using PowerShell commands or Group Policy modifications.

### **4. Log Analysis**

* **Event Logs**: Examine Windows Event Logs for evidence of cleared logs (Event ID 1102 for Windows security log clearance).
* **SIEM Systems**: If a SIEM system is in use, analyse it for gaps or inconsistencies in log data.
* **Security Log Review:** Examine logs for signs of clearing or tampering (e.g., Windows Event ID 1102 indicates security log clearance).
* **Audit Log Settings:** Verify if audit settings were altered to evade detection.
* **File Access Logs:** Check logs for access to sensitive files or logs by unauthorised users or processes.

### **5. Investigating Obfuscation Techniques**

·        **Script Analysis:** Examine any found scripts for obfuscation techniques like base64 encoding, concatenation, or use of uncommon scripting languages. ·        **Command-Line Analysis:** Review command-line history for obfuscated or encoded commands.

### **6. Rootkit Detection**

* **Rootkit Scanners**: Utilize rootkit detection tools like GMER or Rootkit Revealer.
* **Memory Analysis**: Analyse system memory for signs of kernel-level rootkits.

### **7. Analysis of File and Directory Changes**

* **File Integrity Monitoring Tools**: Review reports from file integrity monitoring solutions.
* **Recycle Bin Analysis**: Check the Recycle Bin for recently deleted files.
* **Alternate Data Streams**: Search for hidden data in NTFS Alternate Data Streams.

### **8. Network Traffic Analysis**

* **Network Monitoring Tools**: Use tools like Wireshark or Tcpdump to analyse network traffic for signs of data exfiltration or C2 communication.
* **DNS Query Logs**: Review DNS logs for unusual or repeated queries, which could indicate covert channels.

### **9. Use of Specialised Forensic Tools**

* **Forensic Suites**: Tools like EnCase, AXIOM Cyber, Binalyze-Air or Autopsy for comprehensive system analysis.
* **Sysinternals Suite**: Tools like Process Explorer, Autoruns, and TCPView for detailed system analysis.

### **10. Documentation and Reporting**

* **Detailed Documentation**: Keep a detailed record of all findings, tools used, and methods applied.
* **Forensic Report**: Prepare a comprehensive report detailing the evasion techniques identified and their impact.

### **11. Post-Investigation Actions**

* **Remediation and Mitigation**: Implement security measures to counter the identified evasion techniques.
* **Recovery**: Restore systems from clean backups if necessary.
* **Security Posture Enhancement**: Update security policies and tools based on findings.

### **12.** Tools and Techniques

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

### **13. Key Considerations**

* **Chain of Custody**: Maintain an accurate chain of custody for all evidence.
* **Legal and Compliance**: Ensure compliance with legal and organisational guidelines during the investigation.
* **Confidentiality and Integrity**: Maintain confidentiality and integrity of data throughout the investigation process.

Each case of defence evasion can be unique, requiring a tailored approach depending on the specifics of the incident and the environment.
