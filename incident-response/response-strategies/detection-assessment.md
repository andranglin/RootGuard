# Detection Assessment

**Description:** Forensically investigating detection evasion techniques on workstations and server systems is critical to understanding how an attacker avoids being discovered by security measures. These techniques can range from disabling security software and log tampering to more advanced methods like rootkits or steganography.

### **1. Understanding Common Detection Evasion Techniques**

* **Disabling Security Tools**: Tampering with or disabling antivirus, firewalls, or other security software.
* **Log Tampering**: Deleting or modifying logs to cover tracks.
* **Rootkits**: Using rootkits to hide malicious activities at the system level.
* **Obfuscation**: Encoding or encrypting payloads and commands to evade detection.
* **Living off the Land**: Using legitimate system tools for malicious purposes to blend in with normal activities.
* **Timing-Based Evasion**: Executing activities at times when detection is less likely.

### **2. Initial Data Collection**

* **Forensic Imaging**: Create images of the hard drives of affected systems using tools like FTK Imager or dd.
* **Memory Capture**: Use tools like Magnet RAM Capture or WinPmem for capturing volatile memory, which might contain evidence of evasion techniques.

### **3. Security Software Analysis**

* **Software Logs**: Review logs from antivirus or endpoint detection and response (EDR) solutions for signs of tampering or failure.
* **Configuration Review**: Check security software configurations for unauthorised changes.

### **4. Log Analysis**

* **System and Application Logs**: Look for gaps or inconsistencies in logs that might indicate tampering.
* **Event Logs**: Windows Event Logs can reveal evidence of cleared logs (e.g., Windows Event ID 1102 for security log clearance).

### **5. Rootkit Detection**

* **Rootkit Scanning Tools**: Utilise tools like GMER or Rootkit Revealer on Windows systems.
* **Memory Analysis**: Analyse memory dumps for signs of rootkits using tools like Volatility.

### **6. Investigating Obfuscation Techniques**

* **File Analysis**: Examine scripts and executable files for signs of obfuscation or encoding.
* **Network Traffic Analysis**: Use tools like Wireshark to analyse network traffic for encrypted or unusual communications.

### **7. Living off the Land Tactics**

* **Audit System Tools Usage**: Check for abnormal usage of system tools like PowerShell, WMI, PsExec, or BITSAdmin, which can be exploited for evasion.

### **8. Timing Analysis**

* **Time Stamps**: Review timestamps of files, processes, and log entries to identify activities that occurred during unusual hours.

### **9. Use of Specialised Forensic Tools**

* **Forensic Suites**: Utilise tools like EnCase, X-Ways, or Autopsy for comprehensive system analysis.
* **Sysinternals Suite**: For in-depth analysis of Windows systems, tools like Process Explorer and Autoruns are helpful.

### **10. Documentation and Reporting**

* **Detailed Documentation**: Record all findings, methodologies, and tools used.
* **Forensic Report**: Compile a comprehensive report detailing the investigation and findings.

### **11. Post-Investigation Actions**

* **Mitigation and Remediation**: Based on the findings, implement security measures to prevent similar evasion tactics.
* **Enhancing Defenses**: Update detection capabilities and improve monitoring strategies.

### **12.**  Tools and Techniques

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

* **Chain of Custody**: Maintain a clear chain of custody for all forensic evidence.
* **Legal Compliance**: Ensure the investigation is compliant with legal and organisational policies.
* **Confidentiality and Integrity**: Handle all data securely, maintaining confidentiality and integrity.

Detecting and analysing system compromise techniques is a complex task that requires careful examination of various system components and logs. Tailoring the investigation to the specifics of the incident and the environment is crucial for thorough analysis.
