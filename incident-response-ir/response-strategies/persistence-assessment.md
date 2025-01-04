---
icon: laptop-code
---

# Persistence Assessment

**Description:** Investigating persistence mechanisms in a network, Windows workstations, and server systems is crucial in understanding how attackers maintain access to compromised environments. Persistence allows attackers to regain entry even after initial entry points are closed, making it a critical aspect of forensic analysis.

### **1. Understand Common Persistence Techniques**

* **Registry Keys**: Autoruns, Run keys, and other registry locations where programs can be set to run on startup.
* **Startup Folders**: Programs placed in these directories will automatically launch at startup.
* **Scheduled Tasks**: Malicious tasks can be scheduled to run at specific times or intervals.
* **Service Creation**: Malware can install itself as a service, which is automatically started by Windows.
* **DLL Hijacking**: Malware replaces legitimate DLLs or adds malicious DLLs referenced by legitimate programs.
* **WMI Event Subscriptions**: WMI can execute scripts or binaries in response to certain system events.
* **Account Manipulation**: Creation of new user accounts or modification of existing accounts for future access.

### **2. Data Collection and Preservation**

* **Forensic Imaging**: Use tools like FTK Imager or dd to create images of affected systems.
* **Live System Data**: If possible, gather live data, including running processes, network connections, and currently loaded drivers.
* **Log Collection**: Collect security logs, system logs, application logs, and event logs.

### **3. Analysis Techniques**

* **Registry Analysis**: Use tools like Registry Explorer or RegRipper to analyse registry hives for unauthorised modifications.
* **File System Analysis**: Tools like Autopsy or X-Ways can analyse file systems for suspicious files in startup directories, unusual file creation/modification dates, or hidden files.
* **Scheduled Task Analysis**: Review Windows Task Scheduler for unrecognised or suspicious tasks.
* **Service Analysis**: Examine the list of installed services for unknown or modified services.
* **Log Analysis**: Investigate logs for evidence of account creation, modification, or other signs of unauthorised access.

### **4. Investigate Common Persistence Locations**

* **Autostart Locations**: Check common autostart locations like **HKCU\Software\Microsoft\Windows\CurrentVersion\Run** or **HKLM\Software\Microsoft\Windows\CurrentVersion\Run**.
* **Startup Directories**: Inspect directories like **%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup**.
* **Task Scheduler**: Look for tasks that execute on system start or at regular intervals.
* **Services**: Analyse the list of services (**services.msc**) for new or modified entries.

### **5. Network Analysis**

* **Endpoint Detection and Response (EDR)**: Use EDR tools to monitor network traffic for signs of C2 communication.
* **SIEM Systems**: Analyse aggregated logs for patterns indicative of persistence mechanisms.

### **6. Utilise Specialised Forensic Tools**

* **Sysinternals Suite**: Tools like Autoruns can help identify programs configured to run during system bootup.
* **PowerShell Scripts**: Scripts like **Get-Service**, **Get-ScheduledTask**, or custom scripts can help identify anomalies.

### **7. Documentation and Reporting**

* **Detailed Documentation**: Keep a detailed record of all findings, methods used, and evidence paths.
* **Reporting**: Prepare a comprehensive report outlining the persistence mechanisms found, their impact, and recommendations for remediation.

### **8. Remediation and Recovery**

* **Remove Persistence Mechanisms**: Based on findings, remove or disable the identified persistence mechanisms.
* **Strengthen Defenses**: Update security policies, patch vulnerabilities, and adjust endpoint protection strategies.

### **9. Post-Incident Analysis**

* **Review and Learn**: Analyse the incident to understand how the persistence was established and improve defences accordingly.

### **10.**  Tools and Techniques

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

### **11. Key Considerations**

* **Legal and Compliance**: Ensure compliance with legal and organisational guidelines.
* **Chain of Custody**: Maintain a clear chain of custody for all forensic evidence.
* **Confidentiality**: Ensure that sensitive data is handled appropriately.

Persistence investigation requires a comprehensive approach, leveraging various tools and techniques to uncover how attackers maintain access. Tailor your investigation to the specifics of the incident and the environment you are dealing with.
