---
icon: laptop-code
---

# Command Execution Assessment

**Description:** Investigating command execution on a network, particularly in Windows workstations and server systems, is a crucial aspect of understanding the extent and impact of a security incident. This process involves identifying and analysing the commands that an attacker executes after gaining access.

### **1. Understanding Common Command Execution Sources**

* **Command-Line Interface (CLI):** Windows Command Prompt, PowerShell, and Unix/Linux terminals.
* **Scripts:** Batch files, PowerShell scripts, VBS scripts, etc.
* **Scheduled Tasks:** Tasks that execute commands at specified times.
* **Remote Execution Tools:** Tools like PsExec or remote desktop applications.
* **Application Execution:** Applications that execute system command

### **2. Collecting Data**

* **System Logs:** Collect and examine Windows Event Logs, primarily focusing on the Security, System, and Application logs.
* **Command History:** In Windows, check PowerShell and Command Prompt history. PowerShell logs can be found in Event Viewer under "Windows Logs" > "Application and Services Logs" > "Windows PowerShell".
* **Scheduled Tasks and Startup Programs:** Check for unknown or modified scheduled tasks and startup programs that could execute commands.

### **3. Analysing Execution Artifacts**

* **Prefetch Files:** Analyse Prefetch files in Windows to identify executed programs.
* **Registry Analysis:** Examine registry keys associated with command execution, like **Run**, **RunOnce**, and PowerShell's **Transcription** logging.
* **File System Analysis:** Check the creation and modification dates of suspicious files.
* **Shellbags**: Analyse shellbags for evidence of command execution via Windows Explorer.
* **Command-Line Interface (CLI):** Windows Command Prompt, PowerShell, and Unix/Linux terminals.
* **Scripts:** Batch files, PowerShell scripts, VBScripts, etc.
* **Scheduled Tasks:** Tasks that execute commands at specified times.
* **Remote Execution Tools:** Tools like PsExec or remote desktop applications.
* **Application Execution:** Applications that execute system command

### **4. Memory Forensics**

* Use tools like Volatility to analyse memory dumps for evidence of recently executed commands or processes.

### **5. Network Traffic Analysis**

* **Check for Command & Control Traffic:** Analyse network traffic logs for any signs of command and control communication, which might indicate remote execution of commands.
* **Data Exfiltration:** Look for patterns or large data transfers that might indicate data being collected and sent out.

### **6. Analysis of Command Execution**

* **Windows Command Line Logs:** Windows logs command line activity in Event ID 4688. These logs show the command line process creation events.
* **PowerShell Logging:** Review PowerShell script block logging (Event ID 4104), module logging, and transcription logs for executed commands.
* **Bash History (for Unix/Linux):** Analyse the .bash\_history file for executed commands.
* **Scheduled Tasks Analysis:** Investigate the Windows Task Scheduler and cron jobs (for Unix/Linux) for any scheduled tasks running commands.
* **Remote Execution Tools Logs:** Examine logs from tools like PsExec or remote desktop software

### **7. User Account and Authentication Logs**

* Review logs related to user authentication and account usage, particularly focusing on any elevation of privileges or use of administrative accounts.

### **8. Correlation and Timeline Analysis**

* Correlate the gathered data to build a timeline of events, helping to understand the sequence and scope of the executed commands.

### **9. Malware and Script Analysis**

* If any scripts or malware are found, analyse them to determine their functionality and the commands they execute.

### **10. Interviews and Internal Investigations**

* Talk to relevant personnel who might provide insights into usual and unusual command executions, especially in the case of internal threats.

### **11. Reporting and Documentation**

* Document all findings, methodologies, and evidence in a detailed report for future reference and potential legal proceedings.

### **13.**  Tools and Techniques

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

### **13. Conclusion**

Investigating command execution requires a thorough analysis of various data sources, including system logs, memory, and network traffic. Each step, from data collection to detailed analysis and reporting, is crucial in understanding the scope and impact of the executed commands. Maintaining an updated knowledge of forensic tools and techniques is essential for effective investigation in the ever-evolving landscape of cybersecurity threats.
