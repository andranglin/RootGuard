---
cover: ../../../.gitbook/assets/Screenshot 2025-01-04 152247 (1).png
coverY: 0
---

# Investigate Using MITRE ATT\&CK Methodology

### **Introduction to the MITRE ATT\&CK Framework**

The MITRE ATT\&CK (Adversarial Tactics, Techniques, and Common Knowledge) Framework is a comprehensive and dynamic repository of adversarial behaviours, tactics, techniques, and procedures (TTPs) observed in real-world cyberattacks. Developed by MITRE Corporation, the framework serves as a valuable resource for security professionals, enabling them to understand and anticipate the methods attackers use to compromise systems, escalate privileges, and achieve their objectives. Organised into matrices such as **Enterprise**, **Mobile**, and **ICS**, ATT\&CK provides structured information about attack stages, adversary goals (tactics), and the specific methods employed (techniques and sub-techniques).

***

#### **List of MITRE ATT\&CK Tactics and Techniques**

**Tactics (Adversary Goals)**

1. [**Reconnaissance**:](../../../defensive-security/incident-response/response-strategies/) Gathering information about the target.
2. [**Resource Development**:](reconnaissance-ta0043-techniques.md) Establishing resources like infrastructure, accounts, or tools.
3. [**Initial Access**:](../../../defensive-security/incident-response/response-strategies/initial-impact-assessment-techniques.md) Gaining entry to the target environment (e.g., phishing, exploiting vulnerabilities).
4. [**Execution**: ](command-execution-ta0002-techniques.md)Running malicious code on the system.
5. [**Persistence**:](persistence-ta0003-techniques.md) Maintaining access to the system over time.
6. [**Privilege Escalation**: ](../../junior-analyst-skills/kql-use-cases/privilege-escalation-ta0004.md)Gaining higher-level permissions on the system.
7. [**Defence Evasion**](defence-evasion-ta0005-techniques.md): Avoiding detection by security tools.
8. [**Credential Access**:](credential-access-ta0006-techniques.md) Stealing account credentials.
9. [**Discovery**:](discovery-ta0007-techniques.md) Gaining knowledge about the environment.
10. [**Lateral Movement**:](lateral-movement-ta0008-techniques.md) Moving across systems within the network.
11. [**Collection**:](collection-ta0009-techniques.md) Gathering data from the target.
12. [**Command and Control (C2)**:](command-and-control-c2-ta0011-techniques.md) Communicating with the compromised system.
13. [**Exfiltration**: ](exfiltration-ta0010-techniques.md)Transferring stolen data out of the network.
14. [**Impact**:](impact-ta0040-techniques.md) Disrupting operations or destroying data.

**Example Techniques (Methods Used)**

* **Phishing** (Initial Access): Delivering malicious payloads via email.
* **Command-Line Interface** (Execution): Running commands through shells or terminals.
* **Registry Run Keys/Startup Folder** (Persistence): Adding entries to maintain execution after reboot.
* **Credential Dumping** (Credential Access): Extracting credentials from memory or SAM databases.
* **Remote Desktop Protocol (RDP)** (Lateral Movement): Using RDP to access other systems.
* **Data Encrypted for Impact** (Impact): Encrypting data to render it inaccessible (e.g., ransomware).

***

#### **How Knowing These Tactics and Techniques Helps in DFIR Investigations**

1. **Structured Investigation**:
   * Understanding tactics provides a clear roadmap of an attacker’s objectives at each stage of an intrusion.
   * Techniques and sub-techniques help investigators trace specific actions, such as how initial access was achieved or how data was exfiltrated.
2. **Focused Threat Hunting**:
   * DFIR (Digital Forensics and Incident Response) teams can prioritise areas for analysis based on the techniques most commonly associated with detected adversarial behaviour.
   * For example, if suspicious lateral movement is identified, investigators can focus on techniques like `Remote Services` or `Pass-the-Ticket`.
3. **Log and Artifact Analysis**:
   * Techniques guide investigators on what to search for in logs, memory dumps, or disk images. For instance:
     * **Registry changes** for persistence.
     * **Authentication logs** for credential access and lateral movement.
     * **Command history** for execution techniques.
4. **Incident Scoping and Containment**:
   * By mapping observed behaviors to the MITRE ATT\&CK matrix, DFIR teams can determine the attacker’s progression through the kill chain, allowing for effective scoping of the incident.
   * For example, detecting `C2 over HTTPS` enables teams to block communication and identify other compromised systems.
5. **Proactive Defense and Gap Analysis**:
   * Post-incident, organisations can use ATT\&CK to identify gaps in detection or prevention mechanisms. For instance, if an attack leveraged `PowerShell` for execution and wasn’t detected, this indicates a need for better monitoring of scripting activities.
6. **Communication and Reporting**:
   * ATT\&CK provides a standardised language for documenting findings and communicating with stakeholders, enabling clear and actionable reporting.

***

By integrating the MITRE ATT\&CK framework into DFIR workflows, organisations can improve their ability to detect, analyse, and respond to incidents with precision while also fortifying their defences against future attacks.

#### **Jump In**
