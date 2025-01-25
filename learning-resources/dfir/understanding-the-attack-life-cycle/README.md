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

# Understanding the Attack Life Cycle

## Understanding the Attack Life Cycle in a Windows Environment

The attack life cycle in a Windows environment is broadly divided into three critical phases that outline the progression of an attacker’s activities.&#x20;

#### **Phase 1 – Gaining an Initial Foothold:**

Involves the attacker gaining access to a single endpoint or system within the target network. This is often achieved through tactics like phishing emails, malicious attachments, drive-by downloads, or exploiting vulnerabilities in outdated software. Once access is established, the attacker frequently deploys malware or tools like PowerShell scripts to escalate privileges and establish persistence. At this stage, artifacts such as unusual login attempts, newly created local accounts, and suspicious commandline activity can be observed in Windows Security Logs and endpoint detection tools like Microsoft Defender for Endpoint.

#### **Phase 2 – Maintaining Enterprise-Wide Access and Visibility Across the Network** :

&#x20;This is characterised by the attacker’s efforts to expand their control and reconnaissance capabilities. Using the initial foothold, they typically conduct lateral movement to gain access to other systems and resources within the environment. Common techniques include pass-the-hash, pass-the-ticket, and exploiting unpatched vulnerabilities in Active Directory. Attackers may deploy tools like Mimikatz to harvest credentials or leverage administrative utilities like PsExec and WMI for remote execution. During this phase, network traffic analysis and Windows event logs related to Kerberos and NTLM authentication can provide indicators of unauthorised activities. The attacker’s goal is to embed themselves deeply enough to sustain access without detection.

**Phase 3 – Data Exfiltration and Impact:**&#x20;

The attackers achieve their ultimate objectives, which could range from stealing sensitive data to deploying ransomware or disrupting critical operations. Data exfiltration often involves compressing and encrypting files before transferring them outside the network via HTTP, HTTPS, FTP, or cloud storage services. Attackers may also attempt to delete event logs or disable security tools to cover their tracks. Key indicators during this phase include unusual outbound traffic, large file transfers to unknown IPs, and the use of uncommon protocols. Additionally, attackers might execute destructive actions, such as encrypting files or wiping systems, leaving the organisation with significant operational and financial damage.

By understanding these phases, the security teams and, more broadly, organisations can implement proactive defence measures, such as monitoring for early signs of compromise, securing lateral movement paths, and analysing outbound traffic for potential data exfiltration. In a Windows environment, leveraging tools like Windows Security Event Logs, Defender XDR, and Velociraptor can provide critical insights across the attack life cycle. Additionally, aligning detection and response efforts with the MITRE ATT\&CK framework can enhance an organisation’s ability to identify, contain, and mitigate sophisticated threats effectively.

Throughout the detection and investigative subsections of Understanding the Attack Life Cycle, the Unified Kill Chain model will be used as it capitalises on both the Mitre and Cyber Kill Chain models of attacker methodologies.

## The Unified Kill Chain for Cyber Attack Investigations <a href="#f5bb" id="f5bb"></a>

[The Unified Kill Chain](https://www.unifiedkillchain.com/) is a combination of the [Cyber Kill Chain](https://warnerchad.medium.com/cyber-kill-chain-for-cti-f27438fe2a1) and [MITRE ATT\&CK](https://warnerchad.medium.com/mitre-att-ck-for-cti-5c267dca59c2) tactics. It is intended to be an updated version of the Cyber Kill Chain to better fit modern attacks.

The **Unified Kill Chain (UKC)** defines the attack lifecycle through **three overarching phases**, further broken into **18 distinct steps**. These phases encapsulate the attacker’s journey from initial access to achieving their objectives, providing a comprehensive understanding of modern cyberattacks. Here's a detailed look at the attack phases in the UKC:

***

### **1. Initial Foothold**

This phase covers the attacker’s efforts to infiltrate the target network or system and establish an initial presence. It mirrors the early stages of traditional attack models like reconnaissance and exploitation. The attacker seeks to avoid detection while planting the seeds for further exploitation.

1. **Reconnaissance**: Gathering information about the target, such as network structure, technologies in use, or employee data, to identify vulnerabilities.
2. **Weaponisation**: Developing or acquiring tools, such as malware or exploit kits, to target identified vulnerabilities.
3. **Delivery**: Transmitting the weaponised payload to the target, often via phishing emails, malicious links, or USB drives.
4. **Exploitation**: Exploiting a vulnerability in the target system to gain unauthorised access.
5. **Installation**: Installing malware or a backdoor to maintain access to the compromised system.

***

### **2. Network Propagation**

After gaining a foothold, attackers focus on expanding their control within the target environment. This phase includes lateral movement, privilege escalation, and reconnaissance within the network to achieve broader access and visibility.

6. **Command and Control (C2)**: Establishing a communication channel between the compromised system and the attacker’s infrastructure for remote control.
7. **Internal Reconnaissance**: Mapping the network, discovering connected systems, and identifying valuable assets or credentials for further exploitation.
8. **Credential Dumping**: Extracting credentials from the compromised system for use in lateral movement or privilege escalation.
9. **Privilege Escalation**: Elevating access privileges to administrative or system levels.
10. **Lateral Movement**: Moving across the network to access additional systems or resources using stolen credentials or exploits.
11. **Persistence**: Establishing mechanisms to maintain access over time, such as creating new accounts, modifying registry keys, or deploying backdoors.

***

### **3. Actions on Objectives**

In this final phase, attackers achieve their ultimate objectives, such as stealing data, deploying ransomware, or causing system disruption. This phase represents the culmination of their activities within the target environment.

12. **Data Collection**: Gathering sensitive information, intellectual property, or financial records from compromised systems.
13. **Data Exfiltration**: Transferring stolen data to external locations controlled by the attacker.
14. **Impact**: Causing harm to the organisation, which may include encrypting files (ransomware), destroying systems, or disrupting operations.
15. **Defence Evasion**: Taking steps to avoid detection or remediation by clearing logs, disabling security tools, or masking activity.
16. **Anti-Forensics**: Modifying or destroying forensic evidence to hinder investigation and analysis.
17. **Execution**: Running final malicious commands, scripts, or payloads to achieve their goals.
18. **Action Completion**: Wrapping up the attack by either covering tracks or preparing the system for future exploitation.

***

### Summary of the Unified Kill Chain Phases

The **Initial Foothold** phase focuses on getting access to the target. The **Network Propagation** phase emphasises gaining deeper control and access across the environment. Finally, the **Actions on Objectives** phase centers on achieving the attacker's ultimate goals, which can range from data theft to operational disruption. By breaking down these phases into 18 steps, the UKC provides a granular, actionable roadmap for defenders to identify, mitigate, and disrupt attacks at every stage. It enables a proactive defence by offering insights into the tactics, techniques, and procedures (TTPs) attackers use.
