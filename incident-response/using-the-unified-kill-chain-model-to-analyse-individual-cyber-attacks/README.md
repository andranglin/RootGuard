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

# Using The Unified Kill Chain Model to Analyse  Individual Cyber Attacks

## The Unified Kill Chain <a href="#f5bb" id="f5bb"></a>

[The Unified Kill Chain](https://www.unifiedkillchain.com/) is a combination of the [Cyber Kill Chain](https://warnerchad.medium.com/cyber-kill-chain-for-cti-f27438fe2a1) and [MITRE ATT\&CK](https://warnerchad.medium.com/mitre-att-ck-for-cti-5c267dca59c2) tactics. It is intended to be an updated version of the Cyber Kill Chain to better fit modern attacks.

The **Unified Kill Chain (UKC)** is an evolution of traditional attack kill chain models. It combines concepts from Lockheed Martin's Cyber Kill Chain and MITRE’s ATT\&CK framework to create a comprehensive, detailed representation of the entire attack lifecycle. The UKC bridges gaps in traditional models by including both the attacker’s tactics and techniques and a defender’s perspective for detecting, mitigating, and responding to threats across all stages of an attack.

**UKC** defines the attack lifecycle through **three overarching phases**, further broken into **18 distinct steps**. These phases encapsulate the attacker’s journey from initial access to achieving their objectives, providing a comprehensive understanding of modern cyberattacks.&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-25 110158.png" alt=""><figcaption><p>The Unified Kill Chain Model</p></figcaption></figure>

### Key Characteristics of the Unified Kill Chain

The UKC is organised into three overarching categories that encompass the complete lifecycle of a cyberattack:

1. [**Initial Foothold**](phase-1-gaining-an-initial-foothold/): These steps focus on how attackers gain access to a system or network. Techniques include social engineering, phishing, exploiting vulnerabilities, or supply chain attacks.
2. **Network Propagation**: Once inside, attackers aim to expand their reach within the network. This includes lateral movement, privilege escalation, credential harvesting, and reconnaissance to locate high-value targets.
3. **Actions on Objectives**: In this phase, attackers execute their end goal, such as exfiltrating sensitive data, deploying ransomware, or disrupting services.

By combining and mapping steps from the **Cyber Kill Chain (focused on the progression of an attack)** and MITRE’s ATT\&CK framework (focused on specific techniques and tactics used by attackers), the UKC offers a granular, actionable roadmap for understanding attacks and implementing defences.

### &#x20;The Phases of the Unified Kill Chain - Attack Phases (Tactics) <a href="#id-1d27" id="id-1d27"></a>

The Unified Kill Chain 18 phases or tactics are the steps a cyberattack may progress through. Any particular attack can skip phases, repeat phases, or go out of order.

1. Reconnaissance: identify and select targets
2. Weaponization: set up infrastructure for attack
3. Delivery: Send weaponised object (e.g., malware) to target
4. Social Engineering: manipulate people to perform unsafe actions
5. Exploitation: take advantage of a vulnerability on target’s systems (possibly to execute code)
6. Persistence: maintain access to systems
7. Defense Evasion: avoiding detection and defences
8. Command and Control: communicate with compromised systems to control them
9. Pivoting: use a controlled system to gain access to others
10. Discovery: gain knowledge about system and network
11. Privilege Escalation: gain higher-level permissions
12. Execution: run attacker-controlled code
13. Credential Access: steal usernames and passwords
14. Lateral Movement: access and control other systems
15. Collection: gather data of interest
16. Exfiltration: steal data from the network
17. Impact: manipulate, interrupt, or destroy systems or data
18. Objectives: use social and technical means to achieve strategic goal

### Attack Phase Combinations <a href="#id-0d71" id="id-0d71"></a>

### [**1. Initial Foothold**](phase-1-gaining-an-initial-foothold/)

This phase covers the attacker’s efforts to infiltrate the target network or system and establish an initial presence. It mirrors the early stages of traditional attack models like reconnaissance and exploitation. The attacker seeks to avoid detection while planting the seeds for further exploitation.

1. **Reconnaissance**: Gathering information about the target, such as network structure, technologies in use, or employee data, to identify vulnerabilities.
2. **Weaponisation**: Developing or acquiring tools, such as malware or exploit kits, to target identified vulnerabilities.
3. **Delivery**: Transmitting the weaponised payload to the target, often via phishing emails, malicious links, or USB drives.
4. **Exploitation**: Exploiting a vulnerability in the target system to gain unauthorised access.
5. **Installation**: Installing malware or a backdoor to maintain access to the compromised system.

### **2. Network Propagation**

After gaining a foothold, attackers focus on expanding their control within the target environment. This phase includes lateral movement, privilege escalation, and reconnaissance within the network to achieve broader access and visibility.

6. **Command and Control (C2)**: Establishing a communication channel between the compromised system and the attacker’s infrastructure for remote control.
7. **Internal Reconnaissance**: Mapping the network, discovering connected systems, and identifying valuable assets or credentials for further exploitation.
8. **Credential Dumping**: Extracting credentials from the compromised system for use in lateral movement or privilege escalation.
9. **Privilege Escalation**: Elevating access privileges to administrative or system levels.
10. **Lateral Movement**: Moving across the network to access additional systems or resources using stolen credentials or exploits.
11. **Persistence**: Establishing mechanisms to maintain access over time, such as creating new accounts, modifying registry keys, or deploying backdoors.

### **3. Actions on Objectives**

In this final phase, attackers achieve their ultimate objectives, such as stealing data, deploying ransomware, or causing system disruption. This phase represents the culmination of their activities within the target environment.

12. **Data Collection**: Gathering sensitive information, intellectual property, or financial records from compromised systems.
13. **Data Exfiltration**: Transferring stolen data to external locations controlled by the attacker.
14. **Impact**: Causing harm to the organisation, which may include encrypting files (ransomware), destroying systems, or disrupting operations.
15. **Defence Evasion**: Taking steps to avoid detection or remediation by clearing logs, disabling security tools, or masking activity.
16. **Anti-Forensics**: Modifying or destroying forensic evidence to hinder investigation and analysis.
17. **Execution**: Running final malicious commands, scripts, or payloads to achieve their goals.
18. **Action Completion**: Wrapping up the attack by either covering tracks or preparing the system for future exploitation.

### Benefits of the Unified Kill Chain

The UKC provides defenders with a more flexible and realistic approach to cyber threats compared to earlier models. It emphasises the need for visibility across every phase of the attack lifecycle and supports mapping detection strategies and response actions to attacker behaviours. Additionally, it helps SOC teams and cybersecurity professionals prioritise their efforts by focusing on breaking the chain of events that attackers rely on to achieve their objectives.

By leveraging the UKC, organisations can better align their detection, prevention, and response efforts with real-world attack patterns, improving their resilience against sophisticated threats. It serves as a foundational tool for designing robust defence-in-depth strategies that incorporate endpoint protection, network monitoring, and advanced threat-hunting capabilities.

### Summary of the Unified Kill Chain Phases

The **Initial Foothold** phase focuses on getting access to the target. The **Network Propagation** phase emphasises gaining more profound control and access across the environment. Finally, the **Actions on Objectives** phase centres on achieving the attacker's ultimate goals, ranging from data theft to operational disruption. By breaking down these phases into 18 steps, the UKC provides a granular, actionable roadmap for defenders to identify, mitigate, and disrupt attacks at every stage. It enables a proactive defence by offering insights into attackers' tactics, techniques, and procedures (TTPs).

#### [Jump In](phase-1-gaining-an-initial-foothold/)
