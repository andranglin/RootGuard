---
cover: ../../.gitbook/assets/Screenshot 2025-01-05 110640.png
coverY: 0
---

# Incident Triage

## Introduction

Incident Response (IR) is a specialised area of cybersecurity that focuses on investigating and responding to security incidents. IR techniques are used to uncover the origins and scope of an attack and facilitate a structured approach to mitigate damage, recover affected systems, and strengthen organisational defences.

***

## Difference Between Digital Forensics and Incident Response (DFIR)

Digital Forensics and Incident Response are two interconnected components of cybersecurity within the broader DFIR discipline. While they often overlap, they have distinct objectives, processes, and focuses:

### 1. Purpose

* Digital Forensics:
  * Focuses on the investigative aspect of cybersecurity.
  * Aims to uncover and analyse evidence from digital systems to determine how an incident occurred.
  * Often used to support legal, compliance, or investigative objectives.
* Incident Response:
  * Focuses on the active management of incidents as they occur.
  * Aims to contain, mitigate, and recover from security breaches or attacks.
  * Prioritises rapid action to minimise damage and restore operations.

### 2. Key Goals

* Digital Forensics:
  * Reconstruct the timeline and scope of an attack.
  * Identify the attacker(s) methods, tools, and goals.
  * Collect and preserve evidence for legal or regulatory purposes.
* Incident Response:
  * Limit the immediate impact of a cyber-attack.
  * Remove the threat and prevent further damage.
  * Restore affected systems and ensure business continuity.

### 3. Timing

* Digital Forensics:
  * Conducted after an incident to investigate its root cause and gather evidence.
  * Can also occur proactively, such as during threat-hunting exercises or compliance audits.
* Incident Response:
  * Takes place during or immediately after an incident is detected.
  * Prioritises real-time containment and remediation.

### 4. Focus

* Digital Forensics:
* Emphasises analysing artifacts such as:
  * Hard drives
  * Memory dumps
  * Log files
  * Malware samples
  * Provides a detailed understanding of what occurred and how.
* Incident Response:
* Focuses on:
  * Isolating affected systems
  * Eradicating malware
  * Blocking attacker access
  * Deploying patches and recovery measures

### 5. Tools and Techniques

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
  * EDR (CrowdStrike, SentinelOne, Defender for Endpoint, Cortex XDR, FortiEDR, Veliciraptor)
  * Firewalls and IDS/IPS systems
* Techniques include log analysis, threat containment, and system restoration.

### 6. Use Cases

* Digital Forensics:
  * Investigating a past breach or insider threat.
  * Supporting legal cases with evidence.
  * Compliance audits and regulatory reporting.
* Incident Response:
  * Mitigating ongoing ransomware or malware attacks.
  * Containing phishing or social engineering incidents.
  * Responding to Distributed Denial of Service (DDoS) attacks.

### 7. Output

* Digital Forensics:
* A detailed forensic report outlining:
  * How the attack happened.
  * What was affected.
  * Evidence supporting legal or compliance needs.
* Incident Response:
* An incident response summary including:
  * Steps taken to mitigate the threat.
  * Systems restored and secured.
  * Recommendations to prevent future incidents.

While Digital Forensics focuses on uncovering and analysing evidence to understand the “what” and “how” of an incident, Incident Response focuses on managing and mitigating the incident to minimise damage and ensure quick recovery. Together, they form a comprehensive approach to handling cybersecurity incidents, ensuring both immediate action and long-term learning.

DFIR is critical for modern organisations to combat increasingly sophisticated cyber threats. By combining investigative rigour with proactive response strategies, DFIR helps mitigate the immediate impacts of an attack and strengthens long-term security resilience, ensuring business continuity and stakeholder confidence.

***

## IR Resources <a href="#page-title" id="page-title"></a>

[<mark style="color:blue;">https://www.jaiminton.com</mark>](https://www.jaiminton.com/)<mark style="color:blue;">:</mark> digital forensics and incident response created and published by Jai Minton Information and Cyber Security Professional. Visit his website and support his contributions to the DFIR community.

[<mark style="color:blue;">AboutDFIR.com</mark>](https://aboutdfir.com/)<mark style="color:blue;">:</mark> The Definitive Compendium Project Digital Forensics & Incident Response. Join a community and contribute to sharing content, ideas, jobs, training, books, links, and thoughts to contribute to a global Digital Forensics & Incident Response (DFIR).

[<mark style="color:blue;">Blue-Team-Notes:</mark> ](https://github.com/Purp1eW0lf/Blue-Team-Notes) A collection of one-liners, small scripts, and tips for blue teamwork. Published by Dray Agha (Purp1eW0lf).

[<mark style="color:blue;">Awesome Cybersecurity Blue Team:</mark>](https://github.com/fabacab/awesome-cybersecurity-blueteam) A collection of awesome resources, tools, and other shiny things for cybersecurity blue teams. Published by fabacab.

[<mark style="color:blue;">Infosec Reference:</mark>](https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/DFIR.md) A huge collection of Forensics & Incident Response resources

[<mark style="color:blue;">DFIR MADNESS:</mark>](https://dfirmadness.com/) The mission is to share the “thrill of the hunt” through teaching the art of Defensive Forensics, Incident Response, and Threat Hunting. Published by James Smith

[<mark style="color:blue;">Incident Handler's Handbook</mark>](https://www.sans.org/white-papers/33901/)

[<mark style="color:blue;">Computer Security Incident Handling Guide:</mark> ](https://csrc.nist.gov/pubs/sp/800/61/r2/final)NIST SP 800-61 Rev.2

[<mark style="color:blue;">Public IR Playbooks:</mark>](https://gitlab.com/syntax-ir/playbooks#ir-playbooks) This repository contains a list of Incident Response Playbooks and Workflows that could be used in CSOC.

[<mark style="color:blue;">Incident Response Consortium:</mark> ](https://www.incidentresponse.com/mini-sites/playbooks/)The Incident Response Playbook helps prepare for and handle incidents without worrying about missing a critical step.

[<mark style="color:blue;">SANS Posters & Cheatsheets</mark>](https://www.sans.org/posters/)

***

## Other Open-source Tools

[<mark style="color:blue;">Awesome Incident Response:</mark> ](https://github.com/meirwah/awesome-incident-response)List of DFIR tools

[<mark style="color:blue;">REMnux:</mark> ](https://remnux.org/)A Linux Toolkit for Malware Analysis

[<mark style="color:blue;">FLARE VM:</mark> ](https://cloud.google.com/blog/topics/threat-intelligence/flare-vm-the-windows-malware/)The Windows Malware Analysis Distribution.

[<mark style="color:blue;">SIFT Workstation:</mark> ](https://www.sans.org/tools/sift-workstation/)The SIFT Workstation is a collection of free and open-source incident response and forensic tools designed to perform detailed digital forensic examinations in various settings. It can match any current incident response and forensic tool suite.
