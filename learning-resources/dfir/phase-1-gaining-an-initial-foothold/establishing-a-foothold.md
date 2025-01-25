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

# Establishing a Foothold

### Introduction

Establishing a Foothold is crucial for adversaries to secure persistent access to a target environment in the first phase of an attack. During this phase, attackers deploy various techniques to gain control of systems while remaining undetected. By leveraging the Unified Kill Chain (UKC) model, defenders can systematically investigate these techniques, identify signs of compromise, and implement effective mitigation strategies. This phase often involves sophisticated methods to bypass security controls and embed malicious activity into the system, enabling further propagation across the environment. Below are some of the most prevalent techniques attackers use when it comes to establishing a foothold:

* **External Remote Services (T1133):** Attackers exploit poorly secured remote access mechanisms like RDP, VPNs, or SSH to infiltrate systems.
* **Create Account (T1136):** Adversaries may create new local or domain accounts to ensure persistent access and blend in with legitimate users.
* **Create or Modify System Process (T1543.003):** Modifying system services or processes to execute malicious code under the guise of legitimate functionality.
* **Scheduled Task/Job: Scheduled Task (T1053.005):** Leveraging Windows Task Scheduler to execute payloads or scripts at set intervals.
* **Boot or Logon Autostart Execution (T1547):** Configuring malicious software to start automatically during system boot or user logon.
* **Boot or Logon Initialisation Scripts (T1037):** Modifying initialisation scripts such as `startup.bat` to execute malicious code upon system startup or logon.
* **Hijack Execution Flow (T1574):** Techniques like DLL search order hijacking, DLL injection, or DLL spoofing to redirect legitimate processes into executing malicious code.
* **Modify Authentication Process (T1556):** Tampering with authentication mechanisms or server components to maintain stealthy access or steal credentials.
* **Event Triggered Execution: Component Object Model (COM) Hijacking (T1546.015):** Hijacking COM objects to execute malicious code triggered by specific system events.
* **Event Triggered Execution: Windows Management Instrumentation (WMI) Event Subscription (T1546.003):** Abusing WMI event subscriptions to trigger malicious scripts or executables upon specific events.

By focusing on these techniques, defenders can systematically investigate suspicious activity using detection platforms like Microsoft Sentinel (KQL), Velociraptor (VQL), or Splunk (SPL). Each of these methods leaves traces that, when analysed correctly, can reveal an attacker’s activities. Applying the UKC model to this phase allows for targeted investigation and enables organisations to disrupt attackers before they can achieve their objectives.
