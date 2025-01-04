---
icon: laptop-code
cover: ../../../.gitbook/assets/Screenshot 2025-01-04 152247 (1).png
coverY: 0
---

# Approaches for Investigating Common Attack Techniques

## <mark style="color:blue;">**Introduction**</mark>

In the ever-evolving landscape of cybersecurity, understanding and mitigating common attack techniques is a fundamental skill for security professionals. Adversaries continuously refine their methods, exploiting vulnerabilities and leveraging sophisticated tactics to infiltrate networks, compromise systems, and exfiltrate sensitive data. As defenders, Security Operations Center (SOC) analysts and threat hunters are at the forefront of this battle, tasked with identifying, investigating, and responding to these threats in realtime.

This guide delves into the practical techniques for investigating common attack scenarios, providing actionable insights for detecting malicious activity across various stages of the attack lifecycle. It draws upon established frameworks like MITRE ATT\&CK to break down the tactics and techniques used by adversaries, offering a structured approach to threat investigation. Whether it's uncovering evidence of lateral movement, detecting credential theft attempts, or analysing execution traces in Windows environments, the methodologies presented here are designed to empower security practitioners with the tools and knowledge they need to stay ahead of the adversary.

By focusing on the key pillars of modern threat investigation—such as leveraging Windows Security Logs, analysing commandline activities, and correlating indicators of compromise (IOCs)—this resource aims to equip SOC analysts with the capability to uncover hidden threats and strengthen their organisation's defence posture. From identifying malware infections to tracking actor discovery activities and preventing potential data theft, the techniques outlined in this guide are tailored to address the challenges of investigating the most prevalent attack vectors in today's threat landscape.

Whether you are a seasoned analyst or new to the field, the respective section of this guide is a practical companion for developing effective investigative strategies. Mastering these techniques will enhance your threat-hunting capabilities and contribute to a more robust and proactive cybersecurity ecosystem.

The respective sections use KQL query examples to demonstrate investigative processes and analysis. Regardless of the platform used in your environment, these queries can be translated using a platform like UNCODER.IO. Otherwise, queries are used in their basic form to aid understanding and gain expertise.

Investigating common attack techniques requires a methodical approach tailored to the tactics and techniques attackers use. These approaches align well with the MITRE ATT\&CK framework. Below are common attack techniques, their indicators, and investigative strategies:

## <mark style="color:blue;">1. Phishing (T1566)</mark>

**Objective:** Deliver malicious payloads or steal credentials via deceptive emails or links.

**Indicators:**

* Unusual email domains or senders.
* Suspicious URLs in email content.
* Unexpected attachments or macro-enabled documents.
* User complaints about redirected logins.

**Investigation:**

* Email Analysis:
  * Examine headers to verify the sender's authenticity.
  * Check URLs against threat intelligence sources.
  * Analyse attachments in a sandbox environment.
* Network Monitoring:
  * Look for outbound traffic to newly registered or suspicious domains.
* User Account Activity:
  * Identify unusual login attempts or failed authentications.

### <mark style="color:blue;">Phishing Playbook</mark>

**Preparation:**

* Train users on identifying phishing emails.
* Implement email filtering solutions (SPF, DKIM, DMARC).
* Configure sandboxing for email attachments and URLs.

**Detection:**

* Monitor email logs for suspicious senders or domains.
* Flag emails with unusual attachments (macro-enabled Office files).
* Use threat intelligence feeds to cross-check URLs or attachments.

**Investigation:**

* Analyse email headers for spoofing or forged sender details.
* Extract and analyse URLs or attachments in a secure sandbox.
* Check impacted user accounts for signs of compromise (unauthorised logins).

**Containment:**

* Quarantine suspected emails across user inboxes.
* Block malicious domains, URLs, and IPs on the email gateway and firewall.

**Eradication:**

* Revoke access for compromised accounts.
* Reset passwords and enforce MFA on affected accounts.

**Recovery:**

* Notify users about the phishing attempt.
* Update email filters and threat intelligence rules.

## <mark style="color:blue;">2. Credential Dumping (T1003)</mark>

**Objective:** Extract credentials from memory, files, or databases.

**Indicators:**

* Presence of tools like Mimikatz, ProcDump, or LSASS dumps.
* Access to SAM, NTDS.dit, or LSASS.exe.
* Unusual processes accessing sensitive files.

**Investigation:**

* Host Analysis:
  * Check for the presence of suspicious tools or scripts.
  * Review memory dumps and process activity.
* Log Analysis:
  * Audit Windows Event Logs (Security, System) for anomalies.
  * Look for Event ID 4624 (Logon) and 4672 (Special Privileges Assigned).
* Access Control:
  * Verify if privileged accounts were accessed or used.

### <mark style="color:blue;">Credential Dumping Playbook</mark>

**Preparation:**

* Harden endpoints against dumping tools (disable WDigest, LSASS protections).
* Deploy EDR solutions to detect suspicious memory or credential access.

**Detection:**

* Monitor processes accessing LSASS.exe or credential stores.
* Look for tools like Mimikatz, ProcDump, or custom scripts.

**Investigation:**

* Review endpoint logs for anomalous credential access activities.
* Analyse memory dumps or forensic images for evidence of dumping tools.

**Containment:**

* Isolate affected endpoints from the network.
* Disable compromised accounts and reset passwords.

**Eradication:**

* Remove credential dumping tools and malicious binaries.
* Apply patches for known vulnerabilities that could enable dumping.

**Recovery:**

* Audit all administrative credentials for compromise.
* Implement just-in-time (JIT) or least privilege access for sensitive accounts.

## <mark style="color:blue;">3. Lateral Movement (T1021)</mark>

**Objective:** Move through the network to reach high-value targets.

**Indicators:**

* Use of remote management tools (RDP, PSExec).
* SMB traffic between unexpected hosts.
* Unauthorised use of administrative credentials.

**Investigation:**

* Network Traffic:
  * Inspect internal traffic for unusual RDP, SMB, or WinRM activity.
  * Monitor for brute-force attempts or account enumeration.
* Endpoint Monitoring:
  * Identify processes spawning remote connections.
* Authentication Logs:
  * Review Event IDs 4624 and 4648 for patterns of credential use.
  * Detect unusual logins from geographically or temporally abnormal locations.

### <mark style="color:blue;">Lateral Movement Playbook</mark>

**Preparation:**

* Implement network segmentation and limit lateral communication.
* Enable detailed logging for RDP, SMB, and WinRM activities.

**Detection:**

* Use SIEM to detect unusual SMB traffic or RDP connections.
* Monitor authentication logs for account usage across multiple hosts.

**Investigation:**

* Correlate logs to trace the path of attacker movement.
* Identify compromised credentials used for lateral movement.

**Containment:**

* Disable or isolate accounts used for lateral movement.
* Block malicious connections via firewall rules or endpoint controls.

**Eradication:**

* Patch exploited vulnerabilities.
* Remove tools or scripts facilitating lateral movement.

**Recovery:**

* Review and harden permissions and firewall rules.
* Conduct a security assessment of all affected systems.

## <mark style="color:blue;">4. Privilege Escalation (T1068)</mark>

**Objective:** Gain higher privileges on a compromised system.

**Indicators:**

* Creation or modification of local admin accounts.
* Exploitation of vulnerabilities (e.g., kernel exploits).
* Execution of scripts targeting privilege escalation.

**Investigation:**

* Vulnerability Analysis:
  * Check patch status of the system against known CVEs.
* Log Review:
  * Look for Event ID 4672 (Special Privilege Assigned).
  * Monitor changes in local or domain administrator groups.
* File System:
  * Identify new binaries or scripts in sensitive directories.

### <mark style="color:blue;">Privilege Escalation Playbook</mark>

**Preparation:**

* Ensure systems are up-to-date with security patches.
* Disable unused or risky features (UAC bypass techniques).

**Detection:**

* Monitor for event IDs related to privilege escalation (4672).
* Detect execution of known escalation tools or scripts.

**Investigation:**

* Identify how attackers gained initial access and escalated privileges.
* Analyse new account creations or group membership changes.

**Containment:**

* Revoke elevated privileges for unauthorised users.
* Isolate systems where escalation occurred.

**Eradication:**

* Patch vulnerabilities and harden configurations.
* Remove any persistence mechanisms (malicious services).

**Recovery:**

* Reinforce least privilege policies.
* Conduct periodic privilege audits.

## <mark style="color:blue;">5. Persistence (T1547)</mark>

**Objective:** Maintain long-term access to compromised systems.

**Indicators:**

* New or modified autorun registry keys.
* Scheduled tasks or services created without authorisation.
* Unexpected startup items.

**Investigation:**

* Registry and File Analysis:
  * Inspect autorun locations (HKLM\Software\Microsoft\Windows\CurrentVersion\Run).
  * Check for unusual startup scripts or binaries.
* Scheduled Task Review:
  * Identify newly created or modified tasks.
* Service Analysis:
  * Detect new or altered services (sc query, Get-Service).

### <mark style="color:blue;">Persistence Playbook</mark>

**Preparation:**

* Enable logging for autorun, task scheduler, and service activities.
* Implement file integrity monitoring.

**Detection:**

* Look for new or modified registry keys in autorun locations.
* Monitor for unexpected startup items or scheduled tasks.

**Investigation:**

* Analyse registry keys, tasks, and services for malicious entries.
* Examine file metadata for suspicious executables or scripts.

**Containment:**

* Disable or delete persistence mechanisms.
* Isolate systems where persistence is confirmed.

**Eradication:**

* Remove malicious files and registry entries.
* Reinstall or restore affected services to clean states.

**Recovery:**

* Harden registry and startup configurations.
* Review GPO settings for additional restrictions.

## <mark style="color:blue;">6. Command and Control (C2) Communications (T1071)</mark>

**Objective:** Maintain communication between attacker-controlled infrastructure and compromised systems.

**Indicators:**

* Traffic to uncommon ports or IPs.
* Obfuscated protocols (e.g., DNS tunneling).
* Periodic beaconing patterns.

**Investigation:**

* Network Traffic Analysis:
  * Review logs for suspicious or unknown domains/IPs.
  * Look for irregular patterns in DNS or HTTP traffic.
* Process Monitoring:
  * Identify processes initiating outbound connections.
  * Correlate network activity with local logs.
* Threat Intelligence:
  * Match IOCs with known C2 infrastructure.

### <mark style="color:blue;">Command and Control (C2) Playbook</mark>

**Preparation:**

* Deploy network monitoring tools (e.g., IDS/IPS, NetFlow analysis).
* Update blocklists for known C2 domains and IPs.

**Detection:**

* Monitor outbound traffic for beaconing patterns.
* Look for anomalous use of protocols like DNS, HTTP, or HTTPS.

**Investigation:**

* Identify processes or applications initiating C2 traffic.
* Correlate network traffic with local endpoint logs.

**Containment:**

* Block C2 domains or IPs in firewalls and DNS filters.
* Terminate processes initiating C2 communications.

**Eradication:**

* Remove malware or scripts responsible for C2 traffic.
* Investigate how the C2 infrastructure was set up.

**Recovery:**

* Conduct additional scans for residual C2 activity.
* Harden egress filtering and network segmentation.

## <mark style="color:blue;">7. Data Exfiltration (T1020)</mark>

Objective: Steal sensitive data from the victim's network.

**Indicators:**

* Large volumes of data transferred to external IPs.
* Use of uncommon protocols or tools for data transfer.
* Unusual compression or encryption tools on endpoints.

**Investigation:**

* Data Transfer Monitoring:
  * Review DLP logs for flagged activities.
  * Inspect egress traffic for excessive or unauthorised transfers.
* Host Analysis:
  * Identify compression or encryption utilities.
  * Check for staging directories or temporary file repositories.
* Access Logs:
  * Audit file access patterns for sensitive directories.

### <mark style="color:blue;">Data Exfiltration Playbook</mark>

**Preparation:**

* Implement Data Loss Prevention (DLP) solutions.
* Monitor for large data transfers or unusual compression activities.

**Detection:**

* Detect high-volume or unauthorised data transfers.
* Identify anomalous egress traffic (e.g., new external connections).

**Investigation:**

* Track data flow to determine what was exfiltrated.
* Correlate user or system activities leading to the event.

**Containment:**

* Block external IPs or domains involved in exfiltration.
* Suspend accounts or systems used for the transfer.

**Eradication:**

* Remove tools or processes used to stage or transfer data.
* Mitigate vulnerabilities exploited for access.

**Recovery:**

* Notify relevant stakeholders if sensitive data was leaked.
* Strengthen egress controls and user activity monitoring.

## <mark style="color:blue;">8. Execution (T1059)</mark>

**Objective:** Run malicious code or scripts on target systems.

**Indicators:**

* Use of PowerShell, WMI, or other scripting engines.
* Unusual processes spawned by legitimate applications.
* Files dropped in uncommon directories (e.g., Temp, AppData).

**Investigation:**

* Process Analysis:
  * Look for parent-child relationships (e.g., Word spawning PowerShell).
  * Inspect command-line arguments of suspicious processes.
* Script Review:
  * Analyse PowerShell, VBScript, or Batch files for malicious intent.
* Endpoint Monitoring:
  * Review logs for script block logging (PowerShell Event ID 4104).

### <mark style="color:blue;">Execution Playbook</mark>

**Preparation:**

* Enable detailed logging for script and binary execution.
* Use EDR to monitor process activity and command-line arguments.

**Detection:**

* Detect unusual script execution (e.g., PowerShell, WMI).
* Monitor processes spawned from Office documents or web browsers.

**Investigation:**

* Analyse command-line arguments and scripts for malicious behaviour.
* Correlate execution activity with known IOCs or TTPs.

**Containment:**

* Terminate malicious processes.
* Isolate systems where suspicious execution occurred.

**Eradication:**

* Remove malicious scripts or binaries.
* Patch vulnerabilities exploited for execution.

**Recovery:**

* Harden script execution policies (e.g., PowerShell Constrained Language Mode).
* Update endpoint security configurations.

## <mark style="color:blue;">General Investigation Tips:</mark>

1. Correlate Logs Across Layers:
   * Use SIEM to aggregate and correlate endpoint, network, and application logs.
2. Utilise Threat Intelligence:
   * Enrich IOCs (IPs, hashes, domains) with threat intelligence sources.
3. Preserve Evidence:
   * Follow proper forensic procedures to ensure admissibility in legal contexts.
4. Automate Where Possible:
   * Use SOAR platforms to automate repetitive analysis tasks.

### <mark style="color:blue;">Automation Workflows</mark>

1. **Phishing Workflow:**
   * Automated email analysis: Extract URLs/attachments, sandbox them, and flag malicious artifacts.
   * Auto-quarantine affected emails and block URLs at the gateway.
2. **Credential Dumping Workflow:**
   * Real-time alerts for processes accessing LSASS.exe or dumping credentials.
   * Automated containment actions: Isolate endpoints and disable compromised accounts.
3. **Lateral Movement Workflow:**
   * Monitor for suspicious SMB or RDP activity using SIEM.
   * Automate blocking of lateral connections and alert escalation.
4. **C2 Communication Workflow:**
   * DNS or traffic monitoring for periodic beaconing patterns.
   * Auto-block of malicious IPs/domains and correlated endpoint analysis.
5. **Data Exfiltration Workflow:**
   * DLP alert triggers for high-volume transfers.
   * Automated throttling or blocking of egress traffic.

### <mark style="color:blue;">Platform Integration</mark>

* Splunk/Sentinel SIEM: Custom SPL or KQL query templates for detecting each technique.
* Microsoft Defender: Workflows for automated containment and remediation using Defender XDR/Sentinel.
* SOAR Tools (Palo Alto Cortex XSOAR, IBM Resilient): Pre-built automation scripts and playbooks.

