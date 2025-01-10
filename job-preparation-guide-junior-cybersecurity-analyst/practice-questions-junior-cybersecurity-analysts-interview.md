---
cover: ../.gitbook/assets/Screenshot 2025-01-10 082318.png
coverY: 0
layout:
  cover:
    visible: true
    size: full
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Practice Questions: Junior Cybersecurity Analysts Interview

### <mark style="color:blue;">**Technical Questions**</mark>

1. **What is the CIA Triad?**

* **Answer:** The CIA Triad stands for Confidentiality, Integrity, and Availability – the core principles of cybersecurity.

2. **What is a false positive and false negative in a SOC context?**

* **Answer:** A false positive is a benign event flagged as malicious; a false negative is a malicious event not detected.

3. **What is lateral movement in cybersecurity?**

* **Answer:** The technique attackers use to navigate through a network after gaining initial access to achieve their objectives.

4. **What is an Indicator of Compromise (IoC)?**

* **Answer:** Evidence of a potential security breach, such as malicious file hashes, IP addresses, or unusual behaviour.

5. **Define a zero-day vulnerability.**

* **Answer:** A previously unknown vulnerability that is exploited before a patch is available.

6. **What is the difference between IDS and IPS?**

* **Answer:**
  * **IDS:** Intrusion Detection System monitors and alerts.
  * **IPS:** Intrusion Prevention System actively blocks threats.

7. **What is phishing?**

* **Answer:** A cyberattack where attackers trick users into divulging sensitive information through fake communications.

8. **Explain the difference between encryption and hashing.**

* **Answer:**
  * **Encryption:** Converts data into a secure format and can be decrypted.
  * **Hashing:** Generates a fixed-length string (hash) and is irreversible.

9. **What is the role of SIEM in a SOC?**

* **Answer:** SIEM (Security Information and Event Management) collects, analyses, and correlates logs to detect and respond to security events.

10. **What is the principle of least privilege?**

* **Answer:** Restricting user access to only the resources necessary for their role.

11. **What is the role of EDR in a SOC?**

* **Answer:** Endpoint Detection and Response tools provide real-time endpoint monitoring, detect advanced threats, and enable remote remediation.

12. **What is a web application firewall (WAF), and how does it work?**

* **Answer:** A WAF monitors and filters HTTP/S traffic to protect web applications from common attacks like XSS, SQL injection, and DDoS.

13. **Explain the difference between symmetric and asymmetric encryption.**

* **Answer:**
  * **Symmetric Encryption:** Uses one key for encryption and decryption.
  * **Asymmetric Encryption:** Uses a public key for encryption and a private key for decryption.

14. **What is threat intelligence, and how is it used in a SOC?**

* **Answer:** Threat intelligence provides information about current and emerging threats, enabling proactive defences and better detection of IoCs.

15. **How would you use Splunk to detect unusual login patterns?**

* **Answer:**
  * Query login events using SPL (Search Processing Language).
  * Identify anomalies in login times, geolocations, or failed attempts.
  * Create dashboards for continuous monitoring.

16. &#x20;**What is DNS poisoning, and how can it be detected?**

* **Answer:** DNS poisoning involves altering DNS records to redirect users to malicious sites. Detect using DNS logs, identifying mismatched records, and monitoring for unauthorised changes.

17. &#x20;**How do you secure sensitive data in transit?**

* **Answer:** Use encryption protocols like TLS/SSL, enforce secure cipher suites, and avoid deprecated protocols like SSLv3.

18. &#x20;**What is a honeypot, and how is it used in threat detection?**

* **Answer:** A honeypot is a decoy system designed to attract attackers, allowing observation and collection of attack methods.

19. &#x20;**How can you identify malicious PowerShell activity?**

* **Answer:** Monitor for:
  * Obfuscated commands.
  * Unexpected script executions.
  * PowerShell network connections to unknown IPs.

20. **What are the components of a secure software development lifecycle (SDLC)?**

* **Answer:**
  * Secure design.
  * Code reviews.
  * Static and dynamic analysis.
  * Regular patching and updates.

21. **What are the key fields to monitor in Windows Event ID 4624?**

* **Answer:**
  * **Logon Type:** Identifies the method used to log in (e.g., interactive, remote).
  * **Account Name:** Shows the user who logged in.
  * **Source Network Address:** Indicates the IP address of the logon attempt.

22. **How do you troubleshoot missing logs in a SIEM?**

* **Answer:**
  1. Verify if the log source is configured correctly.
  2. Check network connectivity between the log source and SIEM.
  3. Investigate parsing errors or misconfigurations.

23. **What are the common use cases for correlation rules in a SIEM?**

* **Answer:**
  * Brute force detection.
  * Privilege escalation attempts.
  * Data exfiltration patterns.
  * Lateral movement across systems.

24. **What is the difference between a hash collision and a hash mismatch?**

* **Answer:**
  * **Hash Collision:** Two different inputs produce the same hash value.
  * **Hash Mismatch:** A hash value does not match the expected value, indicating data alteration or corruption.

25. **Explain the importance of timestamp normalisation in SIEM logs.**

* **Answer:** It ensures logs from different sources align with a standard time format, allowing accurate event correlation.

26. **How do you investigate anomalous outbound traffic detected by a firewall?**

* **Answer:**
  * Check destination IPs against threat intelligence.
  * Correlate with internal device logs.
  * Identify processes or users initiating the traffic.

27. **What are the steps to perform static malware analysis?**

* **Answer:**
  1. Extract and analyse file metadata.
  2. Check file hashes against known malware databases.
  3. Inspect strings and code without executing the malware.

28. **How would you detect hidden persistence mechanisms on a compromised system?**

* **Answer:**
  * Review startup items, scheduled tasks, and registry keys.
  * Look for DLL hijacking or unusual services.
  * Check for unsigned binaries or scripts.

29. **What are IOC enrichment techniques in threat analysis?**

* **Answer:**
  * Using threat intelligence feeds to add context to IoCs.
  * Correlating with historical logs.
  * Leveraging tools like VirusTotal for malware hashes.

30. **How do you identify suspicious processes in real-time?**

* **Answer:**
  * Look for processes with unusual names or paths.
  * Check parent-child relationships.
  * Monitor processes consuming excessive CPU or memory.

### <mark style="color:blue;">**Log Analysis and Monitoring**</mark>

31. **What are the key Windows Event IDs for monitoring logon activity?**

* **Answer:**
  * **4624:** Successful logon.
  * **4625:** Failed logon.
  * **4776:** Credential validation.
  * **4769:** Kerberos service ticket request.

32. **How would you identify suspicious command-line activities?**

* **Answer:** Look for unusual or rarely used commands, obfuscated scripts, or command execution from unauthorised accounts.

33. **What is the difference between security logs and application logs?**

* **Answer:**
  * **Security logs** track access, authentication, and unauthorised activities.
  * **Application logs** record software-specific events and errors.

34. **How do you analyse suspicious log entries?**

* **Answer:** Look for abnormal login times, repeated failed attempts, unauthorised access to critical resources, or patterns like privilege escalation.

35. **What is the importance of time synchronisation in log analysis?**

* **Answer:** Ensures all logs across devices have consistent timestamps for accurate correlation and investigation.

36. **What tool would you use to parse large log files, and why?**

* **Answer:** Tools like Splunk, ELK stack, or simple grep commands for filtering and pattern matching efficiently.

37. **How can you identify privilege escalation attempts in Windows Event Logs?**

* **Answer:** Monitor for events like:
  * **4674:** Sensitive privilege use.
  * **4672:** Assigning special privileges.

### <mark style="color:blue;">**Threat Hunting and Incident Response**</mark>

38. **How would you detect PowerShell-based attacks?**

* **Answer:** Monitor for obfuscated commands, unusual PowerShell execution, or processes running under non-standard accounts.

39. **What is the MITRE ATT\&CK framework?**

* **Answer:** A knowledge base of adversarial tactics, techniques, and procedures used to understand, detect, and respond to threats.

40. **What methods would you use to hunt for malware on endpoints?**

* **Answer:**
  * Check for unusual processes.
  * Analyse file hashes using threat intelligence.
  * Review autorun entries and scheduled tasks.

41. **How do you identify command-and-control (C2) communication?**

* **Answer:** Monitor for beacon-like network traffic, connections to suspicious domains, or encrypted traffic on non-standard ports.

42. **What is the difference between a SOC playbook and a runbook?**

* **Answer:**
  * **Playbook:** High-level procedures for specific incidents.
  * **Runbook:** Step-by-step guides for implementing playbook actions.

### <mark style="color:blue;">**Network Security and Malware Analysis**</mark>

43. **What is the purpose of a sandbox environment?**

* **Answer:** A secure environment for analysing potentially malicious files or software without risking the production environment.

44. **How do you analyse packet captures for suspicious activity?**

* **Answer:** Use tools like Wireshark to inspect network traffic for anomalies such as unusual IPs, ports, or payloads.

45. **What is the purpose of network segmentation in security?**

* **Answer:** Minimises the spread of threats and improves monitoring by isolating sensitive systems.

46. **How do you detect malicious traffic in a packet capture (PCAP)?**

* **Answer:** Look for unusual protocols, unauthorised IPs, or payloads with malicious content.

47. **What is the role of the NetFlow tool in network security?**

* **Answer:** Provides metadata about traffic flows, helping identify anomalies like data exfiltration.

### <mark style="color:blue;">**Cloud Security and Tools**</mark>

48. **What are common threats in cloud environments?**

* **Answer:** Misconfigured settings, insecure APIs, insider threats, and data breaches.

49. **How do you use Splunk for threat detection?**

* **Answer:** Use SPL queries to analyse logs, create dashboards, and set alerts for anomalous activities.

50. **How do you investigate a misconfigured cloud storage bucket?**

* **Answer:**
  * Identify permissions and access logs.
  * Check for unauthorised data access.
  * Correct permissions to least privilege.

51. **What tools would you use for threat detection in the cloud?**

* **Answer:** Use tools like AWS GuardDuty, Asure Sentinel, or Google Chronicle for monitoring and alerting.

52. **What are common vulnerabilities in cloud deployments?**

* **Answer:**
  * Misconfigurations.
  * Insecure APIs.
  * Lack of visibility.

53. **Explain how SIEM helps with cloud security.**

* **Answer:** SIEM collects logs from cloud resources, applies correlation rules, and provides dashboards for monitoring threats.

### <mark style="color:blue;">Incident Response and Automation</mark>

54. **What is playbook automation in incident response?**

* **Answer:** Automating repetitive tasks, such as IP blocking, using tools like SOAR (Security Orchestration, Automation, and Response).

55. **What are the stages of the incident response lifecycle?**

* **Answer:** Preparation, Detection, Containment, Eradication, Recovery, and Lessons Learned.

56. **What is the difference between IOC (Indicator of Compromise) and IOA (Indicator of Attack)?**

* **Answer:**
  * **IOC:** Evidence of past compromise (e.g., malicious file hash).
  * **IOA:** Indicators of active attack tactics or behaviours.

57. **How do you handle obfuscated scripts during analysis?**

* **Answer:** Deobfuscate using tools or manually analyse patterns. Check for encoding techniques or hidden payloads.

58. **What is the purpose of using a SOAR platform in a SOC?**

* **Answer:** To automate repetitive security tasks, enhance collaboration, and reduce incident response times.

59. **How do you prioritise response actions during an active attack?**

* **Answer:** Contain the threat to prevent further damage, followed by identification, eradication, and recovery steps.

60. **How would you use YARA rules in malware analysis?**

* **Answer:** CreateAnalyseures to match specific characteristics of known malware, enabling detection across files or memory.

61. **What is a memory dump, and how is it useful?**

* **Answer:** A memory dump captures the contents of system RAM, running processes, loaded modules, and malware artifacts.

62. **What are common SIEM queries to detect brute force attacks?**

* **Answer:**
  * Look for repeated failed login attempts.
  * Correlate login analysis from the same IP in the time frame.
  * Analyse user account lockout logs.

63. **How would you use Velociraptor in threat hunting?**

* **Answer:** Use VQL queries to hunt for malicious processes, analyse file changes, and monitor Windows for suspicious activity.

### <mark style="color:blue;">**Scenario-Based Questions**</mark>&#x20;

1. **A user reports** **their system unauthorisedfiles are disappearing. How would you approach this situation?**
   * **Answer:** Begin by isolating the system to prevent further potential spread of malware. Then, collect initial logs and evidence, such as task manager outputs, network activity, and recent event logs. Analyse for malware indicators like unexpected processes or unauthorised file access.&#x20;
2. What action would you take if you identified unauthorised access to a critical server?
   * **Answer:**
     1. Alert relevant stakeholders.
     2. Immediately terminate the session.
     3. Collect evidence, such as event logs.
     4. Determine the method of entry.
     5. Patch vulnerabilities and reset credentials.
     6. Monitor for further attempts.
3. **Describe your response if an employee reports a phishing email.**
   * **Answer: Quarantine the email, investigate its source, and check for other users who may have received the organisation, if malicious block associated IOCs on the email security devices.** Educate the reporting employee and others about the threat.
4. **You find suspicious outbound traffic from a workstation to an unknown IP. Whatanalyse do?**
   * **Answer:**
     1. Block the IP in the firewall.
     2. Investigate the workstation for signs of compromise.
     3. Analyse network traffic to identify patterns or associated malicious activity.
5. **How would you handle a ransomware outbreak in the organisation?**&#x20;
   * Answer:
     * Isolate affected systems
     * Identify the ransomware type.
     * Notify incident response teams.
     * Use backups for recovery if available.
     * Conduct a root cause analysis and improve defences.
6. What do you do if you detect a brute-force attack on a syste&#x6D;**?**
   * **Answer:**
     1. Identify the source of the attack.
     2. Block the source IP(s).
     3. Increase account lockout settings.
     4. Notify the account owner and SOC team.
     5. Conduct a vulnerability assessment to prevent future occurrences.
7. **A critical patch is released. How do you prioritise deployment?**
   * **Answer:**
     1. Identify affected systems.
     2. Assess the severity of the vulnerability.
     3. Prioritise based on exposure and criticality.
     4. Testorganisation’sa sandbox environment.
     5. Deploy in phases to minimise disruption.
8. **What actions would you take if a malicious insider is identified?**
   * **Answer:** Follow the organisation’s incident response policy:
     1. Gather evidence discreetly.
     2. Notify HR and legal teams.
     3. Revoke access to systems.
     4. Conduct a full audit of activities.
9. **Describe your first steps when investigating a suspected malware infection.**
   * **Answer:**
     1. Isolate the infected machine.
     2. Review logs for suspicious activities.
     3. Identify indicators of compromise (IoCs).
     4. Analyse file hashes against threat intelligence sources.
     5. Eradicate malware and validate remediation.
10. **How would you handle a report of data exfiltration?**
    * **Answer:**
      1. Identify the scope of exfiltration.
      2. Contain the breach.
      3. Notify legal and compliance teams.
      4. Investigate the root cause.
      5. Notify impacted parties if required.
11. **An employee clicks on a phishing link and downloads an attachment. What do you do?**
    * **Answer:**
      1. Isolate the employee’s system immediately.
      2. Scan for malware using endpoint detection tools.
      3. Check logs for lateral movement.
      4. Educate the employee on recognising phishing attempts.
12. **How would you prioritise multiple security alerts in a SOC environment?**
    * **Answer:** Use a risk-based approach considering factors like the criticality of affected systems, the type of alert, and potential business impact.
13. **What would you do if a security tool flagged false positives repeatedly?**
    * **Answer:** Tune the tool’s detection rules based on observed patterns, update threat intelligence sources, and document changes for continuous improvement.
14. **A user reports seeing pop-ups and redirects on their browser. What could this indicate?**
    * **Answer:** Likely adware or browser hijacking. Investigate by checking installed extensions, processes, and web traffic for anomalies.
15. **What would you do if DNS traffic spikes unexpectedly?**
    * **Answer:** Investigate for signs of DNS tunneling or exfiltration. Analyse DNS logs for unusual domains or patterns.
16. **You detect a large number of failed login attempts from a single IP. What do you do?**
    * **Answer:**
      1. Block the IP temporarily.
      2. Analyse logs to confirm a brute force attack.
      3. Notify affected users to secure their accounts.
      4. Strengthen access controls.
17. **How would you handle an alert about suspicious file encryption activity?**
    * **Answer:**
      1. Quarantine the affected system.
      2. Identify the source of encryption processes.
      3. Look for ransomware IoCs and mitigate further spread.
      4. Restore files from backup.
18. **How do you ensure the SOC operates efficiently during a significant incident?**

* **Answer:**
  * Define roles and responsibilities in the incident response plan.
  * Ensure effective communication channels.
  * Use automation to reduce repetitive tasks.

19. **A critical vulnerability is identified in software used by your organisation. What next?**

* **Answer:** Assess exposure, notify teams, and apply mitigations like virtual patches or configuration changes until an official patch is available.

20. **Describe your response if unauthorised access to an email account is reported.**

* **Answer:**
  1. Reset the account credentials.
  2. Investigate login attempts from authorised or suspicious IPs.
  3. Check for potential data leaks.
  4. Enable multi-factor authentication (MFA) if not already in place.

21. **You notice a spike in failed API calls in a cloud environment. What do you do?**

* **Answer:**
  1. Identify the source of the calls.
  2. Review logs for unauthorised access attempts.
  3. Check if API keys have been leaked or misused.
  4. Rotate API credentials and apply stricter rate limiting.

22. **A DDoS attack is targeting your web application. How do you respond?**

* **Answer:**
  1. Enable DDoS protection via WAF or CDN services.
  2. Analyse traffic to identify patterns or attacker IPs.
  3. Implement rate limiting and block IP ranges if necessary.
  4. Notify stakeholders and continue monitoring.

23. **What actions would you take if a vulnerability scan reveals exposed critical ports?**

* **Answer:**
  * Evaluate if the ports are required for business operations.
  * Secure or restrict access using firewalls or security groups.
  * Implement VPN or other access control mechanisms.

24. **How do you handle alerts of suspicious file changes in critical directories?**

* **Answer:**
  1. Check file integrity monitoring (FIM) logs for changes.
  2. Correlate with user or process activity.
  3. Investigate the source and mitigate if unauthorised.

25. **An endpoint protection solution quarantines a critical business application. What do you do?**

* **Answer:**
  * Review the quarantine logs and file signatures.
  * Verify with the vendor if it's a false positive.
  * Temporarily whitelist the application after due diligence.

26. **How would you handle an employee who repeatedly violates acceptable use policies?**

* **Answer:**
  1. Sanitise instances of policy violations.
  2. Educate the employee on the risks.
  3. Escalate to HR if violations persist.

27. **What steps would you take to ensure secure remote access for employees?**

* **Answer:**
  * Enforce MFA.
  * Use a VPN with encryption.
  * Restrict access to sensitive resources based on roles.

28. **Describe your approach to mitigating a cross-site scripting (XSS) vulnerability.**

* **Answer:**
  * Sanitise and validate all user inputs.
  * Apply content security policies (CSPs).
  * Notify developers to patch application code.

29. **What would you do if an unmanaged device connects to the network?**

* **Answer:**
  * Quarantine the device using NAC policies.
  * Investigate the user and intent of connection.
  * Enforce endpoint compliance before granting access.

30. **Describe your actions if malware is found on an external storage device.**

* **Answer:**
  1. Disconnect the device from the network.
  2. Analyse the malware using a sandbox.
  3. Scan connected systems for signs of infection.

## <mark style="color:blue;">**Behavioural Questions**</mark>

1. **How do you manage multiple tasks and alerts in a high-pressure SOC environment?**

* **Answer:**
  * Prioritise tasks based on severity and impact.
  * Use ticketing systems to track progress.
  * Communicate effectively with the team to delegate tasks.

2. **Describe a time you successfully identified and mitigated a security threat.**

* **Answer:** Provide a specific example, explaining the detection method, analysis, and steps taken to resolve the issue.

3. **How do you stay updated with the latest cybersecurity trends and threats?**

* **Answer:**
  * Follow industry blogs and forums.
  * Participate in webinars and conferences.
  * Practice hands-on learning in labs and simulations.

4. **How would you handle a disagreement with a team member about an incident response strategy?**

* **Answer:**
  * Discuss differing viewpoints objectively.
  * Reference documented processes or evidence to support your position.
  * Escalate to a supervisor if no agreement is reached.

5. **What motivates you to pursue a career in cybersecurity?**

* **Answer:** Highlight personal interests in problem-solving, passion for technology, and a desire to protect organisations from evolving threats.
