---
cover: ../../../.gitbook/assets/Screenshot 2025-01-10 081536.png
coverY: 0
---

# SOC Analysts Prep Interview Questions

### Core Concepts

1. **What is the CIA Triad?**\
   Confidentiality (only authorised people see data), Integrity (data is not tampered with), Availability (systems work when needed). In practice: encryption = C, hashing/checksums = I, redundancy & DDoS protection = A.
2. **What are false positives and false negatives in a SOC context?**\
   False positive: benign activity flagged as malicious (e.g., admin running PowerShell). False negative: real threat missed (e.g., fileless malware not triggering signatures). Goal: <20 % false positives, zero false negatives.
3. **What is lateral movement in cybersecurity?**\
   After initial compromise, the attacker moves to other systems (e.g., RDP, PsExec, WMI, stolen tokens). Common TTPs: MITRE T1021 (Remote Services), T1078 (Valid Accounts).
4. **What is an Indicator of Compromise (IoC)?**\
   Forensic artifact: malicious IP, file hash, registry key, unusual process name, etc. Example: 8.8.8.8 is not an IoC by itself, but 185.117.118\[.]88 seen in Qakbot campaigns is.
5. **Define a zero-day vulnerability.**\
   Flaw unknown to the vendor or without a patch, actively exploited in the wild (e.g., MOVEit 2023, Log4Shell before Dec 2021).
6. **What is the difference between IDS and IPS?**\
   IDS = passive detection + alert only (Snort, Suricata in tap mode). IPS = inline and can block/drop (Suricata in IPS mode, Palo Alto, FortiGate).
7. **What is phishing?**\
   Social-engineering attack tricking users into giving credentials or clicking on malicious links. 2025 twist: AI-generated deepfake voice + hyper-personalised emails.
8. **Explain the difference between encryption and hashing.**\
   Encryption: reversible with key (AES, RSA). Hashing: one-way, fixed-length (SHA-256, bcrypt). Use encryption for data in transit/rest, hashing for passwords/integrity checks.
9. **What is the role of SIEM in a SOC?**\
   Collects logs from everywhere → normalises → correlates → alerts → dashboards. 2025 SIEMs (Sentinel, Splunk, QRadar) now have built-in UEBA and auto-tuning.
10. **What is the principle of least privilege?**\
    Users/services get only the permissions they need. Example: Helpdesk can reset passwords but not read emails.
11. **What is the role of EDR in a SOC?**\
    Continuous endpoint monitoring, behavioural detection, response actions (isolate, kill process, rollback). Top 2025 players: CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Carbon Black.
12. **What is a web application firewall (WAF), and how does it work?**\
    Filters HTTP/S traffic, blocks OWASP Top 10 (SQLi, XSS, etc.). Works via signature + anomaly + ML (Cloudflare, Imperva, AWS WAF).
13. **Explain the difference between symmetric and asymmetric encryption.**\
    Symmetric: one shared key (AES-256-GCM – fast). Asymmetric: public/private pair (RSA, ECC – key exchange, signing).
14. **What is threat intelligence, and how is it used in a SOC?**\
    Actionable info about threats (IoCs, TTPs). Used to: enrich alerts, create detection rules, and conduct proactive hunting. Sources: MISP, OTX, Recorded Future, Microsoft Threat Intelligence.
15. **How would you use Splunk to detect unusual login patterns?**\
    index=security EventCode=4624 OR EventCode=4625 | stats count by user, src\_ip | where count > 50 → add geolocation, timechart, or use MLTK for anomalies.
16. **What is DNS poisoning, and how can it be detected?**\
    Attacker injects false DNS records. Detect: DNSSEC validation failures, sudden NXDOMAIN spikes, Zeek logs showing mismatched answers.
17. **How do you secure sensitive data in transit?**\
    Enforce TLS 1.3, HSTS, certificate pinning, disable TLS 1.0/1.1, and monitor for downgrade attacks.
18. **What is a honeypot, and how is it used in threat detection?**\
    Decoy system (e.g., Cowrie SSH, Dionaea) to attract attackers, log their TTPs, and alert when touched.
19. **How can you identify malicious PowerShell activity?**\
    Event IDs 4103/4104 (script block logging), obfuscated base64, Invoke-WebRequest to strange domains, AMSI failures, LOLBAS (powershell.exe spawning cmd.exe).
20. **What are the components of a secure software development lifecycle (SDLC)?**\
    Threat modelling → SAST/DAST/SCA → secure code review → IaC scanning → runtime protection (RASP) → continuous monitoring.

### **Log Analysis & Windows Event IDs**

21. **What are the key Windows Event IDs for monitoring logon activity?**\
    4624 (success), 4625 (fail), 4648 (explicit creds), 4768/4769 (Kerberos), 4776 (NTLM).
22. **What are the key fields to monitor in Windows Event ID 4624?**\
    Logon Type (2=interactive, 3=network, 10=RD), SubjectUser (who initiated), TargetUser, WorkstationName, IpAddress, ProcessName.
23. **How would you identify suspicious command-line activities?**\
    Sysmon ID 1 or Event 4688 with CommandLine, look for base64, ^ escaping, certutil, bitsadmin, living-off-the-land binaries.
24. **What is the difference between security logs and application logs?**\
    Security = auth/access (audit policy). Application = software-specific events (IIS, SQL, custom app logs).
25. **How do you analyse suspicious log entries?**\
    Timeline → context → enrichment (VirusTotal, Greynoise) → correlation with other sources → pivot.
26. **What is the importance of time synchronisation in log analysis?**\
    Accurate correlation across devices. All hosts must sync to NTP (e.g., time.windows.com or pool.ntp.org).
27. **What tool would you use to parse large log files, and why?**\
    Splunk/Elastic for TB-scale, fast search, dashboards. For quick: grep, jq, or CyberChef.
28. **How can you identify privilege escalation attempts in Windows Event Logs?**\
    4672/4673 (SeDebugPrivilege, SeTakeOwnership, etc.), 4674, UAC bypass techniques (eventvwr.exe, fodhelper.exe).
29. **How do you troubleshoot missing logs in a SIEM?**\
    Check forwarder/agent health → network reachability → parsing filters → index/time range → bucket freezes.
30. **What are common SIEM queries to detect brute-force attacks?**\
    EventCode=4625 | stats count by src\_ip, user | where count > 15 in 5m → add geo-filter for non-corporate countries.

### Threat Hunting & Incident Response

31. **How would you detect PowerShell-based attacks?**\
    Enable Script Block + Module logging, AMSI, monitor 4104 for encoded commands and downloads.
32. **What is the MITRE ATT\&CK framework?**\
    Global knowledge base of adversary TTPs, organised in matrices (Enterprise, Mobile, ICS). Used for detection coverage, hunting queries, and red/blue teaming.
33. **What methods would you use to hunt for malware on endpoints?**\
    YARA scans, Sigma rules, Velociraptor artifacts, EDR hunting queries, memory analysis (Volatility/WinDbg).
34. **How do you identify command-and-control (C2) communication?**\
    Regular beaconing (same interval & packet size), high-entropy payloads, JA3/JA3S anomalies, connections to suspicious TLDs (.top, .cc).
35. **What is the difference between a SOC playbook and a runbook?**\
    Playbook = high-level procedure for incident type (e.g., ransomware). Runbook = detailed step-by-step actions (e.g., “run EDR isolate on host X”).
36. **What are the stages of the incident response lifecycle?**\
    NIST: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned.
37. **What is the difference between IOC and IOA (Indicator of Attack)?**\
    IOC = static evidence (hash, IP). IOA = behavioural pattern (e.g., regsvr32 loading from temp).
38. **How do you handle obfuscated scripts during analysis?**\
    CyberChef → PowerShell deobfuscator → manual string extraction → dynamic analysis in sandbox.
39. **What is the purpose of using a SOAR platform in a SOC?**\
    Automate repetitive tasks, orchestrate tools, and reduce MTTR (e.g., Splunk SOAR, Cortex XSOAR, Microsoft Sentinel Playbooks).
40. **How do you prioritise response actions during an active attack?**\
    Contain first → preserve evidence → eradicate → recover. Use severity + business impact matrix.
41. **How would you use YARA rules in malware analysis?**\
    Write or import rules to match strings, hex, imports → scan files, memory dumps, or network traffic.
42. **What is a memory dump, and how is it useful?**\
    Full RAM capture (DumpIt, WinPMEM). Reveals in-memory malware, injected code, decrypted strings.
43. **How would you use Velociraptor in threat hunting?**\
    Deploy agent → run VQL artifacts (e.g., Windows.Persistence.Minimal) → collect across fleet in seconds.

### Network Security & Malware Analysis

44. **What is the purpose of a sandbox environment?**\
    Safe detonation of suspicious files to observe behaviour (C2, file drops, registry changes).
45. **How do you analyse packet captures for suspicious activity?**\
    Wireshark → filters (http.request, tls.handshake), follow streams, statistics → IO graph for beaconing, export objects.
46. **What is the purpose of network segmentation in security?**\
    Limit blast radius; separate OT, guest Wi-Fi, servers, etc. Zero-trust micro-segmentation is 2025 standard.
47. **How do you detect malicious traffic in a packet capture (PCAP)?**\
    Unusual ports, beaconing, DGA domains, high entropy, clear-text credentials, and known bad JA3 fingerprints.
48. **What is the role of NetFlow in network security?**\
    Flow metadata (src/dst IP, ports, bytes) for anomaly detection (exfil, scanning) without storing full packets.
49. **What are the steps to perform static malware analysis?**\
    Hash → strings → PE header (imports, sections) → disassemble (IDA/Ghidra) → check packer.
50. How would you detect hidden persistence mechanisms?\
    Autoruns, scheduled tasks, services, WMI subscriptions, registry Run keys, AppInit\_DLLs, and DLL search order hijacking.

### Cloud Security

51. **What are common threats in cloud environments?**\
    Misconfigurations (public S3), IAM abuse, insecure APIs, serverless flaws, supply-chain (tainted containers).
52. **How do you investigate a misconfigured cloud storage bucket?**\
    Check bucket policy/ACL → CloudTrail for access events → Prowler/ScoutSuite scan → lock down + enable logging.
53. **What tools would you use for threat detection in the cloud?**\
    AWS GuardDuty, Azure Sentinel, GCP Security Command Centre, Prisma Cloud, Lacework.
54. What are common vulnerabilities in cloud deployments?\
    Over-permissive IAM, unencrypted EBS, exposed metadata endpoint (169.254.169.254), SSRF.
55. **Explain how SIEM helps with cloud security.**\
    Ingests CloudTrail, VPC Flow Logs, GuardDuty findings → correlates with on-prem alerts → single pane of glass.

### Emerging & AI-Related Questions

56. How does GenAI impact phishing detection in a SOC?\
    Makes emails nearly perfect. Counter with NLP anomaly detection, sender reputation, and user behaviour.
57. **What role does AI play in SOC automation today?**\
    Auto-triage, false-positive suppression, case summarisation, playbook suggestions (Sentinel Copilot, Splunk Attack Analyser).
58. **How do you detect supply-chain attacks?**\
    SBOM monitoring, in-toto attestations, runtime integrity checks, anomaly detection on third-party processes.
59. **Compare CrowdStrike vs SentinelOne EDR.**\
    CrowdStrike: best threat intel + hunting. SentinelOne: strongest autonomous response & rollback.
60. **How would you safely use LLMs (e.g., ChatGPT) in a SOC workflow?**\
    Air-gapped or enterprise version, never paste PII/IoCs, use for query generation or summarisation only, always verify output.
61. **What is behavioural AI detection vs. signature-based detection?**\
    Signature = exact match (fast, misses new). Behavioural = ML baselines of normal (catches zero-days, higher FP).
62. **How do you secure AI models deployed in your environment?**\
    Model signing, input/output validation, red-teaming, monitoring for prompt injection and data poisoning.

### Scenario-Based Questions&#x20;

(Answers kept concise for interview delivery)

63. **User reports files disappearing** → Isolate host, check for ransomware processes (e.g., .exe writing .lock), preserve memory, restore from backup.
64. **Unauthorised access to critical server** → Kill sessions, force password reset + MFA, check 4624 Type 3/10, hunt lateral movement.
65. **Phishing email reported** → Quarantine in mailbox, detonate attachment, block URL/hash everywhere, send org-wide warning.
66. **Suspicious outbound traffic** → Block destination IP, isolate host, pull PCAP + EDR process tree, enrich IP.
67. **Ransomware outbreak** → Pull LAN cable / disable NIC via EDR, identify variant, don’t pay, restore from offline backups, full IR.
68. **Brute-force attack** → Block source IP, enforce account lockout/MFA, check if credentials were compromised.
69. **Critical patch released** → Scan affected assets, test in lab, phased rollout (canary → pilots → prod).
70. **Malicious insider** → Discreet evidence collection, disable accounts, involve HR/legal, full audit.
71. **Suspected malware infection** → Isolate → memory dump → live response → hash + VT → eradicate → verify.
72. **Data exfiltration report** → Check DLP/NetFlow, contain egress, calculate impact, legal/compliance notification.
73. **Employee clicked phishing + downloaded** → Immediate isolation, full EDR scan, check lateral movement, user re-training.
74. **Multiple alerts at once** → Sort by severity + asset criticality (domain controller > workstation), escalate P1.
75. **Repeated false positives** → Tune rule (add exclusion, adjust threshold), update baselines, document change.
76. **Pop-ups & redirects** → Likely adware/PUP → check browser extensions, rogue processes, reset browser.
77. **DNS traffic spike** → Investigate tunnelling or DGA → Zeek DNS logs → block suspicious domains.
78. **Thousands of failed logins from one IP** → Auto-block via WAF/fail2ban, confirm brute-force, notify user.
79. **Suspicious file encryption** → Quarantine host, check for ransomware note/process, stop spread, restore backups.
80. **Major incident efficiency** → Activate IR plan, clear roles, war room (Teams/Slack), automate containment via SOAR.
81. **Critical vuln discovered** → Inventory exposure → virtual patch/WAF rule → schedule real patch.
82. **Unauthorised email access** → Reset password + MFA, sign-out all sessions, check inbox rules/forwarding, O365 audit log.
83. **Spike in failed API calls** → Likely recon or stolen key → rotate keys, rate-limit, check CloudTrail.
84. **DDoS on web app** → Enable CDN scrubbing (Cloudflare/Akamai), rate-limit, contact ISP.
85. **Exposed critical ports** → Block unless required → require VPN/jump host → justify business need.
86. **Suspicious file changes** → FIM alert → correlate with user/process → revert or investigate.
87. **EDR quarantines legit app** → Verify hash with vendor, temporary exclusion + monitoring.
88. **Repeated policy violations** → Document → retrain → escalate to HR if it continues.
89. **Secure remote access** → ZTNA or VPN + MFA + device compliance + session recording.
90. **XSS vulnerability** → Input validation/encoding, CSP headers, WAF rule, patch code.
91. **Unmanaged device on network** → NAC quarantine → scan → enforce compliance before access.
92. **Malware on USB** → Don’t plug in → scan in isolated sandbox → wipe → update policy.

### Behavioral Questions

93. **How do you manage multiple tasks/alerts under pressure?**\
    Prioritise by risk, use a ticketing system, clear handovers, and automate where possible.
94. **Describe a time you mitigated a real threat** → Use STAR: “During night shift, spotted credential dumping via 4624 Type 10 from Russia → isolated host → found Cobalt Strike → blocked C2 → prevented domain compromise.”
95. **How do you stay updated?**\
    Daily: Krebs, DFIR Report, Twitter lists. Weekly: podcasts (Darknet Diaries), labs (TryHackMe SOC Level 2).
96. **Disagreement with teammate on IR strategy?**\
    Discuss evidence-based, reference playbooks, escalate to lead if needed — goal is best outcome, not ego.
97. **What motivates you in cybersecurity?**\
    Constant cat-and-mouse game, direct impact on protecting people and organisations, and the field evolves every day.
