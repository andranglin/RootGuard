---
cover: ../../../.gitbook/assets/Screenshot 2025-01-04 152539.png
coverY: 0
---

# Becoming A SOC Analyst

#### (The Real Day-to-Day, Not the Job Description Fantasy)

There are three distinct levels you will see in the wild. Know which one you’re interviewing for – the responsibilities, pay, and interview difficulty are completely different.

| Level           | Common Titles                                               | Real Daily Work (2025 reality)                                                                              | Avg Salary Range (US) |
| --------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------- |
| Tier 1          | SOC Analyst, Security Analyst L1, MDR Analyst               | Triage 200–800 alerts/shift, close 90 % as false positive or low-sev, write tickets, escalate the real ones | $65k–$95k             |
| Tier 2          | Senior SOC Analyst, Security Analyst L2, Incident Responder | Deep investigation, PCAP/memory/log analysis, containment, write detailed reports, talk to customers        | $100k–$145k           |
| Tier 3 / Hunter | Threat Hunter, IR Lead, DFIR                                | Proactive hunting, red-team sims, memory forensics, breach lead, testify in legal cases                     | $150k–$220k+          |

99% of entry-level openings are Tier 1. This guide is built for that reality.

#### Key Responsibilities of a Tier 1 SOC Analyst (what you’ll do 95 % of the time)

1. Alert Triage – Open SIEM/EDR alert → decide in < 8 minutes if it’s noise, benign, or evil
2. Phishing Investigation – The #1 alert volume. Verify delivery → detonate → block URL/hash → write user email
3. Credential-Based Alerts – Impossible traveler, brute-force, unusual logon type (4624 type 10 after hours)
4. Endpoint Alerts – PowerShell downgrades, living-off-the-land binaries (rundll32, mshta, wscript), suspicious parent-child processes
5. Ticketing & Escalation – Write clear, reproducible tickets for Tier 2. Bad tickets mean you don’t last long
6. Basic Enrichment – VirusTotal, AbuseIPDB, Greynoise, urlscan.io – you’ll have these tabs permanently open
7. Daily/Weekly Reporting – How many alerts, top 10 malicious IPs, phishing campaigns seen this week

That’s it. You are not “hacking back” or doing memory forensics on your first day.

#### Realistic & Comprehensive Interview Preparation Guide

1. **Know the Exact Tools the Company Uses (this is now mandatory)**

Before you apply:

* Go to YARA-L.com or cyberbackgroundchecks.com → type company name → see their exact SIEM/EDR stack
* Check their job postings for the last 12 months
* Look at employee LinkedIn profiles (“Skills” section often lists Splunk, Sentinel, CrowdStrike, etc.)

Tailor everything below to their stack. Generic answers aren't the way forward.&#x20;

2. **Core Knowledge You Must Own Cold**

Networking (you will be tested)

* Explain the 3-way TCP handshake in < 30 seconds
* Common evil ports: 4444, 3389, 22, 445, 135–139
* How to spot beaconing in PCAP (regular intervals, same-size packets)
* DNS tunnelling indicators
* Difference between TCP and UDP with real attack examples

Windows (80% of breaches still occur here)

Memorise these Event IDs:

* 4624/4625 – Logon/Logon failure (know logon types 2, 3, 10)
* 4688 – Process creation (learn key LOLBAS: cmstp.exe, mshta.exe, regsvr32.exe)
* 4104 – PowerShell script block logging (the goldmine)
* 1/2/3 – Sysmon process creation, network, DNS

**Linux (you’ll see less, but still asked)**

* /var/log/auth.log → failed su/sudo
* Unusual cron jobs, .ssh/authorised\_keys changes

3. **Hands-On Skills That Get You Hired**

**Y**ou need proof, not theory.

#### **Minimum Viable Portfolio – build this in 2–3 months**

1. GitHub or Notion page titled “SOC Analyst Portfolio – \[Your Name]”
2. 8–12 write-ups containing:
   * Phishing investigation (full detonations + screenshots)
   * Suspicious PowerShell in Sysmon/WinEvent logs
   * Living-off-the-land attack (e.g., certutil download)
   * Beaconing PCAP analysis in Wireshark
   * One KQL or SPL query you wrote that found real evil in a lab
3. Link to completed learning paths:
   * TryHackMe SOC Level 1 (full path)
   * LetsDefend or Blue Team Labs Online – 50+ rooms
   * Splunk Fundamentals 1 certificate (free)

Recruiters and hiring managers open this link in < 2 minutes and decide.

#### 4. Certifications That Actually Move the Needle (2025 ranking)

| Priority | Certification             | Why It Matters in 2025               |
| -------- | ------------------------- | ------------------------------------ |
| 1        | CompTIA Security+ SY0-701 | Still the #1 ATS filter              |
| 2        | Microsoft SC-200          | Sentinel + Defender explosion        |
| 3        | Splunk Core → Power User  | Splunk still in 40 %+ of enterprises |
| 4        | Cisco CyberOps Associate  | Good for service-provider/MDR roles  |
| 5        | Blue Team Level 1 (BTL1)  | Proves hands-on blue skills          |

#### 5. Top 15 Interview Questions You Will Get (with winning answer framework)

1. Walk me through how you investigate a phishing alert.\
   → Use the exact 7-step process most MDRs teach internally
2. What are the top 5 Event IDs you look at daily?
3. Explain living-off-the-land binaries with examples.
4. You see 4624 logon type 10 from Russia at 3 a.m. – what next?
5. How do you spot beaconing in Wireshark?
6. What is the difference between an indicator of compromise (IoC) and tactic/technique (TTP)?
7. Write a KQL/SPL query on a whiteboard to find PowerShell downgrades.
8. Tell me about a time you were wrong about an alert (shows maturity).
9. How would you explain a ransomware incident to a non-technical executive?\
   10–15: Tool-specific (Splunk time modifiers, Sentinel hunting bookmarks, CrowdStrike process explorer, etc.)

#### 6. One-Page Interview Prep Checklist (print this)

* MemorisedFinished TryHackMe SOC Level 1 + 30 extra rooms
* Portfolio live with 8+ public write-ups
* Security+ or SC-200 passed
* Memorised top 20 Windows Event IDs + 10 Sysmon
* Can explain MITRE ATT\&CK initial access + execution tactics
* Practiced 5 mock interviews (use Pramp, interviewing.io or a friend)
* Researched exact company stack + prepared one question about their tools
* Clean LinkedIn headline: “Aspiring SOC Analyst | Security+ | SC-200 | 80+ Labs | Ex-Helpdesk”

Do the above, and you are no longer “another resume”—you’re the candidate they fight over.

You don’t need to be a genius. You need to be disciplined, document everything publicly, and speak clearly about the 5–6 things Tier 1 does every shift.

Now go build the proof. The SOC needs you.
