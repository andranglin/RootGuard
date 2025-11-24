---
cover: ../../../.gitbook/assets/Screenshot 2025-01-10 075152.png
coverY: 0
---

# SOC Analysts Roadmap

### Introduction

**From Zero to Hired** – The demand for competent SOC analysts has never been higher. MDR providers are scaling rapidly, enterprises are building or expanding internal SOCs, and even with AI taking over basic alerting, companies still need sharp humans who can investigate, think critically, and write coherent tickets.

**This roadmap is written for two groups:**

* Beginners who want to break in
* Junior analysts already in the chair who want to move from Tier 1 → Tier 2 faster

It is not a 500-page encyclopedia. It is the exact sequence that has worked for hundreds of people I’ve mentored or hired in the last three years.

Realistic Timeline (job market)

| **Phase**                      | **Full-time study** | **Working full-time + evening study** |
| ------------------------------ | ------------------- | ------------------------------------- |
| Step 1 – Master the Basics     | 2–4 months          | 4–8 months                            |
| Step 2 – Core Technical Skills | 4–7 months          | 8–14 months                           |
| First serious certification    | 1–3 months          | 3–6 months                            |
| Total time to first Tier 1 job | 9–18 months         | 18–30 months                          |

**The Minimum Viable SOC Analyst**&#x20;

If you have these five things, you are ahead of 90 % of applicants today:

1. CompTIA Security+ or Microsoft SC-200
2. 50–100 completed rooms on TryHackMe or Blue Team Labs Online (screenshots saved)
3. Can write basic Splunk SPL or KQL searches (free courses exist)
4. Can walk through a full phishing investigation verbally
5. A public GitHub/Notion page with 5–10 write-ups or small scripts

Have that → you’re getting interviews.

#### Step 1: Master the Basics (Don’t skip this — ever)

You cannot analyse what you don’t understand.

* Computer Networking (TCP/IP, OSI model, packet flow)
* Common protocols & standard ports (80, 443, 445, 3389, 22, etc.)
* Subnetting (calculate network/broadcast/host ranges quickly)
* Windows & Linux fundamentals (processes, services, file system, permissions)
* How TLS actually works (you’ll see it every day)
* Basic attack types: phishing, credential abuse, lateral movement, living-off-the-land
* Intro to logs: Windows Event Logs, Sysmon, web server logs

Resources: Professor Messer (Net+/Sec+), NetworkChuck, John Hammond’s free YouTube series

#### Step 2: Core Technical Skills Tier 1 Uses Every Shift

Focus on these tools first. Everything else is a bonus until you’re employed.

**Must-Know for Day 1 on the Job**

* Microsoft Sentinel + Microsoft Defender (exploding in 2024–2026)
* Splunk (still the most common enterprise SIEM)
* Wireshark – be able to open a PCAP and find the evil in < 5 minutes
* Windows Event Logs + Sysmon EID reference in your head
* One modern EDR console cold (CrowdStrike Falcon, Microsoft Defender, SentinelOne – pick one and know the interface)

#### Very Useful Next Tier

* Elastic (ELK) – free and common in smaller shops
* QRadar, LogRhythm
* Zeek, Velociraptor, Volatility (for when you move to Tier 2/DFIR)

#### Scripting (you don’t need to be a developer)

* Python basics: read/write files, parse JSON, simple regex
* PowerShell: Get-Process, Get-EventLog, basic one-liners
* KQL (Kusto) for Sentinel/Hunting

Free: TryHackMe – SOC Level 1 path, Blue Team Labs Online, LetsDefend, Splunk Fundamentals 1 (free)

#### Step 3: Certifications That Actually Open Doors Right Now

**Beginner/Entry-Level (get one of these first)**

1. CompTIA Security+ SY0-701 ← still the #1 gatekeeper
2. Microsoft SC-200 (Security Operations Analyst) ← massive demand
3. Splunk Core Certified User → Splunk Certified Power User
4. Cisco CyberOps Associate
5. SOC-200 (SANS – expensive but respected)

**Once You’re Employed (employer usually pays)**

* CySA+
* GCIH
* TH-200 (SANS Threat Hunting)
* CISSP (after 4–5 years)
* Azure/AWS security certs if you go cloud-heavy

Warning: CEH is often discounted, but it is handy for most hiring managers. Can be skipped unless a specific job asks for it.

#### Step 4: Practical Experience—Where Most People Fail

**Theory without proof = rejected.**

**Best Platforms**

1. TryHackMe – SOC Level 1 & Level 2 paths
2. Blue Team Labs Online
3. LetsDefend
4. Hack The Box – Blue Track
5. RangeForce, CyberDefenders

Do 50–100 rooms. Screenshot every flag/write-up. Put them in a public Notion or GitHub repo.

**Home Lab (you do NOT need everything)**

Minimum practical lab:

* VirtualBox or VMware Workstation
* Windows 10/11 VM (eval license)
* Kali or Ubuntu VM
* Flare-VM (one-click DFIR tools on Windows)
* Sample PCAPs + Wireshark

Add REMnux, CSI Linux, or Tsurugi later if you love malware.

#### Step 5: How to Actually Get Interviews

**The bottleneck is no longer knowledge — it’s visibility.**

1. LinkedIn headline: “Aspiring SOC Analyst | Security+ | SC-200 | 100+ BTLO Rooms | ex-Helpdesk”
2. Resume must contain the keywords: SIEM, EDR, phishing triage, incident response, Splunk, Sentinel, Wireshark
3. Apply aggressively to MDR companies (they hire juniors in bulk):\
   Expel • Red Canary • Critical Start • Arctic Wolf • Huntress • Blackpoint Cyber • Sophos MDR • eSentire • Pondurance
4. Find the exact tools a company uses (YARA-L or their job ads), do a public write-up on one of their blog posts or a related PCAP, then message the hiring manager on LinkedIn with the link.

#### Step 6: Stay Current & Choose Your Specialisation

Cybersecurity is a lifestyle, not a 9-to-5.

**Daily/Weekly habits:**

* Follow Krebs, The DFIR Report, Dark Reading, and company blogs
* Subscribe to one threat intel feed (free: OTX, MISP instances)
* Listen to Darknet Diaries and CyberWire Daily while commuting

**Future specialisations that pay the most (2026+):**

* Cloud Detection & Response (AWS/Azure)
* Threat Hunting
* Incident Response / DFIR
* SOAR Engineering
* Threat Intelligence

**Most analysts move:**\
Tier 1 → Tier 2 → Threat Hunter / IR / Cloud Security Engineer → Senior / Lead / Architect

**Final words**\
Stay curious. Investigate one alert properly every single day. Document everything publicly. The junior who writes clear, public write-ups will always beat the “secret genius” who keeps everything private.

**You’ve got this.**\
Now go build the portfolio that gets you hired.
