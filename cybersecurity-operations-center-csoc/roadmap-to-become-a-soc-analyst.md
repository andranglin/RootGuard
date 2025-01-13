---
cover: ../.gitbook/assets/Screenshot 2025-01-10 075152.png
coverY: 0
layout:
  cover:
    visible: true
    size: hero
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

# Cybersecurity Roadmap to Become A SOC Analyst

## Introduction:&#x20;

The demand for competent Security Operations Center (SOC) Analysts is high. This is partially driven by the rise in demand for Managed Detection and Response (MDR) services and organisations looking to improve and grow their in-house security teams. Whatever the source, competent SOC Analyst skills are in demand even with the growth of Artificial Intelligence (AI) capabilities.

While several blogs and articles have been written on cybersecurity development roadmaps and how to prepare and eventually get into a role, it is a constantly moving target that requires frequent updating. One of the main objectives of this site is to support junior and entry-level analysts already in the field and those looking to enter. The hope is that this roadmap becomes helpful to individuals for whom the pathway is less clear and who are finding it challenging knowing how or where to start.

Cybersecurity is an interesting and rewarding field, but like all other sectors, it has its challenges. Move forward and make your mark. All that's required to start is a positive attitude and the willingness to learn. There are plenty of freely available resources provided on this [site](https://rootguard.gitbook.io/cyberops/cybersecurity-operations-center-csoc) and other areas online, such as [YouTube](https://www.youtube.com/), to get you started.&#x20;

### Step 1: Master the Basics of Cybersecurity

Building a strong foundation is critical for aspiring SOC analysts. Start by acquiring knowledge in these key areas:

* **Computer Networking:** Learn networking principles, including protocols, network design, and traffic analysis.
* **Computer Hardware Components:** Understand how hardware functions and its role in IT infrastructure.
* **Operating Systems:** Gain proficiency in Linux and Windows for a start, as SOC analysts often work across various platforms.
* **Network Topologies:** Study how different network structures work and their impact on security.
* **Standard Ports:** Learn the purpose of well-known ports (e.g., HTTP: 80, HTTPS: 443) and how they can be exploited.
* **IPv4 and IPv6:** Understand IP addressing schemes and their relevance to modern networks. While both should be understood, IPv4 is still used in most organisations; learn it.
* **Subnetting Basics:** Learn how subnets are used for network segmentation and identify key components (hosts, network, broadcast, etc.).
* **Cyberattacks and Cybercrimes:** Study real-world examples to understand attack methods and motives. The[ DFIR Report](https://thedfirreport.com/) is a good place to start.
* **Cryptography:** Learn basic encryption methods and their application in securing data, especially **Transport Layer Security (TLS),** as this will impact your ability to analyse web-related conten&#x74;**.**
* **Security Standards:** Familiarise yourself with frameworks like ISO, NIST, and CSF for structured security practices. If you are in the European Union (EU) or work for organisations in the EU, understanding NIS2 is essential.
* **DFIR Distros:** Explore Linux distributions like **SIFT Workstation, REMnux, CAINE,** on the  **Windows** sid&#x65;**, Flare-VM,** which are widely used in **DFIR.**

**Note:** Gain a solid understanding of the basis. Perseverance is crucial at this point, even though not everything will initially resonate.

***

### Step 2: Develop Technical Skills

**Note:** Threats come in many forms. Therefore, SOC analysts must have the technical expertise to analyse and mitigate threats effectively.

**Programming Skills:**

* Gain an understanding of languages like Python for scripting, Powershell, JavaScript, or a similar language for understanding web application vulnerabilities.

**Operating Systems Expertise:**

* Gain deep knowledge of Linux and Windows. Linux provides excellent tools that are used on a day-to-day basis, and Windows is still the most popular OS used in organisations.

**Cloud and Application Security:**

* Understand cloud security principles, such as securing AWS and Azure environments.
* Learn application security concepts to identify and mitigate software vulnerabilities.

**Tools**

* **SIEM Solutions:** Learn the basis of (Splunk, Sentinel, QRadar, LogRhythm, and The ELK Stack)
* **Endpoint Detection and Response (EDR) Solutions:** Gain experience on any of the following or their open-source equivalent ( Microsoft Defender, CrowdStrikе and SentinelOne)
* **Digital Forensic and Incident Response (DFIR) Solutions:** (Velociraptor, EZ Tools, Cyber Triage, Autopsy, SIFT Workstation, REMnux, Flare-vm, Volatility and Tsurugi Linux) Check out the list at [DFIR Tools](https://www.dfir.training/tools).
* **Network Forensics:** (Wireshark, Tcpdump, Tshark, Ngrep, Zeek, Snort, NetworkMiner)

***

### Step 3: Obtain Certifications

Certifications validate your skills and demonstrate your expertise to potential employers. Rightly or wrongly, without certifications, you might not even get to the interview stage; however, it's your knowledge and understanding of the foundational and core subjects that will land you the job. Certs get you the call from recruiters but don't necessarily get you the job, but improve your chances.

Choose certifications wisely for the stage you're at or want to reach in your career. Certs and their requirement are often challenging to maintain.

#### **Beginner-Level Certifications:**

* CompTIA Network+: Covers networking concepts and practices.
* CyberOps: Cisco Certified CyberOps Associate certification
* CompTIA Security+: An essential credential for understanding general security practices.
* SC-200: Microsoft Security Operations Analyst&#x20;
* CEH (Certified Ethical Hacker): For those interested in ethical hacking.
* SOC-200: Foundational Security Operations and Defensive Analysis.

#### **Intermediate to Advanced Certifications:**&#x20;

**Note:** These are certifications you'll likely target once you are employed. Hopefully, your employer will provide the training and certification budget.

* TH-200: Foundational Threat Hunting&#x20;
* IR-200: Foundational Incident Response
* CISSP (Certified Information Systems Security Professional): Covers comprehensive cybersecurity knowledge.
* CCSP (Certified Cloud Security Professional): Focuses on cloud security expertise.
* CHFI: Computer Hacking Forensic Investigator
* ECIH: EC-Council Certified Incident Handler
* CSIH: Certified Computer Security Incident Handler
* GCIH: GIAC Certified Incident Handler
* CySA+: CompTIA Cybersecurity Analyst

***

### Step 4: Gain Practical Experience

Practical experience helps solidify theoretical knowledge and improves your employability.

**Hands-On Practice:**

* **Online Learning Platform:**
  * Practice on platforms like: ([Hack The Box](https://www.hackthebox.com/), [TryHackMe](https://tryhackme.com/), or [Blue Team Labs](https://blueteamlabs.online/). Focus on the Blue Team tracks and subjects that provide lab activities to enhance your learning.
  * Participate in Capture The Flag (CTF) challenges and other real-world security exercises.
* **Home Lab:**
  * Below is a list of tools and distros I have in my home lab.
    * [Oracle VirtualBox](https://www.virtualbox.org/)
    * [Flare VM](https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html) (Several [DFIR/Malware Analysis tools](https://github.com/fireeye/flare-vm) installed)
    * [CSI Linux](https://csilinux.com/) (Several [OSINT/DFIR/Malware Analysis tools](https://csilinux.com/faq-what-custom-tools-and-features-are-available-in-csi-linux/) installed)
    * [Remnux](https://remnux.org/) (Several [malware analysis tools](https://zeltser.com/remnux-tools-list/) installed)
    * [Tsurugi Linux](https://tsurugi-linux.org/) (Several [OSINT/DFIR/Malware Analysis tools](https://tsurugi-linux.org/documentation_tsurugi_linux_tools_listing.php) installed)
    * [Autopsy](https://www.sleuthkit.org/autopsy/)
    * [FTK Imager](https://accessdata.com/product-download)
    * [Volatility](https://github.com/volatilityfoundation/volatility)
    * [MemProcFS](https://github.com/ufrisk/MemProcFS)
    * [Wireshark](https://www.wireshark.org/) (Sample PCAP files available [here](https://wiki.wireshark.org/SampleCaptures))
  *   **Tools to Supplement Your Learn:**

      *   [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) – A curated list of malware analysis tools and resources.

          [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response) – A curated list of tools for incident response.

          [Awesome Forensics](https://github.com/Cugu/awesome-forensics) – A curated list of forensic analysis tools and resources.

          [RootGuard](https://github.com/andranglin/RootGuard) - Resources targetted at Individuals looking to get into DFIR



**Internships and Entry-Level Roles:**

* Apply for internships or junior roles in security analysis, IT support, or SOC operations. Anything that will get you some real-world experience.

**Project Work:**

* Seek opportunities to work on security-related projects, such as new technology deployments or any security-related activities beneficial to your development.

***

### Step 5: Stay Updated&#x20;

Monitor what is happening in cybersecurity, such as emerging trends, data breaches, and tools and technologies. Cybersecurity is a dynamic field that is often a way of life rather than just a job.

**Continuous Education:**

* Attend webinars and participate in workshops. Many free resources are available online; use them to your advantage.&#x20;
* Subscribe to threat feeds and podcasts to stay informed about emerging threats. Keep up-to-date on AI-driven attacks, quantum threats, and supply chain security issues. The given roles will sometimes help you strategise on areas to focus on.

**Community Involvement:**

* Join cybersecurity forums, local meetups, or online communities to learn from peers and industry professionals.

***

### Step 6: Specialise and Plan Your Career Path

Decide on a path that aligns with your interests and career goals. You are now looking to take that next step in your career development/progression.

**Choose a Specialisation:**

* Options include **network security, cloud security, incident response, threat hunting, compliance, and governance.** While this is not a must, becoming a subject matter expert in any of these areas will set you apart and get you a bigger paycheck.

**Career Progression:**

* Career progression will be different for each, as goals are often personal ambitions driven by different things. However, based on experience, people generally move into the managerial or specialist role, sometimes a combination of both, consultancy.
* Otherwise, advance from SOC Analyst positions to **Security Architect**, **Incident Response Lead**, or **Threat Intelligence Analyst**.

***

While you'll have to create something suitable for your goals and objectives, following the suggested steps can build a strong foundation, gain valuable experience, and progress towards a successful career as a SOC analyst or similar. Stay curious, keep learning, and remain committed to your professional growth.
