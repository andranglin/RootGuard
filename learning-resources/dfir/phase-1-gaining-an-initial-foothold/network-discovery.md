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

# Network Discovery

### Introduction

The **Unified Kill Chain (UKC)** model provides a structured approach to investigating **Network Discovery** activitie&#x73;**,** a crucial stage in an attack lifecycle where adversaries gather information about the network, Active Directory (AD), and connected systems. In this phase, attackers use built-in tools and third-party utilities to perform reconnaissance, map network topology, identify high-value targets, and uncover security gaps. By leveraging the UKC model, defenders can identify signs of unauthorised discovery activity, link them to specific tactics, techniques, and procedures (TTPs), and take appropriate steps to mitigate potential threats.

Attackers often rely on tools that are either built into Microsoft Windows or are easily accessible, making detection more challenging. Below are some commonly used tools and methods during the network discovery phase:

* **ADRecon:** A PowerShell-based tool designed to extract detailed Active Directory information, such as users, groups, and trusts, for reconnaissance purposes.
* **BloodHound (or SharpHound):** A tool that leverages Windows API functions and Lightweight Directory Access Protocol (LDAP) queries to analyse and visualise AD privilege escalation paths.
* **ADFind:** A command-line tool used to query Active Directory for information on objects, attributes, and group memberships.
* **ADExplorer:** A Sysinternals tool that provides advanced browsing and editing capabilities for Active Directory, enabling attackers to view and manipulate directory data.
* **CrackMapExec:** A post-exploitation tool written in Python that automates various tasks, including network reconnaissance, credential validation, and privilege escalation.
* **PowerView:** A PowerShell tool used to gain situational awareness of a Windows network by identifying shares, users, groups, and trust relationships.
* **LDAP Browser:** A utility for browsing and analysing LDAP directories, often used to inspect AD data structures.
* **PowerShell Built-In Applets:** Attackers use native PowerShell cmdlets, such as `Get-ADUser` or `Get-NetIPAddress`, to extract network and AD data stealthily.
* **Nltest:** A command-line tool for querying domain controllers, trust relationships, and domain status.
* **Net.exe:** A Windows command-line tool used to enumerate shared resources, domain groups, and user accounts.

Adversaries frequently use these tools during network discovery due to their availability and ability to blend into normal administrative activity. By focusing on these tools and their usage patterns, defenders can identify suspicious behaviour, such as excessive AD queries, abnormal use of PowerShell, or unauthorised execution of discovery tools. Using detection platforms like Microsoft Sentinel (KQL), Velociraptor (VQL), and Splunk (SPL), SOC analysts can systematically investigate network discovery activities and disrupt attackers early in the attack lifecycle
