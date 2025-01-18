---
cover: ../.gitbook/assets/Screenshot 2025-01-10 074920.png
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

# Detecting and Mitigating Microsoft Active Directory Compromises

### **Introduction**

Microsoft’s Active Directory is a cornerstone of authentication and authorisation in enterprise networks. It offers a suite of services, including Active Directory Domain Services (AD DS), Active Directory Federation Services (AD FS), and Active Directory Certificate Services (AD CS). These services provide various authentication options, such as smart card login and single sign-on for both on-premises and cloud-based services.

Due to its critical role, Active Directory is a prime target for malicious actors. Its susceptibility to compromise stems from permissive default settings, complex relationships, extensive permissions, support for legacy protocols, and inadequate diagnostic tools for security issues. Malicious actors frequently exploit these vulnerabilities to gain control over Active Directory.

One significant factor contributing to Active Directory's vulnerability is that every user has sufficient permissions to identify and exploit weaknesses. This extensive attack surface makes it challenging to defend. Additionally, the intricate and often opaque relationships between users and systems within Active Directory are frequently overlooked by organisations, providing malicious actors with opportunities to gain control over enterprise IT networks.

Control over Active Directory grants malicious actors privileged access to all managed systems and users. This access allows them to bypass other security controls and infiltrate critical systems, including email servers, file servers, and essential business applications. Furthermore, this privileged access can extend to cloud-based systems and services via Microsoft Entra ID, a paid feature. While this facilitates user access to cloud services, it also enables malicious actors to maintain and expand their foothold.

Malicious actors can establish persistence within organisations by exploiting Active Directory. Some techniques allow them to log in remotely, even bypassing multi-factor authentication (MFA) controls. These persistence methods are often resistant to cybersecurity incident response efforts aimed at eviction. Sophisticated actors may remain undetected within Active Directory for months or even years. Evicting these determined adversaries can require drastic measures, such as resetting all user passwords or rebuilding Active Directory entirely. Responding to and recovering from such compromises is time-consuming, costly, and disruptive. Therefore, organisations are urged to implement the recommendations in this guidance to better protect Active Directory from malicious actors and prevent compromises.

### **Understanding Active Directory**

For many organisations, Active Directory (AD) is a complex ecosystem comprising thousands of objects that interact through a web of permissions, configurations, and relationships. These objects include users, groups, computers, and other resources, each with specific permissions and roles within the network. Understanding these object permissions and relationships is crucial for securing an AD environment.

### Enumeration by Malicious Actors

Once malicious actors gain initial access to an environment, they often enumerate Active Directory to gather information. Enumeration involves systematically identifying and cataloguing the objects, configurations, and relationships within AD. This process helps attackers understand the unique structure of the organisation's AD environment, including its strengths and weaknesses. By doing so, they can sometimes gain a better understanding of the environment than the organisation itself, enabling them to target AD with a higher likelihood of success.

### Exploiting Weaknesses and Misconfigurations

Malicious actors use their knowledge of the AD environment to exploit weaknesses and misconfigurations.&#x20;

Common tactics include:

* **Privilege Escalation**: Attackers exploit vulnerabilities to gain higher-level permissions, allowing them to perform actions that would otherwise be restricted.
* **Lateral Movement**: Once inside the network, attackers move laterally to access additional systems and data. This movement is often facilitated by exploiting trust relationships and permissions within AD.
* **Domain Control**: Ultimately, attackers aim to gain full control of the AD domain, which grants them privileged access to all managed systems and users.

### Tools for Understanding and Securing Active Directory

To improve AD security, organisations must thoroughly understand their unique configurations. Several commercial and open-source tools can aid in this understanding:

* **BloodHound**: This tool provides a graphical user interface to help understand AD, identify misconfigurations, and pinpoint weaknesses that malicious actors may exploit. It visualises the relationships and permissions within AD, making it easier to identify potential attack paths.
* **PingCastle**: This tool generates an AD security report, highlighting potential vulnerabilities and providing recommendations for remediation.
* **Purple Knight**: This application offers insights into the security of an AD environment, identifying areas that may require attention to prevent exploitation.

### Persistence Techniques

Malicious actors often establish persistence within organisations by exploiting AD. Persistence techniques allow attackers to maintain access to the network over extended periods, even if initial access points are discovered and remediated. Some techniques enable remote login, bypassing multi-factor authentication (MFA) controls. These methods are often resistant to cybersecurity incident response efforts, making it challenging to evict determined adversaries.

### Responding to and Recovering from Compromises

Responding to and recovering from AD compromises is time-consuming, costly, and disruptive. Organisations may need to take drastic measures, such as resetting all user passwords or rebuilding AD entirely, to evict sophisticated attackers. Therefore, it is crucial for organisations to implement robust security measures and continuously monitor their AD environments to detect and mitigate potential threats.

### Types of Attacks Targetting Active Directory

Note: The following are the attack types that are in scope.

* [Kerberoasting ](kerberoasting.md)
* [Authentication Server Response (AS-REP) Roasting ](authentication-server-response-as-rep-roasting.md)
* [Password Spraying ](../learning-resources/dfir-defender-and-sentinel/password-spraying.md)
* [MachineAccountQuota Compromise](machineaccountquota-compromise.md)
* [Unconstrained delegation](unconstrained-delegation.md)
* [Password in Group Policy Preferences (GPP) Compromise](password-in-group-policy-preferences-gpp-compromise.md)
* [Active Directory Certificate Services (AD CS) Compromise](active-directory-certificate-services-ad-cs-compromise.md)
* [Golden Certificate](golden-certificate.md)
* [DCSync ](dcsync.md)
* [Dumping ntds.dit](dumping-ntds.dit.md)
* [Golden Ticket](golden-ticket.md)
* [Silver Ticket](silver-ticket.md)
* Golden Security Assertion
* Markup Language (SAML)
* Microsoft Entra Connect Compromise
* One-way Domain Trust Bypass&#x20;
* Security Identifier (SID) History Compromise&#x20;
* Skeleton Key

### Detecting and Mitigating Active Directory Compromises

Detecting and mitigating Active Directory compromises involves a multi-faceted approach to ensure the security and integrity of the network. Organisations must continuously monitor their Active Directory environment for unusual activities and potential indicators of compromise. This includes tracking changes to critical objects, monitoring authentication logs, and using advanced threat detection tools to identify suspicious behaviour. Once a compromise is detected, immediate action is required to contain the threat and prevent further damage. Mitigation strategies include isolating affected systems, resetting compromised accounts, and addressing the vulnerabilities that allowed the breach. Implementing robust security measures, such as multi-factor authentication (MFA), regular security audits, and comprehensive incident response plans, is essential to prevent future compromises and maintain a secure Active Directory environment.

**Note:** The respective sections aim to provide an overview of the attacks, options for mitigations, and some KQL queries to detect activities in an Active Directory environment. To develop a comprehensive understanding and tackle more complex challenges, further exploration and learning beyond the the information provided is encouraged.

### Reference:

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
