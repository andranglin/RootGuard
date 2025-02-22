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

# Active Directory Security Controls

### **Introduction**

Organisations with effective mitigation controls are better equipped to prevent, detect, and respond to cybersecurity threats. These controls include a mix of preventive measures, such as firewalls, endpoint protection, and intrusion prevention systems, as well as detective mechanisms like security information and event management (SIEM) systems and anomaly detection tools. By layering these defences, organisations create a robust security framework that minimises the likelihood of breaches while maintaining continuous visibility into their network. Regular vulnerability assessments, penetration testing, and timely patch management ensure that known vulnerabilities are promptly addressed, reducing exposure to attacks.

In addition to technical measures, effective mitigation controls rely on well-defined processes and educated personnel. Incident response plans, for instance, ensure that organisations can react quickly and decisively to mitigate the impact of breaches. Employee security awareness programs equip staff with the knowledge to recognise phishing attempts, suspicious activities, and social engineering tactics, reducing the risk of human error. These measures foster a culture of security across the organisation, making cybersecurity a shared responsibility rather than just the IT department’s concern.

Organisations that prioritise mitigation controls also invest in compliance with regulatory and industry standards, such as GDPR, ISO 27001, and NIST frameworks. This ensures legal compliance and demonstrates a commitment to protecting customer and partner data, fostering trust and credibility. Continuous monitoring and auditing of controls provide real-time insights into the organisation’s security posture, enabling proactive adjustments as threats evolve. In today’s dynamic threat landscape, effective mitigation controls are not just protective measures but enablers of business continuity, resilience, and stakeholder confidence.

**Note:** The following checklist presents the mitigations for each Active Directory compromise detailed on the [Detect and Mitigate Active Directory Compromise](./) page.

### [Mitigating Kerberoasting ](kerberoasting.md)

* [ ] Minimise the number of user objects configured with SPNs.
* [ ] Create user objects with SPNs as gMSAs. However, if this is not feasible, set a minimum 30-character password that is unique, unpredictable, and managed.&#x20;
* [ ] Assign user objects with SPNs the minimum privileges necessary to perform their functions and ensure they are not members of highly privileged security groups, such as the Domain Admins security group.

### [Mitigating AS-REP Roasting ](authentication-server-response-as-rep-roasting.md)

* [ ] Ensure user objects require Kerberos pre-authentication. However, if user objects must be configured to bypass Kerberos pre-authentication, then these user objects should be granted the minimum set of privileges required for them to perform their functions. They should not be members of highly privileged security groups like Domain Admins. Additionally, set a minimum 30-character password that is unique, unpredictable and managed.

### [Mitigating Password Spraying ](password-spraying.md)

* [ ] Create passwords for local administrator accounts, service accounts, and break glass accounts that are long (30-character minimum), unique, unpredictable and managed.
* [ ] Create passwords used for single-factor authentication that consist of at least four random words with a total minimum length of 15-characters.
* [ ] Lock out user objects, except for break glass accounts, after a maximum of five failed logon attempts.
* [ ] Ensure passwords created for user objects are randomly generated, such as when a user object is created, or a user requests a password reset.
* [ ] Configure the built-in ‘Administrator’ domain account as sensitive to ensure it cannot be delegated.
* [ ] Scan networks at least monthly to identify any credentials that are being stored in the clear.&#x20;
* [ ] Disable the NTLM protocol.

### [Mitigating a MachineAccountQuota Compromise ](machineaccountquota-compromise.md)

* [ ] Configure unprivileged user objects so they cannot add computer objects to the domain.
* [ ] Ensure the Domain Computers security group is not a member of privileged security groups.&#x20;
* [ ] Ensure the Domain Computers security group does not have write privileges to any objects in Active Directory.
* [ ] Enable LDAP signing for Domain Controllers.

### [Mitigating an Unconstrained Delegation Compromise ](unconstrained-delegation.md)

* [ ] Ensure computer objects are not configured for unconstrained delegation.&#x20;
* [ ] Ensure privileged user objects are configured as ‘sensitive and cannot be delegated’.
* [ ] Ensure privileged user objects are members of the Protected Users security group.&#x20;
* [ ] Disable the Print Spooler service on Domain Controllers.

### [Mitigating a Password in GPP Compromise](password-in-group-policy-preferences-gpp-compromise.md)&#x20;

* [ ] Remove all GPP passwords.
* [ ] Apply Microsoft’s security patch 2962486 to remove the functionality to create cpasswords.

### [Mitigating an AD CS Compromise ](active-directory-certificate-services-ad-cs-compromise.md)

* [ ] Remove the ‘Enrollee Supplies Subject’ flag.
* [ ] Restrict standard user object permissions on certificate templates.
* [ ] Remove vulnerable AD CS CA configurations.
* [ ] Require CA Certificate Manager approval for certificate templates that allow the SAN to be supplied.
* [ ] Remove EKUs that enable user authentication.
* [ ] Limit access to AD CS CA servers to only privileged users that require access.
* [ ] Restrict privileged access pathways to AD CS CA servers to jump servers and secure admin workstations using only the ports and services that are required for administration.
* [ ] Only use AD CS CA servers for AD CS and do not install any non-security-related services or applications.
* [ ] Encrypt and securely store backups of AD CS CA servers and limit access to only Backup Administrators.
* [ ] Centrally log and analyse AD CS CA server logs in a timely manner to identify malicious activity.

### [Mitigating a Golden Certificate ](golden-certificate.md)

* [ ] Use MFA to authenticate privileged users of systems.
* [ ] Implement application control on AD CS CAs.
* [ ] Use a HSM to protect key material for AD CS CAs.
* [ ] Limit access to AD CS CAs to only privileged users that require access.
* [ ] Restrict privileged access pathways to AD CS CA servers to jump servers and secure admin workstations using only the ports and services that are required for administration.
* [ ] Only use AD CS CA servers for AD CS and do not install any non-security-related services or applications.
* [ ] Encrypt and securely store backups of AD CS CA servers and limit access to only Backup Administrators.
* [ ] Centrally log and analyse AD CS CA logs in a timely manner to identify malicious activity.

### [Mitigating DCSync](dcsync.md)&#x20;

* [ ] Minimise the number of user objects with DCSync permissions.
* [ ] Ensure user objects that are configured with a SPN do not have DCSync permissions.
* [ ] Ensure user objects with DCSync permissions cannot log on to unprivileged operating environments.
* [ ] Review user objects with DCSync permissions every 12 months to determine if these permissions are still required.
* [ ] Disable the NTLMv1 protocol.
* [ ] Ensure LM password hashes are not used.

### [Mitigating Dumping ntds.dit ](dumping-ntds.dit.md)

* [ ] Limit access to Domain Controllers to only privileged users that require access.
* [ ] Restrict privileged access pathways to Domain Controllers to jump servers and secure admin workstations using only the ports and services that are required for administration.
* [ ] Encrypt and securely store backups of Domain Controllers and limit access to only Backup Administrators.&#x20;
* [ ] Only use Domain Controllers for AD DS and do not install any non-security-related services or applications.
* [ ] Centrally log and analyse Domain Controller logs in a timely manner to identify malicious activity
* [ ] Disable the Print Spooler service on Domain Controllers.
* [ ] Disable the SMB version 1 protocol on Domain Controllers.

### [Mitigating a Golden Ticket ](golden-ticket.md)

* [ ] Change the KRBTGT password every 12 months, or when the domain has been compromised or suspected to have been compromised.

### [Mitigating a Silver Ticket ](silver-ticket.md)

* [ ] Create User objects with SPNs as group Managed Service Accounts (gMSAs).
* [ ] Change all computer object (including Domain Controller) passwords every 30 days.
* [ ] Ensure computer objects are not members of privileged security groups, such as the Domain Admins security group.
* [ ] Ensure the Domain Computers security group does not have write or modify permissions to access any objects in the Active Directory.

### [Mitigating a Golden SAML ](golden-security-assertion-markup-language-saml.md)

* [ ] Ensure the AD FS service account is a gMSA.
* [ ] Ensure the AD FS service account is used only for AD FS and no other purpose.
* [ ] Ensure passwords for AD FS server local administrator accounts are long (30-character minimum), unique, unpredictable and managed.
* [ ] Limit access to AD FS servers to only privileged users that require access.
* [ ] Restrict privileged access pathways to AD FS servers to jump servers and secure admin workstations using only the ports and services that are required.
* [ ] Only use AD FS servers for AD FS and ensure no other non-security-related services or applications are installed.
* [ ] Centrally log and analyse AD FS server logs in a timely manner to identify malicious activity.&#x20;
* [ ] Encrypt and securely store backups of AD FS servers and limit access to only Backup Administrators.
* [ ] Rotate AD FS token-signing and encryption certificates every 12 months, or sooner if an AD FS server has been compromised or suspected to have been compromised.

### [Mitigating a Microsoft Entra Connect Compromise ](microsoft-entra-connect-compromise.md)

* [ ] Disable hard match takeover.
* [ ] Disable soft matching.
* [ ] Do not synchronise privileged user objects from AD DS to Microsoft Entra ID. Use separate privileged accounts for AD DS and Microsoft Entra ID.
* [ ] Enable MFA for all privileged users in Microsoft Entra ID.
* [ ] Limit access to Microsoft Entra Connect servers to only privileged users that require access.&#x20;
* [ ] Restrict privileged access pathways to Microsoft Entra Connect servers to jump servers and secure admin workstations using only the ports and services that are required for administration.
* [ ] Ensure that the passwords for Microsoft Entra Connect server local administrator accounts are long (30-character minimum), unique, unpredictable, and managed.
* [ ] Only use Microsoft Entra Connect servers for Microsoft Entra Connect and ensure no other non-security-related services or applications are installed.
* [ ] Encrypt and securely store backups of Microsoft Entra Connect and limit access to only Backup Administrators.
* [ ] Centrally log and analyse Microsoft Entra Connect server logs in a timely manner to identify malicious activity.

### [Mitigating a One-Way Domain Trust Bypass ](one-way-domain-trust-bypass.md)

* [ ] Limit access to Domain Controllers to only privileged users that require access.
* [ ] Restrict privileged access pathways to Domain Controllers to jump servers and secure admin workstations using only the ports and services that are required for administration.
* [ ] Encrypt and securely store backups of Domain Controllers and limit access to only Backup Administrators.
* [ ] Only use Domain Controllers for AD DS and do not install any non-security-related services or applications.
* [ ] Centrally log and analyse Domain Controller logs in a timely manner to identify malicious activity.&#x20;
* [ ] Disable the Print Spooler service on Domain Controllers.

### [Mitigating a SID History Compromise ](security-identifier-sid-history-compromise.md)

* [ ] Ensure the ‘sIDHistory’ attribute is not used.
* [ ] Ensure the ‘sIDHistory’ attribute is checked weekly.
* [ ] Enable SID Filtering for domain and forest trusts.

### [Mitigating Skeleton Key](skeleton-key.md)

* [ ] Limit access to Domain Controllers to only privileged users that require access.
* [ ] Restrict privileged access pathways to Domain Controllers to jump servers and secure admin workstations using only the ports and services that are required for administration.
* [ ] Run the LSASS process in protected mode.
* [ ] Implement Microsoft’s vulnerable driver blocklist.
* [ ] Restrict driver execution to an approved set.
* [ ] Only use Domain Controllers for AD DS and do not install any non-security-related services or applications.
* [ ] Centrally log and analyse Domain Controller logs in a timely manner to identify malicious activity.
* [ ] Disable the Print Spooler service on Domain Controllers.

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
* [Active Directory Security Best Practices](https://www.netwrix.com/active-directory-best-practices.html)
