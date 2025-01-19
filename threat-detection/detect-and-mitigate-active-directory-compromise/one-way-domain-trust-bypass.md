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

# One-way Domain Trust Bypass

### **Introduction**

In multi-domain Active Directory (AD) environments, **one-way domain trust** is a mechanism that allows users in one domain (the trusted domain) to access resources in another domain (the trusting domain). This trust relationship is often used to facilitate resource sharing while maintaining administrative separation between domains. However, this setup can be exploited by attackers through a **one-way domain trust bypass**, enabling unauthorized access to resources in the trusting domain. This occurs when attackers abuse the trust relationship to escalate privileges, perform lateral movement, or access sensitive data.

One-way trust bypass attacks are particularly concerning in environments where domains with varying security levels coexist. Attackers can exploit misconfigurations, weak security practices, or compromised accounts in the trusted domain to gain access to the trusting domain, circumventing security controls and potentially compromising the entire environment.

***

### **Attack Description**

A one-way domain trust bypass leverages the asymmetric nature of trust between domains. In this scenario:

1. The trusted domain allows its users to authenticate to resources in the trusting domain.
2. The trusting domain does not grant reciprocal access to resources in the trusted domain, creating a one-way trust.

Attackers can exploit this by:

* **Compromising Accounts in the Trusted Domain**: Using credentials from the trusted domain to access resources in the trusting domain.
* **Abusing Misconfigurations**: Exploiting weak trust configurations, such as overly permissive access controls or lack of network segmentation.
* **Forging Kerberos Tickets**: Using tools like Mimikatz to create Service Tickets (Silver Tickets) or Golden Tickets to impersonate users in the trusted domain and access resources in the trusting domain.

Once access is gained, attackers may escalate privileges, perform reconnaissance, and pivot to other systems, potentially compromising the trusting domain entirely.

***

### **Detection Techniques**

1.  **Events that detect a One-Way Domain Trust Bypass**

    Source of detection:

    * **Event ID 1102:** Events generated when the ‘Security’ audit log is cleared. To avoid detection, malicious actors may clear this audit log to remove any evidence of their activities. Analysing this event can assist in identifying if a Domain Controller has been compromised.
    * **Event ID 4103:** Events generated when PowerShell executes and logs pipeline execution details. Common malicious tools used to retrieve the TDO password hash, like Mimikatz, use PowerShell. Analysing this event for unusual PowerShell executions on Domain Controllers may indicate the TDO has been compromised.
    * Event ID 4104: Events generated when PowerShell executes code to capture scripts and commands. Common malicious tools used to retrieve the TDO password hash, such as Mimikatz, use PowerShell. Analysing this event for unusual PowerShell executions on Domain Controllers may indicate the TDO has been compromised.
    * Event ID 4768: Events generated when a TGT is requested. After the TDO password hash has been retrieved, it is commonly used to request a TGT in the trusted domain. If the User ID value matches the TDO username, this may indicate the TDO has been compromised and a one-way domain trust bypass has occurred.
2. **Monitor Cross-Domain Authentication**:
   * Analyze logon events (Event ID 4624) to detect unusual authentication from accounts in the trusted domain.
   * Look for service ticket requests (Event ID 4769) involving accounts from the trusted domain accessing high-value systems in the trusting domain.
3. **Track Administrative Activities**:
   * Review events for privileged account usage from the trusted domain, such as group membership changes (Event ID 4728/4732).
4. **Detect Anomalous Traffic**:
   * Monitor network traffic between domains for unusual access patterns or connections to sensitive resources.
5. **Identify Suspicious Ticket Activity**:
   * Look for forged Kerberos tickets (e.g., abnormal ticket encryption types or unusually long ticket lifetimes).
6. **Behavioral Analysis**:
   * Use User and Entity Behavior Analytics (UEBA) to detect deviations from normal cross-domain access patterns.

***

### **Mitigation Techniques**

1. **The following security controls should be implemented to mitigate a one-way domain trust bypass:**
   * Limit access to Domain Controllers to only privileged users that require access. This reduces the number of opportunities for malicious actors to gain access to Domain Controllers.
   * Restrict privileged access pathways to Domain Controllers to jump servers and secure admin workstations using only the ports and services that are required for administration. Domain Controllers are classified as ‘Tier 0’ assets within Microsoft’s ‘Enterprise Access Model’.&#x20;
   * Encrypt and securely store backups of Domain Controllers and limit access to only Backup Administrators. Backups of Domain Controllers need to be afforded the same security as the actual Domain Controllers. Malicious actors may target backup systems to gain access to critical and sensitive computer objects, such as Domain Controllers.
   * Only use Domain Controllers for AD DS and do not install any non-security-related services or applications. This reduces the attack surface of Domain Controllers as there are fewer services, ports and applications that may be vulnerable and used to compromise a Domain Controller.&#x20;
   * Centrally log and analyse Domain Controller logs in a timely manner to identify malicious activity. Domain Controller logs provide a rich source of information that is important for investigating potentially malicious activity on Domain Controllers and in the domain.
   * Disable the Print Spooler service on Domain Controllers. For example, malicious actors have targeted the Print Spooler service on Domain Controllers as a technique to authenticate to a system they control to collect the Domain Controllers computer object password hash or TGT. Malicious actors can then use this to authenticate to the Domain Controller they coerced and gain administrative access.
2. **Harden Trust Configurations**:
   * Use selective authentication for one-way trusts to restrict access to specific resources.
   * Disable unnecessary trusts and ensure all trusts are actively managed.
3. **Enforce Strong Account Security**:
   * Implement multi-factor authentication (MFA) for all accounts in both trusted and trusting domains.
   * Regularly review and rotate credentials for privileged accounts.
4. **Enable Advanced Logging**:
   * Enable detailed Kerberos, logon, and group membership auditing in both domains.
   * Collect and centralize logs for analysis in a SIEM solution.
5. **Segment and Isolate Networks**:
   * Implement network segmentation to limit access between domains, allowing only necessary traffic.
   * Restrict domain controller communication to known, authorized systems.
6. **Regularly Audit Trust Relationships**:
   * Conduct periodic reviews of trust configurations to ensure they follow the principle of least privilege.
   * Test for misconfigurations or overly permissive access settings.
7. **Deploy Threat Detection Tools**:
   * Use tools like Microsoft Defender for Identity, Splunk, or Azure Sentinel to detect and alert on anomalous cross-domain activity.

***

By proactively monitoring and securing domain trust relationships, organizations can prevent attackers from exploiting one-way domain trust bypass vulnerabilities, reducing the risk of privilege escalation and lateral movement across domains.
