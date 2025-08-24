# Active Directory Events for Detecting Compromise

Recommended event IDs to log and monitor to detect the Active Directory compromises detailed in the  [Detect and Mitigate Active Directory Compromise](./) sections

### Domain Controller Events

The following events should be centrally logged and analysed to identify Active Directory compromises involving Domain Controllers.

Table 1. Events that detect compromises involving Domain Controllers

<table data-full-width="false"><thead><tr><th width="118">Event ID</th><th width="216">Compromise</th><th>Description</th></tr></thead><tbody><tr><td>39</td><td>AD CS</td><td>The KDC encountered a valid user certificate that could not be securely mapped to a user (such as via explicit mapping, key trust mapping, or a SID).</td></tr><tr><td>40</td><td>AD CS</td><td>A certificate is issued before the user exists in Active Directory, and no explicit mapping can be found. This event is only logged when the KDC is in Compatibility mode.</td></tr><tr><td>41</td><td>AD CS</td><td>A certificate contains the new SID extension, but it does not match the SID of the corresponding user account.</td></tr><tr><td>1103</td><td>Dumping ntds.dit, One-way Trust Bypass, SID History, Skeleton Key</td><td>The ‘Security’ audit log is cleared.</td></tr><tr><td>2889</td><td>Password Spray</td><td>A computer object tries to make an unsigned LDAP bind.</td></tr><tr><td>3033</td><td>Skeleton Key</td><td>A driver fails to load because it does not meet Microsoft’s signing requirements.</td></tr><tr><td>3063</td><td>Skeleton Key</td><td>A driver fails to load because it does not meet the security requirements for shared sections.</td></tr><tr><td>4103</td><td>Dumping ntds.dit, One-way Trust Bypass, SID History, Skeleton Key</td><td>PowerShell executes and logs pipeline execution details.</td></tr><tr><td>4104</td><td>Dumping ntds.dit, One-way Trust Bypass, SID History, Skeleton Key</td><td>PowerShell executes code to capture scripts and commands.</td></tr><tr><td>4624</td><td>Password Spray, MachineAccountQuota, Unconstrained Delegation</td><td>An account is successfully logged on</td></tr><tr><td>4625</td><td>AS-REP Roasting, Password Spray</td><td>An account fails to log on.</td></tr><tr><td>4656</td><td>Dumping ntds.dit</td><td>A handle to an object is requested.</td></tr><tr><td>4662</td><td>DCSync, Golden SAML</td><td>An operation is performed on an object.</td></tr><tr><td>4663</td><td>Dumping ntds.dit, Skeleton Key</td><td>An attempt is made to access an object.</td></tr><tr><td>4673</td><td>Skeleton Key</td><td>A privileged service is called.</td></tr><tr><td>4674</td><td>AD CS</td><td>An operation is attempted on a privileged object.</td></tr><tr><td>4675</td><td>SID History (Domain hopping with Golden Tickets and SID History)</td><td>SIDs were filtered</td></tr><tr><td>4688</td><td>Dumping ntds.dit</td><td>A new process is created.</td></tr><tr><td>4697</td><td>Skeleton Key</td><td>A service is installed in the system.</td></tr><tr><td>4703</td><td>Skeleton Key</td><td>A user right is adjusted.</td></tr><tr><td>4724</td><td>MachineAccountQuota</td><td>An attempt is made to reset an account's password.</td></tr><tr><td>4738</td><td>Kerberoasting, AS-REP Roasting, SID History</td><td>A user account is changed.</td></tr><tr><td>4740</td><td>Password Spray</td><td>A user account is locked out.</td></tr><tr><td>4741</td><td>MachineAccountQuota</td><td>A computer account was created in Active Directory.</td></tr><tr><td>4768</td><td>AS-REP Roasting, AD CS, Golden Ticket, One-way Trust Bypass</td><td>A Kerberos TGT is requested.</td></tr><tr><td>4769</td><td>Kerberoasting, Golden Ticket</td><td>A TGS is requested.</td></tr><tr><td>4770</td><td>Unconstrained Delegation</td><td>A Kerberos TGT is renewed.</td></tr><tr><td>4771</td><td>Password Spray</td><td>Kerberos pre-authentication fails.</td></tr><tr><td>5136</td><td>Kerberoasting, AS-REP Roasting</td><td>A directory service object was modified.</td></tr><tr><td>8222</td><td>Dumping ntds.dit</td><td>A shadow copy is created.</td></tr></tbody></table>

### Active Directory Certificate Services Certificate Authority (AD CS CA) Events

The below events should be centrally logged and analysed to identify Active Directory compromises involving AD CS CA servers.&#x20;

Table 2. Events that detect compromises involving AD CS CA servers

<table><thead><tr><th>Event ID</th><th>Compromise</th><th width="397">Description</th></tr></thead><tbody><tr><td>1102</td><td>AD CS, Golden Certificate</td><td>The ‘Security’ audit log was cleared.</td></tr><tr><td>4103</td><td>Golden Certificate</td><td>PowerShell module logging.</td></tr><tr><td>4104</td><td>Golden Certificate</td><td>PowerShell script block logging.</td></tr><tr><td>4876</td><td>Golden Certificate</td><td>Certificate Services backup was started.</td></tr><tr><td>4886</td><td>AD CS</td><td>Certificate Services received a certificate request.</td></tr><tr><td>4887</td><td>AD CS</td><td>Certificate Services approved a certificate request and issued a certificate.</td></tr><tr><td>4899</td><td>AD CS</td><td>A Certificate Services template was updated.</td></tr><tr><td>4900</td><td>AD CS</td><td>Certificate Services template security was updated.</td></tr></tbody></table>

### Active Directory Federation Services (AD FS) Events

The events below should be centrally logged and analysed to identify active directory compromises involving AD FS servers.

Table 3. Events that detect compromises involving AD FS servers

<table><thead><tr><th width="180">Event ID</th><th width="185">Compromise</th><th>Description</th></tr></thead><tbody><tr><td>70</td><td>Golden SAML</td><td>A Certificate Private Key was acquired.</td></tr><tr><td>307</td><td>Golden SAML</td><td>The Federation Service configuration was changed.</td></tr><tr><td>510</td><td>Golden SAML</td><td>Additional information about events, such as federation service configuration changes, was requested.</td></tr><tr><td>1007</td><td>Golden SAML</td><td>A certificate was exported.</td></tr><tr><td>1102</td><td>Golden SAML</td><td>The ‘Security’ audit log was cleared.</td></tr><tr><td>1200</td><td>Golden SAML</td><td>The Federation Service issued a valid token.</td></tr><tr><td>1202</td><td>Golden SAML</td><td>The Federation Service validated a new credential.</td></tr></tbody></table>

### Microsoft Entra Connect Server Events&#x20;

The events should be centrally logged and analysed to identify Active Directory compromises involving Microsoft Entra Connect servers.

Table 4. Events that detect compromises involving Microsoft Entra Connect servers

<table><thead><tr><th width="170">Event ID </th><th width="216">Compromise</th><th>Description</th></tr></thead><tbody><tr><td>611</td><td>Microsoft Entra Connect</td><td>PHS failed for the domain.</td></tr><tr><td>650</td><td>Microsoft Entra Connect</td><td>Password synchronisation starts retrieving updated passwords from the on-premises AD DS.</td></tr><tr><td>651</td><td>Microsoft Entra Connect</td><td>Password synchronisation finishes retrieving updated passwords from the on-premises AD DS.</td></tr><tr><td>656</td><td>Microsoft Entra Connect</td><td>Password synchronisation indicates that a password change was detected and there was an attempt to sync it to Microsoft Entra ID.</td></tr><tr><td>657</td><td>Microsoft Entra Connect</td><td>A password was successfully synced for a user object.</td></tr><tr><td>1102</td><td>Microsoft Entra Connect</td><td>The security audit log was cleared.</td></tr><tr><td>4103</td><td>Microsoft Entra Connect</td><td>PowerShell module logging.</td></tr><tr><td>4104</td><td>Microsoft Entra Connect</td><td>PowerShell script block logging.</td></tr></tbody></table>

### Computer Objects Configured for Unconstrained Delegation Events&#x20;

The events below should be centrally logged and analysed to identify Active Directory compromises involving computer objects configured for unconstrained delegation.

Table 5. Events that detect compromises involving computer objects configured for unconstrained delegation

<table><thead><tr><th width="174">Event ID</th><th width="224">Compromise</th><th>Description</th></tr></thead><tbody><tr><td>4103</td><td>Unconstrained delegation</td><td>PowerShell executes and logs pipeline execution details.</td></tr><tr><td>4104</td><td>Unconstrained delegation</td><td>PowerShell executes code to capture scripts and commands.</td></tr><tr><td>4624</td><td>Unconstrained delegation</td><td>An account is successfully logged on.</td></tr><tr><td>4688</td><td>Unconstrained delegation</td><td>A new process is created.</td></tr></tbody></table>

### Computer Objects Compromised by a Silver Ticket

The following events should be centrally logged and analysed to identify Active Directory compromises involving Silver Tickets.

Table 6. Events that detect Silver Ticket compromises

<table><thead><tr><th width="151">Event ID</th><th>Compromise</th><th>Description</th></tr></thead><tbody><tr><td>4624</td><td>Silver Ticket</td><td>This event is generated when an account is logged into a computer. It can be correlated and analysed with event 4627 for signs of a potential Silver Ticket.</td></tr><tr><td>4627</td><td>Silver Ticket</td><td>This event is generated alongside event 4624 and provides additional information regarding the group membership of the account that logged in. This event can be analysed for discrepancies, such as mismatching SID and group membership information for the user object that logged on. Note that a Silver Ticket forges the TGS, which can contain false information, such as a different SID to the user object logging on and different group memberships. Malicious actors falsify this information to escalate their privileges on the target computer object.</td></tr></tbody></table>

### Reference

* [Microsoft Identity and Access documentation](https://learn.microsoft.com/en-au/windows-server/identity/identity-and-access)
* [Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/detecting-and-mitigating-active-directory-compromises?ref=search)
* [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Securing Domain Controllers Against Attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack)
* [Top 25 Active Directory Security Best Practices](https://activedirectorypro.com/active-directory-security-best-practices/)
