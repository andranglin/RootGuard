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

# Critical Windows Event ID’s to Monitor

When building your security program, there are a number of critical Windows Event IDs that should be monitored; the following is not an exhaustive list but a very good starting point.

### Logon events

Most recommended best practices suggest failure or success for [account](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events) and [general](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events) logon events must be monitored. Critical Event IDs to monitor include:

* 4624: User successfully logged on to a computer
* 4625: Attempt made to logon with unknown user name or bad password and failed
* 4634: Logoff process completed for user
* 4647: User Initiated logoff
* 4648: User successfully logged on to a computer using explicit credentials while already logged on as a different user
* 4779: User disconnected terminal server or virtual host session without logging off
* 4798: A user’s local group membership was enumerated.
* 4799: A security-enabled local group membership was enumerated
* 4820: A Kerberos Ticket-granting-ticket (TGT) was denied
* 4821: A Kerberos service ticket was denied because the user, device, or both do not meet the access control restrictions
* 4822: NTLM authentication failed because the account was a member of the Protected User group
* 4823: NTLM authentication failed because access control restrictions are required
* 4824: Kerberos pre-authentication by using DES or RC4 failed because the account was a member of the Protected User group

### Privilege use

Managing how people use their access falls into multiple categories, including object access, non-sensitive privilege use, and sensitive privilege use.

The Event IDs for managing access fall into several categories, including:

* [Object Access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events): resources people use, like files, folders, registry keys, or printers.
* [Audit File System](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system): operating system audit events when users attempt to access file system object that have system access control lists (SACLs) and requested access types (Write, Read, Modify)
* [Audit Non-Sensitive Privilege Use](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-non-sensitive-privilege-use): how people use standard access across Microsoft technologies from workstations to remote systems to files.
* [Audit Sensitive Privilege Use](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-non-sensitive-privilege-use): how people use privileged access like acting as part of the operating system or enabling accounts to be trusted for delegation.

Some important Event IDs to consider include:

* 4103: PowerShell Module Logging
* 4104: PowerShell Script Block Logging
* 4656: Request to handle or access an object
* 4658: Handle to an object was closed
* 4659: Handle to an object was requested with intent to delete
* 4660: Object deleted
* 4663: Attempt to access object was made
* 4664: Attempt to create a hard link was made
* 4670: Object permissions were changed
* 4672: Special Privileges Assigned to New Logon
* 4673: Calling privileged service
* 4674: Attempted operation on a privileged object
* 4985: Transaction state change
* 4691: Indirect access to an object was requested.
* 4698: A scheduled task was created.
* 4699: A scheduled task was deleted.
* 4700: A scheduled task was enabled.
* 4701: A scheduled task was disabled.
* 4702: A scheduled task was updated.
* 5051: File was virtualized

### Windows Server

The following Event IDs can potentially indicate a [high criticality](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) event that applies to Windows Server 2022, [Windows Server 2019,](https://graylog.org/post/monitoring-microsoft-sql-server-login-audit-events-in-graylog/) and newer Windows Servers:

* 1100: The event logging service has shut down
* 1101: Audit events have been dropped by the transport.
* 1102: Audit log cleared
* 1104: The security Log is now full
* 4618: Monitored security event pattern occurred
* 4649: Potential replay attack detected
* 4719: Change to system audit policy
* 4765: SID History added to an account
* 4766: Failed attempt to add SID History to an account
* 4794: Attempt at setting Directory Services Restore Mode
* 4897: Role separation enabled
* 4964: Special groups assigned new logon
* 5124: Update to security setting on OCSP Responder Service

### Microsoft Defender Antivirus

The following [Event IDs](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide) indicate an event with Microsoft 365 antivirus:

* 1002: malware scan stopped before completing scan
* 1003: malware scan paused
* 1005: malware scan failed
* 1006, 1116: malware or unwanted software detected
* 1007, 1117: action to protect system performed
* 1008, 1118: action to protect system failed
* 1009: item restored from quarantine
* 1012: unable to delete item in quarantine
* 1015: suspicious behaviour detected
* 1119: A critical error occurred when taking action
