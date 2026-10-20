# DCSync: Detection and Mitigation

## Overview

DCSync (MITRE ATT&CK T1003.006) abuses Active Directory Directory Replication Service Remote Protocol (MS-DRSR) access to request replicated directory information, potentially including credential material. It does not require interactive execution on the domain controller. An account needs appropriate directory replication rights, and authorised domain controllers and some synchronisation products legitimately use replication.

**Detection hypothesis:** A non-domain-controller principal or unexpected source invokes directory replication operations against a domain controller.

## Prerequisites

- Collect Windows Security Event **4662** from domain controllers and configure the necessary Directory Service Access auditing and directory object SACLs. Event 4662 is not automatically generated for every DCSync attempt.
- Inspect actual `SecurityEvent` records and their `Properties` and `AccessMask` contents. Schema and event rendering vary by agent and collection method.
- Relevant replication extended-right GUIDs include:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes-All
  - `89e95b76-444d-4c62-991a-0facbeda640c` — DS-Replication-Get-Changes-In-Filtered-Set

Event 4662 reports object operations on the domain controller. It does **not** reliably give the network originator's IP address. Neither Event 4672 nor ordinary LDAP connections alone prove DCSync activity.

## Query: Review replication-right accesses

**Status: Concept / unvalidated.** This example hunts for replication-related 4662 events. Verify ingestion and fields before using it in a scheduled detection.

```kusto
let ReplicationRights = dynamic([
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c"
]);
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4662
| extend EventProperties = tostring(column_ifexists("Properties", ""))
| where EventProperties has_any (ReplicationRights)
    or tostring(EventData) has_any (ReplicationRights)
| project TimeGenerated, Computer, Account, SubjectUserName,
          AccessMask, EventProperties, EventData
| order by TimeGenerated desc
```

**Triage:** Identify the principal and domain controller, inspect the original event, and compare the principal with approved domain controller and synchronisation identities. Correlate with network RPC telemetry and endpoint events when available. Some environments may record GUID strings in different formats, or not expose them in indexed fields; compare against raw examples.

## Review directory replication permissions

Replication rights are **extended control access permissions**, usually assigned on the domain naming context. They are not regular attributes of AD user objects. Inspect effective access control entries and nested group membership rather than relying on a nonexistent `ReplicatingDirectoryChanges` property from `Get-ADUser`.

Example for authorised administrators with the ActiveDirectory module:

```powershell
Import-Module ActiveDirectory
$domainDn = (Get-ADDomain).DistinguishedName
(Get-Acl -Path "AD:\\$domainDn").Access |
    Where-Object {
        $_.ObjectType -in @(
            [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
            [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
            [guid]'89e95b76-444d-4c62-991a-0facbeda640c'
        )
    } |
    Select-Object IdentityReference, ActiveDirectoryRights,
                  ObjectType, AccessControlType, IsInherited
```

This lists matching explicit or inherited access control entries, **not an exhaustive effective-permission calculation**. Group nesting, inheritance, denies and other rights must be considered.

## Hardening and response

1. Restrict directory replication rights to approved domain controllers and required synchronisation identities.
2. Review high-privilege group membership and delegated replication permissions regularly.
3. Prevent privileged identities from authenticating on lower-trust endpoints.
4. Restrict unnecessary network access to domain controllers and monitor RPC-based replication from non-DC systems.
5. Investigate suspected credential compromise; if the `krbtgt` credential was exposed, follow a coordinated recovery plan for its password rotation rather than a routine unplanned reset.
6. Keep Windows and domain controllers patched; review related account activity and persistence.

## Limitations

Event 4662 can be missing due to auditing or SACL configuration; legitimate replication creates similar events. The KQL above was not executed in the target environment, and a negative result does not prove DCSync did not occur.

## References

- [MITRE ATT&CK T1003.006: DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [Microsoft Security Event 4662](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)
- [Detection Validation Checklist](../detection-validation-checklist.md)
