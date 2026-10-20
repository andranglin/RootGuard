# Runbook Technical Safety and Validation Standard

**Review date:** 20 October 2026  
**Scope:** Ransomware, lateral movement, identity attack and BEC runbooks.  
**Status:** Editorial and command-risk review; **not** tenant/lab execution validation.

## Execution boundaries

- **Read-only investigation:** Confirm portal, permission, table and schema, time range, collection coverage, and whether the query has been tested.
- **State-changing operations:** Require a named incident, explicit approval, target verification, change record, expected impact, rollback plan and post-action validation.
- **Credential/session actions:** Session revocation is not guaranteed to invalidate all issued access tokens immediately. Password changes do not necessarily terminate workload/app sessions or remove grants.
- **Destructive actions:** Avoid broad deletion of inbox rules, GPOs, services, tasks or privileged identities. Preserve current configuration and evidence; target only validated malicious objects.
- **Domain recovery:** Never carry out `krbtgt` key resets as an unreviewed one-line action. Coordinate staged recovery with Active Directory specialists.
- **PowerShell:** Use supported Microsoft Graph modules for Microsoft Entra actions rather than retired AzureAD/MSOnline cmdlets. Grant only approved least-privileged permissions.

## Command review matrix

| Runbook | Risk identified | Remediation | Outstanding validation |
| --- | --- | --- | --- |
| Business Email Compromise | Bulk inbox-rule deletion; hard-coded shared temporary password | Replace with read-only inspection and approval-gated targeted change | Exchange cmdlets, mailbox permissions, client-rule impact |
| Identity Attack | Retired AzureAD PowerShell commands; overly simple krbtgt recovery | Replace with supported Graph/approved response actions and escalation | Graph permissions, tenant API responses, AD recovery plan |
| Ransomware | Destructive GPO removal and batch account operations | Substitute evidence-preserving review and incident-approved targeting | Tested restore/rollback, identity privileges, estate-specific containment |
| Lateral Movement | Account disable/session revocation without adequate gate | Explicit identity verification and approval before containment | AD and Graph permission scope, cross-host telemetry |

## Review levels

- **Static safety reviewed:** Risky examples and outdated commands addressed in text; not tested for runtime behaviour.
- **Syntax validated:** Confirmed in the actual command environment with module version and permissions.
- **Lab validated:** Repeatable execution with positive/negative test evidence and documented results.
- **Production validated:** Tested in authorised environment, including safety conditions and monitored outcome.

Current four-runbook classification: **Static safety reviewed / runtime validation pending**. Their other KQL/PowerShell samples have **not** been comprehensively executed or confirmed.

## Authoritative references

- [Microsoft Remove-InboxRule](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/remove-inboxrule)
- [Microsoft Graph Revoke-MgUserSignInSession](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users.actions/revoke-mgusersigninsession)
- [Microsoft Entra PowerShell module migration](https://learn.microsoft.com/en-us/powershell/entra-powershell/azuread-powershell-migration)
- [RootGuard Evidence Acquisition and Integrity](../field-guides/evidence-acquisition-and-integrity.md)

[Runbook Execution and Validation Matrix](runbook-execution-validation-matrix.md): query-by-query testing handoff, permission gates and approval requirements.
