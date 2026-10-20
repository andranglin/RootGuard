# Core DFIR Runbooks: Execution and Validation Matrix

**Reviewed:** 20 October 2026  
**Scope:** Four linked runbooks. This is a static review and handoff, not lab or production certification.

## Query testing worksheet

For **each KQL block**, record: runbook and heading, code-block number, execution portal, table/connector, data availability, field names, lookback, run outcome, representative redacted output, false positives, required permissions, any corrections and date/reviewer. Never mark *validated* on appearance alone.

| Runbook | Primary sources to verify | Required checks | Status |
| --- | --- | --- | --- |
| Phishing/BEC | Defender XDR EmailEvents, EmailUrlInfo, UrlClickEvents; Entra SigninLogs/AuditLogs; Exchange mailbox audit | Query-portal boundaries; NetworkMessageId pivots; mailbox rule scope; auditing and licence constraints | Awaiting tenant KQL testing |
| Identity | Sentinel SigninLogs, AuditLogs, SecurityEvent; Graph directory audit | Entra sign-in result semantics, TargetResources dynamic fields, AD event collection and raw event semantics | Awaiting tenant KQL testing |
| Ransomware | Defender XDR DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents; AD/backup telemetry | Defender portal versus Log Analytics; FileEvents ActionType; backup and host evidence; time boundaries | Awaiting tenant KQL testing |
| Lateral movement | Defender XDR DeviceLogonEvents, DeviceProcessEvents, DeviceNetworkEvents; Windows Event 4624/7045 | Source-target identity correlation, LogonType variants, network/RPC limitations, endpoint coverage | Awaiting tenant KQL testing |

## Safe command review and approval gate

| Procedure class | Allowed initial response | Conditional change | Evidence and post-action checks |
| --- | --- | --- | --- |
| Mailbox and transport | Export current rules, forwarding configuration, audit operations and message evidence | Targeted removal of confirmed unauthorised rule/forward only | Before/after configuration, message access review, user impact |
| Entra identity | Read sign-in logs, credentials/auth methods, app grants, role assignments | Approved account restriction, session revocation, credential rotation | Confirm exact object ID/tenant, CA/session caveats, sign-in review |
| AD identity | Review directory identity/group membership, DC logs and attack scope | Approved disable/reset for specific verified identities | Dependencies, privileged/service identity impact, DC replication state |
| GPO | Review linked policies, version, owner and change metadata | Change board/incident command handles scoped disable or removal | Backups, policy link and inheritance impact, rollback and verification |
| Endpoint isolation | EDR device identity and status investigation | Approved isolation using product console/API | EDR reachability, business impact, method and rollback |
| Domain recovery | Preserve compromised key-material evidence, engage specialist | Staged krbtgt recovery only under documented AD recovery plan | Replication health, ticket lifetimes, dependencies and rollback |

## Non-negotiable operational limits

- Do not generate or print plaintext temporary passwords in runbooks.
- Do not bulk-disable accounts, reset all privileged accounts, or require password change for all users from a generic runbook.
- Do not bulk-delete mailbox rules, GPOs or service objects without individually supported findings and approvals.
- Do not infer that disabling accounts or revoking sign-in sessions invalidates every existing access token immediately.
- Do not infer human attribution solely from source IP, account identity or event proximity.
- Check Microsoft Graph module availability, correct delegated/application permissions and RBAC role, and consent before use.
- For command execution, record incident approval, principal, exact target ID, dry-run availability, before/after evidence, errors and outcome.

## Evidence review statuses

**Static safety reviewed** means risky example scripts have been restricted and prerequisite guidance documented. **Syntax checked** means the command/query was run in the correct environment. **Lab validated** requires reproducible positive/negative test cases. **Production validated** requires authorised test results and monitored outcomes in the target environment.

**Current classification:** The four runbooks remain **static safety reviewed; KQL and command validation pending**. Do not infer that every remaining read-only command or KQL is correct.

## Reviewer handoff

For each command or query, report:

| Reference | Portal / tool & version | Prerequisites | Result | False positives / error | Decision |
| --- | --- | --- | --- | --- | --- |
| Runbook + section + snippet | | | Pass / Fail / Not run | | Approve / Fix / Remove |

Track issues in the same PR or a follow-up issue, including redacted logs and tested replacement code. Personal, customer and production secrets must not be committed to this public repository.
