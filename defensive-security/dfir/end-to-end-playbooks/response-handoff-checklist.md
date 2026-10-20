# Incident Response: Analyst-to-Response Handoff

**Purpose:** Turn investigation findings into an accountable response decision. Use with the phishing, ransomware, credential-theft and lateral-movement playbooks.

## Before assigning containment

| Required detail | Analyst record |
| --- | --- |
| Incident ID, severity and decision owner | |
| Business service and asset criticality | |
| Trigger event and independent corroboration | |
| Affected identities, devices and services | |
| Evidence preserved and retention gaps | |
| Current attacker activity or harm | |
| Competing benign or technical explanations | |
| Proposed action and intended outcome | |
| Change approval and execution owner | |
| Dependencies, operational impact and rollback | |
| Verification query/check, accountable reviewer | |

## Escalation decisions

1. **Ongoing material harm:** Escalate to incident command for urgent containment. Evidence collection must not create avoidable ongoing risk.
2. **Likely compromise with incomplete scope:** Restrict the minimum proven exposure first, preserve evidence, and keep investigating related identities and infrastructure.
3. **Ambiguous activity:** Validate change records and independent signals before making disruptive changes unless risks demand emergency action.
4. **Unreliable telemetry:** Document data quality and request missing sources; do not treat an empty query as confirmation of safety.

## Verification and closure

Record the exact action, approver, target object, execution timestamp, technical outcome and business impact. Repeat scoped detection/telemetry checks at an appropriate interval, verify services, and document unresolved risks. Obtain acceptance from the incident commander and business owner where required.

**Validation:** Decision framework only; not a substitute for approved emergency procedures.
