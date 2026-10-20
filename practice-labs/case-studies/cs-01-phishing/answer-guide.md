# CS-01: Expected Findings and Answer Guide

**Teaching purpose:** Assess whether an analyst distinguishes evidence, inference and unknowns.

| Time (UTC) | Events | Intended observation |
| --- | --- | --- |
| 08:41–08:42 | P01–P02 | Two recipients received the campaign email |
| 08:45 | P03 | Maria has a recorded URL click |
| 08:46–08:48 | P04–P05 | Invalid-password result followed by successful result for Maria from `198.51.100.77` |
| 08:51 | P06 | A mailbox rule was created, potentially indicating unauthorised configuration |
| 08:53 | P07 | Ben's separate successful sign-in is not proof of compromise |
| 09:03 | P08 | Security notification provides context, not attack evidence |

## Intended interpretation

The sequence **supports suspicion of phishing-associated account misuse**, but does not independently prove the sign-in belongs to an attacker, that MFA was completed, or that mailbox data was exfiltrated. The rule is described as filing invoice-related messages into an archive folder; it is **not** evidence of external mail forwarding.

## Next evidence

Review full authentication details, conditional access/device context, mailbox rule parameters, mailbox audit and message trace, service-side session evidence and endpoint/browser activity. Confirm whether any message content was accessed or transferred.

## Reasonable response

Escalate the case for identity and mailbox investigation. With appropriate authorisation, restrict account access, revoke relevant sessions and remove confirmed unauthorised rules after preserving evidence. Confirm the affected user and assess business impact.

## Common mistakes

- Treating an Entra result code `0` as proof of a fully trusted session.
- Assuming the presence of a rule means data was exported.
- Treating all users who received an email as compromised.
- Inferring that a source IP identifies a unique individual.

**Suggested confidence:** Moderate suspicion based on correlated synthetic observations; compromise remains unconfirmed without corroboration.
