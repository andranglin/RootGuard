# Case Study 01: Phishing and Identity Compromise

**Scenario:** An employee reports a suspicious document-sharing email. Investigate whether a click occurred, whether a sign-in followed, and whether mailbox persistence was established.

**Estimated level:** Intermediate. **Scope:** Microsoft 365-style email, identity and mailbox events. All event records are synthetic, with simplified schemas.

## Files

- [Download evidence.csv](evidence.csv) (select **Raw** on GitHub to save the CSV)
- [Analyst worksheet](worksheet.md)
- [Expected findings and answer guide](answer-guide.md) (read after completing the worksheet)

## Method

Sort evidence by `time_utc`, identify all events affecting `maria@example.invalid`, and construct an explanation supported by explicit event IDs. Distinguish message delivery, clicking a link, a reported sign-in and mailbox rule creation. This fictional exercise does not establish that an authentication token was issued or that any message was exfiltrated.

Related: [Phishing compromise investigation playbook](../../../defensive-security/dfir/end-to-end-playbooks/phishing-compromise.md).
