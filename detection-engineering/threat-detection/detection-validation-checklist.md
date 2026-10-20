# Detection Engineering Validation Checklist

Use this checklist before publishing a query as a production-ready Microsoft Sentinel or Microsoft Defender XDR detection.

## 1. Establish the detection hypothesis

- [ ] Describe the adversary behaviour and the expected observable evidence.
- [ ] Map the behaviour to the relevant MITRE ATT&CK technique, without treating ATT&CK coverage as proof that the detection works.
- [ ] Define what constitutes a true positive, benign positive and false positive.

## 2. Verify telemetry and schema

- [ ] Identify the exact source product and table (for example `SecurityEvent`, `WindowsEvent`, `SigninLogs` or `DeviceProcessEvents`).
- [ ] Confirm the required connectors, audit policies, permissions and ingestion are enabled.
- [ ] Inspect actual sample records to verify field names, types, casing, and null behaviour.
- [ ] Do not assume Microsoft Sentinel and Defender XDR share identical tables or column availability.
- [ ] Distinguish Windows event status/result codes from pre-authentication types and ticket encryption types.

## 3. Validate logic

- [ ] Run the query successfully against the intended workspace.
- [ ] Check join keys, time-window bounds, aggregations, exclusions and handling of missing data.
- [ ] Verify that thresholds are based on the local activity baseline, not arbitrary constants.
- [ ] Preserve enough event context for analysts to validate findings.
- [ ] Document expected false positives and known blind spots.

## 4. Test and operationalise

- [ ] Where authorised, generate representative test activity and record observed telemetry.
- [ ] Confirm detection of the test without implying that one successful test proves complete coverage.
- [ ] Test benign activity and evaluate alert volume.
- [ ] Document response actions, ownership, severity, review frequency and rollback.
- [ ] Record the last validation date, source versions and any environment-specific assumptions.

## 5. Publication status

Use one of these labels on technical examples:

- **Concept / unvalidated:** Illustrative logic; not tested against a specific tenant.
- **Syntax checked:** The query parses, but detection behaviour is not independently verified.
- **Lab validated:** Behaviour demonstrated in a defined test environment.
- **Production validated:** Tested with approved telemetry and reviewed for operational use.

Do not label a rule production validated without recorded evidence.

## Reference

- [Microsoft Windows Security Event 4768 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768): event semantics, result codes and pre-authentication types.
