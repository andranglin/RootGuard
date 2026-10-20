# [Investigation or Procedure Title]

**Purpose:** What problem does this page solve?  
**Audience:** Analyst level and specialist roles.  
**Environment:** Product/OS and minimum versions where known.  
**Required telemetry:** Specific source tables or logs.  
**Permissions:** Read permissions versus state-changing roles.  
**Review date:** YYYY-MM-DD.  
**Validation:** Concept / unvalidated until tested.

## Before you begin

- Confirm authority, incident ID, business impact and evidence handling requirements.
- Check that telemetry, retention, permissions and execution environment are available.
- Identify whether this guide contains state-changing operations.

## 1. Initial assessment

**Objective:** State the precise decision to be made.

Describe the first read-only investigative step and expected evidence.

## 2. Investigation query or command

```kusto
// Example only. Replace with reviewed query and specify the execution portal.
```

**Expected observations:** What a positive and negative result means.  
**False positives:** Legitimate sources of similar results.  
**Limitations:** Data coverage and semantics.

## 3. Correlation and decision

Record supporting evidence from independent sources, competing hypotheses and confidence.

## 4. Response procedure

Document approver, target ID, permissions, risk, preservation requirements, rollback options and verification. Do not include mass-changing commands in an unvalidated template.

## 5. Recovery and exit criteria

State what must be verified, by whom, and which conditions permit closure.

## Related references

- Link relevant RootGuard material and authoritative product documentation.
