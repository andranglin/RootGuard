# Advanced Case: Windows Remote Execution and Privileged Lateral Movement

**Intended audience:** Experienced SOC/DFIR analysts, incident leads and detection engineers.  
**Data:** 72 entirely fictional, deliberately simplified multi-source event records.  
**Assessment level:** Analytical reasoning and evidence management, not demonstration of a verified intrusion.  
**Caution:** Synthetic correlations and missing fields are intentional. A correlation ID does not prove causality.

## Operational situation

At 10:00 UTC the SOC receives multiple related signals. Security leadership requests an initial impact assessment in 30 minutes and a defensible containment recommendation. The incident response team must distinguish corroborated findings from incomplete event records and normal operations. Work only with the supplied evidence; do not fabricate missing log content.

## Evidence and data dictionary

[Download extended evidence (CSV)](extended-evidence.csv)

| Field | Meaning | Analytical caution |
| --- | --- | --- |
| event_id | Stable row reference for citations | Synthetic identifier |
| time_utc | Claimed UTC event time | No ingestion timestamp or measured clock drift |
| source | Simplified collection family | Not a production vendor schema |
| asset / target | Reported workload or endpoint | Can represent different entity types |
| identity | Principal in event | Does not necessarily identify human operator |
| source_ip | Source address | NAT/proxy/shared host ambiguity |
| activity / outcome | Normalised action and outcome | Outcome does not prove a successful session or execution |
| correlation_id | Exercise grouping | Not a validated cross-product correlation key |
| reliability | Data quality flag | Partial events need corroboration |

## Investigation brief

Produce an analyst-ready incident report, rather than a narrative of every row. The deliverables must include:

1. **Evidence inventory:** table of sources, time coverage, missing fields, provenance limitations and potentially relevant artifacts.
2. **Chronology:** 12–20 *selected* events with IDs, UTC time, confidence and causal claims clearly distinguished from time proximity.
3. **Entity graph:** identities, assets, IP addresses and cross-source links; mark ambiguous links.
4. **Competing hypotheses:** malicious compromise, authorised operations and technical failure or unrelated coincident events. Identify what would falsify each.
5. **Scope:** confirmed, suspected and excluded users/hosts/data, with an explicit uncertainty register.
6. **Containment decision:** action, business impact, approval authority, evidence consequences, rollback and validation.
7. **Detection improvement:** hypothesis and pseudocode/KQL outline with source fields, tests, false positives and collection prerequisites.
8. **Recovery and reporting:** minimum evidence for declaring containment effective and criteria for returning affected assets to service.

## Investigation workflow

### Phase A: Initial triage
Determine critical assets, blast-radius concerns, and whether emergency containment should precede acquisition. Record incident ownership and a timed decision log.

### Phase B: Evidence normalisation
Check duplicates, parse timestamps, build cross-source references, and record all assumptions about event IDs, identity normalisation, host names and addresses. Reject false precision.

### Phase C: Deep-dive investigation
Pivot by identity, source, asset and time. For each candidate chain, cite specific rows and list independent corroboration required (original message headers, authentication detail, endpoint process tree, host-side events, cloud audit, or change records).

### Phase D: Response planning
Choose proportionate containment while preserving evidence. Explain why password rotation, session revocation, endpoint isolation or service restrictions may have different consequences.

### Phase E: Findings and peer review
Write an executive summary (maximum 200 words), detailed findings with confidence, and a technical appendix mapping every conclusion to event references.

## Analyst worksheet

| Question | Evidence references | Confirmed / inferred / unknown | Further validation |
| --- | --- | --- | --- |
| What triggered the response? | | | |
| What are the strongest correlated observations? | | | |
| Which activity could be benign? | | | |
| Where is telemetry missing or contradictory? | | | |
| What is the earliest supported suspicious action? | | | |
| Is identity or host compromise established? | | | |
| Which controls should change immediately? | | | |
| What evidence would close this case? | | | |

## Marking rubric (100 points)

| Criterion | Points |
| --- | ---: |
| Evidence traceability and correct citations | 20 |
| Temporal, identity and asset correlation | 20 |
| Hypothesis testing and treatment of uncertainty | 20 |
| Containment decisions and operational trade-offs | 15 |
| Detection logic and false-positive assessment | 15 |
| Clear report and handover | 10 |

**Critical fail:** Claiming confirmed attacker activity, exfiltration, or attribution from the synthetic data alone without sufficient evidence.

## Instructor guidance and intended findings

The dataset is deliberately insufficient to prove a complete attacker chain. The correct outcome is a bounded investigation, prioritised follow-up requests and a defensible response decision. Repeated records are **not** independent proof; correlated source names do not necessarily describe the same real event. Look at LM-023 (service-path observation), and explain why network logon plus service creation still needs binary and change-control verification.

### Evaluation notes
Full-credit answers cite concrete row IDs, discuss synthetic telemetry's shortcomings, avoid calling a sign-in result or RPC session definitive proof of compromise, and recommend specific next records with an owner and timeframe.

## Professional extension exercise

Design a realistic collection plan using Defender for Endpoint, Windows Security/System, PowerShell operational logs, Sysmon if deployed, AD sign-ins and change-management records. Explain telemetry prerequisites, privacy handling, event retention, time sync, evidentiary integrity and how the raw fields differ from this exercise.

[Back to investigation cases](../README.md)
