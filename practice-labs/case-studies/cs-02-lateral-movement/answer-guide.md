# CS-02: Expected Findings and Answer Guide

## Evidence-backed sequence

| Stage | Evidence IDs | Supported observation |
| --- | --- | --- |
| WS-22 remote management | L01–L02 | `wmic.exe` process and RPC connection toward SRV-04 |
| Server authentication | L03 | Network logon recorded on SRV-04 for helpdesk identity |
| Service creation/execution | L04–L05 | Service installation record followed by a service-launched executable |
| Activity toward DC | L06–L07 | DC-01 logon and an SMB connection from SRV-04; no DC code execution is demonstrated |
| Change context | L08 | Maintenance window exists, but no matching service installation record is provided |

## Interpretation

The ordered observations make lateral movement a **reasonable hypothesis**, not a confirmed malicious campaign. A legitimate but undocumented maintenance action is a plausible alternative; L08 does not validate the service as approved.

The synthetic records do not include full command lines, file hashes, service binary provenance, authenticated change approvals, endpoint alerts or complete domain controller logs.

## Further evidence to request

Change ticket and operator confirmation; service configuration and binary hash/signature; process tree and remote WMI evidence; credential and privileged group review; logon session IDs and target-side process audit; EDR alerts; domain controller and file-share audit details.

## Suggested response

Escalate the service installation and privileged cross-host access, preserve WS-22/SRV-04/DC-01 telemetry and verify the helpdesk account. If malicious execution is supported, coordinate isolation and access restriction using the incident-response process. Do not assume DC-01 was compromised solely because a network connection was observed.

## Assessment rubric

A strong analyst submission cites L01–L08 where relevant, differentiates authentication from execution, addresses the maintenance alternative, describes evidence limitations and makes a proportionate containment recommendation.
