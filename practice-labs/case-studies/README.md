# Downloadable Investigation Case Studies

These case studies contain **fictional evidence** created for defensive training. IP addresses use documentation-only ranges and accounts use the reserved `example.invalid` domain. They are not evidence from actual incidents.

## Choose a case

| Case | Evidence | Analyst tasks |
| --- | --- | --- |
| [CS-01: Phishing and identity compromise](cs-01-phishing/README.md) | Email deliveries, URL clicks, sign-ins and mailbox audit | Link evidence across sources; distinguish attempted from confirmed access |
| [CS-02: Windows lateral movement](cs-02-lateral-movement/README.md) | Logons, processes, remote service and network records | Build a host-to-host timeline and evaluate alternative explanations |

Each case provides a CSV evidence file, an analyst worksheet and an **answer guide containing the intended findings and evidence references**. Attempt the worksheet before reading its solution. CSV datasets are downloadable through GitHub's **Raw** or **Download raw file** control, and can be opened in Excel, pandas or another CSV reader.

## Investigation standards

1. Work from the provided evidence, identifying source and event IDs.
2. Record observed facts separately from hypotheses and conclusions.
3. Note collection gaps: absence of a row in a synthetic dataset is not evidence of absence in a real environment.
4. Assess confidence, impact and proportionate containment.
5. Do not attempt live phishing, credential testing or remote execution to complete these exercises.

**Validation:** Dataset narratives are internally authored teaching exercises, not external forensic ground truth or production-validated detections.
