# SOC Detection Engineer

The practice of designing, building, and maintaining detection logic that identifies threats in your environment—turning threat intelligence into actionable alerts.

***

### What is Detection Engineering?

Detection Engineering bridges the gap between knowing a threat exists and actually detecting it. It's the systematic process of translating adversary behaviours, TTPs, and indicators into detection rules that generate high-fidelity alerts.

| Threat Intelligence | → | Detection Logic       | → | Actionable Alert      |
| ------------------- | - | --------------------- | - | --------------------- |
| ATT\&CK technique   |   | KQL / SPL / YARA rule |   | Triageable event      |
| IOC feed            |   | Correlation rule      |   | Enriched alert        |
| IR findings         |   | Behavioural analytic  |   | Investigation trigger |

**The goal:** Detect real threats with minimal false positives, enabling analysts to focus on what matters.

***

### Why It Matters

Without detection engineering, SOCs drown in vendor-default rules that generate noise without context. Effective detection engineering delivers:

* **Coverage** — Mapped detection across MITRE ATT\&CK tactics
* **Precision** — Reduced false positives through environmental tuning
* **Context** — Alerts enriched with investigative guidance
* **Resilience** — Detections that survive adversary evasion
* **Measurability** — Quantified detection gaps and coverage metrics

***

### Core Responsibilities

#### Rule Development

Writing detection logic in KQL, SPL, Sigma, YARA, or Snort/Suricata syntax based on threat intelligence and attack patterns.

#### Tuning & Optimisation

Reducing false positives by understanding environmental baselines, excluding known-good activity, and refining thresholds.

#### Coverage Analysis

Mapping existing detections to MITRE ATT\&CK, identifying gaps, and prioritising development based on threat relevance.

#### Validation & Testing

Using atomic tests, purple team exercises, and attack simulations to verify detections fire correctly.

#### Documentation

Maintaining detection metadata: intent, data sources, false positive guidance, and response procedures.

***

### The Detection Lifecycle

```bash
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Research   │ →  │   Develop   │ →  │   Validate  │ →  │   Deploy    │
│             │    │             │    │             │    │             │
│ Threat intel│    │ Write logic │    │ Test against│    │ Production  │
│ ATT&CK TTPs │    │ Tune for env│    │ atomic tests│    │ monitoring  │
│ IR findings │    │ Add context │    │ Purple team │    │ Feedback    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                               │
                         ┌─────────────┐                       │
                         │   Maintain  │ ←─────────────────────┘
                         │             │
                         │ Review FPs  │
                         │ Update logic│
                         │ Retire stale│
                         └─────────────┘
```

***

### Detection Types

<table><thead><tr><th width="134">Type</th><th width="243">Description</th><th>Example</th></tr></thead><tbody><tr><td><strong>Signature</strong></td><td>Known-bad indicators</td><td>Hash, IP, domain blocklist</td></tr><tr><td><strong>Behavioural</strong></td><td>Suspicious activity patterns</td><td>LSASS access from unusual process</td></tr><tr><td><strong>Anomaly</strong></td><td>Deviation from baseline</td><td>First-time PowerShell execution by user</td></tr><tr><td><strong>Correlation</strong></td><td>Multiple events combined</td><td>Failed logins + successful auth + data access</td></tr><tr><td><strong>Threshold</strong></td><td>Volume-based triggers</td><td>>10 failed logins in 5 minutes</td></tr></tbody></table>

**Best practice:** Layer detection types—signatures catch known threats, behavioural catches novel attacks.

***

### Key Frameworks & Tools

<table><thead><tr><th width="233">Category</th><th>Tools</th></tr></thead><tbody><tr><td>Detection Language</td><td>KQL, SPL, Sigma, YARA, Snort/Suricata</td></tr><tr><td>SIEM/XDR</td><td>Sentinel, Defender XDR, Splunk, Elastic</td></tr><tr><td>Testing</td><td>Atomic Red Team, MITRE Caldera, Stratus Red Team</td></tr><tr><td>Coverage Mapping</td><td>DeTT&#x26;CT, ATT&#x26;CK Navigator</td></tr><tr><td>Rule Repos</td><td>Sigma HQ, Elastic Detection Rules, Azure Sentinel</td></tr></tbody></table>

***

### From SOC Analyst to Detection Engineer

Detection engineering is a natural progression for analysts who want to move from reactive alert handling to proactive defence.

**Skills to develop:**

* **Query languages** — KQL, SPL, or your platform's syntax
* **Log source knowledge** — Understanding what telemetry exists and what it captures
* **ATT\&CK fluency** — Mapping techniques to data sources and detection opportunities
* **Scripting** — Python/PowerShell for automation and validation
* **Adversary mindset** — Thinking like an attacker to anticipate evasion

\{% hint style="info" %\} **Start here:** Take alerts you've triaged, identify the detection logic behind them, and propose improvements based on false positive patterns or missed context. \{% endhint %\}

***

### Measuring Success

| Metric                      | What It Tells You               |
| --------------------------- | ------------------------------- |
| MITRE coverage %            | Gaps in detection capability    |
| Mean time to detect (MTTD)  | Speed of threat identification  |
| False positive rate         | Rule precision and tuning needs |
| Detection-to-incident ratio | Signal quality                  |
| Rule validation pass rate   | Detection reliability           |

***

### Quick Wins

1. **Document FP patterns** — Track why alerts are closed as false positives; feed back into tuning
2. **Build a Sigma library** — Platform-agnostic rules you can take anywhere
3. **Map one tactic** — Pick a MITRE tactic, audit coverage, build detections for gaps
4. **Automate validation** — Schedule atomic tests against your detection rules
5. **Create runbooks** — Pair every detection with analyst response guidance

***

_Detection engineering transforms SOC operations from alert-driven chaos to intelligence-led defence._
