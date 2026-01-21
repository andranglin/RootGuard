---
cover: ../../../.gitbook/assets/image.jpg
coverY: 0
layout:
  width: default
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Runbooks

While Playbooks cover the high-level strategy (the "Who, What, and Why"), Runbooks focus on the low-level execution (the "How"). The Runbooks included emphasise technical specificity, command-line precision, and automation.

### Cybersecurity Incident Response Runbooks

Precise and technically validated cybersecurity Runbooks are the operational engine of an organisation’s defence, bridging the gap between high-level strategy and technical execution. Unlike broad playbooks, runbooks act as granular, step-by-step checklists that prescribe the exact commands, scripts, and API calls required to neutralise threats. They ensure that complex tasks—such as querying SIEM logs (e.g., KQL for Sentinel or SPL for Splunk), dumping memory for forensic analysis, or isolating a host via EDR—are executed consistently, regardless of which analyst is on duty.

In modern Security Operations Centres (SOCs), effective runbooks have evolved from static PDF documents into "Runbooks as Code". They are increasingly integrated directly into SOAR (Security Orchestration, Automation, and Response) platforms to automate repetitive tasks. For example, a runbook for "Phishing Triage" should not merely suggest "analysing headers" but should automatically parse the email, check the sender's reputation against threat intelligence feeds, and purge malicious emails from user inboxes via API without human intervention. This shift reduces "Time to Acknowledge" (TTA) and eliminates the fatigue associated with manual data entry.

Testing runbooks requires a different approach than strategic tabletops. It demands technical validation and atomic testing. Organisations must regularly execute individual runbook modules against simulated attacks (e.g., using Breach and Attack Simulation tools) to ensure that specific scripts (e.g., PowerShell cleanup commands or firewall block requests) function correctly in the current environment. If a runbook relies on a legacy CLI command or a broken API token, the response fails. Therefore, runbooks must be treated as living software: version-controlled, constantly debugged, and updated weekly to reflect new Indicators of Compromise (IOCs) and changing infrastructure. This technical rigour ensures that when an incident occurs, the response is not just a plan but a precise, executable countermeasure.

***

#### Key Differences: Playbook vs. Runbook

<table data-header-hidden><thead><tr><th width="166"></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Feature</strong></td><td><strong>Playbook (Strategy)</strong></td><td><strong>Runbook (Execution)</strong></td></tr><tr><td>Focus</td><td>Coordination, Decision Making, Communication</td><td>Technical Tasks, Specific Commands, Triage</td></tr><tr><td>Audience</td><td>Incident Commanders, Legal, C-Suite, PR</td><td>SOC Analysts, Threat Hunters, Engineers</td></tr><tr><td>Example Content</td><td>"Determine if breach is material; Notify Legal"</td><td><code>isolate-endpoint -id &#x3C;host_id></code> or <code>Get-MessageTrace</code></td></tr><tr><td>Format</td><td>Flowcharts, Decision Trees, PDF Guides</td><td>Code Snippets, Jupyter Notebooks, SOAR Workflows</td></tr><tr><td>Metric</td><td>Time to Decision (TTD)</td><td>Mean Time to Remediate (MTTR)</td></tr></tbody></table>

#### Example Runbook Modules

1\. Automated Host Isolation (SOAR-Ready)

* Trigger: EDR High Severity Alert (Ransomware behaviour).
* Step 1 (Auto): API call to EDR to isolate Host ID.
* Step 2 (Auto): Snapshot memory and tag for "Forensic Preservation."
* Step 3 (Manual): The Analyst reviews `netstat` and `process list` output pushed to the ticket.

2\. Suspicious Login Investigation (Identity)

* Query: Run KQL to find `SigninLogs` where `Location` != `UserHomeCountry`.
* Action: If impossible travel detected (>500 miles in <1 hour), trigger "Revoke Session Token" script in Entra ID/Okta.
* Validation: Ping user via Out-of-Band (OOB) verified push notification to confirm identity.
