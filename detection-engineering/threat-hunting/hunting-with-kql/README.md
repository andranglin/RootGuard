---
cover: ../../../.gitbook/assets/Screenshot 2025-01-10 080534.png
coverY: 0
---

# Hunting With KQL

## **Introduction**

Threat hunting with KQL (Kusto Query Language) involves leveraging KQL's powerful data querying and filtering capabilities to identify potential security gaps and detect adversarial activities. KQL is widely used in platforms like Microsoft Sentinel, where it enables security analysts to query massive datasets from logs, events, and telemetry. By crafting custom queries, analysts can proactively search for indicators of compromise (IOCs), such as unauthorised access attempts, lateral movement, privilege escalation, or data exfiltration. The language's flexibility allows for precise filtering of log data, making it easier to uncover hidden threats and anomalies indicative of system violations.

KQL integrates seamlessly with security frameworks like MITRE ATT\&CK, enabling analysts to map detected behaviours to known adversarial tactics, techniques, and procedures (TTPs). Through features like joins, unions, and regex filtering, KQL supports complex threat-hunting workflows, such as correlating identity logs with network activity to detect suspicious patterns. Its time-series analysis capabilities help uncover trends in user behaviour, privilege usage, and system changes, which are critical for identifying adversary activities. With its efficiency and integration into tools like Microsoft Defender and Sentinel, KQL empowers security teams to strengthen their OPSEC posture, reduce response times, and mitigate the risk of advanced threats.

The following is a set of KQL queries that can be used to detect and analyse malicious or suspicious activities in your environment. The queries are designed to quickly grab the necessary information that will allow the investigator to determine whether the activity warrants deeper analysis or escalation.

**Note: Sometimes, you may have to customise the queries to your environment. Also, queries will only work if the data is available.**

### Jump In

Explore the respective sections to learn more about the KQL queries that can assist in your investigations. The guides provide a structured approach to threat hunting in a Windows enterprise environment, leveraging **Microsoft Defender XDR** and focusing on key areas of the **MITRE ATT\&CK Framework**. It covers:

* [**Detecting Malware Infection**](detecting-malware-infection-mitre-att-and-ck-t1566-t1059.md)
* [**Discovery Activities**](../../../soc-operations/intermediate-and-advanced-skills/investigate-using-mitre-att-and-ck-methodology/discovery-ta0007-techniques.md)
* [**Credential Theft**](credential-theft-mitre-att-and-ck-t1003-t1078.md)
* [**Lateral Movement**](lateral-movement-mitre-att-and-ck-t1076-t1021.md)
* [**Data Theft**](data-theft-mitre-att-and-ck-t1041-t1071.md)
* [**Detecting CommandLine Executions**](detecting-commandline-executions-mitre-att-and-ck-t1059.md)
* [**Windows Security Logs (Identity and Logon Activities)**](windows-security-logs-identity-and-logon-activities.md)

By regularly performing these searches, security teams can proactively detect and respond to emerging threats, mitigating potential damage before attackers escalate their activities.
