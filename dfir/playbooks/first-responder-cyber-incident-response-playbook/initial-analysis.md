---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Initial Analysis

### Section 6:&#x20;

6.1 Threat Identification

* MDE: KQL: DeviceProcessEvents | where FileName == "svch0st.exe"
* Cyber Triage: CyberTriage.exe --analyze --input E:\Evidence\kape\_output

6.2 Persistence Detection

* Autoruns: autoruns.exe -a E:\Evidence\autoruns.ar

6.3 Network Analysis

* Wireshark: wireshark -r E:\Evidence\network.pcap -Y "ip.addr == 203.0.113.5"
