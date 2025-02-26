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

# Evidence Collection

Efficient tools and capabilities for Digital Forensics and Incident Response (DFIR) evidence collection are critical in today’s fast-evolving cyber threat landscape, where time is often the deciding factor in mitigating damage and preserving evidence. When a security incident occurs—be it a ransomware attack, data breach, or insider threat—the window to collect volatile data, such as running processes, network connections, or memory contents, can close within minutes as systems are powered off or adversaries cover their tracks. Tools like KAPE, Velociraptor, and FTK Imager enable responders to rapidly acquire triage data or full forensic images, ensuring that ephemeral evidence isn’t lost.&#x20;

This speed accelerates the identification of attack vectors and compromised assets and supports timely containment, reducing the potential for prolonged downtime, financial loss, or reputational harm. Beyond speed, efficiency in DFIR tools enhances the accuracy and reliability of evidence collection, which is foundational for both technical resolution and legal admissibility. Modern tools are designed to minimise system impact while maximising data integrity—features like write-blocking, hash verification (e.g., MD5/SHA1 in FTK Imager), and structured output formats (e.g., JSONL in Velociraptor) ensure that collected evidence remains unaltered and defensible in court. Inefficient or manual methods, such as relying solely on native OS commands, risk missing critical artefacts, introducing errors, or failing to meet chain-of-custody standards. Efficient tools automate repetitive tasks, reduce human error, and provide comprehensive coverage—capturing everything from registry hives to unallocated disk space—enabling analysts to confidently build a complete picture of the incident.&#x20;

Robust DFIR capabilities foster organisational resilience and preparedness, aligning technical responses with business and regulatory demands. Efficient tools allow teams to scale evidence collection across multiple endpoints, whether for a single compromised laptop or a network-wide breach, without overwhelming limited resources. This scalability is vital for meeting compliance requirements (e.g., GDPR, HIPAA) that mandate rapid incident reporting and evidence preservation. Moreover, streamlined workflows—such as KAPE’s triage collections or PowerShell’s scripted automation—empower even smaller teams to handle complex investigations, freeing them to focus on analysis and remediation rather than collection logistics. Investing in efficient DFIR tools transforms evidence collection from a bottleneck into a strategic advantage, strengthening an organisation’s ability to respond, recover, and defend against future threats.

The following page of this playbook provides some guidance for conducting DFIR in a Windows environment.

[Acquire Triage Image Using Kape](acquire-triage-image-using-kape.md)

[Acquire Triage Data Using Velociraptor](acquire-triage-data-using-velociraptor.md)

[Acquire Triage Data Using PowerShell](acquire-triage-data-using-powershell.md)

[Acquire Triage Memory Image](acquire-triage-memory-image.md)

[Acquire Image Using FTK](acquire-image-using-ftk.md)
