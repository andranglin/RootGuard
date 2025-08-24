---
description: Pre-Engagement Phase in Penetration Testing
---

# Pre-Engagement

### Pre-Engagement Phase in Penetration Testing

The Pre-Engagement phase is the foundational step in the penetration testing process, setting the stage for a structured, ethical, and effective assessment. During this phase, the penetration testing team collaborates with the client to establish clear objectives, define the scope, and formalise agreements that ensure legal and operational alignment. This preparatory stage is critical to avoid misunderstandings, mitigate risks, and ensure the test delivers actionable results tailored to the client’s needs.

The Pre-Engagement phase encompasses three key components:

1. **Scoping Survey**
2. **Pre-Engagement Consultation**
3. **Kick-Off Session**

Before diving into these components, all parties must sign a Non-Disclosure Agreement (NDA) to safeguard sensitive information. This section explores each component, the necessary documentation, and critical considerations to ensure a successful penetration test.

### Non-Disclosure Agreement (NDA)

An NDA is a prerequisite for any discussions or activities in the penetration testing process. It establishes confidentiality obligations to protect both the client’s sensitive data and the testing team’s methodologies.&#x20;

The type of NDA depends on the engagement’s structure:

* **Unilateral NDA:** One party (typically the penetration testing team) is obligated to maintain confidentiality, while the client may share information with third parties as needed.
* **Bilateral NDA:** Both the client and the testing team agree to keep all project-related information confidential. This is the most common NDA for penetration testing, ensuring mutual protection.
* **Multilateral NDA:** Used when multiple parties, such as third-party service providers or partner organisations, are involved in the test. All parties must commit to confidentiality.

The NDA must be signed before detailed discussions occur to prevent unauthorised disclosure of sensitive information. In urgent scenarios, the process may skip directly to the Kick-Off Session, often conducted virtually, but the NDA remains non-negotiable.

### Authorised Stakeholders

A critical aspect of the Pre-Engagement phase is verifying the authority of the individual or team commissioning the penetration test. Unauthorised requests, such as those from employees without proper approval, can lead to legal and ethical complications. For example, an employee might hire a testing team under the guise of a security check but intend to misuse the results to harm the organisation. To mitigate this risk, the testing team must confirm that the requester has the authority to initiate the test. Typical roles with signatory authority include:

* **C-Level Executives:** Chief Executive Officer (CEO), Chief Information Officer (CIO), Chief Information Security Officer (CISO), Chief Technology Officer (CTO), or Chief Risk Officer (CRO).
* **Senior Management:** Vice President of IT, Director of Information Security, or Internal Audit Manager.
* **Specialised Roles**: IT Security Manager, Compliance Officer, or Network Operations Lead, depending on the organisation’s structure.

In larger organisations, C-level executives may delegate authority to senior IT or security personnel. The testing team must identify primary and secondary points of contact, technical support staff, and escalation contacts for critical issues, ensuring clear communication throughout the engagement.

### Key Documentation

The Pre-Engagement phase involves preparing and signing several documents to formalise the engagement and ensure legal compliance. These documents provide a clear framework for the test and protect all parties from potential legal issues, such as violations of the Computer Misuse Act. The required documents include:

| **Document**                                           | **Purpose**                                                                     | **Timing**                                          |
| ------------------------------------------------------ | ------------------------------------------------------------------------------- | --------------------------------------------------- |
| Non-Disclosure Agreement (NDA)                         | Ensures confidentiality of all project-related information.                     | After initial contact, before detailed discussions. |
| Scoping Survey                                         | Collects detailed information about the client’s testing needs and environment. | Before the Pre-Engagement Consultation.             |
| Scoping Document                                       | Summarizes the scope based on the survey and consultation.                      | During the Pre-Engagement Consultation.             |
| Penetration Testing Agreement (Contract/Scope of Work) | Formalizes the test objectives, scope, and deliverables.                        | During the Pre-Engagement Consultation.             |
| Rules of Engagement (RoE)                              | Defines testing boundaries, methodologies, and communication protocols.         | Before the Kick-Off Session.                        |
| Physical Testing Agreement                             | Outlines permissions and protocols for physical security assessments.           | Before the Kick-Off Session (if applicable).        |
| Final Report                                           | Documents findings, vulnerabilities, and remediation recommendations.           | During and after the penetration test.              |

Note: Legal counsel should review all documents to ensure compliance with applicable laws and regulations.

### Scoping Survey

The Scoping Survey is the first step in understanding the client’s requirements and tailoring the penetration test to their needs. After initial contact, the testing team sends a detailed questionnaire to gather information about the client’s environment, objectives, and preferences. The survey helps the team assess the scope, allocate resources, and estimate costs accurately. The Scoping Survey typically includes options for the client to select from a range of services, such as:

* Internal Network Penetration Test
* External Network Penetration Test
* Web Application Security Assessment
* Mobile Application Security Assessment
* Wireless Network Security Assessment
* Social Engineering Assessment (e.g., phishing, vishing)
* Physical Security Assessment
* Red Team Engagement
* Active Directory Security Assessment
* Cloud Infrastructure Assessment

Additional questions refine the scope and clarify expectations:

* **System Details:** How many live hosts, IP ranges, domains/subdomains, or wireless SSIDs are in scope?
* **Application Testing:** For web or mobile applications, how many user roles (e.g., standard user, admin) require testing? Are credentials provided for authenticated testing?
* **Social Engineering:** For phishing assessments, how many users are targeted, and will the client provide a target list or require OSINT to compile it?
* **Physical Assessments:** How many locations are involved, and are they geographically dispersed?
* **Red Team Objectives:** Are specific activities, such as physical attacks or denial-of-service (DoS) testing, out of scope?
* **Testing Approach:** Should the test be black-box (no prior knowledge), gray-box (limited information), or white-box (full system details)? Should testing be non-evasive, partially evasive, or fully evasive to test detection capabilities?
* **Network Access:** Will testing simulate an anonymous user or a standard domain user? Is bypassing Network Access Control (NAC) required?

The survey also collects logistical details, such as the client’s name, address, and key personnel contact information. The responses inform the Scoping Document, which summarises the scope and serves as a foundation for the Penetration Testing Agreement.

### Pre-Engagement Consultation

The Pre-Engagement Consultation is a collaborative meeting, typically conducted via video conference or in person, to refine the scope and finalise the testing plan. This phase ensures that both the testing team and the client have a shared understanding of the objectives, methodologies, and constraints. For clients new to penetration testing, the consultation may include an educational component to explain the process and address concerns.

Key topics discussed during the consultation include:

* **Objectives and Goals:** Define the primary goals, such as identifying critical vulnerabilities, testing incident response, or ensuring compliance with standards like HIPAA or PCI-DSS. Break down high-level goals into specific, measurable outcomes.
* **Scope Definition:** Confirm the systems, networks, or applications to be tested, including IP ranges, domains, or physical locations. Clarify any exclusions, such as critical production systems that must remain untouched.
* **Testing Type:** Discuss the advantages and disadvantages of black-box, gray-box, or white-box testing. The testing team may recommend an approach based on the client’s goals and environment.
* **Methodologies:** Outline the frameworks to be used, such as OWASP, PTES, or NIST SP 800-115, and explain how automated and manual techniques will be combined.
* **Testing Locations:** Specify whether testing will be conducted remotely (via secure VPN) or on-site, and address any logistical requirements.
* **Timeframe:** Agree on start and end dates, as well as specific time windows for sensitive phases like exploitation or lateral movement, which may occur outside regular business hours to minimise disruption.
* **Third-Party Involvement:** Identify any third-party providers (e.g., cloud services, ISPs) whose systems are in scope and obtain written consent from them to avoid legal issues.
* **Risks and Mitigations:** Discuss potential risks, such as system downtime or user account lockouts due to brute-force attempts, and establish safeguards like backups or test environments.
* **Evasive Testing:** Determine whether the client wants the team to employ stealth techniques to bypass security controls and test detection capabilities.
* Communication Protocols: Establish lines of communication, including primary and escalation contacts, preferred channels (e.g., email, phone, secure portals), and status update frequency.
* **Reporting Preferences:** Clarify the report format, audience (e.g., technical staff vs. executives), and whether a presentation of findings is required.
* **Payment Terms:** Review costs, billing schedules, and any contractual terms.

The consultation results in the Penetration Testing Agreement (also known as the Scope of Work or Contract) and the Rules of Engagement (RoE), which formalise the agreed-upon terms.Penetration Testing Agreement Checklist

| **Checkpoint**       | **Description**                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------ |
| NDA                  | Ensures confidentiality of all project-related information, with provisions for exceptions and penalties.    |
| Objectives           | Defines high-level and granular goals for the test.                                                          |
| Scope                | Lists specific systems, IP ranges, domains, or applications to be tested, with any exclusions clearly noted. |
| Testing Type         | Specifies black-box, gray-box, or white-box approach and level of evasiveness.                               |
| Methodologies        | Details frameworks (e.g., OWASP, PTES) and techniques (e.g., manual testing, exploit development).           |
| Locations            | Clarifies whether testing is external, internal, or remote via secure VPN.                                   |
| Timeframe            | Defines start and end dates, including specific time windows for testing phases.                             |
| Third Parties        | Confirms written consent from third-party providers for testing their systems.                               |
| Risks                | Outlines potential risks (e.g., system downtime) and mitigation strategies.                                  |
| Scope Limitations    | Identifies critical systems or processes to avoid to prevent operational disruptions.                        |
| Information Handling | Specifies compliance with standards like HIPAA, PCI-DSS, or NIST for data protection.                        |
| Communication        | Lists contact details, escalation paths, and preferred communication channels.                               |
| Reporting            | Defines report structure, audience, and delivery preferences.                                                |
| Payment Terms        | Outlines costs, billing schedule, and payment conditions.                                                    |

### Rules of Engagement (RoE)

The Rules of Engagement (RoE) document is a critical agreement that defines the boundaries, methodologies, and protocols for the penetration test. It ensures that testing is conducted safely, ethically, and in alignment with the client’s expectations. The RoE is finalised before the Kick-Off Session and includes:

| **Checkpoint**       | **Contents**                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Introduction         | Overview of the RoE document’s purpose.                                                                                   |
| Contractor Details   | Name, title, and contact information of the testing organization and key personnel.                                       |
| Penetration Testers  | Names and roles of the testers involved.                                                                                  |
| Contact Information  | Client and tester contact details, including escalation contacts.                                                         |
| Purpose              | High-level purpose of the penetration test.                                                                               |
| Goals                | Specific objectives to be achieved.                                                                                       |
| Scope                | Detailed list of in-scope IPs, domains, URLs, or CIDR ranges, with an appendix for client-provided credentials or assets. |
| Communication        | Preferred channels (e.g., email, phone, secure portals) and frequency of updates.                                         |
|  Timeframe           | Start and end dates, plus specific testing windows (e.g., after-hours testing).                                           |
| Testing Type         | Black-box, gray-box, or white-box, with details on evasiveness.                                                           |
| Locations            | External, internal, or remote testing details, including VPN access.                                                      |
| Methodologies        | Frameworks and techniques to be used (e.g., OWASP, PTES, manual testing).                                                 |
| Objectives/Flags     | Specific targets, such as accessing sensitive files or compromising user accounts.                                        |
| Evidence Handling    | Protocols for secure storage and transmission of evidence (e.g., encryption).                                             |
| System Backups       | Requirements for client-side backups to mitigate risks.                                                                   |
| Information Handling | Compliance with data protection standards (e.g., HIPAA, GDPR).                                                            |
| Incident Handling    | Procedures for reporting critical vulnerabilities or pausing testing if issues arise.                                     |
| Status Meetings      | Schedule and participants for progress updates.                                                                           |
| Reporting            | Format, audience, and delivery method for the final report.                                                               |
| Retesting            | Dates and scope for verifying remediation.                                                                                |
| Disclaimers          | Limitations of liability for unintended system impacts.                                                                   |
| Permission to Test   | Signed authorization from the client and any third parties.                                                               |

### Kick-Off Session

The Kick-Off Session marks the official start of the penetration test, typically conducted in person or via video conference after all contracts are signed. Attendees include the client’s points of contact (e.g., IT, Information Security, or Audit teams), technical staff (e.g., developers, system administrators), and the penetration testing team, which may include a project manager, lead tester, and account representative.

Key activities during the Kick-Off Session include:

* **Process Overview:** Explain the penetration testing stages, from Information Gathering to Post-Engagement, ensuring all attendees understand the methodology and timeline.
* **Risk Communication:** Highlight potential risks, such as log entries triggering security alerts, user account lockouts from brute-force attempts, or system performance impacts. Emphasise that testing will pause if critical vulnerabilities (e.g., remote code execution, SQL injection) are identified, with immediate notification to the client’s emergency contacts.
* **Incident Protocols:** Clarify that testing will halt if illegal activity, prior breaches, or external threat actors are detected, with prompt reporting to the client.
* **Client Expectations:** Address any last-minute questions or concerns, tailoring explanations to the audience’s technical expertise. For non-technical stakeholders, use analogies (e.g., comparing penetration testing to a fire drill) to clarify the process.
* **Denial-of-Service (DoS) Restrictions:** Confirm that DoS attacks are typically out of scope to avoid disrupting operations, unless explicitly requested.

The session ensures alignment, builds trust, and sets a professional tone for the engagement. For clients with limited experience, the testing team may need to provide additional context or field detailed questions.

### Physical Testing Agreement

If the penetration test includes physical security assessments, a separate Physical Testing Agreement is required to address unique legal and ethical considerations. Physical tests may involve attempting to gain unauthorised access to facilities, which could lead to confrontations with employees or law enforcement if not properly authorised. This agreement serves as a safeguard, often referred to as a “get out of jail free card,” to protect testers in case of misunderstandings.

Physical Testing Agreement Checklist

| **Checkpoint**      | **Description**                                                           |
| ------------------- | ------------------------------------------------------------------------- |
| Introduction        | Purpose and scope of the physical assessment.                             |
| Contractor          | Name and details of the testing organization.                             |
| Purpose             | Objective of the physical security test.                                  |
|  Goals              | Specific outcomes, such as testing access controls or employee awareness. |
| Penetration Testers | Names and roles of testers involved in physical assessments.              |
| Contact Information | Client and tester contact details, including escalation contacts.         |
| Physical Addresses  | Locations to be tested, including building names and addresses.           |
| Floors/Rooms        | Specific areas within facilities to be assessed.                          |
| Physical Components | Systems or assets targeted (e.g., badge readers, locks).                  |
| Timeline            | Schedule for physical testing activities.                                 |
| Notarisation        | Formal validation of the agreement, if required.                          |
| Permission to Test  | Signed authorization from the client and facility management.             |

This agreement ensures that physical testing is conducted legally and ethically, with clear boundaries to protect all parties.

### Key Considerations

To ensure a successful Pre-Engagement phase, the testing team must:

* **Verify Authorisation:** Confirm the client’s signatory authority to avoid legal risks.
* **Customise the Approach:** Tailor the test to the client’s unique infrastructure, goals, and risk tolerance.
* **Mitigate Risks:** Implement safeguards, such as backups or testing in non-production environments, to prevent disruptions.
* Communicate Clearly: Use language appropriate for both technical and non-technical stakeholders to ensure understanding and buy-in.
* **Engage Third Parties:** Secure written consent from third-party providers whose systems are in scope.
* **Comply with Regulations:** Adhere to legal and compliance requirements, such as GDPR, HIPAA, or the Computer Misuse Act.

### Conclusion

The Pre-Engagement phase is the cornerstone of a successful penetration test, establishing trust, clarity, and a legal framework for the assessment. By carefully defining the scope, securing agreements, and aligning with the client’s objectives, the testing team ensures that the engagement is ethical, effective, and tailored to the organisation’s needs. This phase sets the tone for the entire penetration testing process, enabling a thorough and professional evaluation of the client’s security posture.
