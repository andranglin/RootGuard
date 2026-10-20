# RootGuard Documentation Standards

Follow the [RootGuard Documentation Design System](../design-system/README.md) for visual hierarchy, metadata, and diagram conventions. Use the [Operational Article Template](templates/operational-article.md) for new practitioner workflows.

[Technical Content Review Register](content-review-register.md) tracks prioritised legacy corrections and validation status.

## Writing in plain English

RootGuard is a public technical reference, not an internal status report or marketing brochure.

- Write for a practising analyst or engineer. State the task, prerequisites, procedure, expected observations and limitations without promotional introductions.
- Use direct verbs such as **inspect**, **query**, **compare**, **preserve**, **verify** and **escalate**.
- Avoid em dashes in prose. Prefer a full stop, colon, semicolon or a rewritten sentence.
- Avoid stock phrases such as *ever-evolving threat landscape*, *cutting-edge*, *seamlessly*, *game changer*, *unlock the power of*, *delve into* and *robust solution*. Replace them with a specific claim or remove them.
- Do not repeat generic warning banners on every page. Put important requirements next to the relevant command or decision.
- Do not describe examples as comprehensive, complete, validated or production-ready unless the article provides evidence for that claim.
- Preserve literal syntax in KQL, PowerShell, command output, quoted source material and URLs. Language cleanup must never alter executable logic.
- Read the final article aloud. Remove filler, repeated ideas and unnecessary adjectives.

## Publishing principles

- Prefer evidence-based guidance, clear prerequisites and explicit limitations over unsupported claims.
- Maintain existing URL paths when possible; introduce links to new topic pages rather than moving legacy content.
- Do not publish credentials, customer data or unredacted incident evidence.
- Credit external research and link to authoritative technical documentation.
- Use UK English consistently.
- Label code examples **Concept / unvalidated**, **Syntax checked**, **Lab validated** or **Production validated**, supported by evidence.
- Verify syntax and source telemetry before describing a query as deployable.

## Article requirements

Each substantive technical guide should provide: purpose, scope, threat or problem statement, prerequisites, telemetry or system requirements, reproducible steps, output interpretation, false positives and limitations, validation status, response or next steps, authoritative references, and review metadata.

Use the [Detection Guide template](templates/detection-guide.md), [Incident Response Playbook template](templates/incident-playbook.md), and [Architecture Decision Record template](templates/architecture-decision.md).

## Change review

1. Edit on a topic branch and create a pull request.
2. Run documentation link checks and review the changed pages in GitBook preview.
3. Verify command and query behaviour in a representative lab or clearly mark them unvalidated.
4. Confirm existing public page paths remain stable.
5. Update content review metadata and merge only after checks and review.

Older articles remain available while they are progressively audited. Absence of a validation label on a legacy article is not evidence of production readiness.
