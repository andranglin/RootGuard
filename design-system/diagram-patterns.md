# Diagram Patterns

These examples define a consistent technical diagram style for RootGuard.

## Investigation flow

```mermaid
flowchart TD
    A[Alert or report] --> B[Confirm telemetry and scope]
    B --> C{Ongoing harm?}
    C -->|Yes| D[Approved emergency containment]
    C -->|No| E[Preserve and investigate]
    D --> E
    E --> F[Correlate independent evidence]
    F --> G{Compromise supported?}
    G -->|Yes| H[Remediate and verify]
    G -->|Uncertain| I[Document gaps and escalate]
    H --> J[Close with owner approval]
```

This diagram is a conceptual decision aid. Incident command may prioritise containment over complete collection when risk is urgent.

## Evidence pipeline

```mermaid
flowchart LR
    A[Source events] --> B[Preserved evidence]
    B --> C[Time and identity normalisation]
    C --> D[Correlated timeline]
    D --> E[Analyst findings]
    E --> F[Recovery verification]
```

**Accessibility:** Always provide a text explanation of what the diagram demonstrates. GitBook Mermaid rendering and mobile behaviour must be checked on the published site.

[Design system](README.md)
