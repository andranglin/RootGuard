# RootGuard Documentation Design System

This guide defines the editorial and visual structure for RootGuard's GitBook pages. The goal is a restrained, consistent, accessible technical reference—not decorative dashboards or unsupported claims.

## Visual direction

- **Brand:** deep navy, slate, off-white, and a single blue/cyan accent. Maintain readable contrast in both GitBook light and dark modes.
- **Typography:** one H1 per article, descriptive H2 sections, sentence-case headings, concise opening summaries.
- **Content width:** use GitBook's default article width for investigation procedures and long code examples; avoid wide tables that overflow on mobile.
- **Imagery:** diagrams when they clarify investigative sequence or relationships. Avoid unrelated stock imagery and decorative security clip art.
- **Calls to action:** plain, descriptive links to the next task; avoid repeated promotional buttons.

## Article anatomy

1. Title and one-paragraph summary of the task and intended audience.
2. Metadata: product environment, telemetry required, permissions, review date, validation state.
3. A concise **Before you begin** section covering safety and prerequisites.
4. Procedure split into phases with labelled decision points.
5. Expected observations and limitations next to queries or commands.
6. Recovery, verification and exit criteria.
7. Related references and the owner of outstanding validation.

## Content status vocabulary

| Status | Meaning |
| --- | --- |
| Concept / unvalidated | Reasoned example; syntax and runtime not tested |
| Static safety reviewed | Potentially unsafe operations checked, not runtime validated |
| Syntax checked | Executed for syntactic correctness in a stated environment |
| Lab validated | Repeatable positive and negative tests with recorded outputs |
| Production validated | Approved test in a specified production environment with results |

**Never imply that a successful Markdown link check validates a detection query, procedure, or Microsoft Graph permission.**

## Design tokens for GitBook configuration

These are recommended values for the site administrator—not settings committed through GitHub.

| Token | Suggested use |
| --- | --- |
| Navy `#0B1627` | Dark brand background |
| Slate `#263449` | Secondary dark surfaces |
| Blue `#367BF5` | Links and interactive accent |
| Cyan `#38BDF8` | Diagram highlights (not body text) |
| Off-white `#F8FAFC` | Light backgrounds |
| Charcoal `#172235` | Light-mode text |

Review contrast after configuring colours; do not assume every combination meets accessibility requirements.

## Diagram conventions

Use Mermaid source in Markdown for diagrams that GitBook renders correctly in your deployment. Use short labels, top-down flow for decision paths, and left-to-right flow for investigation pipelines. Diagrams must have explanatory text for accessibility. Avoid placing secrets, customer-specific hostnames or internal addresses in public examples.

[Diagram patterns](diagram-patterns.md) · [Operational article template](../contributing/templates/operational-article.md) · [RootGuard homepage](../README.md)
