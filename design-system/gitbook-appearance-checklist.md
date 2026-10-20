# GitBook Appearance: Administrator Implementation Checklist

**Status:** Configuration specification; GitBook site-level changes require authorised access in GitBook and are not changed via this repository.

## Brand and visual hierarchy

1. Review the GitBook site's current Appearance and Customization controls, which may differ by plan and interface version.
2. Use the [RootGuard Design System](README.md) as the visual baseline, with a restrained navy/slate palette and one blue accent.
3. Review logo and favicon in both light and dark themes. Prefer simple, high-contrast marks at small sizes.
4. Use one article H1 and meaningful H2 headings, with consistent descriptive titles and concise introductions.
5. Avoid oversized page covers on technical articles. Retain purposeful imagery only on principal landing pages.
6. Check sidebar group length, content order and mobile collapsing behaviour against the [Start Here](../start-here/README.md) and [operational playbook index](../defensive-security/dfir/end-to-end-playbooks/README.md).
7. Keep search and table-of-contents discoverable; inspect code-block overflow on small screens.
8. Confirm links, callouts, tables and Mermaid diagrams render appropriately on the published site.

## Suggested checks before sign-off

| Area | Desktop check | Mobile check |
| --- | --- | --- |
| Navigation | Task-based pages easy to locate | Sidebar open/close and breadcrumb clarity |
| Typography | Headings and code distinguishable | No clipped text or unreadable metadata |
| Colour | Contrast in light and dark appearance | Callouts and links not relying on colour alone |
| Media | Covers appropriately cropped | No horizontal overflow |
| Technical content | KQL and PowerShell blocks readable | Code horizontally scrolls instead of breaking layout |
| Diagrams | Mermaid charts render and labels readable | Diagram scaling and text alternatives |
| Accessibility | Keyboard focus, link text, contrast | Tap targets, layout scaling |

## Review pages

- [Homepage](../README.md)
- [Start Here](../start-here/README.md)
- [Digital Forensics and Incident Response](../defensive-security/dfir/README.md)
- [Phishing operational playbook](../defensive-security/dfir/end-to-end-playbooks/phishing-compromise.md)
- [Detection Engineering Kerberoasting](../detection-engineering/threat-detection/ad-detections-and-mitigations/kerberoasting.md)

**Acceptance:** Document the rendered desktop/mobile evidence, colour contrast, accessible navigation, and any theme customisations actually applied. Do not mark this checklist complete solely because it is committed to GitHub.
