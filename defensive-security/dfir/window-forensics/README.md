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
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Windows Forensics

Investigate Windows activity using event logs, execution artefacts, account records, browser history and file-system evidence. Select the artefact that answers your investigative question, then corroborate it with other sources.

## Investigation guides

| Question | Reference |
| --- | --- |
| What programs may have executed? | [Program execution artefacts](program-execution-artifacts-investigation-guide.md) |
| What do Windows event logs show? | [Windows event log investigation](enhanced-windows-event-log-investigation-guide.md) |
| Which account was used? | [Account usage investigation](account-usage-investigation-workflow-and-cheatsheet.md) |
| What can KQL show about account activity? | [Account usage KQL](account-usage-investigation-with-kql-cheatsheet.md) |
| What web activity took place? | [Browser forensics](browser-forensics-dfir-workflow-and-cheatsheet.md) |
| Was a file downloaded? | [File download and browser activity](file-download-and-browser-activity-investigation-guide.md) |
| Which files changed or disappeared? | [Deleted files and file knowledge](deleted-files-and-file-knowledge-dfir-workflow-and-cheatsheet.md) |
| Was removable storage used? | [USB and external storage](usb-device-and-external-storage-dfir-workflow-and-cheatsheet.md) |
| What file or folder access is recorded? | [File and folder access](file-and-folder-access-investigation-guide.md) |
| What is the broader evidence timeline? | [Windows artefact workflow](windows-forensic-artifacts-investigation-workflow-and-cheatsheet.md) |
| How can user activity be correlated? | [User activity KQL](user-activity-tracking-with-kql.md) |

## Before using these guides

- Verify the Windows build, available auditing and collection method.
- Preserve original evidence and document acquisition limitations.
- Treat artefact presence, absence and timestamps according to their actual semantics.
- Test KQL examples against the relevant product schema before operational use.

For first response use [Windows endpoint triage](../field-guides/windows-endpoint-triage.md) and [evidence acquisition and integrity](../field-guides/evidence-acquisition-and-integrity.md).
