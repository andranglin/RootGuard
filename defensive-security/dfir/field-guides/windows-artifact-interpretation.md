# Windows Forensic Artefacts: Interpretation Reference

> **RootGuard technical reference** · **Environment:** Verify product, platform and telemetry prerequisites · **Validation:** Refer to the status below; examples are not automatically production-ready.

**Status:** Technical reference; artefact meaning and location depend on Windows build and configuration.

| Artefact | What it may help establish | Important limitation |
| --- | --- | --- |
| Prefetch | Application launch-related traces, execution counts and timestamps on supported Windows configurations | May be disabled or absent; does not prove specific user identity |
| Amcache | Program/file metadata useful for software presence and activity analysis | An entry alone does not always prove program execution |
| Shimcache / AppCompatCache | Application compatibility metadata and historical file references | Modification and population behaviour vary by version; execution claims require corroboration |
| UserAssist | Explorer-shell user activity for relevant launched items | Does not cover all ways to execute programs |
| BAM/DAM | Relevant process execution metadata on supported builds | Visibility and retention vary, and interpretation needs context |
| SRUM | Resource usage and application/network activity | Collection, retention and parser version affect coverage |
| Event Logs | Logon, service changes, process and PowerShell events when auditing configured | May be missing, overwritten, disabled or tampered with |
| NTFS MFT / USN | File-system metadata and changes | Not a complete record of user intent or every file operation |

## Analysis workflow

1. Determine OS build, time zone, filesystem and artefact availability.
2. Collect source artefacts using validated methods and document acquisition.
3. Use compatible parsers; record tool versions and warnings.
4. Normalise timestamps carefully, preserving raw values.
5. Correlate across at least two independent sources wherever possible.
6. Document positive evidence, gaps, competing explanations and confidence.

An artefact's presence is not automatically proof of malicious execution. Treat missing artefacts as inconclusive unless collection and expected generation are demonstrably reliable.

## Further reading

- [Windows forensics section](../window-forensics/README.md)
- [Windows endpoint triage](windows-endpoint-triage.md)
