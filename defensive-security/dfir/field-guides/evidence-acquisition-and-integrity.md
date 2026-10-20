# Evidence Acquisition and Integrity

**Status:** Procedure template requiring organisational approval and tool-specific validation.

## Before acquisition

Confirm written authorisation and scope, preserve incident metadata, identify storage and encryption requirements, ensure suitable destination capacity and assess the operational impact of acquisition. Coordinate containment requirements with incident command.

Decide deliberately between remote triage, targeted file collection, live memory capture and full disk imaging. These methods capture different evidence and entail different risks.

## Collection record

| Field | Record |
| --- | --- |
| Incident and evidence ID | Unique identifiers |
| Asset identification | Hostname, serial, cloud resource ID as applicable |
| Collector | Individual and role |
| Tool and version | Exact acquisition utility build and options |
| Collection start/end | ISO 8601 timestamps with offsets |
| Source and destination | Paths, devices, media and transfer method |
| Integrity | Algorithm and original/transfer verification hashes |
| Exceptions | Failures, skipped files, collection-induced changes |
| Custody | Every handoff, location, recipient, date and purpose |

## Integrity example

For a copied evidence file, obtain a SHA-256 hash on the acquisition system and compare against the transferred copy when operationally appropriate:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'D:\Evidence\collection.zip'
```

A matching hash establishes byte-level agreement for the hashed files at the times measured. It does not establish forensic completeness, authenticity of the source or legal admissibility.

## Important cautions

- Live acquisition modifies the system. Document collection artefacts and changes.
- Memory acquisition may require drivers or privileged tools and may be blocked by endpoint protections; do not disable security controls without incident-authorised approval.
- Do not assume a file copy is equivalent to a forensically sound disk image.
- Use write-blocking when appropriate to offline media acquisition; do not claim live OS collection is write-blocked.
- Follow organisational privacy rules and apply encryption/access restrictions to evidence.

## Completion

Verify collected items against the approved acquisition plan, record gaps, protect originals and create working copies for analysis. Use a documented evidence handover process.

Related: [Windows endpoint triage](windows-endpoint-triage.md).
