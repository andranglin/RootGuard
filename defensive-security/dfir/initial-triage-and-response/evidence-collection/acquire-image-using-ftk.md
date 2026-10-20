# Forensic Disk Imaging with FTK Imager

**Purpose:** Plan and verify a forensic acquisition using a compatible FTK Imager release.  
**Status:** Static technical review, 20 October 2026; menu labels and supported formats must be verified against the installed version.

## Select the evidence source

Distinguish **physical drive**, **logical volume**, **selected files** and **memory acquisition**. These produce different evidence scopes. For a sector-level image, select the complete physical source when feasible and legally authorised; a logical-volume image or file export is not equivalent.

Confirm whether the source is live or removed/offline. Use an appropriate, tested hardware write-blocker for supported offline media; a running operating system cannot be presumed write-blocked. SSD firmware, TRIM and hardware encryption may affect acquisition.

## Pre-acquisition checklist

- Confirm case ID, investigator, authority, source device serial and storage capacity.
- Confirm source disk versus destination carefully; accidental reversal or use of invasive tools can destroy evidence.
- Use a trusted FTK Imager version compatible with the workstation and source.
- Select an appropriate format and compression strategy based on investigative and downstream-tool requirements. Do not assume the image must always be larger than the source or that a chosen compression ratio guarantees storage savings.
- Protect destination evidence with encryption and restricted access.

## Acquisition workflow

1. In the installed FTK Imager interface, start **Create Disk Image** using the verified acquisition source.
2. Select the source type and positively identify the source disk/device.
3. Choose the image format supported by the tool and investigation requirements.
4. Enter case metadata and select a protected output location.
5. Configure segmentation, compression and verification as supported by the installed version.
6. Start acquisition. Preserve tool logs, warnings, bad-sector reports, timestamps and hash/verification results.
7. Verify completed image segments and transfer hashes; preserve originals and analyse controlled working copies.

## Evidence integrity

Hash validation verifies consistency for the specific acquired bytes or files and algorithm used. It does not prove source completeness, original chain of custody, or that the live source was unchanged during capture. Record the precise scope, errors, bad sectors, image format and whether the tool's verification actually completed.

## Escalation

If a source is encrypted, damaged or unstable, consult the forensic acquisition lead before retrying. Do not attempt repair, formatting, unlock bypass or other invasive action without authorisation.

[Evidence Acquisition and Integrity](../../field-guides/evidence-acquisition-and-integrity.md) · [Windows Forensic Artefacts](../../field-guides/windows-artifact-interpretation.md)
