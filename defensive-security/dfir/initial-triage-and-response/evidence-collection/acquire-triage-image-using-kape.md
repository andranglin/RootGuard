# Targeted Windows Artefact Collection with KAPE

**Purpose:** Acquire selected Windows forensic artefacts for incident triage.  
**Status:** Static technical review, 20 October 2026. Validate KAPE version, Targets and flags against your installed release.

## Important distinction

KAPE's target collection is **not the same as full forensic disk imaging**. A Target selects file paths and artefacts; collection can omit unallocated space and evidence outside the chosen targets. The term *triage image* must not imply a complete sector-by-sector acquisition.

## Planning

1. Confirm incident scope, authorisation, asset identity and applicable collection restrictions.
2. Choose an appropriate trusted KAPE build and verify integrity from the authorised distribution.
3. Inventory available KAPE Targets on the installed version rather than assuming a specific legacy Target name or argument works.
4. Select source volume or a validated mounted forensic image. Determine whether shadow-copy handling is necessary and supported by the acquisition setup.
5. Select a protected destination with sufficient storage **separate from the acquired source when possible**. Record collection-induced changes if working live.
6. Document host time, tool version, selection rationale, privileges and any files skipped because of locks or permissions.

## Execution

Use the validated KAPE command builder or GUI to generate the collection command for your **installed version**, then review source, destination, Target set, and options before running it. Do not paste undocumented flag combinations from old examples.

Run the agreed Target collection and preserve the generated console logs, reports and error messages. Determine whether the tool collected raw files, copies through VSS, or a packaged collection based on the actual options used.

## Evidence quality checks

- Review which Targets ran successfully and whether key artefacts such as EVTX, registry hives or NTFS metadata were skipped.
- Create a manifest with collection item names, paths, hash values where possible, tool version and acquisition window.
- Transfer evidence securely and verify file digests after transfer.
- Distinguish acquisition from parsing: evidence interpretation requires separate, compatible tools and independent corroboration.

## Next actions

Interpret artefacts with the [Windows Artefact Reference](../../field-guides/windows-artifact-interpretation.md), correlating with [Endpoint Triage](../../field-guides/windows-endpoint-triage.md). For complete disk preservation, use a separately planned forensic imaging workflow.

[KAPE documentation and downloads](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
