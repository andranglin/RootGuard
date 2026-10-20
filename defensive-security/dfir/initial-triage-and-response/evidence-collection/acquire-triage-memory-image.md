# Windows Memory Acquisition: Planning and Verification

**Purpose:** Preserve volatile memory when it is proportionate and authorised during an incident.  
**Status:** Static technical review, 20 October 2026; acquisition tool versions and command syntax require lab verification.

## Decision before collection

Determine whether capturing memory is necessary to answer the investigative question, whether the endpoint is safe to keep running, and whether immediate containment takes priority. **Do not delay urgent containment** when malware is actively spreading or causing harm.

Memory capture may be useful for volatile processes, injected code, network artefacts and transient secrets, but it exposes highly sensitive user and credential data. Treat the resulting image as restricted evidence.

## Preparation

1. Identify the host, OS build, physical RAM, encryption state, available disk capacity, current time and operator.
2. Choose a trusted acquisition tool **verified for the actual OS build**, such as an organisation-approved supported version of Magnet RAM Capture, DumpIt, WinPmem or another validated collector.
3. Confirm endpoint-protection compatibility, administrative permissions and whether the tool loads a kernel driver. Do not disable endpoint security merely to make an acquisition succeed without incident approval.
4. Confirm the evidence destination has sufficient usable storage and acceptable encryption/access controls; leave headroom for image metadata and filesystem overhead.
5. Record case number, exact acquisition tool/version, configuration, operator, start time and intended output name.

## Acquisition

Use the verified tool's vendor instructions for its **specific installed version**. This page intentionally avoids generic command flags that may be incompatible or dangerous across versions.

Record tool messages, errors, driver loads, actual output path and acquisition end time. Memory acquisition changes the live system and may be incomplete due to inaccessible memory regions or protection mechanisms.

## Verification and handoff

1. Confirm an output file exists, its size is plausible for the acquisition format and tool warnings are documented.
2. Compute SHA-256 of the completed file and record the digest with evidence ID and tool details.
3. Verify the transferred image using a second SHA-256 hash; keep immutable originals and work from controlled copies.
4. Document acquisition gaps and handling of sensitive credentials and personal data.
5. Only conduct memory parsing with a compatible tool profile or framework and record tool/version failures.

**Interpretation:** File size and a matching transfer hash do not prove that *all* RAM was captured or that the memory image contains no tampering.

[Evidence Acquisition and Integrity](../../field-guides/evidence-acquisition-and-integrity.md) · [Memory analysis references](../../playbooks/volatility-vol3/README.md)
