---
layout:
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
---

# Acquire Triage Image Using KAPE

### Acquiring a triage image with KAPE

1. Setup: Download KAPE from Kroll’s site or GitHub. Run it from a USB or local folder with admin privileges on your forensic workstation.
2. Target: Choose your source—e.g., C: for a live system or a mounted image’s drive letter (use Arsenal Image Mounter for E01 files).
3. Command: Open an admin command prompt, navigate to KAPE’s directory, and run:

{% code overflow="wrap" %}
```powershell
.\kape.exe --tsource C: --tdest "F:\EvidenceCollector\" --tflush --target !SANS_Triage --vhdx PC02 --mflush --gui
```
{% endcode %}

OR&#x20;

{% code overflow="wrap" %}
```powershell
kape.exe --tsource C: --target KapeTriage --tdest D:\TriageOutput --vhdx TriageImage.vhdx --vss
```
{% endcode %}

* \--tsource C:: Source drive to triage.
* \--target KapeTriage: Grabs key artifacts (registry, event logs, etc.).
* \--tdest D:\TriageOutput: Output folder.
* \--vhdx TriageImage.vhdx: Saves as a VHDX file.
* \--vss: Includes Volume Shadow Copies for locked/historical data.

1. Execution: Takes minutes depending on system size. Logs are saved in D:\TriageOutput.
2. Verify: Mount TriageImage.vhdx (right-click > Mount in Windows) or open in FTK Imager/Autopsy to analyze.

Tips: Add --tflush to wipe the destination first. Customize targets in the Targets folder (e.g., RegistryHives or !BasicCollection). For parsing, add --module !EZParser --mdest D:\Parsed. Ready for triage!
