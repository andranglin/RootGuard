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

# Acquire Image Using FTK

1\. Preparation

* Download FTK Imager: Obtain the latest version from the AccessData website (free, no license required). Install it on a forensic workstation or use the portable version from a USB.
* System Requirements: Windows OS (7, 10, 11), admin privileges, and sufficient storage for the image (e.g., an external drive with capacity exceeding the target device).
* Target Device: Identify the source—physical disk (e.g., HDD, SSD), logical drive (e.g., C:), USB, or memory. Attach it to the workstation via a write-blocker (e.g., Tableau or WiebeTech) for physical devices to prevent modification.
* Output Location: Prepare a destination drive (e.g., D:\ForensicImages). Ensure it’s formatted (NTFS recommended) and has space (e.g., a 1 TB target needs 1+ TB free).
* Documentation: Record case details (e.g., case number, date: February 26, 2025) for chain of custody.

2\. Launch FTK Imager

* Install Method: Run FTKImager.exe from the Start menu or desktop shortcut.
* Portable Method: Extract the portable version to a USB (e.g., E:\FTKImager\FTKImager.exe) and double-click to launch. No installation needed—ideal for fieldwork.

3\. Acquire a Forensic ImageFTK Imager supports multiple image types (e.g., E01, RAW/DD, AD1). For a full forensic image, E01 is recommended due to compression and hash verification. Steps vary slightly by target type.Option 1: Physical Disk Image (Full Device)

* Steps:
  1. Open FTK Imager as Administrator (right-click > "Run as administrator").
  2. Click File > Create Disk Image or the "Create Image" toolbar icon.
  3. Select Source Type: Choose "Physical Drive."
  4. Select Drive: From the dropdown, pick the target (e.g., \\\\.\PHYSICALDRIVE0 for the primary disk). Verify by size or label to avoid errors.
  5. Click Finish.
  6. Configure Destination:
     * Image Destination: Click "Add," select "E01" (or "RAW" for uncompressed).
     * Case Info: Enter details (e.g., Case Number: "INC-20250226", Examiner: "Your Name").
     * Image Folder: Set to D:\ForensicImages.
     * Image Filename: e.g., Drive0\_20250226 (FTK adds .E01).
     * Fragment Size: Default (2 GB) is fine; adjust for larger drives (e.g., 8 GB).
     * Compression: 6 (balanced speed/size); use 0 for no compression.
     * Check "Verify images after they are created" for hash validation (MD5/SHA1).
  7. Click Start.
* Process: FTK reads the entire disk sector-by-sector, writing to D:\ForensicImages\Drive0\_20250226.E01. Progress shows percentage, speed (e.g., 100 MB/s), and estimated time.
* Output: E01 file(s) (split if >2 GB) plus a .txt log with hashes.

Option 2: Logical Drive Image (Partition or Volume)

* Steps:
  1. Open FTK Imager as Administrator.
  2. Click File > Create Disk Image.
  3. Select Source Type: Choose "Logical Drive."
  4. Select Drive: Pick a volume (e.g., C:\ or D:\\). Includes mounted USBs or CDs.
  5. Click Finish.
  6. Configure Destination:
     * Add an "E01" destination.
     * Enter case info (e.g., Evidence Number: "VOL001").
     * Set path: D:\ForensicImages\C\_Drive\_20250226.
     * Use default fragment size (2 GB) and compression (6).
     * Enable verification.
  7. Click Start.
* Process: Captures only the selected volume, excluding unallocated space from other partitions.
* Output: Smaller E01 file(s) than a physical image.

Option 3: Memory Image (Live System Triage)

* Steps:
  1. Launch FTK Imager on the live system as Administrator.
  2. Click File > Capture Memory.
  3. Destination: Set to D:\ForensicImages\Memory\_20250226.raw.
  4. Check "Include pagefile" (optional, increases size for virtual memory data).
  5. Click Capture Memory.
* Process: Dumps physical RAM (and pagefile if selected) to a raw file.
* Output: Memory\_20250226.raw (size matches RAM, e.g., 16 GB) plus a .txt log.

Option 4: Custom Content Image (Specific Files/Folders)

* Steps:
  1. Click File > Create Disk Image.
  2. Select Source Type: "Contents of a Folder."
  3. Browse to the folder (e.g., C:\Users\Suspect).
  4. Add destination (e.g., AD1 format for FTK compatibility).
  5. Set path: D:\ForensicImages\UserFiles\_20250226.ad1.
  6. Start the process.
* Output: AD1 file with selected files, not a bit-for-bit image.

4\. Monitor and Verify

* Progress: Watch the status bar (e.g., "50% complete, 2 hours remaining"). Speed depends on device (SSDs are faster than HDDs) and compression.
*   Verification: Post-capture, FTK calculates MD5/SHA1 hashes and compares them to the source. Results appear in the log (e.g., D:\ForensicImages\Drive0\_20250226.txt):

    ```
    MD5: 1234abcd... 
    SHA1: 5678efgh...
    Verification: Passed
    ```
* Errors: If verification fails, check connections or re-image.

5\. Package and Store

* Check Output: Confirm files in D:\ForensicImages (e.g., Drive0\_20250226.E01, .E01.001, etc., for split files).
* Hash Backup: Export hashes manually via Tools > Export Disk Image Hashes if needed.
*   Compress (Optional): Use Compress-Archive in PowerShell for transport:powershell

    {% code overflow="wrap" %}
    ```powershell
    Compress-Archive -Path "D:\ForensicImages\*" -DestinationPath "D:\Case_20250226.zip"
    ```
    {% endcode %}
* Secure Storage: Move to an evidence locker or encrypted drive.

6\. Analyze the Image

* Mount: Use FTK Imager (File > Image Mounting) to mount E01 as a virtual drive for browsing.
* Tools:
  * FTK Toolkit: Full suite for deep analysis (commercial).
  * Autopsy: Open-source, load E01 via "Add Data Source."
  * X-Ways Forensics: Commercial, supports E01 natively.
* Artifacts: File systems, deleted files, registry, logs, etc.

7\. Tips and Best Practices

* Write Protection: Always use a hardware write-blocker for physical devices; FTK doesn’t block writes on live systems.
* Speed: Physical images take hours (e.g., 1 TB HDD at 100 MB/s ≈ 2.8 hours). SSDs are faster.
* Size: E01 compression reduces size (e.g., 1 TB drive might yield 600 GB E01), but RAW matches source exactly.
* Live vs. Dead: For live systems, capture memory first, then image disks to preserve volatile data.
* Chain of Custody: Log all steps, including hashes and acquisition time (e.g., "Started: 2025-02-26 09:00 UTC").
