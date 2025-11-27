# Acquire Triage Memory Image

### 1. Preparation

* Understand the Goal: A triage memory image captures volatile data for quick analysis, not a full forensic memory dump (though the process is similar). Prioritize speed and minimal system impact.
* Select a Tool: Choose a memory acquisition tool based on availability and system compatibility.
  * DumpIt: Free, simple, Windows-focused (from Comae/MoonSols).
  * WinPmem: Open-source, supports Windows, part of the Rekall framework.
  * Magnet RAM Capture: Free, user-friendly, Windows-only.
  * FTK Imager: Free, includes memory capture alongside disk imaging.
  * Belkasoft Live RAM Capturer: Free, lightweight, Windows-specific.
* **Requirements**:
  * Administrative privileges on the target system.
  * External storage (e.g., USB drive) with enough space (RAM size + overhead, e.g., 8-16 GB for a typical system).
*   **Output Location:** Define a destination (e.g., D:\MemoryDump). Create it manually or via command:cmd

    ```
    mkdir D:\MemoryDump
    ```

### 2. Choose Acquisition Method

Memory capture tools typically produce a raw memory dump (.raw, .bin, or .dmp) suitable for triage analysis. Select based on your scenario:

* Live System: Run the tool directly on the target.
* No Forensic Image Support: These methods are for live systems only, not mounted disk images.

### 3. Acquire the Memory Image

Below are detailed steps for popular tools. Use one based on your setup.

#### **Option 1: DumpIt**

* Download: Get DumpIt from the Comae website (free for non-commercial use).
* Setup: Copy DumpIt.exe to a USB or the target system (e.g., D:\Tools\DumpIt.exe).
* Capture:
  1. Open an admin Command Prompt or PowerShell.
  2.  Run:cmd

      <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">D:\Tools\DumpIt.exe /O D:\MemoryDump\MemoryImage_%COMPUTERNAME%_%DATE%.raw
      </code></pre>

      * /O: Specifies output path and filename (e.g., MemoryImage\_PC1\_20250226.raw).
  3. Confirm with Y when prompted.
* Output: A raw memory file (size matches system RAM, e.g., 8 GB for 8 GB RAM).

#### **Option 2: WinPmem**

* Download: Obtain winpmem.exe from the Rekall GitHub or Velociraptor’s tools directory.
* Setup: Place winpmem.exe on a USB (e.g., D:\Tools\winpmem.exe).
* Capture:
  1. Open an admin Command Prompt.
  2.  Run:cmd

      <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">D:\Tools\winpmem.exe -o D:\MemoryDump\MemoryImage_%COMPUTERNAME%_%DATE%.raw
      </code></pre>

      * -o: Output file path.
      * Optional: Add --format raw for explicit raw format.
  3. Wait for completion (no prompt; watch the file size grow).
* Output: Raw memory dump (.raw).

#### **Option 3: Magnet RAM Capture**

* Download: Free from Magnet Forensics’ website.
* Setup: Run the installer or use the portable .exe on a USB (e.g., D:\Tools\MagnetRAMCapture.exe).
* Capture:
  1. Launch MagnetRAMCapture.exe (needs admin rights).
  2. Set output: D:\MemoryDump\MemoryImage\_%COMPUTERNAME%\_%DATE%.raw.
  3. Click "Capture Memory."
* Output: Raw memory file.

#### **Option 4: FTK Imager**

* Download: Free from AccessData’s site.
* Setup: Install or use the portable version (e.g., D:\Tools\FTKImager.exe).
* Capture:
  1. Launch FTK Imager as admin.
  2. File > "Capture Memory."
  3. Set destination: D:\MemoryDump\MemoryImage\_%COMPUTERNAME%\_%DATE%.raw.
  4. Check "Include pagefile" (optional, increases size).
  5. Click "Capture Memory."
* Output: Raw dump plus a .txt log.

#### **Option 5: Belkasoft Live RAM Capturer**

* Download: Free from Belkasoft’s website.
* Setup: Extract to a USB (e.g., D:\Tools\BelkaRAMCapturer.exe).
* Capture:
  1. Run BelkaRAMCapturer.exe as admin.
  2. Select output: D:\MemoryDump\MemoryImage\_%COMPUTERNAME%\_%DATE%.dmp.
  3. Click "Capture."
* Output: Memory dump (.dmp).

### 4. Enhance with PowerShell (Optional)

PowerShell can’t capture memory but can automate tool execution and add metadata:powershell

{% code overflow="wrap" %}
```powershell
$OutputPath = "D:\MemoryDump"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -Path $OutputPath -ItemType Directory -Force

# Run DumpIt (example)
Start-Process -FilePath "D:\Tools\DumpIt.exe" -ArgumentList "/O $OutputPath\MemoryImage_$env:COMPUTERNAME_$Timestamp.raw" -Wait -NoNewWindow

# Add system info
Get-ComputerInfo | Export-Csv "$OutputPath\SystemInfo_$Timestamp.csv" -NoTypeInformation
```
{% endcode %}

### 5. Verify and Package

* Check Output: Ensure the file exists and matches RAM size (e.g., dir D:\MemoryDump or Get-ChildItem $OutputPath).
*   Hash for Integrity:powershell

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-FileHash -Path "$OutputPath\MemoryImage_$env:COMPUTERNAME_$Timestamp.raw" -Algorithm SHA256 | Export-Csv "$OutputPath\MemoryHash_$Timestamp.csv"
    </code></pre>
*   Compress:powershell

    <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Compress-Archive -Path "$OutputPath\*" -DestinationPath "D:\MemoryTriage_$Timestamp.zip"
    </code></pre>

### 6. Analyse the Memory Image

* **Tools**:
  * Volatility: Open-source, command-line (e.g., vol.py -f MemoryImage.raw --profile=Win10x64 pslist).
  * Rekall: Similar to Volatility, with WinPmem integration.
  * Autopsy: GUI, load the .raw file under "Add Data Source."
  * Magnet AXIOM: Commercial, supports memory analysis.
* **Key Artifacts:**
  * Processes (pslist, pstree)
  * Network connections (netscan)
  * Loaded DLLs (dlllist)
  * Registry hives in memory (hivelist)

### 7. Tips and Considerations

* Speed: Triage capture takes minutes (e.g., 1 GB/min on fast storage), ideal for rapid response.
* Size: Plan for RAM size (e.g., 16 GB system = 16+ GB dump with pagefile).
* Impact: Minimal, but tools load drivers—use on responsive systems only.
* Stealth: Run from a USB to avoid writing to C:\\.
* Legal: Ensure authorisation; memory may contain sensitive data.
