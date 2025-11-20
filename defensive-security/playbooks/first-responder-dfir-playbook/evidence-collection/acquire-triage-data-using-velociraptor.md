# Acquire Triage Data Using Velociraptor

1\. Setup Velociraptor

* Download: Get the latest release from the Velociraptor GitHub repository (e.g., velociraptor-v0.7.2-windows-amd64.exe for Windows, or platform-specific binaries for macOS/Linux).
* Install or Deploy: Velociraptor is portable—run it from a USB, local directory, or deploy it as a service. For triage, the standalone binary works fine. Ensure admin privileges for live systems.
* Dependencies: No external installs are required, but for offline use, prepare a collector ahead of time (see Step 3).
* Server (Optional): For centralized analysis, set up a server with velociraptor.exe config generate and host the GUI (velociraptor.exe gui). This isn’t required for triage but enhances post-collection review.

2\. Identify the Target

* Live System: Use the system’s primary drive (e.g., C: on Windows). Ensure Velociraptor has access to the filesystem and registry.
* Forensic Image: Mount the image using a tool like Arsenal Image Mounter or FTK Imager to assign a drive letter (e.g., E:). For raw/DD images, Velociraptor can process them directly with remapping.

3\. Configure the CollectionVelociraptor uses “artifacts” (predefined queries in VQL—Velociraptor Query Language) to specify what data to collect. Common triage artifacts include memory, filesystem, registry, and event logs.Option A: Build an Offline Collector (Recommended for Triage)

* GUI Method:
  1. Launch the GUI: velociraptor.exe gui (requires a config file—generate one with velociraptor.exe config generate -i if needed).
  2. Navigate to "Server Artifacts" > "Build Collector."
  3. Select artifacts:
     * Windows.KapeFiles.Targets (integrates KAPE-style triage; pick KapeTriage for broad coverage or BasicCollection for essentials like $MFT, event logs, and registry hives).
     * Add others like Windows.Sys.Processes (running processes) or Windows.EventLogs.System (system logs).
  4. Set parameters:
     * OS: Match the target (Windows, Linux, macOS).
     * Output: ZIP file (default) or directory.
     * Optional: Encrypt output or limit collection size (e.g., 500MB).
  5. Click "Launch" to create a self-contained binary (e.g., Collector.exe).
* CLI Method:
  *   Generate a collector with a command like:

      <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">velociraptor.exe config generate -i &#x26;&#x26; velociraptor.exe --config server.config.yaml artifacts collect Windows.KapeFiles.Targets --args Target=KapeTriage --output D:\TriageOutput\triage.zip
      </code></pre>

      * \--args Target=KapeTriage: Specifies the triage scope.
      * \--output: Defines the ZIP file location.

Option B: Direct Collection (Live System with Server)

* If the target is online and enrolled in a Velociraptor server:
  1. From the GUI, select the client under "Clients."
  2. Click "Collected Artifacts" > "Add" > Choose Windows.KapeFiles.Targets or custom artifacts.
  3. Run the collection and download results as a ZIP.

4\. Execute the Collection

* Live System:
  * Copy the Collector.exe to the target (e.g., via USB or network share).
  *   Run it from an admin command prompt:

      ```
      Collector.exe
      ```
  * It collects data into a ZIP file (e.g., triage-20250226.zip) in the same directory. Duration varies (5–15 minutes typically) based on scope and system size.
* Forensic Image:
  *   Mount the image or use raw access. For mounted drives:

      <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">velociraptor.exe deaddisk --image E:\mounted_image triage --output D:\TriageOutput\triage.zip
      </code></pre>
  *   For raw images, create a remapping.yaml file to map partitions (e.g., with --add\_windows\_disk), then:

      <pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">velociraptor.exe --remap remapping.yaml deaddisk --image E:\raw_image triage --output D:\TriageOutput\triage.zip
      </code></pre>

5\. Verify and Analyze

* Output Check: Open the ZIP file (e.g., triage.zip)—it contains:
  * JSONL files (structured artifact data).
  * Exported files (e.g., $MFT, logs).
  * Collection metadata (logs, timestamps).
* Analysis Options:
  * Standalone: Extract and review with tools like jq (for JSONL) or forensic software (Autopsy, X-Ways).
  * Server Import: Upload to a Velociraptor server:
    * GUI: "Server Artifacts" > Server.Utils.ImportCollection > Upload ZIP > Set hostname.
    * CLI: velociraptor.exe --config server.config.yaml import D:\TriageOutput\triage.zip.
  * View results in the GUI under "Collected Artifacts" or export as CSV/JSON.
* Validation: Check the collection.log in the ZIP for errors or skipped artifacts.

6\. Tips for Efficiency

* Customize Artifacts: Edit VQL in artifacts/definitions or use the GUI to tailor collections (e.g., focus on suspicious processes with Windows.Sys.Pslist).
* Scope Control: Limit file sizes (e.g., --args MaxSize=50000000) or filter event logs by date.
* Multi-System Triage: Deploy collectors via PsExec, SCCM, or an EDR for networked endpoints.
* Speed: Triage collections are fast (minutes vs. hours for full imaging), ideal for rapid response.
