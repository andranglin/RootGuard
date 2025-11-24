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

## KAPE cheatsheet <a href="#kape-cheatsheet" id="kape-cheatsheet"></a>

#### Basic command

{% code overflow="wrap" %}
```powershell
# Target
.\kape.exe --tsource [DRIVE LETTER] --tdest [DESTINATION INCLUDE FOLDER NAME] --module [MODULE NAME] --gui
# Module
.\kape.exe --msource [DRIVE LETTER] --mdest [DESTINATION INCLUDE FOLDER NAME] --module [MODULE NAME] --gui
```
{% endcode %}

### Target <a href="#target" id="target"></a>

#### KAPE target extraction <a href="#kape-target-extraction" id="kape-target-extraction"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --tsource E: --tdest E:\EvidenceCaseFiles\ --target KapeTriage,MessagingClients,RemoteAdmin,ServerTriage,WebBrowsers,WebServers,WSL,MemoryFiles --gui
```
{% endcode %}

### Module: Live Response <a href="#module-live-response" id="module-live-response"></a>

#### Memory dump <a href="#memory-dump" id="memory-dump"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource C:\ --mdest E:\EvidenceCaseFiles\%m --module MagnetForensics_RAMCapture --gui
```
{% endcode %}

#### Live response command and scanner <a href="#live-response-command-and-scanner" id="live-response-command-and-scanner"></a>

{% code overflow="wrap" %}
```ps1
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\%m --module PowerShell_Get-InjectedThread,PowerShell_Get-NetworkConnection,PowerShell_Netscan,PowerShell_Signed,SIDR_WindowsIndexSearchParser,WIFIPassView,MagnetForensics_EDD,Nirsoft_BluetoothView,Nirsoft_LastActivityView,Nirsoft_OpenedFilesView,NirSoft_USBDeview,NirSoft_VideoCacheView,NirSoft_WebBrowserPassView,Nirsoft_WhatInStartup,Nirsoft_WifiHistoryView,Nirsoft_WirelessKeyView,SysInternals_Autoruns,SysInternals_Handle,SysInternals_PsFile,SysInternals_PsInfo,SysInternals_PsList,SysInternals_PsLoggedOn,SysInternals_PsService,SysInternals_PsTree,SysInternals_Tcpvcon,Powrshell_LiveResponse_SystemInfo,PowerShell_Arp_Cache_Extraction,PowerShell_Bitlocker_Key_Extraction,PowerShell_Bitlocker_Status,PowerShell_Defender_Exclusions,PowerShell_DLL_List,PowerShell_Dns_Cache,PowerShell_Local_Group_List,PowerShell_LocalAdmin,PowerShell_NamedPipes,PowerShell_NetUserAdministrators,PowerShell_Network_Configuration,PowerShell_Network_Connections_Status,PowerShell_Network_Share,PowerShell_Process_Cmdline,PowerShell_ProcessList_CimInstance,PowerShell_ProcessList_WMI,PowerShell_Services_List,PowerShell_SMBMapping,PowerShell_SMBOpenFile,PowerShell_SMBSession,PowerShell_Startup_Commands,PowerShell_User_List,PowerShell_WMIRepositoryAuditing,Windows_ARPCache,Windows_DNSCache,Windows_GpResult,Windows_IPConfig,Windows_MsInfo,Windows_nbtstat_NetBIOSCache,Windows_nbtstat_NetBIOSSessions,Windows_Net_Accounts,Windows_Net_File,Windows_Net_LocalGroup,Windows_Net_Session,Windows_Net_Share,Windows_Net_Start,Windows_Net_Use,Windows_Net_User,Windows_netsh_portproxy,Windows_NetStat,Windows_qwinsta_RDPSessions,Windows_RoutingTable,Windows_schtasks,Windows_SystemInfo,Reghunter,hasherezade_HollowsHunter --gui

.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\%m --module Thor-Lite_Upgrade,Thor-Lite_Scan --gui

.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\%m --module Loki_LiveResponse --gui

.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\%m --module hasherezade_HollowsHunter --gui

.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\%m --module MagnetForensics_RAMCapture --gui
```
{% endcode %}

### Module: Parsing and scanning <a href="#module-parsing-and-scanning" id="module-parsing-and-scanning"></a>

#### All in one artifact parsing <a href="#all-in-one-artifact-parsing" id="all-in-one-artifact-parsing"></a>

Warning: Super slow!

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module Loki_Scan,DensityScout,BackstageParser,BitsParser,CCMRUAFinder_RecentlyUsedApps,Chainsaw,DeepblueCLI,DHParser,EvtxHussar,hasherezade_HollowsHunter,INDXRipper,LevelDBDumper,OneDriveExplorer,PowerShell_Get-ChainsawSigmaRules,TeamsParser,ThumbCacheViewer,WMI-Parser,Zircolite_Scan,Zircolite_Update,LogParser_ApacheAccessLogs,LogParser_DetailedNetworkShareAccess,LogParser_LogonLogoffEvents,LogParser_RDPUsageEvents,LogParser_SMBServerAnonymousLogons,Nirsoft_AlternateStreamView,NirSoft_BrowsingHistoryView,NirSoft_FullEventLogView_AllEventLogs,NirSoft_FullEventLogView_Application,NirSoft_FullEventLogView_PowerShell-Operational,NirSoft_FullEventLogView_PrintService-Operational,NirSoft_FullEventLogView_ScheduledTasks,NirSoft_FullEventLogView_Security,NirSoft_FullEventLogView_System,NirSoft_TurnedOnTimesView,NirSoft_WebBrowserDownloads,Nirsoft_WinLogonView,SysInternals_SigCheck,TZWorks_CAFAE_Registry_System,Events-Ripper,Hayabusa,LogParser,MFTECmd,NTFSLogTracker,RECmd_AllBatchFiles,Reghunter,RegRipper,AmcacheParser,AppCompatCacheParser,EvtxECmd,EvtxECmd_RDP,iisGeoLocate,JLECmd,LECmd,PECmd,RBCmd,RecentFileCacheParser,SBECmd,SQLECmd,SQLECmd_Hunt,SrumECmd,SumECmd,WxTCmd,Sync_EvtxECmd,Sync_KAPE,Sync_RECmd,Sync_SQLECmd,Windows_ManageBDE_BitLockerKeys,Windows_ManageBDE_BitLockerStatus --gui
```
{% endcode %}

#### Event log / log scanning and parsing <a href="#event-log--log-scanning-and-parsing" id="event-log--log-scanning-and-parsing"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module !!ToolSync,PowerShell_Get-ChainsawSigmaRule,Chainsaw,DeepblueCLI,EvtxHussar,Zircolite_Update,Zircolite_Scan,Events-Ripper,hayabusa_EventStatistics,hayabusa_OfflineEventLogs,hayabusa_OfflineLogonSummary,hayabusa_UpdateRules,EvtxECmd,EvtxECmd_RDP,LogParser,iisGeoLocate
```
{% endcode %}

#### Program Execution <a href="#program-execution" id="program-execution"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module CCMRUAFinder_RecentlyUsedApps,AmcacheParser,AppCompatCacheParser,PECmd,RecentFileCacheParser --gui
```
{% endcode %}

#### File folder activity <a href="#file-folder-activity" id="file-folder-activity"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module BackstageParser,OneDriveExplorer,ThumbCacheViewer,JLECmd,LECmd,RBCmd,SBECmd,WxTCmd --gui
```
{% endcode %}

#### NTFS and FileSystem parsing <a href="#ntfs-and-filesystem-parsing" id="ntfs-and-filesystem-parsing"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module !!ToolSync,INDXRipper,MFTECmd,NTFSLogTracker,RegRipper,RECmd_AllBatchFiles --gui
```
{% endcode %}

#### System activity <a href="#system-activity" id="system-activity"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module SRUMDump,WMI-Parser,RECmd_AllBatchFiles,SrumECmd,SumECmd --gui
```
{% endcode %}

#### Mounted image scanner <a href="#mounted-image-scanner" id="mounted-image-scanner"></a>

{% code overflow="wrap" %}
```powershell
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module Loki_Scan --gui
.\kape.exe --msource E:\ --mdest E:\EvidenceCaseFiles\ --module DensityScout --gui
```
{% endcode %}

