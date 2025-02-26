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

# Network Activity

### **Objectives**

**Which** network has the device connected to?

**What** is the last known IP address of the device?&#x20;

**Which** executables have a high network usage?

#### Description&#x20;

Tracks the networks that the local host has connected to&#x20;

#### Location

```powershell
C:\Windows\System32\config\SOFTWARE 
C:\Windows\System32\config\SYSTEM 
```

#### Caveats&#x20;

Different registry keys must be correlated to gain information about network history&#x20;

#### Forensic Analysis

* Tools Registry Explorer

IP Address and Networking Information (per Interface)

```
SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
```

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 142241.png" alt=""><figcaption></figcaption></figure>

Previous Network Connection Information

```csharp
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
```

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 142353.png" alt=""><figcaption></figcaption></figure>

#### Forensic Value

* Previously connected networks
* First and last timestamps of network connections
* Last known IP addresses
* Can include VPN connection information

***

## System Resource Usage Monitor  (SRUM)

#### **Description**

The System Resource Usage Monitor (SRUM) records 30 and 60 days of historical system performance, including applications run, user interaction, and network activit&#x79;**. It** is considered a gold mine of forensic information, as it contains all the activities on a system. SRUM tracks and records program executions, power consumption, network activities, and more information that can be retrieved even if the source has been deleted. The information allows you to gain insights into a system's previous activities and events.&#x20;

#### **Location**

```cs
C:\Windows\System32\SRU\SRUDB.dat
```

#### Structure of SRUM Artifacts

SRUM artifacts are stored in an Extensible Storage Engine (ESE) database format. This database contains multiple tables recording all the activities on a particular system.

#### Caveats&#x20;

Available on Windows version 8 and newer. Data is recorded approximately hourly

#### **Interpretation**

* SRUDB.dat is an Extensible Storage Engine database.
* Three tables in SRUDB.dat are particularly important:
* {973F5D5C-1D90-4944-BE8E-24B94231A174} = Network Data Usage
* {d10ca2fe-6fcf-4f6d-848e-b2e99266fa89} = Application Resource Usage
* {DD6636C4-8929-4683-974E-22C046A43763} = Network Connectivity Usage

#### Forensic Analysis Tools&#x20;

* SrumECmd (Zimmerman tool)

#### Data Capture

FTK Imager

Exports both SRUDB and Software Hive:

* Navigate: "C:\Windows\System32\SRU\SRUDB.dat" right-click SRUDB.dat, select Export Files, choose storage location, OK.
* Navigate: "C:\Windows\System32\config\\
  * Select: SOFTWARE, SOFTWARE.LOG1, SOFTWARE.LOG2, and export files to the same location as SRUDB.dat SrumECmd Parser:

```cs
SrumECmd.exe -d \Users\username\Desktop\sru --csv \Users\username\Desktop\Output
```

#### **Forensic Value**

1. Application resource usage
2. Network connectivity usage
3. Network data usage
4. Bytes Received & Sent

#### Output Fields

Network Usage                                                                              Network Connections

<figure><img src="../../../../.gitbook/assets/Screenshot 2025-02-26 142733.png" alt=""><figcaption></figcaption></figure>
