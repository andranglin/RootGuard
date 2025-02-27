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

# Memory Analysis  (Vol 3)

## Live System

**Best to run the tools from an external USB device.**

* FTK Imager (best to run it from a memory stick)
* MagnetForensics RamCapture
* Belkasoft Live RAM Capturer
* DumpIT
* WinPMEM
* Redline

**Dead System** **Hibernation File**

* Contains a Compressed RAM image
  * %SystemDrive%/hiberfil.sys Also found in Volume Shadow Copies

**Page File**

* %SystemDrive%/pagefile.sys

**Memory Dump**

* %WINDIR%/MEMORY.DMP

**Virtual Machine Memory Acquisition** VMware Workstation

**Windows 10**

{% code overflow="wrap" %}
```powershell
<Drive Letter>:\Users\<username>\Documents\Virtual Machines\<vm name>
```
{% endcode %}

**VMware ESX**

```powershell
<DatacenterName>\<DatastoreName>\<DirectoryName>\<VirtualMachineName>
```

**Volatility**

* Deep dive into memory
* Find more artefacts
* In IR, it is slower to use but more exact and precise

## Analysis

**Find the first&#x20;**_**Hit**_

1. Identify rogue processes
2. Analyse process DLLs and handles
3. Review network artefacts
4. Look for evidence of code injection
5. Check for signs of a rootkit
6. Dump suspicious processes and drivers

## Volatility Process Analysis

#### **OS Information**

```python
./vol.py -f file.dmp windows.info.Info
```

#### **Image info**

```python
./vol.py -f "/path/to/file" windows.info
```

#### **Process Info**

```python
vol.py -f "/path/to/file" windows.pslist
vol.py -f "/path/to/file" windows.psscan
vol.py -f "/path/to/file" windows.pstree
```

```python
python3 vol.py -f file.dmp windows.pstree.PsTree
python3 vol.py -f file.dmp windows.pslist.PsList
python3 vol.py -f file.dmp windows.psscan.PsScan
```

#### **DLL List**

```python
./vol.py -f "/path/to/file" windows.dlllist ‑‑pid <PID>
```

#### **Handles**

```python
./vol.py -f "/path/to/file" windows.handles ‑‑pid <PID>
```

#### **LDR Modules**

```python
python3 vol.py -f /path/to/file/ windows.ldrmodules –pid <PID>
```

#### **Malfind**

```python
python3 vol.py -f /path/to/file/ windows.malfind –pid <PID>
```

#### **Dumpfiles**

{% code overflow="wrap" %}
```python
python3 vol.py -f /path/to/file/ -o /output/file/path/PID1640Dump/ windows.dumpfiles --pid 1640
```
{% endcode %}

#### **Strings per processes**

{% code overflow="wrap" %}
```python
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt
```
{% endcode %}

#### **ProcDump**

{% code overflow="wrap" %}
```python
./vol.py -f "/path/to/file" -o "/path/to/dir" windows.dumpfiles ‑‑pid <PID>
```
{% endcode %}

#### **MemDump**

{% code overflow="wrap" %}
```python
python3 vol.py -f "/path/to/file" -o "/path/to/dir" windows.memmap ‑‑dump ‑‑pid <PID>
```
{% endcode %}

#### **CMDLINE**

{% code overflow="wrap" %}
```python
python3 vol.py -f "/path/to/file" windows.cmdline
```
{% endcode %}

#### **Token privileges**

Get enabled privileges of some processes

{% code overflow="wrap" %}
```python
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
```
{% endcode %}

Get all processes with interesting privileges

{% code overflow="wrap" %}
```python
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endcode %}

#### **UserAssist**

```
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```

#### **Services**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endcode %}

#### **SSL Keys/Certs**

vol3 allows to search for certificates inside the registry

```python
./vol.py -f file.dmp windows.registry.certificates.Certificates
```

#### **Malware**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.malfind.Malfind --dump
```
{% endcode %}

#### Malfind will search for suspicious structures related to malware

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses
./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endcode %}

#### **Drivers**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{% endcode %}

#### **Hashes/Passwords**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endcode %}

### Network Information

#### **Netscan**

{% code overflow="wrap" %}
```python
./vol.py -f "/path/to/file" windows.netscan
./vol.py -f "/path/to/file" windows.netstat
./vol.py -f file.dmp windows.netscan.NetScan
```
{% endcode %}

For network info of linux use volatility2

### Registry

#### **Hivelist**

{% code overflow="wrap" %}
```python
./vol.py -f "/path/to/file" windows.registry.hivescan
./vol.py -f "/path/to/file" windows.registry.hivelist
```
{% endcode %}

#### **Printkey**

{% code overflow="wrap" %}
```python
./vol.py -f "/path/to/file" windows.registry.printkey
./vol.py -f "/path/to/file" windows.registry.printkey ‑‑key "Software\Microsoft\Windows\CurrentVersion"
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endcode %}

#### **HiveDump**

{% code overflow="wrap" %}
```python
./[vol.py](http://vol.py/) -f "/path/to/file" ‑‑profile <profile> printkey`
```
{% endcode %}

### Files

**Filescan**

```python
./vol.py -f "/path/to/file" ‑‑profile <profile> printkey
```

#### **FileDump**

{% code overflow="wrap" %}
```python
./vol.py -f "/path/to/file" -o "/path/to/dir" windows.dumpfiles
./vol.py -f "/path/to/file" -o "/path/to/dir" windows.dumpfiles ‑‑virtaddr <offset>
./vol.py -f "/path/to/file" -o "/path/to/dir" windows.dumpfiles ‑‑physaddr <offset>
./ vol.py -f "/path/to/file" -o "/path/to/dir" windows.dumpfiles ‑‑physaddr <offset>
```
{% endcode %}

#### **Scan/dump**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endcode %}

### Miscellaneous

#### **Malfind**

```python
./vol.py -f "/path/to/file" windows.malfind
```

#### **Yarascan**

{% code overflow="wrap" %}
```python
./vol.py -f "/path/to/file" windows.vadyarascan ‑‑yara-rules <string>
./vol.py -f "/path/to/file" windows.vadyarascan ‑‑yara-file "/path/to/file.yar"
./vol.py -f "/path/to/file" yarascan.yarascan ‑‑yara-file "/path/to/file.yar"
```
{% endcode %}
