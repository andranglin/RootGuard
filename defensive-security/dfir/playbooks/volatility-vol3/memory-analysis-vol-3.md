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

#### OS Information

**Desc:  Vol3 This plugin gives OS information**

```python
./vol.py -f file.dmp windows.info.Info
```

#### Hashes/Passwords

**Desc: Extract SAM hashes, domain cached credentials, and LSA secrets.**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% endcode %}

## Processes

**List processes**

{% code overflow="wrap" %}
```python
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% endcode %}

**Dump proc**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% endcode %}

### Command line

Desc: Anything suspicious was executed?

{% code overflow="wrap" %}
```python
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{% endcode %}

## Services

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endcode %}

### Strings Per Processes

**Volatility allows us to check which process a string belongs to.**

{% code overflow="wrap" %}
```python
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% endcode %}

**Desc: It also allows to search for strings inside a process using the yarascan module:**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% endcode %}

## Environment

**Get the environment variables of each running process. There could be some interesting values.**

{% code overflow="wrap" %}
```python
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% endcode %}

### Token privileges

**Check for privilege tokens in unexpected services. It could be interesting to list the processes using some privileged token.** **Desc: Get enabled privileges of some processes**

```python
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
```

**Desc: Get all processes with interesting privileges**

{% code overflow="wrap" %}
```python
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endcode %}

### SIDs

**Check each SSID owned by a process, it could be interesting to list the processes using a privileges SID (and the processes using some service SID).**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% endcode %}

### Handles

**Useful to know to which other files, keys, threads, processes... a process has a handle for (has opened)**

```python
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```

### DLLs

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% endcode %}

### UserAssist

**Windows systems maintain a set of keys in the registry database (UserAssist keys) to keep track of programs that are executed. The number of executions and the last execution date and time are available in these keys.**

```python
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```

### Network

```python
./vol.py -f file.dmp windows.netscan.NetScan
```

### Registry hive

**Print available hives**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{% endcode %}

#### Get a value

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{% endcode %}

## Filesystem

**Scan/dump**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{% endcode %}

**SSL Keys/Certs**

Desc: search for certificates inside the registry

```python
./vol.py -f file.dmp windows.registry.certificates.Certificates
```

### Malware

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
```
{% endcode %}

Malfind will search for suspicious structures related to malware

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses
```
{% endcode %}

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% endcode %}

### Scanning with yara

Use this script to download and merge all the yara malware rules from github: https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9 Create the rules directory and execute it. This will create a file called malware\_rules.yar which contains all the yara rules for malware.

{% code overflow="wrap" %}
```python
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
```
{% endcode %}

**Only Windows**

{% code overflow="wrap" %}
```python
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
```
{% endcode %}

**All**

```python
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```

### Mutexes

```python
./vol.py -f file.dmp windows.mutantscan.MutantScan
```

### Symlinks

```python
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```

### TimeLine

```python
./vol.py -f file.dmp timeLiner.TimeLiner
```

### Drivers

```python
./vol.py -f file.dmp windows.driverscan.DriverScan
```
