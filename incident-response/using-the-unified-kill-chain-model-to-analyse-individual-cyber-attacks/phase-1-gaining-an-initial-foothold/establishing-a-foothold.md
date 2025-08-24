# Establishing a Foothold

### Introduction

Establishing a Foothold is crucial for adversaries to secure persistent access to a target environment in the first phase of an attack. During this phase, attackers deploy various techniques to gain control of systems while remaining undetected. By leveraging the Unified Kill Chain (UKC) model, defenders can systematically investigate these techniques, identify signs of compromise, and implement effective mitigation strategies. This phase often involves sophisticated methods to bypass security controls and embed malicious activity into the system, enabling further propagation across the environment. Below are some of the most prevalent techniques attackers use when it comes to establishing a foothold:

* **External Remote Services (T1133):** Attackers exploit poorly secured remote access mechanisms like RDP, VPNs, or SSH to infiltrate systems.
* **Create Account (T1136):** Adversaries may create new local or domain accounts to ensure persistent access and blend in with legitimate users.
* **Create or Modify System Process (T1543.003):** Modifying system services or processes to execute malicious code under the guise of legitimate functionality.
* **Scheduled Task/Job: Scheduled Task (T1053.005):** Leveraging Windows Task Scheduler to execute payloads or scripts at set intervals.
* **Boot or Logon Autostart Execution (T1547):** Configuring malicious software to start automatically during system boot or user logon.
* **Boot or Logon Initialisation Scripts (T1037):** Modifying initialisation scripts such as `startup.bat` to execute malicious code upon system startup or logon.
* **Hijack Execution Flow (T1574):** Techniques like DLL search order hijacking, DLL injection, or DLL spoofing to redirect legitimate processes into executing malicious code.
* **Modify Authentication Process (T1556):** Tampering with authentication mechanisms or server components to maintain stealthy access or steal credentials.
* **Event-Triggered Execution: Component Object Model (COM) Hijacking (T1546.015):** Hijacking COM objects to execute malicious code triggered by specific system events.
* **Event-Triggered Execution: Windows Management Instrumentation (WMI) Event Subscription (T1546.003):** Abusing WMI event subscriptions to trigger malicious scripts or executables upon specific events.

***

### Frequently used methods for Establishing a Foothold

**Exploitation for Privilege Escalation (T1068):** This includes operating-system-level and software vulnerabilities. One of the most frequent use cases is local privilege escalation (LPE) vulnerabilities. The goal of LPE is to gain access to the SYSTEM user and get ultimate privileges in the Windows operating system user space.

**Bypass User Account Control (T1548.002):** This technique bypasses administrator confirmation on running specific processes with greater privileges. A vector exploits a Windows elevation mechanism. This technique is frequently used functionality of malware dropped by threat actors.

**Access Token Manipulation (T1134):** Modify access tokens to change ownership or the system security context of the current process to perform actions and bypass access controls. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user who started it.

**Process Injection (T1631):** This technique requires SYSTEM privileges. Typically, attackers prefer to use system processes such as explorer.exe, svchost.exe, system, lsass.exe, regsvr32, rundll32, and others as targets for injection. Interesting sub-techniques of process injection seen in the wild include _**process hollowing**_ and process _**doppelganging**_ (an evasion technique that can bypass traditional security measures where malware creates a copy of a legitimate process but modifies its memory to execute malicious code).

**Event-Triggered Execution (T1546):** For example, WMI event subscription allows event filters, consumers, and bindings to be created that execute code when a defined event occurs. Another example is COM hijacking.

**Hijack Execution Flow (T1574):** The methods mentioned previously are the least probable to find in the wild for privilege escalation. To succeed, the following requisites must be met:

* Find a process that runs or will start as with other privileges with a missing DLL.
* Configure write permission on any folder where the DLL is going to be searched, possibly with the executable directory or some folder inside the SYSTEM path variable.

**Valid accounts (T1078):** Once SYSTEM or local administrator access is obtained on the compromised host, attackers may utilise credential access techniques and gain domain-privileged accounts (domain administrators, service principals, or service accounts).

**Escape to Host (T1611):** This is a rare case but worth mentioning here. Attackers may use misconfigurations in Docker or alternative containers or vulnerabilities in Docker Engine to access the host. The same applies to Kubernetes orchestrating software.

Persistence techniques such as Boot or Logon Autostart Execution (T1547), Boot or Logon Initialisation Scripts (T1037), Create or Modify System Process: Windows Service (T1543.003), Scheduled Task/Job: Scheduled Task (T1053.005) via the sc and schtasks commands, and Event Triggered Execution: COM Hijacking (T1546.015) can also be utilised for privilege escalation.

***

### Credential Access Techniques

Where credential access techniques are used to get legitimate credentials that can give access to other systems, the following are some ways in which adversaries can gather authentication details:

**Brute Force (T1110):** Multiple tools exist that can implement password guessing using pre-built dictionaries and password spraying attacks when applying the same password to multiple user accounts.

**Credentials from Password Stores (T1555):** Credentials from web browsers, Windows Credential Manager (WCM), email clients, or password managers are targeted.

**OS Credential Dumping (T1003):** This technique is often seen. Credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS) is hardly targeted by most threat actors. Tools such as procdump, Task Manager, and direct Windows API calls like MiniDumpWriteDump are used to dump the lsass.exe process. Mimikatz, LaZagne, secretsdump, CrackMapExec, and some built-in DLLs such as comsvcs.dll can either dump the lsass process themselves or use debug privileges to examine credentials inside the process memory.

**Steal or Forge Kerberos Tickets (T1558):** This is done by getting Golden or Silver Kerberos tickets or running a kerberoasting attack by eavesdropping on Kerberos tickets and proceeding with a brute-force attack.

**Modify Authentication Process (T1556):** This allowed attackers to get the cleartext passwords of users attempting to change their passwords. A technique reportedly used by Iranian APT groups to implement password filters, allowing the attacker to add a DLL to the Notification Filter.

**Unsecured Credentials (T1552):** These are a challenge for most organisations. Employees often store passwords in files or, in worse cases, IT may hardcode some credentials in a registry for maintenance and ease of operations or store API keys in configuration files

***

### Defense Evasion

While the above are common techniques attackers use,  organisations often implement security controls that can spot and prevent such activities. As a result, attackers have resorted to using defensive evasion techniques to continue their operations. A wide range of techniques can be enforced for defence evasion tactics. The following are some common examples:

**Impair Defenses (T1562):** This involves disabling or even uninstalling tools such as antivirus, modifying Windows Firewall via the netsh command, disabling Windows event logging, or compromising safe mode boot, something that ransomware groups utilise as security controls do not operate in safe mode.

**Indicator Removal (T1070):** This includes removing files with payloads, wiping event logs, timestomping (modifying the user mode timestamps of the filesystem objects), or detaching network shares.

**Hide Artifacts (T1564):** This includes the hidden NTFS attributes of files and folders, hidden users, and process argument spoofing.

**File and Directory Permissions Modification (T1222):** This technique allows attackers to access required files and folders, most frequently by running the built-in executable.

**Masquerading (T1036):** This is done by signing malicious code using metadata and signature information from a signed legitimate program, renaming system utilities like creating an instance of cmd.exe, wscript.exe, and so on, renaming services and scheduled tasks to look like legitimate ones.

**Hijack Execution Flow (T1574): I**nvolves manipulating how the operating system finds programs to run, libraries to use, and other resources such as file directories or registry keys.

**Obfuscated Files or Information (T1027):** Involves command obfuscations, such as generated variable names, encrypting the code and decrypting it during runtime, code padding (appending 0 bytes), using software packers (such as upx), or using techniques such as HTML smuggling.

Process Injection (T1055): This is used to misdirect security professionals.

**Modifying Registry (T1112).**

**Abuse Elevation Control Mechanism (T1548):** Used for bypassing the UAC technique.

**Access Token Manipulation (T1134):** Involves implementing Windows API features. It consists of token impersonation, creating processes with tokens, parent process ID (PPID) spoofing, and more.

**BITS Jobs (T1197):** Involves using BITS jobs to perform background file transfers.

**Exploitation for Defense Evasion (T1211):** This involves compromising security controls or other existing software that is out of focus and usually trusted by security teams.

By focusing on these techniques, defenders can systematically investigate suspicious activity using detection platforms like Microsoft Sentinel (KQL), Velociraptor (VQL), or Splunk (SPL). Each of these methods leaves traces that, when analysed correctly, can reveal an attacker’s activities. Applying the UKC model to this phase allows for targeted investigation and enables organisations to disrupt attackers before they can achieve their objectives.
