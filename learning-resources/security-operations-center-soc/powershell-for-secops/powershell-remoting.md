---
hidden: true
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

# Powershell Remoting

### Introduction

PowerShell Remoting is a feature of PowerShell that allows users to run commands and scripts on remote systems over a network. It leverages the Windows Remote Management (WinRM) protocol to establish secure, encrypted connections between systems, enabling centralised management, automation, and troubleshooting. PowerShell Remoting is particularly useful for administering multiple machines, conducting incident investigations, and performing automated tasks in large environments. Its secure communication and role-based access controls make it a powerful tool for IT administration and security operations.

### Powershell Remoting

{% code overflow="wrap" %}
```powershell
## One-To-One Remoting
$Cred = Get-Credential
Enter-PSSession -ComputerName dc01 -Credential $Cred

## One-To-Many Remoting
$Cred = Get-Credential
Invoke-Command -ComputerName dc01, sql02, web01 {Get-Service -Name W32time} -Credential $Cred
OR
Invoke-Command -ComputerName dc01, sql02, web01 {Get-Service -Name W32time} -Credential $Cred | Get-Member

## PowerShell Sessions
$Session = New-PSSession -ComputerName dc01, sql02, web01 -Credential $Cred
!
Invoke-Command -Session $Session {(Get-Service -Name W32time).Start()}
Invoke-Command -Session $Session {Get-Service -Name W32time}
!
Get-PSSession | Remove-PSSession


$UserName = "bob01"
$ComputerName = "PC01"
$Credential = Get-Credential -UserName $UserName

Enter-PSSession -ComputerName $ComputerName -Credential $Credential
```
{% endcode %}

### **Benefits of PowerShell Remoting in an InfoSec Environment**

1. **Centralised Management and Investigation**:
   * PowerShell Remoting enables SecOps teams to manage and investigate multiple endpoints from a central administrative system. This is crucial for efficiently handling large environments or distributed networks.
2. **Real-Time Threat Investigation**:
   * Allows analysts to query logs, processes, network connections, and configurations on remote systems without needing physical access, streamlining threat-hunting and incident response workflows.
3. **Automation of Security Tasks**:
   * Automates tasks such as deploying security patches, collecting forensic artifacts, or running IOC (Indicators of Compromise) scans across multiple machines simultaneously, reducing manual effort and human error.
4. **Integration with Security Frameworks**:
   * Facilitates the implementation of **MITRE ATT\&CK-based investigations**, enabling analysts to detect and respond to threats such as lateral movement (T1021.006), execution of malicious scripts (T1059.001), and more.
5. **Reduced Response Time**:
   * SecOps teams can remotely isolate compromised systems, terminate malicious processes, or apply configuration changes without delay, significantly reducing mean time to detect (MTTD) and mean time to respond (MTTR).
6. **Forensic Data Collection**:
   * Enables secure and efficient collection of forensic data (e.g., event logs, memory dumps, registry snapshots) from endpoints, providing valuable insights during incident investigations.
7. **Secure Communication**:
   * Uses **WinRM (Windows Remote Management)** with robust encryption and authentication mechanisms to ensure secure communication between systems, mitigating the risk of interception or unauthorised access.

***

### **Requirements for PowerShell Remoting in an InfoSec Environment**

1. **Secure Configuration**:
   * Enable and configure **WinRM** securely:
     * Use HTTPS for encrypted communication.
     * Restrict access to trusted hosts or networks.
   * Configure firewalls to allow traffic only on specific ports (default: TCP 5986 for HTTPS).
2. **Authentication and Authorisation**:
   * Use Kerberos or certificate-based authentication to ensure secure identity verification.
   * Implement role-based access control (RBAC) to restrict remoting access to authorised users and administrators.
3. **Logging and Monitoring**:
   * Enable PowerShell logging (`Script Block Logging`, `Module Logging`, `Transcription`) and monitor for unusual remote session activity.
   * Track relevant Windows Event IDs:
     * **Event ID 4104**: Script block execution.
     * **Event ID 4624**: Account logon (successful remote logon).
     * **Event ID 7045**: Service installation, which could indicate lateral movement.
4. **Endpoint Hardening**:
   * Harden endpoints by applying Group Policies to restrict remoting to essential use cases and prevent abuse.
   * Enforce execution policies and signed scripts to reduce the risk of malicious script execution.
5. **Operational Tools**:
   * Security tools that integrate with PowerShell Remoting, such as Microsoft Defender for Endpoint, can be used to execute commands or collect logs from endpoints during investigations.
6. **Incident Response Playbooks**:
   * Develop playbooks that detail the use of PowerShell Remoting for specific scenarios, such as memory analysis, process termination, or service inspection.
7. **Network Segmentation**:
   * Ensure that remoting is allowed only between specific admin workstations and endpoints. Block unnecessary cross-segment communication to limit lateral movement risks.
8. **Endpoint Visibility**:
   * Deploy endpoint detection and response (EDR) solutions to monitor and log all remote PowerShell activity for later analysis or real-time alerting.

***

SecOps teams can significantly enhance their ability to manage endpoints, conduct investigations, and respond to threats across the enterprise by securely configuring and effectively utilising PowerShell Remoting while maintaining a strong security posture.
