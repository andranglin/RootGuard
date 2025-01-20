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
