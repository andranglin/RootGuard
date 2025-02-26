# Evidence Collection

4.1 Volatile Data Collection

* PowerShell: netstat -ano | Out-File E:\Evidence\netstat.txt
* Velociraptor: velociraptor.exe collect -a Windows.Memory.Acquisition --output E:\Evidence\memory.bin

4.2 Non-Volatile Data Collection

* KAPE: kape.exe --tsource C: --tdest E:\Evidence --target SANS\_Triage

4.3 Memory and Disk Imaging

* FTK Imager: ftkimager.exe "PhysicalDrive0" E:\Evidence\memory.dmp --mem
