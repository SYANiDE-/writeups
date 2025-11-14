When I am working in a Kerberos realm, there are a few things I do as a collection of standard procedure on any given engagement.

1. `/etc/hosts`: Add hostname mappings to IPs, and for DCs, explode every component of the DCs FQDN and associate it to the IP of the domain controller
2. `/etc/resolv.conf`: map the `domain` and `nameserver` entries to the primary domain and DC 
3. `/etc/krb5.conf`: Generate a new `krb5.conf`, I have a utility I wrote that generates a new one
4. timesync with the DC I am working with (at any given time).

These steps enable `linux` toolchains that are designed to work within a Kerberos realm, such as (just to name a few):

* [impacket](https://github.com/fortra/impacket)
* [bloodyAD](https://github.com/CravateRouge/bloodyAD)
* [powerview.py](https://github.com/aniqfakhrul/powerview.py)
* [bloodhound-python](https://github.com/dirkjanm/BloodHound.py/tree/master) / [bloodhound-ce-python](https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce)
* many, many others

There are many advantages to working from a primarily `linux`-based workflow, such as avoiding dropping files on disk (i.e., `mimikatz`, `rubeus.exe`,`certify` etc.), avoiding `applocker` policies or `Defender`, wonky shells, etc.  

## /etc/hosts

Host entries in `/etc/hosts` should follow a pattern of most-descriptive to least-descriptive.  For example, a domain controller that serves as KDC for the realm would have a host entry like follows:

```
10.1.2.3 dc1.example.com example.com example dc1
```

Some tools and some protocols may only send part or all of the FQDN, an entry like above ensures that no matter the format of the request, the IP is the one that handles the request for that realm.

## /etc/resolv.conf

Consult the [manpage](https://man7.org/linux/man-pages/man5/resolv.conf.5.html) or, a slightly more humanized conversation around [resolv.conf usage](https://www.baeldung.com/linux/etc-resolv-conf-file)

But two entries I like to use as a baseline are the `nameserver` and `search` configuration options, and typically I will make these entries the topmost entries above all others so that they are preferred:

```
search example.com
nameserver 10.1.2.3
```


## /etc/krb5.conf

I have a [utility I wrote](https://github.com/SYANiDE-/make_krb5.conf) for quickly building out the `/etc/krb5.conf`.  Automate the boring they say. 

The `-d` option can take a comma-delimited list of DC FQDNs, which is useful in cases where you need your `krb5.conf` to handle multiple realms.  The first DC specified in the list will be the default realm.

Example:

```sh
sudo make_krb5.conf.py -d dc1.example.com,dc4.dev.example.com,dc2.engineering.example.com -w
```

Generates and writes a new `/etc/krb5.conf` like so:

```
kdc = FILE:/var/log/krb5_kdc.log
admin-server = FILE:/var/log/krb5_admin-server.log
default = FILE:/var/log/krb5_default.log

[libdefaults]
        default_realm = EXAMPLE.COM
        dns_lookup_realm = false
        dns_lookup_kdc = false
        # dns_uri_lookup = false  ## use this when trying to troubleshoot
# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false
# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
    EXAMPLE.COM = {
        kdc = dc1.example.com:88
        admin_server = dc1.example.com
        password_server = dc1.example.com
        default_domain = example.com
    }        
    DEV.EXAMPLE.COM = {
        kdc = dc4.dev.example.com:88
        admin_server = dc4.dev.example.com
        password_server = dc4.dev.example.com
        default_domain = dev.example.com
    }        
    ENGINEERING.EXAMPLE.COM = {
        kdc = dc2.engineering.example.com:88
        admin_server = dc2.engineering.example.com
        password_server = dc2.engineering.example.com
        default_domain = engineering.example.com
    }        

[domain_realm]
    example.com = EXAMPLE.COM
    .example.com = EXAMPLE.COM        
    dev.example.com = DEV.EXAMPLE.COM
    .dev.example.com = DEV.EXAMPLE.COM        
    engineering.example.com = ENGINEERING.EXAMPLE.COM
    .engineering.example.com = ENGINEERING.EXAMPLE.COM                

[+] Writing /etc/krb5.conf

```

## timesync with a DC

Anyone that has ever tried to authenticate to a DC using Kerberos, and the DC is in a different time zone, knows of the pain and struggle:

Example:

```sh
┌──(notroot㉿elysium)-[(master) 1 ~/htb/machines/hercules]
└─$ impacket-getTGT example.com/g.oldie:'RuffigeKru#2'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Now normally, we would just disable `ntpd` :

```
## one of the following, depending on what controls you
sudo timedatectl set-ntp false
sudo systemctl stop ntp.service
```

and sync the time with the DC using `ntpdate`:
```
sudo ntpdate -u dc.example.com
```

However in my case, none of this works like above, because my Kali instance is in `Virtualbox`, and it is the one in control of time syncronization.  

Its a little nuanced.  The short of it is that `virtualbox-guest-utils` service (systemd) is the one that calls  `/usr/sbin/VBoxService`, which handles (among a lot Guest Utils things), keeping the Guest OS time syncronized to the Host OS hypervisor.  I do need Guest Utils things, in fact all of them, with the exception of timesync (on these hacking Kerberos realm occasions).

The service binary `/usr/sbin/VBoxService` can actually be called with an argument that disables time syncronization, but there is not interface for/to it through the `systemd` wrapper around it, or the init file that starts it.  You can't call `virtualbox-guest-utils` with any meaningful argument/environment variable to get passed to it being started, and there's no way of controlling the flag at the systemd unit.  

So what I did was come up with another unit file, and some modifications to the init file, so that Guest Utils can be kept running but without time syncronization.  That way just the time syncronization could be toggled.

Fully documented and repeatable [here](https://github.com/SYANiDE-/tooling/tree/main/vbox-disable-timesync)

But basically with it, I can (effectively) disable just the timesync to the Host OS by starting the new service, then perform an `ntpdate -u [otherdomain]` as normal, and time synced to the otherdomain persists until reboot (or the service is stopped, forcing the real `virtualbox-guest-utils` to start again).

```sh
## decouple from VBox timesync
sudo systemctl start vbox-disable-timesync.service
sudo ntpdate -u dc1.example.com

## recouple
sudo systemctl stop vbox-disable-timesync.service
```

