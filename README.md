# egnet
egnet => pronounced as "easy net" shows some tools or utilities for debugging and troubleshooting network connections, adapter, devices, etc.  

Voluntary Disclosure: The output shown for utilities mentioned below is compiled for illustration purpose only. You may not find all details in your lab/office/dungeon.   

   * [egnet](#egnet)
      * [Introductory Concepts](#introductory-concepts)
      * [Network Adapters](#network-adapters)
      * [`ifconfig`](#ifconfig)
      * [`ip`](#ip)
      * [`ipcalc`](#ipcalc)
      * [`iwconfig`](#iwconfig)
      * [`dstat`](#dstat)
      * [NS Lookup](#ns-lookup) 
      * [Resolve DNS](#resolve-dns) 
      * [`dig` into DNS](#dig-into-dns)
      * [Simple web server](#simple-web-server)
      * [Get files using `wget`](#get-files-using-wget) 
      * [The One with DNS root nameservers](#the-one-with-dns-root-nameservers) 
      * [Email](#email) 
      * [The One with SPF, DKIM and DMARK](#the-one-with-spf-dkim-and-dmark)
      * [The One with LDAP](#the-one-with-ldap)
      * [The One with RADIUS](#the-one-with-radius)
      * [The One with Security](#the-one-with-security) 
      * [The One with Wireshark](#the-one-with-wireshark) 


## Introductory Concepts 
Some [Introductory concepts in computer networking](http://intronetworks.cs.luc.edu/current/html/) online, skip this section and continue if you are already familiar with this domain or looking for the content below. A bookmark, reference or share is okay.  

If you are more comfortable reading a paper book like me, see books - [Computer Networking A Top-Down Approach 8th edition by Kurose and Rose](https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm) - they have added SDN, and [Computer Networks: A Systems Approach by Peterson and Davie](https://book.systemsapproach.org/) - they cover Congestion Control in an elegant manner.   

If you are senior undergrad/postgrad student, explore [Reproducing Networking Research](https://reproducingnetworkresearch.wordpress.com/) blog, and [paper](https://web.stanford.edu/class/cs244/papers/learning-networking-research-by-reproducing.pdf), and [Some course topics with guests](https://web.stanford.edu/class/cs244/). Visit [Barefoot](https://barefootnetworks.com/resources/worlds-fastest-most-programmable-networks/) in the age of programmable networks   


## Network Adapters
Know your network adapters: product, provider, logical names, MAC, capacity in mbps or gbps, capabilities, etc.   
Knowledge of adapter and vendor can help with device driver related issues or to update driver.   
Network adapter's logical name is visible in output of ip command.   

```
$ lshw -class network
  *-network                 
       description: Ethernet interface
       product: RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller
       vendor: Realtek Semiconductor Co., Ltd.
       physical id: 0
       bus info: pci@0000:02:00.0
       logical name: enp2s0
       version: 15
       serial: 54:bf:64:0d:d4:cc
       capacity: 1Gbit/s
       width: 64 bits
       clock: 33MHz
       capabilities: pm msi pciexpress msix bus_master cap_list ethernet physical tp mii 10bt 10bt-fd 100bt 100bt-fd 1000bt-fd autonegotiation
       configuration: autonegotiation=on broadcast=yes driver=r8169 firmware=rtl8168h-2_0.0.2 02/26/15 latency=0 link=no multicast=yes port=MII
       resources: irq:16 ioport:d000(size=256) memory:df104000-df104fff memory:df100000-df103fff
  *-network
       description: Wireless interface
       product: Wireless 8265 / 8275
       vendor: Intel Corporation
       physical id: 0
       bus info: pci@0000:03:00.0
       logical name: wlp3s0
       version: 78
       serial: 34:41:5d:b4:ce:ea
       width: 64 bits
       clock: 33MHz
       capabilities: pm msi pciexpress bus_master cap_list ethernet physical wireless
       configuration: broadcast=yes driver=iwlwifi driverversion=5.4.0-65-generic firmware=36.77d01142.0 ip=10.10.28.48 latency=0 link=yes multicast=yes wireless=IEEE 802.11
       resources: irq:130 memory:df000000-df001fff

```

## ifconfig
ifconfig - to show and manage network interface. Caution: this has been replaced by ip.   
Logical name of interface correponds to Network adapter's logical name in lshw output.   

```
$ ifconfig
enp2s0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 54:bf:64:0d:d4:cc  txqueuelen 1000  (Ethernet)
        RX packets 271060  bytes 197712851 (197.7 MB)
        RX errors 0  dropped 837  overruns 0  frame 0
        TX packets 10  bytes 180 (180.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 112695  bytes 9073702 (9.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 112695  bytes 9073702 (9.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlp3s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.105.214  netmask 255.255.0.0  broadcast 192.168.255.255
        inet6 fe80::2e9f:e4c6:8841:f732  prefixlen 64  scopeid 0x20<link>
        ether 34:41:5d:b4:ce:ea  txqueuelen 1000  (Ethernet)
        RX packets 5522437  bytes 3367406951 (3.3 GB)
        RX errors 0  dropped 642  overruns 0  frame 0
        TX packets 3673197  bytes 2487018132 (2.4 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

## ip
ip - to show and manage network interface and devices. This has replaced ifconfig command.   
Ask "man" for objects addr, link, neigh, route, maddress, vrf, etc.  

Logical name of interface correponds to Network adapter's logical name in lshw output.  
The output below is compiled for illustration purpose only. You may not find all details in your lab/office/dungeon.  
```
$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp2s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 54:bf:64:0d:d4:cc brd ff:ff:ff:ff:ff:ff
3: wlp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 34:41:5d:b4:ce:ea brd ff:ff:ff:ff:ff:ff
    inet 192.168.105.214/16 brd 192.168.255.255 scope global dynamic noprefixroute wlp3s0
       valid_lft 16074sec preferred_lft 16074sec
    inet6 fe80::2e9f:e4c6:8841:f732/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
4: gpd0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN group default qlen 500
    link/none 


$ ip -all link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp2s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 1000
    link/ether 54:bf:64:0d:d4:cc brd ff:ff:ff:ff:ff:ff
3: wlp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether 34:41:5d:b4:ce:ea brd ff:ff:ff:ff:ff:ff
4: gpd0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 500
    link/none 


$ ip neigh
192.168.0.1 dev wlp3s0 lladdr 88:b1:e1:28:6f:e1 REACHABLE


$ ip route
default via 192.168.0.1 dev wlp3s0 proto dhcp metric 600 
169.254.0.0/16 dev wlp3s0 scope link metric 1000 
192.168.0.0/16 dev wlp3s0 proto kernel scope link src 192.168.105.214 metric 600 

```
The above ip options are available on modern switching and routing hardware supporting Software Defined Networking (SDN).  

## ipcalc

Know - IP addressing using ipcalc  
```
$ ipcalc 192.168.0.1/24
Address:   192.168.0.1          11000000.10101000.00000000. 00000001
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
=>
Network:   192.168.0.0/24       11000000.10101000.00000000. 00000000
HostMin:   192.168.0.1          11000000.10101000.00000000. 00000001
HostMax:   192.168.0.254        11000000.10101000.00000000. 11111110
Broadcast: 192.168.0.255        11000000.10101000.00000000. 11111111
Hosts/Net: 254                   Class C, Private Internet

$ ipcalc 10.10.50.1/24
Address:   10.10.50.1           00001010.00001010.00110010. 00000001
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111. 00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000. 11111111
=>
Network:   10.10.50.0/24        00001010.00001010.00110010. 00000000
HostMin:   10.10.50.1           00001010.00001010.00110010. 00000001
HostMax:   10.10.50.254         00001010.00001010.00110010. 11111110
Broadcast: 10.10.50.255         00001010.00001010.00110010. 11111111
Hosts/Net: 254                   Class A, Private Internet
```

----

## iwconfig 

View and manage Wireless network settings, similar to ifconfig, this one is for wireless  
```
$ iwconfig
lo        no wireless extensions.

wlp3s0    IEEE 802.11  ESSID:"Test"  
          Mode:Managed  Frequency:5.18 GHz  Access Point: 88:B1:E1:28:6A:60   
          Bit Rate=780 Mb/s   Tx-Power=22 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          Link Quality=51/70  Signal level=-59 dBm  
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:50   Missed beacon:0

enp2s0    no wireless extensions.

gpd0      no wireless extensions.
```

----

## dstat 

Use **dstat** - a tool for generating system resource statistics such as cpu usage, disk read/write, network data received/sent, etc. To exit type Ctrl+C.    
```
$ dstat
You did not select any stats, using -cdngy by default.
--total-cpu-usage-- -dsk/total- -net/total- ---paging-- ---system--
usr sys idl wai stl| read  writ| recv  send|  in   out | int   csw 
 27   8  64   0   0|5502B   24k|   0     0 |   0     0 | 649  1159 
  2   1  96   1   0|   0    60k| 226B  234B|   0     0 |2176  3796 
  3   1  96   0   0|   0     0 | 303B  405B|   0     0 |2150  3753 
  3   1  95   0   0|   0     0 |1266B 1246B|   0     0 |2272  3889 
  3   1  96   0   0|   0     0 | 984B  786B|   0     0 |2378  3952 ^C

```
Only looking for network bytes receives and sent  
```
$ dstat -n
-net/total-
 recv  send
   0     0 
2439B  943B
   0     0 
  66B   94B
 261B  405B^C

```

----

## NS Lookup  

```
$ nslookup
> set q=ANY
> iitjammu.ac.in 
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
iitjammu.ac.in
	origin = ns1.iitjammu.ac.in
	mail addr = cc\@iitjammu.ac.in
	serial = 2020123155
	refresh = 2800
	retry = 3600
	expire = 1604800
	minimum = 86400
iitjammu.ac.in	nameserver = ns1.iitjammu.ac.in.
iitjammu.ac.in	nameserver = ns3.iitjammu.ac.in.
iitjammu.ac.in	nameserver = ns2.iitjammu.ac.in.
Name:	iitjammu.ac.in
Address: 14.139.53.140
iitjammu.ac.in	mail exchanger = 5 ALT2.ASPMX.L.GOOGLE.COM.
iitjammu.ac.in	mail exchanger = 5 ALT1.ASPMX.L.GOOGLE.COM.
iitjammu.ac.in	mail exchanger = 3 ASPMX.L.GOOGLE.COM.
iitjammu.ac.in	text = "google-site-verification=FbfesMgJWj_x98cASxF4B3J5t9wr0ccF_LXLmKZI1d4"
iitjammu.ac.in	text = "MS=0803D61A210443353771F37FAB6297221EF56F2E" "3600"
iitjammu.ac.in	text = "v=spf1 include:_spf.google.com ~all"

Authoritative answers can be found from:                         <== sample output, not guaranteed the same 
ns1.iitjammu.ac.in	internet address = 14.139.53.132
ns2.iitjammu.ac.in	internet address = 14.139.53.133
ns3.iitjammu.ac.in	internet address = 182.76.238.118
> exit
```

----

## Resolve DNS  

You can check /etc/resolve.conf or use resolvectl Domain Names using resolvectl.  

```
$ man resolvectl 

$ resolvectl dns
Global:
Link 2 (eno2):
Link 3 (eno1): 14.139.53.132 8.8.8.8          <== list of DNS servers, note public DNS 

$ resolvectl status
Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
resolv.conf mode: stub

Link 2 (eno2)
Current Scopes: none
     Protocols: -DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported

Link 3 (eno1)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 14.139.53.132
       DNS Servers: 14.139.53.132 8.8.8.8
        DNS Domain: iitjammu.ac.in
```

----

## dig into DNS

Dig into DNS and query A (IP Address), SOA (Start of Authority - admin record), NS (name server), MX (mail server), TXT (domain ownership, to prevent mail spam), CNAME (canonical name or alias) records  

$ dig @server hostname recort_type

```
dig iitjammu.ac.in MX

; <<>> DiG 9.16.1-Ubuntu <<>> iitjammu.ac.in MX
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10684
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;iitjammu.ac.in.			IN	MX

;; ANSWER SECTION:
iitjammu.ac.in.		8600	IN	MX	3 ASPMX.L.GOOGLE.COM.
iitjammu.ac.in.		8600	IN	MX	5 ALT1.ASPMX.L.GOOGLE.COM.
iitjammu.ac.in.		8600	IN	MX	5 ALT2.ASPMX.L.GOOGLE.COM.

;; Query time: 27 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Sun Feb 07 16:56:34 IST 2021
;; MSG SIZE  rcvd: 119

```

----
Use dig to query hostname using public DNS   
```
$ dig @8.8.8.8 iitjammu.ac.in

; <<>> DiG 9.16.1-Ubuntu <<>> @8.8.8.8 iitjammu.ac.in
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52538
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;iitjammu.ac.in.			IN	A

;; ANSWER SECTION:
iitjammu.ac.in.		8599	IN	A	14.139.53.140

;; Query time: 463 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Fri Feb 12 14:25:35 IST 2021
;; MSG SIZE  rcvd: 59

```

Use dig to find DNS trace leading to hostname (like traceroute)   
Pay attension to root name servers, [DNS registrar](https://www.cloudflare.com/en-gb/learning/dns/glossary/what-is-a-domain-name-registrar/), and intermediate authoritative servers.  
This information is in public domain. DNS is a global public directory of public IPs and hostnames.   

```
$ dig +trace iitjammu.ac.in

; <<>> DiG 9.16.1-Ubuntu <<>> +trace iitjammu.ac.in
;; global options: +cmd
.			72604	IN	NS	e.root-servers.net.
.			72604	IN	NS	j.root-servers.net.
.			72604	IN	NS	c.root-servers.net.
.			72604	IN	NS	h.root-servers.net.
.			72604	IN	NS	a.root-servers.net.
.			72604	IN	NS	b.root-servers.net.
.			72604	IN	NS	m.root-servers.net.
.			72604	IN	NS	k.root-servers.net.
.			72604	IN	NS	g.root-servers.net.
.			72604	IN	NS	i.root-servers.net.
.			72604	IN	NS	f.root-servers.net.
.			72604	IN	NS	l.root-servers.net.
.			72604	IN	NS	d.root-servers.net.
;; Received 262 bytes from 127.0.0.53#53(127.0.0.53) in 7 ms

in.			172800	IN	NS	ns1.registry.in.
in.			172800	IN	NS	ns2.registry.in.
in.			172800	IN	NS	ns3.registry.in.
in.			172800	IN	NS	ns4.registry.in.
in.			172800	IN	NS	ns5.registry.in.
in.			172800	IN	NS	ns6.registry.in.
in.			86400	IN	DS	54739 8 1 2B5CA455A0E65769FF9DF9E75EC40EE1EC1CDCA9
in.			86400	IN	DS	54739 8 2 9F122CFD6604AE6DEDA0FE09F27BE340A318F06AFAC11714A73409D4 3136472C
in.			86400	IN	RRSIG	DS 8 1 86400 20210225050000 20210212040000 42351 . lgk6+SUs00ldOZQLKKvskdt9680VM6ShM5aFmpp+LNsrHzMIFufwQ592 wOqMOxRcdpvjf6W3PvNNZ1SYeWj3ETBZAwRUicNbfaLAv3aVjpO/Rjke VkHt8h8b5AUrFqG3wPbmmYegESbdbg1MphFovL/LP/0b+HW1/RKcX1Wj OPHmwF9VTrbFovqxULB0M5pTnNqisLK3nYYFLLnrNVvhlyo+vFkmMY3/ ZYQCt0a+KlgS5efJEuKCAoxruICkOFh9fbCWiJtKGfYcKbNgfA4kZMe1 HzE1V9+OG/ctnwCJNdFyGP2hs4z1K8zPwJwBNFZa6d54VpCDHLbWgR2c gRQ19w==
;; Received 795 bytes from 199.7.91.13#53(d.root-servers.net) in 279 ms

iitjammu.ac.in.		3600	IN	NS	ns2.iitjammu.ac.in.
iitjammu.ac.in.		3600	IN	NS	ns1.iitjammu.ac.in.
idj3ou7anjce3n70hpktjgs1q54d9usj.ac.in.	1800 IN	NSEC3 1 1 1 F7BDE4B2 TV5S7T20F21KQV26R05RHMAECLP59H6U NS SOA RRSIG DNSKEY NSEC3PARAM TYPE65534
idj3ou7anjce3n70hpktjgs1q54d9usj.ac.in.	1800 IN	RRSIG NSEC3 8 3 1800 20210311064755 20210209054755 5223 ac.in. WYooneOeJLAXxPUx8rxpFg8Ncvmairb6Ja4k4n9X3kClIrpgCxd2Cdn0 hHCBg+7ieNAf3j7E438d/oKFlsmpdESd3/TGzzy+3GZUwPKxJWGs3/xs QSEngsiaiJh2BxbxPMKW+TkJ+NfVQuYWhGwmGxasebov5L3yBMRueGOe ailqHPZwM8j5PkJGLdKVX+YZbun9WJfzWZw8hMQ1AX4coQ==
;; Received 426 bytes from 37.209.196.12#53(ns3.registry.in) in 47 ms

iitjammu.ac.in.		8600	IN	A	14.139.53.140
iitjammu.ac.in.		8600	IN	NS	ns1.iitjammu.ac.in.
iitjammu.ac.in.		8600	IN	NS	ns2.iitjammu.ac.in.
iitjammu.ac.in.		8600	IN	NS	ns3.iitjammu.ac.in.
;; Received 189 bytes from 14.139.53.133#53(ns2.iitjammu.ac.in) in 3 ms

```

----

Public DNS  
Type in web browser: 1.1.1.1 or 8.8.8.8  

----

## Simple web server

One line webserver => a great and simplest way to show files from a directory or local share.   
Note the directory you start this server from and the content you want to share locally.   
```
$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [03/Feb/2021 23:33:21] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [03/Feb/2021 23:33:31] "GET /myvideos/ HTTP/1.1" 200 -
127.0.0.1 - - [03/Feb/2021 23:33:36] "GET /Downloads/ HTTP/1.1" 200 -
^C 
Keyboard interrupt received, exiting.

```
The webserver started above can be opened in a web browser: http://0.0.0.0:8000/  
This page can be opened before you close the server using Ctrl+C.  

----

Where and how to know more about /proc?  

[Cheese on /proc](https://www.kernel.org/doc/Documentation/filesystems/proc.txt)   

----

## Get files using wget 

You can download files or documentation with large number of files using **wget**. This is very much like your own web-doc-ripper!   

```
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://developer.android.com/reference/packages
```

## The One with DNS root nameservers  

Dyno or DNS remains one of the most interesting topics in networking.    

Do you know each DNS resolver knows IP addresses of DNS root nameservers always! This is not a new thing, this has always been the case. This info is actually hardwired or better [hardcoded into BIND-9](https://gitlab.isc.org/isc-projects/bind9/-/blame/4c3b063ef8bd6e47b13c1dac3087daa1301a78ac/lib/dns/rootns.c#L37-80)     
You can find A type DNS records for these 13 root nameservers named from A to M (as on Jan 2022).   

Note:- BIND (Berkeley Internet Name Domain) is an implementation of naming service or DNS used in our end-point devices, networks and to connect or bind the internet. [BIND source code](https://gitlab.isc.org/isc-projects/bind9) is hosted by ISC (Internet Systems Consortium). It was developed in UCB in 1984 and later maintained by ISC.     


## Email  

* Gmail: [dots in username](https://gmail.googleblog.com/2008/03/2-hidden-ways-to-get-more-from-your.html) do not matter for @gmail.com domain. Where else you see this in action? IRCTC emails!  
* Gmail: [plus something in username](https://gmail.googleblog.com/2008/03/2-hidden-ways-to-get-more-from-your.html) can be cool for @gmail.com domain.  


## The One with SPF DKIM and DMARK 

While you may have seen email Spam, you should be familiar with SPF, DKIM and DMARK records.  

A comic take on [SPF and DKIM](https://wizardzines.com/comics/spf-dkim/) by Julia/bork   

Sender Policy Framework - [SPF](https://www.dmarcanalyzer.com/spf/)   

Domain Keys Identified Mail - [DKIM](https://support.google.com/a/answer/180504?hl=en&ref_topic=7564555) and check [DKIM](https://www.dmarcanalyzer.com/dkim/) records   

Domain-based Message Authentication, Reporting, and Conformance - [DMARC](https://support.google.com/a/answer/2466563?hl=en) and check [DMARK](https://www.dmarcanalyzer.com/dmarc/) records   

Sample yml files with "Show Original" option from mail client - adding soon    

## The One with LDAP 

To query and backup/dump LDIF tree:    
```
ldapsearch -x -b "dc=iitx,dc=ac,dc=in" -H ldap://10.10.10.10 -D "cn=admin,dc=iitx,dc=ac,dc=in" -W > backup.ldif  
```
This can be useful to create another instance of LDAP. You need to mention root DN / domain name, LDAP server IP and admin user.    

Sysad should practice and know LDAP related [command line tools](https://docs.oracle.com/cd/A97630_01/network.920/a96579/comtools.htm) to query, add, delete, modify LDAP entries. It's a different experience with command line :) and you can write scripts to automate the housekeeping!    

[Manage LDAP entries using LDAP Account Manager (LAM)](https://www.ldap-account-manager.org/lamcms/) and [Web-based LDAP Schema admin](http://phpldapadmin.sourceforge.net/wiki/index.php/Main_Page)   

## The One with RADIUS 

In network security, **AAA** term is used as an abstraction for authentication, authorization and accounting purposes in relation with WPA2-Enterprise or 802.1x standard for security. RADIUS (Remote Access Dial-In User Service) promises to provide this gold standard of security.    
To provide identity (IDP), RADIUS is often used with LDAP. This combination is definitely fire for sysad not flower even in 2022.    

Relevant posts:    
1. [Cloud Radius](https://www.cloudradius.com/ldap-vs-radius/)    
2. [OpenLDAP](https://wiki.freeradius.org/building/openldap), [FreeRadius setup](https://laravel-example.blogspot.com/2019/01/setup-freeradius-authentication-with.html) and [LAM](https://www.ldap-account-manager.org/static/doc/manual-onePage/index.html)   

## The One with Security 

Some [security-related primer](http://intronetworks.cs.luc.edu/current/html/security.html) and [SSH and TLS](http://intronetworks.cs.luc.edu/current/html/publickey.html#ssh-and-tls)   

Prof Wenliang Du's lab manual (Syracuse Univ) is one of the best ways to study, introduce, or teach security in labs.   

Note:- There is a difference between Satefy and Security. Both are not the same. I believe no language is so poor to have two words for the exact same meaning.   

---- 

## The One with Wireshark 

It is fun to see packets down to protocol level using wireshark - realtime packets or through a saved pcapng file.   

[Download wireshark](https://www.wireshark.org/download.html) | [Docs](https://www.wireshark.org/docs/)   
Start wireshark with root, open a web browser and visit a website. Now, see the packets in wireshark.   
You can filter using a protocol, analyze packets - byte stream or different headers and payload with them.   

