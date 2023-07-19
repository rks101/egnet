# egnet
egnet => pronounced as "easy net" shows some tools or utilities for debugging and troubleshooting network connections, adapters, devices, etc., DNS, and other sysadmin-related self-notes.    

These notes first came out of my habit of writing them down in one place and referencing them later anytime, anywhere. Later, I got involved more while answering some questions often and started asking people to refer to these notes.    

Voluntary Disclosure: The output shown for utilities mentioned below is compiled for illustration purposes only. You may not find all details in your lab/office/dormitory.   

   * [egnet](#egnet)
      * [Introductory Concepts](#introductory-concepts)
      * [PoE](#poe)   
      * [Network Adapters](#network-adapters)
      * [`ifconfig`](#ifconfig) 
      * [`ip`](#ip)
      * [`ipcalc`](#ipcalc)
      * [`iwconfig`](#iwconfig)
      * [`iwlist`](#iwlist)
      * [`dstat`](#dstat)
      * [NS Lookup](#ns-lookup) 
      * [Resolve DNS](#resolve-dns) 
      * [The One with DNS root nameservers](#the-one-with-dns-root-nameservers) 
      * [`dig` into DNS](#dig-into-dns) 
      * [Monitor Network](#monitor-network) 
      * [Know sub-domains they don't give you](#know-sub\-domains) 
      * [Simple web server](#simple-web-server)
      * [Get files using `wget`](#get-files-using-wget) 
      * [Email](#email) 
      * [The One with SPF, DKIM and DMARK](#the-one-with-spf-dkim-and-dmark)
      * [The One with LDAP](#the-one-with-ldap)
      * [The One with RADIUS](#the-one-with-radius)
      * [The One with Security](#the-one-with-security) 
      * [The One with SSL/TLS Certificates](#ssl-tls-certificates)
      * [QUIC](#quic)   
      * [The One with Wireshark](#the-one-with-wireshark)  
      * [The One with Disaster Recovery](#the-one-with-disaster-recovery)
      * [The One with VPN](#the-one-with-vpn) 


## Introductory Concepts 
Some [Introductory concepts in computer networking](http://intronetworks.cs.luc.edu/current/html/) online, skip this section, and continue if you are already familiar with this domain or looking for the content below. A bookmark, reference, or share is okay.  

If you are more comfortable reading a paper book like me, see books - [Computer Networking A Top-Down Approach 8th edition by Kurose and Rose](https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm) - they have added SDN, and [Computer Networks: A Systems Approach by Peterson and Davie](https://book.systemsapproach.org/) - they cover Congestion Control in an elegant manner. Another reference book is [Computer & Internet Security: A Hands-on Approach by Wenliang Du](https://amzn.eu/d/hqd1Ncl) from Syracuse University and maintains [Seed Labs](https://seedsecuritylabs.org/) to combine theory and practice.     

If you are a senior undergrad/postgrad student, explore [Reproducing Networking Research](https://reproducingnetworkresearch.wordpress.com/) blog and [paper](https://web.stanford.edu/class/cs244/papers/learning-networking-research-by-reproducing.pdf), and [Some course topics with guests](https://web.stanford.edu/class/cs244/). Visit [Barefoot](https://barefootnetworks.com/resources/worlds-fastest-most-programmable-networks/) in the age of programmable networks   

You do not need to be a Computer Scientist or Computer Engineering graduate to understand and appreciate these topics 😅   

---- 

## PoE    
Power over Ethernet or PoE can provide DC power over ethernet cables - power and network over a single wire. It's cost-effective. PoE is used for Access Points (APs), IP cameras, and phones. The switch should have PoE ports enabled.    

[What is PoE?](https://notes.networklessons.com/poe-what-is-it)    
[Active or Standardized PoE](https://notes.networklessons.com/poe-standards-based)    
[Passive PoE](https://notes.networklessons.com/poe-passive) - used in PoE injectors and supplied DC current to the device is fixed.   

---- 

## Network Adapters
Know your network adapters: product, provider, logical names, MAC, capacity in Mbps or Gbps, capabilities, etc.   
Knowledge of adapters and vendors can help with device driver-related issues or update drivers.   
The network adapter's logical name is visible in the ip command output.   

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
---- 

## `ifconfig`   

`ifconfig` can be used to show and manage the network interface. Caution: this has been replaced by ip.   
The logical name of the interface corresponds to the Network adapter's logical name in `lshw` output.   

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
---- 

## `ip`   

ip - to show and manage network interface and devices. This has replaced ifconfig command.   
Ask "man" for objects addr, link, neigh, route, maddress, vrf, etc.  

The logical name of the interface corresponds to the Network adapter's logical name in lshw output.  
The output below is compiled for illustration purposes only. You may not find all details in your lab/office/dungeon.  
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

---- 

## `ipcalc`   

Note:-    
1. Classful addressing was used well before 1993 with Class A, B, C, D (Multi-cast), and E (reserved) IP addresses of 32 bits. Class A, B, and C had 8, 16, and 24 bits for the network part and the remaining bits for host iP addresses. To accommodate the need to assign IP addresses for a flexible number of hosts and to manage them efficiently, Classless Inter-Domain Routing (CIDR) notation or /n notation came into existence.    
2. There are three ranges of special private addresses (that are not used to host a service publicly):    
10.x.x.x, 172.16.x.x -to- 172.31.x.x and 192.168.x.x    or better in CIDR notation 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16    
3. Localhost or loopback address: 127.0.0.0/8 or 127.0.0.1 is used for testing locally on a system. It is configured in software such that it does not leave the network adapter buffers. It is used to test local servers or services deployed. e.g., 127.0.0.1:8000 (when some service is running on port 8000)     
4. Three private address ranges (all IPs in them) are not routed outside the local network because if response packets are routed back to these IPs, the router would not know not whom to forward to. In such cases, network address translation (NAT) is required.     

You can learn a few things with `ipcalc` on IP addressing.      

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

The graphical counterpart of `ipcalc` is `ipqalc` 

----

## `iwconfig`   

View and manage Wireless network settings, similar to ifconfig; this command is for wireless.  
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

## `iwlist`    

Work with wireless adapter settings and parameters (scanning, frequency, bitrate, power (on/off), transmit-power, auth) to get detailed wireless information from a wireless interface    

```
$ iwlist wlp0s20f3 scanning
wlp0s20f3  Scan completed :
          Cell 01 - Address: 88:B1:E1:28:AD:81
                    Channel:48
                    Frequency:5.24 GHz (Channel 48)
                    Quality=63/70  Signal level=-47 dBm  
                    Encryption key:on
                    ESSID:"IIT_JMU"
                    Bit Rates:12 Mb/s; 18 Mb/s; 24 Mb/s; 36 Mb/s; 48 Mb/s
                              54 Mb/s
                    Mode:Master
                    Extra:tsf=0000027eee5ce0ec
                    Extra: Last beacon: 105444ms ago
                    IE: Unknown: 00074949545F4A4D55
                    IE: Unknown: 01069824B048606C
                    IE: Unknown: 030130
                    IE: Unknown: 0754494E2024011E28011E2C011E30011E3401173801173C01174001176xxxx truncated 
		    IE: Unknown: 0B05040007127A
                    IE: Unknown: 2D1AEF0903FFFFFFFF00000000000000000100000000000000000000
                    IE: Unknown: 3D1630070400000000000000000000000000000000000000
                    IE: Unknown: 7F080400000200000040
                    IE: Unknown: BF0CF2798333AAFF0000AAFF0020
                    IE: Unknown: C005000000FCFF
                    IE: Unknown: DD180050F2020101840003A4000027A4000042435E0062322F00
                    IE: Unknown: DD3900117400030032363333613362333164326164333137386631393264xxxx truncated 
		    IE: Unknown: DD0C001174000700030400000004
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : 802.1x
                       Preauthentication Supported
```
See channel frequency (in [2.4 Ghz and 5 Ghz RF bands](https://www.intel.in/content/www/in/en/products/docs/wireless/2-4-vs-5ghz.html))     
```
$ iwlist wlp0s20f3 frequency
wlp0s20f3  32 channels in total; available frequencies :
          Channel 01 : 2.412 GHz
          Channel 02 : 2.417 GHz
          Channel 03 : 2.422 GHz
          Channel 04 : 2.427 GHz
          Channel 05 : 2.432 GHz
          Channel 06 : 2.437 GHz
          Channel 07 : 2.442 GHz
          Channel 08 : 2.447 GHz
          Channel 09 : 2.452 GHz
          Channel 10 : 2.457 GHz
          Channel 11 : 2.462 GHz
          Channel 12 : 2.467 GHz
          Channel 13 : 2.472 GHz
          Channel 36 : 5.18 GHz
          Channel 40 : 5.2 GHz
          Channel 44 : 5.22 GHz
          Channel 48 : 5.24 GHz
          Channel 52 : 5.26 GHz
          Channel 56 : 5.28 GHz
          Channel 60 : 5.3 GHz
          Channel 64 : 5.32 GHz
          Channel 100 : 5.5 GHz
          Channel 104 : 5.52 GHz
          Channel 108 : 5.54 GHz
          Channel 112 : 5.56 GHz
          Channel 116 : 5.58 GHz
          Channel 120 : 5.6 GHz
          Channel 124 : 5.62 GHz
          Channel 128 : 5.64 GHz
          Channel 132 : 5.66 GHz
          Channel 136 : 5.68 GHz
          Channel 140 : 5.7 GHz
          Current Frequency:5.24 GHz (Channel 48)

```
Transmit power    
```
$ iwlist wlp0s20f3 txpower
wlp0s20f3  unknown transmit-power information.

          Current Tx-Power=22 dBm  	(158 mW)
```

----

## dstat   

Use **dstat** - a tool for generating system resource statistics such as CPU usage, disk read/write, network data received/sent, etc. To exit type Ctrl+C.    
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
Only looking for network bytes received and sent =>  
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

Another way to nslookup: use -debug for DNS record type.   

```
$ nslookup -type=ns -debug iitjammu.ac.in 
Server:		127.0.0.53
Address:	127.0.0.53#53

------------
    QUESTIONS:
	iitjammu.ac.in, type = NS, class = IN
    ANSWERS:
    ->  iitjammu.ac.in
	nameserver = ns3.iitjammu.ac.in.
	ttl = 8600
    ->  iitjammu.ac.in
	nameserver = ns1.iitjammu.ac.in.
	ttl = 8600
    ->  iitjammu.ac.in
	nameserver = ns2.iitjammu.ac.in.
	ttl = 8600
    AUTHORITY RECORDS:
    ADDITIONAL RECORDS:
    ->  ns1.iitjammu.ac.in
	internet address = 14.139.53.132
	ttl = 8600
    ->  ns2.iitjammu.ac.in
	internet address = 14.139.53.133
	ttl = 8600
    ->  ns3.iitjammu.ac.in
	internet address = 182.76.238.118
	ttl = 8600
------------
Non-authoritative answer:
iitjammu.ac.in	nameserver = ns3.iitjammu.ac.in.
iitjammu.ac.in	nameserver = ns1.iitjammu.ac.in.
iitjammu.ac.in	nameserver = ns2.iitjammu.ac.in.

Authoritative answers can be found from:
ns1.iitjammu.ac.in	internet address = 14.139.53.132
ns2.iitjammu.ac.in	internet address = 14.139.53.133
ns3.iitjammu.ac.in	internet address = 182.76.238.118
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

## The One with DNS root nameservers  

Dyno or DNS remains one of the most interesting topics in networking.    

Do you know each DNS resolver knows the IP addresses of DNS root nameservers always! This is not a new thing; this has always been the case. This info is actually hardwired or better [hardcoded into BIND-9](https://gitlab.isc.org/isc-projects/bind9/-/blame/4c3b063ef8bd6e47b13c1dac3087daa1301a78ac/lib/dns/rootns.c#L37-80). Look at this code, there are 13 DNS root nameservers, and the names are not case-sensitive.     
You can find A type DNS records for these 13 root nameservers named from a to m (as on Jan 2022).    

[IANA](https://www.iana.org/) has listed the [root name servers](https://www.iana.org/domains/root/servers), and [DNS root hint and root zone files](https://www.iana.org/domains/root/files). [Map](https://www.google.com/maps/d/u/0/viewer?mid=1LcHEpzl-7RzziWzDa4h3BxJcbEo&hl=en&ll=24.71341537554179%2C36.13137070989961&z=2) of geographically distributed root name servers reachable using anycast - the same IP mapped to multiple DNS root servers - the one reachable first is returned in DNS query's answer section.    

Note:- BIND (Berkeley Internet Name Domain) is an implementation of naming service or DNS used in our end-point devices and networks to connect or bind the internet. [BIND source code](https://gitlab.isc.org/isc-projects/bind9) is hosted by ISC (Internet Systems Consortium). It was developed in UCB in 1984 and later maintained by ISC.     

Note:- How do we/local DNS servers reach a particular root nameserver while they all are managed by different entities globally? Using IP Anycast => As long as we get a response from any of them is fine to go ahead. No broadcast query or multi-cast query is used to locate a root nameserver.    

To get a list of root nameservers and their IP addresses, just type dig and see the answer section and additional sections.   

```
$ dig 

; <<>> DiG 9.18.12-1-Debian <<>>
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49409
;; flags: qr rd ra; QUERY: 1, ANSWER: 13, AUTHORITY: 0, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;.                              IN      NS

;; ANSWER SECTION:
.                       7173    IN      NS      c.root-servers.net.
.                       7173    IN      NS      e.root-servers.net.
.                       7173    IN      NS      i.root-servers.net.
.                       7173    IN      NS      b.root-servers.net.
.                       7173    IN      NS      j.root-servers.net.
.                       7173    IN      NS      g.root-servers.net.
.                       7173    IN      NS      a.root-servers.net.
.                       7173    IN      NS      d.root-servers.net.
.                       7173    IN      NS      l.root-servers.net.
.                       7173    IN      NS      k.root-servers.net.
.                       7173    IN      NS      f.root-servers.net.
.                       7173    IN      NS      h.root-servers.net.
.                       7173    IN      NS      m.root-servers.net.

;; ADDITIONAL SECTION:
i.root-servers.net.     7173    IN      AAAA    2001:7fe::53
d.root-servers.net.     7173    IN      A       199.7.91.13
m.root-servers.net.     7173    IN      A       202.12.27.33
b.root-servers.net.     7173    IN      A       199.9.14.201
g.root-servers.net.     7173    IN      A       192.112.36.4
m.root-servers.net.     7173    IN      AAAA    2001:dc3::35
e.root-servers.net.     7173    IN      A       192.203.230.10
l.root-servers.net.     7173    IN      AAAA    2001:500:9f::42
e.root-servers.net.     7173    IN      AAAA    2001:500:a8::e
f.root-servers.net.     7173    IN      A       192.5.5.241
h.root-servers.net.     7173    IN      A       198.97.190.53
a.root-servers.net.     7173    IN      A       198.41.0.4
h.root-servers.net.     7173    IN      AAAA    2001:500:1::53
a.root-servers.net.     7173    IN      AAAA    2001:503:ba3e::2:30
d.root-servers.net.     7173    IN      AAAA    2001:500:2d::d
k.root-servers.net.     7173    IN      AAAA    2001:7fd::1
c.root-servers.net.     7173    IN      A       192.33.4.12
j.root-servers.net.     7173    IN      AAAA    2001:503:c27::2:30
i.root-servers.net.     7173    IN      A       192.36.148.17
k.root-servers.net.     7173    IN      A       193.0.14.129
g.root-servers.net.     7173    IN      AAAA    2001:500:12::d0d
c.root-servers.net.     7173    IN      AAAA    2001:500:2::c
b.root-servers.net.     7173    IN      AAAA    2001:500:200::b
j.root-servers.net.     7173    IN      A       192.58.128.30
l.root-servers.net.     7173    IN      A       199.7.83.42
f.root-servers.net.     7173    IN      AAAA    2001:500:2f::f

;; Query time: 0 msec
;; SERVER: 10.0.2.3#53(10.0.2.3) (UDP)
;; WHEN: Tue May 09 01:47:36 EDT 2023
;; MSG SIZE  rcvd: 811
```

----

There are some privately hosted **Public DNS Servers** so that everyone does not need a local DNS server:     
Type in a web browser: 1.1.1.1 or 8.8.8.8   

----

On Ubuntu or similar distro: [DNS config using BIND](https://ubuntu.com/server/docs/service-domain-name-service-dns)   

----

[DNS playground](https://messwithdns.net/) by Julia Evans   

----

## Top Level Domain TLD    

A Top Level Domain or TLD is the most right-end part of a domain name. e.g., TLD for godaddy.com is .com. 

There are gTLD (Generic Top Level) and ccTLD (Country Code Top Level Domain). 

A gTLD is meant to describe the domain name's purpose. e.g., gTLD .com is for commercial entities, .edu for education, and .gov for the government. 

A ccTLD is meant to describe some country or geography. e.g., .in for sites hosted/based in India, .co.uk for sites based in the United Kingdom. 

These days there are too many new gTLDs like .bank, .bharti, .biz, .coffee, .dell, etc. A full list of gTLDs is available on [IANA](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) website.   

Further, second-level domains are registered by organizations. When registering a domain name, the second-level domain name is limited to 63 characters + the TLD and can only use a-z 0-9 and in-between hyphens (cannot start or end with hyphens or have consecutive hyphens). Subdomains added by domain owners have the same limitations. The maximum length of a domain name is 253 characters, including multiple subdomain prefixes like abc.def.lmn.pqrs.example.com     

----

## dig into DNS

Dig into DNS and query A (IP Address), SOA (Start of Authority - admin record), NS (name server), MX (mail server), TXT (domain ownership, to prevent mail spam), CNAME (canonical name or alias) records. Pay attention to the QUESTION, ANSWER, AUTHORITY, and ADDITIONAL sections in the output of dig.    

Note:- Do not ignore DNS TTL values. Sys admin should set DNS TTL values appropriately. See a few [DNS TTL basics](https://www.varonis.com/blog/dns-ttl) and [SOA TTL values](https://ns1.com/resources/understanding-ttl-values-in-dns-records).    

Note:- Before making a major change or to make a change effected presumably faster,   
i) Lower the TTL of the concerned record to get it expired sooner,   
ii) make the change, and   
iii) edit TTL to a suitable value in the next 48-72 hours.    

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
You can use +nocmd +noall +answer flags for a clean and simple output.    

```
$ dig +nocmd iitjammu.ac.in MX +noall +answer   

iitjammu.ac.in.		7174	IN	MX	5 ALT1.ASPMX.L.GOOGLE.COM.
iitjammu.ac.in.		7174	IN	MX	5 ALT2.ASPMX.L.GOOGLE.COM.
iitjammu.ac.in.		7174	IN	MX	3 ASPMX.L.GOOGLE.COM.
```

----

Use dig to query hostname IP address using public DNS, a faster way.    
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
---- 

Use dig to find the DNS trace leading to a hostname (much like traceroute).    
Pay attention to root nameservers, [DNS registrar](https://www.cloudflare.com/en-gb/learning/dns/glossary/what-is-a-domain-name-registrar/), and intermediate authoritative servers.  
This information is in the public domain. DNS is a global public directory of public IPs and hostnames.   
We will see in the later section another iterative way to reach the same answer - the IP address of a domain name iitjammu.ac.in.   

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

Let's tinker more!    

You may have heard of recursive and iterative DNS queries. From your system to the nearest local DNS server, or authoritative DNS nameserver queries are recursive - you are bound to get a DNS reply/answer. In practice, a local DNS server or authoritative DNS nameserver makes iterative queries from all the way up the root server to-> top-level-domain nameserver to-> next-level DNS registrar where your domain name is registered. Try this iterative DNS query thing:    

We ask a.root-servers.net (one of the 13 root DNS servers in the entire DNS hierarchy):   
Notice the sections in the output:   

```
$ dig @a.root-servers.net iitjammu.ac.in

; <<>> DiG 9.18.12-1-Debian <<>> @a.root-servers.net iitjammu.ac.in
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51998
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 13
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;iitjammu.ac.in.                        IN      A

;; AUTHORITY SECTION:
in.                     172800  IN      NS      ns1.registry.in.
in.                     172800  IN      NS      ns4.registry.in.
in.                     172800  IN      NS      ns5.registry.in.
in.                     172800  IN      NS      ns6.registry.in.
in.                     172800  IN      NS      ns3.registry.in.
in.                     172800  IN      NS      ns2.registry.in.

;; ADDITIONAL SECTION:
ns1.registry.in.        172800  IN      A       37.209.192.12
ns1.registry.in.        172800  IN      AAAA    2001:dcd:1::12
ns4.registry.in.        172800  IN      A       37.209.198.12
ns4.registry.in.        172800  IN      AAAA    2001:dcd:4::12
ns5.registry.in.        172800  IN      A       156.154.100.20
ns5.registry.in.        172800  IN      AAAA    2001:502:2eda::20
ns6.registry.in.        172800  IN      A       156.154.101.20
ns6.registry.in.        172800  IN      AAAA    2001:502:ad09::20
ns3.registry.in.        172800  IN      A       37.209.196.12
ns3.registry.in.        172800  IN      AAAA    2001:dcd:3::12
ns2.registry.in.        172800  IN      A       37.209.194.12
ns2.registry.in.        172800  IN      AAAA    2001:dcd:2::12

;; Query time: 159 msec
;; SERVER: 198.41.0.4#53(a.root-servers.net) (UDP)
;; WHEN: Sun May 07 23:47:41 EDT 2023
;; MSG SIZE  rcvd: 424

```
Dearest root server **a** did not tell us the IP address of our domain. It also indicated that recursive query is not entertained. 

However, the root server **a** did return the TLD registrar for **in** domain (see TLD suffix in the domain name) and IP addresses to find those TLD registrars - as authoritative DNS server in AUTHORITY SECTION. Notice the ADDITIONAL SECTION for IP addresses.     

Further, let us ask the TLD in registrar ns1.registry.in:     

```
$ dig @ns1.registry.in iitjammu.ac.in   

; <<>> DiG 9.18.12-1-Debian <<>> @ns1.registry.in iitjammu.ac.in
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63974
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 3, ADDITIONAL: 4
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;iitjammu.ac.in.                        IN      A

;; AUTHORITY SECTION:
iitjammu.ac.in.         3600    IN      NS      ns1.iitjammu.ac.in.
iitjammu.ac.in.         3600    IN      NS      ns3.iitjammu.ac.in.
iitjammu.ac.in.         3600    IN      NS      ns2.iitjammu.ac.in.

;; ADDITIONAL SECTION:
ns3.iitjammu.ac.in.     3600    IN      A       182.76.238.118
ns2.iitjammu.ac.in.     3600    IN      A       14.139.53.133
ns1.iitjammu.ac.in.     3600    IN      A       14.139.53.132

;; Query time: 27 msec
;; SERVER: 37.209.192.12#53(ns1.registry.in) (UDP)
;; WHEN: Sun May 07 23:58:36 EDT 2023
;; MSG SIZE  rcvd: 145

```

Wow! Note the AUTHORITY SECTION ns1.iitjammu.ac.in, it is the local DNS server - it's configured as an authoritative DNS server. Let us ask him :)   

```
$ dig @ns1.iitjammu.ac.in iitjammu.ac.in

; <<>> DiG 9.18.12-1-Debian <<>> @ns1.iitjammu.ac.in iitjammu.ac.in
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11582
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 3, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;iitjammu.ac.in.                        IN      A

;; ANSWER SECTION:
iitjammu.ac.in.         10      IN      A       14.139.53.140

;; AUTHORITY SECTION:
iitjammu.ac.in.         8600    IN      NS      ns2.iitjammu.ac.in.
iitjammu.ac.in.         8600    IN      NS      ns3.iitjammu.ac.in.
iitjammu.ac.in.         8600    IN      NS      ns1.iitjammu.ac.in.

;; ADDITIONAL SECTION:
ns1.iitjammu.ac.in.     8600    IN      A       14.139.53.132
ns2.iitjammu.ac.in.     8600    IN      A       14.139.53.133
ns3.iitjammu.ac.in.     8600    IN      A       182.76.238.118

;; Query time: 4 msec
;; SERVER: 14.139.53.132#53(ns1.iitjammu.ac.in) (UDP)
;; WHEN: Mon May 08 00:08:27 EDT 2023
;; MSG SIZE  rcvd: 161

```

Bingo! note the ANSWER SECTION - this has an IP address of iitjammu.ac.in, and A record is returned. This completes the journey of iterative DNS queries.     
Compare these steps with the output of dig +trace iitjammu.ac.in to find the IP addresses of the domain. This is what happens in practice every single day.    

----

[See sample DNS request and reply packets using **cloudshark**](https://www.cloudshark.org/captures/de434abca073)    

----

DNS Software: What software DNS server is using?    
Dig Dyno for version.bind, chaos class, and TXT record type; see the answer section.     

```
$ dig @ns1.iitjammu.ac.in version.bind chaos txt

; <<>> DiG 9.18.12-0ubuntu0.22.04.2-Ubuntu <<>> @ns1.iitjammu.ac.in version.bind chaos txt
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45153
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;version.bind.			CH	TXT

;; ANSWER SECTION:
version.bind.		0	CH	TXT	"9.9.4-RedHat-9.9.4-73.el7_6"

;; AUTHORITY SECTION:
version.bind.		0	CH	NS	version.bind.

;; Query time: 16 msec
;; SERVER: 14.139.53.132#53(ns1.iitjammu.ac.in) (UDP)
;; WHEN: Sat Jul 08 09:40:45 IST 2023
;; MSG SIZE  rcvd: 95
```

----

[**DNS Cache**](https://www.keycdn.com/support/dns-cache)    

[View and flush DNS Cache on Linux](https://www.makeuseof.com/view-and-flush-dns-cache-on-linux/), [link2](https://unix.stackexchange.com/questions/28553/how-to-read-the-local-dns-cache-contents)     

----

## New Domain 

While you add a new domain name for your organization/institute, the following steps are helpful:     
- decide on a new domain name (e.g., iiitkota.ac.in or iitjammu.ac.in)    
- register the domain at the DNS registrar (ERNET in India) or get one from a private domain service provider (e.g., godaddy.com)    
- provide the new domain name and public IP address of the authoritative nameserver (to find your new domain); this authoritative nameserver can be within another campus or with another ISP    
- Domain registrar adds two resource records (RRs) into the top-level-domain nameserver (e.g. ns1.registry.in), guess the entries from the above discussion, before you proceed further.     
e.g., 1) 
  -> (iiitkota.ac.in, dns1.iiitkota.ac.in, NS, TTL1)    
  -> (dns1.iiitkota.ac.in, 210.212.97.131, A, TTL2)     
e.g., 2) 
  -> (iitjammu.ac.in, dns8.iitd.ac.in, NS, TTL1)    
  -> (dns8.iitd.ac.in, 103.27.8.1, A, TTL2)    
- DNS authoritative name server can be updated after registration.    

----

## Under the hood of DNS   

DJB on [Secure design and coding for DNS](https://cr.yp.to/talks/2009.03.04/slides.pdf)    

[DNS source tree using BIND9](https://gitlab.isc.org/isc-projects/bind9/-/tree/4c3b063ef8bd6e47b13c1dac3087daa1301a78ac/lib/dns)    

----

## Monitor Network    

In Linux, [some CLI tools to monitor network traffic](https://www.binarytides.com/linux-commands-monitor-network/).    

---- 

## Know sub-domains    

Sometimes you wish to know sub-domains and they don't tell you :) so let us knock on the domain quietly.     
[get knock](https://github.com/guelfoweb/knock) or [puredns](https://github.com/d3mondev/puredns)    

```
$ python3 knockpy.py iitjammu.ac.in 

  _  __                 _                
 | |/ /                | |   v6.1.0            
 | ' / _ __   ___   ___| | ___ __  _   _ 
 |  < | '_ \ / _ \ / __| |/ / '_ \| | | |
 | . \| | | | (_) | (__|   <| |_) | |_| |
 |_|\_\_| |_|\___/ \___|_|\_\ .__/ \__, |
                            | |     __/ |
                            |_|    |___/ 

local: 10757 | remote: 33 .py                                                   

Wordlist: 10790 | Target: iitjammu.ac.in | Ip: 14.139.53.140 

12:48:27

Ip address      Code Subdomain                              Server                                 Real hostname
--------------- ---- -------------------------------------- -------------------------------------- --------------------------------------
14.139.53.136   200  apply.iitjammu.ac.in                                                                                                
10.10.120.180   200  beta.iitjammu.ac.in                                                                                                 
10.10.120.101        console.iitjammu.ac.in                                                                                              
174.138.122.103 200  ces.iitjammu.ac.in                     nginx/1.18.0 (Ubuntu)                                                        
14.139.53.135        depo.iitjammu.ac.in                                                                                                 
13.126.157.211  200  egdev.iitjammu.ac.in                   Apache                                                                       
13.126.157.211  200  eg.iitjammu.ac.in                      Apache                                                                       
13.126.157.211  200  egsec.iitjammu.ac.in                   Apache                                                                       
10.10.10.42          archive.iitjammu.ac.in                                                                                              
10.10.10.170    200  apc.iitjammu.ac.in                                                                                                  
14.139.53.135        eservices.iitjammu.ac.in                                                                                            
14.139.53.135   200  idp.iitjammu.ac.in                     nginx/1.14.0 (Ubuntu)                                                        
10.10.10.44     200  intranet.iitjammu.ac.in                                                                                             
10.10.120.55         elearn.iitjammu.ac.in                                                                                               
10.10.10.43     200  list.iitjammu.ac.in                    nginx/1.14.0 (Ubuntu)                                                        
14.139.53.139   200  lists.iitjammu.ac.in                   nginx/1.14.0 (Ubuntu)                                                        
14.139.53.130   200  lms.iitjammu.ac.in                     Apache/2.4.41 (Ubuntu)                                                       
142.250.194.179 404  mail.iitjammu.ac.in                    ghs                                    ghs.googlehosted.com
10.10.10.53          ipa.iitjammu.ac.in                                                                                                  
10.10.10.45     200  libopac.iitjammu.ac.in                 Apache/2.4.29 (Ubuntu)                                                       
10.10.10.46          dspace.iitjammu.ac.in                                                                                               
10.10.96.254         eye.iitjammu.ac.in                                                                                                  
10.10.194.50         firewall.iitjammu.ac.in                                                                                             
10.10.10.76          mrtg.iitjammu.ac.in                                                                                                 
10.10.28.7           skt.iitjammu.ac.in                                                                                                  
10.10.120.113   200  ssp.iitjammu.ac.in                     Apache/2.4.29 (Ubuntu)                                                       
206.189.202.152      videoconf.iitjammu.ac.in                                                                                            
10.10.120.196   200  wifi.iitjammu.ac.in                    Apache/2.4.41 (Ubuntu)                                                       
14.139.53.140   200  www.iitjammu.ac.in                                                                                                  
14.139.53.133        ns2.iitjammu.ac.in                                                                                                  
182.76.238.118       ns3.iitjammu.ac.in                                                                                                  
14.139.53.132        ns1.iitjammu.ac.in                                                                                                  
14.139.53.129        vpn.iitjammu.ac.in                                                                                                  
                                                                                
12:48:49

Ip address: 30 | Subdomain: 33 | elapsed time: 00:00:22 

```

There is another awesome Kali Linux tool: **dnsenum**, that can reveal much more information about a domain. dnsenum can show domains, nameservers, MX records, zone transfer records for sub-domains, a range of public IP addresses, etc.   
``
$dnsenum -r mydomain.ac.in   
``

---- 

## Simple web server

One line webserver => a great and simplest way to show files from a directory or local share.   
Note the directory you start this server from and the content you want to share locally.   
```
$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [03/Feb/2021 23:33:21] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [03/Feb/2021 23:33:31] "GET /myvideos/ HTTP/1.1" 200 -http://127.0.0http://127.0.0.1:8000/Downloads/http://127.0.0.1:8000/Downloads/http://127.0.0.1:8000/Downloads/.1:8000/Downloads/
127.0.0.1 - - [03/Feb/2021 23:33:36] "GET /Downloads/ HTTP/1.1" 200 -
^C 
Keyboard interrupt received, exiting.

```
The web server started above can be opened in a web browser: http://0.0.0.0:8000/  
This page can be opened before you close the server using Ctrl+C.  

----

## Get files using wget 

You can download files or documentation with many files using **wget**. This is very much like your own web-doc-ripper!   

```
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://developer.android.com/reference/packages
```

---- 

## Email  

* Gmail: [dots in username](https://gmail.googleblog.com/2008/03/2-hidden-ways-to-get-more-from-your.html) do not matter for @gmail.com domain. Where else do you see this in action? IRCTC emails!  
* Gmail: [plus something in username](https://gmail.googleblog.com/2008/03/2-hidden-ways-to-get-more-from-your.html) can be cool for @gmail.com domain.  
* Auto-forward email: [username+caf@domain](https://support.google.com/mail/thread/25788054/auto-forward-mails-are-sent-with-username-caf-domain-instead-of-username-domain)   

* [Add a brand logo to outgoing email with BIMI](https://support.google.com/a/answer/10911320), you need a [VMC](https://support.google.com/a/answer/10911320) with trademarked logo.     

* [10,000 email accounts limit in GSuite/Workplace](https://owasp.org/blog/2023/03/23/gsuite-account-cleanup.html). After a while, someone has to invest in it.    

* [Google Workplace pricing plans](https://workspace.google.com/intl/en_in/pricing.html). Things get costly with per-user per-month plans :(   

* [Gmail sending limits in Google Workspace](https://support.google.com/a/answer/166852)   

* [Enable MTA-STS and TLS reporting](https://support.google.com/a/answer/9276512) to improve email security and reporting. 

---- 

## The One with SPF DKIM and DMARK 

While you may have seen email Spam, you should be familiar with SPF, DKIM, and DMARK records. And more recently, BIMI and VMC.    

A comic take on [SPF and DKIM](https://wizardzines.com/comics/spf-dkim/) by Julia/bork   

1. Sender Policy Framework - [SPF](https://www.dmarcanalyzer.com/spf/)   
SPF can fail for forwarded or redirected emails.   

2. Domain Keys Identified Mail - [DKIM](https://support.google.com/a/answer/180504?hl=en&ref_topic=7564555) and check [DKIM](https://www.dmarcanalyzer.com/dkim/) records   
DKIM can fail for anti-spam or content-filtering software updating the subject in the header or parts of the email messages with a disclaimer. DKIM can fail for [replay attack](https://wordtothewise.com/2014/05/dkim-replay-attacks/) or [by chance](https://noxxi.de/research/breaking-dkim-on-purpose-and-by-chance.html).    

3. Domain-based Message Authentication, Reporting, and Conformance - [DMARC](https://support.google.com/a/answer/2466563?hl=en) and check [DMARK](https://www.dmarcanalyzer.com/dmarc/) records   
SPF or DKIM alone or both together are not sufficient to control spam. DMARC or ARC, combined with SPF and DKIM, are together a good team to fight against spam.   

Sample yml files with "Show Original" option from mail client - adding soon    

4. [ARC Email authentication](https://support.google.com/a/answer/13198639)   

[What email headers can be spoofed?](https://www.quora.com/Is-it-possible-to-fake-every-line-in-an-email-header-I-know-it-is-possible-to-fake-some-lines-but-what-about-the-signed-by-and-mailed-by-lines-How-secure-is-SPF-and-DKIM-authentication)     

[Signed-by and emailed-by in email header](https://www.online-tech-tips.com/computer-tips/worry-verification-emails-google/)    
A visible mailed-by field in the email header means the email was SPF-authenticated. A visible signed-by field in the email header means the email was DKIM-signed.     

5. BIMI and VMC - additional reputation    
You can [add a brand logo to outgoing email with BIMI](https://support.google.com/a/answer/10911320), and for this, you need a [VMC](https://support.google.com/a/answer/10911320) with trademarked logo.    

6. [Enable Mail Transfer Agent (MTA) Strict Transport Security (STS) and TLS reporting](https://support.google.com/a/answer/9276512) to improve email security and reporting.    

---- 

## The One with LDAP 

To query and backup/dump the LDIF tree:    
```
ldapsearch -x -b "dc=iitx,dc=ac,dc=in" -H ldap://10.10.10.10 -D "cn=admin,dc=iitx,dc=ac,dc=in" -W > backup.ldif  
```
This can be useful to create another instance of LDAP. You should mention the root DN / domain name, LDAP server IP, and admin user.    

Sysad should practice and know LDAP-related [command line tools](https://docs.oracle.com/cd/A97630_01/network.920/a96579/comtools.htm) to query, add, delete, and modify LDAP entries. It's a different experience with the command line :) and you can write scripts to automate the housekeeping!    

[Manage LDAP entries using LDAP Account Manager (LAM)](https://www.ldap-account-manager.org/lamcms/) and [Web-based LDAP Schema admin](http://phpldapadmin.sourceforge.net/wiki/index.php/Main_Page)   

---- 

## The One with RADIUS 

In network security, **AAA** is used as an abstraction for authentication, authorization, and accounting purposes concerning WPA2-Enterprise or 802.1x standard for security. RADIUS (Remote Access Dial-In User Service) promises to provide this gold security standard.    
To provide identity (IDP), RADIUS is often used with LDAP. This combination is definitely a fire for Sysad.   

Relevant posts:    
1. [Cloud Radius](https://www.cloudradius.com/ldap-vs-radius/)    
2. [OpenLDAP](https://wiki.freeradius.org/building/openldap), [FreeRadius setup](https://laravel-example.blogspot.com/2019/01/setup-freeradius-authentication-with.html) and [LAM](https://www.ldap-account-manager.org/static/doc/manual-onePage/index.html)   

---- 

## The One with Security 

Some [security-related primer](http://intronetworks.cs.luc.edu/current/html/security.html) and [SSH and TLS](http://intronetworks.cs.luc.edu/current/html/publickey.html#ssh-and-tls)   

Prof Wenliang Du's lab manual (Syracuse Univ) is one practical way to study, introduce, or teach security in labs.   

Note:- Safety and Security are two different aspects. No language is so poor to have two such words for the exact same meaning. For digital infrastructure, compute, and network - we discuss security aspects. We discuss safety aspects against fire, civil/electrical infrastructure, and natural calamity. Remember safety checks for fire, building, doors, accessibility, and security at the entrance gate, airports, and computer/mobile/network. 
Exception: In the context of formal verification of models, safety property asserts that a program execution does not reach a bad state.    

---- 

## SSL TLS Certificates 

[TLS v1.3](https://sectigostore.com/blog/tls-version-1-3-what-to-know-about-the-latest-tls-version/), [TLS v1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446) released in August 2018    

[Browser support or compatibility matrix for TLS v1.3](https://caniuse.com/tls1-3). You can upgrade your web browser once, and you should be fine.   

[TLS versions](https://www.covetus.com/blog/different-versions-of-transfer-layer-security-tls-its-working-and-benefits)   
[TLS versions comparison](https://thesecmaster.com/what-is-ssl-tls-how-ssl-tls-1-2-and-tls-1-3-differ-from-each-other/)   

[Enable/Disable TLS versions on popular servers](https://thesecmaster.com/how-to-enable-tls-1-3-on-popular-web-servers/) and [disable older TLS versions](https://www.ssl.com/guide/disable-tls-1-0-and-1-1-apache-nginx/)   

To disable obsolete versions of SSL/TLS supported by Apache on Ubuntu, specify them as follows in /etc/apache2/mods-enabled/ssl.conf, e.g.:
```
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
```
and to allow TLSv1.2 and v1.3 only:   
```
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

Finally, check the sslscan output, TLS certificate checks like the one by [SSL Labs](https://www.ssllabs.com/ssltest) and [DigiCert](https://www.digicert.com/help/) for TLS certs, and some basic vulnerability checks.   

[Understand Online Certificate Status Protocol (OCSP) and Certificate Revokation](https://www.thesslstore.com/blog/ocsp-ocsp-stapling-ocsp-must-staple/)    

On the client side, do not ignore [SSL/TLS Certificate Errors and ways to address them](https://sematext.com/blog/ssl-certificate-error/)   

For **SendGrid domain whitelisting** validation error [check Top-Level-Domain auto-appending](https://web.archive.org/web/20170706082258/https://sendgrid.com/docs/Classroom/Troubleshooting/Authentication/i_have_created_dns_records_but_the_whitelabel_wizard_is_not_validating_them.html). You should check existing entries in DNS too.   

[SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)    

**System upgrade: You may need to upgrade the Apache server to v2.4.38 or higher, open SSL to v1.1.1 or higher, and Ubuntu OS for TLS v1.3    

Notes:-    
* SSL/TLS Certificates are valid for a maximum of 398 days. You should take care of the time zone if the issuer is not in the same time zone as the host.    
* Paid TLS certificates do not use better cryptography than free certificates (e.g., Let's Encrypt). Paid TLS can give you extended validity on certificates.    
* Subject Alternate Name (SAN) or multi-domain TLS certificates allow additional host names to be protected by the same /single TLS certificate when creating the certificate.   
* Apache allows you to virtually host multiple HTTPS sites with a single public IP address using SAN certificates.    
* Wildcard certificate can protect all sub-domains of the same suffix top-level domain (TLD), e.g., *.mydomain.com - while for *.mydomain.org, you need a separate certificate.   
* SSL is only referred to for historical reasons. Most SSL/TLS certificates currently use TLS v1.2 / v1.3.   
* Web browsers have a hardcoded list of trusted certificate authorities (CA) to check that your certificate is signed by someone it trusts.   
* You can make a "self-signed" TLS certificate. Because a trusted certificate authority does not sign that certificate, browsers won't accept it.   

\citations for TLS notes: [1](https://questions.wizardzines.com/tls-certificates.html) and [2](https://www.digicert.com/faq/public-trust-and-certificates)   

----

Using `openssl` for SSL/TLS certificates    

e.g., check if a remote server uses TLSv1.2 - if you get the certificate chain back, it's all good.    
```
openssl s_client -connect server:port -tls1_2 
```    

```
$ openssl s_client -connect eg.iitjammu.ac.in:443 -tls1_2
CONNECTED(00000003)
depth=2 C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
verify return:1
depth=1 C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
verify return:1
depth=0 CN = eg.iitjammu.ac.in
verify return:1
---
**Certificate chain** 
 0 s:CN = eg.iitjammu.ac.in
   i:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Oct  1 07:06:43 2022 GMT; NotAfter: Oct 27 10:53:42 2023 GMT
 1 s:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
   i:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: May  3 07:00:00 2011 GMT; NotAfter: May  3 07:00:00 2031 GMT
 2 s:C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
   i:C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Jan  1 07:00:00 2014 GMT; NotAfter: May 30 07:00:00 2031 GMT
 3 s:C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority
   i:C = US, O = "The Go Daddy Group, Inc.", OU = Go Daddy Class 2 Certification Authority
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA1
   v:NotBefore: Jun 29 17:06:20 2004 GMT; NotAfter: Jun 29 17:06:20 2034 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIblahblahblahvsgfsgdfgdfgdghdhddhgdfgnfgdhfgfsgdfhhhdhdfnrjtukui
........
dshfjdshfssgfsjgjgsjfblahblahblahpakpakpakakpakpakpakakddsjldkd/w
pakpakpakakpakpakpakak==
-----END CERTIFICATE-----
subject=CN = eg.iitjammu.ac.in
issuer=C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
---
No client certificate CA names sent
Peer signing digest: SHA512
Peer signature type: RSA
Server Temp Key: ECDH, prime256v1, 256 bits
---
SSL handshake has read 5831 bytes and written 340 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 79D976C30E8574E4D021E5CF187E27266DD42B368F351A4BFDA865E5EDD8419A
    Session-ID-ctx: 
    Master-Key: B398AD1FBD71E606C4070D86C95808257FB17019ABDA3170F3DFE0B66BC4ACD0D0A11717EA592ACFC9922B11C5D0D531
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 76 31 07 c5 fd 87 0a 74-32 80 20 c2 bd 6f dd 35   v1.....t2. ..o.5
    0010 - ef d7 ac b0 d1 bd 8a e0-15 b9 23 90 72 de 37 1a   ..........#.r.7.
    0020 - 02 08 81 65 2c 54 7a ea-65 77 c1 fb f2 0d a4 fc   ...e,Tz.ew......
    ..............                                           ...
    00b0 - a3 f6 13 72 2a 92 33 cc-68 46 b0 e4 ff 0c 73 24   ...r*.3.hF....s$
    00c0 - 3b 46 c5 64 02 62 f9 ac-01 1a d6 45 f4 b6 7a f3   ;F.d.b.....E..z.

    Start Time: 1689317360
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
```
----

What is my OpenSSL version? 
```
$ openssl version -a
OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
built on: Wed May 24 17:12:55 2023 UTC
platform: debian-amd64
options:  bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -Wa,--noexecstack -g -O2 -ffile-prefix-map=/build/openssl-Z1YLmC/openssl-3.0.2=. -flto=auto -ffat-lto-objects -flto=auto -ffat-lto-objects -fstack-protector-strong -Wformat -Werror=format-security -DOPENSSL_TLS_SECURITY_LEVEL=2 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2
OPENSSLDIR: "/usr/lib/ssl"
ENGINESDIR: "/usr/lib/x86_64-linux-gnu/engines-3"
MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
Seeding source: os-specific
CPUINFO: OPENSSL_ia32cap=0x7ffaf3bfffebffff:0x18c05fdef3bfa7eb

```
[Online OpenSSL cookbook](https://www.feistyduck.com/library/openssl-cookbook/online/)     

----

## QUIC 

QUIC (a transport layer protocol) can improve the performance of connection-oriented web applications (having sessions) by creating multi-plex UDP connections and eliminating TCP at the transport layer! [See reduced RTTs in handshake](https://en.wikipedia.org/wiki/File:Tcp-vs-quic-handshake.svg).    

----

## The One with Wireshark 

It is fun to see packets down to the protocol level using Wireshark - real-time packets or through a saved pcapng file.   

[Download wireshark](https://www.wireshark.org/download.html) | [Docs](https://www.wireshark.org/docs/)   
Start Wireshark with root, open a web browser, and visit a website. Now, please take a look at the packets in Wireshark.   
You can filter using a protocol, analyze packets - byte stream or different headers, and payload with them.   
See if you can build a meaningful context out of packets for protocols HTTP / TCP / UDP / IP / Ethernet, etc.   

e.g., A nice visual lesson of [TCP window size scaling](https://networklessons.com/cisco/ccie-routing-switching-written/tcp-window-size-scaling)    

[Sample packet captures to visualize and understand protocol level details using **cloudshark**](https://www.cloudshark.org/collections/WTRpgLI-GQSDfgzkQixICg)    

TCPDUMP - One can also rely on powerful [tcpdump](https://opensource.com/article/18/10/introduction-tcpdump). [tcpdump-cheat-sheet](https://www.comparitech.com/net-admin/tcpdump-cheat-sheet/)    

---- 

## The One with Disaster Recovery    

While working with a banking major serving multiple countries across multiple physical data centers, the application had a solid daily overnight processing (EoD) and offline availability (stand-in) setup for maintenance. For enterprise storage replication, a remote data facility over synchronous/asynchronous distances up to 160 to 200 km may be provisioned.     

For Disaster Recovery (DR), first, it is necessary to re-architect and design the transactional application itself for DR support in active/passive or active/active scenarios (based on Recovery Point Objectives/Recovery Time Objectives). Not only transactional data on the primary server, offline availability (stand-in), interfacing, and support with 3rd-party applications (bank payment gateway, messaging gateway, payment/collection batch processing) are required in DR fashion. The load balancing and integration with the SendGrid-like mailer in DR fashion are additional considerations. DR site is not just another copy; it is much more than that.     

[A few sample scenarios](https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-options-in-the-cloud.html)     

----

## The One with VPN 

[Linux VPN Myths](https://linuxsecurity.com/features/common-linux-vpn-myths-busted)    

[How secure is Linux?](https://linuxsecurity.com/features/how-secure-is-linux) Do not miss The Bottom Line    

----
